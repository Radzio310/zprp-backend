"""
Panel „Mentor" - kategorie, klipy, zestawienia, wątki i publiczne linki
(`docs/mentor-panel.md`, 4.6-4.8 i 4.12).

Edytować i usuwać można tylko swoje (administrator wszystko); komisja ogląda.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import (
    database,
    mentor_categories,
    mentor_clips,
    mentor_comments,
    mentor_compilation_items,
    mentor_compilations,
    mentor_match_videos,
    mentor_reports,
    mentor_threads,
    mentoring_pairs,
)
from app.mentor_panel_auth import mentor_actor

router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor


async def _ctx_for(table, row_id: str, actor: Actor, *, action: str = "view", missing: str = "Nie znaleziono.") -> tuple:
    row = await C.one(select(table).where(table.c.id == row_id))
    if not row or row.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", missing)
    ctx = await C.pair_context(row["pair_id"], actor, action=action)
    return ctx, row


# ─── Kategorie ──────────────────────────────────────────────────────────────


async def _live_clip_rows(pair_id: str) -> List[Dict[str, Any]]:
    return await C.rows(select(mentor_clips.c.id, mentor_clips.c.category_ids)
                        .where(mentor_clips.c.pair_id == pair_id).where(mentor_clips.c.deleted_at.is_(None)))


async def category_usage(pair_id: str) -> Dict[str, int]:
    """Ile żywych klipów pary nosi każdą kategorię (licznik w Ustawieniach)."""
    usage: Dict[str, int] = {}
    for r in await _live_clip_rows(pair_id):
        for cid in R.json_value(r.get("category_ids"), []):
            key = R.s(cid)
            if key:
                usage[key] = usage.get(key, 0) + 1
    return usage


async def categories_payload(ctx: Dict[str, Any]) -> Dict[str, Any]:
    usage = await category_usage(ctx["pair_id"])
    return {"categories": [{**C.category_shape(r), "clips_count": usage.get(r["id"], 0)} for r in await C.categories(ctx)],
            "palette": list(R.PALETTE), "icons": list(R.ICONS)}


@router.get("/pairs/{pair_id}/categories")
async def list_categories(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    return await categories_payload(ctx)


class CategoryBody(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    color: Optional[str] = Field(default=None, max_length=40)
    icon: Optional[str] = Field(default=None, max_length=60)
    description: Optional[str] = Field(default=None, max_length=800)
    sort: Optional[int] = None
    #: Tylko w PATCH: `false` przywraca kategorię z archiwum.
    archived: Optional[bool] = None
    #: Tylko administrator: kategoria globalna (widzą ją wszystkie pary).
    global_: bool = Field(default=False, alias="global")

    model_config = {"populate_by_name": True}


@router.post("/pairs/{pair_id}/categories")
async def create_category(pair_id: str, body: CategoryBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="categories")
    if body.global_ and not actor.is_admin:
        raise C.err(403, "ADMIN_ONLY", "Kategorie globalne dodaje administrator.")
    try:
        values = R.clean_category(body.model_dump(by_alias=False))
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    existing = await C.categories(ctx)
    if sum(1 for r in existing if not r.get("archived")) >= R.MAX_CATEGORIES:
        raise C.err(409, "TOO_MANY", "Para ma już komplet kategorii - zarchiwizuj nieużywane.")
    row = {"id": R.new_id(), "pair_id": None if body.global_ else ctx["pair_id"], "key": None, "archived": False,
           "created_by": actor.judge_id, "created_at": C.now(),
           "sort": values.pop("sort", max([int(r.get("sort") or 0) for r in existing] + [0]) + 1), **values}
    await database.execute(mentor_categories.insert().values(**row))
    await C.touch(ctx, actor.judge_id, "category_created", "categories", data={"id": row["id"]})
    return C.category_shape(row)


async def _category_ctx(category_id: str, actor: Actor) -> tuple:
    row = await C.one(select(mentor_categories).where(mentor_categories.c.id == category_id))
    if not row:
        raise C.err(404, "NOT_FOUND", "Nie ma takiej kategorii.")
    if row.get("pair_id") is None:
        if not actor.is_admin:
            raise C.err(403, "ADMIN_ONLY", "Kategorię globalną zmienia administrator.")
        return None, row
    return await C.pair_context(row["pair_id"], actor, action="categories"), row


@router.patch("/categories/{category_id}")
async def update_category(category_id: str, body: CategoryBody, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _category_ctx(category_id, actor)
    try:
        values = R.clean_category(body.model_dump(by_alias=False, exclude_unset=True), partial=True)
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    if body.archived is not None:
        values["archived"] = bool(body.archived)
    if values:
        await database.execute(update(mentor_categories).where(mentor_categories.c.id == category_id).values(**values))
    if ctx:
        await C.touch(ctx, actor.judge_id, "category_updated", "categories", data={"id": category_id})
    return C.category_shape({**row, **values})


@router.delete("/categories/{category_id}")
async def archive_category(category_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _category_ctx(category_id, actor)
    await database.execute(update(mentor_categories).where(mentor_categories.c.id == category_id).values(archived=True))
    if ctx:
        await C.touch(ctx, actor.judge_id, "category_archived", "categories", data={"id": category_id})
    return {"ok": True, "category": C.category_shape({**row, "archived": True})}


@router.post("/pairs/{pair_id}/categories/reset")
async def reset_categories(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="categories")
    plan = R.reset_plan(await C.categories(ctx, seed=False))
    for category_id, patch in plan["restore"]:
        await database.execute(update(mentor_categories).where(mentor_categories.c.id == category_id).values(**patch))
    if plan["archive"]:
        await database.execute(update(mentor_categories).where(mentor_categories.c.id.in_(plan["archive"])).values(archived=True))
    for d in plan["create"]:
        await database.execute(mentor_categories.insert().values(
            id=R.new_id(), pair_id=ctx["pair_id"], key=d["key"], name=d["name"], color=d["color"], icon=d["icon"],
            description=d["description"], sort=d["sort"], archived=False, created_by=actor.judge_id, created_at=C.now()))
    await C.touch(ctx, actor.judge_id, "categories_reset", "categories")
    return await categories_payload(ctx)


class OrderBody(BaseModel):
    ids: List[str] = Field(min_length=1, max_length=R.MAX_CATEGORIES * 2)


@router.put("/pairs/{pair_id}/categories/order")
async def order_categories(pair_id: str, body: OrderBody, actor: Actor = Depends(mentor_actor)):
    """Nowa kolejność kategorii pary (pozycja = klawisz 1-9 w pokoju meczu). Globalne pomijamy."""
    ctx = await C.pair_context(pair_id, actor, action="categories")
    own = {r["id"] for r in await C.categories(ctx) if r.get("pair_id") == ctx["pair_id"]}
    ids: List[str] = []
    for raw in body.ids:
        value = R.s(raw)
        if value in own and value not in ids:
            ids.append(value)
    if not ids:
        raise C.err(422, "ORDER_EMPTY", "Kolejność nie zawiera żadnej kategorii tej pary.")
    for i, category_id in enumerate(ids):
        await database.execute(update(mentor_categories).where(mentor_categories.c.id == category_id).values(sort=i))
    # Kategorie pominięte w liście (np. zarchiwizowane) idą na koniec, w dotychczasowym porządku.
    rest = [r for r in await C.categories(ctx, seed=False) if r["id"] in own and r["id"] not in ids]
    for j, r in enumerate(rest):
        await database.execute(update(mentor_categories).where(mentor_categories.c.id == r["id"]).values(sort=len(ids) + j))
    await C.touch(ctx, actor.judge_id, "categories_ordered", "categories", data={"ids": ids})
    return await categories_payload(ctx)


class MergeBody(BaseModel):
    into: str = Field(min_length=1, max_length=80)


class UnmergeBody(BaseModel):
    into: str = Field(min_length=1, max_length=80)
    #: Klipy z odpowiedzi scalania: `added` = klip dostał kategorię docelową dopiero przy scalaniu.
    clips: List[Dict[str, Any]] = Field(default_factory=list, max_length=5000)


def _ids_of(row: Dict[str, Any]) -> List[str]:
    return [R.s(x) for x in R.json_value(row.get("category_ids"), []) if R.s(x)]


async def _merge_pair(category_id: str, into: str, actor: Actor) -> tuple:
    ctx, source = await _category_ctx(category_id, actor)
    if ctx is None:
        raise C.err(403, "GLOBAL_CATEGORY", "Kategorii globalnej nie scala się w parze.")
    target = next((r for r in await C.categories(ctx, seed=False) if r["id"] == R.s(into)), None)
    if not target or target["id"] == source["id"]:
        raise C.err(422, "MERGE_TARGET", "Wybierz inną kategorię tej pary.")
    return ctx, source, target


@router.post("/categories/{category_id}/merge")
async def merge_category(category_id: str, body: MergeBody, actor: Actor = Depends(mentor_actor)):
    """Scal: klipy z kategorią źródłową dostają docelową, źródło idzie do archiwum.
    Odpowiedź niesie listę ruchów - `/unmerge` cofa scalanie co do klipu."""
    ctx, source, target = await _merge_pair(category_id, body.into, actor)
    moved: List[Dict[str, Any]] = []
    for r in await _live_clip_rows(ctx["pair_id"]):
        ids = _ids_of(r)
        if source["id"] not in ids:
            continue
        added = target["id"] not in ids
        out = [target["id"] if x == source["id"] else x for x in ids] if added else [x for x in ids if x != source["id"]]
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == r["id"])
                               .values(category_ids=C.dumps(out), updated_at=C.now()))
        moved.append({"id": r["id"], "added": added})
    await database.execute(update(mentor_categories).where(mentor_categories.c.id == source["id"]).values(archived=True))
    await C.touch(ctx, actor.judge_id, "categories_merged", "categories",
                  data={"from": source["id"], "into": target["id"], "clips": len(moved)})
    return {**await categories_payload(ctx), "merged": {"from": source["id"], "into": target["id"], "clips": moved}}


@router.post("/categories/{category_id}/unmerge")
async def unmerge_category(category_id: str, body: UnmergeBody, actor: Actor = Depends(mentor_actor)):
    """Cofnięcie scalania: źródło wraca z archiwum, klipy odzyskują kategorię źródłową."""
    ctx, source, target = await _merge_pair(category_id, body.into, actor)
    plan = {R.s(c.get("id")): bool(c.get("added")) for c in body.clips if isinstance(c, dict) and R.s(c.get("id"))}
    restored = 0
    for r in await _live_clip_rows(ctx["pair_id"]):
        if r["id"] not in plan:
            continue
        ids = _ids_of(r)
        if plan[r["id"]]:
            ids = [source["id"] if x == target["id"] else x for x in ids] if target["id"] in ids else ids + [source["id"]]
        elif source["id"] not in ids:
            ids = ids + [source["id"]]
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == r["id"])
                               .values(category_ids=C.dumps(ids[:8]), updated_at=C.now()))
        restored += 1
    await database.execute(update(mentor_categories).where(mentor_categories.c.id == source["id"]).values(archived=False))
    await C.touch(ctx, actor.judge_id, "categories_unmerged", "categories",
                  data={"from": source["id"], "into": target["id"], "clips": restored})
    return await categories_payload(ctx)


# ─── Klipy ──────────────────────────────────────────────────────────────────


class ClipBody(BaseModel):
    match_id: str = Field(min_length=1, max_length=80)
    video_id: str = Field(min_length=1, max_length=80)
    start_s: float
    end_s: float
    title: Optional[str] = Field(default=None, max_length=400)
    note: Optional[str] = Field(default=None, max_length=5000)
    category_ids: List[str] = Field(default_factory=list, max_length=20)
    source: Optional[str] = Field(default=None, max_length=20)
    source_key: Optional[str] = Field(default=None, max_length=200)
    match_ms: Optional[int] = None
    half: Optional[int] = None


class ClipPatch(BaseModel):
    start_s: Optional[float] = None
    end_s: Optional[float] = None
    title: Optional[str] = Field(default=None, max_length=400)
    note: Optional[str] = Field(default=None, max_length=5000)
    category_ids: Optional[List[str]] = Field(default=None, max_length=20)


async def _video_of(ctx: Dict[str, Any], match_id: str, video_id: str) -> Dict[str, Any]:
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == video_id))
    if not video or R.s(video.get("match_id")) != R.s(match_id) or R.s(video.get("pair_key")) != ctx["pair_key"]:
        raise C.err(404, "VIDEO_NOT_FOUND", "Nie ma takiego nagrania przy tym meczu.")
    return video


async def _video_duration(video: Dict[str, Any]) -> Optional[float]:
    if video.get("kind") == "upload" and video.get("upload_id"):
        from app.db import mentor_uploads

        upload = await C.one(select(mentor_uploads.c.duration_s).where(mentor_uploads.c.id == video["upload_id"]))
        if upload and upload.get("duration_s"):
            return float(upload["duration_s"])
    return float(video["duration_s"]) if video.get("duration_s") else None


async def _allowed_categories(ctx: Dict[str, Any]) -> List[str]:
    return [r["id"] for r in await C.categories(ctx) if not r.get("archived")]


async def clip_payload(ctx: Dict[str, Any], clip_id: str) -> Dict[str, Any]:
    row = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    return (await C.clips_payload(ctx, [row]))[0]


@router.post("/pairs/{pair_id}/clips")
async def create_clip(pair_id: str, body: ClipBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    card = await C.match_card(ctx, body.match_id)
    video = await _video_of(ctx, card["match_id"], body.video_id)
    try:
        start, end = R.validate_clip(body.start_s, body.end_s, await _video_duration(video))
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    source = body.source if body.source in R.CLIP_SOURCES else "manual"
    stamp = C.now()
    row = {
        "id": R.new_id(), "pair_id": ctx["pair_id"], "match_id": card["match_id"], "video_id": video["id"],
        "start_s": start, "end_s": end, "title": R.plain(body.title, R.MAX_CLIP_TITLE) or None,
        "note": R.plain(body.note, R.MAX_CLIP_NOTE) or None,
        "category_ids": C.dumps(R.clean_category_ids(body.category_ids, await _allowed_categories(ctx))),
        "source": source, "source_key": R.plain(body.source_key, 120) or None,
        "match_ms": body.match_ms if body.match_ms is None or 0 <= body.match_ms <= 3 * 3600 * 1000 else None,
        "half": body.half if body.half in (1, 2) else None, "author_id": actor.judge_id,
        "acted_by": actor.acted_by, "created_at": stamp, "updated_at": stamp, "mp4_status": "none",
    }
    await database.execute(mentor_clips.insert().values(**row))
    await C.touch(ctx, actor.judge_id, "clip_created", "clips", card["match_id"], {"id": row["id"]})
    return await clip_payload(ctx, row["id"])


@router.patch("/clips/{clip_id}")
async def update_clip(clip_id: str, body: ClipPatch, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _ctx_for(mentor_clips, clip_id, actor, missing="Nie ma takiego klipu.")
    C.check(ctx, "edit", owner=R.s(row.get("author_id")) == actor.judge_id)
    patch = body.model_dump(exclude_unset=True)
    values: Dict[str, Any] = {"updated_at": C.now()}
    if "start_s" in patch or "end_s" in patch:
        video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == row["video_id"])) or {}
        try:
            start, end = R.validate_clip(patch.get("start_s", row["start_s"]), patch.get("end_s", row["end_s"]),
                                         await _video_duration(video) if video else None)
        except R.RuleError as exc:
            raise C.rule_error(exc) from exc
        if (start, end) != (row["start_s"], row["end_s"]):
            values.update(start_s=start, end_s=end)
            if row.get("mp4_status") not in (None, "none"):
                from app.mentor_panel_media import forget_object

                forget_object(row.get("mp4_key"))
                values.update(mp4_status="none", mp4_key=None, mp4_size=None)
    if "title" in patch:
        values["title"] = R.plain(patch["title"], R.MAX_CLIP_TITLE) or None
    if "note" in patch:
        values["note"] = R.plain(patch["note"], R.MAX_CLIP_NOTE) or None
    if patch.get("category_ids") is not None:
        values["category_ids"] = C.dumps(R.clean_category_ids(patch["category_ids"], await _allowed_categories(ctx)))
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip_id).values(**values))
    await C.touch(ctx, actor.judge_id, "clip_updated", "clips", row["match_id"], {"id": clip_id})
    return await clip_payload(ctx, clip_id)


@router.delete("/clips/{clip_id}")
async def delete_clip(clip_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _ctx_for(mentor_clips, clip_id, actor, missing="Nie ma takiego klipu.")
    C.check(ctx, "edit", owner=R.s(row.get("author_id")) == actor.judge_id)
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip_id)
                           .values(deleted_at=C.now(), public_token=None, published_at=None))
    if row.get("mp4_key"):
        from app.mentor_panel_media import forget_object

        forget_object(row.get("mp4_key"))
    await C.touch(ctx, actor.judge_id, "clip_deleted", "clips", row["match_id"], {"id": clip_id})
    return {"ok": True}


@router.get("/pairs/{pair_id}/clips")
async def list_clips(pair_id: str, category: str = Query("", max_length=80), match_id: str = Query("", max_length=80),
                     author: str = Query("", max_length=40), q: str = Query("", max_length=80),
                     actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    query = select(mentor_clips).where(mentor_clips.c.pair_id == ctx["pair_id"]).where(mentor_clips.c.deleted_at.is_(None))
    if match_id:
        query = query.where(mentor_clips.c.match_id == match_id)
    if author:
        query = query.where(mentor_clips.c.author_id == author)
    found = await C.rows(query.order_by(mentor_clips.c.created_at.desc()).limit(1000))
    if category:
        found = [r for r in found if category in R.json_value(r.get("category_ids"), [])]
    needle = q.strip().casefold()
    if needle:
        found = [r for r in found if needle in f"{R.s(r.get('title'))} {R.s(r.get('note'))}".casefold()]
    return {"clips": await C.clips_payload(ctx, found), "rev": ctx["rev"]}


# ─── Zestawienia ────────────────────────────────────────────────────────────


class CompilationBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    mode: str = Field(default="free", max_length=20)
    description: Optional[str] = Field(default=None, max_length=2000)
    items: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=R.MAX_COMPILATION_ITEMS)


class CompilationPatch(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    mode: Optional[str] = Field(default=None, max_length=20)
    description: Optional[str] = Field(default=None, max_length=2000)


class ItemsBody(BaseModel):
    items: List[Dict[str, Any]] = Field(default_factory=list, max_length=R.MAX_COMPILATION_ITEMS)
    # Playlista (24.10.2026): klient zapisuje całość jako „free” - stary
    # „kontrast” przechodzi w playlistę tym samym zapisem.
    mode: Optional[str] = Field(default=None, max_length=20)


class ItemBody(BaseModel):
    clip_id: str = Field(min_length=1, max_length=80)
    column: Optional[str] = Field(default=None, max_length=2)
    note: Optional[str] = Field(default=None, max_length=1000)
    label: Optional[str] = Field(default=None, max_length=200)


def _mode(value: Optional[str]) -> str:
    if value not in R.COMPILATION_MODES:
        raise C.err(422, "COMPILATION_MODE", "Rodzaj zestawienia: kontrast, podobne albo wolne.")
    return value


async def _items(compilation_id: str) -> List[Dict[str, Any]]:
    return await C.rows(select(mentor_compilation_items).where(mentor_compilation_items.c.compilation_id == compilation_id)
                        .order_by(mentor_compilation_items.c.position.asc()))


async def _live_clips(pair_id: str, clip_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not clip_ids:
        return {}
    found = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == pair_id).where(mentor_clips.c.id.in_(clip_ids))
                         .where(mentor_clips.c.deleted_at.is_(None)))
    return {r["id"]: r for r in found}


def _cover(clip: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not clip:
        return None
    return {k: clip.get(k) for k in ("id", "match_id", "video_id", "start_s", "end_s", "title")} | {
        "category_ids": R.json_value(clip.get("category_ids"), [])}


async def compilation_summaries(ctx: Dict[str, Any], comp_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    names = await C.people({r.get("created_by") for r in comp_rows} | {r.get("acted_by") for r in comp_rows})
    out = []
    for comp in comp_rows:
        items = await _items(comp["id"])
        clips = await _live_clips(ctx["pair_id"], [i["clip_id"] for i in items])
        live = [i for i in items if i["clip_id"] in clips]
        out.append({
            "id": comp["id"], "name": comp.get("name"), "mode": comp.get("mode"), "description": comp.get("description"),
            "items_count": len(live), "cover_clip": _cover(clips.get(live[0]["clip_id"])) if live else None,
            "created_by": C.person(names, comp.get("created_by")), **C.acted_fields(names, comp), "updated_at": comp.get("updated_at"),
            "public_url": R.public_url("compilation", comp.get("public_token")),
        })
    return out


async def compilation_payload(ctx: Dict[str, Any], compilation_id: str) -> Dict[str, Any]:
    comp = await C.one(select(mentor_compilations).where(mentor_compilations.c.id == compilation_id))
    items = await _items(compilation_id)
    clips = await _live_clips(ctx["pair_id"], [i["clip_id"] for i in items])
    live = [i for i in items if i["clip_id"] in clips]
    shaped = {c["id"]: c for c in await C.clips_payload(ctx, [clips[i["clip_id"]] for i in live])}
    # Sekcje meczów w playliście (herby, numer, data, wynik) - skrót karty meczu przy klipie.
    cards = {c["match_id"]: c for c in await C.pair_match_cards(ctx["judge_ids"])} if live else {}
    for clip in shaped.values():
        clip["match"] = R.slim_match(cards.get(clip.get("match_id")))
    names = await C.people([comp.get("created_by"), comp.get("acted_by")])
    return {
        "id": comp["id"], "pair_id": comp.get("pair_id"), "name": comp.get("name"), "mode": comp.get("mode"),
        "description": comp.get("description"), "created_by": C.person(names, comp.get("created_by")), **C.acted_fields(names, comp),
        "created_at": comp.get("created_at"), "updated_at": comp.get("updated_at"),
        "public_url": R.public_url("compilation", comp.get("public_token")),
        "can_edit": C.may(ctx, "edit", owner=R.s(comp.get("created_by")) == ctx["actor"].judge_id),
        "items": [{"clip": shaped[i["clip_id"]], "column": i.get("column"), "note": i.get("note"),
                   "label": R.legacy_label(i, comp.get("mode") or "free"), "position": n}
                  for n, i in enumerate(live)],
    }


async def _write_items(compilation_id: str, items: List[Dict[str, Any]]) -> None:
    await database.execute(delete(mentor_compilation_items).where(mentor_compilation_items.c.compilation_id == compilation_id))
    for item in items:
        await database.execute(mentor_compilation_items.insert().values(compilation_id=compilation_id, **item))


async def _valid_items(ctx: Dict[str, Any], raw: List[Dict[str, Any]], mode: str) -> List[Dict[str, Any]]:
    ordered = R.order_items(raw, mode)
    clips = await _live_clips(ctx["pair_id"], [i["clip_id"] for i in ordered])
    missing = [i["clip_id"] for i in ordered if i["clip_id"] not in clips]
    if missing:
        raise C.err(422, "CLIP_NOT_FOUND", "Część klipów nie należy do tej pary albo została usunięta.")
    return ordered


@router.get("/pairs/{pair_id}/compilations")
async def list_compilations(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    found = await C.rows(select(mentor_compilations).where(mentor_compilations.c.pair_id == ctx["pair_id"])
                         .order_by(mentor_compilations.c.updated_at.desc()))
    return {"compilations": await compilation_summaries(ctx, found)}


@router.post("/pairs/{pair_id}/compilations")
async def create_compilation(pair_id: str, body: CompilationBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    mode = _mode(body.mode)
    name = R.plain(body.name, 60)
    if not name:
        raise C.err(422, "COMPILATION_NAME", "Podaj nazwę zestawienia.")
    items = await _valid_items(ctx, body.items or [], mode)
    stamp = C.now()
    row = {"id": R.new_id(), "pair_id": ctx["pair_id"], "name": name, "description": R.plain(body.description, 500) or None,
           "mode": mode, "created_by": actor.judge_id, "acted_by": actor.acted_by, "created_at": stamp, "updated_at": stamp}
    await database.execute(mentor_compilations.insert().values(**row))
    await _write_items(row["id"], items)
    await C.touch(ctx, actor.judge_id, "compilation_created", "compilations", data={"id": row["id"]})
    return await compilation_payload(ctx, row["id"])


@router.get("/compilations/{compilation_id}")
async def get_compilation(compilation_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, _row = await _ctx_for(mentor_compilations, compilation_id, actor, missing="Nie ma takiego zestawienia.")
    return await compilation_payload(ctx, compilation_id)


async def _editable_compilation(compilation_id: str, actor: Actor) -> tuple:
    ctx, row = await _ctx_for(mentor_compilations, compilation_id, actor, missing="Nie ma takiego zestawienia.")
    C.check(ctx, "edit", owner=R.s(row.get("created_by")) == actor.judge_id)
    return ctx, row


@router.patch("/compilations/{compilation_id}")
async def update_compilation(compilation_id: str, body: CompilationPatch, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _editable_compilation(compilation_id, actor)
    patch = body.model_dump(exclude_unset=True)
    values: Dict[str, Any] = {"updated_at": C.now()}
    if patch.get("name") is not None:
        values["name"] = R.plain(patch["name"], 60) or row["name"]
    if "description" in patch:
        values["description"] = R.plain(patch["description"], 500) or None
    if patch.get("mode") is not None and patch["mode"] != row.get("mode"):
        values["mode"] = _mode(patch["mode"])
        current = await _items(compilation_id)
        # Kontrast -> playlista: kolumny A/B przechodzą w etykiety, kolejność A1, B1...
        reordered = R.playlist_items(current, row.get("mode") or "free") if values["mode"] == "free" else R.order_items(current, values["mode"])
        await _write_items(compilation_id, reordered)
    await database.execute(update(mentor_compilations).where(mentor_compilations.c.id == compilation_id).values(**values))
    await C.touch(ctx, actor.judge_id, "compilation_updated", "compilations", data={"id": compilation_id})
    return await compilation_payload(ctx, compilation_id)


@router.delete("/compilations/{compilation_id}")
async def delete_compilation(compilation_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, _row = await _editable_compilation(compilation_id, actor)
    await database.execute(delete(mentor_compilation_items).where(mentor_compilation_items.c.compilation_id == compilation_id))
    await database.execute(delete(mentor_compilations).where(mentor_compilations.c.id == compilation_id))
    await C.touch(ctx, actor.judge_id, "compilation_deleted", "compilations", data={"id": compilation_id})
    return {"ok": True}


@router.put("/compilations/{compilation_id}/items")
async def replace_items(compilation_id: str, body: ItemsBody, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _editable_compilation(compilation_id, actor)
    mode = _mode(body.mode) if body.mode is not None else (row.get("mode") or "free")
    items = await _valid_items(ctx, body.items, mode)
    await _write_items(compilation_id, items)
    values: Dict[str, Any] = {"updated_at": C.now()}
    if mode != row.get("mode"):
        values["mode"] = mode
    await database.execute(update(mentor_compilations).where(mentor_compilations.c.id == compilation_id).values(**values))
    await C.touch(ctx, actor.judge_id, "compilation_items", "compilations", data={"id": compilation_id})
    return await compilation_payload(ctx, compilation_id)


@router.post("/compilations/{compilation_id}/items")
async def add_item(compilation_id: str, body: ItemBody, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _editable_compilation(compilation_id, actor)
    mode = row.get("mode") or "free"
    items = R.append_item(await _items(compilation_id), body.clip_id, body.column, mode, body.label)
    if body.note:
        for item in items:
            if item["clip_id"] == body.clip_id:
                item["note"] = R.plain(body.note, 280)
    items = await _valid_items(ctx, items, mode)
    await _write_items(compilation_id, items)
    await database.execute(update(mentor_compilations).where(mentor_compilations.c.id == compilation_id).values(updated_at=C.now()))
    await C.touch(ctx, actor.judge_id, "compilation_items", "compilations", data={"id": compilation_id})
    return await compilation_payload(ctx, compilation_id)


# ─── Wątki ──────────────────────────────────────────────────────────────────


class ThreadBody(BaseModel):
    target_kind: str = Field(max_length=20)
    target_id: str = Field(min_length=1, max_length=80)
    title: Optional[str] = Field(default=None, max_length=400)
    kind: str = Field(default="question", max_length=20)
    body: str = Field(min_length=1, max_length=8000)
    video_id: Optional[str] = Field(default=None, max_length=80)
    video_s: Optional[float] = None
    drawing: Optional[Any] = None
    mentions: List[str] = Field(default_factory=list, max_length=20)


class CommentBody(BaseModel):
    body: str = Field(min_length=1, max_length=8000)
    video_id: Optional[str] = Field(default=None, max_length=80)
    video_s: Optional[float] = None
    drawing: Optional[Any] = None
    mentions: List[str] = Field(default_factory=list, max_length=20)


class CommentPatch(BaseModel):
    body: Optional[str] = Field(default=None, max_length=8000)
    video_s: Optional[float] = None
    drawing: Optional[Any] = None
    mentions: Optional[List[str]] = Field(default=None, max_length=20)


class ThreadPatch(BaseModel):
    status: Optional[str] = Field(default=None, max_length=20)
    title: Optional[str] = Field(default=None, max_length=400)


async def _thread_target(ctx: Dict[str, Any], kind: str, target_id: str) -> Optional[str]:
    """Sprawdza cel wątku i zwraca mecz, którego dotyczy."""
    if kind == "match":
        return (await C.match_card(ctx, target_id))["match_id"]
    if kind == "clip":
        clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == target_id))
        if not clip or clip["pair_id"] != ctx["pair_id"] or clip.get("deleted_at") is not None:
            raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
        return clip["match_id"]
    if kind == "compilation":
        comp = await C.one(select(mentor_compilations).where(mentor_compilations.c.id == target_id))
        if not comp or comp["pair_id"] != ctx["pair_id"]:
            raise C.err(404, "NOT_FOUND", "Nie ma takiego zestawienia.")
        return None
    if kind == "pair":
        if target_id != ctx["pair_id"]:
            raise C.err(422, "THREAD_TARGET", "Wątek pary wskazuje tę parę.")
        return None
    raise C.err(422, "THREAD_TARGET", "Wątek dotyczy meczu, klipu, zestawienia albo pary.")


def _comment_values(ctx: Dict[str, Any], body: Any, *, partial: bool = False) -> Dict[str, Any]:
    data = body.model_dump(exclude_unset=partial)
    values: Dict[str, Any] = {}
    if "body" in data and data["body"] is not None:
        text = R.plain(data["body"], R.MAX_BODY)
        if not text:
            raise C.err(422, "COMMENT_EMPTY", "Komentarz nie może być pusty.")
        values["body"] = text
    if "video_id" in data:
        values["video_id"] = R.s(data.get("video_id")) or None
    if "video_s" in data:
        values["video_s"] = R.clean_video_anchor(data.get("video_s"))
    if "drawing" in data:
        drawing = R.clean_drawing(data.get("drawing"))
        values["drawing_json"] = C.dumps(drawing) if drawing else None
    if "mentions" in data and data.get("mentions") is not None:
        values["mentions"] = C.dumps(R.clean_mentions(data["mentions"], [*ctx["judge_ids"], *ctx["mentor_ids"]]))
    return values


async def _notify_comment(ctx: Dict[str, Any], actor: Actor, thread: Dict[str, Any], body: str, mentions: List[str], *, new: bool) -> None:
    from app.mentor_panel_notify import notify, recipients_for

    target = thread.get("target_id") if thread.get("target_kind") == "clip" else None
    link = f"{C.WEB_BASE}/{ctx['pair_id']}" + (f"/mecz/{thread['match_id']}" if thread.get("match_id") else "")
    excerpt = body if len(body) <= 120 else body[:117] + "..."
    mentioned = [m for m in mentions if m != actor.judge_id]
    if mentioned:
        await notify(ctx, actor.judge_id, f"{actor.display_name} wspomina o Tobie", excerpt, recipients=mentioned,
                     match_id=thread.get("match_id"), clip_id=target, thread_id=thread["id"], link=link)
    others = [r for r in recipients_for(ctx, actor.judge_id) if r not in mentioned]
    title = ("Nowy wątek: " + (thread.get("title") or "bez tytułu")) if new else f"{actor.display_name} odpowiada"
    await notify(ctx, actor.judge_id, title[:120], excerpt, recipients=others, match_id=thread.get("match_id"),
                 clip_id=target, thread_id=thread["id"], link=link)


async def thread_payload(ctx: Dict[str, Any], thread_id: str) -> Dict[str, Any]:
    row = await C.one(select(mentor_threads).where(mentor_threads.c.id == thread_id))
    return (await C.threads_payload(ctx, [row]))[0]


@router.get("/pairs/{pair_id}/threads")
async def list_threads(pair_id: str, target_kind: str = Query("", max_length=20), target_id: str = Query("", max_length=80),
                       status: str = Query("", max_length=20), actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    query = select(mentor_threads).where(mentor_threads.c.pair_id == ctx["pair_id"])
    if target_kind:
        query = query.where(mentor_threads.c.target_kind == target_kind)
    if target_id:
        query = query.where(mentor_threads.c.target_id == target_id)
    if status:
        query = query.where(mentor_threads.c.status == status)
    found = await C.rows(query.order_by(func.coalesce(mentor_threads.c.last_comment_at, mentor_threads.c.created_at).desc()).limit(300))
    return {"threads": await C.threads_payload(ctx, found), "rev": ctx["rev"]}


@router.post("/pairs/{pair_id}/threads")
async def create_thread(pair_id: str, body: ThreadBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    if body.kind not in R.THREAD_KINDS:
        raise C.err(422, "THREAD_KIND", "Rodzaj wątku: pytanie, notatka albo zadanie.")
    match_id = await _thread_target(ctx, body.target_kind, body.target_id)
    comment = _comment_values(ctx, CommentBody(body=body.body, video_id=body.video_id, video_s=body.video_s,
                                               drawing=body.drawing, mentions=body.mentions))
    stamp = C.now()
    thread = {"id": R.new_id(), "pair_id": ctx["pair_id"], "target_kind": body.target_kind, "target_id": body.target_id,
              "match_id": match_id, "title": R.plain(body.title, 120) or None, "kind": body.kind, "status": "open",
              "created_by": actor.judge_id, "acted_by": actor.acted_by, "created_at": stamp, "updated_at": stamp,
              "last_comment_at": stamp}
    await database.execute(mentor_threads.insert().values(**thread))
    await database.execute(mentor_comments.insert().values(id=R.new_id(), thread_id=thread["id"], author_id=actor.judge_id,
                                                           acted_by=actor.acted_by, created_at=stamp, mentions=comment.pop("mentions", "[]"), **comment))
    await C.touch(ctx, actor.judge_id, "thread_created", "threads", match_id, {"id": thread["id"]})
    await _notify_comment(ctx, actor, thread, body.body, R.clean_mentions(body.mentions, [*ctx["judge_ids"], *ctx["mentor_ids"]]), new=True)
    return await thread_payload(ctx, thread["id"])


@router.patch("/threads/{thread_id}")
async def update_thread(thread_id: str, body: ThreadPatch, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _ctx_for(mentor_threads, thread_id, actor, action="create", missing="Nie ma takiego wątku.")
    values: Dict[str, Any] = {"updated_at": C.now()}
    if body.status is not None:
        if body.status not in R.THREAD_STATUSES:
            raise C.err(422, "THREAD_STATUS", "Stan wątku: otwarty albo rozwiązany.")
        values["status"] = body.status
    if body.title is not None:
        C.check(ctx, "edit", owner=R.s(row.get("created_by")) == actor.judge_id)
        values["title"] = R.plain(body.title, 120) or None
    await database.execute(update(mentor_threads).where(mentor_threads.c.id == thread_id).values(**values))
    await C.touch(ctx, actor.judge_id, "thread_updated", "threads", row.get("match_id"), {"id": thread_id})
    return await thread_payload(ctx, thread_id)


@router.post("/threads/{thread_id}/comments")
async def add_comment(thread_id: str, body: CommentBody, actor: Actor = Depends(mentor_actor)):
    ctx, thread = await _ctx_for(mentor_threads, thread_id, actor, action="create", missing="Nie ma takiego wątku.")
    values = _comment_values(ctx, body)
    stamp = C.now()
    comment_id = R.new_id()
    await database.execute(mentor_comments.insert().values(id=comment_id, thread_id=thread_id, author_id=actor.judge_id,
                                                           acted_by=actor.acted_by, created_at=stamp, **{"mentions": "[]", **values}))
    await database.execute(update(mentor_threads).where(mentor_threads.c.id == thread_id)
                           .values(last_comment_at=stamp, updated_at=stamp))
    await C.touch(ctx, actor.judge_id, "comment_created", "threads", thread.get("match_id"), {"id": comment_id})
    await _notify_comment(ctx, actor, thread, values["body"], R.json_value(values.get("mentions"), []), new=False)
    row = await C.one(select(mentor_comments).where(mentor_comments.c.id == comment_id))
    return C.comment_shape(ctx, row, await C.people([actor.judge_id, actor.acted_by]))


async def _comment_ctx(comment_id: str, actor: Actor) -> tuple:
    row = await C.one(select(mentor_comments).where(mentor_comments.c.id == comment_id))
    if not row or row.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego komentarza.")
    thread = await C.one(select(mentor_threads).where(mentor_threads.c.id == row["thread_id"]))
    ctx = await C.pair_context(thread["pair_id"], actor)
    C.check(ctx, "edit", owner=R.s(row.get("author_id")) == actor.judge_id)
    return ctx, row, thread


@router.patch("/comments/{comment_id}")
async def update_comment(comment_id: str, body: CommentPatch, actor: Actor = Depends(mentor_actor)):
    ctx, row, thread = await _comment_ctx(comment_id, actor)
    values = _comment_values(ctx, body, partial=True)
    values["edited_at"] = C.now()
    await database.execute(update(mentor_comments).where(mentor_comments.c.id == comment_id).values(**values))
    await C.touch(ctx, actor.judge_id, "comment_updated", "threads", thread.get("match_id"), {"id": comment_id})
    fresh = await C.one(select(mentor_comments).where(mentor_comments.c.id == comment_id))
    return C.comment_shape(ctx, fresh, await C.people([fresh.get("author_id"), fresh.get("acted_by")]))


@router.delete("/comments/{comment_id}")
async def delete_comment(comment_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, _row, thread = await _comment_ctx(comment_id, actor)
    await database.execute(update(mentor_comments).where(mentor_comments.c.id == comment_id).values(deleted_at=C.now()))
    await C.touch(ctx, actor.judge_id, "comment_deleted", "threads", thread.get("match_id"), {"id": comment_id})
    return {"ok": True}


@router.delete("/threads/{thread_id}")
async def delete_thread(thread_id: str, actor: Actor = Depends(mentor_actor)):
    """Usunięcie całego wątku - tylko autor wątku albo administrator. Razem z odpowiedziami."""
    ctx, row = await _ctx_for(mentor_threads, thread_id, actor, missing="Nie ma takiego wątku.")
    C.check(ctx, "edit", owner=R.s(row.get("created_by")) == actor.judge_id)
    await database.execute(mentor_comments.delete().where(mentor_comments.c.thread_id == thread_id))
    await database.execute(mentor_threads.delete().where(mentor_threads.c.id == thread_id))
    await C.touch(ctx, actor.judge_id, "thread_deleted", "threads", row.get("match_id"), {"id": thread_id})
    return {"ok": True}


# ─── Publiczne linki ────────────────────────────────────────────────────────

PUBLISHABLE = {"clip": mentor_clips, "compilation": mentor_compilations, "report": mentor_reports}
YOUTH_WARNING = "To mecz młodzieżowy - upewnij się, że publiczny link nie narusza wizerunku niepełnoletnich zawodników."


async def _youth(ctx: Dict[str, Any], kind: str, row: Dict[str, Any]) -> bool:
    match_ids: List[str] = []
    if kind == "clip":
        match_ids = [row["match_id"]]
    elif kind == "compilation":
        items = await _items(row["id"])
        clips = await _live_clips(ctx["pair_id"], [i["clip_id"] for i in items])
        match_ids = sorted({c["match_id"] for c in clips.values()})
    if not match_ids:
        return False
    cards = {c["match_id"]: c for c in await C.pair_match_cards(ctx["judge_ids"])}
    return any(R.is_youth(cards.get(m, {}).get("category"), cards.get(m, {}).get("competition_name")) for m in match_ids)


async def publish(kind: str, row_id: str, actor: Actor, *, on: bool) -> Dict[str, Any]:
    table = PUBLISHABLE[kind]
    ctx, row = await _ctx_for(table, row_id, actor, action="publish", missing="Nie znaleziono.")
    if on:
        token = row.get("public_token") or R.public_token()
        await database.execute(update(table).where(table.c.id == row_id).values(public_token=token, published_at=row.get("published_at") or C.now()))
    else:
        token = None
        await database.execute(update(table).where(table.c.id == row_id).values(public_token=None, published_at=None))
    await C.touch(ctx, actor.judge_id, "published" if on else "unpublished", {"clip": "clips", "compilation": "compilations",
                                                                              "report": "reports"}[kind],
                  row.get("match_id"), {"kind": kind, "id": row_id})
    youth = on and await _youth(ctx, kind, row)
    return {"public_url": R.public_url(kind, token), "youth_warning": youth, "warning": YOUTH_WARNING if youth else None}


@router.post("/clips/{clip_id}/publish")
async def publish_clip(clip_id: str, actor: Actor = Depends(mentor_actor)):
    return await publish("clip", clip_id, actor, on=True)


@router.delete("/clips/{clip_id}/publish")
async def unpublish_clip(clip_id: str, actor: Actor = Depends(mentor_actor)):
    return await publish("clip", clip_id, actor, on=False)


@router.post("/compilations/{compilation_id}/publish")
async def publish_compilation(compilation_id: str, actor: Actor = Depends(mentor_actor)):
    return await publish("compilation", compilation_id, actor, on=True)


@router.delete("/compilations/{compilation_id}/publish")
async def unpublish_compilation(compilation_id: str, actor: Actor = Depends(mentor_actor)):
    return await publish("compilation", compilation_id, actor, on=False)


async def _public_pair(pair_id: str) -> Dict[str, Any]:
    pair = await C.one(select(mentoring_pairs).where(mentoring_pairs.c.id == pair_id)) or {}
    return {"judge_ids": [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]}


async def _public_clip(clip: Dict[str, Any], cards: Dict[str, Dict[str, Any]], categories: List[Dict[str, Any]]) -> Dict[str, Any]:
    from app.mentor_panel_media import public_video

    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == clip["video_id"]))
    return R.public_clip(clip, video=await public_video(video) if video else None, match=cards.get(clip["match_id"]),
                         categories=categories)


@router.get("/public/{token}")
async def public_view(token: str):
    """Publiczny odczyt (bez logowania): klip, zestawienie albo raport - bez nazwisk zawodników i arkuszy."""
    token = R.s(token)[:64]
    if len(token) < 10:
        raise C.err(404, "NOT_FOUND", "Ten link nie istnieje albo został wyłączony.")
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.public_token == token).where(mentor_clips.c.deleted_at.is_(None)))
    if clip:
        pair = await _public_pair(clip["pair_id"])
        cards = {c["match_id"]: c for c in await C.pair_match_cards(pair["judge_ids"])}
        cats = await C.rows(select(mentor_categories).where((mentor_categories.c.pair_id == clip["pair_id"]) | mentor_categories.c.pair_id.is_(None)))
        return {"kind": "clip", **await _public_clip(clip, cards, cats)}
    comp = await C.one(select(mentor_compilations).where(mentor_compilations.c.public_token == token))
    if comp:
        pair = await _public_pair(comp["pair_id"])
        cards = {c["match_id"]: c for c in await C.pair_match_cards(pair["judge_ids"])}
        cats = await C.rows(select(mentor_categories).where((mentor_categories.c.pair_id == comp["pair_id"]) | mentor_categories.c.pair_id.is_(None)))
        items = await _items(comp["id"])
        clips = await _live_clips(comp["pair_id"], [i["clip_id"] for i in items])
        out_items = []
        for i in items:
            if i["clip_id"] in clips:
                out_items.append({"clip": await _public_clip(clips[i["clip_id"]], cards, cats), "column": i.get("column"),
                                  "note": R.strip_player_names(i.get("note")) or None,
                                  "label": R.strip_player_names(R.legacy_label(i, comp.get("mode") or "free")) or None,
                                  "position": len(out_items)})
        return {"kind": "compilation", "id": comp["id"], "name": comp.get("name"), "mode": comp.get("mode"),
                "description": comp.get("description"), "items": out_items}
    report = await C.one(select(mentor_reports).where(mentor_reports.c.public_token == token))
    if report:
        snapshot = R.json_value(report.get("snapshot_json"), {})
        return {"kind": "report", "id": report["id"], **R.public_report(snapshot),
                "pdf_url": f"/mentor-panel/public/{token}/pdf"}
    raise C.err(404, "NOT_FOUND", "Ten link nie istnieje albo został wyłączony.")
