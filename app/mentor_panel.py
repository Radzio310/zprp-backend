"""
Panel „Mentor" pary sędziowskiej - API (prefiks `/mentor-panel`).

Kontrakt (JEDYNE źródło kształtów): `docs/mentor-panel.md`. Moduły:
  - `mentor_panel_auth`     logowanie web (QR, login ZPRP), sesja + CSRF, `mentor_actor`,
  - tutaj                   pary, pulpit, mecze, pokój meczu, flagi, arkusze, zmiany na żywo,
  - `mentor_panel_library`  kategorie, klipy, zestawienia, wątki, publiczne linki,
  - `mentor_panel_media`    wideo, wgrywanie do R2, kolejka ffmpeg, MP4 klipów, retencja,
  - `mentor_panel_reports`  raporty (podgląd A4 + PDF),
  - `mentor_panel_core`     wspólne zaplecze, `mentor_panel_rules` czyste reguły.

Każdy zapis podbija `mentor_panels.rev` i zwraca świeży obiekt.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import (
    database,
    mentor_clips,
    mentor_comments,
    mentor_compilations,
    mentor_evaluation_versions,
    mentor_match_flags,
    mentor_match_videos,
    mentor_panels,
    mentor_reads,
    mentor_threads,
    mentoring_assignments,
    mentoring_pairs,
)
from app.mentor_panel_auth import mentor_actor, router as auth_router

router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor


# ─── Pary ───────────────────────────────────────────────────────────────────


async def accessible_pairs(actor: Actor) -> List[Dict[str, Any]]:
    """Pary, do których pytający ma dostęp, z rolą (para / mentor / admin / komisja)."""
    pairs = await C.rows(select(mentoring_pairs))
    links = await C.rows(select(mentoring_assignments))
    by_pair: Dict[str, List[Dict[str, Any]]] = {}
    for link in links:
        by_pair.setdefault(link["pair_id"], []).append(link)
    rule_actor = actor.as_rule_actor()
    configs: Dict[str, Dict[str, Any]] = {}
    out = []
    for pair in pairs:
        pair["judge_ids"] = [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]
        pair["province"] = C.canonical_province(pair.get("province"))
        mine = actor.judge_id in pair["judge_ids"]
        if pair.get("ended_at") is not None and not mine:
            continue
        role = R.role_in_pair(rule_actor, pair, by_pair.get(pair["id"], []), None)
        if role is None and not (actor.province and pair["province"] == actor.province):
            continue
        pair["program"] = await C.pair_program(pair)
        if role is None:
            if pair["province"] not in configs:
                configs[pair["province"]] = await C.mentoring_config(pair["province"])
            role = R.role_in_pair(rule_actor, pair, by_pair.get(pair["id"], []), configs[pair["province"]])
        if role is None:
            continue
        if role == "admin" and pair.get("ended_at") is not None:
            continue
        pair["role"] = role
        pair["mentor_ids"] = [R.s(l["mentor_id"]) for l in by_pair.get(pair["id"], []) if l.get("ended_at") is None]
        out.append(pair)
    return out


async def _unread(pair_id: str, me: str) -> int:
    read = await C.one(select(mentor_reads).where(mentor_reads.c.pair_id == pair_id).where(mentor_reads.c.judge_id == me))
    seen = (read or {}).get("seen_at")
    items: List[Dict[str, Any]] = []
    for table, author in ((mentor_clips, mentor_clips.c.author_id), (mentor_threads, mentor_threads.c.created_by)):
        query = select(author.label("author_id"), table.c.created_at).where(table.c.pair_id == pair_id)
        if seen is not None:
            query = query.where(table.c.created_at > seen)
        items += await C.rows(query.limit(200))
    query = (select(mentor_comments.c.author_id, mentor_comments.c.created_at)
             .select_from(mentor_comments.join(mentor_threads, mentor_threads.c.id == mentor_comments.c.thread_id))
             .where(mentor_threads.c.pair_id == pair_id).where(mentor_comments.c.deleted_at.is_(None)))
    if seen is not None:
        query = query.where(mentor_comments.c.created_at > seen)
    items += await C.rows(query.limit(200))
    return R.unread_count(items, me, seen)


async def _dots(pair: Dict[str, Any], me: str) -> Dict[str, int]:
    """Kropki nowości: wątki z cudzymi odpowiedziami i nowe oceny mentorów (dla sędziów pary)."""
    key = "|".join(sorted(R.s(j) for j in pair["judge_ids"]))
    return {"unread_threads": len(await C.unread_threads(pair["id"], me)),
            "new_sheets": len(await C.unseen_sheets(key, me)) if me in pair["judge_ids"] else 0}


@router.get("/pairs")
async def list_pairs(actor: Actor = Depends(mentor_actor)):
    pairs = await accessible_pairs(actor)
    ids = [p["id"] for p in pairs]
    panels = {r["pair_id"]: r for r in await C.rows(select(mentor_panels).where(mentor_panels.c.pair_id.in_(ids)))} if ids else {}
    names = await C.people({j for p in pairs for j in [*p["judge_ids"], *p["mentor_ids"]]})
    counts: Dict[str, Dict[str, int]] = {pid: {"clips": 0, "open_threads": 0, "to_discuss": 0} for pid in ids}
    if ids:
        for key, query in (
            ("clips", select(mentor_clips.c.pair_id, func.count().label("n")).where(mentor_clips.c.pair_id.in_(ids))
             .where(mentor_clips.c.deleted_at.is_(None)).group_by(mentor_clips.c.pair_id)),
            ("open_threads", select(mentor_threads.c.pair_id, func.count().label("n")).where(mentor_threads.c.pair_id.in_(ids))
             .where(mentor_threads.c.status == "open").group_by(mentor_threads.c.pair_id)),
            ("to_discuss", select(mentor_match_flags.c.pair_id, func.count().label("n")).where(mentor_match_flags.c.pair_id.in_(ids))
             .where(mentor_match_flags.c.submitted.is_(True)).where(mentor_match_flags.c.review_status == "open")
             .group_by(mentor_match_flags.c.pair_id)),
        ):
            for row in await C.rows(query):
                counts[row["pair_id"]][key] = int(row["n"] or 0)
    now = C.now()

    async def build(pair: Dict[str, Any]) -> Dict[str, Any]:
        enabled = bool((panels.get(pair["id"]) or {}).get("enabled"))
        live = enabled and pair["role"] in ("pair", "mentor")

        async def nothing() -> int:
            return 0

        async def no_dots() -> Dict[str, int]:
            return {"unread_threads": 0, "new_sheets": 0}

        matches, unread, dots = await asyncio.gather(
            C.pair_match_cards(pair["judge_ids"]),
            _unread(pair["id"], actor.judge_id) if live else nothing(),
            _dots(pair, actor.judge_id) if live else no_dots())
        nxt, _last = R.next_and_last(matches, now)
        base = C.pair_people_shape(pair, pair["mentor_ids"], names)
        return {
            **base,
            "enabled": enabled,
            "role": pair["role"],
            "unread": unread,
            **dots,
            "next_match": R.public_match(nxt) if nxt else None,
            "counts": {"matches": len(matches), **counts[pair["id"]]},
            "links": C.links_of(pair["id"]),
        }

    # Pary niezależne od siebie: karty liczone równolegle, w ograniczonej paczce (pula połączeń).
    gate = asyncio.Semaphore(4)

    async def limited(pair: Dict[str, Any]) -> Dict[str, Any]:
        async with gate:
            return await build(pair)

    cards = list(await asyncio.gather(*(limited(p) for p in pairs)))
    order = {"pair": 0, "mentor": 1, "committee": 2, "admin": 3}
    cards.sort(key=lambda c: (not c["enabled"], order.get(c["role"], 9), " ".join(j["full_name"] for j in c["judges"])))
    return {"pairs": cards, "me": actor.me()}


class PanelBody(BaseModel):
    enabled: bool


def panel_state(panel: Dict[str, Any]) -> Dict[str, Any]:
    return {"pair_id": panel.get("pair_id"), "enabled": bool(panel.get("enabled")), "enabled_by": panel.get("enabled_by"),
            "enabled_at": panel.get("enabled_at"), "rev": int(panel.get("rev") or 0)}


@router.patch("/pairs/{pair_id}/panel")
async def toggle_panel(pair_id: str, body: PanelBody, actor: Actor = Depends(mentor_actor)):
    """Admin (wszystkie pary) i komisja okręgu (pary okręgowe swojego okręgu)."""
    ctx = await C.pair_context(pair_id, actor, action="toggle")
    stamp = C.now()
    values: Dict[str, Any] = {"enabled": body.enabled, "updated_at": stamp}
    if body.enabled and not ctx["enabled"]:
        values.update(enabled_by=actor.judge_id, enabled_at=stamp)
    await database.execute(update(mentor_panels).where(mentor_panels.c.pair_id == ctx["pair_id"]).values(**values))
    await C.touch(ctx, actor.judge_id, "panel_enabled" if body.enabled else "panel_disabled", "panel")
    return panel_state(await C.ensure_panel(ctx["pair_id"]))


@router.get("/pairs/{pair_id}")
async def dashboard(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    raw_cards = await C.pair_match_cards(ctx["judge_ids"])
    raw_ids = [c["match_id"] for c in raw_cards]
    from app.mentor_panel_library import compilation_summaries

    async def load_clips():
        found = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == ctx["pair_id"])
                             .where(mentor_clips.c.deleted_at.is_(None)).order_by(mentor_clips.c.created_at.desc()).limit(8))
        return await C.clips_payload(ctx, found)

    async def load_threads():
        found = await C.rows(select(mentor_threads).where(mentor_threads.c.pair_id == ctx["pair_id"])
                             .where(mentor_threads.c.status == "open")
                             .order_by(func.coalesce(mentor_threads.c.last_comment_at, mentor_threads.c.created_at).desc()).limit(8))
        return await C.threads_payload(ctx, found, with_comments=False)

    async def load_compilations():
        found = await C.rows(select(mentor_compilations).where(mentor_compilations.c.pair_id == ctx["pair_id"])
                             .order_by(mentor_compilations.c.updated_at.desc()).limit(6))
        return await compilation_summaries(ctx, found)

    # Niezależne odczyty pulpitu równolegle (wcześniej szły jeden po drugim).
    cards, names, new_clips, open_threads, compilations, delegate, mentor, dots = await asyncio.gather(
        C.enrich_cards(ctx, raw_cards),
        C.people([*ctx["judge_ids"], *ctx["mentor_ids"]]),
        load_clips(), load_threads(), load_compilations(),
        C.delegate_sheet_rows(ctx["judge_ids"], raw_ids),
        C.mentor_sheet_rows(ctx["pair_key"]),
        _dots(ctx["pair"], actor.judge_id))
    nxt, last = R.next_and_last(cards, C.now())
    d_rows = [{"date": r.get("match_date"), "points": R.sheet_points(R.json_value(r.get("evaluation_json"), {}))} for r in delegate]
    m_rows = [{"date": r.get("match_at"), "points": r.get("points")} for r in mentor]
    d_trend, m_trend = R.points_trend(d_rows), R.points_trend(m_rows)
    await C.mark_read(ctx)

    return {
        "pair": C.pair_people_shape(ctx["pair"], ctx["mentor_ids"], names),
        "mentors": C.pair_people_shape(ctx["pair"], ctx["mentor_ids"], names)["mentors"],
        "role": ctx["role"], "enabled": ctx["enabled"], "rev": ctx["rev"], "me": actor.me(),
        **dots,
        "can": {action: C.may(ctx, action) for action in ("flag", "video", "create", "categories", "publish", "toggle")},
        "next_match": nxt, "last_match": last,
        "to_discuss": [c for c in cards if c.get("submitted") and c.get("review_status") == "open"],
        "starred_recent": [c for c in cards if c.get("starred")][:6],
        "new_clips": new_clips,
        "open_threads": open_threads,
        "compilations": compilations,
        "sheets_summary": {
            "delegate": {"count": len(delegate), "last_points": d_trend[-1]["points"] if d_trend else None, "trend": d_trend},
            "mentor": {"count": len(mentor), "last_points": m_trend[-1]["points"] if m_trend else None},
        },
        "seasons": R.seasons_of(cards),
        "links": C.links_of(ctx["pair_id"]),
    }


# ─── Mecze ──────────────────────────────────────────────────────────────────


def _tristate(value: Optional[str]) -> Optional[bool]:
    if value in (None, ""):
        return None
    return str(value).lower() in ("1", "true", "tak", "yes")


@router.get("/pairs/{pair_id}/matches")
async def matches(pair_id: str, season: str = Query("", max_length=20), starred: Optional[str] = Query(None),
                  submitted: Optional[str] = Query(None), q: str = Query("", max_length=80),
                  actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    cards = await C.enriched_pair_cards(ctx)
    return {
        "matches": R.filter_cards(cards, season=season, starred=_tristate(starred), submitted=_tristate(submitted), q=q),
        "seasons": R.seasons_of(cards),
        "rev": ctx["rev"],
    }


def delegate_sheet_shape(row: Dict[str, Any]) -> Dict[str, Any]:
    evaluation = R.json_value(row.get("evaluation_json"), {})
    return {
        "id": str(row.get("id")), "match_id": row.get("match_id"), "season": row.get("season"),
        "match_number": row.get("match_number"), "match_date": row.get("match_date"),
        "delegate_name": row.get("delegate_name"), "points": R.sheet_points(evaluation), "evaluation": evaluation,
    }


async def mentor_sheet_shapes(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    from app.mentor_evaluation_rules import delegate_shape, json_list

    ids = {a for r in rows for a in [r.get("author_id"), *json_list(r.get("co_author_ids"))] if a}
    names = await C.people(ids)
    versions: Dict[str, List[Dict[str, Any]]] = {}
    if rows:
        for v in await C.rows(select(mentor_evaluation_versions.c.evaluation_id, mentor_evaluation_versions.c.saved_at,
                                     mentor_evaluation_versions.c.points, mentor_evaluation_versions.c.letter,
                                     mentor_evaluation_versions.c.saved_by)
                              .where(mentor_evaluation_versions.c.evaluation_id.in_([r["id"] for r in rows]))
                              .order_by(mentor_evaluation_versions.c.saved_at.asc())):
            versions.setdefault(v["evaluation_id"], []).append(
                {"saved_at": v.get("saved_at"), "points": v.get("points"), "letter": v.get("letter"), "saved_by": v.get("saved_by")})
    out = []
    for r in rows:
        authors = [r.get("author_id"), *json_list(r.get("co_author_ids"))]
        out.append({
            "id": r["id"], "match_id": r.get("match_id"), "season": r.get("season"), "match_number": r.get("match_number"),
            "match_at": r.get("match_at"), "authors": [C.person(names, a) for a in authors if a],
            "points": r.get("points"), "letter": r.get("letter"), "published_at": r.get("published_at"),
            "sheet": delegate_shape(R.json_value(r.get("published_json"), {})),
            "versions": versions.get(r["id"], []),
        })
    return out


async def _timeline(match_id: str, code: str) -> Dict[str, Any]:
    empty = {"available": False, "half_minutes": 30, "break_minutes": 10, "teams": {}, "events": []}
    try:
        from app.mentor_evaluations import timeline_for_match

        found = await timeline_for_match(match_id, code)
    except Exception:  # noqa: BLE001 - brak osi nie psuje pokoju meczu
        C.logger.warning("mentor: oś meczu nieczytelna", exc_info=True)
        return empty
    # Bez nazwisk zawodników w etykietach? Zostają - to widok pary i mentorów, nie publiczny.
    return found


@router.get("/pairs/{pair_id}/matches/{match_id}")
async def match_room(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    card = await C.match_card(ctx, match_id)
    from app.mentor_panel_media import video_list
    from app.mentor_panel_streams import room_streams
    from app.mentor_video_trash import trash_payload
    from app.mentor_video_rules import clean_markers

    mid = card["match_id"]

    async def load_videos():
        videos, raw = await video_list(ctx, mid)
        # Podpowiedzi transmisji potrzebują nagrań, ale nie blokują reszty pokoju.
        return videos, raw, await room_streams(ctx, card, raw)

    async def load_clips():
        found = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == ctx["pair_id"])
                             .where(mentor_clips.c.match_id == mid).where(mentor_clips.c.deleted_at.is_(None))
                             .order_by(mentor_clips.c.start_s.asc()))
        # Klipy z MP4 po usuniętym nagraniu zostają w Bibliotece, nie w pokoju tego meczu.
        gone = {r["id"] for r in await C.rows(select(mentor_match_videos.c.id).where(mentor_match_videos.c.match_id == mid)
                                              .where(mentor_match_videos.c.deleted_at.is_not(None)))}
        return await C.clips_payload(ctx, [c for c in found if c.get("video_id") not in gone])

    async def load_delegate():
        return [r for r in await C.delegate_sheet_rows(ctx["judge_ids"], [mid]) if R.s(r.get("match_id")) == mid]

    async def load_mentor():
        found = [r for r in await C.mentor_sheet_rows(ctx["pair_key"]) if R.s(r.get("match_id")) == mid]
        return await mentor_sheet_shapes(found)

    async def load_threads():
        found = await C.rows(select(mentor_threads).where(mentor_threads.c.pair_id == ctx["pair_id"])
                             .where(mentor_threads.c.match_id == mid).order_by(mentor_threads.c.created_at.asc()))
        return await C.threads_payload(ctx, found)

    # Niezależne odczyty pokoju (w tym oś ProEla) równolegle zamiast kolejno.
    (videos, raw_videos, streams), clips, delegate, mentor_shapes, threads, timeline = await asyncio.gather(
        load_videos(), load_clips(), load_delegate(), load_mentor(), load_threads(),
        _timeline(mid, R.s(card.get("match_code"))))
    markers: List[Dict[str, Any]] = []
    for video in raw_videos:
        markers += R.markers_as_clips(video, clean_markers(R.json_value(video.get("markers_json"), [])))
    if markers:
        # Znacznik, którego klip usunięto, to nagrobek - nie wraca na oś ani do licznika „Klipy”.
        gone = await C.rows(select(mentor_clips.c.video_id, mentor_clips.c.source_key).where(mentor_clips.c.pair_id == ctx["pair_id"])
                            .where(mentor_clips.c.match_id == mid).where(mentor_clips.c.source == "marker")
                            .where(mentor_clips.c.deleted_at.is_not(None)))
        live_keys = {R.marker_clip_key(c.get("video_id"), c.get("source_key")) for c in clips if c.get("source") == "marker"}
        dead = [R.marker_clip_key(r.get("video_id"), r.get("source_key")) for r in gone if r.get("source_key")]
        markers = R.unclaimed_marker_clips(markers, [k for k in dead if k not in live_keys])
    if markers:
        # Autor znacznika w wierszu osi (kategoria raz + czas + autor).
        marker_names = await C.people({m.get("author_id") for m in markers if m.get("author_id")})
        for m in markers:
            if m.get("author_id"):
                m["author"] = C.person(marker_names, m["author_id"])
    situations: List[Dict[str, Any]] = []
    for r in delegate:
        situations += R.situations_from_sheet(R.json_value(r.get("evaluation_json"), {}), "delegate", r.get("delegate_name"))
    for m in mentor_shapes:
        situations += R.situations_from_sheet(m["sheet"], "mentor", " + ".join(a["name"] for a in m["authors"]))
    return {
        "match": card, "videos": videos, "clips": clips, "markers_from_app": markers,
        "timeline": timeline,
        "sheet_situations": situations,
        "delegate_sheets": [delegate_sheet_shape(r) for r in delegate], "mentor_sheets": mentor_shapes,
        "threads": threads, "rev": ctx["rev"],
        "can": {action: C.may(ctx, action) for action in ("flag", "video", "create", "categories", "publish")},
        "trashed_videos": await trash_payload(ctx, mid),
        "suggested_streams": streams["streams"],
        "stream_search": streams["search"],
    }


class FlagBody(BaseModel):
    starred: Optional[bool] = None
    star_reason: Optional[str] = Field(default=None, max_length=400)
    submitted: Optional[bool] = None
    due_at: Optional[str] = Field(default=None, max_length=40)
    review_status: Optional[str] = Field(default=None, max_length=20)
    note: Optional[str] = Field(default=None, max_length=2000)


# ─── Ocena mentora z przeglądarki (nakładki na `mentor_evaluations`) ────────


class EvaluationBody(BaseModel):
    sheet: Dict[str, Any] = Field(default_factory=dict)
    together: bool = False
    co_author_id: Optional[str] = Field(default=None, max_length=40)


def _evaluation_actor(actor: Actor):
    """Aktor sesji panelu w kształcie, którego oczekuje `mentor_evaluations` (z `acted_by` przy act_as)."""
    from app.mentor_evaluations import Actor as MarketActor

    row = {"province": actor.province, "full_name": actor.display_name, "photo_url": actor.photo_url, "badges": actor.badges}
    out = MarketActor({"judge_id": actor.judge_id}, row, actor.is_admin)
    out.acted_by, out.acted_by_name = actor.acted_by, actor.acted_by_name
    return out


async def _evaluation_ctx(pair_id: str, match_id: str, actor: Actor, action: str) -> str:
    ctx = await C.pair_context(pair_id, actor, action=action)
    return (await C.match_card(ctx, match_id))["match_id"]


@router.get("/pairs/{pair_id}/matches/{match_id}/evaluation")
async def match_evaluation(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    from app import mentor_evaluations as ME

    real_id = await _evaluation_ctx(pair_id, match_id, actor, "view")
    return await ME.for_match(real_id, _evaluation_actor(actor))


@router.put("/pairs/{pair_id}/matches/{match_id}/evaluation")
async def save_match_evaluation(pair_id: str, match_id: str, body: "EvaluationBody", actor: Actor = Depends(mentor_actor)):
    from app import mentor_evaluations as ME

    real_id = await _evaluation_ctx(pair_id, match_id, actor, "create")
    return await ME.save(real_id, ME.SaveRequest(**body.model_dump()), _evaluation_actor(actor), publish=False)


@router.post("/pairs/{pair_id}/matches/{match_id}/evaluation/publish")
async def publish_match_evaluation(pair_id: str, match_id: str, body: "EvaluationBody", actor: Actor = Depends(mentor_actor)):
    from app import mentor_evaluations as ME

    real_id = await _evaluation_ctx(pair_id, match_id, actor, "create")
    return await ME.save(real_id, ME.SaveRequest(**body.model_dump()), _evaluation_actor(actor), publish=True)


@router.post("/pairs/{pair_id}/matches/{match_id}/sheet/seen")
async def sheet_seen(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    """Oznacza wysłane oceny mentora z tego meczu jako obejrzane przeze mnie (gasi kropkę)."""
    ctx = await C.pair_context(pair_id, actor)
    return {"ok": True, "marked": await C.mark_sheets_seen(ctx["pair_key"], match_id, actor.judge_id)}


@router.put("/pairs/{pair_id}/matches/{match_id}/flag")
async def set_flag(pair_id: str, match_id: str, body: FlagBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="flag")
    card = await C.match_card(ctx, match_id)
    current = await C.one(select(mentor_match_flags).where(mentor_match_flags.c.pair_id == ctx["pair_id"])
                          .where(mentor_match_flags.c.match_id == card["match_id"]))
    try:
        row, newly = R.apply_flag(current, body.model_dump(exclude_unset=True), actor.judge_id, C.now())
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    columns = {c.name for c in mentor_match_flags.columns} - {"pair_id", "match_id"}
    values = {k: v for k, v in row.items() if k in columns}
    if current:
        await database.execute(update(mentor_match_flags).where(mentor_match_flags.c.pair_id == ctx["pair_id"])
                               .where(mentor_match_flags.c.match_id == card["match_id"]).values(**values))
    else:
        await database.execute(mentor_match_flags.insert().values(pair_id=ctx["pair_id"], match_id=card["match_id"], **values))
    await C.touch(ctx, actor.judge_id, "flag", "matches", card["match_id"], body.model_dump(exclude_unset=True))
    if newly:
        from app.mentor_panel_notify import notify

        from_pair = actor.judge_id in ctx["judge_ids"]
        targets = ctx["mentor_ids"] if from_pair else ctx["judge_ids"]
        teams = " - ".join(x for x in ((card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")) if x)
        await notify(ctx, actor.judge_id, "Mecz do omówienia",
                     f"{actor.display_name} zgłasza mecz {card.get('match_code') or ''} {teams}".strip(),
                     recipients=[t for t in targets if t != actor.judge_id], match_id=card["match_id"],
                     link=f"{C.WEB_BASE}/{ctx['pair_id']}/mecz/{card['match_id']}")
    return (await C.enrich_cards(ctx, [dict(card)]))[0]


# ─── Arkusze ────────────────────────────────────────────────────────────────


@router.get("/pairs/{pair_id}/sheets")
async def sheets(pair_id: str, season: str = Query("", max_length=20), actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="sheets")
    cards = await C.pair_match_cards(ctx["judge_ids"])
    seasons = {c["match_id"]: c.get("season") for c in cards}
    delegate = await C.delegate_sheet_rows(ctx["judge_ids"], list(seasons))
    mentor = await C.mentor_sheet_rows(ctx["pair_key"])

    def keep(row: Dict[str, Any]) -> bool:
        if not season:
            return True
        found = seasons.get(R.s(row.get("match_id"))) or R.s(row.get("season")) or R.season_key(R.aware(row.get("match_at")))
        return found == season

    delegate = [r for r in delegate if keep(r)]
    mentor = [r for r in mentor if keep(r)]
    delegate.sort(key=lambda r: R._date_text(r.get("match_date")), reverse=True)
    mentor.sort(key=lambda r: R._date_text(r.get("match_at")), reverse=True)
    mentor_shapes = await mentor_sheet_shapes(mentor)
    trend = R.trends(
        [{"match_id": r.get("match_id"), "date": r.get("match_date"), "evaluation": R.json_value(r.get("evaluation_json"), {})} for r in delegate],
        [{"match_id": m["match_id"], "date": m["match_at"], "evaluation": m["sheet"], "points": m["points"]} for m in mentor_shapes],
    )
    return {"delegate": [delegate_sheet_shape(r) for r in delegate], "mentor": mentor_shapes, "trends": trend}


# ─── Zmiany na żywo i obecność ──────────────────────────────────────────────

ALL_SCOPES = ["matches", "clips", "threads", "compilations", "sheets", "videos", "categories", "reports", "panel"]


@router.get("/pairs/{pair_id}/changes")
async def changes(pair_id: str, since: int = Query(0, ge=0), wait: int = Query(25, ge=0, le=C.MAX_WAIT_S),
                  actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    rev = await C.wait_for_change(ctx["pair_id"], since, wait)
    out = {"rev": rev, "changed": False, "scopes": [], "match_ids": [], "viewers": C.viewers(ctx["pair_id"], actor.judge_id)}
    if since > rev:
        out.update(changed=True, scopes=list(ALL_SCOPES))
    elif rev > since:
        out.update(changed=True, **await C.changes_since(ctx["pair_id"], since))
    return out


class PresenceBody(BaseModel):
    where: str = Field(default="dashboard", max_length=80)


@router.post("/pairs/{pair_id}/presence")
async def presence(pair_id: str, body: PresenceBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    C.set_presence(ctx["pair_id"], actor, R.clean_where(body.where))
    return {"ok": True, "viewers": C.viewers(ctx["pair_id"], actor.judge_id)}


# ─── Montaż ─────────────────────────────────────────────────────────────────


def _assemble() -> APIRouter:
    from app.mentor_bastion import router as bastion_router
    from app.mentor_panel_handoff import router as handoff_router
    from app.mentor_panel_library import router as library_router
    from app.mentor_panel_media import router as media_router
    from app.mentor_panel_reports import router as reports_router
    from app.mentor_panel_streams import router as streams_router

    combined = APIRouter()
    for part in (auth_router, router, library_router, media_router, reports_router, handoff_router, streams_router, bastion_router):
        combined.include_router(part)
    return combined


panel_router = _assemble()


async def panel_enabled_map(pair_ids: List[str]) -> Dict[str, bool]:
    """Dla `GET /mentoring/management` (przełącznik w zakładce Mentoring aplikacji)."""
    if not pair_ids:
        return {}
    found = await C.rows(select(mentor_panels.c.pair_id, mentor_panels.c.enabled).where(mentor_panels.c.pair_id.in_(pair_ids)))
    return {r["pair_id"]: bool(r.get("enabled")) for r in found}

