"""Panel „Mentor" - „Szukaj moich meczów na kanale YouTube” (18.11.2026, Ustawienia pary; kontrakt `docs/mentor-panel.md` 16).

Para dodaje kanał (link albo @uchwyt). Na żądanie („Przejrzyj kanał”) serwer czyta filmy kanału i dla każdego szuka meczu
WŚRÓD MECZÓW PARY po tytule (data, drużyny, numer - `app/mentor_channel_rules.py`). Przegląd w Ustawieniach pokazuje
propozycje z pewnością i powodami; „Dodaj wszystkie pewne” albo wybór ręczny podpina filmy jako nagrania meczów.
Mecz w dwóch filmach (I i II połowa): obie części pobieramy z YouTube na serwer i SKLEJAMY w jedno nagranie - tym samym
mechanizmem co wgrywanie kilku plików (`app/mentor_upload_groups.py`): wiersze `mentor_uploads` z `origin='youtube_part'`
czekają na worker tego modułu (pobranie yt-dlp jak „kopia na serwer”), a komplet trafia do kolejki sklejania.

Czytanie kanału: z kluczem `YOUTUBE_API_KEY` pełna lista (playlist „uploads”, do 1000 filmów, limit dobowy wspólny z
transmisjami); bez klucza - strona kanału (ostatnie ~30 filmów), co przegląd mówi wprost (`scan_complete`).
Trasy (prefiks `/mentor-panel`):
  - `GET    /pairs/{p}/channels`                     kanały pary z licznikami,
  - `POST   /pairs/{p}/channels {url}`               dodaj kanał i od razu przejrzyj (akcja `video`),
  - `GET    /channels/{id}`                          kanał + filmy z propozycjami (karty meczów),
  - `POST   /channels/{id}/scan`                     przejrzyj ponownie (decyzje zostają),
  - `POST   /channels/{id}/accept {video_ids, matches?}`  dodaj wybrane (`matches` = {video_id: match_id} wybór ręczny),
  - `POST   /channels/{id}/dismiss {video_ids, undo?}`    odrzuć / przywróć,
  - `DELETE /channels/{id}`                          usuń kanał (dodane nagrania zostają przy meczach).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, update

from app import mentor_channel_rules as CR
from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app.db import database, mentor_channel_videos, mentor_channels, mentor_match_videos, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

PART_ORIGIN = "youtube_part"
MAX_API_PAGES = 20  # 20 x 50 = 1000 filmów
MAX_CHANNELS = 5
HALF_NAME = {0: "I połowa", 1: "II połowa"}


class ChannelBody(BaseModel):
    url: str = Field(min_length=2, max_length=300)


class AcceptBody(BaseModel):
    video_ids: List[str] = Field(default_factory=list, max_length=500)
    #: Wybór ręczny meczu dla filmu (alternatywa zamiast propozycji).
    matches: Dict[str, str] = Field(default_factory=dict)


class DismissBody(BaseModel):
    video_ids: List[str] = Field(default_factory=list, max_length=500)
    undo: bool = False


# ─── Czytanie kanału ────────────────────────────────────────────────────────


def _texts(node: Any) -> List[str]:
    out: List[str] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            if isinstance(x.get("content"), str):
                out.append(x["content"])
            if isinstance(x.get("text"), dict) and isinstance(x["text"].get("content"), str):
                out.append(x["text"]["content"])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(node)
    return out


def parse_channel_page(html: str) -> Optional[Dict[str, Any]]:
    """Strona `/@kanał/videos` -> {channel_id, title, handle, thumbnail_url, videos: [...], more}. Kafle `lockupViewModel`
    (nowy układ) i `videoRenderer` (stary); `more` = strona ma ciąg dalszy (bez API widać tylko początek listy)."""
    m = re.search(r"var ytInitialData = (\{.*?\});</script>", html, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except ValueError:
        return None
    meta = ((data.get("metadata") or {}).get("channelMetadataRenderer") or {})
    videos: List[Dict[str, Any]] = []
    seen = set()

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            lock = o.get("lockupViewModel")
            if isinstance(lock, dict) and lock.get("contentId"):
                vid = str(lock["contentId"])
                meta_vm = ((lock.get("metadata") or {}).get("lockupMetadataViewModel") or {})
                title = ((meta_vm.get("title") or {}).get("content")) or ""
                length = next((t for t in _texts(lock.get("contentImage") or {}) if re.fullmatch(r"\d+:\d{2}(?::\d{2})?", t or "")), None)
                if vid not in seen and title:
                    seen.add(vid)
                    videos.append({"video_id": vid, "title": title.strip(), "duration_s": CR.iso_seconds(length),
                                   "thumbnail_url": f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg", "published": None})
            old = o.get("videoRenderer") or o.get("gridVideoRenderer")
            if isinstance(old, dict) and old.get("videoId"):
                vid = str(old["videoId"])
                t = old.get("title") or {}
                title = t.get("simpleText") or "".join(r.get("text", "") for r in t.get("runs", []))
                if vid not in seen and title:
                    seen.add(vid)
                    videos.append({"video_id": vid, "title": title.strip(), "duration_s": CR.iso_seconds((old.get("lengthText") or {}).get("simpleText")),
                                   "thumbnail_url": f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg", "published": None})
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    thumbs = ((meta.get("avatar") or {}).get("thumbnails") or [])
    vanity = R.s(meta.get("vanityChannelUrl"))
    return {
        "channel_id": R.s(meta.get("externalId")) or None,
        "title": R.s(meta.get("title")) or None,
        "handle": ("@" + vanity.rsplit("@", 1)[1]) if "@" in vanity else None,
        "thumbnail_url": R.s(thumbs[-1].get("url")) if thumbs else None,
        "videos": videos,
        # Ciąg dalszy siatki: strona daje ~30 filmów naraz; mniej = to cały kanał (ślady kontynuacji bywają i wtedy).
        "more": len(videos) >= 28 and '"continuationItemRenderer"' in m.group(1),
    }


async def read_channel(ref: Mapping[str, str]) -> Dict[str, Any]:
    """Kanał i jego filmy: YouTube Data API (pełna lista) albo strona kanału. Błąd = `C.err` z czytelnym zdaniem."""
    from app.streams import net as N
    from app.streams import parsers as P
    from app.streams import store as S

    yt = N.YouTube(S.quota_take)
    if yt.enabled:
        kind, value = ref["kind"], ref["value"]
        info = await yt.channel(handle=value if kind == "handle" else None, channel_id=value if kind == "id" else None,
                                user=value if kind == "user" else None)
        if info and info.get("uploads"):
            videos: List[Dict[str, Any]] = []
            token: Optional[str] = None
            for _ in range(MAX_API_PAGES):
                params: Dict[str, Any] = {"part": "snippet,contentDetails", "playlistId": info["uploads"], "maxResults": 50}
                if token:
                    params["pageToken"] = token
                data = await yt._get("playlistItems", params)
                if not data:
                    break
                videos.extend(P.parse_api_playlist_items(data))
                token = data.get("nextPageToken")
                if not token:
                    break
            durations = {v["video_id"]: v.get("duration_s") for v in await yt.videos([v["video_id"] for v in videos])}
            for v in videos:
                v["duration_s"] = durations.get(v["video_id"])
            return {"channel_id": info["channel_id"], "title": info.get("title"), "handle": info.get("handle"),
                    "thumbnail_url": None, "videos": videos, "source": "api", "complete": token is None}
    if ref["kind"] == "id":
        url = f"https://www.youtube.com/channel/{ref['value']}/videos"
    elif ref["kind"] == "handle":
        url = f"https://www.youtube.com/{ref['value']}/videos"
    else:
        url = f"https://www.youtube.com/c/{ref['value']}/videos"
    page = await N.fetch_page(url, parse_channel_page, youtube=True)
    if not page:
        raise C.err(502, "CHANNEL_UNREACHABLE", "Nie udało się odczytać kanału - sprawdź link albo spróbuj za chwilę.")
    return {**page, "source": "page", "complete": not page.get("more")}


# ─── Zapis przeglądu ────────────────────────────────────────────────────────


async def _pair_cards(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    return await C.pair_match_cards(ctx["judge_ids"])


async def _known_links(ctx: Dict[str, Any], video_ids: List[str]) -> Dict[str, Tuple[str, str]]:
    """Filmy kanału już podpięte jako nagrania meczów pary: {yt_video_id: (match_id, video_row_id)}."""
    if not video_ids:
        return {}
    rows = await C.rows(select(mentor_match_videos.c.id, mentor_match_videos.c.match_id, mentor_match_videos.c.normalized_url)
                        .where(mentor_match_videos.c.pair_key == ctx["pair_key"]).where(mentor_match_videos.c.deleted_at.is_(None))
                        .where(mentor_match_videos.c.provider == "youtube"))
    wanted = set(video_ids)
    out: Dict[str, Tuple[str, str]] = {}
    for r in rows:
        m = re.search(r"[?&]v=([\w-]{11})|youtu\.be/([\w-]{11})|/(?:live|shorts|embed)/([\w-]{11})", R.s(r.get("normalized_url")))
        vid = next((g for g in (m.groups() if m else ()) if g), None)
        if vid in wanted:
            out[vid] = (R.s(r["match_id"]), R.s(r["id"]))
    return out


async def scan(ctx: Dict[str, Any], channel: Dict[str, Any]) -> Dict[str, Any]:
    """Przegląd kanału: filmy -> propozycje meczów pary. Decyzje (dodane, odrzucone, wybór ręczny) zostają."""
    ref = CR.channel_ref(channel.get("channel_id") or channel.get("handle") or channel["url"]) or CR.channel_ref(channel["url"])
    if not ref:
        raise C.err(422, "CHANNEL_URL", "To nie wygląda na kanał YouTube - wklej link w rodzaju youtube.com/@kanal.")
    try:
        found = await read_channel(ref)
    except Exception as exc:
        message = getattr(exc, "detail", None) or "Nie udało się odczytać kanału."
        await database.execute(update(mentor_channels).where(mentor_channels.c.id == channel["id"])
                               .values(scan_error=str(message.get("message") if isinstance(message, dict) else message)[:300], scanned_at=C.now()))
        raise
    cards = await _pair_cards(ctx)
    known = await _known_links(ctx, [v["video_id"] for v in found["videos"]])
    existing = {r["video_id"]: r for r in await C.rows(select(mentor_channel_videos).where(mentor_channel_videos.c.channel_row_id == channel["id"]))}
    stamp = C.now()
    for i, v in enumerate(found["videos"]):
        prop = CR.propose(v["title"], cards)
        old = existing.get(v["video_id"])
        values = {
            "title": v["title"][:500], "thumbnail_url": v.get("thumbnail_url"), "duration_s": v.get("duration_s"),
            "published_at": v.get("published"), "position": i, "parsed_json": json.dumps(prop["parsed"]),
            "match_id": prop["match_id"], "confidence": prop["confidence"], "reasons_json": json.dumps(prop["reasons"], ensure_ascii=False),
            "alternatives_json": json.dumps(prop["alternatives"], ensure_ascii=False), "updated_at": stamp,
        }
        link = known.get(v["video_id"])
        if old:
            if link and old.get("state") != "added":
                values.update(state="added", added_video_id=link[1])
            await database.execute(update(mentor_channel_videos).where(mentor_channel_videos.c.id == old["id"]).values(**values))
        else:
            await database.execute(mentor_channel_videos.insert().values(
                id=R.new_id(), channel_row_id=channel["id"], pair_id=ctx["pair_id"], video_id=v["video_id"],
                state="added" if link else "new", added_video_id=link[1] if link else None, **values))
    await database.execute(update(mentor_channels).where(mentor_channels.c.id == channel["id"]).values(
        channel_id=found.get("channel_id") or channel.get("channel_id"), handle=found.get("handle") or channel.get("handle"),
        title=found.get("title") or channel.get("title"), thumbnail_url=found.get("thumbnail_url") or channel.get("thumbnail_url"),
        scanned_at=stamp, scan_source=found["source"], scan_complete="1" if found.get("complete") else "0", scan_error=None,
        video_count=len(found["videos"])))
    await C.touch(ctx, ctx["actor"].judge_id, "channel_scanned", "videos", None, {"id": channel["id"], "videos": len(found["videos"])})
    return await payload(ctx, channel["id"])


# ─── Kształt odpowiedzi ─────────────────────────────────────────────────────


def _slim(card: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not card:
        return None
    keys = ("match_id", "season", "scheduled_at", "match_code", "competition_name", "round_name", "venue_city", "match_kind")
    out = {k: card.get(k) for k in keys}
    for side in ("home", "away"):
        team = card.get(side) or {}
        out[side] = {"name": team.get("name"), "logo_url": team.get("logo_url"), "score": team.get("score")}
    return out


def channel_shape(row: Mapping[str, Any], counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    return {
        "id": row["id"], "url": row["url"], "channel_id": row.get("channel_id"), "handle": row.get("handle"), "title": row.get("title"),
        "thumbnail_url": row.get("thumbnail_url"), "scanned_at": row.get("scanned_at"), "scan_source": row.get("scan_source"),
        "scan_complete": row.get("scan_complete") != "0", "scan_error": row.get("scan_error"), "video_count": int(row.get("video_count") or 0),
        "counts": counts or {},
    }


async def _group_progress(group_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Stan sklejania połówek: {group_id: {status, done, count, video_id, error, progress}}."""
    if not group_ids:
        return {}
    from app import mentor_upload_group_rules as G
    from app import mentor_youtube_copy as YC

    rows = await C.rows(select(mentor_uploads).where(mentor_uploads.c.group_id.in_(group_ids)))
    by: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by.setdefault(R.s(r["group_id"]), []).append(r)
    out: Dict[str, Dict[str, Any]] = {}
    for gid, members in by.items():
        downloading = [m for m in members if m.get("status") == "downloading"]
        state = G.group_state(members) if not downloading else {"status": "downloading", "done": len(members) - len(downloading), "count": len(members)}
        live = next((YC.live_state(m["id"]) for m in downloading if YC.live_state(m["id"])), None)
        failed = next((m for m in members if m.get("status") == "failed"), None)
        out[gid] = {"status": "failed" if failed else state.get("status"), "done": state.get("done"), "count": state.get("count"),
                    "video_id": state.get("video_id"), "error": (failed or {}).get("error") or state.get("error"),
                    "progress": (live or {}).get("progress")}
    return out


async def payload(ctx: Dict[str, Any], channel_row_id: str) -> Dict[str, Any]:
    row = await C.one(select(mentor_channels).where(mentor_channels.c.id == channel_row_id))
    if not row or row["pair_id"] != ctx["pair_id"]:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego kanału.")
    vids = await C.rows(select(mentor_channel_videos).where(mentor_channel_videos.c.channel_row_id == channel_row_id)
                        .order_by(mentor_channel_videos.c.position.asc()))
    cards = {R.s(c["match_id"]): c for c in await _pair_cards(ctx)}
    items: List[Dict[str, Any]] = []
    for v in vids:
        parsed = R.json_value(v.get("parsed_json"), {})
        mid = v.get("chosen_match_id") or v.get("match_id")
        items.append({
            "video_id": v["video_id"], "title": v["title"], "thumbnail_url": v.get("thumbnail_url"), "duration_s": v.get("duration_s"),
            "published_at": v.get("published_at"), "url": f"https://www.youtube.com/watch?v={v['video_id']}", "parsed": parsed,
            "confidence": "sure" if v.get("chosen_match_id") else v.get("confidence"), "chosen": bool(v.get("chosen_match_id")),
            "reasons": R.json_value(v.get("reasons_json"), []), "match": _slim(cards.get(R.s(mid))) if mid else None,
            "alternatives": [{**a, "match": _slim(cards.get(R.s(a.get("match_id"))))} for a in R.json_value(v.get("alternatives_json"), [])],
            "state": v["state"], "added_video_id": v.get("added_video_id"), "group_id": v.get("group_id"),
            "match_id": mid,
        })
    groups = CR.half_groups([{**i, "confidence": i["confidence"]} for i in items if i["state"] == "new"])
    halves = {vid: mid for mid, pair in groups.items() for vid in pair}
    progress = await _group_progress(sorted({i["group_id"] for i in items if i.get("group_id")}))
    for i in items:
        i["half_of"] = halves.get(i["video_id"])
        i["merge"] = progress.get(i["group_id"]) if i.get("group_id") else None
    return {"channel": channel_shape(row, CR.summary(items)), "videos": items}


# ─── Trasy ──────────────────────────────────────────────────────────────────


async def _channel_ctx(channel_row_id: str, actor: Actor, action: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    row = await C.one(select(mentor_channels).where(mentor_channels.c.id == channel_row_id))
    if not row:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego kanału.")
    ctx = await C.pair_context(row["pair_id"], actor, action=action) if action else await C.pair_context(row["pair_id"], actor)
    return ctx, row


@router.get("/pairs/{pair_id}/channels")
async def list_channels(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    rows = await C.rows(select(mentor_channels).where(mentor_channels.c.pair_id == ctx["pair_id"]).order_by(mentor_channels.c.created_at.asc()))
    out = []
    for r in rows:
        vids = await C.rows(select(mentor_channel_videos.c.confidence, mentor_channel_videos.c.state, mentor_channel_videos.c.chosen_match_id)
                            .where(mentor_channel_videos.c.channel_row_id == r["id"]))
        out.append(channel_shape(r, CR.summary([{**v, "confidence": "sure" if v.get("chosen_match_id") else v.get("confidence")} for v in vids])))
    return {"channels": out, "api": bool(os.getenv("YOUTUBE_API_KEY", "").strip())}


@router.post("/pairs/{pair_id}/channels")
async def add_channel(pair_id: str, body: ChannelBody, actor: Actor = Depends(mentor_actor)):
    """Dodaje kanał i od razu go przegląda (ten sam link drugi raz = przegląd istniejącego)."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    ref = CR.channel_ref(body.url)
    if not ref:
        raise C.err(422, "CHANNEL_URL", "To nie wygląda na kanał YouTube - wklej link w rodzaju youtube.com/@kanal.")
    rows = await C.rows(select(mentor_channels).where(mentor_channels.c.pair_id == ctx["pair_id"]))
    same = next((r for r in rows if CR.channel_ref(r["url"]) == ref or (ref["kind"] == "id" and r.get("channel_id") == ref["value"])
                 or (ref["kind"] == "handle" and R.s(r.get("handle")).lower() == ref["value"].lower())), None)
    if not same:
        if len(rows) >= MAX_CHANNELS:
            raise C.err(409, "TOO_MANY_CHANNELS", f"Para może mieć najwyżej {MAX_CHANNELS} kanałów.")
        same = {"id": R.new_id(), "pair_id": ctx["pair_id"], "url": body.url.strip()[:300], "added_by": actor.judge_id, "created_at": C.now(),
                "handle": ref["value"] if ref["kind"] == "handle" else None, "channel_id": ref["value"] if ref["kind"] == "id" else None}
        await database.execute(mentor_channels.insert().values(**same))
        await C.touch(ctx, actor.judge_id, "channel_added", "videos", None, {"id": same["id"]})
    return await scan(ctx, dict(same))


@router.get("/channels/{channel_row_id}")
async def get_channel(channel_row_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _channel_ctx(channel_row_id, actor)
    return await payload(ctx, row["id"])


@router.post("/channels/{channel_row_id}/scan")
async def rescan(channel_row_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _channel_ctx(channel_row_id, actor, "video")
    return await scan(ctx, row)


@router.delete("/channels/{channel_row_id}")
async def remove_channel(channel_row_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _channel_ctx(channel_row_id, actor, "video")
    await database.execute(delete(mentor_channel_videos).where(mentor_channel_videos.c.channel_row_id == row["id"]))
    await database.execute(delete(mentor_channels).where(mentor_channels.c.id == row["id"]))
    await C.touch(ctx, actor.judge_id, "channel_removed", "videos", None, {"id": row["id"]})
    return {"ok": True}


@router.post("/channels/{channel_row_id}/dismiss")
async def dismiss(channel_row_id: str, body: DismissBody, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _channel_ctx(channel_row_id, actor, "video")
    if body.video_ids:
        q = (update(mentor_channel_videos).where(mentor_channel_videos.c.channel_row_id == row["id"])
             .where(mentor_channel_videos.c.video_id.in_(body.video_ids)))
        if body.undo:
            await database.execute(q.where(mentor_channel_videos.c.state == "dismissed").values(state="new", updated_at=C.now()))
        else:
            await database.execute(q.where(mentor_channel_videos.c.state == "new").values(state="dismissed", updated_at=C.now()))
    return await payload(ctx, row["id"])


@router.post("/channels/{channel_row_id}/accept")
async def accept(channel_row_id: str, body: AcceptBody, actor: Actor = Depends(mentor_actor)):
    """Dodaje wybrane filmy jako nagrania meczów. Obie połówki jednego meczu w wyborze = jedno nagranie sklejane na serwerze;
    pojedynczy film = nagranie-link (jak „Dodaj nagranie”)."""
    ctx, row = await _channel_ctx(channel_row_id, actor, "video")
    from app.mentor_evaluation_request_rules import normalized_video_url
    from app.mentor_evaluations import insert_link_video

    data = await payload(ctx, row["id"])
    cards = {R.s(c["match_id"]) for c in await _pair_cards(ctx)}
    wanted = {v for v in body.video_ids}
    chosen: Dict[str, Dict[str, Any]] = {}
    for item in data["videos"]:
        if item["video_id"] not in wanted or item["state"] != "new":
            continue
        mid = R.s(body.matches.get(item["video_id"]) or item.get("match_id"))
        if not mid or mid not in cards:
            continue
        chosen[item["video_id"]] = {**item, "match_id": mid}
    # Połówki: obie części tego samego meczu w wyborze.
    groups = CR.half_groups([{**i, "confidence": "sure"} for i in chosen.values()])
    in_group = {vid for pair in groups.values() for vid in pair}
    added = 0
    for mid, pair in groups.items():
        group_id = await _start_halves(ctx, actor, mid, [chosen[v] for v in pair])
        for v in pair:
            await database.execute(update(mentor_channel_videos).where(mentor_channel_videos.c.channel_row_id == row["id"])
                                   .where(mentor_channel_videos.c.video_id == v)
                                   .values(state="added", group_id=group_id, chosen_match_id=mid if body.matches.get(v) else None, updated_at=C.now()))
            added += 1
    for vid, item in chosen.items():
        if vid in in_group:
            continue
        url = normalized_video_url(item["url"])
        video, created = await insert_link_video(item["match_id"], ctx["pair_key"], url, actor.judge_id, None)
        if created:
            await C.touch(ctx, actor.judge_id, "video_added", "videos", item["match_id"], {"id": video["id"], "channel": row["id"]})
        await database.execute(update(mentor_channel_videos).where(mentor_channel_videos.c.channel_row_id == row["id"])
                               .where(mentor_channel_videos.c.video_id == vid)
                               .values(state="added", added_video_id=video["id"], chosen_match_id=item["match_id"] if body.matches.get(vid) else None,
                                       updated_at=C.now()))
        added += 1
    if added:
        await C.touch(ctx, actor.judge_id, "channel_accepted", "videos", None, {"id": row["id"], "count": added})
    return await payload(ctx, row["id"])


# ─── Połówki: pobranie z YouTube i sklejenie ───────────────────────────────


async def _start_halves(ctx: Dict[str, Any], actor: Actor, match_id: str, items: List[Dict[str, Any]]) -> str:
    """Grupa wgrań z dwóch części pobieranych z YouTube (`origin='youtube_part'`, `status='downloading'`)."""
    M._storage_or_503()  # bez magazynu R2 nie ma gdzie skleić połówek - czytelny 503 zamiast połowicznej grupy
    group_id, stamp = R.new_id(), C.now()
    card = next((c for c in await _pair_cards(ctx) if R.s(c["match_id"]) == match_id), {})
    expires = R.upload_expires_at(card.get("scheduled_at"), stamp)
    for index, item in enumerate(items):
        upload_id = R.new_id()
        key = M.object_key(ctx["pair_id"], R.s(match_id).replace(":", "_"), upload_id, "original.mp4")
        await database.execute(mentor_uploads.insert().values(
            id=upload_id, pair_id=ctx["pair_id"], match_id=match_id, uploader_id=actor.judge_id,
            filename=f"{HALF_NAME.get(index, f'Część {index + 1}')} - {item['title']}"[:200], size=0, content_type="video/mp4",
            r2_key=key, upload_id=None, status="downloading", created_at=stamp, expires_at=expires, origin=PART_ORIGIN,
            source_url=item["url"], group_id=group_id, group_index=index, group_count=len(items), duration_s=item.get("duration_s")))
    await C.touch(ctx, actor.judge_id, "upload_group_started", "videos", match_id, {"id": group_id, "count": len(items), "order": "youtube"})
    wake_worker()
    return group_id


_wake: Optional[asyncio.Event] = None


def wake_worker() -> None:
    if _wake is not None:
        _wake.set()


async def next_part() -> Optional[Dict[str, Any]]:
    return await C.one(select(mentor_uploads).where(mentor_uploads.c.origin == PART_ORIGIN)
                       .where(mentor_uploads.c.status == "downloading").order_by(mentor_uploads.c.created_at.asc(),
                                                                                mentor_uploads.c.group_index.asc()).limit(1))


async def process_part(row: Dict[str, Any]) -> None:
    """Pobiera jedną połówkę (yt-dlp jak „kopia na serwer”), kładzie ją pod kluczem członka grupy; komplet = sklejanie."""
    from app import mentor_upload_group_rules as G
    from app import mentor_upload_groups as UG
    from app import mentor_youtube_copy as YC
    from app import mentor_youtube_copy_rules as Y

    upload_id = row["id"]
    url = Y.watch_url(row.get("source_url"))
    if not url:
        raise Y.CopyError("NOT_YOUTUBE", Y.MESSAGES["NOT_YOUTUBE"])
    folder = await asyncio.to_thread(M.make_tmpdir, "mentor-ytpart-")
    try:
        cookiefile = await asyncio.to_thread(YC._cookie_file, folder)
        tries = Y.attempts()
        result: Optional[Dict[str, Any]] = None
        for n, proxy in enumerate(tries):
            try:
                result = await asyncio.to_thread(YC._download, upload_id, url, folder, proxy, cookiefile)
                break
            except Y.CopyError as exc:
                if exc.code == "CANCELLED" or n + 1 >= len(tries) or not Y.retry_through_proxy(exc.code):
                    raise
                for name in os.listdir(folder):
                    if name.startswith("source."):
                        os.remove(os.path.join(folder, name))
        assert result is not None
        size = await asyncio.to_thread(M.put_file, result["path"], row["r2_key"], "video/mp4")
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload_id)
                               .where(mentor_uploads.c.status == "downloading").values(status=G.WAITING, size=size, error=None))
    finally:
        YC._live.pop(upload_id, None)
        await asyncio.to_thread(shutil.rmtree, folder, True)
    from app.db import mentoring_pairs

    pair = await C.one(select(mentoring_pairs).where(mentoring_pairs.c.id == row["pair_id"]))
    judge_ids = [R.s(j) for j in R.json_value((pair or {}).get("judge_ids"), [])]
    title = re.sub(r"^(I|II) połowa - ", "", R.s(row.get("filename"))) or None
    video_id, _ = await UG.seal_group("|".join(sorted(judge_ids)), row["group_id"], f"{title} (obie połowy)" if title else None)
    if video_id:
        await C.touch(row["pair_id"], row["uploader_id"], "upload_group_completed", "videos", row["match_id"], {"id": row["group_id"], "video": video_id})
        M.wake_worker()


async def _fail_part(row: Dict[str, Any], message: str) -> None:
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.group_id == row["group_id"])
                           .where(mentor_uploads.c.status.in_(("downloading", "uploaded"))).values(status="failed", error=message[:300]))
    await C.touch(row["pair_id"], row["uploader_id"], "upload_group_failed", "videos", row["match_id"], {"id": row["group_id"]})


async def process_next() -> bool:
    from app import mentor_youtube_copy_rules as Y

    row = await next_part()
    if not row:
        return False
    try:
        await process_part(row)
    except Y.CopyError as exc:
        logger.info("mentor: połówka z kanału %s nieudana: %s", row["id"], exc.code)
        await _fail_part(row, exc.message)
    except Exception:  # noqa: BLE001 - jedna zła połówka nie zatrzymuje kolejki
        logger.warning("mentor: połówka z kanału %s nieudana", row["id"], exc_info=True)
        await _fail_part(row, "Nie udało się pobrać połowy meczu z YouTube.")
    return True


async def run_channel_worker() -> None:
    """Pętla połówek z kanałów: jedna naraz; budzi ją „Dodaj”, inaczej sprawdza co 60 s (po restarcie wznawia)."""
    global _wake
    _wake = asyncio.Event()
    await asyncio.sleep(30)
    while True:
        try:
            busy = await process_next()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: przebieg kolejki połówek nieudany")
            busy = False
        if busy:
            continue
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), 60)
        except asyncio.TimeoutError:
            pass
