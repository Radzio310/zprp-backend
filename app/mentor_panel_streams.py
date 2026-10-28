"""
Panel „Mentor" - nagrania meczu z YouTube (24.10.2026). Kontrakt: `docs/mentor-panel.md` 4.14.

Dwie drogi:
  1. Gotowe trafienia - transmisje, które pętla portalu (`app/streams`) już
     przypisała do meczu (`match_streams`, to samo `match_id` co karta Mentora).
     Pokój meczu pokazuje je jako `suggested_streams`; zero limitu YouTube.
  2. „Poszukaj nagrania" na żądanie pary - jedno `search.list` (100 j.) ze
     WSPÓLNEJ puli dobowej (`store.quota_take`), potem `videos.list` i te same
     reguły dopasowania co pętla (`rules.best_match`). Trafienia zapisujemy do
     `match_streams` (portal też na tym zyskuje), a w `mentor_stream_searches`
     licznik pary (3 na mecz na dobę), ostatni wynik i odrzucone filmy.

Zasady:
  * szukać mogą sędziowie pary i jej mentorzy, przy włączonym panelu,
    w dniu meczu albo później, i tylko gdy nie ma żadnej podpowiedzi,
  * wynik jest wspólny dla pary i mentorów; trafienie trzyma 6 h (drugie
    „Poszukaj" w tym czasie oddaje zapamiętany wynik bez limitu),
  * „Nie ten" chowa film tylko w tej parze (portal dalej go widzi),
  * każda odmowa mówi wprost, co dalej („Spróbuj jutro albo wklej link").
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import and_, select

from app import mentor_panel_core as C
from app import mentor_panel_rules as PR
from app.db import database, mentor_stream_searches
from app.mentor_panel_auth import mentor_actor

router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor
T = mentor_stream_searches

PER_DAY = 3
FRESH = timedelta(hours=6)
#: Okno meczów, z którymi film porównujemy (remis dwóch meczów = nie przypisujemy).
DAY_SPAN = timedelta(hours=18)
SEARCH_COST = 100
MAX_REJECTED = 60
MAX_CHANNELS = 6

TRY_LATER = "Spróbuj jutro albo wklej link."
MESSAGES = {
    "ROLE": "Nagrania szukają sędziowie pary i ich mentorzy.",
    "OFF": "Wyszukiwanie na YouTube jest na serwerze wyłączone. Wklej link do nagrania.",
    "TOO_EARLY": "Nagrania szukamy w dniu meczu i później.",
    "LIMIT": f"Ten mecz szukaliście dziś już {PER_DAY} razy. {TRY_LATER}",
    "QUOTA": f"Dzienna pula wyszukiwań YouTube się wyczerpała. {TRY_LATER}",
    "FAILED": "YouTube nie odpowiedział. Spróbuj za chwilę albo wklej link.",
}
STATUS = {"ROLE": 403, "OFF": 503, "TOO_EARLY": 409, "LIMIT": 429, "QUOTA": 429, "FAILED": 503}
CODES = {"ROLE": "NO_ACCESS", "OFF": "STREAM_SEARCH_OFF", "TOO_EARLY": "STREAM_SEARCH_EARLY",
         "LIMIT": "STREAM_SEARCH_LIMIT", "QUOTA": "STREAM_SEARCH_QUOTA", "FAILED": "STREAM_SEARCH_FAILED"}

_locks: Dict[str, asyncio.Lock] = {}


def clock() -> datetime:
    """Zegar (podmieniany w testach)."""
    return datetime.now(timezone.utc)


def youtube(quota_take):
    """Klient YouTube (podmieniany w testach razem z siecią)."""
    from app.streams import net

    return net.YouTube(quota_take)


# ─── Czyste reguły ──────────────────────────────────────────────────────────


def _json_list(raw: Any) -> List[str]:
    value = PR.json_value(raw, [])
    return [str(v) for v in value if v] if isinstance(value, list) else []


def warsaw_day(moment: Optional[datetime]) -> Optional[date]:
    from app.streams.rules import WARSAW

    if not isinstance(moment, datetime):
        return None
    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return aware.astimezone(WARSAW).date()


def search_window(kickoff: Optional[datetime], kickoff_known: bool, now: datetime) -> Optional[Dict[str, Any]]:
    """Jak szukać teraz: `{event, published_after}` albo None (za wcześnie, przed dniem meczu).

    Przed meczem (w dniu meczu) - zapowiedź transmisji, w trakcie - na żywo,
    po meczu - zwykłe filmy opublikowane od 2 h przed rozpoczęciem (VOD
    transmisji i nagrania wgrane później).
    """
    day = warsaw_day(kickoff)
    if day is None or warsaw_day(now) < day:
        return None
    from app.streams.rules import LIVE_SPAN

    after = (kickoff - timedelta(hours=2)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if kickoff_known:
        if now < kickoff - timedelta(minutes=30):
            return {"event": "upcoming", "published_after": None}
        if now <= kickoff + LIVE_SPAN:
            return {"event": "live", "published_after": None}
    return {"event": None, "published_after": after}


def search_gate(*, role: Optional[str], enabled: bool, yt_enabled: bool, match_day: Optional[date], today: date,
                row: Optional[Dict[str, Any]], visible: int, quota_ok: bool) -> Dict[str, Any]:
    """Czy wolno teraz szukać + zdanie dla ekranu. `reason` None = wolno."""
    used = int((row or {}).get("day_count") or 0) if (row or {}).get("day") == today.isoformat() else 0
    left = max(0, PER_DAY - used)
    if role not in ("pair", "mentor") or not enabled:
        reason: Optional[str] = "ROLE"
    elif not yt_enabled:
        reason = "OFF"
    elif match_day is None or today < match_day:
        reason = "TOO_EARLY"
    elif visible:
        reason = "FOUND"
    elif left <= 0:
        reason = "LIMIT"
    elif not quota_ok:
        reason = "QUOTA"
    else:
        reason = None
    searched = (row or {}).get("searched_at")
    searched = searched if isinstance(searched, datetime) else None
    return {
        "allowed": reason is None,
        "reason": reason,
        "message": MESSAGES.get(reason or ""),
        "left": left,
        "per_day": PER_DAY,
        "searched_at": PR.aware(searched).isoformat() if searched else None,
        "last_found": (row or {}).get("last_count"),
    }


def fresh_hit(row: Optional[Dict[str, Any]], now: datetime) -> bool:
    """Ostatnie szukanie coś znalazło i nie minęło 6 h - oddajemy zapamiętany wynik."""
    searched = PR.aware((row or {}).get("searched_at"))
    return bool(searched and int((row or {}).get("last_count") or 0) > 0 and now - searched < FRESH)


def visible_rows(rows: Iterable[Dict[str, Any]], added: Iterable[str], rejected: Iterable[str],
                 found: Iterable[str]) -> List[Dict[str, Any]]:
    """Podpowiedzi pary: YouTube, `official`/`confirmed` albo znalezione przez parę
    (także `possible`), bez dodanych do pokoju i bez odrzuconych."""
    skip = {v for v in added if v} | {v for v in rejected if v}
    mine = {v for v in found if v}
    return [r for r in rows if r.get("platform") == "youtube" and r.get("video_id") and r["video_id"] not in skip
            and (r.get("confidence") in ("official", "confirmed") or r["video_id"] in mine)]


# ─── Baza ───────────────────────────────────────────────────────────────────


async def _row(pair_id: str, match_id: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(T).where(and_(T.c.pair_id == pair_id, T.c.match_id == match_id)))


async def _save(pair_id: str, match_id: str, exists: bool, **values: Any) -> None:
    values["updated_at"] = clock()
    if exists:
        await database.execute(T.update().where(and_(T.c.pair_id == pair_id, T.c.match_id == match_id)).values(**values))
    else:
        await database.execute(T.insert().values(pair_id=pair_id, match_id=match_id, **values))


def _added_ids(raw_videos: Iterable[Dict[str, Any]]) -> List[str]:
    from app.link_preview_rules import youtube_id

    return [youtube_id(PR.s(v.get("url"))) for v in raw_videos]


def _in_match(raw_videos: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filmy YouTube, które mecz już ma - ekran szukania pokazuje je jako „Już w meczu", nie jako pustkę."""
    from app.link_preview_rules import youtube_id
    from app.mentor_evaluation_request_rules import youtube_thumbnail

    out: List[Dict[str, Any]] = []
    for v in raw_videos:
        url = PR.s(v.get("url"))
        vid = youtube_id(url) if url else None
        if vid:
            out.append({"video_id": vid, "url": url, "title": v.get("title") or "", "thumbnail_url": v.get("thumbnail_url") or youtube_thumbnail(url)})
    return out


async def _raw_videos(ctx: Dict[str, Any], match_id: str) -> List[Dict[str, Any]]:
    from app.mentor_panel_media import video_list

    _, raw = await video_list(ctx, match_id)
    return raw


def card_context(card: Dict[str, Any]) -> Dict[str, Any]:
    """Kontekst dopasowania z karty Mentora (mecz spoza hurtowni portalu)."""
    from app.streams import rules as R

    when = PR.aware(card.get("scheduled_at"))
    local = when.astimezone(R.WARSAW).replace(tzinfo=None) if when else None
    return R.match_context({
        "match_id": card.get("match_id"), "competition_name": card.get("competition_name"),
        "match_code": card.get("match_code"), "home_team_name": (card.get("home") or {}).get("name"),
        "away_team_name": (card.get("away") or {}).get("name"), "scheduled_at": local,
    })


async def match_context(card: Dict[str, Any]) -> Dict[str, Any]:
    from app.streams import store

    match_id = PR.s(card.get("match_id"))
    return (await store.match_contexts([match_id])).get(match_id) or card_context(card)


async def _quota_ok() -> bool:
    from app.streams import store

    status = await store.quota_status()
    units = int(status.get("units_used") or 0)
    return status["searches_left"] > 0 and units + SEARCH_COST <= store.DAILY_UNITS - store.SEARCH_RESERVE


async def _radar_channels(mctx: Dict[str, Any]) -> List[str]:
    """Kanały, po których przesuwa się radar w aplikacji (klubowe + kanał poziomu)."""
    from app.streams import store
    from app.streams.seeds import TIER_CHANNEL

    rows = await store.club_channels([mctx.get("home_club_id"), mctx.get("away_club_id")])
    key = TIER_CHANNEL.get(mctx.get("tier") or "")
    tier = await store.channel_by_key(key) if key else None
    titles: List[str] = []
    for r in ([tier] if tier else []) + [r for r in rows if r.get("platform") == "youtube"]:
        t = PR.s(r.get("title"))
        if t and t not in titles:
            titles.append(t)
    return titles[:MAX_CHANNELS]


async def stream_state(ctx: Dict[str, Any], card: Dict[str, Any], raw_videos: List[Dict[str, Any]],
                       row: Optional[Dict[str, Any]] = None, *, row_loaded: bool = False) -> Dict[str, Any]:
    """`{streams, search}` dla pokoju meczu i odpowiedzi tras."""
    from app.streams import store

    match_id = PR.s(card["match_id"])
    if not row_loaded:
        row = await _row(ctx["pair_id"], match_id)
    rows = visible_rows(await store.streams_for([match_id]), _added_ids(raw_videos), _json_list((row or {}).get("rejected_json")),
                        _json_list((row or {}).get("found_json")))
    streams = await store.with_channels(rows)
    mctx = await match_context(card)
    now = clock()
    gate = search_gate(role=ctx["role"], enabled=ctx["enabled"], yt_enabled=youtube(store.quota_take).enabled,
                       match_day=warsaw_day(mctx.get("kickoff")), today=warsaw_day(now), row=row, visible=len(streams),
                       quota_ok=await _quota_ok())
    gate["channels"] = await _radar_channels(mctx)
    return {"streams": streams, "search": gate, "in_match": _in_match(raw_videos)}


async def room_streams(ctx: Dict[str, Any], card: Dict[str, Any], raw_videos: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Dla `GET .../matches/{id}`: błąd odczytu = brak podpowiedzi, pokój działa dalej."""
    try:
        return await stream_state(ctx, card, raw_videos)
    except Exception:  # noqa: BLE001 - podpowiedź nie psuje pokoju meczu
        C.logger.warning("mentor: podpowiedzi transmisji nieczytelne", exc_info=True)
        return {"streams": [], "search": None}


# ─── Wyszukiwanie ───────────────────────────────────────────────────────────


def _refuse(reason: str):
    return C.err(STATUS[reason], CODES[reason], MESSAGES[reason])


async def _search(ctx: Dict[str, Any], card: Dict[str, Any], actor: Actor) -> Dict[str, Any]:
    from app.streams import cache, store, worker
    from app.streams import rules as R

    match_id = PR.s(card["match_id"])
    raw_videos = await _raw_videos(ctx, match_id)
    row = await _row(ctx["pair_id"], match_id)
    now = clock()
    state = await stream_state(ctx, card, raw_videos, row, row_loaded=True)
    reason = state["search"]["reason"]
    if not state["streams"] and state["in_match"]:
        # Film, który mecz już ma, to ten sam, który znaleźliśmy wcześniej (portal albo szukanie pary) - drugi raz
        # nie szukamy i nie zużywamy puli; ekran pokaże go jako „Już w meczu", nie jako pustkę.
        known = {r.get("video_id") for r in await store.streams_for([match_id])} | set(_json_list((row or {}).get("found_json")))
        if any(v["video_id"] in known for v in state["in_match"]):
            return {**state, "cached": True}
    if state["streams"] and (reason == "FOUND" or fresh_hit(row, now)):
        # Jest co pokazać (portal albo wynik sprzed < 6 h) - bez limitu i bez YouTube.
        return {**state, "cached": True}
    if reason:
        raise _refuse(reason)

    mctx = await match_context(card)
    window = search_window(mctx.get("kickoff"), bool(mctx.get("kickoff_known", True)), now)
    if window is None:
        raise _refuse("TOO_EARLY")
    took: Dict[str, bool] = {}

    async def take(units: int, search: bool) -> bool:
        ok = await store.quota_take(units, search)
        if search:
            took["search"] = ok
        return ok

    yt = youtube(take)
    ids = await yt.search_ids(R.search_query(mctx), window["event"], published_after=window["published_after"])
    if took.get("search") is False:
        raise _refuse("QUOTA")
    today = warsaw_day(now).isoformat()
    used = int((row or {}).get("day_count") or 0) if (row or {}).get("day") == today else 0
    counted = {"day": today, "day_count": used + 1, "searched_at": now, "searched_by": actor.judge_id}
    if ids is None:
        # Jednostki z puli już poszły - próba się liczy, ale ekran mówi, co dalej.
        await _save(ctx["pair_id"], match_id, bool(row), **counted)
        raise _refuse("FAILED")
    await store.mark_searched(f"{match_id}:mentor")
    rejected = set(_json_list((row or {}).get("rejected_json")))
    found: List[str] = []
    if ids:
        pool = [mctx]
        if mctx.get("kickoff"):
            day = await store.window_matches(mctx["kickoff"], before=DAY_SPAN, after=DAY_SPAN)
            pool += [m for m in day if m["match_id"] != match_id]
        for video in await yt.videos([i for i in ids if i not in rejected]):
            owner = await store.channel_by_channel_id(video.get("channel_id"))
            hit = R.best_match(video, pool, owner)
            if not hit or hit[0]["match_id"] != match_id:
                continue
            await worker.store_candidate(video, hit[0], hit[1], owner, source="mentor", verified_by="api", now=now)
            found.append(video["video_id"])
    known = _json_list((row or {}).get("found_json"))
    merged = known + [v for v in found if v not in known]
    await _save(ctx["pair_id"], match_id, bool(row), **counted, last_count=len(found), found_json=json.dumps(merged))
    if found:
        cache.clear()  # portal: świeże transmisje meczu
    await C.touch(ctx, actor.judge_id, "stream_search", "videos", match_id, {"found": len(found)})
    return {**await stream_state(ctx, card, raw_videos), "cached": False}


@router.post("/pairs/{pair_id}/matches/{match_id}/streams/search")
async def search_streams(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    if ctx["role"] not in ("pair", "mentor"):
        raise _refuse("ROLE")
    C.check(ctx, "video")
    card = await C.match_card(ctx, match_id)
    key = f"{ctx['pair_id']}|{card['match_id']}"
    lock = _locks.setdefault(key, asyncio.Lock())
    try:
        async with lock:  # dwa stuknięcia naraz (sędzia i mentor) = jedno wyszukiwanie
            return await _search(ctx, card, actor)
    finally:
        if not lock.locked():
            _locks.pop(key, None)


class RejectBody(BaseModel):
    video_id: str = Field(min_length=6, max_length=20)


@router.post("/pairs/{pair_id}/matches/{match_id}/streams/reject")
async def reject_stream(pair_id: str, match_id: str, body: RejectBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    row = await _row(ctx["pair_id"], card["match_id"])
    rejected = _json_list((row or {}).get("rejected_json"))
    vid = body.video_id.strip()
    if vid not in rejected:
        rejected = (rejected + [vid])[-MAX_REJECTED:]
        await _save(ctx["pair_id"], card["match_id"], bool(row), rejected_json=json.dumps(rejected))
        await C.touch(ctx, actor.judge_id, "stream_reject", "videos", card["match_id"], {"video_id": vid})
    return await stream_state(ctx, card, await _raw_videos(ctx, card["match_id"]))
