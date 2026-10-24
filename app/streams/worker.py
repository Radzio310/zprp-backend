"""Pętla w tle: wykrywanie transmisji meczów. Kontrakt: `docs/streams.md`.

Jeden przebieg (co minutę, najwyżej 4 min):
1. Linki ZPRP (`zprp_public_matches.stream_url`) → `official` (okno ±1 doba;
   raz na dobę także 30 dni wstecz i 14 dni naprzód).
2. Kanały, którym wypada sprawdzenie (`rules.next_check_at`: 60 min przed
   meczem co 5 min, w trakcie co 3 min, do doby po meczu co godzinę, inaczej
   raz na dobę): RSS kanału/playlisty (bez klucza) → dopasowanie do meczów →
   stan z `videos.list` (gdy jest klucz). Kanał klubu w oknie meczu dodatkowo:
   strona `/live` (bez klucza).
3. Odświeżenie stanu transmisji live/upcoming (co 3 min, 1 jednostka / 50 filmów).
4. Podpowiedzi ze strony z listą transmisji (co 10 min w dni meczowe, tylko z
   kluczem - każdy film sprawdza API; nazwa strony nigdzie nie wychodzi).
5. Wyszukiwanie YouTube (100 jednostek) dla najważniejszych meczów bez
   transmisji, ≤ 80 na dobę (`rules.pick_search_targets`).
6. Odkrywanie kanałów klubów ze stron WWW (1 klub co 5 min, ponownie po 30 dniach).

Parsowanie w wątkach (`net`), zapisy idempotentne (`store`). Bez repliki-zamka:
dziś produkcja ma jeden proces; druga replika zmarnowałaby tylko część limitu.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from app.link_preview_rules import youtube_id
from app.streams import cache, net, store
from app.streams import parsers as P
from app.streams import rules as R

log = logging.getLogger(__name__)

WINDOW_BACK = timedelta(hours=26)
WINDOW_AHEAD = timedelta(hours=24)
MAX_CHANNELS_PER_CYCLE = 15
FEED_MAX_AGE = timedelta(days=12)
HINT_URL = os.getenv("STREAMS_HINT_URL", "https://pilkareczna.com/live").strip()

_lock = asyncio.Lock()
_marks: dict[str, datetime] = {}
_seeded = False


def _every(name: str, now: datetime, interval: timedelta) -> bool:
    """Pamięć procesu: czy minęło `interval` od ostatniego wykonania `name`."""
    last = _marks.get(name)
    if last is not None and now - last < interval:
        return False
    _marks[name] = now
    return True


def _watch_url(video_id: str) -> str:
    return f"https://www.youtube.com/watch?v={video_id}"


def _platform(url: str) -> str:
    if youtube_id(url):
        return "youtube"
    host = (urlparse(url).hostname or "").lower()
    if host.endswith("facebook.com") or host == "fb.watch":
        return "facebook"
    return "other"


# ---------------------------------------------------------------------------
# 1. ZPRP
# ---------------------------------------------------------------------------


async def import_zprp(matches: list[dict[str, Any]], now: datetime) -> int:
    changed = 0
    for m in matches:
        url = str(m.get("stream_url") or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        platform = _platform(url)
        vid = youtube_id(url) or None
        values = {
            "match_id": m["match_id"], "url": _watch_url(vid) if vid else url, "platform": platform, "video_id": vid,
            "title": f"{m.get('home_team_name') or ''} – {m.get('away_team_name') or ''}".strip(" –") or None,
            "thumbnail_url": P.thumb(vid) if vid else None,
            "state": R.state_without_api(R.state_kickoff(m), now) if vid else "link",
            "starts_at": R.timed_kickoff(m), "confidence": "official", "source": "zprp", "verified_by": "zprp",
        }
        changed += await store.upsert_stream(values)
    return changed


# ---------------------------------------------------------------------------
# 2. Kanały
# ---------------------------------------------------------------------------


async def _known_channel(channel_id: Optional[str], fallback: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    if fallback and (not channel_id or fallback.get("channel_id") in (None, channel_id)):
        return fallback
    return await store.channel_by_channel_id(channel_id)


async def store_candidate(video: dict[str, Any], match: dict[str, Any], level: str, channel: Optional[dict[str, Any]],
                          *, source: str, verified_by: str, now: datetime) -> bool:
    vid = video["video_id"]
    state = video.get("state") if verified_by in ("api", "page") else R.state_without_api(R.state_kickoff(match), now)
    starts = video.get("starts_at") if verified_by == "api" else R.timed_kickoff(match)
    values = {
        "match_id": match["match_id"], "url": _watch_url(vid), "platform": "youtube", "video_id": vid,
        "channel_ref": (channel or {}).get("id"),
        "channel_title": video.get("channel_title") or (channel or {}).get("title"),
        "channel_url": f"https://www.youtube.com/channel/{video['channel_id']}" if video.get("channel_id") else None,
        "title": video.get("title") or None, "thumbnail_url": video.get("thumbnail_url") or P.thumb(vid),
        "state": state or "vod", "starts_at": starts, "ended_at": video.get("ended_at"),
        "duration_s": video.get("duration_s"), "confidence": level, "source": source, "verified_by": verified_by,
    }
    return await store.upsert_stream(values)


async def _verify_and_store(candidates: list[dict[str, Any]], matches: list[dict[str, Any]],
                            channel: Optional[dict[str, Any]], yt: net.YouTube, now: datetime, *, source: str,
                            require_api: bool = False) -> int:
    """Kandydaci (RSS/strona) → stan z API (gdy jest) → ponowne dopasowanie → zapis."""
    if not candidates or not matches:
        return 0
    details = {v["video_id"]: v for v in await yt.videos([c["video_id"] for c in candidates])} if yt.enabled else {}
    changed = 0
    for cand in candidates:
        api = details.get(cand["video_id"])
        # API odpowiedziało, a filmu nie ma (prywatny/usunięty) - pomijamy; API milczy
        # (brak klucza, limit) - zostaje dopasowanie z RSS/strony.
        if api is None and (require_api or details):
            continue
        video = {**cand, **api} if api else cand
        owner = await _known_channel(video.get("channel_id"), channel)
        found = R.best_match(video, matches, owner)
        if not found:
            continue
        match, level = found
        verified_by = "api" if api else ("page" if cand.get("state") else "rss")
        changed += await store_candidate(video, match, level, owner, source=source, verified_by=verified_by, now=now)
    return changed


async def resolve_channel(ch: dict[str, Any], yt: net.YouTube) -> Optional[str]:
    """Uchwyt/nazwa użytkownika → `UC...` (API 1 jednostka, bez klucza - strona kanału)."""
    if ch.get("channel_id") or ch.get("playlist_id"):
        return ch.get("channel_id")
    handle = ch.get("handle")
    found = None
    if yt.enabled and handle:
        found = await yt.channel(handle=handle)
    if not found and handle:
        found = await net.fetch_page(f"https://www.youtube.com/{handle if handle.startswith('@') else '@' + handle}",
                                     P.parse_channel_page, youtube=True)
    if not found and ch.get("url"):
        found = await net.fetch_page(ch["url"], P.parse_channel_page, youtube=True)
    if not found:
        return None
    await store.update_channel(ch["id"], channel_id=found["channel_id"],
                               title=ch.get("title") or found.get("title"), error=None)
    ch["channel_id"] = found["channel_id"]
    return found["channel_id"]


async def check_channel(ch: dict[str, Any], matches: list[dict[str, Any]], now: datetime, yt: net.YouTube,
                        counters: Counter) -> int:
    relevant = R.relevant_matches(ch, matches)
    nxt = R.next_check_at([k for k in (R.timed_kickoff(m) for m in relevant) if k], now)
    if ch.get("platform") != "youtube" or ch.get("kind") == "tv":
        await store.update_channel(ch["id"], last_checked_at=now, next_check_at=now + timedelta(days=7))
        return 0
    if not await resolve_channel(ch, yt) and not ch.get("playlist_id"):
        await store.update_channel(ch["id"], last_checked_at=now, next_check_at=now + timedelta(hours=6),
                                   error="Nie udało się ustalić identyfikatora kanału")
        return 0
    got = await net.fetch_feed(ch.get("channel_id") if not ch.get("playlist_id") else None, ch.get("playlist_id"))
    counters["feeds"] += 1
    if got is None:
        await store.update_channel(ch["id"], last_checked_at=now, next_check_at=nxt, error="Kanał RSS nie odpowiada")
        return 0
    body, feed = got
    patch: dict[str, Any] = {"last_checked_at": now, "next_check_at": nxt, "error": None,
                             "etag": hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()[:16]}
    if feed.get("channel_id") and not ch.get("channel_id"):
        patch["channel_id"] = feed["channel_id"]
    if feed.get("title") and not ch.get("title"):
        patch["title"] = feed["title"]
    await store.update_channel(ch["id"], **patch)
    if not relevant:
        return 0
    # Filmy już zapisane odświeża `refresh_states` - nie płacimy za nie drugi raz przy każdym sprawdzeniu.
    known = {s.get("video_id") for s in await store.streams_for([m["match_id"] for m in relevant], include_hidden=True)}
    fresh = [e for e in feed["entries"] if e["video_id"] not in known
             and (not e.get("published") or now - e["published"] <= FEED_MAX_AGE)]
    candidates = [e for e in fresh if R.best_match(e, relevant, ch) or _maybe(e, relevant)]
    changed = await _verify_and_store(candidates, relevant, ch, yt, now, source="rss")
    changed += await _probe_live_page(ch, relevant, now, yt)
    return changed


def _maybe(entry: dict[str, Any], matches: list[dict[str, Any]]) -> bool:
    """Wpis RSS, który z samej daty publikacji nie przeszedł, ale tytuł ma obie drużyny
    (zapowiedź transmisji wrzucona dawno) - warto zapytać API o planowany start."""
    title = entry.get("title") or ""
    return any(R.team_level(m.get("home_team_name"), title) != "none" and R.team_level(m.get("away_team_name"), title) != "none"
               for m in matches)


async def _probe_live_page(ch: dict[str, Any], matches: list[dict[str, Any]], now: datetime, yt: net.YouTube) -> int:
    if ch.get("kind") not in ("club", "official") or not ch.get("channel_id"):
        return 0
    live_now = [m for m in matches if R.timed_kickoff(m) and m["kickoff"] - timedelta(minutes=30) <= now <= m["kickoff"] + R.LIVE_SPAN]
    if not live_now:
        return 0
    known = {s.get("video_id") for s in await store.streams_for([m["match_id"] for m in live_now], include_hidden=True)}
    page = await net.fetch_page(f"https://www.youtube.com/channel/{ch['channel_id']}/live", P.parse_live_page, youtube=True)
    if not page or page["video_id"] in known:
        return 0
    cand = {"video_id": page["video_id"], "title": page.get("title") or "", "channel_id": ch["channel_id"],
            "channel_title": ch.get("title"), "state": "live" if page.get("live_now") else "upcoming",
            "is_broadcast": True, "starts_at": now, "thumbnail_url": P.thumb(page["video_id"])}
    return await _verify_and_store([cand], live_now, ch, yt, now, source="live_page")


# ---------------------------------------------------------------------------
# 3. Odświeżenie stanu
# ---------------------------------------------------------------------------


async def refresh_states(matches: list[dict[str, Any]], now: datetime, yt: net.YouTube) -> int:
    rows = await store.active_video_streams([m["match_id"] for m in matches])
    if not rows:
        return 0
    by_match = {m["match_id"]: m for m in matches}
    changed = 0
    details = {v["video_id"]: v for v in await yt.videos([r["video_id"] for r in rows])} if yt.enabled else {}
    for row in rows:
        api = details.get(row["video_id"])
        if api:
            patch = {"state": api["state"], "starts_at": api.get("starts_at"), "ended_at": api.get("ended_at"),
                     "duration_s": api.get("duration_s"), "title": api.get("title") or row.get("title"),
                     "thumbnail_url": api.get("thumbnail_url") or row.get("thumbnail_url"),
                     "channel_title": row.get("channel_title") or api.get("channel_title")}
            if row.get("verified_by") != "admin":
                patch["verified_by"] = "api"
        elif row.get("verified_by") in ("rss", "zprp", "page"):
            patch = {"state": R.state_without_api(R.state_kickoff(by_match.get(row["match_id"]) or {}), now)}
        else:
            continue
        if any(R.aware(row.get(k)) != R.aware(v) if isinstance(v, datetime) else row.get(k) != v for k, v in patch.items()):
            await store.patch_stream(row["id"], last_seen_at=now, **patch)
            changed += 1
    return changed


# ---------------------------------------------------------------------------
# 4. Podpowiedzi, 5. Wyszukiwanie
# ---------------------------------------------------------------------------


def _matchday(matches: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    # Bez godziny (00:00 = do ustalenia) mecz nie ma okna - inaczej limit YouTube szedłby na Superligę o północy.
    return [m for m in matches if R.timed_kickoff(m) and m["kickoff"] - timedelta(hours=3) <= now <= m["kickoff"] + timedelta(hours=2)]


async def hints(matches: list[dict[str, Any]], now: datetime, yt: net.YouTube) -> int:
    active = [m for m in _matchday(matches, now) if m.get("tier") in R.SEARCH_TIERS]
    if not HINT_URL or not yt.enabled or not active:
        return 0
    items = await net.fetch_page(HINT_URL, P.parse_hint_page)
    if not items:
        return 0
    known = {s.get("video_id") for s in await store.streams_for([m["match_id"] for m in matches], include_hidden=True)}
    fresh = [i for i in items if i["video_id"] not in known][:50]
    if not fresh:
        return 0
    details = {v["video_id"]: v for v in await yt.videos([i["video_id"] for i in fresh])}
    changed = 0
    for item in fresh:
        video = details.get(item["video_id"])
        if not video:
            continue
        owner = await store.channel_by_channel_id(video.get("channel_id"))
        found = R.best_match(video, active, owner)
        if not found and item.get("context"):
            # Tytuł filmu bez nazw drużyn - kontekst ze strony wskazuje mecz, ale tylko „possible”
            # i tylko przy pewnym czasie startu transmisji.
            alt = R.best_match({**video, "title": item["context"]}, active, None)
            if alt and video.get("is_broadcast"):
                verdict = R.judge({**video, "title": item["context"]}, alt[0])
                found = (alt[0], "possible") if verdict and verdict.time == "exact" else None
        if not found:
            continue
        match, level = found
        changed += await store_candidate(video, match, level, owner, source="hint", verified_by="api", now=now)
    return changed


async def search(matches: list[dict[str, Any]], now: datetime, yt: net.YouTube) -> int:
    if not yt.enabled:
        return 0
    covered = {s["match_id"] for s in await store.streams_for([m["match_id"] for m in matches])}
    status = await store.quota_status()
    targets = R.pick_search_targets(matches, covered, status["searches"], now, status["searches_left"])
    changed = 0
    for match, event in targets:
        ids = await yt.search(R.search_query(match), event)
        await store.mark_searched(f"{match['match_id']}:{event}")
        if not ids:
            continue
        for video in await yt.videos(ids):
            owner = await store.channel_by_channel_id(video.get("channel_id"))
            found = R.best_match(video, _matchday(matches, now) or [match], owner)
            if found:
                changed += await store_candidate(video, found[0], found[1], owner, source="search", verified_by="api", now=now)
    return changed


# ---------------------------------------------------------------------------
# 6. Kanały klubów ze stron WWW
# ---------------------------------------------------------------------------


def _website(raw: Any) -> Optional[str]:
    value = str(raw or "").strip().split()[0] if str(raw or "").strip() else ""
    if not value:
        return None
    if not value.lower().startswith(("http://", "https://")):
        value = "https://" + value.lstrip("/")
    host = (urlparse(value).hostname or "").lower()
    if not host or "." not in host or host.endswith(("facebook.com", "youtube.com", "instagram.com")):
        return None
    return value


async def _club_youtube(link: dict[str, Any], yt: net.YouTube) -> Optional[dict[str, Any]]:
    if link.get("channel_id"):
        return {"channel_id": link["channel_id"], "title": None}
    if yt.enabled and (link.get("handle") or link.get("user")):
        found = await yt.channel(handle=link.get("handle"), user=link.get("user"))
        if found:
            return found
    return await net.fetch_page(link["url"], P.parse_channel_page, youtube=True)


async def discover_club(club: dict[str, Any], yt: net.YouTube) -> int:
    url = _website(club.get("website"))
    if not url:
        return 0
    links = await net.fetch_page(url, lambda body: P.parse_club_links(body, club.get("name") or ""))
    if not links:
        return 0
    added = 0
    for link in links["youtube"][:1]:
        found = await _club_youtube(link, yt)
        if not found:
            continue
        existing = await store.channel_by_channel_id(found["channel_id"])
        if existing and (existing.get("kind") != "club" or existing.get("club_id") not in (None, club["club_id"])):
            continue  # kanał związku/innego klubu ze stopki - nie przypisujemy
        await store.upsert_channel({
            "key": f"youtube:{found['channel_id']}", "platform": "youtube", "channel_id": found["channel_id"],
            "handle": link.get("handle"), "title": found.get("title") or club.get("name"),
            "url": link["url"], "club_id": club["club_id"], "kind": "club", "verified": False,
            "discovered_from": "club_website", "scope": [],
        })
        added += 1
    for link in links["facebook"][:1]:
        await store.upsert_channel({
            "key": f"facebook:{link['url'].lower()}", "platform": "facebook", "title": club.get("name"),
            "url": link["url"], "club_id": club["club_id"], "kind": "club", "verified": False,
            "discovered_from": "club_website", "scope": [],
        })
        added += 1
    return added


async def discover_clubs(matches: list[dict[str, Any]], now: datetime, yt: net.YouTube, limit: int = 1) -> int:
    state = await store.state_get("streams:club_sites")
    preferred = [c for m in matches for c in (m.get("home_club_id"), m.get("away_club_id"))]
    clubs = await store.clubs_for_discovery(preferred, state, recheck_before=now - timedelta(days=30), limit=limit)
    added = 0
    for club in clubs:
        try:
            added += await discover_club(club, yt)
        finally:
            state[str(club["club_id"])] = now.isoformat()
    if clubs:
        await store.state_set("streams:club_sites", state)
    return added


# ---------------------------------------------------------------------------
# Przebieg i pętla
# ---------------------------------------------------------------------------


def _due(ch: dict[str, Any], now: datetime) -> bool:
    nxt = R.aware(ch.get("next_check_at"))
    return nxt is None or nxt <= now


async def run_cycle(now: Optional[datetime] = None, yt: Optional[net.YouTube] = None) -> dict[str, int]:
    global _seeded
    now = now or datetime.now(timezone.utc)
    yt = yt or net.YouTube(store.quota_take)
    counters: Counter = Counter()
    if not _seeded:
        await store.ensure_seeds()
        _seeded = True
    matches = [m for m in await store.window_matches(now, before=WINDOW_BACK, after=WINDOW_AHEAD) if not m["withdrawn"]]
    counters["changed"] += await import_zprp(matches, now)
    if _every("zprp_backfill", now, timedelta(hours=24)):
        older = await store.matches_with_stream_url(now, back=timedelta(days=30), ahead=timedelta(days=14))
        counters["changed"] += await import_zprp(older, now)
    channels = [c for c in await store.all_channels() if _due(c, now)]
    channels.sort(key=lambda c: R.aware(c.get("next_check_at")) or datetime.min.replace(tzinfo=timezone.utc))
    for ch in channels[:MAX_CHANNELS_PER_CYCLE]:
        try:
            counters["changed"] += await check_channel(ch, matches, now, yt, counters)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - jeden kanał nie zatrzymuje reszty
            log.warning("[streams] kanał %s: %s", ch.get("key"), exc, exc_info=True)
            await store.update_channel(ch["id"], last_checked_at=now, next_check_at=now + timedelta(hours=1),
                                       error=type(exc).__name__)
    if _every("refresh", now, timedelta(minutes=3) - timedelta(seconds=5)):
        counters["changed"] += await refresh_states(matches, now, yt)
    if _every("hints", now, timedelta(minutes=10)):
        counters["changed"] += await hints(matches, now, yt)
    counters["changed"] += await search(matches, now, yt)
    if _every("clubs", now, timedelta(minutes=5)):
        counters["clubs"] += await discover_clubs(matches, now, yt)
    counters["api_calls"] = yt.calls
    if counters["changed"]:
        cache.clear()
    return dict(counters)


async def run_streams_scheduler() -> None:
    """Pętla co minutę; `STREAMS_DISABLED=1` wyłącza."""
    if os.getenv("STREAMS_DISABLED", "").strip().lower() in {"1", "true", "yes", "on"}:
        log.info("[streams] pętla wyłączona przez STREAMS_DISABLED")
        return
    await asyncio.sleep(max(5, int(os.getenv("STREAMS_START_DELAY_SECONDS", "45"))))
    while True:
        try:
            async with _lock:
                await asyncio.wait_for(run_cycle(), timeout=240)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[streams] błąd przebiegu")
        await asyncio.sleep(60)
