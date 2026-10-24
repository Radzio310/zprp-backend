"""Zapisy i odczyty transmisji (baza). Reguły: `app/streams/rules.py`.

Zapisy są idempotentne (klucz: kanał `key`, transmisja `match_id + url`), więc
druga replika serwera najwyżej zmarnuje trochę limitu API, nie zdubluje danych.
Pewności ustawionej przez admina (`verified_by = admin`) pętla nie zmienia,
a ukrytego wpisu nie odkrywa.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import and_, or_, select

from app.db import (
    database,
    match_streams,
    stream_channels,
    stream_quota,
    zprp_public_clubs,
    zprp_public_competitions,
    zprp_public_matches,
    zprp_public_sync_state,
)
from app.time_pl import warsaw_now
from app.streams import rules as R
from app.streams.seeds import SEED_CHANNELS

C = stream_channels
S = match_streams
M = zprp_public_matches
COMP = zprp_public_competitions

#: Sufit dobowy jednostek API (Google daje 10 000) i wyszukiwań. Wyszukiwanie (100 j.)
#: nie może zjeść rezerwy na odświeżanie stanu transmisji (`videos.list`, 1 j.).
DAILY_UNITS = int(os.getenv("STREAMS_YT_DAILY_UNITS", "9500"))
DAILY_SEARCHES = int(os.getenv("STREAMS_YT_SEARCHES_PER_DAY", "80"))
SEARCH_RESERVE = int(os.getenv("STREAMS_YT_RESERVE_UNITS", "1500"))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _d(row: Any) -> dict[str, Any]:
    return dict(row) if row else {}


# ---------------------------------------------------------------------------
# Kanały
# ---------------------------------------------------------------------------


async def all_channels(*, active_only: bool = True) -> list[dict[str, Any]]:
    query = select(C).order_by(C.c.id)
    if active_only:
        query = query.where(C.c.active.is_(True))
    return [_d(r) for r in await database.fetch_all(query)]


async def channel_by_key(key: str) -> Optional[dict[str, Any]]:
    return _d(await database.fetch_one(select(C).where(C.c.key == key))) or None


async def channels_by_ids(ids: Iterable[Any]) -> dict[int, dict[str, Any]]:
    wanted = sorted({int(i) for i in ids if i is not None})
    if not wanted:
        return {}
    return {r["id"]: _d(r) for r in await database.fetch_all(select(C).where(C.c.id.in_(wanted)))}


async def channel_by_channel_id(channel_id: Optional[str]) -> Optional[dict[str, Any]]:
    if not channel_id:
        return None
    return _d(await database.fetch_one(select(C).where(C.c.channel_id == channel_id).order_by(C.c.id).limit(1))) or None


async def club_channels(club_ids: Iterable[Any]) -> list[dict[str, Any]]:
    ids = sorted({str(c) for c in club_ids if c})
    if not ids:
        return []
    rows = await database.fetch_all(select(C).where(C.c.club_id.in_(ids)).where(C.c.active.is_(True)).order_by(C.c.id))
    return [_d(r) for r in rows]


def _channel_values(values: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in values.items() if k in C.c and k != "id"}
    if "scope" in values:
        out["scope_json"] = json.dumps(list(values.get("scope") or []))
    return out


async def upsert_channel(values: dict[str, Any], *, overwrite: bool = False) -> dict[str, Any]:
    """Wstaw kanał albo uzupełnij istniejący (bez nadpisywania danych, chyba że `overwrite`)."""
    clean = _channel_values(values)
    existing = await channel_by_key(clean["key"])
    if not existing:
        clean.setdefault("created_at", now_utc())
        await database.execute(C.insert().values(**clean))
        return await channel_by_key(clean["key"]) or clean
    patch = {k: v for k, v in clean.items() if k != "key" and v is not None and (overwrite or existing.get(k) in (None, "", "[]"))}
    if patch:
        await database.execute(C.update().where(C.c.id == existing["id"]).values(**patch))
        existing.update(patch)
    return existing


async def update_channel(row_id: int, /, **values: Any) -> None:
    """Zmiana wiersza kanału po `id` (pozycyjnie - `channel_id` to pole kanału YouTube)."""
    clean = _channel_values(values)
    if clean:
        await database.execute(C.update().where(C.c.id == row_id).values(**clean))


async def ensure_seeds() -> None:
    for seed in SEED_CHANNELS:
        await upsert_channel({**seed, "discovered_from": "seed", "active": True})


# ---------------------------------------------------------------------------
# Transmisje
# ---------------------------------------------------------------------------

_STREAM_UPDATABLE = ("platform", "video_id", "channel_ref", "channel_title", "channel_url", "title", "thumbnail_url",
                     "state", "starts_at", "ended_at", "duration_s", "verified_by")


async def upsert_stream(values: dict[str, Any]) -> bool:
    """Wstaw/odśwież transmisję. True = coś widocznego się zmieniło."""
    now = now_utc()
    existing = _d(await database.fetch_one(select(S).where(and_(S.c.match_id == values["match_id"], S.c.url == values["url"]))))
    if not existing:
        await database.execute(S.insert().values(**{k: v for k, v in values.items() if k in S.c},
                                                 first_seen_at=now, last_seen_at=now))
        return True
    locked = existing.get("verified_by") == "admin"
    patch: dict[str, Any] = {"last_seen_at": now}
    for key in _STREAM_UPDATABLE:
        if key not in values or values[key] is None:
            continue
        if key == "verified_by" and locked:
            continue
        # Stan z RSS (zgadywany) nie nadpisuje stanu potwierdzonego przez API.
        if key == "state" and values.get("verified_by") == "rss" and existing.get("verified_by") in ("api", "admin", "zprp"):
            continue
        patch[key] = values[key]
    if values.get("confidence"):
        patch["confidence"] = R.merge_confidence(existing.get("confidence"), values["confidence"], locked=locked)
    changed = any(_norm(existing.get(k)) != _norm(v) for k, v in patch.items() if k != "last_seen_at")
    await database.execute(S.update().where(S.c.id == existing["id"]).values(**patch))
    return changed


def _norm(value: Any) -> Any:
    return R.aware(value) if isinstance(value, datetime) else value


async def streams_for(match_ids: Iterable[Any], *, include_hidden: bool = False) -> list[dict[str, Any]]:
    ids = sorted({str(m) for m in match_ids if m})
    if not ids:
        return []
    query = select(S).where(S.c.match_id.in_(ids))
    if not include_hidden:
        query = query.where(S.c.hidden.is_(False))
    return [_d(r) for r in await database.fetch_all(query)]


async def stream_by_id(stream_id: int) -> Optional[dict[str, Any]]:
    return _d(await database.fetch_one(select(S).where(S.c.id == stream_id))) or None


async def patch_stream(stream_id: int, **values: Any) -> None:
    await database.execute(S.update().where(S.c.id == stream_id).values(**values))


async def active_video_streams(match_ids: Iterable[str]) -> list[dict[str, Any]]:
    """Transmisje YouTube w stanie live/upcoming (do odświeżenia stanu przez API)."""
    ids = sorted(set(match_ids))
    if not ids:
        return []
    rows = await database.fetch_all(select(S).where(S.c.match_id.in_(ids)).where(S.c.platform == "youtube")
                                    .where(S.c.state.in_(["live", "upcoming"])).where(S.c.hidden.is_(False)))
    return [_d(r) for r in rows]


async def last_update() -> Optional[str]:
    row = await database.fetch_one(select(S.c.last_seen_at).order_by(S.c.last_seen_at.desc()).limit(1))
    dt = R.aware(row["last_seen_at"]) if row else None
    return dt.isoformat() if dt else None


async def with_channels(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Wiersze transmisji → kształt `Stream` (posortowane)."""
    channels = await channels_by_ids(r.get("channel_ref") for r in rows)
    return R.sort_streams([R.stream_view(r, channels.get(r.get("channel_ref"))) for r in rows])


async def suggested_for_match(match_id: str, exclude_video_ids: Iterable[str]) -> list[dict[str, Any]]:
    """Dla pokoju meczu panelu Mentor: YouTube, `official`/`confirmed`, bez filmów już dodanych."""
    skip = {v for v in exclude_video_ids if v}
    rows = [r for r in await streams_for([match_id]) if r.get("platform") == "youtube"
            and r.get("confidence") in ("official", "confirmed") and r.get("video_id") and r["video_id"] not in skip]
    return await with_channels(rows)


# ---------------------------------------------------------------------------
# Mecze
# ---------------------------------------------------------------------------

MATCH_COLUMNS = ("match_id", "competition_id", "competition_name", "match_code", "home_team_name", "away_team_name",
                 "home_club_id", "away_club_id", "scheduled_at", "stream_url", "withdrawn")


def _match_query():
    return (
        select(*[M.c[c] for c in MATCH_COLUMNS], COMP.c.name.label("comp_name"), COMP.c.category.label("comp_category"),
               COMP.c.gender.label("comp_gender"))
        .select_from(M.outerjoin(COMP, COMP.c.competition_id == M.c.competition_id))
    )


async def window_matches(now: datetime, *, before: timedelta, after: timedelta) -> list[dict[str, Any]]:
    """Mecze z rozpoczęciem w [now - before, now + after] jako kontekst dopasowania."""
    local = now.astimezone(R.WARSAW).replace(tzinfo=None)
    rows = await database.fetch_all(
        _match_query().where(and_(M.c.scheduled_at >= local - before, M.c.scheduled_at <= local + after))
        .order_by(M.c.scheduled_at)
    )
    return [R.match_context(_d(r)) for r in rows]


async def match_contexts(match_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    ids = sorted({str(m) for m in match_ids if m})
    if not ids:
        return {}
    rows = await database.fetch_all(_match_query().where(M.c.match_id.in_(ids)))
    return {str(r["match_id"]): R.match_context(_d(r)) for r in rows}


async def matches_with_stream_url(now: datetime, *, back: timedelta, ahead: timedelta) -> list[dict[str, Any]]:
    local = now.astimezone(R.WARSAW).replace(tzinfo=None)
    rows = await database.fetch_all(
        _match_query().where(M.c.stream_url.is_not(None)).where(M.c.stream_url != "")
        .where(and_(M.c.scheduled_at >= local - back, M.c.scheduled_at <= local + ahead))
    )
    return [R.match_context(_d(r)) for r in rows]


async def clubs_for_discovery(preferred: Iterable[str], checked: dict[str, Any], *, recheck_before: datetime,
                              limit: int) -> list[dict[str, Any]]:
    """Kluby ze stroną WWW do (ponownego) przejrzenia: najpierw grające wkrótce."""
    K = zprp_public_clubs

    def stale(club_id: str) -> bool:
        seen = checked.get(club_id)
        try:
            return not seen or datetime.fromisoformat(str(seen)) < recheck_before
        except ValueError:
            return True

    first = sorted({str(c) for c in preferred if c and stale(str(c))})
    out: list[dict[str, Any]] = []
    if first:
        rows = await database.fetch_all(select(K.c.club_id, K.c.name, K.c.website).where(K.c.club_id.in_(first))
                                        .where(K.c.website.is_not(None)))
        out = [_d(r) for r in rows if (r["website"] or "").strip()]
    if len(out) < limit:
        rows = await database.fetch_all(select(K.c.club_id, K.c.name, K.c.website).where(K.c.website.is_not(None))
                                        .where(K.c.website != "").where(K.c.archived.is_(False)).order_by(K.c.club_id))
        have = {c["club_id"] for c in out}
        out += [_d(r) for r in rows if r["club_id"] not in have and stale(str(r["club_id"]))][: limit - len(out)]
    return out[:limit]


async def competition_match_ids(competition_id: str) -> list[str]:
    rows = await database.fetch_all(select(M.c.match_id).where(M.c.competition_id == competition_id))
    return [str(r["match_id"]) for r in rows]


async def club_match_ids(club_id: str, *, since_days: int = 400) -> list[str]:
    since = warsaw_now() - timedelta(days=since_days)  # scheduled_at to naiwny czas polski
    rows = await database.fetch_all(select(M.c.match_id).where(or_(M.c.home_club_id == club_id, M.c.away_club_id == club_id))
                                    .where(M.c.scheduled_at >= since))
    return [str(r["match_id"]) for r in rows]


# ---------------------------------------------------------------------------
# Limit YouTube API
# ---------------------------------------------------------------------------


async def _quota_row(day: str) -> dict[str, Any]:
    row = _d(await database.fetch_one(select(stream_quota).where(stream_quota.c.day == day)))
    if not row:
        try:
            await database.execute(stream_quota.insert().values(day=day, units_used=0, search_calls=0, searches_json="{}",
                                                                updated_at=now_utc()))
        except Exception:  # noqa: BLE001 - wyścig dwóch zapisów: wiersz już jest
            pass
        row = _d(await database.fetch_one(select(stream_quota).where(stream_quota.c.day == day)))
    return row


async def quota_take(units: int, search: bool) -> bool:
    """Rezerwacja jednostek na dziś (doba Pacyfiku). False = limit wyczerpany."""
    day = R.pacific_day(now_utc())
    row = await _quota_row(day)
    used = int(row.get("units_used") or 0)
    calls = int(row.get("search_calls") or 0)
    if used + units > DAILY_UNITS or (search and (calls >= DAILY_SEARCHES or used + units > DAILY_UNITS - SEARCH_RESERVE)):
        return False
    await database.execute(stream_quota.update().where(stream_quota.c.day == day).values(
        units_used=used + units, search_calls=calls + (1 if search else 0), updated_at=now_utc()))
    return True


async def quota_status() -> dict[str, Any]:
    day = R.pacific_day(now_utc())
    row = await _quota_row(day)
    try:
        searched = json.loads(row.get("searches_json") or "{}")
    except ValueError:
        searched = {}
    return {"day": day, "units_used": int(row.get("units_used") or 0), "search_calls": int(row.get("search_calls") or 0),
            "searches": searched if isinstance(searched, dict) else {},
            "searches_left": max(0, DAILY_SEARCHES - int(row.get("search_calls") or 0)),
            "units_left": max(0, DAILY_UNITS - int(row.get("units_used") or 0))}


async def mark_searched(key: str) -> None:
    status = await quota_status()
    searched = status["searches"]
    searched[key] = int(searched.get(key, 0)) + 1
    await database.execute(stream_quota.update().where(stream_quota.c.day == status["day"])
                           .values(searches_json=json.dumps(searched), updated_at=now_utc()))


# ---------------------------------------------------------------------------
# Stan pętli (wspólna tabela stanu hurtowni)
# ---------------------------------------------------------------------------


async def state_get(key: str) -> dict[str, Any]:
    row = await database.fetch_one(select(zprp_public_sync_state.c.value_json).where(zprp_public_sync_state.c.key == key))
    value = row["value_json"] if row else None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            value = None
    return value if isinstance(value, dict) else {}


async def state_set(key: str, value: dict[str, Any]) -> None:
    T = zprp_public_sync_state
    exists = await database.fetch_one(select(T.c.key).where(T.c.key == key))
    if exists:
        await database.execute(T.update().where(T.c.key == key).values(value_json=value, updated_at=now_utc()))
    else:
        await database.execute(T.insert().values(key=key, value_json=value, updated_at=now_utc()))
