"""Trasy transmisji: publiczne (`/api/v1/handball`) i admina. Kontrakt: `docs/streams.md`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.admin_guard import admin_write_guard
from app.db import database, zprp_public_clubs, zprp_public_competitions, zprp_public_matches
from app.streams import cache, store
from app.streams import parsers as P
from app.streams import rules as R
from app.streams.seeds import TIER_CHANNEL, TV_LINKS

router = APIRouter(prefix="/api/v1/handball", tags=["handball_streams"])
admin_router = APIRouter(
    prefix="/api/v1/handball/admin/streams",
    tags=["handball_streams_admin"],
    dependencies=[Depends(admin_write_guard)],
)

TTL = 60.0
TTL_NOW = 30.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _updated(rows: list[dict[str, Any]]) -> Optional[str]:
    stamps = [R.aware(r.get("last_seen_at")) for r in rows if r.get("last_seen_at")]
    return max(stamps).isoformat() if stamps else None


async def _cards(match_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not match_ids:
        return {}
    from app.zprp_public import portal

    rows = await database.fetch_all(select(*portal._card_cols()).where(zprp_public_matches.c.match_id.in_(sorted(set(match_ids)))))
    return {str(c["match_id"]): c for c in await portal._cards(rows)}


async def _with_cards(streams: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards = await _cards([s["match_id"] for s in streams])
    return [{**s, "match": cards.get(str(s["match_id"]))} for s in streams if cards.get(str(s["match_id"]))]


async def _tier_channels(tier: str) -> list[dict[str, Any]]:
    key = TIER_CHANNEL.get(tier)
    row = await store.channel_by_key(key) if key else None
    return [row] if row and row.get("active", True) else []


async def _links(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    clubs = await store.club_channels([ctx.get("home_club_id"), ctx.get("away_club_id")])
    return R.where_to_watch(ctx.get("tier") or "other", await _tier_channels(ctx.get("tier") or ""), clubs, TV_LINKS)


# ---------------------------------------------------------------------------
# Publiczne
# ---------------------------------------------------------------------------


@router.get("/matches/{match_id}/streams")
async def match_streams(match_id: str) -> dict[str, Any]:
    async def build() -> dict[str, Any]:
        ctx = (await store.match_contexts([match_id])).get(match_id)
        if not ctx:
            raise HTTPException(404, "Nie znaleziono meczu")
        rows = await store.streams_for([match_id])
        return {"streams": await store.with_channels(rows), "where_to_watch": await _links(ctx), "updated_at": _updated(rows)}

    return await cache.cached(f"match:{match_id}", TTL, build)


@router.get("/streams/now")
async def streams_now() -> dict[str, Any]:
    async def build() -> dict[str, Any]:
        now = _now()
        local = now.astimezone(R.WARSAW)
        day_start = local.replace(hour=0, minute=0, second=0, microsecond=0)
        before = max(timedelta(hours=6), local - day_start)
        after = max(timedelta(hours=3), day_start + timedelta(days=1) - local)
        matches = await store.window_matches(now, before=before, after=after)
        rows = await store.streams_for([m["match_id"] for m in matches])
        streams = await store.with_channels(rows)
        live = [s for s in streams if s["state"] == "live"]
        soon_limit = (now + timedelta(hours=3)).astimezone(R.WARSAW).replace(tzinfo=None).isoformat()
        floor = (now - timedelta(minutes=30)).astimezone(R.WARSAW).replace(tzinfo=None).isoformat()
        soon = [s for s in streams if s["state"] == "upcoming" and s.get("starts_at") and floor <= s["starts_at"] <= soon_limit]
        soon.sort(key=lambda s: s["starts_at"])
        today = [m for m in matches if m.get("kickoff") and m["kickoff"].astimezone(R.WARSAW).date() == local.date()
                 and TV_LINKS.get(m.get("tier") or "")]
        cards = await _cards([s["match_id"] for s in live + soon] + [m["match_id"] for m in today])
        return {
            "live": [{**s, "match": cards[s["match_id"]]} for s in live if s["match_id"] in cards],
            "soon": [{**s, "match": cards[s["match_id"]]} for s in soon if s["match_id"] in cards],
            "today_tv": [{"match": cards[m["match_id"]], "links": [dict(link) for link in TV_LINKS[m["tier"]]]}
                         for m in sorted(today, key=lambda m: m["kickoff"]) if m["match_id"] in cards],
            "updated_at": _updated(rows),
        }

    return await cache.cached("now", TTL_NOW, build)


@router.get("/competitions/{competition_id}/streams")
async def competition_streams(competition_id: str) -> dict[str, Any]:
    async def build() -> dict[str, Any]:
        comp = await database.fetch_one(
            select(zprp_public_competitions.c.name, zprp_public_competitions.c.category)
            .where(zprp_public_competitions.c.competition_id == competition_id))
        if not comp:
            raise HTTPException(404, "Nie znaleziono rozgrywek")
        tier = R.competition_tier(comp["name"], "", comp["category"])
        streams = await store.with_channels(await store.streams_for(await store.competition_match_ids(competition_id)))
        recent = sorted([s for s in streams if s["state"] == "vod"], key=lambda s: s.get("starts_at") or "", reverse=True)[:12]
        upcoming = sorted([s for s in streams if s["state"] in ("live", "upcoming")],
                          key=lambda s: (s["state"] != "live", s.get("starts_at") or ""))[:12]
        return {"where_to_watch": R.where_to_watch(tier, await _tier_channels(tier), [], TV_LINKS),
                "recent": await _with_cards(recent), "upcoming": await _with_cards(upcoming)}

    return await cache.cached(f"comp:{competition_id}", TTL, build)


@router.get("/clubs/{club_id}/streams")
async def club_streams(club_id: str) -> dict[str, Any]:
    async def build() -> dict[str, Any]:
        club = await database.fetch_one(select(zprp_public_clubs.c.club_id).where(zprp_public_clubs.c.club_id == club_id))
        if not club:
            raise HTTPException(404, "Nie znaleziono klubu")
        channels = [R.public_channel(c) for c in await store.club_channels([club_id])]
        streams = await store.with_channels(await store.streams_for(await store.club_match_ids(club_id)))
        streams = [s for s in streams if s["platform"] == "youtube" or s["state"] != "link"]
        recent = sorted(streams, key=lambda s: (s["state"] == "live", s.get("starts_at") or ""), reverse=True)[:8]
        return {"channels": channels, "recent": await _with_cards(recent)}

    return await cache.cached(f"club:{club_id}", TTL, build)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------


class ChannelBody(BaseModel):
    url: Optional[str] = Field(default=None, max_length=500)
    channel_id: Optional[str] = Field(default=None, max_length=40)
    handle: Optional[str] = Field(default=None, max_length=60)
    playlist_id: Optional[str] = Field(default=None, max_length=60)
    title: Optional[str] = Field(default=None, max_length=200)
    club_id: Optional[str] = Field(default=None, max_length=40)
    association_id: Optional[str] = Field(default=None, max_length=40)
    kind: Optional[Literal["official", "club", "producer", "broadcaster", "tv"]] = None
    scope: Optional[list[str]] = None
    verified: Optional[bool] = None
    active: Optional[bool] = None


class StreamPatch(BaseModel):
    hidden: Optional[bool] = None
    confidence: Optional[Literal["official", "confirmed", "possible"]] = None


def channel_identity(body: ChannelBody) -> dict[str, Any]:
    """Treść formularza admina → `key`, platforma i pola kanału (422, gdy nic z tego nie wynika)."""
    parts = P.youtube_url_parts(body.url or "") if body.url else {}
    channel_id = body.channel_id or parts.get("channel_id")
    playlist_id = body.playlist_id or parts.get("playlist_id")
    handle = body.handle or parts.get("handle")
    if handle and not handle.startswith("@"):
        handle = "@" + handle
    url = (body.url or "").strip() or None
    if channel_id:
        return {"key": f"youtube:{channel_id}", "platform": "youtube", "channel_id": channel_id, "handle": handle,
                "url": url or f"https://www.youtube.com/channel/{channel_id}"}
    if playlist_id:
        return {"key": f"youtube-playlist:{playlist_id}", "platform": "youtube", "playlist_id": playlist_id,
                "url": url or f"https://www.youtube.com/playlist?list={playlist_id}"}
    if handle:
        return {"key": f"youtube:{handle.lower()}", "platform": "youtube", "handle": handle,
                "url": url or f"https://www.youtube.com/{handle}"}
    if url and ("facebook.com/" in url.lower() or "fb.com/" in url.lower()):
        return {"key": f"facebook:{url.lower().rstrip('/')}", "platform": "facebook", "url": url.rstrip("/")}
    if url and (body.kind == "tv"):
        return {"key": f"web:{url.lower().rstrip('/')}", "platform": "web", "url": url}
    raise HTTPException(422, "Podaj adres kanału YouTube (kanał, @uchwyt albo playlistę) lub strony Facebook")


@admin_router.get("/channels")
async def admin_channels() -> dict[str, Any]:
    rows = await store.all_channels(active_only=False)
    return {"channels": [R.admin_channel(r) for r in rows], "quota": await store.quota_status()}


@admin_router.post("/channels")
async def admin_add_channel(body: ChannelBody) -> dict[str, Any]:
    ident = channel_identity(body)
    if ident.get("channel_id"):
        existing = await store.channel_by_channel_id(ident["channel_id"])
        if existing:
            ident["key"] = existing["key"]
    values: dict[str, Any] = {**ident, "next_check_at": None}
    for name in ("title", "club_id", "association_id", "kind", "verified", "active"):
        value = getattr(body, name)
        if value is not None:
            values[name] = value
    if body.scope is not None:
        values["scope"] = [str(s).strip() for s in body.scope if str(s).strip()][:10]
    if not await store.channel_by_key(values["key"]):
        values.setdefault("kind", "club" if body.club_id else "broadcaster")
        values.setdefault("discovered_from", "admin")
    row = await store.upsert_channel(values, overwrite=True)
    await store.update_channel(row["id"], next_check_at=None, error=None)  # sprawdzić w najbliższym przebiegu
    cache.clear()
    return R.admin_channel(await store.channel_by_key(values["key"]) or row)


@admin_router.patch("/{stream_id}")
async def admin_patch_stream(stream_id: int, body: StreamPatch) -> dict[str, Any]:
    row = await store.stream_by_id(stream_id)
    if not row:
        raise HTTPException(404, "Nie znaleziono transmisji")
    patch: dict[str, Any] = {}
    if body.hidden is not None:
        patch["hidden"] = body.hidden
    if body.confidence is not None:
        patch["confidence"] = body.confidence
        patch["verified_by"] = "admin"
    if patch:
        await store.patch_stream(stream_id, **patch)
        cache.clear()
    fresh = await store.stream_by_id(stream_id) or row
    channels = await store.channels_by_ids([fresh.get("channel_ref")])
    return {**R.stream_view(fresh, channels.get(fresh.get("channel_ref"))), "hidden": bool(fresh.get("hidden"))}
