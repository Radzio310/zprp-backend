"""Trybuna Mentora - obserwowani sędziowie, kanał, kalendarz, kolejka „Do obejrzenia", karta sędziego, szukanie i dzienny push.

Kontrakt: `docs/mentor-panel.md` 8.11. Sprawy użytkownika (obserwowani, kolejka, kanał) używają PRAWDZIWEGO aktora (`base_actor`):
`act_as` nie pożycza cudzych obserwowanych ani cudzego połączenia z Bastionem. Meczotekę czyta wyłącznie sesja connectora
(`GET /games/search`), z pamięcią wyników ~10 min i limitem zapytań na użytkownika (`mentor_bastion_search.Meczoteka`).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, update

from app import mentor_bastion_rules as BR
from app import mentor_bastion_search as S
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import mentor_trybuna_rules as T
from app.db import (
    database,
    match_streams,
    mentor_clips,
    mentor_match_videos,
    mentor_trybuna_clip_tags,
    mentor_trybuna_feed_cache,
    mentor_trybuna_follows,
    mentor_trybuna_notified,
    mentor_trybuna_today,
    mentor_trybuna_queue,
    mentor_watched_matches,
    province_judges,
    saved_matches,
    zprp_public_matches,
)
from app.mentor_panel_auth import base_actor, mentor_actor
from app.streams.rules import WARSAW

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Trybuna"])
Actor = C.MentorActor
F = mentor_trybuna_follows
Q = mentor_trybuna_queue
W = mentor_watched_matches

#: Ile obserwowanych odpytujemy w jednym kanale (reszta w `truncated`) i ile pozycji kanał oddaje.
FEED_FOLLOWS = 12
FEED_ITEMS = 60
FEED_CONCURRENCY = 3
#: Dzienny push: odstęp pętli, okno „nowego" meczu i najwięcej obserwowanych odpytanych w jednym przebiegu.
NOTIFY_EVERY_S = 24 * 3600
NOTIFY_WINDOW_DAYS = 3
NOTIFY_MAX_REFEREES = 40


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else (R.s(value) or None)


def _naive_local_now() -> datetime:
    return datetime.now(WARSAW).replace(tzinfo=None)


def raise_stop(real: Actor, stop: "S._Stop") -> None:
    """Błąd Bastionu w kopercie jak `playback` (nigdy 401): 409 / 403 / 503 / 429 + `connections`."""
    from app.mentor_bastion import _playback_failure

    exc = _playback_failure(BR.load_flags(), real, stop.verdicts)
    kind = S.CODE_KIND.get(exc.detail.get("code"), "unavailable")
    exc.detail["message"] = S.STATE_MESSAGES[kind]
    raise exc from None


def bastion_block(state: str, scope: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    message = None if state == "ok" else S.bastion_state_message(state)
    return {"state": state, "message": message, "scope": scope, **extra}


async def stop_state(stop: "S._Stop") -> str:
    kinds = [v.kind for _, v in stop.verdicts]
    return next((k for k in ("rate_limited", "unavailable", "forbidden") if k in kinds), "auth_required")


# ─── Szukanie (po sędzi, drużynie, kodzie) ──────────────────────────────────


def game_time_known(game: Mapping[str, Any]) -> bool:
    """Godzina 00:00:00 przy meczu bez terminu (`unscheduled`) to brak godziny."""
    return not (game.get("unscheduled") or R.s(game.get("date")).endswith("00:00:00"))


def is_upcoming(game: Mapping[str, Any], today) -> bool:
    day = S.parse_day(game.get("date"))
    return bool(game.get("unscheduled")) or day is None or day > today


def game_row(game: Mapping[str, Any], watched: Mapping[int, str]) -> Dict[str, Any]:
    item = int(game["bunny_item_id"]) if game.get("bunny_item_id") else None
    keep = ("title", "home", "away", "date", "competition", "code", "score", "video_state", "video_coverage", "duration_s")
    return {"bunny_item_id": item, "game_id": game.get("game_id"), "url": BR.canonical_game_url(item) if item else None,
            "thumbnail_url": game.get("thumbnail_url"), **{k: game.get(k) for k in keep},
            "referees": T.clean_referees(game.get("referees") or []), "state": T.feed_state(game.get("video_state")),
            "unscheduled": bool(game.get("unscheduled")), "time_known": game_time_known(game),
            "added": bool(item and item in watched), "match_id": watched.get(item) if item else None}


async def watched_by_item(pair_ids: List[str], items: List[int]) -> Dict[Tuple[str, int], str]:
    if not pair_ids or not items:
        return {}
    found = await C.rows(select(W.c.pair_id, W.c.match_id, W.c.bunny_item_id).where(W.c.pair_id.in_(pair_ids))
                         .where(W.c.bunny_item_id.in_(items)).where(W.c.deleted_at.is_(None)))
    return {(r["pair_id"], int(r["bunny_item_id"])): r["match_id"] for r in found}


class SearchBody(BaseModel):
    q: Optional[str] = Field(default=None, max_length=80)
    #: Imię i nazwisko sędziego (Meczoteka szuka po sędzi; parametr portalu: `REFEREE_PARAM`, do potwierdzenia próbą).
    referee: Optional[str] = Field(default=None, max_length=80)
    video: str = Field(default="any", pattern="^(with|any)$")
    offset: int = Field(default=0, ge=0, le=500)
    #: Filtr czasu (czas polski): dzień = date_from == date_to; godziny opcjonalne (okno przez północ: od > do).
    date_from: Optional[str] = Field(default=None, max_length=10)
    date_to: Optional[str] = Field(default=None, max_length=10)
    time_from: Optional[str] = Field(default=None, max_length=5)
    time_to: Optional[str] = Field(default=None, max_length=5)


MAX_RANGE_DAYS = 366
DAYS_MAX = 62
DAYS_CACHE_S = 600.0
_days_cache: Dict[Tuple[Any, ...], Tuple[float, Dict[str, Any]]] = {}


def parse_range(date_from: Any, date_to: Any, time_from: Any, time_to: Any):
    """(d_from, d_to, t_from, t_to) z napisów albo 422 `BAD_DATE` / `BAD_TIME` / `RANGE_TOO_LONG`."""
    def day(v: Any) -> Optional[date]:
        v = R.s(v)
        if not v:
            return None
        try:
            return date.fromisoformat(v)
        except ValueError:
            raise C.err(422, "BAD_DATE", "Data ma postać RRRR-MM-DD.") from None

    d_from, d_to = day(date_from), day(date_to)
    if d_from and d_to and d_from > d_to:
        raise C.err(422, "BAD_DATE", "Data początkowa jest późniejsza niż końcowa.")
    if d_from and d_to and (d_to - d_from).days > MAX_RANGE_DAYS:
        raise C.err(422, "RANGE_TOO_LONG", f"Zakres dat może mieć najwyżej {MAX_RANGE_DAYS} dni.")
    t_from = S.parse_hm(time_from) if R.s(time_from) else None
    t_to = S.parse_hm(time_to) if R.s(time_to) else None
    if (R.s(time_from) and t_from is None) or (R.s(time_to) and t_to is None):
        raise C.err(422, "BAD_TIME", "Godzina ma postać GG:MM.")
    return d_from, d_to, t_from, t_to


@router.post("/pairs/{pair_id}/trybuna/search")
async def trybuna_search(pair_id: str, body: SearchBody, response: Response, real: Actor = Depends(base_actor),
                         acting: Actor = Depends(mentor_actor)):
    """Szukanie kaset w Meczotece po sędzi (`referee`) albo tekście (`q`: drużyna, kod, data). Odpowiedź: `games` z `added`/`match_id`
    (czy mecz jest już w Trybunie tej pary), `next_offset` (kolejna strona, gdy ta była pełna). Pamięć wyników ~10 min, limit
    zapytań na użytkownika. Błędy Bastionu jak przy `playback` (409/403/503/429, nigdy 401)."""
    from app.mentor_bastion import berr

    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, acting)
    C.check(ctx, "video")
    q, referee = R.s(body.q), R.s(body.referee)
    d_from, d_to, t_from, t_to = parse_range(body.date_from, body.date_to, body.time_from, body.time_to)
    ranged = bool(d_from or d_to or t_from is not None or t_to is not None)
    if not q and not referee and not ranged:
        raise berr(422, "BAD_QUERY", "Wpisz nazwisko sędziego, nazwę drużyny, kod albo datę meczu.")
    if any(ord(ch) < 32 for ch in q + referee):
        raise berr(422, "BAD_QUERY", "Wpisz nazwisko sędziego, nazwę drużyny, kod albo datę meczu.")
    mz, state = S._setup(real)
    if state == "disabled":
        raise berr(404, "BASTION_DISABLED", S.DISABLED_MESSAGE)
    if state == "unconfigured" or mz is None:
        raise berr(503, "BASTION_UNAVAILABLE", S.UNCONFIGURED_MESSAGE)
    meta = None
    try:
        if ranged:
            # Przegląd okresu z tekstem albo sędzią: strony po 50 (do 10), daty i godziny filtrowane po stronie BAZY.
            games, meta = await mz.scan(q=q, referee=referee, video=body.video, d_from=d_from, d_to=d_to, t_from=t_from, t_to=t_to)
            games = games[:100]
        else:
            games = await (mz.search_referee(referee, video=body.video, offset=body.offset) if referee else mz.search(q))
    except S._Stop as stop:
        raise_stop(real, stop)
    if not ranged:
        games = [g for g in games if g.get("bunny_item_id")]
    watched = await watched_by_item([ctx["pair_id"]], [int(g["bunny_item_id"]) for g in games if g.get("bunny_item_id")])
    by_item = {item: mid for (_, item), mid in watched.items()}
    rows = [game_row(g, by_item) for g in games]
    await S.enrich_media(real, mz.scope, rows)
    out = {"games": rows, "offset": body.offset,
           "next_offset": None if ranged else (body.offset + S.PAGE if len(games) >= S.PAGE else None),
           "connection_scope": mz.scope, "query": {"q": q or None, "referee": referee or None}}
    if meta is not None:
        out["range"] = {"date_from": d_from.isoformat() if d_from else None, "date_to": d_to.isoformat() if d_to else None,
                        "time_from": R.s(body.time_from) or None, "time_to": R.s(body.time_to) or None, "pages": meta["pages"],
                        "truncated": meta["truncated"], "local_filter": meta["local_filter"]}
    return out


@router.get("/pairs/{pair_id}/trybuna/youtube")
async def trybuna_youtube(pair_id: str, q: str = Query("", max_length=80), date_from: str = Query("", max_length=10),
                          date_to: str = Query("", max_length=10), time_from: str = Query("", max_length=5),
                          time_to: str = Query("", max_length=5), actor: Actor = Depends(mentor_actor)):
    """Wyniki YouTube do dodania: transmisje, które portal już zna (kanały klubów i ZPRP), po tytule. Bez jednostek z puli dobowej;
    cokolwiek innego z YouTube wchodzi wklejonym linkiem."""
    ctx = await C.pair_context(pair_id, actor)
    C.check(ctx, "video")
    words = [w for w in T.name_key(q).split() if len(w) >= 3][:4]
    d_from, d_to, t_from, t_to = parse_range(date_from, date_to, time_from, time_to)
    since = datetime.now(timezone.utc) - timedelta(days=120)
    if d_from:
        since = min(since, datetime(d_from.year, d_from.month, d_from.day, tzinfo=timezone.utc) - timedelta(days=1))
    query = (select(match_streams).where(match_streams.c.platform == "youtube").where(match_streams.c.hidden.is_(False))
             .where(match_streams.c.last_seen_at >= since).order_by(match_streams.c.starts_at.desc()).limit(300))
    found = await C.rows(query)
    out, seen = [], set()
    for s in found:
        hay = T.name_key(f"{s.get('title') or ''} {s.get('channel_title') or ''}")
        if words and not all(w in hay for w in words):
            continue
        vid = R.s(s.get("video_id"))
        if not vid or vid in seen:
            continue
        starts = s.get("starts_at")
        local = starts.astimezone(WARSAW).strftime("%Y-%m-%d %H:%M:%S") if isinstance(starts, datetime) else None
        # Ten sam filtr czasu co dla Bastionu; transmisja bez godziny startu przechodzi filtr godzin jako "godzina nieznana".
        if not S.in_range({"date": local, "unscheduled": local is None}, d_from, d_to, t_from, t_to):
            continue
        seen.add(vid)
        out.append({"video_id": vid, "url": s.get("url"), "title": s.get("title"),
                    "thumbnail_url": s.get("thumbnail_url") or f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg",
                    "thumbnail_maxres_url": f"https://i.ytimg.com/vi/{vid}/maxresdefault.jpg", "duration_s": s.get("duration_s"),
                    "channel": s.get("channel_title"), "starts_at": _iso(s.get("starts_at")), "published_at": _iso(s.get("starts_at") or s.get("first_seen_at")),
                    "confidence": s.get("confidence"), "official": s.get("confidence") in ("official", "confirmed"),
                    "zprp_match_id": s.get("match_id")})
        if len(out) >= 20:
            break
    return {"streams": out, "query": q or None, "range": {"date_from": d_from.isoformat() if d_from else None,
            "date_to": d_to.isoformat() if d_to else None, "time_from": time_from or None, "time_to": time_to or None}}


# ─── Obserwowani ────────────────────────────────────────────────────────────


async def resolve_judge(name: str) -> Optional[str]:
    """Numer sędziego z listy sędziów po nazwisku, gdy jest jednoznaczny; inaczej None."""
    key = T.name_key(name)
    parts = key.split()
    if not parts:
        return None
    try:
        found = await C.rows(select(province_judges.c.judge_id, province_judges.c.full_name)
                             .where(province_judges.c.full_name.ilike(f"%{max(parts, key=len)}%")).limit(60))
    except Exception:  # noqa: BLE001
        return None
    same = {R.s(r["judge_id"]) for r in found if T.name_key(r.get("full_name")) == key}
    return same.pop() if len(same) == 1 else None


class FollowBody(BaseModel):
    kind: str = Field(default="referee", pattern="^(referee|pair|delegate)$")
    name: Optional[str] = Field(default=None, max_length=80)
    judge_id: Optional[str] = Field(default=None, max_length=20)
    #: Para: dwie nazwy i (opcjonalnie) dwa numery.
    names: Optional[List[str]] = Field(default=None, max_length=2)
    judge_ids: Optional[List[str]] = Field(default=None, max_length=2)


async def my_follows(judge_id: str) -> List[Dict[str, Any]]:
    return [T.follow_shape(r) for r in await C.rows(select(F).where(F.c.judge_id == judge_id).order_by(F.c.created_at.asc()))]


@router.get("/trybuna/follows")
async def list_follows(real: Actor = Depends(base_actor)):
    return {"follows": await my_follows(real.judge_id), "limit": T.MAX_FOLLOWS}


@router.post("/trybuna/follows")
async def follow(body: FollowBody, real: Actor = Depends(base_actor)):
    """Obserwuj sędziego albo parę. Numer sędziego uzupełniamy z listy sędziów, gdy nazwisko jest jednoznaczne.
    Powtórka zwraca istniejący wpis (`created:false`)."""
    names = [R.plain(n, 80) for n in (body.names or ([body.name] if body.name else [])) if R.plain(n, 80)]
    want = 2 if body.kind == "pair" else 1
    if len(names) != want:
        raise C.err(422, "FOLLOW_NAMES", "Podaj nazwisko sędziego (dla pary: dwa nazwiska).")
    ids = [R.s(i) for i in (body.judge_ids or ([body.judge_id] if body.judge_id else []))]
    ids = (ids + [""] * want)[:want]
    for i, nm in enumerate(names):
        if not ids[i]:
            ids[i] = await resolve_judge(nm) or ""
    key = T.follow_key(body.kind, ids, names)
    mine = await C.rows(select(F).where(F.c.judge_id == real.judge_id))
    for row in mine:
        if row["kind"] == body.kind and row["ref_key"] == key:
            return {"follow": T.follow_shape(row), "created": False, "follows": await my_follows(real.judge_id)}
    if len(mine) >= T.MAX_FOLLOWS:
        raise C.err(422, "FOLLOW_LIMIT", f"Możesz obserwować najwyżej {T.MAX_FOLLOWS} sędziów i par.")
    row = {"id": R.new_id(), "judge_id": real.judge_id, "kind": body.kind, "ref_key": key, "name": " + ".join(names),
           "judge_ids": C.dumps([i for i in ids if i]), "names": C.dumps(names), "created_at": C.now()}
    await database.execute(F.insert().values(**row))
    return {"follow": T.follow_shape(row), "created": True, "follows": await my_follows(real.judge_id)}


@router.delete("/trybuna/follows/{follow_id}")
async def unfollow(follow_id: str, real: Actor = Depends(base_actor)):
    row = await C.one(select(F).where(F.c.id == follow_id).where(F.c.judge_id == real.judge_id))
    if not row:
        raise C.err(404, "NOT_FOUND", "Nie obserwujesz takiego sędziego.")
    await database.execute(F.delete().where(F.c.id == follow_id))
    return {"ok": True, "follows": await my_follows(real.judge_id)}


# ─── Kanał „Nowe od obserwowanych" ──────────────────────────────────────────


def follow_names(follow: Mapping[str, Any]) -> List[str]:
    return list(follow.get("names") or []) or [R.s(follow.get("name"))]


async def zprp_rows_for(follows: List[Dict[str, Any]], start: datetime, end: datetime) -> List[Dict[str, Any]]:
    """Mecze z obsady ZPRP w oknie czasu (czas lokalny bez strefy), w których jest ktoś z obserwowanych."""
    M = zprp_public_matches
    conds = []
    for delegate in (False, True):
        group = [f for f in follows if (f["kind"] == "delegate") == delegate]
        ids = sorted({i for f in group for i in f.get("judge_ids") or []})
        c1, c2 = (M.c.delegate_1_id, M.c.delegate_2_id) if delegate else (M.c.referee_1_id, M.c.referee_2_id)
        n1, n2 = (M.c.delegate_1_name, M.c.delegate_2_name) if delegate else (M.c.referee_1_name, M.c.referee_2_name)
        if ids:
            conds += [c1.in_(ids), c2.in_(ids)]
        for f in group:
            if len(f.get("judge_ids") or []) < len(follow_names(f)):
                for nm in follow_names(f):
                    word = max(T.name_key(nm).split() or [""], key=len)
                    if len(word) >= 3:
                        conds += [n1.ilike(f"%{word}%"), n2.ilike(f"%{word}%")]
    if not conds:
        return []
    try:
        found = await C.rows(select(M).where(or_(*conds)).where(M.c.scheduled_at >= start).where(M.c.scheduled_at < end)
                             .order_by(M.c.scheduled_at.desc()).limit(400))
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: odczyt obsady ZPRP nieudany", exc_info=True)
        return []
    keep = []
    for r in found:
        refs = T.referees_of_zprp_row(r)
        if any(T.follow_matches(f, refs) for f in follows):
            keep.append(r)
    return keep


def match_game_to_zprp(game: Mapping[str, Any], cards: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Najlepszy mecz ZPRP dla kasety (pewność >= 75 i bez konfliktu kategorii) albo None."""
    best, best_score = None, 0
    for row, card in cards:
        scored = S.score_game(game, card)
        if scored["confidence"] > best_score:
            best, best_score = row, scored["confidence"]
    return best if best_score >= T.AUTO_MIN else None


async def build_feed(real: Actor, follows: List[Dict[str, Any]], days: int, *, retry_429: bool = False) -> Dict[str, Any]:
    start_day, end_day = T.feed_window(days)
    truncated = max(0, len(follows) - FEED_FOLLOWS)
    follows = follows[:FEED_FOLLOWS]
    start = datetime(start_day.year, start_day.month, start_day.day)
    end = datetime(end_day.year, end_day.month, end_day.day) + timedelta(days=1)
    zrows = await zprp_rows_for(follows, start, end) if follows else []
    cards = [(r, R.card_from_public(r)) for r in zrows]

    bastion = bastion_block("ok")
    games: List[Dict[str, Any]] = []
    mz, state = S._setup(real) if follows else (None, None)
    if follows and mz is None:
        bastion = bastion_block(state or "unconfigured")
    elif mz is not None:
        mz.retry_429 = retry_429
        gate = asyncio.Semaphore(FEED_CONCURRENCY)
        halted: List[str] = []
        names: List[Tuple[str, str]] = []
        for f in follows:
            for nm in follow_names(f):
                role = "delegate" if f["kind"] == "delegate" else "referee"
                if (T.name_key(nm), role) not in {(T.name_key(x), r) for x, r in names}:
                    names.append((nm, role))

        async def one(pair: Tuple[str, str]) -> None:
            name, role = pair
            if halted:
                return
            async with gate:
                if halted:
                    return
                try:
                    found = await mz.search_referee(name, video="any", role=role)
                except S._Stop as stop:
                    halted.append(await stop_state(stop))
                    return
                for g in found:
                    g = dict(g)
                    g.setdefault("referees", [])
                    games.append(g)

        if names:
            await one(names[0])  # pierwsze zapytanie ustala połączenie (domyślne/osobiste)
            if not halted:
                await asyncio.gather(*(one(n) for n in names[1:]))
        bastion = bastion_block(halted[0] if halted else "ok", mz.scope, partial=bool(halted and games))

    # Wiersze Meczoteki w oknie dat, bez powtórzeń (kaseta po numerze nagrania, mecz bez nagrania po numerze meczu portalu).
    seen_items: Dict[Any, Dict[str, Any]] = {}
    for g in games:
        day = S.parse_day(g.get("date"))
        if day is None or day < start_day or day > end_day or g.get("unscheduled"):
            continue  # przyszłe i bez terminu mecze idą do kalendarza, nie do kanału
        ident = g.get("bunny_item_id") or (f"g{g['game_id']}" if g.get("game_id") else None)
        if ident is None:
            continue
        seen_items.setdefault(ident, g)

    items: List[Dict[str, Any]] = []
    used_items: set = set()
    for row, card in cards:
        game = next((g for g in seen_items.values() if S.score_game(g, card)["confidence"] >= T.AUTO_MIN), None)
        refs = T.referees_of_zprp_row(row)
        if game:
            used_items.add(game.get("bunny_item_id") or f"g{game.get('game_id')}")
        items.append(_feed_item(card, row["match_id"], refs, game, follows))
    for ident, g in seen_items.items():
        if ident in used_items:
            continue
        refs = T.clean_referees(g.get("referees") or [])
        if match_game_to_zprp(g, cards) is not None:
            continue
        # Wiersz nieznany w obsadzie ZPRP: pokazujemy go, gdy obsada z portalu (`nominees`) wskazuje obserwowanego albo
        # portal nie niesie obsady wcale (wtedy zapytanie po nazwisku jest jedynym dowodem; q trafia też w drużyny).
        matched = [f for f in follows if T.follow_matches(f, refs)] if refs else [f for f in follows if f["kind"] == "referee"]
        if not matched:
            continue
        card = T.card_from_snapshot(f"bastion-{ident}", T.snapshot_from_game(g))
        items.append(_feed_item(card, None, refs, g, follows))
    items.sort(key=lambda i: R.s(i.get("date")), reverse=True)
    items = items[:FEED_ITEMS]
    # Gdzie ten mecz już jest w Trybunie moich par.
    if mz is not None:
        await S.enrich_media(real, mz.scope, [i["bastion"] for i in items if i.get("bastion")])
    await S.attach_crests(items)
    await fill_watched_in(real, items)
    return {"items": items, "follows": len(follows), "truncated": truncated, "window": {"from": start_day.isoformat(), "to": end_day.isoformat()},
            "zprp": bool(zrows) or bool(follows), "bastion": bastion}


def _feed_item(card: Mapping[str, Any], zprp_id: Optional[str], refs: List[Dict[str, Any]], game: Optional[Mapping[str, Any]],
               follows: List[Dict[str, Any]]) -> Dict[str, Any]:
    has_video = bool(game and game.get("bunny_item_id"))
    state = T.feed_state((game or {}).get("video_state")) if has_video else "waiting"
    when = card.get("scheduled_at")
    return {
        "key": f"bastion:{game['bunny_item_id']}" if has_video else f"game:{game.get('game_id')}" if game and game.get("game_id") else f"zprp:{zprp_id}",
        "date": _iso(when), "home": (card.get("home") or {}).get("name"), "away": (card.get("away") or {}).get("name"),
        "score": [(card.get("home") or {}).get("score"), (card.get("away") or {}).get("score")],
        "competition": card.get("competition_name"), "code": card.get("match_code"), "zprp_match_id": zprp_id,
        "referees": refs or T.clean_referees((game or {}).get("referees") or []),
        "followed": [f["id"] for f in follows if T.follow_matches(f, refs or T.clean_referees((game or {}).get("referees") or []))],
        "state": state,  # "video" = jest nagranie, "waiting" = czeka na nagranie
        "bastion": ({"bunny_item_id": int(game["bunny_item_id"]), "url": BR.canonical_game_url(int(game["bunny_item_id"])),
                     "video_state": game.get("video_state"), "title": game.get("title"),
                     "thumbnail_url": game.get("thumbnail_url"), "duration_s": game.get("duration_s")} if has_video else None),
        "video_state": (game or {}).get("video_state"),
    }


async def _my_pairs(real: Actor) -> List[Dict[str, Any]]:
    from app.mentor_panel import accessible_pairs

    try:
        return await accessible_pairs(real)
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: lista par nieczytelna", exc_info=True)
        return []


FEED_REFRESH_S = 30 * 60
FEED_STALE_S = 40 * 60
FEED_FORCE_MIN_S = 120
FC = mentor_trybuna_feed_cache
_refreshing: set = set()


async def load_feed_cache(judge_id: str) -> Optional[Dict[str, Any]]:
    row = await C.one(select(FC).where(FC.c.judge_id == judge_id))
    if not row:
        return None
    payload = R.json_value(row.get("payload_json"), {})
    return {"payload": payload, "computed_at": R.aware(row.get("computed_at"))}


async def refresh_feed(real: Actor) -> None:
    """Liczy kanał obserwowanych (14 dni, wszyscy obserwowani) i trzyma go w bazie. Jedno liczenie na osobę naraz."""
    if real.judge_id in _refreshing:
        return
    _refreshing.add(real.judge_id)
    try:
        follows = await my_follows(real.judge_id)
        payload = await build_feed(real, follows, 14, retry_429=True) if follows else {
            "items": [], "follows": 0, "truncated": 0, "window": None, "zprp": False, "bastion": bastion_block("ok")}
        text = C.dumps(payload)
        await database.execute(FC.delete().where(FC.c.judge_id == real.judge_id))
        await database.execute(FC.insert().values(judge_id=real.judge_id, payload_json=text, computed_at=C.now()))
    except Exception:  # noqa: BLE001 - kanał w tle nie może zabić pętli ani odpowiedzi
        logger.warning("trybuna: liczenie kanału nieudane", exc_info=True)
    finally:
        _refreshing.discard(real.judge_id)


def kick_refresh(real: Actor) -> bool:
    if real.judge_id in _refreshing:
        return False
    asyncio.ensure_future(refresh_feed(real))
    return True


async def fill_watched_in(real: Actor, items: List[Dict[str, Any]]) -> None:
    pair_ids = [p["id"] for p in await _my_pairs(real)]
    got = await watched_by_item(pair_ids, [i["bastion"]["bunny_item_id"] for i in items if i.get("bastion")])
    for i in items:
        b = i.get("bastion")
        i["watched_in"] = [{"pair_id": pid, "match_id": mid} for (pid, item), mid in got.items() if b and item == b["bunny_item_id"]]


@router.get("/trybuna/feed")
async def feed(response: Response, days: int = Query(14, ge=1, le=60), follow_id: str = Query("", max_length=40),
               refresh: int = Query(0, ge=0, le=1), real: Actor = Depends(base_actor)):
    """„Nowe od obserwowanych". Domyślny kanał (14 dni, wszyscy obserwowani) jest liczony w tle co 30 min i trzymany w bazie: odpowiedź
    wraca od razu `{items, ..., computed_at, refreshing}`. Brak zapisu albo starszy niż 40 min uruchamia liczenie (`refreshing:true`,
    przy pierwszym razie `items` puste); `?refresh=1` wymusza liczenie nie częściej niż co 2 min. Inne `days` / `follow_id` są liczone
    na żywo. `state`: `video` (jest nagranie) albo `waiting` (czeka na nagranie). `bastion.state` mówi, czy Meczoteka odpowiedziała."""
    response.headers["Cache-Control"] = "no-store"
    follows = await my_follows(real.judge_id)
    if not follows or (follow_id and not any(f["id"] == follow_id for f in follows)):
        return {"items": [], "follows": 0, "truncated": 0, "window": None, "zprp": False, "bastion": bastion_block("ok"),
                "computed_at": None, "refreshing": False}
    if follow_id or days != 14:
        live = await build_feed(real, [f for f in follows if not follow_id or f["id"] == follow_id], days)
        return {**live, "computed_at": C.now().isoformat(), "refreshing": False}
    cached = await load_feed_cache(real.judge_id)
    age = (C.now() - cached["computed_at"]).total_seconds() if cached and cached["computed_at"] else None
    started = False
    if cached is None or age is None or age > FEED_STALE_S or (refresh and age > FEED_FORCE_MIN_S):
        started = kick_refresh(real)
    if cached is None:
        return {"items": [], "follows": len(follows), "truncated": 0, "window": None, "zprp": False, "bastion": bastion_block("ok"),
                "computed_at": None, "refreshing": started or real.judge_id in _refreshing}
    payload = dict(cached["payload"])
    await fill_watched_in(real, payload.get("items") or [])
    payload["follows"] = len(follows)
    payload["computed_at"] = cached["computed_at"].isoformat()
    payload["refreshing"] = started or real.judge_id in _refreshing
    return payload


async def run_trybuna_feed_refresher() -> None:
    """Co 30 min liczy kanał każdemu, kto ma obserwowanych (jeden po drugim, z przerwą, żeby nie zalać Meczoteki)."""
    await asyncio.sleep(120)
    while True:
        try:
            judges = sorted({r["judge_id"] for r in await C.rows(select(F.c.judge_id))})
            for jid in judges:
                try:
                    await refresh_feed(await C.load_actor(jid, via="jwt"))
                except Exception:  # noqa: BLE001
                    logger.warning("trybuna: kanał w tle dla %s nieudany", jid, exc_info=True)
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("trybuna: pętla kanału")
        await asyncio.sleep(FEED_REFRESH_S)


class HarvestBody(BaseModel):
    season: str = Field(default="", max_length=20)
    pages: int = Field(default=3, ge=1, le=6)


@router.post("/trybuna/follows/{follow_id}/harvest")
async def harvest(follow_id: str, body: HarvestBody, response: Response, real: Actor = Depends(base_actor)):
    """„Wczytaj sezon obserwowanego": kolejne strony Meczoteki po nazwisku (do 6), z łącznym czasem i jednym ponowieniem po 429.
    Odpowiedź to propozycje (`games`) do `POST /pairs/{p}/trybuna/matches/bulk` - niczego nie dodaje."""
    response.headers["Cache-Control"] = "no-store"
    row = await C.one(select(F).where(F.c.id == follow_id).where(F.c.judge_id == real.judge_id))
    if not row:
        raise C.err(404, "NOT_FOUND", "Nie obserwujesz takiego sędziego.")
    follow_ = T.follow_shape(row)
    mz, state = S._setup(real)
    if mz is None:
        return {"games": [], "pages": 0, "season": body.season or None, "partial": False, "bastion": bastion_block(state or "unconfigured")}
    mz.retry_429 = True
    deadline = time.monotonic() + S.SEASON_DEADLINE_S
    name = follow_names(follow_)[0]
    games: Dict[int, Dict[str, Any]] = {}
    block, pages, partial = bastion_block("ok"), 0, False
    for page in range(body.pages):
        if time.monotonic() > deadline:
            partial = True
            break
        try:
            found = await mz.search_referee(name, video="any", offset=page * S.PAGE, role="delegate" if follow_["kind"] == "delegate" else "referee")
        except S._Stop as stop:
            block = bastion_block(await stop_state(stop), mz.scope)
            partial = bool(games)
            break
        pages += 1
        for g in found:
            try:
                games.setdefault(int(g["bunny_item_id"]), g)
            except (KeyError, TypeError, ValueError):
                continue
        if len(found) < S.PAGE:
            break
    if block["state"] == "ok":
        block["scope"] = mz.scope
    rows = []
    for g in games.values():
        snap = T.snapshot_from_game(g)
        if body.season and snap.get("season") != body.season:
            continue
        refs = T.clean_referees(g.get("referees") or [])
        if refs and not T.follow_matches(follow_, refs):
            continue
        rows.append(game_row(g, {}))
    rows.sort(key=lambda r: R.s(r.get("date")), reverse=True)
    return {"games": rows, "pages": pages, "season": body.season or None, "partial": partial or bool(block["state"] != "ok" and rows),
            "bastion": block}


# ─── Kalendarz obserwowanych ────────────────────────────────────────────────


@router.get("/trybuna/calendar")
async def calendar(days: int = Query(30, ge=1, le=90), real: Actor = Depends(base_actor)):
    """Nadchodzące mecze obserwowanych z obsady ZPRP i z Meczoteki (kto, gdzie, kiedy). `unresolved` = obserwowani bez numeru
    sędziego, których szukamy po nazwisku w obsadzie. Pozycje mają `home_crest` / `away_crest`."""
    return await calendar_for(real, await my_follows(real.judge_id), days)


async def calendar_for(real: Actor, follows: List[Dict[str, Any]], days: int, mz_override: Any = None, whole_day: bool = False) -> Dict[str, Any]:
    now = _naive_local_now()
    if whole_day:  # od północy: poranny push widzi też mecze, które dziś już się zaczęły
        now = now.replace(hour=0, minute=0, second=0, microsecond=0)
    rows = await zprp_rows_for(follows, now, now + timedelta(days=days)) if follows else []
    items = []
    cards = []
    for r in sorted(rows, key=lambda x: x["scheduled_at"]):
        card = R.card_from_public(r)
        cards.append((r, card))
        refs = T.referees_of_zprp_row(r)
        items.append({"source": "zprp", "zprp_match_id": R.s(r["match_id"]), "date": _iso(card.get("scheduled_at")), "time_known": True,
                      "unscheduled": False, "home": (card.get("home") or {}).get("name"),
                      "away": (card.get("away") or {}).get("name"), "competition": card.get("competition_name"),
                      "code": card.get("match_code"), "venue_city": card.get("venue_city"), "referees": refs,
                      "followed": [f["id"] for f in follows if T.follow_matches(f, refs)], "bunny_item_id": None})
    # Przyszłe i bez terminu mecze z Meczoteki (portal pokazuje je przed obsadą ZPRP): tylko te, których nie ma w obsadzie.
    bastion = bastion_block("ok")
    mz, state = (mz_override, None) if mz_override is not None else (S._setup(real) if follows else (None, None))
    if follows and mz is None:
        bastion = bastion_block(state or "unconfigured")
    elif mz is not None:
        today = now.date()
        horizon = today + timedelta(days=days)
        pairs: List[Tuple[str, str]] = []
        for f in follows:
            for nm in follow_names(f):
                pr = (nm, "delegate" if f["kind"] == "delegate" else "referee")
                if (T.name_key(pr[0]), pr[1]) not in {(T.name_key(x), r) for x, r in pairs}:
                    pairs.append(pr)
        try:
            for nm, role in pairs[:FEED_FOLLOWS]:
                for g in await mz.search_referee(nm, video="any", role=role):
                    day = S.parse_day(g.get("date"))
                    if not is_upcoming(g, today) or (day and day > horizon) or match_game_to_zprp(g, cards) is not None:
                        continue
                    refs = T.clean_referees(g.get("referees") or [])
                    key = f"bastion:{g.get('bunny_item_id')}" if g.get("bunny_item_id") else f"game:{g.get('game_id')}"
                    if any(i.get("key") == key for i in items):
                        continue
                    items.append({"source": "bastion", "key": key, "zprp_match_id": None, "date": g.get("date") if day else None,
                                  "time_known": game_time_known(g), "unscheduled": bool(g.get("unscheduled")), "home": g.get("home"),
                                  "away": g.get("away"), "competition": g.get("competition"), "code": g.get("code"), "venue_city": None,
                                  "referees": refs, "followed": [f["id"] for f in follows if T.follow_matches(f, refs)],
                                  "bunny_item_id": g.get("bunny_item_id")})
            bastion = bastion_block("ok", mz.scope)
        except S._Stop as stop:
            bastion = bastion_block(await stop_state(stop), mz.scope)
    items.sort(key=lambda i: (i.get("date") is None, R.s(i.get("date"))))
    await S.attach_crests(items)
    return {"items": items, "follows": len(follows), "days": days, "bastion": bastion,
            "unresolved": [f["name"] for f in follows if len(f.get("judge_ids") or []) < len(follow_names(f))]}


# ─── Podgląd kasety przed dodaniem ──────────────────────────────────────────


class PreviewBody(BaseModel):
    bunny_item_id: int = Field(ge=1)


@router.post("/pairs/{pair_id}/trybuna/preview")
async def trybuna_preview(pair_id: str, body: PreviewBody, response: Response, real: Actor = Depends(base_actor),
                          acting: Actor = Depends(mentor_actor)):
    """Podgląd na miejscu PRZED dodaniem: krótko ważny `embed_url` Bastionu dla kasety, której nie ma jeszcze w żadnym meczu
    (te same zasady co `POST .../videos/{v}/playback`: `Cache-Control: no-store`, adres nigdy nie jest zapisywany ani logowany,
    połączenie domyślne potem osobiste prawdziwego użytkownika, błędy w kopercie 409/403/503/429 z `connections`, nigdy 401).
    Odpowiedź: `{provider, mode:"bunny_embed", embed_url, expires_at, connection_scope, capabilities, duration_s, video_state,
    bunny_item_id, thumbnail_url}`. Akcja `video` (kto może dodać, może obejrzeć). Do nagrania już dodanego służy `playback`."""
    from app import mentor_bastion_client as CL
    from app.mentor_bastion import CAPABILITIES, _client, _playback_failure, _scope_judge, apply_verdict, berr

    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, acting)
    C.check(ctx, "video")
    flags = BR.load_flags()
    if not flags.enabled:
        raise berr(404, "BASTION_DISABLED", S.DISABLED_MESSAGE)
    scopes = BR.candidate_scopes(flags)
    if not scopes or not flags.configured:
        raise berr(503, "BASTION_UNAVAILABLE", S.UNCONFIGURED_MESSAGE)
    client = _client()
    verdicts: List[Tuple[str, BR.PlaybackVerdict]] = []
    for scope in scopes:
        owner = _scope_judge(scope, real)
        try:
            reply = await client.playback(scope, owner, body.bunny_item_id)
        except CL.ConnectorUnavailable:
            verdicts.append((scope, BR.PlaybackVerdict("unavailable", "BASTION_UNAVAILABLE")))
            break
        verdict = BR.classify_playback(reply.status, reply.body)
        if verdict.kind == "ok" and not BR.embed_url_ok(reply.body.get("embed_url")):
            verdict = BR.PlaybackVerdict("unavailable", "BASTION_BAD_RESPONSE")
        await apply_verdict(scope, owner, verdict)
        if verdict.kind == "ok":
            return {"provider": BR.PROVIDER, "mode": "bunny_embed", "embed_url": reply.body["embed_url"],
                    "expires_at": BR.embed_expiry_hint(reply.body.get("expires_at")), "connection_scope": scope,
                    "capabilities": dict(CAPABILITIES), "duration_s": reply.body.get("duration_s"),
                    "video_state": reply.body.get("video_state"), "bunny_item_id": body.bunny_item_id,
                    "thumbnail_url": reply.body.get("thumbnail_url")}
        verdicts.append((scope, verdict))
        if verdict.kind in ("rate_limited", "unavailable"):
            break
    raise _playback_failure(flags, real, verdicts)


# ─── Kalendarz nagrań: mapa dni ─────────────────────────────────────────────


def forget_days_cache() -> None:
    _days_cache.clear()


@router.get("/pairs/{pair_id}/trybuna/days")
async def trybuna_days(pair_id: str, response: Response, from_: str = Query(..., alias="from", max_length=10),
                       to: str = Query(..., max_length=10), real: Actor = Depends(base_actor), acting: Actor = Depends(mentor_actor)):
    """Mapa nagrań (kalendarz Trybuny): dla każdego dnia zakresu `{date, with_video, total, followed}`. `total`/`with_video` z Meczoteki
    (wiersze portalu w tym dniu / z gotowym nagraniem), `followed` = mecze obserwowanych (nominees z portalu i obsada ZPRP, bez
    podwójnego liczenia). Najwyżej 62 dni; wynik pamiętany 10 min na użytkownika i zakres. `bastion.state` mówi, czy Meczoteka
    odpowiedziała (inaczej tylko `followed` z ZPRP), `bastion.truncated` - że przegląd urwał się na 10 stronach."""
    response.headers["Cache-Control"] = "no-store"
    await C.pair_context(pair_id, acting)
    d_from, d_to, _, _ = parse_range(from_, to, "", "")
    if not d_from or not d_to:
        raise C.err(422, "BAD_DATE", "Podaj from i to w postaci RRRR-MM-DD.")
    if (d_to - d_from).days + 1 > DAYS_MAX:
        raise C.err(422, "RANGE_TOO_LONG", f"Kalendarz pokazuje najwyżej {DAYS_MAX} dni naraz.")
    key = (real.judge_id, d_from, d_to)
    hit = _days_cache.get(key)
    if hit and time.monotonic() - hit[0] < DAYS_CACHE_S:
        return hit[1]
    follows = await my_follows(real.judge_id)
    counts: Dict[date, Dict[str, int]] = {}
    for i in range((d_to - d_from).days + 1):
        counts[d_from + timedelta(days=i)] = {"with_video": 0, "total": 0, "followed": 0}
    followed_keys: Dict[date, set] = {d: set() for d in counts}
    bastion: Dict[str, Any] = {"state": "ok", "truncated": False}
    mz, state = S._setup(real)
    games: List[Dict[str, Any]] = []
    if mz is None:
        bastion = {"state": state or "unconfigured", "truncated": False}
    else:
        try:
            games, meta = await mz.scan(video="any", d_from=d_from, d_to=d_to)
            bastion["truncated"] = bool(meta["truncated"])
        except S._Stop as stop:
            bastion = {"state": await stop_state(stop), "truncated": False}
    for g in games:
        day = S.parse_day(g.get("date"))
        if day not in counts:
            continue
        counts[day]["total"] += 1
        if g.get("bunny_item_id") and T.feed_state(g.get("video_state")) == "video":
            counts[day]["with_video"] += 1
        refs = T.clean_referees(g.get("referees") or [])
        if any(T.follow_matches(f, refs) for f in follows):
            followed_keys[day].add(f"b:{g.get('bunny_item_id') or g.get('game_id')}")
    if follows:
        zrows = await zprp_rows_for(follows, datetime(d_from.year, d_from.month, d_from.day),
                                    datetime(d_to.year, d_to.month, d_to.day) + timedelta(days=1))
        for r in zrows:
            card = R.card_from_public(r)
            day = S.card_day(card)
            if day not in counts:
                continue
            twin = next((g for g in games if S.score_game(g, card)["confidence"] >= T.AUTO_MIN), None)
            followed_keys[day].add(f"b:{twin.get('bunny_item_id') or twin.get('game_id')}" if twin else f"z:{r['match_id']}")
    for d, keys in followed_keys.items():
        counts[d]["followed"] = len(keys)
    out = {"days": [{"date": d.isoformat(), **c} for d, c in sorted(counts.items())], "bastion": bastion}
    if len(_days_cache) > 300:
        _days_cache.clear()
    _days_cache[key] = (time.monotonic(), out)
    return out


# ─── Kolejka „Do obejrzenia" ────────────────────────────────────────────────


class QueueAdd(BaseModel):
    pair_id: str = Field(min_length=1, max_length=64)
    match_id: str = Field(min_length=1, max_length=64)
    video_id: Optional[str] = Field(default=None, max_length=64)


class QueuePatch(BaseModel):
    progress_s: Optional[int] = Field(default=None, ge=0, le=86400)
    done: Optional[bool] = None
    position: Optional[int] = Field(default=None, ge=0, le=10000)
    video_id: Optional[str] = Field(default=None, max_length=64)


async def _queue_payload(real: Actor) -> Dict[str, Any]:
    rows = await C.rows(select(Q).where(Q.c.judge_id == real.judge_id).order_by(Q.c.position.asc(), Q.c.added_at.asc()))
    if not rows:
        return {"items": [], "pending": 0, "done": 0, "limit": T.MAX_QUEUE}
    pair_ids = sorted({r["pair_id"] for r in rows})
    alive: Dict[str, Dict[str, Any]] = {}
    for pid in pair_ids:
        try:
            ctx = await C.pair_context(pid, real)
        except Exception:  # noqa: BLE001 - utracony dostęp do pary chowa jej pozycje, nie psuje listy
            continue
        from app.mentor_trybuna import watched_cards

        ids = [r["match_id"] for r in rows if r["pair_id"] == pid]
        for card in await watched_cards(ctx, ids=ids):
            alive[(pid, card["match_id"])] = card
    names = await C.people({r.get("recommended_by") for r in rows if r.get("recommended_by")})
    vids = [r["video_id"] for r in rows if r.get("video_id")]
    videos = {v["id"]: v for v in await C.rows(select(mentor_match_videos.c.id, mentor_match_videos.c.title, mentor_match_videos.c.thumbnail_url,
                                                      mentor_match_videos.c.duration_s, mentor_match_videos.c.provider)
                                               .where(mentor_match_videos.c.id.in_(vids)))} if vids else {}
    items = []
    for r in rows:
        card = alive.get((r["pair_id"], r["match_id"]))
        if card is None:
            continue
        items.append({"pair_id": r["pair_id"], "match_id": r["match_id"], "position": int(r.get("position") or 0), "progress_s": int(r.get("progress_s") or 0),
                      "video_id": r.get("video_id"), "video": videos.get(r.get("video_id")), "added_at": _iso(r.get("added_at")),
                      "done_at": _iso(r.get("done_at")), "match": R.slim_match(card) | {"origin": card.get("origin"), "referees": card.get("referees")},
                      "recommended_by": ({"judge_id": r["recommended_by"], "name": C.person(names, r["recommended_by"])["name"]}
                                         if r.get("recommended_by") else None),
                      "note": r.get("note"), "recommended_at": _iso(r.get("recommended_at")), "clip_id": r.get("clip_id")})
    return {"items": items, "pending": sum(1 for i in items if not i["done_at"]), "done": sum(1 for i in items if i["done_at"]), "limit": T.MAX_QUEUE}


@router.get("/trybuna/queue")
async def get_queue(response: Response, real: Actor = Depends(base_actor)):
    """Moja kolejka „Do obejrzenia": mecze z Trybuny moich par z postępem w sekundach (`progress_s`)."""
    response.headers["Cache-Control"] = "no-store"
    return await _queue_payload(real)


@router.post("/trybuna/queue")
async def queue_add(body: QueueAdd, real: Actor = Depends(base_actor)):
    from app.mentor_trybuna import watched_row

    ctx = await C.pair_context(body.pair_id, real)
    if not await watched_row(ctx["pair_id"], body.match_id):
        raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
    mine = await C.rows(select(Q.c.match_id, Q.c.pair_id, Q.c.position).where(Q.c.judge_id == real.judge_id))
    if any(m["pair_id"] == ctx["pair_id"] and m["match_id"] == body.match_id for m in mine):
        return await _queue_payload(real)
    if len(mine) >= T.MAX_QUEUE:
        raise C.err(422, "QUEUE_LIMIT", f"Kolejka mieści najwyżej {T.MAX_QUEUE} pozycji.")
    await database.execute(Q.insert().values(judge_id=real.judge_id, pair_id=ctx["pair_id"], match_id=body.match_id, video_id=body.video_id,
                                             position=max([int(m.get("position") or 0) for m in mine], default=-1) + 1, added_at=C.now(), updated_at=C.now()))
    return await _queue_payload(real)


@router.patch("/trybuna/queue/{pair_id}/{match_id}")
async def queue_patch(pair_id: str, match_id: str, body: QueuePatch, real: Actor = Depends(base_actor)):
    """Postęp (`progress_s`), „obejrzane" (`done`), miejsce w kolejce (`position`) albo nagranie (`video_id`)."""
    row = await C.one(select(Q).where(Q.c.judge_id == real.judge_id).where(Q.c.pair_id == pair_id).where(Q.c.match_id == match_id))
    if not row:
        raise C.err(404, "NOT_FOUND", "Tego meczu nie ma w Twojej kolejce.")
    values: Dict[str, Any] = {"updated_at": C.now()}
    if body.progress_s is not None:
        values["progress_s"] = body.progress_s
    if body.done is not None:
        values["done_at"] = C.now() if body.done else None
    if body.position is not None:
        values["position"] = body.position
    if body.video_id is not None:
        values["video_id"] = body.video_id or None
    await database.execute(update(Q).where(Q.c.judge_id == real.judge_id).where(Q.c.pair_id == pair_id).where(Q.c.match_id == match_id).values(**values))
    return await _queue_payload(real)


@router.delete("/trybuna/queue/{pair_id}/{match_id}")
async def queue_remove(pair_id: str, match_id: str, real: Actor = Depends(base_actor)):
    await database.execute(Q.delete().where(Q.c.judge_id == real.judge_id).where(Q.c.pair_id == pair_id).where(Q.c.match_id == match_id))
    return await _queue_payload(real)


class QueueOrder(BaseModel):
    items: List[Dict[str, str]] = Field(max_length=T.MAX_QUEUE)


@router.put("/trybuna/queue/order")
async def queue_order(body: QueueOrder, real: Actor = Depends(base_actor)):
    """Cała kolejność naraz: `items:[{pair_id, match_id}]` w nowej kolejności (pominięte zostają na końcu)."""
    for pos, item in enumerate(body.items):
        await database.execute(update(Q).where(Q.c.judge_id == real.judge_id).where(Q.c.pair_id == R.s(item.get("pair_id")))
                               .where(Q.c.match_id == R.s(item.get("match_id"))).values(position=pos))
    return await _queue_payload(real)


# ─── Karta sędziego ─────────────────────────────────────────────────────────


@router.get("/trybuna/referees/card")
async def referee_card(response: Response, name: str = Query("", max_length=80), judge_id: str = Query("", max_length=20),
                       real: Actor = Depends(base_actor)):
    """Karta sędziego: czy obserwuję, jego mecze z Meczoteki (dostępne nagrania), statystyki ProEla/ZPRP i MOJE klipy z jego udziałem
    (oznaczone na klipie albo z meczu z Trybuny, w którym sędziuje)."""
    response.headers["Cache-Control"] = "no-store"
    name, judge_id = R.plain(name, 80), R.s(judge_id)
    if not name and not judge_id:
        raise C.err(422, "BAD_QUERY", "Podaj nazwisko albo numer sędziego.")
    if judge_id and not name:
        who = await C.people([judge_id])
        name = (who.get(judge_id) or {}).get("full_name") or ""
    if not judge_id:
        judge_id = await resolve_judge(name) or ""
    me = {"name": name, "judge_id": judge_id or None}
    key = T.referee_key(name, judge_id)
    follows = await my_follows(real.judge_id)
    mine = next((f for f in follows if f["kind"] == "referee" and T.follow_matches(f, [me])), None)

    # ZPRP: obsada i protokoły.
    zprp: Dict[str, Any] = {"judge_id": judge_id or None, "matches": 0, "seasons": [], "recent": [], "upcoming": [], "proel_protocols": 0}
    zprp_rows: List[Dict[str, Any]] = []
    if judge_id:
        M = zprp_public_matches
        rows = await C.rows(select(M).where(or_(M.c.referee_1_id == judge_id, M.c.referee_2_id == judge_id))
                            .order_by(M.c.scheduled_at.desc()).limit(300))
        now = _naive_local_now()
        seasons: Dict[str, int] = {}
        for r in rows:
            card = R.card_from_public(r)
            seasons[card.get("season") or ""] = seasons.get(card.get("season") or "", 0) + 1
        zprp_rows = rows
        zprp["matches"] = len(rows)
        zprp["seasons"] = [{"season": s, "matches": n} for s, n in sorted(seasons.items(), reverse=True) if s]
        for r in rows:
            card = R.card_from_public(r)
            entry = {"zprp_match_id": R.s(r["match_id"]), "date": _iso(card.get("scheduled_at")), "home": (card.get("home") or {}).get("name"),
                     "away": (card.get("away") or {}).get("name"), "competition": card.get("competition_name"), "code": card.get("match_code")}
            (zprp["upcoming"] if r.get("scheduled_at") and r["scheduled_at"] >= now else zprp["recent"]).append(entry)
        zprp["upcoming"] = zprp["upcoming"][-5:][::-1]
        zprp["recent"] = zprp["recent"][:8]
        ids = [R.s(r["match_id"]) for r in rows]
        if ids:
            found = await C.rows(select(saved_matches.c.zprp_match_id).where(saved_matches.c.zprp_match_id.in_(ids)))
            zprp["proel_protocols"] = len({R.s(f["zprp_match_id"]) for f in found})

    # Meczoteka: dostępne mecze (do 5 stron po nazwisku, obsada potwierdzona w nominees).
    available: Dict[str, Any] = {"games": [], "bastion": bastion_block("ok")}
    mz, state = S._setup(real)
    all_games: List[Dict[str, Any]] = []
    if mz is None:
        available["bastion"] = bastion_block(state or "unconfigured")
    else:
        try:
            all_games, _meta = await mz.scan(referee=name, video="any")
            pair_ids = [p["id"] for p in await _my_pairs(real)]
            got = await watched_by_item(pair_ids, [int(g["bunny_item_id"]) for g in all_games if g.get("bunny_item_id")])
            marks = {item: mid for (_, item), mid in got.items()}
            available["games"] = [game_row(g, marks) for g in all_games if g.get("bunny_item_id")][:12]
            await S.enrich_media(real, mz.scope, available["games"])
            available["bastion"] = bastion_block("ok", mz.scope)
        except S._Stop as stop:
            available["bastion"] = bastion_block(await stop_state(stop), mz.scope)
    await S.attach_crests(zprp["recent"] + zprp["upcoming"])
    extras = await card_extras(judge_id, name, zprp_rows if judge_id else [], all_games)

    # Moje klipy z udziałem sędziego.
    my_clips = await clips_with_referee(real, me, key)
    return {"referee": me, "follow": mine, "zprp": zprp, "available": available, "my_clips": my_clips, **extras}


async def card_extras(judge_id: str, name: str, rows: List[Dict[str, Any]], games: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Dodatki karty sędziego: forma w sezonie, najczęstszy partner, rozgrywki, liczniki i okręg (herb jak na ekranach egzaminu)."""
    me = {"name": name, "judge_id": judge_id or None}
    season = R.season_key(datetime.now(timezone.utc))
    partners: Dict[str, Dict[str, Any]] = {}
    comps: Dict[str, int] = {}
    form: List[Dict[str, Any]] = []
    now = _naive_local_now()
    for r in rows:
        card = R.card_from_public(r)
        refs = [x for x in T.referees_of_zprp_row(r) if x["role"] == "referee"]
        mine = next((x for x in refs if T.same_referee(x, me)), None)
        for other in refs:
            if other is not mine and not T.same_referee(other, me):
                entry = partners.setdefault(T.name_key(other["name"]), {"name": other["name"], "count": 0})
                entry["count"] += 1
        if card.get("competition_name"):
            comps[card["competition_name"]] = comps.get(card["competition_name"], 0) + 1
        if card.get("season") == season and r.get("scheduled_at") and r["scheduled_at"] < now and len(form) < 40:
            twin = next((g for g in games if g.get("bunny_item_id") and T.feed_state(g.get("video_state")) == "video"
                         and S.score_game(g, card)["confidence"] >= T.AUTO_MIN), None)
            form.append({"date": _iso(card.get("scheduled_at")), "code": card.get("match_code"), "home": (card.get("home") or {}).get("name"),
                         "away": (card.get("away") or {}).get("name"), "has_video": twin is not None, "role": "referee",
                         "position": (mine or {}).get("position")})
    await S.attach_crests(form)
    top = max(partners.values(), key=lambda p: p["count"], default=None)
    province = None
    if judge_id:
        who = await C.one(select(province_judges.c.province).where(province_judges.c.judge_id == judge_id))
        if who and who.get("province"):
            from app import exam_live_brand as EB

            palette = EB.palette_for("province", who["province"])
            province = {"name": who["province"], "crest": f"/exam-live/assets/img/{EB.crest_name(palette)}" if palette.get("kind") == "province" else None}
    with_video = [g for g in games if g.get("bunny_item_id") and T.feed_state(g.get("video_state")) == "video"]
    return {"season_form": form, "top_partner": top, "competitions": [{"name": n, "count": c} for n, c in sorted(comps.items(), key=lambda x: -x[1])[:5]],
            "videos_count": len(with_video), "matches_count": len(rows) or len(games), "province": province}


async def clips_with_referee(real: Actor, me: Mapping[str, Any], key: str, limit: int = 30) -> List[Dict[str, Any]]:
    pair_ids = [p["id"] for p in await _my_pairs(real)]
    if not pair_ids:
        return []
    TG = mentor_trybuna_clip_tags
    tagged = await C.rows(select(TG).where(TG.c.pair_id.in_(pair_ids)))
    clip_ids = {t["clip_id"] for t in tagged if T.same_referee({"name": t.get("name"), "judge_id": t.get("judge_id")}, me)}
    # Klipy z meczów z Trybuny, w których sędziuje.
    wrows = await C.rows(select(W.c.match_id, W.c.pair_id, W.c.referees_json).where(W.c.pair_id.in_(pair_ids)).where(W.c.deleted_at.is_(None)))
    match_ids = [w["match_id"] for w in wrows if any(T.same_referee(r, me) for r in T.clean_referees(R.json_value(w.get("referees_json"), [])))]
    cond = []
    if clip_ids:
        cond.append(mentor_clips.c.id.in_(sorted(clip_ids)))
    if match_ids:
        cond.append(mentor_clips.c.match_id.in_(match_ids))
    if not cond:
        return []
    found = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id.in_(pair_ids)).where(mentor_clips.c.deleted_at.is_(None))
                         .where(or_(*cond)).order_by(mentor_clips.c.created_at.desc()).limit(limit * 2))
    mine = [c for c in found if R.s(c.get("author_id")) == real.judge_id][:limit]
    return [{"id": c["id"], "pair_id": c["pair_id"], "match_id": c["match_id"], "video_id": c["video_id"], "title": c.get("title"),
             "start_s": c["start_s"], "end_s": c["end_s"], "tagged": c["id"] in clip_ids} for c in mine]


# ─── Dzienny push: nowe nagrania obserwowanych ──────────────────────────────


def new_games_for(follow_row: Mapping[str, Any], games: List[Mapping[str, Any]], notified: set, today) -> List[Mapping[str, Any]]:
    """Gry z gotowym nagraniem z ostatnich dni, których ta osoba jeszcze nie dostała; dla pary tylko, gdy obsada (jeśli znana) ma oboje."""
    follow_ = T.follow_shape(follow_row)
    out = []
    for g in games:
        try:
            item = int(g["bunny_item_id"])
        except (KeyError, TypeError, ValueError):
            continue
        day = S.parse_day(g.get("date"))
        if item in notified or T.feed_state(g.get("video_state")) != "video" or day is None:
            continue
        if (today - day).days > NOTIFY_WINDOW_DAYS or day > today:
            continue
        refs = T.clean_referees(g.get("referees") or [])
        if refs and not T.follow_matches(follow_, refs):
            continue
        out.append(g)
    return out


async def notify_once(now: Optional[datetime] = None) -> Dict[str, int]:
    """Jeden przebieg: dla obserwowanych (połączenie domyślne) szuka nowych meczów z nagraniem i wysyła JEDEN cichy push na osobę.
    Ślad w `mentor_trybuna_notified` (osoba + nagranie) gwarantuje brak powtórek między przebiegami."""
    counts = {"referees": 0, "games": 0, "pushed": 0}
    flags = BR.load_flags()
    if not flags.enabled or not flags.configured or not flags.default_enabled:
        return counts
    from app import mentor_bastion_client as CL

    try:
        client = CL.get_client()
    except CL.ConnectorUnavailable:
        return counts
    rows = await C.rows(select(F))
    if not rows:
        return counts
    system = C.MentorActor("0", display_name="Trybuna")
    mz = S.Meczoteka(client, ["default"], system)
    by_name: Dict[Tuple[str, str], str] = {}
    for r in rows:
        for nm in R.json_value(r.get("names"), []):
            by_name.setdefault((T.name_key(nm), "delegate" if r["kind"] == "delegate" else "referee"), R.s(nm))
    today = (now or datetime.now(timezone.utc)).astimezone(WARSAW).date()
    games_by_name: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for key, nm in list(by_name.items())[:NOTIFY_MAX_REFEREES]:
        try:
            games_by_name[key] = [g for g in await mz.search_referee(nm, video="with", role=key[1]) if g.get("bunny_item_id")]
        except S._Stop:
            break
        counts["referees"] += 1
        await asyncio.sleep(0.5)
    done = {(r["judge_id"], int(r["bunny_item_id"])) for r in await C.rows(select(mentor_trybuna_notified))}
    per_judge: Dict[str, List[Tuple[str, Mapping[str, Any]]]] = {}
    for r in rows:
        mine = {i for (j, i) in done if j == r["judge_id"]}
        for nm in R.json_value(r.get("names"), []):
            for g in new_games_for(r, games_by_name.get((T.name_key(nm), "delegate" if r["kind"] == "delegate" else "referee"), []), mine, today):
                item = int(g["bunny_item_id"])
                if any(int(x[1]["bunny_item_id"]) == item for x in per_judge.get(r["judge_id"], [])):
                    continue
                per_judge.setdefault(r["judge_id"], []).append((R.s(nm), g))
    for judge_id, found in per_judge.items():
        counts["games"] += len(found)
        title = "Trybuna: nowe nagrania"
        first_name, first = found[0]
        teams = " - ".join(x for x in (first.get("home"), first.get("away")) if x)
        body = f"{first_name}: {teams}".strip(": ") + (f" i {len(found) - 1} inne" if len(found) > 1 else "")
        try:
            from app.mentor_panel_notify import push_data
            from app.push.push import send_push_to_judges_report

            data = push_data("trybuna", target="trybuna", tag="mentor-trybuna", quiet=True,
                             extra={"bunnyItemId": str(first["bunny_item_id"])})
            await send_push_to_judges_report([judge_id], title, body, data, app_variant="baza", preference_key="mentorPanel")
            counts["pushed"] += 1
        except Exception:  # noqa: BLE001 - push nieudany: ślad zapisujemy mimo to, żeby nie wysyłać po raz drugi
            logger.warning("trybuna: push nieudany", exc_info=True)
        for _, g in found:
            try:
                await database.execute(mentor_trybuna_notified.insert().values(judge_id=judge_id, bunny_item_id=int(g["bunny_item_id"]), notified_at=C.now()))
            except Exception:  # noqa: BLE001 - wyścig dwóch przebiegów: już zapisane
                pass
    return counts


async def run_trybuna_notifier() -> None:
    """Zadanie dzienne (pierwszy przebieg 20 minut po starcie, potem co dobę)."""
    await asyncio.sleep(1200)
    while True:
        try:
            counts = await notify_once()
            logger.info("mentor: trybuna push %s", counts)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: trybuna push nieudany")
        await asyncio.sleep(NOTIFY_EVERY_S)


# ─── Mentor poleca ──────────────────────────────────────────────────────────


class RecommendBody(BaseModel):
    match_id: Optional[str] = Field(default=None, max_length=64)
    bunny_item_id: Optional[int] = Field(default=None, ge=1)
    url: Optional[str] = Field(default=None, max_length=2048)
    clip_id: Optional[str] = Field(default=None, max_length=64)
    note: str = Field(default="", max_length=280)


@router.post("/pairs/{pair_id}/trybuna/recommend")
async def recommend(pair_id: str, body: RecommendBody, response: Response, real: Actor = Depends(base_actor),
                    actor: Actor = Depends(mentor_actor)):
    """Mentor poleca parze mecz (albo klip) z Trybuny: `{match_id? | bunny_item_id? | url? | clip_id?, note <= 280}`. Tylko mentor
    pary (403 `NOT_MENTOR`). Gdy podano kasetę albo adres, mecz z Trybuny powstaje, jeśli go nie ma (jak `POST .../trybuna/matches`).
    Pozycja trafia NA POCZĄTEK kolejki „Do obejrzenia" obu sędziów pary z `recommended_by`, `note`, `recommended_at` (i `clip_id`),
    a oni dostają push „Mentor poleca" (deep link do meczu / klipu). -> `{ok, match_id, clip_id, created_match, queued: [judge_id]}`."""
    from app.mentor_panel_notify import notify
    from app.mentor_trybuna import WatchBody, create_watched, watched_card, watched_row

    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="create")
    if ctx["role"] != "mentor":
        raise C.err(403, "NOT_MENTOR", "Polecać mecze z Trybuny może tylko mentor tej pary.")
    clip = None
    created = False
    if body.clip_id:
        clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == body.clip_id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                           .where(mentor_clips.c.deleted_at.is_(None)))
        if not clip:
            raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
        if not T.is_watched(clip["match_id"]):
            raise C.err(422, "NOT_TRYBUNA", "Polecać można klipy z meczów z Trybuny.")
        match_id = clip["match_id"]
    elif body.match_id:
        row = await watched_row(ctx["pair_id"], body.match_id)
        if not row:
            raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
        match_id = row["match_id"]
    elif body.bunny_item_id or body.url:
        row, created = await create_watched(ctx, actor, real, WatchBody(url=body.url, bunny_item_id=body.bunny_item_id), link=True)
        match_id = row["match_id"]
    else:
        raise C.err(422, "RECOMMEND_TARGET", "Podaj mecz, kasetę, adres albo klip do polecenia.")
    video = await C.one(select(mentor_match_videos.c.id).where(mentor_match_videos.c.match_id == match_id)
                        .where(mentor_match_videos.c.pair_key == ctx["pair_key"]).where(mentor_match_videos.c.deleted_at.is_(None))
                        .order_by(mentor_match_videos.c.created_at.asc()).limit(1))
    note, stamp = R.plain(body.note, 280) or None, C.now()
    queued = []
    for jid in ctx["judge_ids"]:
        mine = await C.rows(select(Q.c.match_id, Q.c.position).where(Q.c.judge_id == jid))
        top = min([int(m.get("position") or 0) for m in mine], default=0) - 1
        values = dict(position=top, video_id=(video or {}).get("id"), recommended_by=actor.judge_id, note=note, recommended_at=stamp,
                      clip_id=body.clip_id or None, done_at=None, progress_s=0, updated_at=stamp)
        if any(m["match_id"] == match_id for m in mine):
            await database.execute(update(Q).where(Q.c.judge_id == jid).where(Q.c.pair_id == ctx["pair_id"]).where(Q.c.match_id == match_id).values(**values))
        else:
            await database.execute(Q.insert().values(judge_id=jid, pair_id=ctx["pair_id"], match_id=match_id, added_at=stamp, **values))
        queued.append(jid)
    card = await watched_card(ctx, match_id)
    teams = " - ".join(x for x in ((card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")) if x) or card.get("title") or "mecz"
    await C.touch(ctx, actor.judge_id, "trybuna_recommended", "matches", match_id, {"clip": body.clip_id})
    link = f"{C.WEB_BASE}/{ctx['pair_id']}/klipy?klip={body.clip_id}" if body.clip_id else f"{C.WEB_BASE}/{ctx['pair_id']}/mecz/{match_id}"
    await notify(ctx, actor.judge_id, "Mentor poleca", f"{actor.display_name}: {teams}" + (f" - {note}" if note else ""),
                 recipients=queued, match_id=match_id, clip_id=body.clip_id, link=link, target="trybuna", tag=f"mentor-poleca-{match_id}")
    return {"ok": True, "match_id": match_id, "clip_id": body.clip_id, "created_match": created, "queued": queued}


# ─── Sugestie: kogo obserwować ──────────────────────────────────────────────

SUGGESTIONS_MAX = 12


@router.get("/trybuna/follows/suggestions")
async def follow_suggestions(response: Response, real: Actor = Depends(base_actor)):
    """Podpowiedzi „kogo jeszcze obserwować" (do 12, bez już obserwowanych): częsty współsędzia obserwowanych (z obsady ZPRP), sędziowie z tej
    samej ligi / rozgrywek co obserwowani, sędziowie z meczów dodanych przez Twoje pary; dla stałych duetów obserwowanego dochodzi
    propozycja pary. -> tablica `[{kind: "referee"|"pair", name, judge_id|null / names+judge_ids, reason, matches_with_video|null, crest|null}]`.
    `matches_with_video` = ile meczów z nagraniem Meczoteka pokazuje na pierwszej stronie (null, gdy Meczoteka niedostępna)."""
    response.headers["Cache-Control"] = "no-store"
    follows = await my_follows(real.judge_id)
    followed_names = {T.name_key(n) for f in follows for n in follow_names(f)}
    followed_ids = {i for f in follows for i in f.get("judge_ids") or []}
    pair_follows = {frozenset(T.name_key(n) for n in f["names"]) for f in follows if f["kind"] == "pair"}
    cands: Dict[str, Dict[str, Any]] = {}

    def bump(name: str, jid: Any, reason: str, weight: int) -> None:
        key = T.name_key(name)
        if not key or key in followed_names or (R.s(jid) and R.s(jid) in followed_ids):
            return
        c = cands.setdefault(key, {"name": name, "judge_id": R.s(jid) or None, "score": 0, "reason": reason, "best": 0})
        c["score"] += weight
        if weight > c["best"]:
            c["reason"], c["best"] = reason, weight
        c["judge_id"] = c["judge_id"] or R.s(jid) or None

    M = zprp_public_matches
    ids = sorted(followed_ids)
    duos: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if ids:
        rows = await C.rows(select(M).where(or_(M.c.referee_1_id.in_(ids), M.c.referee_2_id.in_(ids))).order_by(M.c.scheduled_at.desc()).limit(400))
        comps: Dict[str, Tuple[str, int]] = {}
        for r in rows:
            refs = [x for x in T.referees_of_zprp_row(r) if x["role"] == "referee"]
            mine = [x for x in refs if x.get("judge_id") in followed_ids]
            for other in refs:
                if other in mine or other.get("judge_id") in followed_ids:
                    continue
                for m in mine:
                    d = duos.setdefault((T.name_key(m["name"]), T.name_key(other["name"])), {"a": m, "b": other, "count": 0})
                    d["count"] += 1
            if r.get("competition_id"):
                name, n = comps.get(r["competition_id"], (r.get("competition_name") or "", 0))
                comps[r["competition_id"]] = (name, n + 1)
        for d in duos.values():
            bump(d["b"]["name"], d["b"].get("judge_id"), f"Częsty współsędzia: {d['a']['name']} ({d['count']} meczów)", 10 * d["count"])
        top = [cid for cid, _ in sorted(comps.items(), key=lambda x: -x[1][1])[:3]]
        if top:
            since = _naive_local_now() - timedelta(days=120)
            others = await C.rows(select(M).where(M.c.competition_id.in_(top)).where(M.c.scheduled_at >= since).limit(600))
            for r in others:
                for x in T.referees_of_zprp_row(r):
                    if x["role"] == "referee":
                        bump(x["name"], x.get("judge_id"), f"Ta sama liga: {r.get('competition_name') or 'rozgrywki obserwowanych'}", 1)
    pair_ids = [p["id"] for p in await _my_pairs(real)]
    if pair_ids:
        for w in await C.rows(select(W.c.referees_json).where(W.c.pair_id.in_(pair_ids)).where(W.c.deleted_at.is_(None)).limit(200)):
            for x in T.clean_referees(R.json_value(w.get("referees_json"), [])):
                if x["role"] == "referee":
                    bump(x["name"], x.get("judge_id"), "Z meczów dodanych przez Twoją parę", 3)
    ranked = sorted(cands.values(), key=lambda c: -c["score"])
    out: List[Dict[str, Any]] = []
    for d in sorted(duos.values(), key=lambda d: -d["count"]):
        if d["count"] >= 3 and frozenset((T.name_key(d["a"]["name"]), T.name_key(d["b"]["name"]))) not in pair_follows:
            out.append({"kind": "pair", "name": f"{d['a']['name']} + {d['b']['name']}", "names": [d["a"]["name"], d["b"]["name"]],
                        "judge_ids": [d["a"].get("judge_id"), d["b"].get("judge_id")], "judge_id": None,
                        "reason": f"Stały duet ({d['count']} meczów razem)", "matches_with_video": None, "crest": None})
            break
    for c in ranked:
        if len(out) >= SUGGESTIONS_MAX:
            break
        out.append({"kind": "referee", "name": c["name"], "judge_id": c["judge_id"], "reason": c["reason"], "matches_with_video": None, "crest": None})
    mz, _state = S._setup(real)
    if mz is not None and out:
        gate = asyncio.Semaphore(3)

        async def count(item: Dict[str, Any]) -> None:
            async with gate:
                try:
                    item["matches_with_video"] = len([g for g in await mz.search_referee(item["names"][0] if item["kind"] == "pair" else item["name"],
                                                                                         video="with") if g.get("bunny_item_id")])
                except S._Stop:
                    item["matches_with_video"] = None

        await asyncio.gather(*(count(i) for i in out))
    return out[:SUGGESTIONS_MAX]


# ─── „Dziś sędziuje" (8:00) ─────────────────────────────────────────────────


def hhmm(item: Mapping[str, Any]) -> Optional[str]:
    """Godzina meczu (czas polski) z pozycji kalendarza albo None, gdy nieznana."""
    if not item.get("time_known"):
        return None
    raw = R.s(item.get("date"))
    try:
        if "T" in raw and (raw.endswith("Z") or "+" in raw[10:]):
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(WARSAW).strftime("%H:%M")
        return raw[11:16] or None
    except ValueError:
        return None


async def morning_once(now: Optional[datetime] = None) -> Dict[str, int]:
    """Poranny cichy push „Dziś sędziuje": jeden zbiorczy na osobę (obsada ZPRP + Meczoteka nadchodzące), ślad w `mentor_trybuna_today`
    (osoba + dzień) daje brak powtórek przy restarcie."""
    counts = {"judges": 0, "pushed": 0}
    today = (now or datetime.now(timezone.utc)).astimezone(WARSAW).date()
    day = today.isoformat()
    rows = await C.rows(select(F))
    if not rows:
        return counts
    sent = {r["judge_id"] for r in await C.rows(select(mentor_trybuna_today).where(mentor_trybuna_today.c.day == day))}
    mz = None
    flags = BR.load_flags()
    if flags.enabled and flags.configured and flags.default_enabled:
        from app import mentor_bastion_client as CL

        try:
            mz = S.Meczoteka(CL.get_client(), ["default"], C.MentorActor("0", display_name="Trybuna"))
        except CL.ConnectorUnavailable:
            mz = None
    by_judge: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_judge.setdefault(r["judge_id"], []).append(T.follow_shape(r))
    for jid, follows in by_judge.items():
        if jid in sent:
            continue
        counts["judges"] += 1
        try:
            cal = await calendar_for(await C.load_actor(jid, via="jwt"), follows, 1, mz_override=mz, whole_day=True)
        except Exception:  # noqa: BLE001
            logger.warning("trybuna: poranny kalendarz %s nieudany", jid, exc_info=True)
            continue
        mine = [i for i in cal["items"] if i.get("followed") and S.parse_day(i.get("date")) == today]
        if mine:
            first = mine[0]
            who = next((f["name"] for f in follows if f["id"] in first["followed"]), "obserwowany")
            when = hhmm(first)
            body = f"{who}: {first.get('home') or '?'} - {first.get('away') or '?'}" + (f" ({when})" if when else "")
            if len(mine) > 1:
                body += f" i {len(mine) - 1} inne"
            try:
                from app.mentor_panel_notify import push_data
                from app.push.push import send_push_to_judges_report

                data = push_data("trybuna", target="trybuna_calendar", tag="mentor-trybuna-today", quiet=True, extra={"day": day})
                await send_push_to_judges_report([jid], "Dziś sędziuje", body, data, app_variant="baza", preference_key="mentorPanel")
                counts["pushed"] += 1
            except Exception:  # noqa: BLE001
                logger.warning("trybuna: push porannego kalendarza nieudany", exc_info=True)
        try:
            await database.execute(mentor_trybuna_today.insert().values(judge_id=jid, day=day, sent_at=C.now()))
        except Exception:  # noqa: BLE001 - wyścig: już zapisane
            pass
    return counts


def seconds_to_morning(now: Optional[datetime] = None) -> float:
    """Sekundy do najbliższej 8:00 czasu polskiego."""
    local = (now or datetime.now(timezone.utc)).astimezone(WARSAW)
    target = local.replace(hour=8, minute=0, second=0, microsecond=0)
    if target <= local:
        target += timedelta(days=1)
    return (target - local).total_seconds()


async def run_trybuna_morning() -> None:
    """Pętla: po starcie (między 8:00 a 12:00 od razu - ślad chroni przed powtórką), potem co dobę o 8:00 czasu polskiego."""
    await asyncio.sleep(300)
    if 8 <= datetime.now(timezone.utc).astimezone(WARSAW).hour < 12:
        try:
            logger.info("mentor: trybuna rano %s", await morning_once())
        except Exception:  # noqa: BLE001
            logger.exception("mentor: trybuna rano nieudane")
    while True:
        try:
            await asyncio.sleep(seconds_to_morning())
            logger.info("mentor: trybuna rano %s", await morning_once())
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: trybuna rano nieudane")
            await asyncio.sleep(60)
