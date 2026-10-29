"""Trybuna Mentora - cudze mecze oglądane przez parę (28.10.2026). Kontrakt: `docs/mentor-panel.md` 8.11.

Mecz z Trybuny to wiersz `mentor_watched_matches` o `match_id` z przedrostkiem `tr_`. Reszta pokoju (nagrania, klipy, wątki,
REC, oś ProEla, synchronizacja, Biblioteka, Zestawienia, MP4) działa na tym samym `match_id` w zwykłych tabelach -
`mentor_panel_core.match_card` po prostu umie zbudować kartę takiego meczu. NIE MA oceny meczu (ani mentora, ani pary).

Ten moduł: karta meczu, dodawanie (kaseta Bastionu, YouTube, wklejony link), „bilet spinający" (ZPRP, ProEl, drugie źródło
wideo z pewnością i kandydatami), ręczne poprawki, szukanie, półki, oznaczenia sędziów na klipach i „Twoje zdanie".
Obserwowani, kanał, kolejka, karta sędziego i dzienny push: `app/mentor_trybuna_feed.py`.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, update

from app import mentor_bastion_rules as BR
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import mentor_trybuna_rules as T
from app.db import (
    database,
    mentor_clips,
    mentor_match_videos,
    mentor_threads,
    mentor_trybuna_clip_tags,
    mentor_trybuna_opinions,
    mentor_trybuna_shelf_clips,
    mentor_trybuna_shelves,
    mentor_watched_matches,
    saved_matches,
    zprp_public_matches,
)
from app.mentor_panel_auth import base_actor, mentor_actor

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Trybuna"])
Actor = C.MentorActor
W = mentor_watched_matches

MSG_NO_EVALUATION = "Mecz z Trybuny nie ma oceny - to materiał do oglądania i omawiania, nie do oceniania."


def no_evaluation() -> Exception:
    return C.err(409, "TRYBUNA_NO_EVALUATION", MSG_NO_EVALUATION)


# ─── Karta meczu z Trybuny ──────────────────────────────────────────────────


def _snap(row: Mapping[str, Any]) -> Dict[str, Any]:
    return R.json_value(row.get("card_json"), {})


def _links(row: Mapping[str, Any]) -> Dict[str, Any]:
    return R.json_value(row.get("links_json"), {})


def _refs(row: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return T.clean_referees(R.json_value(row.get("referees_json"), []))


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=lambda v: v.isoformat() if hasattr(v, "isoformat") else str(v))


async def watched_row(pair_id: str, match_id: str, *, alive: bool = True) -> Optional[Dict[str, Any]]:
    query = select(W).where(W.c.match_id == R.s(match_id)).where(W.c.pair_id == R.s(pair_id))
    if alive:
        query = query.where(W.c.deleted_at.is_(None))
    return await C.one(query)


def extras_of(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Pola karty meczu z Trybuny ponad zwykłym `MatchCard` (flaga `watched` odróżnia ją od meczów pary)."""
    links = _links(row)
    return {
        "watched": True, "origin": row.get("origin"), "bunny_item_id": row.get("bunny_item_id"), "title": row.get("title"),
        "zprp_match_id": row.get("zprp_match_id"), "proel_key": row.get("proel_key"),
        "referees": [r for r in _refs(row) if r.get("role") not in ("delegate", "table")],
        "delegates": [r for r in _refs(row) if r.get("role") == "delegate"],
        "tables": [r for r in _refs(row) if r.get("role") == "table"],
        "note": row.get("note"), "added_by": row.get("created_by"), "added_at": row.get("created_at"),
        "link_state": {kind: (links.get(kind) or {}).get("state", "none") for kind in T.LINK_KINDS},
        "can_evaluate": False,
    }


async def watched_card(ctx: Dict[str, Any], match_id: str, *, required: bool = True) -> Optional[Dict[str, Any]]:
    """Karta meczu z Trybuny (wzbogacona jak karta meczu pary); wołana z `mentor_panel_core.match_card`."""
    row = await watched_row(ctx["pair_id"], match_id)
    if not row:
        if required:
            raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
        return None
    card = T.card_from_snapshot(row["match_id"], _snap(row), title=row.get("title"))
    card.update(extras_of(row))
    out = (await C.enrich_cards(ctx, [card]))[0]
    out["has_proel"] = bool(row.get("proel_key"))
    out["sheets"] = {"delegate": None, "mentor": None}
    return out


async def watched_cards(ctx: Dict[str, Any], *, ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    query = select(W).where(W.c.pair_id == ctx["pair_id"]).where(W.c.deleted_at.is_(None)).order_by(W.c.created_at.desc())
    if ids is not None:
        query = query.where(W.c.match_id.in_(ids))
    found = await C.rows(query.limit(500))
    cards = []
    for row in found:
        card = T.card_from_snapshot(row["match_id"], _snap(row), title=row.get("title"))
        card.update(extras_of(row))
        cards.append(card)
    cards = await C.enrich_cards(ctx, cards)
    by_id = {r["match_id"]: r for r in found}
    for card in cards:
        card["has_proel"] = bool(by_id[card["match_id"]].get("proel_key"))
        card["sheets"] = {"delegate": None, "mentor": None}
    return cards


async def lookup_cards(pair_id: str, ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Lekkie karty (bez wzbogacania) meczów z Trybuny - dla Biblioteki, Zestawień i publicznych klipów."""
    wanted = [R.s(i) for i in ids if T.is_watched(i)]
    if not wanted:
        return {}
    found = await C.rows(select(W).where(W.c.pair_id == R.s(pair_id)).where(W.c.match_id.in_(wanted)))
    out = {}
    for row in found:
        card = T.card_from_snapshot(row["match_id"], _snap(row), title=row.get("title"))
        card.update(extras_of(row))
        out[row["match_id"]] = card
    return out


# ─── Bilet spinający: ZPRP, ProEl, drugie źródło wideo ──────────────────────


def _slim_zprp(card: Mapping[str, Any]) -> Dict[str, Any]:
    return {"match_id": card.get("match_id"), "scheduled_at": card.get("scheduled_at"), "match_code": card.get("match_code"),
            "competition_name": card.get("competition_name"), "round_name": card.get("round_name"),
            "home": {"name": (card.get("home") or {}).get("name"), "score": (card.get("home") or {}).get("score")},
            "away": {"name": (card.get("away") or {}).get("name"), "score": (card.get("away") or {}).get("score")}}


def _naive_local(day, shift: int) -> datetime:
    return datetime(day.year, day.month, day.day) + timedelta(days=shift)


async def zprp_candidates(snap: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Mecze z hurtowni ZPRP, które mogą być tym meczem: po kodzie (+- 3 dni), po dniu (+- 1 dzień) albo po rdzeniu nazwy drużyny."""
    from app.mentor_bastion_search import card_day, parse_day, team_tokens

    M = zprp_public_matches
    game_card = T.card_from_snapshot("x", snap)
    day = card_day(game_card) or parse_day(snap.get("scheduled_at"))
    code = R.s(snap.get("match_code"))
    conds = []
    if day:
        conds.append(and_(M.c.scheduled_at >= _naive_local(day, -1), M.c.scheduled_at < _naive_local(day, 2)))
    if code:
        window = and_(M.c.match_code == code)
        if day:
            window = and_(window, M.c.scheduled_at >= _naive_local(day, -3), M.c.scheduled_at < _naive_local(day, 4))
        conds.append(window)
    if not conds:
        words = {max(team_tokens((snap.get(side) or {}).get("name")) or [""], key=len) for side in ("home", "away")}
        words = {w for w in words if len(w) >= 4}
        for w in words:
            conds.append(or_(M.c.home_team_name.ilike(f"%{w}%"), M.c.away_team_name.ilike(f"%{w}%")))
    if not conds:
        return []
    try:
        found = await C.rows(select(M).where(or_(*conds)).limit(500))
    except Exception:  # noqa: BLE001 - brak hurtowni nie zatrzymuje dodawania
        logger.warning("trybuna: odczyt hurtowni ZPRP nieudany", exc_info=True)
        return []
    out = []
    for row in found:
        card = R.card_from_public(row)
        scored = T.score_zprp(snap, card)
        out.append({"zprp_match_id": R.s(row["match_id"]), **scored, "match": _slim_zprp(card),
                    "referees": T.referees_of_zprp_row(row)})
    return out


async def zprp_by_id(zprp_match_id: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(zprp_public_matches).where(zprp_public_matches.c.match_id == R.s(zprp_match_id)))


async def proel_candidates(zprp_match_id: Optional[str], code: Optional[str]) -> List[Dict[str, Any]]:
    """Protokoły ProEla: oficjalny (klucz = numer meczu) albo szkoleniowe (T-XXXXXXXX/NUMER). Zwykły numer nie jest kluczem
    między sezonami, więc zgodność ID ZPRP podnosi pewność, a rozjazd ID wyklucza wiersz."""
    from app.proel_training_key import is_training_key, match_number_from_key

    code = R.s(code)
    zid = R.s(zprp_match_id)
    if not code and not zid:
        return []
    conds = []
    if zid:
        conds.append(saved_matches.c.zprp_match_id == zid)
    if code:
        conds.append(saved_matches.c.match_number == code)
        conds.append(saved_matches.c.match_number.like(f"T-%/{code}"))
    try:
        found = await C.rows(select(saved_matches.c.match_number, saved_matches.c.zprp_match_id, saved_matches.c.status,
                                    saved_matches.c.updated_at).where(or_(*conds)).limit(40))
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: odczyt protokołów ProEla nieudany", exc_info=True)
        return []
    out = []
    for row in found:
        key = R.s(row["match_number"])
        stored = R.s(row.get("zprp_match_id"))
        if zid and stored and stored != zid:
            continue  # ten sam numer, inny mecz (inny sezon)
        training = is_training_key(key)
        number = match_number_from_key(key)
        if code and number != code and stored != zid:
            continue
        same_id = bool(zid and stored == zid)
        if training:
            conf, sure = (80 if same_id else 55), False
        else:
            conf, sure = (100 if same_id else 80 if number == code else 40), same_id
        out.append({"key": key, "kind": "training" if training else "official", "status": row.get("status"),
                    "zprp_match_id": stored or None, "updated_at": row.get("updated_at"), "confidence": conf, "sure": sure})
    out.sort(key=lambda c: (-c["confidence"], R.s(c["updated_at"]) and 0))
    return out


async def youtube_candidates(zprp_match_id: Optional[str], skip_ids: List[str]) -> List[Dict[str, Any]]:
    """Transmisje YouTube przypisane przez portal do meczu ZPRP (zero jednostek z puli dobowej)."""
    if not R.s(zprp_match_id):
        return []
    try:
        from app.streams import store

        rows = await store.streams_for([R.s(zprp_match_id)])
        streams = await store.with_channels(rows)
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: transmisje meczu nieczytelne", exc_info=True)
        return []
    out = []
    for s in streams:
        if s.get("platform") not in (None, "youtube") or R.s(s.get("video_id")) in skip_ids or not s.get("url"):
            continue
        conf = {"official": 100, "confirmed": 90}.get(s.get("confidence"), 50)
        out.append({"source": "youtube", "key": f"yt:{s.get('video_id')}", "url": s.get("url"), "title": s.get("title"),
                    "confidence": conf, "sure": conf >= 90, "thumbnail_url": s.get("thumbnail_url"),
                    "channel": s.get("channel_title") or (s.get("channel") or {}).get("title") if isinstance(s.get("channel"), dict) else s.get("channel_title")})
    out.sort(key=lambda c: -c["confidence"])
    return out[:5]


async def bastion_candidates(real: Actor, card: Mapping[str, Any], added_items: List[int]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Kasety z Meczoteki dla meczu (to samo, co Archiwista) + stan połączenia."""
    from app import mentor_bastion_search as S

    mz, state = S._setup(real)
    if mz is None:
        return [], {"state": state or "unconfigured", "message": S.bastion_state_message(state or "unconfigured")}
    try:
        games, _ = await S.find_for_card(mz, card, added_items, max_queries=2)
    except S._Stop as stop:
        kinds = [v.kind for _, v in stop.verdicts]
        kind = next((k for k in ("rate_limited", "unavailable", "forbidden") if k in kinds), "auth_required")
        return [], {"state": kind, "message": S.STATE_MESSAGES.get(kind)}
    out = [S._bastion_proposal(g) for g in games if g["confidence"] >= T.CANDIDATE_MIN and not g["added"]]
    return out[:5], {"state": "ok", "message": None}


def _public_zprp(c: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: c.get(k) for k in ("zprp_match_id", "confidence", "sure", "signals", "match", "referees")}


async def video_items_of(ctx: Dict[str, Any], match_id: str) -> Tuple[List[int], List[str]]:
    """(numery nagrań Bastion, identyfikatory filmów YouTube) już dodanych do pokoju meczu."""
    found = await C.rows(select(mentor_match_videos.c.url, mentor_match_videos.c.provider)
                         .where(mentor_match_videos.c.match_id == match_id).where(mentor_match_videos.c.pair_key == ctx["pair_key"])
                         .where(mentor_match_videos.c.deleted_at.is_(None)))
    items, yt = [], []
    for v in found:
        item = BR.parse_game_url(v.get("url")) if v.get("provider") == BR.PROVIDER else None
        if item:
            items.append(item)
        elif v.get("provider") == "youtube":
            yt.append(_youtube_id(v.get("url")))
    return items, [y for y in yt if y]


def _youtube_id(url: Any) -> str:
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(R.s(url))
    if parsed.hostname == "youtu.be":
        return parsed.path.strip("/")[:20]
    return (parse_qs(parsed.query).get("v") or [""])[0][:20]


async def autolink(ctx: Dict[str, Any], row: Dict[str, Any], real: Optional[Actor], *, kinds=T.LINK_KINDS,
                   keep_manual: bool = True) -> Dict[str, Any]:
    """Liczy (ponownie) powiązania meczu i zapisuje wynik. Ręczne poprawki (`manual`) zostają, dopóki nie `keep_manual=False`.

    Zwraca `LinkState`: {zprp, proel, video} - każde z `state` (auto|manual|candidates|none), `confidence`, `chosen`,
    `candidates`. Wideo: pewna propozycja (`sure`) dochodzi do pokoju sama, reszta czeka na jedno kliknięcie."""
    links = _links(row)
    snap = _snap(row)
    values: Dict[str, Any] = {}
    refs = _refs(row)

    def manual(kind: str) -> bool:
        return keep_manual and bool((links.get(kind) or {}).get("manual"))

    # 1. ZPRP
    if "zprp" in kinds and not manual("zprp"):
        cands = await zprp_candidates(snap)
        summary_id = R.s((links.get("zprp") or {}).get("hint_zprp_match_id"))
        if summary_id and not any(c["zprp_match_id"] == summary_id for c in cands):
            hit = await zprp_by_id(summary_id)
            if hit:
                card = R.card_from_public(hit)
                cands.append({"zprp_match_id": summary_id, "confidence": 100, "sure": True, "signals": {"code": None, "teams": None, "date": None, "category": None},
                              "match": _slim_zprp(card), "referees": T.referees_of_zprp_row(hit)})
        for c in cands:
            if c["zprp_match_id"] == summary_id:  # numer meczu podany przez Bastion to najmocniejszy dowód
                c["confidence"], c["sure"] = 100, True
        picked = T.pick_link(cands)
        links["zprp"] = {"state": picked["state"], "confidence": picked["confidence"], "sure": picked["sure"],
                         "chosen": _public_zprp(picked["chosen"]) if picked["chosen"] else None,
                         "candidates": [_public_zprp(c) for c in picked["candidates"]], "hint_zprp_match_id": summary_id or None}
        values["zprp_match_id"] = picked["chosen"]["zprp_match_id"] if picked["chosen"] else None
    zid = values.get("zprp_match_id", row.get("zprp_match_id"))
    if "zprp" in kinds and zid and not manual("zprp"):
        hit = await zprp_by_id(zid)
        if hit:
            snap = _fill_blanks(snap, R.card_from_public(hit))  # ZPRP uzupełnia puste pola, nie nadpisuje znanych
            from_zprp = T.referees_of_zprp_row(hit)
            if from_zprp:
                refs = from_zprp
            values["card_json"] = _dump(snap)
            values["referees_json"] = _dump(refs)
    # 2. ProEl
    if "proel" in kinds and not manual("proel"):
        code = R.s(snap.get("match_code"))
        if zid:
            hit = await zprp_by_id(zid)
            code = R.s((hit or {}).get("match_code")) or code
        cands = await proel_candidates(zid, code)
        picked = T.pick_link([{**c, "confidence": c["confidence"]} for c in cands])
        links["proel"] = {"state": picked["state"], "confidence": picked["confidence"], "sure": picked["sure"],
                          "chosen": picked["chosen"], "candidates": picked["candidates"]}
        values["proel_key"] = picked["chosen"]["key"] if picked["chosen"] else None
    # 3. Drugie źródło wideo
    if "video" in kinds:
        links["video"] = await _link_video(ctx, row, real, links.get("video") or {}, zid, snap)
    values.update(links_json=_dump(links), updated_at=C.now())
    await database.execute(update(W).where(W.c.match_id == row["match_id"]).values(**values))
    return await link_state(ctx, {**row, **values})


def _fill_blanks(snap: Mapping[str, Any], card: Mapping[str, Any]) -> Dict[str, Any]:
    """Migawka uzupełniona polami z karty ZPRP tam, gdzie była pusta (nigdy nie nadpisuje tego, co już znamy)."""
    base = T.card_snapshot(card) if card else {}
    return T.merge_snapshot(base, {k: v for k, v in snap.items()})


async def _link_video(ctx: Dict[str, Any], row: Dict[str, Any], real: Optional[Actor], previous: Dict[str, Any],
                      zid: Optional[str], snap: Mapping[str, Any]) -> Dict[str, Any]:
    if (previous or {}).get("manual"):
        return previous
    items, yt = await video_items_of(ctx, row["match_id"])
    card = T.card_from_snapshot(row["match_id"], snap, title=row.get("title"))
    state = {"state": "none", "candidates": [], "added": None, "message": None, "confidence": 0, "sure": False}
    cands: List[Dict[str, Any]] = []
    if row.get("origin") == "bastion":
        cands += await youtube_candidates(zid, yt)
    else:
        if real is not None:
            found, bastion = await bastion_candidates(real, card, items)
            cands += found
            if bastion["state"] != "ok":
                state["message"] = bastion["message"]
                state["bastion_state"] = bastion["state"]
        cands += await youtube_candidates(zid, yt) if row.get("origin") == "link" else []
    cands = [c for c in cands if c["confidence"] >= T.CANDIDATE_MIN]
    cands.sort(key=lambda c: -c["confidence"])
    state["candidates"] = [_slim_video_candidate(c) for c in cands[:T.MAX_CANDIDATES]]
    if cands:
        state.update(state="candidates", confidence=cands[0]["confidence"], sure=bool(cands[0]["sure"]))
    sure = [c for c in cands if c["sure"]]
    # Jeden pewny kandydat = dochodzi do pokoju sam (dwóch pewnych to niejednoznaczność: wybiera człowiek).
    if len(sure) == 1:
        from app.mentor_evaluations import insert_link_video

        try:
            from app.mentor_evaluation_request_rules import normalized_video_url

            video, _ = await insert_link_video(row["match_id"], ctx["pair_key"], normalized_video_url(sure[0]["url"]), ctx["actor"].judge_id)
            state.update(state="auto_added", added={"video_id": video["id"], "url": video.get("url"), "source": sure[0]["source"]})
            state["candidates"] = [c for c in state["candidates"] if c["key"] != sure[0]["key"]]
        except Exception:  # noqa: BLE001 - dodanie drugiego źródła nie może zepsuć dodania meczu
            logger.warning("trybuna: automatyczne dodanie drugiego źródła nieudane", exc_info=True)
    return state


def _slim_video_candidate(c: Mapping[str, Any]) -> Dict[str, Any]:
    out = {k: c.get(k) for k in ("source", "key", "url", "title", "confidence", "sure", "thumbnail_url", "channel")}
    game = c.get("game")
    if game:
        out["game"] = {k: game.get(k) for k in ("bunny_item_id", "home", "away", "date", "competition", "code", "score",
                                                "video_state", "signals")}
    return out


async def link_state(ctx: Dict[str, Any], row: Mapping[str, Any]) -> Dict[str, Any]:
    """Zapisany stan powiązań (bez ponownego liczenia); kandydaci wideo odświeżeni o to, co już jest w pokoju."""
    links = _links(row)
    out = {kind: dict(links.get(kind) or {"state": "none", "confidence": 0, "sure": False, "chosen": None, "candidates": []})
           for kind in T.LINK_KINDS}
    out["video"].setdefault("candidates", [])
    items, yt = await video_items_of(ctx, row["match_id"])
    have = set(f"bastion:{i}" for i in items) | set(f"yt:{y}" for y in yt)
    out["video"]["candidates"] = [c for c in out["video"].get("candidates") or [] if c.get("key") not in have]
    out["zprp_match_id"] = row.get("zprp_match_id")
    out["proel_key"] = row.get("proel_key")
    out["referees"] = _refs(row)
    # Komplet (runda 2): ZPRP i ProEl spięte (auto/manual), co najmniej jedno wideo w pokoju i nic nie czeka na wybór.
    videos = await C.rows(select(mentor_match_videos.c.id).where(mentor_match_videos.c.match_id == row["match_id"])
                          .where(mentor_match_videos.c.pair_key == ctx["pair_key"]).where(mentor_match_videos.c.deleted_at.is_(None)).limit(1))
    settled = all(out[k].get("state") in ("auto", "manual") for k in ("zprp", "proel"))
    open_choices = out["video"].get("state") == "candidates" or bool(out["video"].get("candidates"))
    complete = bool(settled and videos and not open_choices)
    stored = links.get("completed_at")
    if complete and not stored:
        stored = C.now().isoformat()
        links["completed_at"] = stored
        await database.execute(update(W).where(W.c.match_id == row["match_id"]).values(links_json=_dump(links)))
    elif not complete and stored:
        stored = None
        links.pop("completed_at", None)
        await database.execute(update(W).where(W.c.match_id == row["match_id"]).values(links_json=_dump(links)))
    out["complete"], out["completed_at"] = complete, stored if complete else None
    return out


# ─── Dodawanie meczu ────────────────────────────────────────────────────────


class GameIn(BaseModel):
    bunny_item_id: Optional[int] = None
    title: Optional[str] = Field(default=None, max_length=200)
    home: Optional[str] = Field(default=None, max_length=120)
    away: Optional[str] = Field(default=None, max_length=120)
    date: Optional[str] = Field(default=None, max_length=40)
    competition: Optional[str] = Field(default=None, max_length=120)
    code: Optional[str] = Field(default=None, max_length=40)
    score: Optional[str] = Field(default=None, max_length=20)
    referees: Optional[List[Any]] = Field(default=None, max_length=8)


class WatchBody(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2048)
    bunny_item_id: Optional[int] = Field(default=None, ge=1)
    game: Optional[GameIn] = None
    #: Ręczne uzupełnienia (YouTube i linki nie niosą składów ani daty).
    home: Optional[str] = Field(default=None, max_length=120)
    away: Optional[str] = Field(default=None, max_length=120)
    date: Optional[str] = Field(default=None, max_length=40)
    competition: Optional[str] = Field(default=None, max_length=120)
    code: Optional[str] = Field(default=None, max_length=40)
    referees: Optional[List[Any]] = Field(default=None, max_length=8)
    note: Optional[str] = Field(default=None, max_length=2000)
    link: bool = True


async def _bastion_summary(real: Actor, item: int) -> Optional[Dict[str, Any]]:
    """Podsumowanie meczu z game-context (bez embedu); brak sesji/dostępu = None, dodanie idzie dalej."""
    try:
        from app import mentor_bastion_client as CL
        from app.mentor_bastion import _client, _scope_judge, apply_verdict

        flags = BR.load_flags()
        scopes = BR.candidate_scopes(flags)
        if not flags.enabled or not scopes or not flags.configured:
            return None
        client = _client()
        for scope in scopes:
            owner = _scope_judge(scope, real)
            try:
                reply = await client.playback(scope, owner, item, include_embed=False)
            except CL.ConnectorUnavailable:
                return None
            verdict = BR.classify_playback(reply.status, reply.body)
            await apply_verdict(scope, owner, verdict)
            if verdict.kind == "ok":
                summary = reply.body.get("match") if isinstance(reply.body.get("match"), dict) else None
                return BR.public_match_summary(summary)
            if verdict.kind in ("rate_limited", "unavailable"):
                return None
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: podsumowanie meczu z Bastionu nieudane", exc_info=True)
    return None


def _resolve_source(body: WatchBody) -> Tuple[str, str, Optional[int]]:
    """(znormalizowany adres, pochodzenie, numer nagrania Bastion). 422 przy złym adresie."""
    from app.mentor_evaluation_request_rules import normalized_video_url, video_provider

    item = body.bunny_item_id or (body.game.bunny_item_id if body.game else None)
    raw = BR.canonical_game_url(item) if item else R.s(body.url)
    if not raw:
        raise C.err(422, "VIDEO_URL", "Podaj link do nagrania albo wybierz kasetę z Bastionu.")
    try:
        url = normalized_video_url(raw)
    except ValueError as exc:
        raise C.err(422, "VIDEO_URL", str(exc)) from exc
    if not url:
        raise C.err(422, "VIDEO_URL", "Podaj link do nagrania.")
    provider = video_provider(url)
    bunny = BR.parse_game_url(url) if provider == BR.PROVIDER else None
    origin = "bastion" if bunny else "youtube" if provider == "youtube" else "link"
    return url, origin, bunny


async def existing_for_url(ctx: Dict[str, Any], url: str) -> Optional[Dict[str, Any]]:
    """Mecz z Trybuny tej pary, który już ma to nagranie (jeden adres = jeden mecz na parę)."""
    found = await C.rows(select(mentor_match_videos.c.match_id).where(mentor_match_videos.c.pair_key == ctx["pair_key"])
                         .where(mentor_match_videos.c.normalized_url == url).where(mentor_match_videos.c.match_id.like("tr_%"))
                         .where(mentor_match_videos.c.deleted_at.is_(None)))
    for f in found:
        row = await watched_row(ctx["pair_id"], f["match_id"])
        if row:
            return row
    return None


async def create_watched(ctx: Dict[str, Any], actor: Actor, real: Optional[Actor], body: WatchBody, *, key: Optional[str] = None,
                         link: bool = True, find_video: bool = True) -> Tuple[Dict[str, Any], bool]:
    """Zakłada mecz z Trybuny z jednym nagraniem. Zwraca (wiersz, created). Ten sam adres w parze = ten sam mecz."""
    from app.mentor_evaluations import insert_link_video

    url, origin, bunny = _resolve_source(body)
    prior = await existing_for_url(ctx, url)
    if prior:
        return prior, False
    game = body.game.model_dump() if body.game else {}
    summary = await _bastion_summary(real, bunny) if (bunny and real is not None and not (game.get("home") and game.get("away"))) else None
    if summary:
        game = {**summary, **{k: v for k, v in game.items() if v}}
    snap = T.snapshot_from_game(game) if game else T.snapshot_from_title(None)
    over = {"home": {"name": R.plain(body.home, 120) or None}, "away": {"name": R.plain(body.away, 120) or None},
            "competition_name": R.plain(body.competition, 120) or None, "match_code": R.plain(body.code, 40) or None}
    if body.date:
        over.update(T.snapshot_from_game({"date": body.date}))
        over.pop("home", None)
        over.pop("away", None)
        over.pop("match_code", None)
        over.pop("competition_name", None)
        over["competition_name"] = R.plain(body.competition, 120) or None
        over["match_code"] = R.plain(body.code, 40) or None
        over["home"] = {"name": R.plain(body.home, 120) or None}
        over["away"] = {"name": R.plain(body.away, 120) or None}
    snap = T.merge_snapshot(snap, {k: v for k, v in over.items() if k not in ("score",)})
    refs = T.clean_referees((body.referees or []) + (game.get("referees") or []))
    match_id = T.new_match_id()
    stamp = C.now()
    hint = R.s(game.get("zprp_match_id"))
    row = {
        "match_id": match_id, "pair_id": ctx["pair_id"], "created_by": actor.judge_id, "created_at": stamp, "updated_at": stamp,
        "origin": origin, "bunny_item_id": bunny,
        "title": R.plain((game.get("title") or (body.game.title if body.game else None)), 200) or (f"Mecz z Bastionu #{bunny}" if bunny else None),
        "card_json": _dump(snap), "zprp_match_id": None, "proel_key": None,
        "links_json": _dump({"zprp": {"hint_zprp_match_id": hint} if hint else {}}), "referees_json": _dump(refs),
        "note": R.plain(body.note, 2000) or None,
    }
    await database.execute(W.insert().values(**row))
    try:
        video, _ = await insert_link_video(match_id, ctx["pair_key"], url, actor.judge_id, key)
    except Exception:
        await database.execute(W.delete().where(W.c.match_id == match_id))  # bez nagrania nie zostaje pusty mecz
        raise
    if origin != "bastion" and not (snap.get("home") or {}).get("name") and R.s(video.get("title")):
        patched = T.merge_snapshot(snap, T.snapshot_from_title(video.get("title")))
        await database.execute(update(W).where(W.c.match_id == match_id).values(card_json=_dump(patched), title=R.plain(video.get("title"), 200)))
        row["card_json"] = _dump(patched)
    elif not row["title"] and R.s(video.get("title")):
        await database.execute(update(W).where(W.c.match_id == match_id).values(title=R.plain(video.get("title"), 200)))
    await C.touch(ctx, actor.judge_id, "watched_added", "matches", match_id, {"origin": origin})
    fresh = await watched_row(ctx["pair_id"], match_id)
    if link:
        await autolink(ctx, fresh, real if find_video else None, kinds=T.LINK_KINDS if find_video else ("zprp", "proel"))
        fresh = await watched_row(ctx["pair_id"], match_id)
    return fresh, True


@router.post("/pairs/{pair_id}/trybuna/matches")
async def add_watched(pair_id: str, body: WatchBody, response: Response, real: Actor = Depends(base_actor),
                      actor: Actor = Depends(mentor_actor),
                      idempotency_header: Optional[str] = Header(default=None, alias="Idempotency-Key")):
    """Dodaje mecz do Trybuny: z kasety Bastionu (`bunny_item_id` + opcjonalnie `game`), z linku YouTube albo wklejonego adresu.
    Serwer od razu spina ID zawodów ZPRP, protokół ProEla i drugie źródło wideo (`links`). Ten sam adres w parze = ten sam mecz
    (`created:false`). Brak oceny meczu."""
    from app.mentor_panel_media import idempotency_key

    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="video")
    row, created = await create_watched(ctx, actor, real, body, key=idempotency_key(idempotency_header), link=body.link)
    return await _created_payload(ctx, row, created)


async def _created_payload(ctx: Dict[str, Any], row: Mapping[str, Any], created: bool) -> Dict[str, Any]:
    from app.mentor_panel_media import video_list

    card = await watched_card(ctx, row["match_id"])
    videos, _ = await video_list(ctx, row["match_id"])
    return {"created": created, "match": card, "videos": videos, "links": await link_state(ctx, row), "rev": ctx["rev"]}


class BulkItem(BaseModel):
    bunny_item_id: int = Field(ge=1)
    game: Optional[GameIn] = None


class BulkBody(BaseModel):
    items: List[BulkItem] = Field(min_length=1, max_length=20)


@router.post("/pairs/{pair_id}/trybuna/matches/bulk")
async def add_watched_bulk(pair_id: str, body: BulkBody, response: Response, real: Actor = Depends(base_actor),
                           actor: Actor = Depends(mentor_actor)):
    """Do 20 kaset naraz (np. po „Wczytaj sezon obserwowanego"): bez szukania drugiego źródła wideo, tylko ZPRP i ProEl z bazy."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="video")
    created, existing, failed = [], [], []
    for item in body.items:
        try:
            row, made = await create_watched(ctx, actor, None, WatchBody(bunny_item_id=item.bunny_item_id, game=item.game),
                                             find_video=False)
            (created if made else existing).append(row["match_id"])
        except Exception as exc:  # noqa: BLE001 - jedna zła kaseta nie zabiera reszty
            failed.append({"bunny_item_id": item.bunny_item_id, "code": getattr(getattr(exc, "detail", None), "get", lambda *_: None)("code") or "ERROR"})
    return {"created": created, "existing": existing, "failed": failed, "rev": ctx["rev"]}


@router.get("/pairs/{pair_id}/trybuna/matches")
async def list_watched(pair_id: str, q: str = Query("", max_length=80), referee: str = Query("", max_length=80),
                       origin: str = Query("", max_length=10), season: str = Query("", max_length=20),
                       trashed: int = Query(0, ge=0, le=1), actor: Actor = Depends(mentor_actor)):
    """Mecze z Trybuny tej pary (ostatnio dodane najpierw). Filtry: `q` (drużyny/kod/tytuł), `referee`, `origin`, `season`.
    Każdy mecz ma pola do grupowania: `home`/`away` (+ `home_crest`/`away_crest`), `competition`, `match_code`, `played_at`, `referees[]`,
    `videos_count`, `clips_count`, `added_at`, `added_by` (+ `added_by_name`). `trashed=1` zwraca kosz (usunięte w ostatnich 30 dniach,
    z `deleted_at` i `expires_at`)."""
    ctx = await C.pair_context(pair_id, actor)
    if trashed:
        return await trashed_matches(ctx)
    cards = await watched_cards(ctx)
    from app import mentor_bastion_search as S

    await S.attach_crests(cards, (("home", "home_crest"), ("away", "away_crest")))
    needle = T.name_key(q) if q else ""
    ref_key = T.name_key(referee) if referee else ""
    out = []
    for c in cards:
        if origin and c.get("origin") != origin:
            continue
        if season and c.get("season") != season:
            continue
        if needle:
            hay = T.name_key(" ".join(R.s(x) for x in ((c.get("home") or {}).get("name"), (c.get("away") or {}).get("name"),
                                                        c.get("match_code"), c.get("title"), c.get("competition_name"))))
            if not all(w in hay.split() or w in hay for w in needle.split()):
                continue
        if ref_key and not any(T.name_key(r.get("name")) == ref_key for r in c.get("referees") or []):
            continue
        out.append(c)
    names = await C.people({c.get("added_by") for c in out if c.get("added_by")})
    for c in out:
        when = c.get("scheduled_at")
        c.update({"competition": c.get("competition_name"), "played_at": when.isoformat() if hasattr(when, "isoformat") else when,
                  "videos_count": int((c.get("videos") or {}).get("count") or 0), "clips_count": int((c.get("clips") or {}).get("count") or 0),
                  "added_by_name": C.person(names, c["added_by"])["name"] if c.get("added_by") else None})
    return {"matches": out, "seasons": R.seasons_of(out), "rev": ctx["rev"]}


class WatchedPatch(BaseModel):
    note: Optional[str] = Field(default=None, max_length=2000)
    home: Optional[str] = Field(default=None, max_length=120)
    away: Optional[str] = Field(default=None, max_length=120)
    date: Optional[str] = Field(default=None, max_length=40)
    competition: Optional[str] = Field(default=None, max_length=120)
    code: Optional[str] = Field(default=None, max_length=40)
    referees: Optional[List[Any]] = Field(default=None, max_length=8)


@router.patch("/pairs/{pair_id}/trybuna/matches/{match_id}")
async def edit_watched(pair_id: str, match_id: str, body: WatchedPatch, actor: Actor = Depends(mentor_actor)):
    """Poprawka opisu meczu (drużyny, data, kod, sędziowie, notatka); po zmianie drużyn/daty/kodu serwer liczy powiązania od nowa."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await watched_row(ctx["pair_id"], match_id)
    if not row:
        raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
    snap = _snap(row)
    over: Dict[str, Any] = {}
    changed = False
    for field, key in (("home", "home"), ("away", "away")):
        if getattr(body, field) is not None:
            over[key] = {"name": R.plain(getattr(body, field), 120) or None}
            changed = True
    if body.competition is not None:
        over["competition_name"] = R.plain(body.competition, 120) or None
    if body.code is not None:
        over["match_code"] = R.plain(body.code, 40) or None
        changed = True
    if body.date is not None:
        parsed = T.snapshot_from_game({"date": body.date})
        if parsed.get("scheduled_at"):
            over["scheduled_at"], over["season"] = parsed["scheduled_at"], parsed["season"]
            changed = True
    values: Dict[str, Any] = {"updated_at": C.now()}
    if over:
        values["card_json"] = _dump(T.merge_snapshot(snap, over))
    if body.referees is not None:
        values["referees_json"] = _dump(T.clean_referees(body.referees))
    if body.note is not None:
        values["note"] = R.plain(body.note, 2000) or None
    await database.execute(update(W).where(W.c.match_id == row["match_id"]).values(**values))
    fresh = await watched_row(ctx["pair_id"], match_id)
    await C.touch(ctx, actor.judge_id, "watched_edited", "matches", row["match_id"], {})
    if changed:
        await autolink(ctx, fresh, None, kinds=("zprp", "proel"))
    return await _created_payload(ctx, await watched_row(ctx["pair_id"], match_id), False)


TRASH_DAYS = 30


async def match_impact(ctx: Dict[str, Any], match_id: str) -> Dict[str, int]:
    """Co dotyczy meczu z Trybuny: `clips` (żywe klipy), `threads` (wątki), `queue` (wpisy w kolejkach „Do obejrzenia")."""
    from app.db import mentor_trybuna_queue

    clips = await C.rows(select(mentor_clips.c.id).where(mentor_clips.c.pair_id == ctx["pair_id"]).where(mentor_clips.c.match_id == match_id)
                         .where(mentor_clips.c.deleted_at.is_(None)))
    threads = await C.rows(select(mentor_threads.c.id).where(mentor_threads.c.pair_id == ctx["pair_id"]).where(mentor_threads.c.match_id == match_id))
    queue = await C.rows(select(mentor_trybuna_queue.c.judge_id).where(mentor_trybuna_queue.c.pair_id == ctx["pair_id"])
                         .where(mentor_trybuna_queue.c.match_id == match_id))
    return {"clips": len(clips), "threads": len(threads), "queue": len(queue)}


@router.delete("/pairs/{pair_id}/trybuna/matches/{match_id}")
async def remove_watched(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    """Przenosi mecz z Trybuny do kosza (30 dni, `POST .../restore` przywraca). Odpowiedź: `{ok, match_id, impact: {clips, threads, queue},
    expires_at}`. Nagrania, klipy i wątki zostają w bazie: klipy dalej są w Bibliotece, a mecz znika z listy, pokoju i kolejek."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await watched_row(ctx["pair_id"], match_id)
    if not row:
        raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
    impact = await match_impact(ctx, row["match_id"])
    stamp = C.now()
    await database.execute(update(W).where(W.c.match_id == row["match_id"]).where(W.c.deleted_at.is_(None))
                           .values(deleted_at=stamp, deleted_by=actor.judge_id))
    await C.touch(ctx, actor.judge_id, "watched_removed", "matches", row["match_id"], {})
    return {"ok": True, "match_id": row["match_id"], "impact": impact, "expires_at": stamp + timedelta(days=TRASH_DAYS)}


@router.post("/pairs/{pair_id}/trybuna/matches/{match_id}/restore")
async def restore_watched(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    """Przywraca mecz z kosza (do 30 dni od usunięcia): 409 `NOT_IN_TRASH`, gdy meczu nie ma w koszu, 409 `TRASH_EXPIRED` po 30 dniach."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await watched_row(ctx["pair_id"], match_id, alive=False)
    if not row or row.get("deleted_at") is None:
        raise C.err(409, "NOT_IN_TRASH", "Ten mecz nie leży w koszu.")
    if R.aware(row["deleted_at"]) < C.now() - timedelta(days=TRASH_DAYS):
        raise C.err(409, "TRASH_EXPIRED", "Minęło 30 dni - tego meczu nie da się już przywrócić.")
    await database.execute(update(W).where(W.c.match_id == row["match_id"]).values(deleted_at=None, deleted_by=None, updated_at=C.now()))
    await C.touch(ctx, actor.judge_id, "watched_restored", "matches", row["match_id"], {})
    return {"ok": True, "match": await watched_card(ctx, row["match_id"]), "rev": ctx["rev"]}


async def trashed_matches(ctx: Dict[str, Any]) -> Dict[str, Any]:
    limit = C.now() - timedelta(days=TRASH_DAYS)
    found = await C.rows(select(W).where(W.c.pair_id == ctx["pair_id"]).where(W.c.deleted_at.is_not(None)).order_by(W.c.deleted_at.desc()).limit(200))
    names = await C.people({r.get("deleted_by") for r in found if r.get("deleted_by")})
    out = []
    for r in found:
        if R.aware(r["deleted_at"]) < limit:
            continue
        card = T.card_from_snapshot(r["match_id"], _snap(r), title=r.get("title"))
        card.update(extras_of(r))
        out.append({**card, "deleted_at": r["deleted_at"], "deleted_by": C.person(names, r.get("deleted_by")) if r.get("deleted_by") else None,
                    "expires_at": R.aware(r["deleted_at"]) + timedelta(days=TRASH_DAYS), "impact": await match_impact(ctx, r["match_id"])})
    return {"matches": out, "trashed": True, "rev": ctx["rev"]}


# ─── Powiązania: odczyt, ponowne liczenie, ręczna poprawka ──────────────────


@router.get("/pairs/{pair_id}/trybuna/matches/{match_id}/links")
async def get_links(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    row = await watched_row(ctx["pair_id"], match_id)
    if not row:
        raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
    return {"links": await link_state(ctx, row), "rev": ctx["rev"]}


class RelinkBody(BaseModel):
    kinds: Optional[List[str]] = Field(default=None, max_length=3)
    #: true = także odrzuć wcześniejsze ręczne poprawki.
    force: bool = False


@router.post("/pairs/{pair_id}/trybuna/matches/{match_id}/relink")
async def relink(pair_id: str, match_id: str, response: Response, body: Optional[RelinkBody] = None,
                 real: Actor = Depends(base_actor), actor: Actor = Depends(mentor_actor)):
    """Liczy powiązania od nowa (`kinds`: zprp, proel, video; domyślnie wszystkie). Ręczne poprawki zostają bez `force`."""
    response.headers["Cache-Control"] = "no-store"
    body = body or RelinkBody()
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await watched_row(ctx["pair_id"], match_id)
    if not row:
        raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
    kinds = tuple(k for k in (body.kinds or T.LINK_KINDS) if k in T.LINK_KINDS) or T.LINK_KINDS
    links = await autolink(ctx, row, real, kinds=kinds, keep_manual=not body.force)
    await C.touch(ctx, actor.judge_id, "watched_relinked", "matches", row["match_id"], {"kinds": list(kinds)})
    return {"links": links, "match": await watched_card(ctx, row["match_id"]), "rev": ctx["rev"]}


class LinkPut(BaseModel):
    #: Numer meczu w hurtowni ZPRP; `""` zdejmuje powiązanie (i nie pozwala automatowi go odtworzyć).
    zprp_match_id: Optional[str] = Field(default=None, max_length=40)
    #: Klucz protokołu ProEla (numer meczu albo T-XXXXXXXX/NUMER); `""` zdejmuje.
    proel_key: Optional[str] = Field(default=None, max_length=80)
    #: Adres kandydata drugiego źródła wideo - dodaje go do pokoju („jedno kliknięcie").
    video_url: Optional[str] = Field(default=None, max_length=2048)


@router.put("/pairs/{pair_id}/trybuna/matches/{match_id}/links")
async def put_links(pair_id: str, match_id: str, body: LinkPut, response: Response, actor: Actor = Depends(mentor_actor)):
    """Ręczna poprawka biletu: wskazanie meczu ZPRP / protokołu ProEla / dodanie kandydata wideo. Poprawka jest „manual" -
    automat jej nie nadpisze, dopóki nie przyjdzie `relink` z `force`."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await watched_row(ctx["pair_id"], match_id)
    if not row:
        raise C.err(404, "MATCH_NOT_FOUND", "To nie jest mecz z Trybuny tej pary.")
    links = _links(row)
    values: Dict[str, Any] = {"updated_at": C.now()}
    sent = body.model_fields_set
    if "zprp_match_id" in sent:
        zid = R.s(body.zprp_match_id)
        if zid:
            hit = await zprp_by_id(zid)
            if not hit:
                raise C.err(404, "ZPRP_MATCH_NOT_FOUND", "Nie ma takiego meczu w hurtowni ZPRP.")
            card = R.card_from_public(hit)
            scored = T.score_zprp(_snap(row), card)
            chosen = {"zprp_match_id": zid, **scored, "match": _slim_zprp(card), "referees": T.referees_of_zprp_row(hit)}
            links["zprp"] = {"state": "manual", "manual": True, "confidence": 100, "sure": True, "chosen": _public_zprp(chosen),
                             "candidates": (links.get("zprp") or {}).get("candidates") or []}
            values.update(zprp_match_id=zid, card_json=_dump(_fill_blanks(_snap(row), card)),
                          referees_json=_dump(T.referees_of_zprp_row(hit) or _refs(row)))
        else:
            links["zprp"] = {"state": "none", "manual": True, "confidence": 0, "sure": False, "chosen": None,
                             "candidates": (links.get("zprp") or {}).get("candidates") or []}
            values["zprp_match_id"] = None
    if "proel_key" in sent:
        key = R.s(body.proel_key)
        if key:
            hit = await C.one(select(saved_matches.c.match_number, saved_matches.c.status).where(saved_matches.c.match_number == key))
            if not hit:
                raise C.err(404, "PROEL_NOT_FOUND", "Nie ma takiego protokołu w ProElu.")
            links["proel"] = {"state": "manual", "manual": True, "confidence": 100, "sure": True,
                              "chosen": {"key": key, "kind": "training" if key.startswith("T-") else "official", "status": hit.get("status")},
                              "candidates": (links.get("proel") or {}).get("candidates") or []}
            values["proel_key"] = key
        else:
            links["proel"] = {"state": "none", "manual": True, "confidence": 0, "sure": False, "chosen": None,
                              "candidates": (links.get("proel") or {}).get("candidates") or []}
            values["proel_key"] = None
    values["links_json"] = _dump(links)
    await database.execute(update(W).where(W.c.match_id == row["match_id"]).values(**values))
    fresh = await watched_row(ctx["pair_id"], match_id)
    # Zmiana meczu ZPRP odświeża protokół ProEla (chyba że ręczny).
    if "zprp_match_id" in sent and "proel_key" not in sent:
        await autolink(ctx, fresh, None, kinds=("proel",))
        fresh = await watched_row(ctx["pair_id"], match_id)
    if body.video_url:
        from app.mentor_evaluation_request_rules import normalized_video_url
        from app.mentor_evaluations import insert_link_video

        try:
            url = normalized_video_url(body.video_url)
        except ValueError as exc:
            raise C.err(422, "VIDEO_URL", str(exc)) from exc
        await insert_link_video(row["match_id"], ctx["pair_key"], url, actor.judge_id)
    await C.touch(ctx, actor.judge_id, "watched_linked", "matches", row["match_id"], {})
    return {"links": await link_state(ctx, fresh), "match": await watched_card(ctx, row["match_id"]), "rev": ctx["rev"]}


# ─── Półki ──────────────────────────────────────────────────────────────────

SH = mentor_trybuna_shelves
SC = mentor_trybuna_shelf_clips


class ShelfBody(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    color: Optional[str] = Field(default=None, max_length=20)


class ShelfPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=60)
    color: Optional[str] = Field(default=None, max_length=20)
    archived: Optional[bool] = None
    sort: Optional[int] = Field(default=None, ge=0, le=1000)


async def _shelf(ctx: Dict[str, Any], shelf_id: str) -> Dict[str, Any]:
    if shelf_id == "disputed":
        raise C.err(422, "SHELF_SYSTEM", "Półka \"Sporne\" jest systemowa - wypełnia się sama.")
    row = await C.one(select(SH).where(SH.c.id == shelf_id).where(SH.c.pair_id == ctx["pair_id"]))
    if not row:
        raise C.err(404, "NOT_FOUND", "Nie ma takiej półki.")
    return row


async def shelves_payload(ctx: Dict[str, Any]) -> Dict[str, Any]:
    shelves = await C.rows(select(SH).where(SH.c.pair_id == ctx["pair_id"]).order_by(SH.c.sort.asc(), SH.c.created_at.asc()))
    ids = [s["id"] for s in shelves]
    links = await C.rows(select(SC).where(SC.c.shelf_id.in_(ids)).order_by(SC.c.position.asc())) if ids else []
    live = {c["id"]: c for c in await C.rows(select(mentor_clips.c.id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                                              .where(mentor_clips.c.deleted_at.is_(None)))} if links else {}
    by_shelf: Dict[str, List[str]] = {}
    by_clip: Dict[str, List[str]] = {}
    for l in links:
        if l["clip_id"] in live:
            by_shelf.setdefault(l["shelf_id"], []).append(l["clip_id"])
            by_clip.setdefault(l["clip_id"], []).append(l["shelf_id"])
    # Systemowa półka "Sporne": klipy, przy których zdania pary są podzielone (agree i differ).
    disputed = sorted(await disputed_clip_ids(ctx), key=lambda c: c)
    live_ids = {c["id"] for c in await C.rows(select(mentor_clips.c.id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                                              .where(mentor_clips.c.deleted_at.is_(None)).where(mentor_clips.c.id.in_(disputed)))} if disputed else set()
    disputed = [c for c in disputed if c in live_ids]
    for cid in disputed:
        by_clip.setdefault(cid, []).append("disputed")
    system = {"id": "disputed", "system": True, "name": "Sporne", "color": None, "sort": -1, "archived": False, "clip_ids": disputed,
              "clips_count": len(disputed), "created_by": None}
    return {"shelves": [system] + [{"id": s["id"], "system": False, "name": s["name"], "color": s.get("color"), "sort": int(s.get("sort") or 0),
                                    "archived": bool(s.get("archived")), "clip_ids": by_shelf.get(s["id"], []),
                                    "clips_count": len(by_shelf.get(s["id"], [])), "created_by": s.get("created_by")} for s in shelves],
            "by_clip": by_clip, "limit": T.MAX_SHELVES, "rev": ctx["rev"]}


@router.get("/pairs/{pair_id}/trybuna/shelves")
async def list_shelves(pair_id: str, actor: Actor = Depends(mentor_actor)):
    """Półki tematyczne pary (np. „Linia 6 m", „Kontakt") z `clip_ids` w kolejności; ten sam klip może leżeć na wielu półkach."""
    return await shelves_payload(await C.pair_context(pair_id, actor))


@router.post("/pairs/{pair_id}/trybuna/shelves")
async def create_shelf(pair_id: str, body: ShelfBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    existing = await C.rows(select(SH.c.id, SH.c.name).where(SH.c.pair_id == ctx["pair_id"]))
    if len(existing) >= T.MAX_SHELVES:
        raise C.err(422, "SHELF_LIMIT", f"Para może mieć najwyżej {T.MAX_SHELVES} półek.")
    name = R.plain(body.name, 60)
    if any(T.name_key(e["name"]) == T.name_key(name) for e in existing):
        raise C.err(409, "SHELF_EXISTS", "Półka o takiej nazwie już jest.")
    await database.execute(SH.insert().values(id=R.new_id(), pair_id=ctx["pair_id"], name=name, color=R.plain(body.color, 20) or None,
                                              sort=len(existing), created_by=actor.judge_id, created_at=C.now()))
    await C.touch(ctx, actor.judge_id, "shelf_created", "clips", None, {"name": name})
    return await shelves_payload(ctx)


@router.patch("/pairs/{pair_id}/trybuna/shelves/{shelf_id}")
async def patch_shelf(pair_id: str, shelf_id: str, body: ShelfPatch, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    await _shelf(ctx, shelf_id)
    values: Dict[str, Any] = {}
    if body.name is not None:
        values["name"] = R.plain(body.name, 60)
    if body.color is not None:
        values["color"] = R.plain(body.color, 20) or None
    if body.archived is not None:
        values["archived"] = body.archived
    if body.sort is not None:
        values["sort"] = body.sort
    if values:
        await database.execute(update(SH).where(SH.c.id == shelf_id).values(**values))
        await C.touch(ctx, actor.judge_id, "shelf_updated", "clips", None, {"id": shelf_id})
    return await shelves_payload(ctx)


@router.delete("/pairs/{pair_id}/trybuna/shelves/{shelf_id}")
async def delete_shelf(pair_id: str, shelf_id: str, actor: Actor = Depends(mentor_actor)):
    """Usuwa półkę (klipy zostają w Bibliotece)."""
    ctx = await C.pair_context(pair_id, actor, action="create")
    await _shelf(ctx, shelf_id)
    await database.execute(SC.delete().where(SC.c.shelf_id == shelf_id))
    await database.execute(SH.delete().where(SH.c.id == shelf_id))
    await C.touch(ctx, actor.judge_id, "shelf_deleted", "clips", None, {"id": shelf_id})
    return await shelves_payload(ctx)


class ShelfClips(BaseModel):
    clip_ids: List[str] = Field(default_factory=list, max_length=300)


@router.put("/pairs/{pair_id}/trybuna/shelves/{shelf_id}/clips")
async def set_shelf_clips(pair_id: str, shelf_id: str, body: ShelfClips, actor: Actor = Depends(mentor_actor)):
    """Cała zawartość półki w kolejności (pozycja = kolejność listy). Klipy muszą należeć do pary."""
    ctx = await C.pair_context(pair_id, actor, action="create")
    await _shelf(ctx, shelf_id)
    wanted = list(dict.fromkeys(R.s(c) for c in body.clip_ids if R.s(c)))
    mine = {c["id"] for c in await C.rows(select(mentor_clips.c.id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                                           .where(mentor_clips.c.id.in_(wanted)).where(mentor_clips.c.deleted_at.is_(None)))} if wanted else set()
    if len(mine) != len(wanted):
        raise C.err(404, "NOT_FOUND", "Któregoś klipu nie ma w tej parze.")
    stamp = C.now()
    async with database.transaction():
        await database.execute(SC.delete().where(SC.c.shelf_id == shelf_id))
        for pos, cid in enumerate(wanted):
            await database.execute(SC.insert().values(shelf_id=shelf_id, clip_id=cid, position=pos, added_by=actor.judge_id, added_at=stamp))
    await C.touch(ctx, actor.judge_id, "shelf_clips", "clips", None, {"id": shelf_id})
    return await shelves_payload(ctx)


class ShelfClipOne(BaseModel):
    clip_id: str = Field(min_length=1, max_length=64)


@router.post("/pairs/{pair_id}/trybuna/shelves/{shelf_id}/clips")
async def add_shelf_clip(pair_id: str, shelf_id: str, body: ShelfClipOne, actor: Actor = Depends(mentor_actor)):
    """„Dodaj na półkę" - jeden klip, na końcu; powtórka nic nie robi. Ten sam klip może być na wielu półkach."""
    ctx = await C.pair_context(pair_id, actor, action="create")
    await _shelf(ctx, shelf_id)
    clip = await C.one(select(mentor_clips.c.id).where(mentor_clips.c.id == body.clip_id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                       .where(mentor_clips.c.deleted_at.is_(None)))
    if not clip:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    have = await C.rows(select(SC.c.clip_id, SC.c.position).where(SC.c.shelf_id == shelf_id))
    if not any(h["clip_id"] == body.clip_id for h in have):
        await database.execute(SC.insert().values(shelf_id=shelf_id, clip_id=body.clip_id, added_by=actor.judge_id, added_at=C.now(),
                                                  position=max([int(h.get("position") or 0) for h in have], default=-1) + 1))
        await C.touch(ctx, actor.judge_id, "shelf_clip_added", "clips", None, {"id": shelf_id, "clip": body.clip_id})
    return await shelves_payload(ctx)


@router.delete("/pairs/{pair_id}/trybuna/shelves/{shelf_id}/clips/{clip_id}")
async def remove_shelf_clip(pair_id: str, shelf_id: str, clip_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    await _shelf(ctx, shelf_id)
    await database.execute(SC.delete().where(SC.c.shelf_id == shelf_id).where(SC.c.clip_id == clip_id))
    await C.touch(ctx, actor.judge_id, "shelf_clip_removed", "clips", None, {"id": shelf_id, "clip": clip_id})
    return await shelves_payload(ctx)


class ExportBody(BaseModel):
    target: str = Field(pattern="^(zestawienie|seans)$")


@router.post("/pairs/{pair_id}/trybuna/shelves/{shelf_id}/export")
async def export_shelf(pair_id: str, shelf_id: str, body: ExportBody, actor: Actor = Depends(mentor_actor)):
    """Eksport półki do Zestawienia (istniejący mechanizm `POST /pairs/{p}/compilations`, tryb `free`, klipy w kolejności półki).
    `target: "seans"` robi to samo z nazwą "Seans: <półka>" i opisem seansu (wspólne oglądanie). Półka systemowa `disputed` też.
    -> `{id, kind, url_path, name, clips}`. 422 `SHELF_EMPTY`, gdy półka nie ma żywych klipów."""
    from app import mentor_panel_library as L

    ctx = await C.pair_context(pair_id, actor, action="create")
    if shelf_id == "disputed":
        name, clip_ids = "Sporne", sorted(await disputed_clip_ids(ctx))
    else:
        shelf = await _shelf(ctx, shelf_id)
        name = shelf["name"]
        clip_ids = [r["clip_id"] for r in await C.rows(select(SC).where(SC.c.shelf_id == shelf_id).order_by(SC.c.position.asc()))]
    live = {c["id"] for c in await C.rows(select(mentor_clips.c.id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                                           .where(mentor_clips.c.deleted_at.is_(None)).where(mentor_clips.c.id.in_(clip_ids)))} if clip_ids else set()
    clip_ids = [c for c in clip_ids if c in live]
    if not clip_ids:
        raise C.err(422, "SHELF_EMPTY", "Na tej półce nie ma jeszcze klipów do wyeksportowania.")
    title = name if body.target == "zestawienie" else f"Seans: {name}"
    desc = f"Z półki \"{name}\"." if body.target == "zestawienie" else f"Seans do wspólnego oglądania z półki \"{name}\"."
    comp = await L.create_compilation(pair_id, L.CompilationBody(name=title[:60], mode="free", description=desc,
                                                                 items=[{"clip_id": c} for c in clip_ids]), actor)
    return {"id": comp["id"], "kind": body.target, "url_path": f"/mentor/{ctx['pair_id']}/zestawienia/{comp['id']}", "name": comp.get("name"),
            "clips": len(clip_ids)}


# ─── Oznaczenia sędziów na klipie ───────────────────────────────────────────

TG = mentor_trybuna_clip_tags


async def _clip_ctx(clip_id: str, actor: Actor, action: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    if not clip or clip.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    return await C.pair_context(clip["pair_id"], actor, action=action), clip


def tag_shape(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {"name": row.get("name"), "judge_id": row.get("judge_id"), "role": row.get("role") or "?", "position": row.get("position"),
            "created_by": row.get("created_by")}


@router.get("/clips/{clip_id}/referees")
async def clip_referees(clip_id: str, actor: Actor = Depends(mentor_actor)):
    """Sędziowie oznaczeni na klipie: nazwisko, rola A/B/?, pozycja. Do podpowiedzi: sędziowie meczu z Trybuny."""
    ctx, clip = await _clip_ctx(clip_id, actor, "view")
    tags = await C.rows(select(TG).where(TG.c.clip_id == clip_id).order_by(TG.c.created_at.asc()))
    row = await watched_row(ctx["pair_id"], clip["match_id"]) if T.is_watched(clip["match_id"]) else None
    return {"referees": [tag_shape(t) for t in tags], "suggestions": _refs(row) if row else [], "roles": list(T.ROLES)}


class RefereeTags(BaseModel):
    referees: List[Dict[str, Any]] = Field(default_factory=list, max_length=T.MAX_REFEREE_TAGS + 2)


@router.put("/clips/{clip_id}/referees")
async def set_clip_referees(clip_id: str, body: RefereeTags, actor: Actor = Depends(mentor_actor)):
    """Zastępuje oznaczenia sędziów na klipie (A/B/? + pozycja). To nie jest ocena - tylko wskazanie, kogo dotyczy fragment."""
    ctx, clip = await _clip_ctx(clip_id, actor, "create")
    try:
        tags = T.clean_tags(body.referees)
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    stamp = C.now()
    async with database.transaction():
        await database.execute(TG.delete().where(TG.c.clip_id == clip_id))
        for t in tags:
            await database.execute(TG.insert().values(clip_id=clip_id, ref_key=T.referee_key(t["name"], t["judge_id"]), pair_id=ctx["pair_id"],
                                                      name=t["name"], judge_id=t["judge_id"], role=t["role"], position=t["position"],
                                                      created_by=actor.judge_id, created_at=stamp))
    await C.touch(ctx, actor.judge_id, "clip_referees", "clips", clip["match_id"], {"id": clip_id})
    return {"referees": tags, "rev": ctx["rev"]}


# ─── „Twoje zdanie" w wątku klipu (to NIE jest ocena; tylko mecze z Trybuny) ─

OP = mentor_trybuna_opinions
RULE_REF = re.compile(r"^\d{1,2}(:\d{1,2}[a-z]?)?(\.\d{1,2})?$")


async def _clip_thread(thread_id: str, actor: Actor, action: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    thread = await C.one(select(mentor_threads).where(mentor_threads.c.id == thread_id))
    if not thread or thread.get("target_kind") != "clip":
        raise C.err(404, "NOT_FOUND", "Nie ma takiego wątku klipu.")
    ctx = await C.pair_context(thread["pair_id"], actor, action=action)
    if not T.is_watched(thread.get("match_id")):
        raise C.err(409, "OPINION_TRYBUNA_ONLY", "Twoje zdanie jest tylko przy klipach z meczów z Trybuny.")
    return ctx, thread


def _disputed(rows: List[Mapping[str, Any]], mentor_ids: set) -> bool:
    """Sporne = wśród głosów NIE-mentorów są i "Zgadzam się", i "Inaczej", razem co najmniej 2 (głos mentora nie zdradza sporu parze)."""
    votes = [r.get("vote") for r in rows if R.s(r.get("judge_id")) not in mentor_ids]
    return len(votes) >= 2 and "agree" in votes and "differ" in votes


async def disputed_clip_ids(ctx: Dict[str, Any], clip_ids: Optional[List[str]] = None) -> set:
    """Klipy pary ze spornymi zdaniami (w którymkolwiek wątku klipu)."""
    query = select(mentor_threads.c.id, mentor_threads.c.target_id).where(mentor_threads.c.pair_id == ctx["pair_id"]) \
        .where(mentor_threads.c.target_kind == "clip").where(mentor_threads.c.match_id.like("tr_%"))
    if clip_ids is not None:
        query = query.where(mentor_threads.c.target_id.in_(list(clip_ids)))
    threads = await C.rows(query)
    if not threads:
        return set()
    votes = await C.rows(select(OP).where(OP.c.thread_id.in_([t["id"] for t in threads])))
    mentors = set(ctx.get("all_mentor_ids") or [])
    by_thread: Dict[str, List[Dict[str, Any]]] = {}
    for v in votes:
        by_thread.setdefault(v["thread_id"], []).append(v)
    return {t["target_id"] for t in threads if _disputed(by_thread.get(t["id"], []), mentors)}


async def opinions_payload(ctx: Dict[str, Any], thread_id: str, me: str) -> Dict[str, Any]:
    """Ankieta wątku klipu. Zasady: wyniki (`counts`, `voters`) widać dopiero po własnym głosie (mentor, admin i komisja widzą od razu);
    głos mentora (`mentor_vote`) para widzi dopiero, gdy obaj sędziowie pary zagłosowali (`reveal`), a do tego czasu nie wchodzi
    do `total`, `counts` ani `voters` pary."""
    found = await C.rows(select(OP).where(OP.c.thread_id == thread_id))
    names = await C.people({r["judge_id"] for r in found})
    pair_ids, mentor_ids = set(ctx["judge_ids"]), set(ctx.get("all_mentor_ids") or [])
    reveal = bool(pair_ids) and pair_ids <= {r["judge_id"] for r in found}
    viewer_is_pair = R.s(me) in pair_ids
    mine = next((r["vote"] for r in found if r["judge_id"] == R.s(me)), None)
    visible = [r for r in found if not (viewer_is_pair and not reveal and r["judge_id"] in mentor_ids)]
    mentor_row = max((r for r in found if r["judge_id"] in mentor_ids), key=lambda r: R.s(r.get("updated_at")), default=None)
    mentor_vote = None
    if mentor_row and (reveal or not viewer_is_pair):
        mentor_vote = {"name": C.person(names, mentor_row["judge_id"])["name"], "vote": mentor_row["vote"],
                       "reason": mentor_row.get("reason"), "rule_ref": mentor_row.get("rule_ref")}
    show = (not viewer_is_pair) or mine is not None
    my_row = next((r for r in found if r["judge_id"] == R.s(me)), None)
    out: Dict[str, Any] = {"total": len(visible), "mine": mine, "my_reason": (my_row or {}).get("reason"),
                           "my_rule_ref": (my_row or {}).get("rule_ref"), "counts": None, "voters": None, "mentor_vote": mentor_vote,
                           "mentor_voted": mentor_row is not None,
                           "reveal": reveal, "labels": dict(T.VOTE_LABELS), "disputed": _disputed(found, mentor_ids)}
    if show:
        out["counts"] = {v: sum(1 for r in visible if r["vote"] == v) for v in T.VOTES}
        out["voters"] = [{"judge_id": r["judge_id"], "name": C.person(names, r["judge_id"])["name"], "vote": r["vote"],
                          "reason": r.get("reason"), "rule_ref": r.get("rule_ref"), "is_mentor": r["judge_id"] in mentor_ids} for r in visible]
    return out


@router.get("/threads/{thread_id}/opinion")
async def get_opinion(thread_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, _ = await _clip_thread(thread_id, actor, "view")
    return await opinions_payload(ctx, thread_id, actor.judge_id)


class OpinionBody(BaseModel):
    vote: Optional[str] = Field(default=None, max_length=10)
    reason: Optional[str] = Field(default=None, max_length=200)
    #: Odsyłacz do przepisu, np. "8:5b" (tylko przy "Inaczej").
    rule_ref: Optional[str] = Field(default=None, max_length=12)


@router.put("/threads/{thread_id}/opinion")
async def put_opinion(thread_id: str, body: OpinionBody, actor: Actor = Depends(mentor_actor)):
    """„Twoje zdanie": `agree` (Zgadzam się), `differ` (Inaczej), `unsure` (Nie wiem); `null` cofa głos. Przy `differ` można dodać powód
    (do 200 znaków) i odsyłacz do przepisu (`rule_ref`, np. "8:5b"; format sprawdzany); przy pozostałych głosach powód i odsyłacz są
    odrzucane (422 `REASON_ONLY_DIFFER`). Jeden głos na osobę; nie jest oceną. Zwraca ankietę jak `GET`."""
    ctx, thread = await _clip_thread(thread_id, actor, "create")
    vote = R.s(body.vote)
    if vote and vote not in T.VOTES:
        raise C.err(422, "BAD_VOTE", "Głos to agree, differ albo unsure.")
    reason, rule_ref = R.plain(body.reason, 200) or None, R.s(body.rule_ref) or None
    if (reason or rule_ref) and vote != "differ":
        raise C.err(422, "REASON_ONLY_DIFFER", "Powód i odsyłacz do przepisu można dodać tylko do głosu \"Inaczej\".")
    if rule_ref and not RULE_REF.match(rule_ref):
        raise C.err(422, "BAD_RULE_REF", "Odsyłacz do przepisu ma postać np. 8:5b.")
    await database.execute(OP.delete().where(OP.c.thread_id == thread_id).where(OP.c.judge_id == actor.judge_id))
    if vote:
        await database.execute(OP.insert().values(thread_id=thread_id, judge_id=actor.judge_id, pair_id=ctx["pair_id"], vote=vote,
                                                  reason=reason, rule_ref=rule_ref, updated_at=C.now()))
    await C.touch(ctx, actor.judge_id, "opinion", "threads", thread.get("match_id"), {"thread": thread_id})
    return await opinions_payload(ctx, thread_id, actor.judge_id)
