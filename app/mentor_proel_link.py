"""Ręczne podpięcie protokołu ProEla do karty meczu pary + wyszukiwarka meczów ProEla (31.10.2026).

Kontrakt: `docs/mecze-wspolne-api.md` (sekcja B). Decyzje: pamięć `mecze-reczne-wspolne-decyzje`.

  - Podpięcie dotyczy DOWOLNEJ karty pary (hurtownia, monitor, archiwum, mecz wspólny `my:`); dla karty z Trybuny (`tr_`) trasa
    deleguje do istniejącego `PUT .../trybuna/matches/{id}/links` (jedna logika, bez kopii).
  - To tylko ODCZYT: nic nie jest zapisywane w `proel_matches` i nic nie daje praw zapisu. Wiersz `mentor_proel_links` to wskaźnik.
  - Ręczne podpięcie ma pierwszeństwo przed automatem (dopasowanie po ID ZPRP / numerze meczu).
  - Zakres: dowolny mecz OFICJALNY; szkoleniowy (`T-XXXXXXXX/NUMER`) tylko taki, który napisał ktoś z pary.
  - Numer meczu nie jest kluczem między sezonami: wybór idzie po PEŁNYM kluczu wiersza, a podgląd niesie datę i drużyny.
  - Klucz szkoleniowy z `promoted_to` rozwiązuje się przy odczycie do oficjalnego (`app/mentor_evaluations.timeline_for_match`).
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, or_, select

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import shared_match_rules as SR
from app.db import database, mentor_proel_links, saved_matches
from app.mentor_panel_auth import mentor_actor
from app.mentor_video_rules import EVENT_KINDS
from app.proel_training_key import TRAINING_KEY_LIKE, is_training_key, match_number_from_key

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor ProEl"])
Actor = C.MentorActor
L = mentor_proel_links
S = saved_matches
s = R.s

MAX_SEARCH = 30


# ─── Odczyt podpięcia ───────────────────────────────────────────────────────


async def get_link(pair_id: str, match_id: str) -> Optional[Dict[str, Any]]:
    try:
        return await C.one(select(L).where(L.c.pair_id == s(pair_id)).where(L.c.match_id == s(match_id)))
    except Exception:  # noqa: BLE001 - brak tabeli/odczytu nie psuje pokoju meczu
        logger.warning("mentor: odczyt podpięcia ProEla nieudany", exc_info=True)
        return None


async def links_for(pair_id: str, match_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    ids = [s(m) for m in match_ids if s(m)]
    if not ids:
        return {}
    try:
        found = await C.rows(select(L).where(L.c.pair_id == s(pair_id)).where(L.c.match_id.in_(ids)))
    except Exception:  # noqa: BLE001
        logger.warning("mentor: odczyt podpięć ProEla nieudany", exc_info=True)
        return {}
    return {s(r["match_id"]): r for r in found}


def link_brief(link: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Lekki kształt na karcie meczu (`card.proel_link`)."""
    if not link:
        return None
    key = s(link.get("proel_key"))
    return {"key": key, "kind": "training" if is_training_key(key) else "official", "number": match_number_from_key(key),
            "linked_by": link.get("linked_by"), "linked_at": link.get("linked_at"), "manual": True}


# ─── Oś czasu: skąd brać protokół ───────────────────────────────────────────


async def timeline_target(ctx: Dict[str, Any], card: Dict[str, Any]) -> Dict[str, Any]:
    """Argumenty dla `timeline_for_match`: ręczne podpięcie > klucz meczu wspólnego/Trybuny > automat (ID ZPRP + numer meczu)."""
    mid = s(card.get("match_id"))
    link = await get_link(ctx["pair_id"], mid)
    owners = list(ctx["judge_ids"])
    if link:
        return {"match_id": s(card.get("zprp_match_id")), "code": s(link["proel_key"]), "trusted": True, "owner_ids": owners, "source": "manual"}
    if card.get("watched"):  # Trybuna działa jak dotąd
        return {"match_id": s(card.get("zprp_match_id")), "code": s(card.get("proel_key") or card.get("match_code")),
                "trusted": False, "owner_ids": None, "source": "trybuna"}
    if card.get("shared"):
        if s(card.get("proel_key")):
            return {"match_id": s(card.get("zprp_match_id")), "code": s(card["proel_key"]), "trusted": True, "owner_ids": owners, "source": "shared"}
        # Ręczny numer meczu bez ID ZPRP nie wskazuje niczego pewnego (numer nie jest kluczem między sezonami).
        if s(card.get("zprp_match_id")):
            return {"match_id": s(card["zprp_match_id"]), "code": s(card.get("match_code")), "trusted": False, "owner_ids": None, "source": "auto"}
        return {"match_id": mid, "code": "", "trusted": False, "owner_ids": None, "source": "none"}
    return {"match_id": mid, "code": s(card.get("proel_key") or card.get("match_code")), "trusted": False, "owner_ids": None, "source": "auto"}


# ─── Wyszukiwarka meczów ProEla ─────────────────────────────────────────────


def _blob(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def count_events(protocol: Any) -> int:
    """Zdarzenia osi (bez serii karnych i typów spoza osi) - tyle, ile zaimportuje się jako znaczniki."""
    data = _blob(protocol)
    if not isinstance(data, list):
        return 0
    return sum(1 for e in data if isinstance(e, dict) and not e.get("shootout") and s(e.get("type")) in EVENT_KINDS)


def owner_variants(judge_ids: Iterable[Any]) -> List[str]:
    """Numer sędziego bywa zapisany z zerem wiodącym albo bez - SQL dostaje oba zapisy."""
    out: List[str] = []
    for j in judge_ids:
        text = s(j)
        for variant in (text, text.lstrip("0")):
            if variant and variant not in out:
                out.append(variant)
    return out


def scope_clause(owner_ids: Iterable[Any], kind: str = "all"):
    """Zakres wyszukiwania: oficjalne bez ograniczeń, szkoleniowe tylko zapisane przez ludzi z pary."""
    official = ~S.c.match_number.ilike(TRAINING_KEY_LIKE)
    variants = owner_variants(owner_ids)
    training = and_(S.c.match_number.ilike(TRAINING_KEY_LIKE), S.c.doc_writer_judge.in_(variants)) if variants else None
    if kind == "official":
        return official
    if kind == "training":
        return training if training is not None else (S.c.match_number == "\u0000")
    return or_(official, training) if training is not None else official


async def search_proel(owner_ids: Iterable[Any], *, q: str = "", number: str = "", team: str = "", date: str = "", kind: str = "all",
                       limit: int = 20) -> List[Dict[str, Any]]:
    """Mecze ProEla do podpięcia. Wszystkie wartości idą jako parametry SQL (wzorce LIKE bez znaków specjalnych)."""
    limit = max(1, min(int(limit or 20), MAX_SEARCH))
    cfg = S.c.data_json["matchConfig"]
    host = cfg["hostTeamName"].as_string()
    guest = cfg["guestTeamName"].as_string()
    blob_date = S.c.data_json["date"].as_string()
    cfg_date = cfg["date"].as_string()
    conds = [scope_clause(owner_ids, kind)]
    if s(number):
        conds.append(S.c.match_number.ilike(SR.like_pattern(number), escape="\\"))
    if s(team):
        pattern = SR.like_pattern(team)
        conds.append(or_(host.ilike(pattern, escape="\\"), guest.ilike(pattern, escape="\\")))
    if s(q):
        pattern = SR.like_pattern(q)
        conds.append(or_(S.c.match_number.ilike(pattern, escape="\\"), host.ilike(pattern, escape="\\"), guest.ilike(pattern, escape="\\")))
    day = None
    if s(date):
        day = _parse_day(date)
        # Data w bloku jest w UTC, mecz bywa wieczorem po polsku - bierzemy sąsiednie dni, a dokładny dzień sprawdzamy niżej.
        prefixes = [(day + timedelta(days=d)).isoformat() + "%" for d in (-1, 0, 1)]
        conds.append(or_(*[blob_date.like(p) for p in prefixes], *[cfg_date.like(p) for p in prefixes]))
    query = (select(S.c.match_number, S.c.status, S.c.zprp_match_id, S.c.updated_at, S.c.promoted_to, S.c.doc_writer_judge,
                    host.label("host"), guest.label("guest"), blob_date.label("date_blob"), cfg_date.label("date_cfg"),
                    S.c.data_json["scoreHost"].as_string().label("score_host"), S.c.data_json["scoreGuest"].as_string().label("score_guest"),
                    S.c.data_json["protocol"].label("protocol"))
             .where(and_(*conds)).order_by(S.c.updated_at.desc(), S.c.match_number.desc()).limit(limit * (3 if day else 1)))
    found = await C.rows(query)
    from app.proel_stats_rules import parse_at

    out: List[Dict[str, Any]] = []
    for row in found:
        when = parse_at(row.get("date_blob")) or parse_at(row.get("date_cfg"))
        if day is not None:
            if not when or when.astimezone(SR.WARSAW).date() != day:
                continue
        key = s(row["match_number"])
        training = is_training_key(key)
        out.append({
            "key": key, "kind": "training" if training else "official", "official": not training, "number": match_number_from_key(key),
            "status": row.get("status"), "home": row.get("host") or None, "away": row.get("guest") or None,
            "date": when.isoformat() if when else None, "score_home": _int(row.get("score_host")), "score_away": _int(row.get("score_guest")),
            "events": count_events(row.get("protocol")), "zprp_match_id": row.get("zprp_match_id") or None,
            "promoted_to": s(row.get("promoted_to")) or None, "updated_at": row.get("updated_at"),
        })
        if len(out) >= limit:
            break
    return out


def _int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _parse_day(value: str):
    from datetime import date as _date

    try:
        return _date.fromisoformat(s(value)[:10])
    except ValueError:
        raise C.err(422, "VALIDATION", "Data ma mieć format RRRR-MM-DD.") from None


@router.get("/pairs/{pair_id}/proel/search")
async def proel_search(pair_id: str, response: Response, q: str = Query("", max_length=60), number: str = Query("", max_length=60),
                       team: str = Query("", max_length=60), date: str = Query("", max_length=10),
                       kind: str = Query("all", pattern="^(all|official|training)$"), limit: int = Query(20, ge=1, le=MAX_SEARCH),
                       actor: Actor = Depends(mentor_actor)):
    """Szukaj meczu ProEla do podpięcia: po numerze, drużynach (`team`), dacie (`date`=RRRR-MM-DD) albo wolnym tekście (`q`).

    Zakres: dowolny mecz oficjalny; szkoleniowy tylko zapisany przez sędziego tej pary. Wynik niesie datę i drużyny, bo numer
    meczu nie jest kluczem między sezonami - wybierasz po `key`."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="video")
    found = await search_proel(ctx["judge_ids"], q=q, number=number, team=team, date=date, kind=kind, limit=limit)
    return {"results": found, "count": len(found), "limit": limit}


# ─── Podpinanie ─────────────────────────────────────────────────────────────


class LinkBody(BaseModel):
    #: Pełny klucz wiersza ProEla (numer meczu albo T-XXXXXXXX/NUMER) - z wyniku wyszukiwarki.
    proel_key: str = Field(min_length=1, max_length=80)


async def _checked_row(key: str, judge_ids: Iterable[Any]) -> Dict[str, Any]:
    """Wiersz ProEla do podpięcia albo 404/403. Czyta nagłówek wiersza - nie zmienia niczego."""
    row = await C.one(select(S.c.match_number, S.c.status, S.c.zprp_match_id, S.c.promoted_to, S.c.doc_writer_judge)
                      .where(S.c.match_number == key))
    if not row:
        raise C.err(404, "PROEL_NOT_FOUND", "Nie ma takiego protokołu w ProElu.")
    if is_training_key(key):
        from app.proel_fields import same_judge_number

        writer = s(row.get("doc_writer_judge"))
        if not writer or not any(same_judge_number(writer, j) for j in judge_ids):
            raise C.err(403, "PROEL_SCOPE", "Mecz szkoleniowy może podpiąć tylko ten, kto go prowadził, albo jego partner z pary.")
    return row


async def preview_of(key: str) -> Optional[Dict[str, Any]]:
    """Podgląd podpiętego protokołu: drużyny, data, liczba zdarzeń, rodzaj."""
    found = await search_proel_by_key(key)
    return found


async def search_proel_by_key(key: str) -> Optional[Dict[str, Any]]:
    cfg = S.c.data_json["matchConfig"]
    row = await C.one(select(S.c.match_number, S.c.status, S.c.zprp_match_id, S.c.updated_at, S.c.promoted_to,
                             cfg["hostTeamName"].as_string().label("host"), cfg["guestTeamName"].as_string().label("guest"),
                             S.c.data_json["date"].as_string().label("date_blob"), cfg["date"].as_string().label("date_cfg"),
                             S.c.data_json["scoreHost"].as_string().label("score_host"),
                             S.c.data_json["scoreGuest"].as_string().label("score_guest"),
                             S.c.data_json["protocol"].label("protocol")).where(S.c.match_number == key))
    if not row:
        return None
    from app.proel_stats_rules import parse_at

    when = parse_at(row.get("date_blob")) or parse_at(row.get("date_cfg"))
    training = is_training_key(key)
    return {"key": key, "kind": "training" if training else "official", "official": not training, "number": match_number_from_key(key),
            "status": row.get("status"), "home": row.get("host") or None, "away": row.get("guest") or None,
            "date": when.isoformat() if when else None, "score_home": _int(row.get("score_host")), "score_away": _int(row.get("score_guest")),
            "events": count_events(row.get("protocol")), "zprp_match_id": row.get("zprp_match_id") or None,
            "promoted_to": s(row.get("promoted_to")) or None, "updated_at": row.get("updated_at")}


async def link_payload(link: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not link:
        return None
    brief = link_brief(link)
    brief["preview"] = await preview_of(brief["key"])
    resolved = (brief["preview"] or {}).get("promoted_to")
    brief["resolved_key"] = resolved or brief["key"]
    names = await C.people([link.get("linked_by")])
    brief["linked_by_name"] = C.person(names, link.get("linked_by")).get("name")
    return brief


@router.get("/pairs/{pair_id}/matches/{match_id}/proel-link")
async def get_proel_link(pair_id: str, match_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    """Ręczne podpięcie tej karty (albo null) razem z podglądem protokołu (drużyny, data, liczba zdarzeń)."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor)
    card = await C.match_card(ctx, match_id)
    link = await get_link(ctx["pair_id"], card["match_id"])
    return {"link": await link_payload(link), "match_id": card["match_id"]}


@router.put("/pairs/{pair_id}/matches/{match_id}/proel-link")
async def put_proel_link(pair_id: str, match_id: str, body: LinkBody, response: Response, actor: Actor = Depends(mentor_actor)):
    """Podepnij protokół ProEla do karty meczu pary (tylko odczyt, odpinane; pierwszeństwo przed automatem)."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    key = s(body.proel_key)
    await _checked_row(key, ctx["judge_ids"])
    if s(card["match_id"]).startswith("tr_"):
        from app.mentor_trybuna import LinkPut, put_links

        out = await put_links(pair_id, card["match_id"], LinkPut(proel_key=key), response, actor)
        return {"ok": True, "via": "trybuna", "match_id": card["match_id"], "result": out}
    existing = await get_link(ctx["pair_id"], card["match_id"])
    if existing:
        await database.execute(L.update().where(L.c.pair_id == ctx["pair_id"]).where(L.c.match_id == card["match_id"])
                               .values(proel_key=key, linked_by=actor.judge_id, linked_at=C.now()))
    else:
        await database.execute(L.insert().values(pair_id=ctx["pair_id"], match_id=card["match_id"], proel_key=key,
                                                  linked_by=actor.judge_id, linked_at=C.now()))
    await C.touch(ctx, actor.judge_id, "proel_linked", "matches", card["match_id"], {"proel_key": key})
    C.forget_matches(ctx["pair_key"])
    return {"ok": True, "via": "pair", "match_id": card["match_id"], "link": await link_payload(await get_link(ctx["pair_id"], card["match_id"])),
            "rev": ctx["rev"]}


@router.delete("/pairs/{pair_id}/matches/{match_id}/proel-link")
async def delete_proel_link(pair_id: str, match_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    """Odepnij ręcznie podpięty protokół. Karta wraca do automatu (ID ZPRP + numer meczu)."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    if s(card["match_id"]).startswith("tr_"):
        from app.mentor_trybuna import LinkPut, put_links

        out = await put_links(pair_id, card["match_id"], LinkPut(proel_key=""), response, actor)
        return {"ok": True, "via": "trybuna", "match_id": card["match_id"], "result": out}
    await database.execute(delete(L).where(L.c.pair_id == ctx["pair_id"]).where(L.c.match_id == card["match_id"]))
    await C.touch(ctx, actor.judge_id, "proel_unlinked", "matches", card["match_id"], {})
    C.forget_matches(ctx["pair_key"])
    return {"ok": True, "via": "pair", "match_id": card["match_id"], "link": None, "rev": ctx["rev"]}
