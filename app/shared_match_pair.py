"""Mecze wspólne jako źródło kart w panelu Mentor pary (31.10.2026).

Mecz wspólny, w którym OBAJ sędziowie pary są w obsadzie jako sędzia 1 / sędzia 2, pojawia się na liście meczów pary jako
osobne źródło kart (obok hurtowni, monitora okręgu i archiwum). Identyfikator karty ma przedrostek `my:` - nie koliduje
z numerami ZPRP ani z `tr_` Trybuny. Flagi, nagrania, klipy i wątki pary działają na tym identyfikatorze bez zmian
(wszystkie kolumny `match_id` w panelu to zwykłe napisy).

Moduł jest wołany z `mentor_panel_core.pair_match_cards` (import leniwy - bez cyklu) i po każdej zmianie meczu wspólnego
(`refresh_pairs`): zrzuca pamięć kart pary i podbija `rev` panelu, żeby web i aplikacja odświeżyły listę.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import func, select

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import (
    database,
    mentoring_pairs,
    shared_match_members,
    shared_matches,
)
from app.shared_match_rules import REFEREE_ROLES, s
from app.shared_match_tables import SHARED_CARD_PREFIX

logger = logging.getLogger("app.shared_match")

M = shared_matches
MM = shared_match_members


def card_id(match_id: str) -> str:
    return f"{SHARED_CARD_PREFIX}{match_id}"


def is_shared_card_id(value: Any) -> bool:
    return s(value).startswith(SHARED_CARD_PREFIX)


def shared_id_of(card_match_id: Any) -> str:
    text = s(card_match_id)
    return text[len(SHARED_CARD_PREFIX):] if text.startswith(SHARED_CARD_PREFIX) else ""


def card_from_shared(row: Dict[str, Any], crew: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Karta meczu pary z wiersza meczu wspólnego (kształt jak `card_from_public`, plus znacznik pochodzenia)."""
    card = R.base_card(card_id(row["id"]))
    when = R.aware(row.get("match_at"))
    half = (row.get("half_home"), row.get("half_away"))
    delegate = next((m.get("name") for m in crew if m.get("role") == "delegat" and s(m.get("name"))), None)
    card.update({
        "scheduled_at": when, "season": R.season_key(when), "competition_name": row.get("competition"),
        "home": {"name": row.get("home_name"), "logo_url": None, "score": row.get("score_home")},
        "away": {"name": row.get("away_name"), "logo_url": None, "score": row.get("score_away")},
        "halftime": f"{half[0]}:{half[1]}" if half[0] is not None and half[1] is not None else None,
        "venue_city": row.get("city") or row.get("hall"), "match_code": row.get("code"), "delegate_name": delegate,
        "source": "my",
        # Znacznik pochodzenia na karcie (aplikacja i web pokazują „Mecz wspólny" / „Ręczny").
        "shared": True, "origin_kind": "shared", "shared_id": row["id"],
        "zprp_match_id": row.get("zprp_match_id"), "proel_key": row.get("proel_key"),
        "result_by": row.get("result_by"), "result_at": row.get("result_at"),
        "shared_rev": int(row.get("rev") or 1),
    })
    return card


async def pair_cards(a: str, b: str) -> List[Dict[str, Any]]:
    """Mecze wspólne, w których `a` i `b` są razem w obsadzie sędziowskiej (loader dla `pair_match_cards`)."""
    hits = await C.rows(
        select(MM.c.match_id).where(MM.c.judge_id.in_([a, b])).where(MM.c.role.in_(REFEREE_ROLES))
        .group_by(MM.c.match_id).having(func.count(func.distinct(MM.c.judge_id)) == 2)
    )
    ids = sorted({s(h["match_id"]) for h in hits})
    if not ids:
        return []
    matches = await C.rows(select(M).where(M.c.id.in_(ids)).where(M.c.deleted_at.is_(None)))
    crew: Dict[str, List[Dict[str, Any]]] = {}
    for member in await C.rows(select(MM).where(MM.c.match_id.in_([m["id"] for m in matches]))):
        crew.setdefault(s(member["match_id"]), []).append(member)
    return [card_from_shared(m, crew.get(m["id"], [])) for m in matches]


async def pairs_touching(judge_ids: Iterable[Any]) -> List[Dict[str, Any]]:
    """Aktywne pary mentoringu, których OBAJ sędziowie należą do podanego zbioru."""
    wanted = {s(j) for j in judge_ids if s(j)}
    if len(wanted) < 2:
        return []
    found = await C.rows(select(mentoring_pairs.c.id, mentoring_pairs.c.judge_ids).where(mentoring_pairs.c.ended_at.is_(None)))
    out = []
    for pair in found:
        ids = [s(j) for j in R.json_value(pair.get("judge_ids"), [])]
        if len(ids) == 2 and set(ids) <= wanted:
            out.append({"pair_id": pair["id"], "pair_key": "|".join(sorted(ids))})
    return out


async def refresh_pairs(judge_ids: Iterable[Any], actor_id: str = "", match_id: Optional[str] = None) -> int:
    """Po zmianie meczu wspólnego: zrzuć pamięć kart dotkniętych par i podbij `rev` ich paneli. Nigdy nie rzuca."""
    try:
        touched = await pairs_touching(judge_ids)
        for pair in touched:
            C.forget_matches(pair["pair_key"])
            await C.touch(pair["pair_id"], actor_id, "shared_match_changed", "matches", card_id(match_id) if match_id else None, {})
        return len(touched)
    except Exception:  # noqa: BLE001 - odświeżenie panelu nie cofa zapisu meczu
        logger.warning("mecz wspólny: odświeżenie par nieudane", exc_info=True)
        return 0


async def _has_pair_data(match_key: str) -> bool:
    """Czy pod tą kartą (`match_id`) jest jakiekolwiek dane pary. Błąd odczytu = traktuj jak „są” (nic nie może przepaść)."""
    from app import db as _db

    names = ("mentor_match_flags", "mentor_clips", "mentor_threads", "mentor_uploads", "mentor_evaluations",
             "mentor_evaluation_requests", "mentor_match_videos", "mentor_bastion_clip_jobs", "mentor_proel_links")
    try:
        for name in names:
            table = getattr(_db, name)
            if "match_id" not in table.c:
                continue
            if await C.one(select(table.c.match_id).where(table.c.match_id == match_key).limit(1)):
                return True
        return False
    except Exception:  # noqa: BLE001
        logger.warning("mecz wspólny: sprawdzenie danych pary nieudane", exc_info=True)
        return True


async def collapse_linked(cards: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Po powiązaniu z ZPRP ten sam mecz nie może być dwiema kartami (`my:<id>` i numer ZPRP).

    Główna jest karta ZPRP. Wyjątek: jeśli dane pary wiszą pod `my:<id>` (a pod numerem ZPRP ich nie ma), główną zostaje karta `my:`,
    żeby nic nie przepadło ani nie stało się niedostępne. Gdy dane są po obu stronach, zostają obie karty (nic nie jest scalane na siłę).
    Brakujące pola głównej karty uzupełnia druga.
    """
    by_id = {s(c.get("match_id")): c for c in cards}
    drop: set = set()
    for card in cards:
        mine_id = s(card.get("match_id"))
        zprp_id = s(card.get("zprp_match_id"))
        if not (is_shared_card_id(mine_id) and zprp_id and zprp_id in by_id and zprp_id != mine_id):
            continue
        official = by_id[zprp_id]
        mine_has = await _has_pair_data(mine_id)
        if not mine_has:
            R._fill(official, card)
            drop.add(mine_id)
        elif not await _has_pair_data(zprp_id):
            R._fill(card, official)
            drop.add(zprp_id)
    return [c for c in cards if s(c.get("match_id")) not in drop]
