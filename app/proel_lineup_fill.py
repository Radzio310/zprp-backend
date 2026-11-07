"""Nazwiska i osoby A-E ze składu meczu wspólnego w protokole ProEla (07.11.2026).

Zgłoszenie: mecz ręczny współtworzony, skład wczytany ze zdjęcia protokołu na jednym
telefonie (z nazwiskami), a mecz rozpoczęty na INNYM urządzeniu - bez najnowszej
wersji - miał w ProElu same numery, bez nazwisk i bez osób towarzyszących.

Aplikacja od 07.11 sama dopisuje braki (`BAZA/utils/proelLineupRepair.ts`), ale
telefon ze starszą wersją tego nie zrobi. Dlatego gwarancja leży TU: każdy zapis
protokołu meczu ręcznego (klucz `M-<TULEJA>/<NUMER>`) dostaje ze składu meczu
wspólnego (`shared_matches.extra_json.lineup`) brakujące nazwiska po numerze
i brakujące osoby A-E po literze. Tylko braki - nic, co wpisał sędzia, nie jest
nadpisywane, a numerów spoza meczu nie dokładamy.

Skład z ZPRP (mecz połączony z numerycznym IdZawody) jest prawdą związku - nie ruszamy.
Funkcja nigdy nie rzuca: zapis meczu jest ważniejszy niż dopisanie nazwisk.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

STAFF_SLOTS = ("A", "B", "C", "D", "E")


def _s(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value if value is not None else "")).strip()


def _team_key(value: Any) -> str:
    text = unicodedata.normalize("NFD", _s(value).lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def _number(value: Any) -> Optional[int]:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 99 else None


def _swapped(mc: Dict[str, Any], lineup: Dict[str, Any]) -> bool:
    """Gospodarz protokołu to gość kartki, gdy nazwy drużyn mówią to wprost."""
    host, guest = _team_key(mc.get("hostTeamName")), _team_key(mc.get("guestTeamName"))
    home = _team_key((lineup.get("home") or {}).get("name"))
    away = _team_key((lineup.get("away") or {}).get("name"))
    return bool(host and guest and home and away and host == away and guest == home and host != guest)


def _fill_cards(cards: Any, numbers: Any, team: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    out: List[Dict[str, Any]] = [dict(c) for c in (cards if isinstance(cards, list) else []) if isinstance(c, dict)]
    roster = {n for n in (_number(x) for x in (numbers if isinstance(numbers, list) else [])) if n is not None}
    changed = False
    for p in team.get("players") or []:
        if not isinstance(p, dict):
            continue
        name, number = _s(p.get("name")), _number(p.get("number"))
        if not name or number is None:
            continue
        card = next((c for c in out if _number(c.get("number")) == number), None)
        if card is not None:
            if not _s(card.get("fullName")):
                card["fullName"] = name
                changed = True
            continue
        if not roster or number in roster:
            out.append({"number": number, "fullName": name})
            changed = True
    return out, changed


def _fill_companions(companions: Any, team: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    out: List[Dict[str, Any]] = [dict(c) for c in (companions if isinstance(companions, list) else []) if isinstance(c, dict)]
    changed = False
    for st in team.get("staff") or []:
        if not isinstance(st, dict):
            continue
        slot, name = _s(st.get("slot")).upper(), _s(st.get("name"))
        if slot not in STAFF_SLOTS or not name:
            continue
        cur = next((c for c in out if _s(c.get("id")).upper() == slot), None)
        if cur is None:
            row: Dict[str, Any] = {"id": slot, "fullName": name}
            if _s(st.get("function")):
                row["function"] = _s(st.get("function"))
            if _s(st.get("license")):
                row["license"] = _s(st.get("license"))
            out.append(row)
            changed = True
            continue
        if not _s(cur.get("fullName")):
            # Kary ławki (U/2'/D) zostają - dopisujemy tylko to, czego brak.
            cur["fullName"] = name
            if not _s(cur.get("function")) and _s(st.get("function")):
                cur["function"] = _s(st.get("function"))
            if not _s(cur.get("license")) and _s(st.get("license")):
                cur["license"] = _s(st.get("license"))
            changed = True
    out.sort(key=lambda c: _s(c.get("id")))
    return out, changed


def fill_blob_from_lineup(blob: Any, lineup: Any) -> Tuple[Any, bool]:
    """Czysta funkcja: blob ProEla z dopisanymi brakami ze składu. Zwraca (blob, czy_zmienione)."""
    if not isinstance(blob, dict) or not isinstance(lineup, dict):
        return blob, False
    mc = blob.get("matchConfig")
    if not isinstance(mc, dict):
        return blob, False
    home, away = lineup.get("home") or {}, lineup.get("away") or {}
    if not isinstance(home, dict) or not isinstance(away, dict):
        return blob, False
    if _swapped(mc, lineup):
        home, away = away, home
    hp, hpc = _fill_cards(mc.get("hostPlayerCards"), mc.get("hostPlayers"), home)
    gp, gpc = _fill_cards(mc.get("guestPlayerCards"), mc.get("guestPlayers"), away)
    hc, hcc = _fill_companions(mc.get("hostCompanions"), home)
    gc, gcc = _fill_companions(mc.get("guestCompanions"), away)
    if not (hpc or gpc or hcc or gcc):
        return blob, False
    out = copy.copy(blob)
    new_mc = dict(mc)
    if hpc:
        new_mc["hostPlayerCards"] = hp
    if gpc:
        new_mc["guestPlayerCards"] = gp
    if hcc:
        new_mc["hostCompanions"] = hc
    if gcc:
        new_mc["guestCompanions"] = gc
    out["matchConfig"] = new_mc
    return out, True


def _shared_key(match_number: Any, blob: Any) -> str:
    from app.proel_match_key import is_shared_key, shared_key_of_blob

    key = _s(match_number)
    if is_shared_key(key):
        return key
    return shared_key_of_blob(blob)


async def lineup_for_key(key: str) -> Optional[Dict[str, Any]]:
    """Skład meczu wspólnego, do którego należy klucz `M-...` (albo None)."""
    from app.db import database, shared_matches
    from app.proel_match_key import shared_stem_of_key, stem_of_row
    from sqlalchemy import select

    stem = shared_stem_of_key(key)
    if not stem:
        return None
    rows = await database.fetch_all(
        select(shared_matches.c.id, shared_matches.c.proel_stem, shared_matches.c.zprp_match_id, shared_matches.c.extra_json)
        .where(shared_matches.c.deleted_at.is_(None))
        .where((shared_matches.c.proel_stem == stem) | (shared_matches.c.proel_stem.ilike(stem)) | (shared_matches.c.id.ilike(f"{stem.lower()}%")))
        .limit(20)
    )
    for r in rows:
        row = dict(r)
        if stem_of_row(row) != stem:
            continue
        if re.fullmatch(r"\d+", _s(row.get("zprp_match_id"))):
            return None  # skład z ZPRP wygrywa
        try:
            extra = json.loads(row.get("extra_json") or "{}")
        except (TypeError, ValueError):
            return None
        lineup = extra.get("lineup") if isinstance(extra, dict) else None
        return lineup if isinstance(lineup, dict) else None
    return None


async def fill_shared_lineup(match_number: Any, blob: Any) -> Any:
    """Zapis protokołu meczu ręcznego: dopisz braki ze składu meczu wspólnego. Nigdy nie rzuca."""
    try:
        if not isinstance(blob, dict):
            return blob
        key = _shared_key(match_number, blob)
        if not key:
            return blob
        lineup = await lineup_for_key(key)
        if not lineup:
            return blob
        out, changed = fill_blob_from_lineup(blob, lineup)
        if changed:
            logger.info("proel: dopisano braki ze składu meczu wspólnego %s", key)
        return out
    except Exception:  # noqa: BLE001 - zapis meczu jest ważniejszy niż nazwiska
        logger.warning("proel: dopisanie składu nieudane", exc_info=True)
        return blob
