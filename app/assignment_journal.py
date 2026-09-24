"""
Dziennik zapisów do ZPRP (Obsada 2.0, 24.09.2026) - zapis wpisów.

KAŻDY udany zapis obsady (`/zprp/obsada/save`) i hali (`/zprp/obsada/save-hall`)
zostawia tu ślad: ręczny, z automatu i „cichy" (uzupełnianie zakończonego
meczu) tak samo. Historia w panelu (`/province/assignment/zprp-history`) i
cofanie po stronie klienta żyją z tych wpisów.

Obok zostaje `province_assignment_changes` - historia PRZEBIEGÓW automatu
(`run_id`), z której żyje cofanie przebiegu. Tamtej tabeli nie ruszamy.

Reguły (które gniazda, kto przed, kto po) siedzą w liściu
`assignment_board_rules`; tutaj tylko baza. Całość jest osłonięta u wołającego:
zapis w bazie związku JUŻ przeszedł i brak wpisu nie może go unieważnić.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Iterable, Mapping, Optional

from app import assignment_board_rules as B

logger = logging.getLogger(__name__)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _names(slots: Mapping[str, Any]) -> dict[str, str]:
    """{gniazdo formularza: {"name": …}} -> {gniazdo modułu: nazwisko}."""
    out: dict[str, str] = {}
    for label, data in (slots or {}).items():
        slot = B.normalize_slot(label)
        if slot:
            out[slot] = _s((data or {}).get("name") if isinstance(data, Mapping) else data)
    return out


async def _match_info(province: str, match_id: str) -> tuple[str, str, str, dict]:
    """(okręg z wiersza migawki, numer meczu, podpis meczu, stan) - albo pustki."""
    from sqlalchemy import and_, select

    from app.db import database, province_matches
    from app.match_market_rules import state_dict
    from app.settlement_province import canonical, spellings

    key = canonical(province) or _s(province)
    row = await database.fetch_one(
        select(
            province_matches.c.province,
            province_matches.c.match_code,
            province_matches.c.state_json,
        ).where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.match_id == _s(match_id),
            )
        )
    )
    if row is None:
        return key, "", "", {}
    state = state_dict(row["state_json"]) or {}
    code = _s(state.get("RozgrywkiCode") or row["match_code"])
    return key, code, B.match_label(state, code), state


async def _insert(rows: list[dict]) -> list[int]:
    from sqlalchemy import insert

    from app.db import database, province_zprp_write_journal

    ids: list[int] = []
    for row in rows:
        new_id = await database.fetch_val(
            insert(province_zprp_write_journal)
            .values(**row)
            .returning(province_zprp_write_journal.c.id)
        )
        ids.append(int(new_id))
    return ids


async def record_lineup_write(
    province: str,
    match_id: str,
    *,
    sent: Iterable[str],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    assigned: Optional[Mapping[str, Any]] = None,
    batch_id: Optional[str] = None,
    actor: Optional[str] = None,
    run_id: Optional[int] = None,
    reverted_of: Any = None,
) -> dict:
    """
    Wpisy dziennika dla jednego udanego zapisu obsady meczu.

    Numer nowego sędziego podaje panel (`assigned`, gniazda modułu); numer
    poprzedniego bierzemy z migawki (jeszcze sprzed ogłoszenia zapisu), a gdy
    tam go nie ma - po nazwisku z listy okręgu.
    """
    from app.assignment_board_cache import bump
    from app.assignment_notify import numbers_by_name
    from app.assignment_rules import slot_person

    key, code, label, state = await _match_info(province, match_id)
    before_names = _names(before)
    after_names = _names(after)

    ids_before: dict[str, str] = {}
    for slot, name in before_names.items():
        person = slot_person(state, slot) or {}
        if name and _s(person.get("number")) and B.same_person(person.get("name"), name):
            ids_before[slot] = _s(person.get("number"))
    missing = [name for slot, name in before_names.items() if name and slot not in ids_before]
    if missing:
        from app.assignment_people import name_key

        found = await numbers_by_name(key, missing)
        for slot, name in before_names.items():
            if name and slot not in ids_before and found.get(name_key(name)):
                ids_before[slot] = found[name_key(name)]

    ids_after = {B.normalize_slot(slot): _s(value) for slot, value in (assigned or {}).items()}
    missing_after = [
        name for slot, name in after_names.items() if name and not ids_after.get(slot)
    ]
    if missing_after:
        from app.assignment_people import name_key

        found = await numbers_by_name(key, missing_after)
        for slot, name in after_names.items():
            if name and not ids_after.get(slot) and found.get(name_key(name)):
                ids_after[slot] = found[name_key(name)]

    lines = B.journal_slot_rows(
        sent, before_names, after_names, ids_after=ids_after, ids_before=ids_before
    )
    if not lines:
        return {"batch_id": _s(batch_id) or None, "ids": []}

    batch = _s(batch_id) or uuid.uuid4().hex
    rows = [
        {
            "province": key,
            "batch_id": batch,
            "match_id": _s(match_id),
            "match_code": code or None,
            "match_label": label or None,
            "actor": _s(actor) or None,
            "run_id": int(run_id) if run_id is not None else None,
            "reverted_of": B.reverted_for(reverted_of, line["slot"] or ""),
            **line,
        }
        for line in lines
    ]
    ids = await _insert(rows)
    bump(key)
    return {"batch_id": batch, "ids": ids}


async def record_hall_write(
    province: str,
    match_id: str,
    *,
    hall_before: Any,
    hall_after: Any,
    batch_id: Optional[str] = None,
    actor: Optional[str] = None,
    reverted_of: Any = None,
) -> dict:
    """Wpis dziennika dla udanego zapisu hali - także gdy hala została ta sama."""
    from app.assignment_board_cache import bump

    key, code, label, _state = await _match_info(province, match_id)
    batch = _s(batch_id) or uuid.uuid4().hex
    ids = await _insert(
        [
            {
                "province": key,
                "batch_id": batch,
                "match_id": _s(match_id),
                "match_code": code or None,
                "match_label": label or None,
                "kind": "hall",
                "slot": None,
                "hall_before": _s(hall_before) or None,
                "hall_after": _s(hall_after) or None,
                "actor": _s(actor) or None,
                "reverted_of": B.reverted_for(reverted_of, "hall"),
            }
        ]
    )
    bump(key)
    return {"batch_id": batch, "ids": ids}
