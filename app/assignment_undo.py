"""
Cofanie przebiegu automatu i sprawdzanie, czy da się go dziś ułożyć lepiej.

Dwie czynności, jedna zasada: **decyzja człowieka jest ważniejsza niż nasza**.

COFNIĘCIE przywraca stan sprzed przebiegu, ale gniazda, w których od tamtej pory
ktoś stanął ręcznie, zostawia nietknięte i mówi o nich wprost. Automat nie ma
prawa skasować cudzej poprawki tylko dlatego, że sam coś tam wcześniej wpisał.

OPTYMALIZACJA nie zmienia niczego. Liczy obsadę dla tych samych meczów jeszcze
raz, na DZISIEJSZYCH danych (nowe niedyspozycje, nowe przerwy, uzupełnione
odległości, obsady dołożone ręcznie), i pokazuje różnicę w kilometrach.
Zmiana idzie do ZPRP dopiero wtedy, gdy człowiek ją zatwierdzi.

⚠ Żadna z nich NIE zapisuje sama w bazie związku. Oddają PLAN, a wykonuje go
panel tą samą jedyną drogą, co każdy inny zapis obsady (`/zprp/obsada/save`).
Druga ścieżka zapisu byłaby drugim miejscem, w którym można się pomylić.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

#: Werdykty dla pojedynczego gniazda przy cofaniu.
RESTORE = "restore"      # przywracamy poprzednika (albo zwalniamy gniazdo)
KEPT = "kept"            # ktoś zmienił to ręcznie - zostawiamy
GONE = "gone"            # meczu nie ma już w migawce
DONE = "done"            # cofnięte wcześniej


def _s(value: Any) -> str:
    return str(value or "").strip()


def verdict(change: Any, state_now: dict) -> tuple[str, str]:
    """
    Co zrobić z jedną zmianą. Zwraca `(werdykt, wyjaśnienie dla człowieka)`.

    MODUŁ-LIŚĆ w tej części: dostaje wiersz historii i OBECNY stan meczu, więc
    całą regułę da się sprawdzić testem.

    Zasada jest jedna: cofamy tylko to, co nadal wygląda tak, jak zostawił to
    automat. Gdy w gnieździe stoi ktoś inny, znaczy, że człowiek już tu był -
    i jego decyzja zostaje.
    """
    from app.assignment_notify import SLOT_TO_CREW
    from app.match_market_rules import CREW_STATE_FIELDS, names_match

    row = change if isinstance(change, dict) else dict(change)
    if row.get("undone_at"):
        return DONE, "już cofnięte"
    if not state_now:
        return GONE, "meczu nie ma już w terminarzu okręgu"

    crew_slot = SLOT_TO_CREW.get(_s(row.get("slot")))
    fields = CREW_STATE_FIELDS.get(crew_slot or "")
    if not fields:
        return GONE, "nieznane gniazdo"

    id_field, name_field = fields
    now_id, now_name = _s(state_now.get(id_field)), _s(state_now.get(name_field))
    if now_id == "0":
        now_id = ""
    put_id, put_name = _s(row.get("judge_id")), _s(row.get("judge_name"))

    same = (put_id and now_id and put_id == now_id) or (
        not put_id and not now_id
    ) or (put_name and now_name and names_match(put_name, now_name))
    if not same:
        who = now_name or "ktoś inny"
        return KEPT, f"po automacie zmienił to człowiek - teraz stoi {who}"

    back_name = _s(row.get("before_name"))
    return RESTORE, (
        f"wracamy do {back_name}" if back_name else "zwalniamy gniazdo"
    )


async def undo_plan(province: str, run_id: int) -> dict:
    """
    Co trzeba wysłać do ZPRP, żeby cofnąć ten przebieg - mecz po meczu.

    Nic nie zapisuje. Panel bierze `matches` i publikuje je tą samą drogą, co
    zwykły zapis obsady, a potem melduje wynik przez `mark_undone`.
    """
    from sqlalchemy import and_, select

    from app.db import database, province_assignment_changes, province_matches
    from app.match_market_rules import state_dict
    from app.settlement_province import spellings

    rows = await database.fetch_all(
        select(province_assignment_changes)
        .where(
            and_(
                province_assignment_changes.c.province == province,
                province_assignment_changes.c.run_id == int(run_id),
            )
        )
        .order_by(province_assignment_changes.c.id)
    )
    if not rows:
        return {"matches": [], "kept": [], "totals": {"restore": 0, "kept": 0, "done": 0, "gone": 0}}

    match_ids = sorted({_s(row["match_id"]) for row in rows})
    snapshots = await database.fetch_all(
        select(province_matches.c.match_id, province_matches.c.state_json).where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.match_id.in_(match_ids),
            )
        )
    )
    states = {_s(row["match_id"]): state_dict(row["state_json"]) for row in snapshots}

    # ⚠ To samo gniazdo może mieć w jednym przebiegu KILKA wpisów: najpierw
    # automat, potem optymalizacja. Cofamy do stanu sprzed CAŁEGO przebiegu,
    # więc `before` bierzemy z wpisu NAJSTARSZEGO, a to, co ma tam teraz stać,
    # z NAJNOWSZEGO. Inaczej cofnięcie wróciłoby do stanu pośredniego - czyli
    # do kogoś, kogo i tak wpisał automat.
    merged: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for row in rows:
        data = dict(row)
        key = (_s(data.get("match_id")), _s(data.get("slot")))
        if key not in merged:
            merged[key] = dict(data)
            order.append(key)
            continue
        first = merged[key]
        # Najnowszy decyduje o tym, kto stoi i który wiersz stemplujemy.
        first["id"] = data.get("id")
        first["judge_id"] = data.get("judge_id")
        first["judge_name"] = data.get("judge_name")
        first["undone_at"] = data.get("undone_at")
        first.setdefault("extra_ids", []).append(int(dict(row).get("id")))

    by_match: dict[str, dict] = {}
    kept: list[dict] = []
    totals = {"restore": 0, "kept": 0, "done": 0, "gone": 0}

    for key in order:
        data = merged[key]
        match_id = key[0]
        call, why = verdict(data, states.get(match_id, {}))
        totals[call] = totals.get(call, 0) + 1
        entry = {
            "change_id": int(data.get("id")),
            "also_ids": [int(item) for item in (data.get("extra_ids") or [])],
            "match_id": match_id,
            "code": _s(data.get("match_code")),
            "slot": _s(data.get("slot")),
            "judge_name": _s(data.get("judge_name")),
            "before_id": _s(data.get("before_id")),
            "before_name": _s(data.get("before_name")),
            "why": why,
        }
        if call != RESTORE:
            kept.append({**entry, "verdict": call})
            continue
        target = by_match.setdefault(
            match_id,
            {"match_id": match_id, "code": entry["code"], "slots": []},
        )
        target["slots"].append(
            {
                "change_id": entry["change_id"],
                # Pozostałe wpisy TEGO gniazda - stempel cofnięcia obejmuje
                # wszystkie, inaczej w historii zostałby wpis „niecofnięty".
                "also_ids": entry["also_ids"],
                "slot": entry["slot"],
                # Puste = zwolnij gniazdo. Tak właśnie wyglądało przed automatem.
                "judge_id": entry["before_id"],
                "name": entry["before_name"],
                "why": why,
            }
        )

    return {
        "run_id": int(run_id),
        "matches": sorted(by_match.values(), key=lambda item: item["code"] or item["match_id"]),
        "kept": kept,
        "totals": totals,
    }


async def mark_undone(province: str, change_ids: list[int], note: str = "") -> int:
    """Stempluje cofnięte zmiany. Wiersz zostaje - historia pokazuje też odwołania."""
    from datetime import datetime, timezone

    from sqlalchemy import and_, update

    from app.db import database, province_assignment_changes

    wanted = [int(item) for item in change_ids if str(item).strip()]
    if not wanted:
        return 0
    await database.execute(
        update(province_assignment_changes)
        .where(
            and_(
                province_assignment_changes.c.province == province,
                province_assignment_changes.c.id.in_(wanted),
                province_assignment_changes.c.undone_at.is_(None),
            )
        )
        .values(undone_at=datetime.now(timezone.utc), undo_note=_s(note) or None)
    )
    return len(wanted)


def compare(before: list[dict], after: list[dict]) -> dict:
    """
    Czy nowy układ jest lepszy od obecnego - i o ile.

    MODUŁ-LIŚĆ: dwie listy `{match_id, slot, judge_id, name, km}` i nic więcej.
    Liczymy to, co dla obsadowego znaczy „lepiej": mniej kilometrów i mniej
    pustych gniazd. Remis NIE jest powodem do zmiany - przestawianie ludzi bez
    zysku to tylko zamieszanie w terminarzu i kolejne powiadomienia.
    """
    def key(item: dict) -> tuple[str, str]:
        return (_s(item.get("match_id")), _s(item.get("slot")))

    old_by = {key(item): item for item in before}
    new_by = {key(item): item for item in after}

    moves: list[dict] = []
    km_before = km_after = 0.0
    unknown = 0
    for slot_key, fresh in new_by.items():
        stale = old_by.get(slot_key)
        was_km = stale.get("km") if stale else None
        now_km = fresh.get("km")
        if was_km is None or now_km is None:
            unknown += 1
        else:
            km_before += float(was_km)
            km_after += float(now_km)
        same_person = stale and _s(stale.get("judge_id")) == _s(fresh.get("judge_id"))
        if same_person:
            continue
        moves.append(
            {
                "match_id": slot_key[0],
                "slot": slot_key[1],
                "code": fresh.get("code") or (stale or {}).get("code"),
                "from_id": _s((stale or {}).get("judge_id")),
                "from_name": _s((stale or {}).get("name")),
                "to_id": _s(fresh.get("judge_id")),
                "to_name": _s(fresh.get("name")),
                "km_before": was_km,
                "km_after": now_km,
                "gain": (
                    round(float(was_km) - float(now_km), 1)
                    if was_km is not None and now_km is not None
                    else None
                ),
                "reasons": fresh.get("reasons") or [],
            }
        )

    saved = round(km_before - km_after, 1)
    filled_before = sum(1 for item in before if _s(item.get("judge_id")))
    filled_after = sum(1 for item in after if _s(item.get("judge_id")))
    return {
        "moves": sorted(moves, key=lambda item: (-(item["gain"] or 0), item["code"] or "")),
        "km_before": round(km_before, 1),
        "km_after": round(km_after, 1),
        "km_saved": saved,
        "filled_before": filled_before,
        "filled_after": filled_after,
        "unknown_km": unknown,
        # „Warto" znaczy: krócej się jeździ ALBO ubywa pustych gniazd.
        "worth_it": saved > 0 or filled_after > filled_before,
    }
