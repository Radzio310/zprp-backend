"""
Moduł obsadowego - czego mecz potrzebuje i czego mu brakuje.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

Decyzje użytkownika z 11.09.2026 (Śląsk, ale reguła jest ogólna):
  - DWÓCH sędziów boiskowych wszędzie od Młodzika w górę; Młodzik młodszy
    i Dzieci mogą mieć jednego,
  - DWÓCH stolikowych tak samo, ale JEDEN stolikowy to nie błąd: klub często
    daje swojego, więc brak drugiego jest tylko lekka różnica, a nie dziura,
  - DELEGATA na meczach okręgowych nie ma nigdy, na II lidze zdarza się bardzo
    rzadko - nigdy nie liczy się jako brak, pokazujemy go tylko, gdy jest.

Stąd trzy różne stany, nie dwa: „dziura" (brakuje kogoś, kogo musimy wystawić),
„lekka różnica" (jeden stolikowy zamiast dwóch) i „komplet".
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from app import settlement_rates as R

#: Gniazda obsady w kolejności, w jakiej pokazuje je formularz ZPRP.
FIELD_SLOTS = ("pierwszy", "drugi")
TABLE_SLOTS = ("sekretarz", "czas")
DELEGATE_SLOTS = ("delegat", "delegat2")
SLOTS = FIELD_SLOTS + TABLE_SLOTS + DELEGATE_SLOTS

#: Kategorie, w których wystarczy jeden boiskowy i jeden stolikowy.
SMALL_PREFIXES = frozenset({"DZM", "DZK", "MLM1213", "MLK1213"})

#: Stany gniazda i meczu.
COMPLETE = "complete"
SOFT = "soft"
GAP = "gap"


def _s(value: Any) -> str:
    return str(value or "").strip()


def crew_needs(code: Any) -> dict[str, int]:
    """Ilu ludzi ma stanąć przy tym meczu: boiskowi i stolik."""
    small = R.competition_prefix(code) in SMALL_PREFIXES
    return {"field": 1 if small else 2, "table": 1 if small else 2}


def slot_person(state: Mapping[str, Any], slot: str) -> Optional[dict[str, str]]:
    """
    Kto stoi w gnieździe: numer i nazwisko, albo None.

    ⚠ „0" to PUSTE GNIAZDO, nie sędzia - tak ZPRP zapisuje zdjęta obsadę.
    Nazwisko bez numeru też jest człowiekiem: terminarz podaje same nazwiska,
    numery dochodzą dopiero z publicznego API.
    """
    number = _s(state.get(f"NrSedzia_{slot}"))
    name = _s(state.get(f"NrSedzia_{slot}_nazwisko"))
    if number in ("", "0") and not name:
        return None
    return {"number": "" if number == "0" else number, "name": name}


def crew(state: Mapping[str, Any]) -> dict[str, Optional[dict[str, str]]]:
    """Cała szóstka gniazd meczu."""
    return {slot: slot_person(state, slot) for slot in SLOTS}


def _have(people: Mapping[str, Optional[dict[str, str]]], slots: Iterable[str]) -> int:
    return sum(1 for slot in slots if people.get(slot))


def crew_status(state: Mapping[str, Any], code: Any) -> dict:
    """
    Stan obsady meczu: dziury, lekkie różnice i komplet.

    Dziura = brakujący boiskowy albo PUSTY stolik. Jeden stolikowy zamiast dwóch
    to `soft` - obsadowy ma to widzieć, ale nie jako błąd do poprawienia.
    """
    people = crew(state)
    needs = crew_needs(code)

    field_have = _have(people, FIELD_SLOTS)
    table_have = _have(people, TABLE_SLOTS)
    delegate_have = _have(people, DELEGATE_SLOTS)

    field_missing = max(0, needs["field"] - field_have)
    table_missing = needs["table"] if table_have == 0 else 0
    table_soft = max(0, needs["table"] - table_have) if table_have else 0

    gaps = field_missing + table_missing
    return {
        "field": {"have": field_have, "need": needs["field"], "missing": field_missing},
        "table": {
            "have": table_have,
            "need": needs["table"],
            "missing": table_missing,
            "soft": table_soft,
        },
        "delegate": {"have": delegate_have},
        "gaps": gaps,
        "soft": table_soft,
        "state": GAP if gaps else (SOFT if table_soft else COMPLETE),
    }


def match_category(code: Any) -> str:
    """Kategoria meczu z numeru („Junior ml.", „II liga kobiet")."""
    return R.district_category(code) or R.central_category(code) or ""


def competition_key(code: Any) -> str:
    """
    Rozgrywki, do których należy mecz: numer bez ostatniego członu.

    „IIK4/1" -> „IIK4", „S/JmM/12" -> „S/JmM". Po tym grupujemy listę i budujemy
    filtr rozgrywek - `competition_prefix` skleiłby razem całe województwa.
    """
    text = " ".join(_s(code).split())
    parts = [part for part in text.split("/") if part]
    if len(parts) < 2:
        return text
    return "/".join(parts[:-1])
