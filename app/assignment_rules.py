"""
Modul obsadowego - czego mecz potrzebuje i czego mu brakuje.

MODUL-LISC: bez bazy i sieci, zeby regula chodzila w tescie.

Decyzje uzytkownika z 11.09.2026 (Slask, ale regula jest ogolna):
  - DWOCH sedziow boiskowych wszedzie od Mlodzika w gore; Mlodzik mlodszy
    i Dzieci moga miec jednego,
  - DWOCH stolikowych tak samo, ale JEDEN stolikowy to nie blad: klub czesto
    daje swojego, wiec brak drugiego jest tylko lekka roznica, a nie dziura,
  - DELEGATA na meczach okregowych nie ma nigdy, na II lidze zdarza sie bardzo
    rzadko - nigdy nie liczy sie jako brak, pokazujemy go tylko, gdy jest.

Stad trzy rozne stany, nie dwa: „dziura" (brakuje kogos, kogo musimy wystawic),
„lekka roznica" (jeden stolikowy zamiast dwoch) i „komplet".
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from app import settlement_rates as R

#: Gniazda obsady w kolejnosci, w jakiej pokazuje je formularz ZPRP.
FIELD_SLOTS = ("pierwszy", "drugi")
TABLE_SLOTS = ("sekretarz", "czas")
DELEGATE_SLOTS = ("delegat", "delegat2")
SLOTS = FIELD_SLOTS + TABLE_SLOTS + DELEGATE_SLOTS

#: Kategorie, w ktorych wystarczy jeden boiskowy i jeden stolikowy.
SMALL_PREFIXES = frozenset({"DZM", "DZK", "MLM1213", "MLK1213"})

#: Stany gniazda i meczu.
COMPLETE = "complete"
SOFT = "soft"
GAP = "gap"


def _s(value: Any) -> str:
    return str(value or "").strip()


def crew_needs(code: Any) -> dict[str, int]:
    """Ilu ludzi ma stanac przy tym meczu: boiskowi i stolik."""
    small = R.competition_prefix(code) in SMALL_PREFIXES
    return {"field": 1 if small else 2, "table": 1 if small else 2}


def slot_person(state: Mapping[str, Any], slot: str) -> Optional[dict[str, str]]:
    """
    Kto stoi w gniezdzie: numer i nazwisko, albo None.

    ⚠ „0" to PUSTE GNIAZDO, nie sedzia - tak ZPRP zapisuje zdjeta obsade.
    Nazwisko bez numeru tez jest czlowiekiem: terminarz podaje same nazwiska,
    numery dochodza dopiero z publicznego API.
    """
    number = _s(state.get(f"NrSedzia_{slot}"))
    name = _s(state.get(f"NrSedzia_{slot}_nazwisko"))
    if number in ("", "0") and not name:
        return None
    return {"number": "" if number == "0" else number, "name": name}


def crew(state: Mapping[str, Any]) -> dict[str, Optional[dict[str, str]]]:
    """Cala szostka gniazd meczu."""
    return {slot: slot_person(state, slot) for slot in SLOTS}


def _have(people: Mapping[str, Optional[dict[str, str]]], slots: Iterable[str]) -> int:
    return sum(1 for slot in slots if people.get(slot))


def crew_status(state: Mapping[str, Any], code: Any) -> dict:
    """
    Stan obsady meczu: dziury, lekkie roznice i komplet.

    Dziura = brakujacy boiskowy albo PUSTY stolik. Jeden stolikowy zamiast dwoch
    to `soft` - obsadowy ma to widziec, ale nie jako blad do poprawienia.
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
    Rozgrywki, do ktorych nalezy mecz: numer bez ostatniego czlonu.

    „IIK4/1" -> „IIK4", „S/JmM/12" -> „S/JmM". Po tym grupujemy liste i budujemy
    filtr rozgrywek - `competition_prefix` skleilby razem cale wojewodztwa.
    """
    text = " ".join(_s(code).split())
    parts = [part for part in text.split("/") if part]
    if len(parts) < 2:
        return text
    return "/".join(parts[:-1])
