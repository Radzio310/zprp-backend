"""Mecze międzypaństwowe i międzynarodowe w tabeli centralnej - LIŚĆ: bez bazy i bez sieci.

Źródło: Tabela Ryczałtów Sędziowskich ZPRP, uchwała 44/26, tabela A, od 01.09.2026. Kształt taki sam jak reszta `weekend`/`weekday`.

Międzynarodowe młodzieżowe stoją w tabeli w kolumnie II ligi, która ma TYLKO dwa progi. `above300` równa się więc `100to300`, tak samo
jak w zastanym kluczu „II liga": tabela nie podaje wyższej stawki, a aplikacja mówi o tym wprost przy kwocie.
"""

from __future__ import annotations

import copy
from typing import Any, Dict

#: Pierwszy dzień obowiązywania tych stawek.
INTL_FROM = "2026-09-01"

#: Stolik na każdym szczeblu centralnym tabeli A.
INTL_TABLE_RATE = 110


def _band(below100: int, mid: int, above300: int) -> Dict[str, int]:
    return {"below100": below100, "100to300": mid, "above300": above300}


INTL_FIELD_RATES: Dict[str, Dict[str, Dict[str, int]]] = {
    "weekend": {
        "Międzypaństwowe seniorzy": _band(529, 579, 739),
        "Międzypaństwowe młodzież": _band(339, 389, 549),
        "Międzynarodowe seniorzy": _band(264, 314, 474),
        "Międzynarodowe młodzież": _band(195, 245, 245),
    },
    "weekday": {
        "Międzypaństwowe seniorzy": _band(592, 642, 802),
        "Międzypaństwowe młodzież": _band(408, 458, 618),
        "Międzynarodowe seniorzy": _band(327, 377, 537),
        "Międzynarodowe młodzież": _band(247, 297, 297),
    },
}


def with_intl_categories(content: Any) -> Any:
    """Tabela z dopisanymi BRAKUJĄCYMI kategoriami. Istniejące klucze zostają co do złotówki; wejście nietknięte."""
    if not isinstance(content, dict):
        return content
    out = copy.deepcopy(content)
    for day, rates in INTL_FIELD_RATES.items():
        section = out.setdefault(day, {})
        field = section.setdefault("boiskowy", {})
        table = section.setdefault("stolikowy", {})
        for key, band in rates.items():
            field.setdefault(key, dict(band))
            table.setdefault(key, INTL_TABLE_RATE)
    return out


def intl_keys() -> set:
    return {key for rates in INTL_FIELD_RATES.values() for key in rates}


def has_intl_entry(content: Any) -> bool:
    """Czy tabela ma JAKIKOLWIEK wpis meczu międzypaństwowego/międzynarodowego (stawka boiskowa lub stolikowa).

    Wpis oznacza, że wersja była już zasilona albo poprawiana przez człowieka. Wtedy nie dopisujemy niczego, także brakującego klucza:
    klucz mógł zostać usunięty świadomie i nie wolno go przywracać przy każdym starcie serwera."""
    if not isinstance(content, dict):
        return False
    keys = intl_keys()
    for day in INTL_FIELD_RATES:
        section = content.get(day)
        if not isinstance(section, dict):
            continue
        for part in ("boiskowy", "stolikowy"):
            block = section.get(part)
            if isinstance(block, dict) and keys & set(block):
                return True
    return False


def needs_intl_seed(valid_from: Any, content: Any) -> bool:
    """Tylko wersja, która startuje DOKŁADNIE od 01.09.2026 i nie ma jeszcze żadnego wpisu międzypaństwowego."""
    from datetime import date

    try:
        starts = valid_from if isinstance(valid_from, date) else date.fromisoformat(str(valid_from)[:10])
    except (TypeError, ValueError):
        return False
    return starts == date.fromisoformat(INTL_FROM) and isinstance(content, dict) and bool(content) and not has_intl_entry(content)

