"""
SMS z wynikiem meczu - sama reguła (08.10.2026).

MODUŁ-LIŚĆ: bez bazy i sieci, żeby walidacja i wartości domyślne miały test.
Schemat w `app/sms_config_tables.py`, trasy w `app/sms_config.py`.

DECYZJE UŻYTKOWNIKA (08.10.2026):
  - Mecze centralne mają jedną konfigurację (`central`) - dziś numer
    604583150 i rozgrywki: Liga Centralna, I liga, MP, PP.
  - Każdy okręg włącza SMS osobno i ustawia GRUPY (jak adresaci dodatkowego
    raportu): nazwa, kategorie meczów i numer. Ta sama kategoria w dwóch
    grupach okręgu - wygrywa pierwsza.
  - O okręgu decyduje mecz (związek PROWADZĄCY rozgrywki), nie sędzia.
  - Szablon treści per zakres: „central" (jak SMS z meczów centralnych)
    albo „pair" (para sędziowska - dotychczasowy Dolny Śląsk).
  - Dolny Śląsk wczytuje się z tym, co działało: 602120659, szablon „pair",
    rozgrywki prowadzone przez okręg.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

CENTRAL = "central"

TEMPLATE_CENTRAL = "central"
TEMPLATE_PAIR = "pair"
TEMPLATES = (TEMPLATE_CENTRAL, TEMPLATE_PAIR)

#: Kategorie z plakietek numerów meczów (`BAZA/utils/matchCategoryColor.ts`,
#: `CATEGORY_FIXED_ORDER`) - te same, którymi admin ustawia dodatkowy raport.
CATEGORIES = (
    "MP", "PP", "SPM", "SPK",
    "MłM1213", "MłK1213", "MłM", "MłK",
    "JmM", "JmK", "JK", "JM",
    "IIIM", "IIIK", "IIM", "IIK",
    "IK", "IM", "LCM", "LCK",
    "OSM", "OSK", "SM", "SK",
)

#: Rozgrywki prowadzone przez okręgi (od II ligi w dół).
DISTRICT_CATEGORIES = (
    "IIM", "IIK", "IIIM", "IIIK",
    "JM", "JK", "JmM", "JmK",
    "MłM", "MłK", "MłM1213", "MłK1213",
)

MAX_GROUPS = 10
MAX_NAME = 60

DEFAULTS: dict[str, dict] = {
    CENTRAL: {
        "enabled": True,
        "template": TEMPLATE_CENTRAL,
        "groups": [
            {
                "name": "Rozgrywki centralne",
                "categories": ["LCM", "LCK", "IM", "IK", "MP", "PP"],
                "phone": "604583150",
            }
        ],
    },
    "DOLNOSLASKIE": {
        "enabled": True,
        "template": TEMPLATE_PAIR,
        "groups": [
            {
                "name": "Mecze okręgowe",
                "categories": list(DISTRICT_CATEGORIES),
                "phone": "602120659",
            }
        ],
    },
}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def normalize_phone(value: Any) -> str:
    """
    Numer do zapisu: same cyfry, z „+" na początku tylko przy numerze
    zagranicznym. „+48 604 583 150" i „604-583-150" to ten sam numer -
    zapisujemy „604583150", bo tak wpisuje go composer SMS w telefonie.
    """
    raw = _s(value)
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("00"):
        digits = digits[2:]
        raw = "+" + digits
    if len(digits) == 11 and digits.startswith("48") and (raw.startswith("+") or raw.startswith("48")):
        return digits[2:]
    if raw.startswith("+"):
        return "+" + digits
    return digits


def phone_problem(phone: str) -> Optional[str]:
    if not phone:
        return "Wpisz numer, na który idzie SMS."
    digits = phone.lstrip("+")
    if len(digits) < 9 or len(digits) > 15:
        return f"Numer „{phone}” wygląda na niepełny - polski numer ma 9 cyfr."
    return None


def clean_categories(values: Iterable[Any]) -> list[str]:
    """Znane kategorie, bez powtórek, w kolejności plakietek."""
    wanted = {_s(v) for v in values or []}
    return [code for code in CATEGORIES if code in wanted]


def clean_scope(raw: dict, *, label: str) -> dict:
    """
    Zakres z panelu -> zapis. Wyjątek `ValueError` z ludzkim zdaniem, gdy
    czegoś brakuje - panel pokaże je przy grupie.

    Wyłączony zakres może mieć grupy bez numeru (admin dopiero ustawia), ale
    włączony musi mieć przynajmniej jedną kompletną grupę: inaczej sędzia
    zobaczyłby przycisk SMS bez adresata.
    """
    enabled = bool(raw.get("enabled"))
    template = _s(raw.get("template")) or TEMPLATE_CENTRAL
    if template not in TEMPLATES:
        raise ValueError(f"{label}: nieznany szablon treści „{template}”.")
    groups_in = list(raw.get("groups") or [])
    if len(groups_in) > MAX_GROUPS:
        raise ValueError(f"{label}: najwyżej {MAX_GROUPS} grup.")
    groups: list[dict] = []
    for index, group in enumerate(groups_in, start=1):
        name = _s(group.get("name"))[:MAX_NAME] or f"Grupa {index}"
        phone = normalize_phone(group.get("phone"))
        categories = clean_categories(group.get("categories") or [])
        if enabled:
            problem = phone_problem(phone)
            if problem:
                raise ValueError(f"{label} · {name}: {problem}")
            if not categories:
                raise ValueError(f"{label} · {name}: zaznacz kategorie meczów.")
        groups.append({"name": name, "categories": categories, "phone": phone})
    if enabled and not groups:
        raise ValueError(f"{label}: dodaj grupę z numerem i kategoriami.")
    return {"enabled": enabled, "template": template, "groups": groups}


def default_scope(scope: str) -> dict:
    """Konfiguracja zakresu, którego admin jeszcze nie zapisał."""
    base = DEFAULTS.get(scope)
    if base is None:
        return {"enabled": False, "template": TEMPLATE_CENTRAL, "groups": []}
    return {
        "enabled": base["enabled"],
        "template": base["template"],
        "groups": [dict(g, categories=list(g["categories"])) for g in base["groups"]],
    }


def group_for(scope: dict, category: str) -> Optional[dict]:
    """Pierwsza grupa włączonego zakresu z tą kategorią - albo None."""
    if not scope.get("enabled"):
        return None
    for group in scope.get("groups") or []:
        if category in (group.get("categories") or []) and group.get("phone"):
            return group
    return None
