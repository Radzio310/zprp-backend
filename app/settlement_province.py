"""
Wojewodztwo w rozliczeniach: JEDEN klucz dla naszych tabel, komplet pisowni
do zapytan o cudze.

Tabele w bazie trzymaja wojewodztwo na trzy sposoby:
  - "ŚLĄSKIE", "KUJAWSKO-POMORSKIE" - `okreg_rates`, `okreg_distances`,
    `province_judges` (tak, jak przysyla to aplikacja),
  - "SLASKIE", "KUJAWSKO_POMORSKIE" - `province_matches` i konta z Railway
    (`zprp_accounts.normalize_province`),
  - "KUJAWSKOPOMORSKIE" - `settlement_rates.province_key`, tylko do porownan.

Pierwsza wersja modulu zapisywala "ŚLĄSKIE", a pytala o "SLASKIE": wlaczony
modul raportowal sie jako wylaczony, kafle w aplikacji sie nie pokazywaly, a
petla dobowa nigdy nie ruszala. Dlatego nasze tabele (`province_modules`,
`province_settlement_*`) trzymaja jeden klucz - ten z kont Railway, bo z nimi
laczy sie petla - a do cudzych tabel pytamy zbiorem wszystkich znanych pisowni.

MODUL-LISC: bez bazy, zeby regule dalo sie sprawdzic testem.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from app.zprp_accounts import PROVINCE_ENV_SUFFIXES, normalize_province

#: Klucz kont Railway -> nazwa, jaka widzi czlowiek (i jaka przysyla aplikacja).
DISPLAY: dict[str, str] = {
    "DOLNOSLASKIE": "DOLNOŚLĄSKIE",
    "KUJAWSKO_POMORSKIE": "KUJAWSKO-POMORSKIE",
    "LUBELSKIE": "LUBELSKIE",
    "LUBUSKIE": "LUBUSKIE",
    "LODZKIE": "ŁÓDZKIE",
    "MALOPOLSKIE": "MAŁOPOLSKIE",
    "MAZOWIECKIE": "MAZOWIECKIE",
    "OPOLSKIE": "OPOLSKIE",
    "PODKARPACKIE": "PODKARPACKIE",
    "PODLASKIE": "PODLASKIE",
    "POMORSKIE": "POMORSKIE",
    "SLASKIE": "ŚLĄSKIE",
    "SWIETOKRZYSKIE": "ŚWIĘTOKRZYSKIE",
    "WARMINSKO_MAZURSKIE": "WARMIŃSKO-MAZURSKIE",
    "WIELKOPOLSKIE": "WIELKOPOLSKIE",
    "ZACHODNIOPOMORSKIE": "ZACHODNIOPOMORSKIE",
}

assert set(DISPLAY) == set(PROVINCE_ENV_SUFFIXES), "DISPLAY musi znac wszystkie 16 wojewodztw"


def _strip(value: str) -> str:
    text = value.replace("Ł", "L").replace("ł", "l")
    return "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )


def canonical(value: Any) -> str:
    """Klucz naszych tabel, np. "SLASKIE". Pusty napis = nieznane wojewodztwo."""
    return normalize_province(value)


def display(value: Any) -> str:
    """Nazwa dla czlowieka, np. "ŚLĄSKIE"."""
    key = canonical(value)
    return DISPLAY.get(key, str(value or "").strip().upper())


def spellings(value: Any) -> list[str]:
    """
    Wszystkie pisownie, pod ktorymi to wojewodztwo moze lezec w cudzej tabeli.

    Wielkie litery, bo kazdy zapis w bazie idzie przez `.upper()`. Dla nazwy,
    ktorej nie znamy, oddajemy ja sama - lepiej zapytac wprost, niz nie
    zapytac wcale.
    """
    key = canonical(value)
    if not key:
        raw = str(value or "").strip().upper()
        return [raw] if raw else []
    name = DISPLAY[key]
    plain = _strip(name)
    variants = {
        key,
        name,
        plain,
        name.replace("-", "_"),
        plain.replace("-", "_"),
        key.replace("_", "-"),
        key.replace("_", ""),
        name.replace("-", " "),
        plain.replace("-", " "),
    }
    return sorted(v for v in variants if v)
