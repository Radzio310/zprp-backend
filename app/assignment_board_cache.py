"""
Pamięć podręczna Obsady 2.0 - gotowy stan panelu trzymany w procesie.

MODUŁ-LIŚĆ: bez bazy i sieci. Serwer chodzi w jednym procesie (uvicorn bez
`--workers`), więc zwykły słownik wystarcza.

Zasada jest prosta i dlatego poprawna:
  - każdy okręg ma LICZNIK WERSJI; `bump(okręg)` podbija go przy każdym zapisie,
    który zmienia to, co widzi panel (obsada, hala, ustawienia sędziów i klubów,
    pary, pary mentorskie, przebieg synchronizacji meczów i niedyspozycji),
  - wpis w pamięci pamięta wersję, z której powstał; inna wersja = wpis martwy,
  - do tego krótki `TTL`: część danych (odznaki, uprawnienia z formularza,
    licznik sezonu z rozliczeń) zmienia się drogami, które licznika nie ruszają.
    Po `TTL` stan buduje się od nowa, nawet bez zapisu.

ETag to skrót wersji, chwili zbudowania i numeru szkicu kolejki (szkic czytamy
zawsze świeży - jest mały i zmienia się najczęściej).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Callable, Optional

from app.settlement_province import canonical

#: Ile sekund gotowy stan żyje bez żadnego zapisu.
TTL_SECONDS = 600

_versions: dict[str, int] = {}
_entries: dict[tuple[str, Any, str], tuple[int, float, Any]] = {}


def _key(province: Any) -> str:
    return canonical(province) or str(province or "").strip().upper()


def version(province: Any) -> int:
    return _versions.get(_key(province), 0)


def bump(province: Any) -> int:
    """Unieważnia wszystko, co zbudowano dla tego okręgu. Zwraca nową wersję."""
    key = _key(province)
    _versions[key] = _versions.get(key, 0) + 1
    return _versions[key]


def bump_all() -> None:
    """Zapis, który nie zna okręgu (rejestr sędziów po samym numerze) - wszystko do przebudowy."""
    for key in list(_versions) + [entry[0] for entry in list(_entries)]:
        _versions[key] = _versions.get(key, 0) + 1
    _entries.clear()


def get(
    province: Any,
    season: Any,
    kind: str,
    *,
    now: Optional[Callable[[], float]] = None,
    ttl: float = TTL_SECONDS,
) -> Optional[tuple[int, float, Any]]:
    """(wersja, chwila zbudowania, wartość) - albo None, gdy wpis martwy."""
    clock = now or time.time
    entry = _entries.get((_key(province), season, kind))
    if entry is None:
        return None
    built_version, built_at, _value = entry
    if built_version != version(province) or clock() - built_at > ttl:
        _entries.pop((_key(province), season, kind), None)
        return None
    return entry


def put(
    province: Any,
    season: Any,
    kind: str,
    value: Any,
    *,
    built_version: Optional[int] = None,
    now: Optional[Callable[[], float]] = None,
) -> tuple[int, float, Any]:
    """
    Zapamiętuje wartość zbudowaną z wersji `built_version`.

    Wersję trzeba odczytać PRZED budowaniem: zapis, który przyszedł w trakcie,
    podbił licznik i taki wpis od razu będzie martwy - zamiast przykryć świeżą
    zmianę starym stanem.
    """
    clock = now or time.time
    entry = (
        version(province) if built_version is None else int(built_version),
        clock(),
        value,
    )
    _entries[(_key(province), season, kind)] = entry
    return entry


def etag(built_version: int, built_at: float, draft_rev: int = 0) -> str:
    raw = f"{built_version}:{built_at:.3f}:{int(draft_rev or 0)}"
    return 'W/"' + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20] + '"'


def clear() -> None:
    """Tylko dla testów."""
    _versions.clear()
    _entries.clear()
