"""
Kilometry dla automatu obsady: NAJPIERW tabela okregu, potem pamiec, na koncu Google.

Decyzja uzytkownika z 12.09.2026: „liczac kilometry liczyc je z tabeli
odleglosci, a nie recznie z Google API wszystko. Tylko brakujace kombinacje
miasto sedziego - miasto hali mozesz z Google'a". Tak wiec:

  1. to samo miasto        -> 0 km, bez pytania kogokolwiek,
  2. `okreg_distances`     -> tabela zmierzona przez okreg, ta sama, ktora
                              rozlicza przejazdy (jeden slownik pojec),
  3. `city_distances`      -> para, o ktora juz kiedys pytalismy Google,
  4. Google Distance Matrix-> tylko pary, ktorych nie ma nigdzie wyzej,
                              i od razu zapisane do `city_distances`.

Automat pyta o odleglosc TYSIACE razy (kazdy sedzia x kazdy mecz), a `Context`
oczekuje zwyklej funkcji - dlatego caly zbior par wypelniamy PRZED ukladaniem
planu, a w trakcie liczenia jest juz tylko odczyt ze slownika w pamieci.

⚠ Brak odleglosci NIE jest zerem. Automat karze „nie wiemy" osobna waga, a
raport pokazuje, ilu par nie znamy - inaczej sedzia z drugiego konca
wojewodztwa wygladalby na najblizszego.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from app.settlement_distances import (
    DistanceIndex,
    google_distance,
    normalize_city,
)
from app.settlement_province import spellings

logger = logging.getLogger(__name__)

#: Ile par jednego przebiegu wolno dopytac Google. Zapora na rachunek: przy
#: pierwszym uruchomieniu w nowym okregu brakowac moze setek par, a lepiej
#: uzupelniac je po kawalku niz wystawic sobie fakture jednym klikiem.
GOOGLE_BUDGET = 120


class DistanceBook:
    """Odleglosci gotowe do czytania - tabela okregu plus zapamietane pary."""

    __slots__ = ("index", "_cache", "_asked", "from_table", "from_memory", "from_google")

    def __init__(self, index: DistanceIndex, cache: dict[tuple[str, str], float] | None = None):
        self.index = index
        self._cache: dict[tuple[str, str], float] = dict(cache or {})
        #: Pary, o ktore pytano i ktorych NIE znalazl nikt - zeby nie pytac w kolko.
        self._asked: set[tuple[str, str]] = set()
        self.from_table = 0
        self.from_memory = 0
        self.from_google = 0

    @staticmethod
    def key(origin: Any, destination: Any) -> Optional[tuple[str, str]]:
        left = normalize_city(origin)[0]
        right = normalize_city(destination)[0]
        if not left or not right:
            return None
        return (left, right) if left <= right else (right, left)

    def km(self, origin: Any, destination: Any) -> Optional[float]:
        """Kilometry albo None. Funkcja dla `Context.km` - czysty odczyt."""
        key = self.key(origin, destination)
        if key is None:
            return None
        if key[0] == key[1]:
            return 0.0
        hit = self.index.lookup(origin, destination)
        if hit is not None:
            self.from_table += 1
            return hit
        remembered = self._cache.get(key)
        if remembered is not None:
            self.from_memory += 1
            return float(remembered)
        return None

    def missing(self, pairs: Iterable[tuple[Any, Any]]) -> list[tuple[str, str]]:
        """Pary, ktorych nie zna ani tabela, ani pamiec - kandydatki do Google."""
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for origin, destination in pairs:
            key = self.key(origin, destination)
            if key is None or key[0] == key[1] or key in seen or key in self._asked:
                continue
            seen.add(key)
            if self.index.lookup(origin, destination) is not None:
                continue
            if key in self._cache:
                continue
            out.append(key)
        return out

    def remember(self, key: tuple[str, str], km: Optional[float]) -> None:
        if km is None:
            self._asked.add(key)
            return
        self._cache[key] = float(km)
        self.from_google += 1

    @property
    def stats(self) -> dict:
        return {
            "table": self.from_table,
            "memory": self.from_memory,
            "google": self.from_google,
            "unknown_pairs": len(self._asked),
            "table_pairs": self.index.pairs,
            "remembered_pairs": len(self._cache),
        }


async def load_book(province: str) -> DistanceBook:
    """Tabela okregu plus wszystko, co juz kiedys policzyl Google."""
    # Import lokalny: `app.db` laczy sie z Postgresem przy imporcie, a sama
    # ksiega odleglosci jest czysta - dzieki temu chodzi w tescie bez bazy.
    from sqlalchemy import select

    from app.db import city_distances, database, okreg_distances

    row = await database.fetch_one(
        select(okreg_distances.c.content).where(
            okreg_distances.c.province.in_(spellings(province))
        )
    )
    content = row["content"] if row else None
    if isinstance(content, (str, bytes, bytearray)):
        # ⚠ Kolumna JSON potrafi wrocic SUROWYM NAPISEM (asyncpg bez kodeka).
        import json

        try:
            content = json.loads(content)
        except ValueError:
            content = None
    index = DistanceIndex(content)

    cache: dict[tuple[str, str], float] = {}
    for saved in await database.fetch_all(select(city_distances)):
        left = str(saved["from_key"] or "")
        right = str(saved["to_key"] or "")
        if not left or not right:
            continue
        key = (left, right) if left <= right else (right, left)
        cache[key] = float(saved["km"] or 0.0)
    return DistanceBook(index, cache)


async def fill_missing(
    book: DistanceBook,
    pairs: Iterable[tuple[Any, Any]],
    *,
    budget: int = GOOGLE_BUDGET,
    client: Any = None,
) -> dict:
    """
    Dopytuje Google o pary, ktorych nie zna nikt, i ZAPISUJE je na zawsze.

    Zapis idzie do `city_distances`, wiec nastepny przebieg - i nastepny miesiac -
    ma te pare za darmo. Bez klucza do Google konczy sie po cichu: automat
    policzy plan z tym, co wie, a raport pokaze, ile par zostalo nieznanych.
    """
    todo = book.missing(pairs)[: max(0, int(budget))]
    if not todo:
        return {"asked": 0, "saved": 0, "missing": 0}

    # Import po odsianiu pustego przebiegu: `app.db` laczy sie z Postgresem juz
    # przy imporcie, a „nie ma czego dopytac" nie potrzebuje zadnej bazy.
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import city_distances, database

    own_client = client is None
    if own_client:
        from httpx import AsyncClient

        client = AsyncClient(timeout=20.0)

    saved = 0
    try:
        for left, right in todo:
            km = await google_distance(client, left, right)
            book.remember((left, right), km)
            if km is None:
                continue
            try:
                await database.execute(
                    pg_insert(city_distances)
                    .values(from_key=left, to_key=right, km=float(km), source="google")
                    .on_conflict_do_update(
                        index_elements=[city_distances.c.from_key, city_distances.c.to_key],
                        set_={"km": float(km), "source": "google"},
                    )
                )
                saved += 1
            except Exception:
                # Pamiec jest wygoda, nie warunkiem. Plan i tak ma juz te liczbe.
                logger.exception("obsada: nie udało się zapamiętać odległości %s-%s", left, right)
    finally:
        if own_client:
            await client.aclose()

    return {
        "asked": len(todo),
        "saved": saved,
        "missing": len(book.missing(pairs)),
    }
