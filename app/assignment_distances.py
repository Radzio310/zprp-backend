"""
Kilometry dla automatu obsady: NAJPIERW tabela okręgu, potem pamięć, na końcu Google.

Decyzja użytkownika z 12.09.2026: „licząc kilometry liczyć je z tabeli
odległości, a nie ręcznie z Google API wszystko. Tylko brakujące kombinacje
miasto sędziego - miasto hali możesz z Google'a". Tak więc:

  1. to samo miasto        -> 0 km, bez pytania kogokolwiek,
  2. `okreg_distances`     -> tabela zmierzona przez okręg, ta sama, która
                              rozlicza przejazdy (jeden słownik pojęć),
  3. `city_distances`      -> para, o którą już kiedyś pytaliśmy Google,
  4. Google Distance Matrix-> tylko pary, których nie ma nigdzie wyżej,
                              i od razu zapisane do `city_distances`.

Automat pyta o odległość TYSIĄCE razy (każdy sędzia x każdy mecz), a `Context`
oczekuje zwykłej funkcji - dlatego cały zbiór par wypełniamy PRZED układaniem
planu, a w trakcie liczenia jest już tylko odczyt ze słownika w pamięci.

⚠ Brak odległości NIE jest zerem. Automat karze „nie wiemy" osobna waga, a
raport pokazuje, ilu par nie znamy - inaczej sędzia z drugiego końca
województwa wyglądałby na najbliższego.
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

#: Ile par jednego przebiegu wolno dopytać Google. Zapora na rachunek: przy
#: pierwszym uruchomieniu w nowym okręgu brakować może setek par, a lepiej
#: uzupełniać je po kawałku niż wystawić sobie fakturę jednym klikiem.
GOOGLE_BUDGET = 120


class DistanceBook:
    """Odległości gotowe do czytania - tabela okręgu plus zapamiętane pary."""

    __slots__ = (
        "index", "_cache", "_asked", "_seen",
        "from_table", "from_memory", "from_google",
    )

    def __init__(self, index: DistanceIndex, cache: dict[tuple[str, str], float] | None = None):
        self.index = index
        self._cache: dict[tuple[str, str], float] = dict(cache or {})
        #: Odpowiedzi po SUROWEJ parze napisów.
        #:
        #: ⚠ Automat pyta o odległość ~130 tysięcy razy przy jednym przebiegu
        #: (każdy sędzia razy każde gniazdo), a `normalize_city` to kilka
        #: wyrażeń regularnych na wywołanie - bez tej pamięci same odległości
        #: zjadały sześć z siedmiu sekund przebiegu. Miast jest kilkadziesiąt,
        #: więc słownik zostaje malutki, a trafia prawie zawsze.
        self._seen: dict[tuple[str, str], Optional[float]] = {}
        #: Pary, o które pytano i których NIE znalazł nikt - żeby nie pytać w kółko.
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
        raw = (str(origin or ""), str(destination or ""))
        if raw in self._seen:
            return self._seen[raw]
        value = self._lookup(origin, destination)
        self._seen[raw] = value
        return value

    def _lookup(self, origin: Any, destination: Any) -> Optional[float]:
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
        """Pary, których nie zna ani tabela, ani pamięć - kandydatki do Google."""
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
        # Nowa odpowiedź unieważnia pamięć po surowych napisach - inaczej para,
        # o którą pytaliśmy przed Google'em, na zawsze zostałaby nieznana.
        self._seen.clear()
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
    """Tabela okręgu plus wszystko, co już kiedyś policzył Google."""
    # Import lokalny: `app.db` łączy się z Postgresem przy imporcie, a sama
    # księga odległości jest czysta - dzięki temu chodzi w teście bez bazy.
    from sqlalchemy import select

    from app.db import city_distances, database, okreg_distances

    row = await database.fetch_one(
        select(okreg_distances.c.content).where(
            okreg_distances.c.province.in_(spellings(province))
        )
    )
    content = row["content"] if row else None
    if isinstance(content, (str, bytes, bytearray)):
        # ⚠ Kolumna JSON potrafi wrócić SUROWYM NAPISEM (asyncpg bez kodeka).
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
    Dopytuje Google o pary, których nie zna nikt, i ZAPISUJE je na zawsze.

    Zapis idzie do `city_distances`, więc następny przebieg - i następny miesiąc -
    ma tę parę za darmo. Bez klucza do Google kończy się po cichu: automat
    policzy plan z tym, co wie, a raport pokaze, ile par zostało nieznanych.
    """
    todo = book.missing(pairs)[: max(0, int(budget))]
    if not todo:
        return {"asked": 0, "saved": 0, "missing": 0}

    # Import po odsianiu pustego przebiegu: `app.db` łączy się z Postgresem już
    # przy imporcie, a „nie ma czego dopytać" nie potrzebuje żadnej bazy.
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
                # Pamięć jest wygoda, nie warunkiem. Plan i tak ma już tę liczbę.
                logger.exception("obsada: nie udało się zapamiętać odległości %s-%s", left, right)
    finally:
        if own_client:
            await client.aclose()

    return {
        "asked": len(todo),
        "saved": saved,
        "missing": len(book.missing(pairs)),
    }
