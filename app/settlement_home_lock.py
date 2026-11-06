"""
Miasto zamieszkania sędziego zamrożone w chwili rozliczenia (decyzja właściciela 06.11.2026).

Problem: przebieg odświeżania (nocny i ręczny) brał miasto sędziego z BIEŻĄCEJ listy
„Sędziowie i Delegaci" i wpisywał je do KAŻDEGO meczu sezonu, także rozliczonego
miesiące temu. Po przeprowadzce stare mecze dostawały nową trasę, inne kilometry
i inną kwotę niż ta, którą sędzia dostał na konto.

Reguła: KLUCZOWY JEST MOMENT ROZLICZENIA.
  - Wydanie OFICJALNEGO dokumentu (zestawienie albo przejazdy) zamraża miasto
    zamieszkania, kilometry i ich źródło na każdym meczu tego sędziego, który stoi
    w rozliczonym okresie (`lock_homes`). Zapisujemy numer pierwszego dokumentu.
  - Odświeżanie i zmiany obsady na żywo nie ruszają zamrożonych pól (`apply_locks`).
  - Mecze jeszcze nierozliczone liczą się z miasta, które jest teraz w ZPRP.
  - Unieważnienie numeru (np. odblokowanie podziału na listy) NIE zdejmuje blokady:
    ponowne wydanie tego okresu ma wyjść z tym samym dojazdem, który już raz poszedł.

Sędzia widzi w aplikacji, z jakiego miasta liczono dany okres i dlaczego
(`home_story`, pole `home` w `/me/season`).
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

_PL = ZoneInfo("Europe/Warsaw")

#: Pola wiersza obsady, które blokada zamraża.
LOCKED_FIELDS = ("home_city", "distance_km", "distance_source")

#: Ile kluczy w jednym `IN` (limit parametrów zapytania).
_CHUNK = 400


def _s(value: Any) -> str:
    return str(value or "").strip()


def fold_city(value: Any) -> str:
    """Porównanie miast bez wielkości liter i zbędnych spacji."""
    return " ".join(_s(value).lower().split())


# ---------------------------------------------------------------------------
# Reguły (czyste - testy w tests/test_settlement_home_lock.py)
# ---------------------------------------------------------------------------

def apply_locks(
    batch: Mapping[tuple[str, str], dict],
    locked: Mapping[tuple[str, str], Mapping[str, Any]],
) -> int:
    """
    Zamrożone pola wracają do wierszy przebiegu (w miejscu). Zwraca liczbę
    wierszy, w których blokada coś zmieniła.

    `batch` - (judge_id, match_key) -> wartości do zapisu,
    `locked` - (judge_id, match_key) -> zamrożone `home_city`, `distance_km`, `distance_source`.
    """
    changed = 0
    for key, values in batch.items():
        frozen = locked.get(key)
        if frozen is None:
            continue
        before = tuple(values.get(field) for field in LOCKED_FIELDS)
        for field in LOCKED_FIELDS:
            values[field] = frozen.get(field)
        if before != tuple(values.get(field) for field in LOCKED_FIELDS):
            changed += 1
    return changed


def lock_keys_of(matches: Iterable[Any]) -> list[str]:
    """Klucze meczów do zamrożenia - bez ręcznych meczów z karty klubu (osobna tabela)."""
    out: list[str] = []
    seen: set[str] = set()
    for match in matches:
        key = _s(getattr(match, "match_key", None) if not isinstance(match, Mapping) else match.get("match_key"))
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def home_story(rows: Iterable[Mapping[str, Any]], current: Any) -> dict | None:
    """
    Wyjaśnienie dla sędziego: z jakiego miasta liczono dojazdy okresu.

    `rows` - wiersze meczów okresu (`home_city`, `home_locked`, `distance_km`, `future`),
    `current` - miasto zamieszkania, które ZPRP podaje teraz.

    Zwraca None, gdy nie ma czego tłumaczyć (żaden mecz okresu nie ma miasta).
    `changed` = okres liczony (choćby częściowo) z innego miasta niż dzisiejsze.
    """
    now_city = _s(current)
    cities: OrderedDict[str, dict] = OrderedDict()
    for row in rows:
        city = _s(row.get("home_city"))
        if not city:
            continue
        slot = cities.setdefault(
            fold_city(city),
            {"city": city, "matches": 0, "locked": 0, "documents": []},
        )
        slot["matches"] += 1
        doc = _s(row.get("home_locked"))
        if doc:
            slot["locked"] += 1
            if doc not in slot["documents"]:
                slot["documents"].append(doc)
    if not cities:
        return None
    items = list(cities.values())
    for item in items:
        item["current"] = bool(now_city) and fold_city(item["city"]) == fold_city(now_city)
    changed = bool(now_city) and any(not item["current"] for item in items)
    locked = sum(item["locked"] for item in items)
    total = sum(item["matches"] for item in items)
    return {
        "current": now_city or None,
        "changed": changed,
        # „all" - cały okres rozliczony dokumentem, „some" - część, „none" - jeszcze nic.
        "settled": "all" if locked and locked == total else ("some" if locked else "none"),
        "cities": items,
    }


def register_window(
    date_from: date | None,
    date_to: date | None,
    created_at: datetime | None,
    include_future: bool,
) -> tuple[datetime, datetime] | None:
    """
    Zakres meczów dokumentu wydanego PRZED blokadą (zamrożenie wstecz z rejestru):
    dni okresu po czasie polskim, a bez „przyszłych" - tylko mecze sprzed wydania
    (późniejszych na dokumencie nie było).
    """
    if date_from is None or date_to is None:
        return None
    start = datetime.combine(date_from, time.min, _PL)
    end = datetime.combine(date_to + timedelta(days=1), time.min, _PL)
    if not include_future and created_at is not None:
        stamp = created_at if created_at.tzinfo else created_at.replace(tzinfo=_PL)
        end = min(end, stamp)
    return (start, end) if end > start else None


# ---------------------------------------------------------------------------
# Baza
# ---------------------------------------------------------------------------

async def locked_homes(province: str, keys: Iterable[tuple[str, str]] | None = None) -> dict:
    """(judge_id, match_key) -> zamrożone pola; `keys=None` - cały okręg."""
    from sqlalchemy import and_, select, tuple_

    from app.db import database
    from app.db import province_settlement_matches as M

    columns = [M.c.judge_id, M.c.match_key, *(M.c[f] for f in LOCKED_FIELDS)]
    base = and_(M.c.province == province, M.c.home_locked_at.isnot(None))
    rows: list = []
    if keys is None:
        rows = list(await database.fetch_all(select(*columns).where(base)))
    else:
        wanted = list(dict.fromkeys((_s(j), _s(k)) for j, k in keys))
        for start in range(0, len(wanted), _CHUNK):
            chunk = wanted[start : start + _CHUNK]
            rows.extend(
                await database.fetch_all(
                    select(*columns).where(and_(base, tuple_(M.c.judge_id, M.c.match_key).in_(chunk)))
                )
            )
    return {
        (_s(row["judge_id"]), _s(row["match_key"])): {f: row[f] for f in LOCKED_FIELDS}
        for row in rows
    }


async def lock_homes(
    province: str,
    keys_by_judge: Mapping[str, Iterable[str]],
    number: str,
    now: datetime | None = None,
) -> int:
    """
    Zamrożenie po wydaniu oficjalnego dokumentu `number` - tylko wierszy jeszcze
    niezamrożonych (pierwszy dokument wygrywa). Wołać w transakcji wydania.
    """
    from datetime import timezone

    from sqlalchemy import and_, update

    from app.db import database
    from app.db import province_settlement_matches as M

    stamp = now or datetime.now(timezone.utc)
    done = 0
    for judge_id, keys in keys_by_judge.items():
        wanted = list(dict.fromkeys(_s(k) for k in keys if _s(k)))
        for start in range(0, len(wanted), _CHUNK):
            chunk = wanted[start : start + _CHUNK]
            await database.execute(
                update(M)
                .where(
                    and_(
                        M.c.province == province,
                        M.c.judge_id == _s(judge_id),
                        M.c.match_key.in_(chunk),
                        M.c.home_locked_at.is_(None),
                    )
                )
                .values(home_locked_doc=_s(number), home_locked_at=stamp)
            )
            done += len(chunk)
    return done


async def current_home(province: str, judge_id: str) -> str:
    """Miasto zamieszkania z ostatniej listy okręgu (to, z którego liczą się nierozliczone mecze)."""
    from sqlalchemy import and_, select

    from app.db import database
    from app.db import province_settlement_judges as J

    row = await database.fetch_one(
        select(J.c.home_city).where(and_(J.c.province == province, J.c.judge_id == _s(judge_id)))
    )
    return _s(row["home_city"]) if row else ""


async def backfill_from_register(province: str) -> int:
    """
    Raz na okręg: zamrożenie meczów z dokumentów wydanych, zanim istniała blokada.

    Rejestr pamięta sędziów i okres każdego dokumentu (nie mecze), więc bierzemy
    obsady sędziego z okresu dokumentu - najstarszy dokument pierwszy (pierwszy
    wygrywa, tak jak przy wydaniu). Zamraża stan, który jest teraz w bazie: mecz
    już przeliczony na nowe miasto zostaje z nowym (tego nie da się odtworzyć),
    ale od tej chwili nic go już nie zmieni.
    """
    import json

    from sqlalchemy import and_, select, update

    from app.db import database
    from app.db import province_settlement_matches as M
    from app.db import province_settlement_register as T

    docs = await database.fetch_all(
        select(T.c.number, T.c.date_from, T.c.date_to, T.c.include_future, T.c.items_json, T.c.created_at)
        .where(T.c.province == province)
        .order_by(T.c.created_at.asc(), T.c.id.asc())
    )
    locked = 0
    for doc in docs:
        window = register_window(doc["date_from"], doc["date_to"], doc["created_at"], bool(doc["include_future"]))
        if window is None:
            continue
        try:
            items = json.loads(doc["items_json"] or "[]")
        except (TypeError, ValueError):
            continue
        judges = sorted({_s(item.get("judge_id")) for item in items if isinstance(item, dict)} - {""})
        if not judges:
            continue
        stamp = doc["created_at"] or datetime.now(_PL)
        await database.execute(
            update(M)
            .where(
                and_(
                    M.c.province == province,
                    M.c.judge_id.in_(judges),
                    M.c.match_at >= window[0],
                    M.c.match_at < window[1],
                    M.c.home_locked_at.is_(None),
                )
            )
            .values(home_locked_doc=_s(doc["number"]), home_locked_at=stamp)
        )
        locked += len(judges)
    return locked
