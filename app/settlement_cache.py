"""
Pamięć policzonych rozliczeń - żeby zakładka Rozliczenia chodziła od ręki.

MODUŁ-LIŚĆ: bez bazy i bez sieci (`app.db` łączy się z bazą przy imporcie).
Bazę dostaje z zewnątrz tylko `install_write_hook`, i to jako gotowy obiekt.

SKĄD TO SIĘ WZIĘŁO. Każde kliknięcie w panelu (podgląd sędziego, przełączenie
miesiąca, karta klubu) liczyło od zera CAŁY okręg: wszystkie obsady z historii,
tabele stawek, nazwiska, zakres klubów. Lista klubów i karta klubu to były dwa
pełne przeliczenia sezonu na jedno kliknięcie (zgłoszenie z 24.09.2026: „ma
chodzić milion razy płynniej"). Serwer trzyma teraz WYNIK i oddaje go od ręki,
dopóki nic się nie zmieniło.

JAK SIĘ UNIEWAŻNIA. Każdy okręg ma licznik wersji. Wpis w pamięci pamięta, przy
której wersji powstał; gdy licznik pójdzie w górę, wpis jest martwy i następne
pytanie liczy od nowa. Licznik podbijają:

  * jawne `bump(province)` w miejscach zapisu (wpłaty, ustawienia klubów,
    wyjątki na meczach, ręczne mecze, faktury, budżety, rozliczenie sezonu,
    koniec pobierania z ZPRP),
  * haczyk na zapisach do bazy (`install_write_hook`) - łapie KAŻDY INSERT,
    UPDATE i DELETE na tabelach, z których liczą się rozliczenia, także z modułów,
    które o tej pamięci nic nie wiedzą (tabele stawek w panelu admina,
    deklaracje stolikowych w Obsadzie). Zapis w transakcji widać w bazie dopiero
    po jej zamknięciu, więc haczyk podbija licznik drugi raz chwilę później -
    wynik policzony w międzyczasie z danych sprzed zatwierdzenia nie zostaje,
  * siatka bezpieczeństwa: wpis starszy niż `TTL_SECONDS` liczy się od nowa
    (terminarz okręgu, nazwiska z API ZPRP, „mecz już się odbył").

Pamięć jest w procesie (serwer chodzi w jednym procesie uvicorna). Po zapisie
w TYM procesie nieaktualny wynik nie wyjdzie już ani razu.
"""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import re
import time
from collections import OrderedDict
from decimal import Decimal
from typing import Any, Awaitable, Callable, Hashable, Iterable, Optional

logger = logging.getLogger(__name__)

#: Siatka bezpieczeństwa dla zmian, których nie widać w licznikach.
TTL_SECONDS = 600.0
#: Ile wyników trzymamy naraz (miesiące x przełączniki x sezony x okręgi).
MAX_ENTRIES = 160
#: Po tylu sekundach od zapisu haczyk podbija licznik drugi raz (transakcje).
LATE_BUMPS = (0.4, 2.5)
#: Odpowiedź krótsza niż tyle bajtów idzie bez kompresji.
GZIP_FROM = 1400

#: Tabele, z których liczą się rozliczenia sędziów i panel klubów. Zapis do
#: którejkolwiek unieważnia policzone wyniki okręgu (albo wszystkich okręgów,
#: gdy z zapytania nie da się wyczytać województwa - np. tabela stawek ZPRP).
#:
#: ⚠ Świadomie BEZ `province_matches` i `zprp_judges_seen`: monitor meczów pisze
#: do nich co kilka minut (`last_seen_at`), a zmieniają tylko gospodarza meczu
#: i nazwisko z API - to łapie siatka bezpieczeństwa TTL.
WATCHED_TABLES = frozenset(
    {
        "province_settlement_matches",
        "province_settlement_judges",
        "province_judges",
        "central_rates",
        "okreg_rates",
        "province_match_overrides",
        "province_manual_charges",
        "province_club_entries",
        "province_clubs",
        "province_club_assignment",
        "province_club_teams",
        "province_competitions",
        "province_club_seasons",
        "province_club_season_closures",
        "province_club_budgets",
        "province_modules",
    }
)

#: Tabele FAKTÓW okręgu (obsady, stawki, nazwiska, ręczne mecze, x3) - z nich
#: liczy się wspólna baza (`province_settlements._base`). Wpłata, ustawienie
#: klubu czy budżet jej nie ruszają, więc po takim zapisie przeliczamy sezon
#: na gotowych faktach, zamiast czytać całą historię z bazy od nowa.
BASE_TABLES = frozenset(
    {
        "province_settlement_matches",
        "province_settlement_judges",
        "province_judges",
        "central_rates",
        "okreg_rates",
        "province_match_overrides",
        "province_manual_charges",
    }
)
#: Rodzaje wyników, które zależą TYLKO od tabel faktów.
BASE_KINDS = frozenset({"base"})

_ALL = "*"
#: (okręg, zakres) -> licznik; zakres "all" = każdy zapis, "base" = tylko fakty.
_versions: dict[tuple[str, str], int] = {}
_store: "OrderedDict[tuple, _Entry]" = OrderedDict()
_inflight: dict[tuple, "asyncio.Future[Any]"] = {}
_stats = {"hits": 0, "misses": 0, "bumps": 0}


class _Entry:
    __slots__ = ("value", "version", "stored_at")

    def __init__(self, value: Any, version: tuple[int, int], stored_at: float) -> None:
        self.value = value
        self.version = version
        self.stored_at = stored_at


def _key_of(province: Any) -> str:
    """Klucz okręgu - ten sam co w tabelach („SLASKIE"), bez importu bazy."""
    text = str(province or "").strip()
    if not text or text == _ALL:
        return _ALL
    try:
        from app.settlement_province import canonical

        return canonical(text) or text.upper()
    except Exception:  # pragma: no cover - reguła pisowni nie może zatrzymać zapisu
        return text.upper()


def _scope(kind: str) -> str:
    return "base" if kind in BASE_KINDS else "all"


def version(province: Any, scope: str = "all") -> tuple[int, int]:
    """(licznik wszystkich okręgów, licznik tego okręgu) w danym zakresie."""
    return _versions.get((_ALL, scope), 0), _versions.get((_key_of(province), scope), 0)


def bump(province: Any = None, *, base: bool = True, reason: str = "") -> None:
    """
    Unieważnia policzone wyniki okręgu (bez okręgu - wszystkich okręgów).

    `base=False` - zapis nie dotyczy faktów okręgu (np. wpłata klubu): wspólna
    baza zostaje, przeliczają się tylko wyniki z niej złożone.
    Nigdy nie rzuca: pamięć podręczna nie ma prawa zepsuć zapisu.
    """
    try:
        key = _key_of(province)
        scopes = ("all", "base") if base else ("all",)
        for scope in scopes:
            _versions[(key, scope)] = _versions.get((key, scope), 0) + 1
        _stats["bumps"] += 1
        if reason:
            logger.debug("[settlement_cache] %s: %s", key, reason)
    except Exception:  # pragma: no cover
        logger.exception("[settlement_cache] bump")


_late: dict[tuple[str, bool], list] = {}


def bump_later(province: Any = None, *, base: bool = True, reason: str = "") -> None:
    """
    Podbicie teraz i jeszcze raz po `LATE_BUMPS` - po zamknięciu transakcji.

    Seria zapisów (pobieranie z ZPRP pisze tysiące wierszy) nie mnoży zegarów:
    kolejny zapis przesuwa już ustawione późne podbicia tego okręgu.
    """
    bump(province, base=base, reason=reason)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    slot = (_key_of(province), bool(base))
    for handle in _late.pop(slot, []):
        handle.cancel()
    _late[slot] = [
        loop.call_later(delay, _late_bump, slot, index) for index, delay in enumerate(LATE_BUMPS)
    ]


def _late_bump(slot: tuple[str, bool], index: int) -> None:
    bump(slot[0], base=slot[1])
    if index == len(LATE_BUMPS) - 1:
        _late.pop(slot, None)


def clear() -> None:
    """Wszystko od nowa - dla testów."""
    _versions.clear()
    for handles in _late.values():
        for handle in handles:
            handle.cancel()
    _late.clear()
    _store.clear()
    _inflight.clear()
    for name in _stats:
        _stats[name] = 0


def stats() -> dict[str, int]:
    return {**_stats, "entries": len(_store), "inflight": len(_inflight)}


def _alive(entry: _Entry, current: tuple[int, int], now: float) -> bool:
    return entry.version == current and now - entry.stored_at < TTL_SECONDS


def peek(kind: str, province: Any, params: Hashable = ()) -> Any:
    """Wynik z pamięci, jeśli jest świeży - bez liczenia. Inaczej None."""
    key = (kind, _key_of(province), params)
    entry = _store.get(key)
    if entry is None or not _alive(entry, version(province, _scope(kind)), time.monotonic()):
        return None
    _store.move_to_end(key)
    _stats["hits"] += 1
    return entry.value


async def remember(
    kind: str,
    province: Any,
    params: Hashable,
    compute: Callable[[], Awaitable[Any]],
) -> Any:
    """
    Wynik `compute()` z pamięci albo policzony teraz.

    Dwa pytania o to samo w tej samej chwili liczą RAZ - drugie czeka na wynik
    pierwszego. Gdy w trakcie liczenia ktoś coś zapisze, wynik trafia do pytającego,
    ale nie do pamięci pod nową wersją (został policzony ze starych danych).
    """
    current = version(province, _scope(kind))
    key = (kind, _key_of(province), params)
    now = time.monotonic()
    entry = _store.get(key)
    if entry is not None and _alive(entry, current, now):
        _store.move_to_end(key)
        _stats["hits"] += 1
        return entry.value

    flight_key = (key, current)
    pending = _inflight.get(flight_key)
    if pending is not None:
        _stats["hits"] += 1
        try:
            return await asyncio.shield(pending)
        except asyncio.CancelledError:
            task = asyncio.current_task()
            cancelling = getattr(task, "cancelling", lambda: 0)() if task else 0
            if pending.cancelled() and not cancelling:
                # Przerwano tamto pytanie, nie nasze - liczymy sami.
                return await remember(kind, province, params, compute)
            raise

    _stats["misses"] += 1
    loop = asyncio.get_running_loop()
    future: asyncio.Future[Any] = loop.create_future()
    _inflight[flight_key] = future
    try:
        value = await compute()
    except asyncio.CancelledError:
        if not future.done():
            future.cancel()
        raise
    except BaseException as exc:
        if not future.done():
            future.set_exception(exc)
            # Nikt inny nie czekał - wyjątek nie może zostać „niezauważony".
            future.exception()
        raise
    finally:
        _inflight.pop(flight_key, None)
    if not future.done():
        future.set_result(value)
    if version(province, _scope(kind)) == current:
        _store[key] = _Entry(value, current, now)
        _store.move_to_end(key)
        while len(_store) > MAX_ENTRIES:
            _store.popitem(last=False)
    return value


# ---------------------------------------------------------------------------
# Gotowe odpowiedzi HTTP: JSON policzony raz, ETag, gzip
# ---------------------------------------------------------------------------

class Packed:
    """Odpowiedź gotowa do wysłania: bajty JSON, ich gzip i ETag."""

    __slots__ = ("body", "zipped", "etag")

    def __init__(self, payload: Any) -> None:
        self.body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), default=_json_default
        ).encode("utf-8")
        self.zipped = gzip.compress(self.body, 5) if len(self.body) >= GZIP_FROM else None
        self.etag = '"' + hashlib.sha1(self.body).hexdigest()[:24] + '"'


def _json_default(value: Any) -> Any:
    # Kolumna NUMERIC przychodzi z bazy jako Decimal - kwota ma zostać liczbą.
    if isinstance(value, Decimal):
        return float(value)
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        return iso()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return str(value)


def etag_matches(header: Optional[str], etag: str) -> bool:
    """`If-None-Match` może nieść kilka znaczników, także słabych (W/)."""
    if not header:
        return False
    tags = [part.strip() for part in header.split(",")]
    return any(tag == "*" or tag.removeprefix("W/") == etag for tag in tags)


def accepts_gzip(header: Optional[str]) -> bool:
    return bool(header) and re.search(r"(^|[,\s])gzip(\s*;\s*q=(?!0(\.0*)?\b)[\d.]+)?\s*(,|$)", header or "") is not None


async def packed(
    kind: str,
    province: Any,
    params: Hashable,
    build: Callable[[], Awaitable[Any]],
) -> Packed:
    """Odpowiedź z pamięci (bajty już gotowe) albo zbudowana i spakowana teraz."""

    async def compute() -> Packed:
        return Packed(await build())

    return await remember("http:" + kind, province, params, compute)


def respond(request: Any, pack: Packed) -> Any:
    """
    Odpowiedź FastAPI z paczki: 304 przy zgodnym ETagu, gzip, gdy klient chce.

    `Cache-Control: no-cache` = przeglądarka trzyma kopię, ale za każdym razem
    pyta serwer z `If-None-Match`; niezmienione dane wracają jako puste 304.
    """
    from fastapi.responses import Response

    headers = {"ETag": pack.etag, "Cache-Control": "private, no-cache", "Vary": "Accept-Encoding"}
    request_headers = getattr(request, "headers", None) or {}
    if etag_matches(request_headers.get("if-none-match"), pack.etag):
        return Response(status_code=304, headers=headers)
    if pack.zipped is not None and accepts_gzip(request_headers.get("accept-encoding")):
        return Response(
            content=pack.zipped,
            media_type="application/json",
            headers={**headers, "Content-Encoding": "gzip"},
        )
    return Response(content=pack.body, media_type="application/json", headers=headers)


# ---------------------------------------------------------------------------
# Haczyk na zapisach do bazy
# ---------------------------------------------------------------------------

_DML = re.compile(r"^\s*(insert|update|delete|with)\b", re.I)
_TABLE_WORDS = re.compile(r"\b(" + "|".join(sorted(WATCHED_TABLES)) + r")\b")


def written_tables(query: Any) -> set[str]:
    """Obserwowane tabele, do których pisze zapytanie (puste = to nie zapis)."""
    if isinstance(query, str):
        if not _DML.match(query):
            return set()
        return set(_TABLE_WORDS.findall(query))
    if not getattr(query, "is_dml", False):
        return set()
    table = getattr(query, "table", None)
    name = getattr(table, "name", None)
    return {name} if name in WATCHED_TABLES else set()


def _provinces_in(values: Iterable[Any]) -> set[str]:
    out: set[str] = set()
    for value in values:
        if isinstance(value, (list, tuple, set, frozenset)):
            out |= _provinces_in(value)
        elif isinstance(value, str) and value.strip():
            out.add(_key_of(value))
    return out


def provinces_of(query: Any, values: Any = None) -> set[str]:
    """
    Okręgi, których dotyczy zapis - z parametrów o nazwie `province*`.

    Nie da się wyczytać (surowy SQL, tabela bez kolumny okręgu) = pusty zbiór,
    czyli „wszystkie okręgi" - lepiej przeliczyć za dużo niż pokazać stare.
    """
    found: set[str] = set()
    rows = values if isinstance(values, list) else [values] if isinstance(values, dict) else []
    for row in rows:
        if isinstance(row, dict):
            found |= _provinces_in(v for k, v in row.items() if str(k).startswith("province"))
    if found or isinstance(query, str):
        return found
    try:
        from sqlalchemy.dialects import postgresql

        params = query.compile(dialect=postgresql.dialect()).params
    except Exception:
        return set()
    return _provinces_in(v for k, v in params.items() if str(k).startswith("province"))


def note_write(query: Any, values: Any = None) -> None:
    """Zapis do obserwowanej tabeli podbija wersję jego okręgu. Nigdy nie rzuca."""
    try:
        tables = written_tables(query)
        if not tables:
            return
        provinces = provinces_of(query, values) or {_ALL}
        base = bool(tables & BASE_TABLES)
        reason = "zapis: " + ",".join(sorted(tables))
        for province in provinces:
            bump_later(province, base=base, reason=reason)
            if _open_transactions:
                _noted.append((province, base))
    except Exception:  # pragma: no cover
        logger.exception("[settlement_cache] note_write")


_HOOKED_ATTR = "_settlement_cache_hooked"
#: Otwarte transakcje i okręgi zapisane w ich trakcie - po zamknięciu transakcji
#: podbijamy je jeszcze raz (patrz `_Transaction`).
_open_transactions = 0
_noted: list[tuple[str, bool]] = []


class _Transaction:
    """
    Transakcja bazy z podbiciem wersji PO zatwierdzeniu.

    Pytanie, które przyszło w trakcie transakcji, policzyło się z danych sprzed
    niej i mogło trafić do pamięci pod wersją podbitą przy samym zapisie. Bez
    tego po zapisie grupowym panel przez chwilę dostawałby stare salda.
    """

    __slots__ = ("_inner", "_mark")

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._mark = 0

    async def __aenter__(self) -> Any:
        global _open_transactions
        result = await self._inner.__aenter__()
        _open_transactions += 1
        self._mark = len(_noted)
        return result

    async def __aexit__(self, *exc: Any) -> Any:
        global _open_transactions
        try:
            return await self._inner.__aexit__(*exc)
        finally:
            touched = set(_noted[self._mark:])
            _open_transactions = max(0, _open_transactions - 1)
            if not _open_transactions:
                _noted.clear()
            for province, base in touched:
                bump(province, base=base, reason="koniec transakcji")

    def __call__(self, func: Any) -> Any:
        return self._inner(func)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def install_write_hook(database: Any) -> None:
    """
    Owija `execute`/`execute_many`/`fetch_one`/`fetch_val` bazy tak, żeby każdy
    zapis do obserwowanej tabeli unieważniał pamięć. Drugie wywołanie nic nie robi.
    """
    if database is None or getattr(database, _HOOKED_ATTR, False):
        return

    def wrap(name: str) -> None:
        original = getattr(database, name, None)
        if original is None:
            return

        async def hooked(query: Any, values: Any = None, *args: Any, **kwargs: Any) -> Any:
            result = await original(query, values, *args, **kwargs)
            note_write(query, values)
            return result

        hooked.__name__ = f"{name}_with_settlement_cache"
        setattr(database, name, hooked)

    for name in ("execute", "execute_many", "fetch_one", "fetch_val"):
        wrap(name)

    original_transaction = getattr(database, "transaction", None)
    if original_transaction is not None:

        def transaction(*args: Any, **kwargs: Any) -> Any:
            return _Transaction(original_transaction(*args, **kwargs))

        setattr(database, "transaction", transaction)
    setattr(database, _HOOKED_ATTR, True)
