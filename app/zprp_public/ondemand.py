"""Pobieranie szczegółów meczu na żądanie + czysta logika priorytetów/świeżości.

Funkcje czyste (``is_finished``, ``needs_details``, ``backfill_sort_key``,
``NegativeCache``) nie dotykają bazy ani sieci - są testowane osobno.
"""
from __future__ import annotations

from app.zprp_details import details_path

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.time_pl import has_kickoff_time, warsaw_to_utc

log = logging.getLogger(__name__)

RECENT_WINDOW = timedelta(days=3)
STALE_AFTER = timedelta(hours=6)
BACKFILL_RECENT = timedelta(days=14)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _match_aware(value: datetime | None) -> datetime | None:
    """Termin meczu (naiwny = czas WARSZAWSKI, nie UTC) → aware UTC."""
    return warsaw_to_utc(value) if isinstance(value, datetime) else None


def match_moment(played_at: datetime | None, scheduled_at: datetime | None) -> datetime | None:
    return _match_aware(played_at) or _match_aware(scheduled_at)


def is_finished(score_home: Any, played_at: datetime | None, scheduled_at: datetime | None, now: datetime) -> bool:
    """Mecz rozegrany: ma wynik albo datę rozegrania w przeszłości.

    Termin bez godziny (00:00 = do ustalenia) mija dopiero z końcem swojej doby.
    """
    if score_home is not None:
        return True
    played = _match_aware(played_at)
    if played is not None and not has_kickoff_time(played_at):
        played = _match_aware(played_at + timedelta(days=1))
    return played is not None and played <= now


def needs_details(
    details_fetched_at: datetime | None,
    finished: bool,
    moment: datetime | None,
    now: datetime,
    *,
    complete: bool = True,
    proel_done_at: datetime | None = None,
    proel_linked: bool = False,
    timed: bool = True,
) -> bool:
    """Czy pobrać szczegóły meczu teraz.

    Bez dodatkowych argumentów - dawna reguła (świeże 6 h przez 3 dni od meczu).
    Mecz „gorący" (do 6 h od rozpoczęcia albo od końca w ProElu) z niepełnym
    protokołem ZPRP odświeżamy co kilka minut - patrz `details_stale_after`.
    """
    if not finished and not _recent(proel_done_at, now):
        return False
    fetched = _aware(details_fetched_at)
    if fetched is None:
        return True
    stale_after = details_stale_after(moment, now, complete=complete, proel_done_at=proel_done_at,
                                      proel_linked=proel_linked, timed=timed)
    if stale_after is not None:
        return now - fetched > stale_after
    return False


# --- Kadencja „do skutku": mecz po końcowej syrenie, protokół ZPRP niepełny ---
#
# Sekretarz wysyła do ZPRP wynik i statystyki dopiero po meczu, pojedynczo.
# Szczegóły pobrane w trakcie (albo w połowie wysyłki) dawały częściowy skład,
# który przy 6-godzinnej świeżości wisiał na portalu do nocy. Teraz taki mecz
# pobieramy ponownie co HOT_STALE_AFTER (ProEl już zakończył mecz - wysyłka
# do ZPRP tuż-tuż) albo co HOT_STALE_PLAIN (mecz w toku, bez ProEla - mniej
# pewne, że ZPRP w ogóle dostanie skład), aż protokół będzie kompletny albo
# minie HOT_WINDOW. Te same reguły stosuje cykl LIVE (`sync._sync_hot_details`).
HOT_WINDOW = timedelta(hours=6)
HOT_STALE_AFTER = timedelta(minutes=max(2, int(os.getenv("ZPRP_PUBLIC_HOT_STALE_MIN", "5"))))
HOT_STALE_PLAIN = timedelta(minutes=max(5, int(os.getenv("ZPRP_PUBLIC_HOT_STALE_PLAIN_MIN", "15"))))
#: Mecz bez godziny (00:00) jest „gorący" przez całą swoją dobę i jeszcze HOT_WINDOW.
_UNTIMED_SPAN = timedelta(days=1)


def _recent(at: datetime | None, now: datetime) -> bool:
    at = _aware(at)
    return at is not None and timedelta(0) <= now - at <= HOT_WINDOW


def in_hot_window(moment: datetime | None, now: datetime, proel_done_at: datetime | None = None, timed: bool = True) -> bool:
    """Mecz rozpoczął się nie dawniej niż HOT_WINDOW temu albo ProEl zakończył go w tym oknie."""
    if _recent(proel_done_at, now):
        return True
    moment = _aware(moment)
    if moment is None:
        return False
    span = HOT_WINDOW if timed else HOT_WINDOW + _UNTIMED_SPAN
    return timedelta(0) <= now - moment <= span


def lineups_complete(
    home_players: int,
    away_players: int,
    score_home: Any,
    score_away: Any,
    home_goals: int | None = None,
    away_goals: int | None = None,
) -> bool:
    """Protokół ZPRP kompletny: obie strony mają zawodników i jest wynik.

    Bramki zawodników (gdy podane i niezerowe) muszą dać wynik strony - suma
    mniejsza od wyniku to wysyłka w połowie (sekretarz wysyła po jednym).
    """
    if int(home_players or 0) <= 0 or int(away_players or 0) <= 0:
        return False
    if score_home is None or score_away is None:
        return False
    for goals, score in ((home_goals, score_home), (away_goals, score_away)):
        if goals and int(goals) != int(score):
            return False
    return True


def details_stale_after(
    moment: datetime | None,
    now: datetime,
    *,
    complete: bool = True,
    proel_done_at: datetime | None = None,
    proel_linked: bool = False,
    timed: bool = True,
) -> timedelta | None:
    """Po jakim czasie szczegóły są nieaktualne; None = nie odświeżamy (stary mecz)."""
    if not complete and in_hot_window(moment, now, proel_done_at, timed):
        # Koniec w ProElu = wysyłka do ZPRP tuż-tuż. Mecz w toku (także prowadzony w ProElu) - rzadziej.
        if proel_done_at is not None:
            return HOT_STALE_AFTER
        # Bez godziny (00:00) okno trwa całą dobę - rzadziej, póki ProEl nie powie „koniec".
        return HOT_STALE_PLAIN if timed else HOT_STALE_PLAIN * 2
    moment = _aware(moment)
    if moment is not None and now - moment <= RECENT_WINDOW:
        return STALE_AFTER
    return None


def backfill_sort_key(
    played_at: datetime | None,
    scheduled_at: datetime | None,
    score_home: Any,
    now: datetime,
) -> tuple[int, int, float]:
    """Klucz rosnący: rozegrane z ostatnich 14 dni, potem starsze rozegrane (od najnowszych), potem reszta."""
    moment = match_moment(played_at, scheduled_at)
    ts = (moment or _EPOCH).timestamp()
    if score_home is None:
        return (2, 0, -ts)
    recent = moment is not None and now - moment <= BACKFILL_RECENT
    return (0 if recent else 1, 0, -ts)


class NegativeCache:
    """Krótkotrwała pamięć nieudanych prób (nie młotkujemy upstreamu)."""

    def __init__(self, ttl: float = 120.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self._clock = clock
        self._until: dict[str, float] = {}

    def block(self, key: str) -> None:
        self._until[key] = self._clock() + self.ttl
        if len(self._until) > 2000:
            self.purge()

    def blocked(self, key: str) -> bool:
        until = self._until.get(key)
        if until is None:
            return False
        if self._clock() >= until:
            self._until.pop(key, None)
            return False
        return True

    def purge(self) -> None:
        now = self._clock()
        for key in [k for k, v in self._until.items() if v <= now]:
            self._until.pop(key, None)


_negative = NegativeCache(ttl=float(os.getenv("ZPRP_PUBLIC_ONDEMAND_NEG_TTL", "120")))
_locks: dict[str, asyncio.Lock] = {}
_slots = asyncio.Semaphore(max(1, int(os.getenv("ZPRP_PUBLIC_ONDEMAND_CONCURRENCY", "3"))))
_client: Any = None


def _get_client() -> Any:
    global _client
    if _client is None:
        from app.zprp_public.client import PublicZprpClient

        _client = PublicZprpClient()
    return _client


async def freshness_inputs(match_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Dla kadencji: zawodnicy i bramki na stronę (ZPRP) oraz koniec meczu w ProElu.

    -> {match_id: {"players": {side: n}, "goals": {side: n}, "proel_done_at", "proel_linked"}}.
    Dwa lekkie zapytania po kluczach z indeksem; błąd = puste dane (dawna reguła).
    """
    out: dict[str, dict[str, Any]] = {
        str(m): {"players": {}, "goals": {}, "proel_done_at": None, "proel_linked": False} for m in match_ids if m
    }
    if not out:
        return out
    try:
        from sqlalchemy import func, select

        from app.db import database, zprp_public_match_players as MP

        ids = list(out)
        rows = await database.fetch_all(
            select(MP.c.match_id, MP.c.side, func.count().label("n"), func.coalesce(func.sum(MP.c.goals), 0).label("g"))
            .where(MP.c.match_id.in_(ids)).group_by(MP.c.match_id, MP.c.side)
        )
        for r in rows:
            item = out.get(str(r["match_id"]))
            if item is not None:
                item["players"][r["side"]] = int(r["n"] or 0)
                item["goals"][r["side"]] = int(r["g"] or 0)
        try:
            from app.db import saved_matches as T

            proel = await database.fetch_all(
                select(T.c.zprp_match_id, T.c.status, T.c.updated_at).where(T.c.zprp_match_id.in_(ids))
            )
            for r in proel:
                item = out.get(str(r["zprp_match_id"]))
                if item is None:
                    continue
                item["proel_linked"] = True
                if r["status"] in ("finished", "approved"):
                    at = _aware(r["updated_at"])
                    if at is not None and (item["proel_done_at"] is None or at > item["proel_done_at"]):
                        item["proel_done_at"] = at
        except Exception:  # protokół ProEl to tylko przyspieszenie kadencji
            log.debug("[zprp_public] kadencja: odczyt ProEl", exc_info=True)
    except Exception:
        log.debug("[zprp_public] kadencja: odczyt składów", exc_info=True)
    return out


def cadence_for(match: Any, info: dict[str, Any] | None, now: datetime) -> dict[str, Any]:
    """Argumenty `needs_details` dla wiersza meczu (czysta funkcja nad tym, co zwraca `freshness_inputs`)."""
    info = info or {}
    players, goals = info.get("players") or {}, info.get("goals") or {}
    local = match["played_at"] or match["scheduled_at"]
    return {
        "complete": lineups_complete(players.get("home", 0), players.get("away", 0), match["score_home"], match["score_away"],
                                     goals.get("home"), goals.get("away")),
        "proel_done_at": info.get("proel_done_at"),
        "proel_linked": bool(info.get("proel_linked")),
        "timed": has_kickoff_time(local) if isinstance(local, datetime) else True,
    }


def lineups_hot(match: Any, info: dict[str, Any] | None, now: datetime) -> bool:
    """Czy portal ma jeszcze czekać na protokół (front odświeża stronę co minutę)."""
    cad = cadence_for(match, info, now)
    moment = match_moment(match["played_at"], match["scheduled_at"])
    return not cad["complete"] and in_hot_window(moment, now, cad["proel_done_at"], cad["timed"])


async def ensure_details(match: Any, info: dict[str, Any] | None = None) -> bool:
    """Zwraca True, gdy szczegóły są w toku/nieaktualne i nie udało się ich pobrać (``details_pending``).

    `info` (z `freshness_inputs`) włącza kadencję „do skutku" dla świeżo
    zakończonych meczów z niepełnym protokołem.
    """
    now = datetime.now(timezone.utc)
    moment = match_moment(match["played_at"], match["scheduled_at"])
    finished = is_finished(match["score_home"], match["played_at"], match["scheduled_at"], now)
    cad = cadence_for(match, info, now) if info is not None else {}
    if cad and not finished and match["score_home"] is None:
        # termin minął (bez daty rozegrania) - w gorącym oknie też pytamy ZPRP
        finished = in_hot_window(moment, now, None, cad.get("timed", True)) and moment is not None and moment <= now
    if not needs_details(match["details_fetched_at"], finished, moment, now, **cad):
        return False
    match_id = str(match["match_id"])
    if _negative.blocked(match_id):
        return True
    lock = _locks.setdefault(match_id, asyncio.Lock())
    if lock.locked():
        # ktoś już pobiera - poczekaj chwilę na jego wynik
        try:
            await asyncio.wait_for(lock.acquire(), timeout=4)
            lock.release()
            return False
        except asyncio.TimeoutError:
            return True
    if _slots.locked():
        return True
    try:
        async with lock:
            async with _slots:
                from app.zprp_public.sync import Counters, _sync_match_details

                counters = Counters()
                await asyncio.wait_for(
                    _sync_match_details(_get_client(), match_id, counters),
                    timeout=float(os.getenv("ZPRP_PUBLIC_ONDEMAND_TIMEOUT", "4")),
                )
            if not counters.get("match_details"):
                _negative.block(match_id)
                return True
            return False
    except Exception as exc:  # timeout, błąd upstreamu, błąd bazy
        _negative.block(match_id)
        log.warning("[zprp_public] on-demand %s: %r", match_id, exc)
        return True
    finally:
        if not lock.locked():
            _locks.pop(match_id, None)


# --- Odświeżenie szczegółów po sygnale z ProEla (koniec meczu, wysyłka do ZPRP) ---
#
# Koniec meczu w ProElu, wynik skrócony i statystyki wysłane do ZPRP to znak, że
# publiczny protokół właśnie się zmienia. Zamiast czekać na cykl synchronizacji
# pobieramy szczegóły tego meczu w tle, po krótkiej zwłoce (ZPRP potrzebuje
# chwili). Jedno zadanie na mecz: kolejne sygnały przesuwają termin (statystyki
# lecą po jednym zawodniku - pobieramy po ostatnim), ale nie dalej niż
# KICK_MAX_DEFER od pierwszego sygnału. Limit równoległości wspólny z wejściami
# na stronę (`_slots`), osobna pamięć porażek nie jest potrzebna - błąd to log.
KICK_MAX_DEFER = 120.0
KICK_TIMEOUT = float(os.getenv("ZPRP_PUBLIC_KICK_TIMEOUT", "20"))
_kick_due: dict[str, tuple[float, float]] = {}   # match_id -> (pierwszy sygnał, termin)
_kick_tasks: dict[str, "asyncio.Task[None]"] = {}


def next_due(current: tuple[float, float] | None, now: float, delay: float, debounce: bool) -> tuple[float, float]:
    """Termin pobrania po kolejnym sygnale: (pierwszy sygnał, termin).

    Bez `debounce` wygrywa wcześniejszy termin (pilny sygnał przyspiesza),
    z `debounce` - późniejszy, ale najwyżej KICK_MAX_DEFER od pierwszego sygnału.
    """
    want = now + max(0.0, delay)
    if current is None:
        return (now, want)
    first, due = current
    if debounce:
        return (first, min(max(due, want), first + KICK_MAX_DEFER))
    return (first, min(due, want))


async def fetch_details_now(match_id: str, timeout: float = KICK_TIMEOUT) -> bool:
    """Pobiera szczegóły meczu teraz (czeka na wolne miejsce). True = zapisane."""
    match_id = str(match_id)
    lock = _locks.setdefault(match_id, asyncio.Lock())
    try:
        async with lock:
            async with _slots:
                from app.zprp_public.sync import Counters, _sync_match_details

                counters = Counters()
                await asyncio.wait_for(_sync_match_details(_get_client(), match_id, counters), timeout=timeout)
            return bool(counters.get("match_details"))
    except Exception as exc:
        log.warning("[zprp_public] odświeżenie po ProElu %s: %r", match_id, exc)
        return False
    finally:
        if not lock.locked():
            _locks.pop(match_id, None)


async def _kick_runner(match_id: str) -> None:
    loop = asyncio.get_running_loop()
    try:
        # Sygnał w trakcie pobierania zostawia nowy termin - pętla zrobi kolejne pobranie.
        while True:
            slot = _kick_due.get(match_id)
            if slot is None:
                return
            wait = slot[1] - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
                continue
            _kick_due.pop(match_id, None)
            await fetch_details_now(match_id)
    finally:
        if _kick_tasks.get(match_id) is asyncio.current_task():
            _kick_tasks.pop(match_id, None)


def kick_on_status(match_id: Any, previous: str | None, final: str | None) -> bool:
    """ProEl zmienił status meczu: koniec (albo zatwierdzenie) = pobierz szczegóły ZPRP za chwilę.

    Sekretarz zwykle wysyła wynik i składy tuż po syrenie; cykl „do skutku"
    (`_sync_hot_details`) dokończy, jeśli wysyłka potrwa dłużej.
    """
    if final not in ("finished", "approved") or previous == final:
        return False
    return kick_details_refresh(match_id, delay=30.0)


def _kicks_enabled() -> bool:
    """Wyłączone razem z synchronizacją; w testach domyślnie wyłączone (bez sieci w tle)."""
    on = {"1", "true", "yes", "on"}
    if os.getenv("ZPRP_PUBLIC_SYNC_ENABLED", "1").strip().lower() not in on:
        return False
    default = "0" if os.getenv("ENVIRONMENT", "").strip().lower() == "test" else "1"
    return os.getenv("ZPRP_PUBLIC_KICK_ENABLED", default).strip().lower() in on


def kick_details_refresh(match_id: Any, delay: float = 20.0, debounce: bool = False) -> bool:
    """Zaplanuj pobranie szczegółów meczu ZPRP w tle. Nigdy nie rzuca; False = nie zaplanowano."""
    try:
        mid = str(match_id or "").strip()
        if not mid or mid in {"0", "None"} or not _kicks_enabled():
            return False
        loop = asyncio.get_running_loop()
        _kick_due[mid] = next_due(_kick_due.get(mid), loop.time(), delay, debounce)
        task = _kick_tasks.get(mid)
        if task is None or task.done():
            _kick_tasks[mid] = loop.create_task(_kick_runner(mid))
        return True
    except Exception:
        log.debug("[zprp_public] kick_details_refresh %r", match_id, exc_info=True)
        return False


# --- Odświeżenie meczu na żądanie (wejście na stronę meczu / profil sędziego) ---
REFRESH_MIN_INTERVAL = float(os.getenv("ZPRP_PUBLIC_REFRESH_INTERVAL", "120"))
_refreshed_at: dict[str, float] = {}
_refresh_locks: dict[str, asyncio.Lock] = {}
_OFFICIAL_COLS = ("referee_1_id", "referee_1_name", "referee_2_id", "referee_2_name", "scheduled_at",
                  "venue_name", "venue_city", "score_home", "score_away", "home_team_id", "away_team_id",
                  "home_club_id", "away_club_id", "home_team_name", "away_team_name")


async def _refresh_header(match_id: str, existing: Any) -> bool:
    """Lekkie odświeżenie: tylko nagłówek meczu (obsada, termin, hala, wynik, drużyny).
    Bez składów, migawek i gzip - żadnej ciężkiej pracy na pętli zdarzeń."""
    from app.zprp_public.client import rows
    from app.zprp_public.store import now_utc, upsert_values
    from app.zprp_public.sync import _match_values
    from app.db import zprp_public_matches as M

    payload = await _get_client().get(await details_path(match_id))
    header: dict[str, Any] = {}
    if isinstance(payload, dict):
        zero = payload.get("0")
        header = zero[0] if isinstance(zero, list) and zero and isinstance(zero[0], dict) else (zero if isinstance(zero, dict) else {})
    elif isinstance(payload, list) and payload:  # goła tablica [[{...}]]
        bucket = payload[0]
        header = bucket[0] if isinstance(bucket, list) and bucket and isinstance(bucket[0], dict) else {}
    if not header:
        return False
    keep = {c: existing[c] for c in ("season_id", "competition_id", "competition_name", "round_id", "round_name",
                                      "matchday_id", "matchday_name")}
    values = _match_values(header, **keep)
    values["details_fetched_at"] = now_utc()
    # Nie ruszamy source_hash/source_json: pełny zapis zrobi synchronizacja.
    await upsert_values(M, values, key_columns=("match_id",))
    return True


async def refresh_match(match_id: str, force: bool = False) -> dict[str, Any]:
    """Pobiera mecz z ZPRP (nie częściej niż co REFRESH_MIN_INTERVAL). Nigdy nie rzuca:
    błąd/timeout = stan z bazy. Zwraca {refreshed, changed, throttled, error}."""
    from sqlalchemy import select
    from app.db import database, zprp_public_matches as M

    match_id = str(match_id)
    now = time.monotonic()
    last = _refreshed_at.get(match_id)
    if not force and last is not None and now - last < REFRESH_MIN_INTERVAL:
        return {"refreshed": False, "changed": False, "throttled": True}
    lock = _refresh_locks.setdefault(match_id, asyncio.Lock())
    if lock.locked():
        # drugie wejście czeka na to samo pobranie zamiast robić własne
        try:
            await asyncio.wait_for(lock.acquire(), timeout=10)
            lock.release()
        except asyncio.TimeoutError:
            pass
        return {"refreshed": False, "changed": False, "throttled": True}
    try:
        async with lock:
            before = await database.fetch_one(select(M).where(M.c.match_id == match_id))
            if not before:
                return {"refreshed": False, "changed": False, "throttled": False}
            async with _slots:
                ok = await asyncio.wait_for(
                    _refresh_header(match_id, before),
                    timeout=float(os.getenv("ZPRP_PUBLIC_REFRESH_TIMEOUT", "8")),
                )
            if not ok:
                _refreshed_at[match_id] = time.monotonic() - REFRESH_MIN_INTERVAL + 20  # krótka blokada po pustej odpowiedzi
                return {"refreshed": False, "changed": False, "throttled": False, "empty": True}
            _refreshed_at[match_id] = time.monotonic()
            if len(_refreshed_at) > 5000:
                cutoff = time.monotonic() - REFRESH_MIN_INTERVAL
                for k in [k for k, v in _refreshed_at.items() if v < cutoff]:
                    _refreshed_at.pop(k, None)
            after = await database.fetch_one(select(M).where(M.c.match_id == match_id))
            changed = bool(after) and any(before[c] != after[c] for c in _OFFICIAL_COLS)
            if changed:
                try:
                    from app.zprp_public import portal

                    portal.invalidate_caches()
                except Exception:  # pragma: no cover
                    log.exception("[zprp_public] invalidate_caches")
            return {"refreshed": True, "changed": changed, "throttled": False}
    except Exception as exc:
        _refreshed_at[match_id] = time.monotonic() - REFRESH_MIN_INTERVAL + 20
        log.warning("[zprp_public] refresh %s: %r", match_id, exc)
        return {"refreshed": False, "changed": False, "throttled": False, "error": True}
    finally:
        if not lock.locked():
            _refresh_locks.pop(match_id, None)
