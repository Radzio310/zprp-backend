"""Pobieranie WSZYSTKICH minionych sezonów ZPRP w tle (pełna historia dla BAZY pod Ręką).

Osobna, wolna pętla, niezależna od ``run_zprp_public_scheduler`` (nie bierze jego
blokady, ma własnego klienta z limitem ok. 1 zapytania na sekundę), więc nie
spowalnia bieżącej synchronizacji.

Kolejność: od najnowszego minionego sezonu wstecz. Sezon = trzy fazy:

1. ``tree``    - rozgrywki po kolei: rundy, kolejki, mecze, tabele, strzelcy,
2. ``rosters`` - składy zespołów, które wystąpiły w meczach sezonu,
3. ``details`` - szczegóły meczów (składy meczowe, zdarzenia, protokoły).

Wznawianie po restarcie: stan siedzi w ``zprp_public_sync_state`` (klucz
``history``), a każdy zapis do tabel to idempotentny upsert. Fazy 2 i 3 są
sterowane zapytaniem (``roster_fetched_at`` / ``details_fetched_at`` puste), więc
po restarcie same zaczynają od miejsca przerwania. Faza 1 pamięta listę
zakończonych rozgrywek.

Lista sezonów pochodzi z ``pokaz_sezony.php`` (ID_sezon jest nieliniowy, nie
zgadujemy kolejnych numerów). Miniony = ``Stan`` nieaktywny i rok rozpoczęcia
mniejszy niż sezonu aktywnego wg API.

Sterowanie: ``/admin/handball-sync/history/{start,stop,status}``. Automatyczny
start po wdrożeniu: ``ZPRP_HISTORY_AUTOSTART`` (1/0); gdy brak zmiennej, włączony
tylko gdy ``RAILWAY_ENVIRONMENT_NAME=production``. Ręczne ``stop`` zapamiętuje się
i wyłącza autostart aż do kolejnego ``start``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy import and_, func, select, update

from app.db import (
    database,
    zprp_public_matches,
    zprp_public_seasons,
    zprp_public_sync_state,
    zprp_public_teams,
)
from app.zprp_public.client import PublicZprpClient, int_value, rows, text_value
from app.zprp_public.store import now_utc, upsert_values
from app.zprp_public import sync as sync_mod

log = logging.getLogger(__name__)

STATE_KEY = "history"
LEASE_SECONDS = 180
MAX_ITEM_FAILURES = 3
_TRUE = {"1", "true", "yes", "on", "tak"}

# Wartości domyślne można zmienić zmiennymi środowiskowymi.
def _interval() -> float:
    return max(0.3, float(os.getenv("ZPRP_HISTORY_MIN_INTERVAL", "1.0")))


def autostart_enabled() -> bool:
    raw = os.getenv("ZPRP_HISTORY_AUTOSTART")
    if raw is not None and raw.strip() != "":
        return raw.strip().lower() in _TRUE
    return os.getenv("RAILWAY_ENVIRONMENT_NAME", "").strip().lower() == "production"


class HistoryStop(Exception):
    """Prośba o zatrzymanie albo utrata dzierżawy przez tę replikę."""


# --- stan ---------------------------------------------------------------------

def _empty_state() -> dict[str, Any]:
    return {"enabled": False, "user_stopped": False, "seasons": {}, "counters": {}, "lease": None}


async def load_state() -> dict[str, Any]:
    row = await database.fetch_one(
        select(zprp_public_sync_state.c.value_json).where(zprp_public_sync_state.c.key == STATE_KEY)
    )
    value = row["value_json"] if row else None
    if isinstance(value, str):
        import json

        value = json.loads(value)
    state = _empty_state()
    if isinstance(value, dict):
        state.update(value)
    return state


async def save_state(state: dict[str, Any]) -> None:
    await upsert_values(
        zprp_public_sync_state,
        {"key": STATE_KEY, "value_json": state, "updated_at": now_utc()},
        key_columns=("key",),
    )


async def patch_control(**fields: Any) -> dict[str, Any]:
    """Zmienia tylko pola sterujące, nie ruszając postępu zapisywanego przez pętlę."""
    state = await load_state()
    state.update(fields)
    await save_state(state)
    return state


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def lease_fresh(state: dict[str, Any], me: str | None = None) -> bool:
    lease = state.get("lease") or {}
    if me and lease.get("id") == me:
        return False
    at = _parse_dt(lease.get("at"))
    return bool(at and now_utc() - at < timedelta(seconds=LEASE_SECONDS))


class Runner:
    """Jedna instancja pracy: zapis postępu + sprawdzanie stopu i dzierżawy."""

    def __init__(self) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.state: dict[str, Any] = _empty_state()
        self._last_save = 0.0
        self.client: PublicZprpClient | None = None

    async def checkpoint(self, *, force: bool = False) -> None:
        """Zapisuje postęp (z dławieniem co ok. 5 s) i przerywa, gdy trzeba."""
        loop_time = asyncio.get_running_loop().time()
        if not force and loop_time - self._last_save < 5:
            return
        self._last_save = loop_time
        stored = await load_state()
        lease = stored.get("lease") or {}
        if lease.get("id") not in (None, self.id) and lease_fresh(stored, self.id):
            raise HistoryStop("lease-lost")
        if not stored.get("enabled"):
            raise HistoryStop("stopped")
        self.state["enabled"] = True
        self.state["user_stopped"] = False
        if self.client is not None:
            self.state.setdefault("counters", {})["requests_this_run"] = self.client.requests
        self.state["lease"] = {"id": self.id, "at": now_utc().isoformat()}
        await save_state(self.state)

    def season(self, season_id: str) -> dict[str, Any]:
        return self.state["seasons"].setdefault(season_id, {})

    def bump(self, key: str, amount: int = 1) -> None:
        counters = self.state.setdefault("counters", {})
        counters[key] = int(counters.get(key, 0)) + amount


# --- seasons ------------------------------------------------------------------

def past_seasons(upstream: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Minione sezony od najnowszego wstecz, wg listy z API."""
    valid = [item for item in upstream if item.get("ID_sezon")]
    valid.sort(key=lambda item: int_value(item.get("Rok_rozpoczecia"), 0) or 0, reverse=True)
    active = next((item for item in valid if sync_mod._truth(item.get("Stan"))), None)
    active_year = int_value(active.get("Rok_rozpoczecia"), 0) if active else None
    result = []
    for item in valid:
        year = int_value(item.get("Rok_rozpoczecia"), 0) or 0
        if sync_mod._truth(item.get("Stan")):
            continue
        if active_year is not None and year >= active_year:
            continue
        result.append(item)
    return result


async def _guarded(runner: Runner, label: str, action: Callable[[], Awaitable[Any]]) -> bool:
    """Wykonuje krok z ponowieniem i wydłużającą się przerwą; True gdy się udał."""
    for attempt in range(MAX_ITEM_FAILURES):
        try:
            await action()
            return True
        except HistoryStop:
            raise
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            runner.bump("errors")
            pause = 10 * (3**attempt)  # 10 s, 30 s, 90 s: wystarcza na 429 i krótką awarię
            runner.state["last_error"] = f"{label}: {exc}"[:300]
            log.warning("[zprp_history] %s (próba %s): %s", label, attempt + 1, exc)
            await runner.checkpoint(force=True)
            if attempt < MAX_ITEM_FAILURES - 1:
                await asyncio.sleep(pause)
    return False


# --- fazy ---------------------------------------------------------------------

async def _phase_tree(runner: Runner, client: PublicZprpClient, season_id: str) -> None:
    info = runner.season(season_id)
    payload = await client.get(f"pokaz_rozgrywki.php?Sezon={season_id}")
    competitions = [item for item in rows(payload) if item.get("Id_rozgrywki")]
    counters = sync_mod.Counters()
    for item in competitions:
        await sync_mod._store_competition(item, season_id, counters)
    info["competitions_total"] = len(competitions)
    done = set(info.get("competitions_done", []))
    failed = set(info.get("competitions_failed", []))
    for item in competitions:
        cid = text_value(item.get("Id_rozgrywki"))
        if cid in done or cid in failed:
            continue
        info["current"] = f"rozgrywki {cid}"
        await runner.checkpoint()
        local = sync_mod.Counters()

        async def work(item=item, local=local) -> None:
            await sync_mod._sync_competition_tree(client, item, local, include_stats=True)

        ok = await _guarded(runner, f"sezon {season_id} rozgrywki {cid}", work)
        if ok:
            done.add(cid)
            for key in ("matches", "standings", "scorers"):
                runner.bump(key, int(local.get(key, 0)))
        else:
            failed.add(cid)
        info["competitions_done"] = sorted(done)
        info["competitions_failed"] = sorted(failed)
        await runner.checkpoint(force=True)
    info["tree"] = "done"


async def _pending_rosters(season_id: str) -> list[str]:
    team_rows = await database.fetch_all(
        select(zprp_public_matches.c.home_team_id, zprp_public_matches.c.away_team_id).where(
            zprp_public_matches.c.season_id == season_id
        )
    )
    wanted: set[str] = set()
    for row in team_rows:
        for key in ("home_team_id", "away_team_id"):
            value = text_value(row[key])
            if value:
                wanted.add(value)
    fetched = await database.fetch_all(
        select(zprp_public_teams.c.team_id).where(
            and_(zprp_public_teams.c.season_id == season_id, zprp_public_teams.c.roster_fetched_at.is_not(None))
        )
    )
    have = {text_value(row["team_id"]) for row in fetched}
    return sorted(wanted - have)


async def _phase_rosters(runner: Runner, client: PublicZprpClient, season_id: str) -> None:
    info = runner.season(season_id)
    failed = set(info.get("rosters_failed", []))
    pending = [t for t in await _pending_rosters(season_id) if t not in failed]
    info["rosters_pending"] = len(pending)
    for index, team_id in enumerate(pending):
        info["current"] = f"skład {team_id}"
        await runner.checkpoint()

        async def work(team_id=team_id) -> None:
            local = sync_mod.Counters()
            await sync_mod._sync_roster(client, team_id, season_id, local)

        if await _guarded(runner, f"sezon {season_id} skład {team_id}", work):
            runner.bump("rosters")
        else:
            failed.add(team_id)
            info["rosters_failed"] = sorted(failed)
        info["rosters_pending"] = len(pending) - index - 1
    info["rosters"] = "done"
    await runner.checkpoint(force=True)


async def _pending_details(season_id: str, limit: int) -> list[str]:
    result = await database.fetch_all(
        select(zprp_public_matches.c.match_id)
        .where(
            and_(
                zprp_public_matches.c.season_id == season_id,
                zprp_public_matches.c.details_fetched_at.is_(None),
            )
        )
        .order_by(zprp_public_matches.c.match_id)
        .limit(limit)
    )
    return [text_value(row["match_id"]) for row in result]


async def _phase_details(runner: Runner, client: PublicZprpClient, season_id: str) -> None:
    info = runner.season(season_id)
    failed = set(info.get("details_failed", []))
    empty = 0
    while True:
        batch = [m for m in await _pending_details(season_id, 200 + len(failed)) if m not in failed]
        if not batch:
            break
        info["details_pending_batch"] = len(batch)
        for match_id in batch:
            info["current"] = f"mecz {match_id}"
            await runner.checkpoint()

            async def work(match_id=match_id) -> None:
                nonlocal empty
                local = sync_mod.Counters()
                result = await sync_mod._sync_match_details(client, match_id, local)
                if not result:
                    # Brak szczegółów u źródła (mecz odwołany, bez protokołu): zamykamy,
                    # żeby zapytanie nie wracało do niego w kółko.
                    empty += 1
                    await database.execute(
                        update(zprp_public_matches)
                        .where(zprp_public_matches.c.match_id == match_id)
                        .values(details_fetched_at=now_utc())
                    )

            if await _guarded(runner, f"sezon {season_id} mecz {match_id}", work):
                runner.bump("details")
            else:
                failed.add(match_id)
                info["details_failed"] = sorted(failed)
    info["details"] = "done"
    info["details_empty"] = int(info.get("details_empty", 0)) + empty
    await runner.checkpoint(force=True)


async def process_season(runner: Runner, client: PublicZprpClient, season_id: str) -> None:
    info = runner.season(season_id)
    info.setdefault("started_at", now_utc().isoformat())
    info["status"] = "running"
    if info.get("tree") != "done":
        await _phase_tree(runner, client, season_id)
    if info.get("rosters") != "done":
        await _phase_rosters(runner, client, season_id)
    if info.get("details") != "done":
        await _phase_details(runner, client, season_id)
    has_failures = any(info.get(k) for k in ("competitions_failed", "rosters_failed", "details_failed"))
    info["status"] = "done_with_errors" if has_failures else "done"
    info["finished_at"] = now_utc().isoformat()
    info.pop("current", None)
    await runner.checkpoint(force=True)


def is_complete(state: dict[str, Any], season_ids: list[str]) -> bool:
    seasons = state.get("seasons", {})
    return bool(season_ids) and all(seasons.get(s, {}).get("status") in {"done", "done_with_errors"} for s in season_ids)


async def run_history(runner: Runner | None = None, client: PublicZprpClient | None = None) -> dict[str, Any]:
    """Jedno przejście po wszystkich minionych sezonach. Zwraca stan końcowy."""
    runner = runner or Runner()
    own_client = client is None
    client = client or PublicZprpClient(min_interval=_interval(), concurrency=1, retries=3)
    runner.client = client
    try:
        stored = await load_state()
        runner.state = stored
        runner.state["enabled"] = True
        runner.state["user_stopped"] = False
        runner.state["run_started_at"] = now_utc().isoformat()
        runner.state.pop("last_error", None)
        await runner.checkpoint(force=True)

        upstream = rows(await client.get("pokaz_sezony.php"))
        # Zapisujemy listę sezonów (także bieżącej synchronizacji), bo portal pokazuje ją w pigułce.
        for item in upstream:
            if not text_value(item.get("ID_sezon")):
                continue
            await sync_mod.store_entity(
                zprp_public_seasons,
                {
                    "season_id": text_value(item.get("ID_sezon")),
                    "start_year": int_value(item.get("Rok_rozpoczecia")),
                    "name": text_value(item.get("Nazwa")),
                    "active": sync_mod._truth(item.get("Stan")),
                    "competition_count": int_value(item.get("IleRozgrywek"), 0) or 0,
                },
                key_columns=("season_id",),
                resource_type="season",
                resource_key=text_value(item.get("ID_sezon")),
                source=item,
                keep_snapshot=False,
            )
        seasons = past_seasons(upstream)
        ids = [text_value(item.get("ID_sezon")) for item in seasons]
        runner.state["season_order"] = ids
        runner.state["season_names"] = {text_value(i.get("ID_sezon")): text_value(i.get("Nazwa")) for i in seasons}
        if runner.state.pop("retry_failed", False):
            for sid in ids:
                if runner.season(sid).get("status") == "done_with_errors":
                    runner.state["seasons"][sid] = {}
        await runner.checkpoint(force=True)

        for sid in ids:
            if runner.season(sid).get("status") in {"done", "done_with_errors"}:
                continue
            log.info("[zprp_history] sezon %s (%s)", sid, runner.state["season_names"].get(sid))
            await process_season(runner, client, sid)
        runner.state["completed_at"] = now_utc().isoformat()
        runner.state["enabled"] = False
        runner.state["lease"] = None
        await save_state(runner.state)
        log.info("[zprp_history] ukończono wszystkie minione sezony")
    except HistoryStop as stop:
        log.info("[zprp_history] zatrzymano: %s", stop)
        if str(stop) == "stopped":
            latest = await load_state()
            await save_state(
                {**latest, "seasons": runner.state.get("seasons", {}), "counters": runner.state.get("counters", {}), "lease": None}
            )
    except asyncio.CancelledError:
        # Wyłączenie procesu (wdrożenie): oddajemy dzierżawę, żeby nowa instancja ruszyła od razu.
        try:
            await save_state({**runner.state, "lease": None})
        except Exception:
            pass
        raise
    finally:
        if own_client:
            await client.close()
    return runner.state


# --- sterowanie ----------------------------------------------------------------

async def start(retry_failed: bool = False) -> dict[str, Any]:
    """Włącza pobieranie; pętla ``history_loop`` podejmie je w ciągu ok. minuty."""
    return await patch_control(enabled=True, user_stopped=False, retry_failed=retry_failed, completed_at=None)


async def stop() -> dict[str, Any]:
    return await patch_control(enabled=False, user_stopped=True)


async def history_loop() -> None:
    """Pętla pilnująca: gdy włączone i nikt nie trzyma dzierżawy, uruchamia przebieg."""
    await asyncio.sleep(max(5, int(os.getenv("ZPRP_HISTORY_START_DELAY_SECONDS", "90"))))
    while True:
        try:
            state = await load_state()
            if state.get("enabled") and not lease_fresh(state):
                await run_history()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("[zprp_history] błąd pętli")
        await asyncio.sleep(60)


async def run_history_scheduler() -> None:
    """Start z main.py: autostart po wdrożeniu, jeśli nie ukończone i nie zatrzymane ręcznie."""
    state = await load_state()
    if autostart_enabled() and not state.get("user_stopped") and not state.get("completed_at"):
        if not state.get("enabled"):
            await patch_control(enabled=True)
        log.info("[zprp_history] autostart włączony")
    elif not autostart_enabled():
        log.info("[zprp_history] autostart wyłączony (ZPRP_HISTORY_AUTOSTART / środowisko)")
    await history_loop()


# --- status --------------------------------------------------------------------

async def status() -> dict[str, Any]:
    state = await load_state()
    counts = await database.fetch_all(
        select(
            zprp_public_matches.c.season_id,
            func.count().label("matches"),
            func.count(zprp_public_matches.c.details_fetched_at).label("with_details"),
        ).group_by(zprp_public_matches.c.season_id)
    )
    by_season = {text_value(r["season_id"]): {"matches": int(r["matches"]), "with_details": int(r["with_details"])} for r in counts}
    order = state.get("season_order", [])
    names = state.get("season_names", {})
    seasons = []
    for sid in order:
        info = dict(state.get("seasons", {}).get(sid, {}))
        total = int(info.get("competitions_total", 0))
        seasons.append(
            {
                "season_id": sid,
                "name": names.get(sid),
                "status": info.get("status", "pending"),
                "competitions": f"{len(info.get('competitions_done', []))}/{total}" if total else None,
                "failed": {
                    k: len(info.get(k, []))
                    for k in ("competitions_failed", "rosters_failed", "details_failed")
                    if info.get(k)
                },
                "current": info.get("current"),
                "tree": info.get("tree"),
                "rosters": info.get("rosters"),
                "details": info.get("details"),
                **by_season.get(sid, {"matches": 0, "with_details": 0}),
            }
        )
    heartbeat = _parse_dt((state.get("lease") or {}).get("at"))
    running = bool(heartbeat and now_utc() - heartbeat < timedelta(seconds=LEASE_SECONDS))
    return {
        "enabled": bool(state.get("enabled")),
        "running": running,
        "user_stopped": bool(state.get("user_stopped")),
        "completed_at": state.get("completed_at"),
        "autostart": autostart_enabled(),
        "interval_seconds": _interval(),
        "last_heartbeat": heartbeat.isoformat() if heartbeat else None,
        "run_started_at": state.get("run_started_at"),
        "counters": state.get("counters", {}),
        "last_error": state.get("last_error"),
        "seasons": seasons,
    }
