"""
Na jakim etapie jest liczenie rozliczenia - dla zasłony w panelu okręgu.

MODUŁ-LIŚĆ: bez bazy i bez sieci.

SKĄD TO SIĘ WZIĘŁO. Zasłona „Przeliczam rozliczenia" pokazywała pasek, który
jechał sam z siebie do 92% i stał tam, aż przyszły dane (zgłoszenie
z 27.10.2026: ma pokazywać, na jakim jest etapie). Teraz liczenie zapisuje
tutaj każdy etap, a panel o niego pyta.

JAK. Liczenie biegnie w jednym zadaniu asyncio, przez kilka modułów
(`province_settlements.load_settlement`, `_base`, podsumowanie). Zamiast
przeciągać obiekt postępu przez wszystkie sygnatury, `tracking(key)` ustawia
go w zmiennej kontekstu, a głębokie funkcje wołają `stage("rates")`. Poza
śledzonym liczeniem (PDF, telefon sędziego) `stage` nic nie robi.

Dwa pytania o ten sam miesiąc liczą RAZ (`settlement_cache.remember`), więc
drugie widzi postęp pierwszego - klucz to parametry, nie pytający.

Czas każdego etapu idzie też do logu: następnym razem, gdy coś będzie wolne,
log powie, który etap.
"""
from __future__ import annotations

import contextvars
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Hashable, Optional

logger = logging.getLogger(__name__)

#: Etapy liczenia miesiąca, po kolei. Panel ma do nich własne napisy.
STAGES = ("facts", "names", "rates", "clubs", "extras", "checks")

#: Po tylu sekundach od końca wpis znika (panel zdąży odczytać „gotowe").
KEEP_SECONDS = 60.0


class Progress:
    __slots__ = ("key", "stage", "detail", "done", "started", "stage_started", "finished")

    def __init__(self, key: Hashable) -> None:
        self.key = key
        self.stage: Optional[str] = None
        self.detail: Optional[str] = None
        #: Zakończone etapy: (nazwa, milisekundy).
        self.done: list[tuple[str, int]] = []
        self.started = time.monotonic()
        self.stage_started = self.started
        self.finished: Optional[float] = None

    def _close_stage(self, now: float) -> None:
        if self.stage is not None:
            self.done.append((self.stage, int((now - self.stage_started) * 1000)))

    def enter(self, name: str, detail: Optional[str] = None) -> None:
        now = time.monotonic()
        if name == self.stage:
            self.detail = detail
            return
        self._close_stage(now)
        self.stage = name
        self.detail = detail
        self.stage_started = now

    def finish(self) -> None:
        now = time.monotonic()
        self._close_stage(now)
        self.stage = None
        self.detail = None
        self.finished = now

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        return {
            "active": self.finished is None,
            "stage": self.stage,
            "detail": self.detail,
            "done": [name for name, _ in self.done],
            "elapsed_ms": int(((self.finished or now) - self.started) * 1000),
        }


_runs: dict[Hashable, Progress] = {}
_current: contextvars.ContextVar[Optional[Progress]] = contextvars.ContextVar(
    "settlement_progress", default=None
)


def _prune(now: float) -> None:
    for key, item in list(_runs.items()):
        if item.finished is not None and now - item.finished > KEEP_SECONDS:
            _runs.pop(key, None)


@asynccontextmanager
async def tracking(key: Hashable, *, label: str = "") -> AsyncIterator[Progress]:
    """
    Śledzi liczenie pod kluczem `key` na czas bloku.

    Gdy pod tym kluczem już ktoś liczy (drugie pytanie o to samo), nie zakłada
    drugiego wpisu - czeka razem z pierwszym, a panel widzi jeden postęp.
    """
    now = time.monotonic()
    _prune(now)
    running = _runs.get(key)
    if running is not None and running.finished is None:
        token = _current.set(None)
        try:
            yield running
        finally:
            _current.reset(token)
        return

    progress = Progress(key)
    _runs[key] = progress
    token = _current.set(progress)
    try:
        yield progress
    finally:
        _current.reset(token)
        progress.finish()
        # Same szybkie odpowiedzi z pamięci nie mają czego logować.
        if progress.done:
            total = int((progress.finished - progress.started) * 1000)
            parts = ", ".join(f"{name} {ms} ms" for name, ms in progress.done)
            logger.info("[settlement] liczenie %s: %d ms (%s)", label or key, total, parts)


def stage(name: str, detail: Optional[str] = None) -> None:
    """Liczenie weszło w etap `name` (poza śledzeniem - nic). Nigdy nie rzuca."""
    try:
        progress = _current.get()
        if progress is not None:
            progress.enter(name, detail)
    except Exception:  # pragma: no cover - postęp nie może zatrzymać rachunku
        logger.exception("[settlement_progress] stage")


def snapshot(key: Hashable) -> Optional[dict[str, Any]]:
    """Stan liczenia pod kluczem albo None, gdy nikt nie liczy (ani niedawno nie liczył)."""
    _prune(time.monotonic())
    item = _runs.get(key)
    return item.snapshot() if item is not None else None


# ---------------------------------------------------------------------------
# Pobieranie z ZPRP (przebieg w tle, minuty) - etap i licznik sędziów
# ---------------------------------------------------------------------------

#: Etapy przebiegu, po kolei. Panel ma do nich własne napisy.
RUN_STAGES = ("login", "judges", "matches", "venues", "distances", "store")

_run_steps: dict[int, dict[str, Any]] = {}


def run_step(
    run_id: Any, stage: str, *, done: Optional[int] = None, total: Optional[int] = None
) -> None:
    """Przebieg `run_id` jest na etapie `stage` (np. sędzia `done` z `total`). Nigdy nie rzuca."""
    try:
        _run_steps[int(run_id)] = {
            "stage": stage,
            "done": done,
            "total": total,
            "at": time.monotonic(),
        }
    except Exception:  # pragma: no cover - postęp nie może zatrzymać przebiegu
        logger.exception("[settlement_progress] run_step")


def run_snapshot(run_id: Any) -> Optional[dict[str, Any]]:
    """Etap przebiegu albo None (nieznany, inny proces, już zamknięty)."""
    try:
        item = _run_steps.get(int(run_id))
    except (TypeError, ValueError):
        return None
    if item is None:
        return None
    return {"stage": item["stage"], "done": item["done"], "total": item["total"]}


def run_end(run_id: Any) -> None:
    try:
        _run_steps.pop(int(run_id), None)
    except (TypeError, ValueError):
        pass


def clear() -> None:
    """Wszystko od nowa - dla testów."""
    _runs.clear()
    _run_steps.clear()
