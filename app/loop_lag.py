"""Monitor opóźnienia pętli zdarzeń (kto blokuje serwer i na jak długo).

Dwa elementy:

* zadanie ``_ticker`` budzi się co 100 ms i mierzy spóźnienie ponad plan,
* wątek-strażnik (poza pętlą!) co 25 ms sprawdza, czy ticker się odezwał; gdy
  pętla milczy dłużej niż próg, pobiera stos wątku pętli (``sys._current_frames``)
  oraz nazwę aktualnie wykonywanego zadania. Dzięki temu widać WINNEGO w trakcie
  blokady, a nie dopiero po fakcie.

Dane są bezpieczne do pokazania: nazwy zadań i funkcji (plik:linia), żadnych
argumentów, zmiennych ani treści żądań.

Używane też przez zadania o niskim priorytecie (archiwum): ``busy()`` mówi, czy
serwer ma teraz ruch albo pętla jest spóźniona, a ``wait_for_calm()`` czeka, aż
się uspokoi.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import sys
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

TICK = 0.1
WARN_MS = 200.0
SAMPLE_AFTER_MS = 120.0
KEEP_SPIKES = 60
KEEP_SAMPLES = 2000  # próbki opóźnienia do p50/p95 (ok. 3,5 min)

_samples: collections.deque[float] = collections.deque(maxlen=KEEP_SAMPLES)
_spikes: collections.deque[dict[str, Any]] = collections.deque(maxlen=KEEP_SPIKES)
_state: dict[str, Any] = {
    "beat": time.monotonic(),
    "started": None,
    "loop": None,
    "main_ident": None,
    "episode": None,  # trwająca blokada: {"t0": ..., "stacks": Counter, "task": str}
    "recent_lag_ms": 0.0,
    "last_request": 0.0,
}
_thread: threading.Thread | None = None
_task: asyncio.Task | None = None
_stop = threading.Event()


def _short(path: str) -> str:
    path = path.replace("\\", "/")
    for marker in ("/app/", "/site-packages/", "/lib/"):
        i = path.rfind(marker)
        if i >= 0:
            return path[i + 1 :]
    return path.rsplit("/", 1)[-1]


def _stack_of_main(depth: int = 6) -> tuple[str, ...]:
    frame = sys._current_frames().get(_state["main_ident"])
    out: list[str] = []
    while frame is not None and len(out) < 40:
        code = frame.f_code
        out.append(f"{_short(code.co_filename)}:{frame.f_lineno} {getattr(code, 'co_qualname', code.co_name)}")
        frame = frame.f_back
    # najgłębsze ramki pierwsze; pomijamy samo asyncio, jeśli jest coś swojego
    own = [f for f in out if not f.startswith(("asyncio/", "lib/asyncio"))] or out
    return tuple(own[:depth])


def _current_task_name() -> str:
    """Zadanie, którego korutyna właśnie działa (cr_running); z wątku-strażnika."""
    loop = _state["loop"]
    try:
        for task in list(asyncio.all_tasks(loop)):
            coro = task.get_coro()
            if getattr(coro, "cr_running", False):
                qual = getattr(coro, "__qualname__", None) or getattr(coro, "__name__", "?")
                return f"{task.get_name()}<{qual}>"
    except Exception:  # noqa: BLE001
        pass
    return "?"


def _watchdog() -> None:
    while not _stop.wait(0.025):
        if _state["loop"] is None:
            continue
        stale_ms = (time.monotonic() - _state["beat"]) * 1000.0
        ep = _state["episode"]
        if stale_ms - TICK * 1000.0 >= SAMPLE_AFTER_MS:
            if ep is None:
                ep = _state["episode"] = {"stacks": collections.Counter(), "tasks": collections.Counter()}
            ep["stacks"][_stack_of_main()] += 1
            ep["tasks"][_current_task_name()] += 1


async def _ticker() -> None:
    last = time.monotonic()
    while True:
        await asyncio.sleep(TICK)
        now = time.monotonic()
        lag_ms = max(0.0, (now - last - TICK) * 1000.0)
        last = now
        _state["beat"] = now
        _state["recent_lag_ms"] = lag_ms
        _samples.append(lag_ms)
        ep = _state["episode"]
        _state["episode"] = None
        if lag_ms >= WARN_MS:
            top_stack: tuple[str, ...] = ()
            task = "?"
            if ep and ep["stacks"]:
                top_stack = ep["stacks"].most_common(1)[0][0]
                task = ep["tasks"].most_common(1)[0][0]
            spike = {
                "at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
                "lag_ms": round(lag_ms),
                "task": task,
                "stack": list(top_stack),
            }
            _spikes.append(spike)
            log.warning("[loop_lag] pętla spóźniona o %d ms, zadanie=%s, stos=%s", round(lag_ms), task, " < ".join(top_stack[:3]))


def start() -> None:
    """Wywołać z kontekstu pętli (startup)."""
    global _thread, _task
    if _task is not None and not _task.done():
        return
    _state["loop"] = asyncio.get_running_loop()
    _state["main_ident"] = threading.get_ident()
    _state["started"] = time.time()
    _state["beat"] = time.monotonic()
    _stop.clear()
    _task = asyncio.create_task(_ticker(), name="loop-lag-ticker")
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_watchdog, name="loop-lag-watchdog", daemon=True)
        _thread.start()


def stop() -> None:
    _stop.set()
    if _task is not None:
        _task.cancel()


def note_request() -> None:
    _state["last_request"] = time.monotonic()


def busy(window: float = 3.0, lag_ms: float = 80.0) -> bool:
    """Czy serwer ma teraz ruch od użytkowników albo pętla jest spóźniona."""
    if _state["recent_lag_ms"] >= lag_ms:
        return True
    return time.monotonic() - _state["last_request"] < window


async def wait_for_calm(max_wait: float = 30.0) -> float:
    """Czeka (maks. ``max_wait`` s), aż nie będzie ruchu i lagu. Zwraca czas czekania."""
    t0 = time.monotonic()
    while busy() and time.monotonic() - t0 < max_wait:
        await asyncio.sleep(0.5)
    return time.monotonic() - t0


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 1)


def report() -> dict[str, Any]:
    values = list(_samples)
    return {
        "running": _task is not None and not _task.done(),
        "uptime_s": round(time.time() - _state["started"]) if _state["started"] else 0,
        "samples": len(values),
        "p50_ms": _pct(values, 0.50),
        "p95_ms": _pct(values, 0.95),
        "p99_ms": _pct(values, 0.99),
        "max_ms": round(max(values), 1) if values else 0.0,
        "over_200ms": sum(1 for v in values if v >= WARN_MS),
        "current_lag_ms": round(_state["recent_lag_ms"], 1),
        "spikes": list(reversed(_spikes)),
    }


class RequestNoteMiddleware:
    """Czysty ASGI: zapisuje tylko czas ostatniego żądania HTTP (do ``busy()``)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            _state["last_request"] = time.monotonic()
        await self.app(scope, receive, send)


def make_router():
    from fastapi import APIRouter

    router = APIRouter(tags=["diagnostics"])

    @router.get("/admin/loop-lag")
    async def loop_lag_report() -> dict[str, Any]:
        return report()

    return router
