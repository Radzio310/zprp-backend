"""
Egzamin na żywo - gniazda WebSocket w pamięci procesu (etap 5, 16.10.2026).

═══ ZNANA GRANICA: JEDEN PROCES ═══

Lista otwartych gniazd to zwykły słownik w pamięci tego procesu (tak samo jak w Communio:
`ws_manager.py`, `song_live.py`). Railway uruchamia dla BAZY jeden proces, więc każdy
uczestnik, prowadzący i rzutnik jednej sesji siedzą w tym samym słowniku i rozgłoszenie
dociera do wszystkich.

Co by się stało przy dwóch procesach (skalowanie poziome): gniazdo podpięte do procesu B nie
dostałoby rozgłoszenia z akcji obsłużonej przez proces A. NIE tracimy wtedy danych - stan
sesji (faza, termin, odpowiedzi, wyniki) leży w bazie, a każdy klient po każdym
ponownym połączeniu i co kilka sekund w trybie awaryjnym robi GET migawki z `rev`.
Skutek byłby więc tylko opóźnieniem do kilku sekund, nie błędem. Gdyby kiedyś doszło
do skalowania, wystarczy dołożyć Redis pub/sub albo Postgres LISTEN/NOTIFY do `Hub.publish`
- reszta kodu (migawki z bazy) zostaje bez zmian.

Restart procesu (deploy) zrywa wszystkie gniazda; klienci łączą się ponownie z wykładniczym
opóźnieniem i dostają migawkę z bazy. Sesja przeżywa restart.

Moduł nie zna sesji ani reguł: trzyma gniazda i potrafi je obsypać ramkami. Co i komu wysłać,
rozstrzyga `exam_live_routes.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)

#: Rozgłoszenia wywołane odpowiedziami łączymy w okna tej długości (200 osób odpowiada naraz).
COALESCE_S = 0.35
#: Twardy limit gniazd na sesję (obrona przed zalewem; uczestników i tak jest max 400).
MAX_SOCKETS_PER_SESSION = 700


@dataclass(eq=False)
class Conn:
    ws: WebSocket
    role: str  # host | player | projector
    participant_id: Optional[str] = None


@dataclass
class Hub:
    conns: Dict[str, List[Conn]] = field(default_factory=lambda: defaultdict(list))
    pending: Dict[str, asyncio.Task] = field(default_factory=dict)
    timers: Dict[str, Any] = field(default_factory=dict)

    def add(self, session_id: str, conn: Conn) -> bool:
        if len(self.conns[session_id]) >= MAX_SOCKETS_PER_SESSION:
            return False
        self.conns[session_id].append(conn)
        return True

    def remove(self, session_id: str, conn: Conn) -> None:
        lst = self.conns.get(session_id, [])
        if conn in lst:
            lst.remove(conn)
        if not lst:
            self.conns.pop(session_id, None)

    def count(self, session_id: str) -> int:
        return len(self.conns.get(session_id, []))

    def of(self, session_id: str) -> List[Conn]:
        return list(self.conns.get(session_id, []))

    async def send(self, session_id: str, conn: Conn, frame: Dict[str, Any]) -> bool:
        try:
            await conn.ws.send_text(json.dumps(frame, default=str, ensure_ascii=False))
            return True
        except Exception:  # noqa: BLE001 - martwe gniazdo, usuwamy po cichu (klient wróci przez GET)
            self.remove(session_id, conn)
            return False

    def schedule(self, session_id: str, render: Callable[[str], Awaitable[None]], *, immediate: bool) -> None:
        """Rozgłoszenie natychmiast albo w oknie łączącym (odpowiedzi uczestników)."""
        if not self.conns.get(session_id):
            return
        task = self.pending.get(session_id)
        if immediate:
            if task and not task.done():
                task.cancel()
            self.pending[session_id] = asyncio.ensure_future(self._run(session_id, render, 0.0))
            return
        if task and not task.done():
            return
        self.pending[session_id] = asyncio.ensure_future(self._run(session_id, render, COALESCE_S))

    async def _run(self, session_id: str, render: Callable[[str], Awaitable[None]], delay: float) -> None:
        try:
            if delay:
                await asyncio.sleep(delay)
            await render(session_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.warning("egzamin na żywo: rozgłoszenie sesji %s nieudane", session_id, exc_info=True)

    def arm(self, session_id: str, key: Any, delay_s: float, fire: Callable[[], Awaitable[None]]) -> None:
        """Zegar terminu pytania: po `delay_s` uruchom `fire` (auto-reveal). Jeden zegar na sesję."""
        current = self.timers.get(session_id)
        if current and current[0] == key and not current[1].done():
            return
        if current and not current[1].done():
            current[1].cancel()

        async def runner() -> None:
            try:
                await asyncio.sleep(max(0.0, delay_s))
                await fire()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.warning("egzamin na żywo: zegar sesji %s nieudany", session_id, exc_info=True)

        self.timers[session_id] = (key, asyncio.ensure_future(runner()))

    def forget(self, session_id: str) -> None:
        timer = self.timers.pop(session_id, None)
        if timer and not timer[1].done():
            timer[1].cancel()
