"""
Stan przebiegu odswiezania: czy jeszcze trwa i czy wolno odpalic kolejny.

Pelne pobranie okregu to kilkaset zapytan do ZPRP (lista sedziow po stronach
plus lista meczow kazdego sedziego) i trwa minuty. Dlatego odswiezanie na
zadanie idzie w TLE: serwer od razu odpowiada numerem przebiegu, a klient
sledzi go przez `/status`. Te reguly decyduja, kiedy nowy przebieg w ogole
wolno zaczac.

MODUL-LISC - bez bazy, zeby reguly czasu mialy test.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

#: Przebieg bez `finished_at` starszy niz tyle umarl razem z procesem (restart
#: Railway w polowie pobierania). Traktujemy go jak zakonczony - inaczej okreg
#: zostalby zablokowany na zawsze przez wiersz, ktorego nikt juz nie domknie.
RUN_STALE_AFTER = timedelta(minutes=25)

#: Odswiezenie na zadanie BEZ poswiadczen (kontem `sync`) nie czesciej niz co
#: tyle. Dziesiec telefonow wchodzacych naraz na ekran nie moze zamienic sie
#: w dziesiec przebiegow po kilkaset zapytan do jednej maszyny zwiazku.
MANUAL_COOLDOWN = timedelta(minutes=10)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def run_is_active(
    started_at: Optional[datetime],
    finished_at: Optional[datetime],
    now: datetime,
    heartbeat_at: Optional[datetime] = None,
) -> bool:
    """
    Czy przebieg jeszcze trwa (i nie jest trupem po restarcie).

    `heartbeat_at` - znak zycia, ktory przebieg stawia po kazdym sedzim.
    Pobranie wszystkich sezonow wstecz trwa dluzej niz `RUN_STALE_AFTER`, a
    liczone od samego startu uznaloby zywy przebieg za trupa i pozwolilo
    odpalic drugi rownolegle. Trupa wykrywamy po ciszy, nie po dlugosci.
    """
    started = _aware(started_at)
    if started is None or finished_at is not None:
        return False
    beat = _aware(heartbeat_at)
    last = max(started, beat) if beat else started
    return _aware(now) - last < RUN_STALE_AFTER


def cooldown_left(
    finished_at: Optional[datetime],
    ok: Optional[bool],
    now: datetime,
) -> Optional[timedelta]:
    """
    Ile jeszcze trzeba poczekac na kolejne odswiezenie kontem `sync`.

    Tylko po UDANYM przebiegu. Po nieudanym ponowienie wolno od razu - czekanie
    dziesiec minut na to, zeby sprobowac jeszcze raz, niczego nie chroni.
    """
    finished = _aware(finished_at)
    if finished is None or not ok:
        return None
    left = MANUAL_COOLDOWN - (_aware(now) - finished)
    return left if left > timedelta(0) else None
