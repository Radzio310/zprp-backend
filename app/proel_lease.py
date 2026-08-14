"""Kto prowadzi mecz — czysta arytmetyka leasingu, bez bazy.

Wydzielone z `app/proel.py` z jednego konkretnego powodu: `app.proel` ciągnie
za sobą `app.db`, a ten przy imporcie zakłada tabele — czyli test tej logiki
wymagałby żywej bazy. Reguła „kto może pisać w trakcie meczu" jest zbyt
kosztowna w skutkach (dwa protokoły jednego meczu), żeby zostać bez testów.

Zegarem porządkującym w całym systemie jest Postgres. Tutaj używamy zegara
procesu wyłącznie do policzenia MOMENTU WYGAŚNIĘCIA, który zaraz potem zapisuje
się do bazy — nigdy do porównywania czasów pochodzących z różnych urządzeń.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

#: Zwykły leasing aplikacji: 90 s, bicie serca co 25 s.
LEASE_TTL_SECONDS = 90
#: Aplikacja w tle bije rzadziej — wtedy wydłużamy okno, żeby zminimalizowana
#: aplikacja prowadzącego nie oddawała meczu po półtorej minuty.
LEASE_TTL_BACKGROUND_SECONDS = 300
#: Leasing-widmo obejmowany za starą aplikację. Dłuższy, bo stary klient pisze
#: co 60 s i nie ma czym bić serca — dwa przegapione zapisy nie mogą oddać
#: meczu komuś innemu.
LEGACY_LEASE_TTL_SECONDS = 180


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def lease_active(state: Optional[Dict[str, Any]]) -> bool:
    until = _as_aware((state or {}).get("lease_until"))
    return until is not None and until > now_utc()


def legacy_lease_values(
    state: Dict[str, Any], writer_install: str
) -> Optional[Dict[str, Any]]:
    """Pola leasingu-widma dla zapisu ze starej aplikacji, albo `None`.

    Stara wersja aplikacji nigdy nie zawoła `/lease`, więc mecz przez nią
    prowadzony wyglądałby dla nowej aplikacji na nieprowadzony przez nikogo —
    i nowa aplikacja weszłaby w niego bez ostrzeżenia. Widmo obejmujemy za nią
    przy zapisie bloba.

    `None` znaczy „nie ruszamy leasingu": prowadzenie objął ktoś świadomie i to
    on nim rozporządza.
    """
    writer = str(writer_install or "")
    mine = (
        state.get("lease_kind") == "legacy"
        and str(state.get("lease_install") or "") == writer
    )
    if not mine and lease_active(state):
        return None

    values: Dict[str, Any] = {
        "lease_install": writer,
        "lease_judge_id": "",
        "lease_name": "",
        "lease_kind": "legacy",
        "lease_until": now_utc() + timedelta(seconds=LEGACY_LEASE_TTL_SECONDS),
    }
    # Epokę podbijamy tylko przy OBJĘCIU widma — przedłużenie własnego nie może
    # unieważniać niczyjego bicia serca.
    if not mine:
        values["lease_epoch"] = int(state.get("lease_epoch") or 0) + 1
    return values
