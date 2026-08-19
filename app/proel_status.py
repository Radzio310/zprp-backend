"""Status meczu w ProEl'u: ustalanie i przejścia.

Wydzielone z `app/proel.py` jako LIŚĆ - moduł bez bazy, bez routera i bez
importów w drugą stronę. Dzięki temu reguła przejścia da się przetestować bez
stawiania schematu (metadane ProEla używają typów wyłącznie postgresowych,
więc sam import `app.proel` przewraca zbieranie testów na sqlite).

Trzy statusy, jedna droga w każdą stronę:

    in_progress → finished → approved
                     ↑__________|      (cofnięcie zatwierdzenia)
"""
from __future__ import annotations

from typing import Optional

VALID_STATUSES = ("in_progress", "finished", "approved")


def resolve_status(
    status: Optional[str],
    is_finished: Optional[bool],
    fallback: str,
) -> str:
    """Status na podstawie (priorytetowo) jawnego pola `status`, a w jego braku
    starego pola `is_finished`.

    `is_finished=True` z dawnych klientów mapujemy na "finished" i NIGDY na
    "approved" - zatwierdzenie to świadoma, osobna czynność sędziego.
    """
    if status:
        s = str(status).strip().lower()
        if s in VALID_STATUSES:
            return s
    if is_finished is not None:
        return "finished" if is_finished else "in_progress"
    return fallback


def is_finished_for(status: str) -> bool:
    return status in ("finished", "approved")


def unapprove_requested(req_status: Optional[str]) -> bool:
    """Czy żądanie zapisu jest ŚWIADOMYM cofnięciem zatwierdzenia.

    To jedyny zapis, który wolno przyjąć na meczu ze statusem "approved" - bez
    niego zatwierdzenie było stanem bez wyjścia, bo blokada odrzucała także
    żądanie, które miało je zdjąć, zanim ktokolwiek zajrzał do jego treści.

    Wymagamy JAWNEGO pola `status`, i to innego niż "approved". Starsze wersje
    aplikacji nie wysyłają go wcale, tylko `is_finished=True` (co
    `resolve_status` mapuje na "finished") - gdyby ta droga wystarczała, zwykły
    autozapis starego telefonu po cichu odtwierdzałby zamknięty protokół.
    """
    s = str(req_status or "").strip().lower()
    return s in VALID_STATUSES and s != "approved"
