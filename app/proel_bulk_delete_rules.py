"""Reguły grupowego usuwania zapisów ProEl - liść bez bazy i bez sieci.

Administrator czyści listę ze śmieci (mecze w toku porzucone po próbach,
ćwiczenia, testy), które zaburzają statystyki. Trasa w `app/proel_archive.py`
tylko zbiera wiersze i woła tę samą archiwizację co pojedyncze usunięcie;
wszystko, co decyduje o tym, CO zniknie, siedzi tutaj i ma testy
(`tests/test_proel_bulk_delete_rules.py`), bo testy z Postgresem są w tym
projekcie pomijane.

Trzy zasady:

1. Zatwierdzonego protokołu grupowo nie usuwamy - tak samo jak pojedynczo
   w podsumowaniu meczu. Serwer pilnuje tego sam, bo aplikacja steruje tylko
   tym, co da się zaznaczyć.
2. Brak wiersza to nie błąd: celem jest „tego meczu ma nie być".
3. PIN sprawdza serwer w TYM SAMYM żądaniu, które usuwa. Po kilku pomyłkach
   z rzędu żądania są odrzucane na chwilę - czterocyfrowy PIN zgadnie się
   inaczej w kilka minut.
"""
from __future__ import annotations

import time
from typing import Callable, Dict, Iterable, List, Optional

#: Tyle zapisów naraz. Lista w aplikacji pokazuje maksymalnie 500, ale jedno
#: potwierdzenie ma dotyczyć czegoś, co da się jeszcze przeczytać w arkuszu.
MAX_BULK = 200

APPROVED_MESSAGE = (
    "Zatwierdzonych protokołów nie usuwamy - tak samo jak pojedynczo "
    "w podsumowaniu meczu."
)

#: Pomyłki PIN-u, po których trasa odmawia na `PIN_LOCK_SECONDS`.
PIN_MAX_FAILS = 5
PIN_LOCK_SECONDS = 10 * 60


def normalize_keys(raw: Optional[Iterable[object]]) -> List[str]:
    """Klucze bez pustych i bez powtórzeń, w kolejności zaznaczenia.

    Wielkości liter NIE ruszamy: serwer zna wiersz pod dokładnie tym kluczem,
    pod którym go zapisano, a lista w aplikacji oddaje go bez zmian.
    """
    out: List[str] = []
    seen = set()
    for item in raw or []:
        key = str(item if item is not None else "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def plan_bulk_delete(
    keys: List[str],
    statuses: Dict[str, Optional[str]],
) -> Dict[str, list]:
    """Podział zaznaczonych kluczy: do usunięcia, już nieistniejące, odmowy.

    `statuses` = status każdego wiersza, który JEST w bazie (klucz -> status).
    Klucza, którego tam nie ma, nie ma też w słowniku.
    """
    delete: List[str] = []
    missing: List[str] = []
    refused: List[Dict[str, str]] = []
    for key in keys:
        if key not in statuses:
            missing.append(key)
        elif (statuses.get(key) or "") == "approved":
            refused.append(
                {"key": key, "reason": "approved", "message": APPROVED_MESSAGE}
            )
        else:
            delete.append(key)
    return {"delete": delete, "missing": missing, "refused": refused}


class PinThrottle:
    """Licznik pomyłek PIN-u na administratora, w pamięci procesu.

    Restart serwera zeruje liczniki - to hamulec na zgadywanie, nie rejestr.
    Zegar wstrzykiwany, żeby test nie musiał czekać dziesięciu minut.
    """

    def __init__(
        self,
        max_fails: int = PIN_MAX_FAILS,
        lock_seconds: int = PIN_LOCK_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_fails = max_fails
        self.lock_seconds = lock_seconds
        self.clock = clock
        self._fails: Dict[str, List[float]] = {}

    def _recent(self, who: str) -> List[float]:
        now = self.clock()
        kept = [t for t in self._fails.get(who, []) if now - t < self.lock_seconds]
        if kept:
            self._fails[who] = kept
        else:
            self._fails.pop(who, None)
        return kept

    def blocked(self, who: str) -> bool:
        return len(self._recent(who)) >= self.max_fails

    def seconds_left(self, who: str) -> int:
        recent = self._recent(who)
        if len(recent) < self.max_fails:
            return 0
        return max(1, int(self.lock_seconds - (self.clock() - recent[0])))

    def fail(self, who: str) -> None:
        self._fails.setdefault(who, []).append(self.clock())

    def reset(self, who: str) -> None:
        self._fails.pop(who, None)


def lock_message(
    seconds_left: int,
    *,
    action: str = "Usuwanie",
    outcome: str = "nic nie zostało usunięte",
) -> str:
    """Komunikat blokady PIN-u.

    Licznik pomyłek jest jeden na administratora i wspólny dla wszystkich
    tras z PIN-em (usuwanie, przenoszenie zapisów szkoleniowych) - zgadywanie
    na jednej trasie nie może dawać świeżych prób na drugiej. Zmienia się
    tylko to, co komunikat mówi o skutku.
    """
    minutes = max(1, (int(seconds_left) + 59) // 60)
    return (
        f"Za dużo błędnych PIN-ów. {action} wróci za "
        f"{minutes} min - {outcome}."
    )
