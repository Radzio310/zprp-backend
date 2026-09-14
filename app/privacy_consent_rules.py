"""Reguły zgody na klauzulę informacyjną RODO.

Czysty moduł-liść: żadnej bazy, żadnej sieci - dzięki temu reguła daje się
sprawdzić testem, a `app/db.py` (który łączy się z bazą już przy imporcie) nie
musi być wciągany do testów.

MODEL PRAWNY. To NIE jest "zgoda na przetwarzanie danych". Konto działa na
podstawie umowy (art. 6 ust. 1 lit. b RODO), więc imię, nazwisko, okręg, miasto
i adres e-mail są niezbędne do jego prowadzenia i nikt o nie nie prosi o zgodę -
o nich się INFORMUJE (art. 13 RODO). Zapisujemy zatem POTWIERDZENIE ZAPOZNANIA
SIĘ z klauzulą, a osobno - dobrowolną zgodę na numer telefonu, bo ten jedyny
nie jest do niczego potrzebny.

Ma to praktyczny skutek: potwierdzenia zapoznania się nie da się "wycofać"
w sposób, który unieruchamiałby konto. Wycofać da się zgodę na telefon - przez
skasowanie numeru.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

#: Wersja klauzuli. Podniesienie tej liczby sprawia, że aplikacja poprosi
#: WSZYSTKICH o ponowne zapoznanie się - podnoś ją tylko przy zmianie, która
#: dotyczy użytkownika (administrator, zakres danych, odbiorcy, prawa),
#: a nie przy poprawce literówki.
#:
#: ⚠ Ta sama liczba stoi w `BAZA/utils/privacyConsent.ts`. Rozjazd oznacza, że
#: telefon i serwer liczą różne wersje tej samej zgody - pilnuje tego test.
CURRENT_CLAUSE_VERSION = 2

#: Kto jest administratorem danych. Zmiana tych danych to zmiana klauzuli,
#: więc idzie w parze z podniesieniem wersji wyżej.
CONTROLLER_NAME = "Catch App"
CONTROLLER_TAX_ID = "2220935509"
CONTROLLER_EMAIL = "radoslawwitkowicz@catchapp.com.pl"

#: Konto ProEl (klucz: identyfikator konta) albo sędzia logujący się numerem
#: ZPRP (klucz: numer sędziego). To dwa różne światy i nie wolno ich mieszać:
#: ten sam człowiek może mieć jedno, drugie albo oba.
SUBJECT_TYPES = ("proel", "zprp")

#: Skąd przyszło potwierdzenie - do audytu, nie do logiki.
SOURCES = ("signup", "login", "in_app")


def normalize_subject_type(value: Any) -> str:
    """Rodzaj podmiotu albo wyjątek - nie zgadujemy."""
    text = str(value or "").strip().lower()
    if text not in SUBJECT_TYPES:
        raise ValueError(f"Nieznany rodzaj podmiotu zgody: {value!r}")
    return text


def normalize_subject_id(value: Any) -> str:
    """Identyfikator podmiotu jako napis, bez białych znaków."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("Pusty identyfikator podmiotu zgody.")
    return text


def normalize_source(value: Any) -> str:
    """Źródło potwierdzenia; nieznane traktujemy jak logowanie."""
    text = str(value or "").strip().lower()
    return text if text in SOURCES else "login"


def normalize_version(value: Any) -> int:
    """Wersja klauzuli jako liczba; śmieć to brak wersji, czyli zero."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def accepted_version(rows: Iterable[Any]) -> int:
    """Najwyższa wersja, którą podmiot kiedykolwiek potwierdził.

    Bierzemy MAKSIMUM, a nie ostatni wpis: gdyby kiedyś trafił się zapis
    starszej wersji po nowszej (ponowna instalacja, zapis z opóźnieniem),
    użytkownik nie ma powodu czytać tego samego drugi raz.
    """
    best = 0
    for row in rows or ():
        if isinstance(row, dict):
            candidate = normalize_version(row.get("version"))
        else:
            candidate = normalize_version(row)
        best = max(best, candidate)
    return best


def needs_consent(version: Optional[int], *, current: int = CURRENT_CLAUSE_VERSION) -> bool:
    """Czy trzeba pokazać klauzulę.

    `None` i zero to brak potwierdzenia - czyli tak. Wersja WYŻSZA od bieżącej
    też wystarcza: to znaczy, że telefon ma nowszą aplikację niż serwer, a nie
    że ktoś czegoś nie przeczytał.
    """
    return normalize_version(version) < current


def is_fresh_install(version: Optional[int]) -> bool:
    """Czy to pierwsze zetknięcie z klauzulą, czy tylko jej nowa wersja.

    Rozróżnienie jest po to, żeby ponowne pytanie NIE wyglądało jak błąd.
    Ktoś, kto klauzulę już kiedyś zaakceptował, ma zobaczyć „zmieniliśmy
    treść", a nie ten sam komunikat, co ktoś zupełnie nowy.
    """
    return normalize_version(version) == 0
