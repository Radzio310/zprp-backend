"""Mecz szkoleniowy w ProElu - klucz wiersza i jego zgodność z blobem.

Realny zapis w `proel_matches` należy wyłącznie do meczu prowadzonego własnym
kontem sędziego, tokenem meczu albo założonego ręcznie. Każde inne wejście -
cudzy mecz wzięty z terminarza ZPRP, ćwiczenie z kursokonferencji, mecz
testowy - jest SZKOLENIOWE i musi trafić pod własny klucz.

Powód jest prosty: kluczem głównym `proel_matches` jest NUMER meczu, a numer
mają wspólny wszystkie te przebiegi. Dwadzieścia osób ćwiczących na „SPM/1"
pisało do jednego wiersza i odbierało sobie prowadzenie - a przy okazji
prawdziwemu stolikowi, który ten mecz naprawdę prowadził.

Klucz szkoleniowy to numer z przedrostkiem podejścia: ``T-K3N8P2WQ/SPM/1``.
Schemat bazy zostaje bez zmian (klucz główny to dalej napis), a filtr listy
sprowadza się do zapytania o przedrostek.

Moduł-LIŚĆ: bez bazy, bez routera, bez importów w drugą stronę. `app.proel`
ciągnie `app.db`, a ten przy imporcie zakłada schemat na Postgresie - czyli
test tej reguły wymagałby żywej bazy. A to jest reguła, która decyduje o tym,
czy ćwiczenie nadpisze cudzy protokół.
"""

from __future__ import annotations

import re
from typing import Any

#: Przedrostek klucza szkoleniowego. Myślnik jest tu celowo: numery ZPRP go nie
#: używają, więc przedrostek nie ma jak pomylić się z prawdziwym numerem meczu.
TRAINING_KEY_PREFIX = "T-"

#: `T-<PODEJŚCIE>/<NUMER>` - identyfikator podejścia ma 6-16 znaków [A-Z0-9].
_TRAINING_KEY_RE = re.compile(r"^T-[A-Z0-9]{6,16}/.+$", re.IGNORECASE)

#: Wzorzec do `LIKE` w SQL. Zawężony do przedrostka, więc idzie po indeksie
#: klucza głównego zamiast po całej tabeli.
TRAINING_KEY_LIKE = "T-%/%"


def is_training_key(key: Any) -> bool:
    """Czy ten klucz wiersza należy do meczu szkoleniowego."""
    return bool(_TRAINING_KEY_RE.match(str(key or "").strip()))


def match_number_from_key(key: Any) -> str:
    """Numer meczu ukryty w kluczu - do pokazania i do porównań z bazą ZPRP.

    Klucz, który nie jest szkoleniowy, wraca bez zmian: on już jest numerem.
    """
    text = str(key or "").strip()
    if not is_training_key(text):
        return text
    return text[text.index("/") + 1 :]


def training_run_from_key(key: Any) -> str:
    """Identyfikator podejścia - pusty, gdy klucz nie jest szkoleniowy."""
    text = str(key or "").strip()
    if not is_training_key(text):
        return ""
    return text[len(TRAINING_KEY_PREFIX) : text.index("/")]


def blob_is_training(blob: Any) -> bool:
    """Czy blob opisuje mecz szkoleniowy.

    Trzy powody, wszystkie równoważne i wszystkie jadące w konfiguracji meczu
    od aplikacji: jawne pochodzenie, flaga meczu testowego i znacznik ćwiczenia
    z kursokonferencji.
    """
    try:
        config = (blob or {}).get("matchConfig") or {}
    except AttributeError:
        return False
    if str(config.get("origin") or "").strip() == "training":
        return True
    if config.get("isTest"):
        return True
    training = config.get("training") or {}
    try:
        return bool(str(training.get("eventId") or "").strip())
    except AttributeError:
        return False


def blob_knows_provenance(blob: Any) -> bool:
    """Czy ten blob w ogóle wie, skąd się wziął.

    Wersje aplikacji sprzed tej reguły nie wysyłają `origin` i nie mają jak go
    wysłać. Ich zapisy przepuszczamy bez pytania - tak samo, jak przepuszczamy
    ich zapisy przy twardej blokadzie prowadzenia. Zamykanie tej furtki dzieje
    się samo, w miarę jak flota się aktualizuje.

    Mecz testowy i ćwiczenie rozpoznajemy jednak ZAWSZE: te dwa znaczniki
    jadą w konfiguracji od dawna, więc ich obecność jest wiedzą, a nie brakiem.
    """
    try:
        config = (blob or {}).get("matchConfig") or {}
    except AttributeError:
        return False
    if str(config.get("origin") or "").strip():
        return True
    return blob_is_training(blob)


def key_conflicts_with_blob(key: Any, blob: Any) -> bool:
    """Czy zapis pod tym kluczem kłóci się z pochodzeniem meczu.

    Dwa błędy, oba kosztowne w drugą stronę:

    * mecz szkoleniowy pod czystym numerem nadpisuje cudzy protokół - to
      dokładnie ta kolizja, przed którą stoi cały ten moduł;
    * mecz oficjalny pod kluczem szkoleniowym znika z listy stolików, bo lista
      odsiewa przedrostek.

    Blob, który o swoim pochodzeniu nic nie mówi (stara aplikacja), nie może
    być w konflikcie - nie ma z czym.
    """
    if not blob_knows_provenance(blob):
        return False
    return is_training_key(key) != blob_is_training(blob)
