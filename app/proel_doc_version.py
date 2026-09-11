"""Wersja treści meczu (`doc_rev`) - czysta logika, bez bazy.

Po co to w ogóle jest. `rev` w `proel_match_state` rośnie przy KAŻDYM biciu
serca leasingu, każdym patchu pola i każdym zwolnieniu prowadzenia, a `PUT`
odpowiadał samym `{success}`. Telefon nie miał więc czym odróżnić dwóch
zupełnie różnych sytuacji:

* "na serwerze leży treść zapisana z INNEGO urządzenia, a ja buduję na
  starszej" - czyli mój zapis po cichu zniszczyłby cudzą pracę,
* "na serwerze leży moja własna treść, tylko odpowiedź na zapis zginęła po
  drodze" - czyli nic się nie stało i trzeba po prostu pisać dalej.

`doc_rev` w `proel_matches` rośnie WYŁĄCZNIE przy przyjętym pełnym zapisie
treści (`POST /proel/`, `PUT /proel/{klucz}`) i niesie ze sobą, kto ten zapis
zrobił. Reprojekcja overlaya i sama zmiana statusu go nie ruszają: pola
overlaya (podpisy, obsada, lekarz, `post.*`, badania) serwer scala po polu
sam, więc to nie są konflikty treści.

Moduł-LIŚĆ z tego samego powodu co `app/proel_training_key.py`: `app.proel`
ciągnie `app.db`, a ten przy imporcie zakłada schemat na Postgresie. Reguła,
która decyduje, czy zapis zostanie przyjęty, nie może zostać bez testów.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional

#: Nagłówek z wersją treści, na której telefon zbudował swój zapis.
BASE_REV_HEADER = "X-Proel-Base-Rev"
#: Nagłówek świadomego wyboru w arkuszu konfliktu.
OVERWRITE_HEADER = "X-Proel-Overwrite"
#: Jedyna znana wartość `X-Proel-Overwrite`: "wybrałem swoją wersję, widząc
#: aktualną wersję serwera".
OVERWRITE_CONFLICT = "conflict"

#: Ile trzymamy wersje odłożone do historii. Ten sam rok co archiwum usuniętych.
HISTORY_RETENTION_DAYS = 365

#: Wersja z telefonu, która przegrała: sędzia wybrał wersję z serwera.
REASON_REJECTED_LOCAL = "rejected_local"
#: Wersja z serwera, którą sędzia świadomie nadpisał swoją.
REASON_OVERWRITTEN = "overwritten_by_choice"

#: Powody, które wolno podać telefonowi. `overwritten_by_choice` wpisuje
#: WYŁĄCZNIE serwer, w transakcji zapisu - telefon nie ma czym tego dowieść.
CLIENT_REASONS = frozenset({REASON_REJECTED_LOCAL})

#: Górny limit bloba odkładanego do historii przez telefon. Pełny protokół
#: z przebiegiem i podpisami ma setki kilobajtów; osiem megabajtów to zapas,
#: a nie zaproszenie do wysyłania czegokolwiek.
MAX_HISTORY_BYTES = 8 * 1024 * 1024

STALE_MESSAGE = (
    "Na serwerze jest nowsza wersja tego meczu, zapisana z innego urządzenia. "
    "Twój zapis nie został przyjęty - wybierz wersję przy następnym wejściu do meczu."
)


def parse_base_rev(raw: Any) -> Optional[int]:
    """Wersja z nagłówka albo `None`, gdy jej nie ma albo nie da się jej odczytać.

    `None` znaczy "stara aplikacja" i zapis zachowuje się dokładnie tak jak
    przed tą zmianą. Wartość ujemna jest tak samo bez sensu jak napis, więc
    traktujemy ją tak samo - lepiej przepuścić zapis, niż odmówić z powodu
    nagłówka, którego nikt świadomie nie wysłał.
    """
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value >= 0 else None


def parse_overwrite(raw: Any) -> bool:
    """Czy telefon świadomie wybrał swoją wersję w arkuszu konfliktu."""
    return str(raw or "").strip().lower() == OVERWRITE_CONFLICT


def same_install(a: Any, b: Any) -> bool:
    """To samo urządzenie - wyłącznie przy niepustych identyfikatorach po OBU
    stronach. Puste równe pustemu uznałoby każdego starego klienta za autora
    każdego zapisu."""
    left = str(a or "").strip()
    right = str(b or "").strip()
    return bool(left) and bool(right) and left == right


def is_stale_write(
    base_rev: Optional[int],
    current_rev: int,
    writer_install: Optional[str],
    my_install: Optional[str],
    *,
    doc_exists: bool = True,
    overwrite: bool = False,
) -> bool:
    """Czy zapis buduje na treści starszej niż ta, którą ktoś INNY już zapisał.

    Kolejność warunków jest kolejnością "czego nie wolno pomylić z konfliktem":

    * brak nagłówka - stara aplikacja, zachowanie sprzed tej zmiany;
    * wersja bazowa `0` przy ISTNIEJĄCYM protokole - telefon zaczął mecz od
      zera i myśli, że na serwerze nic nie ma. Świeży, pusty mecz nie ma prawa
      nadpisać protokołu, który napisał kto inny (porzucony mecz na drugim
      telefonie), także w wierszu sprzed wersjonowania - dlatego ten warunek
      stoi PRZED "nigdy niewersjonowany". Nieznany autor to autor obcy.
      Wyjątek: świadomy wybór w arkuszu konfliktu (`overwrite`). Telefon
      widział wtedy wersję serwera i wysyła ją jako bazową - dla wiersza
      niewersjonowanego to jest właśnie `0`, a bez wyjątku sędzia nie
      mógłby wybrać swojej wersji nigdy;
    * wiersz nigdy niewersjonowany (`0`) - nie ma z czym porównać, a wersja
      bazowa większa od zera pochodzi ze starej lokalnej kopii;
    * ta sama wersja - telefon zna dokładnie to, co leży na serwerze;
    * nowsza wersja pochodzi z TEGO urządzenia - to jego własny zapis, na
      który nie dostał odpowiedzi (padła sieć w hali). Odmowa zamieniłaby
      zgubioną odpowiedź w fałszywy konflikt z samym sobą.

    Wszystko inne to cudza treść, której telefon nie widział.
    """
    if base_rev is None:
        return False
    if int(base_rev) == 0 and doc_exists and not overwrite:
        return not same_install(writer_install, my_install)
    current = int(current_rev or 0)
    if current == 0:
        return False
    if int(base_rev) == current:
        return False
    if same_install(writer_install, my_install):
        return False
    return True


def should_bump(*, approval_transition: bool, content_changed: bool) -> bool:
    """Czy ten zapis podnosi wersję treści.

    Zatwierdzenie i jego cofnięcie niosą pełny blob (aplikacja buduje go
    z własnego stanu), ale nie są pracą nad treścią - są decyzją o statusie.
    Gdyby podnosiły wersję, każde inne urządzenie przy następnym wejściu
    dostałoby arkusz "na serwerze jest nowsza wersja" dla meczu, w którym nic
    się nie zmieniło poza pieczątką.

    Zapis bajt w bajt taki sam jak ten na serwerze też nie jest zmianą treści:
    podniesienie wersji przepisałoby autorstwo na urządzenie, które niczego
    nie zmieniło, a prawdziwy autor dostałby konflikt z własną treścią.
    """
    if approval_transition:
        return False
    return bool(content_changed)


def should_archive_on_overwrite(
    overwrite: bool, writer_install: Optional[str], my_install: Optional[str]
) -> bool:
    """Czy przed nadpisaniem odłożyć bieżącą wersję serwera do historii.

    Tylko przy świadomym wyborze i tylko wtedy, gdy nadpisywana wersja NIE
    jest własną wersją tego urządzenia. Ponowienie tego samego zapisu z
    kolejki (odpowiedź zginęła) trafia na serwerze na własną treść telefonu -
    odkładanie jej drugi raz dawałoby w historii duplikaty zamiast śladu.
    Nieznany autor (wiersz sprzed wersjonowania) to wciąż cudza treść.
    """
    if not overwrite:
        return False
    return not same_install(writer_install, my_install)


def iso(value: Any) -> Optional[str]:
    """Znacznik czasu w ISO albo `None` - kolumny czasu wracają z bazy różnie."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    text = str(value).strip()
    return text or None


def stale_detail(
    current_rev: int, writer_name: Optional[str], written_at: Any
) -> Dict[str, Any]:
    """Treść odmowy 409 `DOC_STALE`.

    Pola dodatkowe siedzą W `detail`, bo `main.py` zawija `detail` w kopertę
    `{"error": ...}` - poza nim nie dojechałyby do telefonu.
    `writer_install_is_you` jest zawsze fałszem: własny zapis tego urządzenia
    nigdy nie jest konfliktem (`is_stale_write`), więc gdyby tu był prawdą,
    odmowa w ogóle by nie padła.
    """
    return {
        "code": "DOC_STALE",
        "message": STALE_MESSAGE,
        "doc_rev": int(current_rev or 0),
        "writer_name": (str(writer_name or "").strip() or None),
        "written_at": iso(written_at),
        "writer_install_is_you": False,
    }


def writer_view(
    writer_install: Optional[str],
    writer_judge: Optional[str],
    writer_name: Optional[str],
    my_install: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Autor ostatniej wersji w kształcie dla telefonu - bez cudzej instalacji.

    Surowy identyfikator instalacji innego urządzenia nie ma prawa wyjść
    z serwera: to on przesądza o "to mój zapis". Telefonowi wystarcza
    odpowiedź na jedyne pytanie, jakie zadaje: czy to ja.
    `None`, gdy o autorze nie wiadomo nic (wiersz sprzed wersjonowania).
    """
    judge = str(writer_judge or "").strip()
    name = str(writer_name or "").strip()
    install = str(writer_install or "").strip()
    if not (judge or name or install):
        return None
    return {
        "install_is_you": same_install(install, my_install),
        "judge_id": judge or None,
        "name": name or None,
    }


def conflict_event_key(match_number: str, current_rev: int, my_install: Optional[str]) -> str:
    """Klucz idempotencji wpisu `match.doc_conflict` w dzienniku.

    Telefon z przeterminowaną wersją ponawia zapis w rytmie autozapisu, więc
    bez klucza jedna niezgodność zamieniałaby oś czasu meczu w ścianę
    identycznych odmów. Jeden wpis na klucz meczu, wersję serwera i urządzenie:
    drugie urządzenie w tej samej sytuacji to osobny fakt i też ma być widać.
    """
    who = str(my_install or "").strip() or "-"
    return f"doc_conflict:{str(match_number or '').strip()}:{int(current_rev or 0)}:{who}"


def json_value(raw: Any) -> Any:
    """Kolumna JSON w kształcie, w jakim ją zapisano - niezależnie od sterownika.

    asyncpg pod `databases` potrafi oddać JSON/JSONB surowym NAPISEM (ta sama
    pułapka co w giełdzie meczów). Porównanie treści napisu z obiektem zawsze
    mówiłoby "zmieniono", a napis wstawiony do kolumny JSON zakodowałby się
    drugi raz. Napis nie do sparsowania wraca bez zmian.
    """
    if raw is None or isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return raw


def payload_bytes(value: Any) -> int:
    """Rozmiar bloba po serializacji - do limitu historii."""
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return MAX_HISTORY_BYTES + 1
