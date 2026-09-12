"""Dziennik zdarzeń meczu ProEl: kto, kiedy i co zrobił.

Po co: do tej pory system zbierał tożsamość przy każdym wywołaniu ProEla
(`X-Judge-Id`, `X-Installation-Id`, `X-Actor-Name`) i wyrzucał ją na dwóch
najważniejszych ścieżkach - `POST /proel/` i `PUT /proel/{nr}` nie czytały
aktora, więc założenie, zakończenie i zatwierdzenie meczu były anonimowe.
Na pytanie „kto zamknął ten protokół" nie było odpowiedzi i nie było jej skąd
wziąć, bo dane nie były zapisywane.

Dwie zasady, obie twarde:

1. **Zapis do dziennika nigdy nie może wywrócić operacji, którą opisuje.**
   `log_match_event` łyka wszystko. Protokół jest ważniejszy od swojej
   historii, a dziennik, który potrafi zablokować zakończenie meczu, jest
   gorszy niż brak dziennika.

2. **Aktora czytamy MIĘKKO.** Twarda zależność (`Depends(proel_actor)`)
   zwraca 401 przy braku nagłówków - a stara wersja aplikacji ich nie wysyła.
   Wymuszenie tożsamości na zapisie bloba oznaczałoby ciche gubienie meczów
   prowadzonych ze starszych telefonów.

Odczyt jest wyłącznie dla administratora i stronicuje się KURSOREM po `id`,
nie `OFFSET`-em: dziennik rośnie w trakcie przeglądania, a offset przy
dopisywanym logu gubi i dubluje wiersze.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import exists, func, literal, select

from app.proel_auth import (
    Actor,
    DEVICE_PREFIX,
    header_text,
    is_admin,
    is_synthetic_judge_id,
    proel_actor,
)
from app.proel_admin_guard import proel_admin_guard
from app.proel_fields import UnknownPath, parse_path
from app.proel_lease import _as_aware, now_utc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/journal", tags=["ProEl: dziennik"])


# ─────────────────────────── nazwy zdarzeń ───────────────────────────
#
# JEDNA tablica na cały system - i backend, i panel biorą etykiety stąd.
# W panelu Beacha te same nazwy żyją w dwóch plikach i dawno się rozjechały.

EVENT_LABELS: Dict[str, str] = {
    "match.created": "Założenie meczu",
    "match.live_started": "Start prowadzenia",
    "table.taken_over": "Przejęcie stolika",
    "match.finished": "Zakończenie meczu",
    "match.approved": "Zatwierdzenie protokołu",
    "match.unapproved": "Cofnięcie zatwierdzenia",
    "match.deleted": "Usunięcie zapisu",
    "match.restored": "Przywrócenie zapisu",
    "match.id_conflict": "Odrzucony zapis (inny mecz)",
    # Wersja treści (`app/proel_doc_version.py`) i przeniesienie zapisu
    # szkoleniowego do oficjalnego (`app/proel_promote_rules.py`).
    "match.doc_conflict": "Odrzucony zapis (nowsza wersja na serwerze)",
    "match.overwritten_by_choice": "Nadpisanie wersji z serwera wyborem sędziego",
    "match.promoted": "Przeniesienie do oficjalnego zapisu",
    "field.changed": "Zmiana pól",
    "protocol.pdf_generated": "Wygenerowanie protokołu PDF",
    "zprp.summary_sent": "Wynik skrócony do ZPRP",
    "zprp.full_data_sent": "Pełne dane meczu do ZPRP",
    "zprp.players_sent": "Statystyki zawodników do ZPRP",
    "zprp.officials_sent": "Kary osób towarzyszących do ZPRP",
    "zprp.comment_sent": "Uwagi verte do ZPRP",
    # Wysyłka pełnych danych zaczęła się, ale nie zgłosiła końca. To NIE jest
    # osobne zdarzenie w bazie - powstaje przy odczycie z samego początku serii,
    # gdy zabrakło jej domknięcia (patrz `collapse_full_data_run`).
    "zprp.full_data_running": "Trwa wysyłka pełnych danych",
    "zprp.full_data_stalled": "Przerwana wysyłka pełnych danych",
    "zprp.attachment_sent": "Protokół PDF wysłany do ZPRP",
    # Nieudana próba wysyłki. Dziennik ma odpowiadać na pytanie „czemu dane nie
    # doszły", a nie tylko „kiedy doszły" - bez tego wpisu mecz, którego nie
    # udało się wysłać, wygląda w dzienniku identycznie jak mecz, którego nikt
    # nie próbował wysłać.
    "zprp.send_failed": "Nieudana próba wysyłki do ZPRP",
    "zprp.send_queued": "Wysyłka odłożona do dosyłki",
    # SMS nie idzie do bazy ZPRP, tylko wiadomością na numer z ustaleń
    # rozgrywek - stąd inna rodzina zdarzenia niż `zprp.*`.
    "match.sms_sent": "Zgłoszenie wyniku SMS-em",
    "match.reopened": "Wznowienie meczu",
    # Badania mają własne zdarzenia, a nie „Zmianę pól": administrator pyta
    # „kto potwierdził nr 77 i kiedy", nie „które ścieżki overlaya się zmieniły".
    "exam.confirmed": "Potwierdzenie badań",
    "exam.withdrawn": "Cofnięcie potwierdzenia badań",
    "exam.promoted": "Badania potwierdzone przez ZPRP",
    "exam.rechecked": "Sprawdzenie badań w bazie związku",
    # Podpisy mają własne zdarzenie z tego samego powodu co badania: „Zmiana
    # pól: sędzia 1 - podpis" nie odpowiadała na pytanie „czy protokół jest
    # podpisany i przez kogo".
    "match.signed": "Podpis pod protokołem",
    "match.signature_removed": "Usunięcie podpisu",
    # Raport dodatkowy: samo złożenie PDF-u, nie ptaszek „był raport" w polach.
    "report.submitted": "Złożenie raportu dodatkowego",
}


# ─────────────────────── pola po ludzku ───────────────────────
#
# Dziennik czyta CZŁOWIEK, nie serwer. `post.protocolSent` mówi coś tylko temu,
# kto zna rejestr pól z `proel_fields`; administrator sprawdzający, co się działo
# przy meczu, ma prawo zobaczyć „protokół PDF trafił do załączników".
#
# Tłumaczenie żyje po stronie serwera razem z nazwami zdarzeń - z tego samego
# powodu, dla którego `EVENT_LABELS` nie mieszka w panelu: żeby nie było dwóch
# list, które się rozjadą.

_ROLE_NAMES: Dict[str, str] = {
    "referee1": "sędzia 1",
    "referee2": "sędzia 2",
    "secretary": "sekretarz",
    "timekeeper": "mierzący czas",
    "delegate": "delegat",
    "delegate2": "delegat 2",
}

_LEAF_NAMES: Dict[str, str] = {
    "fullName": "nazwisko",
    "city": "miejscowość",
    "signature": "podpis",
    "function": "funkcja",
    "license": "licencja",
}

_TEAM_NAMES: Dict[str, str] = {"host": "gospodarzy", "guest": "gości"}

#: Medyk ma własną gałąź rejestru (jedna osoba, bez roli w kluczu). Bez tych
#: nazw `medic.signature` wracało do panelu jako surowa ścieżka techniczna.
_MEDIC_NAMES: Dict[str, str] = {
    "fullName": "nazwisko",
    "number": "numer",
    "role": "rola",
    "signature": "podpis",
}

#: Pola „po meczu" - klucze z `_POST_EXTRAS` w `app/proel_fields.py`.
_POST_NAMES: Dict[str, str] = {
    "spectatorsCount": "liczba widzów",
    "venueCapacity": "pojemność hali",
    "eventRegistration": "rejestracja zawodów",
    "detailedRefereeNotes": "uwagi verte (zaznaczenie)",
    "extraReport": "dodatkowy raport",
    "notesText": "treść uwag sędziów",
    "shortResultSent": "znacznik: wynik skrócony w bazie ZPRP",
    "fullDataSent": "znacznik: pełne dane w bazie ZPRP",
    "protocolSent": "znacznik: protokół PDF w załącznikach",
    "smsSent": "znacznik: zgłoszenie SMS-em otwarte",
}

_CFG_NAMES: Dict[str, str] = {
    "referee1": "sędzia 1",
    "referee2": "sędzia 2",
    "delegate": "delegat",
    "delegate2": "delegat 2",
    "timekeeper": "mierzący czas",
    "secretary": "sekretarz",
    "venueAddress": "adres hali",
}

_EXTRAS_NAMES: Dict[str, str] = {
    "matchDate": "data meczu",
    "matchTime": "godzina meczu",
}

#: Znaczniki wysyłki opisujemy zdaniem, nie nazwą pola - bo to jedyne „pola",
#: których zmiana jest sama w sobie zdarzeniem, a nie poprawką w rubryce.
_MARK_SENTENCES: Dict[str, str] = {
    "post.shortResultSent": "wynik skrócony trafił do bazy ZPRP",
    "post.fullDataSent": "pełne dane meczu trafiły do bazy ZPRP",
    "post.protocolSent": "protokół PDF trafił do załączników meczu",
    "post.smsSent": "zgłoszenie wyniku poszło SMS-em",
}

# Znacznik zadania pomeczowego nie jest zwykłą zmianą rubryki. Powstaje dopiero
# po potwierdzonym sukcesie wysyłki, więc w dzienniku ma być samodzielnym
# zdarzeniem, na które administrator może odpowiedzieć „kto i kiedy".
_SENT_EVENT_BY_PATH: Dict[str, str] = {
    "post.shortResultSent": "zprp.summary_sent",
    "post.fullDataSent": "zprp.full_data_sent",
    "post.protocolSent": "zprp.attachment_sent",
    "post.smsSent": "match.sms_sent",
}


def is_signature_path(path: Any) -> bool:
    """Czy ta ścieżka rejestru pól jest podpisem pod protokołem."""
    parts = str(path or "").split(".")
    if len(parts) == 3 and parts[0] == "sig" and parts[1] == "team":
        return True
    if len(parts) == 3 and parts[0] == "official" and parts[2] == "signature":
        return True
    return len(parts) == 2 and parts[0] == "medic" and parts[1] == "signature"


def signature_who(path: Any) -> str:
    """Kto się podpisał: „sędzia 1", „drużyna gospodarzy", „medyk"."""
    parts = str(path or "").split(".")
    if parts[0] == "sig" and len(parts) == 3:
        return f"drużyna {_TEAM_NAMES.get(parts[2], parts[2])}"
    if parts[0] == "official" and len(parts) == 3:
        return _ROLE_NAMES.get(parts[1], parts[1])
    return "medyk"


def describe_field(path: str) -> str:
    """Ścieżka pola z `proel_fields` jako kawałek polskiego zdania."""
    raw = str(path or "").strip()
    if not raw:
        return ""

    parts = raw.split(".")
    head = parts[0]

    if raw in _MARK_SENTENCES:
        return _MARK_SENTENCES[raw]

    if head == "post" and len(parts) == 2:
        return _POST_NAMES.get(parts[1], parts[1])

    if head == "cfg" and len(parts) == 2:
        return _CFG_NAMES.get(parts[1], parts[1])

    if head == "extras" and len(parts) == 2:
        return _EXTRAS_NAMES.get(parts[1], parts[1])

    if head == "sig" and len(parts) == 3 and parts[1] == "team":
        return f"podpis {_TEAM_NAMES.get(parts[2], parts[2])}"

    if head == "official" and len(parts) == 3:
        role = _ROLE_NAMES.get(parts[1], parts[1])
        return f"{role} - {_LEAF_NAMES.get(parts[2], parts[2])}"

    if head == "companion" and len(parts) == 4:
        team = _TEAM_NAMES.get(parts[1], parts[1])
        leaf = _LEAF_NAMES.get(parts[3], parts[3])
        return f"osoba towarzysząca {parts[2]} {team} - {leaf}"

    if head == "medic" and len(parts) == 2:
        return f"medyk - {_MEDIC_NAMES.get(parts[1], _LEAF_NAMES.get(parts[1], parts[1]))}"

    if head == "exam" and len(parts) == 3:
        team = _TEAM_NAMES.get(parts[1], parts[1])
        number = parts[2].lstrip("#")
        return f"badania zawodnika nr {number} ({team})"

    # Nieznana ścieżka wraca taka, jaka jest - lepiej techniczna prawda niż
    # ładne kłamstwo. To także sygnał, że doszło pole bez nazwy.
    return raw


def _fields_word(n: int) -> str:
    """„pole" / „pola" / „pól" - odmiana po polsku."""
    if n == 1:
        return "pole"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return "pola"
    return "pól"


def _entries_word(n: int) -> str:
    """„opis" / „opisy" / „opisów" - pozycje raportu dodatkowego."""
    if n == 1:
        return "opis"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return "opisy"
    return "opisów"


def _join_fields(paths: List[str], limit: int = 3) -> str:
    named = [describe_field(p) for p in paths if str(p or "").strip()]
    if not named:
        return ""
    if len(named) <= limit:
        return ", ".join(named)
    rest = len(named) - limit
    tail = "pole" if rest == 1 else ("pola" if 2 <= rest <= 4 else "pól")
    return f"{', '.join(named[:limit])} i {rest} {tail} więcej"


#: Rodzaje raportu dodatkowego - klucz `kind` z `app/extra_reports.py`.
_REPORT_KINDS: Dict[str, str] = {
    "referee": "raport sędziów",
    "delegate": "raport delegata",
}

#: Skąd przyszło potwierdzenie - dziennik ma odpowiadać na „gdzie to zrobiono".
_EXAM_SOURCE_NOTES: Dict[str, str] = {
    "config": "w ekranie konfiguracji",
    "sheet": "w arkuszu „Sprawdź badania”",
}


def exam_players_sentence(players: Any) -> str:
    """„nr 77 GAKIDOVA Ivana (gospodarzy), nr 3 NOWAK Anna (gości)"."""
    parts: List[str] = []
    for raw in players or []:
        if not isinstance(raw, dict):
            continue
        number = str(raw.get("number") or "").strip()
        name = str(raw.get("name") or "").strip()
        team = _TEAM_NAMES.get(str(raw.get("team") or ""), "")
        who = " ".join(x for x in (f"nr {number}" if number else "", name) if x)
        if team:
            who = f"{who} ({team})" if who else team
        if who:
            parts.append(who)
    return ", ".join(parts)


def signature_events_from_ops(
    changed: List[Tuple[str, Any]],
) -> List[Tuple[str, Dict[str, Any]]]:
    """Przyjęte operacje patcha -> zdarzenia podpisów, albo `[]`, gdy to nie podpisy.

    Patch mieszany (podpis i zwykłe pole razem) zostaje „Zmianą pól" - ta sama
    zasada co przy badaniach: lepsza jedna ogólna prawda niż dwa wpisy, z
    których jeden gubi część.

    W szczegółach NIE MA samego podpisu. Obrazek waży kilkadziesiąt kilobajtów
    i nie jest informacją dla administratora; dziennik niesie „kto" i „czy
    złożony", bo tylko o to ktokolwiek pyta.
    """
    signed: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    for path, value in changed:
        if not is_signature_path(path):
            return []
        entry = {"path": str(path), "who": signature_who(path)}
        (signed if str(value or "").strip() else removed).append(entry)
    out: List[Tuple[str, Dict[str, Any]]] = []
    if signed:
        out.append(("match.signed", {"signatures": signed}))
    if removed:
        out.append(("match.signature_removed", {"signatures": removed}))
    return out


def _signature_who_list(details: Optional[Dict[str, Any]]) -> str:
    """„sędzia 1, drużyna gospodarzy" - z nowych szczegółów albo ze ścieżek."""
    d = details or {}
    names: List[str] = []
    for raw in d.get("signatures") or []:
        if isinstance(raw, dict):
            who = str(raw.get("who") or "").strip() or signature_who(raw.get("path"))
            if who:
                names.append(who)
    if not names:
        # Wiersze sprzed tego zdarzenia mają same ścieżki - patrz `_effective_event`.
        names = [signature_who(p) for p in (d.get("paths") or []) if is_signature_path(p)]
    seen: List[str] = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return ", ".join(seen)


def exam_events_from_ops(changed: List[Tuple[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    """Przyjęte operacje patcha -> zdarzenia badań, albo `[]`, gdy to nie same badania.

    Patch mieszany (badania i podpis w jednym) zostaje zwykłą „Zmianą pól" -
    lepsza jedna ogólna prawda niż dwa wpisy, z których jeden gubi część.
    """
    confirmed: List[Dict[str, Any]] = []
    withdrawn: List[Dict[str, Any]] = []
    for path, value in changed:
        try:
            spec, params = parse_path(str(path))
        except UnknownPath:
            return []
        if spec.name != "exam":
            return []
        v = value if isinstance(value, dict) else {}
        player = {
            "team": params.get("team", ""),
            "number": params.get("num", ""),
            "name": str(v.get("name") or "").strip(),
        }
        mark = str(v.get("mark") or "none").strip().lower()
        (withdrawn if mark == "none" else confirmed).append(player)
    out: List[Tuple[str, Dict[str, Any]]] = []
    if confirmed:
        out.append(("exam.confirmed", {"players": confirmed, "source": "sheet"}))
    if withdrawn:
        out.append(("exam.withdrawn", {"players": withdrawn, "source": "sheet"}))
    return out


_STATUS_NAMES: Dict[str, str] = {
    "in_progress": "w toku",
    "finished": "zakończony",
    "approved": "zatwierdzony",
    "deleted": "usunięty",
}


#: Co próbowaliśmy wysłać - po ludzku, w mianowniku.
_SEND_BLOCK_NAMES: Dict[str, str] = {
    "full": "pełnych danych meczu",
    "summary": "wyniku skróconego",
    "players": "statystyk zawodników",
    "officials": "kar osób towarzyszących",
    "comment": "uwag verte",
    "attachment": "protokołu PDF",
    "numbers": "numerów koszulek",
}


#: Czym wykonano wysyłkę. Dwie drogi, dwie zupełnie różne odpowiedzi na
#: reklamację - oficjalne API pisze pojedyncze pola, formularz wypełnia rubryki
#: protokołu na stronie związku POŚWIADCZENIAMI konkretnego konta.
_ROUTE_NAMES: Dict[str, str] = {
    "official": "oficjalnym API",
    "legacy": "drogą awaryjną (formularz na baza.zprp.pl)",
    "mixed": "częściowo oficjalnym API, częściowo formularzem",
}


def send_context_sentence(details: Optional[Dict[str, Any]]) -> str:
    """Okoliczności wysyłki: czym, czyim kontem i po ilu podejściach.

    Dziennik odpowiada na pytanie „kto to zrobił" nagłówkiem wiersza (`actor`),
    ale przy wysyłce do ZPRP samo nazwisko nie wystarcza: czynność wykonuje
    OSOBA, a przepuszcza ją KONTO - i przy podniesionych uprawnieniach to bywają
    dwie różne tożsamości. Administrator spoza obsady otwiera sesję numerem
    sędziego prowadzącego, bo własnym numerem baza związku by go nie wpuściła.
    To musi być w dzienniku napisane wprost, inaczej wpis mówi nieprawdę o tym,
    czyim numerem podpisano zapis po tamtej stronie.
    """
    d = details or {}
    bits: List[str] = []

    route = _ROUTE_NAMES.get(str(d.get("via") or "").strip(), "")
    if route:
        bits.append(route)

    # Konto formularza. Podajemy je TYLKO przy drodze awaryjnej, bo tylko tam
    # w ogóle padło hasło - oficjalne API autoryzuje samym numerem.
    account = str(d.get("zprp_account") or "").strip()
    if account:
        bits.append(f"kontem {account}")

    judge = str(d.get("zprp_judge") or "").strip()
    on_behalf = str(d.get("on_behalf") or "").strip()
    if judge and on_behalf:
        bits.append(f"numerem sędziego {judge} ({on_behalf})")
    elif judge:
        bits.append(f"numerem sędziego {judge}")
    elif on_behalf:
        bits.append(f"numerem sędziego {on_behalf}")

    if d.get("admin") is True:
        bits.append("dostęp z uprawnień administratora")

    attempts = d.get("attempts")
    if isinstance(attempts, int) and attempts > 1:
        bits.append(f"po {attempts} podejściach")

    return ", ".join(bits)


def send_attempt_sentence(event: str, details: Optional[Dict[str, Any]]) -> str:
    """Jedno zdanie o nieudanej próbie wysyłki.

    Administrator czyta dziennik, żeby odpowiedzieć sędziemu na pytanie „czemu
    moje dane nie doszły". Odpowiedź musi być w tym jednym wierszu, a nie w
    rozwiniętych szczegółach - stąd numer próby, ile jednak przeszło i DOSŁOWNA
    odpowiedź związku, gdy jakaś przyszła. To ostatnie jest tu najważniejsze:
    bez cytatu z ZPRP każda odmowa wygląda tak samo.
    """
    d = details or {}
    what = _SEND_BLOCK_NAMES.get(str(d.get("what") or ""), "danych meczu")

    head = (
        f"Wysyłka {what} odłożona do dosyłki"
        if str(event) == "zprp.send_queued"
        else f"Nie udało się wysłać {what}"
    )

    bits: List[str] = []
    attempt = d.get("attempt")
    of = d.get("of")
    if isinstance(attempt, int) and attempt > 0:
        bits.append(f"próba {attempt} z {of}" if isinstance(of, int) and of > 0 else f"próba {attempt}")
    sent = d.get("sent")
    if isinstance(sent, int) and sent > 0:
        bits.append(f"zapisano {sent}")
    left = d.get("left")
    if isinstance(left, int) and left > 0:
        bits.append(f"bez zapisu {left}")

    reason = str(d.get("reason") or "").strip()
    upstream = str(d.get("upstream") or "").strip()
    tail = ""
    if upstream:
        tail = f' Odpowiedź ZPRP: "{upstream[:200]}".'
    elif reason:
        tail = f" {reason[:200]}"

    # Okoliczności doklejamy do NAWIASU, a nie na koniec: cytat z ZPRP ma
    # zostać ostatnią rzeczą w wierszu, bo to on rozstrzyga, co dalej robić.
    context = send_context_sentence(d)
    if context:
        bits.append(context)

    return (head + (f" ({', '.join(bits)})" if bits else "") + "." + tail).strip()


def _with_context(sentence: str, details: Optional[Dict[str, Any]]) -> str:
    """Zdanie o wysyłce plus jej okoliczności, gdy aplikacja je podała.

    Wiersze sprzed tej zmiany okoliczności nie mają i mają wyglądać dokładnie
    tak, jak wyglądały - dziennik jest księgą, a nie widokiem do przepisania.
    """
    context = send_context_sentence(details)
    return f"{sentence} - {context}" if context else sentence


def event_summary(event: str, details: Optional[Dict[str, Any]]) -> str:
    """Jedno zdanie o tym, co się właściwie stało.

    Podtytuł wiersza w dzienniku. Wcześniej stała tu surowa treść `details_json`
    - administrator oglądał `{"paths":["post.protocolSent"],"rev":313}` i musiał
    sam zgadnąć, co to znaczy.
    """
    d = details or {}
    ev = str(event or "")

    if ev == "field.changed":
        paths = [str(x) for x in (d.get("paths") or []) if str(x or "").strip()]
        if len(paths) == 1 and paths[0] in _MARK_SENTENCES:
            # Znacznik wysyłki niesie całą treść sam - „zmieniono" brzmiałoby
            # tu jak poprawka w rubryce, a to jest fakt z przebiegu meczu.
            sentence = _MARK_SENTENCES[paths[0]]
            # Wielka litera TYLKO pierwsza - `capitalize()` zjadałoby skróty
            # w środku zdania („PDF" na „pdf").
            return _with_context(sentence[:1].upper() + sentence[1:], d)
        joined = _join_fields(paths)
        if not joined:
            return ""
        # Liczba PRZED wyliczeniem: wiersz scalony z kilkunastu poprawek ma
        # powiedzieć wprost, ile ich było, zanim urwie listę na trzeciej.
        if len(paths) > 1:
            return f"Zmieniono {len(paths)} {_fields_word(len(paths))}: {joined}"
        return f"Zmieniono: {joined}"

    if ev == "table.taken_over":
        who = str(d.get("from") or "").strip()
        return f"Prowadzenie odebrane urządzeniu: {who}" if who else "Prowadzenie przeszło na inne urządzenie"

    if ev == "match.id_conflict":
        return (
            f"W bazie leży mecz {d.get('known') or '?'}, "
            f"a przyszedł zapis meczu {d.get('incoming') or '?'}"
        )

    # Trzy zdarzenia wersji treści mają własne zdania PRZED ogólną gałęzią
    # statusu na końcu: niosą `from`/`to` z kluczami meczów, a tamta czytałaby
    # je jako statusy i oddawała pusty podtytuł.
    if ev == "match.doc_conflict":
        writer = str(d.get("writer_name") or "").strip() or "inne urządzenie"
        return (
            f"Zapis zbudowany na wersji {d.get('base_rev', '?')}, a na serwerze "
            f"leży wersja {d.get('doc_rev', '?')} ({writer})"
        )

    if ev == "match.overwritten_by_choice":
        writer = str(d.get("replaced_writer") or "").strip() or "nieznany autor"
        return (
            f"Wersja {d.get('replaced_rev', '?')} z serwera ({writer}) odłożona "
            "do historii i zastąpiona wersją z telefonu"
        )

    if ev == "match.promoted":
        return (
            f"Zapis szkoleniowy {d.get('from') or '?'} przeniesiony do "
            f"oficjalnego meczu {d.get('to') or '?'}"
        )

    if ev == "protocol.pdf_generated":
        code = str(d.get("audit_code") or "").strip()
        return f"Kod dziennika protokołów: {code}" if code else ""

    if ev == "exam.rechecked":
        # Dowód na to, że ręczny ptaszek postawiono PO sprawdzeniu.
        who = exam_players_sentence(d.get("players"))
        # Godzina od telefonu (czas hali); ISO z bloba to tylko zapas.
        at = str(d.get("at") or "")
        clock = str(d.get("clock") or "").strip() or (
            at[11:16] if len(at) >= 16 else ""
        )
        head = "Baza związku nadal bez badań"
        sentence = f"{head}: {who}" if who else head
        return f"{sentence} (sprawdzono {clock})" if clock else sentence

    if ev in ("exam.confirmed", "exam.withdrawn", "exam.promoted"):
        who = exam_players_sentence(d.get("players"))
        if ev == "exam.promoted":
            head = "Baza związku potwierdziła badania"
            tail = " - ręczny znacznik zastąpiony"
            return f"{head}: {who}{tail}" if who else f"{head}{tail}"
        head = "Potwierdzono ręcznie" if ev == "exam.confirmed" else "Cofnięto potwierdzenie"
        note = _EXAM_SOURCE_NOTES.get(str(d.get("source") or ""), "")
        sentence = f"{head}: {who}" if who else f"{head} badania"
        return f"{sentence} - {note}" if note else sentence

    if ev in ("match.signed", "match.signature_removed"):
        who = _signature_who_list(d)
        if not d.get("signatures"):
            # Wiersz sprzed tego zdarzenia niesie same ścieżki, bez wartości -
            # nie wiemy, czy podpis doszedł, czy zniknął, więc nie zgadujemy.
            return f"Podpis: {who}" if who else "Podpis pod protokołem"
        many = "," in who
        if ev == "match.signed":
            head = "Złożono podpisy" if many else "Złożono podpis"
        else:
            head = "Usunięto podpisy" if many else "Usunięto podpis"
        return f"{head}: {who}" if who else head

    if ev == "report.submitted":
        kind = _REPORT_KINDS.get(str(d.get("kind") or ""), "")
        head = f"Złożono {kind}" if kind else "Złożono raport dodatkowy"
        try:
            entries = int(d.get("entries") or 0)
        except (TypeError, ValueError):
            entries = 0
        return f"{head} ({entries} {_entries_word(entries)})" if entries else head

    if ev in ("zprp.send_failed", "zprp.send_queued"):
        return send_attempt_sentence(ev, d)

    if ev in ("zprp.full_data_running", "zprp.full_data_stalled"):
        # Wiersz powstał z POCZĄTKU serii, więc liczba pod nim mówi, ile żądań
        # zdążyło dojść - i to jest cała odpowiedź na pytanie „ile z tego
        # weszło do bazy związku, zanim się urwało".
        parts = int(d.get("merged") or 1)
        many = f"{parts} zapisów doszło" if parts > 1 else "jeden zapis doszedł"
        if ev == "zprp.full_data_running":
            return f"Wysyłka w toku - {many}, czekamy na potwierdzenie końca"
        return (
            f"Wysyłka nie zgłosiła końca - {many}, "
            "reszty danych może nie być w bazie ZPRP"
        )

    if ev in _SENT_EVENT_BY_PATH.values():
        paths = [str(x) for x in (d.get("paths") or []) if str(x or "").strip()]
        sentence = _MARK_SENTENCES.get(paths[0], "") if len(paths) == 1 else ""
        if not sentence:
            # Wiersz bez ścieżki (starszy klient) - samo zdarzenie już mówi, co
            # poszło, więc zostaje sam kontekst zamiast pustki.
            return send_context_sentence(d)
        return _with_context(sentence[:1].upper() + sentence[1:], d)

    frm = _STATUS_NAMES.get(str(d.get("from") or ""), "")
    to = _STATUS_NAMES.get(str(d.get("to") or ""), "")
    if frm and to:
        return f"Stan meczu: {frm} → {to}"
    if to:
        return f"Stan meczu: {to}"
    return ""


def client_ip(request: Optional[Request], forwarded: Optional[str] = None) -> str:
    """Adres klienta zza proxy Railway - ten sam odczyt co w `proel_zprp`."""
    if forwarded:
        first = str(forwarded).split(",")[0].strip()
        if first:
            return first[:64]
    try:
        return (request.client.host if request and request.client else "")[:64]
    except Exception:
        return ""


async def soft_actor(
    x_judge_id: Optional[str] = None,
    x_installation_id: Optional[str] = None,
    x_actor_name: Optional[str] = None,
    authorization: Optional[str] = None,
    x_elevation: Optional[str] = None,
) -> Optional[Actor]:
    """Aktor bez rzucania 401.

    Wspólny resolver dla dziennika i PDF: brak nagłówków to normalna sytuacja
    (stara aplikacja, gość bez powiadomień), a nie błąd.
    Zwraca `None`, gdy nie ma czego zapisać.
    """
    judge_id = str(x_judge_id or "").strip()
    install = str(x_installation_id or "").strip()
    if (isinstance(authorization, str) and authorization.strip()) or (
        isinstance(x_elevation, str) and x_elevation.strip()
    ):
        try:
            return await proel_actor(
                x_judge_id=x_judge_id,
                x_installation_id=x_installation_id,
                x_actor_name=x_actor_name,
                authorization=authorization,
                x_elevation=x_elevation,
            )
        except Exception:
            # Stare zapisy nadal mogą działać bez sesji, ale brak dowodu
            # aktualnego konta nie może oznaczać podpisu poprzedniego sędziego.
            return Actor(judge_id=f"{DEVICE_PREFIX}{install}", installation_id=install) if install else None
    if not judge_id and not install:
        return None

    actor = Actor(
        judge_id=judge_id,
        installation_id=install,
        name=header_text(x_actor_name),
    )
    # `proel:` / `inst:` to nie numer sędziego - rejestr urządzeń nie ma go z
    # czym zestawić, a zapytanie i tak skończyłoby się na `verified = False`.
    if not judge_id or not install or is_synthetic_judge_id(judge_id):
        return actor

    try:
        from app.db import database, push_tokens

        row = await database.fetch_one(
            select(push_tokens).where(push_tokens.c.installation_id == install)
        )
        if row is not None:
            known = str(row["judge_id"] or "").strip()
            actor.verified = bool(known) and known == judge_id
    except Exception:
        # Brak potwierdzenia to nie to samo co oszustwo - zapisujemy jako
        # niezweryfikowanego i idziemy dalej.
        pass
    return actor


async def log_match_event(
    *,
    match_number: str,
    event: str,
    actor: Optional[Actor] = None,
    zprp_match_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    event_key: Optional[str] = None,
    app_version: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Dopisuje zdarzenie. NIGDY nie rzuca.

    `event_key` jest unikalny w tabeli - dzięki temu bicie serca leasingu co
    25 s daje jeden wpis, a ponowienie z outboxa nie dopisuje drugiego.
    Kolizja klucza jest normalnym wynikiem, nie błędem.
    """
    number = str(match_number or "").strip()
    if not number or not event:
        return

    try:
        from app.db import database, proel_activity_log

        if event_key:
            exists = await database.fetch_one(
                select(proel_activity_log.c.id).where(
                    proel_activity_log.c.event_key == event_key
                )
            )
            if exists is not None:
                return

        await database.execute(
            proel_activity_log.insert().values(
                match_number=number,
                zprp_match_id=(str(zprp_match_id).strip() or None)
                if zprp_match_id
                else None,
                event=str(event),
                actor_judge_id=(actor.judge_id or None) if actor else None,
                actor_name=(actor.name or None) if actor else None,
                actor_install=(actor.installation_id or None) if actor else None,
                actor_verified=bool(actor.verified) if actor else False,
                details_json=details or None,
                app_version=(str(app_version).strip()[:32] or None)
                if app_version
                else None,
                client_ip=(str(ip).strip()[:64] or None) if ip else None,
                event_key=event_key,
            )
        )
    except Exception:
        # Wpis do dziennika nie ma prawa wywrócić operacji, którą opisuje.
        logger.debug("proel journal: nie zapisano %s dla %s", event, number, exc_info=True)


# ─────────────────────────── odczyt (admin) ───────────────────────────

_protocol_pdf_backfill_done = False


async def _backfill_protocol_pdf_events() -> None:
    """Przenosi wcześniejsze generowania PDF na wspólną oś czasu meczu.

    Generator od dawna zapisuje dokładny `protocol_audit`, więc utrata tej
    historii tylko dlatego, że wspólny dziennik powstał później, byłaby
    sztuczna. Klucz `protocol-pdf:<kod>` zapewnia idempotencję także przy
    restarcie procesu. Funkcja jest best-effort tak samo jak sam dziennik.
    """
    global _protocol_pdf_backfill_done
    if _protocol_pdf_backfill_done:
        return

    try:
        from app.db import database, proel_activity_log, protocol_audit

        event_key = literal("protocol-pdf:") + protocol_audit.c.code
        rows = await database.fetch_all(
            select(protocol_audit).where(
                protocol_audit.c.match_number.isnot(None),
                protocol_audit.c.match_number != "",
                ~exists(
                    select(proel_activity_log.c.id).where(
                        proel_activity_log.c.event_key == event_key
                    )
                ),
            )
        )
        had_failure = False
        for row in rows:
            try:
                await database.execute(
                    proel_activity_log.insert().values(
                        match_number=str(row["match_number"] or "").strip(),
                        zprp_match_id=row["match_id"],
                        event="protocol.pdf_generated",
                        actor_judge_id=row["judge_id"],
                        actor_name=row["actor_name"],
                        actor_install=row["installation_id"],
                        actor_verified=bool(row["verified"]),
                        details_json={"audit_code": row["code"]},
                        app_version=row["app_version"],
                        client_ip=row["client_ip"],
                        event_key=f"protocol-pdf:{row['code']}",
                        created_at=row["created_at"],
                    )
                )
            except Exception:
                had_failure = True
                # Równoległe otwarcie panelu może wygrać wyścig o UNIQUE;
                # pojedynczy taki wiersz nie może przerwać reszty migracji.
                logger.debug(
                    "proel journal: pominięto backfill PDF %s",
                    row["code"],
                    exc_info=True,
                )
        # Przy realnej awarii ponowimy brakujące wiersze przy kolejnym odczycie.
        # Kolizja UNIQUE po równoległym odczycie także jest bezpieczna: następne
        # zapytanie nie wybierze już wstawionego przez drugi proces kodu.
        _protocol_pdf_backfill_done = not had_failure
    except Exception:
        logger.debug("proel journal: backfill PDF nieudany", exc_info=True)


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "FORBIDDEN",
                "message": "Dziennik meczów jest dostępny tylko dla administratora.",
            },
        )


#: Żądania, z których składa się JEDNA wysyłka pełnych danych meczu.
#
# Każde z nich zapisuje serwer w chwili, gdy je przepuszcza do ZPRP - i to jest
# POCZĄTEK serii, niezależny od tego, czy telefon dożyje jej końca. Koniec
# zgłasza aplikacja osobno (`POST /proel/zprp/full-data-done`), bo po żadnym
# pojedynczym żądaniu nie da się poznać, że było ostatnie: osoby towarzyszące
# bywa że nie idą wcale, a uwagi bez zmian nie wychodzą z telefonu.
_FULL_DATA_PARTS = ("zprp.players_sent", "zprp.officials_sent", "zprp.comment_sent")


def _effective_event(event: str, details: Optional[Dict[str, Any]]) -> str:
    """Nazwa zdarzenia poprawiona o to, co widać w szczegółach.

    Do niedawna zdarzenie wybierał sam status DOCELOWY, więc cofnięcie
    zatwierdzenia (z „approved" do „finished") zapisywało się jako zwykłe
    zakończenie meczu. Emiter jest już naprawiony, ale wiersze sprzed poprawki
    leżą w bazie - i to one opisują mecze, o które ktoś zapyta. Prostujemy je
    przy ODCZYCIE, bo dziennik jest księgą: wpisów się nie przepisuje.
    """
    d = details or {}
    if str(event) == "field.changed":
        paths = [str(x) for x in (d.get("paths") or []) if str(x or "").strip()]
        if len(paths) == 1 and paths[0] in _SENT_EVENT_BY_PATH:
            # Prostujemy także wpisy już istniejące w bazie. Dziennik jest
            # niezmienny, więc nie robimy migracji historycznych wierszy.
            return _SENT_EVENT_BY_PATH[paths[0]]
        # Podpisy zebrane przed tą zmianą leżą w bazie jako zwykła „Zmiana
        # pól". Prostujemy je przy odczycie tak samo jak znaczniki wysyłki -
        # administrator pyta „czy protokół jest podpisany", nie „które ścieżki
        # overlaya się zmieniły".
        if paths and all(is_signature_path(p) for p in paths):
            return "match.signed"
    if str(event) == "match.finished" and str(d.get("from") or "") == "approved":
        return "match.unapproved"
    # Początek serii bez jej końca - znacznik dokłada `collapse_full_data_run`
    # przy odczycie, bo dopiero wtedy widać, czy koniec kiedykolwiek przyszedł.
    if str(event) in _FULL_DATA_PARTS:
        if d.get("stalled"):
            return "zprp.full_data_stalled"
        if d.get("running"):
            return "zprp.full_data_running"
    return str(event or "")


#: Ile czasu może dzielić dwie zmiany pól, żeby dziennik uznał je za jedną pracę.
#
# Formularz wysyła KAŻDE pole osobno (patrz kolejka w aplikacji), więc wpisanie
# osoby towarzyszącej to trzy wiersze, a skład sztabu - kilkanaście. Panel
# pokazywał ścianę wpisów „Zmieniono: osoba towarzysząca B gości - licencja",
# przez którą nie było widać ani podpisów, ani wysyłek.
_FIELD_MERGE_WINDOW_S = 300


def _actor_key(row: Dict[str, Any]) -> Tuple[str, str]:
    return (str(row.get("actor_judge_id") or ""), str(row.get("actor_install") or ""))


def _gap_seconds(newer: Any, older: Any) -> Optional[float]:
    # `_as_aware` z jednego powodu: Postgres oddaje czas ze strefą, a SQLite
    # w testach bez niej. Odejmowanie takiej pary rzuca TypeError, a wtedy
    # „nie wiem, ile minęło" udawałoby „minęło za dużo".
    try:
        return float((_as_aware(newer) - _as_aware(older)).total_seconds())
    except Exception:
        return None


#: Wysyłki, które mogą trafić do dziennika DWA razy: raz od serwera w chwili
#: wysyłania (`app/proel_send_journal.py`), raz ze znacznika zapisanego przez
#: telefon po sukcesie. To jest ta sama czynność, więc w panelu ma być jednym
#: wierszem - zostaje ten ze znacznika, bo niesie okoliczności („czyim kontem,
#: po ilu podejściach").
_SEND_EVENTS = set(_SENT_EVENT_BY_PATH.values()) | {
    "zprp.players_sent",
    "zprp.officials_sent",
    "zprp.comment_sent",
}
_SEND_DEDUP_WINDOW_S = 900


def collapse_duplicate_sends(
    rows: Sequence[Any],
    window_s: int = _SEND_DEDUP_WINDOW_S,
) -> List[Dict[str, Any]]:
    """Dwa zapisy tej samej wysyłki -> jeden wiersz.

    Powtórna wysyłka po dłuższej chwili zostaje osobnym wierszem: okno jest
    krótkie z rozmysłu, bo „wysłałem jeszcze raz po poprawce" to inny fakt niż
    „ta sama wysyłka zapisana z dwóch stron".
    """
    out: List[Dict[str, Any]] = []
    kept: Dict[str, Dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        details = dict(row.get("details_json") or {})
        row["details_json"] = details
        event = _effective_event(str(row.get("event") or ""), details)
        if event in _SEND_EVENTS:
            prev = kept.get(event)
            if prev is not None:
                gap = _gap_seconds(prev.get("created_at"), row.get("created_at"))
                if gap is not None and 0 <= gap <= window_s:
                    prev_details = prev["details_json"]
                    prev_details["merged"] = int(prev_details.get("merged") or 1) + 1
                    continue
            kept[event] = row
        out.append(row)
    return out


#: Jak długo po pierwszym żądaniu serii może przyjść jej koniec.
#
# Pełne dane to kilkanaście żądań plus ponowienia (`FULL_SEND_ATTEMPTS`), a
# między seriami są przerwy - pół godziny mieści najdłuższą realną wysyłkę
# razem z nimi.
_FULL_DATA_WINDOW_S = 1800
#: Dopóki tyle nie minie, brak końca znaczy „jeszcze trwa", nie „przerwane".
_FULL_DATA_GRACE_S = 600


def _absorb_row(host: Dict[str, Any], row: Dict[str, Any]) -> None:
    """Wciąga wiersz w inny: liczba surowych wpisów i godzina najstarszego."""
    details = host["details_json"]
    details["merged"] = int(details.get("merged") or 1) + 1
    oldest = details.get("_oldest_at") or host.get("created_at")
    mine = row.get("created_at")
    if mine is not None and (oldest is None or mine < oldest):
        oldest = mine
    details["_oldest_at"] = oldest


def collapse_full_data_run(
    rows: Sequence[Any],
    window_s: int = _FULL_DATA_WINDOW_S,
    grace_s: int = _FULL_DATA_GRACE_S,
    now: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Seria „Zapisz pełne dane meczu" -> JEDEN wiersz.

    Administrator pyta „czy pełne dane poszły", a dziennik odpowiadał na to
    czterema wierszami pod rząd: statystyki zawodników, kary osób
    towarzyszących, uwagi verte i dopiero znacznik z telefonu. Składamy je przy
    ODCZYCIE (surowe wpisy zostają w bazie) w jeden z dwóch wyników:

      • jest koniec serii -> zostaje wiersz końca, a części wsiąkają w niego
        jako `merged` i `since`,
      • nie ma końca -> zostaje POCZĄTEK serii, opisany jako przesyłanie
        przerwane (albo trwające, gdy zaczęło się przed chwilą).

    Ograniczenie świadome: wiersze przychodzą stronami, więc seria rozcięta
    granicą strony zostaje na tej starszej pokazana jako przerwana. Okno jest
    krótsze od strony dziennika, więc zdarza się to rzadko, a pomyłka idzie w
    stronę ostrożną - „sprawdź" zamiast „na pewno doszło".
    """
    prepared: List[Dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        row["details_json"] = dict(row.get("details_json") or {})
        prepared.append(row)

    def event_of(row: Dict[str, Any]) -> str:
        return str(row.get("event") or "")

    def match_of(row: Dict[str, Any]) -> str:
        return str(row.get("zprp_match_id") or row.get("match_number") or "")

    ends = [r for r in prepared if event_of(r) == "zprp.full_data_sent"]

    orphans: Dict[str, List[Dict[str, Any]]] = {}
    kept: List[Dict[str, Any]] = []
    for row in prepared:
        if event_of(row) not in _FULL_DATA_PARTS:
            kept.append(row)
            continue
        host = None
        for end in ends:
            if match_of(end) != match_of(row):
                continue
            # Koniec jest MŁODSZY od swoich części - ujemny odstęp znaczy, że
            # to koniec poprzedniej wysyłki, a nie tej.
            gap = _gap_seconds(end.get("created_at"), row.get("created_at"))
            if gap is not None and 0 <= gap <= window_s:
                host = end
                break
        if host is not None:
            _absorb_row(host, row)
            continue
        orphans.setdefault(match_of(row), []).append(row)
        kept.append(row)

    # Osierocone części jednej serii: zostaje NAJSTARSZA, czyli początek.
    # Wiersze idą od najnowszego, więc to ostatnia w grupie.
    drop: set = set()
    for group in orphans.values():
        i = 0
        while i < len(group):
            run = [group[i]]
            j = i + 1
            while j < len(group):
                gap = _gap_seconds(run[0].get("created_at"), group[j].get("created_at"))
                if gap is None or not (0 <= gap <= window_s):
                    break
                run.append(group[j])
                j += 1
            start = run[-1]
            for row in run[:-1]:
                _absorb_row(start, row)
                drop.add(id(row))
            fresh = False
            if now is not None:
                gap = _gap_seconds(now, start.get("created_at"))
                fresh = gap is not None and gap <= grace_s
            start["details_json"]["stalled" if not fresh else "running"] = True
            i = j

    out = [row for row in kept if id(row) not in drop]
    for row in out:
        details = row.get("details_json") or {}
        oldest = details.pop("_oldest_at", None)
        if oldest is not None and details.get("merged"):
            details["since"] = (
                oldest.isoformat() if hasattr(oldest, "isoformat") else str(oldest)
            )
    return out


def merge_field_changes(
    rows: Sequence[Any],
    window_s: int = _FIELD_MERGE_WINDOW_S,
) -> List[Dict[str, Any]]:
    """Sąsiadujące „Zmiany pól" jednej osoby w jednym posiedzeniu -> jeden wiersz.

    Scalamy przy ODCZYCIE, nie przy zapisie: dziennik jest księgą, więc surowe
    wiersze zostają w bazie, a scalony wiersz niesie ich liczbę (`merged`) i
    godzinę najstarszej poprawki (`since`).

    Scalamy TYLKO zwykłe zmiany pól tego samego autora. Znacznik wysyłki,
    podpis i badania mają własne zdarzenia, więc `_effective_event` wyprowadza
    je z tej gałęzi jeszcze przed porównaniem.
    """
    out: List[Dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        details = dict(row.get("details_json") or {})
        row["details_json"] = details
        if _effective_event(str(row.get("event") or ""), details) != "field.changed":
            out.append(row)
            continue

        prev = out[-1] if out else None
        prev_details = dict(prev.get("details_json") or {}) if prev else {}
        mergeable = (
            prev is not None
            and _effective_event(str(prev.get("event") or ""), prev_details)
            == "field.changed"
            and _actor_key(prev) == _actor_key(row)
        )
        if mergeable and prev is not None:
            # Wiersze idą od najnowszego, więc „poprzedni" jest młodszy.
            oldest = prev_details.get("_oldest_at") or prev.get("created_at")
            gap = _gap_seconds(oldest, row.get("created_at"))
            if gap is not None and 0 <= gap <= window_s:
                paths = list(prev_details.get("paths") or [])
                for p in details.get("paths") or []:
                    if p not in paths:
                        paths.append(p)
                prev_details["paths"] = paths
                prev_details["merged"] = int(prev_details.get("merged") or 1) + 1
                prev_details["_oldest_at"] = row.get("created_at")
                prev["details_json"] = prev_details
                continue
        out.append(row)

    for row in out:
        details = row.get("details_json") or {}
        oldest = details.pop("_oldest_at", None)
        if oldest is not None and details.get("merged"):
            details["since"] = (
                oldest.isoformat() if hasattr(oldest, "isoformat") else str(oldest)
            )
    return out


def _row_out(row: Any) -> Dict[str, Any]:
    d = dict(row)
    created = d.get("created_at")
    details = d.get("details_json") or {}
    event = _effective_event(str(d.get("event") or ""), details)
    return {
        "id": int(d["id"]),
        "match_number": d.get("match_number") or "",
        "zprp_match_id": d.get("zprp_match_id"),
        "event": event,
        "label": EVENT_LABELS.get(event, event),
        # Jedno zdanie po ludzku - patrz `event_summary`. Panel NIE składa
        # tego sam, żeby nie powstała druga lista nazw pól.
        "summary": event_summary(event, details),
        # Dla właściwego zdarzenia wysyłki ścieżka markera jest szczegółem
        # technicznym, nie „zmienionym polem" do pokazania administratorowi.
        "fields": (
            [describe_field(x) for x in (details.get("paths") or [])]
            if event in ("field.changed", "match.signed", "match.signature_removed")
            else []
        ),
        # Ile surowych wpisów stoi za tym wierszem i od kiedy - patrz
        # `merge_field_changes`. Wiersz niescalony ma 1 i `None`.
        "merged": int(details.get("merged") or 1),
        "since": details.get("since"),
        "actor": {
            "judge_id": d.get("actor_judge_id"),
            "name": d.get("actor_name"),
            "install": d.get("actor_install"),
            "verified": bool(d.get("actor_verified")),
        },
        "details": d.get("details_json"),
        "app_version": d.get("app_version"),
        "client_ip": d.get("client_ip"),
        "created_at": created.isoformat() if created is not None else None,
    }


# Dwa odczyty niżej to trasy ADMINA - dziennik pokazuje, kto co zmienił w
# cudzym meczu, razem z nazwiskami. Numer admina z nagłówka jest deklaracją,
# więc bramka żąda jego dowodu (`app/proel_admin_guard.py`); odmowę 403 dla
# nie-admina wystawia dalej `_require_admin`. `POST /proel/journal/event`
# zostaje BEZ bramki: zgłasza je każda aplikacja po nieudanej wysyłce.
@router.get(
    "/matches",
    summary="Mecze widziane od strony dziennika - jeden wiersz na mecz",
    dependencies=[Depends(proel_admin_guard)],
)
async def journal_matches(
    q: Optional[str] = Query(None, description="Fragment numeru meczu"),
    limit: int = Query(40, ge=1, le=200),
    offset: int = Query(0, ge=0),
    actor: Actor = Depends(proel_actor),
):
    """Poziom pierwszy panelu: co w ogóle się działo i przy którym meczu.

    Grupujemy w bazie, a nie w aplikacji: przy tysiącu meczów ściągnięcie
    całego dziennika po to, żeby go policzyć na telefonie, jest tym samym
    błędem co `GET /proel/` z pełnymi blobami.
    """
    await _require_admin(actor)
    await _backfill_protocol_pdf_events()

    from app.db import database, proel_activity_log, saved_matches

    log = proel_activity_log
    grouped = (
        select(
            log.c.match_number.label("match_number"),
            func.count().label("events"),
            func.max(log.c.created_at).label("last_at"),
            func.max(log.c.id).label("last_id"),
        )
        .group_by(log.c.match_number)
        .order_by(func.max(log.c.id).desc())
    )
    if q:
        grouped = grouped.where(log.c.match_number.ilike(f"%{str(q).strip()}%"))

    rows = await database.fetch_all(grouped.limit(limit).offset(offset))

    out: List[Dict[str, Any]] = []
    for row in rows:
        number = row["match_number"]

        last = await database.fetch_one(
            select(log).where(log.c.id == row["last_id"])
        )
        # Kto brał udział - do inicjałów na kaflu meczu.
        people = await database.fetch_all(
            select(log.c.actor_name)
            .where(log.c.match_number == number, log.c.actor_name.isnot(None))
            .group_by(log.c.actor_name)
            .limit(8)
        )
        doc = await database.fetch_one(
            select(saved_matches.c.status).where(
                saved_matches.c.match_number == number
            )
        )

        last_at = row["last_at"]
        out.append(
            {
                "match_number": number,
                "events": int(row["events"] or 0),
                "last_at": last_at.isoformat() if last_at is not None else None,
                "last_event": _row_out(last) if last is not None else None,
                "people": [str(p["actor_name"]) for p in people if p["actor_name"]],
                # Brak wiersza w `proel_matches` znaczy „zapis usunięty" -
                # dziennik zostaje i to jest jego sens.
                "status": (doc["status"] if doc is not None else "deleted"),
            }
        )
    return {"matches": out, "has_more": len(rows) == limit}


#: Zdarzenia, KTÓRE WOLNO ZGŁOSIĆ APLIKACJI.
#
# Reszta dziennika powstaje po stronie serwera przy operacji, którą opisuje -
# i tak ma zostać, bo wpis „zatwierdzono protokół" musi znaczyć, że protokół
# NAPRAWDĘ został zatwierdzony, a nie że ktoś tak powiedział. Nieudana próba
# wysyłki jest inna: dzieje się WYŁĄCZNIE na telefonie, między aplikacją a
# serwerem związku, i serwer BAZY nie ma jak się o niej dowiedzieć.
_CLIENT_REPORTABLE = {"zprp.send_failed", "zprp.send_queued"}


class JournalEventIn(BaseModel):
    match_number: str
    event: str
    zprp_match_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    #: Klucz idempotencji - dosyłka z kolejki nie ma dopisywać drugiego wiersza.
    event_key: Optional[str] = None
    app_version: Optional[str] = None


@router.post(
    "/event",
    summary="Zgłoszenie zdarzenia z aplikacji (tylko nieudane wysyłki)",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def journal_event_from_app(
    payload: JournalEventIn,
    request: Request,
    x_judge_id: Optional[str] = Header(None),
    x_installation_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    x_elevation: Optional[str] = Header(None),
    x_forwarded_for: Optional[str] = Header(None),
):
    """Dziennikowy wpis o czymś, co widzi tylko telefon.

    Świadomie BEZ 401 przy braku tożsamości: `soft_actor` oddaje `None`, a wpis
    bez nazwiska jest wart więcej niż brak wpisu. Świadomie też bez błędu przy
    obcym zdarzeniu - aplikacja nie ma tu czego naprawiać, a odmowa kończyłaby
    się w `catch` i tak.
    """
    event = str(payload.event or "").strip()
    if event not in _CLIENT_REPORTABLE:
        return None

    # Nagłówki czytamy JAWNIE i wołamy resolver ręcznie - `soft_actor` ma
    # zwykłe wartości domyślne zamiast `Header(...)`, więc jako `Depends`
    # FastAPI wziąłby je za parametry zapytania i tożsamość przepadłaby po
    # cichu. Tak samo robią wszystkie pozostałe miejsca.
    actor = await soft_actor(
        x_judge_id,
        x_installation_id,
        x_actor_name,
        authorization=authorization,
        x_elevation=x_elevation,
    )
    await log_match_event(
        match_number=payload.match_number,
        event=event,
        actor=actor,
        zprp_match_id=payload.zprp_match_id,
        details=payload.details,
        event_key=payload.event_key,
        app_version=payload.app_version,
        ip=client_ip(request, x_forwarded_for),
    )
    return None


@router.get(
    "",
    summary="Zdarzenia dziennika - stronicowanie kursorem po id",
    dependencies=[Depends(proel_admin_guard)],
)
async def journal_events(
    match: Optional[str] = Query(None, description="Numer meczu"),
    event: Optional[str] = Query(None, description="Nazwa zdarzenia"),
    actor_id: Optional[str] = Query(None, description="Numer sędziego"),
    before_id: Optional[int] = Query(
        None, description="Kursor: zwróć zdarzenia starsze niż to id"
    ),
    limit: int = Query(50, ge=1, le=200),
    actor: Actor = Depends(proel_actor),
):
    await _require_admin(actor)
    await _backfill_protocol_pdf_events()

    from app.db import database, proel_activity_log

    log = proel_activity_log
    stmt = select(log).order_by(log.c.id.desc())
    if match:
        stmt = stmt.where(log.c.match_number == str(match).strip())
    if event:
        stmt = stmt.where(log.c.event == str(event).strip())
    if actor_id:
        stmt = stmt.where(log.c.actor_judge_id == str(actor_id).strip())
    if before_id:
        stmt = stmt.where(log.c.id < int(before_id))

    rows = await database.fetch_all(stmt.limit(limit))
    # Kursor liczymy z SUROWYCH wierszy, zanim scalanie zabierze te najstarsze
    # ze strony - inaczej „Starsze zdarzenia" przeskakiwałyby wpisy.
    next_cursor = int(rows[-1]["id"]) if len(rows) == limit else None
    # Kolejność trzech scaleń nie jest dowolna: najpierw gasną duplikaty tej
    # samej wysyłki (inaczej seria wsiąkłaby w wiersz, który zaraz zniknie),
    # potem składa się seria pełnych danych, a na końcu zwykłe zmiany pól.
    items = [
        _row_out(r)
        for r in merge_field_changes(
            collapse_full_data_run(
                collapse_duplicate_sends(rows), now=now_utc()
            )
        )
    ]
    return {
        "events": items,
        "next_cursor": next_cursor,
        "labels": EVENT_LABELS,
    }
