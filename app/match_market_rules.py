# app/match_market_rules.py
#
# Reguły giełdy meczów - bez bazy, bez sieci, bez zegara systemowego.
#
# Liść wydzielony z tego samego powodu, co `app/training_stage.py`: te funkcje
# decydują o CUDZEJ obsadzie na mecz, który naprawdę się odbędzie. Pomyłka w
# progu czasowym albo w tabeli przejść nie kończy się brzydkim ekranem, tylko
# sędzią, który nie wie, czy ma jechać. Mają się dać sprawdzić testem, a nie
# dopiero w sobotę rano.
#
# Wszystkie funkcje przyjmują czas jako argument. Nic tu nie woła `now()` samo.

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

#: Gniazda protokołu, którymi wolno się wymieniać, wraz z nazwą pola w
#: formularzu ZPRP `zawody_UstawSedziow.php`.
#:
#: Delegaci są tu ŚWIADOMIE pominięci. Delegat ma inne wymagania niż sędzia
#: boiskowy i jego zmiana jest decyzją okręgu, a nie umową dwóch osób. Pełna
#: mapa sześciu gniazd żyje w `app/zprp/assignments.py` i obsługuje moduł
#: obsadowego - tam jest na miejscu, bo tam obsadowy zmienia każde pole.
TRADEABLE_SLOTS: Dict[str, str] = {
    "sedzia1": "NrSedzia_pierwszy",
    "sedzia2": "NrSedzia_drugi",
    "sekretarz": "NrSedzia_sekretarz",
    "czas": "NrSedzia_czas",
}

#: Podpis gniazda dla człowieka - jeden słownik na aplikację i na powiadomienia.
SLOT_LABELS: Dict[str, str] = {
    "sedzia1": "sędzia 1",
    "sedzia2": "sędzia 2",
    "sekretarz": "sekretarz",
    "czas": "mierzący czas",
}

#: Próg wystawienia, gdy okręg nie ustawił własnego.
DEFAULT_DEADLINE_HOURS = 48

#: Stany, w których oferta ZAJMUJE gniazdo - żadna druga nie może stanąć obok.
#: Ta sama para siedzi w warunku indeksu `uq_match_market_live_slot` w `db.py`.
LIVE_OFFER_STATUSES: Set[str] = {"open", "applying"}

#: Stany, po których nie da się już nic zrobić.
FINAL_OFFER_STATUSES: Set[str] = {"done", "rejected", "cancelled", "expired"}

# ── Przejścia oferty ────────────────────────────────────────────────────────
#
# `apply_failed` wraca do `open`, a nie do stanu końcowego. Nieudany zapis w
# ZPRP to najczęściej wygasła sesja albo obsada zmieniona w międzyczasie przez
# kogo innego - czyli coś, co za pięć minut może się udać. Zamknięcie oferty
# kazałoby sędziemu wystawiać ją od nowa, a obsadowemu szukać jej w historii.
_OFFER_TRANSITIONS: Dict[str, Dict[str, str]] = {
    "open": {
        "withdraw": "cancelled",
        "approve": "applying",
        "reject": "rejected",
        "expire": "expired",
    },
    "applying": {
        "applied": "done",
        "apply_failed": "open",
    },
}

# ── Przejścia zgłoszenia ────────────────────────────────────────────────────
_CLAIM_TRANSITIONS: Dict[str, Dict[str, str]] = {
    "pending": {
        "withdraw": "withdrawn",
        "choose": "chosen",
        "decline": "declined",
    },
    # Wybrany chętny wraca do puli, gdy zapis w ZPRP nie przeszedł - inaczej
    # ponowna próba nie miałaby kogo wybrać.
    "chosen": {
        "release": "pending",
    },
}


def slot_is_tradeable(slot: object) -> bool:
    """Czy tym gniazdem wolno się wymieniać."""
    return str(slot or "").strip() in TRADEABLE_SLOTS


def slot_select_name(slot: object) -> str:
    """Nazwa pola w formularzu ZPRP. Pusty string dla gniazda spoza giełdy."""
    return TRADEABLE_SLOTS.get(str(slot or "").strip(), "")


def slot_label(slot: object) -> str:
    """Podpis gniazda dla człowieka; nieznane oddajemy bez zmiany."""
    key = str(slot or "").strip()
    return SLOT_LABELS.get(key, key)


def normalize_deadline_hours(value: object) -> int:
    """Próg okręgu sprowadzony do sensownego zakresu.

    Zero znaczy „bez ograniczeń" i jest dozwolone - są okręgi, które wolą
    przyjmować zgłoszenia do ostatniej chwili. Górna granica to dwa tygodnie:
    wyżej próg przestaje chronić obsadowego, a zaczyna wygaszać giełdę.
    """
    try:
        hours = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_DEADLINE_HOURS
    return max(0, min(336, hours))


def deadline_for(match_at: Optional[datetime], deadline_hours: object) -> Optional[datetime]:
    """Chwila, po której oferta przestaje przyjmować zgłoszenia.

    `None` znaczy „bez terminu" i wychodzi w dwóch wypadkach: mecz bez daty w
    bazie związku albo próg ustawiony na zero.
    """
    if match_at is None:
        return None
    hours = normalize_deadline_hours(deadline_hours)
    if hours <= 0:
        return None
    return match_at - timedelta(hours=hours)


def can_offer(
    match_at: Optional[datetime],
    now: datetime,
    deadline_hours: object = DEFAULT_DEADLINE_HOURS,
) -> bool:
    """Czy ten mecz wolno TERAZ wystawić na giełdę.

    Mecz bez daty przepuszczamy: brak terminu w bazie związku to luka w danych,
    a nie powód, żeby odciąć sędziego od jedynej drogi oddania meczu. Mecz,
    który się już odbył, odpada zawsze - niezależnie od progu.
    """
    if match_at is None:
        return True
    if match_at <= now:
        return False
    limit = deadline_for(match_at, deadline_hours)
    return True if limit is None else now < limit


def next_offer_status(current: object, action: object) -> Optional[str]:
    """Stan po akcji albo `None`, gdy taka droga nie istnieje.

    `None` jest tu odpowiedzią, a nie wyjątkiem: wołający zamienia je na 409 z
    własnym komunikatem, bo „oferta została już rozstrzygnięta" znaczy co
    innego dla oddającego, a co innego dla obsadowego.
    """
    return _OFFER_TRANSITIONS.get(str(current or ""), {}).get(str(action or ""))


def next_claim_status(current: object, action: object) -> Optional[str]:
    """Stan zgłoszenia po akcji albo `None`."""
    return _CLAIM_TRANSITIONS.get(str(current or ""), {}).get(str(action or ""))


def offer_is_live(status: object) -> bool:
    """Czy oferta wciąż zajmuje gniazdo."""
    return str(status or "") in LIVE_OFFER_STATUSES


#: Gniazdo → (pole z NUMEREM sędziego, pole z nazwiskiem) w `state_json`
#: wiersza `province_matches`.
#:
#: Numer bywa pusty: lekki przebieg monitora czyta listę meczów sędziego, która
#: podaje same nazwiska, a numery dochodzą dopiero z publicznego API przy
#: głębokim sprawdzeniu. Stąd dwa pola i kolejność w `slots_held_by`.
SLOT_STATE_FIELDS: Dict[str, Tuple[str, str]] = {
    "sedzia1": ("NrSedzia_pierwszy", "NrSedzia_pierwszy_nazwisko"),
    "sedzia2": ("NrSedzia_drugi", "NrSedzia_drugi_nazwisko"),
    "sekretarz": ("NrSedzia_sekretarz", "NrSedzia_sekretarz_nazwisko"),
    "czas": ("NrSedzia_czas", "NrSedzia_czas_nazwisko"),
}


#: Litery, których rozkład NFD NIE tyka.
#:
#: „ł" nie jest „l" z ogonkiem, tylko osobnym znakiem, więc `unicodedata`
#: zostawia je w spokoju - a sito niżej przepuszcza wyłącznie ASCII i kasowało
#: je bez śladu. „ŁACNY" stawał się przez to „acny", „Bartłomiej" rozpadał się
#: na „bart" i „omiej", i nazwisko przestawało pasować do samego siebie
#: zapisanego bez ogonków. Dotyczy każdego polskiego nazwiska z „ł", czyli
#: kilku procent obsady.
_HARD_FOLD = str.maketrans({"ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "đ": "d", "Đ": "D"})


def _fold(text: object) -> str:
    """Tekst bez znaków diakrytycznych, małymi literami."""
    raw = str(text or "").translate(_HARD_FOLD)
    raw = unicodedata.normalize("NFD", raw)
    raw = "".join(ch for ch in raw if unicodedata.category(ch) != "Mn")
    return raw.lower().strip()


def _name_parts(text: object) -> List[str]:
    """Znaczące człony nazwiska - bez inicjałów i śmieci."""
    cleaned = re.sub(r"[^a-z0-9]+", " ", _fold(text))
    return [p for p in cleaned.split() if len(p) > 1]


def names_match(a: object, b: object) -> bool:
    """Czy to ten sam człowiek, mimo innej kolejności członów.

    ZPRP zapisuje „NOWAK Jan", a nasza lista sędziów okręgu bywa prowadzona jako
    „Jan Nowak" - i to samo nazwisko z drugiej strony przestawało pasować.
    Porównujemy więc ZBIÓR członów, a nie tekst. Pojedynczy człon nie wystarcza:
    samo „Nowak" pasowałoby do każdego Nowaka w okręgu.
    """
    pa, pb = _name_parts(a), _name_parts(b)
    if not pa or not pb:
        return False
    if pa == pb:
        return True
    if len(pa) < 2 or len(pb) < 2:
        return False
    shorter, longer = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    return all(part in longer for part in shorter)


def slot_holder_name(state: Mapping[str, Any], slot: object) -> str:
    """Nazwisko, które stoi w tym gnieździe - w postaci zapisanej przez ZPRP.

    To ta sama postać, którą niesie opcja w formularzu obsady, więc nadaje się
    wprost na strażnika `expect` przy zapisie.
    """
    fields = SLOT_STATE_FIELDS.get(str(slot or "").strip())
    if not fields:
        return ""
    return str((state or {}).get(fields[1]) or "").strip()


def slots_held_by(
    state: Mapping[str, Any],
    judge_id: object,
    full_name: object = "",
) -> List[str]:
    """Gniazda giełdowe, które w tym meczu zajmuje ten sędzia.

    NUMER PRZED NAZWISKIEM, dokładnie jak w `roles_for` ProEla: gdy w stanie
    meczu jest numer, rozstrzyga on i nie zgadujemy po nazwisku. Dopasowanie po
    nazwisku zostaje dla meczów, których monitor nie zdążył sprawdzić głęboko -
    tam numerów po prostu nie ma.
    """
    wanted_id = str(judge_id or "").strip()
    out: List[str] = []
    for slot, (id_field, name_field) in SLOT_STATE_FIELDS.items():
        raw_id = str((state or {}).get(id_field) or "").strip()
        if raw_id:
            if wanted_id and raw_id == wanted_id:
                out.append(slot)
            continue
        if full_name and names_match((state or {}).get(name_field), full_name):
            out.append(slot)
    return out


def may_claim(
    offer_status: object,
    offer_from_judge_id: object,
    claimer_judge_id: object,
    deadline_at: Optional[datetime],
    now: datetime,
) -> Optional[str]:
    """Powód odmowy zgłoszenia albo `None`, gdy wolno.

    Kolizji terminarza tu NIE ma i to jest decyzja, nie przeoczenie: kolizja
    jest ostrzeżeniem dla obsadowego, a nie zakazem. Sędzia bywa mądrzejszy od
    własnego kalendarza sprzed miesiąca.
    """
    if str(offer_status or "") != "open":
        return "Ta oferta nie zbiera już zgłoszeń."
    if str(offer_from_judge_id or "").strip() == str(claimer_judge_id or "").strip():
        return "To Twój własny mecz."
    if deadline_at is not None and now >= deadline_at:
        return "Minął termin zgłoszeń dla tego meczu."
    return None


# ── Uprawnienia okręgu do meczu ─────────────────────────────────────────────
#
# Sędzia widzi w aplikacji WSZYSTKIE swoje mecze, ale okręg obsadza tylko część
# z nich - Superligę, ligi centralne i turnieje młodzieżowe obsadza związek.
# Konto wojewódzkie nie ma tam czego kliknąć, więc mecz z takich rozgrywek nie
# ma prawa trafić na giełdę: umowa dwóch sędziów rozbiłaby się dopiero o zapis,
# już po decyzji obsadowego.
#
# Odpowiedź daje sonda w `app.zprp.assignments.probe_assignment_rights`, czyli
# ten sam formularz, którym potem zapisujemy. Tu mieszka wyłącznie to, co da się
# rozstrzygnąć bez sieci: jak długo werdykt jest świeży i jak go nazwać.

#: Jak długo werdykt sondy uchodzi za aktualny.
#:
#: Uprawnienia okręgu zmieniają się raz na sezon, nie raz na godzinę. Doba to
#: kompromis między niepotrzebnym ruchem na serwerze związku a ryzykiem, że po
#: przekazaniu rozgrywek okręgowi sędzia jeszcze przez chwilę widzi starą
#: odmowę. Pomyłka w tę stronę nic nie psuje - zapis i tak ma własnego
#: strażnika przy zatwierdzaniu.
ASSIGNABILITY_TTL_HOURS = 24

#: Ile meczów sonda sprawdza w jednym wywołaniu.
#:
#: Każdy sprawdzony mecz to osobne wejście na stronę związku. Limit jest po to,
#: żeby otwarcie arkusza „Oddaj mecz" przez sędziego z pełnym terminarzem nie
#: zamieniło się w trzydzieści zapytań pod rząd. Reszta doczeka następnego
#: wejścia, a odpowiedź MÓWI, ile zostało niesprawdzonych - liczba, której się
#: nie pokazuje, wygląda jak komplet.
PROBE_BATCH_LIMIT = 12

#: Powód odmowy → zdanie dla sędziego. Jedno źródło dla serwera i dla ekranu.
ASSIGNABILITY_MESSAGES: Dict[str, str] = {
    "NO_FORM": (
        "Tego meczu nie obsadza okręg - obsadę ustala związek, więc giełda nie ma "
        "jak przekazać go innemu sędziemu."
    ),
    "NO_OPTIONS": (
        "Konto obsadowe okręgu otwiera ten mecz, ale nie widzi przy nim żadnego "
        "sędziego do wyboru - takiej zmiany nie da się zapisać."
    ),
    "NO_ACCOUNT": (
        "Ten okręg nie ma jeszcze konta obsadowego na serwerze, więc giełda nie ma "
        "czym zapisać zmiany w bazie związku."
    ),
    "PROBE_FAILED": (
        "Nie udało się sprawdzić w bazie związku, czy okręg obsadza ten mecz. "
        "Spróbuj za chwilę."
    ),
    "UNCHECKED": "Sprawdzimy uprawnienia okręgu, zanim wystawisz ten mecz.",
}


def assignability_message(reason: object) -> str:
    """Zdanie tłumaczące odmowę. Nieznany kod dostaje ogólne, ale prawdziwe."""
    key = str(reason or "").strip().upper()
    if key == "OK":
        return ""
    return ASSIGNABILITY_MESSAGES.get(
        key, "Giełda nie potwierdziła, że okręg obsadza ten mecz."
    )


def assignability_is_fresh(
    checked_at: Optional[datetime],
    now: datetime,
    ttl_hours: object = ASSIGNABILITY_TTL_HOURS,
) -> bool:
    """Czy zapisany werdykt wolno jeszcze podać bez pytania ZPRP.

    Werdykt z przyszłości traktujemy jako świeży, a nie jako błąd: to znaczy
    tyle, że zegar bazy wyprzedza nasz o sekundy, i odrzucanie go kazałoby
    sondzie chodzić przy każdym wejściu na ekran.
    """
    if checked_at is None:
        return False
    try:
        hours = max(0, int(ttl_hours))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        hours = ASSIGNABILITY_TTL_HOURS
    if hours <= 0:
        return False
    return checked_at + timedelta(hours=hours) > now


def market_pushes_allowed(prefs: Any) -> bool:
    """Czy na to urządzenie wolno wysłać ROZSYŁKĘ o nowej ofercie.

    Dotyczy wyłącznie jednego powiadomienia: „ktoś oddaje mecz", które idzie do
    całego województwa. Reszta - „ktoś zgłosił się na TWÓJ mecz", „wymianę
    zatwierdzono", „zapis nie przeszedł" - to następstwa własnych czynności
    adresata i nie chowa się za przełącznikiem od cudzych ofert.

    Kształt preferencji jest ten sam, co w monitorze meczów
    (`_prefs_allow`): brak wpisu znaczy ZGODA, bo moduł ma działać od razu po
    włączeniu w okręgu, a nie dopiero po tym, jak każdy sędzia odszuka
    przełącznik w ustawieniach.
    """
    if not isinstance(prefs, dict):
        return True
    if prefs.get("enabled") is False:
        return False
    types = prefs.get("notificationTypes")
    if not isinstance(types, dict):
        return True
    return types.get("matchMarket", True) is not False
