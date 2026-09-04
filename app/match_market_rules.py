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

import json
import re
import unicodedata
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

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


def state_dict(value: Any) -> Dict[str, Any]:
    """Kolumna JSON jako słownik - niezależnie od sterownika bazy.

    SQLite w testach oddaje słownik, ale asyncpg pod `databases` potrafi oddać
    SUROWY NAPIS: bez zarejestrowanego kodeka typu jsonb nie dekoduje niczego.
    Pierwsze zgłoszenie z produkcji to dokładnie `'str' object has no attribute
    'get'` w `slots_held_by` - cała lista „moich meczów" kładła się o FORMAT
    kolumny, nie o jej treść. Napis nie do sparsowania znaczy „brak stanu",
    nie awarię.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


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
    if isinstance(prefs, (str, bytes, bytearray)):
        # Ten sam sterownikowy kaprys, co przy stanie meczu - patrz `state_dict`.
        prefs = state_dict(prefs)
    if not isinstance(prefs, dict):
        return True
    if prefs.get("enabled") is False:
        return False
    types = prefs.get("notificationTypes")
    if not isinstance(types, dict):
        return True
    return types.get("matchMarket", True) is not False


#: Gniazdo → (numer, nazwisko) dla CAŁEJ obsady, także tej spoza giełdy.
#:
#: Delegaci nie handlują gniazdami, ale mecz z nimi dzielą - a to znaczy, że o
#: zmianie w obsadzie mają prawo wiedzieć. Stąd osobny słownik zamiast
#: dosypywania delegatów do `SLOT_STATE_FIELDS`, którego jedynym zadaniem jest
#: mówić, co da się oddać.
CREW_STATE_FIELDS: Dict[str, Tuple[str, str]] = {
    **SLOT_STATE_FIELDS,
    "delegat": ("NrSedzia_delegat", "NrSedzia_delegat_nazwisko"),
    "delegat2": ("NrSedzia_delegat2", "NrSedzia_delegat2_nazwisko"),
}


def with_slot_holder(
    state: Mapping[str, Any],
    slot: object,
    judge_id: object,
    full_name: object,
) -> Dict[str, Any]:
    """Migawka meczu z nowym gospodarzem gniazda - KOPIA, nie zmiana w miejscu.

    Po zapisie wymiany w bazie związku migawka okręgu wie jeszcze swoje, bo
    wypełnia ją monitor przy własnym przebiegu. Do tego czasu `slots_held_by`
    czytało w gnieździe poprzednika i mecz, który sędzia właśnie odzyskał,
    znikał mu z listy „Oddaj mecz" bez słowa wyjaśnienia. Nazwisko wchodzi w
    postaci ZPRP („NAZWISKO Imię"), czyli tej samej, którą później zapisze
    monitor - inaczej ta sama obsada wyglądałaby na dwa różne stany.
    """
    fields = CREW_STATE_FIELDS.get(str(slot or "").strip())
    patched = dict(state or {})
    if not fields:
        return patched
    id_field, name_field = fields
    patched[id_field] = str(judge_id or "").strip()
    patched[name_field] = str(full_name or "").strip()
    return patched


def crew_judge_ids(state: Mapping[str, Any], exclude: Iterable[object] = ()) -> List[str]:
    """Numery sędziów, którzy zostają przy tym meczu.

    „0" przy pustym nazwisku to ZPRP-owy sposób powiedzenia „nikogo tu nie ma"
    (patrz nota o polach obsady w monitorze), więc nie jest numerem sędziego.
    """
    skip = {str(item or "").strip() for item in exclude if str(item or "").strip()}
    out: List[str] = []
    for id_field, _name_field in CREW_STATE_FIELDS.values():
        raw = str((state or {}).get(id_field) or "").strip()
        if not raw or raw == "0" or raw in skip or raw in out:
            continue
        out.append(raw)
    return out


def apply_known_swaps(
    state: Mapping[str, Any],
    swaps: Iterable[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Stan meczu z dopisanymi wymianami, które giełda SAMA zapisała.

    Migawkę terminarza wypełnia monitor, więc zaraz po zatwierdzonej wymianie
    siedzi w niej jeszcze poprzedni sędzia. `with_slot_holder` poprawia ją w
    chwili zapisu, ale to poprawka w JEDNĄ stronę: nie pomoże wymianie zapisanej
    przed jej wdrożeniem ani takiej, przy której samo odświeżenie się nie udało.
    Dlatego lista „moich meczów" nakłada tu jeszcze WŁASNĄ pamięć giełdy -
    zatwierdzone i potwierdzone w bazie związku wymiany, o których migawka może
    nie wiedzieć. Giełda nie ma prawa zapomnieć, co sama zrobiła.

    Rygiel jest ostry: wymiana wchodzi TYLKO wtedy, gdy w gnieździe stoi
    dokładnie ten, kto mecz oddał. Gdy stoi tam kto trzeci, świat poszedł dalej
    (obsadowy zmienił obsadę ręcznie w ZPRP) i nasza pamięć jest nieaktualna -
    wtedy rządzi migawka. `swaps` przychodzą od najstarszej, żeby łańcuch
    wymian tego samego gniazda złożył się po kolei.

    Każda wymiana to `{"slot", "from_judge_id", "from_name", "to_judge_id",
    "to_name"}`.
    """
    out = dict(state or {})
    for swap in swaps:
        fields = SLOT_STATE_FIELDS.get(str((swap or {}).get("slot") or "").strip())
        if not fields:
            continue
        id_field, name_field = fields
        giver_id = str(swap.get("from_judge_id") or "").strip()
        raw_id = str(out.get(id_field) or "").strip()
        if raw_id:
            # Numer w migawce rozstrzyga - tak samo jak w `slots_held_by`.
            if not giver_id or raw_id != giver_id:
                continue
        elif not names_match(out.get(name_field), swap.get("from_name")):
            # Migawka bez numeru (lekki przebieg monitora) - zostaje nazwisko.
            continue
        out[id_field] = str(swap.get("to_judge_id") or "").strip()
        out[name_field] = str(swap.get("to_name") or "").strip()
    return out
