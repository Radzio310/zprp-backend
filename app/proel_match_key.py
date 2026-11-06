"""Który mecz leży pod tym numerem - czysta logika, bez bazy.

Wydzielone z `app/proel.py` z tego samego powodu co leasing: `app.proel`
ciągnie za sobą `app.db`, a ten przy imporcie zakłada schemat na Postgresie -
czyli test tej logiki wymagałby żywej bazy. A to jest reguła, która decyduje
o tym, czy zapis nadpisze CUDZY protokół, więc nie może zostać bez testów.

Sedno problemu: kluczem głównym `proel_matches` jest NUMER meczu ("OSK/12"),
a numer jest unikalny w rozgrywkach, nie między sezonami. Mecz z nowego sezonu
o tym samym numerze trafiał więc dokładnie w wiersz sprzed roku: `POST`
odbijał się z 409, aplikacja logowała to do konsoli i szła dalej, a następny
`PUT` przechodził bez słowa i nadpisywał tamten protokół.
"""

from __future__ import annotations

import re
from typing import Any, Dict

#: Pola konfiguracji, które wystarczają, żeby narysować wiersz na liście wyboru
#: meczu. Wszystko poza nimi (składy, badania, przebieg, kary) zostaje na
#: serwerze do czasu, aż ktoś naprawdę otworzy ten mecz.
HEAD_CONFIG_KEYS = (
    "matchNumber",
    "matchId",
    "hostTeamName",
    "guestTeamName",
    "isTest",
    # Skąd wzięło się prowadzenie i pod jakim kluczem leży wiersz.
    # Bez nich lista nie wie, że wznowienie ma pytać o klucz
    # szkoleniowy, a nie o czysty numer meczu widoczny na kafelku.
    "origin",
    "proelKey",
    # Obsada i miejsce (od 2026-09-06): to, co stoi na kafelku archiwum i po
    # czym sędzia szuka meczu. W bazie związku są publiczne; dane osobowe
    # zawodników - składy, licencje, badania - i podpisy (`extras`) nadal
    # zostają za drzwiami.
    "referee1",
    "referee2",
    "delegate",
    "delegate2",
    "secretary",
    "timekeeper",
    "venueCity",
    "venueAddress",
    "hala",
)

def _training_head(config: Dict[str, Any]) -> Any:
    """`matchConfig.training` przycięte do samego `eventId`, albo `None`.

    Lista wiersza szkoleniowego musi wiedzieć, że to ćwiczenie z
    kursokonferencji (wznowienie, filtr, blokada przeniesienia do
    oficjalnych), a nagłówek gubił to pole w całości. Reszta `training`
    (wyniki, oceny) zostaje za drzwiami razem z resztą bloba.
    """
    training = config.get("training")
    if not isinstance(training, dict):
        return None
    event_id = training.get("eventId")
    if not str(event_id or "").strip():
        return None
    return {"eventId": event_id}


#: Pola najwyższego poziomu bloba, które niesie nagłówek listy.
#:
#: `penaltyScore` jest tu nie dla ozdoby: listy meczów rysują z niego wynik
#: rzutów karnych, a bez niego zakończony mecz po dogrywce wyglądałby na remis.
HEAD_TOP_KEYS = ("scoreHost", "scoreGuest", "date", "penaltyScore")


def zprp_id_of(blob: Any) -> str:
    """`data_json.matchConfig.matchId` - identyfikator meczu w bazie ZPRP.

    Czytamy go z BLOBA, a nie z osobnego pola żądania: dzięki temu guard działa
    także dla wersji aplikacji, które o nim nie wiedzą - `matchId` jedzie
    w konfiguracji meczu od zawsze.

    Bierzemy wyłącznie czyste liczby. Mecze zakładane ręcznie mają
    identyfikatory syntetyczne (`Date.now()-…`), a te nie identyfikują niczego
    w ZPRP i uznanie ich za identyfikator zablokowałoby zwykłą pracę.
    """
    try:
        value = (blob or {}).get("matchConfig", {}).get("matchId")
    except AttributeError:
        return ""
    text_id = str(value or "").strip()
    return text_id if text_id.isdigit() else ""


def match_id_conflict(known: str, incoming: str) -> bool:
    """Czy blob opisuje INNY mecz niż ten, który leży pod tym numerem.

    Porównujemy wyłącznie wtedy, gdy obie strony wiedzą, o który mecz chodzi.
    Pusty identyfikator (mecz ręczny, zapis sprzed tej kolumny) nigdy nie jest
    konfliktem - inaczej guard blokowałby prowadzenie meczu bez ZPRP, czyli
    sytuację całkowicie normalną.
    """
    return bool(known) and bool(incoming) and known != incoming


def match_head(blob: Any) -> Dict[str, Any]:
    """Nagłówek meczu w kształcie `data_json`, ale bez danych osobowych.

    Kształt jest ten sam, w jakim czyta go lista wyboru meczu
    (`data_json.matchConfig`), więc ekran nie musi wiedzieć o istnieniu
    projekcji - a przestaje ściągać na telefon składy, licencje i przebieg
    wszystkich meczów w systemie naraz.
    """
    try:
        config = dict((blob or {}).get("matchConfig") or {})
    except AttributeError:
        return {"matchConfig": {}}

    out: Dict[str, Any] = {
        "matchConfig": {k: config.get(k) for k in HEAD_CONFIG_KEYS if k in config}
    }
    training = _training_head(config)
    if training is not None:
        out["matchConfig"]["training"] = training
    for key in HEAD_TOP_KEYS:
        try:
            if key in blob:
                out[key] = blob[key]
        except TypeError:
            break
    return out

#: Pola zegara i tablicy wyniku - nagłówek meczu PROWADZONEGO W TEJ CHWILI.
#:
#: Kafelek „na żywo" w szczegółach meczu musi pokazywać wynik i zegar, a jest
#: otwarty tak długo, jak długo ktoś patrzy na mecz. Ciągnięcie po to całego
#: `data_json` (składy, licencje, przebieg, stos cofania) raz na minutę to
#: kilkadziesiąt kilobajtów transferu w hali, w której zasięg bywa jedyną
#: rzeczą, jakiej brakuje. Stąd osobna, płaska projekcja.
#:
#: `savedAtMs` jest tu kluczowe: bez niego zegar w podglądzie stoi na wartości
#: sprzed minuty. Z nim aplikacja liczy czas dalej od znacznika - dokładnie
#: tak, jak robi to pływający dymek aktywnego meczu.
HEAD_CLOCK_KEYS = (
    "mainTime",
    "isFirstHalf",
    "isGameRunning",
    "isHalfBreak",
    "isBreakRunning",
    "savedAtMs",
    "breakRemainingMs",
    "halfBreakRemainingMs",
    "halfScore",
    "penaltyShootoutActive",
    "penaltyShootoutScoreLabel",
)

#: Pola konfiguracji potrzebne tablicy wyniku ponad `HEAD_CONFIG_KEYS`.
#: Kolory koszulek, bo tablica maluje nimi nazwy drużyn, i długość połowy,
#: bez której nie da się powiedzieć, czy zegar dobił do końca czasu.
HEAD_LIVE_CONFIG_KEYS = HEAD_CONFIG_KEYS + (
    "hostJerseyColor",
    "guestJerseyColor",
    "halfTime",
    "date",
)


def live_head(blob: Any) -> Dict[str, Any]:
    """Nagłówek meczu w toku: wynik, zegar, faza - i nic poza tym.

    Rozszerza `match_head` o stan zegara. Dalej BEZ danych osobowych: składy,
    licencje, badania i przebieg zostają na serwerze, bo do narysowania
    tablicy wyniku nie są potrzebne.
    """
    out = match_head(blob)
    try:
        config = dict((blob or {}).get("matchConfig") or {})
    except AttributeError:
        return out
    out["matchConfig"] = {
        k: config.get(k) for k in HEAD_LIVE_CONFIG_KEYS if k in config
    }
    training = _training_head(config)
    if training is not None:
        out["matchConfig"]["training"] = training
    for key in HEAD_CLOCK_KEYS:
        try:
            if key in blob:
                out[key] = blob[key]
        except TypeError:
            break
    return out


# ─────────────────────────── TOŻSAMOŚĆ MECZU ───────────────────────────
#
# `zprp_match_id` zamykał kolizję numerów tylko połowicznie, bo działa
# WYŁĄCZNIE wtedy, gdy obie strony znają identyfikator z bazy ZPRP. A numery
# powtarzają najczęściej dokładnie te mecze, które go nie mają: zakładane
# ręcznie i szkoleniowe. Mecz ręczny "SL/123" wchodził więc w wiersz stanu
# prawdziwego "SL/123", obejmował leasing i odbierał prowadzenie sędziemu,
# który sędziował naprawdę.
#
# Stąd druga warstwa: ODCISK LOKALNY, czyli numer razem z nazwami drużyn.
# Liczy go wyłącznie serwer i wyłącznie z danych, które i tak dostaje
# (`/ensure` niesie obsadę i drużyny, blob niesie `matchConfig`) - dzięki temu
# nie ma drugiej implementacji normalizacji po stronie aplikacji, która mogłaby
# się z tą rozjechać, i działa też dla starych wersji aplikacji.
#
# CZEGO ODCISK NIE ZAŁATWI, świadomie: ręcznej KOPII prawdziwego meczu, czyli
# tego samego numeru i tych samych drużyn. Taki mecz jest nieodróżnialny od
# oryginału po samych danych. Rozstrzyga go dopiero drabina niżej: mecz z bazy
# ZPRP jest silniejszy od ręcznego i odbiera mu wiersz.

#: Polskie znaki złożone rozkładają się na literę bazową - dwie osoby wpisujące
#: tę samą drużynę różnią się zwykle właśnie ogonkiem albo kropką.
_FOLD = str.maketrans(
    {
        "Ą": "A", "Ć": "C", "Ę": "E", "Ł": "L", "Ń": "N",
        "Ó": "O", "Ś": "S", "Ź": "Z", "Ż": "Z",
    }
)


def _fold(value: Any) -> str:
    """Nazwa drużyny sprowadzona do porównywalnej postaci.

    Zostają wyłącznie litery i cyfry: kropki, myślniki, spacje i wielkość liter
    dzielą ten sam klub na kilka bytów, a nie o taki podział tu chodzi.
    """
    text = str(value or "").strip().upper().translate(_FOLD)
    return "".join(ch for ch in text if ch.isalnum())


def local_key_of(match_number: Any, host: Any, guest: Any) -> str:
    """Odcisk meczu bez identyfikatora ZPRP: numer plus obie drużyny.

    Pusty, gdy którejś drużyny nie znamy - a to nie jest przeoczenie. Sam numer
    nie identyfikuje niczego (właśnie o to rozbiła się pierwsza wersja guardu),
    a odcisk zbudowany z połowy danych blokowałby mecze, o których nic nie wiemy.
    Pusty odcisk znaczy „nie wiem, który to mecz" i nigdy nikogo nie blokuje.
    """
    number = _fold(match_number)
    a = _fold(host)
    b = _fold(guest)
    if not number or not a or not b:
        return ""
    return f"{number}|{a}|{b}"


def local_key_from_blob(blob: Any) -> str:
    """Odcisk policzony z `data_json.matchConfig` - dla zapisu bloba."""
    try:
        config = (blob or {}).get("matchConfig") or {}
    except AttributeError:
        return ""
    return local_key_of(
        config.get("matchNumber"),
        config.get("hostTeamName"),
        config.get("guestTeamName"),
    )


def local_key_from_guard(match_number: Any, guard: Any) -> str:
    """Odcisk policzony z ładunku `/ensure` - ten sam kształt co z bloba."""
    data = guard if isinstance(guard, dict) else {}
    return local_key_of(
        match_number, data.get("hostTeamName"), data.get("guestTeamName")
    )


def match_identity(zprp_id: Any, local_key: Any) -> str:
    """Kim jest ten mecz: `zprp:<id>`, `local:<odcisk>` albo nic.

    Identyfikator z bazy ZPRP wygrywa z odciskiem, bo jest mocniejszy: mówi
    o konkretnym wpisie w rozgrywkach, a nie o zbieżności nazw.
    """
    zprp = str(zprp_id or "").strip()
    if zprp:
        return f"zprp:{zprp}"
    local = str(local_key or "").strip()
    return f"local:{local}" if local else ""


def identity_rank(identity: Any) -> int:
    """Siła tożsamości: 2 = wpis w ZPRP, 1 = odcisk lokalny, 0 = nie wiadomo."""
    text = str(identity or "")
    if text.startswith("zprp:"):
        return 2
    if text.startswith("local:"):
        return 1
    return 0


#: Tożsamości się zgadzają albo jednej ze stron brakuje - wpuszczamy.
IDENTITY_OK = "ok"
#: Wiersz nie wiedział, czyj jest - zapisujemy tożsamość przychodzącego.
IDENTITY_ADOPT = "adopt"
#: Mecz z bazy ZPRP wchodzi na wiersz zajęty przez mecz ręczny. Wiersz zmienia
#: właściciela, a leasing ręcznego przepada - numer należy do rozgrywek.
IDENTITY_UPGRADE = "upgrade"
#: Dwa różne mecze pod jednym numerem - odmawiamy.
IDENTITY_CONFLICT = "conflict"


def identity_verdict(known: Any, incoming: Any) -> str:
    """Czy przychodzący mecz może rozporządzać wierszem pod tym numerem.

    Drabina, a nie proste porównanie, bo kolejność wejścia jest przypadkowa.
    Gdyby liczyło się „kto pierwszy", ręczna kopia założona kwadrans przed
    meczem odbierałaby wiersz meczowi z rozgrywek - czyli dokładnie temu, który
    ten numer naprawdę nosi.
    """
    inc = str(incoming or "")
    kn = str(known or "")
    if not inc:
        return IDENTITY_OK
    if not kn:
        return IDENTITY_ADOPT
    if kn == inc:
        return IDENTITY_OK
    if identity_rank(inc) > identity_rank(kn):
        return IDENTITY_UPGRADE
    return IDENTITY_CONFLICT


# ─────────────────── KLUCZ PROTOKOŁU MECZU RĘCZNEGO (WSPÓLNEGO) ───────────────────
#
# Mecz ręczny nie ma IdZawody, a numer ("EHF/1") wpisują sędziowie sami, więc dwa
# różne mecze o tym samym numerze trafiały w jeden wiersz `proel_matches`. Mecz
# ręczny dostaje więc klucz z przedrostkiem jak szkoleniowy (`T-`), ale własnym:
#
#     M-<TULEJA 8 znaków>/<NUMER>      np. M-3F9A0C21/EHF/1
#
# Mecz POZOSTAJE oficjalny (nie jest szkoleniowy, nie trafia pod `T-%`), a sędzia
# na ekranach widzi sam numer. Tuleja jest jedna na mecz wspólny i taka sama na
# telefonach całej obsady, bo to serwer ją zapisuje (`shared_matches.proel_stem`)
# i oddaje w `key_stem`.
#
# TULEJA liczona jest z (twórca, local_id) - a nie z id serwera - bo telefon
# twórcy musi znać klucz ZANIM mecz dotrze na serwer (start offline w hali). Obie
# strony (aplikacja: `utils/sharedProelKey.ts`, serwer: tu) liczą ten sam skrót,
# co pilnują wektory testowe po obu stronach. Mecz bez `local_id` (albo sprzed tej
# zmiany: kolumna pusta) ma tuleję = pierwsze 8 znaków id serwera.

#: Przedrostek klucza meczu ręcznego. Myślnik jak przy `T-`: numery ZPRP go nie mają.
SHARED_KEY_PREFIX = "M-"

#: Wzorzec do `LIKE` w SQL (jak `TRAINING_KEY_LIKE`).
SHARED_KEY_LIKE = "M-%/%"

_SHARED_KEY_RE = re.compile(r"^M-[A-Z0-9]{6,16}/.+$", re.IGNORECASE)

_STEM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
STEM_LENGTH = 8


def _fnv32(text: str, basis: int) -> int:
    """FNV-1a po kodach UTF-16 znaków - tak samo liczy to `Math.imul` po stronie aplikacji."""
    h = basis & 0xFFFFFFFF
    units = text.encode("utf-16-le")
    for i in range(0, len(units), 2):
        h ^= units[i] | (units[i + 1] << 8)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def stem_from_local(creator_id: Any, local_id: Any) -> str:
    """Tuleja klucza z twórcy i lokalnego `Id` wpisu - pusta, gdy któregoś brakuje."""
    creator = str(creator_id or "").strip()
    local = str(local_id or "").strip()
    if not creator or not local:
        return ""
    text = f"{creator}|{local}"
    bits = _fnv32(text, 0x811C9DC5) * 256 + (_fnv32(text, 0x9747B28C) & 255)
    out = ""
    for i in range(STEM_LENGTH):
        out += _STEM_ALPHABET[(bits >> (5 * (STEM_LENGTH - 1 - i))) & 31]
    return out


def stem_from_server_id(server_id: Any) -> str:
    """Tuleja z id serwera - dla meczu bez `local_id` i dla wierszy sprzed kolumny."""
    return "".join(ch for ch in str(server_id or "").upper() if ch.isalnum())[:STEM_LENGTH]


def new_shared_stem(creator_id: Any, local_id: Any, server_id: Any) -> str:
    """Tuleja nowego meczu wspólnego: z twórcy i `local_id`, a bez nich z id serwera."""
    return stem_from_local(creator_id, local_id) or stem_from_server_id(server_id)


def is_shared_key(key: Any) -> bool:
    """Czy ten klucz wiersza należy do meczu ręcznego (wspólnego)."""
    return bool(_SHARED_KEY_RE.match(str(key or "").strip()))


def shared_key_of(stem: Any, match_number: Any) -> str:
    """`M-<TULEJA>/<NUMER>` albo pusty napis, gdy brakuje któregoś składnika."""
    s = str(stem or "").strip().upper()
    number = str(match_number or "").strip()
    # Wielkie litery w całości - tak samo jak `proelMatchKey` w aplikacji (numer jest w kluczu kanoniczny).
    return f"{SHARED_KEY_PREFIX}{s}/{number}".upper() if s and number else ""


def shared_stem_of_key(key: Any) -> str:
    """Tuleja z klucza meczu ręcznego (pusta dla innych kluczy)."""
    text = str(key or "").strip()
    if not is_shared_key(text):
        return ""
    return text[len(SHARED_KEY_PREFIX) : text.index("/")].upper()


def number_of_key(key: Any) -> str:
    """Numer meczu bez przedrostka `M-`; inny klucz wraca bez zmian (szkoleniowy obsługuje `proel_training_key`)."""
    text = str(key or "").strip()
    return text[text.index("/") + 1 :] if is_shared_key(text) else text


def stem_of_row(row: Any) -> str:
    """Tuleja zapisanego meczu wspólnego: kolumna, a w wierszu sprzed kolumny początek id serwera."""
    try:
        stored = str(row.get("proel_stem") or "").strip()
        return stored.upper() or stem_from_server_id(row.get("id"))
    except AttributeError:
        return ""


def public_rows_clause(match_number_col: Any, zprp_col: Any = None) -> Any:
    """Warunek SQL „wiersz może trafić do publicznych zestawień": nie szkoleniowy i nie prywatny mecz ręczny.

    Mecz ręczny (`M-...`) bez numerycznego IdZawody nie istnieje w rozgrywkach, więc nie wchodzi w publiczne statystyki
    ani na żywo. Gdy został połączony z prawdziwym meczem (kolumna `zprp_col` niepusta), jest taki jak każdy inny.
    """
    from sqlalchemy import and_, or_

    from app.proel_training_key import TRAINING_KEY_LIKE

    private = match_number_col.ilike(SHARED_KEY_LIKE)
    linked = and_(zprp_col.isnot(None), zprp_col != "") if zprp_col is not None else None
    allowed = or_(~private, linked) if linked is not None else ~private
    return and_(~match_number_col.ilike(TRAINING_KEY_LIKE), allowed)


def shared_key_of_blob(data_json: Any) -> str:
    """Klucz `M-...` z `matchConfig.proelKey` albo "" (mecz z ZPRP, szkoleniowy, brak)."""
    cfg = (data_json or {}).get("matchConfig") if isinstance(data_json, dict) else None
    key = str((cfg or {}).get("proelKey") or "").strip() if isinstance(cfg, dict) else ""
    return key if key and is_shared_key(key) else ""
