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
)

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
    "hala",
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
