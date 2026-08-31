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
