"""
Czy mecz z listy sędziego to mecz NASZEGO okręgu - reguła dla minionych sezonów.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

Monitor okręgu trzyma tylko bieżący terminarz, więc mecze minionych sezonów
znamy wyłącznie z prywatnych list sędziów. Na tych listach sa też mecze INNYCH
okręgów - sędzia ze Śląska w meczu ligi lubelskiej („L/MłK/20"). Dotąd każdy
mecz okręgowy z listy minionego sezonu szedł jako nasz, we wszystkich rolach,
a ten sam mecz w bieżącym sezonie wchodzi tylko dla stolikowego, jako mecz
spoza okręgu. Decyzja użytkownika z 11.09.2026: minione sezony liczą się tak
samo.

Przynależność rozpoznajemy po PRZEDROSTKU numeru („S/" to Śląsk, „L/"
Lubelskie). Nasze przedrostki bierzemy z WŁASNEGO terminarza okręgu zamiast
trzymać mape województw - numeracji ZPRP nie mamy skąd potwierdzić, a terminarz
jest faktem. Numer bez przedrostka („JMM/3", „IIIM/9") nie mówi nic, więc
zostaje nasz, jak dotąd.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Iterable, Optional

from app import settlement_rates as R
from app.proel_stats_rules import prefix_of
from app.settlement_seasons import season_of

#: Tyle meczów z danym przedrostkiem musi stać w naszym terminarzu, żeby uznać
#: go za nasz - jeden zabłąkany numer nie przypisze okręgowi cudzej ligi.
MIN_OWN_MATCHES = 2

#: ...i taką część meczów NAJCZĘSTSZEGO przedrostka. Terminarz okręgu to nie
#: tylko nasz terminarz: monitor śledzi też mecze z list naszych sędziów, więc
#: sędzia z Częstochowy z dwoma meczami juniorek w Piotrkowie („E/JmK/1",
#: „E/JmK/3") robił z „E" nasz przedrostek (zgłoszenie z 06.10.2026). Własny
#: przedrostek ma w terminarzu setki meczów, cudzy - pojedyncze.
OWN_SHARE_OF_TOP = 0.25

#: Werdykty `history_fix` dla obsady zapisanej stara reguła.
KEEP = "keep"
OUTSIDE = "outside"
DROP = "drop"

#: Szczeble, które z listy minionego sezonu wchodzą jak własne - bez zmian
#: względem dotychczasowej reguły, dochodzi tylko warunek przedrostka.
_OWN_LEVELS = ("district", "cup")


def own_prefixes(codes: Iterable[Any], *, min_matches: int = MIN_OWN_MATCHES) -> set[str]:
    """
    Przedrostki numerów z terminarza okręgu: rozgrywki okręgowe i puchar wojewódzki.

    Przedrostek jest nasz, gdy stoi przy co najmniej `min_matches` meczach ORAZ
    przy ćwierci tego, co ma przedrostek najczęstszy (`OWN_SHARE_OF_TOP`) -
    patrz uwaga przy stałej.
    """
    counts: Counter = Counter()
    for code in codes:
        prefix = prefix_of(code)
        if prefix and (R.match_level(code) == "district" or R.is_provincial_cup(code)):
            counts[prefix] += 1
    if not counts:
        return set()
    top = max(counts.values())
    return {
        prefix
        for prefix, count in counts.items()
        if count >= min_matches and count >= top * OWN_SHARE_OF_TOP
    }


def is_other_district(code: Any, own: Iterable[str]) -> bool:
    """
    Numer z przedrostkiem okręgu, który NIE jest naszym.

    Bez przedrostka albo bez wiedzy o naszych przedrostkach nie wiemy nic - wtedy
    mecz NIE jest obcy (zostaje, jak był), zamiast po cichu wypaść z rozliczenia.
    """
    prefix = prefix_of(code)
    mine = set(own or ())
    return bool(prefix and mine and prefix not in mine)


def foreign_exempt(code: Any) -> bool:
    """
    Rozgrywki z cudzym przedrostkiem, które mimo to są NASZE.

    Młodzik makroregionalny („K/MłMR/12", „K/MłKR/3"): makroregion prowadzą
    razem sąsiednie okręgi i numer nadaje jeden z nich, a nasi sędziowie
    sędziują te turnieje w obsadzie okręgu. Decyzja użytkownika z 06.10.2026:
    takie mecze liczą się normalnie, w każdej roli - z rozliczenia zdejmuje je
    tylko „Nie obciążaj klubów" w Panelu klubów. Reguła meczów innych okręgów
    („E/JmK/3") zostaje dla całej reszty.
    """
    return R.is_regional_youth_competition(code)


def _foreign(code: Any, own: Iterable[str]) -> bool:
    return is_other_district(code, own) and not foreign_exempt(code)


def _district_level(code: Any) -> bool:
    """
    Szczebel, który z listy minionego sezonu wchodzi jak własny.

    ⚠ Puchar wojewódzki („S/PPK/2") ma szczebel „central", bo płaci stawkami
    II ligi - ale to mecz OKRĘGU i okręg rozlicza go w KAŻDEJ roli. Bez tego
    warunku z minionych sezonów wchodziły same jego stoliki (poprawka 11.09.2026).
    """
    return R.match_level(code) in _OWN_LEVELS or R.is_provincial_cup(code)


def foreign_district_match(code: Any, own: Iterable[str]) -> bool:
    """
    Mecz rozgrywek okręgowych INNEGO okręgu („E/JmK/3" przy naszym „S/").

    Nie jest nasz w żadnym sezonie: liczy się jak mecz spoza okręgu, czyli tylko
    stolik (decyzja z 11.09.2026, od 06.10.2026 także w bieżącym sezonie).
    """
    return _district_level(code) and _foreign(code, own)


def own_past_match(code: Any, own: Iterable[str]) -> bool:
    """
    Mecz minionego sezonu z listy sędziego liczony jak WŁASNY, czyli w każdej roli.

    Rozgrywki okręgowe, puchary i puchar wojewódzki - ale bez meczów innych
    okręgów: te idą jak w bieżącym sezonie, tylko stolik, jako mecz spoza okręgu.
    """
    return _district_level(code) and not _foreign(code, own)


def collected_after_season(first_seen: Optional[datetime], season: str) -> bool:
    """Obsada zapisana dopiero PO sezonie - czyli z listy sędziego, nie z terminarza."""
    seen = season_of(first_seen)
    return bool(seen and season and seen > season)


def history_fix(
    *,
    match_key: Any,
    match_code: Any,
    role: Any,
    season: str,
    first_seen: Optional[datetime],
    current: str,
    own: Iterable[str],
) -> str:
    """
    Co zrobić z obsada „d:" meczu INNEGO okręgu.

    Mecz innego okręgu: stolik przechodzi na „o:" (mecz spoza okręgu), każda
    inna rola gaśnie.

    BIEŻĄCY sezon (06.10.2026): zawsze. Terminarz okręgu trzyma też mecze z list
    naszych sędziów, więc „d:" nie znaczy tu „obsadza nas okręg" - sędzia
    boiskowy meczu juniorek w Piotrkowie dostawał go od nas jak własny.

    MINIONE sezony: jak dotąd tylko obsady, które przyszły z listy sędziego
    (zapisane po końcu sezonu). Tamte sezony są rozliczone i zamknięte - ich
    terminarza nie ruszamy.
    """
    if not str(match_key or "").startswith("d:"):
        return KEEP
    if not season or not current:
        return KEEP
    if not foreign_district_match(match_code, own):
        return KEEP
    if season < current and not collected_after_season(first_seen, season):
        return KEEP
    return OUTSIDE if str(role or "").strip() == R.ROLE_TABLE else DROP
