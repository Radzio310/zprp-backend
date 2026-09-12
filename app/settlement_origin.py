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

#: Werdykty `history_fix` dla obsady zapisanej stara reguła.
KEEP = "keep"
OUTSIDE = "outside"
DROP = "drop"

#: Szczeble, które z listy minionego sezonu wchodzą jak własne - bez zmian
#: względem dotychczasowej reguły, dochodzi tylko warunek przedrostka.
_OWN_LEVELS = ("district", "cup")


def own_prefixes(codes: Iterable[Any], *, min_matches: int = MIN_OWN_MATCHES) -> set[str]:
    """Przedrostki numerów z terminarza okręgu: rozgrywki okręgowe i puchar wojewódzki."""
    counts: Counter = Counter()
    for code in codes:
        prefix = prefix_of(code)
        if prefix and (R.match_level(code) == "district" or R.is_provincial_cup(code)):
            counts[prefix] += 1
    return {prefix for prefix, count in counts.items() if count >= min_matches}


def is_other_district(code: Any, own: Iterable[str]) -> bool:
    """
    Numer z przedrostkiem okręgu, który NIE jest naszym.

    Bez przedrostka albo bez wiedzy o naszych przedrostkach nie wiemy nic - wtedy
    mecz NIE jest obcy (zostaje, jak był), zamiast po cichu wypaść z rozliczenia.
    """
    prefix = prefix_of(code)
    mine = set(own or ())
    return bool(prefix and mine and prefix not in mine)


def _district_level(code: Any) -> bool:
    """
    Szczebel, który z listy minionego sezonu wchodzi jak własny.

    ⚠ Puchar wojewódzki („S/PPK/2") ma szczebel „central", bo płaci stawkami
    II ligi - ale to mecz OKRĘGU i okręg rozlicza go w KAŻDEJ roli. Bez tego
    warunku z minionych sezonów wchodziły same jego stoliki (poprawka 11.09.2026).
    """
    return R.match_level(code) in _OWN_LEVELS or R.is_provincial_cup(code)


def own_past_match(code: Any, own: Iterable[str]) -> bool:
    """
    Mecz minionego sezonu z listy sędziego liczony jak WŁASNY, czyli w każdej roli.

    Rozgrywki okręgowe, puchary i puchar wojewódzki - ale bez meczów innych
    okręgów: te idą jak w bieżącym sezonie, tylko stolik, jako mecz spoza okręgu.
    """
    return _district_level(code) and not is_other_district(code, own)


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
    Co zrobić z obsada zapisana reguła sprzed 11.09.2026.

    Dotyczy wyłącznie obsad „d:" z minionych sezonów, które przyszły z listy
    sędziego (zapisane po końcu sezonu) - terminarz okręgu to nasza kaskada
    i jego nie ruszamy. Mecz innego okręgu: stolik przechodzi na „o:" (jak
    w bieżącym sezonie), każda inna rola gaśnie.
    """
    if not str(match_key or "").startswith("d:"):
        return KEEP
    if not season or not current or season >= current:
        return KEEP
    if not collected_after_season(first_seen, season):
        return KEEP
    if not _district_level(match_code) or not is_other_district(match_code, own):
        return KEEP
    return OUTSIDE if str(role or "").strip() == R.ROLE_TABLE else DROP
