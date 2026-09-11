"""
Czy mecz z listy sedziego to mecz NASZEGO okregu - regula dla minionych sezonow.

MODUL-LISC: bez bazy i sieci, zeby regula chodzila w tescie.

Monitor okregu trzyma tylko biezacy terminarz, wiec mecze minionych sezonow
znamy wylacznie z prywatnych list sedziow. Na tych listach sa tez mecze INNYCH
okregow - sedzia ze Slaska w meczu ligi lubelskiej („L/MłK/20"). Dotad kazdy
mecz okregowy z listy minionego sezonu szedl jako nasz, we wszystkich rolach,
a ten sam mecz w biezacym sezonie wchodzi tylko dla stolikowego, jako mecz
spoza okregu. Decyzja uzytkownika z 11.09.2026: minione sezony licza sie tak
samo.

Przynaleznosc rozpoznajemy po PRZEDROSTKU numeru („S/" to Slask, „L/"
Lubelskie). Nasze przedrostki bierzemy z WLASNEGO terminarza okregu zamiast
trzymac mape wojewodztw - numeracji ZPRP nie mamy skad potwierdzic, a terminarz
jest faktem. Numer bez przedrostka („JMM/3", „IIIM/9") nie mowi nic, wiec
zostaje nasz, jak dotad.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Iterable, Optional

from app import settlement_rates as R
from app.proel_stats_rules import prefix_of
from app.settlement_seasons import season_of

#: Tyle meczow z danym przedrostkiem musi stac w naszym terminarzu, zeby uznac
#: go za nasz - jeden zablakany numer nie przypisze okregowi cudzej ligi.
MIN_OWN_MATCHES = 2

#: Werdykty `history_fix` dla obsady zapisanej stara regula.
KEEP = "keep"
OUTSIDE = "outside"
DROP = "drop"

#: Szczeble, ktore z listy minionego sezonu wchodza jak wlasne - bez zmian
#: wzgledem dotychczasowej reguly, dochodzi tylko warunek przedrostka.
_OWN_LEVELS = ("district", "cup")


def own_prefixes(codes: Iterable[Any], *, min_matches: int = MIN_OWN_MATCHES) -> set[str]:
    """Przedrostki numerow z terminarza okregu: rozgrywki okregowe i puchar wojewodzki."""
    counts: Counter = Counter()
    for code in codes:
        prefix = prefix_of(code)
        if prefix and (R.match_level(code) == "district" or R.is_provincial_cup(code)):
            counts[prefix] += 1
    return {prefix for prefix, count in counts.items() if count >= min_matches}


def is_other_district(code: Any, own: Iterable[str]) -> bool:
    """
    Numer z przedrostkiem okregu, ktory NIE jest naszym.

    Bez przedrostka albo bez wiedzy o naszych przedrostkach nie wiemy nic - wtedy
    mecz NIE jest obcy (zostaje, jak byl), zamiast po cichu wypasc z rozliczenia.
    """
    prefix = prefix_of(code)
    mine = set(own or ())
    return bool(prefix and mine and prefix not in mine)


def own_past_match(code: Any, own: Iterable[str]) -> bool:
    """
    Mecz minionego sezonu z listy sedziego liczony jak WLASNY, czyli w kazdej roli.

    Szczebel jak dotad (rozgrywki okregowe i puchary), ale bez meczow innych
    okregow - te ida jak w biezacym sezonie: tylko stolik, jako mecz spoza okregu.
    """
    return R.match_level(code) in _OWN_LEVELS and not is_other_district(code, own)


def collected_after_season(first_seen: Optional[datetime], season: str) -> bool:
    """Obsada zapisana dopiero PO sezonie - czyli z listy sedziego, nie z terminarza."""
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
    Co zrobic z obsada zapisana regula sprzed 11.09.2026.

    Dotyczy wylacznie obsad „d:" z minionych sezonow, ktore przyszly z listy
    sedziego (zapisane po koncu sezonu) - terminarz okregu to nasza kaskada
    i jego nie ruszamy. Mecz innego okregu: stolik przechodzi na „o:" (jak
    w biezacym sezonie), kazda inna rola gasnie.
    """
    if not str(match_key or "").startswith("d:"):
        return KEEP
    if not season or not current or season >= current:
        return KEEP
    if not collected_after_season(first_seen, season):
        return KEEP
    if R.match_level(match_code) not in _OWN_LEVELS or not is_other_district(match_code, own):
        return KEEP
    return OUTSIDE if str(role or "").strip() == R.ROLE_TABLE else DROP
