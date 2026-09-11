"""
Panel klubow - ktore kluby naleza do sezonu.

MODUL-LISC: bez bazy i sieci, zeby regula chodzila w tescie.

⚠ Tabela `province_clubs` trzyma KAZDY klub, ktory kiedykolwiek pojawil sie na
liscie druzyn: pobieranie dopisuje go tam przy pierwszym spotkaniu, zeby mial
nazwe i ustawienia. Lista sezonu doklejala wszystkie te wiersze, wiec klub
z innego sezonu wisial w kazdym sezonie z „0 druzyn" (zgloszenie 11.09.2026).

Drugie zrodlo szumu to grupy II ligi prowadzone przez okreg. Na ich listach sa
tez rywale z innych wojewodztw (AZS AGH Krakow, kluby z Kielc i Pulaw), a oni
okregowi nic nie placa - u siebie maja stoliki ze swojego okregu.

Klub nalezy do sezonu, gdy:
  - ma w nim mecz na koncie (w kazdym statusie) albo wplate / wyplate -
    pieniadze nie moga zniknac z widoku,
  - albo gra w rozgrywkach OKREGOWYCH (tam gospodarz placi okregowi, nawet gdy
    jest z sasiedniego wojewodztwa),
  - albo jest z NASZEGO wojewodztwa i gra w rozgrywkach centralnych.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from app import settlement_rates as R


def is_district_code(code: Any) -> bool:
    """Rozgrywki okregu: III liga i nizej oraz puchar wojewodzki („S/PPK")."""
    return R.is_provincial_cup(code) or R.match_level(code) == "district"


def _province(team: dict) -> str:
    return str(team.get("province") or "").strip().upper()


def _plays_district(team: dict) -> bool:
    return any(is_district_code(code) for code in team.get("codes") or ())


def home_province(teams: Iterable[dict]) -> str:
    """
    Kod naszego wojewodztwa na listach druzyn („SL").

    Nie trzymamy mapy okreg -> kod: bierzemy najczestszy kod wsrod druzyn
    rozgrywek okregowych, a bez nich - wsrod wszystkich druzyn sezonu. Remis
    rozstrzyga alfabet, zeby wynik nie zalezal od kolejnosci pobierania.
    """
    teams = list(teams)
    counts = Counter(_province(team) for team in teams if _province(team) and _plays_district(team))
    if not counts:
        counts = Counter(_province(team) for team in teams if _province(team))
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def team_in_scope(team: dict, home: str) -> bool:
    """Druzyna, ktora moze okregowi cos zaplacic."""
    if _plays_district(team):
        return True
    province = _province(team)
    return not home or not province or province == home


def season_club_ids(teams: Iterable[dict], active: Iterable[Any]) -> set[str]:
    """
    Kluby sezonu: kazdy z meczem albo wpisem (`active`) i kazdy z druzyna
    w zasiegu okregu. Sam wiersz ustawien klubu NIE wystarcza.
    """
    teams = list(teams)
    home = home_province(teams)
    out = {str(value).strip() for value in active if str(value or "").strip()}
    for team in teams:
        club_id = str(team.get("club_id") or "").strip()
        if club_id and team_in_scope(team, home):
            out.add(club_id)
    return out
