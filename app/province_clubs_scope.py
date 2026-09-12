"""
Panel klubów - które kluby należą do sezonu.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

⚠ Tabela `province_clubs` trzyma KAŻDY klub, który kiedykolwiek pojawił się na
liście drużyn: pobieranie dopisuje go tam przy pierwszym spotkaniu, żeby miał
nazwę i ustawienia. Lista sezonu doklejała wszystkie te wiersze, więc klub
z innego sezonu wisiał w każdym sezonie z „0 drużyn" (zgłoszenie 11.09.2026).

Drugie źródło szumu to grupy II ligi prowadzone przez okręg. Na ich listach sa
też rywale z innych województw (AZS AGH Kraków, kluby z Kielc i Puław), a oni
okręgowi nic nie płacą - u siebie mają stoliki ze swojego okręgu.

Klub należy do sezonu, gdy:
  - ma w nim mecz na koncie (w każdym statusie) albo wpłatę / wypłatę -
    pieniądze nie mogą zniknąć z widoku,
  - albo gra w rozgrywkach OKRĘGOWYCH (tam gospodarz płaci okręgowi, nawet gdy
    jest z sąsiedniego województwa),
  - albo jest z NASZEGO województwa i gra w rozgrywkach centralnych.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from app import settlement_rates as R


def is_district_code(code: Any) -> bool:
    """Rozgrywki okręgu: III liga i niżej oraz puchar wojewódzki („S/PPK")."""
    return R.is_provincial_cup(code) or R.match_level(code) == "district"


def _province(team: dict) -> str:
    return str(team.get("province") or "").strip().upper()


def _plays_district(team: dict) -> bool:
    return any(is_district_code(code) for code in team.get("codes") or ())


def home_province(teams: Iterable[dict]) -> str:
    """
    Kod naszego województwa na listach drużyn („SL").

    Nie trzymamy mapy okręg -> kod: bierzemy najczęstszy kod wśród drużyn
    rozgrywek okręgowych, a bez nich - wśród wszystkich drużyn sezonu. Remis
    rozstrzyga alfabet, żeby wynik nie zależał od kolejności pobierania.
    """
    teams = list(teams)
    counts = Counter(_province(team) for team in teams if _province(team) and _plays_district(team))
    if not counts:
        counts = Counter(_province(team) for team in teams if _province(team))
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def team_in_scope(team: dict, home: str) -> bool:
    """Drużyna, która może okręgowi coś zapłacić."""
    if _plays_district(team):
        return True
    province = _province(team)
    return not home or not province or province == home


def season_club_ids(teams: Iterable[dict], active: Iterable[Any]) -> set[str]:
    """
    Kluby sezonu: każdy z meczem albo wpisem (`active`) i każdy z drużyna
    w zasięgu okręgu. Sam wiersz ustawień klubu NIE wystarcza.
    """
    teams = list(teams)
    home = home_province(teams)
    out = {str(value).strip() for value in active if str(value or "").strip()}
    for team in teams:
        club_id = str(team.get("club_id") or "").strip()
        if club_id and team_in_scope(team, home):
            out.add(club_id)
    return out
