"""
Obciazenia klubow za mecze - ile klub gospodarza jest winien okregowi.

Decyzje uzytkownika z 10.09.2026:
  - klub placi BRUTTO + PRZEJAZDY calej obsady, ktora rozlicza OKREG, czyli
    dokladnie tyle, ile okreg za ten mecz wyplaca (rachunek robi
    `settlement_engine`, tutaj tylko sumujemy),
  - obciazamy mecze okregowe ORAZ stoliki na meczach centralnych - to samo, co
    okreg ma w zestawieniu, wiec kwoty po obu stronach sie schodza,
  - placi GOSPODARZ; zmiana gospodarza albo zwolnienie meczu z oplaty to reczny
    wyjatek na meczu,
  - klub z odznaczonym „rozlicza sie przez okreg" nie jest obciazany od daty
    wskazanej przy odznaczeniu (historia zostaje).

⚠ Mecze nie niosa numeru druzyny, tylko nazwe gospodarza - dopasowanie idzie po
kluczu nazwy (`province_clubs_scrape.team_key`). Nazwa, ktorej nie znamy, NIE
znika: mecz dostaje status „unassigned" i czeka na reczne wskazanie druzyny.

MODUL-LISC: bez bazy i sieci, zeby cala regula chodzila w tescie.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Iterable, Optional

#: Status wiersza obciazenia - powod, dla ktorego mecz placi albo nie placi.
CHARGED = "charged"
UNASSIGNED = "unassigned"
CLUB_OFF = "club-off"
EXCLUDED = "excluded"
#: Mecz spoza terminarza okregu (stolik w innym wojewodztwie) - gospodarza nie
#: znamy i nikt z NASZYCH klubow za niego nie placi. To nie jest brak
#: przypisania do poprawienia, wiec ma wlasny status.
NO_HOST = "no-host"


@dataclass(frozen=True)
class TeamRef:
    """Druzyna ze slownika sezonu."""

    team_id: str
    club_id: str
    name: str
    category: str = ""
    gender: str = ""


@dataclass
class MatchOverride:
    """Reczny wyjatek na meczu."""

    excluded: bool = False
    team_id: str = ""
    team_name: str = ""
    triple_table: bool = False


@dataclass
class ClubSetting:
    """Czy i od kiedy klub rozlicza sie przez okreg."""

    settles: bool = True
    since: Optional[date] = None


@dataclass
class RefereeShare:
    """Ile z tego meczu poszlo na jednego sedziego."""

    judge_id: str
    name: str
    role: str
    gross: int
    travel: int
    triple: bool = False


@dataclass
class ChargeRow:
    """Jeden mecz w rachunku klubu."""

    match_key: str
    match_at: Optional[datetime]
    day: Optional[date]
    code: str
    category: str
    city: str
    host_name: str
    team_id: str = ""
    team_name: str = ""
    club_id: str = ""
    gross: int = 0
    travel: int = 0
    amount: int = 0
    status: str = CHARGED
    moved: bool = False
    triple: bool = False
    referees: list[RefereeShare] = field(default_factory=list)


def _as_date(value: Any) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return None


def build_charges(
    settled: Iterable[Any],
    *,
    hosts: dict[str, str],
    teams_by_key: dict[str, TeamRef],
    teams_by_id: Optional[dict[str, TeamRef]] = None,
    overrides: Optional[dict[str, MatchOverride]] = None,
    clubs: Optional[dict[str, ClubSetting]] = None,
    judge_names: Optional[dict[str, str]] = None,
    key_of: Any = None,
) -> list[ChargeRow]:
    """
    Z obsad policzonych przez silnik robi wiersze obciazen, mecz po meczu.

    `settled` to `SettledMatch` z `settlement_engine` (jeden wiersz = jedna
    obsada). `key_of` to funkcja normalizujaca nazwe druzyny - wstrzykiwana,
    zeby modul zostal lisciem (parser stron ma wlasne zaleznosci).
    """
    overrides = overrides or {}
    clubs = clubs or {}
    judge_names = judge_names or {}
    teams_by_id = teams_by_id or {}
    normalize = key_of or (lambda value: str(value or "").strip().lower())

    grouped: dict[str, ChargeRow] = {}
    for item in settled:
        row = grouped.get(item.match_key)
        if row is None:
            row = ChargeRow(
                match_key=item.match_key,
                match_at=item.match_at,
                day=item.day,
                code=item.match_code,
                category=item.category,
                city=item.city,
                host_name=hosts.get(item.match_key, ""),
            )
            grouped[item.match_key] = row
        row.gross += int(item.gross or 0)
        row.travel += int(item.travel or 0)
        row.triple = row.triple or bool(getattr(item, "triple_table", False))
        row.referees.append(
            RefereeShare(
                judge_id=item.judge_id,
                name=judge_names.get(item.judge_id, ""),
                role=item.role,
                gross=int(item.gross or 0),
                travel=int(item.travel or 0),
                triple=bool(getattr(item, "triple_table", False)),
            )
        )

    out: list[ChargeRow] = []
    for row in grouped.values():
        row.amount = row.gross + row.travel
        row.referees.sort(key=lambda share: (share.role, share.name, share.judge_id))
        override = overrides.get(row.match_key) or MatchOverride()

        team: Optional[TeamRef] = None
        if override.team_id:
            team = teams_by_id.get(override.team_id)
            row.moved = True
            if team is None and override.team_name:
                team = teams_by_key.get(normalize(override.team_name))
        if team is None and not override.team_id:
            team = teams_by_key.get(normalize(row.host_name))

        if team is not None:
            row.team_id = team.team_id
            row.team_name = team.name
            row.club_id = team.club_id

        if override.excluded:
            row.status = EXCLUDED
        elif team is None:
            row.status = UNASSIGNED if row.host_name else NO_HOST
        else:
            setting = clubs.get(team.club_id) or ClubSetting()
            if not setting.settles and (
                setting.since is None or (_as_date(row.day) or date.max) >= setting.since
            ):
                row.status = CLUB_OFF
            else:
                row.status = CHARGED
        out.append(row)

    out.sort(key=lambda item: (item.day or date.min, item.match_key))
    return out


def club_totals(rows: Iterable[ChargeRow]) -> dict[str, dict[str, int]]:
    """Suma obciazen na klub - liczymy TYLKO wiersze ze statusem `charged`."""
    totals: dict[str, dict[str, int]] = {}
    for row in rows:
        if row.status != CHARGED or not row.club_id:
            continue
        entry = totals.setdefault(row.club_id, {"charged": 0, "matches": 0, "gross": 0, "travel": 0})
        entry["charged"] += row.amount
        entry["gross"] += row.gross
        entry["travel"] += row.travel
        entry["matches"] += 1
    return totals


def team_totals(rows: Iterable[ChargeRow]) -> dict[str, dict[str, int]]:
    """To samo w rozbiciu na druzyny - do rozliczenia klubu z kilkoma zespolami."""
    totals: dict[str, dict[str, int]] = {}
    for row in rows:
        if row.status != CHARGED or not row.team_id:
            continue
        entry = totals.setdefault(row.team_id, {"charged": 0, "matches": 0})
        entry["charged"] += row.amount
        entry["matches"] += 1
    return totals


def balance(*, paid_in: float, paid_out: float, charged: float) -> int:
    """
    Saldo klubu: wplaty minus wyplaty minus obciazenia.

    Dodatnie = klub ma u okregu nadwyzke, ujemne = zalega.
    """
    return round(float(paid_in) - float(paid_out) - float(charged))
