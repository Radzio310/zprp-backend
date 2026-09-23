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

Decyzja uzytkownika z 18.09.2026 - „4. sedzia" (drugi stolikowy):
  - klub, ktory zadeklarowal, ze drugiego stolikowego stawia SAM
    (`province_club_assignment.table_by_club = 1`, zakladka Kluby w Obsadzie),
    placi na meczu OKREGOWYM tylko za JEDNEGO stolikowego z okregu. Gdyby okreg
    i tak wystawil dwoch, drugiego pokrywa okreg - mecz dostaje ostrzezenie,
    zamiast po cichu zmienic kwote,
  - gdy stolikowy klubu sie nie stawi, sedzia okregu zostaje przy stoliku sam
    i dostaje POTROJNY ryczalt. To jest ten jeden stolikowy, wiec klub placi
    cale x3 - regula „jeden stolikowy" niczego z tego nie ucina,
  - stoliki lig centralnych i pucharu wojewodzkiego sa poza regula (tam obu
    stolikowych daje zawsze okreg, tak samo jak przy potrojnym ryczalcie),
  - dziala od `table_by_club_since`, zeby zmiana w polowie sezonu nie
    przeliczyla wstecz meczow juz rozliczonych z klubem.

⚠ Gospodarz: najpierw terminarz okregu (`province_matches`), a gdy go tam nie
ma - napis „Gospodarz - Gość", ktory ma KAZDA obsada w bazie. Terminarz trzyma
tylko BIEZACY sezon: mecze minionych sezonow nie mialy gospodarza, po cichu
nikogo nie obciazaly i panel pokazywal 0 zl za caly sezon 2025/2026.

⚠ Mecze nie niosa numeru druzyny, tylko nazwe gospodarza. Dopasowanie idzie po
kluczu nazwy (`province_clubs_scrape.team_key`), a gdy ten sie nie zgadza - po
slowach (`TeamIndex`), bo terminarz i lista druzyn pisza te sama druzyne
roznie („SPR Pogoń 1945 II Zabrze" i „SPR Pogoń II Zabrze"). Nazwa, ktorej nie
znamy, NIE znika: mecz okregowy dostaje status „unassigned" i czeka na reczne
wskazanie druzyny.

MODUL-LISC: bez bazy i sieci, zeby cala regula chodzila w tescie.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Iterable, Optional

from app import settlement_rates as R

#: Status wiersza obciazenia - powod, dla ktorego mecz placi albo nie placi.
CHARGED = "charged"
UNASSIGNED = "unassigned"
CLUB_OFF = "club-off"
EXCLUDED = "excluded"
#: Mecz spoza terminarza okregu (klucz „o:" - stolik na meczu centralnym albo
#: w innym wojewodztwie), ktorego gospodarz nie jest zadna z NASZYCH druzyn.
#: Nikt u nas za niego nie placi i nie ma czego poprawiac, wiec ma wlasny status.
NO_HOST = "no-host"

#: Klucz obsady spoza terminarza okregu.
OUTSIDE_PREFIX = "o:"

#: Liczebniki rzymskie w nazwach druzyn. „Sośnica" i „Sośnica II" to dwie
#: rozne druzyny, wiec przy dopasowaniu po slowach musza sie zgadzac.
_ROMAN = frozenset({"ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x"})


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
    """Czy i od kiedy klub rozlicza sie przez okreg - i kto daje drugi stolik."""

    settles: bool = True
    since: Optional[date] = None
    #: Ilu stolikowych klub stawia SAM, grajac u siebie (0 albo 1).
    table_by_club: int = 0
    #: Od kiedy ta deklaracja dziala na obciazenia. Pusta = od zawsze.
    table_since: Optional[date] = None


@dataclass
class RefereeShare:
    """Ile z tego meczu poszlo na jednego sedziego."""

    judge_id: str
    name: str
    role: str
    gross: int
    travel: float
    triple: bool = False
    #: Czy ta osoba wchodzi do rachunku klubu. `False` = drugi stolikowy
    #: u klubu, ktory stolikowego stawia sam - placi za niego okreg.
    charged: bool = True


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
    travel: float = 0
    amount: float = 0
    status: str = CHARGED
    moved: bool = False
    triple: bool = False
    referees: list[RefereeShare] = field(default_factory=list)
    #: „Gospodarz - Gość" z obsady i sam gosc - panel pokazuje, kto z kim gral.
    teams: str = ""
    guest_name: str = ""
    #: Klub gospodarza stawia drugiego stolikowego sam (deklaracja w Obsadzie)
    #: i w dniu meczu ta deklaracja juz obowiazywala.
    own_table: bool = False
    #: Okreg wystawil drugiego stolikowego wbrew deklaracji klubu - klub za
    #: niego nie placi, a panel pokazuje to jako ostrzezenie.
    extra_table: bool = False
    #: Numer recznego meczu (`manual_charge_rules`) - wiersz dopisany z karty
    #: klubu, a nie z terminarza. `None` = zwykly mecz.
    manual_id: Optional[int] = None


def _as_date(value: Any) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return None


def _default_key(value: Any) -> str:
    return " ".join(str(value or "").lower().split())


def host_from_teams(
    teams: Any,
    *,
    known: Any = (),
    key_of: Optional[Callable[[Any], str]] = None,
) -> str:
    """
    Gospodarz z napisu „Gospodarz - Gość", ktory ma kazda obsada w bazie.

    Nazwa druzyny potrafi sama miec „ - " w srodku, wiec gdy znamy druzyny
    sezonu, wygrywa pierwszy podzial, ktorego lewa strona jest znana druzyna;
    inaczej tekst przed pierwszym „ - ". Bez separatora nie wiadomo, czy to
    gospodarz, czy gosc - wtedy pusto.
    """
    text = " ".join(str(teams or "").split())
    parts = text.split(" - ")
    if len(parts) < 2:
        return ""
    normalize = key_of or _default_key
    for cut in range(1, len(parts)):
        candidate = " - ".join(parts[:cut])
        if normalize(candidate) in known:
            return candidate
    return parts[0]


def guest_from_teams(teams: Any, host: Any) -> str:
    """
    Gosc z napisu „Gospodarz - Gość": to, co stoi za gospodarzem.

    Gospodarz z terminarza bywa zapisany inaczej niz w napisie obsady - wtedy
    tekst za pierwszym „ - ". Bez separatora goscia nie znamy.
    """
    text = " ".join(str(teams or "").split())
    host_text = " ".join(str(host or "").split())
    if host_text and text.startswith(host_text + " - "):
        return text[len(host_text) + 3:]
    parts = text.split(" - ")
    return " - ".join(parts[1:]) if len(parts) > 1 else ""


def category_matches(
    team_category: Any, match_category: Any, key_of: Optional[Callable[[Any], str]] = None
) -> bool:
    """
    „Junior mł." z listy druzyn i „Junior młodszy" z meczu to ta sama kategoria:
    slowo po slowie jedno jest poczatkiem drugiego.
    """
    normalize = key_of or _default_key
    ours = normalize(team_category).split()
    theirs = normalize(match_category).split()
    if not ours or len(ours) != len(theirs):
        return False
    return all(a.startswith(b) or b.startswith(a) for a, b in zip(ours, theirs))


class TeamIndex:
    """
    Druzyny sezonu do rozpoznania gospodarza meczu.

    Najpierw klucz nazwy 1:1. Potem po SLOWACH, bo terminarz i lista druzyn
    potrafia pisac te sama druzyne inaczej („SPR Pogoń 1945 II Zabrze" w meczu,
    „SPR Pogoń II Zabrze" na liscie). Luzne dopasowanie wymaga, zeby:
      - jedna nazwa zawierala wszystkie slowa drugiej (i co najmniej dwa wspolne),
      - liczebniki rzymskie byly TE SAME (II to inna druzyna niz pierwsza),
      - kandydat byl JEDEN - remis zostaje nieprzypisany, zamiast obciazac zly
        klub.
    Ta sama nazwa w kilku kategoriach (klub z juniorami i seniorami) - wygrywa
    druzyna z kategorii meczu.
    """

    def __init__(self, teams: Iterable[TeamRef], key_of: Optional[Callable[[Any], str]] = None):
        self.normalize = key_of or _default_key
        self.by_key: dict[str, list[TeamRef]] = {}
        for team in teams:
            key = self.normalize(team.name)
            if key:
                self.by_key.setdefault(key, []).append(team)
        self.keys = frozenset(self.by_key)
        self._words = {key: frozenset(key.split()) for key in self.by_key}
        self._index: dict[str, set[str]] = {}
        for key, words in self._words.items():
            for word in words:
                self._index.setdefault(word, set()).add(key)
        self._loose: dict[str, Optional[str]] = {}

    def _loose_key(self, key: str) -> Optional[str]:
        if key in self._loose:
            return self._loose[key]
        words = frozenset(key.split())
        roman = words & _ROMAN
        shared: dict[str, int] = {}
        for word in words:
            for other in self._index.get(word, ()):
                shared[other] = shared.get(other, 0) + 1
        ranked = sorted(
            (
                (count, other)
                for other, count in shared.items()
                if count >= 2
                and (self._words[other] & _ROMAN) == roman
                and (self._words[other] <= words or words <= self._words[other])
            ),
            reverse=True,
        )
        best = None
        if ranked and (len(ranked) == 1 or ranked[0][0] > ranked[1][0]):
            best = ranked[0][1]
        self._loose[key] = best
        return best

    def find(self, name: Any, category: Any = "") -> Optional[TeamRef]:
        key = self.normalize(name)
        if not key:
            return None
        if key not in self.by_key:
            key = self._loose_key(key)
            if key is None:
                return None
        options = self.by_key[key]
        for team in options:
            if category_matches(team.category, category, self.normalize):
                return team
        return options[0]


def own_table_applies(setting: Optional[ClubSetting], code: Any, day: Any) -> bool:
    """
    Czy na tym meczu klub gospodarza placi tylko za JEDNEGO stolikowego.

    Trzy warunki naraz: klub zadeklarowal wlasnego stolikowego, mecz jest
    OKREGOWY (stoliki lig centralnych i pucharu wojewodzkiego daje zawsze
    okreg - ta sama granica co przy potrojnym ryczalcie), a deklaracja
    obowiazywala juz w dniu meczu.
    """
    if setting is None or int(setting.table_by_club or 0) <= 0:
        return False
    if R.is_provincial_cup(code) or R.match_level(code) != "district":
        return False
    when = _as_date(day)
    if setting.table_since is not None and (when is None or when < setting.table_since):
        return False
    return True


def keep_one_table(shares: list[RefereeShare]) -> bool:
    """
    Zostawia w rachunku klubu JEDNEGO stolikowego, reszta dostaje `charged=False`.

    Zostaje TANSZY: ryczalt obu stolikowych na tym samym meczu jest ten sam,
    roznia sie tylko dojazdem, a drugiego wystawil okreg wbrew deklaracji klubu.
    Klub nie powinien placic za dalszy dojazd osoby, ktorej nie zamawial.

    ⚠ Wybor zalezy wylacznie od danych, ktore zostaja na zawsze (kwoty i numery
    sedziow). Terminarz okregu wie, kto siedzial na „czasie", ale trzyma tylko
    biezacy sezon - regula oparta na nim zmienilaby rachunek meczu po przelomie
    sezonu.

    Zwraca True, gdy cokolwiek zdjeto.
    """
    tables = [share for share in shares if share.role.startswith(R.ROLE_TABLE)]
    if len(tables) < 2:
        return False
    keep = min(tables, key=lambda share: (share.gross + share.travel, share.judge_id))
    for share in tables:
        if share is not keep:
            share.charged = False
    return True


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
    obsada). `hosts` to gospodarze z terminarza okregu (klucz meczu -> nazwa).
    `key_of` to funkcja normalizujaca nazwe druzyny - wstrzykiwana, zeby modul
    zostal lisciem (parser stron ma wlasne zaleznosci).
    """
    overrides = overrides or {}
    clubs = clubs or {}
    judge_names = judge_names or {}
    teams_by_id = teams_by_id or {}
    normalize = key_of or _default_key
    # Wszystkie druzyny sezonu - `teams_by_key` trzyma tylko pierwsza z danej
    # nazwy, a ta sama nazwa bywa w kilku kategoriach.
    index = TeamIndex(list(teams_by_id.values()) or list(teams_by_key.values()), normalize)

    grouped: dict[str, ChargeRow] = {}
    for item in settled:
        row = grouped.get(item.match_key)
        teams = " ".join(str(getattr(item, "teams", "") or "").split())
        if row is None:
            host = hosts.get(item.match_key, "") or host_from_teams(
                teams, known=index.keys, key_of=normalize
            )
            row = ChargeRow(
                match_key=item.match_key,
                match_at=item.match_at,
                day=item.day,
                code=item.match_code,
                category=item.category,
                city=item.city,
                host_name=host,
                teams=teams,
                guest_name=guest_from_teams(teams, host),
            )
            grouped[item.match_key] = row
        elif teams and not row.teams:
            # Pierwsza obsada meczu bywa bez napisu druzyn - bierzemy z kolejnej.
            row.host_name = row.host_name or host_from_teams(teams, known=index.keys, key_of=normalize)
            row.teams = teams
            row.guest_name = guest_from_teams(teams, row.host_name)
        row.gross += int(item.gross or 0)
        row.travel = round(row.travel + float(item.travel or 0), 2)
        row.triple = row.triple or bool(getattr(item, "triple_table", False))
        row.referees.append(
            RefereeShare(
                judge_id=item.judge_id,
                name=judge_names.get(item.judge_id, ""),
                role=item.role,
                gross=int(item.gross or 0),
                travel=float(item.travel or 0),
                triple=bool(getattr(item, "triple_table", False)),
            )
        )

    out: list[ChargeRow] = []
    for row in grouped.values():
        row.referees.sort(key=lambda share: (share.role, share.name, share.judge_id))
        override = overrides.get(row.match_key) or MatchOverride()

        team: Optional[TeamRef] = None
        if override.team_id:
            team = teams_by_id.get(override.team_id)
            row.moved = True
            if team is None and override.team_name:
                team = teams_by_key.get(normalize(override.team_name)) or index.find(
                    override.team_name
                )
        if team is None and not override.team_id:
            team = index.find(row.host_name, row.category)

        if team is not None:
            row.team_id = team.team_id
            row.team_name = team.name
            row.club_id = team.club_id

        # Drugi stolikowy u klubu, ktory stolikowego stawia sam. Liczymy przed
        # kwota, bo kwota to suma tylko tych, ktorzy wchodza do rachunku.
        setting = clubs.get(team.club_id) if team is not None else None
        if own_table_applies(setting, row.code, row.day):
            row.own_table = True
            row.extra_table = keep_one_table(row.referees)
        charged_shares = [share for share in row.referees if share.charged]
        row.gross = sum(int(share.gross or 0) for share in charged_shares)
        row.travel = round(sum(float(share.travel or 0) for share in charged_shares), 2)
        row.amount = round(row.gross + row.travel, 2)

        if override.excluded:
            row.status = EXCLUDED
        elif team is None:
            # Mecz okregowy bez druzyny to dziura do poprawienia - panel pokazuje
            # go w „bez rozpoznanej druzyny". Stolik spoza terminarza z obcym
            # gospodarzem nie jest nasza sprawa.
            row.status = NO_HOST if row.match_key.startswith(OUTSIDE_PREFIX) else UNASSIGNED
        else:
            setting = setting or ClubSetting()
            if not setting.settles and (
                setting.since is None or (_as_date(row.day) or date.max) >= setting.since
            ):
                row.status = CLUB_OFF
            else:
                row.status = CHARGED
        out.append(row)

    out.sort(key=lambda item: (item.day or date.min, item.match_key))
    return out


def club_totals(rows: Iterable[ChargeRow]) -> dict[str, dict[str, int | float]]:
    """Suma obciazen na klub - liczymy TYLKO wiersze ze statusem `charged`."""
    totals: dict[str, dict[str, int | float]] = {}
    for row in rows:
        if row.status != CHARGED or not row.club_id:
            continue
        entry = totals.setdefault(row.club_id, {"charged": 0, "matches": 0, "gross": 0, "travel": 0})
        entry["charged"] = round(entry["charged"] + row.amount, 2)
        entry["gross"] += row.gross
        entry["travel"] = round(entry["travel"] + row.travel, 2)
        entry["matches"] += 1
    return totals


def team_totals(rows: Iterable[ChargeRow]) -> dict[str, dict[str, int | float]]:
    """To samo w rozbiciu na druzyny - do rozliczenia klubu z kilkoma zespolami."""
    totals: dict[str, dict[str, int | float]] = {}
    for row in rows:
        if row.status != CHARGED or not row.team_id:
            continue
        entry = totals.setdefault(row.team_id, {"charged": 0, "matches": 0})
        entry["charged"] = round(entry["charged"] + row.amount, 2)
        entry["matches"] += 1
    return totals


def balance(*, paid_in: float, paid_out: float, charged: float) -> int:
    """
    Saldo klubu: wplaty minus wyplaty minus obciazenia.

    Dodatnie = klub ma u okregu nadwyzke, ujemne = zalega.
    """
    return round(float(paid_in) - float(paid_out) - float(charged))
