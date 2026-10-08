"""Podzial rozliczenia wedlug tego, kto faktycznie placi obsade.

Panel klubow od dawna umial oznaczyc klub jako nierozliczany przez okreg, ale
ta informacja nie byla stosowana do listy wyplat sedziow. Ten modul jest jednym
mostem pomiedzy tymi dwiema czesciami aplikacji. Nie liczy kwot: rozpoznaje
mecze klubow z wylaczonym rozliczaniem (`match_keys`) i mecze zdjete z rozliczen
przyciskiem „Nie obciazaj klubow" (`excluded_keys`), a silnik rozliczen
przelicza grupy osobno.

Decyzja uzytkownika z 06.10.2026: „Nie obciazaj klubow" znaczy „nikt u nas za
ten mecz nie placi" - mecz wypada takze z wyplat okregu (sedzia widzi go
w bloku „Poza rozliczeniem okregu", bez kwot). Gdy okreg ma placic sam, jest
„Przenies koszt na okreg" (`district_payer`).

II LIGA (decyzja z 07.10.2026). Grupa II ligi powierzona okregowi (IIM4/IIK4
na Slasku) ma kluby z kilku wojewodztw - Szulc i Wieclaw dostawali od Slaska
mecze w Kielcach. Mecz II ligi idzie do wyplat okregu TYLKO, gdy gospodarzem
jest klub z panelu tego okregu rozliczany przez okreg (albo koszt
przeniesiono na okreg); kazdy inny - klub z okregu nierozliczany przez okreg,
gospodarz spoza okregu, gospodarz nierozpoznany - idzie jak klub
rozliczajacy sie sam (blok „Rozliczane bezposrednio przez kluby").
Regula jest ogolna, dla kazdego okregu.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any, Iterable

from sqlalchemy import and_, select

from app import club_charges as C
from app.db import (
    database,
    province_club_teams,
    province_clubs,
    province_match_overrides,
    province_matches,
    province_tournament_hosts,
)
from app.province_clubs_scrape import team_key
from app.settlement_province import spellings

#: Od tego dnia „Nie obciazaj klubow" zdejmuje mecz takze z wyplat okregu.
#: Wczesniej przycisk znaczyl „okreg placi, klub nie" i tak rozliczono minione
#: sezony - ich nie przepisujemy (ta sama granica co w `club_charges`).
EXCLUDED_UNPAID_SINCE = date(2026, 9, 1)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _state(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


def _foreign_clubs(rows: Iterable[Any]) -> dict[str, set[str]]:
    """
    Kluby z INNEGO wojewodztwa, sezon po sezonie (07.10.2026) - rywale z grup
    II ligi prowadzonych przez okreg (`club_charges.paid_by_club`). Nasze
    wojewodztwo jak w panelu klubow (`province_clubs_scope.home_province`);
    klub z choc jedna druzyna u nas jest nasz.
    """
    from app.province_clubs_scope import home_province

    by_season: dict[str, list[dict]] = {}
    for row in rows:
        by_season.setdefault(_s(row["season"]), []).append(
            {
                "province": _s(row["team_province"]),
                "codes": [_s(row["competition_code"])],
                "club_id": _s(row["club_id"]),
            }
        )
    out: dict[str, set[str]] = {}
    for season, items in by_season.items():
        home = home_province(items)
        ours = {
            i["club_id"]
            for i in items
            if i["club_id"] and (not home or not i["province"] or i["province"].upper() == home)
        }
        out[season] = {i["club_id"] for i in items if i["club_id"] and i["club_id"] not in ours}
    return out


async def club_scope(province: str, season: str, matches: Iterable[Any]) -> dict:
    """Zwraca klucze meczow poza rozliczeniem i opis klubow do zalacznika."""
    return await club_scope_many(province, {season: list(matches)})


async def club_scope_many(province: str, by_season: dict[str, list]) -> dict:
    """
    To samo, co `club_scope`, ale dla KILKU sezonow naraz i jednym odczytem bazy.

    Siatka miesiecy (`/province/settlements/months`) siega kilka sezonow wstecz,
    a pytanie o kazdy sezon osobno byloby kilkudziesiecioma zapytaniami na jedno
    wejscie na ekran. Dopasowanie druzyn liczymy mimo to SEZON PO SEZONIE: ten
    sam numer druzyny bywa w innym sezonie w innym klubie, a nazwy druzyn
    zmieniaja sie miedzy sezonami.
    """
    seasons = [season for season in by_season if season]
    if not seasons:
        return {"match_keys": set(), "excluded_keys": set(), "clubs": [], "club_of": {}}

    rows = await database.fetch_all(
        select(province_club_teams).where(
            and_(
                province_club_teams.c.province == province,
                province_club_teams.c.season.in_(seasons),
            )
        )
    )
    #: sezon -> (druzyny po numerze, druzyny po kluczu nazwy)
    teams: dict[str, tuple[dict[str, C.TeamRef], dict[str, C.TeamRef]]] = {
        season: ({}, {}) for season in seasons
    }
    foreign = _foreign_clubs(rows)
    for row in rows:
        by_id, by_key = teams.setdefault(_s(row["season"]), ({}, {}))
        ref = C.TeamRef(
            team_id=_s(row["team_id"]),
            club_id=_s(row["club_id"]),
            name=_s(row["team_name"]),
            category=_s(row["category"]),
            gender=_s(row["gender"]),
        )
        by_id[ref.team_id] = ref
        by_key.setdefault(_s(row["name_key"]) or team_key(ref.name), ref)

    setting_rows = await database.fetch_all(
        select(province_clubs).where(province_clubs.c.province == province)
    )
    settings = {
        _s(row["club_id"]): C.ClubSetting(
            settles=bool(row["settles_via_district"]), since=row["settles_since"]
        )
        for row in setting_rows
    }
    club_names = {
        _s(row["club_id"]): _s(row["display_name"]) or _s(row["club_id"])
        for row in setting_rows
    }

    override_rows = await database.fetch_all(
        select(province_match_overrides).where(province_match_overrides.c.province == province)
    )
    overrides = {
        _s(row["match_key"]): C.MatchOverride(
            excluded=bool(row["excluded"]),
            team_id=_s(row["team_id"]),
            team_name=_s(row["team_name"]),
            triple_table=bool(row["triple_table"]),
        )
        for row in override_rows
    }

    tournament_rows = await database.fetch_all(
        select(province_tournament_hosts).where(province_tournament_hosts.c.province == province)
    )
    tournament_hosts = {
        _s(row["tournament_key"]): C.MatchOverride(
            team_id=_s(row["team_id"]), team_name=_s(row["team_name"])
        )
        for row in tournament_rows
    }

    host_rows = await database.fetch_all(
        select(province_matches.c.match_id, province_matches.c.state_json).where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.active.is_(True),
            )
        )
    )
    hosts: dict[str, str] = {}
    guests: dict[str, str] = {}
    swapped_matches: set[str] = set()
    for row in host_rows:
        state = _state(row["state_json"])
        host, guest, swapped = C.actual_match_sides(state)
        match_key = f"d:{_s(row['match_id'])}"
        if host:
            hosts[match_key] = host
        if guest:
            guests[match_key] = guest
        if swapped:
            swapped_matches.add(match_key)

    club_keys: set[str] = set()
    excluded_keys: set[str] = set()
    details: dict[str, dict] = {}
    #: mecz -> klub, który za niego płaci (widok jednego sędziego liczy
    #: kluby tylko ze swoich meczów, choć turniej rozstrzygał się na całym).
    club_of: dict[str, str] = {}
    for season, matches in by_season.items():
        by_id, by_key = teams.get(season, ({}, {}))
        charges = C.build_charges(
            matches,
            hosts=hosts,
            guests=guests,
            swapped_matches=swapped_matches,
            teams_by_key=by_key,
            teams_by_id=by_id,
            overrides=overrides,
            clubs=settings,
            key_of=team_key,
            tournament_hosts=tournament_hosts,
        )
        for row in charges:
            if row.status == C.EXCLUDED:
                if (row.day or date.min) >= EXCLUDED_UNPAID_SINCE:
                    excluded_keys.add(row.match_key)
                continue
            # Mecz przeniesiony na OKRĘG jako płatnika (`district_payer`) ma
            # status `charged`, nie `club-off` - zostaje w rozliczeniu okręgu,
            # bo to okręg płaci sędziom. Zmienia się tylko, kto jest obciążony.
            if not C.paid_by_club(row, foreign.get(season, set())):
                continue
            club_keys.add(row.match_key)
            # Gospodarz spoza panelu (np. klub z Kielc w II lidze) nie ma
            # numeru klubu - grupujemy po nazwie z terminarza.
            club_id = row.club_id or f"host:{row.host_name or '?'}"
            club_of[row.match_key] = club_id
            item = details.setdefault(
                club_id,
                {
                    "club_id": club_id,
                    "club_name": club_names.get(club_id)
                    or row.team_name
                    or row.host_name
                    or "Gospodarz spoza panelu",
                    "matches": 0,
                    "amount": 0.0,
                },
            )
            item["matches"] += 1
            item["amount"] = round(item["amount"] + row.amount, 2)
    return {
        "match_keys": club_keys,
        "excluded_keys": excluded_keys,
        "clubs": list(details.values()),
        "club_of": club_of,
    }
