"""Podzial rozliczenia wedlug tego, kto faktycznie placi obsade.

Panel klubow od dawna umial oznaczyc klub jako nierozliczany przez okreg, ale
ta informacja nie byla stosowana do listy wyplat sedziow. Ten modul jest jednym
mostem pomiedzy tymi dwiema czesciami aplikacji. Nie liczy kwot: rozpoznaje
wylacznie mecze klubow z wylaczonym rozliczaniem, a silnik rozliczen przelicza
obie grupy osobno.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy import and_, select

from app import club_charges as C
from app.db import (
    database,
    province_club_teams,
    province_clubs,
    province_match_overrides,
    province_matches,
)
from app.province_clubs_scrape import team_key
from app.settlement_province import spellings


def _s(value: Any) -> str:
    return str(value or "").strip()


def _state(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


async def club_scope(province: str, season: str, matches: Iterable[Any]) -> dict:
    """Zwraca klucze meczow poza rozliczeniem i opis klubow do zalacznika."""
    rows = await database.fetch_all(
        select(province_club_teams).where(
            and_(
                province_club_teams.c.province == province,
                province_club_teams.c.season == season,
            )
        )
    )
    by_id: dict[str, C.TeamRef] = {}
    by_key: dict[str, C.TeamRef] = {}
    team_meta: dict[str, dict] = {}
    for row in rows:
        ref = C.TeamRef(
            team_id=_s(row["team_id"]),
            club_id=_s(row["club_id"]),
            name=_s(row["team_name"]),
            category=_s(row["category"]),
            gender=_s(row["gender"]),
        )
        by_id[ref.team_id] = ref
        by_key.setdefault(_s(row["name_key"]) or team_key(ref.name), ref)
        team_meta[ref.team_id] = {"team_name": ref.name, "club_id": ref.club_id}

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

    host_rows = await database.fetch_all(
        select(province_matches.c.match_id, province_matches.c.state_json).where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.active.is_(True),
            )
        )
    )
    hosts = {}
    for row in host_rows:
        host = _s(_state(row["state_json"]).get("ID_zespoly_gosp_ZespolNazwa"))
        if host:
            hosts[f"d:{_s(row['match_id'])}"] = host

    charges = C.build_charges(
        matches,
        hosts=hosts,
        teams_by_key=by_key,
        teams_by_id=by_id,
        overrides=overrides,
        clubs=settings,
        key_of=team_key,
    )
    excluded_keys = {row.match_key for row in charges if row.status == C.CLUB_OFF}
    details = {}
    for row in charges:
        if row.match_key not in excluded_keys:
            continue
        club_id = row.club_id
        item = details.setdefault(
            club_id,
            {
                "club_id": club_id,
                "club_name": club_names.get(club_id) or row.team_name or club_id,
                "matches": 0,
                "amount": 0.0,
            },
        )
        item["matches"] += 1
        item["amount"] = round(item["amount"] + row.amount, 2)
    return {"match_keys": excluded_keys, "clubs": list(details.values())}
