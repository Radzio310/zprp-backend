"""Katalog drużyn własnego okręgu, z potwierdzoną przynależnością i sezonem."""
from __future__ import annotations

from app.assignment_access import access_for, own_participant
from app.province_clubs_scrape import team_key
from app.settlement_seasons import normalize_season_label

# Skróty BAZA, nie miasta wyciągane z nazwy drużyny.
PROVINCE_SHORT = dict(zip(
    ("DOLNOSLASKIE", "KUJAWSKO_POMORSKIE", "LUBELSKIE", "LUBUSKIE", "LODZKIE",
     "MALOPOLSKIE", "MAZOWIECKIE", "OPOLSKIE", "PODKARPACKIE", "PODLASKIE",
     "POMORSKIE", "SLASKIE", "SWIETOKRZYSKIE", "WARMINSKO_MAZURSKIE",
     "WIELKOPOLSKIE", "ZACHODNIOPOMORSKIE"),
    ("DS", "KP", "LU", "LB", "LD", "MA", "MZ", "OP", "PK", "PD", "PM", "SL", "SK", "WN", "WP", "ZP")))

# Publiczne rozgrywki.zprp.pl używa innego słownika niż prywatna BAZA.
PUBLIC_PROVINCE_CODE = dict(zip(PROVINCE_SHORT,
    ("DOL", "KPO", "LBE", "LBU", "LDZ", "MLP", "MAZ", "OPL", "PDK", "POD", "POM", "SLK", "SWK", "WMZ", "WLP", "ZPO")))


async def own_teams(province: str) -> dict[str, tuple[set[str], set[str]]]:
    from sqlalchemy import select
    from app.db import database, province_club_teams as teams
    from app.settlement_province import spellings
    from app.zprp_accounts import normalize_province
    key = normalize_province(province)
    rows = await database.fetch_all(select(teams).where(teams.c.province.in_(spellings(province))))
    result = {}
    for row in rows:
        membership = str(row["team_province"] or "").strip().upper()
        if membership != PROVINCE_SHORT.get(key) and normalize_province(membership) != key:
            continue
        names, ids = result.setdefault(normalize_season_label(row["season"]), (set(), set()))
        names.add(team_key(row["team_name"]))
        ids.add(str(row["team_id"]))
    # Katalog klubów obejmuje także drużyny DRK, których nie ma w ligach okręgu.
    from app.db import zprp_public_teams as public_teams, zprp_public_clubs as clubs, zprp_public_associations as associations
    public_rows = await database.fetch_all(
        select(public_teams.c.team_id, public_teams.c.name, public_teams.c.season_name)
        .select_from(public_teams.join(clubs, public_teams.c.club_id == clubs.c.club_id)
                     .join(associations, clubs.c.association_id == associations.c.association_id))
        .where(associations.c.code == PUBLIC_PROVINCE_CODE.get(key, "")))
    for row in public_rows:
        names, ids = result.setdefault(normalize_season_label(row["season_name"]), (set(), set()))
        names.add(team_key(row["name"]))
        ids.add(str(row["team_id"]))
    return result


def resolve_access(state: dict, code: str, teams: dict, *, season: str = "", managed=(), own=(), province: str = "") -> dict:
    names, ids = teams.get(normalize_season_label(state.get("season") or season), (set(), set()))
    return access_for(state, code, managed=managed, own=own, province=province,
                      own_team=own_participant(state, names, ids))
