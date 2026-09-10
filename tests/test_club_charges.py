"""
Obciazenia klubow: kto placi za mecz, ile i kiedy nie placi.
"""

from datetime import date, datetime, timezone

from app import settlement_engine as E
from app.club_charges import (
    CHARGED,
    CLUB_OFF,
    EXCLUDED,
    NO_HOST,
    UNASSIGNED,
    ClubSetting,
    MatchOverride,
    TeamRef,
    balance,
    build_charges,
    club_totals,
    team_totals,
)
from app.province_clubs_scrape import team_key

SOSNICA = TeamRef(team_id="17583", club_id="4893", name="SPR Sośnica II Gliwice", category="Senior")
START = TeamRef(team_id="5192", club_id="2851", name="MKS Start Michałkowice", category="Senior")

TEAMS_BY_KEY = {team_key(t.name): t for t in (SOSNICA, START)}
TEAMS_BY_ID = {t.team_id: t for t in (SOSNICA, START)}

NAMES = {"5124": "KOWALSKI Jan", "7788": "NOWAK Anna"}


def crew(
    match_key,
    judge,
    role,
    gross,
    travel,
    *,
    day=date(2026, 10, 4),
    code="S/JMM/7",
    triple=False,
):
    return E.SettledMatch(
        match_key=match_key,
        judge_id=judge,
        match_at=datetime(day.year, day.month, day.day, 10, 0, tzinfo=timezone.utc),
        day=day,
        match_code=code,
        category="Junior mł.",
        level="district",
        role=role,
        origin="district",
        city="Gliwice",
        home_city="Bystra",
        teams="Gospodarz - Gość",
        distance_km=20.0,
        distance_source="table",
        km_rate=0.7,
        gross=gross,
        travel=travel,
        travel_shared=False,
        future=False,
        approved=None,
        triple_table=triple,
    )


def charges(rows, *, hosts, overrides=None, clubs=None):
    return build_charges(
        rows,
        hosts=hosts,
        teams_by_key=TEAMS_BY_KEY,
        teams_by_id=TEAMS_BY_ID,
        overrides=overrides,
        clubs=clubs,
        judge_names=NAMES,
        key_of=team_key,
    )


def test_klub_placi_brutto_i_przejazdy_calej_obsady():
    rows = charges(
        [
            crew("d:1", "5124", E.R.ROLE_FIELD, 132, 28),
            crew("d:1", "7788", E.R.ROLE_TABLE, 60, 14),
        ],
        hosts={"d:1": "SPR Sośnica II Gliwice"},
    )
    [row] = rows
    assert row.status == CHARGED
    assert row.club_id == "4893"
    assert row.team_name == "SPR Sośnica II Gliwice"
    assert (row.gross, row.travel, row.amount) == (192, 42, 234)
    assert [share.name for share in row.referees] == ["KOWALSKI Jan", "NOWAK Anna"]
    assert club_totals(rows)["4893"] == {"charged": 234, "matches": 1, "gross": 192, "travel": 42}
    assert team_totals(rows)["17583"]["charged"] == 234


def test_nieznana_nazwa_gospodarza_nie_znika():
    rows = charges([crew("d:2", "5124", E.R.ROLE_FIELD, 132, 28)], hosts={"d:2": "Jakiś Klub"})
    assert rows[0].status == UNASSIGNED
    assert rows[0].club_id == ""
    assert club_totals(rows) == {}


def test_przeniesienie_meczu_na_inna_druzyne():
    rows = charges(
        [crew("d:3", "5124", E.R.ROLE_FIELD, 132, 28)],
        hosts={"d:3": "SPR Sośnica II Gliwice"},
        overrides={"d:3": MatchOverride(team_id="5192")},
    )
    assert rows[0].moved is True
    assert rows[0].club_id == "2851"
    assert club_totals(rows)["2851"]["charged"] == 160


def test_mecz_wylaczony_z_oplaty():
    rows = charges(
        [crew("d:4", "5124", E.R.ROLE_FIELD, 132, 28)],
        hosts={"d:4": "MKS Start Michałkowice"},
        overrides={"d:4": MatchOverride(excluded=True)},
    )
    assert rows[0].status == EXCLUDED
    assert club_totals(rows) == {}


def test_klub_poza_rozliczeniem_okregu_od_wskazanej_daty():
    settings = {"2851": ClubSetting(settles=False, since=date(2026, 10, 1))}
    rows = charges(
        [
            crew("d:5", "5124", E.R.ROLE_FIELD, 132, 28, day=date(2026, 9, 20)),
            crew("d:6", "5124", E.R.ROLE_FIELD, 132, 28, day=date(2026, 10, 4)),
        ],
        hosts={"d:5": "MKS Start Michałkowice", "d:6": "MKS Start Michałkowice"},
        clubs=settings,
    )
    statuses = {row.match_key: row.status for row in rows}
    assert statuses == {"d:5": CHARGED, "d:6": CLUB_OFF}
    # Historia zostaje: wrzesniowy mecz nadal obciaza klub.
    assert club_totals(rows)["2851"]["matches"] == 1


def test_potrojny_ryczalt_widac_w_wierszu_klubu():
    rows = charges(
        [crew("d:7", "7788", E.R.ROLE_TABLE, 180, 14, triple=True)],
        hosts={"d:7": "MKS Start Michałkowice"},
    )
    assert rows[0].triple is True
    assert rows[0].referees[0].triple is True
    # Silnik oddaje juz potrojna kwote - klub placi dokladnie to, co sedzia dostaje.
    assert rows[0].amount == 194


def test_mecz_spoza_terminarza_okregu_nie_jest_do_poprawy():
    """Stolik w innym wojewodztwie: gospodarza nie znamy i nikt u nas nie placi."""
    rows = charges([crew("o:9", "7788", E.R.ROLE_TABLE, 110, 80)], hosts={})
    assert rows[0].status == NO_HOST
    assert club_totals(rows) == {}


def test_saldo_klubu():
    assert balance(paid_in=1000, paid_out=200, charged=500) == 300
    assert balance(paid_in=0, paid_out=0, charged=234) == -234
