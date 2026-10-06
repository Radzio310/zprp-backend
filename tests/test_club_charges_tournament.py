"""
Turniej = jeden płatnik (decyzja użytkownika z 06.10.2026).

Zgłoszenie: turniej młodzików w Rudzie Śląskiej, gospodarz turnieju Grunwald,
a mecz „MKS Start Michałkowice - OSP Świętochłowice 1" poszedł do „płaci klub"
(Michałkowice rozliczają się same), reszta turnieju do okręgu. Sędzia miał
jeden wyjazd rozcięty na dwóch płatników.
"""

from datetime import date, datetime, timezone

from app import settlement_engine as E
from app.club_charges import (
    CHARGED,
    CLUB_OFF,
    HOST_HALL_CITY,
    HOST_MANUAL,
    HOST_SAME_CLUB,
    HOST_UNKNOWN,
    UNASSIGNED,
    ClubSetting,
    MatchOverride,
    TeamRef,
    build_charges,
    tournament_key,
)
from app.district_payer import DISTRICT_PAYER_ID
from app.province_clubs_scrape import team_key

GRUNWALD = TeamRef(team_id="900", club_id="90", name="KS Grunwald Ruda Śląska", category="Młodzik")
START = TeamRef(team_id="5192", club_id="2851", name="MKS Start Michałkowice", category="Młodzik")
OSP = TeamRef(team_id="700", club_id="70", name="OSP Świętochłowice 1", category="Młodzik")
SPARTA = TeamRef(team_id="800", club_id="80", name="Sparta Katowice", category="Młodzik")
TEAMS = (GRUNWALD, START, OSP, SPARTA)
BY_ID = {t.team_id: t for t in TEAMS}
BY_KEY = {team_key(t.name): t for t in TEAMS}

DAY = date(2026, 10, 4)
HALL = "Hala MOSiR"
CITY = "Ruda Śląska"


def crew(match_key, judge, teams, *, hour=9, code="S/MłKR/3", day=DAY, hall=HALL, city=CITY):
    return E.SettledMatch(
        match_key=match_key,
        judge_id=judge,
        match_at=datetime(day.year, day.month, day.day, hour, 0, tzinfo=timezone.utc),
        day=day,
        match_code=code,
        category="Młodzik",
        level="district",
        role="Sędzia boiskowy",
        origin="district",
        city=city,
        home_city="Bytom",
        teams=teams,
        distance_km=13.0,
        distance_source="table",
        km_rate=0.7,
        gross=117.0,
        travel=18.2,
        travel_shared=False,
        future=False,
        approved=None,
        hall=hall,
    )


def run(rows, *, clubs=None, tournament_hosts=None, overrides=None):
    return {
        row.match_key: row
        for row in build_charges(
            rows,
            hosts={},
            teams_by_key=BY_KEY,
            teams_by_id=BY_ID,
            clubs=clubs or {},
            overrides=overrides or {},
            key_of=team_key,
            tournament_hosts=tournament_hosts or {},
        )
    }


RUDA = [
    crew("d:1", "11", "MKS Start Michałkowice - OSP Świętochłowice 1", hour=8),
    crew("d:2", "11", "KS Grunwald Ruda Śląska - Sparta Katowice", hour=9),
    crew("d:3", "11", "OSP Świętochłowice 1 - KS Grunwald Ruda Śląska", hour=10),
]


def test_tournament_key_is_day_and_hall():
    key = tournament_key("S/MłKR/3", datetime(2026, 10, 4, 22, 30, tzinfo=timezone.utc), DAY, HALL, CITY)
    # 22:30 UTC to 00:30 w Polsce - już 5 października.
    assert key.startswith("t:2026-10-05|")
    assert tournament_key("S/JMM/3", None, DAY, HALL, CITY) == ""        # nie turniej
    assert tournament_key("S/DzM/3", None, date(2026, 8, 30), HALL, CITY) == ""  # przed sezonem


def test_host_from_hall_city_pays_for_whole_tournament():
    rows = run(RUDA, clubs={"2851": ClubSetting(settles=False)})
    for key in ("d:1", "d:2", "d:3"):
        assert rows[key].club_id == "90"
        assert rows[key].tournament_host == HOST_HALL_CITY
        assert rows[key].tournament_size == 3
        # Michałkowice rozliczają się same, ale turniej płaci Grunwald przez okręg.
        assert rows[key].status == CHARGED


def test_club_off_host_moves_whole_tournament_to_club():
    rows = run(RUDA, clubs={"90": ClubSetting(settles=False)})
    assert {row.status for row in rows.values()} == {CLUB_OFF}


def test_manual_host_wins_with_automat():
    key = tournament_key("S/MłKR/3", RUDA[0].match_at, DAY, HALL, CITY)
    rows = run(RUDA, tournament_hosts={key: MatchOverride(team_id="5192")})
    assert {row.club_id for row in rows.values()} == {"2851"}
    assert {row.tournament_host for row in rows.values()} == {HOST_MANUAL}


def test_manual_host_can_be_the_district():
    key = tournament_key("S/MłKR/3", RUDA[0].match_at, DAY, HALL, CITY)
    rows = run(RUDA, tournament_hosts={key: MatchOverride(team_id=DISTRICT_PAYER_ID)})
    assert {row.club_id for row in rows.values()} == {DISTRICT_PAYER_ID}
    assert {row.status for row in rows.values()} == {CHARGED}


def test_match_override_wins_with_tournament_host():
    rows = run(RUDA, overrides={"d:1": MatchOverride(team_id="800")})
    assert rows["d:1"].club_id == "80"
    assert rows["d:2"].club_id == "90"


def test_same_club_everywhere_is_the_host():
    rows = run(
        [
            crew("d:1", "11", "Sparta Katowice - MKS Start Michałkowice", city="Chorzów"),
            crew("d:2", "11", "Sparta Katowice - OSP Świętochłowice 1", city="Chorzów", hour=10),
        ]
    )
    assert {row.club_id for row in rows.values()} == {"80"}
    assert {row.tournament_host for row in rows.values()} == {HOST_SAME_CLUB}


def test_unknown_host_waits_for_a_human():
    rows = run(
        [
            crew("d:1", "11", "Sparta Katowice - MKS Start Michałkowice", city="Chorzów"),
            crew("d:2", "11", "OSP Świętochłowice 1 - Sparta Katowice", city="Chorzów", hour=10),
        ]
    )
    assert {row.status for row in rows.values()} == {UNASSIGNED}
    assert {row.tournament_host for row in rows.values()} == {HOST_UNKNOWN}


def test_single_match_in_hall_is_paid_by_its_host():
    rows = run([crew("d:1", "11", "Sparta Katowice - MKS Start Michałkowice", city="Chorzów")])
    assert rows["d:1"].club_id == "80"
    assert rows["d:1"].tournament_host == ""


def test_regular_match_is_not_a_tournament():
    rows = run([crew("d:1", "11", "Sparta Katowice - MKS Start Michałkowice", code="S/MłM/3")])
    assert rows["d:1"].tournament_key == ""
    assert rows["d:1"].club_id == "80"
