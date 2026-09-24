"""
Okręg jako płatnik: mecz przeniesiony na okręg, nazwa płatnika, odmowy.
"""

from datetime import date

from app import district_payer as DP
from app.club_charges import (
    CHARGED,
    EXCLUDED,
    ClubSetting,
    MatchOverride,
    build_charges,
    club_totals,
)
from app.province_clubs_scrape import team_key
from tests.test_club_charges import NAMES, SOSNICA, TEAMS_BY_ID, TEAMS_BY_KEY, crew


def _charges(rows, *, hosts, overrides=None, clubs=None, label="ŚlZPR"):
    return build_charges(
        rows,
        hosts=hosts,
        teams_by_key=TEAMS_BY_KEY,
        teams_by_id=TEAMS_BY_ID,
        overrides=overrides,
        clubs=clubs,
        judge_names=NAMES,
        key_of=team_key,
        district_label=label,
    )


def test_label_slaskie_and_fallback():
    assert DP.default_label("ŚLĄSKIE") == "ŚlZPR"
    assert DP.default_label("SLASKIE") == "ŚlZPR"
    assert DP.default_label("MAZOWIECKIE") == "Okręg MAZOWIECKIE"
    assert DP.label("SLASKIE", "Śl. ZPR") == "Śl. ZPR"
    assert DP.label("SLASKIE", "  ") == "ŚlZPR"


def test_is_district_payer_and_without():
    assert DP.is_district_payer("OKREG")
    assert DP.is_district_payer(" okreg ")
    assert not DP.is_district_payer("4893")
    assert DP.without_district(["4893", "OKREG", "", "2851"]) == ["4893", "2851"]


def test_refuse_reason_names_the_action():
    assert DP.refuse_reason(["4893"], "Wspólny budżet") == ""
    reason = DP.refuse_reason(["4893", "OKREG"], "Wspólny budżet")
    assert reason.startswith("Wspólny budżet")
    assert "okręgu" in reason


def test_match_moved_to_district_charges_district_not_host():
    rows = [
        crew("d:1", "5124", "Sędzia 1", 117.5, 14.0),
        crew("d:1", "7788", "Sędzia stolikowy", 77, 0),
    ]
    hosts = {"d:1": SOSNICA.name}
    [plain] = _charges(rows, hosts=hosts)
    assert plain.club_id == SOSNICA.club_id

    [moved] = _charges(rows, hosts=hosts, overrides={"d:1": MatchOverride(team_id="OKREG")})
    assert moved.club_id == DP.DISTRICT_PAYER_ID
    assert moved.team_id == DP.DISTRICT_PAYER_ID
    assert moved.team_name == "ŚlZPR"
    assert moved.moved is True
    assert moved.status == CHARGED
    # Kwota ta sama co u klubu - zmienia się tylko, kto płaci. Grosze zostają.
    assert moved.amount == plain.amount == 208.5
    totals = club_totals([moved])
    assert totals == {"OKREG": {"charged": 208.5, "matches": 1, "gross": 194.5, "travel": 14.0}}


def test_district_ignores_club_off_and_own_table():
    """Klub gospodarza poza okręgiem, a mecz przeniesiony na okręg - płaci okręg."""
    rows = [
        crew("d:2", "5124", "Sędzia stolikowy", 77, 10),
        crew("d:2", "7788", "Sędzia stolikowy", 77, 30),
    ]
    hosts = {"d:2": SOSNICA.name}
    clubs = {
        SOSNICA.club_id: ClubSetting(settles=False, since=date(2020, 1, 1), table_by_club=1),
        # Nawet gdyby ktoś zapisał okręgowi „nie rozlicza się" - bez znaczenia.
        "OKREG": ClubSetting(settles=False, since=date(2020, 1, 1), table_by_club=1),
    }
    [row] = _charges(rows, hosts=hosts, clubs=clubs, overrides={"d:2": MatchOverride(team_id="OKREG")})
    assert row.status == CHARGED
    assert row.own_table is False
    assert all(share.charged for share in row.referees)
    assert row.amount == 194


def test_excluded_wins_over_district():
    rows = [crew("d:3", "5124", "Sędzia 1", 117, 0)]
    [row] = _charges(
        rows,
        hosts={"d:3": SOSNICA.name},
        overrides={"d:3": MatchOverride(team_id="OKREG", excluded=True)},
    )
    assert row.status == EXCLUDED
    assert row.club_id == "OKREG"


def test_unassigned_match_can_go_to_district():
    rows = [crew("d:4", "5124", "Sędzia 1", 117, 0, teams="Nieznani - Obcy")]
    [row] = _charges(rows, hosts={}, overrides={"d:4": MatchOverride(team_id="OKREG")})
    assert row.status == CHARGED
    assert row.club_id == "OKREG"
