import pytest

from app.province_club_budgets_rules import (
    DEFAULT_BUDGETS,
    clean_members,
    conflicts,
    dump_members,
    member_map,
    merge_budgets,
    parse_members,
    seed_plan,
)


def club(club_id, *, name=None, paid_in=0.0, paid_out=0.0, settled=0.0, charged=0, matches=0,
         settles=True, table=0, teams=None):
    from app.club_charges import balance

    return {
        "club_id": club_id,
        "name": name or f"Klub {club_id}",
        "settles_via_district": settles,
        "settles_since": None,
        "table_by_club": table,
        "table_by_club_since": None,
        "note": "",
        "teams": teams or [],
        "paid_in": paid_in,
        "paid_out": paid_out,
        "settled": settled,
        "charged": charged,
        "matches": matches,
        "balance": balance(paid_in=paid_in + settled, paid_out=paid_out, charged=charged),
    }


BUDGET = {"budget_id": 7, "name": None, "primary_club_id": "3608", "member_ids": ["3608", "4986"]}


def test_budget_sums_money_and_recomputes_balance():
    clubs = {
        "3608": club("3608", name="KS Bystra", paid_in=100.4, charged=300, matches=2,
                     teams=[{"team_id": "t2", "name": "Bystra II", "club_id": "3608"}]),
        "4986": club("4986", name="Beskidzki Handball", paid_in=100.4, settled=50, charged=0.6, matches=1,
                     teams=[{"team_id": "t1", "name": "Beskidzki", "club_id": "4986"}]),
        "9": club("9", paid_in=10),
    }
    out = merge_budgets(clubs, [BUDGET])
    assert set(out) == {"3608", "9"}
    budget = out["3608"]
    assert budget["name"] == "KS Bystra"
    assert budget["paid_in"] == 200.8
    assert budget["settled"] == 50
    assert budget["charged"] == 300.6
    assert budget["matches"] == 3
    # Saldo z sum, nie suma zaokrąglonych sald: 200.8 + 50 - 300.6 = -49.8 -> -50.
    assert budget["balance"] == -50
    assert [team["name"] for team in budget["teams"]] == ["Beskidzki", "Bystra II"]
    assert budget["member_ids"] == ["3608", "4986"]
    assert [m["name"] for m in budget["members"]] == ["KS Bystra", "Beskidzki Handball"]
    assert budget["budget_id"] == 7
    assert budget["mixed_settings"] is False


def test_club_outside_budgets_keeps_shape_and_gets_member_ids():
    clubs = {"9": club("9", paid_in=10)}
    out = merge_budgets(clubs, [BUDGET])
    assert out["9"]["balance"] == 10
    assert out["9"]["member_ids"] == ["9"]
    assert out["9"]["budget_id"] is None


def test_settings_come_from_primary_and_differences_are_flagged():
    clubs = {
        "3608": club("3608", settles=False, table=1),
        "4986": club("4986", settles=True, table=0),
    }
    budget = merge_budgets(clubs, [BUDGET])["3608"]
    assert budget["settles_via_district"] is False
    assert budget["table_by_club"] == 1
    assert budget["mixed_settings"] is True


def test_absent_primary_still_keys_the_budget_by_primary():
    clubs = {"4986": club("4986", name="Beskidzki", paid_in=20)}
    out = merge_budgets(clubs, [BUDGET], names={"3608": "KS Bystra"})
    assert list(out) == ["3608"]
    assert out["3608"]["name"] == "KS Bystra"
    assert out["3608"]["members"][0] == {"club_id": "3608", "name": "KS Bystra", "present": False}


def test_budget_without_any_member_in_season_is_skipped():
    assert merge_budgets({"9": club("9")}, [BUDGET]).keys() == {"9"}


def test_manual_name_wins():
    clubs = {"3608": club("3608"), "4986": club("4986")}
    out = merge_budgets(clubs, [{**BUDGET, "name": "Bystra razem"}])
    assert out["3608"]["name"] == "Bystra razem"


def test_clean_members_puts_primary_first_and_needs_two():
    assert clean_members("41", ["4927", "41", " 4927 "]) == ["41", "4927"]
    with pytest.raises(ValueError):
        clean_members("41", ["41"])
    with pytest.raises(ValueError):
        clean_members("", ["41", "4927"])


def test_conflicts_ignore_the_budget_being_edited():
    budgets = [BUDGET, {"budget_id": 8, "primary_club_id": "41", "member_ids": ["41", "4927"]}]
    assert set(conflicts(["3608", "41"], budgets)) == {"3608", "41"}
    assert set(conflicts(["3608", "41"], budgets, budget_id=7)) == {"41"}


def test_members_roundtrip_through_text_column():
    assert parse_members(dump_members(["27", "5011"])) == ["27", "5011"]
    assert parse_members(None) == []
    assert parse_members("nie json") == ["nie json"]
    assert member_map([BUDGET]) == {"3608": "3608", "4986": "3608"}


def test_seed_is_idempotent_and_never_moves_a_club():
    defaults = DEFAULT_BUDGETS["SLASKIE"]
    first = seed_plan([], defaults)
    assert [item["primary_club_id"] for item in first] == ["3608", "41", "2049", "27"]
    assert first[3]["member_ids"] == ["27", "5011"]
    created = [{"budget_id": i, **item} for i, item in enumerate(first)]
    assert seed_plan(created, defaults) == []
    # Ktoś ręcznie spiął 5011 z innym klubem - seed tej grupy nie ruszy.
    manual = [{"budget_id": 1, "primary_club_id": "99", "member_ids": ["99", "5011"]}]
    assert [item["primary_club_id"] for item in seed_plan(manual, defaults)] == ["3608", "41", "2049"]
