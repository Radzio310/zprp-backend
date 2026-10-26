import pytest

from app import province_club_splits_rules as SR

TEAMS = ["t1", "t2", "t3"]


def part(name, teams, expected=0):
    return {"name": name, "team_ids": teams, "expected_in": expected}


# --- walidacja -------------------------------------------------------------

def test_default_names():
    assert SR.default_names("Pogoń", 3) == ["Pogoń (I)", "Pogoń (II)", "Pogoń (III)"]


def test_valid_plan_normalizes():
    out = SR.validate_plan(TEAMS, [part(" A ", ["t1", "t2"], 100), part("B", ["t3"])])
    assert out[0] == {"name": "A", "team_ids": ["t1", "t2"], "expected_in": 100.0}
    assert out[1]["expected_in"] == 0.0


def test_single_team_club_cannot_split():
    with pytest.raises(ValueError, match="jedną drużynę"):
        SR.validate_plan(["t1"], [part("A", ["t1"]), part("B", [])])


@pytest.mark.parametrize(
    "parts,msg",
    [
        ([part("A", TEAMS)], "co najmniej dwóch"),
        ([part("A", ["t1"]), part("B", ["t2"]), part("C", ["t3"]), part("D", [])], "najwyżej tyle"),
        ([part("A", ["t1", "t2", "t3"]), part("B", [])], "nie ma żadnej drużyny"),
        ([part("A", ["t1", "t2"]), part("B", ["t2", "t3"])], "dwóch części"),
        ([part("A", ["t1"]), part("B", ["t2"])], "nie ma przypisanej"),
        ([part("A", ["t1", "t2"]), part("", ["t3"])], "nie ma nazwy"),
        ([part("A", ["t1", "t2"]), part("a", ["t3"])], "tę samą nazwę"),
        ([part("A", ["t1", "t2"]), part("B", ["x"])], "nie należy"),
        ([part("A", ["t1", "t2"]), part("B", ["t3"], -5)], "ujemna"),
    ],
)
def test_invalid_plans_explain(parts, msg):
    with pytest.raises(ValueError, match=msg):
        SR.validate_plan(TEAMS, parts)


def test_forbidden_reason_wins():
    with pytest.raises(ValueError, match="budżet"):
        SR.validate_plan(TEAMS, [part("A", ["t1"]), part("B", ["t2", "t3"])], forbidden="budżet")


def test_part_ids():
    assert SR.part_club_id("3608", []) == "split:3608:2"
    assert SR.part_club_id("3608", ["split:3608:2"]) == "split:3608:3"
    assert SR.parent_of_part("split:eligible-team:abc:2") == "eligible-team:abc"
    assert SR.is_part_id("split:1:2") and not SR.is_part_id("12")


# --- dziedziczenie sezonów i sync -------------------------------------------

def row(season, team, club, parent="10", name_key=None, id_=0):
    return {"id": id_, "parent_club_id": parent, "season": season, "team_id": team,
            "name_key": name_key if name_key is not None else f"k{team}", "club_id": club}


ROWS = [row("2025/2026", "t2", "split:10:2", id_=1), row("2025/2026", "t1", "10", id_=2)]


def club_of(rows, season, team, zprp="10", name_key=None):
    maps = SR.effective_maps(rows, season)
    return SR.resolve_club(zprp, team, name_key if name_key is not None else f"k{team}", maps)


def test_split_applies_from_its_season_and_is_inherited():
    assert club_of(ROWS, "2024/2025", "t2") == "10"
    assert club_of(ROWS, "2025/2026", "t2") == "split:10:2"
    assert club_of(ROWS, "2026/2027", "t2") == "split:10:2"
    assert club_of(ROWS, "2026/2027", "t1") == "10"
    assert club_of(ROWS, "2026/2027", "t3") == "10"


def test_later_change_overrides_only_from_that_season():
    rows = ROWS + [row("2026/2027", "t2", "10", id_=3)]
    assert club_of(rows, "2025/2026", "t2") == "split:10:2"
    assert club_of(rows, "2026/2027", "t2") == "10"
    assert club_of(rows, "2027/2028", "t2") == "10"


def test_next_season_team_with_new_id_is_matched_by_name():
    assert club_of(ROWS, "2026/2027", "NEW", name_key="kt2") == "split:10:2"


def test_sync_cannot_undo_split():
    # Synchronizacja przepisuje province_club_teams (ten sam klub z ZPRP) - nakładka
    # leży osobno, więc po syncu drużyna zostaje w części.
    for _ in range(3):
        assert club_of(ROWS, "2025/2026", "t2", zprp="10") == "split:10:2"


def test_team_that_zprp_moved_to_other_club_is_not_dragged_back():
    assert club_of(ROWS, "2025/2026", "t2", zprp="77") == "77"


def test_no_rows_means_zprp_club():
    assert club_of([], "2025/2026", "t2") == "10"


def test_split_info_active_only_with_teams_in_season():
    groups = [
        {"club_id": "10", "parent_club_id": "10", "part_no": 1, "name": "K (I)"},
        {"club_id": "split:10:2", "parent_club_id": "10", "part_no": 2, "name": "K (II)", "expected_in": 50},
    ]
    assert SR.split_info(groups, {"10"}) == {}
    info = SR.split_info(groups, {"10", "split:10:2"})
    assert info["10"]["role"] == "parent" and info["split:10:2"]["role"] == "part"
    assert info["split:10:2"]["expected_in"] == 50
    assert [p["club_id"] for p in info["10"]["parts"]] == ["10", "split:10:2"]


def test_overlay_settings_inherits_and_does_not_burn_name():
    info = SR.split_info(
        [
            {"club_id": "10", "parent_club_id": "10", "part_no": 1, "name": "K (I)"},
            {"club_id": "split:10:2", "parent_club_id": "10", "part_no": 2, "name": "K (II)"},
        ],
        {"10", "split:10:2"},
    )
    settings = {"10": {"display_name": "K", "settles_via_district": False, "note": "x"}}
    out = SR.overlay_settings(settings, info)
    assert out["10"]["display_name"] == "K" and out["10"]["split_name"] == "K (I)"
    part_settings = out["split:10:2"]
    assert part_settings["settles_via_district"] is False and part_settings["note"] == "x"
    assert part_settings["display_name"] == "K (II)" and "split_name" not in part_settings
    assert "split_name" not in settings["10"]


# --- przeliczenie sald -------------------------------------------------------

def test_preview_charges_follow_teams_entries_stay():
    entries = [
        {"id": 1, "kind": "in", "amount": 1000, "source": "manual"},
        {"id": 2, "kind": "in", "amount": 300, "source": "manual"},
        {"id": 3, "kind": "out", "amount": 50, "source": "manual"},
    ]
    parts = SR.validate_plan(TEAMS, [part("A", ["t1"]), part("B", ["t2", "t3"], 200)])
    out = SR.preview_balances(
        parent="10", part_ids=["10", "split:10:2"], names=["A", "B"], parts=parts,
        team_charged={"t1": 400, "t2": 150.5, "t3": 100}, team_matches={"t1": 4, "t2": 2, "t3": 1},
        entries=entries, entry_moves={2: 1},
    )
    assert out["before"]["balance"] == 1000 + 300 - 50 - 650.5
    a, b = out["after"]
    assert (a["paid_in"], a["paid_out"], a["charged"], a["balance"]) == (1000, 50, 400, 550)
    assert (b["paid_in"], b["charged"], b["balance"], b["expected_in"], b["matches"]) == (300, 250.5, 49.5, 200.0, 3)
    # suma sald części = saldo przed
    assert round(a["balance"] + b["balance"], 2) == out["before"]["balance"]


def test_preview_season_close_is_its_own_bucket():
    entries = [{"id": 1, "kind": "in", "amount": 90, "source": "season-close"}]
    parts = SR.validate_plan(TEAMS, [part("A", ["t1"]), part("B", ["t2", "t3"])])
    out = SR.preview_balances(parent="10", part_ids=["10", "s"], names=["A", "B"], parts=parts,
                              team_charged={"t1": 90}, team_matches={}, entries=entries, entry_moves={})
    assert out["after"][0]["settled"] == 90 and out["after"][0]["balance"] == 0


def test_entry_moves_validation():
    entries = [{"id": 1}, {"id": 2}]
    assert SR.validate_entry_moves(entries, {"1": 1, "2": 0}, 2) == {1: 1}
    with pytest.raises(ValueError, match="nie należy"):
        SR.validate_entry_moves(entries, {"9": 1}, 2)
    with pytest.raises(ValueError, match="nieistniejącą"):
        SR.validate_entry_moves(entries, {"1": 5}, 2)


# --- przenoszenie i scalanie -------------------------------------------------

def test_move_team_rules():
    kw = dict(rows=[], parent="10", season="2025/2026", team_id="t2", name_key="kt2",
              group_clubs=["10", "s2"], team_counts={"10": 2, "s2": 1})
    with pytest.raises(ValueError, match="jedyna drużyna"):
        SR.move_team(**kw, to_club_id="10", from_club_id="s2")
    with pytest.raises(ValueError, match="tego samego klubu"):
        SR.move_team(**kw, to_club_id="zzz", from_club_id="10")
    with pytest.raises(ValueError, match="już jest"):
        SR.move_team(**kw, to_club_id="10", from_club_id="10")
    plan = SR.move_team(**kw, to_club_id="s2", from_club_id="10")
    assert plan["insert"]["club_id"] == "s2" and plan["insert"]["season"] == "2025/2026"


def test_merge_back_all_returns_every_team_and_drops_future_rows():
    rows = [
        row("2025/2026", "t2", "split:10:2", id_=1),
        row("2025/2026", "t1", "10", id_=2),
        row("2026/2027", "t3", "split:10:2", id_=3),
    ]
    teams = [
        {"team_id": "t1", "name_key": "kt1", "club_id": "10"},
        {"team_id": "t2", "name_key": "kt2", "club_id": "split:10:2"},
        {"team_id": "t3", "name_key": "kt3", "club_id": "split:10:2"},
    ]
    plan = SR.merge_back(rows, parent="10", season="2026/2027", part_id=None, teams=teams)
    assert plan["delete_ids"] == [3]
    new_rows = rows[:2] + plan["insert"]
    assert club_of(new_rows, "2025/2026", "t2") == "split:10:2"   # przeszłość bez zmian
    for team in ("t1", "t2", "t3"):
        assert club_of(new_rows, "2026/2027", team) == "10"
    assert plan["entry_clubs"] == ["split:10:2"]


def test_merge_back_single_part_leaves_others():
    rows = [row("2025/2026", "t2", "s2", id_=1), row("2025/2026", "t3", "s3", id_=2)]
    teams = [{"team_id": "t2", "name_key": "kt2", "club_id": "s2"},
             {"team_id": "t3", "name_key": "kt3", "club_id": "s3"}]
    plan = SR.merge_back(rows, parent="10", season="2025/2026", part_id="s2", teams=teams)
    assert plan["delete_ids"] == [1] and [r["team_id"] for r in plan["insert"]] == ["t2"]
    remaining = [rows[1]] + plan["insert"]
    assert club_of(remaining, "2025/2026", "t2") == "10"
    assert club_of(remaining, "2025/2026", "t3") == "s3"


def test_assignment_rows_for_plan_pins_first_part_to_parent():
    parts = SR.validate_plan(TEAMS, [part("A", ["t1"]), part("B", ["t2", "t3"])])
    rows = SR.assignment_rows_for_plan("10", "2025/2026", parts, ["10", "s2"], {"t1": "k1"})
    assert [(r["team_id"], r["club_id"]) for r in rows] == [("t1", "10"), ("t2", "s2"), ("t3", "s2")]
