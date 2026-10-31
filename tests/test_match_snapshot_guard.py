from datetime import datetime, timedelta, timezone

from app.match_snapshot_guard import explicit_removals, merge_observation, verified_state


def test_only_explicit_numeric_replacements_remove_a_judge():
    old = {"NrSedzia_czas": "1", "NrSedzia_sekretarz": "2"}
    assert explicit_removals(old, {"NrSedzia_czas": "3", "NrSedzia_sekretarz": "2"}) == {"1"}
    assert explicit_removals(old, {"NrSedzia_czas": "0", "NrSedzia_sekretarz": "2"}) == {"1"}
    assert explicit_removals(old, {"NrSedzia_czas": ""}) == set()
    assert explicit_removals(old, {"NrSedzia_czas": "2", "NrSedzia_sekretarz": "1"}) == set()


def test_in_flight_observation_cannot_undo_verified_assignment():
    now = datetime(2026, 10, 31, tzinfo=timezone.utc)
    old = {"NrSedzia_czas": "1", "NrSedzia_czas_nazwisko": "Old", "wynik_gosp_full": "10"}
    saved = verified_state(old, {**old, "NrSedzia_czas": "2", "NrSedzia_czas_nazwisko": "New"}, now=now)
    stale = {**old, "_observed_at": (now - timedelta(seconds=10)).isoformat(), "wynik_gosp_full": "11"}
    merged = merge_observation(saved, stale)
    assert merged["NrSedzia_czas"] == "2"
    assert merged["NrSedzia_czas_nazwisko"] == "New"
    assert merged["wynik_gosp_full"] == "11"


def test_newer_external_changes_are_still_accepted():
    now = datetime(2026, 10, 31, tzinfo=timezone.utc)
    saved = verified_state({"NrSedzia_czas": "1"}, {"NrSedzia_czas": "2"}, now=now)
    fresh = {"NrSedzia_czas": "3", "_observed_at": (now + timedelta(seconds=1)).isoformat()}
    assert merge_observation(saved, fresh)["NrSedzia_czas"] == "3"
