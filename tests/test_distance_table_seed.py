from app.distance_table_seed import (
    load_silesia_2026_table,
    should_promote,
)
from app.settlement_distances import VersionedDistanceIndex


def test_bundled_silesia_table_is_complete_and_versioned():
    table = load_silesia_2026_table()

    assert table["validFrom"] == "2026-09-01"
    assert len(table["cities"]) == 43
    assert len(table["edges"]) == 903
    assert table["previous"][0]["validUntil"] == "2026-08-31"
    assert len(table["previous"][0]["edges"]) == 849


def test_deployment_promotes_only_older_content():
    bundled = {"validFrom": "2026-09-01"}

    assert should_promote(None, bundled)
    assert should_promote({"edges": []}, bundled)
    assert should_promote({"validFrom": "2025-09-01"}, bundled)
    assert not should_promote({"validFrom": "2026-09-01"}, bundled)
    assert not should_promote({"validFrom": "2027-09-01"}, bundled)


def test_real_table_changes_exactly_on_first_of_september():
    distances = VersionedDistanceIndex(load_silesia_2026_table())

    assert distances.lookup("Godziszka", "Zabrze", "2026-08-31") == 102
    assert distances.lookup("Godziszka", "Zabrze", "2026-09-01") == 77
