from pathlib import Path

from app.hall_reports import merge_halls


def _report(report_id=7, teams=None):
    return {
        "id": report_id,
        "Hala_nazwa": "Arena Śląska",
        "Hala_miasto": "Katowice",
        "Hala_ulica": "Spodek",
        "Hala_numer": "1",
        "Druzyny": teams or ["GKS"],
    }


def test_accept_adds_hall():
    halls, added, merged = merge_halls([], [_report()])
    assert added == 1
    assert merged == 0
    assert halls[0]["Hala_nazwa"] == "Arena Śląska"


def test_accept_merges_teams_for_exact_existing_hall():
    halls, added, merged = merge_halls(
        [{**_report(1, ["Stary klub"]), "Druzyny": ["Stary klub"]}],
        [_report(8, ["Nowy klub"])],
    )
    assert added == 0
    assert merged == 1
    assert halls[0]["Druzyny"] == ["Stary klub", "Nowy klub"]


def test_accept_route_is_transactional_and_does_not_reject():
    source = (Path(__file__).resolve().parents[1] / "app" / "admin.py").read_text(
        encoding="utf-8"
    )
    body = source.split("async def accept_hall_reports", 1)[1].split(
        "@router.delete", 1
    )[0]
    assert "database.transaction()" in body
    assert "with_for_update()" in body
    assert "rejected_halls" not in body


# --- szybkie wczytywanie pliku hal i zbiorcze odrzucanie ---

from datetime import datetime, timezone

from app.hall_reports import MAX_BULK_REJECT, clean_report_ids, etag_matches, json_file_etag


def test_etag_changes_with_every_save():
    first = json_file_etag("hale", datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc))
    second = json_file_etag("hale", datetime(2026, 9, 30, 12, 0, 1, tzinfo=timezone.utc))
    assert first != second
    assert first.startswith('W/"hale-')


def test_etag_matches_weak_strong_and_lists():
    tag = json_file_etag("hale", datetime(2026, 9, 30, tzinfo=timezone.utc))
    assert etag_matches(tag, tag)
    assert etag_matches(tag.removeprefix("W/"), tag)
    assert etag_matches(f'"inny", {tag}', tag)
    assert etag_matches("*", tag)
    assert not etag_matches(None, tag)
    assert not etag_matches('W/"hale-stary"', tag)


def test_clean_report_ids_dedupes_and_caps():
    assert clean_report_ids([3, "3", 0, -1, "x", None, 7]) == [3, 7]
    assert len(clean_report_ids(range(1, MAX_BULK_REJECT + 50))) == MAX_BULK_REJECT


def test_admin_routes_wired():
    source = (Path(__file__).resolve().parents[1] / "app" / "admin.py").read_text(encoding="utf-8")
    assert '"/halls/reports/reject"' in source
    assert "etag_matches(request.headers.get(\"if-none-match\")" in source
    assert "pending: bool = False" in source
