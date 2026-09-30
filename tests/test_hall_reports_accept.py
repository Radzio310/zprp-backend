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
