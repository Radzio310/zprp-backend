from datetime import date
from types import SimpleNamespace

from app.club_charges import UNASSIGNED, build_charges, guest_from_teams


def _share(**changes):
    base = dict(
        match_key="d:1",
        match_at=None,
        day=date(2025, 11, 30),
        match_code="L/MłK/20",
        category="Młodziczki",
        city="Lublin",
        gross=100,
        travel=93,
        judge_id="465",
        role="sędzia",
        teams="",
    )
    base.update(changes)
    return SimpleNamespace(**base)


def test_guest_is_everything_after_the_host():
    assert guest_from_teams("MKS LubTech Energo Lublin I - KPR Ruch Chorzów", "MKS LubTech Energo Lublin I") == "KPR Ruch Chorzów"


def test_guest_when_the_host_has_a_dash_in_its_name():
    assert guest_from_teams("UKS Dwójka - Zabrze - MKS Otwock", "UKS Dwójka - Zabrze") == "MKS Otwock"


def test_guest_when_the_schedule_spells_the_host_differently():
    assert guest_from_teams("SPR Pogoń 1945 II Zabrze - KS Sośnica", "SPR Pogoń II Zabrze") == "KS Sośnica"


def test_no_separator_no_guest():
    assert guest_from_teams("MKS Lublin", "MKS Lublin") == ""
    assert guest_from_teams("", "") == ""


def test_unassigned_row_shows_both_teams():
    rows = build_charges(
        [_share(teams="MKS LubTech Energo Lublin I - KPR Ruch Chorzów")],
        hosts={},
        teams_by_key={},
    )
    row = rows[0]
    assert row.status == UNASSIGNED
    assert row.host_name == "MKS LubTech Energo Lublin I"
    assert row.guest_name == "KPR Ruch Chorzów"
    assert row.teams == "MKS LubTech Energo Lublin I - KPR Ruch Chorzów"


def test_teams_come_from_a_later_share_when_the_first_has_none():
    rows = build_charges(
        [_share(judge_id="1"), _share(judge_id="2", teams="A B - C D")],
        hosts={},
        teams_by_key={},
    )
    assert rows[0].teams == "A B - C D"
    assert rows[0].host_name == "A B"
    assert rows[0].guest_name == "C D"
