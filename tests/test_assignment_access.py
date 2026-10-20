from datetime import datetime

import pytest
from bs4 import BeautifulSoup

from app.assignment_access import access_for, schedule_controls, form_editable
from app.assignment_access_data import resolve_access
from app.assignment_context import Roster, need_from_state
from app.assignment_rules import crew_status
from app.assignment_auto import MatchNeed, role_access_refusal, build_plan
from app.assignment_people import make_judge
from app.zprp import assignments as Z
from test_assignment_auto import world, JAN, ANNA
from test_zprp_assignment_apply import form_html, table_official_form_html, BASE_OPTIONS, FakeHttp


def state(code="LCK/39", own=True, button=True):
    data = {"season": "2026/2027", "RozgrywkiCode": code,
            "ID_zespoly_gosp_ZespolNazwa": "MTS Trendy Top Żory" if own else "MOSiR Bochnia",
            "ID_zespoly_gosc_ZespolNazwa": "Jutrzenka Płock",
            "assignment_controls": {"referees": button, "hall": True, "date": False}}
    data["assignment_access"] = access_for(data, code, own_team=own, own={"S"})
    return data


@pytest.mark.parametrize("style", ['style="display: none"', 'hidden', 'disabled', 'style="visibility:hidden"'])
def test_hidden_or_disabled_control_is_not_permission(style):
    soup = BeautifulSoup(f'<td><form action="zawody_UstawHale.php"><button {style}>Ustaw halę</button></form></td>', "html.parser")
    assert schedule_controls([soup.td]) == {"referees": False, "hall": False, "date": False}


def test_visible_button_does_not_require_own_team_for_manual_assignment():
    access = state("K/JM/18", own=False)["assignment_access"]
    assert access["manual"]
    assert "delegat" in access["editable_slots"]
    assert not access["recommended"] and access["auto_slots"] == []


def test_own_team_is_required_even_for_own_organizer_suggestions():
    assert state("S/JK/1", own=False)["assignment_access"]["auto_slots"] == []


def test_drk_suggests_only_table_and_does_not_count_field_gaps():
    data = state()
    access = data["assignment_access"]
    assert access["auto_slots"] == ["sekretarz", "czas"]
    status = crew_status(data, "LCK/39", slots=access["editable_slots"])
    assert status["field"]["missing"] == 0
    assert status["gaps"] == 2


def test_missing_button_hides_match_even_with_own_team():
    access = state(button=False)["assignment_access"]
    assert not access["manual"] and not access["recommended"]


def test_old_snapshot_cannot_infer_permission_from_own_competition_prefix():
    access = access_for({}, "S/JM/1", managed={"S"}, own={"S"}, own_team=True)
    assert not access["manual"] and not access["recommended"]
    assert access["editable_slots"] == [] and access["auto_slots"] == []
    assert not access["hall"] and not access["date"]


def test_drk_group_takes_precedence_also_for_second_league_code():
    data = state("IIK1/5")
    data["organizer_label"] = "Departament Rozgrywek Krajowych"
    access = access_for(data, "IIK1/5", own_team=True)
    assert access["organizer_kind"] == "drk"
    assert access["editable_slots"] == ["sekretarz", "czas"]


def test_membership_uses_season_and_catalogue_not_city():
    data = state()
    catalogue = {"2026/2027": ({"mts trendy top zory"}, {"100"})}
    assert resolve_access(data, "LCK/39", catalogue)["own_team"]
    data["season"] = "2025/2026"
    assert not resolve_access(data, "LCK/39", catalogue)["own_team"]
    data["season"] = "2026/2027"
    data["ID_zespoly_gosp_ZespolNazwa"] = "Inny klub Żory"
    assert not resolve_access(data, "LCK/39", catalogue)["own_team"]


def test_group_organizer_overrides_prefix_frequency():
    data = state("K/JM/18")
    data["organizer_label"] = "Małopolski Związek Piłki Ręcznej"
    assert access_for(data, "K/JM/18", own={"K", "S"}, province="SLASKIE")["organizer_kind"] == "foreign"


def test_organizer_province_comes_from_group_owner_not_guessing():
    data = state("K/JM/18")
    data["organizer_label"] = "Małopolski Związek Piłki Ręcznej"
    assert access_for(data, "K/JM/18", province="SLASKIE")["organizer_province"] == "MALOPOLSKIE"
    data["organizer_label"] = "Śląski Związek Piłki Ręcznej"
    own = access_for(data, "K/JM/18", province="SLASKIE")
    assert own["organizer_kind"] == "own" and own["organizer_province"] == "SLASKIE"
    data["organizer_label"] = "Departament Rozgrywek Krajowych"
    assert access_for(data, "K/JM/18", province="SLASKIE")["organizer_province"] == ""
    data["organizer_label"] = "Nieznana grupa"
    assert access_for(data, "K/JM/18", province="SLASKIE")["organizer_province"] in ("", "SLASKIE")


def test_need_cannot_be_widened_with_request_slots():
    data = state()
    need = need_from_state("39", data, "LCK/39", datetime(2026, 10, 31, 17), Roster(),
                           slots=["pierwszy", "sekretarz", "delegat"])
    assert need.field_needed == [] and need.table_needed == ["sekretarz"]
    data = state("K/JM/18", own=False)
    need = need_from_state("18", data, "K/JM/18", None, Roster())
    assert need.field_needed == [] and need.table_needed == []


def test_form_exposes_hidden_disabled_and_editable_roles_separately():
    html = table_official_form_html().replace('name="NrSedzia_czas"', 'disabled name="NrSedzia_czas"')
    parsed = Z._parse_referee_form(html)
    assert form_editable(parsed["slots"]) == ["sekretarz"]
    assert parsed["slots"]["sedzia1"]["field_kind"] == "hidden"
    assert parsed["slots"]["czas"]["editable"] is False


@pytest.mark.parametrize("field", ["NrSedzia_pierwszy", "NrSedzia_delegat"])
@pytest.mark.parametrize("value", ["", "1"])
async def test_forbidden_write_or_clear_fails_before_submission(monkeypatch, field, value):
    fake = FakeHttp(table_official_form_html())
    monkeypatch.setattr(Z, "fetch_with_correct_encoding", fake)
    result = await Z.apply_referee_assignment(None, {}, "208136", {field: (value, None), "NrSedzia_sekretarz": ("", "NOWAK Jan")})
    assert result["code"] == "SLOT_FORBIDDEN"
    assert len(fake.calls) == 1
    assert "akcja_edycja" not in fake.calls[0]["data"]


async def test_enabled_delegate_remains_manually_editable(monkeypatch):
    page = form_html({"NrSedzia_delegat": "1"}, BASE_OPTIONS)
    fake = FakeHttp(page, form_html({"NrSedzia_delegat": "2"}, BASE_OPTIONS))
    monkeypatch.setattr(Z, "fetch_with_correct_encoding", fake)
    result = await Z.apply_referee_assignment(None, {}, "208136", {"NrSedzia_delegat": ("", "KOWALSKI Piotr")}, require_name_match=True)
    assert result["success"]
    assert fake.submitted["NrSedzia_delegat"] == "2"


async def test_unknown_name_is_rejected_instead_of_clearing(monkeypatch):
    fake = FakeHttp(form_html({}, BASE_OPTIONS))
    monkeypatch.setattr(Z, "fetch_with_correct_encoding", fake)
    result = await Z.apply_referee_assignment(None, {}, "208136", {"NrSedzia_sekretarz": ("", "NIEZNANY Ktoś")}, require_name_match=True)
    assert result["code"] == "NAME_NOT_IN_OPTIONS" and len(fake.calls) == 1


def test_automatic_proposals_respect_live_person_lists():
    moment = datetime(2026, 10, 31, 17)
    need = MatchNeed("39", "S/JK/39", moment, moment.date(), "Katowice",
                     table_needed=["sekretarz"], allowed_slots={"sekretarz"},
                     allowed_names={"sekretarz": [JAN.name]})
    assert role_access_refusal(ANNA, need, "table")
    assert role_access_refusal(JAN, need, "field")
    assert role_access_refusal(JAN, need, "table") is None
    plan = build_plan([need], world([JAN, ANNA]))
    assert [(p.slot, p.judge_id) for p in plan.proposals] == [("sekretarz", JAN.judge_id)]


def test_disabled_venue_form_is_not_editable():
    assert not Z._parse_hall_form('<select disabled name="IdHala"><option value="1">Hala</option></select>')["editable"]
    assert not Z._parse_date_form('<form><input readonly name="data_fakt" value="2026-10-31 17:00"></form>')["editable"]


async def test_live_rights_verify_roles_and_names_without_any_save(monkeypatch):
    from app import assignment_live_access as live
    from app import zprp_accounts, deps, utils
    from app.zprp import schedule
    from types import SimpleNamespace
    live._cache.clear()
    monkeypatch.setattr(zprp_accounts, "credentials_for", lambda *args: ("test-account", "test-password"))
    monkeypatch.setattr(deps, "get_settings", lambda: SimpleNamespace(ZPRP_BASE_URL="https://example.invalid"))
    calls = []
    async def login(*args):
        return {}
    async def fetch(client, path, **kwargs):
        calls.append(kwargs["data"])
        return None, table_official_form_html()
    monkeypatch.setattr(schedule, "_login_zprp_and_get_cookies", login)
    monkeypatch.setattr(utils, "fetch_with_correct_encoding", fetch)
    data = state()
    result = await live.verify_matches("SLASKIE", {"208136": data})
    access = result["208136"]["assignment_access"]
    assert access["verified"]
    assert access["auto_slots"] == ["sekretarz", "czas"]
    assert set(access["allowed_names"]) == {"sekretarz", "czas"}
    assert calls == [{"IdZawody": "208136", "akcja": "UstawSedziow", "user": ""}]
    await live.verify_matches("SLASKIE", {"208136": data})
    assert len(calls) == 1
    # Te same prawa formularza nie poszerzają później zawężonego zakresu.
    data["assignment_access"]["auto_slots"] = ["sekretarz"]
    result = await live.verify_matches("SLASKIE", {"208136": data})
    assert result["208136"]["assignment_access"]["auto_slots"] == ["sekretarz"]
    # Obce mecze pozostają ręczne i nie wywołują weryfikacji sugestii.
    other = state("K/JM/18", own=False)
    assert await live.verify_matches("SLASKIE", {"18": other}) == {"18": other}
    assert len(calls) == 1
    live._cache.clear()


async def test_live_rights_fail_closed_for_wrong_match(monkeypatch):
    from app import assignment_live_access as live
    from app import zprp_accounts, deps, utils
    from app.zprp import schedule
    from fastapi import HTTPException
    from types import SimpleNamespace
    live._cache.clear()
    monkeypatch.setattr(zprp_accounts, "credentials_for", lambda *args: ("test-account", "test-password"))
    monkeypatch.setattr(deps, "get_settings", lambda: SimpleNamespace(ZPRP_BASE_URL="https://example.invalid"))
    async def login(*args):
        return {}
    async def fetch(*args, **kwargs):
        return None, table_official_form_html()
    monkeypatch.setattr(schedule, "_login_zprp_and_get_cookies", login)
    monkeypatch.setattr(utils, "fetch_with_correct_encoding", fetch)
    with pytest.raises(HTTPException) as exc:
        await live.verify_matches("SLASKIE", {"999": state()})
    assert exc.value.status_code == 503
    assert not live._cache


def test_schedule_retains_actual_organizer_and_enabled_controls():
    from test_zprp_schedule_assignment import _schedule_html
    from app.zprp.schedule import _parse_matches_table
    selector = '<select name="IdRozgr"><optgroup label="Małopolski Związek Piłki Ręcznej"><option value="12033">Liga Juniorów</option></optgroup></select>'
    html = selector + _schedule_html('<b>30.09.2026</b>')
    html = html.replace('<input name="IdZawody" value="12345">', '<form action="zawody_UstawSedziow.php"><input name="IdZawody" value="12345"><input type="submit" value="Sędziowie"></form>')
    parsed = next(iter(_parse_matches_table(html, context_prefix="195|junior|12033").values()))
    assert parsed["assignment_controls"] == {"referees": True, "hall": False, "date": False}
    assert parsed["organizer_label"] == "Małopolski Związek Piłki Ręcznej"
    assert parsed["competition_id"] == "12033"
    assert parsed["competition_label"] == "Liga Juniorów"


async def test_team_catalogue_uses_public_association_codes_and_actual_membership(monkeypatch):
    import sys
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from sqlalchemy import MetaData, table, column
    from app.zprp_public_tables import define_tables
    from app.assignment_access_data import own_teams
    tables = {item.name: item for item in define_tables(MetaData())}
    db = SimpleNamespace(fetch_all=AsyncMock(side_effect=[
        [{"team_province": "SL", "season": "2026/2027", "team_name": "Własna drużyna", "team_id": "1"},
         {"team_province": "MA", "season": "2026/2027", "team_name": "Obca drużyna", "team_id": "2"}],
        [{"season_name": "2026/2027", "name": "DRK własna drużyna", "team_id": "3"}],
    ]))
    monkeypatch.setitem(sys.modules, "app.db", SimpleNamespace(database=db,
        province_club_teams=table("province_club_teams", column("province")), **tables))
    result = await own_teams("SLASKIE")
    names, ids = result["2026/2027"]
    assert ids == {"1", "3"}
    assert names == {"wlasna druzyna", "drk wlasna druzyna"}
    query = db.fetch_all.call_args_list[1].args[0]
    assert "SLK" in query.compile().params.values()
    assert "SL" not in query.compile().params.values()
