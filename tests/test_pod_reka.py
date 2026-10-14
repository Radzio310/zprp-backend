from sqlalchemy import MetaData

from app.pod_reka_rules import parse_club_scope, sanitize_public
from app.pod_reka_tables import define_tables


def test_club_scope_is_derived_from_server_pages_only():
    account_html = """
    <small>Zalogowany:</small> Klub Testowy |
    <select name="uprawnienia"><option value="2" selected>Klub</option></select>
    <input name="NrKlubu" value="0042" disabled>
    <select name="czy_aktywny"><option value="1" selected>Tak</option></select>
    """
    teams_html = """
    <a href="?a=druzyny&Filtr_zespol=100&NrKlubu=0042">Młodziczki</a>
    <a href="?a=druzyny&Filtr_zespol=101&NrKlubu=0042">Juniorki</a>
    <a href="?a=druzyny&Filtr_zespol=999&NrKlubu=7777">Obcy klub</a>
    """

    scope = parse_club_scope(account_html, teams_html)

    assert scope["account_type"] == "club"
    assert scope["active"] is True
    assert scope["club_id"] == "0042"
    assert scope["team_ids"] == ["100", "101"]


def test_public_payload_sanitizer_removes_sensitive_fields_recursively():
    source = {
        "name": "Anna",
        "birth_date": "2010-05-11",
        "tests": [{"speed": 4.2, "medical_status": "OK"}],
        "contact": {"phone": "123", "note": "publiczna"},
    }

    clean = sanitize_public(source)

    assert clean["name"] == "Anna"
    assert "birth_date" not in clean
    assert clean["tests"] == [{"speed": 4.2}]
    assert clean["contact"] == {"note": "publiczna"}


def test_pod_reka_schema_separates_sessions_reports_and_talents():
    metadata = MetaData()
    tables = {table.name: table for table in define_tables(metadata)}

    assert set(tables) == {
        "pod_reka_reports",
        "pod_reka_club_sessions",
        "pod_reka_talent_templates",
        "pod_reka_talent_submissions",
        "pod_reka_talent_audit",
        "pod_reka_push_subscriptions",
    }
    assert "upstream_cookies_encrypted" in tables["pod_reka_club_sessions"].c
    assert "password" not in tables["pod_reka_club_sessions"].c
    assert "private_score" in tables["pod_reka_talent_submissions"].c
    assert "endpoint" in tables["pod_reka_push_subscriptions"].c
    assert "delete_token_hash" in tables["pod_reka_push_subscriptions"].c
