"""Autor stolikowego dopisanego z aplikacji - kto może go usunąć."""

from datetime import datetime, timezone

from app.table_official_authors import (
    author_name_from_match,
    author_view,
    name_key,
    removal_refusal,
)

ROW = {
    "name_key": name_key("KOWALSKA Anna"),
    "author_judge_id": "0123",
    "author_name": "NOWAK Jan",
    "created_at": datetime(2026, 10, 16, tzinfo=timezone.utc),
}


def test_name_key_ignores_order_case_and_diacritics():
    assert name_key("ŁUKASIK Żaneta") == name_key("Zaneta Lukasik")
    assert name_key("") == ""


def test_author_view_only_for_current_holder():
    view = author_view(ROW, "Anna Kowalska", "123")
    assert view and view["is_me"] is True and view["name"] == "NOWAK Jan"
    assert author_view(ROW, "WIŚNIEWSKA Ewa", "123") is None
    assert author_view(ROW, "", "123") is None
    assert author_view(None, "KOWALSKA Anna", "123") is None
    assert author_view(ROW, "KOWALSKA Anna", "999")["is_me"] is False


def test_only_author_may_remove():
    assert removal_refusal(ROW, "KOWALSKA Anna", "123") is None
    other = removal_refusal(ROW, "KOWALSKA Anna", "999")
    assert other and "NOWAK Jan" in other
    assert "obsadowy" in removal_refusal(None, "KOWALSKA Anna", "123")
    # Obsadowy zmienił osobę w ZPRP - stary wpis nie daje prawa usunięcia.
    assert removal_refusal(ROW, "WIŚNIEWSKA Ewa", "123")
    assert removal_refusal(ROW, "", "123")


def test_author_name_from_match_by_number():
    match = {
        "NrSedzia_pierwszy": "55",
        "NrSedzia_pierwszy_nazwisko": "ZIELIŃSKI Piotr",
        "NrSedzia_delegat": "0123",
        "NrSedzia_delegat_nazwisko": "NOWAK Jan",
    }
    assert author_name_from_match(match, "123") == "NOWAK Jan"
    assert author_name_from_match(match, "7") == ""
    assert author_name_from_match(None, "7") == ""
