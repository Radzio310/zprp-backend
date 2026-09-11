"""
Nazwisko sedziego z obsady meczu - „465" w zestawieniu to BLOCH Wojciech.

Prawdziwy przypadek: mecz S/MłK/167 (Zawody=194144). Lista okregu miala sedziego
465 bez nazwiska, a publiczne API meczu podaje numer obok nazwiska.
"""

from datetime import datetime, timezone

from app.settlement_names_rules import (
    given_first,
    is_missing_name,
    match_id_of,
    officials_from_payload,
    officials_from_record,
    pick_unnamed,
)

RECORD = {
    "Id_rozgrywki": 11684,
    "NrSedzia_pierwszy": 465,
    "NrSedzia_drugi": 5689,
    "NrSedzia_delegat": None,
    "NrSedzia_delegat2": None,
    "NrSedzia_sekretarz": None,
    "NrSedzia_czas": 0,
    "NrSedzia_pierwszy_nazwisko": "BLOCH Wojciech",
    "NrSedzia_drugi_nazwisko": "ANDERS Magdalena",
    "NrSedzia_delegat_nazwisko": "",
    "NrSedzia_delegat2_nazwisko": "",
    "NrSedzia_sekretarz_nazwisko": "",
    "NrSedzia_czas_nazwisko": "",
    "NrSedzia_pierwszy_miasto": "Nakło Śląskie",
    "NrSedzia_drugi_miasto": "Ruda Śląska",
    "Hala_miasto": "Zabrze",
}


def test_number_name_and_city_of_each_official():
    assert officials_from_record(RECORD) == [
        {"judge_id": "465", "name": "BLOCH Wojciech", "city": "Nakło Śląskie", "slot": "pierwszy"},
        {"judge_id": "5689", "name": "ANDERS Magdalena", "city": "Ruda Śląska", "slot": "drugi"},
    ]


def test_empty_and_zero_slots_are_not_officials():
    record = {**RECORD, "NrSedzia_czas": 0, "NrSedzia_czas_nazwisko": "NOWAK Jan"}
    assert [item["judge_id"] for item in officials_from_record(record)] == ["465", "5689"]


def test_both_shapes_of_the_api_answer():
    with_rosters = {"0": [RECORD], "gosp": {}, "gosc": {}}
    bare = [[RECORD]]
    assert officials_from_payload(with_rosters)[0]["name"] == "BLOCH Wojciech"
    assert officials_from_payload(bare)[0]["name"] == "BLOCH Wojciech"
    assert officials_from_payload(None) == []


def test_name_is_stored_given_name_first_like_the_district_list():
    assert given_first("BLOCH Wojciech") == "Wojciech BLOCH"
    assert given_first("Wojciech BLOCH") == "Wojciech BLOCH"
    assert given_first("KOWALSKA-NOWAK Anna Maria") == "Anna Maria KOWALSKA-NOWAK"


def test_a_number_is_not_a_name():
    assert is_missing_name("465", "465")
    assert is_missing_name("465")
    assert is_missing_name("   ")
    assert is_missing_name(None)
    assert not is_missing_name("Wojciech BLOCH", "465")


def test_match_id_from_the_settlement_key():
    assert match_id_of("d:194144") == "194144"
    assert match_id_of("o:207001") == "207001"
    assert match_id_of("x") == ""
    assert match_id_of("d:abc") == ""


def test_pick_recent_matches_of_unnamed_judges_only():
    march = datetime(2026, 3, 7, tzinfo=timezone.utc)
    may = datetime(2026, 5, 4, tzinfo=timezone.utc)
    rows = [
        ("465", "d:180001", march),
        ("465", "d:194144", may),
        ("465", "x:bez-numeru", may),
        ("5689", "d:194144", may),
        ("777", "d:190000", march),
    ]
    names = {"465": "465", "5689": "Magdalena ANDERS", "777": ""}
    picked = pick_unnamed(rows, names)
    assert picked == {"465": ["194144", "180001"], "777": ["190000"]}
    assert pick_unnamed(rows, names, only={"777"}) == {"777": ["190000"]}
    assert len(pick_unnamed(rows, names, limit=1)) == 1
