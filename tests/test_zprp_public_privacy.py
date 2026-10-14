from __future__ import annotations

import gzip
import json
from sqlalchemy import MetaData

from app.zprp_public.client import birth_year, canonical_json, rows, sanitize
from app.zprp_public.privacy import public_club, public_team
from app.zprp_public_tables import define_tables


def test_sanitize_removes_birth_dates_and_medical_flags_recursively():
    source = {
        "gosp": {
            "77": {
                "Imie": "Anna",
                "DataUr": "2010-05-11",
                "badania_ZPRP": "OK",
                "badania_WZPR": "OK",
                "Foto": "https://baza.zprp.pl/foto/77.jpg",
            }
        }
    }

    clean = sanitize(source)
    encoded = canonical_json(source)

    assert clean["gosp"]["77"]["Imie"] == "Anna"
    assert clean["gosp"]["77"]["Foto"].endswith("77.jpg")
    assert "DataUr" not in clean["gosp"]["77"]
    assert "badania_ZPRP" not in clean["gosp"]["77"]
    assert b"2010-05-11" not in encoded
    assert "badania" not in encoded.decode("utf-8").lower()
    assert json.loads(gzip.decompress(gzip.compress(encoded))) == clean


def test_only_birth_year_is_derived_for_normalized_player():
    assert birth_year("2011-09-16") == 2011
    assert birth_year("") is None
    assert birth_year("nieznana") is None


def test_rows_accepts_php_numeric_object_and_json_array():
    assert rows({"1": {"Id": "a"}, "2": {"Id": "b"}}) == [{"Id": "a"}, {"Id": "b"}]
    assert rows([{"Id": "a"}, "skip"]) == [{"Id": "a"}]


def test_schema_keeps_public_player_photo_but_no_sensitive_columns():
    metadata = MetaData()
    tables = define_tables(metadata)
    by_name = {table.name: table for table in tables}
    player = by_name["zprp_public_players"]

    assert "birth_year" in player.c
    assert "photo_url" in player.c
    assert "birth_date" not in player.c
    assert "medical_status" not in player.c
    assert len(tables) >= 15


def test_public_club_and_team_details_never_expose_contact_fields():
    source = {
        "club_id": "11",
        "team_id": "22",
        "season_id": "2026",
        "name": "Klub Testowy",
        "city": "Warszawa",
        "website": "https://example.org",
        "email": "sekret@example.org",
        "phone_1": "+48 000 000 000",
        "street": "Ukryta 1",
        "postal_code": "00-000",
        "source_json": {"PESEL": "00000000000"},
    }

    club = public_club(source)
    team = public_team(source)

    assert club["website"] == "https://example.org"
    assert team["city"] == "Warszawa"
    for payload in (club, team):
        assert "email" not in payload
        assert "phone_1" not in payload
        assert "street" not in payload
        assert "postal_code" not in payload
        assert "source_json" not in payload

