from unittest.mock import patch

import pytest

from app.national_distance_parser import (
    validate_settlement_candidate,
    normalize_city_key,
    parse_settlement_pdf,
)


def test_parses_official_round_trip_and_uses_clean_city_hint_for_broken_font():
    extracted = """
    S�DZIA: WITKOWICZ Rados�aw
    zam. Mys�owice
    Miejsce rozgrywania zawod�w: Opole
    Przejazd 2x
    122 = 244 km
    """
    with patch("app.national_distance_parser.read_pdf_text", return_value=extracted):
        result = parse_settlement_pdf(
            b"%PDF-fake",
            judge_city_hint="Mysłowice",
            venue_city_hint="Opole",
        )

    assert result.judge_city == "Mysłowice"
    assert result.venue_city == "Opole"
    assert result.one_way_km == 122
    assert result.round_trip_km == 244


def test_rejects_inconsistent_round_trip():
    extracted = """
    zam. Katowice
    Miejsce rozgrywania zawodow: Kraków
    Przejazd 2x 80 = 111 km
    """
    with patch("app.national_distance_parser.read_pdf_text", return_value=extracted):
        with pytest.raises(ValueError, match="niespójne"):
            parse_settlement_pdf(b"%PDF-fake")


def test_city_key_is_direction_independent_and_diacritic_free():
    assert normalize_city_key(" Mysłowice ") == "myslowice"
    assert sorted([normalize_city_key("Opole"), normalize_city_key("Mysłowice")]) == [
        "myslowice",
        "opole",
    ]


def test_accepts_only_real_zprp_settlement_links():
    parsed = validate_settlement_candidate(
        url="https://baza.zprp.pl/sedzia_ryczalt_PDF.php?Id=16294&IdZawody=207406",
        match_code="IMD/3",
    )
    assert parsed["source_key"] == "16294:207406"
    assert parsed["match_id"] == "207406"

    with pytest.raises(ValueError):
        validate_settlement_candidate(
            url="https://example.org/sedzia_ryczalt_PDF.php?Id=16294&IdZawody=207406"
        )
