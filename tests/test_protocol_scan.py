"""
Sprawdzanie wizualne protokołu — odczyt ze zdjęcia kontra dziennik.

Sedno tych testów: przy zdjęciu NIE MA skrótu ani podpisu, bo wydruk gubi
metadane. Jedyne, co da się zrobić, to odczytać widoczne wartości i zapytać
dziennik, czy tak było w chwili generowania.

Najważniejsza reguła sprawdzana niżej: pole nieodczytane NIGDY nie może zostać
zgłoszone jako różnica. Fałszywe „podrobiony" na rozmazanym zdjęciu kosztuje
czyjąś opinię — brak odpowiedzi kosztuje jedno kolejne zdjęcie.
"""
import pytest

from app.results import (
    PROTOCOL_SCAN_FIELDS,
    _compare_scan_to_state,
    _scan_code_from_text,
    _scan_media_type,
    _scan_values_match,
)

STATE = {
    "matchConfig": {
        "matchNumber": "ML/251",
        "hostTeamName": "KS Vive Kielce",
        "guestTeamName": "Azoty Puławy",
        "extras": {
            "spectatorsCount": "852",
            "venueCapacity": "2318",
            "matchDate": "2026-08-15",
            "matchTime": "21:23",
            "medic": {"fullName": "NOWAK Jan"},
        },
    },
    "scoreHost": 5,
    "scoreGuest": 3,
    "halfScore": {"host": 4, "guest": 2},
}

FULL_READ = {
    "match_number": "ML/251",
    "host_team": "KS Vive Kielce",
    "guest_team": "Azoty Puławy",
    "score_host": "5",
    "score_guest": "3",
    "half_host": "4",
    "half_guest": "2",
    "spectators": "852",
    "venue_capacity": "2318",
    "match_date": "15.08.2026",
    "match_time": "21:23",
    "medic_name": "NOWAK Jan",
}


# ─────────────────────── rozpoznanie pliku ───────────────────────

def test_media_type_detects_jpeg_and_png():
    assert _scan_media_type(b"\xff\xd8\xff\xe0reszta") == "image/jpeg"
    assert _scan_media_type(b"\x89PNG\r\n\x1a\nreszta") == "image/png"


def test_media_type_rejects_pdf_and_junk():
    """PDF ma własną, mocniejszą drogę weryfikacji — tu nie ma po co trafiać."""
    assert _scan_media_type(b"%PDF-1.7") == ""
    assert _scan_media_type(b"") == ""


# ─────────────────────── kod ze stopki ───────────────────────

def test_code_read_from_footer_text():
    assert _scan_code_from_text("… dnia 15.08.2026 · BZ-0QT9-MGXP") == "BZ-0QT9-MGXP"


def test_code_tolerates_spacing_and_case():
    """Model bywa kreatywny z myślnikami i wielkością liter."""
    assert _scan_code_from_text("bz 0qt9 mgxp") == "BZ-0QT9-MGXP"


def test_code_empty_when_absent():
    assert _scan_code_from_text("brak kodu") == ""
    assert _scan_code_from_text("") == ""


# ─────────────────────── porównanie wartości ───────────────────────

def test_numbers_compare_as_numbers():
    assert _scan_values_match("852", "852", "number")
    assert _scan_values_match("5", "5.0", "number")
    assert not _scan_values_match("2318", "2319", "number")


def test_text_ignores_case_and_accents():
    """Drukowane wersaliki i ogonki to nie fałszerstwo."""
    assert _scan_values_match("Azoty Puławy", "AZOTY PULAWY", "text")
    assert not _scan_values_match("Azoty Puławy", "Azoty Police", "text")


def test_whitespace_never_counts_as_change():
    assert _scan_values_match("KS  Vive Kielce", " KS Vive Kielce ", "text")


# ─────────────────────── zestawienie z dziennikiem ───────────────────────

def test_clean_photo_matches_ledger():
    out = _compare_scan_to_state(FULL_READ, STATE)
    assert out["changes"] == []
    assert len(out["checked"]) == len(PROTOCOL_SCAN_FIELDS)
    assert out["unreadable"] == []


def test_date_and_time_compared_in_printed_form():
    """W stanie leży `2026-08-15`, a na papierze `15.08.2026` — to ta sama data."""
    out = _compare_scan_to_state(FULL_READ, STATE)
    labels = [c["label"] for c in out["changes"]]
    assert "Data zawodów" not in labels
    assert "Godzina zawodów" not in labels


def test_edited_value_is_caught_and_named():
    """Przypadek z testu na żywo: pojemność podmieniona na wydruku."""
    read = {**FULL_READ, "venue_capacity": "2319"}
    out = _compare_scan_to_state(read, STATE)
    assert len(out["changes"]) == 1
    ch = out["changes"][0]
    assert ch["label"] == "Pojemność obiektu"
    assert ch["before"] == "2318"
    assert ch["after"] == "2319"


def test_unreadable_field_is_never_reported_as_change():
    """
    Reguła, na której wszystko stoi. Model zwrócił `null`, bo pole było
    rozmazane — to NIE jest dowód na fałszerstwo.
    """
    read = {**FULL_READ, "spectators": None}
    out = _compare_scan_to_state(read, STATE)
    assert out["changes"] == []
    assert "Liczba widzów" in out["unreadable"]


def test_empty_string_counts_as_unreadable_too():
    read = {**FULL_READ, "spectators": "   "}
    out = _compare_scan_to_state(read, STATE)
    assert out["changes"] == []
    assert "Liczba widzów" in out["unreadable"]


def test_value_present_on_paper_but_empty_in_ledger_is_a_change():
    """Dopisanie czegoś do pustej rubryki to też fałszerstwo."""
    state = {**STATE, "matchConfig": {**STATE["matchConfig"], "extras": {}}}
    read = {"spectators": "852"}
    out = _compare_scan_to_state(read, state)
    assert out["changes"][0]["label"] == "Liczba widzów"
    assert out["changes"][0]["before"] == "—"


def test_field_empty_on_both_sides_is_silent():
    """Pusta rubryka w dzienniku i na papierze — nie ma o czym mówić."""
    state = {"matchConfig": {"extras": {}}}
    out = _compare_scan_to_state({}, state)
    assert out["changes"] == []
    assert out["checked"] == []
    assert out["unreadable"] == []


def test_missing_state_does_not_explode():
    out = _compare_scan_to_state(FULL_READ, None)
    # Bez stanu nie ma z czym porównywać — wszystko wygląda jak dopisane,
    # ale funkcja ma zwrócić wynik, a nie wyjątek.
    assert isinstance(out["changes"], list)
