"""Zgłoszenie 02.11.2026: konto z Dyskiem Mentora nie mogło połączyć kalendarza
(„Scope has changed"), bo Google dokładał do odpowiedzi dawną zgodę drive.file."""
from pathlib import Path

from app.calendar_secondary_rules import lacks_events_scope

ROOT = Path(__file__).resolve().parents[1]
EVENTS = "https://www.googleapis.com/auth/calendar.events"
READONLY = "https://www.googleapis.com/auth/calendar.readonly"
DRIVE = "https://www.googleapis.com/auth/drive.file"


def test_dodatkowy_zakres_nie_jest_odmowa():
    assert lacks_events_scope(f"{EVENTS} {READONLY} {DRIVE}") is False


def test_zgoda_bez_kalendarza_jest_odmowa():
    assert lacks_events_scope(f"{READONLY} {DRIVE}") is True


def test_brak_informacji_o_zakresach_nie_jest_odmowa():
    assert lacks_events_scope(None) is False
    assert lacks_events_scope("") is False


def test_zaden_przeplyw_kalendarza_nie_dokleja_dawnych_zgod():
    for path in ("app/calendar.py", "app/beach/calendar.py"):
        assert 'include_granted_scopes="true"' not in (ROOT / path).read_text(encoding="utf-8")


def test_oauthlib_nie_przerywa_przy_innym_zakresie():
    source = (ROOT / "app/calendar_utils.py").read_text(encoding="utf-8")
    assert 'os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")' in source
