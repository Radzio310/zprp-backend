"""Archiwum usuniętych zapisów meczów ProEl.

Testujemy to, co da się sprawdzić bez bazy: kształt wiersza na liście i
serializację stanu współpracy. Obie te rzeczy mają jeden powód istnienia i
łatwo je zepsuć po cichu.

`_summary` NIE może nieść `data_json`. Blob to pełny protokół z przebiegiem
meczu, potrafi mieć setki kilobajtów, a lista pokazuje kilkadziesiąt pozycji -
gdyby go niosła, jedno wejście w zakładkę ściągałoby kilkanaście megabajtów.

`_state_snapshot` musi zamieniać daty na tekst. Kolumna docelowa jest JSON-em,
a `datetime` nie jest serializowalny; bez tej zamiany usunięcie meczu, który
kiedykolwiek miał stan współpracy, wywracałoby się na zapisie do archiwum -
czyli dokładnie wtedy, gdy najbardziej zależy nam, żeby dane przetrwały.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

# `app.proel` ciągnie za sobą `app.db`, a ten przy imporcie zakłada schemat.
# Schemat używa typów wyłącznie postgresowych (ARRAY/JSONB/UUID), więc bez
# Postgresa nie da się nawet zaimportować modułu - ta sama bariera co w
# `conftest.requires_db`.
pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgres"),
    reason="Wymaga Postgresa (schemat używa ARRAY/JSONB/UUID). Ustaw DATABASE_URL=postgresql://…",
)

if os.getenv("DATABASE_URL", "").startswith("postgres"):
    from app.proel import _state_snapshot
    from app.proel_archive import RETENTION_DAYS, _summary


def _row(**over):
    base = {
        "id": 7,
        "match_number": "OSK/12",
        "zprp_match_id": "208136",
        "status": "approved",
        "data_json": {
            "date": "2026-08-14T18:30:00.000Z",
            "matchConfig": {
                "hostTeamName": "Gospodarze SA",
                "guestTeamName": "Goście SA",
                "isTest": False,
            },
            # Celowo duży fragment - ma NIE trafić na listę.
            "protocol": [{"type": "goal"} for _ in range(500)],
        },
        "state_json": {"fields_json": {}},
        "deleted_at": datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
        "deleted_by_judge_id": "12345",
        "deleted_by_name": "KOWALSKI Jan",
        "deleted_by_install": "inst-1",
        "deleted_by_verified": True,
        "expires_at": datetime(2027, 8, 20, 10, 0, tzinfo=timezone.utc),
        "restored_at": None,
        "restored_by_judge_id": None,
    }
    base.update(over)
    return base


def test_lista_nie_niesie_blobow():
    out = _summary(_row())
    assert "data_json" not in out
    assert "state_json" not in out


def test_lista_wyciaga_druzyny_i_date_z_protokolu():
    """Admin szuka po nazwach drużyn, a te leżą wewnątrz bloba."""
    out = _summary(_row())
    assert out["host_team_name"] == "Gospodarze SA"
    assert out["guest_team_name"] == "Goście SA"
    assert out["match_date"] == "2026-08-14T18:30:00.000Z"
    assert out["match_number"] == "OSK/12"


def test_mecz_testowy_jest_oznaczony():
    out = _summary(_row(data_json={"matchConfig": {"isTest": True}}))
    assert out["is_test"] is True


def test_kto_usunal_zostaje_na_liscie():
    out = _summary(_row())
    assert out["deleted_by_judge_id"] == "12345"
    assert out["deleted_by_name"] == "KOWALSKI Jan"
    assert out["deleted_by_verified"] is True


def test_pusty_blob_nie_wywraca_listy():
    """Starsze zapisy bywają bez `matchConfig` - lista ma je przeżyć."""
    out = _summary(_row(data_json={}))
    assert out["host_team_name"] is None
    assert out["is_test"] is False


def test_snapshot_stanu_zamienia_daty_na_tekst():
    row = {
        "match_number": "OSK/12",
        "rev": 12,
        "fields_json": {"sig.team.host": {"v": "x"}},
        "created_at": datetime(2026, 8, 14, 18, 0, tzinfo=timezone.utc),
        "lease_until": None,
    }
    out = _state_snapshot(row)
    assert isinstance(out["created_at"], str)
    assert out["created_at"].startswith("2026-08-14")
    assert out["rev"] == 12
    assert out["fields_json"] == {"sig.team.host": {"v": "x"}}
    assert out["lease_until"] is None


def test_snapshot_bierze_komplet_kolumn():
    """Nie wybieramy „pól ważnych" - lista ważnych rozjechałaby się z tabelą."""
    row = {"match_number": "A", "nowa_kolumna": 1, "inna": None}
    assert set(_state_snapshot(row)) == {"match_number", "nowa_kolumna", "inna"}


def test_okres_przechowywania_to_rok():
    assert RETENTION_DAYS == 365
