"""Prognoza „Moje rozliczenie": co z telefonu wolno dokleic do rachunku."""

from datetime import datetime, timezone

from app import settlement_forecast_rules as F
from app import settlement_rates as R

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def pick(items, known=(), own=("S",)):
    return F.pick_forecast(items, known_ids=set(known), own_prefixes=set(own), now=NOW)


def test_dokleja_tylko_przyszle_i_nieznane_serwerowi():
    out = pick(
        [
            {"match_id": "100", "code": "S/JMM/1", "when": "2026-11-05T16:00:00Z", "role": "Sędzia boiskowy"},
            {"match_id": "101", "code": "S/JMM/2", "when": "2026-09-20T16:00:00Z"},  # rozegrany
            {"match_id": "102", "code": "S/JMM/3", "when": "2026-11-06T16:00:00Z"},  # serwer zna
            {"match_id": "100", "code": "S/JMM/1", "when": "2026-11-05T16:00:00Z"},  # powtórka
        ],
        known={"102"},
    )
    assert [item["match_key"] for item in out] == ["f:100"]
    assert out[0]["role"] == R.ROLE_FIELD


def test_boiskowy_obcego_okregu_nie_wchodzi_a_stolik_tak():
    out = pick(
        [
            {"match_id": "1", "code": "L/JMM/1", "when": "2026-11-05T16:00:00Z", "role": "Sędzia boiskowy"},
            {"match_id": "2", "code": "L/JMM/2", "when": "2026-11-05T18:00:00Z", "role": "Sekretarz"},
            {"match_id": "3", "code": "IIM4/7", "when": "2026-11-07T18:00:00Z", "role": "Sędzia boiskowy"},
        ]
    )
    assert [(item["match_key"], item["role"]) for item in out] == [
        ("f:2", R.ROLE_TABLE),
        # Centralny wchodzi - silnik sam odłoży go jako obsadę ZPRP, bez kwoty.
        ("f:3", R.ROLE_FIELD),
    ]


def test_bez_daty_i_bez_numeru_nic_nie_zgadujemy():
    assert pick([{"match_id": "9", "code": "S/JMM/1", "when": ""}]) == []
    assert pick([{"match_id": "9", "code": "", "when": "2026-11-05T16:00:00Z"}]) == []


def test_klucz_meczu_z_synchronizacji_rozpoznaje_ten_sam_mecz():
    assert F.match_id_of("d:194144") == "194144"
    assert F.match_id_of("194144") == "194144"
    assert F.role_of("Delegat") == R.ROLE_DELEGATE
    assert F.role_of("Sędzia stolikowy") == R.ROLE_TABLE
