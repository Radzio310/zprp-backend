"""Konta wojewódzkie ZPRP - rozdział ról i to, co wolno powiedzieć o sekretach.

Dwie rzeczy pilnowane tutaj są decyzjami, a nie szczegółem implementacji:

* tryb `own` NIE schodzi po cichu do konta monitora - okręg bez konta obsadowego
  ma nie działać zamiast działać cudzym kontem,
* `account_status` nie oddaje ani jednego znaku hasła.
"""
from __future__ import annotations

from app.zprp_accounts import (
    PROVINCE_ENV_SUFFIXES,
    account_status,
    assign_credentials,
    configured_provinces,
    credentials_for,
    env_var_names,
    normalize_province,
)

SLASK_SYNC = {
    "ZPRP_SYNC_SLASKIE_USERNAME": "monitor",
    "ZPRP_SYNC_SLASKIE_PASSWORD": "tajne1",
}
SLASK_ASSIGN = {
    "ZPRP_ASSIGN_SLASKIE_USERNAME": "obsadowy",
    "ZPRP_ASSIGN_SLASKIE_PASSWORD": "tajne2",
}


def test_province_names_are_normalized():
    assert normalize_province("Śląskie") == "SLASKIE"
    assert normalize_province("  województwo śląskie ") == "SLASKIE"
    assert normalize_province("dolny śląsk") == "DOLNOSLASKIE"
    assert normalize_province("warmińsko-mazurskie") == "WARMINSKO_MAZURSKIE"


def test_unknown_province_is_an_answer_not_a_crash():
    assert normalize_province("Bawaria") == ""
    assert normalize_province(None) == ""
    assert env_var_names("Bawaria", "sync") == ("", "")


def test_variable_names_are_shown_verbatim():
    # Panel administratora pokazuje je wprost, żeby dołożenie okręgu nie
    # wymagało zaglądania do kodu.
    assert env_var_names("Śląskie", "sync") == (
        "ZPRP_SYNC_SLASKIE_USERNAME",
        "ZPRP_SYNC_SLASKIE_PASSWORD",
    )
    assert env_var_names("Śląskie", "assign") == (
        "ZPRP_ASSIGN_SLASKIE_USERNAME",
        "ZPRP_ASSIGN_SLASKIE_PASSWORD",
    )


def test_half_a_pair_is_not_an_account():
    # Logowanie samym loginem i tak by nie przeszło, a cicha próba zostawiłaby
    # w logach ZPRP serię nieudanych uwierzytelnień z naszego adresu.
    env = {"ZPRP_SYNC_SLASKIE_USERNAME": "monitor"}
    assert credentials_for("SLASKIE", "sync", env) is None


def test_configured_provinces_lists_only_complete_accounts():
    env = dict(SLASK_SYNC)
    env["ZPRP_SYNC_OPOLSKIE_USERNAME"] = "polowa"
    assert configured_provinces(env) == {"SLASKIE": ("monitor", "tajne1")}


def test_own_mode_uses_the_assignment_account():
    env = {**SLASK_SYNC, **SLASK_ASSIGN}
    out = assign_credentials("SLASKIE", "own", env)
    assert out["configured"] is True
    assert out["username"] == "obsadowy"
    assert out["role"] == "assign"


def test_own_mode_does_not_fall_back_to_the_monitor_account():
    # Sedno rozdziału ról: brak konta obsadowego znaczy „nie działa", a nie
    # „zapisz kontem, którym chodzą powiadomienia całego województwa".
    out = assign_credentials("SLASKIE", "own", dict(SLASK_SYNC))
    assert out["configured"] is False
    assert out["username"] == ""


def test_same_as_sync_is_a_deliberate_choice():
    out = assign_credentials("SLASKIE", "same_as_sync", dict(SLASK_SYNC))
    assert out["configured"] is True
    assert out["username"] == "monitor"
    assert out["mode"] == "same_as_sync"


def test_status_never_leaks_a_password():
    env = {**SLASK_SYNC, **SLASK_ASSIGN}
    status = account_status("Śląskie", "own", env)
    flat = repr(status)
    assert "tajne1" not in flat and "tajne2" not in flat
    assert "monitor" not in flat and "obsadowy" not in flat


def test_status_answers_the_only_question_the_panel_asks():
    env = {**SLASK_SYNC, **SLASK_ASSIGN}
    status = account_status("Śląskie", "own", env)
    assert status["known"] is True
    assert status["sync"]["configured"] is True
    assert status["assign"]["configured"] is True
    assert status["ready"] is True

    without_assign = account_status("Śląskie", "own", dict(SLASK_SYNC))
    assert without_assign["assign"]["configured"] is False
    assert without_assign["ready"] is False
    # Panel ma czym podpowiedzieć, co dodać na Railway.
    assert without_assign["assign"]["vars"]["username"] == "ZPRP_ASSIGN_SLASKIE_USERNAME"


def test_status_of_a_foreign_name_is_not_ready():
    status = account_status("Bawaria", "own", {})
    assert status["known"] is False
    assert status["ready"] is False


def test_all_sixteen_provinces_are_known():
    assert len(PROVINCE_ENV_SUFFIXES) == 16
