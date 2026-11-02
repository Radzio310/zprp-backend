"""Kalendarze drugorzędne Google: czyste reguły."""

from __future__ import annotations

import base64
import json

import pytest

from app.calendar_secondary_rules import (
    DISTRICT_SCOPES,
    MATCHES_SCOPES,
    SCOPE_APP_CREATED,
    SCOPE_CALENDARLIST,
    SCOPE_CALENDARS_RO,
    SCOPE_EVENTS,
    SecondaryError,
    access_level,
    email_from_id_token,
    flag_enabled,
    flag_from_env,
    foreground_for,
    granted_scopes,
    has_color_access,
    is_beach_key,
    make_state,
    missing_scopes,
    normalize_hex,
    parse_tier,
    resolve_target,
    scope_to_string,
    scopes_for_tier,
    target_from_title,
    tier_from_state,
    uses_secondary,
)


def test_access_levels_from_granted_scopes():
    assert access_level(None) == "legacy" and access_level("") == "legacy"
    assert access_level(f"{SCOPE_APP_CREATED} openid email") == "matches"
    assert access_level(f"{SCOPE_APP_CREATED} {SCOPE_EVENTS}") == "district"
    assert access_level("openid") == "none"


def test_scopes_per_tier_are_incremental():
    assert set(MATCHES_SCOPES) < set(DISTRICT_SCOPES)
    assert scopes_for_tier("matches") == MATCHES_SCOPES
    # Kolor wymaga listy kalendarzy, a jej brak nie blokuje zgody na mecze.
    assert SCOPE_CALENDARLIST in MATCHES_SCOPES
    assert not missing_scopes("matches", SCOPE_APP_CREATED)
    # Zapis listy wystarcza tam, gdzie moduł okręgowy czyta listę.
    assert not missing_scopes(
        "district",
        f"{SCOPE_APP_CREATED} {SCOPE_CALENDARLIST} {SCOPE_EVENTS} {SCOPE_CALENDARS_RO}",
    )
    assert has_color_access(SCOPE_CALENDARLIST) and not has_color_access(SCOPE_APP_CREATED)
    assert not has_color_access(None)
    assert SCOPE_EVENTS in scopes_for_tier("district")
    assert SCOPE_EVENTS not in scopes_for_tier("matches")
    assert granted_scopes("email openid")  # krótkie nazwy są normalizowane
    assert scope_to_string(["b", "a"]) == "a b"


def test_flag_is_strict_and_beach_is_never_secondary():
    class S:
        GOOGLE_CALENDAR_SECONDARY_ENABLED = True

    assert flag_enabled(S()) is True
    assert flag_enabled(object()) is False
    assert flag_from_env("TRUE") and not flag_from_env("") and not flag_from_env(None)
    assert not uses_secondary(False, "u", f"{SCOPE_APP_CREATED}")
    assert uses_secondary(True, "u", f"{SCOPE_APP_CREATED}")
    assert not uses_secondary(True, "u", None)
    assert is_beach_key("beach:12") and not uses_secondary(True, "beach:12", SCOPE_APP_CREATED)


def test_state_carries_tier_and_bad_tier_is_a_coded_error():
    assert tier_from_state(make_state("district", "abc")) == "district"
    assert tier_from_state(make_state("matches", "abc")) == "matches"
    assert tier_from_state("losowy") is None
    assert parse_tier(None) == "matches"
    with pytest.raises(SecondaryError) as err:
        parse_tier("admin")
    assert err.value.status == 400 and err.value.code == "invalid_tier"


def test_target_prefix_and_explicit_override():
    assert target_from_title("⚽️ A") == "whistle"
    assert target_from_title("⏱️ A") == "stopwatch"
    assert target_from_title("Urlop") == "primary" and target_from_title(None) == "primary"
    assert resolve_target("Urlop", "whistle") == "whistle"
    assert resolve_target("⚽️ A", "") == "whistle"


def test_colors_and_foreground():
    assert normalize_hex(" #ABCDEF ") == "#abcdef"
    assert normalize_hex("abcdef") is None and normalize_hex(5) is None
    assert foreground_for("#f6bf26") == "#000000" and foreground_for("#0b8043") == "#ffffff"
    assert foreground_for("zle") == "#ffffff"


def test_email_from_id_token_reads_payload_only():
    payload = base64.urlsafe_b64encode(json.dumps({"email": "a@b.pl"}).encode()).decode().rstrip("=")
    assert email_from_id_token(f"x.{payload}.y") == "a@b.pl"
    assert email_from_id_token("bzdura") is None and email_from_id_token(None) is None
