"""Adresowanie maila o kolizji niedyspozycyjności z obsadą."""

from app.zprp_unavailability_mail_rules import (
    DEFAULT_DELEGATE_RECIPIENT,
    cc_recipients,
    mutual_partner_id,
    primary_recipients,
)


def test_referee_overlap_uses_central_recipients_without_duplicates():
    row = {"matches_json": [{"role": "sędzia 1"}]}
    settings = {
        "recipient_emails": ["Obsada@ZPRP.pl", "drugi@zprp.pl"],
        "recipient_email": "obsada@zprp.pl",
        "delegate_recipient_email": "delegaci@zprp.pl",
    }

    assert primary_recipients(row, settings) == [
        "obsada@zprp.pl",
        "drugi@zprp.pl",
    ]


def test_delegate_overlap_uses_separate_configured_recipient():
    row = {"matches_json": [{"role": "delegat 2"}]}
    settings = {
        "recipient_emails": ["obsada@zprp.pl"],
        "delegate_recipient_email": "Delegaci@ZPRP.pl",
    }

    assert primary_recipients(row, settings) == ["delegaci@zprp.pl"]


def test_delegate_overlap_has_safe_default_for_existing_configuration():
    row = {"matches_json": [{"role": "DELEGAT"}]}

    assert primary_recipients(row, {}) == [DEFAULT_DELEGATE_RECIPIENT]


def test_partner_is_added_to_cc_beside_province_addresses():
    assert cc_recipients(
        ["okręg@zprp.pl", "partner@zprp.pl"],
        partner_email="PARTNER@zprp.pl",
        primary=["obsada@zprp.pl"],
    ) == ["okręg@zprp.pl", "partner@zprp.pl"]


def test_primary_recipient_is_never_repeated_in_cc():
    assert cc_recipients(
        ["obsada@zprp.pl"],
        partner_email="OBSADA@ZPRP.PL",
        primary=["obsada@zprp.pl"],
    ) == []


def test_only_mutual_pair_is_treated_as_paired():
    assert mutual_partner_id("100", "200", "100") == "200"
    assert mutual_partner_id("100", "200", "") == ""
    assert mutual_partner_id("100", "200", "300") == ""
    assert mutual_partner_id("100", "100", "100") == ""
