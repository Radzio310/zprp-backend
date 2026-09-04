# Dziennik gieldy meczow - katalog zdarzen i zdania dla czlowieka.
#
# Rejestr jest jedynym sladem po rzeczach, ktore nadpisal pozniejszy stan:
# wycofanych zgloszeniach, nieudanych zapisach do ZPRP i tym, kto co odrzucil.
# Te testy pilnuja dwoch rzeczy: zeby zaden rodzaj zdarzenia nie zostal bez
# grupy, ikony i podpisu, i zeby zdanie o zdarzeniu dalo sie przeczytac bez
# zagladania w baze.

import pytest

from app.match_market_journal import (
    CONFIG_FIELD_LABELS,
    EVENT_GROUPS,
    EVENT_KINDS,
    config_diff_message,
    event_sentence,
    is_known_kind,
    kind_group,
    kind_icon,
    kind_label,
    kinds_in_group,
)


def test_every_kind_has_group_icon_and_label():
    for kind, entry in EVENT_KINDS.items():
        group, icon, label = entry
        assert group, kind
        assert icon, kind
        assert label, kind
        # Grupa musi istniec w pigulkach filtra - inaczej zdarzenie byloby
        # zapisywane i nigdy niewidoczne w panelu.
        assert group in {key for key, _ in EVENT_GROUPS}, kind


def test_groups_cover_all_kinds():
    covered = set()
    for group, _ in EVENT_GROUPS:
        covered.update(kinds_in_group(group))
    assert covered == set(EVENT_KINDS)


def test_unknown_kind_never_crashes_the_view():
    assert is_known_kind("offer_created") is True
    assert is_known_kind("cos_nowego") is False
    # Panel dostaje cos sensownego takze dla wpisu z przyszlej wersji serwera.
    assert kind_group("cos_nowego") == "decisions"
    assert kind_icon("cos_nowego")
    assert kind_label("cos_nowego") == "cos_nowego"


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("offer_created", "NOWAK Jan wystawił mecz IIM4/1 na giełdę."),
        ("offer_withdrawn", "NOWAK Jan zabrał mecz IIM4/1 z giełdy."),
        ("claim_created", "NOWAK Jan zgłosił się na mecz IIM4/1."),
        ("claim_withdrawn", "NOWAK Jan wycofał zgłoszenie na mecz IIM4/1."),
        ("decision_rejected", "NOWAK Jan odrzucił wymianę meczu IIM4/1."),
    ],
)
def test_sentences_name_the_person_and_the_match(kind, expected):
    assert (
        event_sentence({"kind": kind, "actor_name": "NOWAK Jan", "match_code": "IIM4/1"})
        == expected
    )


def test_decision_names_both_sides():
    assert event_sentence(
        {
            "kind": "decision_approved",
            "actor_name": "OBSADOWY Adam",
            "subject_name": "KOWALSKI Piotr",
            "match_code": "IIM4/1",
        }
    ) == "OBSADOWY Adam przyznał mecz IIM4/1 sędziemu KOWALSKI Piotr."


def test_failed_write_carries_the_reason():
    sentence = event_sentence(
        {
            "kind": "zprp_failed",
            "actor_name": "OBSADOWY Adam",
            "match_code": "IIM4/1",
            "message": "Krzysztof WITKOWICZ nie występuje na liście sędziów.",
        }
    )
    assert sentence.startswith("Zapis obsady meczu IIM4/1 w bazie związku nie przeszedł.")
    assert "nie występuje na liście" in sentence


def test_missing_name_falls_back_to_the_number_not_to_nothing():
    assert event_sentence(
        {"kind": "offer_created", "actor_judge_id": "5124", "match_code": "IIM4/1"}
    ) == "5124 wystawił mecz IIM4/1 na giełdę."
    # Nawet bez sprawcy zdanie ma sie skladac.
    assert event_sentence({"kind": "offer_created"}) == "Ktoś wystawił mecz na giełdę."


def test_config_diff_names_only_what_changed():
    message = config_diff_message(
        {
            "market_enabled": False,
            "offer_deadline_hours": 48,
            "assign_account_mode": "own",
        },
        {"market_enabled": True, "offer_deadline_hours": 48},
    )
    assert "giełda: wyłączona → włączona" in message
    # Prog sie nie zmienil, wiec nie ma prawa zaslaniac tego, co sie zmienilo.
    assert "próg" not in message


def test_config_diff_on_first_write_lists_the_values():
    message = config_diff_message(None, {"market_enabled": True, "offer_deadline_hours": 24})
    assert "giełda: włączona" in message
    assert "próg oddania (h): 24" in message


def test_config_diff_reads_badges_and_account_mode():
    message = config_diff_message(
        {"approver_badges": ["Obsadowy"], "assign_account_mode": "own"},
        {"approver_badges": ["Obsadowy", "Szef"], "assign_account_mode": "same_as_sync"},
    )
    assert "Obsadowy → Obsadowy, Szef" in message
    assert "własne konto → to samo, co monitor" in message


def test_every_config_field_has_a_human_label():
    # Pole bez podpisu wyszloby w panelu jako nazwa kolumny bazy.
    assert set(CONFIG_FIELD_LABELS) == {
        "market_enabled",
        "offer_deadline_hours",
        "assign_account_mode",
        "approver_badges",
    }
