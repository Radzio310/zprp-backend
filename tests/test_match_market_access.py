"""Kto może zatwierdzić wymianę meczu - czysta logika, bez bazy.

Najważniejszy test to `test_province_comes_from_the_database_not_the_phone`:
województwo w tokenie ustawia sobie sam użytkownik w ustawieniach aplikacji, a
zatwierdzenie zmienia obsadę w bazie związku. Gdyby decydowało to pierwsze,
wystarczyłoby przestawić pole w ustawieniach, żeby rozstrzygać cudzy okręg.
"""
from __future__ import annotations

from app.match_market_access import (
    APPROVER_BADGE,
    approver_judge_ids,
    badge_names,
    has_approver_badge,
    may_approve,
    may_manage_config,
)

SLASK = "ŚLĄSKIE"
OPOLE = "OPOLSKIE"


def test_admin_may_approve_anywhere():
    assert may_approve(is_admin=True, province=SLASK, judge_province="", badges_raw=None)


def test_badge_holder_may_approve_in_own_province():
    assert may_approve(
        is_admin=False,
        province=SLASK,
        judge_province=SLASK,
        badges_raw={APPROVER_BADGE: True},
    )


def test_badge_holder_may_not_approve_elsewhere():
    assert not may_approve(
        is_admin=False,
        province=OPOLE,
        judge_province=SLASK,
        badges_raw={APPROVER_BADGE: True},
    )


def test_province_comes_from_the_database_not_the_phone():
    # `judge_province` to wiersz z `province_judges`. Sędzia bez wpisu w tym
    # okręgu nie zatwierdza w nim niczego, choćby miał odznakę gdzie indziej.
    assert not may_approve(
        is_admin=False,
        province=SLASK,
        judge_province="",
        badges_raw={APPROVER_BADGE: True},
    )


def test_judge_without_badge_is_refused():
    assert not may_approve(
        is_admin=False,
        province=SLASK,
        judge_province=SLASK,
        badges_raw={"Komisja": True},
    )


def test_disabled_badge_does_not_count():
    # Odznaka wyłączona zapisuje się jako `false`, a nie znika z obiektu.
    assert not has_approver_badge({APPROVER_BADGE: False})
    assert not may_approve(
        is_admin=False,
        province=SLASK,
        judge_province=SLASK,
        badges_raw={APPROVER_BADGE: False},
    )


def test_province_comparison_ignores_case_and_spaces():
    assert may_approve(
        is_admin=False,
        province="  śląskie ",
        judge_province="ŚLĄSKIE",
        badges_raw=[APPROVER_BADGE],
    )


def test_badges_read_from_both_shapes():
    assert badge_names({APPROVER_BADGE: True, "Komisja": False}) == [APPROVER_BADGE]
    assert badge_names([APPROVER_BADGE]) == [APPROVER_BADGE]
    assert badge_names(None) == []
    assert badge_names("Obsadowy") == []


def test_config_is_admin_only():
    # Obsadowy rozstrzyga pojedyncze wymiany, ale nie zmienia zasad okręgu.
    assert may_manage_config(is_admin=True)
    assert not may_manage_config(is_admin=False)


def test_notification_targets_are_badge_holders_of_that_province():
    rows = [
        {"judge_id": "100", "province": SLASK, "badges": {APPROVER_BADGE: True}},
        {"judge_id": "200", "province": SLASK, "badges": {"Komisja": True}},
        {"judge_id": "300", "province": OPOLE, "badges": {APPROVER_BADGE: True}},
    ]
    assert approver_judge_ids(rows, SLASK) == ["100"]


def test_admins_are_added_even_without_a_province_row():
    rows = [{"judge_id": "100", "province": SLASK, "badges": {APPROVER_BADGE: True}}]
    assert approver_judge_ids(rows, SLASK, admin_ids=["999", "100", ""]) == ["100", "999"]


def test_empty_input_is_survivable():
    assert approver_judge_ids([], SLASK) == []
    assert approver_judge_ids(None, SLASK) == []
