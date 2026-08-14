"""Testy rozpoznawania roli w meczu — czysta logika, bez bazy.

Rola daje teraz PRAWO ZAPISU (kto może potwierdzić badania, kto podpisać,
kto przejąć prowadzenie), więc pomyłka tutaj to albo zablokowany sędzia
w hali, albo obcy człowiek piszący po cudzym protokole.
"""
from __future__ import annotations

import pytest

from app.proel_auth import (
    Actor,
    can_confirm_exams,
    merge_guard,
    names_match,
    roles_for,
)
from app.proel_fields import ALL_ROLES


def actor(judge_id="5124", name="WITKOWICZ Radosław", install="ins_a"):
    return Actor(judge_id=judge_id, installation_id=install, name=name)


# ─────────────────────────── names_match ───────────────────────────


def test_names_match_ignores_order_and_case():
    assert names_match("WITKOWICZ Radosław", "Radosław Witkowicz")
    assert names_match("kowalski jan", "KOWALSKI Jan")


def test_names_match_is_symmetric_for_partial_names():
    """Oryginalny `namesMatch` z aplikacji jest jednostronny.

    Wymaga, żeby WSZYSTKIE tokeny pierwszego argumentu były w drugim, więc
    „NOWAK-KOWALSKI Jan" vs „NOWAK Jan" gubiło rolę zależnie od kolejności
    argumentów. Skoro rola daje prawo zapisu, sprawdzamy obie strony.
    """
    assert names_match("NOWAK Jan", "NOWAK Jan Krzysztof")
    assert names_match("NOWAK Jan Krzysztof", "NOWAK Jan")


def test_names_match_rejects_empty_and_unrelated():
    assert not names_match("", "KOWALSKI Jan")
    assert not names_match("KOWALSKI Jan", "")
    assert not names_match(None, None)
    assert not names_match("KOWALSKI Jan", "NOWAK Piotr")


# ─────────────────────────── roles_for ───────────────────────────


def test_role_by_judge_number_wins():
    officials = {
        "referee1": {"name": "KTOŚ ZUPEŁNIE INNY", "judgeId": "5124"},
        "secretary": {"name": "WITKOWICZ Radosław", "judgeId": "9999"},
    }
    roles = roles_for(actor(), officials)
    # numer rozstrzyga: jesteśmy referee1, mimo że nazwisko pasuje do sekretarza
    assert roles == {"referee1"}


def test_number_mismatch_is_not_rescued_by_name():
    """Dwóch Kowalskich na jednym meczu to realny przypadek."""
    officials = {"secretary": {"name": "WITKOWICZ Radosław", "judgeId": "9999"}}
    assert roles_for(actor(judge_id="5124"), officials) == set()


def test_falls_back_to_name_when_number_missing():
    officials = {"delegate": {"name": "WITKOWICZ Radosław"}}
    assert roles_for(actor(), officials) == {"delegate"}


def test_accepts_legacy_flat_string_officials():
    officials = {"referee2": "WITKOWICZ Radosław"}
    assert roles_for(actor(), officials) == {"referee2"}


def test_user_can_hold_two_roles():
    officials = {
        "referee1": {"name": "WITKOWICZ Radosław"},
        "delegate": {"name": "WITKOWICZ Radosław"},
    }
    assert roles_for(actor(), officials) == {"referee1", "delegate"}


def test_brak_guarda_to_brak_rol():
    """`None` znaczy „nie ma nawet gdzie szukać" — inaczej niż pusta obsada."""
    assert roles_for(actor(), None) == set()


def test_nieznana_obsada_daje_wszystkie_role():
    """Mecz stolikowy założony ręcznie nie ma i nie będzie miał obsady z ZPRP.

    Odmawianie wszystkim przy pustej liście zamykało jedynego człowieka
    prowadzącego taki mecz: nie mógłby zapisać ani badań, ani danych
    pomeczowych. Brak wiedzy o obsadzie to nie to samo, co wiedza, że ktoś do
    niej nie należy.
    """
    assert roles_for(actor(), {}) == ALL_ROLES
    # Same puste pola to nadal „nic nie wiemy".
    assert roles_for(actor(), {"referee1": {"name": ""}, "delegate": ""}) == ALL_ROLES


def test_znana_obsada_bez_nas_to_zero_rol():
    """Gdy wiemy, kto sędziuje, i nie ma tam nas — nie piszemy."""
    officials = {"referee1": {"name": "NOWAK Piotr"}}
    assert roles_for(actor(name="WITKOWICZ Radosław"), officials) == set()


def test_unknown_role_keys_are_ignored():
    officials = {
        "referee1": {"name": "NOWAK Piotr"},  # obsada JEST znana
        "kapitan": {"name": "WITKOWICZ Radosław"},
    }
    assert roles_for(actor(), officials) == set()


# ─────────────────────────── merge_guard ───────────────────────────


def test_merge_guard_nie_gubi_numeru_sedziego():
    """Ekran finalizacji zna obsadę tylko z nazwisk.

    Płytkie `dict.update` zastąpiłoby nim całe `officials` i numery sędziów by
    przepadły — a numer jest rozstrzygający przy rozpoznawaniu roli.
    """
    existing = {
        "hostTeamName": "Gospodarz",
        "officials": {
            "referee1": {"name": "NOWAK Piotr", "judgeId": "5124"},
            "delegate": {"name": "KOWALSKI Jan", "judgeId": "777"},
        },
    }
    incoming = {
        "officials": {
            "referee1": {"name": "NOWAK Piotr"},
            "delegate": {"name": ""},
        }
    }
    out = merge_guard(existing, incoming)
    assert out["officials"]["referee1"]["judgeId"] == "5124"
    assert out["officials"]["delegate"]["judgeId"] == "777"
    # Pusta nazwa nie kasuje wypełnionej.
    assert out["officials"]["delegate"]["name"] == "KOWALSKI Jan"
    assert out["hostTeamName"] == "Gospodarz"


def test_merge_guard_dopisuje_nowa_role():
    existing = {"officials": {"referee1": {"name": "NOWAK Piotr", "judgeId": "5124"}}}
    incoming = {"officials": {"secretary": {"name": "WITKOWICZ Radosław"}}}
    out = merge_guard(existing, incoming)
    assert out["officials"]["referee1"]["judgeId"] == "5124"
    assert out["officials"]["secretary"]["name"] == "WITKOWICZ Radosław"


def test_merge_guard_przyjmuje_poprawke_nazwiska():
    existing = {"officials": {"referee2": {"name": "NOWAK Piotr"}}}
    incoming = {"officials": {"referee2": {"name": "NOWAK Piotr Jan"}}}
    out = merge_guard(existing, incoming)
    assert out["officials"]["referee2"]["name"] == "NOWAK Piotr Jan"


def test_merge_guard_znosi_stary_plaski_ksztalt():
    existing = {"officials": {"delegate": "KOWALSKI Jan"}}
    incoming = {"officials": {"delegate": {"name": "KOWALSKI Jan", "judgeId": "777"}}}
    out = merge_guard(existing, incoming)
    assert out["officials"]["delegate"]["judgeId"] == "777"


def test_merge_guard_bez_niczego_nie_wywraca_sie():
    assert merge_guard(None, None) == {}
    assert merge_guard(None, {"hostTeamName": "X"}) == {"hostTeamName": "X"}


def test_actor_without_name_or_number_gets_nothing():
    officials = {"referee1": {"name": "KOWALSKI Jan"}}
    assert roles_for(actor(judge_id="", name=""), officials) == set()


# ─────────────────────── kto widzi „Sprawdź badania" ───────────────────────


@pytest.mark.parametrize(
    "roles,expected",
    [
        ({"referee1"}, True),
        ({"referee2"}, True),
        ({"delegate"}, True),
        ({"secretary"}, False),
        ({"timekeeper"}, False),
        ({"secretary", "delegate"}, True),
        (set(), False),
    ],
)
def test_can_confirm_exams(roles, expected):
    assert can_confirm_exams(roles) is expected
