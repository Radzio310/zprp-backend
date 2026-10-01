# -*- coding: utf-8 -*-
"""
Kolejka na stolik okregowy - piec grup (decyzje uzytkownika z 01.10.2026).

Do 30.09.2026 o stoliku decydowala jedna odznaka „Stolikowi" plus prog
`TABLE_BADGE_SLACK` („stolikowi maja miec najwyzej 1 mecz wiecej"). Prog
zniknal, a na jego miejsce weszla jawna kolejnosc:

    mentorzy pary tego meczu -> stolikowi -> delegaci -> pozostali -> mlodzi

przy czym „pozostali" to ligowcy i okregowi RAZEM: centralna licencja nie jest
powodem, zeby kogos odsuwac, ale nie wyprzedza tez stolikowego ani delegata.
Rowny podzial liczy sie WEWNATRZ grupy, a miedzy grupami wyrownuje `W_PERIOD`.
"""
from __future__ import annotations

from app.assignment_auto import (
    TIER_DELEGATE,
    TIER_MENTOR,
    TIER_REST,
    TIER_TABLE_BADGE,
    TIER_YOUNG,
    table_tier,
)
from app.assignment_people import make_judge, role_refusal


def judge(judge_id, **kwargs):
    return make_judge(judge_id, f"OSOBA {judge_id}", **kwargs)


STOLIKOWY = judge("1", badges=["Stolikowi"])
DELEGAT = judge("2", roles=["delegat"])
LIGOWIEC = judge("3", letters=["I"])
OKREGOWY = judge("4", letters=["III"])
MLODY = judge("5", badges=["Młodzi"])


class TestKolejkaGrup:
    def test_piec_grup_w_tej_kolejnosci(self):
        assert table_tier(STOLIKOWY, badge_first=True) == TIER_TABLE_BADGE
        assert table_tier(DELEGAT, badge_first=True) == TIER_DELEGATE
        assert table_tier(OKREGOWY, badge_first=True) == TIER_REST
        assert table_tier(MLODY, badge_first=True) == TIER_YOUNG
        assert TIER_MENTOR < TIER_TABLE_BADGE < TIER_DELEGATE < TIER_REST < TIER_YOUNG

    def test_mentor_pary_wyprzedza_wszystkich(self):
        """Mentor siada przy stoliku po to, zeby patrzec na swoja pare."""
        assert table_tier(STOLIKOWY, badge_first=True, mentor_ids=frozenset({"1"})) == TIER_MENTOR
        assert table_tier(MLODY, badge_first=True, mentor_ids=frozenset({"5"})) == TIER_MENTOR

    def test_ligowiec_stoi_rowno_z_okregowym(self):
        """
        Centralna licencja nie spycha na sam koniec: w grupie „pozostali"
        ligowiec i okregowy sa rowni, a mlody idzie za nimi.
        """
        assert table_tier(LIGOWIEC, badge_first=True) == table_tier(OKREGOWY, badge_first=True)
        assert table_tier(LIGOWIEC, badge_first=True) < table_tier(MLODY, badge_first=True)

    def test_ligowiec_nie_wyprzedza_stolikowego_ani_delegata(self):
        assert table_tier(LIGOWIEC, badge_first=True) > table_tier(STOLIKOWY, badge_first=True)
        assert table_tier(LIGOWIEC, badge_first=True) > table_tier(DELEGAT, badge_first=True)

    def test_poza_okregiem_wszyscy_rowno(self):
        """II liga, I liga, LC i SL: kolejki nie ma, licza sie same licencje."""
        for person in (STOLIKOWY, DELEGAT, LIGOWIEC, OKREGOWY, MLODY):
            assert table_tier(person, badge_first=False) == TIER_MENTOR

    def test_obciazenie_nie_zmienia_juz_grupy(self):
        """
        Stolikowy nie wypada z grupy za trzy mecze w okresie - to robil
        skasowany `TABLE_BADGE_SLACK`. Wyrownaniem zajmuja sie punkty okresu,
        bo inaczej sama liczba meczow przestawialaby regule okregu.
        """
        assert table_tier(STOLIKOWY, badge_first=True) == TIER_TABLE_BADGE


class TestDelegatNaBoisku:
    def test_delegat_nie_idzie_na_boisko(self):
        assert role_refusal(DELEGAT, "field") == "delegat - nie na boisko"
        assert role_refusal(judge("6", badges=["Delegaci"]), "field") == "delegat - nie na boisko"

    def test_delegat_moze_na_stolik(self):
        assert role_refusal(DELEGAT, "table") is None

    def test_reczne_ustawienie_okregu_wygrywa(self):
        """
        „Wolno recznie" z decyzji 01.10.2026: okreg moze wprost dopuscic
        delegata na boisko (`assign_role`), i to ma byc mocniejsze niz regula.
        """
        assert role_refusal(judge("7", roles=["delegat"], assign_role="field"), "field") is None
        assert role_refusal(judge("8", roles=["delegat"], assign_role="both"), "field") is None


class TestNieSedziujeSam:
    """
    Przelacznik sedziego: „nie prowadzi meczu SAM" (decyzja 01.10.2026).

    Dotyczy meczow, przy ktorych stoi JEDEN boiskowy - Dzieci i Mlodzik
    mlodszy (`assignment_rules.crew_needs`). W parze taki sedzia pracuje
    normalnie, wiec regula patrzy na mecz, a nie na sedziego.
    """

    def test_mecz_jednoosobowy_rozpoznany_po_rozgrywkach(self):
        from app.assignment_auto import solo_match

        assert solo_match("DZM/4") is True
        assert solo_match("MLK1213/2") is True
        assert solo_match("S/JmM") is False
        assert solo_match("IIM4") is False

    def test_sedzia_bez_przelacznika_sedziuje_wszedzie(self):
        from app.assignment_auto import solo_match

        zwykly = judge("9")
        assert zwykly.no_solo is False
        assert solo_match("DZM/4") is True

    def test_przelacznik_zapisuje_sie_na_sedzim(self):
        assert judge("10", no_solo=True).no_solo is True
