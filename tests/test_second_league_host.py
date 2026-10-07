# -*- coding: utf-8 -*-
"""
II liga tylko z gospodarzem rozliczanym przez okręg (07.10.2026).

Grupa II ligi powierzona Śląskowi (IIM4/IIK4) ma kluby z kilku województw -
Szulc i Więcław dostawali od Śląska mecze w Kielcach. Mecz II ligi idzie do
wypłat okręgu tylko z gospodarzem z panelu rozliczanym przez okręg (albo
z kosztem przeniesionym na okręg); reszta - jak klub rozliczający się sam.
"""
from __future__ import annotations

from datetime import date

from app import club_charges as C


def row(code: str, status: str, day: date = date(2026, 9, 20)) -> C.ChargeRow:
    return C.ChargeRow(
        match_key="d:1", match_at=None, day=day, code=code, category="II liga",
        city="Kielce", host_name="KSZO Kielce", status=status,
    )


def test_druga_liga_bez_naszego_gospodarza_idzie_poza_wyplaty():
    assert C.paid_by_club(row("IIK4/12", C.UNASSIGNED))     # gospodarz spoza panelu
    assert C.paid_by_club(row("IIM4/3", C.NO_HOST))         # stolik spoza terminarza
    assert C.paid_by_club(row("IIM4/3", C.CLUB_OFF))        # nasz klub, nie przez okręg


def test_druga_liga_z_naszym_gospodarzem_zostaje():
    assert not C.paid_by_club(row("IIK4/12", C.CHARGED))    # klub rozliczany przez okręg
                                                            # albo koszt przeniesiony na okręg


def test_inne_ligi_i_stare_mecze_bez_zmian():
    assert not C.paid_by_club(row("IIIM/9", C.UNASSIGNED))  # III liga - jak dotąd
    assert not C.paid_by_club(row("S/MłK/1", C.UNASSIGNED))
    assert not C.paid_by_club(row("IIK4/12", C.UNASSIGNED, date(2026, 8, 20)))  # przed sezonem
    assert C.is_second_league("IIM4/1") and not C.is_second_league("IIIK/2")


def test_klub_z_innego_wojewodztwa_nie_placi_przez_okreg_mimo_statusu():
    # 07.10.2026: rywal z Szaflar był w słowniku drużyn (grupa II ligi
    # prowadzona przez okręg) i bez ustawień liczył się jak rozliczany przez okręg.
    hosted = row("IIM4/7", C.CHARGED)
    hosted.club_id = "900"
    assert C.paid_by_club(hosted, {"900"})
    assert not C.paid_by_club(hosted, {"123"})
    stolik = row("IKB/5", C.CHARGED)
    stolik.club_id = "900"
    assert not C.paid_by_club(stolik, {"900"})          # I liga - bez zmian
