"""Bicie serca prowadzącego - wygaśnięcie to nie przejęcie.

Leasing żyje 90 s, bicie serca idzie co 25 s, ale interwał w telefonie zasypia
razem z ekranem. Prowadzenie gaśnie wtedy samo i NIKT go nie ma - a serwer
odpowiadał na to tym samym 412 co przy prawdziwym przejęciu. Sędzia dostawał
pełnoekranowe „Mecz prowadzi teraz ktoś inny" na mecz, którego nikt poza nim
nie tknął, i to w trakcie gry.

Ten plik pilnuje, żeby jedyną przyczyną utraty prowadzenia był drugi stolik.
"""
from __future__ import annotations

from app.proel_lease import (
    HEARTBEAT_LOST,
    HEARTBEAT_OK,
    HEARTBEAT_RECLAIM,
    heartbeat_decision,
)


def test_wlasny_zywy_leasing_tylko_sie_przedluza():
    assert (
        heartbeat_decision(held=True, mine=True, epoch=7, claimed_epoch=7)
        == HEARTBEAT_OK
    )


def test_bicie_serca_bez_epoki_tez_przechodzi():
    # Starsza aplikacja nie wysyła epoki - brak epoki nie może znaczyć „utrata".
    assert (
        heartbeat_decision(held=True, mine=True, epoch=7, claimed_epoch=None)
        == HEARTBEAT_OK
    )


def test_wygasly_leasing_wraca_do_prowadzacego():
    # Wygaszony ekran na dwie minuty: leasing zgasł, ale nikt go nie objął.
    assert (
        heartbeat_decision(held=False, mine=False, epoch=7, claimed_epoch=7)
        == HEARTBEAT_RECLAIM
    )


def test_wygasly_leasing_wraca_takze_ze_stara_epoka():
    # Po wygaśnięciu epoka i tak przestaje cokolwiek chronić - nie ma czego.
    assert (
        heartbeat_decision(held=False, mine=False, epoch=9, claimed_epoch=3)
        == HEARTBEAT_RECLAIM
    )


def test_zywy_leasing_kogos_innego_to_utrata():
    assert (
        heartbeat_decision(held=True, mine=False, epoch=7, claimed_epoch=7)
        == HEARTBEAT_LOST
    )


def test_druga_sesja_na_tym_samym_urzadzeniu_ucisza_pierwsza():
    # `mine` po numerze instalacji, ale epoka poszła w górę - ktoś objął
    # prowadzenie na nowo i stara sesja ma zamilknąć.
    assert (
        heartbeat_decision(held=True, mine=True, epoch=8, claimed_epoch=7)
        == HEARTBEAT_LOST
    )
