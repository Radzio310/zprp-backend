"""Czy sędzia zobaczy SWÓJ mecz, czy podgląd cudzego.

Ten plik istnieje po zgłoszeniu z pola: sędzia wyszedł z prowadzonego przez
siebie meczu, wrócił do jego szczegółów i dostał „Podgląd na żywo - prowadzi
inna osoba" na własnym protokole.

Mechanizm był taki: aplikacja uznaje mecz za żywy także przez dwie minuty po
ostatnim pełnym autozapisie (autozapis idzie co 60 s), a oddanie leasingu
kasowało `lease_install` razem z resztą. Odpowiedź mówiła więc „ktoś tu jest,
nie wiadomo kto" - a nie wiadomo kto znaczy dla aplikacji „ktoś inny".
"""
from __future__ import annotations

from datetime import timedelta

from app.proel_lease import lease_view, now_utc

MOJ = "install-moj"
CUDZY = "install-cudzy"


def _state(**over):
    base = {
        "lease_install": MOJ,
        "lease_judge_id": "1234",
        "lease_name": "KOWALSKI Jan",
        "lease_kind": "app",
        "lease_epoch": 3,
        "lease_until": now_utc() + timedelta(seconds=90),
    }
    base.update(over)
    return base


def test_wlasny_zywy_leasing_jest_rozpoznany():
    view = lease_view(_state(), MOJ, "1234")
    assert view["held"] is True
    assert view["is_you"] is True


def test_oddany_leasing_nadal_wie_kto_go_trzymal():
    # SEDNO. `lease_until` wyzerowane przy wyjściu z meczu, tożsamość zostaje.
    view = lease_view(_state(lease_until=None), MOJ, "1234")
    assert view["held"] is False
    assert view["is_you"] is True, "to jest ten telefon - podgląd byłby błędem"
    assert view["same_judge"] is True
    assert view["until"] is None


def test_oddany_leasing_kogos_innego_zostaje_cudzy():
    view = lease_view(_state(lease_until=None), CUDZY, "9999")
    assert view["held"] is False
    assert view["is_you"] is False
    assert view["same_judge"] is False
    assert view["name"] == "KOWALSKI Jan"


def test_ten_sam_sedzia_z_drugiego_telefonu_po_oddaniu():
    # Przesiadka na tablet nie może wyglądać jak cudze prowadzenie.
    view = lease_view(_state(lease_until=None), CUDZY, "1234")
    assert view["is_you"] is False
    assert view["same_judge"] is True


def test_wygasly_leasing_odroznia_sie_od_oddanego():
    # Wygaśnięcie to nie oddanie: przy wygasłym `expired` jest prawdą, bo tam
    # prowadzący nadal siedzi przy stoliku i tylko przespał bicie serca.
    wygasly = lease_view(_state(lease_until=now_utc() - timedelta(seconds=1)), MOJ)
    oddany = lease_view(_state(lease_until=None), MOJ)
    assert wygasly["held"] is False and wygasly["expired"] is True
    assert oddany["held"] is False and oddany["expired"] is False


def test_wiersz_ktorego_nikt_nigdy_nie_prowadzil():
    view = lease_view(
        {"lease_install": None, "lease_until": None, "lease_kind": None}, MOJ, "1234"
    )
    assert view["held"] is False
    assert view["is_you"] is False
    assert view["same_judge"] is False


def test_brak_wiersza_stanu():
    assert lease_view(None, MOJ, "1234") == {"held": False}
