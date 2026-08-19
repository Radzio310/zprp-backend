"""Przesiadka sędziego na drugie urządzenie w trakcie meczu.

Blokada prowadzenia istnieje przeciwko dwóm OSOBOM piszącym jeden protokół.
Jedna osoba z dwóch swoich urządzeń to nie ten przypadek i nie ma czekać, aż
wygaśnie leasing sprzed przesiadki — dlatego ta reguła ma testy, tak jak reszta
arytmetyki leasingu.
"""

from app.proel_lease import same_judge_lease


def _app_lease(judge_id: str) -> dict:
    return {"lease_kind": "app", "lease_judge_id": judge_id}


def test_ten_sam_sedzia_z_innego_urzadzenia():
    assert same_judge_lease(_app_lease("1234"), "1234") is True


def test_spacje_nie_psuja_dopasowania():
    assert same_judge_lease(_app_lease(" 1234 "), "1234\n") is True


def test_inny_sedzia_nie_przechodzi():
    assert same_judge_lease(_app_lease("1234"), "9999") is False


def test_pusty_numer_trzymajacego_nie_pasuje_do_nikogo():
    """Puste równe pustemu uznałoby każdego za właściciela cudzego leasingu."""
    assert same_judge_lease(_app_lease(""), "") is False
    assert same_judge_lease(_app_lease(""), "1234") is False
    assert same_judge_lease(_app_lease("1234"), "") is False


def test_leasing_widmo_nigdy_nie_jest_niczyj():
    """Widmo obejmowane za starą aplikację nie wie, kto je trzyma."""
    state = {"lease_kind": "legacy", "lease_judge_id": "1234"}
    assert same_judge_lease(state, "1234") is False


def test_brak_stanu():
    assert same_judge_lease(None, "1234") is False
