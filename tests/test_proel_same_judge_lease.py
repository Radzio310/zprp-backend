"""Przesiadka sędziego na drugie urządzenie w trakcie meczu.

Blokada prowadzenia istnieje przeciwko dwóm OSOBOM piszącym jeden protokół.
Jedna osoba z dwóch swoich urządzeń to nie ten przypadek i nie ma czekać, aż
wygaśnie leasing sprzed przesiadki — dlatego ta reguła ma testy, tak jak reszta
arytmetyki leasingu.
"""

from app.proel_lease import may_open_state_on_lease, same_judge_lease


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


def test_obejmowanie_prowadzenia_zaklada_brakujacy_stan():
    """`acquire` znaczy „zaczynam prowadzić" - brak wiersza nie może go odbić.

    To jest ta luka, przez którą mecz prowadzony w MatchScreen nie zostawiał na
    serwerze żadnego śladu: `/lease` odbijał 404, bo wiersz stanu zakłada
    wyłącznie `/ensure`, a wołał je jedynie ekran konfiguracji i to dopiero przy
    pierwszej zmianie pola współdzielonego. Reszta obsady widziała wtedy
    spokojne „Rozegraj w ProElu" dla meczu, który trwał.
    """
    assert may_open_state_on_lease("acquire") is True


def test_bicie_serca_nie_zaklada_niczego():
    """Przedłużanie leasingu, którego nikt nie objął, nie ma sensu.

    Klient odpowiada na 404 objęciem prowadzenia od nowa, więc odmowa tutaj
    niczego nie gubi - a chroni przed zakładaniem wierszy przez klienta, który
    bije serce w pętli po skasowanym meczu.
    """
    assert may_open_state_on_lease("heartbeat") is False
