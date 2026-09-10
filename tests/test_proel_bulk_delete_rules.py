"""Grupowe usuwanie zapisów ProEl: co zniknie, co zostanie, kiedy PIN hamuje."""
from app.proel_bulk_delete_rules import (
    APPROVED_MESSAGE,
    MAX_BULK,
    PinThrottle,
    lock_message,
    normalize_keys,
    plan_bulk_delete,
)


def test_klucze_bez_pustych_i_powtorzen_w_kolejnosci():
    assert normalize_keys([" SM/8 ", "", None, "SM/8", "T-ABCD1234/SM/8", "sm/8"]) == [
        "SM/8",
        "T-ABCD1234/SM/8",
        "sm/8",
    ]
    assert normalize_keys(None) == []


def test_zatwierdzony_odmowa_brakujacy_to_nie_blad():
    plan = plan_bulk_delete(
        ["SM/8", "SM/9", "OJK89", "T-ABCD1234/SM/8"],
        {
            "SM/8": "in_progress",
            "SM/9": "approved",
            "T-ABCD1234/SM/8": "finished",
        },
    )
    assert plan["delete"] == ["SM/8", "T-ABCD1234/SM/8"]
    assert plan["missing"] == ["OJK89"]
    assert plan["refused"] == [
        {"key": "SM/9", "reason": "approved", "message": APPROVED_MESSAGE}
    ]


def test_brak_statusu_to_nie_zatwierdzenie():
    plan = plan_bulk_delete(["A/1"], {"A/1": None})
    assert plan["delete"] == ["A/1"]


def test_limit_jest_rozsadny():
    assert 50 <= MAX_BULK <= 500


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_pin_hamuje_po_pieciu_pomylkach_i_puszcza_po_czasie():
    clock = _Clock()
    throttle = PinThrottle(max_fails=5, lock_seconds=600, clock=clock)
    for _ in range(4):
        throttle.fail("7")
    assert not throttle.blocked("7")
    throttle.fail("7")
    assert throttle.blocked("7")
    assert throttle.seconds_left("7") == 600
    # inny admin nie płaci za cudze pomyłki
    assert not throttle.blocked("8")
    clock.now += 601
    assert not throttle.blocked("7")
    assert throttle.seconds_left("7") == 0


def test_poprawny_pin_zeruje_licznik():
    clock = _Clock()
    throttle = PinThrottle(max_fails=3, lock_seconds=600, clock=clock)
    throttle.fail("7")
    throttle.fail("7")
    throttle.reset("7")
    throttle.fail("7")
    assert not throttle.blocked("7")


def test_komunikat_blokady_mowi_ile_czekac_i_ze_nic_nie_znikło():
    assert "10 min" in lock_message(600)
    assert "1 min" in lock_message(5)
    assert "nic nie zostało usunięte" in lock_message(120)
