"""Stara droga wyniku skróconego: kiedy backend ma jeszcze przestawiać strony.

Aplikacja liczy dziś orientację pól u siebie (nominalnie, jak kolumny ZPRP)
i mówi o tym znacznikiem ``pola_nominalne``. Bez znacznika zostaje dawne
zachowanie dla wydania 2.0.1, które wysyła kolejność protokołu. Dwa
przestawienia dają lustro - to był realny błąd z meczu test/2.
"""
from __future__ import annotations

from app.results import _legacy_swap_needed, _swap_gosp_gosc


def test_nowe_wydanie_nie_dostaje_drugiego_przestawienia():
    assert _legacy_swap_needed(host_swapped=True, pola_nominalne=True) is False


def test_stare_wydanie_dalej_jest_przestawiane_przy_zamianie():
    assert _legacy_swap_needed(host_swapped=True, pola_nominalne=False) is True


def test_bez_zamiany_nikt_niczego_nie_przestawia():
    assert _legacy_swap_needed(host_swapped=False, pola_nominalne=False) is False
    assert _legacy_swap_needed(host_swapped=False, pola_nominalne=True) is False


def test_przestawienie_jest_samoodwrotne():
    fields = {
        "wynik_gosp_pol": "19",
        "wynik_gosc_pol": "18",
        "karne_ile_gosp": "5",
        "karne_ile_gosc": "4",
        "timeout1_gosp_ii": "24",
        "timeout1_gosc_ii": "15",
        "widzowie": "1258",
    }
    once = _swap_gosp_gosc(fields)
    assert once["wynik_gosp_pol"] == "18" and once["wynik_gosc_pol"] == "19"
    assert once["widzowie"] == "1258"
    assert _swap_gosp_gosc(once) == fields
