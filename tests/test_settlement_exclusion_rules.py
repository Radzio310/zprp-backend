# -*- coding: utf-8 -*-
"""
Podpowiedzi zdjęcia meczu z rozliczeń (06.10.2026).

Mecz nie znika sam z powodu numeru. Gdy z rozgrywek innego okręgu zdjęto już
mecz („Nie obciążaj klubów" / „Nie naliczaj"), kolejne mecze tych rozgrywek
dostają podpowiedź „zdjąć?" - u każdego sędziego.
"""
from __future__ import annotations

from app import settlement_exclusion_rules as X

OWN = {"S"}


def test_klucz_rozgrywek():
    assert X.competition_label("E/JmK/3") == "E/JmK"
    assert X.competition_key("E/JmK/3") == "E/JMK"
    assert X.competition_key("e/jmk/17") == "E/JMK"
    assert X.competition_label("MP/JM/12") == "MP/JM"
    assert X.competition_label("") == ""


def test_liczy_tylko_rozgrywki_innych_okregow():
    found = X.excluded_competitions(["E/JmK/3", "E/JmK/5", "S/MłK/1", "SM/8"], OWN)
    assert found == {"E/JMK": 2}


def test_podpowiedz_dla_kazdego_sedziego_tych_samych_rozgrywek():
    found = {"E/JMK": 2}
    assert "E/JmK" in X.hint("E/JmK/9", found, OWN)
    assert "2 mecze" in X.hint("E/JmK/9", found, OWN)
    # Inne rozgrywki tego samego okręgu - bez podpowiedzi.
    assert X.hint("E/DzM/1", found, OWN) is None
    # Nasza liga nigdy - zdjęcie jednego meczu nie flaguje setek.
    assert X.hint("S/MłK/1", {"S/MLK": 5}, OWN) is None
    # Bez wiedzy o naszych przedrostkach - nie zgadujemy.
    assert X.hint("E/JmK/9", found, set()) is None
