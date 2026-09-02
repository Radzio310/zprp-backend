"""Materiał szkoleniowy: dane dla szablonu prezentacji.

Sprawdzamy KONTEKST, nie złożony PDF. Decyzje - kolejność, scalanie akcji,
rozmiar pisma - zapadają tutaj; samo złożenie jest już mechaniczne i wymaga
WeasyPrinta, którego w środowisku testowym nie ma (tak samo jak przy raportach
BAZA Beach).
"""
from __future__ import annotations

from app.training_spk_pdf import ACCENT, SIZE_STEPS, _size_class, build_slides_context


def ev(t, kind="goal", team="host", player=16, half=1, **extra):
    out = {"time": t, "type": kind, "team": team, "player": player, "half": half}
    out.update(extra)
    return out


META = {
    "matchNumber": "SPK/1",
    "hostTeamName": "Zagłębie",
    "guestTeamName": "MKS",
    "finalHost": "30",
    "finalGuest": "24",
}


def test_kontekst_niesie_slajdy_i_naglowek():
    ctx = build_slides_context([ev(0)], META)
    assert len(ctx["slides"]) == 1
    assert ctx["head"]["matchNumber"] == "SPK/1"
    assert ctx["accent"] == ACCENT


def test_krotkie_polecenie_dostaje_najwieksze_pismo():
    assert _size_class("Bramka gospodarzy nr 7") == "s1"


def test_dlugie_polecenie_schodzi_o_stopien():
    limit = SIZE_STEPS[0][0]
    assert _size_class("x" * (limit + 1)) == "s2"
    assert _size_class("x" * (SIZE_STEPS[1][0] + 1)) == "s3"


def test_rozmiar_liczony_z_pierwszej_akcji():
    """Druga akcja ma własny, mniejszy wiersz - nie może zmniejszać pierwszej."""
    ctx = build_slides_context(
        [ev(0, player=7), ev(0, kind="penalty1", team="guest", player=11)], META
    )
    assert ctx["slides"][0]["sizeClass"] == "s1"
    assert len(ctx["slides"][0]["actions"]) == 2


def test_pusta_os_czasu_daje_pusty_kontekst():
    """Błąd rzuca dopiero składanie - kontekst ma po prostu nie mieć slajdów."""
    assert build_slides_context([], META)["slides"] == []
