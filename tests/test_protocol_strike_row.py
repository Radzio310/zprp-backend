"""Skreślenie wiersza zawodnika bez ważnych badań na protokole.

Zawodnik bez badań zostaje na wydruku - był zgłoszony, więc numer i nazwisko
muszą być widoczne - ale jego wiersz jest przekreślony na całej szerokości
tabeli. Testy pilnują trzech rzeczy, z których każda po cichu psuje protokół:

  • zasięgu kreski (fizycznie od B do AL, czyli wszystko poza kolumną ptaszków),
  • tego, że kreska trafia w ŚRODEK wiersza, a nie na jego krawędź,
  • i najważniejszego wyjątku: pusta mapa badań znaczy „zapis nic nie wie
    o badaniach", a nie „nikt ich nie ma". Skreślenie całego składu na
    protokole sprzed wprowadzenia tej kolumny byłoby nieprawdą.
"""
import os

from openpyxl import load_workbook

from app.results import (
    _STRIKE_COL_FROM,
    _STRIKE_COL_TO,
    ShiftedWS,
    _fill_players_block,
)

TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app",
    "templates",
    "protocol_template.xlsx",
)


def _sheet():
    wb = load_workbook(TEMPLATE)
    raw = wb.active
    return raw, ShiftedWS(raw)


def _fill(raw, ws, exam_by_number):
    _fill_players_block(
        ws,
        players=[7, 61],
        stats_by_number={},
        fullnames_by_number={7: "KOZAK Mikołaj", 61: "RAJCA Oliwier"},
        start_row=11,
        end_row=28,
        exam_by_number=exam_by_number,
        mark_ws=raw,
    )


def test_brak_badan_skresla_wiersz():
    raw, ws = _sheet()
    base = len(raw._images)

    # 7 ma badania, 61 nie - przy niepustej mapie to znaczy „sprawdzone i brak".
    _fill(raw, ws, {7: "zprp"})

    added = raw._images[base:]
    assert len(added) == 2  # ptaszek dla 7 + kreska dla 61


def test_kreska_idzie_od_B_do_AL():
    raw, ws = _sheet()
    base = len(raw._images)
    _fill(raw, ws, {7: "zprp"})

    # Ptaszek ma kotwicę jednokomórkową, kreska dwukomórkową - po tym je
    # rozróżniamy, bez polegania na kolejności wstawiania.
    strikes = [im for im in raw._images[base:] if getattr(im.anchor, "to", None)]
    assert len(strikes) == 1
    anchor = strikes[0].anchor

    # Fizyczna kolumna B (0-based 1) do początku AM, czyli prawej krawędzi AL.
    assert anchor._from.col == _STRIKE_COL_FROM == 1
    assert anchor.to.col == _STRIKE_COL_TO == 38


def test_kreska_jest_w_srodku_wiersza():
    raw, ws = _sheet()
    base = len(raw._images)
    _fill(raw, ws, {7: "zprp"})

    strikes = [im for im in raw._images[base:] if getattr(im.anchor, "to", None)]
    anchor = strikes[0].anchor

    # Wiersz 12 (drugi zawodnik) - kotwica jest 0-based.
    assert anchor._from.row == 11
    assert anchor.to.row == 11
    # Cienki pasek w połowie wysokości, a nie na całą komórkę.
    assert anchor.to.rowOff > anchor._from.rowOff
    grubosc = anchor.to.rowOff - anchor._from.rowOff
    assert 0 < grubosc < 30_000  # < ~2,4 pt


def test_pusta_mapa_badan_nie_skresla_nikogo():
    """Sedno wyjątku: protokół sprzed kolumny ptaszków ma wyglądać jak dotąd."""
    raw, ws = _sheet()
    base = len(raw._images)

    _fill(raw, ws, {})

    assert len(raw._images) == base


def test_brak_mapy_badan_nie_skresla_nikogo():
    raw, ws = _sheet()
    base = len(raw._images)

    _fill(raw, ws, None)

    assert len(raw._images) == base


def test_wszyscy_z_badaniami_bez_kresek():
    raw, ws = _sheet()
    base = len(raw._images)

    _fill(raw, ws, {7: "zprp", 61: "manual"})

    added = raw._images[base:]
    assert len(added) == 2
    assert all(getattr(im.anchor, "to", None) is None for im in added)


def test_numer_i_nazwisko_zostaja_mimo_skreslenia():
    """Skreślamy wiersz, nie kasujemy zawodnika - to dwie różne rzeczy."""
    raw, ws = _sheet()
    _fill(raw, ws, {7: "zprp"})

    assert raw["B12"].value == 61
    assert raw["D12"].value == "RAJCA Oliwier"
