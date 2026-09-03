"""Wynik w przebiegu zawodów ma się kleić do dwukropka.

Gospodarz jest wyrównany do prawej, gość do lewej - dzięki temu każdy wpis
wygląda tak samo, niezależnie od tego, czy wynik jest jedno- czy dwucyfrowy.

W szablonie dwa wiersze przebiegu (28 i 52, na styku sekcji formularza) miały
wyrównanie do ŚRODKA. Przy jednocyfrowym wyniku nikt tego nie widział, ale
przy dwucyfrowym liczby odsuwały się od dwukropka i wpis rozjeżdżał się w bok:
„11 : 10" wyglądało szerzej niż wszystko dookoła. Dlatego wyrównanie ustawiamy
sami, w każdym wierszu, zamiast ufać szablonowi.
"""
import os

from openpyxl import load_workbook

from app.results import (
    TIMELINE_END_ROW,
    TIMELINE_ROWS,
    TIMELINE_START_ROW,
    ShiftedWS,
    _fill_timeline_half_chunk,
)

TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app",
    "templates",
    "protocol_template.xlsx",
)

#: Wiersze, w których szablon miał wyrównanie do środka.
CROOKED_ROWS = [28, 52]


def _sheet():
    wb = load_workbook(TEMPLATE)
    raw = wb.active
    return raw, ShiftedWS(raw)


def _fill(ws, evs):
    _fill_timeline_half_chunk(
        ws,
        evs=evs,
        start_row=TIMELINE_START_ROW,
        end_row=TIMELINE_END_ROW,
        half_ms=30 * 60 * 1000,
        start_score_host=9,
        start_score_guest=9,
        col_minute="AL",
        col_host_action="AN",
        col_host_score="AP",
        col_guest_score="AS",
        col_guest_action="AU",
    )


def test_szablon_ma_dwa_wiersze_z_wyrownaniem_do_srodka():
    """Bez tego testu poprawka niżej wygląda na obronę przed niczym."""
    raw, _ = _sheet()
    centered = [
        r for r in TIMELINE_ROWS if raw[f"AQ{r}"].alignment.horizontal == "center"
    ]
    assert centered == CROOKED_ROWS


def test_wynik_klei_sie_do_dwukropka_w_kazdym_wierszu():
    raw, ws = _sheet()
    _fill(ws, [{"time": 60_000, "team": "host", "player": 7, "type": "goal"}])

    for r in TIMELINE_ROWS:
        # AQ/AT to fizyczne komórki wyniku (logiczne AP/AS + przesunięcie).
        assert raw[f"AQ{r}"].alignment.horizontal == "right", r
        assert raw[f"AT{r}"].alignment.horizontal == "left", r


def test_puste_wiersze_tez_sa_prostowane():
    """„-- : --" stoi w tych samych kolumnach - musi trzymać ten sam pion."""
    raw, ws = _sheet()
    _fill(ws, [])

    for r in CROOKED_ROWS:
        assert raw[f"AQ{r}"].value == "--"
        assert raw[f"AQ{r}"].alignment.horizontal == "right"
        assert raw[f"AT{r}"].alignment.horizontal == "left"


def test_dwucyfrowy_wynik_nie_zmienia_stylu():
    raw, ws = _sheet()
    evs = [
        {"time": 1_000 * i, "team": "host", "player": 7, "type": "goal"}
        for i in range(1, 6)
    ]
    _fill(ws, evs)

    # 9 + 5 goli = 14, czyli dwie cyfry - dokładnie ten przypadek, który
    # rozjeżdżał wpis.
    wyniki = [raw[f"AQ{r}"].value for r in TIMELINE_ROWS[:5]]
    assert wyniki[-1] == "14"
    assert raw[f"AQ{TIMELINE_ROWS[4]}"].alignment.horizontal == "right"


def test_reszta_stylu_zostaje_nietknieta():
    """Prostujemy poziom, a nie cały styl - rozmiar czcionki ma zostać."""
    raw, ws = _sheet()
    przed = raw[f"AQ{CROOKED_ROWS[0]}"].font.size
    _fill(ws, [])
    assert raw[f"AQ{CROOKED_ROWS[0]}"].font.size == przed
