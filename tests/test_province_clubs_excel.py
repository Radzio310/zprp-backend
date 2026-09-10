"""
Szablon wplat i wyplat: eksport -> wypelnienie -> import.

Kolumna „Nr druzyny" jest tu najwazniejsza - to po niej import trafia do
wlasciwej druzyny nawet wtedy, gdy ktos poprawi nazwe w Excelu.
"""

import io

from openpyxl import load_workbook

from app.province_clubs_excel import build_workbook, parse_workbook

ROWS = [
    {"team_id": "5192", "team_name": "MKS Start Michałkowice", "club_name": "MKS Start Michałkowice", "category": "Senior"},
    {"team_id": "17583", "team_name": "SPR Sośnica II Gliwice", "club_name": "Sośnica Gliwice", "category": "Senior"},
]


def test_szablon_ma_naglowki_i_druzyny():
    data = build_workbook(ROWS, title="Wpłaty i wypłaty - ŚLĄSKIE 2026/2027")
    sheet = load_workbook(io.BytesIO(data)).active

    headers = [cell.value for cell in sheet[4]]
    assert headers[:4] == ["Nr drużyny", "Klub", "Drużyna", "Kategoria"]
    assert headers[4:] == ["Wpłata", "Opis wpłaty", "Wypłata", "Opis wypłaty"]
    assert sheet.cell(row=5, column=1).value == "5192"
    assert sheet.cell(row=6, column=3).value == "SPR Sośnica II Gliwice"


def test_import_czyta_wpisane_kwoty_i_pomija_puste():
    data = build_workbook(ROWS, title="Wpłaty")
    workbook = load_workbook(io.BytesIO(data))
    sheet = workbook.active
    sheet.cell(row=5, column=5, value=1500)                 # wpłata liczbą
    sheet.cell(row=5, column=6, value="składka za wrzesień")
    sheet.cell(row=6, column=7, value="240,50 zł")          # wypłata napisem
    sheet.cell(row=6, column=8, value="zwrot nadpłaty")
    buffer = io.BytesIO()
    workbook.save(buffer)

    items = parse_workbook(buffer.getvalue())
    assert len(items) == 2

    wplata = next(item for item in items if item["in_amount"])
    assert wplata["team_id"] == "5192"
    assert wplata["in_amount"] == 1500.0
    assert wplata["in_note"] == "składka za wrzesień"
    assert wplata["out_amount"] is None

    wyplata = next(item for item in items if item["out_amount"])
    assert wyplata["team_id"] == "17583"
    assert wyplata["out_amount"] == 240.5
    assert wyplata["out_note"] == "zwrot nadpłaty"


def test_pusty_szablon_nie_daje_wpisow():
    assert parse_workbook(build_workbook(ROWS, title="Wpłaty")) == []
