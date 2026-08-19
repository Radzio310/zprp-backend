"""Strona szczegółowych uwag sędziów - układ dopasowany do długości opisu.

Wcześniej ta strona miała układ sztywny: opis w scalonej komórce A3:N30 i
podpisy zawsze w wierszach 32-37. Krótka uwaga zostawiała pół pustej kartki
między tekstem a podpisami, a długa nie miała gdzie się zmieścić.

Testy pilnują trzech rzeczy, których nie widać po samym otwarciu pliku:
  • podpisy idą ZARAZ pod opisem, a nie na sztywnej pozycji,
  • przy długim opisie strona łamie się sama, a blok podpisów przechodzi na
    następną kartkę W CAŁOŚCI (nazwisko bez podpisu to nie jest podpis),
  • każda strona uwag dostaje własny nagłówek, więc numeracja „Strona X/Y"
    ma gdzie usiąść.
"""
from openpyxl import Workbook

from app.results import (
    _NOTES_PAGE_BUDGET_PT,
    _NOTES_SIGN_BLOCK_PT,
    _create_detailed_notes_sheet,
    _wrap_notes_text,
)

REF1 = "WITKOWICZ Radosław"
REF2 = "WITKOWICZ Krzysztof"


def _build(text: str):
    wb = Workbook()
    ws, header_rows = _create_detailed_notes_sheet(
        wb,
        date_ddmmyyyy="20.08.2026",
        place="Mysłowice",
        notes_text=text,
        referee1_name=REF1,
        referee2_name=REF2,
        referee1_sig_bytes=b"",
        referee2_sig_bytes=b"",
    )
    return ws, header_rows


def _rows_with(ws, value: str):
    return [
        c.row
        for row in ws.iter_rows()
        for c in row
        if isinstance(c.value, str) and c.value.strip() == value
    ]


def test_krotki_opis_podpisy_tuz_pod_tekstem():
    ws, header_rows = _build(
        "Zawodnik drużyny gospodarzy z numerem 34 otrzymał karę dyskwalifikacji."
    )

    assert len(header_rows) == 1  # wszystko na jednej kartce

    last_text_row = max(
        c.row
        for row in ws.iter_rows()
        for c in row
        if isinstance(c.value, str) and "dyskwalifikacji" in c.value
    )
    first_name_row = _rows_with(ws, REF1)[0]

    # Jeden wiersz odstępu - nie kilkanaście jak w sztywnym układzie.
    assert first_name_row - last_text_row == 2


def test_podpisy_sedziow_blisko_siebie():
    ws, _ = _build("Krótka uwaga.")

    r1 = _rows_with(ws, REF1)[0]
    r2 = _rows_with(ws, REF2)[0]

    # nazwisko + podpis + przerwa + nazwisko = 3 wiersze odstępu.
    assert r2 - r1 == 3


def test_dlugi_opis_lamie_strone_a_podpisy_ida_w_calosci():
    # Tyle tekstu, że sam opis przekracza jedną kartkę.
    text = " ".join(f"zdanie numer {i} o przebiegu zawodów" for i in range(220))
    ws, header_rows = _build(text)

    assert len(header_rows) >= 2
    assert ws.row_breaks.count >= 1

    r1 = _rows_with(ws, REF1)[0]
    r2 = _rows_with(ws, REF2)[0]
    last_page_start = header_rows[-1]

    # Cały blok podpisów na tej samej, ostatniej stronie.
    assert r1 > last_page_start
    assert r2 > last_page_start


def test_kazda_strona_ma_wlasny_naglowek():
    text = " ".join(f"wiersz {i} opisu zdarzenia" for i in range(220))
    ws, header_rows = _build(text)

    for row in header_rows:
        assert ws.cell(row=row, column=1).value == "Strona"
        assert ws.cell(row=row, column=7).value == "20.08.2026, Mysłowice"


def test_blok_podpisow_nie_wisi_na_krawedzi_strony():
    """Opis dobrany tak, by kończył się tuż przed dolną krawędzią kartki."""
    # Szukamy długości, przy której podpisy MUSZĄ zejść na kolejną stronę.
    text = " ".join(f"linia {i} treści" for i in range(150))
    ws, header_rows = _build(text)

    r1 = _rows_with(ws, REF1)[0]
    if len(header_rows) > 1:
        assert r1 > header_rows[-1]
    # Blok podpisów nigdy nie jest wyższy niż budżet strony - inaczej nie
    # zmieściłby się nigdzie i pętla szukania miejsca nie miałaby końca.
    assert _NOTES_SIGN_BLOCK_PT < _NOTES_PAGE_BUDGET_PT


def test_zawijanie_zachowuje_akapity():
    lines = _wrap_notes_text("pierwszy akapit\n\ndrugi akapit", 74)
    assert lines[0] == "pierwszy akapit"
    assert lines[1] == ""
    assert lines[2] == "drugi akapit"


def test_zawijanie_tnie_slowo_dluzsze_niz_wiersz():
    long_word = "x" * 200
    lines = _wrap_notes_text(long_word, 74)
    assert all(len(l) <= 74 for l in lines)
    assert "".join(lines) == long_word


def test_zawijanie_nie_gubi_slow():
    text = " ".join(f"slowo{i}" for i in range(400))
    lines = _wrap_notes_text(text, 74)
    assert " ".join(lines).split() == text.split()


def test_podpis_miesci_sie_w_szerokosci_kartki():
    """Guard przed pustą stroną: obrazek nie ma prawa wystawać poza kolumnę N.

    Renderer nie przycina tego, co wystaje w prawo - wypycha to na dodatkową
    stronę. Objawem był jeden zawijas samotnie stojący na czwartej kartce.
    """
    from openpyxl.utils import column_index_from_string

    from app.results import (
        _NOTES_SIGN_ANCHOR_COL,
        _NOTES_SIGN_MAX_W_PX,
    )

    ws, _ = _build("Krótka uwaga.")

    def _px(width: float) -> float:
        return width * 7 + 5

    first = column_index_from_string(_NOTES_SIGN_ANCHOR_COL)
    last = column_index_from_string("N")
    available = sum(
        _px(ws.column_dimensions[chr(ord("A") + c - 1)].width)
        for c in range(first, last + 1)
    )

    assert _NOTES_SIGN_MAX_W_PX < available


def test_arkusz_miesci_sie_w_szerokosci_A4():
    """Sedno „pustej czwartej strony".

    Wszystko, co nie mieści się w szerokości obszaru druku, renderer przenosi
    na kolejną kartkę - w praktyce wychodzi z tego pusta strona z pionowym
    paskiem papieru. Arkusz musi mieć zapas, nie mieścić się „na styk".
    """
    ws, _ = _build("Krótka uwaga.")

    szerokosc_px = sum(
        ws.column_dimensions[chr(ord("A") + i)].width * 7 + 5 for i in range(14)
    )
    obszar_druku_cali = 8.268 - ws.page_margins.left - ws.page_margins.right

    assert szerokosc_px / 96.0 < obszar_druku_cali * 0.95
