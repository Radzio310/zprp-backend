# -*- coding: utf-8 -*-
"""
Plik księgowej (04.11.2026): formuły podatku, kody enova, numeracja
kalendarzowa i sam skoroszyt - bez bazy.

Przykłady z prawdziwych list Wojtka (zestawienie 1/S/2026) i z arkusza
księgowej („dane do importu", formuły =IF(H<=200,0,H*0.2), =ROUND(J*0.12,0)).
"""
from __future__ import annotations

import io
import zipfile
from datetime import date

import openpyxl

from app import settlement_accounting_excel as X
from app import settlement_accounting_rules as A
from app import settlement_register_rules as G
from app.settlement_rates import net_parts


# ---------------------------------------------------------------------------
# Podatek
# ---------------------------------------------------------------------------

def test_formula_baza_to_dokladnie_rozliczenie_bazy():
    for gross in [1, 139, 150.5, 200, 200.01, 201, 224, 252.5, 318, 474, 1012, 2991, 4520.37]:
        mine = A.tax_parts(gross, A.FORMULA_BAZA)
        theirs = net_parts(gross)
        assert (mine["costs"], mine["taxable"], mine["tax"], mine["net"]) == (
            theirs["costs"], theirs["taxable"], theirs["tax"], theirs["net"],
        ), gross


def test_formula_arkusza_jak_lista_wojtka_1_S_2026():
    # Wiersze z PDF-u „ZESTAWIENIE 1/S/2026": brutto -> KUP, podstawa, podatek, do wypłaty.
    cases = {
        291: (58.20, 232.80, 28, 263.00),
        318: (63.60, 254.40, 31, 287.00),   # BOCZEK - tu BAZA daje 30 zł
        139: (0.00, 139.00, 17, 122.00),    # ERTEL - poniżej progu 200 zł
        1012: (202.40, 809.60, 97, 915.00),
        2991: (598.20, 2392.80, 287, 2704.00),
    }
    for gross, (costs, taxable, tax, net) in cases.items():
        got = A.tax_parts(gross, A.FORMULA_SHEET)
        assert (got["costs"], got["taxable"], got["tax"], got["net"]) == (costs, taxable, tax, net), gross


def test_formula_enova_ma_podatek_bazy_i_kup_z_groszami():
    for gross in range(1, 4001):
        enova = A.tax_parts(gross, A.FORMULA_ENOVA)
        baza = A.tax_parts(gross, A.FORMULA_BAZA)
        assert enova["tax"] == baza["tax"], gross
    assert A.tax_parts(318, A.FORMULA_ENOVA)["costs"] == 63.60
    assert A.tax_parts(318, A.FORMULA_ENOVA)["taxable"] == 254.0


def test_roznica_formul_to_najwyzej_zlotowka():
    differs = 0
    for gross in range(1, 6001):
        a = A.tax_parts(gross, A.FORMULA_BAZA)["tax"]
        b = A.tax_parts(gross, A.FORMULA_SHEET)["tax"]
        assert abs(a - b) <= 1
        differs += a != b
    # Ok. 3% kwot - dlatego plik zaznacza takie wiersze.
    assert 100 < differs < 300


def test_formuly_excela_dla_kazdej_formuly():
    assert A.excel_formulas(A.FORMULA_SHEET, 2) == {
        "I": "=IF(H2<=200,0,H2*0.2)", "J": "=H2-I2", "K": "=ROUND(J2*0.12,0)", "L": "=H2-K2",
    }
    assert A.excel_formulas(A.FORMULA_BAZA, 5)["I"] == "=IF(H5<=200,0,ROUND(H5*0.2,0))"
    assert A.excel_formulas(A.FORMULA_ENOVA, 5)["I"] == "=IF(H5<=200,0,ROUND(H5*0.2,2))"
    assert A.formula_of("ARKUSZ") == A.FORMULA_SHEET
    assert A.formula_of("cokolwiek") == A.FORMULA_BAZA


# ---------------------------------------------------------------------------
# Kody enova
# ---------------------------------------------------------------------------

def test_kod_to_nazwisko_a_przy_zbieznosci_nazwisko_i_imie_do_15_znakow():
    people = [
        ("1", "PYTLIK Aleksandra"),
        ("2", "PYTLIK Krzysztof"),
        ("3", "PYTLIK Marcin"),
        ("4", "URZYŃSKI Patryk"),
        ("5", "KOWALSKA-NOWAK Anna"),
    ]
    picks = A.suggest_codes(people, {})
    assert picks["1"].code == "PYTLIKALEKSANDR"   # obcięte do 15 znaków, jak u księgowej
    assert picks["2"].code == "PYTLIKKRZYSZTOF"
    assert picks["3"].code == "PYTLIKMARCIN"
    assert picks["4"].code == "URZYŃSKI"          # polskie litery zostają
    assert picks["5"].code == "KOWALSKANOWAK"
    assert all(p.source == "suggested" and not p.conflict_with for p in picks.values())


def test_slownik_wygrywa_a_powtorzony_kod_to_konflikt():
    people = [("1", "KRAWCZYK Rafał"), ("2", "NOWAK Jan"), ("3", "NOWAKOWSKI Piotr")]
    picks = A.suggest_codes(people, {"1": "krawczykrafał", "3": "NOWAK"})
    assert picks["1"].code == "KRAWCZYKRAFAŁ" and picks["1"].source == "saved"
    assert picks["2"].conflict_with == ["3"]
    assert picks["3"].conflict_with == ["2"]
    assert A.normalize_code("  pazur leszek ") == "PAZURLESZEK"


# ---------------------------------------------------------------------------
# Numeracja
# ---------------------------------------------------------------------------

def test_numer_kalendarzowy_jak_u_ksiegowej():
    assert G.number_text("SL", 2026, 9, G.ZESTAWIENIE, G.SCHEME_CALENDAR, "S") == "9/S/2026"
    assert G.number_text("SL", 2026, 3, G.PRZEJAZDY, G.SCHEME_CALENDAR, "P") == "3/P/2026"
    assert G.number_prefix("SL", 2026, G.ZESTAWIENIE, G.SCHEME_CALENDAR, "S") == ""
    assert G.number_suffix("SL", 2026, G.ZESTAWIENIE, G.SCHEME_CALENDAR, "S") == "/S/2026"
    # Sezonowy bez zmian.
    assert G.number_text("SL", 2026, 14) == "SL/2026_27/14"
    assert G.number_suffix("SL", 2026) == ""
    assert G.counter_label(2026, G.SCHEME_CALENDAR) == "rok 2026"
    assert G.counter_label(2026) == "sezon 2026/27"


def test_ustawienia_ksiegowosci_sa_bezpieczne():
    clean = A.clean_extra({"tax_formula": "x", "number_scheme": "calendar", "number_marks": {"zestawienie": " s/ "}})
    assert clean["tax_formula"] == A.FORMULA_BAZA
    assert clean["number_scheme"] == A.SCHEME_CALENDAR
    assert clean["number_marks"] == {"zestawienie": "S", "przejazdy": "P"}
    assert clean["consent_text"] == A.CONSENT_DEFAULT
    assert clean["show_consent"] is True
    assert clean["enova"]["element"] == "PIT-11.5.Działalność wyk. osobiście"


def test_okres_dla_ksiegowej_i_dla_enova():
    assert A.period_text(date(2026, 6, 1), date(2026, 6, 30)) == "01.06.2026…30.06.2026"
    assert A.period_text(date(2026, 6, 1), date(2026, 6, 30), enova=True) == "01.06.2026...30.06.2026"
    assert A.file_name("10/S/2026", draft=False, period_tag="10_2026") == "ksiegowa_10_S_2026.xlsx"
    assert A.file_name("", draft=True, period_tag="lista_B_10_2026") == "SZKIC_ksiegowa_lista_B_10_2026.xlsx"


# ---------------------------------------------------------------------------
# Skoroszyt
# ---------------------------------------------------------------------------

def _rows(formula=A.FORMULA_BAZA):
    people = [("1", "ANDERS Magdalena"), ("2", "BOCZEK Michał"), ("3", "PYTLIK Aleksandra"), ("4", "PYTLIK Marcin")]
    items = [
        {"judge_id": "1", "name": "ANDERS Magdalena", "gross": 291},
        {"judge_id": "2", "name": "BOCZEK Michał", "gross": 318},
        # Sędzia wypłacany w częściach: każda część to osobna umowa w enova.
        {"judge_id": "3", "name": "PYTLIK Aleksandra", "gross": 300, "part": "A", "part_of": 2},
        {"judge_id": "3", "name": "PYTLIK Aleksandra", "gross": 201, "part": "B", "part_of": 2},
    ]
    return A.sheet_rows(items, A.suggest_codes(people, {"1": "ANDERS"}), formula)


def _meta(draft=False, formula=A.FORMULA_BAZA):
    return X.Meta(
        number="10/S/2026",
        draft=draft,
        org_name="Śląski Związek Piłki Ręcznej",
        period_from=date(2026, 10, 1),
        period_to=date(2026, 10, 31),
        period_label="październik 2026",
        payout_date=date(2026, 11, 9),
        formula=formula,
    )


def test_skoroszyt_ma_zakladki_ksiegowej_i_zrodlo_na_poczatku():
    data = X.build_workbook(_rows(), _meta())
    wb = openpyxl.load_workbook(io.BytesIO(data))
    assert wb.sheetnames == [
        "Ryczałty sędziowskie", "Import", "dane do importu", "Zestaw. umów(stawka za godzinę)", "Uwagi",
    ]
    # Zakładka Import - jej formuły: dane przerzucają się z „dane do importu".
    imp = wb["Import"]
    assert [c.value for c in imp[1]][:12] == [
        "Class", "Definicja:Symbol", "Pracownik:Kod", "Data", "Wydzial:Kod", "Seria", "Opis", "Tytul",
        "Okres", "Wartosc", "Element:Nazwa", "RodzajRozliczenia",
    ]
    assert imp["C2"].value == "='dane do importu'!C2"
    assert imp["G2"].value == "='dane do importu'!F2"
    assert imp["J2"].value == "='dane do importu'!H2"
    assert imp["K2"].value == "=Uwagi!$A$18"
    assert wb["dane do importu"]["H2"].value == "='Ryczałty sędziowskie'!H7"
    assert imp.max_row == 5  # 4 wiersze, część A i B osobno


def test_skoroszyt_czyta_sie_bez_przeliczania():
    data = X.build_workbook(_rows(), _meta())
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True)
    imp = wb["Import"]
    assert [imp[f"{c}2"].value for c in "ABCEFGHIJKL"] == [
        "Umowa", "RS", "ANDERS", "FIRMA", "EX", "10/S/2026", "BRAK UBEZPIECZEŃ",
        "01.10.2026...31.10.2026", 291, "PIT-11.5.Działalność wyk. osobiście", "KwotaDoWypłaty",
    ]
    assert imp["C3"].value == "BOCZEK"
    assert imp["C4"].value == "PYTLIKALEKSANDR"
    data_sheet = wb["dane do importu"]
    assert [data_sheet[f"{c}3"].value for c in "BCDEFHIJKL"] == [
        "BOCZEK Michał", "BOCZEK", "Michał", "01.10.2026…31.10.2026", "10/S/2026", 318, 64, 254, 30, 288,
    ]
    summary = wb["Ryczałty sędziowskie"]
    total = X.FIRST + 4
    assert summary[f"H{total}"].value == 291 + 318 + 300 + 201
    assert summary[f"K{total}"].value == sum(r.tax for r in _rows())


def test_szkic_nie_wejdzie_do_enova():
    data = X.build_workbook(_rows(), _meta(draft=True))
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True)
    assert wb["Import"]["G2"].value is None           # pusty Opis
    assert "SZKIC" in wb["Ryczałty sędziowskie"]["A4"].value
    assert all(ws.sheet_properties.tabColor.rgb.endswith(X.DRAFT) for ws in wb.worksheets)


def test_wiersz_z_inna_kwota_wg_drugiej_formuly_jest_opisany():
    rows = _rows()
    boczek = next(r for r in rows if r.judge_id == "2")
    assert boczek.tax == 30 and boczek.other_tax == 31 and boczek.differs
    assert "wg arkusza: podatek 31 zł" in boczek.note("wg arkusza")
    anders = next(r for r in rows if r.judge_id == "1")
    assert anders.code_source == "saved"
    assert "lista A (z 2)" in rows[2].note("wg arkusza")
    sums = A.totals(rows)
    assert sums["people"] == 3 and sums["rows"] == 4 and sums["differs"] >= 1


def test_szablon_bez_danych_osobowych():
    wb = openpyxl.load_workbook(X.TEMPLATE)
    assert wb["Import"].max_row == 1
    names = [c.value for row in wb["dane do importu"].iter_rows(min_row=2) for c in row if c.value is not None]
    assert names == []
    with zipfile.ZipFile(X.TEMPLATE) as archive:
        core = archive.read("docProps/core.xml").decode("utf-8")
    assert "<dc:creator" in core and ">BAZA<" in core
