"""Kreator nowych sędziów na baza.zprp.pl (`app/referee_onboarding_rules.py`, `app/referee_onboarding_excel.py`)."""
from __future__ import annotations

import datetime as dt
import io

import pytest

from app import referee_onboarding_rules as R
from app.referee_onboarding_excel import SheetError, read_table

# Skrót strony `?a=sedzia&b=dodaj` (układ jak na produkcji 09.11.2026, nazwiska zmyślone).
ADD_PAGE = """
<html><body>
<form method='POST' name='nowy' action='?a=sedzia&amp;b=dodaj' autocomplete="off">
<input type='text' name='Imie' value="" required>
<input type='text' name='Nazwisko' value="" required>
<input type='date' name="DataUr" value="" required />
<select name="woj" id="woj" required disabled="disabled">
  <option value="">Wybierz województwo</option>
  <option value="1">DOLNOŚLĄSKIE</option>
  <option value="12" selected="selected">ŚLĄSKIE</option>
</select>
<input type="hidden" name="woj" value="12" />
<select name="NrSedzia_para">
  <option value="">Wybierz parę sędziowską</option>
  <option value="1107">--- --- (ZIELNA Ewa)</option>
  <option value="5124">NOWACKI Radosław (NOWACKI Krzysztof)</option>
  <option value="3688">KOWALCZYK Bartłomiej          L (SZPINDA Michał)</option>
  <option value="5694">KONIECZNY SARA</option>
  <option value="5596">PIEŃKOWSKI  Tomasz  (PIEŃKOWSKI Paweł)</option>
  <option value="5857">JASTRZĘBSKI-MIKIPROWICZ Maksymilian</option>
</select>
<button name="akcja" value="ZAPISZ_NOWY" class="przycisk3" type="submit">ZAPISZ</button>
</form></body></html>
"""

LIST_PAGE = '<a href="?a=sedzia&amp;b=dodaj" class="przycisk">NOWY</a><table id="tabelka"></table>'


def person(**kw):
    base = {
        "first_name": "martyna ",
        "last_name": "Wiąckiewicz ",
        "gender": "k",
        "birth_date": "23.02.2010",
        "phone": "+48 516 442 882",
        "postal_code": "41706",
        "city": "ruda śląska",
        "email": "Martyna@Example.com",
        "roles": [],
    }
    base.update(kw)
    return R.normalize_person(base)


# ---------------------------------------------------------------------------
# Strona ZPRP
# ---------------------------------------------------------------------------


def test_strona_dodaj_formularz_wojewodztwo_i_lista_osob():
    page = R.parse_add_page(ADD_PAGE)
    assert page["has_form"] is True
    assert page["woj_code"] == "12"
    assert page["woj_name"] == "ŚLĄSKIE"
    by_nr = {o["nr"]: o for o in page["options"]}
    assert "1107" not in by_nr  # „--- ---" to puste pole ZPRP
    assert by_nr["5124"]["last_name"] == "NOWACKI" and by_nr["5124"]["first_name"] == "Radosław"
    assert by_nr["5124"]["partner"] == "NOWACKI Krzysztof"
    assert by_nr["5694"]["last_name"] == "KONIECZNY" and by_nr["5694"]["first_name"] == "SARA"
    assert by_nr["3688"]["first_name"].startswith("Bartłomiej")
    assert by_nr["5857"]["last_name"] == "JASTRZĘBSKI-MIKIPROWICZ"


def test_konto_bez_opcji_nowy():
    page = R.parse_add_page("<html><body>Brak uprawnień</body></html>")
    assert page["has_form"] is False
    assert R.has_new_button(LIST_PAGE) is True
    assert R.has_new_button('<a href="?a=sedzia&amp;b=edycja&amp;NrSedzia=1">x</a>') is False


# ---------------------------------------------------------------------------
# Osoba i formularz
# ---------------------------------------------------------------------------


def test_normalizacja_osoby():
    p = person()
    assert p["first_name"] == "Martyna"
    assert p["last_name"] == "WIĄCKIEWICZ"
    assert p["gender"] == "K"
    assert p["birth_date"] == "2010-02-23"
    assert p["phone"] == "516442882"
    assert p["postal_code"] == "41-706"
    assert p["city"] == "Ruda Śląska"
    assert p["email"] == "martyna@example.com"
    assert p["roles"] == ["sedzia"]  # domyślnie Sędzia
    assert R.cap_name("anna-maria") == "Anna-Maria"


def test_walidacja_pol_wymaganych():
    assert R.validate_person(person()) == []
    errs = R.validate_person(person(first_name="", gender="", birth_date="2099-01-01"))
    assert any("imienia" in e for e in errs)
    assert any("płci" in e for e in errs)
    assert any("zakresu" in e for e in errs)
    assert R.validate_person(person(email="a@b"))  # błędny email


def test_formularz_post_bez_pary_z_rolami():
    form = R.build_form(person(roles=["Sędzia", "Delegat"]), "12")
    assert form["Imie"] == "Martyna"
    assert form["Nazwisko"] == "WIĄCKIEWICZ"
    assert form["Plec"] == "K"
    assert form["DataUr"] == "2010-02-23"
    assert form["woj"] == "12"
    assert form["CzySedzia"] == "1" and form["CzyDelegat"] == "1"
    assert "CzyStolikowy" not in form
    assert form["NrSedzia_para"] == ""
    assert form["akcja"] == "ZAPISZ_NOWY"


def test_znaki_spoza_iso_8859_2():
    assert R.encodable(person(first_name="Ярослава")) == ["first_name"]
    assert R.encodable(person()) == []


# ---------------------------------------------------------------------------
# Duplikaty
# ---------------------------------------------------------------------------


def test_duplikaty_po_nazwisku_i_dacie():
    page = R.parse_add_page(ADD_PAGE)
    p = R.normalize_person({"first_name": "Radosław", "last_name": "Nowacki", "birth_date": "2001-05-05"})
    matches = R.match_candidates(p, page["options"])
    assert [m["nr"] for m in matches] == ["5124"]
    assert R.classify_duplicate(p, matches) == R.DUP_PROBABLE  # data nieznana -> blokuje
    matches[0]["birth_date"] = "2001-05-05"
    assert R.classify_duplicate(p, matches) == R.DUP_EXACT
    matches[0]["birth_date"] = "1980-01-01"
    assert R.classify_duplicate(p, matches) == R.DUP_NAMESAKE  # imiennik -> tylko ostrzeżenie
    assert R.DUP_NAMESAKE not in R.BLOCKING


def test_podobne_nazwisko_i_zamiana_kolejnosci():
    page = R.parse_add_page(ADD_PAGE)
    typo = R.normalize_person({"first_name": "Radosław", "last_name": "Nowacky"})
    assert R.classify_duplicate(typo, R.match_candidates(typo, page["options"])) == R.DUP_SIMILAR
    swapped = R.normalize_person({"first_name": "Nowacki", "last_name": "Radosław"})
    assert R.match_candidates(swapped, page["options"])[0]["relation"] == "similar"
    double = R.normalize_person({"first_name": "Maksymilian", "last_name": "Jastrzębski"})
    assert R.match_candidates(double, page["options"])[0]["nr"] == "5857"
    other = R.normalize_person({"first_name": "Jan", "last_name": "Zupełnie"})
    assert R.match_candidates(other, page["options"]) == []


def test_rejestr_baza_oba_zapisy_nazwiska():
    assert R.split_full_name("Jan Kowalski") == {"first_name": "Jan", "last_name": "Kowalski"}
    assert R.split_full_name("KOWALSKI Jan")["last_name"] == "KOWALSKI"


def test_data_urodzenia_z_karty_edycji():
    assert R.birth_date_from_edit_page('<input type="date" name="DataUr" value="1999-12-31">') == "1999-12-31"
    assert R.birth_date_from_edit_page("<p>brak</p>") == ""


# ---------------------------------------------------------------------------
# Wynik zapisu
# ---------------------------------------------------------------------------


def test_wynik_karta_edycji_nowej_osoby():
    html = (
        '<div id="info_edit">Zapisano nowy wpis</div>'
        '<input name="NrSedzia" type="hidden" value="5999">'
        '<input name="Imie" value="Martyna"><input name="Nazwisko" value="WIĄCKIEWICZ">'
    )
    res = R.detect_result(person(), html, [])
    assert res == {"status": "created", "nr": "5999", "message": "Zapisano nowy wpis"}


def test_wynik_nowa_pozycja_na_liscie():
    before = R.parse_add_page(ADD_PAGE)["options"]
    after = before + [{"nr": "6001", "first_name": "Martyna", "last_name": "WIĄCKIEWICZ"}]
    res = R.detect_result(person(), "<html>lista</html>", before, after)
    assert res["status"] == "created" and res["nr"] == "6001"


def test_wynik_formularz_wrocil_z_danymi_to_blad():
    html = ADD_PAGE.replace("name='Imie' value=\"\"", "name='Imie' value=\"Martyna\"").replace(
        "name='Nazwisko' value=\"\"", "name='Nazwisko' value=\"WIĄCKIEWICZ\""
    ) + "<script>alert('Błędna data');</script>"
    res = R.detect_result(person(), html, [], [])
    assert res["status"] == "error" and res["message"] == "Błędna data"


def test_wynik_niepotwierdzony():
    res = R.detect_result(person(), "<html>ok</html>", [], [])
    assert res["status"] == "unconfirmed"


# ---------------------------------------------------------------------------
# Plik
# ---------------------------------------------------------------------------


def _xlsx(hidden_rows=(), hidden_sheet=False) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Odpowiedzi"
    ws.append(["Sygnatura czasowa", "Pesel", "Imię", "Nazwisko", "Data urodzenia"])
    ws.append([dt.datetime(2026, 9, 22, 20, 2), 10222304482.0, "Martyna", "Wiąckiewicz", dt.datetime(2010, 2, 23)])
    ws.append([dt.datetime(2026, 9, 23, 23, 13), 2270803628.0, "Jan", "Testowy", dt.datetime(2002, 7, 8)])
    ws.append([None, None, None, None, None])
    ws.append([dt.datetime(2026, 9, 24, 8, 0), None, "Ukryty", "Wiersz", "2001-01-01"])
    for r in hidden_rows:
        ws.row_dimensions[r].hidden = True
    ws.column_dimensions["A"].hidden = True
    if hidden_sheet:
        extra = wb.create_sheet("Stare")
        extra.append(["x"])
        extra.sheet_state = "hidden"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_xlsx_ukryte_wiersze_daty_i_liczby():
    table = read_table(_xlsx(hidden_rows=[5], hidden_sheet=True), "Odpowiedzi.xlsx")
    assert table["kind"] == "xlsx"
    sheet = table["sheets"][0]
    rows = sheet["rows"]
    assert [r["row"] for r in rows] == [1, 2, 3, 5]  # pusty wiersz 4 wypada, numeracja zostaje
    assert rows[1]["cells"] == ["2026-09-22 20:02", "10222304482", "Martyna", "Wiąckiewicz", "2010-02-23"]
    assert rows[2]["cells"][1] == "2270803628"  # zero z przodu PESEL-u dokłada kreator
    assert [r["hidden"] for r in rows] == [False, False, False, True]
    assert sheet["hidden_rows"] == 1
    assert sheet["hidden_columns"] == [0]
    assert table["sheets"][1]["hidden"] is True


def test_csv_srednik_i_cp1250():
    data = "Imię;Nazwisko;Płeć\nŁucja;Żak;Kobieta\n".encode("cp1250")
    table = read_table(data, "lista.csv")
    assert table["kind"] == "csv"
    assert table["sheets"][0]["rows"][1]["cells"] == ["Łucja", "Żak", "Kobieta"]


def test_xls_stary_format():
    xlwt = pytest.importorskip("xlwt")
    wb = xlwt.Workbook()
    ws = wb.add_sheet("Lista")
    ws.write(0, 0, "Imię")
    ws.write(0, 1, "Nazwisko")
    ws.write(1, 0, "Anna")
    ws.write(1, 1, "Nowak")
    ws.write(2, 0, "Ukryta")
    ws.write(2, 1, "Osoba")
    ws.row(2).hidden = True
    buf = io.BytesIO()
    wb.save(buf)
    rows = read_table(buf.getvalue(), "lista.xls")["sheets"][0]["rows"]
    assert [r["cells"] for r in rows] == [["Imię", "Nazwisko"], ["Anna", "Nowak"], ["Ukryta", "Osoba"]]
    assert [r["hidden"] for r in rows] == [False, False, True]


def test_pusty_plik():
    with pytest.raises(SheetError):
        read_table(b"", "x.csv")
