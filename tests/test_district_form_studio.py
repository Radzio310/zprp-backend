"""Formularze okręgowe - studio eksportu (bez bazy): plan, lustro widoku, HTML, Excel, strona publiczna."""
from __future__ import annotations

import io
import pathlib

from app import district_form_studio as ST

ROOT = pathlib.Path(__file__).resolve().parents[1]

COLUMNS = [
    {"id": "status", "type": "status", "title": "Obecność", "visibility": "all",
     "options": [{"id": "yes", "label": "Będę", "tone": "positive"}, {"id": "no", "label": "Nie będę", "tone": "negative"}]},
    {"id": "wplata", "type": "confirm", "title": "Wpłata", "visibility": "self", "amount": 50},
    {"id": "osoby", "type": "number", "title": "Osoby", "visibility": "all"},
    {"id": "uwagi", "type": "text", "title": "Uwagi", "visibility": "managers"},
]


def row(key, name, status=None, pay=None, people=None, filled=True, updated=None):
    return {"key": key, "name": name, "cells": {"status": status, "wplata": pay, "osoby": people}, "filled": filled,
            "web_review": False, "updated_at": updated}


ROWS = [
    row("1", "Łukasz Żak", "yes", "confirmed", 2, updated="2026-11-10T10:00:00+00:00"),
    row("2", "Anna Lis", "no", None, None),
    row("3", "Adam Ćwik", "yes", "declared", 1, updated="2026-11-11T10:00:00+00:00"),
    row("4", "Ewa Bąk", None, None, None, filled=False),
]


def test_plan_odrzuca_nieznane_kolumny_i_zle_wartosci():
    plan = ST.clean_plan({"format": "exe", "layout": "x", "theme": "neon", "columns": ["status", "hack"], "keys": ["1", "1", "2"],
                          "groups": [{"label": "Będę", "tone": "bad", "keys": ["1"]}], "lenses": ["Obecność: Będę"]}, COLUMNS)
    assert plan["format"] == "pdf" and plan["layout"] == "checklist" and plan["theme"] == "province"
    assert plan["columns"] == ["status"]
    assert plan["keys"] == ["1", "2"]
    assert plan["groups"][0]["tone"] == ""
    whole = ST.clean_plan({"scope": "all", "keys": ["1"], "lenses": ["x"]}, COLUMNS)
    assert whole["keys"] is None and whole["lenses"] == [] and whole["columns"] == [c["id"] for c in COLUMNS]


def test_kolejnosc_z_telefonu_jest_zachowana():
    assert [r["key"] for r in ST.order_by_keys(ROWS, ["3", "nie-ma", "1"])] == ["3", "1"]
    assert len(ST.order_by_keys(ROWS, None)) == 4


def test_sortowanie_po_polsku():
    names = sorted(["Żak", "Zając", "Łoś", "Lis", "Ćwik", "Cebula"], key=ST.pl_key)
    assert names == ["Cebula", "Ćwik", "Lis", "Łoś", "Zając", "Żak"]


def test_widok_filtr_sort_grupy_zaznaczenie():
    rows, groups = ST.apply_view(ROWS, COLUMNS, {"filter": {"status": ["yes", "none"]}, "sort": {"col": "__name", "dir": "asc"}})
    assert [r["key"] for r in rows] == ["3", "4", "1"]
    assert groups is None
    rows, groups = ST.apply_view(ROWS, COLUMNS, {"groupBy": "wplata"})
    assert [g["label"] for g in groups] == ["Otrzymano", "Zapłaciłem", "Nie zapłacono"]
    assert groups[2]["keys"] == ["2", "4"]
    rows, _ = ST.apply_view(ROWS, COLUMNS, {"selectedIds": ["2", "1"], "sort": {"col": "osoby", "dir": "desc"}})
    assert [r["key"] for r in rows] == ["1", "2"]
    rows, _ = ST.apply_view(ROWS, COLUMNS, {"filter": {"__filled": ["no"]}})
    assert [r["key"] for r in rows] == ["4"]
    rows, _ = ST.apply_view(ROWS, COLUMNS, {"sort": {"col": "__updated", "dir": "desc"}})
    assert [r["key"] for r in rows][:2] == ["3", "1"]


def test_sumy_grupy_jak_w_aplikacji():
    aggs = ST.group_aggs(COLUMNS, ROWS)
    assert "Wpłata: 50 zł" in aggs and "zgłoszone 50 zł" in aggs and "Osoby: Σ 3" in aggs


def _doc(rows=ROWS, groups=None, lenses=("Obecność: Będę",)):
    table = [[str(i + 1), r["name"], ST.cell_text(COLUMNS[0], r["cells"]["status"])] for i, r in enumerate(rows)]
    tones = [["", "", ST._cell_tone(COLUMNS[0], r["cells"]["status"])] for r in rows]
    stats = ST.list_stats_for(COLUMNS, rows)
    return ST.build_doc(form={"title": "Wigilia <okręgu>", "closes_at": None}, province="Śląskie", generated="12.11.2026 10:00",
                        kind="list", header=["Lp.", "Sędzia", "Obecność"], table=table, tones=tones, names=[r["name"] for r in rows],
                        groups=groups, stats=stats, charts=ST.charts_for_list(COLUMNS, stats), lenses=list(lenses), scope="view")


def test_html_lista_do_odhaczania_i_raport():
    doc = _doc(groups=[{"label": "Będę", "tone": "positive", "size": 2, "aggs": ["Wpłata: 50 zł"]}, {"label": "Reszta", "tone": "", "size": 2, "aggs": []}])
    checklist = ST.render_html(doc, theme="province", province_key="SLASKIE", layout="checklist", mode="print")
    assert 'class="box"' in checklist and "Sprawdził" in checklist and 'id="q"' not in checklist
    assert "Wigilia &lt;okręgu&gt;" in checklist and "Obecność: Będę" in checklist and "Wpłata: 50 zł" in checklist
    report = ST.render_html(doc, theme="premium", province_key=None, layout="report", mode="file")
    assert 'class="ring"' in report and 'class="funnel"' in report and 'id="q"' in report and "<script>" in report
    assert 'class="box"' not in report


def test_strona_publiczna_przycina_do_poziomu():
    doc = _doc()
    stats = ST.render_html(doc, theme="elegant", province_key="SLASKIE", layout="report", mode="public", level="stats")
    assert "Łukasz Żak" not in stats and 'class="ring"' in stats and "noindex" in stats
    initials = ST.render_html(doc, theme="elegant", province_key="SLASKIE", layout="report", mode="public", level="initials")
    assert "Łukasz Żak" not in initials and "Ł. Ż." in initials


def test_pusty_widok_mowi_wprost():
    doc = _doc(rows=[])
    out = ST.render_html(doc, theme="province", province_key=None, layout="checklist", mode="print")
    assert "Nikt nie pasuje" in out


def test_excel_otwiera_sie_i_ma_grupy():
    from openpyxl import load_workbook

    doc = _doc(groups=[{"label": "Będę", "tone": "positive", "size": 2, "aggs": []}, {"label": "Reszta", "tone": "", "size": 2, "aggs": []}])
    data = ST.to_xlsx(doc, theme="province", province_key="SLASKIE", layout="report")
    book = load_workbook(io.BytesIO(data))
    sheet = book["Lista"]
    values = [c.value for c in sheet["A"]]
    assert "Będę (2)" in values and "Reszta (2)" in values
    assert "Podsumowanie" in book.sheetnames
    check = ST.to_xlsx(doc, theme="premium", province_key=None, layout="checklist")
    assert load_workbook(io.BytesIO(check))["Lista"].cell(row=5, column=1).value == "✓"


def test_link_publiczny_ustawienia_i_widok():
    s = ST.clean_link_settings({"level": "full", "columns": ["status", "wplata", "uwagi", "osoby"], "view": {"filter": {"x": ["1"], "status": ["yes"]}}}, COLUMNS)
    assert s["columns"] == ["status", "osoby"]
    assert s["view"]["filter"] == {"status": ["yes"]}
    assert ST.link_view(None, lambda c: c)["enabled"] is False
    view = ST.link_view({"code": "abc", "views": 3, "disabled_at": None}, lambda c: f"/r/{c}")
    assert view["enabled"] and view["url"] == "/r/abc" and view["views"] == 3


def test_trasy_studia_istnieja():
    text = (ROOT / "app/district_forms.py").read_text(encoding="utf-8")
    for path in ('"/{form_id}/studio-export"', '"/{form_id}/public-link"'):
        assert path in text
    public = (ROOT / "app/district_forms_public.py").read_text(encoding="utf-8")
    assert '"/results/{code}"' in public


def test_strona_wynikow_otwarta_bez_klucza():
    from app.client_key_rules import is_open_path

    assert is_open_path("/public/forms/results/abcd2345")
    assert not is_open_path("/district-forms/abc/public-link")


def test_ladny_adres_wynikow():
    from app.district_forms import results_url

    assert results_url("abcd2345") == "https://www.bazapodreka.app/f/wyniki/abcd2345"
