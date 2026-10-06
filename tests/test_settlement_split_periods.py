# -*- coding: utf-8 -*-
"""
Podział puli na listy sędziowskie w okresach wypłat (06.10.2026).

Zgłoszenie: w Rozliczeniach zniknął przycisk „Podziel". Okręg z własnymi
okresami wypłat (Śląsk ma je zawsze - `SILESIA_2026`) oglądał tylko okresy,
a podział był kluczowany samym miesiącem i w okresie był wyłączony. Teraz
klucz podziału ma okres (`period_id`, pusty = miesiąc kalendarzowy), bo
w grudniu dwa okresy mają ten sam miesiąc wypłaty.

⚠ Trasy ciągną `app/db.py` (łączy się z bazą przy imporcie) - czytamy ŹRÓDŁO,
a schemat tabeli z liścia `settlement_split_tables`.
"""
from __future__ import annotations

import pathlib

from sqlalchemy import MetaData

from app.settlement_split_tables import define_tables

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPLITS = (ROOT / "app" / "province_settlement_splits.py").read_text(encoding="utf-8")
ROUTES = (ROOT / "app" / "province_settlements.py").read_text(encoding="utf-8")
DB = (ROOT / "app" / "db.py").read_text(encoding="utf-8")


def test_klucz_tabeli_ma_okres():
    (table,) = define_tables(MetaData())
    assert "period_id" in table.c
    unique = [ix for ix in table.indexes if ix.unique]
    assert len(unique) == 1
    assert [c.name for c in unique[0].columns] == [
        "province", "period_year", "period_month", "period_id", "judge_id",
    ]


def test_migracja_zamienia_stary_indeks():
    assert "ADD COLUMN IF NOT EXISTS period_id" in DB
    assert "DROP INDEX IF EXISTS ux_province_settlement_splits_key" in DB
    assert "ux_province_settlement_splits_period_key" in DB


def test_rozliczenie_okresu_stosuje_podzial():
    assert "await apply_splits(province, year, month, entries, period_id)" in ROUTES
    assert "if not period_id:\n        await apply_splits" not in ROUTES


def test_kazdy_odczyt_podzialu_zna_okres():
    calls = [line.strip() for line in SPLITS.splitlines() if "await _row(" in line]
    assert calls, "brak odczytów podziału"
    for call in calls:
        assert "period_id" in call, call
    # Zapis szkicu i wydania trafia w nowy klucz.
    assert SPLITS.count("index_elements=KEY_COLUMNS") == 2
    assert "T.c.period_id, T.c.judge_id]" in SPLITS


def test_siatka_miesiecy_bierze_tylko_podzialy_miesiecy():
    body = SPLITS[SPLITS.index("async def split_month_deltas") :][:1500]
    assert 'T.c.period_id == ""' in body


def test_lista_okresu_nosi_daty_okresu():
    body = SPLITS[SPLITS.index("async def _period(") :][:1200]
    assert "settlement_range" in body
    assert "strftime('%d.%m.%Y')" in body
    # Wpis w księdze dostaje początek okresu, nie pierwszy dzień miesiąca.
    assert 'date_from=date.fromisoformat(snapshot["period"]["from"])' in SPLITS
