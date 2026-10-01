# -*- coding: utf-8 -*-
"""Publiczne liczby BAZY dla bazaapp.online - reguły liczenia i pamięć podręczna.

Testujemy liść, bo `app.public_stats` ciągnie `app.db`, a ten łączy się
z Postgresem przy imporcie. Wiązanie trasy sprawdzamy z drzewa składni.
"""
from __future__ import annotations

import ast
import pathlib
from datetime import datetime, timedelta, timezone

from app.public_stats_rules import (
    CACHE_TTL_S,
    FIELDS,
    LIST_FIELDS,
    StatsCache,
    build_payload,
    canonical_province,
    count_panel_provinces,
    is_official_match,
    merge_sections,
    panel_province_list,
    sort_provinces,
    summarize_panel,
    summarize_judges,
    summarize_matches,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


class TestWojewodztwa:
    def test_pisownia_z_ogonkami_i_bez_to_ten_sam_okreg(self):
        assert canonical_province("ŚLĄSKIE") == "SLASKIE"
        assert canonical_province("slaskie") == "SLASKIE"
        assert canonical_province(" Łódzkie ") == "LODZKIE"
        assert canonical_province("woj. małopolskie") == "MALOPOLSKIE"
        assert canonical_province("Warmińsko - Mazurskie") == "WARMINSKO-MAZURSKIE"

    def test_smieci_nie_sa_okregiem(self):
        for value in ("", None, "POLSKA", "ZPRP", "123"):
            assert canonical_province(value) == "", value

    def test_panel_liczy_tylko_wlaczone_i_raz_na_okreg(self):
        rows = [
            {"province": "ŚLĄSKIE", "enabled": True},
            {"province": "SLASKIE", "enabled": True},
            {"province": "MAZOWIECKIE", "enabled": False},
            {"province": "OPOLSKIE", "enabled": True},
            {"province": "BZDURA", "enabled": True},
        ]
        assert count_panel_provinces(rows) == 2


class TestSedziowie:
    def test_sedziowie_aktywni_i_okregi(self):
        rows = [
            # aktywny przez logowanie
            {"judge_id": "101", "province": "ŚLĄSKIE", "last_login_at": NOW - timedelta(days=2), "last_open_at": None},
            # logowanie stare, ale otwarcie aplikacji świeże
            {"judge_id": "102", "province": "SLASKIE", "last_login_at": NOW - timedelta(days=200), "last_open_at": NOW - timedelta(days=29)},
            # nieaktywny
            {"judge_id": "103", "province": "OPOLSKIE", "last_login_at": NOW - timedelta(days=31), "last_open_at": None},
            # bez okręgu - liczy się jako sędzia, nie dokłada okręgu
            {"judge_id": "104", "province": "", "last_login_at": NOW - timedelta(days=1), "last_open_at": None},
            # pusty numer i duplikat nie liczą się
            {"judge_id": "", "province": "LUBUSKIE", "last_login_at": NOW, "last_open_at": None},
            {"judge_id": "101", "province": "LUBUSKIE", "last_login_at": NOW, "last_open_at": None},
        ]
        assert summarize_judges(rows, NOW) == {
            "judges": 4,
            "active_judges_30d": 3,
            "provinces": 2,
        }

    def test_naiwny_znacznik_czasu_traktowany_jak_utc(self):
        naive = (NOW - timedelta(days=1)).replace(tzinfo=None)
        rows = [{"judge_id": "1", "province": "PODLASKIE", "last_login_at": naive}]
        assert summarize_judges(rows, NOW)["active_judges_30d"] == 1


class TestMeczeProEla:
    def test_mecz_oficjalny(self):
        assert is_official_match("SPM/1", {"matchNumber": "SPM/1"})
        assert is_official_match("OSK/12", None)

    def test_szkoleniowe_i_testowe_odpadaja(self):
        assert not is_official_match("T-K3N8P2WQ/SPM/1", {})
        assert not is_official_match("SPM/2", {"isTest": True})
        assert not is_official_match("SPM/3", {"origin": "training"})
        assert not is_official_match("SPM/4", {"training": {"eventId": "abc"}})
        assert not is_official_match("", {})

    def test_konfiguracja_jako_surowy_napis_json(self):
        # asyncpg bez kodeka potrafi oddać kolumnę JSON jako napis
        assert not is_official_match("SPM/5", '{"isTest": true}')
        assert is_official_match("SPM/6", '{"isTest": false}')
        assert is_official_match("SPM/7", "to nie jest json")

    def test_sumy_meczow_i_zatwierdzonych(self):
        rows = [
            {"match_number": "SPM/1", "status": "approved", "config": {}},
            {"match_number": "SPM/2", "status": "finished", "config": {}},
            {"match_number": "SPM/3", "status": "in_progress", "config": None},
            {"match_number": "T-K3N8P2WQ/SPM/1", "status": "approved", "config": {}},
            {"match_number": "SPM/9", "status": "approved", "config": {"isTest": True}},
        ]
        assert summarize_matches(rows) == {"proel_matches": 3, "proel_protocols": 1}


class TestSkladanieOdpowiedzi:
    def test_brakujaca_sekcja_bierze_poprzednia_wartosc(self):
        previous = {"judges": 500, "proel_matches": 40}
        fresh = {"judges": 510, "active_judges_30d": 300}
        merged = merge_sections(fresh, previous)
        assert merged["judges"] == 510
        assert merged["proel_matches"] == 40
        assert merged["proel_protocols"] is None
        assert list(merged) == list(FIELDS) + list(LIST_FIELDS)
        assert merged["panel_province_list"] is None

    def test_odpowiedz_ma_same_liczby_i_date(self):
        payload = build_payload({"judges": 1}, None, NOW)
        assert payload["updated_at"] == "2026-10-01T12:00:00+00:00"
        assert payload["stale"] is False
        for field in FIELDS:
            assert payload[field] is None or isinstance(payload[field], int)
        assert set(payload) == set(FIELDS) | set(LIST_FIELDS) | {"updated_at", "stale"}


class TestPamiecPodreczna:
    def test_waznosc_dziesiec_minut(self):
        assert CACHE_TTL_S == 600
        cache = StatsCache()
        assert cache.fresh(0) is None and cache.stale() is None
        cache.put({"judges": 1, "stale": False}, 100.0)
        assert cache.fresh(100.0 + CACHE_TTL_S - 1) == {"judges": 1, "stale": False}
        assert cache.fresh(100.0 + CACHE_TTL_S) is None

    def test_po_wygasnieciu_zostaje_ostatnia_znana(self):
        cache = StatsCache(ttl_s=10)
        cache.put({"judges": 7, "stale": False}, 0.0)
        assert cache.fresh(50.0) is None
        assert cache.last() == {"judges": 7, "stale": False}
        assert cache.stale() == {"judges": 7, "stale": True}
        # oznaczenie nie psuje zapamiętanej odpowiedzi
        assert cache.last()["stale"] is False


class TestWiazanie:
    def test_trasa_publiczna_bez_autoryzacji(self):
        tree = ast.parse((ROOT / "app" / "public_stats.py").read_text(encoding="utf-8"))
        routes = {}
        for node in tree.body:
            if isinstance(node, ast.AsyncFunctionDef):
                for deco in node.decorator_list:
                    if isinstance(deco, ast.Call) and getattr(deco.func, "attr", "") == "get":
                        routes[deco.args[0].value] = node
        assert "/baza-stats" in routes
        source = ast.unparse(routes["/baza-stats"])
        assert "Depends" not in source

    def test_modul_nie_importuje_bazy_na_gorze(self):
        tree = ast.parse((ROOT / "app" / "public_stats.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                assert node.module != "app.db", "app.db tylko wewnątrz funkcji"

    def test_router_i_cors_w_main(self):
        main = (ROOT / "main.py").read_text(encoding="utf-8")
        assert "app.include_router(public_stats_router)" in main
        assert '"https://bazaapp.online"' in main
        assert '"https://www.bazaapp.online"' in main


class TestPrzerwaPoAwarii:
    def test_po_nieudanym_liczeniu_minuta_przerwy(self):
        cache = StatsCache(ttl_s=600, retry_after_s=60)
        assert not cache.in_backoff(0.0)
        cache.mark_failure(100.0)
        assert cache.in_backoff(159.0)
        assert not cache.in_backoff(160.0)

    def test_udany_zapis_konczy_przerwe(self):
        cache = StatsCache(ttl_s=600, retry_after_s=60)
        cache.mark_failure(100.0)
        cache.put({"judges": 1, "stale": False}, 110.0)
        assert not cache.in_backoff(111.0)


class TestListaOkregowZPanelem:
    ROWS = [
        {"province": "SLASKIE", "enabled": True},
        {"province": "ŚLĄSKIE", "enabled": True},
        {"province": "dolnoslaskie", "enabled": True},
        {"province": "Łódzkie", "enabled": True},
        {"province": "LUBUSKIE", "enabled": True},
        {"province": "MAZOWIECKIE", "enabled": False},
        {"province": "BZDURA", "enabled": True},
        {"province": None, "enabled": True},
    ]

    def test_nazwy_z_polskimi_znakami_posortowane_bez_powtorzen(self):
        assert panel_province_list(self.ROWS) == [
            "DOLNOŚLĄSKIE",
            "LUBUSKIE",
            "ŁÓDZKIE",
            "ŚLĄSKIE",
        ]

    def test_liczba_i_lista_z_jednego_odczytu(self):
        section = summarize_panel(self.ROWS)
        assert section["panel_provinces"] == 4
        assert section["panel_province_list"] == panel_province_list(self.ROWS)

    def test_sortowanie_wedlug_polskiego_alfabetu(self):
        assert sort_provinces(["ŚWIĘTOKRZYSKIE", "SLASKIE", "ŚLĄSKIE", "ŁÓDZKIE", "LUBELSKIE"]) == [
            "LUBELSKIE",
            "ŁÓDZKIE",
            "SLASKIE",
            "ŚLĄSKIE",
            "ŚWIĘTOKRZYSKIE",
        ]

    def test_pusta_tabela_to_pusta_lista_nie_null(self):
        assert summarize_panel([]) == {"panel_provinces": 0, "panel_province_list": []}
        assert merge_sections({"panel_province_list": []}, None)["panel_province_list"] == []

    def test_awaria_sekcji_bierze_poprzednia_liste(self):
        previous = {"panel_provinces": 2, "panel_province_list": ["OPOLSKIE", "ŚLĄSKIE"]}
        merged = merge_sections({"judges": 5}, previous)
        assert merged["panel_province_list"] == ["OPOLSKIE", "ŚLĄSKIE"]
        assert merged["panel_provinces"] == 2

    def test_awaria_bez_poprzedniej_odpowiedzi_to_null(self):
        assert merge_sections({"judges": 5}, None)["panel_province_list"] is None

    def test_odpowiedz_niesie_liste(self):
        payload = build_payload(summarize_panel(self.ROWS), None, NOW)
        assert payload["panel_province_list"] == ["DOLNOŚLĄSKIE", "LUBUSKIE", "ŁÓDZKIE", "ŚLĄSKIE"]
