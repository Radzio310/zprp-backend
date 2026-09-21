# -*- coding: utf-8 -*-
"""
Siatka miesiecy i ekran miesiaca musza liczyc TO SAMO.

Zgloszenie z 22.09.2026: kafel „Moje rozliczenie okregowe" pokazywal 173,80 zl,
a ekran pod nim 0,00 zl i pusta liste meczow. Oba mowily prawde o swoim
rachunku - tyle ze rachunki byly dwa. `/me` dzieli mecze wedlug tego, KTO PLACI
obsade (`club_scope`: klub z wylaczonym rozliczaniem przez okreg placi sam),
a `/months` liczyl wszystko jednym workiem.

Rozstrzygniecie: dwa punkty widzenia, jeden rachunek. Okreg pyta „ile
WYPLACAM" (bez meczow klubowych), sedzia „ile ZARABIAM" (z nimi, osobno
oznaczonymi). Stad `include_clubs` - i dlatego kazda grupa liczy sie OSOBNO,
bo koszty uzyskania i prog 200 zl ida od sumy miesiaca u danego platnika.

⚠ Czytamy ZRODLO: `app/province_settlements.py` i `app/settlement_club_scope.py`
ciagna `app/db.py`, ktory laczy sie z baza juz przy imporcie (ta sama droga co
w `test_distance_versions.py`). Sam podzial „kto placi" ma wlasny test na
lisciu - `test_club_charges.py`, status `club-off`.
"""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUTES = (ROOT / "app" / "province_settlements.py").read_text(encoding="utf-8")
SCOPE = (ROOT / "app" / "settlement_club_scope.py").read_text(encoding="utf-8")


def _body(source: str, marker: str, length: int = 2000) -> str:
    return source[source.index(marker) : source.index(marker) + length]


class TestSiatkaMiesiecy:
    def test_okreg_nie_placi_meczow_klubowych(self):
        """Domyslnie (panel okregu) mecz placony przez klub wypada z sumy."""
        body = _body(ROUTES, '@router.get("/months"', 3000)
        assert "_club_paid_keys(" in body
        assert "[item for item in assignments if item.match_key not in club_paid]" in body
        # Do silnika nie moze juz isc surowa lista obsad.
        assert "monthly_totals(assignments" not in ROUTES

    def test_sedzia_dolicza_swoj_zarobek_od_klubu(self):
        """`include_clubs` - ten sam mecz jest jego pieniedzmi, tylko od klubu."""
        body = _body(ROUTES, '@router.get("/months"', 3000)
        assert "include_clubs: bool = Query(" in body
        assert "if include_clubs and club_paid:" in body
        assert "[item for item in assignments if item.match_key in club_paid]" in body

    def test_kazda_grupa_liczy_sie_osobno(self):
        """Prog 200 zl i koszty ida od sumy miesiaca U PLATNIKA, nie lacznie."""
        body = _body(ROUTES, '@router.get("/months"', 3000)
        # Dwa niezalezne przebiegi silnika, dopiero ich wyniki sie skladaja.
        assert body.count("E.monthly_totals(") == 2
        assert "_merge_months(" in body

    def test_skladanie_miesiecy_sumuje_kwoty_ale_nie_osoby(self):
        body = _body(ROUTES, "def _merge_months")
        assert 'if field == "judges":' in body
        assert "max(item[field], value)" in body
        assert "round(item[field] + value, 2)" in body

    def test_rozpoznanie_idzie_przez_ten_sam_modul_co_ekran(self):
        """Dwa rachunki rozjechaly sie raz - nie moga po raz drugi."""
        body = _body(ROUTES, "async def _club_paid_keys")
        assert "club_scope_many(province, by_season)" in body
        assert "season_of(match.day)" in body

    def test_przebieg_rozpoznawczy_bierze_wszystko(self):
        """Podzial „kto placi" nie moze zalezec od przelacznikow ekranu."""
        body = _body(ROUTES, "async def _club_paid_keys")
        assert "include_future=True" in body
        assert "include_zprp=True" in body


class TestWspolnyPodzial:
    def test_club_scope_to_jeden_sezon_tego_samego(self):
        """Jedna reguła w dwóch funkcjach = dwie reguły. Stąd delegacja."""
        body = _body(SCOPE, "async def club_scope(", 400)
        assert "return await club_scope_many(province, {season: list(matches)})" in body

    def test_druzyny_dopasowywane_sezon_po_sezonie(self):
        """Ten sam numer druzyny bywa w innym sezonie w innym klubie."""
        body = _body(SCOPE, "async def club_scope_many", 4000)
        assert "province_club_teams.c.season.in_(seasons)" in body
        assert "for season, matches in by_season.items():" in body
        assert "teams.get(season, ({}, {}))" in body

    def test_pusty_zakres_nie_pyta_bazy(self):
        body = _body(SCOPE, "async def club_scope_many")
        assert 'return {"match_keys": set(), "clubs": []}' in body
