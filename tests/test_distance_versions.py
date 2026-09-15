# -*- coding: utf-8 -*-
"""
Wersje tabel odleglosci okregu.

Kilometry z tabeli wchodza do rozliczen, a synchronizacja przelicza takze
sezony miniete. Regula jest wiec jedna: wersje wybiera DATA MECZU. Te testy
pilnuja, zeby aktualizacja tabeli nigdy nie przeliczyla archiwum.
"""
from datetime import datetime

from app.settlement_distances import (
    VersionedDistanceIndex,
    pick_distance_table,
)

TRESC = {
    "validFrom": "2026-09-01",
    "cities": ["Wroclaw", "Legnica"],
    "edges": [{"from": "Wroclaw", "to": "Legnica", "distance_km": 80}],
    "previous": [
        {
            "validFrom": "2000-01-01",
            "validUntil": "2026-08-31",
            "cities": ["Wroclaw", "Legnica"],
            "edges": [{"from": "Wroclaw", "to": "Legnica", "distance_km": 95}],
        }
    ],
}

STARA_TRESC = {
    "cities": ["Wroclaw", "Legnica"],
    "edges": [{"from": "Wroclaw", "to": "Legnica", "distance_km": 95}],
}


def km(table):
    return table["edges"][0]["distance_km"]


class TestWyborWersji:
    def test_mecz_od_pierwszego_dnia_bierze_nowa(self):
        assert km(pick_distance_table(TRESC, "2026-09-01")) == 80
        assert km(pick_distance_table(TRESC, "2027-05-10T18:00:00")) == 80

    def test_mecz_wczesniejszy_bierze_stara(self):
        assert km(pick_distance_table(TRESC, "2026-08-31")) == 95
        assert km(pick_distance_table(TRESC, "2025-11-02 20:00")) == 95

    def test_datetime_tez_dziala(self):
        assert km(pick_distance_table(TRESC, datetime(2026, 8, 31, 23, 30))) == 95
        assert km(pick_distance_table(TRESC, datetime(2026, 9, 1, 0, 5))) == 80

    def test_zapis_polski(self):
        assert km(pick_distance_table(TRESC, "31.08.2026")) == 95
        assert km(pick_distance_table(TRESC, "01.09.2026")) == 80

    def test_bez_daty_liczymy_najnowsza(self):
        # Automat obsadowy planuje mecze przyszle i daty nie podaje.
        assert km(pick_distance_table(TRESC, None)) == 80
        assert km(pick_distance_table(TRESC)) == 80

    def test_mecz_starszy_niz_wszystko_liczy_najstarsza(self):
        assert km(pick_distance_table(TRESC, "1999-01-01")) == 95

    def test_tresc_bez_wersji_przechodzi_bez_zmian(self):
        assert km(pick_distance_table(STARA_TRESC, "2026-09-05")) == 95
        assert km(pick_distance_table(STARA_TRESC, None)) == 95

    def test_smieci_nie_wywracaja(self):
        assert pick_distance_table(None, "2026-09-05") is None
        assert pick_distance_table("nie json", "2026-09-05") == "nie json"
        assert pick_distance_table({}, "2026-09-05") == {}


class TestIndeksuWersjonowanego:
    def test_ta_sama_para_ma_inne_kilometry_w_roznych_sezonach(self):
        book = VersionedDistanceIndex(TRESC)
        assert book.lookup("Wroclaw", "Legnica", "2026-09-05") == 80
        assert book.lookup("Wroclaw", "Legnica", "2026-08-05") == 95

    def test_indeks_budowany_raz_na_wersje(self):
        book = VersionedDistanceIndex(TRESC)
        first = book.for_day("2026-09-05")
        second = book.for_day("2027-01-20")
        assert first is second
        assert book.for_day("2026-01-20") is not first

    def test_to_samo_miasto_to_zero_niezaleznie_od_wersji(self):
        book = VersionedDistanceIndex(TRESC)
        assert book.lookup("Wroclaw", "Wroclaw", "2020-01-01") == 0.0

    def test_pary_spoza_tabeli_nie_ma(self):
        book = VersionedDistanceIndex(TRESC)
        assert book.lookup("Wroclaw", "Gdansk", "2026-09-05") is None


class TestTrasaManifestu:
    """
    Manifest MUSI byc deklarowany przed "/okreg_distances/{province}".

    FastAPI dopasowuje trasy po kolei. Gdyby manifest stal nizej, adres
    "/admin/okreg_distances/manifest" trafilby do handlera wojewodztwa,
    ktory poszedlby do bazy po wojewodztwo o nazwie "MANIFEST" i zwrocil 404 -
    a odswiezanie tabel w tle w BAZA po cichu przestaloby dzialac.

    Sprawdzamy ZRODLO, nie zaimportowany modul: `app.admin` ciagnie `app.db`,
    ktore laczy sie z Postgresem przy imporcie i pod SQLite nawet sie nie
    kompiluje. Reguly trasowania to i tak kolejnosc w pliku.
    """

    def test_manifest_stoi_przed_wojewodztwem(self):
        import io
        import os

        source = io.open(
            os.path.join(os.path.dirname(__file__), "..", "app", "admin.py"),
            encoding="utf-8",
        ).read()

        manifest = source.find('@router.get("/okreg_distances/manifest"')
        province = source.find('@router.get("/okreg_distances/{province}"')
        assert manifest > 0, "brak trasy manifestu"
        assert province > 0, "brak trasy wojewodztwa"
        assert manifest < province, "manifest musi byc zadeklarowany wyzej"


class TestZnacznikaZmiany:
    """
    Wgranie tabeli MUSI przesunac `updated_at`.

    Kolumna ma w `db.py` `onupdate=func.now()`, ale to hak SQLAlchemy odpalany
    wylacznie przy `Table.update()` - przy "INSERT ... ON CONFLICT DO UPDATE"
    nie dziala. Bez jawnego ustawienia data stalaby na chwili pierwszego
    wstawienia, manifest pokazalby stary odcisk i nowa tabela nie doszlaby
    w tle do zadnego telefonu. Ta sama pulapka zablokowala kiedys odswiezanie
    dokumentow, wiec pilnujemy jej testem, a nie pamiecia.
    """

    def _zrodlo(self):
        import io
        import os

        return io.open(
            os.path.join(os.path.dirname(__file__), "..", "app", "admin.py"),
            encoding="utf-8",
        ).read()

    def test_upsert_ustawia_updated_at_wprost(self):
        source = self._zrodlo()
        start = source.index("async def upsert_okreg_distance")
        body = source[start : start + 1800]
        assert "on_conflict_do_update" in body
        assert '"updated_at": func.now()' in body

    def test_manifest_podaje_drugi_slad_zmiany(self):
        source = self._zrodlo()
        start = source.index("async def okreg_distances_manifest")
        body = source[start : start + 2200]
        # Sama data potrafi sklamac - odcisk ma jeszcze z czego sie zlozyc.
        assert '"valid_from"' in body
        assert '"pairs"' in body
