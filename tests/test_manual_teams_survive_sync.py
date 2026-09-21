# -*- coding: utf-8 -*-
"""
Reczne wpisy z Panelu klubow maja PRZEZYC dobowa migawke sezonu.

Zgloszenie z 22.09.2026: „Dodaj druzyne do Panelu" dziala, ale po dobie mecz
wraca do „bez rozpoznanej druzyny gospodarza". Przyczyna byla w migawce -
`_store_season` kasowalo WSZYSTKIE druzyny sezonu i wpisywalo to, co oddalo
ZPRP. Gospodarza dodanego recznie ZPRP nie odda nigdy, wiec znikal, a wyjatek
na meczu (`province_match_overrides`) zostawal i wskazywal na nieistniejacy
numer druzyny. W produkcji widac to bylo jako `moved: true` przy pustym
`team_id`.

⚠ Czytamy ZRODLO, a nie importujemy modulu: `app/province_clubs_sync.py`
ciagnie `app/db.py`, ktory laczy sie z baza juz przy imporcie (ta sama droga co
w `test_distance_versions.py`).
"""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SYNC = (ROOT / "app" / "province_clubs_sync.py").read_text(encoding="utf-8")
CLUBS = (ROOT / "app" / "province_clubs.py").read_text(encoding="utf-8")


def _delete_block(table: str) -> str:
    """Tresc jednego `<tabela>.delete().where(...)` z migawki sezonu."""
    start = SYNC.index(f"{table}.delete()")
    return SYNC[start : SYNC.index("    )\n", SYNC.index("where(", start))]


class TestPrefiksRecznegoWpisu:
    def test_obie_strony_mowia_o_tym_samym_prefiksie(self):
        """Numer nadaje panel, a rozpoznaje migawka - rozjazd kasuje po cichu."""
        assert 'return f"manual:{prefix}:{digest}"' in CLUBS
        assert 'MANUAL_PREFIX = "manual:"' in SYNC


class TestMigawkaSezonu:
    def test_nie_kasuje_recznie_dodanych_druzyn(self):
        block = _delete_block("province_club_teams")
        assert "not_(province_club_teams.c.team_id.like(f\"{MANUAL_PREFIX}%\"))" in block

    def test_nie_kasuje_recznie_zalozonych_rozgrywek(self):
        block = _delete_block("province_competitions")
        assert (
            "not_(province_competitions.c.competition_id.like(f\"{MANUAL_PREFIX}%\"))"
            in block
        )

    def test_druzyna_wycofana_z_ZPRP_nadal_znika(self):
        """Wyjatek dotyczy TYLKO recznych - reszta sezonu ma sie kasowac."""
        for table, column in (
            ("province_club_teams", "team_id"),
            ("province_competitions", "competition_id"),
        ):
            block = _delete_block(table)
            assert f"{table}.c.province == province" in block
            assert f"{table}.c.season == season" in block
            # Warunek jest zawezeniem kasowania, a nie jego zniesieniem.
            assert f"{table}.c.{column}.like" in block

    def test_import_not_jest_na_miejscu(self):
        assert "from sqlalchemy import and_, insert, not_, select, update" in SYNC
