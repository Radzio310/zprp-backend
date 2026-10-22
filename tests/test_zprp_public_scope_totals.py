"""Profile portalu: liczniki z serwera, bez obcięcia list i w jednym zakresie sezonu.

Klub/drużyna: `recent_matches`/`upcoming_matches` to podgląd po 5, ale liczniki
(`match_counts`, `upcoming_count`) i pełna lista (`matches`) idą z całego sezonu.
Zawodnik: `/players/{id}/matches` bez limitu; licznik zakładki = kafle = lista.
Trener: skład tylko z najnowszego sezonu drużyny (jak /trainer/overview).
"""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import insert

from app.national_distance_tables import define_tables as define_national
from app.pod_reka_tables import define_tables as define_pod_reka
from app.zprp_public import portal_rules as R
from app.zprp_public_geocode_tables import define_tables as define_geocode
from app.zprp_public_tables import define_tables as define_public

_MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.api", "app.zprp_public.portal",
            "app.zprp_public.extras", "app.zprp_public.geocode", "app.pod_reka")


def _forget_modules():
    # Moduły z `from app.db import database` trzymają bazę z poprzedniego testu - czyścimy
    # wszystkie poza czystymi regułami (`*_rules`, bez bazy).
    # Atrybut pakietu też: `from app.zprp_public import portal` bierze go przed sys.modules.
    pkg = sys.modules.get("app.zprp_public")
    for name in [n for n in sys.modules if n in _MODULES or (n.startswith("app.zprp_public.") and not n.endswith("_rules"))]:
        sys.modules.pop(name, None)
        child = name.rsplit(".", 1)[1]
        if pkg is not None and name.startswith("app.zprp_public.") and hasattr(pkg, child):
            delattr(pkg, child)


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    tables = list(define_public(metadata)) + list(define_national(metadata)) + list(define_pod_reka(metadata))
    tables.append(define_geocode(metadata))
    url = f"sqlite:///{tmp_path / 'scope.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in tables:
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    _forget_modules()
    portal = importlib.import_module("app.zprp_public.portal")
    portal._nodes_cache.update(at=0.0, index={})
    portal._map_cache.clear()
    from app.zprp_public import enrich

    enrich._seasons_cache.update(at=float("-inf"), seasons={}, current=None)  # pamięć z innego testu
    yield portal, fake.database, {t.name: t for t in tables}
    _forget_modules()


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T):
    """Klub c1 (drużyna t1) z 7 rozegranymi i 8 nadchodzącymi meczami w S1 + 1 wycofanym;
    zawodnik p1 z 12 meczami w dwóch sezonach (S0 bez zgłoszenia do składu)."""
    now = datetime.now().replace(microsecond=0)
    ins = lambda table, **v: db.execute(insert(T[table]).values(**v))  # noqa: E731
    await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
    await ins("zprp_public_seasons", season_id="S0", start_year=2025, name="2025/26", active=False, **_h())
    await ins("zprp_public_associations", association_id="A1", name="Śląski ZPRP", **_h())
    for cid, name in (("c1", "KS Kielce"), ("c2", "Piast Gliwice")):
        await ins("zprp_public_clubs", club_id=cid, association_id="A1", name=name, city="Kielce", archived=False, **_h())
    for tid, cid, sid, sname in (("t1", "c1", "S1", "2026/27"), ("t2", "c2", "S1", "2026/27"),
                                 ("t1", "c1", "S0", "2025/26"), ("t2", "c2", "S0", "2025/26")):
        await ins("zprp_public_teams", team_id=tid, season_id=sid, club_id=cid, season_name=sname,
                  name="Kielce SPR" if tid == "t1" else "Piast", **_h())
    await ins("zprp_public_competitions", competition_id="K1", season_id="S1", name="Liga", **_h())
    await ins("zprp_public_competitions", competition_id="K0", season_id="S0", name="Liga 25", **_h())
    base = dict(competition_name="Liga", home_team_id="t1", away_team_id="t2", home_club_id="c1", away_club_id="c2",
                home_team_name="Kielce SPR", away_team_name="Piast", **_h())
    for i in range(7):
        await ins("zprp_public_matches", match_id=f"p{i}", season_id="S1", competition_id="K1",
                  scheduled_at=now - timedelta(days=30 - i), score_home=30 + i, score_away=20, **base)
    for i in range(8):
        await ins("zprp_public_matches", match_id=f"u{i}", season_id="S1", competition_id="K1",
                  scheduled_at=now + timedelta(days=2 + i), **base)
    await ins("zprp_public_matches", match_id="w1", season_id="S1", competition_id="K1",
              scheduled_at=now + timedelta(days=20), withdrawn=True, **base)
    for i in range(5):  # sezon S0: najlepszy mecz kariery (15 bramek) poza 10 ostatnimi
        await ins("zprp_public_matches", match_id=f"o{i}", season_id="S0", competition_id="K0",
                  scheduled_at=now - timedelta(days=400 - i), score_home=25, score_away=24, **base)
    await ins("zprp_public_players", player_id="pl", first_name="Ala", last_name="Nowak", birth_year=2008, **_h())
    await ins("zprp_public_team_rosters", team_id="t1", season_id="S1", player_id="pl", shirt_number="7", active=True, **_h())
    await ins("zprp_public_team_rosters", team_id="t1", season_id="S0", player_id="old", shirt_number="9", active=True, **_h())
    await ins("zprp_public_players", player_id="old", first_name="Ola", last_name="Dawna", birth_year=2007, **_h())
    for i in range(7):
        await ins("zprp_public_match_players", match_id=f"p{i}", team_id="t1", player_id="pl", side="home", goals=3, **_h())
    for i in range(5):
        await ins("zprp_public_match_players", match_id=f"o{i}", team_id="t1", player_id="pl", side="home",
                  goals=15 if i == 0 else 1, two_minutes=1, **_h())


def _run(env, factory):
    module, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await factory(module)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_liczniki_meczow_z_pelnej_listy():
    now = datetime(2026, 10, 22, 12, 0)
    cards = [
        {"score_home": 1, "score_away": 0, "scheduled_at": now - timedelta(days=1)},
        {"score_home": None, "score_away": None, "scheduled_at": now + timedelta(days=1)},
        {"score_home": None, "score_away": None, "scheduled_at": now - timedelta(hours=1)},   # w toku = przed nami
        {"score_home": None, "score_away": None, "scheduled_at": now - timedelta(days=2)},    # czeka na wynik
        {"score_home": None, "score_away": None, "scheduled_at": now + timedelta(days=3), "withdrawn": True},
        {"score_home": None, "score_away": None, "scheduled_at": None},
    ]
    counts = R.match_counts(cards, now)
    assert counts == {"all": 6, "played": 1, "upcoming": 3, "today": 1, "pending": 1, "withdrawn": 1}
    assert counts["all"] == counts["played"] + counts["upcoming"] + counts["pending"] + counts["withdrawn"]


def test_klub_i_druzyna_licza_caly_sezon_a_nie_podglad(env):
    async def go(m):
        return await m.club_overview("c1", "S1"), await m.team_overview("t1", "S1")

    club, team = _run(env, go)
    # Podgląd zostaje po 5 (zgodność), ale liczniki i pełna lista są z całego sezonu.
    assert len(club["recent_matches"]) == 5 and len(club["upcoming_matches"]) == 5
    assert len(club["matches"]) == 16 and club["match_counts"]["all"] == 16
    assert club["match_counts"]["played"] == 7 == club["stats"]["played"]
    assert club["match_counts"]["upcoming"] == 8 and club["match_counts"]["withdrawn"] == 1
    assert team["upcoming_count"] == 8 and len(team["upcoming_matches"]) == 5
    assert team["match_counts"]["played"] == team["stats"]["played"] == 7
    assert team["match_counts"]["all"] == len(team["matches"]) == 16


def test_zawodnik_bez_limitu_i_jeden_zakres(env):
    async def go(m):
        return (await m.player_overview("pl"), await m.player_matches("pl", ""),
                await m.player_matches("pl", "S1"), await m.player_matches("pl", "S0"))

    over, career, s1, s0 = _run(env, go)
    assert len(over["recent_matches"]) == 10                              # podgląd
    assert over["matches_count"] == over["totals"]["matches"] == 12        # nagłówek = kariera
    assert career["count"] == len(career["matches"]) == career["totals"]["matches"] == 12
    by_season = {s["season_id"]: s for s in over["seasons"]}
    # Zakres sezonu: licznik, kafle i lista z jednego miejsca, zgodne z wierszem sezonu w przeglądzie.
    for scope, sid in ((s1, "S1"), (s0, "S0")):
        assert scope["count"] == len(scope["matches"]) == scope["totals"]["matches"] == by_season[sid]["matches"]
        assert scope["totals"]["goals"] == by_season[sid]["goals"]
    assert s1["count"] + s0["count"] == career["count"]
    # „Wszystkie” nigdy mniejsze niż jeden sezon.
    assert career["count"] >= max(s1["count"], s0["count"])
    # Sezon bez zgłoszenia do składu ma nazwę z tabeli sezonów, a drużyny z protokołów.
    assert by_season["S0"]["season_name"] == "2025/26"
    assert by_season["S0"]["teams"][0] == {"team_id": "t1", "team_name": "Kielce SPR", "matches": 5}
    assert [s["season_id"] for s in over["seasons"]] == ["S1", "S0"]
    # Najlepszy mecz kariery jest poza 10 ostatnimi - opis i tak przychodzi z serwera.
    best = over["totals"]["best_match"]
    assert best["goals"] == 15 and best["match_id"] == "o0"
    assert best["home_team_name"] == "Kielce SPR" and best["competition_name"] == "Liga" and best["scheduled_at"]
    assert all(c["match_id"] != "o0" for c in over["recent_matches"])
    assert s0["matches"][0]["player_line"]["goals"] in (1, 15)


def test_zawodnik_nieznany_404(env):
    from fastapi import HTTPException

    async def go(m):
        with pytest.raises(HTTPException):
            await m.player_matches("nikt", "")
        return True

    assert _run(env, go)


def test_sklad_trenera_tylko_z_najnowszego_sezonu(env):
    async def go(_m):
        pod_reka = importlib.import_module("app.pod_reka")
        return await pod_reka.trainer_roster(session={"team_ids_json": ["t1"]})

    roster = _run(env, go)
    assert [r["player_id"] for r in roster["items"]] == ["pl"]   # „old” był w składzie t1 tylko w S0
    assert roster["count"] == 1 and roster["items"][0]["season_id"] == "S1"
