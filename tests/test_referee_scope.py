"""Profil sędziego: kariera bez limitów, jeden zakres dla wszystkich sekcji, wyszukiwarka = kariera.

Zgłoszenie (WITKOWICZ Radosław): nagłówek „100 meczów” (lista ucięta do 100), chipy sezonów
sumowały się do 162, wyszukiwarka mówiła 74, a mapa i kluby liczyły inny sezon niż pasek liczb.
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
from app.zprp_public import referee_stats as RS
from app.zprp_public_tables import define_tables as define_public

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras")


# ---------------------------------------------------------------------------
# Reguły (czyste)
# ---------------------------------------------------------------------------


def test_zakres_domyslny_biezacy_albo_ostatni_z_meczami():
    order = ["S1", "S0", "Sm"]
    assert RS.pick_season("", {"S1": 3, "S0": 5}, "S1", order) == "S1"
    assert RS.pick_season("", {"S0": 5}, "S1", ["S0"]) == "S0"          # bieżący pusty -> ostatni z meczami
    assert RS.pick_season("S0", {"S1": 3}, "S1", order) == "S0"
    assert RS.pick_season("all", {"S1": 3}, "S1", order) == RS.ALL_SEASONS
    assert RS.pick_season(" Wszystkie ", {"S1": 3}, "S1", order) == RS.ALL_SEASONS


def test_kariera_bez_limitu_z_grup():
    groups = [{"season_id": "S1", "competition_id": "K1", "n": 10}, {"season_id": "S0", "competition_id": "K0", "n": 63},
              {"season_id": "S0", "competition_id": "K2", "n": 50}, {"season_id": "Sm", "competition_id": "K3", "n": 39}]
    out = RS.career_totals(groups)
    assert out["matches"] == 162 and out["seasons"] == 3 and out["competitions"] == 4
    assert out["by_season"] == {"S1": 10, "S0": 113, "Sm": 39}


def test_miasta_bez_wspolrzednych_licza_sie_w_notce():
    rows = [
        {"match_id": "a", "referee_1_id": "r1", "venue_city": "Kielce", "venue_name": "H1", "score_home": 1, "score_away": 0},
        {"match_id": "b", "referee_1_id": "r1", "venue_city": "Kielce", "venue_name": "H1", "score_home": 1, "score_away": 0},
        {"match_id": "c", "referee_1_id": "r1", "venue_city": "Wieś Nieznana", "venue_name": "H2", "score_home": 1, "score_away": 0},
        {"match_id": "d", "referee_1_id": "r1", "venue_city": None, "venue_name": None, "score_home": 1, "score_away": 0},
    ]
    out = RS.summarize(rows, "r1", {}, venue_key=lambda n, c: f"{n}|{c}", display_city=lambda c: str(c))
    RS.attach_geo(out, {"Kielce": (50.87, 20.63)})
    assert out["unlocated"] == {"cities": 1, "matches": 2, "names": ["Wieś Nieznana"]}
    assert out["km"]["matches_counted"] + out["unlocated"]["matches"] == out["matches"] == 4
    assert out["venues_count"] == 2


# ---------------------------------------------------------------------------
# Trasy na małej bazie
# ---------------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    tables = list(define_public(metadata)) + list(define_national(metadata))
    try:  # pamięć geokodera (jeśli jest w tej wersji) - żeby trasy nie trafiały w MagicMock
        from app.zprp_public_geocode_tables import define_tables as define_geo

        tables.append(define_geo(metadata))
    except ImportError:
        pass
    url = f"sqlite:///{tmp_path / 'ref.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in tables:
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    extras = importlib.import_module("app.zprp_public.extras")
    extras.clear_cache()
    importlib.import_module("app.zprp_public.enrich").invalidate()
    portal = importlib.import_module("app.zprp_public.portal")
    yield extras, portal, fake.database, {t.name: t for t in tables}
    # Także atrybuty pakietu: `from app.zprp_public import portal` w innym teście nie może
    # dostać modułu związanego z tą (już zamkniętą) bazą.
    pkg = sys.modules.get("app.zprp_public")
    for name in MODULES:
        sys.modules.pop(name, None)
        if pkg is not None:
            pkg.__dict__.pop(name.rsplit(".", 1)[1], None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


S0_MATCHES = 120  # więcej niż dawny limit listy (100)


async def _seed(db, T):
    now = datetime.now().replace(microsecond=0)

    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    for sid, year, name, active in (("S1", 2026, "2026/27", True), ("S0", 2025, "2025/26", False), ("Sm", 2024, "2024/25", False)):
        await ins("zprp_public_seasons", season_id=sid, start_year=year, name=name, active=active, **_h())
    for cid, name, city in (("c1", "KS Kielce", "Kielce"), ("c2", "Piast Gliwice", "Gliwice"), ("c3", "Trzeci", "Opole")):
        await ins("zprp_public_clubs", club_id=cid, name=name, city=city, archived=False, logo_url=f"https://l/{cid}.png", **_h())
    for comp, sid, cat in (("K1", "S1", "Seniorzy"), ("K0", "S0", "Seniorzy"), ("J0", "S0", "Juniorzy"), ("Km", "Sm", "Seniorzy")):
        await ins("zprp_public_competitions", competition_id=comp, season_id=sid, name=f"Liga {comp}", category=cat, gender="M", **_h())
    for city, lat, lon in (("Kielce", 50.87, 20.63), ("Opole", 50.67, 17.92), ("Gliwice", 50.29, 18.67)):
        await ins("national_distance_cities", city_key=city.lower(), name=city, name_key=city.lower(), latitude=lat,
                  longitude=lon, province="x", observations=10)

    n = 0

    async def match(sid, comp, days_ago, *, r1="r1", r1_name="WITKOWICZ Radosław", r2="r2", r2_name="PARA Adam",
                    city="Kielce", hall="Hala Kielce", played=True, home="c1", away="c2"):
        nonlocal n
        n += 1
        await ins("zprp_public_matches", match_id=f"m{n}", season_id=sid, competition_id=comp, competition_name=f"Liga {comp}",
                  home_team_id=f"t{home}", away_team_id=f"t{away}", home_club_id=home, away_club_id=away,
                  home_team_name=home, away_team_name=away, score_home=25 if played else None, score_away=22 if played else None,
                  scheduled_at=now - timedelta(days=days_ago), venue_name=hall, venue_city=city,
                  referee_1_id=r1, referee_1_name=r1_name, referee_2_id=r2, referee_2_name=r2_name, **_h())

    # S1 (bieżący): 2 rozegrane + 1 przed nami, jeden w Opolu.
    await match("S1", "K1", 10)
    await match("S1", "K1", 3, city="Opole", hall="Hala Opole", home="c3", away="c1")
    await match("S1", "K1", -2, played=False)
    # S0: 120 meczów w dwóch rozgrywkach; co dziesiąty bez miasta hali (miasto gospodarza = Gliwice).
    for i in range(S0_MATCHES):
        no_city = i % 10 == 0
        await match("S0", "K0" if i % 3 else "J0", 400 - i, city=None if no_city else ("Kielce" if i % 2 else "Opole"),
                    hall=None if no_city else "Hala", home="c2" if no_city else "c1", away="c3")
    # Sm: 4 mecze, w terminarzu BEZ nazwiska sędziego (wyszukiwarka liczyła tylko wiersze z nazwiskiem).
    for i in range(4):
        await match("Sm", "Km", 800 - i, r1_name="", city="Wieś Nieznana")
    # r3 gwizdał tylko w S0 - domyślny zakres to ostatni sezon z meczami.
    await match("S0", "K0", 300, r1="r3", r1_name="TRZECI Jan", r2="r4", r2_name="CZWARTY Ewa")


def run(env, factory):
    extras, portal, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await factory(extras, portal)
        finally:
            await db.disconnect()

    return asyncio.run(go())


TOTAL = 3 + S0_MATCHES + 4


def test_profil_kariera_bez_limitu(env):
    async def go(x, _p):
        return await x.referee_profile("r1", 1000), await x.referee_profile("r1", 0)

    full, light = run(env, go)
    assert full["matches_total"] == TOTAL and full["career"]["matches"] == TOTAL
    assert full["career"]["seasons"] == 3 and full["career"]["competitions"] == 4
    assert sum(s["matches"] for s in full["seasons"]) == TOTAL
    assert [s["season_id"] for s in full["seasons"]] == ["S1", "S0", "Sm"] and full["seasons"][0]["is_current"] is True
    assert len(full["matches"]) == TOTAL and full["matches_truncated"] is False   # starsze klienty liczą z listy
    assert light["matches"] == [] and light["matches_total"] == TOTAL and light["matches_truncated"] is True
    assert full["default_season_id"] == "S1" and full["current_season_id"] == "S1"
    assert full["name"] == "WITKOWICZ Radosław"
    assert sum(c["matches"] for c in full["competitions"]) == TOTAL


def test_statystyki_wszystkie_sezony(env):
    async def go(x, _p):
        return await x.referee_stats("r1", "all"), await x.referee_matches("r1", "all", 1000, 0)

    st, ms = run(env, go)
    assert st["scope"] == "all" and st["season"]["season_id"] == "all" and st["season"]["all"] is True
    assert st["matches"] == TOTAL == st["career"]["matches"] == ms["count"] == len(ms["items"])
    assert sum(c["matches"] for c in st["by_competition"]) == TOTAL
    assert st["km"]["matches_counted"] + st["unlocated"]["matches"] == TOTAL
    assert st["unlocated"]["names"] == ["Wieś Nieznana"]
    assert {c["city"] for c in st["cities"] if c["lat"] is not None} == {"Kielce", "Opole", "Gliwice"}
    assert st["next"]["match_id"] == "m3"


def test_kazda_sekcja_ten_sam_zakres(env):
    async def go(x, _p):
        out = {}
        for sid in ("S1", "S0", "Sm", "all"):
            out[sid] = (await x.referee_stats("r1", sid), await x.referee_matches("r1", sid, 1000, 0))
        return out, await x.referee_profile("r1", 0)

    out, prof = run(env, go)
    chips = {s["season_id"]: s["matches"] for s in prof["seasons"]}
    chips["all"] = prof["matches_total"]
    for sid, (st, ms) in out.items():
        n = st["matches"]
        assert n == chips[sid] == ms["count"] == len(ms["items"]), sid
        assert st["season"]["season_id"] == ms["season"]["season_id"] == sid
        assert sum(c["matches"] for c in st["by_competition"]) == n
        assert sum(c["matches"] for c in st["by_category"]) == n
        assert sum(c["matches"] for c in st["cities"]) + st["no_city_matches"] == n
        assert st["finished"] == ms["finished"]
        if st["km"]:
            assert st["km"]["matches_counted"] + st["unlocated"]["matches"] == n
        assert all(i["season_id"] == sid for i in ms["items"]) or sid == "all"
        assert st["partners"][0]["matches"] <= n and all(c["matches"] <= n for c in st["clubs"])
    # S0: mecze bez miasta hali trafiają na mapę z miastem gospodarza.
    s0 = out["S0"][0]
    assert s0["no_city_matches"] == 0 and any(c["city"] == "Gliwice" for c in s0["cities"])
    assert out["S1"][0]["next"]["match_id"] == "m3" and out["S0"][0]["next"] is None


def test_domyslny_zakres_ostatni_sezon_z_meczami(env):
    async def go(x, _p):
        return await x.referee_stats("r3", ""), await x.referee_profile("r3", 0), await x.referee_stats("r1", "")

    st3, prof3, st1 = run(env, go)
    assert st3["season"]["season_id"] == "S0" and st3["season"]["is_current"] is False and st3["matches"] == 1
    assert prof3["default_season_id"] == "S0"
    assert st1["season"]["season_id"] == "S1" and st1["season"]["is_current"] is True and st1["matches"] == 3
    assert st1["career"]["matches"] == TOTAL


def test_wyszukiwarka_liczy_kariere_jak_profil(env):
    async def go(x, portal):
        index = await portal._build_referee_index()
        portal._REF_INDEX.update(rows=index)
        prof = await x.referee_profile("r1", 0)
        hits = portal._match_referees(portal._REF_INDEX["rows"], "witkowicz", 5)
        return index, prof, hits

    index, prof, hits = run(env, go)
    r1 = next(e for e in index if e["referee_id"] == "r1")
    assert r1["matches"] == TOTAL == prof["matches_total"]   # także 4 mecze bez nazwiska w terminarzu
    assert r1["name"] == "WITKOWICZ Radosław"
    assert hits[0]["referee_id"] == "r1" and hits[0]["matches"] == TOTAL
