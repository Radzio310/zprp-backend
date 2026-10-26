"""Ekran „Statystyki" - trasy /api/v1/handball/stats/* na małej bazie SQLite."""

import asyncio
import importlib
import json
import sys
import types
from datetime import datetime, time, timedelta, timezone
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import JSON, BigInteger, Column, DateTime, Integer, String, Table, insert, select

from app.national_distance_tables import define_tables as define_national
from app.zprp_public_stats_tables import define_tables as define_stats
from app.zprp_public_tables import define_tables as define_public

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.zprp_public.live", "app.zprp_public.stats")
WARSAW = ZoneInfo("Europe/Warsaw")
# Dziś 15:00 w Warszawie - mecze dnia są przed i po tej chwili, niezależnie od godziny uruchomienia testu.
LOCAL_NOW = datetime.combine(datetime.now(WARSAW).date(), time(15, 0))
UTC_NOW = LOCAL_NOW.replace(tzinfo=WARSAW).astimezone(timezone.utc)
SECRET = "Tajne Nazwisko"


def _proel_tables(metadata):
    saved = Table(
        "proel_matches", metadata,
        Column("match_number", String, primary_key=True), Column("data_json", JSON), Column("status", String),
        Column("zprp_match_id", String), Column("updated_at", DateTime(timezone=True)),
    )
    state = Table(
        "proel_match_state", metadata,
        Column("match_number", String, primary_key=True), Column("zprp_match_id", String),
        Column("rev", BigInteger), Column("live_started_at", DateTime(timezone=True)),
        Column("lease_until", DateTime(timezone=True)), Column("lease_epoch", Integer),
        Column("updated_at", DateTime(timezone=True)),
    )
    return saved, state


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    nat = define_national(metadata)
    snaps = define_stats(metadata)
    saved, state = _proel_tables(metadata)
    url = f"sqlite:///{tmp_path / 'stats.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in list(pub) + list(nat) + [snaps]:
        setattr(fake, table.name, table)
    fake.saved_matches = saved
    fake.proel_match_state = state
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    from app import time_pl

    monkeypatch.setattr(time_pl, "utc_now", lambda: UTC_NOW)
    stats = importlib.import_module("app.zprp_public.stats")
    importlib.import_module("app.zprp_public.enrich").invalidate()
    importlib.import_module("app.zprp_public.corrections").invalidate()
    stats.clear_cache()
    yield stats, fake.database, {t.name: t for t in list(pub) + list(nat) + [saved, state, snaps]}
    stats.clear_cache()
    for name in MODULES:
        sys.modules.pop(name, None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


NAMES = {"t1": "Pogoń Szczecin", "t2": "Wisła Płock", "t3": "Górnik Zabrze"}
CLUB = {"t1": "c1", "t2": "c2", "t3": "c3"}


def _ev(kind, team, t, player=7):
    return {"type": kind, "team": team, "player": player, "time": t, "half": 1 if t <= 1_800_000 else 2}


def _blob(match_id, host, guest, protocol, **extra):
    blob = {"matchConfig": {"matchId": match_id, "hostTeamName": NAMES[host], "guestTeamName": NAMES[guest], "halfTime": 30,
                            "hostPlayerCards": [{"number": 7, "fullName": SECRET}],
                            "guestPlayerCards": [{"number": 7, "fullName": "Jan Kowalski"}], "referee1": "Sędzia Stolikowy"},
            "protocol": protocol, "mainTime": 1_500_000, "isFirstHalf": True, "isGameRunning": True,
            "savedAtMs": int(UTC_NOW.timestamp() * 1000) - 5_000}
    blob.update(extra)
    return blob


async def _seed(db, T):
    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
    await ins("zprp_public_associations", association_id="12", name="ŚLĄSKIE", **_h())
    await ins("zprp_public_associations", association_id="7", name="MAZOWIECKIE", **_h())
    for cid, aid in (("c1", "12"), ("c2", "7"), ("c3", "12")):
        await ins("zprp_public_clubs", club_id=cid, association_id=aid, name=f"Klub {cid}", archived=False,
                  logo_url=f"https://l/{cid}.png", **_h())
    for comp, name, gender, cat, assoc in (("OS", "Superliga Mężczyzn", "M", "1", "Departament Rozgrywek"),
                                           ("JS", "Śląska Liga Juniorów", "M", "2", "ŚLĄSKIE"),
                                           ("JK", "Mazowiecka Liga Juniorek", "K", "2", "MAZOWIECKIE")):
        await ins("zprp_public_competitions", competition_id=comp, season_id="S1", name=name, gender=gender, category=cat,
                  association_name=assoc, **_h())
    for pid, first, last in (("p1", "Adam", "Strzelec"), ("p7", "Jan", "Kowalski")):
        await ins("zprp_public_players", player_id=pid, first_name=first, last_name=last, **_h())
    await ins("zprp_public_team_rosters", team_id="t1", season_id="S1", player_id="p7", shirt_number="7", active=True, **_h())

    def match(mid, comp, h, a, at, sh=None, sa=None, **kw):
        return dict(match_id=mid, season_id="S1", competition_id=comp, competition_name=comp, match_code=kw.pop("code", f"X/{mid}"),
                    home_team_id=h, away_team_id=a, home_club_id=CLUB[h], away_club_id=CLUB[a],
                    home_team_name=NAMES[h], away_team_name=NAMES[a], scheduled_at=at, score_home=sh, score_away=sa,
                    referee_1_id="r1", referee_1_name="Sędzia Jeden", **kw, **_h())

    day = LOCAL_NOW.replace(hour=0)
    await ins("zprp_public_matches", **match("h1", "OS", "t1", "t2", LOCAL_NOW - timedelta(days=7), 30, 25, halftime_home=15, halftime_away=12))
    await ins("zprp_public_matches", **match("h2", "JS", "t1", "t3", LOCAL_NOW - timedelta(days=1), 40, 22))
    await ins("zprp_public_matches", **match("h3", "JK", "t2", "t3", LOCAL_NOW - timedelta(days=3), 20, 21, spectators=150))
    await ins("zprp_public_matches", **match("d1", "OS", "t1", "t2", day.replace(hour=12), 31, 30))
    await ins("zprp_public_matches", **match("d2", "JS", "t1", "t3", day.replace(hour=13)))
    await ins("zprp_public_matches", **match("d3", "JS", "t3", "t1", day.replace(hour=14, minute=30)))
    await ins("zprp_public_matches", **match("d4", "JK", "t2", "t3", day.replace(hour=18)))
    await ins("zprp_public_matches", **match("d5", "OS", "t2", "t1", day))

    for mid, side, team, goals, two in (("h1", "home", "t1", 12, 2), ("d1", "home", "t1", 10, 1)):
        await ins("zprp_public_match_players", match_id=mid, team_id=team, player_id="p1", side=side, shirt_number="9",
                  goals=goals, two_minutes=two, penalty_goals=2, penalty_attempts=3, **_h())

    utc = UTC_NOW
    finished_h1 = _blob("h1", "t1", "t2", [_ev("goal", "guest", 30_000), _ev("goal", "host", 90_000), _ev("goal", "host", 200_000),
                                          _ev("goal", "host", 260_000), _ev("teamTime", "guest", 300_000), _ev("goal", "host", 3_500_000)])
    await ins("proel_matches", match_number="X/h1", zprp_match_id="h1", status="approved", updated_at=utc - timedelta(days=7),
              data_json=finished_h1)
    finished_d2 = _blob("d2", "t1", "t3", [_ev("goal", "host", 60_000), _ev("goal", "guest", 120_000), _ev("goal", "host", 3_000_000)],
                        scoreHost=2, scoreGuest=1)
    await ins("proel_matches", match_number="X/d2", zprp_match_id="d2", status="finished", updated_at=utc - timedelta(minutes=30),
              data_json=finished_d2)
    live_d3 = _blob("d3", "t3", "t1", [_ev("goal", "guest", 600_000), _ev("goal", "host", 900_000), _ev("goal", "guest", 1_400_000),
                                       _ev("penalty1", "host", 1_450_000)], scoreHost=1, scoreGuest=2)
    await ins("proel_matches", match_number="X/d3", zprp_match_id="d3", status="in_progress", updated_at=utc - timedelta(seconds=20),
              data_json=live_d3)
    await ins("proel_match_state", match_number="X/d3", zprp_match_id="d3", rev=9, live_started_at=utc - timedelta(minutes=30),
              lease_until=utc + timedelta(seconds=60), updated_at=utc)
    test_d4 = _blob("d4", "t2", "t3", [_ev("goal", "host", 60_000)], scoreHost=1, scoreGuest=0)
    test_d4["matchConfig"]["isTest"] = True
    await ins("proel_matches", match_number="X/d4", zprp_match_id="d4", status="finished", updated_at=utc, data_json=test_d4)


def run(env, factory):
    module, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await factory(module, db, T)
        finally:
            await db.disconnect()

    return asyncio.run(go())


ALL = dict(gender="", category="", age="", level="", province="")


def test_filtry_i_sezon_spojne_w_zakresach(env):
    async def go(stats, db, T):
        filters = await stats.stats_filters(season_id="")
        full = await stats.stats_season(season_id="", **ALL)
        geo = await stats.stats_geo(season_id="", **ALL)
        per_cat = [await stats.stats_season(season_id="", **{**ALL, "category": c["key"]}) for c in filters["categories"]]
        per_prov = [await stats.stats_season(season_id="", **{**ALL, "province": p["key"]}) for p in filters["provinces"]]
        central = await stats.stats_season(season_id="", **{**ALL, "level": "central"})
        district = await stats.stats_season(season_id="", **{**ALL, "level": "district"})
        return filters, full, geo, per_cat, per_prov, central, district

    filters, full, geo, per_cat, per_prov, central, district = run(env, go)
    assert filters["season"]["season_id"] == "S1" and filters["defaults"]["season_id"] == "S1"
    assert {c["key"] for c in filters["categories"]} == {"OS", "J"}
    assert len(filters["provinces"]) == 16
    total = full["totals"]["matches"]
    assert total == 8 and full["totals"]["played"] == 4
    assert sum(s["totals"]["matches"] for s in per_cat) == total
    assert central["totals"]["matches"] + district["totals"]["matches"] == total
    unknown = (geo["unknown"] or {}).get("matches", 0)
    assert sum(s["totals"]["matches"] for s in per_prov) + unknown == total
    assert sum(p["goals"] for p in geo["provinces"]) + (geo["unknown"] or {}).get("goals", 0) == full["totals"]["goals"]
    top = full["top_scorers"][0]
    assert top["player"]["last_name"] == "Strzelec" and top["goals"] == 22 and top["matches"] == 2
    assert full["scope"]["season_id"] == "S1" and full["next_refresh_s"] == 600


def test_dzis_na_zywo_bez_podwojnego_liczenia_i_bez_nazwisk_z_proela(env):
    async def go(stats, db, T):
        return await stats.stats_today(**ALL), await stats.stats_today(**{**ALL, "province": "mazowieckie"})

    out, maz = run(env, go)
    assert out["date"] == LOCAL_NOW.date().isoformat() and out["next_refresh_s"] == 25
    c = out["counts"]
    assert (c["total"], c["played"], c["live"], c["upcoming"], c["no_hour"]) == (5, 2, 1, 2, 1)
    g = out["goals"]
    assert g["sources"] == {"zprp": 1, "proel": 1, "proel_live": 1}
    assert g["total"] == 61 + 3 + 3 and g["live"] == 3 and g["avg_per_match"] == 32.0
    assert out["highest_scoring"]["match_id"] == "d1"
    ticker = [e for e in out["ticker"] if e["match"]["match_id"] == "d3"]
    assert ticker and ticker[0]["live"] is True and ticker[0]["score"] == {"home": 1, "away": 2}
    # Bramka gościa (Pogoń, nr 7) -> zawodnik z publicznej kadry ZPRP, nie z karty ProEla.
    assert ticker[0]["player"]["player_id"] == "p7" and ticker[0]["player"]["last_name"] == "Kowalski"
    scorers = {(s["match"]["match_id"], s["number"]): s for s in out["top_scorers"]}
    assert scorers[("d1", 9)]["goals"] == 10 and scorers[("d1", 9)]["source"] == "zprp"
    assert scorers[("d3", 7)]["source"] == "proel"
    assert out["live"][0]["match_id"] == "d3" and out["live"][0]["minute"] == 26
    assert out["discipline"]["two_minutes"] >= 2
    assert out["comparison"]["weekday_avg"]["days"] == 1 and out["comparison"]["yesterday"]["matches"] == 1
    assert sum(r["matches"] for r in out["by_category"]) == 5
    assert SECRET not in json.dumps(out, default=str) and "Stolikowy" not in json.dumps(out, default=str)
    assert maz["counts"]["total"] == 2  # d4 (JK) + d5 (OS u gospodarza z mazowieckiego)


def test_trendy_proel_i_trwale_streszczenia(env):
    async def go(stats, db, T):
        trends = await stats.stats_trends(season_id="", **ALL)
        proel = await stats.stats_proel(season_id="", **ALL)
        rows = await db.fetch_all(select(T["zprp_public_stats_snapshots"].c.key))
        stats.clear_cache()
        read_again = await stats.refresh_proel()
        cycle = await stats.run_once()
        return trends, proel, sorted(r["key"] for r in rows), read_again, cycle

    trends, proel, keys, read_again, cycle = run(env, go)
    kinds = {r["kind"] for r in trends["records"]}
    assert {"highest_scoring_match", "biggest_win", "fastest_goal", "longest_run"} <= kinds
    assert trends["cumulative"]["total_goals"] == 55 + 62 + 41 + 61
    assert trends["facts"] and all(f["text"] for f in trends["facts"])
    assert proel["matches"] == 2  # h1 (zatwierdzony) + d2 (zakończony, wynik jeszcze tylko w protokole)
    assert proel["coverage"]["protocols"] == 2 and proel["first_goal_winner_pct"] is not None
    assert sum(x["goals"] for x in proel["goals_by_minute"]) == 8
    assert keys == ["proel:X/d2", "proel:X/d4", "proel:X/h1"]  # test zapisany jako „skip", w toku - wcale
    assert read_again == 0  # po restarcie pamięci streszczenia wracają z tabeli, bez czytania blobów
    assert cycle["season_id"] == "S1" and cycle["matches"] == 8
    assert SECRET not in json.dumps([trends, proel], default=str)


def test_nieznane_wojewodztwo_daje_pusty_zakres_nie_blad(env):
    async def go(stats, db, T):
        return await stats.stats_season(season_id="", **{**ALL, "province": "atlantyda"})

    out = run(env, go)
    assert out["totals"]["matches"] == 0 and out["top_scorers"] == []
