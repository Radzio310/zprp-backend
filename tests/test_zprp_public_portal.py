"""Portal publiczny: reguły miast i statystyk oraz trasy na małej bazie SQLite.

`app.db` łączy się z Postgresem przy imporcie, więc podmieniamy go modułem z
samymi tabelami hurtowni i tabelą miast (reszta kodu działa naprawdę).
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

from app.zprp_public import portal_rules as R
from app.zprp_public_tables import define_tables as define_public
from app.national_distance_tables import define_tables as define_national


# ---------------------------------------------------------------------------
# Reguły
# ---------------------------------------------------------------------------


def test_warianty_nazwy_miasta():
    assert R.city_variants("43-300 Bielsko-Biała") == ["bielsko biala"]
    assert "krakow" in R.city_variants("m. Kraków (Nowa Huta)")
    assert "kedzierzyn kozle" in R.city_variants("Kędzierzyn-Koźle")
    assert R.city_variants("") == []
    assert R.display_city("gm. Kielce - Dyoniczak") == "Kielce"


def test_wybor_miasta_z_wielu_kandydatow_wg_wojewodztwa():
    index = R.build_index([
        {"key": "a", "name": "Zalesie", "name_key": "zalesie", "lat": 1.0, "lon": 1.0, "province": "slaskie", "weight": 50},
        {"key": "b", "name": "Zalesie", "name_key": "zalesie", "lat": 2.0, "lon": 2.0, "province": "podlaskie", "weight": 5},
    ])
    assert R.resolve_city("Zalesie", index)["key"] == "a"          # bez wskazówki: najczęstsze
    assert R.resolve_city("Zalesie", index, "podlaskie")["key"] == "b"  # wskazówka z okręgu
    assert R.resolve_city("Nieistniejące", index) is None


def test_rezerwa_skorowidza_i_brak_wspolrzednych():
    index = R.build_index([{"key": "x", "name": "Pusta", "name_key": "pusta", "lat": None, "lon": None, "province": "", "weight": 1}])
    assert R.resolve_city("Pusta", index) is None
    fallback = lambda key: [{"key": "gz:1", "name": "Pusta", "lat": 50.0, "lon": 20.0, "province": "malopolskie", "weight": 10}] if key == "pusta" else []
    hit = R.resolve_city("Pusta", index, "", fallback)
    assert hit["source"] == "gazetteer" and hit["lat"] == 50.0


def test_bilans_i_forma():
    matches = [
        {"scheduled_at": 1, "home_team_id": "a", "away_team_id": "b", "score_home": 30, "score_away": 20},
        {"scheduled_at": 2, "home_team_id": "c", "away_team_id": "a", "score_home": 25, "score_away": 25},
        {"scheduled_at": 3, "home_team_id": "a", "away_team_id": "d", "score_home": 10, "score_away": 12},
        {"scheduled_at": 4, "home_team_id": "a", "away_team_id": "e", "score_home": None, "score_away": None},
    ]
    rec = R.team_record(matches, lambda side, m: m[f"{side}_team_id"] == "a")
    assert (rec["played"], rec["wins"], rec["draws"], rec["losses"]) == (3, 1, 1, 1)
    assert rec["goals_for"] == 65 and rec["goals_against"] == 57
    assert rec["form"] == ["W", "D", "L"]
    assert rec["home_played"] == 2 and rec["away_played"] == 1


def test_radar_normalizuje_do_maksimum():
    items = [{"metrics": {"goals": 10, "x": None}}, {"metrics": {"goals": 20, "x": 3}}]
    scale = R.normalise_for_radar(items, ["goals", "x"])
    assert scale["max"] == {"goals": 20, "x": 3}
    assert items[0]["radar"] == {"goals": 0.5, "x": 0.0}
    assert items[1]["radar"]["goals"] == 1.0


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------


@pytest.fixture
def portal(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    nat = define_national(metadata)
    url = f"sqlite:///{tmp_path / 'portal.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in list(pub) + list(nat):
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.api", "app.zprp_public.portal"):
        sys.modules.pop(name, None)
    module = importlib.import_module("app.zprp_public.portal")
    module._nodes_cache.update(at=0.0, index={})
    module._map_cache.clear()
    yield module, fake.database, {t.name: t for t in list(pub) + list(nat)}
    for name in ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.api", "app.zprp_public.portal"):
        sys.modules.pop(name, None)


def _hash(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T):
    now = datetime.now().replace(microsecond=0)
    await db.execute(insert(T["zprp_public_seasons"]).values(season_id="S1", start_year=2026, name="2026/27", active=True, **_hash()))
    await db.execute(insert(T["zprp_public_associations"]).values(association_id="A1", name="Śląski ZPRP", **_hash()))
    for cid, name, city in (("c1", "KS Kielce", "26-600 Kielce"), ("c2", "Piast Gliwice", "Gliwice"), ("c3", "Dziwny Klub", "Wioska Nieznana")):
        await db.execute(insert(T["zprp_public_clubs"]).values(club_id=cid, association_id="A1", name=name, city=city, archived=False, **_hash()))
    for tid, cid, name in (("t1", "c1", "Kielce SPR"), ("t2", "c2", "Piast U18")):
        await db.execute(insert(T["zprp_public_teams"]).values(team_id=tid, season_id="S1", club_id=cid, season_name="2026/27", name=name, **_hash()))
    await db.execute(insert(T["zprp_public_competitions"]).values(competition_id="K1", season_id="S1", name="Liga", **_hash()))
    await db.execute(insert(T["zprp_public_rounds"]).values(round_id="R1", competition_id="K1", name="Runda 1", **_hash()))
    await db.execute(insert(T["zprp_public_matchdays"]).values(matchday_id="D1", round_id="R1", number=1, sequence=1, name="Kolejka 1", **_hash()))
    base = dict(season_id="S1", competition_id="K1", round_id="R1", matchday_id="D1", competition_name="Liga",
                home_team_id="t1", away_team_id="t2", home_club_id="c1", away_club_id="c2",
                home_team_name="Kielce SPR", away_team_name="Piast U18", **_hash())
    await db.execute(insert(T["zprp_public_matches"]).values(match_id="m1", scheduled_at=now - timedelta(days=7), score_home=30, score_away=25,
                                                              referee_1_name="Jan Sędzia", venue_city="Kielce", **base))
    await db.execute(insert(T["zprp_public_matches"]).values(match_id="m2", scheduled_at=now + timedelta(minutes=5), venue_city="26-600 Kielce",
                                                              **{**base, "home_team_id": "t2", "away_team_id": "t1", "home_club_id": "c2", "away_club_id": "c1"}))
    await db.execute(insert(T["zprp_public_players"]).values(player_id="p1", first_name="Ala", last_name="Nowak", birth_year=2008, **_hash()))
    await db.execute(insert(T["zprp_public_team_rosters"]).values(team_id="t1", season_id="S1", player_id="p1", shirt_number="7", active=True, **_hash()))
    await db.execute(insert(T["zprp_public_match_players"]).values(match_id="m1", team_id="t1", player_id="p1", side="home", goals=9,
                                                                    penalty_attempts=3, penalty_goals=2, two_minutes=1, **_hash()))
    await db.execute(insert(T["zprp_public_standings"]).values(competition_id="K1", table_id="T", group_id="", team_id="t1", position=1,
                                                                team_name="Kielce SPR", matches=1, wins=1, points=2, source_hash="h"))
    await db.execute(insert(T["zprp_public_scorers"]).values(competition_id="K1", player_id="p1", team_id="t1", goals=9, matches=1, **_hash()))
    await db.execute(insert(T["national_distance_cities"]).values(city_key="kielce", name="Kielce", name_key="kielce", latitude=50.87, longitude=20.63,
                                                                   province="swietokrzyskie", observations=40))


def run(portal, coro_factory):
    module, db, T = portal

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await coro_factory(module)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_mapa_miast_klubow_z_niedopasowanymi(portal, monkeypatch):
    async def go(m):
        async def no_gazetteer():
            return lambda key: [{"key": "gz:g", "name": "Gliwice", "lat": 50.29, "lon": 18.67, "province": "slaskie", "weight": 180000}] if key == "gliwice" else []
        monkeypatch.setattr(m, "_gazetteer_lookup", no_gazetteer)
        return await m.handball_map(season_id="S1")

    data = run(portal, go)
    by_city = {c["city"]: c for c in data["cities"]}
    assert by_city["Kielce"]["lat"] == 50.87 and by_city["Kielce"]["voivodeship"] == "świętokrzyskie"
    assert by_city["Kielce"]["clubs"][0]["name"] == "KS Kielce" and by_city["Kielce"]["teams_count"] == 1
    assert by_city["Kielce"]["matches_today"] == 1          # m2 dziś, miejsce „26-600 Kielce"
    assert by_city["Gliwice"]["source"] == "gazetteer"
    assert data["unmatched"]["count"] == 1 and data["unmatched"]["items"][0]["city"] == "Wioska Nieznana"
    assert data["stats"]["clubs"] == 3 and data["stats"]["clubs_on_map"] == 2


def test_profile_klubu_druzyny_zawodnika(portal):
    async def go(m):
        return (await m.club_overview("c1", ""), await m.team_overview("t1", ""), await m.player_overview("p1"))

    club, team, player = run(portal, go)
    assert club["players_count"] == 1 and club["teams_count"] == 1
    assert club["stats"]["played"] == 1 and club["stats"]["wins"] == 1 and club["stats"]["goals_for"] == 30
    assert [c["match_id"] for c in club["recent_matches"]] == ["m1"]
    assert [c["match_id"] for c in club["upcoming_matches"]] == ["m2"]
    assert all(c["status"] != "live" for c in club["recent_matches"] + club["upcoming_matches"])
    assert club["top_scorers"][0]["goals"] == 9 and club["standings"][0]["position"] == 1
    assert team["roster"][0]["stats"]["goals"] == 9 and team["stats"]["played"] == 1 and len(team["matches"]) == 2
    assert team["discipline"]["matches"] == 1 and team["discipline"]["per_match"] is not None
    assert player["totals"]["goals"] == 9 and player["totals"]["penalty_accuracy"] == pytest.approx(0.667, abs=1e-3)
    assert player["seasons"][0]["season_id"] == "S1" and player["totals"]["best_match"]["match_id"] == "m1"
    assert player["recent_matches"][0]["player_line"]["goals"] == 9


def test_mecz_terminarz_szukanie_porownanie(portal, monkeypatch):
    async def go(m):
        async def no_gazetteer():
            return None
        monkeypatch.setattr(m, "_gazetteer_lookup", no_gazetteer)
        match = await m.match_overview("m1")
        schedule = await m.competition_schedule("K1", "")
        found = await m.search_global(q="kiel", limit_per_type=5)
        cmp_players = await m.compare(type="club", ids="c1,c2", season_id="S1")
        return match, schedule, found, cmp_players

    match, schedule, found, cmp_ = run(portal, go)
    assert match["home"]["score"] == 30 and match["lineups"]["home"][0]["goals"] == 9
    assert match["officials"] == [{"role": "Sędzia", "id": None, "name": "Jan Sędzia"}]
    assert match["events_available"] is False and match["status"] == "finished"
    assert match["head_to_head"] == []                      # m2 jest przyszły
    assert schedule["rounds"][0]["matchdays"][0]["matches"][0]["match_id"] in {"m1", "m2"}
    assert schedule["count"] == 2 and schedule["unassigned"] == []
    assert [c["city"] for c in found["cities"]] == ["Kielce"]
    assert found["clubs"][0]["name"] == "KS Kielce" and found["matches"]
    assert [i["id"] for i in cmp_["items"]] == ["c1", "c2"]
    assert cmp_["items"][0]["radar"]["wins_regular"] == 1.0 and cmp_["max"]["wins_regular"] == 1


def test_korekty_nakladane_przy_odczycie_i_wycofywane(portal):
    from app.zprp_public import corrections as C

    async def go(m):
        C.invalidate()
        assert await C.entity_exists("club", "c1") and not await C.entity_exists("club", "nope")
        first = await C.create("club", "c1", "name", "KS Kielce 1", "literówka", "tester")
        await C.create("club", "c1", "logo_url", "https://x.example/l.png", None, "tester")
        second = await C.create("club", "c1", "name", "Korona Kielce", None, "tester")   # zastępuje pierwszą
        await C.create("player", "p1", "last_name", "Kowalska", None, "tester")
        with pytest.raises(ValueError):
            C.validate("club", "source_json", "x")
        with pytest.raises(ValueError):
            C.validate("club", "logo_url", "javascript:alert(1)")
        club = await m.club_overview("c1")
        match = await m.match_overview("m1")
        player = await m.player_overview("p1")
        assert await C.revoke(second["correction_id"], "tester") and not await C.revoke(first["correction_id"], "tester")
        after = await m.club_overview("c1")
        return club, match, player, after

    club, match, player, after = run(portal, go)
    assert club["club"]["name"] == "Korona Kielce" and club["club"]["corrected_fields"] == ["logo_url", "name"]
    assert club["recent_matches"][0]["home_logo_url"] == "https://x.example/l.png"
    assert match["home"]["club_name"] == "Korona Kielce" and match["home"]["logo_url"] == "https://x.example/l.png"
    assert player["player"]["last_name"] == "Kowalska"
    assert after["club"]["name"] == "KS Kielce"          # wycofanie przywraca dane źródłowe


def test_retry_after_i_kolory_herbu():
    from datetime import datetime, timedelta, timezone
    from app.pod_reka_login_rules import AttemptLimiter

    limiter = AttemptLimiter(limit=2, window=timedelta(minutes=10))
    now = datetime.now(timezone.utc)
    limiter.fail("ip:1", now=now - timedelta(minutes=4))
    limiter.fail("ip:1", now=now - timedelta(minutes=1))
    assert limiter.blocked("ip:1", now=now)
    assert 5 * 60 <= limiter.retry_after("ip:1", now=now) <= 6 * 60 + 2

    import io
    from PIL import Image
    from app.zprp_public.crest import extract_colors

    img = Image.new("RGBA", (40, 40), (255, 255, 255, 255))
    for x in range(40):
        for y in range(40):
            if x < 20:
                img.putpixel((x, y), (200, 20, 30, 255))
            elif y < 20:
                img.putpixel((x, y), (20, 40, 200, 255))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    colors = extract_colors(buf.getvalue())
    assert colors["primary"].startswith("#c") and colors["secondary"].startswith("#1") and colors["text"] == "#ffffff"
    assert extract_colors(b"<svg/>") is None


def test_team_record_tolerates_missing_schedule_dates():
    from datetime import datetime
    from app.zprp_public import portal_rules as R

    matches = [
        {"scheduled_at": datetime(2026, 10, 1), "score_home": 20, "score_away": 10, "home_club_id": "a", "away_club_id": "b"},
        {"scheduled_at": None, "score_home": 15, "score_away": 15, "home_club_id": "b", "away_club_id": "a"},
    ]
    rec = R.team_record(matches, lambda side, m: m.get(f"{side}_club_id") == "a")
    assert rec["played"] == 2 and rec["wins"] == 1 and rec["draws"] == 1


def test_skladu_zamienione_stronami_i_brak_bramek():
    from app.zprp_public import match_rules as MR

    # 212530: wynik 44:24, a sumy w kluczach gosp/gosc to 24 i 44
    assert MR.lineups_swapped(24, 44, 44, 24) is True
    assert MR.lineups_swapped(44, 24, 44, 24) is False
    assert MR.lineups_swapped(0, 0, 26, 26) is False          # 208152: brak bramek, nie zgadujemy
    assert MR.lineups_swapped(10, 10, 10, 10) is False
    assert MR.lineups_swapped(0, 30, 30, 0) is False          # jednostronne dane - bez zamiany
    assert MR.goals_known(0, 0, 26, 26) is False
    assert MR.goals_known(0, 0, 0, 0) is True
    assert MR.goals_known(44, 24, 44, 24) is True


def test_szukanie_sedziow_bez_ogonkow_i_wielkosci(portal):
    async def go(m):
        rows = [
            {"referee_id": "1", "name": "Żółkiewski Łukasz", "matches": 10},
            {"referee_id": "2", "name": "Zółkowska Anna", "matches": 40},
            {"referee_id": "3", "name": "Kowalski Jan", "matches": 5},
        ]
        found = m._match_referees(rows, "ZOLK", 5)
        both = m._match_referees(rows, "lukasz zolkiewski", 5)
        none = m._match_referees(rows, "x", 5)
        route = await m.search_global(q="sedzia", limit_per_type=5)
        return found, both, none, route

    found, both, none, route = run(portal, go)
    assert [r["referee_id"] for r in found] == ["2", "1"]     # więcej meczów wyżej przy równym trafieniu
    assert [r["referee_id"] for r in both] == ["1"]
    assert none == []
    assert route["referees"] == []


def test_invalidate_caches_czysci_indeks_sedziow_i_pamiec_extras(portal):
    from app.zprp_public import extras

    portal = portal[0]
    portal._REF_INDEX.update(at=1e12, rows=[{"referee_id": "1"}])
    portal._map_cache["x"] = (0.0, {})
    extras._cache["venue-index"] = (0.0, [])
    portal.invalidate_caches()
    assert portal._REF_INDEX["rows"] == [] and not portal._map_cache and not extras._cache
