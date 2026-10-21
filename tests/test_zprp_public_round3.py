"""Pod Ręką runda 3: reguły (czyste) i trasy na małej bazie SQLite."""

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

from app.zprp_public import match_rules as MR
from app.zprp_public_tables import define_tables as define_public
from app.national_distance_tables import define_tables as define_national

# ---------------------------------------------------------------------------
# Reguły
# ---------------------------------------------------------------------------


def test_karne_z_payloadu_i_zero_zero():
    assert MR.parse_shootout({"dogrywka_karne_gosp": "4", "dogrywka_karne_gosc": "3", "Id": "1"}) == (4, 3)
    assert MR.parse_shootout({"0": [{"Id": "1", "dogrywka_karne_gosp": 2, "dogrywka_karne_gosc": "5"}]}) == (2, 5)
    assert MR.parse_shootout([[{"Id": "1", "dogrywka_karne_gosp": "0", "dogrywka_karne_gosc": "0"}]]) == (None, None)
    assert MR.parse_shootout({"Id": "1", "dogrywka_karne_gosp": None, "dogrywka_karne_gosc": None}) == (None, None)
    assert MR.parse_shootout(None) == (None, None)


def test_zwyciezca_i_sposob_rozstrzygniecia():
    assert MR.outcome({"score_home": 30, "score_away": 25}) == ("home", "regular")
    assert MR.outcome({"score_home": 20, "score_away": 20}) == (None, "regular")
    assert MR.outcome({"score_home": 28, "score_away": 28, "shootout_home": 3, "shootout_away": 4}) == ("away", "shootout")
    assert MR.outcome({"score_home": 10, "score_away": 0, "walkover_team_id": "t2", "winner": "1"}) == ("home", "walkover")
    assert MR.outcome({"score_home": None, "score_away": None}) == (None, "regular")


def test_numer_meczu_sezon_i_staff():
    assert MR.full_match_code("S/DzK/1") == "S/DzK/1"
    assert MR.full_match_code("12", "I liga") == "I liga/12"
    assert MR.full_match_code("", "x") is None
    seasons = {"S1": {"season_id": "S1", "name": "2026/27", "start_year": 2026, "active": True}}
    item = MR.apply_match_extras({"season_id": "S1", "score_home": 1, "score_away": 0, "match_code": "A/1"}, seasons, "S1", {})
    assert item["season_name"] == "2026/27" and item["is_current_season"] is True and item["winner_side"] == "home"
    staff = MR.staff_view({"role": "A", "function": "Trener", "source_json": {"upomnienie": "1", "2minuty": 2, "dyskwalifikacja": "0"}})
    assert staff["letter"] == "A" and staff["warnings"] == 1 and staff["two_minutes"] == 2 and "source_json" not in staff


def test_penalty_fields_bez_czasow_upstream():
    pf = MR.penalty_fields("1", 2, "0", "1")
    assert pf["warning_time"] is None and pf["two_minutes_times"] == [] and pf["disqualification_time"] is None
    assert pf["extra_penalty"] is True and pf["extra_penalty_time"] is None
    assert MR.penalty_fields(0, 0, 0, 0)["extra_penalty"] is False
    staff = MR.staff_view({"role": "A", "source_json": {"kd": "1"}})
    assert staff["extra_penalty"] is True and staff["penalty_attempts"] == 0


def test_tabela_serie_i_strzelcy():
    def m(h, a, sh, sa, **kw):
        return {"home_team_id": h, "away_team_id": a, "home_team_name": h, "away_team_name": a, "score_home": sh, "score_away": sa, **kw}

    table = MR.simulate_table([m("A", "B", 30, 20), m("B", "C", 25, 25), m("C", "A", 20, 21)])
    assert [r["team_id"] for r in table] == ["A", "C", "B"] and table[0]["points"] == 6 and table[1]["points"] == 1
    assert (MR.points_for(True, "regular"), MR.points_for(True, "walkover"), MR.points_for(False, "walkover")) == (3, 3, 0)
    assert (MR.points_for(True, "shootout"), MR.points_for(False, "shootout"), MR.points_for(False, "regular")) == (2, 1, 0)
    assert MR.streaks(["W", "W", "D", "W", "L", "L"]) == {
        "current": {"type": "L", "length": 2}, "longest_win": 2, "longest_unbeaten": 4, "longest_loss": 2}
    rows = [
        {"player_id": "1", "first_name": "A", "last_name": "A", "team_name": "T", "goals": 10, "matches": 2, "penalty_goals": 3, "penalty_attempts": 3},
        {"player_id": "1", "first_name": "A", "last_name": "A", "team_name": "T2", "goals": 2, "matches": 1, "penalty_goals": 0, "penalty_attempts": 1},
        {"player_id": "2", "first_name": "B", "last_name": "B", "team_name": "T", "goals": 12, "matches": 3, "penalty_goals": 1, "penalty_attempts": 2},
    ]
    top = MR.aggregate_scorers(rows, "goals")
    one = next(i for i in top if i["player_id"] == "1")
    assert one["goals"] == 12 and one["matches"] == 3 and one["team"] == "T" and one["pen_acc"] == 0.75
    assert [i["rank"] for i in top] == [1, 1]          # 12 bramek w 3 meczach u obu: remis
    by_acc = MR.aggregate_scorers(rows, "pen_acc")
    assert [i["player_id"] for i in by_acc] == ["1"]   # gracz 2 ma 2 próby < próg


def test_ics_i_adresy_zalacznikow():
    ics = MR.build_ics("Drużyna, A", [{"match_id": "9", "scheduled_at": datetime(2026, 10, 3, 18, 0),
                                       "home_team_name": "A", "away_team_name": "B", "venue_name": "Hala"}], "t1")
    assert ics.startswith("BEGIN:VCALENDAR") and "DTSTART:20261003T160000Z" in ics and "UID:9-t1@" in ics
    assert "X-WR-CALNAME:Drużyna\\, A" in ics and "\r\n" in ics
    ok = "https://baza.zprp.pl/zawody_zalaczniki/1_1.jpg"
    assert MR.is_allowed_attachment_url(ok)
    for bad in ("http://baza.zprp.pl/zawody_zalaczniki/a.jpg", "https://evil.pl/zawody_zalaczniki/a.jpg",
                "https://baza.zprp.pl/login", "https://baza.zprp.pl/zawody_zalaczniki/../x",
                "https://baza.zprp.pl@evil.pl/zawody_zalaczniki/a.jpg", ""):
        assert not MR.is_allowed_attachment_url(bad)
    items = MR.attachment_items(
        {"1": {"filename": "a.jpg", "label": "Skan", "file_url": ok, "is_pdf": False},
         "2": {"filename": "b.pdf", "label": "PDF", "file_url": ok.replace("1_1.jpg", "b.pdf"), "is_pdf": True},
         "3": {"filename": "c.jpg", "label": "Ukryty", "file_url": ok, "is_pdf": False}},
        ["3"], lambda u: "/p?u=" + u)
    assert [i["id"] for i in items] == ["1", "2"] and items[0]["thumb_url"] and items[1]["thumb_url"] is None
    assert items[1]["type"] == "pdf" and MR.venue_key("Hala Łódź", "90-001 Łódź") == "hala-lodz--lodz"


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras")


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    nat = define_national(metadata)
    url = f"sqlite:///{tmp_path / 'r3.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in list(pub) + list(nat):
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    extras = importlib.import_module("app.zprp_public.extras")
    extras.clear_cache()
    importlib.import_module("app.zprp_public.enrich").invalidate()
    yield extras, fake.database, {t.name: t for t in list(pub) + list(nat)}
    for name in MODULES:
        sys.modules.pop(name, None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T):
    now = datetime.now().replace(microsecond=0)

    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
    await ins("zprp_public_seasons", season_id="S0", start_year=2025, name="2025/26", active=False, **_h())
    await ins("zprp_public_associations", association_id="A1", name="Śląski ZPRP", **_h())
    for cid, name, city in (("c1", "KS Kielce", "Kielce"), ("c2", "Piast Gliwice", "Gliwice"), ("c3", "Trzeci", "Opole")):
        await ins("zprp_public_clubs", club_id=cid, association_id="A1", name=name, city=city, archived=False,
                  logo_url=f"https://l/{cid}.png", **_h())
    for tid, cid, name in (("t1", "c1", "Kielce"), ("t2", "c2", "Piast"), ("t3", "c3", "Trzeci")):
        await ins("zprp_public_teams", team_id=tid, season_id="S1", club_id=cid, season_name="2026/27", name=name, **_h())
    await ins("zprp_public_competitions", competition_id="K1", season_id="S1", association_id="A1", name="Liga",
              gender="M", category="Seniorzy", code="I", **_h())
    await ins("zprp_public_rounds", round_id="R1", competition_id="K1", name="Runda 1", **_h())
    for i in (1, 2, 3):
        await ins("zprp_public_matchdays", matchday_id=f"D{i}", round_id="R1", number=i, sequence=i, name=f"Kolejka {i}", **_h())
    base = dict(season_id="S1", competition_id="K1", round_id="R1", competition_name="Liga", **_h())
    club_of = {"t1": "c1", "t2": "c2", "t3": "c3"}

    def match(mid, day, h, a, sh, sa, days_ago, **kw):
        return dict(match_id=mid, matchday_id=day, home_team_id=h, away_team_id=a, home_club_id=club_of[h],
                    away_club_id=club_of[a], home_team_name=h, away_team_name=a, score_home=sh, score_away=sa,
                    scheduled_at=now - timedelta(days=days_ago), venue_name="Hala Kielce", venue_city="Kielce", **base, **kw)

    rows = [
        match("m1", "D1", "t1", "t2", 30, 20, 21, match_code="S/1", spectators=300, referee_1_id="r1", referee_1_name="Jan Sędzia"),
        match("m2", "D1", "t3", "t2", 25, 25, 20, shootout_home=3, shootout_away=5, match_code="S/2"),
        match("m3", "D2", "t2", "t1", 22, 22, 14, match_code="S/3"),
        match("m4", "D2", "t1", "t3", 28, 27, 13, match_code="S/4", spectators=900),
        match("m5", "D3", "t2", "t3", None, None, -3, match_code="S/5", referee_1_id="r1", referee_1_name="Jan Sędzia"),
    ]
    for r in rows:
        await ins("zprp_public_matches", **r)
    await ins("zprp_public_players", player_id="p1", first_name="Ala", last_name="Nowak", **_h())
    await ins("zprp_public_players", player_id="p2", first_name="Ola", last_name="Kot", **_h())
    await ins("zprp_public_match_players", match_id="m1", team_id="t1", player_id="p1", side="home", goals=12,
              penalty_goals=3, penalty_attempts=4, **_h())
    await ins("zprp_public_match_players", match_id="m1", team_id="t2", player_id="p2", side="away", goals=5,
              two_minutes=2, **_h())
    await ins("zprp_public_match_staff", match_id="m1", team_id="t1", person_id="s1", side="home", first_name="Jan",
              last_name="Trener", role="A", function="Trener", source_hash="h",
              source_json={"rola": "A", "upomnienie": "1", "2minuty": "0"})
    await ins("zprp_public_scorers", competition_id="K1", player_id="p1", team_id="t1", team_name="Kielce", goals=40,
              matches=4, penalty_goals=8, penalty_attempts=10, **_h())
    await ins("zprp_public_scorers", competition_id="K1", player_id="p2", team_id="t2", team_name="Piast", goals=22,
              matches=4, **_h())
    await ins("national_distance_cities", city_key="kielce", name="Kielce", name_key="kielce", latitude=50.87,
              longitude=20.63, province="swietokrzyskie", observations=40)


def run(env, factory):
    module, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await factory(module)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_karty_meczow_maja_pola_kontraktu(env):
    async def go(x):
        api = sys.modules["app.zprp_public.api"]
        portal = sys.modules["app.zprp_public.portal"]
        listing = await api.list_matches(competition_id="K1", team_id="", season_id="", date_from=None, date_to=None,
                                         limit=50, offset=0)
        detail = await api.match_details("m2")
        overview = await portal.match_overview("m2")
        sched = await portal.competition_schedule("K1", "")
        return listing, detail, overview, sched

    listing, detail, overview, sched = run(env, go)
    by_id = {m["match_id"]: m for m in listing["items"]}
    m2 = by_id["m2"]
    assert (m2["shootout_home"], m2["shootout_away"], m2["winner_side"], m2["decided_by"]) == (3, 5, "away", "shootout")
    assert m2["match_code_full"] == "S/2" and m2["season_name"] == "2026/27" and m2["is_current_season"] is True
    assert by_id["m1"]["decided_by"] == "regular" and by_id["m1"]["winner_side"] == "home"
    assert by_id["m5"]["winner_side"] is None
    assert detail["match"]["winner_side"] == "away" and overview["match"]["decided_by"] == "shootout"
    assert overview["home"]["shootout"] == 3
    cards = [c for r in sched["rounds"] for d in r["matchdays"] for c in d["matches"]] + sched["unassigned"]
    assert {c["match_id"]: c["winner_side"] for c in cards}["m2"] == "away"


def test_sztab_z_kartkami_w_szczegolach(env):
    async def go(x):
        api = sys.modules["app.zprp_public.api"]
        return await api.match_details("m1"), await sys.modules["app.zprp_public.portal"].match_overview("m1")

    detail, overview = run(env, go)
    for staff in (detail["staff"][0], overview["staff"][0]):
        assert staff["letter"] == "A" and staff["warnings"] == 1 and "source_json" not in staff


def test_zalaczniki_i_proxy(env, monkeypatch):
    async def go(x):
        async def fake(match_id):
            return [{"id": "1", "name": "Skan", "type": "image", "url": "/p", "thumb_url": "/p"}]

        monkeypatch.setattr(x, "_fetch_attachments", fake)
        resp = await x.match_attachments("1")
        bad_status = None
        try:
            await x.attachment_file(u="https://evil.example/zawody_zalaczniki/a.jpg")
        except Exception as exc:  # noqa: BLE001
            bad_status = getattr(exc, "status_code", None)
        bad_id = None
        try:
            await x.match_attachments("abc")
        except Exception as exc:  # noqa: BLE001
            bad_id = getattr(exc, "status_code", None)
        return resp, bad_status, bad_id

    resp, bad_status, bad_id = run(env, go)
    assert resp.headers["access-control-allow-origin"] == "*" and b"Skan" in resp.body
    assert bad_status == 400 and bad_id == 400


def test_strzelcy_wg_zakresu(env):
    async def go(x):
        common = dict(competition_id="", association_id="", season_id="", category="", gender="", limit=10)
        country = await x.scorers(scope="country", sort="goals", **common)
        comp = await x.scorers(scope="competition", sort="avg", **{**common, "competition_id": "K1"})
        empty = await x.scorers(scope="association", sort="goals", **{**common, "association_id": "NOPE"})
        return country, comp, empty

    country, comp, empty = run(env, go)
    first = country["items"][0]
    assert (first["rank"], first["player_id"], first["goals"], first["avg"], first["pen_goals"], first["pen_attempts"]) == (1, "p1", 40, 10.0, 8, 10)
    assert first["club_id"] == "c1" and first["club_logo_url"] == "https://l/c1.png" and first["name"] == "Ala Nowak"
    assert {"seasons", "categories", "genders", "associations"} <= set(country["filters"])
    assert country["filters"]["categories"] == ["Seniorzy"]
    assert comp["items"][0]["player_id"] == "p1" and empty["items"] == []


def test_hale(env):
    async def go(x):
        lst = await x.venues(q="kiel", limit=10, offset=0)
        det = await x.venue_details(lst["items"][0]["key"])
        return lst, det

    lst, det = run(env, go)
    assert lst["count"] == 1 and lst["items"][0]["name"] == "Hala Kielce"
    assert det["lat"] == 50.87 and {c["club_id"] for c in det["clubs"]} >= {"c1"}
    assert det["attendance_records"][0]["spectators"] == 900 and any(w["match_id"] == "m5" for w in det["week"])


def test_wykres_sezonu_ics_rekordy_h2h(env):
    async def go(x):
        chart = await x.team_season_chart("t1", "")
        ics = await x.team_calendar("t1", "")
        rec = await x.records(season_id="", scope="season")
        h2h = await x.head_to_head(club_a="c1", club_b="c2", limit=50)
        return chart, ics, rec, h2h

    chart, ics, rec, h2h = run(env, go)
    assert [r["result"] for r in chart["rounds"]] == ["W", "D", "W"]
    assert chart["rounds"][0]["position"] == 1 and chart["rounds"][-1]["points"] == 7
    assert chart["streaks"]["longest_win"] == 1 and chart["best_match"]["match_id"] == "m1"
    assert chart["best_match"]["margin"] == 10
    assert ics.media_type.startswith("text/calendar") and ics.body.count(b"BEGIN:VEVENT") == 3
    kinds = {i["kind"]: i for i in rec["items"]}
    assert kinds["highest_attendance"]["value"] == 900 and kinds["most_goals_player"]["value"] == 12
    assert kinds["most_goals_player"]["player_id"] == "p1" and kinds["biggest_win"]["match_id"] == "m1"
    assert kinds["shootout_matches"]["value"] == 1
    # Karta meczu-rekordu: obie drużyny z herbami, wynik, data i rozgrywki bez dodatkowych zapytań do ZPRP.
    card = kinds["biggest_win"]["match"]
    assert card["home_logo_url"] == "https://l/c1.png" and card["away_logo_url"] == "https://l/c2.png"
    assert (card["score_home"], card["score_away"], card["competition_name"]) == (30, 20, "Liga") and card["scheduled_at"]
    assert kinds["biggest_win"]["side"] == "home" and kinds["most_goals_player"]["side"] == "home"
    assert kinds["most_goals_player"]["player_name"] == "Ala Nowak" and kinds["most_goals_player"]["match"]["match_id"] == "m1"
    assert kinds["shootout_matches"]["match"] is None and kinds["shootout_matches"]["latest"]["match_id"] == "m2"
    assert (h2h["balance"]["a_wins"], h2h["balance"]["b_wins"], h2h["balance"]["draws"]) == (1, 0, 1)
    assert h2h["biggest_wins"]["a"]["match_id"] == "m1" and h2h["biggest_wins"]["b"] is None


def test_h2h_tylko_ta_sama_kategoria(env):
    module, db, T = env

    async def go(x):
        await db.execute(insert(T["zprp_public_competitions"]).values(
            competition_id="KJ", season_id="S1", association_id="A1", name="Liga Juniorów", gender="M",
            category="Juniorzy", code="J", **_h()))
        await db.execute(insert(T["zprp_public_matches"]).values(
            match_id="mj", season_id="S1", competition_id="KJ", competition_name="Liga Juniorów",
            home_team_id="t1", away_team_id="t2", home_club_id="c1", away_club_id="c2", home_team_name="t1",
            away_team_name="t2", score_home=10, score_away=31, scheduled_at=datetime.now() - timedelta(days=2), **_h()))
        every = await x.head_to_head(club_a="c1", club_b="c2", limit=50)
        seniors = await x.head_to_head(club_a="c1", club_b="c2", limit=50, category="Seniorzy", gender="M")
        juniors = await x.head_to_head(club_a="c1", club_b="c2", limit=50, category="Juniorzy")
        women = await x.head_to_head(club_a="c1", club_b="c2", limit=50, gender="K")
        overview = await sys.modules["app.zprp_public.portal"].match_overview("m1")
        return every, seniors, juniors, women, overview

    every, seniors, juniors, women, overview = run(env, go)
    assert {c["match_id"] for c in every["matches"]} == {"m1", "m3", "mj"}
    assert {c["match_id"] for c in seniors["matches"]} == {"m1", "m3"}
    assert [c["match_id"] for c in juniors["matches"]] == ["mj"] and juniors["balance"]["b_wins"] == 1
    assert women["matches"] == [] and women["total"] == 0
    assert all(c["competition_category"] == "Seniorzy" for c in seniors["matches"])
    assert [c["match_id"] for c in overview["head_to_head"]] == ["m3"]
    assert overview["match"]["competition_category"] == "Seniorzy" and overview["match"]["competition_gender"] == "M"


def test_kolejka_sedzia(env):
    async def go(x):
        return await x.round_review("K1", "2"), await x.referee_profile("r1", 100)

    review, ref = run(env, go)
    assert {c["match_id"] for c in review["results"]} == {"m3", "m4"}
    moves = {m["team_id"]: m for m in review["table_moves"]}
    assert moves["t1"]["position"] == 1 and moves["t1"]["previous_position"] == 1
    assert moves["t3"]["previous_position"] is not None
    assert ref["name"] == "Jan Sędzia" and ref["matches_total"] == 2 and ref["seasons"][0]["name"] == "2026/27"


def test_scorers_photo_and_player_competitions_order():
    rows = [{"player_id": "1", "first_name": "A", "last_name": "B", "goals": 3, "matches": 2,
             "photo_url": "https://baza.zprp.pl/foto/1.jpg"}]
    assert MR.aggregate_scorers(rows)[0]["photo_url"] == "https://baza.zprp.pl/foto/1.jpg"
    assert MR.aggregate_scorers([{**rows[0], "photo_url": ""}])[0]["photo_url"] is None
    comps = [{"season_id": "10", "goals": 5, "name": "a"}, {"season_id": "12", "goals": 1, "name": "b"},
             {"season_id": "11", "goals": 9, "name": "c"}, {"season_id": "12", "goals": 4, "name": "d"}]
    out = MR.sort_player_competitions(comps, "11")
    assert [c["name"] for c in out] == ["c", "d", "b", "a"]


def test_czasy_kar_z_protokolu_baza():
    from app.zprp_public import protocol_times as PT
    blob = {
        "matchConfig": {"hostPlayerCards": [{"number": 7, "fullName": "KOWALSKI Jan"}]},
        "protocol": [
            {"type": "penalty2", "team": "host", "player": 7, "time": 1_200_000},
            {"type": "penalty1", "team": "host", "player": 7, "time": 600_000},
            {"type": "warning", "team": "host", "player": 7, "time": 300_000},
            {"type": "disqualification", "team": "guest", "player": 9, "time": 1_805_000},
            {"type": "penaltyExtra", "team": "guest", "player": 9, "time": 1_900_000},
            {"type": "warning", "team": "guest", "player": "A", "time": 61_000},
            {"type": "penalty1", "team": "guest", "player": 9, "time": 3_600_000, "shootout": True},
        ],
    }
    ex = PT.extract_times(blob)
    players = [
        {"side": "home", "shirt_number": "7", "last_name": "Kowalski"},
        {"side": "home", "shirt_number": "7", "last_name": "Inny"},
        {"side": "away", "shirt_number": "9", "last_name": "X"},
    ]
    staff = [{"side": "away", "letter": "A"}, {"side": "home", "letter": "B"}]
    assert PT.apply_times(players, staff, ex) == 3
    assert players[0]["two_minutes_times"] == ["10:00", "20:00"] and players[0]["warning_time"] == "05:00"
    assert "two_minutes_times" not in players[1]
    assert players[2]["disqualification_time"] == "30:05" and players[2]["extra_penalty_time"] == "31:40"
    assert players[2]["extra_penalty"] is True and players[2].get("two_minutes_times") == []
    assert staff[0]["warning_time"] == "01:01" and "warning_time" not in staff[1]
    rows = [{"status": "in_progress", "zprp_match_id": "1"}, {"status": "finished", "zprp_match_id": "1"},
            {"status": "approved", "zprp_match_id": "2"}, {"status": "approved", "zprp_match_id": "1"}]
    assert PT.pick_row(rows, "1") == rows[3] and PT.pick_row(rows[:1], "1") is None


def test_wykres_sezonu_tylko_wlasna_grupa_i_tabela_zprp(env):
    """Rozgrywki z dwiema grupami pod jednym competition_id: symulacja nie miesza
    grup, a ostatni punkt wykresu to miejsce z tabeli ZPRP."""
    module, db, T = env

    async def go(x):
        now = datetime.now().replace(microsecond=0)
        for tid in ("t8", "t9"):
            await db.execute(insert(T["zprp_public_teams"]).values(
                team_id=tid, season_id="S1", club_id="c3", season_name="2026/27", name=tid, **_h()))
        # Druga grupa: wysoka wygrana przed pierwszą kolejką t1 - bez poprawki t8 wyprzedzał t1.
        await db.execute(insert(T["zprp_public_matches"]).values(
            match_id="g2", season_id="S1", competition_id="K1", competition_name="Liga", home_team_id="t8",
            away_team_id="t9", home_club_id="c3", away_club_id="c3", home_team_name="t8", away_team_name="t9",
            score_home=40, score_away=10, scheduled_at=now - timedelta(days=22), **_h()))
        for tid, pos, table in (("t1", 2, "G1"), ("t2", 3, "G1"), ("t3", 1, "G1"), ("t8", 1, "G2"), ("t9", 2, "G2")):
            await db.execute(insert(T["zprp_public_standings"]).values(
                competition_id="K1", table_id=table, group_id="", team_id=tid, position=pos, team_name=tid,
                matches=3 if tid == "t1" else 2, source_hash="h"))
        return await x.team_season_chart("t1", "")

    chart = run(env, go)
    assert chart["rounds"][0]["position"] == 1
    assert chart["table_size"] == 3
    assert chart["rounds"][-1]["position"] == 2 and chart["rounds"][-1]["official"] is True


def test_h2h_tylko_te_dwie_druzyny_przez_sezony(env):
    """Inna drużyna tego samego klubu i mecz klubu z samym sobą nie wchodzą do bilansu;
    ta sama drużyna ze starszego sezonu (inne team_id, ta sama nazwa) - tak."""
    module, db, T = env

    async def go(x):
        def row(mid, hid, hclub, hname, aid, aclub, aname, days):
            return dict(match_id=mid, season_id="S1", competition_id="K1", competition_name="Liga",
                        home_team_id=hid, away_team_id=aid, home_club_id=hclub, away_club_id=aclub,
                        home_team_name=hname, away_team_name=aname, score_home=20, score_away=18,
                        scheduled_at=datetime.now() - timedelta(days=days), **_h())
        for r in (
            row("old", "t1-old", "c1", "T1", "t2-old", "c2", "T2", 400),          # ta sama para, stary sezon
            row("mks", "t9", "c1", "Kielce MKS", "t2", "c2", "t2", 5),              # inna drużyna klubu A
            row("self", "t1", "c1", "t1", "t9", "c1", "Kielce MKS", 6),            # klub z samym sobą
        ):
            await db.execute(insert(T["zprp_public_matches"]).values(**r))
        overview = await sys.modules["app.zprp_public.portal"].match_overview("m1")
        by_name = await x.head_to_head(club_a="c1", club_b="c2", limit=50, team_a="t1", team_b="t2")
        return overview, by_name

    overview, by_name = run(env, go)
    assert {c["match_id"] for c in overview["head_to_head"]} == {"m3", "old"}
    assert {c["match_id"] for c in by_name["matches"]} == {"m1", "m3", "old"}


def test_sezony_historyczne_tylko_z_danymi(env):
    module, db, T = env

    async def go(x):
        await db.execute(insert(T["zprp_public_seasons"]).values(season_id="S9", start_year=2019, name="2019/20", active=False, **_h()))
        await db.execute(insert(T["zprp_public_seasons"]).values(season_id="S8", start_year=2018, name="2018/19", active=False, **_h()))
        await db.execute(insert(T["zprp_public_competitions"]).values(
            competition_id="KOLD", season_id="S9", association_id="A1", name="Stara liga", gender="M", category="Seniorzy", code="X", **_h()))
        return await sys.modules["app.zprp_public.api"].list_seasons(include_historical=True)

    out = run(env, go)
    ids = {s["season_id"] for s in out["items"]}
    assert "S9" in ids and "S8" not in ids and "S0" not in ids and "S1" in ids


def test_bilans_bez_remisow_tabela_h2h_wykres(env):
    """Z/Zk/Pk/P: karne rozbijają „Remisy” tabeli, H2H i wykres sezonu znają Zk/Pk."""
    module, db, T = env

    async def go(x):
        for tid, pos, w, d, lo, pts in (("t1", 1, 2, 0, 0, 6), ("t2", 2, 0, 1, 1, 2), ("t3", 3, 0, 1, 1, 1)):
            await db.execute(insert(T["zprp_public_standings"]).values(
                competition_id="K1", table_id="T", group_id="", team_id=tid, position=pos, team_name=tid,
                matches=2, wins=w, draws=d, losses=lo, points=pts, source_hash="h"))
        api = sys.modules["app.zprp_public.api"]
        table = await api.competition_standings("K1")
        h2h = await x.head_to_head(club_a="c2", club_b="c3", limit=50)
        chart = await x.team_season_chart("t2", "")
        team = await sys.modules["app.zprp_public.portal"].team_overview("t2")
        return table, h2h, chart, team

    table, h2h, chart, team = run(env, go)
    rec = {r["team_id"]: r["record"] for r in table["items"]}
    assert rec["t2"] == {"w": 0, "wk": 1, "lk": 0, "l": 1, "source": "matches"}
    assert rec["t3"] == {"w": 0, "wk": 0, "lk": 1, "l": 1, "source": "matches"}
    assert rec["t1"]["w"] == 2 and "extra_json" not in table["items"][0]
    bal = h2h["balance"]
    assert bal["a_wins"] == 1 and bal["a_wins_shootout"] == 1 and bal["draws"] == 0
    assert bal["a_record"] == {"w": 0, "wk": 1, "lk": 0, "l": 0} and bal["b_record"] == {"w": 0, "wk": 0, "lk": 1, "l": 0}
    by_match = {r["match_id"]: r for r in chart["rounds"]}
    assert by_match["m2"]["result_detail"] == "WK" and by_match["m2"]["result"] == "W"
    assert by_match["m2"]["decided_by"] == "shootout" and by_match["m1"]["result_detail"] == "L"
    assert chart["record"]["wk"] == 1 and chart["record"]["l"] == 1
    assert team["stats"]["record"] == {"w": 0, "wk": 1, "lk": 0, "l": 1}
    assert team["stats"]["form_detail"] == ["L", "WK"] and team["stats"]["draws"] == 1
    assert team["standings"][0]["record"]["wk"] == 1
