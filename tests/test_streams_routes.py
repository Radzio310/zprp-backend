"""Transmisje: przebieg pętli i trasy na małej bazie SQLite, sieć podmieniona (respx)."""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx
import sqlalchemy
from databases import Database
from sqlalchemy import insert, select

from app.national_distance_tables import define_tables as define_national
from app.stream_tables import define_tables as define_streams
from app.zprp_public_tables import define_tables as define_public

FIX = Path(__file__).parent / "fixtures" / "streams"
WARSAW = ZoneInfo("Europe/Warsaw")
MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.streams.store", "app.streams.routes",
           "app.streams.worker", "app.streams.cache")
HP = "UCabcdefghijklmnopqrstuv"
CLUB_TV = "UCwybrzezegdansktv000001"


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    tables = list(define_public(metadata)) + list(define_national(metadata)) + list(define_streams(metadata))
    url = f"sqlite:///{tmp_path / 'streams.db'}"
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
    mods = types.SimpleNamespace(
        store=importlib.import_module("app.streams.store"),
        routes=importlib.import_module("app.streams.routes"),
        worker=importlib.import_module("app.streams.worker"),
        cache=importlib.import_module("app.streams.cache"),
        net=importlib.import_module("app.streams.net"),
    )
    importlib.import_module("app.zprp_public.enrich").invalidate()

    async def public_dns(host):
        return ["8.8.8.8"]

    monkeypatch.setattr(mods.net, "resolver", public_dns)
    yield mods, fake.database, {t.name: t for t in tables}
    for name in MODULES:
        sys.modules.pop(name, None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


def _z(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class World:
    """Czas „teraz” i mecze względem dzisiejszej daty (bez dat na sztywno)."""

    def __init__(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        local = self.now.astimezone(WARSAW).replace(tzinfo=None)
        self.k1 = local + timedelta(minutes=10)   # LC: Handball Polska nadaje
        self.k2 = local + timedelta(minutes=5)    # Superliga: link ZPRP (Facebook)
        self.k3 = local + timedelta(minutes=15)   # I liga: tylko wyszukiwanie
        self.k1_utc = self.k1.replace(tzinfo=WARSAW).astimezone(timezone.utc)
        self.k3_utc = self.k3.replace(tzinfo=WARSAW).astimezone(timezone.utc)

    async def seed(self, db, T):
        def ins(table, /, **v):
            return db.execute(insert(T[table]).values(**v))

        await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
        clubs = (("c1", "MKS Wybrzeże Gdańsk", "wybrzeze-gdansk.pl"), ("c2", "Pogoń Szczecin", None),
                 ("c3", "Industria Kielce", None), ("c4", "Orlen Wisła Płock", None),
                 ("c5", "KPR Ostrovia Ostrów", None), ("c6", "Siódemka Huras Legnica", None))
        for cid, name, site in clubs:
            await ins("zprp_public_clubs", club_id=cid, name=name, website=site, archived=False, **_h())
        comps = (("LC", "Liga Centralna mężczyzn"), ("OS", "ORLEN Superliga"), ("I", "I liga mężczyzn"))
        for cid, name in comps:
            await ins("zprp_public_competitions", competition_id=cid, season_id="S1", name=name, gender="M",
                      category="Seniorzy", **_h())
        rows = (("m1", "LC", "LCM/12", "c1", "c2", self.k1, None), ("m2", "OS", "SM/5", "c3", "c4", self.k2,
                "https://www.facebook.com/kielcehandball/videos/123"), ("m3", "I", "IM/2", "c5", "c6", self.k3, None))
        names = dict((cid, name) for cid, name, _ in clubs)
        for mid, comp, code, h, a, when, stream in rows:
            await ins("zprp_public_matches", match_id=mid, season_id="S1", competition_id=comp, competition_name=dict(comps)[comp],
                      match_code=code, home_club_id=h, away_club_id=a, home_team_name=names[h], away_team_name=names[a],
                      home_team_id=f"t{h}", away_team_id=f"t{a}", scheduled_at=when, stream_url=stream, **_h())

    # --- odpowiedzi „sieci” ---------------------------------------------------

    def feed(self):
        text = (FIX / "channel_feed.xml").read_text(encoding="utf-8")
        return text.replace("18.10.2026", self.k1.strftime("%d.%m.%Y"))

    def videos(self):
        title = f"LIVE: Wybrzeże Gdańsk - Pogoń Szczecin | Liga Centralna mężczyzn | {self.k1.strftime('%d.%m.%Y')}"
        return {
            "LCvid000001": {"id": "LCvid000001", "snippet": {
                "publishedAt": _z(self.now - timedelta(days=3)), "channelId": HP, "title": title,
                "channelTitle": "Handball Polska", "liveBroadcastContent": "live",
                "thumbnails": {"high": {"url": "https://i.ytimg.com/vi/LCvid000001/hqdefault_live.jpg"}}},
                "contentDetails": {"duration": "P0D"},
                "liveStreamingDetails": {"actualStartTime": _z(self.k1_utc - timedelta(minutes=3))}},
            "SRvid000001": {"id": "SRvid000001", "snippet": {
                "publishedAt": _z(self.now - timedelta(hours=5)), "channelId": "UCrandomproducer00000001",
                "title": "Ostrovia Ostrów Wlkp. - Siódemka Legnica LIVE", "channelTitle": "Sport Wielkopolska",
                "liveBroadcastContent": "upcoming"},
                "contentDetails": {"duration": "P0D"},
                "liveStreamingDetails": {"scheduledStartTime": _z(self.k3_utc)}},
        }

    def api(self, request):
        params = dict(request.url.params)
        endpoint = request.url.path.rsplit("/", 1)[-1]
        assert params.get("key") == "test-key"
        if endpoint == "videos":
            known = self.videos()
            items = [known[i] for i in params["id"].split(",") if i in known]
            return httpx.Response(200, json={"items": items})
        if endpoint == "channels":
            if params.get("forHandle") == "@HandballPolska":
                return httpx.Response(200, text=(FIX / "api_channels.json").read_text(encoding="utf-8"))
            if params.get("forHandle") == "@WybrzezeGdanskTV":
                return httpx.Response(200, json={"items": [{"id": CLUB_TV, "snippet": {"title": "Wybrzeże Gdańsk TV"}}]})
            return httpx.Response(200, json={"items": []})
        if endpoint == "search":
            return httpx.Response(200, json={"items": [{"id": {"kind": "youtube#video", "videoId": "SRvid000001"}}]})
        return httpx.Response(404)

    def rss(self, request):
        params = dict(request.url.params)
        if params.get("channel_id") == HP:
            return httpx.Response(200, text=self.feed())
        if params.get("playlist_id"):
            return httpx.Response(200, text=(FIX / "playlist_feed.xml").read_text(encoding="utf-8"))
        return httpx.Response(404)


def mock_net(world):
    mock = respx.mock(assert_all_called=False)
    mock.get(host="www.googleapis.com").mock(side_effect=world.api)
    mock.get(host="www.youtube.com", path="/feeds/videos.xml").mock(side_effect=world.rss)
    mock.get(f"https://www.youtube.com/channel/{HP}/live").mock(
        return_value=httpx.Response(200, text=(FIX / "live_page_offline.html").read_text(encoding="utf-8")))
    mock.get("https://wybrzeze-gdansk.pl").mock(
        return_value=httpx.Response(200, text=(FIX / "club_home.html").read_text(encoding="utf-8")))
    mock.get("https://pilkareczna.com/live").mock(
        return_value=httpx.Response(200, text=(FIX / "hint_page.html").read_text(encoding="utf-8")))
    mock.route().mock(return_value=httpx.Response(404))
    return mock


def run(env, factory):
    mods, db, T = env
    world = World()

    async def go():
        await db.connect()
        try:
            await world.seed(db, T)
            with mock_net(world):
                return await factory(mods, db, T, world)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_przebieg_petli_i_trasy_publiczne(env):
    async def go(mods, db, T, world):
        yt = mods.net.YouTube(mods.store.quota_take, key="test-key")
        counters = await mods.worker.run_cycle(world.now, yt)
        streams = [dict(r) for r in await db.fetch_all(select(T["match_streams"]))]
        channels = [dict(r) for r in await db.fetch_all(select(T["stream_channels"]))]
        quota = await mods.store.quota_status()
        r = mods.routes
        payload = {
            "match": await r.match_streams("m1"), "match2": await r.match_streams("m2"),
            "now": await r.streams_now(), "comp": await r.competition_streams("LC"),
            "club": await r.club_streams("c1"),
        }
        # Drugi przebieg chwilę później nic nie dubluje.
        yt2 = mods.net.YouTube(mods.store.quota_take, key="test-key")
        await mods.worker.run_cycle(world.now + timedelta(minutes=1), yt2)
        again = await db.fetch_all(select(T["match_streams"]))
        return counters, streams, channels, quota, payload, len(again)

    counters, streams, channels, quota, payload, count_again = run(env, go)
    by_match = {s["match_id"]: s for s in streams}
    assert set(by_match) == {"m1", "m2", "m3"} and count_again == 3
    m1 = by_match["m1"]
    assert (m1["video_id"], m1["state"], m1["confidence"], m1["verified_by"], m1["source"]) == (
        "LCvid000001", "live", "official", "api", "rss")
    m2 = by_match["m2"]
    assert (m2["platform"], m2["state"], m2["confidence"], m2["source"]) == ("facebook", "link", "official", "zprp")
    m3 = by_match["m3"]
    assert (m3["video_id"], m3["state"], m3["confidence"], m3["source"]) == ("SRvid000001", "upcoming", "confirmed", "search")
    keyed = {c["key"]: c for c in channels}
    hp = keyed["youtube:@handballpolska"]
    assert hp["channel_id"] == HP and m1["channel_ref"] == hp["id"] and hp["error"] is None
    # Mecz za 10 min: kanał wraca do kolejki za 5 min (okno 60 min przed meczem).
    assert hp["next_check_at"].replace(tzinfo=None) - hp["last_checked_at"].replace(tzinfo=None) == timedelta(minutes=5)
    assert keyed["youtube-playlist:PL3NkJuwI5L5d7vPRyvudHKhgP8Q1AMGeP"]["channel_id"] == "UCczarnypiotrusmedia0001"
    club_tv = keyed[f"youtube:{CLUB_TV}"]
    assert (club_tv["club_id"], club_tv["kind"], club_tv["verified"], club_tv["discovered_from"]) == ("c1", "club", False, "club_website")
    assert keyed["facebook:https://www.facebook.com/wybrzezegdansk"]["club_id"] == "c1"
    assert not any(c.get("channel_id") == "UCzprpofficialchannel001" for c in channels)  # stopka strony klubu
    assert quota["search_calls"] == 1 and quota["units_used"] >= 100 and counters["api_calls"] >= 4

    match = payload["match"]
    first = match["streams"][0]
    assert first["embed_url"] == "https://www.youtube-nocookie.com/embed/LCvid000001" and first["state"] == "live"
    assert first["channel"] == {"title": "Handball Polska", "url": "https://www.youtube.com/@HandballPolska",
                                "kind": "official", "verified": True}
    kinds = [(w["kind"], w["url"]) for w in match["where_to_watch"]]
    assert ("channel", "https://www.youtube.com/@HandballPolska") in kinds
    assert ("channel", "https://www.youtube.com/@WybrzezeGdanskTV") in kinds and kinds[-1][0] == "facebook"
    assert match["updated_at"]
    assert [w["platform"] for w in payload["match2"]["where_to_watch"]][:3] == ["polsat_sport", "polsat_box_go", "emocje_tv"]
    now = payload["now"]
    assert [s["match_id"] for s in now["live"]] == ["m1"] and now["live"][0]["match"]["home_team_name"] == "MKS Wybrzeże Gdańsk"
    assert [s["match_id"] for s in now["soon"]] == ["m3"]
    if world_day_same(world_k2_date_offset=5):
        assert [t["match"]["match_id"] for t in now["today_tv"]] == ["m2"] and now["today_tv"][0]["links"][0]["kind"] == "tv"
    assert [s["match_id"] for s in payload["comp"]["upcoming"]] == ["m1"]
    assert payload["comp"]["where_to_watch"][0]["url"] == "https://www.youtube.com/@HandballPolska"
    club = payload["club"]
    assert {c["platform"] for c in club["channels"]} == {"youtube", "facebook"}
    assert [s["match_id"] for s in club["recent"]] == ["m1"]


def world_day_same(world_k2_date_offset: int) -> bool:
    """Mecz za X minut jest jeszcze dziś (test o 23:58 nie może kłamać o „dzisiejszych”)."""
    now = datetime.now(WARSAW)
    return (now + timedelta(minutes=world_k2_date_offset)).date() == now.date()


def test_bez_klucza_api_tylko_rss_i_linki(env):
    async def go(mods, db, T, world):
        yt = mods.net.YouTube(mods.store.quota_take, key="")
        await mods.worker.run_cycle(world.now, yt)
        return [dict(r) for r in await db.fetch_all(select(T["match_streams"]))], await mods.store.quota_status()

    streams, quota = run(env, go)
    by_match = {s["match_id"]: s for s in streams}
    # Uchwyt Handball Polska ustalony ze strony kanału? Tu strona nie odpowiada (404) - kanał czeka,
    # a link ZPRP i tak jest. Wyszukiwania i API - zero.
    assert set(by_match) == {"m2"} and quota["units_used"] == 0 and quota["search_calls"] == 0


def test_admin_kanal_i_ukrycie(env):
    async def go(mods, db, T, world):
        r = mods.routes
        yt = mods.net.YouTube(mods.store.quota_take, key="test-key")
        await mods.worker.run_cycle(world.now, yt)
        added = await r.admin_add_channel(r.ChannelBody(url="https://www.youtube.com/@NowyKanal", club_id="c2", title="Pogoń TV"))
        again = await r.admin_add_channel(r.ChannelBody(handle="NowyKanal", verified=True))
        listing = await r.admin_channels()
        before = await r.match_streams("m1")
        sid = before["streams"][0]["id"]
        hidden = await r.admin_patch_stream(sid, r.StreamPatch(hidden=True))
        after = await r.match_streams("m1")
        m3 = (await r.match_streams("m3"))["streams"][0]
        demoted = await r.admin_patch_stream(m3["id"], r.StreamPatch(confidence="possible"))
        # Pętla nie podnosi pewności ustawionej przez admina.
        await mods.worker.run_cycle(world.now + timedelta(minutes=4), mods.net.YouTube(mods.store.quota_take, key="test-key"))
        row = await mods.store.stream_by_id(m3["id"])
        with pytest.raises(Exception) as missing:
            await r.match_streams("nie-ma")
        return added, again, listing, hidden, after, demoted, row, missing.value

    added, again, listing, hidden, after, demoted, row, missing = run(env, go)
    assert (added["kind"], added["club_id"], added["handle"], added["verified"]) == ("club", "c2", "@NowyKanal", False)
    assert again["id"] == added["id"] and again["verified"] is True and again["title"] == "Pogoń TV"
    assert any(c["handle"] == "@NowyKanal" for c in listing["channels"]) and "units_left" in listing["quota"]
    assert hidden["hidden"] is True and after["streams"] == []
    assert demoted["confidence"] == "possible" and row["confidence"] == "possible" and row["verified_by"] == "admin"
    assert getattr(missing, "status_code", None) == 404


def test_admin_niepoprawny_adres(env):
    async def go(mods, db, T, world):
        r = mods.routes
        with pytest.raises(Exception) as bad:
            await r.admin_add_channel(r.ChannelBody(url="https://example.com/klub"))
        return bad.value

    assert getattr(run(env, go), "status_code", None) == 422


def test_limit_api_rezerwa_na_odswiezanie(env, monkeypatch):
    async def go(mods, db, T, world):
        store = mods.store
        monkeypatch.setattr(store, "DAILY_UNITS", 300)
        monkeypatch.setattr(store, "SEARCH_RESERVE", 150)
        monkeypatch.setattr(store, "DAILY_SEARCHES", 5)
        first = await store.quota_take(100, True)       # 100 <= 300-150
        second = await store.quota_take(100, True)      # 200 > 150 - rezerwa
        small = await store.quota_take(1, False)        # odświeżanie nadal działa
        rest = await store.quota_take(200, False)       # 301 > 300
        return first, second, small, rest, await store.quota_status()

    first, second, small, rest, status = run(env, go)
    assert (first, second, small, rest) == (True, False, True, False)
    assert status["units_used"] == 101 and status["search_calls"] == 1
