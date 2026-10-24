"""Skład z protokołu elektronicznego, gdy ZPRP jeszcze go nie opublikował, i kadencja odświeżania.

Zgłoszenie z 24.10.2026: Chrobry - Industria (Superliga, prowadzony LIVE w ProElu)
- na stronie meczu po końcu pięciu zawodników Chrobrego, wynik 0, Industria bez
nikogo. Szczegóły pobrane w trakcie wysyłki nie były pobierane ponownie przez
6 h, a mecz bez godziny (00:00) wypadał z limitu cyklu LIVE.
"""

import asyncio
import importlib
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import JSON, BigInteger, Column, DateTime, Integer, String, Table, insert

from app.zprp_public import ondemand as OD
from app.zprp_public import proel_lineup_rules as PL
from app.zprp_public_tables import define_tables as define_public
from app.national_distance_tables import define_tables as define_national

NOW = datetime(2026, 10, 24, 20, 18, tzinfo=timezone.utc)
WARSAW = ZoneInfo("Europe/Warsaw")


# ---------------------------------------------------------------------------
# Kadencja (czyste funkcje)
# ---------------------------------------------------------------------------


def test_kompletny_protokol_wymaga_obu_skladow_wyniku_i_zgodnych_bramek():
    assert OD.lineups_complete(14, 15, 30, 28, 30, 28)
    assert OD.lineups_complete(14, 15, 30, 28, 0, 0)          # źródło bez bramek zawodników
    assert not OD.lineups_complete(5, 0, None, None)          # zgłoszenie z 24.10
    assert not OD.lineups_complete(14, 15, None, None)        # bez wyniku
    assert not OD.lineups_complete(14, 15, 30, 28, 12, 28)    # wysyłka w połowie


def test_goracy_mecz_niepelny_odswiezany_co_kilka_minut():
    kickoff = NOW - timedelta(hours=2)
    fetched = NOW - timedelta(minutes=20)
    # dawna reguła: 6 h świeżości
    assert not OD.needs_details(fetched, True, kickoff, NOW)
    # niepełny protokół, mecz w toku albo bez ProEla: co 15 min
    assert OD.needs_details(fetched, True, kickoff, NOW, complete=False)
    assert not OD.needs_details(NOW - timedelta(minutes=10), True, kickoff, NOW, complete=False)
    # ProEl zakończył mecz: co 5 min
    done = NOW - timedelta(minutes=30)
    assert OD.needs_details(NOW - timedelta(minutes=6), True, kickoff, NOW, complete=False, proel_done_at=done)
    assert not OD.needs_details(NOW - timedelta(minutes=4), True, kickoff, NOW, complete=False, proel_done_at=done)
    # komplet: wracamy do zwykłej kadencji
    assert not OD.needs_details(NOW - timedelta(minutes=6), True, kickoff, NOW, complete=True, proel_done_at=done)


def test_okno_goracego_meczu():
    assert OD.in_hot_window(NOW - timedelta(hours=5), NOW)
    assert not OD.in_hot_window(NOW - timedelta(hours=7), NOW)
    assert not OD.in_hot_window(NOW + timedelta(hours=1), NOW)          # jeszcze nie zaczęty
    assert OD.in_hot_window(NOW - timedelta(hours=9), NOW, proel_done_at=NOW - timedelta(hours=1))
    # bez godziny (00:00): cała doba + okno
    midnight = NOW.replace(hour=0, minute=0) - timedelta(hours=2)
    assert OD.in_hot_window(midnight, NOW, timed=False)
    assert not OD.in_hot_window(midnight, NOW, timed=True)
    # po oknie stary mecz bez zmian (6 h przez 3 dni)
    assert OD.details_stale_after(NOW - timedelta(hours=8), NOW, complete=False) == OD.STALE_AFTER
    assert OD.details_stale_after(NOW - timedelta(days=5), NOW, complete=False) is None
    assert OD.details_stale_after(NOW - timedelta(hours=1), NOW, complete=False, timed=False) == OD.HOT_STALE_PLAIN * 2


def test_koniec_w_proelu_bez_wyniku_w_zprp_tez_liczy_sie_za_rozegrany():
    done = NOW - timedelta(minutes=10)
    assert OD.needs_details(NOW - timedelta(hours=1), False, None, NOW, complete=False, proel_done_at=done)
    assert not OD.needs_details(NOW - timedelta(hours=1), False, None, NOW)


def test_termin_sygnalu_debounce_i_pilny():
    first = OD.next_due(None, 100.0, 45.0, True)
    assert first == (100.0, 145.0)
    later = OD.next_due(first, 130.0, 45.0, True)       # kolejny zawodnik - po ostatnim
    assert later == (100.0, 175.0)
    capped = OD.next_due(later, 210.0, 45.0, True)      # nie dalej niż 2 min od pierwszego
    assert capped == (100.0, 100.0 + OD.KICK_MAX_DEFER)
    urgent = OD.next_due(later, 131.0, 5.0, False)      # „wysłano komplet" - od razu
    assert urgent == (100.0, 136.0)


def test_status_z_proela_wyzwala_odswiezenie(monkeypatch):
    calls = []
    monkeypatch.setattr(OD, "kick_details_refresh", lambda mid, delay=20.0, debounce=False: calls.append((mid, delay)) or True)
    assert OD.kick_on_status("123", "in_progress", "finished")
    assert OD.kick_on_status("123", "finished", "approved")
    assert not OD.kick_on_status("123", "finished", "finished")
    assert not OD.kick_on_status("123", "finished", "in_progress")
    assert calls == [("123", 30.0), ("123", 30.0)]


def test_sygnal_pobiera_szczegoly_w_tle_raz_po_serii(monkeypatch):
    monkeypatch.setenv("ZPRP_PUBLIC_KICK_ENABLED", "1")
    fetched = []

    async def fake_fetch(match_id, timeout=OD.KICK_TIMEOUT):
        fetched.append(match_id)
        return True

    monkeypatch.setattr(OD, "fetch_details_now", fake_fetch)

    async def go():
        assert OD.kick_details_refresh("777", delay=0.05, debounce=True)
        assert OD.kick_details_refresh("777", delay=0.08, debounce=True)   # ta sama seria
        assert not OD.kick_details_refresh("", delay=0.01)
        await asyncio.sleep(0.25)
        assert fetched == ["777"]
        OD.kick_details_refresh("777", delay=0.01)                         # nowa seria = nowe pobranie
        await asyncio.sleep(0.1)

    asyncio.run(go())
    assert fetched == ["777", "777"]


def test_sygnaly_wylaczone_w_testach_domyslnie(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("ZPRP_PUBLIC_KICK_ENABLED", raising=False)

    async def go():
        return OD.kick_details_refresh("1", delay=0.01)

    assert asyncio.run(go()) is False


def test_wysylka_do_zprp_wyzwala_odswiezenie_portalu(monkeypatch):
    import app.proel_zprp as z

    calls = []
    # inne testy przeładowują moduły - podmieniamy to, co faktycznie zaimportuje trasa
    live_od = importlib.import_module("app.zprp_public.ondemand")
    monkeypatch.setattr(live_od, "kick_details_refresh", lambda mid, delay=20.0, debounce=False: calls.append((mid, delay, debounce)) or True)

    async def no_journal(*a, **k):
        return None

    monkeypatch.setattr(z, "_journal_send", no_journal)

    async def go():
        return await z.zprp_full_data_done(z.ZprpFullDataDoneRequest(id_zawody=4321))

    assert asyncio.run(go()) == {"status": "success"}
    z._kick_public(4321, 45.0, debounce=True)
    assert calls == [(4321, 5.0, False), (4321, 45.0, True)]


# ---------------------------------------------------------------------------
# Skład z protokołu (czyste reguły)
# ---------------------------------------------------------------------------


def _blob(**over):
    blob = {
        "matchConfig": {
            "hostTeamName": "KGHM Chrobry Głogów", "guestTeamName": "Industria Kielce", "halfTime": 30,
            "hostPlayerCards": [
                {"number": 7, "fullName": "TAJNE Dane", "zprpId": 9001},
                {"number": 11, "fullName": "KOWAL Jan"},
                {"number": 21, "fullName": "PRYWATNY Zawodnik"},
                {"number": 99, "fullName": "SKRESLONY Ktos", "struck": True},
            ],
            "guestPlayerCards": [{"number": 5, "fullName": "NOWAK Piotr"}, {"number": 33, "fullName": "INNY Gosc"}],
            "hostCompanions": [{"id": "A", "fullName": "TRENER Marek"}, {"id": "B", "fullName": "MASAZYSTA Sekret"}],
            "guestCompanions": [{"id": "A", "fullName": "OBCY Trener"}],
        },
        "scoreHost": 3, "scoreGuest": 2,
        "protocol": [
            {"type": "goal", "team": "host", "player": 7, "time": 60_000, "half": 1},
            {"type": "goal", "team": "host", "player": 7, "time": 90_000, "half": 1},
            {"type": "goalRemoved", "team": "host", "player": 7, "time": 95_000, "half": 1, "extra": {"origTime": 90_000}},
            {"type": "penaltyKickScored", "team": "host", "player": 11, "time": 120_000, "half": 1},
            {"type": "penaltyKickMissed", "team": "host", "player": 11, "time": 400_000, "half": 1},
            {"type": "goal", "team": "host", "player": 21, "time": 2_000_000, "half": 2},
            {"type": "warning", "team": "host", "player": 11, "time": 300_000, "half": 1},
            {"type": "penalty1", "team": "host", "player": 11, "time": 2_801_000, "half": 2},
            {"type": "penalty2", "team": "host", "player": 11, "time": 3_000_000, "half": 2},
            {"type": "disqualificationBlue", "team": "host", "player": 11, "time": 3_001_000, "half": 2},
            {"type": "penaltyExtra", "team": "guest", "player": 5, "time": 1_500_000, "half": 1},
            {"type": "goal", "team": "guest", "player": 5, "time": 200_000, "half": 1},
            {"type": "goal", "team": "guest", "player": 33, "time": 210_000, "half": 1},
            {"type": "warning", "team": "host", "player": "a", "time": 500_000, "half": 1},
            {"type": "penalty1", "team": "guest", "player": "A", "time": 1_000_000, "half": 1},
            {"type": "teamTime", "team": "host", "player": None, "time": 800_000, "half": 1},
            {"type": "goal", "team": "host", "player": 7, "time": 3_600_000, "half": 2, "shootout": True},
        ],
        "penaltyShots": {"host": [{"player": 7, "result": 1}], "guest": [{"player": 5, "result": 0}]},
    }
    blob.update(over)
    return blob


def test_statystyki_z_protokolu_po_numerach():
    stats = PL.protocol_stats(_blob(), host_home=True)
    h, a = stats["home"]["players"], stats["away"]["players"]
    assert h[7]["goals"] == 1 and h[7]["shootout_attempts"] == 1 and h[7]["shootout_goals"] == 1   # cofnięta bramka zdjęta
    assert (h[11]["goals"], h[11]["penalty_attempts"], h[11]["penalty_goals"]) == (1, 2, 1)
    assert h[11]["warning_time"] == "05:00" and h[11]["two_minutes_times"] == ["46:41", "50:00"]
    assert h[11]["disqualifications"] == 1 and h[11]["disqualification_blue"] and h[11]["disqualification_time"] == "50:01"
    assert a[5]["direct_red_cards"] == 1 and a[5]["extra_penalty"] and a[5]["extra_penalty_time"] == "25:00"
    assert stats["home"]["staff"]["A"]["warnings"] == 1 and stats["away"]["staff"]["A"]["two_minutes"] == 1
    # zamiana stron: gospodarz ProEla to gość w ZPRP
    swapped = PL.protocol_stats(_blob(), host_home=False)
    assert swapped["away"]["players"][11]["goals"] == 1 and 5 in swapped["home"]["players"]


def test_numery_najswiezsze_wygrywaja():
    apps = [
        {"player_id": "p1", "shirt_number": "11", "at": datetime(2026, 9, 1)},
        {"player_id": "p1", "shirt_number": "17", "at": datetime(2026, 10, 1)},   # zmienił numer
        {"player_id": "p2", "shirt_number": "11", "at": datetime(2026, 9, 20)},
        {"player_id": "p3", "shirt_number": "4", "at": None},
    ]
    roster = [{"player_id": "p9", "shirt_number": "21"}, {"player_id": "p1", "shirt_number": "30"}]
    idx = PL.number_index(apps, roster)
    assert idx[11] == "p2" and idx[17] == "p1" and idx[4] == "p3" and idx[21] == "p9"
    assert 30 not in idx   # p1 już ma numer z występów


def _public():
    return {
        "9001": {"player_id": "9001", "first_name": "Adam", "last_name": "Publiczny", "photo_url": None},
        "p11": {"player_id": "p11", "first_name": "Jan", "last_name": "Kowal"},
        "p21": {"player_id": "p21", "first_name": "Ola", "last_name": "Inna"},    # numer 21 ma ktoś inny niż w karcie
        "p5": {"player_id": "p5", "first_name": "Piotr", "last_name": "Nowak"},
    }


def test_nazwiska_tylko_z_publicznego_zprp_bez_danych_proela():
    blob = _blob()
    stats = PL.protocol_stats(blob, True)
    roster = PL.proel_roster(blob, True)
    pub = _public()
    home = PL.build_players(roster["home"]["players"], stats["home"]["players"], "home", "t1", pub,
                            {11: "p11", 21: "p21"}, [pub["p11"], pub["p21"]], {"p11": "BR"}, roster["home"]["struck"])
    by_nr = {p["shirt_number"]: p for p in home}
    assert sorted(by_nr, key=int) == ["7", "11", "21"]                       # skreślony 99 bez zdarzeń wypada
    assert by_nr["7"]["last_name"] == "Publiczny" and by_nr["7"]["name_source"] == "zprp_id"
    assert by_nr["11"]["player_id"] == "p11" and by_nr["11"]["name_source"] == "zprp_number" and by_nr["11"]["position"] == "BR"
    # numer 21 w publicznych składach należy do kogoś innego niż karta: bez nazwiska
    assert by_nr["21"]["player_id"] is None and by_nr["21"]["last_name"] is None and by_nr["21"]["goals"] == 1
    assert all(p["source"] == "proel" for p in home)
    staff = PL.build_staff(roster["home"]["staff"], stats["home"]["staff"], "home", "t1",
                           {"A": [{"letter": "A", "first_name": "Marek", "last_name": "Trener", "person_id": "o1", "function": "Trener"}],
                            "B": [{"letter": "B", "first_name": "Zenon", "last_name": "Ktos", "person_id": "o2"}]})
    assert [(s["letter"], s["last_name"]) for s in staff] == [("A", "Trener"), ("B", None)]
    text = json.dumps([home, staff], default=str)
    for secret in ("TAJNE", "Tajne", "PRYWATNY", "SKRESLONY", "MASAZYSTA", "Sekret"):
        assert secret not in text


def test_nazwisko_z_puli_druzyny_gdy_numer_nieznany():
    pool = [{"player_id": "p5", "first_name": "Piotr", "last_name": "Nowak"}, {"player_id": "p6", "first_name": "Anna", "last_name": "Nowak"}]
    person, how = PL.resolve_player({"number": 5, "zprp_id": None, "check": "NOWAK Piotr"}, {}, {}, pool)
    assert person["player_id"] == "p5" and how == "zprp_name"
    assert PL.resolve_player({"number": 5, "zprp_id": None, "check": None}, {}, {}, pool) == (None, None)


def test_zrodlo_skladu_na_strone():
    z = {"home": [{"goals": 0}] * 5, "away": []}
    f = {"home": [{"goals": 2}] * 14, "away": [{"goals": 2}] * 14}
    assert PL.choose_sources(z, f, False) == {"home": "proel", "away": "proel"}
    full = {"home": [{"goals": 2}] * 14, "away": []}
    assert PL.choose_sources(full, f, False) == {"home": "zprp", "away": "proel"}
    # zgłoszenie wpisane przed meczem (komplet nazwisk, zero bramek) - póki ZPRP nie ma statystyk, protokół
    entered = {"home": [{"goals": 0}] * 14, "away": [{"goals": 0}] * 14}
    assert PL.choose_sources(entered, f, False) == {"home": "proel", "away": "proel"}
    assert PL.choose_sources(full, None, False) == {"home": "zprp", "away": None}
    assert PL.choose_sources({"home": [{"goals": 1}], "away": [{"goals": 1}]}, f, True) == {"home": "zprp", "away": "zprp"}


def test_wynik_tylko_z_zakonczonego_protokolu():
    assert PL.final_score(_blob(), True, "finished") == {"home": 3, "away": 2}
    assert PL.final_score(_blob(), False, "approved") == {"home": 2, "away": 3}
    assert PL.final_score(_blob(), True, "in_progress") is None


# ---------------------------------------------------------------------------
# Strona meczu na małej bazie SQLite
# ---------------------------------------------------------------------------

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.zprp_public.live", "app.zprp_public.proel_lineups")


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
    saved, state = _proel_tables(metadata)
    url = f"sqlite:///{tmp_path / 'lineups.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in list(pub) + list(nat):
        setattr(fake, table.name, table)
    fake.saved_matches = saved
    fake.proel_match_state = state
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    portal = importlib.import_module("app.zprp_public.portal")
    importlib.import_module("app.zprp_public.enrich").invalidate()

    async def no_fetch(match, info=None):
        return False

    monkeypatch.setattr(portal, "ensure_details", no_fetch)
    yield portal, fake.database, {t.name: t for t in list(pub) + list(nat) + [saved, state]}
    for name in MODULES:
        sys.modules.pop(name, None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T, status="finished", zprp_full=False):
    local = datetime.now(WARSAW).replace(tzinfo=None, microsecond=0)
    utc = datetime.now(timezone.utc)

    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
    base = dict(season_id="S1", competition_id="K1", competition_name="Superliga Mężczyzn", **_h())
    teams = dict(home_team_id="tc", away_team_id="ti", home_club_id="cc", away_club_id="ci",
                 home_team_name="KGHM Chrobry Głogów", away_team_name="Industria Kielce")
    # mecz dzisiaj bez godziny (Superliga: 00:00), ZPRP bez wyniku
    today = local.replace(hour=0, minute=0, second=0)
    await ins("zprp_public_matches", match_id="m1", match_code="SM/1", scheduled_at=today,
              score_home=30 if zprp_full else None, score_away=28 if zprp_full else None, **teams, **base)
    # wcześniejszy mecz Chrobrego w sezonie - publiczne numery
    await ins("zprp_public_matches", match_id="m0", match_code="SM/0", scheduled_at=today - timedelta(days=7),
              score_home=25, score_away=20, **teams, **base)
    for pid, first, last in (("9001", "Adam", "Publiczny"), ("p11", "Jan", "Kowal"), ("p21", "Ola", "Inna"),
                             ("p5", "Piotr", "Nowak"), ("p3", "Tomasz", "Wczesny")):
        await ins("zprp_public_players", player_id=pid, first_name=first, last_name=last, **_h())
    await ins("zprp_public_match_players", match_id="m0", team_id="tc", player_id="p11", side="home", shirt_number="11", position="BR", **_h())
    await ins("zprp_public_match_players", match_id="m0", team_id="tc", player_id="p21", side="home", shirt_number="21", **_h())
    await ins("zprp_public_match_players", match_id="m0", team_id="ti", player_id="p5", side="away", shirt_number="5", **_h())
    await ins("zprp_public_match_staff", match_id="m0", team_id="tc", person_id="o1", side="home", first_name="Marek",
              last_name="Trener", role="A", function="Trener", **_h())
    # zgłoszenie z 24.10: pięciu... tu jeden zawodnik Chrobrego w ZPRP, bez bramek; Industria pusta
    await ins("zprp_public_match_players", match_id="m1", team_id="tc", player_id="p3", side="home", shirt_number="3", **_h())
    if zprp_full:
        await ins("zprp_public_match_players", match_id="m1", team_id="ti", player_id="p5", side="away", shirt_number="5", goals=28, **_h())
        await db.execute(T["zprp_public_match_players"].update().where(T["zprp_public_match_players"].c.player_id == "p3").values(goals=30))
    await ins("proel_matches", match_number="SM/1", zprp_match_id="m1", status=status,
              updated_at=utc - timedelta(minutes=5), data_json=_blob())
    await ins("proel_match_state", match_number="SM/1", zprp_match_id="m1", rev=9, live_started_at=utc - timedelta(hours=2),
              updated_at=utc)


def run(env, factory, **seed):
    module, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T, **seed)
            return await factory(module)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_strona_meczu_sklad_z_proela_gdy_zprp_niepelny(env):
    out = run(env, lambda portal: portal.match_overview("m1"))
    assert out["lineups_source"] == {"home": "proel", "away": "proel"}
    assert out["lineups_complete"] is False and out["lineups_refresh"] is True
    assert out["lineups_score"] == {"home": 3, "away": 2}
    home = {p["shirt_number"]: p for p in out["lineups"]["home"]}
    assert home["7"]["last_name"] == "Publiczny" and home["7"]["goals"] == 1
    assert home["11"]["last_name"] == "Kowal" and home["11"]["two_minutes_times"] == ["46:41", "50:00"]
    # numer 21 w publicznych składach to „Ola Inna", a karta mówi kto inny: bez nazwiska, statystyki zostają
    assert home["21"]["last_name"] is None and home["21"]["player_id"] is None and home["21"]["goals"] == 1
    away = {p["shirt_number"]: p for p in out["lineups"]["away"]}
    assert away["5"]["last_name"] == "Nowak" and away["33"]["player_id"] is None
    staff = {(s["side"], s["letter"]): s for s in out["staff"]}
    assert staff[("home", "A")]["last_name"] == "Trener" and staff[("home", "B")]["last_name"] is None
    assert out["lineups_goals_known"] is True
    text = json.dumps(out, default=str)
    for secret in ("TAJNE", "Tajne", "PRYWATNY", "SKRESLONY", "MASAZYSTA", "Sekret", "OBCY", "INNY Gosc"):
        assert secret not in text


def test_strona_meczu_komplet_w_zprp_bez_proela(env):
    out = run(env, lambda portal: portal.match_overview("m1"), zprp_full=True)
    assert out["lineups_source"] == {"home": "zprp", "away": "zprp"}
    assert out["lineups_complete"] is True and out["lineups_refresh"] is False and out["lineups_score"] is None
    assert [p["player_id"] for p in out["lineups"]["home"]] == ["p3"]


def test_strona_meczu_protokol_testowy_nigdy(env):
    async def go(portal):
        module, db, T = env
        await db.execute(T["proel_matches"].update().values(data_json=_blob(matchConfig={"isTest": True, "hostTeamName": "x"})))
        return await portal.match_overview("m1")

    out = run(env, go)
    assert out["lineups_source"] == {"home": "zprp", "away": None}
    assert [p["player_id"] for p in out["lineups"]["home"]] == ["p3"]
