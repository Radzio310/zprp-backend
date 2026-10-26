"""Kolejki „Kolejka N" z zakresem dat, godzina meczów centralnych i zapas z ProEla.

Zgłoszenie z 24.10.2026 22:18: terminarz Superligi pokazywał „Seria 8", chipy
kolejek z samym pierwszym dniem, a wszystkie mecze 8. kolejki „godz. do ustalenia"
i „0/6 rozegranych", choć KGHM Chrobry Głogów - Industria Kielce był już
rozegrany (i prowadzony w ProElu). Zegar wstrzykiwany przez `time_pl.utc_now`.
"""

import asyncio
import importlib
import sys
import types
from datetime import date, datetime, timezone
from unittest.mock import MagicMock

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import JSON, BigInteger, Column, DateTime, Integer, String, Table, insert

from app import time_pl as TP
from app.national_distance_tables import define_tables as define_national
from app.zprp_public import proel_card_rules as PR
from app.zprp_public import round_rules as RR
from app.zprp_public_tables import define_tables as define_public

UTC = timezone.utc
MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.zprp_public.live", "app.zprp_public.proel_cards")
NOW = datetime(2026, 10, 24, 20, 18, tzinfo=UTC)  # sobota 22:18 w Warszawie (CEST)
LOCAL_NOW = datetime(2026, 10, 24, 22, 18)


# ---------------------------------------------------------------------------
# Kolejki: nazwa i zakres dat (czyste)
# ---------------------------------------------------------------------------


def test_nazwa_kolejki_zawsze_kolejka_n():
    assert RR.matchday_label(8, "Seria 8") == "Kolejka 8"
    assert RR.matchday_label(None, "seria 12") == "Kolejka 12"
    assert RR.matchday_label(3, "3. kolejka") == "Kolejka 3"
    assert RR.matchday_label(None, "Kolejka nr 5") == "Kolejka 5"
    assert RR.matchday_label(4, "") == "Kolejka 4"
    assert RR.matchday_label(None, "7") == "Kolejka 7"
    # Nazwa ZPRP („Seria 8") wygrywa z rozjechanym `Nr` - tak kolejkę widzi kibic.
    assert RR.matchday_label(9, "Seria 8") == "Kolejka 8"
    # To nie kolejki ligowe - nazwa zostaje.
    assert RR.matchday_label(1, "Turniej Bystra") == "Turniej Bystra"
    assert RR.matchday_label(None, "1/2 finału") == "1/2 finału"
    assert RR.matchday_label(None, "Finał") == "Finał"
    assert RR.matchday_label(None, None) == "Kolejka"
    assert RR.card_matchday_label("Seria 8") == "Kolejka 8"
    assert RR.card_matchday_label("") is None
    assert RR.matchday_number(None, "Seria 8") == 8 and RR.matchday_number(0, "Finał") is None


def test_zakres_dat_kolejki():
    # Okno ZPRP (DataStart/DataKoniec) ma pierwszeństwo przed datami meczów (przełożony mecz nie rozciąga kolejki).
    assert RR.matchday_range("2026-10-24", "2026-10-25 00:00:00", [datetime(2026, 12, 9, 18, 0)]) == ("2026-10-24", "2026-10-25")
    assert RR.matchday_range("24.10.2026", "", []) == ("2026-10-24", "2026-10-24")
    # Bez okna: pierwszy i ostatni dzień meczów.
    assert RR.matchday_range(None, None, [datetime(2026, 11, 2, 19, 0), datetime(2026, 10, 31, 18, 0), None]) == ("2026-10-31", "2026-11-02")
    assert RR.matchday_range(None, None, []) == (None, None)
    assert RR.matchday_range("2026-10-25", "2026-10-24") == ("2026-10-24", "2026-10-25")


def test_kolejka_dostaje_pola_addytywne_i_zachowuje_surowe():
    day = {"matchday_id": "D8", "number": None, "name": "Seria 8", "starts_on": "2026-10-24", "ends_on": "2026-10-25"}
    matches = [{"score_home": 30, "score_away": 28}, {"score_home": None, "score_away": None}, {"withdrawn": True}]
    out = RR.decorate_matchday(day, matches)
    assert out["name"] == "Seria 8" and out["starts_on"] == "2026-10-24"  # zgodność wstecz
    assert out["number"] == 8 and out["label"] == "Kolejka 8"
    assert (out["date_from"], out["date_to"]) == ("2026-10-24", "2026-10-25")
    assert (out["matches_played"], out["matches_total"]) == (1, 2)  # wycofany się nie liczy
    assert "matches_total" not in RR.decorate_matchday({"name": "Seria 1"})


# ---------------------------------------------------------------------------
# ProEl jako zapas godziny i wyniku (czyste)
# ---------------------------------------------------------------------------


def _blob(host="Industria Kielce", guest="KGHM Chrobry Głogów", **over):
    blob = {"matchConfig": {"matchId": "g1", "hostTeamName": host, "guestTeamName": guest,
                            "extras": {"matchDate": "2026-10-24", "matchTime": "18:00"}},
            "scoreHost": 33, "scoreGuest": 29, "halfScore": {"host": 17, "guest": 14}}
    blob.update(over)
    return blob


def test_godzina_z_protokolu_i_pierwszego_gwizdka():
    day = date(2026, 10, 24)
    assert PR.proel_kickoff(_blob(), day) == datetime(2026, 10, 24, 18, 0)
    # Inny dzień w protokole (stary termin) = brak godziny.
    assert PR.proel_kickoff(_blob(), date(2026, 10, 25)) is None
    # Godzina 00:00 w protokole to też „do ustalenia" - wtedy pierwszy gwizdek (UTC -> Warszawa, pełna minuta).
    untimed = _blob(matchConfig={"hostTeamName": "A", "guestTeamName": "B", "extras": {"matchDate": "2026-10-24", "matchTime": "00:00"}})
    assert PR.proel_kickoff(untimed, day, datetime(2026, 10, 24, 15, 2, 41, tzinfo=UTC)) == datetime(2026, 10, 24, 17, 2)
    assert PR.proel_kickoff(untimed, day, None) is None
    # Szkolenie/test nigdy.
    assert PR.proel_kickoff(_blob(matchConfig={"isTest": True, "extras": {"matchTime": "18:00"}}), day) is None
    assert PR.parse_clock("18.30") is not None and PR.parse_clock("25:00") is None and PR.parse_clock("") is None


def test_wynik_z_protokolu_w_orientacji_zprp():
    # ProEl: gospodarz Industria (zamiana stron), ZPRP: gospodarz Chrobry.
    res = PR.proel_result(_blob(), "approved", "KGHM Chrobry Głogów", "Industria Kielce")
    assert (res["score_home"], res["score_away"]) == (29, 33)
    assert (res["halftime_home"], res["halftime_away"]) == (14, 17)
    assert res["shootout_home"] is None
    # Mecz w toku - nigdy wynik.
    assert PR.proel_result(_blob(), "in_progress", "KGHM Chrobry Głogów", "Industria Kielce") is None
    # Remis + karne „4 - 3" (gospodarz - gość).
    tie = PR.proel_result(_blob(host="A Team", guest="B Team", scoreHost=30, scoreGuest=30, penaltyScore="4 - 3"), "finished", "A Team", "B Team")
    assert (tie["shootout_home"], tie["shootout_away"]) == (4, 3)


def test_zapas_nie_nadpisuje_zprp_i_oznacza_zrodlo():
    card = {"match_id": "g1", "scheduled_at": datetime(2026, 10, 24, 0, 0), "score_home": None, "score_away": None,
            "status": "scheduled", "home_team_name": "KGHM Chrobry Głogów", "away_team_name": "Industria Kielce"}
    assert PR.needs(card, LOCAL_NOW) == (True, True)
    found = PR.extract({"zprp_match_id": "g1", "status": "approved", "blob": _blob()}, card)
    PR.apply(card, found)
    PR.mark_sources(card, LOCAL_NOW)
    assert (card["score_home"], card["score_away"], card["status"]) == (29, 33, "finished")
    assert card["score_source"] == "proel" and card["kickoff_source"] == "proel"
    assert card["scheduled_at"] == datetime(2026, 10, 24, 18, 0) and card["result_pending"] is False
    zprp = {"match_id": "g4", "scheduled_at": datetime(2026, 10, 24, 15, 0), "score_home": 30, "score_away": 28, "status": "finished"}
    PR.apply(zprp, {"result": {"score_home": 31, "score_away": 28}})
    PR.mark_sources(zprp, LOCAL_NOW)
    assert (zprp["score_home"], zprp["score_source"], zprp["kickoff_source"]) == (30, "zprp", "zprp")


def test_czeka_na_wynik():
    timed = {"scheduled_at": datetime(2026, 10, 24, 18, 0), "score_home": None, "score_away": None}
    assert PR.result_pending(timed, LOCAL_NOW)
    assert not PR.result_pending({**timed, "scheduled_at": datetime(2026, 10, 24, 21, 0)}, LOCAL_NOW)
    # Bez godziny: dopiero od następnego dnia.
    assert not PR.result_pending({**timed, "scheduled_at": datetime(2026, 10, 24, 0, 0)}, LOCAL_NOW)
    assert PR.result_pending({**timed, "scheduled_at": datetime(2026, 10, 23, 0, 0)}, LOCAL_NOW)
    assert not PR.result_pending({**timed, "withdrawn": True}, LOCAL_NOW)


def test_wiersz_bez_id_tylko_przy_zgodnym_dniu():
    card = {"match_id": "g5", "match_code": "SM/61", "scheduled_at": datetime(2026, 10, 24, 0, 0)}
    stary = {"match_number": "SM/61", "zprp_match_id": None, "status": "approved",
             "blob": _blob(matchConfig={"hostTeamName": "A", "guestTeamName": "B", "extras": {"matchDate": "2025-10-24"}})}
    assert PR.pick_row([stary], card) is None
    dzis = {**stary, "blob": _blob(matchConfig={"hostTeamName": "A", "guestTeamName": "B", "extras": {"matchDate": "2026-10-24"}})}
    assert PR.pick_row([stary, dzis], card) is dzis
    obcy = {"match_number": "SM/61", "zprp_match_id": "inny", "status": "approved", "blob": dzis["blob"]}
    assert PR.pick_row([obcy], card) is None


# ---------------------------------------------------------------------------
# Synchronizacja: godzina z pola transmisji, wynik końcowy
# ---------------------------------------------------------------------------


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
    url = f"sqlite:///{tmp_path / 'rounds.db'}"
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
    monkeypatch.setattr(TP, "utc_now", lambda: NOW)
    for name in MODULES:
        sys.modules.pop(name, None)
    portal = importlib.import_module("app.zprp_public.portal")
    importlib.import_module("app.zprp_public.enrich").invalidate()
    yield portal, fake.database, {t.name: t for t in list(pub) + list(nat) + [saved, state]}
    for name in MODULES:
        sys.modules.pop(name, None)


def test_godzina_meczu_centralnego_z_pola_transmisji(env):
    sync = sys.modules["app.zprp_public.sync"]
    kick = sync._kickoff
    tv = {"data_prop": "2026-10-24 00:00:00", "data_fakt": "2026-10-24 00:00:00", "transmisja_godzina": "18:00"}
    assert kick(tv) == datetime(2026, 10, 24, 18, 0)
    assert kick({**tv, "transmisja_godzina": "18:00:00"}) == datetime(2026, 10, 24, 18, 0)
    # Puste pole (mecze okręgowe) i godzina w terminie - bez zmian.
    assert kick({**tv, "transmisja_godzina": ""}) == datetime(2026, 10, 24, 0, 0)
    assert kick({**tv, "data_fakt": "2026-10-24 17:30:00", "transmisja_godzina": "20:00"}) == datetime(2026, 10, 24, 17, 30)
    assert kick({"data_fakt": "2026-10-24", "transmisja_godzina": "śmieci"}) == datetime(2026, 10, 24, 0, 0)


def test_wynik_koncowy_jako_ostatni_zapas(env):
    sync = sys.modules["app.zprp_public.sync"]
    values = sync._match_values({"Id": "1", "wynik_koncowy_gosp": "31", "wynik_koncowy_gosc": "29"})
    assert (values["score_home"], values["score_away"]) == (31, 29)
    values = sync._match_values({"Id": "1", "wynik_bramki_gosp": "30", "wynik_bramki_gosc": "28", "wynik_koncowy_gosp": "33"})
    assert (values["score_home"], values["score_away"]) == (30, 28)


# ---------------------------------------------------------------------------
# Terminarz rozgrywek: kolejki + zapas ProEl na kartach
# ---------------------------------------------------------------------------


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T):
    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
    await ins("zprp_public_competitions", competition_id="K1", season_id="S1", name="LOTTO Superliga", **_h())
    await ins("zprp_public_rounds", round_id="R1", competition_id="K1", name="Runda zasadnicza", **_h())
    await ins("zprp_public_matchdays", matchday_id="D7", round_id="R1", number=7, sequence=7, name="Seria 7",
              starts_on="2026-10-17", ends_on="2026-10-18", **_h())
    await ins("zprp_public_matchdays", matchday_id="D8", round_id="R1", number=8, sequence=8, name="Seria 8",
              starts_on="2026-10-24", ends_on="2026-10-25", **_h())
    await ins("zprp_public_matchdays", matchday_id="D9", round_id="R1", number=None, sequence=9, name="Seria 9", **_h())
    base = dict(season_id="S1", competition_id="K1", competition_name="LOTTO Superliga", round_id="R1", **_h())

    def match(mid, day, at, home, away, **kw):
        return dict(match_id=mid, matchday_id=day, matchday_name=f"Seria {day[1:]}", scheduled_at=at,
                    home_team_name=home, away_team_name=away, home_team_id=f"t-{home}", away_team_id=f"t-{away}", **base, **kw)

    await ins("zprp_public_matches", **match("o1", "D7", datetime(2026, 10, 17, 18, 0), "Orlen Wisła Płock", "Górnik Zabrze",
                                             score_home=31, score_away=25))
    # 8. kolejka: ZPRP bez godziny (00:00) i bez wyników.
    await ins("zprp_public_matches", **match("g1", "D8", datetime(2026, 10, 24, 0, 0), "KGHM Chrobry Głogów", "Industria Kielce",
                                             match_code="SM/57"))
    await ins("zprp_public_matches", **match("g2", "D8", datetime(2026, 10, 24, 0, 0), "Energa MKS Kalisz", "Azoty Puławy",
                                             match_code="SM/58"))
    await ins("zprp_public_matches", **match("g3", "D8", datetime(2026, 10, 25, 0, 0), "Zagłębie Lubin", "Stal Mielec",
                                             match_code="SM/59"))
    await ins("zprp_public_matches", **match("g4", "D8", datetime(2026, 10, 24, 15, 0), "Gwardia Opole", "Piotrkowianin",
                                             match_code="SM/60", score_home=30, score_away=28))
    await ins("zprp_public_matches", **match("g5", "D8", datetime(2026, 10, 24, 0, 0), "MMTS Kwidzyn", "Śląsk Wrocław",
                                             match_code="SM/61"))
    await ins("zprp_public_matches", **match("n1", "D9", datetime(2026, 11, 2, 19, 0), "Górnik Zabrze", "Gwardia Opole"))
    await ins("zprp_public_matches", **match("n2", "D9", datetime(2026, 10, 31, 18, 0), "Azoty Puławy", "MMTS Kwidzyn"))

    # g1: zatwierdzony protokół ProEl, gospodarz w protokole odwrotnie niż w ZPRP.
    await ins("proel_matches", match_number="SM/57", zprp_match_id="g1", status="approved", updated_at=NOW,
              data_json=_blob(host="Industria Kielce", guest="KGHM Chrobry Głogów"))
    # g2: mecz w toku, bez godziny w konfiguracji - godzina z pierwszego gwizdka (17:02), bez wyniku.
    await ins("proel_matches", match_number="SM/58", zprp_match_id="g2", status="in_progress", updated_at=NOW,
              data_json=_blob(host="Energa MKS Kalisz", guest="Azoty Puławy",
                              matchConfig={"hostTeamName": "Energa MKS Kalisz", "guestTeamName": "Azoty Puławy",
                                           "extras": {"matchDate": "2026-10-24"}}))
    await ins("proel_match_state", match_number="SM/58", zprp_match_id="g2", rev=3,
              live_started_at=datetime(2026, 10, 24, 15, 2, 30, tzinfo=UTC), updated_at=NOW)
    # g4: ZPRP ma wynik - protokół (inny wynik) go nie rusza.
    await ins("proel_matches", match_number="SM/60", zprp_match_id="g4", status="approved", updated_at=NOW,
              data_json=_blob(host="Gwardia Opole", guest="Piotrkowianin", scoreHost=31, scoreGuest=28))
    # g5: ten sam numer z zeszłego sezonu, bez identyfikatora ZPRP - nie ten mecz.
    await ins("proel_matches", match_number="SM/61", zprp_match_id=None, status="approved", updated_at=NOW,
              data_json=_blob(host="MMTS Kwidzyn", guest="Śląsk Wrocław",
                              matchConfig={"hostTeamName": "MMTS Kwidzyn", "guestTeamName": "Śląsk Wrocław",
                                           "extras": {"matchDate": "2025-10-25", "matchTime": "17:00"}}))


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


def test_terminarz_kolejki_i_zapas_proel(env):
    async def go(portal, db, T):
        return await portal.competition_schedule("K1")

    out = run(env, go)
    days = {d["matchday_id"]: d for r in out["rounds"] for d in r["matchdays"]}
    assert [days[k]["label"] for k in ("D7", "D8", "D9")] == ["Kolejka 7", "Kolejka 8", "Kolejka 9"]
    assert days["D8"]["name"] == "Seria 8"  # surowa nazwa zostaje
    assert (days["D8"]["date_from"], days["D8"]["date_to"]) == ("2026-10-24", "2026-10-25")
    assert (days["D9"]["date_from"], days["D9"]["date_to"], days["D9"]["number"]) == ("2026-10-31", "2026-11-02", 9)
    # 0/6 -> 2/5: g1 z protokołu elektronicznego, g4 z ZPRP.
    assert (days["D8"]["matches_played"], days["D8"]["matches_total"]) == (2, 5)

    cards = {c["match_id"]: c for c in days["D8"]["matches"]}
    g1 = cards["g1"]
    assert (g1["score_home"], g1["score_away"], g1["status"], g1["winner_side"]) == (29, 33, "finished", "away")
    assert g1["score_source"] == "proel" and g1["kickoff_source"] == "proel" and g1["kickoff_time_known"] is True
    assert g1["matchday_label"] == "Kolejka 8"
    g2 = cards["g2"]
    assert g2["scheduled_at"] == datetime(2026, 10, 24, 17, 2) and g2["score_home"] is None and g2["status"] == "scheduled"
    assert cards["g4"]["score_home"] == 30 and cards["g4"]["score_source"] == "zprp"
    assert cards["g5"]["kickoff_time_known"] is False and cards["g5"]["score_source"] is None
    assert cards["g3"]["kickoff_source"] is None and cards["g3"]["result_pending"] is False
    # W dniu: z godziną po kolei, „do ustalenia" na końcu dnia.
    assert [c["match_id"] for c in days["D8"]["matches"]] == ["g4", "g2", "g1", "g5", "g3"]


def test_przeglad_kolejki_niesie_etykiete_i_daty(env):
    async def go(portal, db, T):
        extras = importlib.import_module("app.zprp_public.extras")
        return await extras.round_review("K1", "8")

    out = run(env, go)
    assert out["round"]["label"] == "Kolejka 8" and out["round"]["name"] == "Seria 8"
    assert (out["round"]["date_from"], out["round"]["date_to"]) == ("2026-10-24", "2026-10-25")
    assert {r["match_id"]: r["score_source"] for r in out["results"]}["g1"] == "proel"


def test_przeglad_kolejki_ruchy_licza_wynik_z_protokolu(env):
    """Ruchy w tabeli: wynik z ProEla (g1, ZPRP jeszcze go nie ma) liczy się do tabeli kolejki."""
    async def go(portal, db, T):
        extras = importlib.import_module("app.zprp_public.extras")
        return await extras.round_review("K1", "8")

    out = run(env, go)
    moves = {m["team_name"]: m for m in out["table_moves"]}
    ind, kghm = moves["Industria Kielce"], moves["KGHM Chrobry Głogów"]
    assert ind["points_gained"] == 3 and ind["round_results"][0]["code"] == "W"
    assert kghm["round_results"][0]["code"] == "L" and kghm["points_gained"] == 0
    # Pole klienta `previous` = `previous_position` (dawniej tylko to drugie - portal pokazywał same kreski).
    assert all(m["previous"] == m["previous_position"] for m in out["table_moves"])
    assert any(m["status"] in ("up", "down") for m in out["table_moves"])
    assert out["moves_source"] == "results" and out["win_points"] == 3
    assert out["stats"]["matches"] == 2 and out["stats"]["goals"] == 120
