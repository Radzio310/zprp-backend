"""Czas polski portalu: doba, „teraz", mecze bez godziny (00:00) i zmiana czasu.

Zegar wstrzykiwany przez `monkeypatch.setattr(time_pl, "utc_now", ...)` - serwer
chodzi w UTC, a `scheduled_at` to naiwny czas warszawski.
"""

import asyncio
import importlib
import sys
import types
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import insert

from app import time_pl as TP
from app.national_distance_tables import define_tables as define_national
from app.zprp_public_tables import define_tables as define_public

UTC = timezone.utc


def _clock(monkeypatch, *args):
    moment = datetime(*args, tzinfo=UTC)
    monkeypatch.setattr(TP, "utc_now", lambda: moment)
    return moment


# ---------------------------------------------------------------------------
# Pomocnik
# ---------------------------------------------------------------------------


def test_po_polnocy_w_polsce_jest_juz_nowa_doba_mimo_ze_w_utc_wczoraj(monkeypatch):
    # 24.10.2026 00:30 w Warszawie (CEST, UTC+2) = 23.10 22:30 UTC.
    _clock(monkeypatch, 2026, 10, 23, 22, 30)
    assert TP.warsaw_now() == datetime(2026, 10, 24, 0, 30)
    assert TP.warsaw_today() == date(2026, 10, 24)
    assert TP.today_bounds() == (datetime(2026, 10, 24), datetime(2026, 10, 25))
    # Gołe datetime.now() na serwerze UTC dałoby 23.10 - stąd „wczorajsze Dziś".


def test_dzien_zmiany_czasu_jesien_2026(monkeypatch):
    # 25.10.2026: 03:00 CEST -> 02:00 CET (01:00 UTC).
    _clock(monkeypatch, 2026, 10, 24, 22, 30)
    assert TP.warsaw_now() == datetime(2026, 10, 25, 0, 30)
    _clock(monkeypatch, 2026, 10, 25, 0, 30)
    assert TP.warsaw_now() == datetime(2026, 10, 25, 2, 30)  # jeszcze CEST
    _clock(monkeypatch, 2026, 10, 25, 1, 30)
    assert TP.warsaw_now() == datetime(2026, 10, 25, 2, 30)  # już CET (powtórzona godzina)
    _clock(monkeypatch, 2026, 10, 25, 23, 30)
    assert TP.warsaw_today() == date(2026, 10, 26)            # po zmianie offset +1
    assert TP.warsaw_to_utc(datetime(2026, 10, 25, 18, 0)) == datetime(2026, 10, 25, 17, 0, tzinfo=UTC)
    assert TP.warsaw_to_utc(datetime(2026, 10, 24, 18, 0)) == datetime(2026, 10, 24, 16, 0, tzinfo=UTC)


def test_dzien_zmiany_czasu_wiosna_2027(monkeypatch):
    # 28.03.2027: 02:00 CET -> 03:00 CEST (01:00 UTC).
    _clock(monkeypatch, 2027, 3, 27, 23, 30)
    assert TP.warsaw_today() == date(2027, 3, 28)
    _clock(monkeypatch, 2027, 3, 28, 0, 59)
    assert TP.warsaw_now() == datetime(2027, 3, 28, 1, 59)
    _clock(monkeypatch, 2027, 3, 28, 1, 0)
    assert TP.warsaw_now() == datetime(2027, 3, 28, 3, 0)
    _clock(monkeypatch, 2027, 3, 28, 22, 30)
    assert TP.warsaw_today() == date(2027, 3, 29)
    assert TP.warsaw_to_utc(datetime(2027, 3, 28, 12, 0)) == datetime(2027, 3, 28, 10, 0, tzinfo=UTC)


def test_konwersje_i_wstrzykniety_zegar():
    assert TP.to_warsaw_naive(None) is None
    assert TP.to_warsaw_naive(datetime(2026, 7, 1, 18, 0)) == datetime(2026, 7, 1, 18, 0)
    assert TP.to_warsaw_naive(datetime(2026, 7, 1, 16, 0, tzinfo=UTC)) == datetime(2026, 7, 1, 18, 0)
    assert TP.warsaw_now(datetime(2026, 12, 31, 23, 30, tzinfo=UTC)) == datetime(2027, 1, 1, 0, 30)
    assert TP.warsaw_now(datetime(2026, 12, 31, 23, 30)) == datetime(2027, 1, 1, 0, 30)  # naiwny = UTC


def test_godzina_do_ustalenia_i_sortowanie():
    untimed = datetime(2026, 10, 24, 0, 0)
    assert not TP.has_kickoff_time(untimed)
    assert not TP.has_kickoff_time(None)
    assert TP.has_kickoff_time(datetime(2026, 10, 24, 0, 30))
    assert TP.has_kickoff_time(datetime(2026, 10, 24, 18, 0))
    order = sorted(
        [untimed, datetime(2026, 10, 24, 18, 0), None, datetime(2026, 10, 25, 0, 0), datetime(2026, 10, 24, 12, 0)],
        key=TP.kickoff_sort_key,
    )
    assert order == [datetime(2026, 10, 24, 12, 0), datetime(2026, 10, 24, 18, 0), untimed, datetime(2026, 10, 25, 0, 0), None]


def test_przed_nami_regula_3h_i_bez_godziny():
    grace = timedelta(hours=3)
    now = datetime(2026, 10, 24, 15, 0)
    assert TP.is_upcoming_at(datetime(2026, 10, 24, 12, 30), now, grace)       # w toku
    assert not TP.is_upcoming_at(datetime(2026, 10, 24, 11, 59), now, grace)
    # 00:00 = do ustalenia: przed nami cały swój dzień, nie znika o 3:00.
    assert TP.is_upcoming_at(datetime(2026, 10, 24, 0, 0), now, grace)
    assert TP.is_upcoming_at(datetime(2026, 10, 24, 0, 0), datetime(2026, 10, 24, 23, 59), grace)
    assert not TP.is_upcoming_at(datetime(2026, 10, 23, 0, 0), datetime(2026, 10, 24, 0, 5), grace)
    assert TP.is_upcoming_at(None, now, grace)


# ---------------------------------------------------------------------------
# Parser ZPRP, ICS, ondemand, transmisje
# ---------------------------------------------------------------------------


def test_parser_terminu_zprp_bez_strefy_i_ze_strefa(env):
    _dt = sys.modules["app.zprp_public.sync"]._dt  # sync importowany na podmienionym app.db (fixture)

    assert _dt("2026-10-24 18:00:00") == datetime(2026, 10, 24, 18, 0)   # czas polski bez strefy
    assert _dt("2026-10-24 00:00:00") == datetime(2026, 10, 24, 0, 0)    # placeholder „bez godziny"
    assert _dt("2026-10-24") == datetime(2026, 10, 24, 0, 0)
    assert _dt("24.10.2026 18:00") == datetime(2026, 10, 24, 18, 0)
    # Ze strefą: przeliczenie, nie obcięcie (UTC 16:00 = 18:00 CEST).
    assert _dt("2026-10-24T16:00:00Z") == datetime(2026, 10, 24, 18, 0)
    assert _dt("2026-10-24T18:00:00+02:00") == datetime(2026, 10, 24, 18, 0)
    assert _dt("2026-11-14T17:30:00+00:00") == datetime(2026, 11, 14, 18, 30)
    assert _dt("") is None and _dt("jutro") is None


def test_termin_meczu_z_data_fakt_przed_data_prop(env):
    sync = sys.modules["app.zprp_public.sync"]
    kick = sync._kickoff
    # Proponowany sam dzień (00:00), faktyczny z godziną - godzina z faktycznego.
    assert kick({"data_prop": "2026-10-24 00:00:00", "data_fakt": "2026-10-24 17:30:00"}) == datetime(2026, 10, 24, 17, 30)
    # Mecz przełożony: faktyczny termin wygrywa (dawniej portal pokazywał stary dzień).
    assert kick({"data_prop": "2026-10-24 18:00:00", "data_fakt": "2026-10-26 19:00:00"}) == datetime(2026, 10, 26, 19, 0)
    # Faktyczny bez godziny, proponowany tego samego dnia z godziną - godzina z proponowanego.
    assert kick({"data_prop": "2026-10-24 18:00:00", "data_fakt": "2026-10-24 00:00:00"}) == datetime(2026, 10, 24, 18, 0)
    # Faktyczny bez godziny innego dnia - dzień faktyczny, godzina do ustalenia.
    assert kick({"data_prop": "2026-10-24 18:00:00", "data_fakt": "2026-10-25 00:00:00"}) == datetime(2026, 10, 25, 0, 0)
    assert kick({"data_prop": "2026-10-24 00:00:00"}) == datetime(2026, 10, 24, 0, 0)
    assert kick({}) is None
    values = sync._match_values({"Id": "1", "data_prop": "2026-10-24 00:00:00", "data_fakt": "2026-10-24 17:30:00"})
    assert values["scheduled_at"] == datetime(2026, 10, 24, 17, 30) and values["played_at"] == datetime(2026, 10, 24, 17, 30)


def test_ics_mecz_bez_godziny_jako_calodniowy():
    from app.zprp_public.match_rules import build_ics

    body = build_ics("Druzyna", [
        {"match_id": "a", "scheduled_at": datetime(2026, 10, 24, 0, 0), "home_team_name": "A", "away_team_name": "B"},
        {"match_id": "b", "scheduled_at": datetime(2026, 10, 25, 18, 0), "home_team_name": "A", "away_team_name": "C"},
    ], "t1", now=datetime(2026, 10, 20, tzinfo=UTC))
    assert "DTSTART;VALUE=DATE:20261024" in body and "DTEND;VALUE=DATE:20261025" in body
    assert "DTSTART:20261023T220000Z" not in body
    assert "DTSTART:20261025T170000Z" in body  # po zmianie czasu: 18:00 CET = 17:00 UTC


def test_karta_meczu_niesie_kickoff_time_known():
    from app.zprp_public.match_rules import apply_match_extras

    assert apply_match_extras({"scheduled_at": datetime(2026, 10, 24, 0, 0)}, {}, None, {})["kickoff_time_known"] is False
    assert apply_match_extras({"scheduled_at": datetime(2026, 10, 24, 18, 0)}, {}, None, {})["kickoff_time_known"] is True
    assert "kickoff_time_known" not in apply_match_extras({}, {}, None, {})


def test_ondemand_termin_naiwny_to_czas_polski():
    from app.zprp_public.ondemand import is_finished, match_moment

    assert match_moment(None, datetime(2026, 10, 24, 18, 0)) == datetime(2026, 10, 24, 16, 0, tzinfo=UTC)
    # 18:00 CEST minęła o 16:01 UTC (dawniej czytane jako 18:00 UTC - 2 h za późno).
    assert is_finished(None, datetime(2026, 10, 24, 18, 0), None, datetime(2026, 10, 24, 16, 1, tzinfo=UTC))
    # Bez godziny: mija dopiero z końcem doby.
    assert not is_finished(None, datetime(2026, 10, 24, 0, 0), None, datetime(2026, 10, 24, 10, 0, tzinfo=UTC))
    assert is_finished(None, datetime(2026, 10, 24, 0, 0), None, datetime(2026, 10, 24, 22, 1, tzinfo=UTC))


def test_transmisje_bez_godziny_nie_maja_okna_o_polnocy():
    from app.streams import rules as R

    untimed = R.match_context({"match_id": "x", "scheduled_at": datetime(2026, 10, 24, 0, 0), "competition_name": "Superliga"})
    timed = R.match_context({"match_id": "y", "scheduled_at": datetime(2026, 10, 24, 18, 0), "competition_name": "Superliga"})
    assert untimed["kickoff_known"] is False and timed["kickoff_known"] is True
    assert R.timed_kickoff(untimed) is None and R.timed_kickoff(timed) == datetime(2026, 10, 24, 16, 0, tzinfo=UTC)
    # Film z RSS meczu „do ustalenia": upcoming do północy, potem vod.
    assert R.state_without_api(R.state_kickoff(untimed), datetime(2026, 10, 24, 20, 0, tzinfo=UTC)) == "upcoming"
    assert R.state_without_api(R.state_kickoff(untimed), datetime(2026, 10, 24, 22, 30, tzinfo=UTC)) == "vod"
    # Wyszukiwanie YouTube nie pali limitu na mecz „o 00:00".
    for m in (untimed, timed):
        m["tier"] = "OS"
    at_midnight = datetime(2026, 10, 23, 22, 10, tzinfo=UTC)
    assert R.pick_search_targets([untimed, timed], set(), {}, at_midnight, remaining=10) == []
    near_timed = datetime(2026, 10, 24, 15, 45, tzinfo=UTC)
    assert [m["match_id"] for m, _ in R.pick_search_targets([untimed, timed], set(), {}, near_timed, remaining=10)] == ["y"]


# ---------------------------------------------------------------------------
# Trasy na SQLite z zamrożonym zegarem
# ---------------------------------------------------------------------------

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.zprp_public.live")


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    nat = define_national(metadata)
    url = f"sqlite:///{tmp_path / 'tz.db'}"
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
    api = importlib.import_module("app.zprp_public.api")
    portal = importlib.import_module("app.zprp_public.portal")
    importlib.import_module("app.zprp_public.enrich").invalidate()
    portal._map_cache.clear()
    yield api, portal, fake.database, {t.name: t for t in list(pub) + list(nat)}
    for name in MODULES:
        sys.modules.pop(name, None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T):
    if await db.fetch_val(sqlalchemy.select(sqlalchemy.func.count()).select_from(T["zprp_public_seasons"])):
        return
    await db.execute(insert(T["zprp_public_seasons"]).values(season_id="S1", start_year=2026, name="2026/27", active=True, **_h()))
    await db.execute(insert(T["zprp_public_clubs"]).values(club_id="c1", name="Śląsk", city="Wrocław", archived=False, **_h()))
    await db.execute(insert(T["zprp_public_clubs"]).values(club_id="c2", name="MMTS", city="Kwidzyn", archived=False, **_h()))
    await db.execute(insert(T["zprp_public_teams"]).values(team_id="t1", season_id="S1", club_id="c1", season_name="2026/27", name="Śląsk", **_h()))
    base = dict(season_id="S1", competition_id="K1", competition_name="LOTTO Superliga", home_team_id="t1", away_team_id="t2",
                home_club_id="c1", away_club_id="c2", home_team_name="Śląsk", away_team_name="MMTS", **_h())
    rows = {
        "wczoraj": dict(scheduled_at=datetime(2026, 10, 23, 18, 0), score_home=30, score_away=28),
        "bez_godziny": dict(scheduled_at=datetime(2026, 10, 24, 0, 0)),
        "poludnie": dict(scheduled_at=datetime(2026, 10, 24, 12, 0)),
        "wieczor": dict(scheduled_at=datetime(2026, 10, 24, 18, 0)),
        "jutro": dict(scheduled_at=datetime(2026, 10, 25, 17, 0)),
    }
    for mid, extra in rows.items():
        await db.execute(insert(T["zprp_public_matches"]).values(match_id=mid, **{**base, **extra}))


def _run(env, factory):
    api, portal, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await factory(api, portal)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_dzis_po_polnocy_to_nowa_doba_a_mecz_bez_godziny_na_koncu(env, monkeypatch):
    # Sobota 24.10.2026 00:30 w Polsce = piątek 22:30 UTC na serwerze.
    _clock(monkeypatch, 2026, 10, 23, 22, 30)
    out = _run(env, lambda api, portal: api.portal_overview())
    assert [m["match_id"] for m in out["today"]] == ["poludnie", "wieczor", "bez_godziny"]
    assert out["today_total"] == 3
    assert [m["kickoff_time_known"] for m in out["today"]] == [True, True, False]
    # Najbliższy: najpierw mecze z godziną, „do ustalenia" dnia za nimi, ale wciąż przed nami.
    assert [m["match_id"] for m in out["upcoming"]][:3] == ["poludnie", "wieczor", "bez_godziny"]
    assert [m["match_id"] for m in out["recent"]] == ["wczoraj"]


def test_dzis_przy_zmianie_czasu_i_klub_przed_nami(env, monkeypatch):
    # 24.10 23:30 UTC = 25.10 01:30 CEST (przed cofnięciem zegara): już niedziela.
    _clock(monkeypatch, 2026, 10, 24, 23, 30)
    out = _run(env, lambda api, portal: api.portal_overview())
    assert [m["match_id"] for m in out["today"]] == ["jutro"]

    # Sobota 15:00 CEST (13:00 UTC): „bez godziny" nadal przed nami (reguła 3 h go nie zdejmuje).
    _clock(monkeypatch, 2026, 10, 24, 13, 0)
    club = _run(env, lambda api, portal: portal.club_overview("c1"))
    assert [m["match_id"] for m in club["upcoming_matches"]] == ["poludnie", "wieczor", "bez_godziny", "jutro"]
    assert [m["match_id"] for m in club["today_matches"]] == ["poludnie", "wieczor", "bez_godziny"]
    assert club["match_counts"]["today"] == 3


def test_live_okno_bez_meczow_bez_godziny(env, monkeypatch):
    def build(api, portal):
        live = importlib.import_module("app.zprp_public.live")
        return live._build_live([])

    # 00:10 w Polsce: mecz „00:00" (do ustalenia) nie „powinien trwać".
    _clock(monkeypatch, 2026, 10, 23, 22, 10)
    out = _run(env, build)
    assert out["window"] == [] and out["soon"] == []
    # 22:30 dzień wcześniej: nie jest też „za chwilę".
    _clock(monkeypatch, 2026, 10, 23, 20, 30)
    assert _run(env, build)["soon"] == []
    # 12:30 CEST: mecz z 12:00 jest w oknie.
    _clock(monkeypatch, 2026, 10, 24, 10, 30)
    assert [c["match_id"] for c in _run(env, build)["window"]] == ["poludnie"]
