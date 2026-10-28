"""Mentor x Bastion: „Szukaj w Bastionie” (Archiwista) i „Wczytaj nagrania sezonu” - reguły pewności i trasy
na atrapie connectora (httpx.MockTransport), bez sieci."""

import importlib
import sys
from datetime import date, datetime, timezone

import httpx
import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from tests.mentor_panel_support import JUDGES, PAIR, STRANGER, Env

A, B = JUDGES


def fresh(monkeypatch):
    """Moduł trzyma `mentor_panel_core` z bazą - po każdym `Env` importujemy go od nowa (jak MODULES w support)."""
    import app as app_package

    monkeypatch.delitem(sys.modules, "app.mentor_bastion_search", raising=False)
    monkeypatch.delattr(app_package, "mentor_bastion_search", raising=False)
    return importlib.import_module("app.mentor_bastion_search")


@pytest.fixture
def S(monkeypatch, tmp_path):
    """Moduł importuje `app.db` (łączy się przy imporcie) - najpierw środowisko testowe."""
    Env(monkeypatch, tmp_path)
    return fresh(monkeypatch)


# ─── Reguły ─────────────────────────────────────────────────────────────────


def card(**kw):
    base = {"match_id": "m1", "match_code": "ISM/1", "home": {"name": "SPR Gliwice"}, "away": {"name": "KS Opole"},
            "scheduled_at": datetime(2026, 10, 12, 16, 0, tzinfo=timezone.utc)}
    base.update(kw)
    return base


def test_team_similarity_ignores_club_prefixes_and_polish_letters(S):
    assert S.team_similarity("SPR Gliwice", "Gliwice") == 1.0
    assert S.team_similarity("MKS Kalisz", "Energa MKS Kalisz") >= 0.8
    assert S.team_similarity("KS Azoty-PWSZ Puławy", "Azoty Pulawy") >= 0.8
    assert S.team_similarity("Łódź", "lodz") == 1.0
    assert S.team_similarity("SPR Gliwice", "KS Opole") == 0.0
    assert S.team_similarity("", "KS Opole") == 0.0


def test_parse_day_formats_and_warsaw_midnight(S):
    assert S.parse_day("2026-10-12") == date(2026, 10, 12)
    assert S.parse_day("12.10.2026 18:00") == date(2026, 10, 12)
    assert S.parse_day("2026-10-12T22:30:00Z") == date(2026, 10, 13)  # 00:30 w Warszawie
    assert S.parse_day("jutro") is None
    assert S.parse_day(None) is None


def test_score_sure_needs_code_teams_and_day(S):
    full = S.score_game({"code": "ISM 1", "home": "Gliwice", "away": "Opole", "date": "2026-10-12"}, card())
    assert full == {"confidence": 100, "sure": True, "signals": {"code": True, "teams": "both", "date": "same"}}
    swapped = S.score_game({"code": "ISM/1", "home": "KS Opole", "away": "SPR Gliwice", "date": "2026-10-12"}, card())
    assert swapped["sure"] is True
    no_code = S.score_game({"home": "Gliwice", "away": "Opole", "date": "2026-10-12"}, card())
    assert no_code["sure"] is False and no_code["confidence"] == 60 and no_code["signals"]["code"] is None
    other_day = S.score_game({"code": "ISM/1", "home": "Gliwice", "away": "Opole", "date": "2026-11-20"}, card())
    assert other_day["sure"] is False and other_day["signals"]["date"] == "far" and other_day["confidence"] == 55
    wrong = S.score_game({"code": "ISM/2", "home": "Gliwice", "away": "Zabrze", "date": "2026-11-20"}, card())
    assert wrong["confidence"] == 0


def test_live_shape_28_10_and_code_case(S):
    """Kształt z próby na żywo (q=LCM/32): data "YYYY-MM-DD HH:MM:SS" czasu polskiego, kod jak w ZPRP."""
    live = {"bunny_item_id": 5632, "home": "AZS AGH Kraków", "away": "ENERGA GWARDIA Koszalin", "date": "2026-10-10 19:00:00",
            "competition": "Liga Centralna Mężczyzn", "code": "LCM/32", "score": "37:32", "video_state": "READY"}
    lcm = card(match_code="LCM/32", home={"name": "AZS AGH Kraków"}, away={"name": "Energa Gwardia Koszalin"},
               scheduled_at=datetime(2026, 10, 10, 17, 0, tzinfo=timezone.utc))
    assert S.score_game(live, lcm)["sure"] is True
    loose = S.score_game({**live, "code": "lcm/32"}, lcm)
    assert loose["signals"]["code"] == "case" and loose["sure"] is False and loose["confidence"] == 75


def test_queries_code_then_team_cores_or_user_text(S):
    assert S.search_queries(card()) == ["ISM/1", "gliwice", "opole"]
    assert S.search_queries(card(), "  Opole  ") == ["Opole"]
    assert S.search_queries(card(match_code=None, home={"name": "KS Opole"}, away={"name": "MKS Opole"})) == ["opole"]


def test_rank_dedupes_marks_added_and_best_skips_added(S):
    games = [
        {"bunny_item_id": 7, "code": "ISM/1", "home": "Gliwice", "away": "Opole", "date": "2026-10-12"},
        {"bunny_item_id": 7, "code": "ISM/1", "home": "Gliwice", "away": "Opole", "date": "2026-10-12"},
        {"bunny_item_id": 8, "home": "Gliwice", "away": "Opole", "date": "2026-10-12"},
        {"bunny_item_id": "x"},
    ]
    ranked = S.rank_games(games, card(), added=[7])
    assert [g["bunny_item_id"] for g in ranked] == [7, 8]
    assert ranked[0]["added"] is True and ranked[0]["url"] == "https://portal.handball-bastion.pl/game?bunny_item_id=7"
    assert S.best_of(ranked) == 8


# ─── Trasy ──────────────────────────────────────────────────────────────────


class Meczoteka:
    """Atrapa connectora: `/games/search` per klucz połączenia (scope / judge)."""

    def __init__(self):
        self.calls = []
        self.games = {}  # klucz -> (http, body)

    def handler(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        self.calls.append((request.url.path, params))
        key = "default" if params.get("scope") == "default" else f"personal-{params.get('judge_id')}"
        if request.url.path == "/games/search":
            http, body = self.games.get(key, (409, {"error": "BASTION_AUTH_REQUIRED"}))
            return httpx.Response(http, json=body)
        return httpx.Response(200, json={"connection": key, "status": "stored"})


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    for k, v in {"BASTION_ENABLED": "true", "BASTION_DEFAULT_ENABLED": "true", "BASTION_PERSONAL_ENABLED": "true",
                 "BASTION_STATUS_CACHE_S": "0", "BASTION_CONNECTOR_URL": "http://connector", "BASTION_CONNECTOR_TOKEN": "t" * 40}.items():
        monkeypatch.setenv(k, v)
    e.search = fresh(monkeypatch)
    e.fake = Meczoteka()
    e.client = e.bastion_client.ConnectorClient("http://connector", "t" * 40, transport=httpx.MockTransport(e.fake.handler),
                                                breaker=e.bastion_client.Breaker(threshold=99))
    monkeypatch.setattr(e.bastion_client, "get_client", lambda: e.client)
    e.mp = monkeypatch
    return e


async def actors(env, judge):
    async def decode(_request, _token):
        return {"judge_id": judge}

    env.mp.setattr(env.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await env.auth.base_actor(r), await env.auth.mentor_actor(r)


async def denied(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail["code"], exc.detail
    raise AssertionError("oczekiwano odmowy")


async def m1_day(env):
    ctx = await env.core.pair_context(PAIR, (await actors(env, A))[1])
    return env.search.card_day(await env.core.match_card(ctx, "m1")).isoformat()


def test_search_ranks_and_picks_best_on_default(env):
    async def go():
        day = await m1_day(env)
        env.fake.games["default"] = (200, {"games": [
            {"bunny_item_id": 11, "home": "SPR Gliwice", "away": "Zabrze", "date": day},
            {"bunny_item_id": 12, "code": "ISM/1", "home": "Gliwice", "away": "KS Opole", "date": day},
        ], "total": 2, "has_more": False})
        real, acting = await actors(env, A)
        out = await env.search.bastion_search(PAIR, "m1", Response(), None, real, acting)
        assert out["best"] == 12 and out["games"][0]["sure"] is True
        assert out["connection_scope"] == "default"
        # Pewne trafienie po pierwszym zapytaniu (kod) - bez dalszych zapytań.
        assert [p["q"] for path, p in env.fake.calls if path == "/games/search"] == ["ISM/1"]
        assert out["games"][1]["confidence"] < 60

    env.run(go)


def test_search_falls_back_to_personal_and_never_401(env):
    async def go():
        env.fake.games[f"personal-{A}"] = (200, {"games": []})
        real, acting = await actors(env, A)
        out = await env.search.bastion_search(PAIR, "m1", Response(), env.search.SearchBody(q="Opole"), real, acting)
        assert out["games"] == [] and out["best"] is None and out["connection_scope"] == "personal"
        env.fake.games.clear()
        status, code, detail = await denied(env.search.bastion_search(PAIR, "m1", Response(), None, real, acting))
        assert (status, code) == (409, "BASTION_AUTH_REQUIRED")
        assert "Połącz" in detail["message"] and detail["can_connect_personal"] is True

    env.run(go)


def test_search_disabled_and_access(env):
    async def go():
        real, acting = await actors(env, STRANGER)
        status, _, _ = await denied(env.search.bastion_search(PAIR, "m1", Response(), None, real, acting))
        assert status in (403, 404)
        env.mp.setenv("BASTION_ENABLED", "false")
        real, acting = await actors(env, A)
        status, code, detail = await denied(env.search.bastion_search(PAIR, "m1", Response(), None, real, acting))
        assert (status, code) == (404, "BASTION_DISABLED") and "YouTube" in detail["message"]

    env.run(go)


def test_search_rate_limit_and_unavailable(env):
    async def go():
        real, acting = await actors(env, A)
        env.fake.games["default"] = (429, {"error": "BASTION_RATE_LIMITED"})
        assert (await denied(env.search.bastion_search(PAIR, "m1", Response(), None, real, acting)))[:2] == (429, "BASTION_RATE_LIMITED")
        env.fake.games["default"] = (503, {"error": "BASTION_UNAVAILABLE"})
        assert (await denied(env.search.bastion_search(PAIR, "m1", Response(), None, real, acting)))[:2] == (503, "BASTION_UNAVAILABLE")

    env.run(go)


def test_season_proposals_skip_matches_with_video_and_future(env):
    async def go():
        env.fake.games["default"] = (200, {"games": [{"bunny_item_id": 40, "code": "SL/3", "home": "Gospodarz", "away": "Gość",
                                                      "date": "2000-01-01"}]})
        real, acting = await actors(env, A)
        out = await env.search.season_proposals(PAIR, Response(), None, real, acting)
        ids = [i["match"]["match_id"] for i in out["items"]]
        assert "m1" not in ids and "m2" not in ids and "m3" in ids  # m1 ma nagranie, m2 dopiero za tydzień
        m3 = next(i for i in out["items"] if i["match"]["match_id"] == "m3")
        # Kod i drużyny się zgadzają, data nie: 55 punktów = próg listy, ale bez pieczątki pewności.
        assert [p["source"] for p in m3["proposals"]] == ["bastion"] and m3["proposals"][0]["sure"] is False
        assert out["bastion"]["state"] == "ok" and out["bastion"]["scope"] == "default"

    env.run(go)


def test_season_proposals_bastion_off_keeps_list(env):
    async def go():
        env.mp.setenv("BASTION_ENABLED", "false")
        real, acting = await actors(env, A)
        out = await env.search.season_proposals(PAIR, Response(), None, real, acting)
        assert out["bastion"]["state"] == "disabled" and "YouTube" in out["bastion"]["message"]
        assert out["scanned"] >= 1 and all(not i["proposals"] for i in out["items"])

    env.run(go)


def test_season_proposals_stops_on_auth(env):
    async def go():
        real, acting = await actors(env, A)
        out = await env.search.season_proposals(PAIR, Response(), None, real, acting)
        assert out["bastion"]["state"] == "auth_required" and "Połącz" in out["bastion"]["message"]

    env.run(go)
