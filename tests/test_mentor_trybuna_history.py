"""Trybuna: cała historia meczów osoby (GET /mentor-panel/trybuna/referees/history) - strony, filtry, rola, partner, sygnały nagrania."""

import importlib
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from tests.mentor_panel_support import JUDGES, PAIR, STRANGER, Env

H = {"source_hash": "h", "source_json": {}}


class _Resp:
    def __init__(self):
        self.headers = {}


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    # Moduł historii ładujemy na nowo NA atrapie bazy (Env przeładował moduły Trybuny, z których korzysta).
    import app as app_package

    monkeypatch.delitem(sys.modules, "app.mentor_trybuna_history", raising=False)
    monkeypatch.delattr(app_package, "mentor_trybuna_history", raising=False)
    e.history = importlib.import_module("app.mentor_trybuna_history")
    importlib.import_module("app.mentor_bastion_search").forget_swr()
    return e


def call(env, actor, **kw):
    args = {"name": "", "judge_id": "", "offset": 0, "limit": 30, "season": "", "role": "", "scope": "past"}
    args.update(kw)
    return env.history.referee_history(_Resp(), args["name"], args["judge_id"], args["offset"], args["limit"], args["season"],
                                       args["role"], args["scope"], actor)


async def code_of(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, (exc.detail or {}).get("code")
    raise AssertionError("oczekiwano odmowy")


def test_strony_do_konca_najnowsze_najpierw_bez_nadchodzacych(env):
    async def go():
        a = await env.actor(STRANGER)
        base = datetime.now() - timedelta(days=5)
        for i in range(45):
            await env.ins("zprp_public_matches", match_id=f"h{i:02d}", season_id="S1", competition_id="K1", competition_name="I liga mężczyzn",
                          match_code=f"H/{i}", home_team_name=f"Dom {i}", away_team_name=f"Gość {i}", scheduled_at=base - timedelta(days=i),
                          referee_1_id=JUDGES[0], referee_2_name="RAWICKI Jakub", score_home=25, score_away=24, **H)
        p1 = await call(env, a, judge_id=JUDGES[0], limit=20)
        p2 = await call(env, a, judge_id=JUDGES[0], limit=20, offset=p1["next_offset"])
        p3 = await call(env, a, judge_id=JUDGES[0], limit=20, offset=p2["next_offset"])
        everything = await call(env, a, judge_id=JUDGES[0], limit=100, scope="all")
        return p1, p2, p3, everything

    p1, p2, p3, everything = env.run(go)
    # 45 dodanych + m1 i m5 z zasiewu (m2 jest za tydzień, więc nie należy do rozegranych).
    assert p1["total"] == 47 and len(p1["items"]) == 20 and p1["next_offset"] == 20
    assert len(p3["items"]) == 7 and p3["next_offset"] is None
    ids = [i["zprp_match_id"] for p in (p1, p2, p3) for i in p["items"]]
    assert len(ids) == len(set(ids)) == 47 and "m2" not in ids
    dates = [i["date"] for p in (p1, p2, p3) for i in p["items"]]
    assert dates == sorted(dates, reverse=True)
    assert p1["referee"] == {"name": "Anna Nowak", "judge_id": JUDGES[0]}
    first = next(i for i in p1["items"] if i["zprp_match_id"] == "h00")
    assert first["score"] == "25:24" and first["role"] == "referee" and first["role_label"] == "sędzia" and first["position"] == "A"
    assert first["partner"]["name"] == "Jakub Rawicki" and first["upcoming"] is False
    assert {s["season"] for s in p1["seasons"]} and p1["roles"]["referee"] == 47 and "seasons" not in p2
    up = next(i for i in everything["items"] if i["zprp_match_id"] == "m2")
    assert up["upcoming"] is True and everything["total"] == 48


def test_rola_sezon_i_partner_z_listy_sedziow(env):
    async def go():
        a = await env.actor(JUDGES[1])
        old = datetime.now() - timedelta(days=800)
        await env.ins("zprp_public_matches", match_id="old1", season_id="S0", competition_id="K1", competition_name="I liga mężczyzn",
                      match_code="O/1", home_team_name="Stary", away_team_name="Mecz", scheduled_at=old, referee_1_id=JUDGES[0],
                      referee_2_id=JUDGES[1], **H)
        await env.ins("zprp_public_matches", match_id="dl1", season_id="S1", competition_id="K1", competition_name="I liga mężczyzn",
                      match_code="D/1", home_team_name="Delegowany", away_team_name="Mecz", scheduled_at=datetime.now() - timedelta(hours=2),
                      delegate_1_id=JUDGES[0], referee_1_name="NOWAK Adam", referee_2_name="LIS Ewa", **H)
        seasons = await call(env, a, judge_id=JUDGES[0])
        old_season = next(i["season"] for i in seasons["items"] if i["zprp_match_id"] == "old1")
        only_old = await call(env, a, judge_id=JUDGES[0], season=old_season)
        delegate = await call(env, a, judge_id=JUDGES[0], role="delegate")
        referee = await call(env, a, judge_id=JUDGES[0], role="referee")
        bad = await code_of(call(env, a, judge_id=JUDGES[0], season="2025-26"))
        empty = await code_of(call(env, a))
        unknown = await call(env, a, name="Nikt Nieznany")
        return seasons, old_season, only_old, delegate, referee, bad, empty, unknown

    seasons, old_season, only_old, delegate, referee, bad, empty, unknown = env.run(go)
    assert [i["zprp_match_id"] for i in only_old["items"]] == ["old1"] and only_old["season"] == old_season
    assert len(seasons["seasons"]) >= 2 and seasons["roles"] == {"referee": 3, "delegate": 1}
    assert [i["zprp_match_id"] for i in delegate["items"]] == ["dl1"]
    d = delegate["items"][0]
    assert d["role"] == "delegate" and d["role_label"] == "delegat" and d["position"] == "D1" and d["partner"] is None
    assert [r["name"] for r in d["referees"] if r["role"] == "referee"] == ["Adam Nowak", "Ewa Lis"]
    assert "dl1" not in [i["zprp_match_id"] for i in referee["items"]]
    old = next(i for i in seasons["items"] if i["zprp_match_id"] == "old1")
    assert old["partner"] == {"name": "Piotr Lis", "judge_id": JUDGES[1]}   # numer bez nazwiska w hurtowni -> z listy sędziów
    assert bad == (422, "BAD_SEASON") and empty == (422, "BAD_QUERY")
    assert unknown["items"] == [] and unknown["unresolved"] is True and unknown["next_offset"] is None


def test_sygnaly_nagrania_proel_youtube_baza_i_kaseta_z_pamieci_karty(env):
    S = importlib.import_module("app.mentor_bastion_search")
    T = env.trybuna_rules

    async def go():
        a = await env.actor(JUDGES[0])
        now = datetime.now(timezone.utc)
        await env.ins("saved_matches", match_number="ISM/1", zprp_match_id="m1", data_json={}, status="final", updated_at=now)
        await env.ins("match_streams", match_id="m5", url="https://youtu.be/xyzxyzxyz12", platform="youtube", video_id="xyzxyzxyz12",
                      title="A - B", state="vod", confidence="official", source="test")
        cold = await call(env, a, judge_id=JUDGES[0])
        row = await env.db.fetch_one(select(env.T["zprp_public_matches"]).where(env.T["zprp_public_matches"].c.match_id == "m1"))
        card = env.core.R.card_from_public(dict(row))
        local = card["scheduled_at"].astimezone(importlib.import_module("app.streams.rules").WARSAW).strftime("%Y-%m-%d %H:%M:%S")
        game = {"bunny_item_id": 777, "code": "ISM/1", "home": "SPR Gliwice", "away": "KS Opole", "date": local,
                "competition": "I liga mężczyzn", "video_state": "READY", "referees": ["Anna Nowak", "Piotr Lis"]}
        S._swr[("card", a.judge_id, T.name_key("Anna Nowak"), "any")] = (time.monotonic(), ([game], "scope"))
        warm = await call(env, a, judge_id=JUDGES[0])
        return cold, warm

    cold, warm = env.run(go)
    by = {i["zprp_match_id"]: i for i in cold["items"]}
    assert cold["bastion_state"] == "cold" and by["m1"]["bastion"] is None
    assert by["m1"]["proel"] is True and by["m5"]["proel"] is False
    assert by["m5"]["youtube"]["video_id"] == "xyzxyzxyz12" and by["m5"]["youtube"]["official"] is True and by["m5"]["has_video"] is True
    assert {"pair_id": PAIR, "match_id": "m1", "kind": "pair_match"} in by["m1"]["baza"] and by["m1"]["has_video"] is True
    assert by["m1"]["partner"] == {"name": "Piotr Lis", "judge_id": JUDGES[1]}
    assert "home_crest" in by["m1"] and "away_crest" in by["m1"]
    w = {i["zprp_match_id"]: i for i in warm["items"]}
    assert warm["bastion_state"] == "cached"
    assert w["m1"]["bastion"]["bunny_item_id"] == 777 and w["m1"]["bastion"]["state"] == "video" and w["m1"]["bastion"]["added"] is False
    assert w["m5"]["bastion"] is None


def test_odczyt_nie_zmienia_bazy_i_naglowek_no_store(env):
    async def go():
        a = await env.actor(STRANGER)
        resp = _Resp()
        before = len(await env.db.fetch_all(select(env.T["mentor_watched_matches"])))
        out = await env.history.referee_history(resp, "", JUDGES[0], 0, 5, "", "", "past", a)
        after = len(await env.db.fetch_all(select(env.T["mentor_watched_matches"])))
        return resp.headers, out, before, after

    headers, out, before, after = env.run(go)
    assert headers["Cache-Control"] == "no-store" and before == after and len(out["items"]) <= 5


def test_granice_sezonu(env):
    h = env.history
    assert h.season_bounds("2025/2026") == (datetime(2025, 9, 1), datetime(2026, 9, 1))
    assert h.season_bounds("2025/2027") is None and h.season_bounds("") is None and h.season_bounds("abc") is None
