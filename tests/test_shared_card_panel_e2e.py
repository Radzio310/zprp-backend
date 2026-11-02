"""Karta `my:<id>` meczu wspólnego: pełny zestaw pary i mentora (wideo, klip, wątek, flaga, ocena) - 02.11.2026."""

import pytest
from fastapi import HTTPException

from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, STRANGER, Env
from tests.test_shared_matches import denied, make

A, B = JUDGES


class FakeActor:
    def __init__(self, payload, row, admin):
        self.judge_id = str(payload.get("judge_id"))
        self.is_admin = bool(admin)
        self.full_name = (row or {}).get("full_name") or ""
        self.province = (row or {}).get("province") or ""


@pytest.fixture
def env(monkeypatch, tmp_path):
    import importlib

    e = Env(monkeypatch, tmp_path)
    ev = importlib.import_module("app.mentor_evaluations")
    monkeypatch.setattr(ev, "Actor", FakeActor)
    e.seen = []

    async def mentors_of(pair, province):  # tabela tablic obsady jest atrapą; sprawdzamy, co dostaje z karty `my:`
        e.seen.append((tuple(pair), province))
        return {"mentoring": {MENTOR}, "obsada": set()}

    monkeypatch.setattr(ev, "mentors_of", mentors_of)
    return e


def test_mentor_i_para_na_karcie_my(env):
    async def go():
        created = await make(env, code="EHF/2", home_name="Polska", away_name="Słowenia")
        mid = f"my:{created['match']['id']}"
        pair_a, pair_b, mentor = await env.actor(A), await env.actor(B), await env.actor(MENTOR)
        out = {"mid": mid}
        # Mentor widzi kartę i pokój (nie jest w obsadzie meczu).
        room = await env.panel.match_room(PAIR, mid, mentor)
        out["room"] = room["match"]["match_id"]
        # Wideo (link) dodaje mentor, widzi je para.
        video = await env.media.add_video(PAIR, mid, env.media.VideoBody(url="https://vimeo.com/123"), mentor)
        out["video_match"] = video.get("match_id", mid)
        room_b = await env.panel.match_room(PAIR, mid, pair_b)
        out["videos_seen"] = len(room_b["videos"])
        # Klip + wątek + flaga.
        clip = await env.library.create_clip(PAIR, env.library.ClipBody(match_id=mid, video_id=video["id"], start_s=10, end_s=20, title="Faul"), pair_a)
        thread = await env.library.create_thread(PAIR, env.library.ThreadBody(target_kind="clip", target_id=clip["id"], kind="question", body="Czy faul?"), pair_a)
        await env.library.add_comment(thread["id"], env.library.CommentBody(body="Tak."), mentor)
        await env.panel.set_flag(PAIR, mid, env.panel.FlagBody(starred=True), mentor)
        card = await env.core.match_card(await env.core.pair_context(PAIR, pair_a), mid)
        out["card"] = (card["clips"]["count"], card["threads"]["total"], card["starred"], card["videos"]["count"])
        # Ocena mentora (stara ścieżka `mentor_evaluations` też zna `my:`).
        sheet = {"sections": {"I": {"main": "D"}, "II": {"main": "E"}}}
        saved = await env.panel.publish_match_evaluation(PAIR, mid, env.panel.EvaluationBody(sheet=sheet), mentor)
        out["published"] = bool(saved.get("ok"))
        ev = await env.panel.match_evaluation(PAIR, mid, pair_a)
        out["pair_sees"] = bool(ev["published"])
        # Obcy nie ma dostępu.
        out["stranger"] = (await denied(env.panel.match_room(PAIR, mid, await env.actor(STRANGER))))[0]
        return out

    out = env.run(go)
    assert out["room"] == out["mid"] and out["videos_seen"] == 1
    assert out["card"] == (1, 1, True, 1)
    assert out["published"] and out["pair_sees"]
    assert out["stranger"] in (403, 404)
    assert env.seen and env.seen[0][0] == (A, B) and env.seen[0][1] == "ŚLĄSKIE"


def test_numer_zprp_meczu_wspolnego_otwiera_karte_my(env):
    async def go():
        created = await make(env, zprp_match_id="777")
        mid = f"my:{created['match']['id']}"
        await env.panel.set_flag(PAIR, mid, env.panel.FlagBody(starred=True), await env.actor(A))
        ctx = await env.core.pair_context(PAIR, await env.actor(B))
        env.core._match_cache.clear()
        card = await env.core.match_card(ctx, "777")  # aplikacja zna tylko numer ZPRP
        return mid, card["match_id"]

    mid, got = env.run(go)
    assert got == mid
