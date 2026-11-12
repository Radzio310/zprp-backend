"""Podpowiedzi zestawień dla klipu: z tego meczu, po kategorii (udział i nazwa), ostatnio używane, `has_clip`,
trasa z prawami edycji i usuwanie jednego klipu z zestawienia."""

from datetime import datetime, timedelta, timezone

from app import mentor_compilation_suggest as S
from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, Env

import pytest
from starlette.requests import Request

A, _B = JUDGES


def test_ranking_mecz_kategoria_nazwa_i_dopelnienie():
    comps = [{"id": "z_new", "name": "Rzuty"}, {"id": "z_cat", "name": "Kary - listopad"}, {"id": "z_match", "name": "Mecz z Gwardią"},
             {"id": "z_has", "name": "Moje"}, {"id": "z_old", "name": "Stare"}]
    clips = {"a": {"match_id": "m1", "category_ids": []}, "b": {"match_id": "m1", "category_ids": ["kary"]},
             "c": {"match_id": "m2", "category_ids": ["kary"]}, "d": {"match_id": "m3", "category_ids": []}, "me": {"match_id": "m1", "category_ids": ["kary"]}}
    items = {"z_match": ["a", "b"], "z_cat": ["c"], "z_has": ["me", "d"], "z_new": ["d"], "z_old": []}
    out = S.rank(comps, items, clips, match_id="m1", category_ids=["kary"], clip_id="me", category_names={"kary": "Kary"})
    ids = [o["id"] for o in out]
    assert ids[0] == "z_has" and out[0]["has_clip"] is True
    assert ids[1] == "z_match" and out[1]["reasons"][0] == {"kind": "match", "count": 2}
    # Zestawienie z tym klipem liczy też jego: „me” (m1) i „d” (m3) - jeden klip z tego meczu.
    assert out[0]["reasons"][0] == {"kind": "match", "count": 1} and out[0]["items_count"] == 2
    assert ids[2] == "z_cat" and out[2]["reasons"][0]["in_name"] is True and out[2]["reasons"][0]["count"] == 1
    # Dopełnienie „ostatnio używane”, gdy pasujących (bez has_clip) jest mniej niż trzy.
    assert out[3]["reasons"] == [{"kind": "recent"}] and len([o for o in out if o["reasons"][:1] == [{"kind": "recent"}]]) <= 2


def test_nazwa_kategorii_calym_slowem_i_bez_polskich_znakow():
    assert S.name_has("Kary - listopad", "kary")
    assert S.name_has("Błędy sygnalizacji", "bledy")
    assert not S.name_has("Karygodne", "kary")
    assert S.reason_text({"kind": "match", "count": 3}) == "3 klipy z tego meczu"
    assert S.reason_text({"kind": "category", "name": "Kary", "count": 0, "in_name": True}) == "Kary w nazwie"


@pytest.fixture
def e(monkeypatch, tmp_path):
    env = Env(monkeypatch, tmp_path)
    env.mp = monkeypatch
    return env


async def actor_for(e, judge=A):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "GET", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await e.auth.mentor_actor(r)


def test_trasa_podpowiada_i_usuwa_klip(e):
    async def go():
        now = datetime.now(timezone.utc)
        for cid, mid, cats in (("c1", "m1", '["k1"]'), ("c2", "m1", "[]"), ("c3", "m2", '["k1"]')):
            await e.ins("mentor_clips", id=cid, pair_id=PAIR, match_id=mid, video_id="v", start_s=0, end_s=5, title=cid, author_id=A,
                        category_ids=cats, source="manual", created_at=now, updated_at=now, mp4_status="none", media_rev=1)
        await e.ins("mentor_compilations", id="zm", pair_id=PAIR, name="Mecz 1", mode="free", created_by=A, created_at=now, updated_at=now)
        await e.ins("mentor_compilations", id="zc", pair_id=PAIR, name="Inne", mode="free", created_by=MENTOR, created_at=now,
                    updated_at=now - timedelta(days=1))
        await e.ins("mentor_compilation_items", compilation_id="zm", clip_id="c2", position=0)
        await e.ins("mentor_compilation_items", compilation_id="zm", clip_id="c1", position=1)
        await e.ins("mentor_compilation_items", compilation_id="zc", clip_id="c3", position=0)
        actor = await actor_for(e)
        sug = await e.library.suggest_compilations(PAIR, match_id="m1", category_ids="k1", clip_id="c1", actor=actor)
        removed = await e.library.remove_item("zm", "c1", actor)
        return sug, removed

    sug, removed = e.run(go)
    first = sug["suggestions"][0]
    assert first["id"] == "zm" and first["has_clip"] is True and first["reason_text"].startswith("2 klipy z tego meczu")
    assert [i["clip"]["id"] for i in removed["items"]] == ["c2"]
