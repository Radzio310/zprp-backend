"""Panel „Mentor" - trasy na małej bazie SQLite (R2, ffmpeg i push podmienione)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from tests.mentor_panel_support import ADMIN, COMMITTEE, JUDGES, MENTOR, PAIR, STRANGER, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def raises(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail.get("code") if isinstance(exc.detail, dict) else exc.detail
    raise AssertionError("oczekiwano odmowy")


def clip_body(env, **over):
    return env.library.ClipBody(**{"match_id": "m1", "video_id": "v1", "start_s": 100, "end_s": 120, "title": "Faul", **over})


# ─── Dostęp ─────────────────────────────────────────────────────────────────


def test_role_i_uprawnienia(env):
    async def go():
        P = env.panel
        out = {}
        for judge in (JUDGES[0], MENTOR, ADMIN, COMMITTEE):
            dash = await P.dashboard(PAIR, await env.actor(judge))
            out[judge] = (dash["role"], dash["can"]["create"], dash["can"]["toggle"])
        out["stranger"] = await raises(P.dashboard(PAIR, await env.actor(STRANGER)))
        committee = await env.actor(COMMITTEE)
        out["committee_clip"] = await raises(env.library.create_clip(PAIR, clip_body(env), committee))
        out["pair_toggle"] = await raises(P.toggle_panel(PAIR, P.PanelBody(enabled=False), await env.actor(JUDGES[0])))
        state = await P.toggle_panel(PAIR, P.PanelBody(enabled=False), committee)
        out["disabled_pair"] = await raises(P.dashboard(PAIR, await env.actor(JUDGES[1])))
        out["disabled_admin"] = (await P.dashboard(PAIR, await env.actor(ADMIN)))["enabled"]
        out["state"] = state
        out["list"] = [(c["id"], c["enabled"], c["role"]) for c in (await P.list_pairs(await env.actor(JUDGES[1])))["pairs"]]
        out["list_stranger"] = (await P.list_pairs(await env.actor(STRANGER)))["pairs"]
        # Para Mentor 2028: komisja nie ma podglądu, admin tak.
        await env.db.execute(update(env.T["mentoring_pairs"]).values(program="mentor2028"))
        out["m2028_committee"] = await raises(P.dashboard(PAIR, committee))
        return out

    out = env.run(go)
    assert out[JUDGES[0]] == ("pair", True, False)
    assert out[MENTOR] == ("mentor", True, False)
    assert out[ADMIN] == ("admin", True, True)
    assert out[COMMITTEE] == ("committee", False, True)
    assert out["stranger"] == (403, "NO_ACCESS")
    assert out["committee_clip"] == (403, "READ_ONLY")
    assert out["pair_toggle"] == (403, "NO_TOGGLE")
    assert out["state"]["enabled"] is False and out["state"]["rev"] == 1
    assert out["disabled_pair"] == (403, "PANEL_DISABLED")
    assert out["disabled_admin"] is False
    assert out["list"] == [(PAIR, False, "pair")]
    assert out["list_stranger"] == []
    assert out["m2028_committee"] == (403, "NO_ACCESS")


def test_mecze_z_trzech_zrodel_bez_duplikatow(env):
    async def go():
        actor = await env.actor(MENTOR)
        listing = await env.panel.matches(PAIR, "", None, None, "", actor)
        only_old = await env.panel.matches(PAIR, listing["seasons"][-1]["season"], None, None, "", actor)
        search = await env.panel.matches(PAIR, "", None, None, "opole", actor)
        return listing, only_old, search

    listing, only_old, search = env.run(go)
    ids = [m["match_id"] for m in listing["matches"]]
    assert ids == ["m2", "m1", "m3", "m4"]  # m5 to inna para, m1 tylko raz
    m1 = listing["matches"][1]
    assert m1["venue_city"] == "Gliwice"  # uzupełnione z monitora okręgu
    assert m1["home"]["logo_url"] == "https://l/c1.png" and m1["category"] == "Seniorzy"
    assert m1["videos"] == {"count": 1, "uploads": 0} and m1["sheets"]["delegate"] == 5.0
    assert listing["matches"][3]["delegate_name"] == "Archiwalny Delegat"
    assert [m["match_id"] for m in only_old["matches"]] == ["m4"]
    assert [m["match_id"] for m in search["matches"]] == ["m1"]
    assert sum(s["matches"] for s in listing["seasons"]) == 4


def test_flaga_zgloszenie_i_powiadomienie(env):
    async def go():
        P = env.panel
        pair = await env.actor(JUDGES[0])
        card = await P.set_flag(PAIR, "m1", P.FlagBody(starred=True, star_reason="Trudny mecz", submitted=True), pair)
        again = await P.set_flag(PAIR, "m1", P.FlagBody(review_status="discussed"), await env.actor(MENTOR))
        dash = await P.dashboard(PAIR, pair)
        foreign = await raises(P.set_flag(PAIR, "m5", P.FlagBody(starred=True), pair))
        return card, again, dash, foreign

    card, again, dash, foreign = env.run(go)
    assert card["starred"] and card["star_reason"] == "Trudny mecz" and card["submitted"] and card["review_status"] == "open"
    assert again["review_status"] == "discussed"
    assert [s["title"] for s in env.sent] == ["Mecz do omówienia"]
    assert env.sent[0]["recipients"] == [MENTOR]  # para zgłasza -> mentorzy
    assert dash["starred_recent"][0]["match_id"] == "m1" and dash["to_discuss"] == []
    assert foreign == (404, "MATCH_NOT_FOUND")


# ─── Klipy, kategorie, zestawienia ──────────────────────────────────────────


def test_kategorie_seed_dodaj_i_przywroc(env):
    async def go():
        L = env.library
        actor = await env.actor(MENTOR)
        first = await L.list_categories(PAIR, actor)
        own = await L.create_category(PAIR, L.CategoryBody(name="Ustawienie", color="teal", icon="walk"), actor)
        changed = await L.update_category(first["categories"][0]["id"], L.CategoryBody(name="Świetna decyzja"), actor)
        bad = await raises(L.create_category(PAIR, L.CategoryBody(name="X", color="#fff", icon="walk"), actor))
        no_global = await raises(L.create_category(PAIR, L.CategoryBody(name="G", color="teal", icon="walk", **{"global": True}), actor))
        reset = await L.reset_categories(PAIR, actor)
        return first, own, changed, bad, no_global, reset

    first, own, changed, bad, no_global, reset = env.run(go)
    assert [c["key"] for c in first["categories"]] == ["dobra", "zla", "dyskusja", "pytanie", "kluczowa"]
    assert "emerald" in first["palette"] and "checkmark-circle" in first["icons"]
    assert own["name"] == "Ustawienie" and own["global"] is False
    assert changed["name"] == "Świetna decyzja"
    assert bad == (422, "CATEGORY_COLOR") and no_global == (403, "ADMIN_ONLY")
    by_name = {c["name"]: c for c in reset["categories"]}
    assert by_name["Dobra decyzja"]["archived"] is False and by_name["Ustawienie"]["archived"] is True
    assert len([c for c in reset["categories"] if not c["archived"]]) == 5


def test_kategorie_kolejnosc_licznik_scalanie_i_cofniecie(env):
    async def go():
        L = env.library
        pair = await env.actor(JUDGES[0])
        committee = await env.actor(COMMITTEE)
        cats = (await L.list_categories(PAIR, pair))["categories"]
        a, b, c = cats[0]["id"], cats[1]["id"], cats[2]["id"]
        only_a = await L.create_clip(PAIR, clip_body(env, category_ids=[a]), pair)
        both = await L.create_clip(PAIR, clip_body(env, category_ids=[a, b], start_s=200, end_s=210), pair)
        await L.create_clip(PAIR, clip_body(env, category_ids=[c], start_s=300, end_s=310), pair)
        counted = await L.list_categories(PAIR, pair)
        ordered = await L.order_categories(PAIR, L.OrderBody(ids=[c, a, "obca", b]), pair)
        no_rights = await raises(L.order_categories(PAIR, L.OrderBody(ids=[a]), committee))
        same = await raises(L.merge_category(a, L.MergeBody(into=a), pair))
        merged = await L.merge_category(a, L.MergeBody(into=b), pair)
        after = {x["id"]: x["category_ids"] for x in (await L.list_clips(PAIR, "", "", "", "", markers=False, actor=pair))["clips"]}
        undone = await L.unmerge_category(a, L.UnmergeBody(into=b, clips=merged["merged"]["clips"]), pair)
        back = {x["id"]: x["category_ids"] for x in (await L.list_clips(PAIR, "", "", "", "", markers=False, actor=pair))["clips"]}
        return a, b, c, only_a, both, counted, ordered, no_rights, same, merged, after, undone, back

    a, b, c, only_a, both, counted, ordered, no_rights, same, merged, after, undone, back = env.run(go)
    usage = {x["id"]: x["clips_count"] for x in counted["categories"]}
    assert usage[a] == 2 and usage[b] == 1 and usage[c] == 1
    live = [x["id"] for x in ordered["categories"] if not x["archived"]]
    assert live[:3] == [c, a, b]
    assert no_rights[0] == 403 and same == (422, "MERGE_TARGET")
    by_id = {x["id"]: x for x in merged["categories"]}
    assert by_id[a]["archived"] is True and by_id[b]["clips_count"] == 2
    assert after[only_a["id"]] == [b] and after[both["id"]] == [b]
    assert {x["id"]: x["archived"] for x in undone["categories"]}[a] is False
    assert back[only_a["id"]] == [a] and sorted(back[both["id"]]) == sorted([a, b])


def test_klipy_wlasnosc_i_walidacja(env):
    async def go():
        L = env.library
        pair, mentor, admin = await env.actor(JUDGES[0]), await env.actor(MENTOR), await env.actor(ADMIN)
        cats = (await L.list_categories(PAIR, pair))["categories"]
        clip = await L.create_clip(PAIR, clip_body(env, category_ids=[cats[0]["id"], "obca"], title="Kara — nr 7 Kowalski"), pair)
        too_long = await raises(L.create_clip(PAIR, clip_body(env, start_s=0, end_s=700), pair))
        beyond = await raises(L.create_clip(PAIR, clip_body(env, start_s=3990, end_s=4100), pair))
        wrong_video = await raises(L.create_clip(PAIR, clip_body(env, match_id="m3"), pair))
        not_owner = await raises(L.update_clip(clip["id"], L.ClipPatch(title="Moje"), mentor))
        as_mentor = await L.list_clips(PAIR, "", "", "", "", markers=False, actor=mentor)
        edited = await L.update_clip(clip["id"], L.ClipPatch(end_s=125, note="Opis"), pair)
        by_category = await L.list_clips(PAIR, cats[0]["id"], "", "", "", markers=False, actor=pair)
        search = await L.list_clips(PAIR, "", "", "", "opis", markers=False, actor=pair)
        deleted = await L.delete_clip(clip["id"], admin)
        after = await L.list_clips(PAIR, "", "", "", "", markers=False, actor=pair)
        return clip, too_long, beyond, wrong_video, not_owner, as_mentor, edited, by_category, search, deleted, after

    clip, too_long, beyond, wrong_video, not_owner, as_mentor, edited, by_category, search, deleted, after = env.run(go)
    assert clip["author"] == {"judge_id": JUDGES[0], "name": "Anna Nowak"} and clip["can_edit"]
    assert clip["title"] == "Kara - nr 7 Kowalski" and len(clip["category_ids"]) == 1
    assert clip["mp4_status"] == "none" and clip["public_url"] is None and clip["thread"] is None
    assert too_long == (422, "CLIP_TOO_LONG") and beyond == (422, "CLIP_RANGE")
    assert wrong_video == (404, "VIDEO_NOT_FOUND") and not_owner == (403, "NOT_OWNER")
    assert as_mentor["clips"][0]["can_edit"] is False
    assert edited["end_s"] == 125 and edited["note"] == "Opis"
    assert len(by_category["clips"]) == 1 and len(search["clips"]) == 1
    assert deleted == {"ok": True} and after["clips"] == []


def test_klip_znaki_istotny_i_do_omowienia(env, monkeypatch):
    sent = []

    async def fake_notify(ctx, actor_id, title, body, **kw):
        sent.append((title, kw.get("recipients"), kw.get("clip_id")))
        return {}

    import app.mentor_panel_notify as N
    monkeypatch.setattr(N, "notify", fake_notify)

    async def go():
        L = env.library
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        clip = await L.create_clip(PAIR, clip_body(env), pair)
        stranger = await raises(L.update_clip(clip["id"], L.ClipPatch(important=True), mentor))
        flagged = await L.update_clip(clip["id"], L.ClipPatch(important=True, to_discuss=True), pair)
        again = await L.update_clip(clip["id"], L.ClipPatch(to_discuss=True), pair)
        cleared = await L.update_clip(clip["id"], L.ClipPatch(important=False, to_discuss=False), pair)
        return clip, stranger, flagged, again, cleared

    clip, stranger, flagged, again, cleared = env.run(go)
    assert clip["important"] is False and clip["to_discuss"] is False
    assert stranger == (403, "NOT_OWNER")
    assert flagged["important"] and flagged["to_discuss"] and again["to_discuss"]
    assert cleared["important"] is False and cleared["to_discuss"] is False
    assert len(sent) == 1 and sent[0][2] == clip["id"] and sent[0][1] == [MENTOR]


def test_zestawienia_kolejnosc_i_wlasnosc(env):
    async def go():
        L = env.library
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        a = await L.create_clip(PAIR, clip_body(env, start_s=10, end_s=20), pair)
        b = await L.create_clip(PAIR, clip_body(env, start_s=30, end_s=40), mentor)
        comp = await L.create_compilation(PAIR, L.CompilationBody(name="Kontrast linii", mode="contrast",
                                                                  items=[{"clip_id": b["id"], "column": "b"}]), pair)
        added = await L.add_item(comp["id"], L.ItemBody(clip_id=a["id"], column="a"), pair)
        reordered = await L.replace_items(comp["id"], L.ItemsBody(items=[{"clip_id": a["id"], "column": "a"},
                                                                        {"clip_id": b["id"], "column": "b"}]), pair)
        foreign = await raises(L.add_item(comp["id"], L.ItemBody(clip_id=a["id"]), mentor))
        missing = await raises(L.replace_items(comp["id"], L.ItemsBody(items=[{"clip_id": "nie-ma"}]), pair))
        bad_mode = await raises(L.create_compilation(PAIR, L.CompilationBody(name="X", mode="inne"), pair))
        await L.delete_clip(b["id"], mentor)
        listing = await L.list_compilations(PAIR, mentor)
        full = await L.get_compilation(comp["id"], mentor)
        renamed = await L.update_compilation(comp["id"], L.CompilationPatch(mode="free"), pair)
        return added, reordered, foreign, missing, bad_mode, listing, full, renamed

    added, reordered, foreign, missing, bad_mode, listing, full, renamed = env.run(go)
    assert [(i["column"], i["position"]) for i in added["items"]] == [("b", 0), ("a", 1)]
    assert [i["clip"]["start_s"] for i in reordered["items"]] == [10, 30]
    assert foreign == (403, "NOT_OWNER") and missing == (422, "CLIP_NOT_FOUND") and bad_mode == (422, "COMPILATION_MODE")
    summary = listing["compilations"][0]
    assert summary["items_count"] == 1 and summary["cover_clip"]["start_s"] == 10 and summary["mode"] == "contrast"
    assert len(full["items"]) == 1 and full["can_edit"] is False
    assert renamed["mode"] == "free" and renamed["items"][0]["column"] is None


def test_zestawienie_jako_playlista_z_etykietami(env):
    async def go():
        L = env.library
        pair = await env.actor(JUDGES[0])
        a = await L.create_clip(PAIR, clip_body(env, start_s=10, end_s=20), pair)
        b = await L.create_clip(PAIR, clip_body(env, start_s=30, end_s=40), pair)
        c = await L.create_clip(PAIR, clip_body(env, start_s=50, end_s=60), pair)
        old = await L.create_compilation(PAIR, L.CompilationBody(name="Stary", mode="contrast",
                                                                 items=[{"clip_id": a["id"], "column": "a"}, {"clip_id": b["id"], "column": "b"}]), pair)
        legacy_read = await L.get_compilation(old["id"], pair)
        saved = await L.replace_items(old["id"], L.ItemsBody(mode="free", items=[
            {"clip_id": b["id"], "label": "Zła decyzja", "note": "spóźniony gwizdek"},
            {"clip_id": a["id"], "label": "Dobra decyzja"}]), pair)
        added = await L.add_item(old["id"], L.ItemBody(clip_id=c["id"], label="Balans", note="obie strony"), pair)
        bad = await raises(L.replace_items(old["id"], L.ItemsBody(mode="inne", items=[]), pair))
        return legacy_read, saved, added, bad

    legacy_read, saved, added, bad = env.run(go)
    assert [i["label"] for i in legacy_read["items"]] == ["Wzorzec", "Do poprawy"]
    assert saved["mode"] == "free" and [(i["label"], i["note"], i["column"]) for i in saved["items"]] == [
        ("Zła decyzja", "spóźniony gwizdek", None), ("Dobra decyzja", None, None)]
    assert [(i["label"], i["note"]) for i in added["items"]][-1] == ("Balans", "obie strony")
    assert bad == (422, "COMPILATION_MODE")


# ─── Wątki ──────────────────────────────────────────────────────────────────


def test_watki_komentarze_wzmianki(env):
    async def go():
        L = env.library
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        clip = await L.create_clip(PAIR, clip_body(env), pair)
        thread = await L.create_thread(PAIR, L.ThreadBody(target_kind="clip", target_id=clip["id"], title="Czy to był faul?",
                                                          kind="question", body="Jak to ocenić?", video_id="v1", video_s=105,
                                                          drawing=[{"kind": "arrow", "points": [[0.1, 0.1], [0.5, 0.5]]}],
                                                          mentions=[MENTOR, STRANGER]), pair)
        reply = await L.add_comment(thread["id"], L.CommentBody(body="Dobra decyzja.", mentions=[JUDGES[1]]), mentor)
        not_owner = await raises(L.update_comment(reply["id"], L.CommentPatch(body="Zmiana"), pair))
        edited = await L.update_comment(reply["id"], L.CommentPatch(body="Bardzo dobra decyzja."), mentor)
        resolved = await L.update_thread(thread["id"], L.ThreadPatch(status="resolved"), pair)
        bad_target = await raises(L.create_thread(PAIR, L.ThreadBody(target_kind="match", target_id="m5", kind="note", body="x"), pair))
        clip_view = (await L.list_clips(PAIR, "", "", "", "", markers=False, actor=pair))["clips"][0]
        listing = await L.list_threads(PAIR, "clip", clip["id"], "", mentor)
        room = await env.panel.match_room(PAIR, "m1", mentor)
        await L.delete_comment(reply["id"], mentor)
        after = await L.list_threads(PAIR, "", "", "resolved", mentor)
        return thread, reply, not_owner, edited, resolved, bad_target, clip_view, listing, room, after

    thread, reply, not_owner, edited, resolved, bad_target, clip_view, listing, room, after = env.run(go)
    first = thread["comments"][0]
    assert thread["match_id"] == "m1" and thread["status"] == "open" and thread["kind"] == "question"
    assert first["video_s"] == 105 and first["mentions"] == [MENTOR] and first["drawing"][0]["kind"] == "arrow"
    assert first["author"]["role"] == "pair"
    assert reply["author"]["role"] == "mentor" and reply["can_edit"]
    assert not_owner == (403, "NOT_OWNER") and edited["body"] == "Bardzo dobra decyzja." and edited["edited_at"]
    assert resolved["status"] == "resolved" and len(resolved["comments"]) == 2
    assert bad_target == (404, "MATCH_NOT_FOUND")
    assert clip_view["thread"] == {"id": thread["id"], "open": False, "comments": 2}
    assert len(listing["threads"]) == 1 and room["threads"][0]["id"] == thread["id"]
    assert len(after["threads"][0]["comments"]) == 1
    titles = [(s["title"], tuple(s["recipients"])) for s in env.sent]
    assert ("Anna Nowak wspomina o Tobie", (MENTOR,)) in titles
    assert ("Nowy wątek: Czy to był faul?", (JUDGES[1],)) in titles
    assert ("Jan Mentor wspomina o Tobie", (JUDGES[1],)) in titles
    assert ("Czy to był faul?", (JUDGES[0],)) in titles


# ─── Publiczne linki ────────────────────────────────────────────────────────


def test_publikacja_i_projekcja_publiczna(env):
    async def go():
        L = env.library
        pair = await env.actor(JUDGES[0])
        clip = await L.create_clip(PAIR, clip_body(env, title="Kara - nr 7 Kowalski"), pair)
        published = await L.publish_clip(clip["id"], pair)
        token = published["public_url"].rsplit("/", 1)[1]
        public = await L.public_view(token)
        comp = await L.create_compilation(PAIR, L.CompilationBody(name="Z", mode="free", items=[{"clip_id": clip["id"]}]), pair)
        comp_url = (await L.publish_compilation(comp["id"], pair))["public_url"]
        public_comp = await L.public_view(comp_url.rsplit("/", 1)[1])
        await env.ins("zprp_public_matches", match_id="m6", season_id="S1", competition_id="K2", competition_name="Liga juniorów",
                      home_team_name="X", away_team_name="Y", scheduled_at=datetime.now() - timedelta(days=1),
                      referee_1_id=JUDGES[0], referee_2_id=JUDGES[1], source_hash="h", source_json={})
        env.core.forget_matches()
        await env.ins("mentor_match_videos", id="v6", match_id="m6", pair_key="|".join(sorted(JUDGES)), url="https://vimeo.com/1",
                      normalized_url="https://vimeo.com/1", provider="vimeo", added_by=JUDGES[0], kind="link")
        youth_clip = await L.create_clip(PAIR, clip_body(env, match_id="m6", video_id="v6"), pair)
        youth = await L.publish_clip(youth_clip["id"], pair)
        off = await L.unpublish_clip(clip["id"], pair)
        gone = await raises(L.public_view(token))
        return published, public, public_comp, youth, off, gone

    published, public, public_comp, youth, off, gone = env.run(go)
    assert published["public_url"].startswith("https://www.bazapodreka.app/mentor/k/") and published["youth_warning"] is False
    assert public["kind"] == "clip" and public["title"] == "Kara - nr 7"
    assert "author" not in public and public["source"]["provider"] == "youtube" and "added_by" not in public["source"]
    assert public["match"]["home"]["name"] == "SPR Gliwice" and "delegate_name" not in public["match"]
    assert public_comp["kind"] == "compilation" and public_comp["items"][0]["clip"]["title"] == "Kara - nr 7"
    assert youth["youth_warning"] is True and "młodzieżowy" in youth["warning"]
    assert off["public_url"] is None and gone == (404, "NOT_FOUND")


# ─── Zmiany na żywo ─────────────────────────────────────────────────────────


def test_zmiany_long_poll_i_obecnosc(env):
    async def go():
        P, L = env.panel, env.library
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        idle = await P.changes(PAIR, 0, 0, pair)
        await P.presence(PAIR, P.PresenceBody(where="match:m1"), mentor)

        async def write_later():
            await asyncio.sleep(0.3)
            await L.create_clip(PAIR, clip_body(env), mentor)

        writer = asyncio.ensure_future(write_later())
        started = asyncio.get_event_loop().time()
        woke = await P.changes(PAIR, 0, 5, pair)
        waited = asyncio.get_event_loop().time() - started
        await writer
        later = await P.changes(PAIR, woke["rev"], 0, pair)
        future = await P.changes(PAIR, 999, 0, pair)
        return idle, woke, waited, later, future

    idle, woke, waited, later, future = env.run(go)
    assert idle == {"rev": 0, "changed": False, "scopes": [], "match_ids": [], "viewers": []}
    assert woke["changed"] and woke["rev"] == 1 and woke["scopes"] == ["clips"] and woke["match_ids"] == ["m1"]
    assert woke["viewers"] == [{"judge_id": MENTOR, "name": "Jan Mentor", "where": "match:m1"}]
    assert waited < 3
    assert later["changed"] is False
    assert future["changed"] is True and "clips" in future["scopes"]


# ─── Wideo, wgrywanie, MP4, retencja ────────────────────────────────────────


class FakeS3:
    def __init__(self):
        self.calls = []

    def create_multipart_upload(self, **kw):
        self.calls.append(("create", kw))
        return {"UploadId": "UP-1"}

    def generate_presigned_url(self, op, Params, ExpiresIn):
        self.calls.append(("sign", op, Params.get("PartNumber"), Params.get("ResponseContentDisposition")))
        return f"https://r2/{op}/{Params['Key']}?part={Params.get('PartNumber')}"

    def complete_multipart_upload(self, **kw):
        self.calls.append(("complete", kw))

    def abort_multipart_upload(self, **kw):
        self.calls.append(("abort", kw))

    def upload_file(self, path, bucket, key, ExtraArgs=None):
        self.calls.append(("upload", key))

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Key))

    def put_object(self, **kw):
        self.calls.append(("put", kw["Key"]))


def _storage(monkeypatch, env):
    s3 = FakeS3()
    monkeypatch.setattr(env.media, "storage_config", lambda: {"endpoint": "e", "region": "auto", "bucket": "b",
                                                              "access_key": "a", "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(env.media, "s3_client", lambda config=None: s3)
    return s3


def test_wgrywanie_transkodowanie_i_mp4(env, monkeypatch, tmp_path):
    s3 = _storage(monkeypatch, env)
    M = env.media
    monkeypatch.setattr(M, "probe", lambda src: {"duration_s": 3600.0, "width": 3840, "height": 2160})

    def fake_transcode(source, target, height, duration, on_progress, cancelled):
        on_progress(0.5)
        open(target, "wb").write(b"mp4")

    def fake_poster(source, target, duration):
        open(target, "wb").write(b"jpg")
        return True

    class Done:
        returncode = 0
        stderr = ""

    def fake_run(args, timeout=None):
        open(args[-1], "wb").write(b"clip-bytes")
        return Done()

    monkeypatch.setattr(M, "transcode", fake_transcode)
    monkeypatch.setattr(M, "poster", fake_poster)
    monkeypatch.setattr(M, "_run", fake_run)

    async def go():
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        started = await M.start_upload(PAIR, "m1", M.UploadBody(filename="mecz.MP4", size=M.R.PART_SIZE * 2 + 5,
                                                                 content_type="video/mp4"), pair)
        uid = started["upload_id"]
        more = await M.more_parts(PAIR, "m1", uid, 3, pair)
        stranger_complete = await raises(M.complete_upload(PAIR, "m1", uid, M.CompleteBody(parts=[]), mentor))
        missing = await raises(M.complete_upload(PAIR, "m1", uid, M.CompleteBody(parts=[{"n": 1, "etag": "a"}]), pair))
        done = await M.complete_upload(PAIR, "m1", uid, M.CompleteBody(parts=[{"n": n, "etag": f"e{n}"} for n in (1, 2, 3)]), pair)
        status_before = await M.upload_status(PAIR, "m1", uid, mentor)
        room_before = await env.panel.match_room(PAIR, "m1", mentor)
        worked = await M.process_next()
        status_after = await M.upload_status(PAIR, "m1", uid, mentor)
        room = await env.panel.match_room(PAIR, "m1", mentor)
        video = next(v for v in room["videos"] if v["kind"] == "upload")
        clip = await env.library.create_clip(PAIR, clip_body(env, video_id=video["id"], start_s=60, end_s=90), mentor)
        link_mp4 = await raises(M.request_mp4((await env.library.create_clip(PAIR, clip_body(env), mentor))["id"], mentor))
        queued = await M.request_mp4(clip["id"], mentor)
        not_ready = await raises(M.download_mp4(clip["id"], mentor))
        await M.process_next()
        download = await M.download_mp4(clip["id"], pair)
        idle = await M.process_next()
        return started, more, stranger_complete, missing, done, status_before, room_before, worked, status_after, video, \
            link_mp4, queued, not_ready, download, idle

    (started, more, stranger_complete, missing, done, status_before, room_before, worked, status_after, video,
     link_mp4, queued, not_ready, download, idle) = env.run(go)
    assert started["total_parts"] == 3 and [p["n"] for p in started["parts"]] == [1, 2, 3]
    assert started["part_size"] == 64 * 1024 * 1024
    create = next(c for c in s3.calls if c[0] == "create")[1]
    assert create["Key"].startswith(f"mentor/{PAIR}/m1/") and create["Key"].endswith("/original.mp4")
    assert [p["n"] for p in more["parts"]] == [3]
    assert stranger_complete == (403, "NOT_OWNER") and missing == (422, "UPLOAD_PARTS")
    assert done["status"] == "processing"
    assert status_before["status"] == "processing"
    pending = next(v for v in room_before["videos"] if v["kind"] == "upload")
    assert pending["upload_status"] == "processing" and pending["playable"] is False
    assert worked is True and status_after == {"status": "ready", "progress": 1.0, "error": None, "video_id": done["video_id"]}
    assert video["playable"] and video["play_url"].endswith("/play.mp4?part=None") and video["poster_url"]
    assert video["provider"] == "upload" and video["duration_s"] == 3600.0
    assert ("upload", create["Key"].rsplit("/", 1)[0] + "/play.mp4") in s3.calls
    assert link_mp4 == (409, "MP4_LINK_VIDEO") and queued == {"mp4_status": "queued"} and not_ready == (409, "MP4_NOT_READY")
    assert download["filename"].endswith("01-00.mp4") and download["size"] == len(b"clip-bytes")
    assert any(c[0] == "sign" and c[3] and "attachment" in c[3] for c in s3.calls)
    assert idle is False


def test_wideo_link_i_usuwanie(env, monkeypatch):
    async def fake_insert(match_id, pair_key, url, added_by, idempotency_key=None):
        row = {"id": "vx", "match_id": match_id, "pair_key": pair_key, "url": url, "normalized_url": url, "provider": "vimeo",
               "added_by": added_by, "kind": "link", "created_at": datetime.now(timezone.utc)}
        await env.db.execute(env.T["mentor_match_videos"].insert().values(**row))
        return row, True

    import app.mentor_evaluations as legacy

    monkeypatch.setattr(legacy, "insert_link_video", fake_insert)

    async def go():
        M = env.media
        mentor, pair = await env.actor(MENTOR), await env.actor(JUDGES[0])
        video = await M.add_video(PAIR, "m3", M.VideoBody(url="https://vimeo.com/123"), mentor)
        bad = await raises(M.add_video(PAIR, "m3", M.VideoBody(url="ftp://zly.adres/x"), mentor))
        synced = await M.update_video(PAIR, "m3", "vx", M.VideoPatch(sync={"match_start_s": 42}), pair)
        # Kto może dodać nagranie, ten może je usunąć (kosz 30 dni, kontrakt 8.9) - także para cudze nagranie mentora.
        deleted = await M.delete_video(PAIR, "m3", "vx", pair)
        return video, bad, synced, None, deleted

    video, bad, synced, not_owner, deleted = env.run(go)
    assert video["kind"] == "link" and video["provider"] == "vimeo" and video["playable"] and video["added_by"]["judge_id"] == MENTOR
    assert bad[0] == 422 and synced["sync"]["match_start_s"] == 42
    assert deleted["ok"] and deleted["trashed"]


def test_retencja_nagran(env, monkeypatch):
    s3 = _storage(monkeypatch, env)

    async def go():
        now = datetime.now(timezone.utc)
        base = {"pair_id": PAIR, "match_id": "m1", "uploader_id": JUDGES[0], "filename": "f.mp4", "size": 10}
        await env.ins("mentor_uploads", id="ready", status="ready", r2_key="o1", play_key="p1", poster_key="j1",
                      created_at=now, expires_at=now + timedelta(days=30), **base)
        await env.ins("mentor_uploads", id="old", status="ready", r2_key=None, play_key="p2", poster_key="j2",
                      created_at=now, expires_at=now - timedelta(days=1), **base)
        await env.ins("mentor_uploads", id="stale", status="uploading", r2_key="o3", upload_id="U3",
                      created_at=now - timedelta(days=2), expires_at=now + timedelta(days=300), **base)
        counts = await env.media.retention_once(now)
        rows = {r["id"]: dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]))}
        return counts, rows

    counts, rows = env.run(go)
    assert counts == {"originals": 1, "expired": 1, "aborted": 1}
    assert rows["ready"]["r2_key"] is None and rows["ready"]["play_key"] == "p1"
    assert rows["old"]["status"] == "expired" and rows["old"]["play_key"] is None
    assert rows["stale"]["status"] == "failed"
    deleted = [c[1] for c in s3.calls if c[0] == "delete"]
    assert set(deleted) == {"o1", "p2", "j2"} and ("abort",) == next(c[:1] for c in s3.calls if c[0] == "abort")


# ─── Arkusze i raporty ──────────────────────────────────────────────────────


def test_arkusze_pary_z_wersjami_mentora(env):
    async def go():
        now = datetime.now(timezone.utc)
        await env.ins("mentor_evaluations", id="e1", match_id="m1", province="ŚLĄSKIE", season="2026/2027", pair_key="|".join(sorted(JUDGES)),
                      author_id=MENTOR, co_author_ids="[]", source="mentoring", status="published", points=5.5, letter="F",
                      sheet_json="{}", published_json='{"sections": {"I": {"main": "E"}}, "priorities": ["Ruch", "", ""]}',
                      match_at=now - timedelta(days=3), published_at=now, created_at=now, updated_at=now)
        await env.ins("mentor_evaluation_versions", evaluation_id="e1", saved_by=MENTOR, sheet_json="{}", points=5.0, letter="E", saved_at=now)
        await env.ins("mentor_evaluations", id="e2", match_id="m9", province="ŚLĄSKIE", pair_key="101|999", author_id=MENTOR,
                      co_author_ids="[]", source="mentoring", status="published", sheet_json="{}", published_json="{}",
                      created_at=now, updated_at=now)
        committee = await env.actor(COMMITTEE)
        return await env.panel.sheets(PAIR, "", committee)

    out = env.run(go)
    assert [d["match_id"] for d in out["delegate"]] == ["m1"]
    assert [m["id"] for m in out["mentor"]] == ["e1"]
    mentor = out["mentor"][0]
    assert mentor["authors"] == [{"judge_id": MENTOR, "name": "Jan Mentor"}] and mentor["versions"][0]["letter"] == "E"
    assert mentor["sheet"]["sections"][0]["mainGrade"] == "E"
    assert out["trends"]["delegate_vs_mentor"] == [{"match_id": "m1", "delegate": 5.0, "mentor": 5.5}]
    assert {p["text"] for p in out["trends"]["priorities"]} == {"Współpraca przy linii 6 m", "Ruch"}


def test_arkusze_zablokowanej_pary_daja_piecz(env):
    async def go():
        committee = await env.actor(COMMITTEE)
        before = await env.panel.sheets(PAIR, "", committee)
        await env.ins("delegate_evaluation_sharing", judge_id=JUDGES[0], sharing_enabled=False)
        one = await env.panel.sheets(PAIR, "", committee)
        await env.ins("delegate_evaluation_sharing", judge_id=JUDGES[1], sharing_enabled=False)
        both = await env.panel.sheets(PAIR, "", committee)
        room = await env.panel.match_room(PAIR, "m1", committee)
        return before, one, both, room

    before, one, both, room = env.run(go)
    assert "sealed" not in before and "sealed" not in one and len(one["delegate"]) == 1
    assert both["delegate"] == [] and both["sealed"]["sheets"] == 1
    pair = both["sealed"]["pairs"][0]
    assert sorted(pair["judge_ids"]) == sorted(JUDGES) and pair["sheets"] == 1 and "evaluation" not in pair
    assert room["delegate_sheets"] == [] and room["sealed"]["sheets"] == 1



def _weasyprint_ok():
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001 - brak biblioteki systemowej (gobject/pango), np. Windows
        return False
    return True


@pytest.mark.skipif(not _weasyprint_ok(), reason="weasyprint/gobject niedostępne na tej maszynie (PDF raportu)")
def test_raport_podglad_pdf_i_publiczny(env, monkeypatch):
    monkeypatch.setattr(env.reports, "THUMB_HOSTS", ())  # bez sieci w testach

    async def go():
        Rp, L = env.reports, env.library
        pair = await env.actor(JUDGES[0])
        await L.create_clip(PAIR, clip_body(env, title="Kara - nr 7 Kowalski"), pair)
        body = Rp.ReportBody(scope={"kind": "season", "season": "2026/2027"}, title="Raport jesień",
                             sections=["summary", "matches", "clips", "sheets", "trends", "priorities", "goals"], goals="Ruch bez piłki")
        preview = await Rp.preview(PAIR, body, pair)
        created = await Rp.create_report(PAIR, body, pair)
        listing = await Rp.list_reports(PAIR, await env.actor(MENTOR))
        published = await Rp.publish_report(created["id"], pair)
        token = published["public_url"].rsplit("/", 1)[1]
        public = await L.public_view(token)
        pdf = await Rp.public_pdf(token)
        own_pdf = await Rp.report_pdf(created["id"], pair)
        return preview, created, listing, public, pdf, own_pdf

    preview, created, listing, public, pdf, own_pdf = env.run(go)
    html = preview["html"]
    assert "Raport jesień" in html and "Sezon 2026/2027" in html and "SPR Gliwice" in html and "Arkusz delegata" in html
    assert "Ruch bez piłki" in html
    assert created["pdf_url"] == f"/mentor-panel/reports/{created['id']}/pdf" and created["public_url"] is None
    assert listing["reports"][0]["title"] == "Raport jesień"
    assert public["kind"] == "report" and "sheets" not in public["sections"] and "delegate_sheets" not in public
    assert public["clips"][0]["title"] == "Kara - nr 7"
    assert pdf.body[:4] == b"%PDF" and own_pdf.body[:4] == b"%PDF"
    assert pdf.media_type == "application/pdf"


# ─── Logowanie web (QR, sesja, CSRF) ────────────────────────────────────────


def test_logowanie_qr_sesja_i_csrf(env, monkeypatch):
    async def fake_bearer(request, token):
        return {"sub": "x", "judge_id": token}

    monkeypatch.setattr(env.auth, "_decode_bearer", fake_bearer)
    app = FastAPI()
    app.include_router(env.panel.panel_router)

    @app.on_event("startup")
    async def start():
        await env.db.connect()
        await env.seed()

    @app.on_event("shutdown")
    async def stop():
        await env.db.disconnect()

    with TestClient(app) as client:
        assert client.get("/mentor-panel/pairs").status_code == 401
        qr = client.post("/mentor-panel/auth/qr", headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"}).json()
        code, poll = qr["code"], qr["poll_token"]
        assert qr["approve_url"] == f"https://www.bazapodreka.app/mentor/zaloguj/{code}"
        assert client.get(f"/mentor-panel/auth/qr/{code}", params={"poll_token": poll, "wait": 0}).json() == {"status": "waiting"}
        assert client.get(f"/mentor-panel/auth/qr/{code}", params={"poll_token": "zly", "wait": 0}).status_code == 404
        approve = client.post(f"/mentor-panel/auth/qr/{code}/approve", headers={"authorization": f"Bearer {JUDGES[0]}"})
        assert approve.json() == {"ok": True, "device_hint": "Chrome na Windows"}
        assert client.post(f"/mentor-panel/auth/qr/{code}/approve", headers={"authorization": f"Bearer {JUDGES[1]}"}).status_code == 409
        done = client.get(f"/mentor-panel/auth/qr/{code}", params={"poll_token": poll, "wait": 0})
        body = done.json()
        assert body["status"] == "approved" and body["me"]["judge_id"] == JUDGES[0] and body["me"]["via"] == "web"
        assert "baza_mentor_session" in done.cookies and "baza_mentor_csrf" in done.cookies
        # Kod jest jednorazowy.
        assert client.get(f"/mentor-panel/auth/qr/{code}", params={"poll_token": poll, "wait": 0}).json() == {"status": "expired"}
        csrf = body["csrf"]
        me = client.get("/mentor-panel/auth/me").json()
        assert me["csrf"] == csrf and me["display_name"] == "Anna Nowak"
        assert client.get("/mentor-panel/pairs").json()["pairs"][0]["id"] == PAIR
        clip = {"match_id": "m1", "video_id": "v1", "start_s": 1, "end_s": 5}
        denied = client.post(f"/mentor-panel/pairs/{PAIR}/clips", json=clip)
        assert denied.status_code == 403 and denied.json()["detail"]["code"] == "CSRF"
        ok = client.post(f"/mentor-panel/pairs/{PAIR}/clips", json=clip, headers={"x-csrf-token": csrf})
        assert ok.status_code == 200 and ok.json()["author"]["judge_id"] == JUDGES[0]
        fresh = client.get("/mentor-panel/auth/csrf").json()["csrf"]
        assert fresh != csrf
        assert client.post(f"/mentor-panel/pairs/{PAIR}/clips", json=clip, headers={"x-csrf-token": csrf}).status_code == 403
        assert client.post(f"/mentor-panel/pairs/{PAIR}/clips", json=clip, headers={"x-csrf-token": fresh}).status_code == 200
        # Aplikacja (JWT) nie potrzebuje CSRF; zatwierdzanie QR tylko z JWT.
        app_call = client.post(f"/mentor-panel/pairs/{PAIR}/clips", json=clip, headers={"authorization": f"Bearer {MENTOR}"})
        assert app_call.status_code == 200
        assert client.post("/mentor-panel/auth/qr/ABCDEFGH/approve").status_code == 401
        assert client.post("/mentor-panel/auth/logout").json() == {"ok": True}
        client.cookies.clear()
        assert client.get("/mentor-panel/auth/me").status_code == 401


def test_logowanie_haslem_z_limitem(env, monkeypatch):
    attempts = []

    async def fake_login(username, password):
        attempts.append(username)
        if password != "dobre":
            raise env.core.R.RuleError(401, "BAD_CREDENTIALS", "Login albo hasło się nie zgadza.")
        return {"judge_id": MENTOR, "display_name": "Jan Mentor | Śląski ZPR"}

    monkeypatch.setattr(env.auth, "_zprp_login", fake_login)
    monkeypatch.setattr(env.auth, "_LOGIN_LIMITER", env.auth.AttemptLimiter(limit=3))
    app = FastAPI()
    app.include_router(env.panel.panel_router)

    @app.on_event("startup")
    async def start():
        await env.db.connect()
        await env.seed()

    @app.on_event("shutdown")
    async def stop():
        await env.db.disconnect()

    with TestClient(app) as client:
        ok = client.post("/mentor-panel/auth/login", json={"username": "jan", "password": "dobre"})
        assert ok.status_code == 200 and ok.json()["me"]["judge_id"] == MENTOR
        client.cookies.clear()
        for _ in range(3):
            assert client.post("/mentor-panel/auth/login", json={"username": "jan", "password": "zle"}).status_code == 401
        blocked = client.post("/mentor-panel/auth/login", json={"username": "jan", "password": "dobre"})
        assert blocked.status_code == 429 and blocked.json()["detail"]["code"] == "RATE_LIMITED"
        assert attempts == ["jan"] * 4


# ─── Powiadomienia ──────────────────────────────────────────────────────────


def test_push_i_zbiorczy_email(env, monkeypatch):
    import importlib
    import sys
    import types

    notify = importlib.reload(env.notify)
    pushes, mails = [], []
    push_module = types.ModuleType("app.push.push")

    async def fake_push(ids, title, body, data, app_variant=None, preference_key=None):
        pushes.append((ids, title, data, preference_key))
        return {"status": "accepted"}

    push_module.send_push_to_judges_report = fake_push
    alerts = types.ModuleType("app.district_alerts")

    async def fake_emails(key, ids, names=None):
        return {i: (f"{i}@x.pl", "login") for i in ids}

    alerts._judge_email_detail = fake_emails
    emails = types.ModuleType("app.province_alert_emails")

    async def fake_send(recipients, subject, html, text, **kw):
        mails.append((recipients, subject))
        return "id"

    emails.send_alert_email = fake_send
    monkeypatch.setitem(sys.modules, "app.push.push", push_module)
    monkeypatch.setitem(sys.modules, "app.district_alerts", alerts)
    monkeypatch.setitem(sys.modules, "app.province_alert_emails", emails)
    ctx = {"pair_id": PAIR, "judge_ids": list(JUDGES), "mentor_ids": [MENTOR], "pair": {"province": "ŚLĄSKIE"}}

    async def go():
        await notify.notify(ctx, JUDGES[0], "Nowy wątek", "Treść", match_id="m1", thread_id="t1")
        await notify.notify(ctx, JUDGES[0], "Odpowiedź", "Treść 2", thread_id="t1")
        first = await notify.flush_emails(now=10_000.0)
        await notify.notify(ctx, MENTOR, "Kolejny", "x", thread_id="t2")
        soon = await notify.flush_emails(now=10_060.0)
        later = await notify.flush_emails(now=10_000.0 + notify.EMAIL_EVERY_S + 1)
        return first, soon, later

    first, soon, later = asyncio.run(go())
    assert pushes[0][0] == [JUDGES[1], MENTOR] and pushes[0][3] == "mentorPanel"
    assert pushes[0][2] == {"type": "mentor_panel", "kind": "mentor_panel", "pairId": PAIR, "matchId": "m1", "threadId": "t1",
                           "target": "thread", "notificationColor": "#FF7A59"}
    assert first == 2 and sorted(m[0][0] for m in mails[:2]) == [f"{JUDGES[1]}@x.pl", f"{MENTOR}@x.pl"]
    assert mails[0][1] == "Mentor: 2 nowe sprawy w panelu pary"
    # Autor („Kolejny" - mentor) nie dostaje; Anna jeszcze nie miała listu, Piotr - dopiero po 30 min.
    assert soon == 1 and mails[2][0] == [f"{JUDGES[0]}@x.pl"]
    assert later == 1 and mails[3][0] == [f"{JUDGES[1]}@x.pl"]


def test_pokoj_meczu_os_z_protokolu_proela(env):
    async def go():
        blob = {"matchConfig": {"hostTeamName": "SPR", "guestTeamName": "KS", "halfTime": 30},
                "protocol": [{"type": "goal", "team": "host", "player": 7, "time": 120000, "half": 1},
                             {"type": "penalty1", "team": "guest", "player": 4, "time": 900000, "half": 1}]}
        await env.ins("saved_matches", match_number="ISM/1", zprp_match_id="m1", data_json=blob, status="finished")
        room = await env.panel.match_room(PAIR, "m1", await env.actor(MENTOR))
        return room

    room = env.run(go)
    assert room["match"]["has_proel"] is True
    timeline = room["timeline"]
    assert timeline["available"] is True and [e["type"] for e in timeline["events"]] == ["goal", "penalty1"]
    assert timeline["events"][1]["clock"] == "15:00"
