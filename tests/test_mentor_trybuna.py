"""Trybuna Mentora: mecz z flagą w pokoju, bilet spinający, bez oceny, idempotencja, kolejka, półki, oznaczenia, głosy, obserwowani."""

import importlib
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from tests.mentor_panel_support import ADMIN, COMMITTEE, JUDGES, MENTOR, PAIR, STRANGER, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)

    async def preview(url):
        return {"title": "SPR Gliwice - KS Opole", "thumbnail_url": None}

    async def start(url, timeout_s=6.0):
        return None

    monkeypatch.setattr(importlib.import_module("app.link_preview"), "preview_or_instant", preview)
    monkeypatch.setattr(importlib.import_module("app.mentor_evaluations"), "_stream_start_or_none", start)
    return e


async def code_of(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, (exc.detail or {}).get("code")
    raise AssertionError("oczekiwano odmowy")


async def m1_when(env):
    from app.streams.rules import WARSAW

    row = await env.db.fetch_one(select(env.T["zprp_public_matches"]).where(env.T["zprp_public_matches"].c.match_id == "m1"))
    card = env.core.R.card_from_public(dict(row))
    return card["scheduled_at"].astimezone(WARSAW).strftime("%Y-%m-%d %H:%M")


def body(env, **kw):
    return env.trybuna.WatchBody(**kw)


# ─── Reguły (czyste) ────────────────────────────────────────────────────────


def test_kategoria_u18_to_osobny_sygnal_i_obniza_pewnosc(env):
    S = importlib.import_module("app.mentor_bastion_search")
    card = {"match_code": "ISM/1", "home": {"name": "SPR Gliwice"}, "away": {"name": "KS Opole"}, "competition_name": "I liga mężczyzn",
            "scheduled_at": datetime(2026, 10, 12, 16, 0, tzinfo=timezone.utc)}
    senior = {"code": "ISM/1", "home": "SPR Gliwice", "away": "KS Opole", "date": "2026-10-12 18:00:00", "competition": "I Liga Mężczyzn"}
    youth = dict(senior, competition="Mistrzostwa Polski U18")
    women = dict(senior, competition="Superliga Kobiet")
    a, b, c = S.score_game(senior, card), S.score_game(youth, card), S.score_game(women, card)
    assert a["sure"] and a["signals"]["category"] == "same"
    assert b["signals"]["category"] == "diff" and not b["sure"] and b["confidence"] < a["confidence"]
    assert c["signals"]["category"] == "diff" and not c["sure"]
    assert S.category_signal({"competition": "Juniorzy młodsi"}, {"competition_name": "Liga U16"}) == "same"
    assert S.category_signal({}, {"competition_name": "x"}) is None


def test_best_wymaga_kodu_meczu(env):
    S = importlib.import_module("app.mentor_bastion_search")
    no_code = [{"bunny_item_id": 1, "added": False, "confidence": 80, "signals": {"code": None}}]
    with_code = [{"bunny_item_id": 2, "added": False, "confidence": 80, "signals": {"code": True}}]
    case_only = [{"bunny_item_id": 3, "added": False, "confidence": 80, "signals": {"code": "case"}}]
    assert S.best_of(no_code) is None and S.best_of(case_only) is None and S.best_of(with_code) == 2


def test_pick_link_auto_tylko_przy_luce(env):
    T = env.trybuna_rules
    one = T.pick_link([{"confidence": 80, "sure": False}, {"confidence": 40, "sure": False}])
    close = T.pick_link([{"confidence": 80, "sure": False}, {"confidence": 75, "sure": False}])
    two_sure = T.pick_link([{"confidence": 100, "sure": True}, {"confidence": 100, "sure": True}])
    none = T.pick_link([{"confidence": 10}])
    assert one["state"] == "auto" and close["state"] == "candidates" and two_sure["state"] == "candidates" and none["state"] == "none"


def test_nazwisko_bez_kolejnosci_i_polskich_znakow(env):
    T = env.trybuna_rules
    assert T.name_key("Łukasz Żółć") == T.name_key("zolc lukasz")
    assert T.same_referee({"name": "Jan Kowalski"}, {"name": "kowalski jan"})
    assert not T.same_referee({"name": "Jan Kowalski", "judge_id": "1"}, {"name": "Jan Kowalski", "judge_id": "2"})
    assert [r["name"] for r in T.clean_referees(["Jan Kowalski", {"name": "kowalski jan"}, "Adam Nowak"])] == ["Jan Kowalski", "Adam Nowak"]


# ─── Dodawanie, bilet, pokój ────────────────────────────────────────────────


def test_dodanie_z_youtube_spina_zprp_i_pokoj_dziala_bez_oceny(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        when = await m1_when(env)
        out = await env.trybuna.add_watched(
            PAIR, body(env, url="https://youtu.be/abcdefghijk", home="SPR Gliwice", away="KS Opole", date=when, code="ISM/1"),
            _Resp(), actor, actor, idempotency_header=None)
        mid = out["match"]["match_id"]
        room = await env.panel.match_room(PAIR, mid, actor)
        err = await code_of(env.panel.match_evaluation(PAIR, mid, actor))
        err2 = await code_of(env.panel.save_match_evaluation(PAIR, mid, env.panel.EvaluationBody(sheet={}), actor))
        listing = await env.trybuna.list_watched(PAIR, q="", referee="", origin="", season="", actor=actor)
        pair_matches = await env.panel.matches(PAIR, season="", starred=None, submitted=None, q="", actor=actor)
        return out, room, err, err2, listing, pair_matches

    out, room, err, err2, listing, pair_matches = env.run(go)
    assert out["created"] and out["match"]["watched"] is True and out["match"]["match_id"].startswith("tr_")
    assert out["links"]["zprp"]["state"] == "auto" and out["links"]["zprp"]["chosen"]["zprp_match_id"] == "m1"
    assert out["match"]["zprp_match_id"] == "m1" and [r["judge_id"] for r in out["match"]["referees"]] == list(JUDGES)
    assert len(out["videos"]) == 1
    assert room["match"]["watched"] and room["watched"] and len(room["videos"]) == 1
    assert room["delegate_sheets"] == [] and room["mentor_sheets"] == []
    assert err == (409, "TRYBUNA_NO_EVALUATION") and err2 == (409, "TRYBUNA_NO_EVALUATION")
    assert [m["match_id"] for m in listing["matches"]] == [out["match"]["match_id"]]
    assert out["match"]["match_id"] not in [m["match_id"] for m in pair_matches["matches"]]  # mecze pary bez Trybuny


class _Resp:
    def __init__(self):
        self.headers = {}


def test_ten_sam_adres_to_ten_sam_mecz_i_prawa(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        first = await env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/abcdefghijk", home="A", away="B"), _Resp(), actor, actor,
                                              idempotency_header=None)
        again = await env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/abcdefghijk"), _Resp(), actor, actor,
                                              idempotency_header=None)
        stranger = await env.actor(STRANGER)
        committee = await env.actor(COMMITTEE)
        mentor = await env.actor(MENTOR)
        denied = await code_of(env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/zzzzzzzzzzz"), _Resp(), stranger, stranger,
                                                       idempotency_header=None))
        ro = await code_of(env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/zzzzzzzzzzz"), _Resp(), committee, committee,
                                                   idempotency_header=None))
        viewed = await env.trybuna.list_watched(PAIR, q="", referee="", origin="", season="", actor=mentor)
        return first, again, denied, ro, viewed

    first, again, denied, ro, viewed = env.run(go)
    assert not again["created"] and again["match"]["match_id"] == first["match"]["match_id"]
    assert denied[0] in (403, 404) and ro[0] == 403
    assert len(viewed["matches"]) == 1  # mentor widzi mecz pary


def test_klip_watek_i_zdanie_na_meczu_z_trybuny(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        out = await env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/abcdefghijk", home="A", away="B"), _Resp(), actor, actor,
                                            idempotency_header=None)
        mid, vid = out["match"]["match_id"], out["videos"][0]["id"]
        clip = await env.library.create_clip(PAIR, env.library.ClipBody(match_id=mid, video_id=vid, start_s=10, end_s=30, title="Faul"), actor)
        thread = await env.library.create_thread(PAIR, env.library.ThreadBody(target_kind="clip", target_id=clip["id"], body="Co sadzicie?", kind="question", video_s=15), actor)
        mentor = await env.actor(MENTOR)
        v1 = await env.trybuna.put_opinion(thread["id"], env.trybuna.OpinionBody(vote="agree"), actor)
        v2 = await env.trybuna.put_opinion(thread["id"], env.trybuna.OpinionBody(vote="differ"), mentor)
        v3 = await env.trybuna.put_opinion(thread["id"], env.trybuna.OpinionBody(vote="differ"), actor)
        bad = await code_of(env.trybuna.put_opinion(thread["id"], env.trybuna.OpinionBody(vote="zle"), actor))
        gone = await env.trybuna.put_opinion(thread["id"], env.trybuna.OpinionBody(vote=None), mentor)
        tags = await env.trybuna.set_clip_referees(clip["id"], env.trybuna.RefereeTags(referees=[{"name": "Jan Kowalski", "role": "a", "position": "bramkowy"}]), actor)
        shown = await env.trybuna.clip_referees(clip["id"], actor)
        too_many = await code_of(env.trybuna.set_clip_referees(clip["id"], env.trybuna.RefereeTags(referees=[{"name": f"S{i}"} for i in range(5)]), actor))
        bad_role = await code_of(env.trybuna.set_clip_referees(clip["id"], env.trybuna.RefereeTags(referees=[{"name": "X", "role": "Z"}]), actor))
        room = await env.panel.match_room(PAIR, mid, actor)
        lib = await env.library.list_clips(PAIR, category="", match_id=mid, author="", q="", markers=False, actor=actor)
        return clip, v1, v2, v3, bad, gone, tags, shown, too_many, bad_role, room, lib

    clip, v1, v2, v3, bad, gone, tags, shown, too_many, bad_role, room, lib = env.run(go)
    assert v1["counts"]["agree"] == 1 and v1["mine"] == "agree"
    assert v2["total"] == 2 and v3["counts"] == {"agree": 0, "differ": 2, "unsure": 0} and v3["mine"] == "differ"
    assert bad[1] == "BAD_VOTE" and gone["total"] == 1
    assert tags["referees"][0]["role"] == "A" and shown["referees"][0]["position"] == "bramkowy"
    assert too_many[1] == "TAG_LIMIT" and bad_role[1] == "TAG_ROLE"
    assert [c["id"] for c in room["clips"]] == [clip["id"]]
    assert [c["id"] for c in lib["clips"]] == [clip["id"]]


def test_reczna_poprawka_biletu_jest_trwala(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        out = await env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/abcdefghijk", home="Zupelnie", away="Inny"), _Resp(), actor, actor,
                                            idempotency_header=None)
        mid = out["match"]["match_id"]
        before = out["links"]["zprp"]["state"]
        put = await env.trybuna.put_links(PAIR, mid, env.trybuna.LinkPut(zprp_match_id="m1"), _Resp(), actor)
        again = await env.trybuna.relink(PAIR, mid, _Resp(), env.trybuna.RelinkBody(kinds=["zprp"]), actor, actor)
        forced = await env.trybuna.relink(PAIR, mid, _Resp(), env.trybuna.RelinkBody(kinds=["zprp"], force=True), actor, actor)
        missing = await code_of(env.trybuna.put_links(PAIR, mid, env.trybuna.LinkPut(zprp_match_id="nie-ma"), _Resp(), actor))
        cleared = await env.trybuna.put_links(PAIR, mid, env.trybuna.LinkPut(zprp_match_id=""), _Resp(), actor)
        return before, put, again, forced, missing, cleared

    before, put, again, forced, missing, cleared = env.run(go)
    assert before in ("none", "candidates")
    assert put["links"]["zprp"]["state"] == "manual" and put["match"]["zprp_match_id"] == "m1"
    assert again["links"]["zprp"]["state"] == "manual"  # automat nie nadpisuje poprawki
    assert forced["links"]["zprp"]["state"] != "manual"
    assert missing == (404, "ZPRP_MATCH_NOT_FOUND")
    assert cleared["links"]["zprp"]["state"] == "none" and cleared["match"]["zprp_match_id"] is None


# ─── Idempotencja ───────────────────────────────────────────────────────────


def test_idempotency_key_powtorka_zwraca_to_samo(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        a = await env.media.add_video(PAIR, "m1", env.media.VideoBody(url="https://youtu.be/newvideo001"), actor, idempotency_header="11111111-aaaa")
        b = await env.media.add_video(PAIR, "m1", env.media.VideoBody(url="https://youtu.be/newvideo001"), actor, idempotency_header="11111111-aaaa")
        other_url = await code_of(env.media.add_video(PAIR, "m1", env.media.VideoBody(url="https://youtu.be/newvideo002"), actor,
                                                      idempotency_header="11111111-aaaa"))
        bad = await code_of(env.media.add_video(PAIR, "m1", env.media.VideoBody(url="https://youtu.be/newvideo003"), actor, idempotency_header="x y"))
        rows = await env.db.fetch_all(select(env.T["mentor_match_videos"]).where(env.T["mentor_match_videos"].c.idempotency_key == "11111111-aaaa"))
        from app.mentor_evaluations import insert_link_video

        # Wyścig: wiersz o tym kluczu już istnieje (wstawił go równoległy proces) - druga próba nie robi duplikatu.
        c, created = await insert_link_video("m1", "|".join(sorted(JUDGES)), "https://youtu.be/newvideo001", JUDGES[0], "11111111-aaaa")
        return a, b, other_url, bad, rows, c, created

    a, b, other_url, bad, rows, c, created = env.run(go)
    assert a["id"] == b["id"] and len(rows) == 1 and c["id"] == a["id"] and created is False
    assert other_url == (409, "IDEMPOTENCY_KEY_REUSED") and bad[1] == "BAD_IDEMPOTENCY_KEY"


# ─── Kosz: transakcja, komentarze, osierocone klipy ────────────────────────


async def seed_video_case(env):
    now = datetime.now(timezone.utc)
    await env.ins("mentor_clips", id="c1", pair_id=PAIR, match_id="m1", video_id="v1", start_s=10, end_s=20, author_id=JUDGES[0])
    await env.ins("mentor_threads", id="t2", pair_id=PAIR, target_kind="match", target_id="m1", match_id="m1", created_by=MENTOR)
    await env.ins("mentor_comments", id="k2", thread_id="t2", author_id=MENTOR, body="Kotwica", video_id="v1", video_s=50, created_at=now)
    await env.ins("mentor_comments", id="k9", thread_id="t2", author_id=MENTOR, body="Skasowany wczesniej", video_id="v1", video_s=60,
                  created_at=now, deleted_at=now)


def test_kosz_transakcja_podwojne_usuniecie_i_trwale_kasuje_komentarze(env):
    async def go():
        await seed_video_case(env)
        pair = await env.actor(JUDGES[0])
        impact = await env.media.video_delete_impact(PAIR, "m1", "v1", pair)
        first = await env.media.delete_video(PAIR, "m1", "v1", pair)
        again = await code_of(env.media.delete_video(PAIR, "m1", "v1", pair))
        trashed = await env.db.fetch_all(select(env.T["mentor_match_videos"].c.deleted_at).where(env.T["mentor_match_videos"].c.id == "v1"))
        purged = await env.media.purge_video(PAIR, "m1", "v1", pair)
        comments = {r["id"] for r in await env.db.fetch_all(select(env.T["mentor_comments"].c.id))}
        row = await env.db.fetch_one(select(env.T["mentor_match_videos"].c.trash_json).where(env.T["mentor_match_videos"].c.id == "v1"))
        again_purge = await code_of(env.media.purge_video(PAIR, "m1", "v1", pair))
        return impact, first, again, trashed, purged, comments, row, again_purge

    impact, first, again, trashed, purged, comments, row, again_purge = env.run(go)
    assert impact["orphan_clips"] == 1 and impact["orphans_permanent"] is False  # link wraca z kosza
    assert first["trashed"] and first["orphan_clips"] == 1
    assert again[0] == 404 and trashed[0]["deleted_at"] is not None
    assert purged["purged"] and purged["tombstone"] is True  # klip c1 trzyma nagrobek
    assert "k2" not in comments and "k9" not in comments  # miękko usunięte komentarze znikają przy "usuń na zawsze"
    assert "purged" in (row["trash_json"] or "")
    assert again_purge[0] == 409


def test_usuniecie_wgranego_nagrania_ostrzega_o_osieroconych_klipach(env):
    async def go():
        await seed_video_case(env)
        await env.ins("mentor_uploads", id="u1", pair_id=PAIR, match_id="m1", filename="mecz.mp4", size=10, status="ready", uploader_id=JUDGES[0])
        await env.db.execute(env.T["mentor_match_videos"].update().where(env.T["mentor_match_videos"].c.id == "v1")
                             .values(kind="upload", upload_id="u1", provider="upload"))
        pair = await env.actor(JUDGES[0])
        impact = await env.media.video_delete_impact(PAIR, "m1", "v1", pair)
        out = await env.media.delete_video(PAIR, "m1", "v1", pair)
        return impact, out

    impact, out = env.run(go)
    assert impact["orphan_clips"] == 1 and impact["orphans_permanent"] is True and impact["restorable"] is False
    assert out["trashed"] is False and out["orphan_clips"] == 1


# ─── Szukanie: pamięć, limit, strona druga, 429 ─────────────────────────────


class FakeClient:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    async def request(self, method, path, params=None, json=None, timeout=None):
        from app import mentor_bastion_client as CL

        self.calls.append(dict(params or {}))
        status, body = self.pages[min(len(self.calls) - 1, len(self.pages) - 1)]
        return CL.Reply(status, body) if hasattr(CL, "Reply") else (status, body)


def meczoteka(env, pages, **kw):
    S = importlib.import_module("app.mentor_bastion_search")
    S.forget_search_cache()
    client = FakeClient(pages)

    class Real:
        judge_id = JUDGES[0]

    return S, client, S.Meczoteka(client, ["default"], Real(), **kw)


def test_pamiec_wynikow_i_limit_na_uzytkownika(env):
    async def go():
        S, client, mz = meczoteka(env, [(200, {"games": [{"bunny_item_id": 1}], "has_more": False})])
        a = await mz.search("ISM/1")
        b = await mz.search("ISM/1")  # z pamięci - bez zapytania
        calls = len(client.calls)
        S.RATE_MAX = 2
        S.forget_search_cache()
        await mz.search("a")
        await mz.search("b")
        try:
            await mz.search("c")
            blocked = False
        except S._Stop as stop:
            blocked = stop.verdicts[0][1].kind == "rate_limited"
        return a, b, calls, blocked

    a, b, calls, blocked = env.run(go)
    assert a == b and calls == 1 and blocked


def test_druga_strona_gdy_pierwsza_pusta(env):
    async def go():
        S, client, mz = meczoteka(env, [(200, {"games": [], "has_more": True}), (200, {"games": [{"bunny_item_id": 7}], "has_more": False})])
        games = await mz.search("kod")
        return games, client.calls

    games, calls = env.run(go)
    assert [g["bunny_item_id"] for g in games] == [7] and calls[1]["offset"] == 20


def test_jedno_ponowienie_po_429(env):
    async def go():
        S, client, mz = meczoteka(env, [(429, {"error": "x"}), (200, {"games": [{"bunny_item_id": 3}], "has_more": False})], retry_429=True)
        S.RETRY_429_DELAY_S = 0
        ok = await mz.search("a")
        S2, client2, mz2 = meczoteka(env, [(429, {"error": "x"}), (429, {"error": "x"}), (200, {"games": [], "has_more": False})], retry_429=True)
        S2.RETRY_429_DELAY_S = 0
        try:
            await mz2.search("a")
            second = None
        except S2._Stop as stop:
            second = stop.verdicts[0][1].kind
        return ok, len(client.calls), second, len(client2.calls)

    ok, calls, second, calls2 = env.run(go)
    assert [g["bunny_item_id"] for g in ok] == [3] and calls == 2
    assert second == "rate_limited" and calls2 == 2  # tylko jedno ponowienie


# ─── Obserwowani, kanał, kolejka, półki, dzienny push ──────────────────────


def test_obserwowani_kalendarz_i_kolejka(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        made = await env.trybuna_feed.follow(env.trybuna_feed.FollowBody(kind="referee", name="Piotr Lis"), actor)
        dup = await env.trybuna_feed.follow(env.trybuna_feed.FollowBody(kind="referee", name="lis piotr"), actor)
        pair_follow = await env.trybuna_feed.follow(env.trybuna_feed.FollowBody(kind="pair", names=["Anna Nowak", "Piotr Lis"]), actor)
        bad = await code_of(env.trybuna_feed.follow(env.trybuna_feed.FollowBody(kind="pair", names=["Anna Nowak"]), actor))
        cal = await env.trybuna_feed.calendar(30, actor)
        out = await env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/abcdefghijk", home="A", away="B"), _Resp(), actor, actor,
                                            idempotency_header=None)
        mid = out["match"]["match_id"]
        q = await env.trybuna_feed.queue_add(env.trybuna_feed.QueueAdd(pair_id=PAIR, match_id=mid), actor)
        qq = await env.trybuna_feed.queue_add(env.trybuna_feed.QueueAdd(pair_id=PAIR, match_id=mid), actor)
        patched = await env.trybuna_feed.queue_patch(PAIR, mid, env.trybuna_feed.QueuePatch(progress_s=95), actor)
        done = await env.trybuna_feed.queue_patch(PAIR, mid, env.trybuna_feed.QueuePatch(done=True), actor)
        removed = await env.trybuna_feed.queue_remove(PAIR, mid, actor)
        foreign = await code_of(env.trybuna_feed.queue_add(env.trybuna_feed.QueueAdd(pair_id=PAIR, match_id="m1"), actor))
        gone = await env.trybuna_feed.unfollow(made["follow"]["id"], actor)
        return made, dup, pair_follow, bad, cal, q, qq, patched, done, removed, foreign, gone

    made, dup, pair_follow, bad, cal, q, qq, patched, done, removed, foreign, gone = env.run(go)
    assert made["created"] and made["follow"]["judge_ids"] == [JUDGES[1]] and dup["created"] is False
    assert pair_follow["follow"]["judge_ids"] == list(JUDGES) and bad[1] == "FOLLOW_NAMES"
    assert [i["zprp_match_id"] for i in cal["items"]] == ["m2"]  # jedyny nadchodzący z Piotrem Lisem w obsadzie
    assert q["pending"] == 1 and qq["pending"] == 1 and patched["items"][0]["progress_s"] == 95
    assert done["done"] == 1 and removed["items"] == [] and foreign[1] == "MATCH_NOT_FOUND"
    assert len(gone["follows"]) == 1


def test_polki_klip_na_wielu_polkach(env):
    async def go():
        actor = await env.actor(JUDGES[0])
        out = await env.trybuna.add_watched(PAIR, body(env, url="https://youtu.be/abcdefghijk", home="A", away="B"), _Resp(), actor, actor,
                                            idempotency_header=None)
        mid, vid = out["match"]["match_id"], out["videos"][0]["id"]
        clip = await env.library.create_clip(PAIR, env.library.ClipBody(match_id=mid, video_id=vid, start_s=1, end_s=9), actor)
        s1 = (await env.trybuna.create_shelf(PAIR, env.trybuna.ShelfBody(name="Linia 6 m"), actor))["shelves"][0]
        dup = await code_of(env.trybuna.create_shelf(PAIR, env.trybuna.ShelfBody(name="linia 6 M"), actor))
        await env.trybuna.create_shelf(PAIR, env.trybuna.ShelfBody(name="Kontakt"), actor)
        shelves = (await env.trybuna.list_shelves(PAIR, actor))["shelves"]
        for s in shelves:
            await env.trybuna.add_shelf_clip(PAIR, s["id"], env.trybuna.ShelfClipOne(clip_id=clip["id"]), actor)
        both = await env.trybuna.add_shelf_clip(PAIR, s1["id"], env.trybuna.ShelfClipOne(clip_id=clip["id"]), actor)  # powtórka nic nie robi
        foreign = await code_of(env.trybuna.add_shelf_clip(PAIR, s1["id"], env.trybuna.ShelfClipOne(clip_id="nie-moj"), actor))
        mentor = await env.actor(MENTOR)
        shared = await env.trybuna.list_shelves(PAIR, mentor)
        return clip, dup, both, foreign, shared

    clip, dup, both, foreign, shared = env.run(go)
    assert dup[1] == "SHELF_EXISTS" and foreign[0] == 404
    assert sorted(len(v) for v in both["by_clip"].values()) == [2] and len(both["by_clip"][clip["id"]]) == 2
    assert all(s["clips_count"] == 1 for s in shared["shelves"])


def test_dzienny_push_bez_powtorek_i_okno_dat(env):
    S = importlib.import_module("app.mentor_bastion_search")
    F = env.trybuna_feed
    from datetime import date

    today = date(2026, 10, 28)
    row = {"id": "f", "judge_id": "5", "kind": "referee", "name": "Jan Kowalski", "judge_ids": "[]", "names": '["Jan Kowalski"]'}
    games = [
        {"bunny_item_id": 1, "date": "2026-10-27 18:00:00", "video_state": "READY", "referees": []},
        {"bunny_item_id": 2, "date": "2026-10-27 18:00:00", "video_state": "PROCESSING", "referees": []},  # czeka na nagranie
        {"bunny_item_id": 3, "date": "2026-09-01 18:00:00", "video_state": "READY", "referees": []},  # za stary
        {"bunny_item_id": 4, "date": "2026-10-28 12:00:00", "video_state": "READY", "referees": [{"name": "Adam Nowak"}]},  # inny sędzia
        {"bunny_item_id": 5, "date": "2026-10-28 12:00:00", "video_state": "READY", "referees": [{"name": "kowalski jan"}]},
    ]
    first = [g["bunny_item_id"] for g in F.new_games_for(row, games, set(), today)]
    second = [g["bunny_item_id"] for g in F.new_games_for(row, games, {1, 5}, today)]
    assert first == [1, 5] and second == []


# ─── nominees: filtr po obsadzie, role, kalendarz przyszłych meczów ────────


def test_q_po_sedzi_zostawia_tylko_mecze_z_nim_w_obsadzie_i_rozroznia_role(env):
    async def go():
        ref = [{"name": "Jakub Rawicki", "role": "referee", "position": "B"}, {"name": "Michał Fabryczny", "role": "referee", "position": "A"},
               {"name": "Jakub Tarczykowski", "role": "delegate", "position": "D1"}]
        pages = [(200, {"games": [
            {"bunny_item_id": 1, "referees": ref},
            {"bunny_item_id": 2, "referees": [{"name": "Ktoś Inny", "role": "referee"}]},   # q trafiło drużynę
            {"bunny_item_id": 3, "referees": []},                                          # brak obsady = brak dowodu
            {"bunny_item_id": None, "game_id": 8, "referees": ref, "video_state": "NONE"},
        ], "has_more": False})]
        S, client, mz = meczoteka(env, pages)
        as_ref = await mz.search_referee("RAWICKI Jakub")
        S.forget_search_cache()
        as_delegate = await mz.search_referee("jakub tarczykowski", role="delegate")
        S.forget_search_cache()
        wrong_role = await mz.search_referee("Jakub Tarczykowski")
        return as_ref, as_delegate, wrong_role

    as_ref, as_delegate, wrong_role = env.run(go)
    assert [g.get("bunny_item_id") for g in as_ref] == [1, None]
    assert [g.get("bunny_item_id") for g in as_delegate] == [1, None] and wrong_role == []


def test_obsada_zprp_i_obserwowanie_delegata(env):
    T = env.trybuna_rules
    refs = T.referees_of_zprp_row({"referee_1_name": "Anna Nowak", "referee_1_id": "101", "referee_2_name": "Piotr Lis", "delegate_1_name": "Delegat Dobry"})
    assert [(r["position"], r["role"]) for r in refs] == [("A", "referee"), ("B", "referee"), ("D1", "delegate")]
    assert T.follow_matches({"kind": "delegate", "name": "dobry delegat", "judge_ids": [], "names": ["dobry delegat"]}, refs)
    assert not T.follow_matches({"kind": "referee", "name": "Delegat Dobry", "judge_ids": [], "names": []}, refs)  # delegat to nie sędzia
    assert T.same_referee({"name": "RAWICKI Jakub"}, {"name": "Jakub Rawicki"})


def test_kalendarz_ma_przyszle_i_bez_terminu_a_kanal_ich_nie(env, monkeypatch):
    async def go():
        from datetime import date, timedelta

        actor = await env.actor(JUDGES[0])
        await env.trybuna_feed.follow(env.trybuna_feed.FollowBody(kind="referee", name="Piotr Lis"), actor)
        ref = [{"name": "Piotr Lis", "role": "referee", "position": "A"}]
        day = lambda n: (date.today() + timedelta(days=n)).isoformat()
        pages = [(200, {"games": [
            {"bunny_item_id": None, "game_id": 5, "date": f"{day(10)} 00:00:00", "unscheduled": True, "home": "X", "away": "Y", "video_state": "NONE", "referees": ref},
            {"bunny_item_id": None, "game_id": 6, "date": f"{day(12)} 18:00:00", "home": "Z", "away": "W", "video_state": "NONE", "referees": ref},
            {"bunny_item_id": 77, "game_id": 7, "date": f"{day(-2)} 18:00:00", "home": "Stary", "away": "Mecz", "video_state": "READY", "referees": ref},
        ], "has_more": False})]
        S, client, mz = meczoteka(env, pages)
        monkeypatch.setattr(env.trybuna_feed.S, "_setup", lambda real: (mz, None))
        cal = await env.trybuna_feed.calendar(30, actor)
        S.forget_search_cache()
        feed = await env.trybuna_feed.feed(_Resp(), 14, "", actor)
        return cal, feed

    cal, feed = env.run(go)
    bastion_items = [i for i in cal["items"] if i["source"] == "bastion"]
    assert sorted(i["home"] for i in bastion_items) == ["X", "Z"]
    by_home = {i["home"]: i for i in bastion_items}
    assert by_home["X"]["unscheduled"] is True and by_home["X"]["time_known"] is False and by_home["Z"]["time_known"] is True
    assert "m2" in [i["zprp_match_id"] for i in cal["items"]]
    homes = [i["home"] for i in feed["items"]]
    assert "Stary" in homes and "X" not in homes and "Z" not in homes
