"""Automatyczna kopia transmisji YouTube na serwer (07.11.2026): reguły (koniec meczu = YouTube albo ProEl, próby co
5 minut przez 30 minut z nadpisywaniem, jedna próba po 60 minutach, gdy w oknie nic nie wyszło) i przebieg na atrapach
yt-dlp, ffmpeg, R2 i YouTube."""

import importlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from starlette.requests import Request

from app import mentor_live_copy_rules as L
from app import mentor_youtube_copy_rules as Y
from tests.mentor_panel_support import JUDGES, PAIR, Env

A, B = JUDGES
PAIR_KEY = "|".join(sorted(JUDGES))
YT_URL = "https://www.youtube.com/watch?v=abcdefghijk"
T0 = datetime(2026, 11, 7, 17, 0, tzinfo=timezone.utc)


# ─── Reguły ─────────────────────────────────────────────────────────────────


def armed_row(**extra):
    row = {"id": "v", **L.arm_values(T0)}
    row.update(extra)
    return row


def M(minutes):
    return T0 + timedelta(minutes=minutes)


def test_koniec_meczu_kto_pierwszy_youtube_albo_proel():
    row = armed_row()
    assert row["auto_copy_state"] == "waiting_end"
    assert L.on_live_info(row, {"state": "live"}, T0) == {} and L.on_live_info(row, {"state": "upcoming"}, T0) == {}
    out = L.on_live_info(row, {"state": "vod", "ended_at": M(0)}, M(2))
    assert out["auto_copy_state"] == "scheduled" and out["auto_end_at"] == M(0) and out["auto_next_at"] == M(5)
    row.update(out)
    # ProEl po YouTube: zapisany, ale koniec meczu się nie przesuwa.
    later = L.on_proel_finished(row, M(3))
    assert later == {"proel_finished_at": M(3)}
    # ProEl pierwszy: koniec meczu = sygnał z ProEla, pierwsza próba po 5 minutach.
    other = armed_row()
    other.update(L.on_proel_finished(other, M(0)))
    assert other["auto_end_at"] == M(0) and other["auto_next_at"] == M(5) and L.due(other, M(4)) is None
    assert L.due(other, M(5)) == "window"
    other.update(L.on_live_info(other, {"state": "vod", "ended_at": M(4)}, M(4)))
    assert other["auto_end_at"] == M(0) and other["live_ended_at"] == M(4)


def test_okno_30_minut_co_5_minut_kazda_udana_nadpisuje():
    row = armed_row(auto_copy_state="scheduled", auto_end_at=M(0), auto_next_at=M(5))
    assert [L.next_slot(M(0), M(m)) for m in (0, 5, 12, 29, 30)] == [M(5), M(10), M(15), M(30), None]
    row.update(L.on_start(row, M(5), False))
    assert row["auto_copy_state"] == "copying" and row["auto_attempts"] == 1
    out = L.on_failure(row, M(6), "POST_LIVE", Y.MESSAGES["POST_LIVE"], False)
    assert out == {"auto_copy_state": "scheduled", "auto_next_at": M(10), "auto_reason": L.CALM["POST_LIVE"]}  # spokojnie
    row.update(out)
    row.update(L.on_start(row, M(10), False))
    row.update(L.on_success(row, M(12)))
    assert row["auto_copy_state"] == "scheduled" and row["auto_next_at"] == M(15) and row["auto_reason"] is None
    row.update(L.on_start(row, M(15), True))
    assert row["auto_copy_state"] == "refreshing"  # dobra kopia jest: to nadpisanie
    out = L.on_failure(row, M(16), "BLOCKED", "x", True)
    assert out["auto_copy_state"] == "scheduled" and out["auto_next_at"] == M(20)  # nieudane nadpisanie: kopia zostaje
    row.update(L.on_start({**row, **out}, M(30), True))
    assert L.on_success(row, M(31)) == {"auto_copy_state": "done", "auto_next_at": None, "auto_reason": None}
    # po oknie z kopią nieudane nadpisanie też kończy (bez próby po godzinie)
    assert L.on_failure(row, M(31), "BLOCKED", "x", True)["auto_copy_state"] == "done"


def test_bez_kopii_w_oknie_jedna_proba_po_godzinie_potem_koniec():
    row = armed_row(auto_copy_state="copying", auto_end_at=M(0), auto_attempts=6)
    out = L.on_failure(row, M(31), "POST_LIVE", Y.MESSAGES["POST_LIVE"], False)
    assert out["auto_copy_state"] == "last_try" and out["auto_next_at"] == M(60)
    row.update(out)
    assert L.due(row, M(59)) is None and L.due(row, M(60)) == "last"
    row.update(L.on_start(row, M(60), False))
    assert row["auto_copy_state"] == "last_try" and row["auto_next_at"] is None and L.running(row)
    failed = L.on_failure(row, M(62), "BLOCKED", Y.MESSAGES["BLOCKED"], False)
    assert failed["auto_copy_state"] == "gave_up" and Y.MESSAGES["BLOCKED"] in failed["auto_reason"]
    assert L.on_success(row, M(62))["auto_copy_state"] == "done"
    # długa próba skończona po +60: ostatnia próba od razu
    late = armed_row(auto_copy_state="copying", auto_end_at=M(0))
    assert L.on_failure(late, M(75), "FAILED", "x", False)["auto_next_at"] == M(75)
    # błąd, którego ponawianie nie naprawi: koniec od razu
    assert L.on_failure(armed_row(auto_copy_state="copying", auto_end_at=M(0)), M(6), "TOO_LONG", "za długi", False)["auto_copy_state"] == "gave_up"
    assert L.on_failure(armed_row(auto_copy_state="refreshing", auto_end_at=M(0)), M(6), "TOO_LONG", "x", True)["auto_copy_state"] == "done"


def test_czekanie_bez_konca_i_ksztalt_api():
    assert L.housekeeping(armed_row(), T0 + timedelta(days=2)) == {}
    assert L.housekeeping(armed_row(), T0 + timedelta(days=3))["auto_copy_state"] == "gave_up"
    shape = L.auto_shape(armed_row(auto_copy_state="scheduled", auto_next_at=M(10), auto_attempts=1, auto_end_at=M(0),
                                   auto_reason="YouTube jeszcze przetwarza zapis transmisji.", proel_finished_at=M(0)))
    assert shape == {"state": "scheduled", "next_at": "2026-11-07T17:10:00Z", "attempt": 1, "until": "2026-11-07T17:30:00Z",
                     "last_try_at": "2026-11-07T18:00:00Z", "reason": "YouTube jeszcze przetwarza zapis transmisji.",
                     "ended_at": "2026-11-07T17:00:00Z", "live_ended_at": None, "proel_finished_at": "2026-11-07T17:00:00Z"}
    waiting = L.auto_shape(armed_row())
    assert waiting["state"] == "waiting_end" and waiting["next_at"] is None and waiting["until"] is None and waiting["ended_at"] is None
    assert L.auto_shape({"auto_copy_state": "off"}) is None and L.auto_shape({}) is None and L.auto_shape(None) is None


def test_stan_transmisji_ze_strony_i_z_api():
    live = '{"liveBroadcastDetails":{"isLiveNow":true,"startTimestamp":"2026-11-07T17:01:02+00:00"}}'
    info = L.page_live_info(live)
    assert info["state"] == "live" and info["started_ms"] == int(datetime(2026, 11, 7, 17, 1, 2, tzinfo=timezone.utc).timestamp() * 1000)
    ended = '{"liveBroadcastDetails":{"isLiveNow":false,"startTimestamp":"2026-11-07T17:01:02+00:00","endTimestamp":"2026-11-07T18:40:00+00:00"}}'
    assert L.page_live_info(ended)["state"] == "vod" and L.page_live_info(ended)["ended_at"].hour == 18
    assert L.page_live_info('{"liveBroadcastDetails":{"isLiveNow":false,"startTimestamp":"2026-11-08T17:00:00+00:00"}}')["state"] == "upcoming"
    assert L.page_live_info('"isLiveContent":false')["state"] == "vod" and L.page_live_info("<html></html>") is None
    api = L.api_live_info({"state": "vod", "is_broadcast": True, "starts_at": T0, "ended_at": T0 + timedelta(hours=2)})
    assert api["state"] == "vod" and api["started_ms"] == int(T0.timestamp() * 1000) and api["ended_at"] == T0 + timedelta(hours=2)
    assert L.api_live_info({"state": "upcoming", "is_broadcast": True, "starts_at": T0})["started_ms"] is None


def test_mirror_czekajacy_to_working_w_kolejce_a_odswiezenie_osobno():
    base = {"id": "u", "uploader_id": A, "size": 0, "created_at": None}
    waiting = Y.mirror_shape({**base, "status": "waiting"}, {"phase": "downloading"}, None, None, {"state": "retrying"})
    assert waiting["status"] == "working" and waiting["phase"] == "queued" and waiting["waiting"] is True
    assert waiting["auto"] == {"state": "retrying"} and waiting["error"] is None
    ready = Y.mirror_shape({**base, "status": "ready", "refresh_at": T0}, {"phase": "downloading", "progress": 0.3}, "https://p", None)
    assert ready["status"] == "ready" and ready["refresh"]["status"] == "working" and ready["refresh"]["phase"] == "downloading"
    kept = Y.mirror_shape({**base, "status": "ready", "error": "Odświeżenie nie wyszło"}, None, "https://p", None)
    assert kept["status"] == "ready" and kept["refresh"]["status"] == "failed" and kept["error"] is None
    assert Y.mirror_shape({**base, "status": "ready"}, None, "https://p", None)["refresh"] is None


# ─── Przebieg ───────────────────────────────────────────────────────────────


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.copy = importlib.import_module("app.mentor_youtube_copy")
    e.live = importlib.import_module("app.mentor_live_copy")
    e.evals = importlib.import_module("app.mentor_evaluations")
    e.mp = monkeypatch
    e.calls, e.uploaded, e.forgotten = [], [], []
    e.download_errors = []
    e.duration = 5400.0
    e.infos = {}
    monkeypatch.setenv("MENTOR_LIVE_COPY", "1")
    monkeypatch.delenv("MENTOR_YT_PROXY", raising=False)
    monkeypatch.delenv("MENTOR_YT_COPY", raising=False)
    monkeypatch.setenv("MENTOR_MEDIA_TMP", str(tmp_path / "work"))
    monkeypatch.setattr(e.media, "storage_ready", lambda: True)
    monkeypatch.setattr(e.media, "storage_config", lambda: {"endpoint": "x", "region": "auto", "bucket": "b", "access_key": "k",
                                                            "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(e.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2/{key}" if key else None)
    monkeypatch.setattr(e.media, "forget_object", lambda *keys: e.forgotten.extend(k for k in keys if k))
    monkeypatch.setattr(e.copy, "_tool", True)
    e.live._pairs.clear()
    e.t0 = datetime.now(timezone.utc).replace(microsecond=0)
    e.clock = [e.t0]
    monkeypatch.setattr(e.core, "now", lambda: e.clock[0])

    def fake_download(upload_id, url, folder, proxy, cookiefile):
        e.calls.append({"url": url, "proxy": proxy})
        if e.download_errors:
            raise e.download_errors.pop(0)
        path = os.path.join(folder, "source.mp4")
        with open(path, "wb") as handle:
            handle.write(b"x" * 64)
        return {"path": path, "info": {"title": "LCM/32 Zagłębie - Śląsk", "duration": e.duration}}

    def fake_put(upload_id, path, key):
        e.uploaded.append(key)
        return 2_000_000_000

    def fake_remux(source, target):
        with open(target, "wb") as handle:
            handle.write(b"mp4")

    async def fake_infos(ids, *, use_api=True, page_ids=None):
        return {i: e.infos[i] for i in ids if i in e.infos}

    async def no_preview(url):
        return {"title": "Transmisja"}

    async def no_stream(url, timeout_s=6.0):
        return None

    monkeypatch.setattr(e.copy, "_download", fake_download)
    monkeypatch.setattr(e.copy, "_codecs", lambda path: {"video": "h264", "audio": "aac", "height": 1080, "width": 1920, "duration_s": e.duration})
    monkeypatch.setattr(e.copy, "_remux", fake_remux)
    monkeypatch.setattr(e.copy, "_put", fake_put)
    monkeypatch.setattr(e.media, "put_file", lambda path, key, content_type: e.uploaded.append(key) or 10)
    monkeypatch.setattr(e.media, "poster", lambda source, target, duration: open(target, "wb").close() or True)
    monkeypatch.setattr(e.live, "fetch_infos", fake_infos)
    monkeypatch.setattr(importlib.import_module("app.link_preview"), "preview_or_instant", no_preview)
    monkeypatch.setattr(e.evals, "_stream_start_or_none", no_stream)
    return e


async def actor_for(e, judge=A):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await e.auth.mentor_actor(r)


async def video_row(e, video_id):
    T = e.T["mentor_match_videos"]
    return await e.core.one(select(T).where(T.c.id == video_id))


async def upload_row(e, upload_id):
    T = e.T["mentor_uploads"]
    return await e.core.one(select(T).where(T.c.id == upload_id))


async def add_live(e, actor, url=YT_URL):
    return await e.media.add_video(PAIR, "m1", e.media.VideoBody(url=url), actor, None)


def at(e, minutes):
    """Zegar serwera (`mentor_panel_core.now`) przestawiony na koniec meczu + `minutes`."""
    e.clock[0] = e.t0 + timedelta(minutes=minutes)


async def step(e, minutes, error=None):
    """Przegląd automatu w chwili koniec meczu + `minutes` i jedna praca workera (z błędem albo bez)."""
    at(e, minutes)
    queued = await e.live.tick(check_live=False)
    if error:
        e.download_errors.append(error)
    worked = await e.copy.process_next()
    return queued, worked


def test_transmisja_od_dodania_przez_okno_30_minut(d):
    started = int(datetime(2026, 11, 7, 17, 1, tzinfo=timezone.utc).timestamp() * 1000)
    d.infos["abcdefghijk"] = {"state": "upcoming", "started_ms": None, "ended_at": None}

    async def go():
        actor = await actor_for(d)
        out = {"added": await add_live(d, actor)}
        vid = out["added"]["id"]
        # Zapowiedź -> transmisja trwa: godzina startu dochodzi sama (synchronizacja gwizdka w aplikacji).
        d.infos["abcdefghijk"] = {"state": "live", "started_ms": started, "ended_at": None}
        await d.live.tick(force=True)
        out["live"] = await video_row(d, vid)
        # Koniec transmisji w YouTube = koniec meczu: pierwsza próba po 5 minutach.
        d.infos["abcdefghijk"] = {"state": "vod", "started_ms": started, "ended_at": d.t0}
        at(d, 0)
        await d.live.tick(force=True)
        out["ended"] = await d.copy.copy_status(PAIR, "m1", vid, actor)
        out["early"] = await step(d, 4)
        out["s5"] = await step(d, 5, Y.CopyError("POST_LIVE", Y.MESSAGES["POST_LIVE"]))  # zapis jeszcze się przetwarza
        out["waiting"] = await d.copy.copy_status(PAIR, "m1", vid, actor)
        await step(d, 10)  # pierwsza kopia
        first = dict(await upload_row(d, (await video_row(d, vid))["mirror_upload_id"]))
        out["first"] = first
        out["ready"] = await d.copy.copy_status(PAIR, "m1", vid, actor)
        d.duration = 5520.0
        await step(d, 15)  # nadpisanie: nowsza wersja wygrywa
        await step(d, 20, Y.CopyError("BLOCKED", Y.MESSAGES["BLOCKED"]))  # nieudane nadpisanie nie psuje kopii
        out["kept"] = await d.copy.copy_status(PAIR, "m1", vid, actor)
        await step(d, 25)
        d.duration = 5580.0
        await step(d, 30)
        out["after"] = await upload_row(d, first["id"])
        ctx = await d.core.pair_context(PAIR, actor)
        out["listed"], _ = await d.media.video_list(ctx, "m1")
        out["done"] = await video_row(d, vid)
        out["idle"] = await step(d, 61)  # była kopia w oknie: bez próby po godzinie
        return out

    out = d.run(go)
    assert out["added"]["auto_copy"]["state"] == "waiting_end" and out["added"]["mirror"] is None
    assert json.loads(out["live"]["sync_json"])["stream_start_ms"] == started
    ended = out["ended"]
    assert ended["mirror"] is None and ended["auto_copy"]["state"] == "scheduled"
    assert L.aware(ended["auto_copy"]["next_at"]) == d.t0 + timedelta(minutes=5) and L.aware(ended["auto_copy"]["ended_at"]) == d.t0
    assert out["early"] == (0, False) and out["s5"] == (1, True)
    waiting = out["waiting"]
    assert waiting["mirror"]["status"] == "working" and waiting["mirror"]["phase"] == "queued" and waiting["mirror"]["waiting"] is True
    assert waiting["auto_copy"]["state"] == "scheduled" and waiting["auto_copy"]["reason"] == L.CALM["POST_LIVE"]
    assert L.aware(waiting["auto_copy"]["next_at"]) == d.t0 + timedelta(minutes=10) and waiting["mirror"]["auto"]["state"] == "scheduled"
    assert out["ready"]["mirror"]["status"] == "ready" and out["ready"]["auto_copy"]["state"] == "scheduled"
    kept = out["kept"]
    assert kept["mirror"]["status"] == "ready" and kept["mirror"]["refresh"] is None and kept["auto_copy"]["state"] == "scheduled"
    after, first = out["after"], out["first"]
    assert after["id"] == first["id"] and after["play_key"] == first["play_key"] and after["video_id"] == first["video_id"]
    assert after["status"] == "ready" and after["refresh_at"] is None and after["duration_s"] == 5580.0
    assert d.uploaded.count(first["play_key"]) == 4  # +10, +15, +25, +30: ten sam klucz R2 nadpisywany, nie nowe kopie
    copies = [v for v in out["listed"] if v.get("copy_of")]
    assert len(copies) == 1 and copies[0]["id"] == first["video_id"] and copies[0]["duration_s"] == 5580
    assert out["done"]["auto_copy_state"] == "done" and out["idle"] == (0, False) and len(d.calls) == 6


def test_bez_kopii_w_oknie_ostatnia_proba_po_godzinie(d):
    d.infos["abcdefghijk"] = {"state": "live", "started_ms": None, "ended_at": None}
    blocked = Y.CopyError("BLOCKED", Y.MESSAGES["BLOCKED"])

    async def go():
        actor = await actor_for(d)
        vid = (await add_live(d, actor))["id"]
        at(d, 0)
        await d.live.mark_proel_finished("ISM/1", "m1")  # ProEl pierwszy
        for minute in (5, 10, 15, 20, 25, 30):
            await step(d, minute, blocked)
        last = await d.copy.copy_status(PAIR, "m1", vid, actor)
        early = await step(d, 45)
        await step(d, 60, blocked)
        return last, early, await d.copy.copy_status(PAIR, "m1", vid, actor), await step(d, 90)

    last, early, gave_up, idle = d.run(go)
    assert last["auto_copy"]["state"] == "last_try" and L.aware(last["auto_copy"]["next_at"]) == d.t0 + timedelta(minutes=60)
    assert last["mirror"]["status"] == "working" and last["mirror"]["waiting"] is True  # wciąż spokojnie, nie błąd
    assert early == (0, False) and len(d.calls) == 7
    assert gave_up["auto_copy"]["state"] == "gave_up" and gave_up["mirror"]["status"] == "failed"
    assert Y.MESSAGES["BLOCKED"] in gave_up["mirror"]["error"] and gave_up["auto_copy"]["reason"] == gave_up["mirror"]["error"]
    assert idle == (0, False)


def test_ostatnia_proba_udana_konczy_z_kopia(d):
    d.infos["abcdefghijk"] = {"state": "live", "started_ms": None, "ended_at": None}
    post = Y.CopyError("POST_LIVE", Y.MESSAGES["POST_LIVE"])

    async def go():
        actor = await actor_for(d)
        vid = (await add_live(d, actor))["id"]
        at(d, 0)
        await d.live.mark_proel_finished("ISM/1", "m1")
        for minute in (5, 10, 15, 20, 25, 30):
            await step(d, minute, post)
        await step(d, 60)
        return await d.copy.copy_status(PAIR, "m1", vid, actor)

    status = d.run(go)
    assert status["auto_copy"]["state"] == "done" and status["mirror"]["status"] == "ready"


def test_koniec_meczu_w_proelu_i_powiazania(d):
    d.infos["abcdefghijk"] = {"state": "live", "started_ms": None, "ended_at": None}

    async def go():
        actor = await actor_for(d)
        vid = (await add_live(d, actor))["id"]
        stamp = d.t0
        # mecz wspólny `my:s1` (klucz M-<tuleja>/<numer>) i mecz podpięty ręcznie kluczem szkoleniowym
        await d.ins("shared_matches", id="s1", creator_id=A, code="12", proel_stem="ABCD2345", created_at=stamp, updated_at=stamp)
        await d.ins("mentor_proel_links", pair_id=PAIR, match_id="m3", proel_key="T-XY/7", linked_by=A, linked_at=stamp)
        await d.ins("saved_matches", match_number="T-XY/7", promoted_to="ZPRP-9", status="finished")
        ids_shared = await d.live.match_ids_for_proel("M-ABCD2345/12", None)
        ids_promoted = await d.live.match_ids_for_proel("ZPRP-9", "777")
        none = await d.live.mark_proel_finished("OTHER", "m2")
        at(d, 0)
        marked = await d.live.mark_proel_finished("ISM/1", "m1")
        again = await d.live.mark_proel_finished("ISM/1", "m1")
        row = await video_row(d, vid)
        kicked_off = d.live.kick_on_proel_status("ISM/1", "m1", "in_progress", "in_progress")
        return ids_shared, ids_promoted, none, marked, again, row, kicked_off

    ids_shared, ids_promoted, none, marked, again, row, kicked_off = d.run(go)
    assert ids_shared == ["my:s1"] and ids_promoted == ["777", "m3"]
    assert none == 0 and marked == 1 and again == 0
    assert row["auto_copy_state"] == "scheduled" and L.aware(row["auto_end_at"]) == d.t0
    assert L.aware(row["auto_next_at"]) == d.t0 + timedelta(minutes=5)
    assert kicked_off is False


def test_kick_z_proela_w_testach_wylaczony_bez_jawnej_zgody(monkeypatch):
    from app import mentor_live_copy

    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("MENTOR_LIVE_COPY", raising=False)
    assert mentor_live_copy.enabled() is False
    assert mentor_live_copy.kick_on_proel_status("ISM/1", "m1", "in_progress", "finished") is False


def test_reczne_odswiezenie_nadpisuje_zostawia_nazwe_i_nie_dubluje(d):
    async def go():
        stamp = d.t0
        await d.ins("mentor_match_videos", id="yt", match_id="m1", pair_key=PAIR_KEY, url=YT_URL, normalized_url=YT_URL,
                    provider="youtube", added_by=A, created_at=stamp, kind="link", title="Transmisja")
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        up_id = (await video_row(d, "yt"))["mirror_upload_id"]
        before = dict(await upload_row(d, up_id))
        copy_id = before["video_id"]
        await d.media.update_video(PAIR, "m1", copy_id, d.media.VideoPatch(title="Moja nazwa"), actor)
        plain = await d.copy.start_copy(PAIR, "m1", "yt", actor)  # bez refresh: gotowa kopia wraca bez zmian
        d.duration = 5600.0
        ordered = await d.copy.start_copy(PAIR, "m1", "yt", actor, body=d.copy.CopyBody(refresh=True))
        twice = await d.copy.start_copy(PAIR, "m1", "yt", actor, refresh=True)
        await d.copy.process_next()
        after = await upload_row(d, up_id)
        copy = await video_row(d, copy_id)
        # Nieudane odświeżenie: dobra kopia zostaje, błąd tylko w `mirror.refresh`.
        d.download_errors.append(Y.CopyError("BLOCKED", Y.MESSAGES["BLOCKED"]))
        await d.copy.start_copy(PAIR, "m1", "yt", actor, refresh=True)
        await d.copy.process_next()
        broken = await d.copy.copy_status(PAIR, "m1", "yt", actor)
        return before, plain, ordered, twice, after, copy, broken

    before, plain, ordered, twice, after, copy, broken = d.run(go)
    assert plain["mirror"]["refresh"] is None and len(d.calls) == 3
    assert ordered["mirror"]["status"] == "ready" and ordered["mirror"]["refresh"]["status"] == "working"
    assert twice["mirror"]["refresh"]["requested_at"] == ordered["mirror"]["refresh"]["requested_at"]
    assert after["id"] == before["id"] and after["play_key"] == before["play_key"] and after["duration_s"] == 5600.0
    assert copy["title"] == "Moja nazwa" and copy["duration_s"] == 5600  # nazwa pary zostaje, długość nowa
    assert broken["mirror"]["status"] == "ready" and broken["mirror"]["play_url"]
    assert broken["mirror"]["refresh"]["status"] == "failed" and broken["mirror"]["refresh"]["error"] == Y.MESSAGES["BLOCKED"]
    assert broken["auto_copy"] is None


def test_anulowanie_czekajacej_kopii_wylacza_automat(d):
    d.infos["abcdefghijk"] = {"state": "live", "started_ms": None, "ended_at": None}

    async def go():
        actor = await actor_for(d)
        vid = (await add_live(d, actor))["id"]
        d.infos["abcdefghijk"] = {"state": "vod", "started_ms": None, "ended_at": d.t0}
        await d.live.tick(force=True)
        await step(d, 5, Y.CopyError("POST_LIVE", Y.MESSAGES["POST_LIVE"]))
        removed = await d.copy.remove_copy(PAIR, "m1", vid, actor)
        at(d, 10)
        queued = await d.live.tick(check_live=False)
        return removed, queued, await video_row(d, vid)

    removed, queued, row = d.run(go)
    assert removed["video"]["mirror"] is None and removed["video"]["auto_copy"] is None
    assert queued == 0 and row["auto_copy_state"] == "off"


def test_zwykly_film_nie_jest_uzbrajany(d):
    d.infos["abcdefghijk"] = {"state": "vod", "started_ms": None, "ended_at": None}

    async def go():
        actor = await actor_for(d)
        added = await add_live(d, actor)
        return added, await video_row(d, added["id"])

    added, row = d.run(go)
    assert added["auto_copy"] is None and row["auto_copy_state"] is None
