"""Pobieranie klipów Mentora jako MP4: plan, zamówienie z przeliczeniem czasu (plik, Bastion), NEED_SYNC, NO_SOURCE,
plansza tytułowa jako osobny wariant i paczka. Atrapa magazynu i ffmpeg, bez sieci."""

import json
import subprocess
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from tests.mentor_panel_support import JUDGES, PAIR, Env

A, B = JUDGES
PAIR_KEY = "|".join(sorted(JUDGES))
SYNC_YT = {"match_start_s": 100, "second_half_s": 2000}
SYNC_FILE = {"match_start_s": 40, "second_half_s": 1900}
BASTION_URL = "https://portal.handball-bastion.pl/game?bunny_item_id=5632"


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    monkeypatch.setenv("BASTION_ENABLED", "true")
    monkeypatch.setenv("BASTION_CONNECTOR_URL", "http://connector")
    monkeypatch.setenv("BASTION_CONNECTOR_TOKEN", "t" * 40)
    e.mp = monkeypatch
    e.runs = []
    e.puts = []
    monkeypatch.setattr(e.media, "storage_ready", lambda: True)
    monkeypatch.setattr(e.media, "storage_config", lambda: {"endpoint": "x", "region": "auto", "bucket": "b", "access_key": "k",
                                                            "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(e.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2/{key}?f={filename}" if key else None)

    def fake_run(args, timeout=None):
        e.runs.append(list(args))
        with open(args[-1], "wb") as handle:
            handle.write(b"mp4")
        return subprocess.CompletedProcess(args, 0, "", "")

    def fake_put(path, key, content_type):
        e.puts.append(key)
        return 3

    monkeypatch.setattr(e.media, "_run", fake_run)
    monkeypatch.setattr(e.media, "put_file", fake_put)
    import app.mentor_bastion_media as BM

    monkeypatch.setattr(BM, "ffprobe_file", lambda path, timeout_s=60.0: {"width": 1280, "height": 720, "has_audio": True, "duration_s": 22})
    return e


async def actor_for(e, judge=A):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await e.auth.mentor_actor(r)


async def seed(e, *, file=True, bastion=False, yt_sync=SYNC_YT, file_sync=SYNC_FILE, bastion_sync=SYNC_FILE, ready=True):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_match_videos", id="yt", match_id="m1", pair_key=PAIR_KEY, url="https://youtu.be/abc", normalized_url="yt:abc",
                provider="youtube", added_by=A, created_at=now, kind="link", title="Transmisja",
                sync_json=json.dumps(yt_sync) if yt_sync else None)
    if file:
        await e.ins("mentor_uploads", id="u1", pair_id=PAIR, match_id="m1", video_id="vf", uploader_id=A, filename="mecz.mp4", size=10,
                    r2_key="mentor/orig.mp4", status="ready" if ready else "processing", play_key="mentor/play.mp4" if ready else None,
                    created_at=now)
        await e.ins("mentor_match_videos", id="vf", match_id="m1", pair_key=PAIR_KEY, url="upload:u1", normalized_url="upload:u1",
                    provider="upload", added_by=A, created_at=now, kind="upload", upload_id="u1", title="mecz.mp4",
                    sync_json=json.dumps(file_sync) if file_sync else None)
    if bastion:
        await e.ins("mentor_match_videos", id="vb", match_id="m1", pair_key=PAIR_KEY, url=BASTION_URL, normalized_url=BASTION_URL,
                    provider="bastion", external_id="5632", added_by=A, created_at=now, kind="link",
                    sync_json=json.dumps(bastion_sync) if bastion_sync else None)


async def add_clip(e, clip_id="c1", video_id="yt", start=1500.0, end=1520.0, title="Kara 2 min - czerwona"):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_clips", id=clip_id, pair_id=PAIR, match_id="m1", video_id=video_id, start_s=start, end_s=end, title=title,
                author_id=A, category_ids="[]", source="manual", created_at=now, updated_at=now, mp4_status="none", media_rev=1,
                to_discuss=True)


async def clip_row(e, clip_id="c1"):
    T = e.T["mentor_clips"]
    return await e.core.one(select(T).where(T.c.id == clip_id))


async def plan_of(e, clip_id="c1", actor=None, title_card=False):
    actor = actor or await actor_for(e)
    ctx = await e.core.pair_context(PAIR, actor)
    return await e.download.build_plan(e.download.Context(ctx), await clip_row(e, clip_id), actor, title_card=title_card)


async def failure(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.detail
    return None


def test_plan_klipu_z_linku_przez_wlasny_plik_z_przeliczonym_zakresem_nazwa_i_folder(d):
    async def go():
        await seed(d)
        await add_clip(d)
        return await plan_of(d)

    plan = d.run(go)
    assert plan["can_download"] is True and plan["source"] == "file" and plan["reason"] is None and plan["missing"] == []
    assert plan["source_range"] == {"video_id": "vf", "start_s": 1440.0, "end_s": 1460.0}
    assert plan["filename"] == "23m20 Kara 2 min - czerwona.mp4"
    assert plan["folder"]["category"] == "Do dyskusji" and plan["folder"]["match"]
    assert plan["mp4_status"] == "none" and plan["url"] is None and plan["estimated_s"] > 0
    assert plan["title_card_available"] is True and plan["hint"]


def test_zamowienie_tnie_przeliczony_zakres_z_pliku_a_drugie_jest_idempotentne(d):
    async def go():
        await seed(d)
        await add_clip(d)
        actor = await actor_for(d)
        one = await d.media.request_mp4("c1", actor)
        two = await d.media.request_mp4("c1", actor)
        worked = await d.media.process_next()
        row = await clip_row(d)
        plan = await plan_of(d, actor=actor)
        return one, two, worked, row, plan

    one, two, worked, row, plan = d.run(go)
    assert one == {"mp4_status": "queued"} and two == {"mp4_status": "queued"} and worked is True
    cut = d.runs[0]
    assert cut[cut.index("-ss") + 1] == "1440.00" and cut[cut.index("-t") + 1] == "20.00"
    assert row["mp4_status"] == "ready" and json.loads(row["mp4_source_json"])["video_id"] == "vf"
    assert plan["mp4_status"] == "ready" and plan["url"].endswith("f=23m20 Kara 2 min - czerwona.mp4")


def test_brak_gwizdka_to_need_sync_z_lista_czego_brakuje(d):
    async def go():
        await seed(d, yt_sync={"match_start_s": 100}, file_sync={"second_half_s": 1900})
        await add_clip(d)
        actor = await actor_for(d)
        return await failure(d.media.request_mp4("c1", actor)), await plan_of(d, actor=actor)

    detail, plan = d.run(go)
    assert detail["code"] == "NEED_SYNC"
    assert detail["missing"] == [{"video_id": "yt", "label": "Transmisja", "whistle": "second_half"},
                                 {"video_id": "vf", "label": "mecz.mp4", "whistle": "start"}]
    assert plan["can_download"] is False and plan["reason"] == "NEED_SYNC" and plan["missing"] == detail["missing"]
    assert plan["source"] is None and plan["url"] is None and "Brakuje" in plan["hint"]


def test_sam_youtube_to_no_source(d):
    async def go():
        await seed(d, file=False)
        await add_clip(d)
        actor = await actor_for(d)
        return await failure(d.media.request_mp4("c1", actor)), await plan_of(d, actor=actor)

    detail, plan = d.run(go)
    assert detail["code"] == "NO_SOURCE" and plan["reason"] == "NO_SOURCE" and plan["can_download"] is False


def test_plik_w_przetwarzaniu_to_not_ready(d):
    async def go():
        await seed(d, ready=False)
        await add_clip(d)
        return await plan_of(d)

    plan = d.run(go)
    assert plan["reason"] == "NOT_READY" and plan["can_download"] is False


def test_bastion_dostaje_zadanie_z_przeliczonego_zakresu_a_zmiana_synchronizacji_robi_nowa_rewizje(d):
    async def go():
        await seed(d, file=False, bastion=True)
        await add_clip(d)
        actor = await actor_for(d)
        jobs_T = d.T["mentor_bastion_clip_jobs"]
        first = await d.media.request_mp4("c1", actor)
        again = await d.media.request_mp4("c1", actor)
        jobs = await d.core.rows(select(jobs_T))
        plan = await plan_of(d, actor=actor)
        # Poprawiona synchronizacja Bastionu: zakres się zmienia, więc powstaje nowa rewizja i nowe zadanie.
        V = d.T["mentor_match_videos"]
        await d.db.execute(V.update().where(V.c.id == "vb").values(sync_json=json.dumps({"match_start_s": 50, "second_half_s": 1900})))
        third = await d.media.request_mp4("c1", actor)
        jobs2 = await d.core.rows(select(jobs_T).order_by(jobs_T.c.clip_revision))
        return first, again, jobs, plan, third, jobs2, await clip_row(d)

    first, again, jobs, plan, third, jobs2, row = d.run(go)
    assert first["mp4_status"] in ("queued", "working") and again["mp4_status"] in ("queued", "working")
    assert len(jobs) == 1 and (jobs[0]["start_s"], jobs[0]["end_s"]) == (1440, 1460) and jobs[0]["source_bunny_item_id"] == 5632
    assert jobs[0]["source_video_id"] == "vb"
    assert plan["source"] == "bastion" and plan["mp4_status"] == "working" and plan["estimated_s"] == 90
    assert len(jobs2) == 2 and row["media_rev"] == 2 and (jobs2[1]["start_s"], jobs2[1]["end_s"]) == (1450, 1470)
    assert third["mp4_status"] in ("queued", "working")


def test_zakres_poza_limitem_bastionu_to_bad_range(d):
    async def go():
        await seed(d, file=False, bastion=True)
        await add_clip(d, end=1900.0)
        actor = await actor_for(d)
        return await plan_of(d, actor=actor), await failure(d.media.request_mp4("c1", actor))

    plan, detail = d.run(go)
    assert plan["reason"] == "BAD_RANGE" and detail["code"] == "CLIP_RANGE"


def test_plansza_to_osobny_wariant_zwykly_plik_zostaje(d):
    async def go():
        await seed(d)
        await add_clip(d)
        actor = await actor_for(d)
        queued = await d.media.request_mp4("c1", actor, d.media.Mp4Request(title_card=True))
        before = await plan_of(d, actor=actor, title_card=True)
        await d.media.process_next()  # zwykły MP4
        await d.media.process_next()  # wariant z planszą
        row = await clip_row(d)
        card_plan = await plan_of(d, actor=actor, title_card=True)
        plain_plan = await plan_of(d, actor=actor)
        return queued, before, row, card_plan, plain_plan

    queued, before, row, card_plan, plain_plan = d.run(go)
    assert queued["card_status"] == "queued" and before["mp4_status"] == "queued" and before["url"] is None
    assert row["mp4_status"] == "ready" and row["card_status"] == "ready" and row["card_key"] != row["mp4_key"]
    assert row["card_key"].endswith("c1-plansza.mp4") and row["mp4_key"].endswith("c1.mp4")
    ff = d.runs[1]
    assert "-loop" in ff and "concat=n=2:v=1:a=1" in ff[ff.index("-filter_complex") + 1]
    assert card_plan["mp4_status"] == "ready" and "c1-plansza.mp4" in card_plan["url"]
    assert plain_plan["mp4_status"] == "ready" and "c1.mp4" in plain_plan["url"] and "plansza" not in plain_plan["url"]


def test_zmiana_tytulu_uniewaznia_wariant_z_plansza(d):
    async def go():
        await seed(d)
        await add_clip(d)
        actor = await actor_for(d)
        await d.media.request_mp4("c1", actor, d.media.Mp4Request(title_card=True))
        await d.media.process_next()
        await d.media.process_next()
        T = d.T["mentor_clips"]
        await d.db.execute(T.update().where(T.c.id == "c1").values(title="Inny tytuł"))
        return await plan_of(d, actor=actor, title_card=True)

    plan = d.run(go)
    assert plan["mp4_status"] == "none" and plan["url"] is None


def test_plansza_png_ma_wymiary_filmu(d, tmp_path):
    from PIL import Image

    target = tmp_path / "card.png"
    d.download.render_card_png(["2026-10-10 AGH Kraków - Gwardia (LCM-32)", "26m23", "Kara 2 min - czerwona", "Do dyskusji"], 1280, 720, str(target))
    assert Image.open(target).size == (1280, 720)


def test_paczka_zamawia_mozliwe_a_reszta_wraca_z_powodem(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1")
        await add_clip(d, "c2", start=1600.0, end=1620.0, title="Druga")
        actor = await actor_for(d)
        body = d.download.BatchBody(clip_ids=["c1", "c2", "nie-ma"])
        out = await d.download.download_batch(PAIR, body, actor)
        T = d.T["mentor_clips"]
        # Klip bez synchronizacji w drugiej paczce (wideo bez gwizdków).
        V = d.T["mentor_match_videos"]
        await d.db.execute(V.update().where(V.c.id == "yt").values(sync_json=json.dumps({"match_start_s": 100})))
        await add_clip(d, "c3", start=1700.0, end=1710.0, title="Trzecia")
        out2 = await d.download.download_batch(PAIR, d.download.BatchBody(clip_ids=["c3"]), actor)
        out3 = await d.download.download_batch(PAIR, d.download.BatchBody(match_id="m1"), actor)
        return out, out2, out3, await d.core.rows(select(T.c.id, T.c.mp4_status))

    out, out2, out3, statuses = d.run(go)
    items = {i["clip_id"]: i for i in out["items"]}
    assert items["c1"]["ordered"] and items["c1"]["mp4_status"] == "queued" and items["c1"]["source"] == "file"
    assert items["c2"]["ordered"] and items["c2"]["filename"].endswith("Druga.mp4")
    assert items["nie-ma"]["can_download"] is False and items["nie-ma"]["reason"] == "NOT_FOUND"
    item = out2["items"][0]
    assert item["ordered"] is False and item["reason"] == "NEED_SYNC" and item["missing"]
    assert {s["id"]: s["mp4_status"] for s in statuses} == {"c1": "queued", "c2": "queued", "c3": "none"}
    # Cały mecz: match_id zamiast clip_ids obejmuje wszystkie nieusunięte klipy (po czasie w nagraniu); synchronizacja
    # wideo-linku jest już niepełna, więc żaden nie jest zamawiany.
    assert [i["clip_id"] for i in out3["items"]] == ["c1", "c2", "c3"]
    assert {i["reason"] for i in out3["items"]} == {"NEED_SYNC"} and not any(i["ordered"] for i in out3["items"])


def test_paczka_nie_przekracza_limitu_kolejki_bastionu(d):
    async def go():
        await seed(d, file=False, bastion=True)
        for n in range(3):
            await add_clip(d, f"c{n}", start=1500.0 + n * 40, end=1520.0 + n * 40, title=f"K{n}")
        actor = await actor_for(d)
        d.mp.setattr("app.mentor_clip_download_rules.BASTION_ACTIVE_CAP", 2)
        out = await d.download.download_batch(PAIR, d.download.BatchBody(clip_ids=["c0", "c1", "c2"]), actor)
        return out, await d.core.rows(select(d.T["mentor_bastion_clip_jobs"]))

    out, jobs = d.run(go)
    assert [i["ordered"] for i in out["items"]] == [True, True, False]
    assert out["items"][2]["reason"] == "QUEUE_LIMIT" and len(jobs) == 2
