"""Montaż zestawienia w jeden film: reguły osi czasu, gotowość pozycji (pliki, YouTube, gwizdki), zamówienie, przegląd,
pominięcie brakujących, ponowne użycie, usuwanie, film przy zestawieniu i prawdziwy render krótkich klipów (ffmpeg)."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from app import mentor_montage_rules as MR
from tests.mentor_panel_support import JUDGES, PAIR, STRANGER, Env

A, B = JUDGES
PAIR_KEY = "|".join(sorted(JUDGES))
SYNC_YT = {"match_start_s": 100, "second_half_s": 2000}
SYNC_FILE = {"match_start_s": 40, "second_half_s": 1900}


# ─── Reguły ─────────────────────────────────────────────────────────────────


def test_os_czasu_sklada_sie_co_do_klatki_i_przejscia_maja_dobre_offsety():
    plan = MR.timeline([5.0, 4.0, 6.0], [True, False, True], 3, 10)
    assert plan["cover_frames"] == 120
    first, second, third = plan["segments"]
    # Pierwszy odcinek: ogon okładki -> plansza meczu -> belka -> klip.
    assert [p[0] for p in first["parts"]] == ["tail", "chapter", "bar", "clip"]
    assert first["fades"] == [MR.fs(18), MR.fs(MR.frames(MR.XF_S)), MR.fs(MR.frames(MR.XF_S))]
    assert first["offsets"][0] == 0.0  # ogon (0,6 s) w całości przenika się w planszę
    assert second["parts"][0][0] == "tail" and [p[0] for p in second["parts"]][1] == "bar"
    # Ogon pierwszego klipu = 30% z 5 s, ale najwyżej TAIL_S.
    assert second["tail_in"] == MR.fs(MR.frames(MR.TAIL_S))
    total = plan["cover_frames"] + sum(s["frames"] for s in plan["segments"]) + plan["end"]["frames"]
    assert total == plan["total_frames"]
    # Odcinek zaczyna się tam, gdzie kończy się poprzedni.
    assert second["start_s"] == pytest.approx(first["start_s"] + MR.fs(first["frames"]))
    # Klip w odcinku startuje w chwili ostatniego przejścia, a do końca odcinka gra dokładnie body_s.
    for seg in plan["segments"]:
        assert MR.fs(seg["frames"]) - seg["clip_at"] == pytest.approx(seg["body_s"], abs=1e-6)


def test_krotki_klip_oddaje_najwyzej_30_procent_na_ogon():
    assert MR.tail_of(1.0) == MR.fs(MR.frames(0.3))
    assert MR.tail_of(30.0) == MR.fs(MR.frames(MR.TAIL_S))


def test_rozdzialy_meczow_i_numery():
    assert MR.chapter_flags(["a", "a", "b", "a"]) == [True, False, True, True]
    assert MR.chapter_numbers(["a", "a", "b", "a"]) == [1, 1, 2, 3]


def test_wybor_n_klipow_z_zestawienia_w_nowej_kolejnosci():
    base = [{"clip_id": "c1", "label": "Wzorzec", "note": ""}, {"clip_id": "c2", "label": "", "note": "x"}, {"clip_id": "c3"}]
    assert [i["clip_id"] for i in MR.pick_items(base, ["c3", "c1"])] == ["c3", "c1"]
    assert MR.pick_items(base, ["c3", "c1"])[1]["label"] == "Wzorzec"
    assert [i["clip_id"] for i in MR.pick_items(base, None)] == ["c1", "c2", "c3"]
    with pytest.raises(MR.MontageError) as exc:
        MR.pick_items(base, ["c9"])
    assert exc.value.code == "MONTAGE_ITEM_UNKNOWN"
    with pytest.raises(MR.MontageError):
        MR.check_count([])
    with pytest.raises(MR.MontageError) as many:
        MR.check_count(list(range(MR.MAX_ITEMS + 1)))
    assert many.value.code == "MONTAGE_TOO_MANY"


def test_stan_pozycji_z_planu_pobrania():
    assert MR.item_state({"can_download": True, "mp4_status": "ready"})["state"] == "ready"
    assert MR.item_state({"can_download": True, "mp4_status": "working"})["state"] == "cutting"
    failed = MR.item_state({"can_download": True, "mp4_status": "failed"})
    assert failed["state"] == "failed" and failed["action"] == "retry"
    youtube = MR.item_state({"can_download": False, "reason": "NO_SOURCE"}, own_provider="youtube", can_copy=True)
    assert youtube == {**youtube, "state": "blocked", "reason": "NEED_COPY", "action": "copy"}
    copying = MR.item_state({"can_download": False, "reason": "NO_SOURCE"}, own_provider="youtube", can_copy=True, copy_status="downloading")
    assert copying["state"] == "copying" and copying["action"] is None
    sync = MR.item_state({"can_download": False, "reason": "NEED_SYNC", "hint": "Brakuje"})
    assert sync["action"] == "sync" and sync["state"] == "blocked"
    assert MR.item_state({"can_download": False, "reason": "QUEUE_LIMIT"})["state"] == "waiting"
    assert MR.item_state({"can_download": False, "reason": "NO_SOURCE"}, own_provider="vimeo")["action"] is None


def test_co_dalej_z_przygotowaniem():
    assert MR.next_status(["ready", "ready"], False) == "queued"
    assert MR.next_status(["ready", "blocked"], False) == "preparing"
    assert MR.next_status(["ready", "blocked"], True) == "queued"
    assert MR.next_status(["ready", "cutting", "blocked"], True) == "preparing"  # pominięcie czeka na klipy w drodze
    assert MR.next_status(["blocked", "failed"], True) == "failed"


def test_okno_zoomu_jak_w_panelu():
    track = [{"s": 10.0, "cx": 0.5, "cy": 0.5, "zoom": 1.0}, {"s": 12.0, "cx": 0.25, "cy": 0.25, "zoom": 2.0}]
    assert MR.zoom_window(track, 9.0) == (0.0, 0.0, 1.0)
    left, top, size = MR.zoom_window(track, 12.0)
    assert (left, top, size) == pytest.approx((0.0, 0.0, 0.5))
    # W połowie: liniowo w przestrzeni (z, ox, oy) - z = 1,5, ox = oy = 0.
    assert MR.zoom_window(track, 11.0) == pytest.approx((0.0, 0.0, 1 / 1.5))
    assert MR.parse_zoom(json.dumps(track)) and MR.parse_zoom([{"s": 1, "cx": 0.5, "cy": 0.5, "zoom": 1}] * 2) is None


def test_rozmiar_filmu_nazwa_i_rozdzialy_w_pliku():
    assert MR.target_size([1080, 1080]) == (1920, 1080)
    assert MR.target_size([1080, 720]) == (1280, 720)
    assert MR.target_size([]) == (1280, 720)
    assert MR.default_name([{"home": "AZS", "away": "Gwardia"}]) == "AZS - Gwardia"
    assert MR.default_name([{"home": "A"}, {"home": "B"}, {"home": "C"}]) == "Wybrane klipy · 3 mecze"
    meta = MR.ffmetadata([{"title": "1. 23:41 · A=B; #1", "start_s": 4.0, "end_s": 9.5}], "Film")
    assert "title=1. 23:41 · A\\=B\\; \\#1" in meta and "START=4000" in meta and "END=9500" in meta
    assert MR.film_filename("Kary / listopad").endswith(".mp4") and "/" not in MR.film_filename("Kary / listopad")
    assert MR.label_color("Wzorzec") == MR.TONE_COLORS["model"] and MR.label_color("coś swojego") == MR.TONE_COLORS["own"]


# ─── Trasy ──────────────────────────────────────────────────────────────────


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.mp = monkeypatch
    e.runs = []
    monkeypatch.setattr(e.media, "storage_ready", lambda: True)
    monkeypatch.setattr(e.media, "storage_config", lambda: {"endpoint": "x", "region": "auto", "bucket": "b", "access_key": "k",
                                                            "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(e.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2/{key}?f={filename}" if key else None)

    def fake_run(args, timeout=None):
        e.runs.append(list(args))
        with open(args[-1], "wb") as handle:
            handle.write(b"mp4")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(e.media, "_run", fake_run)
    monkeypatch.setattr(e.media, "put_file", lambda path, key, content_type: 3)
    monkeypatch.setattr(e.media, "delete_objects", lambda keys: None)
    import app.mentor_youtube_copy as Y

    monkeypatch.setattr(Y, "available", lambda: True)
    return e


async def actor_for(e, judge=A):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await e.auth.mentor_actor(r)


async def seed(e, *, file=True, yt_sync=SYNC_YT, file_sync=SYNC_FILE, mirror=None):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_match_videos", id="yt", match_id="m1", pair_key=PAIR_KEY, url="https://youtu.be/abc", normalized_url="yt:abc",
                provider="youtube", added_by=A, created_at=now, kind="link", title="Transmisja",
                sync_json=json.dumps(yt_sync) if yt_sync else None, mirror_upload_id=mirror)
    if mirror:
        await e.ins("mentor_uploads", id=mirror, pair_id=PAIR, match_id="m1", video_id="yt", uploader_id=A, filename="kopia.mp4", size=10,
                    r2_key="mentor/copy.mp4", status="downloading", origin="youtube", created_at=now)
    if file:
        await e.ins("mentor_uploads", id="u1", pair_id=PAIR, match_id="m1", video_id="vf", uploader_id=A, filename="mecz.mp4", size=10,
                    r2_key="mentor/orig.mp4", status="ready", play_key="mentor/play.mp4", created_at=now)
        await e.ins("mentor_match_videos", id="vf", match_id="m1", pair_key=PAIR_KEY, url="upload:u1", normalized_url="upload:u1",
                    provider="upload", added_by=A, created_at=now, kind="upload", upload_id="u1", title="mecz.mp4",
                    sync_json=json.dumps(file_sync) if file_sync else None)


async def add_clip(e, clip_id, video_id="yt", start=1500.0, end=1510.0, title="Kara 2 min", match_id="m1"):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_clips", id=clip_id, pair_id=PAIR, match_id=match_id, video_id=video_id, start_s=start, end_s=end, title=title,
                author_id=A, category_ids="[]", source="manual", created_at=now, updated_at=now, mp4_status="none", media_rev=1)


async def add_compilation(e, clip_ids, labels=None):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_compilations", id="z1", pair_id=PAIR, name="Kary - listopad", description="Co pokazujemy", mode="free",
                created_by=A, created_at=now, updated_at=now)
    for n, cid in enumerate(clip_ids):
        await e.ins("mentor_compilation_items", compilation_id="z1", clip_id=cid, position=n, label=(labels or {}).get(cid), note=None)


async def failure(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.detail
    return None


def body(**kw):
    from app.mentor_montage import MontageBody

    return MontageBody(**kw)


def test_film_z_zestawienia_zamawia_pliki_klipow_i_po_cieciu_trafia_do_renderu(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1", start=1500, end=1510)
        await add_clip(d, "c2", start=1600, end=1612, title="Pasywna gra")
        await add_compilation(d, ["c1", "c2"], {"c1": "Wzorzec"})
        actor = await actor_for(d)
        made = await d.montage.create_montage(PAIR, body(compilation_id="z1"), actor)
        while await d.media.process_next():
            pass
        await d.montage.tick_preparing()
        after = await d.montage.get_montage(made["id"], actor)
        return made, after

    made, after = d.run(go)
    assert made["status"] == "preparing" and made["name"] == "Kary - listopad" and made["description"] == "Co pokazujemy"
    assert [i["clip_id"] for i in made["items"]] == ["c1", "c2"] and made["items"][0]["label"] == "Wzorzec"
    assert {i["state"] for i in made["items"]} == {"cutting"}
    assert after["status"] == "queued" and after["counts"]["ready"] == 2
    cuts = [r for r in d.runs if "-ss" in r]
    assert len(cuts) == 2  # dwa zwykłe MP4 z przeliczonego zakresu (plik meczu)


def test_wybrane_klipy_w_nowej_kolejnosci_i_klip_spoza_zestawienia(d):
    async def go():
        await seed(d)
        for cid in ("c1", "c2", "c3"):
            await add_clip(d, cid)
        await add_compilation(d, ["c1", "c2", "c3"])
        actor = await actor_for(d)
        made = await d.montage.preflight(PAIR, body(compilation_id="z1", clip_ids=["c3", "c1"]), actor)
        bad = await failure(d.montage.preflight(PAIR, body(compilation_id="z1", clip_ids=["c9"]), actor))
        return made, bad

    made, bad = d.run(go)
    assert [i["clip_id"] for i in made["items"]] == ["c3", "c1"] and made["counts"]["total"] == 2
    assert made["film_s"] > 20 and made["estimate_s"] > 0 and made["can_create"] is True
    assert bad["code"] == "MONTAGE_ITEM_UNKNOWN"


def test_mecz_tylko_z_youtube_proponuje_kopie_a_kopia_w_toku_odblokuje_sama(d):
    async def go():
        await seed(d, file=False)
        await add_clip(d, "c1")
        actor = await actor_for(d)
        blocked = await d.montage.preflight(PAIR, body(clip_ids=["c1"]), actor)
        V = d.T["mentor_match_videos"]
        await d.ins("mentor_uploads", id="cp", pair_id=PAIR, match_id="m1", video_id="yt", uploader_id=A, filename="kopia.mp4", size=10,
                    r2_key="mentor/copy.mp4", status="downloading", origin="youtube", created_at=datetime.now(timezone.utc))
        await d.db.execute(V.update().where(V.c.id == "yt").values(mirror_upload_id="cp"))
        copying = await d.montage.preflight(PAIR, body(clip_ids=["c1"]), actor)
        return blocked, copying

    blocked, copying = d.run(go)
    item = blocked["items"][0]
    assert item["state"] == "blocked" and item["action"] == "copy" and item["reason"] == "NEED_COPY"
    assert item["video_id"] == "yt" and item["match_id"] == "m1" and "kopię" in item["hint"]
    assert blocked["name"]  # nazwa szybkiego montażu z meczu
    assert copying["items"][0]["state"] == "copying"


def test_brak_gwizdka_to_akcja_synchronizacji_z_lista_brakow(d):
    async def go():
        await seed(d, yt_sync={"match_start_s": 100})
        await add_clip(d, "c1")
        return await d.montage.preflight(PAIR, body(clip_ids=["c1"]), await actor_for(d))

    made = d.run(go)
    item = made["items"][0]
    assert item["action"] == "sync" and item["state"] == "blocked" and item["missing"]


def test_pominiecie_brakujacych_rusza_z_gotowymi(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1", video_id="vf", start=100, end=110)
        await add_clip(d, "c2", match_id="m2", video_id="yt2")
        now = datetime.now(timezone.utc)
        await d.ins("mentor_match_videos", id="yt2", match_id="m2", pair_key=PAIR_KEY, url="https://youtu.be/xyz", normalized_url="yt:xyz",
                    provider="youtube", added_by=A, created_at=now, kind="link", title="Inna transmisja")
        actor = await actor_for(d)
        waiting = await d.montage.create_montage(PAIR, body(clip_ids=["c1", "c2"], name="Mieszane"), actor)
        while await d.media.process_next():
            pass
        await d.montage.tick_preparing()
        still = await d.montage.get_montage(waiting["id"], actor)
        await d.montage.patch_montage(waiting["id"], d.montage.SkipBody(skip_missing=True), actor)
        await d.montage.tick_preparing()
        moved = await d.montage.get_montage(waiting["id"], actor)
        return still, moved

    still, moved = d.run(go)
    assert still["status"] == "preparing" and still["counts"]["ready"] == 1 and still["counts"]["blocked"] == 1
    assert moved["status"] == "queued" and moved["skip_missing"] is True


def test_to_samo_zamowienie_zwraca_ten_sam_film_a_obcy_nie_usunie(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1")
        actor = await actor_for(d)
        one = await d.montage.create_montage(PAIR, body(clip_ids=["c1"], name="Jeden"), actor)
        two = await d.montage.create_montage(PAIR, body(clip_ids=["c1"], name="Jeden"), actor)
        stranger = await actor_for(d, STRANGER)
        denied = await failure(d.montage.delete_montage(one["id"], stranger))
        removed = await d.montage.delete_montage(one["id"], actor)
        gone = await failure(d.montage.get_montage(one["id"], actor))
        return one, two, denied, removed, gone

    one, two, denied, removed, gone = d.run(go)
    assert two["id"] == one["id"] and two["reused"] is True
    assert denied["code"] == "NO_ACCESS" and removed == {"ok": True} and gone["code"] == "NOT_FOUND"


def test_zbyt_wiele_klipow_i_pusty_wybor(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1")
        actor = await actor_for(d)
        many = await failure(d.montage.create_montage(PAIR, body(clip_ids=[f"x{i}" for i in range(61)]), actor))
        empty = await failure(d.montage.create_montage(PAIR, body(clip_ids=[]), actor))
        foreign = await failure(d.montage.create_montage(PAIR, body(clip_ids=["nie-ma"]), actor))
        return many, empty, foreign

    many, empty, foreign = d.run(go)
    assert many["code"] == "MONTAGE_TOO_MANY" and empty["code"] == "MONTAGE_EMPTY" and foreign["code"] == "CLIP_NOT_FOUND"


def test_zestawienie_niesie_ostatni_film(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1")
        await add_compilation(d, ["c1"])
        actor = await actor_for(d)
        made = await d.montage.create_montage(PAIR, body(compilation_id="z1"), actor)
        listed = await d.library.list_compilations(PAIR, actor)
        one = await d.library.get_compilation("z1", actor)
        return made, listed, one

    made, listed, one = d.run(go)
    film = listed["compilations"][0]["film"]
    assert film["id"] == made["id"] and film["status"] in ("preparing", "queued") and film["items_count"] == 1
    assert one["film"]["id"] == made["id"]


# ─── Prawdziwy render ───────────────────────────────────────────────────────


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="brak ffmpeg")
def test_prawdziwy_render_sklada_film_z_rozdzialami(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    for name, extra in (("a.mp4", ["-f", "lavfi", "-i", "sine=frequency=440:duration=4", "-c:a", "aac", "-shortest"]), ("b.mp4", ["-an"])):
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=25:duration=4",
                        *extra[:4], "-c:v", "libx264", "-preset", "ultrafast", *extra[4:], str(src / name)], check=True)
    M = e.montage

    async def no_crests(_match):
        return {"home": None, "away": None}, {"home": "#c8141e", "away": "#1e50c8"}

    monkeypatch.setattr(M.D, "card_assets", no_crests)
    monkeypatch.setattr(M.M, "storage_ready", lambda: False)
    monkeypatch.setattr(M.M, "object_key", lambda *p: "/".join(p))
    stored = {}

    def put(path, key, _type):
        stored[key] = os.path.getsize(path)
        return stored[key]

    monkeypatch.setattr(M.M, "put_file", put)
    monkeypatch.setattr(M.M, "presign_get", lambda key, *a, **k: f"https://r2/{key}" if key else None)

    def entry(name, cid, mid, audio, zoom=None, label=""):
        return {"clip_id": cid, "match_id": mid, "clip": {"start_s": 10.0}, "match": {"home": "AZS", "away": "Gwardia", "code": "LCM-1",
                                                                                     "date": "2026-10-10", "competition": "Liga"},
                "source": {"url": str(src / name), "has_audio": audio, "key": name}, "src_w": 640, "src_h": 360, "offset": 0.5,
                "duration": 2.5, "zoom": zoom, "title": "Kara", "minute": "12:00", "half": "I połowa", "category": "Kary",
                "category_color": "rose", "label": label, "label_color": MR.label_color(label) or "", "note": "Notatka"}

    zoom = [{"s": 10.0, "cx": 0.5, "cy": 0.5, "zoom": 1.0}, {"s": 12.0, "cx": 0.4, "cy": 0.4, "zoom": 2.0}]
    entries = [entry("a.mp4", "c1", "m1", True, label="Wzorzec"), entry("b.mp4", "c2", "m2", False, zoom=zoom)]

    async def go():
        await e.db.connect()
        try:
            await e.db.execute(e.T["mentor_montages"].insert().values(id="mt", pair_id=PAIR, name="Test", items_json="[]", status="rendering",
                                                                       created_by=A))
            folder = tmp_path / "work"
            folder.mkdir()

            async def touch(*_a, **_k):
                return 1

            monkeypatch.setattr(M.C, "touch", touch)
            await M._render({"id": "mt", "pair_id": PAIR, "name": "Test", "description": "", "created_by": A}, entries, str(folder))
            film = folder / "film.mp4"
            probe = json.loads(subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_streams", "-show_chapters", str(film)],
                                              capture_output=True, text=True, check=True).stdout)
            row = await e.db.fetch_one(select(e.T["mentor_montages"]))
            return probe, dict(row._mapping)
        finally:
            await e.db.disconnect()

    probe, row = asyncio.run(go())
    plan = MR.timeline([2.5, 2.5], [True, True], 2, 10)
    video = next(s for s in probe["streams"] if s["codec_type"] == "video")
    assert int(video["nb_frames"]) == plan["total_frames"] and (video["width"], video["height"]) == (1280, 720)
    audio = next(s for s in probe["streams"] if s["codec_type"] == "audio")
    # Dźwięk jest jeden (AAC ze sklejki PCM), równy obrazowi co do kilkudziesięciu ms - bez narastania na granicach odcinków.
    assert audio["codec_name"] == "aac" and abs(float(audio["duration"]) - float(video["duration"])) < 0.06
    assert [c["tags"]["title"] for c in probe["chapters"]] == ["Test", "1. 12:00 · Wzorzec · Kara", "2. 12:00 · Kara", "Spis klipów"]
    assert row["status"] == "ready" and json.loads(row["rendered_json"]) == ["c1", "c2"] and row["poster_key"].endswith(".jpg")


def test_usuniety_film_nie_wraca_z_przegladu(d):
    async def go():
        await seed(d)
        await add_clip(d, "c1")
        actor = await actor_for(d)
        made = await d.montage.create_montage(PAIR, body(clip_ids=["c1"], name="Do usunięcia"), actor)
        while await d.media.process_next():
            pass
        row = await d.core.one(select(d.T["mentor_montages"]).where(d.T["mentor_montages"].c.id == made["id"]))
        await d.montage.delete_montage(made["id"], actor)
        await d.montage._tick_one(row)  # przegląd czytał wiersz przed usunięciem
        after = await d.core.one(select(d.T["mentor_montages"]).where(d.T["mentor_montages"].c.id == made["id"]))
        rendered = await d.montage.render_next()
        return after, rendered

    after, rendered = d.run(go)
    assert after["status"] == "cancelled" and rendered is False
