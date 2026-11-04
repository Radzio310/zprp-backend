"""Zrzuty klatek Mentora: reguły, wypalanie kształtów, trasy, dołączanie do klipów, obraz (przeglądarka, plik, Veo, Bastion), Teczka.

R2, ffmpeg, Veo, connector Bastionu i Google są atrapami. Nic z tego nie dotyka sieci ani prawdziwego ffmpeg.
"""

import io
import subprocess
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from PIL import Image
from sqlalchemy import select

from app import mentor_shot_render as SH
from app import mentor_shot_rules as SR
from app import mentor_panel_rules as R
from app.mentor_shot_tables import MIGRATIONS
from tests.mentor_panel_support import ADMIN, COMMITTEE, JUDGES, MENTOR, PAIR, STRANGER, Env
from tests.test_mentor_drive import FakeGoogle, with_folder

A, B = JUDGES


def jpeg(width=640, height=360, color=(30, 120, 60)):
    out = io.BytesIO()
    Image.new("RGB", (width, height), color).save(out, "JPEG", quality=85)
    return out.getvalue()


def webp(width=320, height=200):
    out = io.BytesIO()
    Image.new("RGB", (width, height), (200, 30, 30)).save(out, "WEBP")
    return out.getvalue()


class FakeRequest:
    def __init__(self, body: bytes, content_type="image/jpeg", declared=None):
        self.headers = {"content-type": content_type}
        if declared is not None:
            self.headers["content-length"] = str(declared)
        self._body = body

    async def stream(self):
        for i in range(0, len(self._body), 4096):
            yield self._body[i:i + 4096]


class FakeStore:
    def __init__(self):
        self.blobs = {}
        self.forgotten = []


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.mp = monkeypatch
    store = FakeStore()
    e.store = store
    S = e.shots
    monkeypatch.setattr(S, "INLINE", True)
    monkeypatch.setattr(S, "store_ready", lambda: True)
    monkeypatch.setattr(S, "store_put", lambda key, data, ct: store.blobs.__setitem__(key, data))
    monkeypatch.setattr(S, "store_get", lambda key: store.blobs[key])
    monkeypatch.setattr(S, "store_forget", lambda *keys: store.forgotten.extend(k for k in keys if k))
    monkeypatch.setattr(S, "store_url", lambda key: f"https://r2.example/{key}?sig=SECRET" if key else None)
    from app import mentor_panel_media as M

    monkeypatch.setattr(M, "object_key", lambda *parts: "mentor/" + "/".join(str(p).strip("/") for p in parts), raising=False)
    monkeypatch.setattr(e.media, "object_key", lambda *parts: "mentor/" + "/".join(str(p).strip("/") for p in parts))
    return e


async def add_video(e, vid, **over):
    now = datetime.now(timezone.utc)
    base = dict(id=vid, match_id="m1", pair_key="|".join(sorted(JUDGES)), url=f"https://x.example/{vid}", normalized_url=f"https://x.example/{vid}",
                provider="video", added_by=A, created_at=now, duration_s=4000, kind="link")
    base.update(over)
    await e.ins("mentor_match_videos", **base)


async def add_upload_video(e, vid="vu", status="ready"):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_uploads", id="up1", pair_id=PAIR, match_id="m1", uploader_id=A, filename="m.mp4", size=10, status=status,
                duration_s=3000, play_key="mentor/pair/play.mp4" if status == "ready" else None, created_at=now)
    await add_video(e, vid, kind="upload", upload_id="up1", provider="upload", url="upload://up1", normalized_url="upload://up1")


async def add_clip(e, cid, start, end, video="v1", created=None):
    now = created or datetime.now(timezone.utc)
    await e.ins("mentor_clips", id=cid, pair_id=PAIR, match_id="m1", video_id=video, start_s=float(start), end_s=float(end), title=cid,
                author_id=A, category_ids="[]", source="manual", created_at=now, updated_at=now, mp4_status="none", media_rev=1)


async def new_shot(e, author=A, at=110.5, **over):
    body = e.shots.ShotBody(match_id=over.pop("match_id", "m1"), video_id=over.pop("video_id", "v1"), at_s=at, **over)
    return await e.shots.create_shot(PAIR, body, await e.actor(author))


async def denied(coro):
    with pytest.raises(HTTPException) as caught:
        await coro
    d = caught.value.detail
    return caught.value.status_code, d.get("code") if isinstance(d, dict) else d


def ellipse(**o):
    return {"type": "ellipse", "cx": 0.5, "cy": 0.5, "rx": 0.1, "ry": 0.15, "color": "#ff0000", **o}


# ─── Reguły: kształty i limity ───────────────────────────────────────────────


def test_wszystkie_typy_ksztaltow_przechodza_walidacje_z_domyslnymi():
    shapes = SR.clean_shapes([
        ellipse(), {"type": "arrow", "x1": 0.1, "y1": 0.1, "x2": 0.4, "y2": 0.3},
        {"type": "text", "x": 0.2, "y": 0.8, "text": "Kontakt – w polu"},
        {"type": "free", "points": [[0.1, 0.1], [0.2, 0.15], [0.3, 0.1]], "color": "#00FF00", "width": 0.01},
        {"type": "spotlight", "cx": 0.5, "cy": 0.5, "rx": 0.2, "ry": 0.3},
        {"type": "loupe", "cx": 0.7, "cy": 0.4},
    ])
    assert [s["type"] for s in shapes] == ["ellipse", "arrow", "text", "free", "spotlight", "loupe"]
    assert shapes[1]["color"] == SR.DEFAULT_COLOR and shapes[1]["width"] == SR.DEFAULT_WIDTH
    assert shapes[2]["text"] == "Kontakt - w polu" and shapes[2]["size"] == SR.DEFAULT_TEXT_SIZE
    assert shapes[3]["color"] == "#00ff00" and shapes[4]["dim"] == 0.6 and shapes[5]["zoom"] == 2.5 and shapes[5]["r"] == 0.1


@pytest.mark.parametrize("bad", [
    {"type": "line", "x1": 0, "y1": 0, "x2": 1, "y2": 1}, ellipse(cx=1.2), ellipse(cx="abc"), ellipse(rx=0), ellipse(color="red"),
    ellipse(width=0.5), {"type": "arrow", "x1": 0.3, "y1": 0.3, "x2": 0.3, "y2": 0.3}, {"type": "text", "x": 0.1, "y": 0.1, "text": "  "},
    {"type": "free", "points": [[0.1, 0.1]]}, {"type": "free", "points": [[0.1, 0.1], [2, 0.2]]},
    {"type": "free", "points": [[0.1, 0.1]] * (SR.MAX_FREE_POINTS + 1)}, {"type": "loupe", "cx": 0.5, "cy": 0.5, "zoom": 20},
    {"type": "loupe", "cx": float("nan"), "cy": 0.5}, "napis", 5,
])
def test_zle_ksztalty_sa_odrzucane_z_kodem_i_numerem(bad):
    with pytest.raises(R.RuleError) as caught:
        SR.clean_shapes([ellipse(), bad])
    assert caught.value.status == 422 and caught.value.code == "SHOT_SHAPES_INVALID" and "nr 2" in caught.value.message


def test_limity_liczby_i_rozmiaru_ksztaltow():
    with pytest.raises(R.RuleError) as many:
        SR.clean_shapes([ellipse()] * (SR.MAX_SHAPES + 1))
    assert many.value.code == "SHOT_SHAPES_TOO_MANY"
    SR.clean_shapes([ellipse()] * SR.MAX_SHAPES)
    with pytest.raises(R.RuleError) as loupes:
        SR.clean_shapes([{"type": "loupe", "cx": 0.5, "cy": 0.5}] * (SR.MAX_LOUPES + 1))
    assert loupes.value.code == "SHOT_SHAPES_TOO_MANY"
    with pytest.raises(R.RuleError) as spots:
        SR.clean_shapes([{"type": "spotlight", "cx": 0.5, "cy": 0.5, "rx": 0.1, "ry": 0.1}] * 2)
    assert spots.value.code == "SHOT_SHAPES_TOO_MANY"
    big = [{"type": "free", "points": [[i / 300, 0.123456] for i in range(300)], "id": "x" * 40} for _ in range(30)]
    with pytest.raises(R.RuleError) as large:
        SR.clean_shapes(big)
    assert large.value.code == "SHOT_SHAPES_TOO_LARGE"
    assert SR.clean_shapes(None) == [] and SR.clean_shapes("") == []
    with pytest.raises(R.RuleError):
        SR.clean_shapes({"type": "ellipse"})


def test_czas_zrzutu_ulamki_i_zakres():
    assert SR.validate_at(12.3456, 100) == 12.346 and SR.validate_at(0) == 0.0 and SR.validate_at(100, 100) == 100.0
    for bad, dur in ((-1, 100), (100.5, 100), ("x", None), (float("inf"), None), (None, None), (SR.MAX_AT_S + 5, None), (True, None)):
        with pytest.raises(R.RuleError):
            SR.validate_at(bad, dur)


def test_wybor_klipu_najkrotszy_na_tym_samym_nagraniu():
    clips = [{"id": "dlugi", "video_id": "v1", "start_s": 0, "end_s": 300, "created_at": "1"},
             {"id": "krotki", "video_id": "v1", "start_s": 100, "end_s": 120, "created_at": "2"},
             {"id": "inne", "video_id": "v2", "start_s": 105, "end_s": 108, "created_at": "3"},
             {"id": "skasowany", "video_id": "v1", "start_s": 109, "end_s": 111, "created_at": "4", "deleted_at": "x"}]
    assert SR.pick_clip(clips, "v1", 110) == "krotki" and SR.pick_clip(clips, "v1", 250) == "dlugi"
    assert SR.pick_clip(clips, "v1", 400) is None and SR.pick_clip(clips, "v1", 100) == "krotki" and SR.pick_clip(clips, "v1", 120) == "krotki"
    equal = [{"id": "b", "video_id": "v", "start_s": 0, "end_s": 10, "created_at": "2"}, {"id": "a", "video_id": "v", "start_s": 5, "end_s": 15, "created_at": "1"}]
    assert SR.pick_clip(equal, "v", 7) == "a"  # remis: starszy


def test_reguly_ponownego_dolaczania_nie_ruszaja_manual_i_detached():
    clip = {"id": "c", "video_id": "v1", "start_s": 100, "end_s": 120}
    shots = [{"id": "auto_wolny", "video_id": "v1", "at_s": 110, "attach_mode": "auto", "clip_id": None},
             {"id": "manual", "video_id": "v1", "at_s": 110, "attach_mode": "manual", "clip_id": None},
             {"id": "detached", "video_id": "v1", "at_s": 110, "attach_mode": "detached", "clip_id": None},
             {"id": "poza", "video_id": "v1", "at_s": 130, "attach_mode": "auto", "clip_id": None},
             {"id": "wypadl", "video_id": "v1", "at_s": 130, "attach_mode": "auto", "clip_id": "c"},
             {"id": "zostaje", "video_id": "v1", "at_s": 105, "attach_mode": "auto", "clip_id": "c"},
             {"id": "inne_nagranie", "video_id": "v2", "at_s": 110, "attach_mode": "auto", "clip_id": None}]
    assert SR.reattach_after_clip_change(shots, clip) == [{"id": "auto_wolny", "clip_id": "c"}, {"id": "wypadl", "clip_id": None}]


def test_obraz_typ_rozmiar_i_magiczne_bajty():
    assert SR.check_upload(jpeg(), "image/jpeg") == "jpeg" and SR.check_upload(webp(), "image/webp; charset=x") == "webp"
    for data, ct, code in ((b"", "image/jpeg", "SHOT_IMAGE_EMPTY"), (jpeg(), "image/png", "SHOT_IMAGE_TYPE"), (webp(), "image/jpeg", "SHOT_IMAGE_TYPE"),
                           (b"GIF89a....", "image/jpeg", "SHOT_IMAGE_TYPE"), (b"x" * (SR.MAX_IMAGE_BYTES + 1), "image/jpeg", "SHOT_IMAGE_TOO_LARGE"),
                           (jpeg(), None, "SHOT_IMAGE_TYPE")):
        with pytest.raises(R.RuleError) as caught:
            SR.check_upload(data, ct)
        assert caught.value.code == code


def test_nazwy_i_pasek():
    assert SR.clock(83.25) == "01:23.3" or SR.clock(83.25) == "01:23.2"
    assert SR.clock(3725) == "1:02:05" and SR.clock(0) == "00:00"
    assert SR.png_filename("Kara 2 min", "ISM/1", 83.4) == "ISM-1 Kara 2 min 01-23.4.png"
    assert SR.png_filename(None, None, 5).endswith(".png") and SR.banner_lines("A - B (X/1)", 83, "Faul") == ["A - B (X/1)", "01:23", "Faul"]
    assert SR.banner_lines("", 83, "") == ["01:23"]


def test_migracja_idempotentna(env):
    from sqlalchemy import create_engine, text

    engine = create_engine(env.url)
    with engine.connect() as conn:
        for _ in range(2):
            for statement in (m for m in MIGRATIONS if "ADD COLUMN" not in m):  # SQLite nie zna IF NOT EXISTS dla kolumn
                conn.execute(text(statement))
            conn.commit()
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(mentor_shots)"))}
    assert {"id", "pair_id", "match_id", "video_id", "at_s", "shapes_json", "clip_id", "attach_mode", "image_status", "image_reason",
            "image_source", "image_key", "thumb_key", "width", "height", "deleted_at", "view_json"} <= cols
    assert any("view_json" in m for m in MIGRATIONS)


# ─── Wypalanie: Pillow ───────────────────────────────────────────────────────


def png_pixels(data):
    image = Image.open(io.BytesIO(data))
    assert image.format == "PNG"
    return image.convert("RGB")


def test_wypalenie_wszystkich_typow_i_czytelnosc_na_kazdym_rozmiarze():
    shapes = SR.clean_shapes([
        ellipse(color="#ff0000", width=0.01), {"type": "arrow", "x1": 0.1, "y1": 0.9, "x2": 0.4, "y2": 0.6, "color": "#00ff00"},
        {"type": "text", "x": 0.05, "y": 0.05, "text": "Żółć Ąę", "color": "#ffffff", "size": 0.08},
        {"type": "free", "points": [[0.6, 0.8], [0.7, 0.9], [0.8, 0.8]], "color": "#0000ff", "width": 0.01}])
    for width, height in ((160, 90), (640, 360), (1920, 1080), (3000, 1700)):
        base = jpeg(width, height, (90, 90, 90))
        out = png_pixels(SH.render_png(base, shapes))
        assert out.size == (width, height)
        # czerwona obwódka elipsy tuż przy prawej krawędzi (cx+rx = 0.6), widoczna mimo szarego tła
        x = int(0.6 * width)
        reds = [out.getpixel((min(width - 1, x + dx), height // 2)) for dx in range(-4, 5)]
        assert any(r > 200 and g < 80 and b < 80 for r, g, b in reds), (width, reds)
        # zielona strzałka, niebieski odręczny i biały tekst istnieją
        pix = list(out.getdata())
        assert any(g > 200 and r < 80 and b < 80 for r, g, b in pix)
        assert any(b > 200 and r < 80 and g < 80 for r, g, b in pix)
        assert any(r > 240 and g > 240 and b > 240 for r, g, b in pix[: width * int(0.2 * height)])


def test_reflektor_sciemnia_poza_elipsa_a_lupa_powieksza():
    base = Image.new("RGB", (400, 300), (200, 200, 200))
    for x in range(190, 210):  # mały jasny pasek w środku, reszta szara
        for y in range(140, 160):
            base.putpixel((x, y), (255, 255, 0))
    buf = io.BytesIO()
    base.save(buf, "PNG")
    # PNG nie przechodzi przez upload, ale render akceptuje każdy obraz Pillow
    spot = SR.clean_shapes([{"type": "spotlight", "cx": 0.5, "cy": 0.5, "rx": 0.15, "ry": 0.2, "dim": 0.8, "color": "#ffffff", "width": 0.002}])
    out = png_pixels(SH.render_png(buf.getvalue(), spot))
    assert out.getpixel((200, 150))[0] > 190 and out.getpixel((10, 10))[0] < 80  # środek jasny, narożnik ciemny
    loupe = SR.clean_shapes([{"type": "loupe", "cx": 0.5, "cy": 0.5, "r": 0.2, "zoom": 4, "color": "#ff00ff", "width": 0.01}])
    zoomed = png_pixels(SH.render_png(buf.getvalue(), loupe))
    yellow = sum(1 for p in zoomed.getdata() if p[0] > 230 and p[1] > 230 and p[2] < 60)
    plain = sum(1 for p in base.getdata() if p[0] > 230 and p[1] > 230 and p[2] < 60)
    assert yellow > plain * 8  # powiększenie 4x = ok. 16x pól, nawet po przycięciu kołem
    assert any(p[0] > 200 and p[2] > 200 and p[1] < 80 for p in zoomed.getdata())  # obwódka lupy


def test_pasek_dolacza_sie_pod_kadrem_i_nie_zakrywa_go():
    base = jpeg(800, 450, (10, 200, 10))
    plain = png_pixels(SH.render_png(base, []))
    banner = png_pixels(SH.render_png(base, [], ["Gwardia - AGH (LCM-32)", "23:20", "Faul"]))
    assert banner.size[0] == 800 and banner.size[1] > 450
    assert banner.getpixel((400, 225)) == plain.getpixel((400, 225))
    bar = [banner.getpixel((x, banner.size[1] - 3)) for x in range(0, 800, 40)]
    assert all(sum(p) < 120 for p in bar)
    assert any(p[0] > 200 and p[1] > 200 and p[2] > 200 for p in banner.crop((0, 450, 800, banner.size[1])).getdata())


def test_przygotowanie_obrazu_miniatura_wymiary_i_uszkodzony_plik():
    prepared = SH.prepare_stored(jpeg(2000, 1000))
    assert (prepared["width"], prepared["height"]) == (2000, 1000)
    thumb = Image.open(io.BytesIO(prepared["thumb"]))
    assert max(thumb.size) == SR.THUMB_SIDE
    assert (SH.prepare_stored(webp())["width"]) == 320
    with pytest.raises(R.RuleError) as small:
        SH.prepare_stored(jpeg(30, 30))
    assert small.value.code == "SHOT_IMAGE_SMALL"
    with pytest.raises(R.RuleError) as corrupt:
        SH.prepare_stored(jpeg()[:200])
    assert corrupt.value.code == "SHOT_IMAGE_CORRUPT"
    with pytest.raises(R.RuleError) as big:
        SH.prepare_stored(jpeg(SR.MAX_IMAGE_SIDE + 10, 100))
    assert big.value.code == "SHOT_IMAGE_DIMENSIONS"


# ─── Trasy: tworzenie, lista, zmiana, kosz ───────────────────────────────────


def test_tworzenie_lista_zmiana_i_kosz(env):
    async def go():
        shot = await new_shot(env, title="  Faul — ręka ", note="Notatka", shapes=[ellipse()])
        assert shot["at_s"] == 110.5 and shot["title"] == "Faul - ręka" and shot["shapes"][0]["type"] == "ellipse"
        assert shot["attach_mode"] == "auto" and shot["clip_id"] is None
        assert shot["image_status"] == "none" and shot["image_reason"] == "YOUTUBE_NO_IMAGE" and "YouTube" in shot["image_message"]
        assert shot["image_url"] is None and shot["thumb_url"] is None and shot["author"]["judge_id"] == A and shot["can_edit"] is True
        assert shot["threads"] == {"total": 0, "open": 0, "comments": 0}
        other = await new_shot(env, at=300)
        listed = await env.shots.list_shots(PAIR, match_id="m1", clip_id="", video_id="", category="", author="", q="", standalone=False,
                                            actor=await env.actor(B))
        assert [s["id"] for s in listed["shots"]] == [other["id"], shot["id"]]  # od najnowszego; partner widzi i nie edytuje
        assert listed["shots"][1]["can_edit"] is False
        found = await env.shots.list_shots(PAIR, match_id="", clip_id="", video_id="", category="", author="", q="ręka", standalone=True,
                                           actor=await env.actor(MENTOR))
        assert [s["id"] for s in found["shots"]] == [shot["id"]]
        patched = await env.shots.update_shot(shot["id"], env.shots.ShotPatch(title="Nowy", shapes=[{"type": "arrow", "x1": 0, "y1": 0, "x2": 1, "y2": 1}]),
                                              await env.actor(A))
        assert patched["title"] == "Nowy" and patched["shapes"][0]["type"] == "arrow" and patched["at_s"] == 110.5
        assert (await denied(env.shots.update_shot(shot["id"], env.shots.ShotPatch(title="x"), await env.actor(B))))[0] == 403
        removed = await env.shots.delete_shot(shot["id"], await env.actor(A))
        assert removed == {"ok": True}
        assert await denied(env.shots.get_shot(shot["id"], await env.actor(A))) == (404, "NOT_FOUND")
        listed = await env.shots.list_shots(PAIR, match_id="", clip_id="", video_id="", category="", author="", q="", standalone=False, actor=await env.actor(A))
        assert [s["id"] for s in listed["shots"]] == [other["id"]]
        row = await env.core.one(select(env.T["mentor_shots"]).where(env.T["mentor_shots"].c.id == shot["id"]))
        assert row["deleted_at"] is not None  # kosz jak przy klipach: wiersz zostaje
        changes = await env.core.changes_since(PAIR, 0)
        assert "shots" in changes["scopes"]

    env.run(go)


def test_walidacja_przy_tworzeniu_i_odmowy_dostepu(env):
    async def go():
        assert (await denied(new_shot(env, at=-3)))[1] == "SHOT_AT"
        assert (await denied(new_shot(env, at=99999)))[1] == "SHOT_AT_RANGE"
        assert (await denied(new_shot(env, shapes=[{"type": "kolo"}])))[1] == "SHOT_SHAPES_INVALID"
        assert (await denied(new_shot(env, video_id="nie-ma")))[1] == "VIDEO_NOT_FOUND"
        assert (await denied(new_shot(env, attach_mode="manual")))[1] == "SHOT_ATTACH_MODE"
        assert (await denied(new_shot(env, clip_id="brak")))[1] == "NOT_FOUND"
        assert (await denied(new_shot(env, author=STRANGER)))[0] == 403
        assert (await denied(new_shot(env, author=COMMITTEE)))[0] == 403  # komisja ogląda, nie tworzy
        shot = await new_shot(env)
        assert (await denied(env.shots.get_shot(shot["id"], await env.actor(STRANGER))))[0] == 403
        assert (await denied(env.shots.delete_shot(shot["id"], await env.actor(B))))[0] == 403
        assert (await denied(env.shots.upload_image(shot["id"], FakeRequest(jpeg()), await env.actor(B))))[0] == 403
        assert (await denied(env.shots.download_png(shot["id"], False, True, await env.actor(STRANGER))))[0] == 403
        assert (await env.shots.get_shot(shot["id"], await env.actor(COMMITTEE)))["id"] == shot["id"]  # komisja czyta
        assert (await env.shots.delete_shot(shot["id"], await env.actor(ADMIN))) == {"ok": True}  # administrator może wszystko
        # limit na mecz
        env.mp.setattr(SR, "MAX_SHOTS_PER_MATCH", 2)
        await new_shot(env, at=1)
        await new_shot(env, at=2)
        assert (await denied(new_shot(env, at=3)))[1] == "SHOT_LIMIT"

    env.run(go)


# ─── Dołączanie do klipów ────────────────────────────────────────────────────


def test_nowy_zrzut_dolacza_sie_do_najkrotszego_klipu(env):
    async def go():
        await add_clip(env, "dlugi", 0, 300)
        await add_clip(env, "krotki", 100, 120)
        inside = await new_shot(env, at=110)
        long_only = await new_shot(env, at=250)
        none = await new_shot(env, at=500)
        assert (inside["clip_id"], inside["attach_mode"]) == ("krotki", "auto")
        assert long_only["clip_id"] == "dlugi" and none["clip_id"] is None
        manual = await new_shot(env, at=110, clip_id="dlugi")
        assert (manual["clip_id"], manual["attach_mode"]) == ("dlugi", "manual")
        detached = await new_shot(env, at=110, attach_mode="detached")
        assert (detached["clip_id"], detached["attach_mode"]) == (None, "detached")
        assert (await denied(new_shot(env, at=110, clip_id="dlugi", match_id="m2")))[0] in (403, 404, 422)
        clips = (await env.library.list_clips(PAIR, category="", match_id="", author="", q="", markers=False, actor=await env.actor(A)))["clips"]
        counts = {c["id"]: c["shots_count"] for c in clips}
        assert counts == {"dlugi": 2, "krotki": 1}
        room = await env.panel.match_room(PAIR, "m1", await env.actor(B))
        assert {c["id"]: c["shots_count"] for c in room["clips"]} == counts and len(room["shots"]) == 5
        assert [s["at_s"] for s in room["shots"]] == sorted(s["at_s"] for s in room["shots"])

    env.run(go)


def test_nowy_i_zmieniony_klip_zgarnia_tylko_auto_bez_klipu(env):
    async def go():
        a = await new_shot(env, at=110)  # auto, wolny
        manual_free = await new_shot(env, at=111)
        await env.shots.update_shot(manual_free["id"], env.shots.ShotPatch(attach_mode="detached"), await env.actor(A))
        d = await env.shots.get_shot(a["id"], await env.actor(A))
        assert d["clip_id"] is None
        clip = await env.library.create_clip(PAIR, env.library.ClipBody(match_id="m1", video_id="v1", start_s=100, end_s=120), await env.actor(A))
        got = {s["id"]: s for s in (await env.shots.list_shots(PAIR, match_id="m1", clip_id="", video_id="", category="", author="", q="", standalone=False,
                                                              actor=await env.actor(A)))["shots"]}
        assert got[a["id"]]["clip_id"] == clip["id"] and got[a["id"]]["attach_mode"] == "auto"
        assert got[manual_free["id"]]["clip_id"] is None and got[manual_free["id"]]["attach_mode"] == "detached"  # odłączony ręcznie nie wraca sam
        # zmiana zakresu: zrzut poza zakresem wraca do stanu bez klipu, a w nowym zakresie zostaje zgarnięty
        late = await new_shot(env, at=200)
        await env.library.update_clip(clip["id"], env.library.ClipPatch(start_s=150, end_s=210), await env.actor(A))
        after = {s["id"]: s for s in (await env.shots.list_shots(PAIR, match_id="m1", clip_id="", video_id="", category="", author="", q="", standalone=False,
                                                                actor=await env.actor(A)))["shots"]}
        assert after[a["id"]]["clip_id"] is None and after[late["id"]]["clip_id"] == clip["id"]
        # zmiana bez zmiany zakresu niczego nie rusza
        await env.library.update_clip(clip["id"], env.library.ClipPatch(title="Inny"), await env.actor(A))
        # ręczne dołączenie nie zależy od zakresu i przeżywa zmianę zakresu
        far = await env.shots.update_shot(a["id"], env.shots.ShotPatch(clip_id=clip["id"]), await env.actor(A))
        assert (far["clip_id"], far["attach_mode"]) == (clip["id"], "manual")
        await env.library.update_clip(clip["id"], env.library.ClipPatch(start_s=190, end_s=210), await env.actor(A))
        assert (await env.shots.get_shot(a["id"], await env.actor(A)))["clip_id"] == clip["id"]

    env.run(go)


def test_odlaczenie_dolaczenie_i_powrot_do_automatu(env):
    async def go():
        await add_clip(env, "c1", 100, 120)
        await add_clip(env, "c2", 105, 400)
        shot = await new_shot(env, at=110)
        assert shot["clip_id"] == "c1"
        p = await env.shots.update_shot(shot["id"], env.shots.ShotPatch(clip_id=None), await env.actor(A))
        assert (p["clip_id"], p["attach_mode"]) == (None, "detached")
        p = await env.shots.update_shot(shot["id"], env.shots.ShotPatch(clip_id="c2"), await env.actor(A))
        assert (p["clip_id"], p["attach_mode"]) == ("c2", "manual")
        p = await env.shots.update_shot(shot["id"], env.shots.ShotPatch(attach_mode="auto"), await env.actor(A))
        assert (p["clip_id"], p["attach_mode"]) == ("c1", "auto")  # automat wybiera najkrótszy
        assert (await denied(env.shots.update_shot(shot["id"], env.shots.ShotPatch(clip_id="c1", attach_mode="auto"), await env.actor(A))))[1] == "SHOT_ATTACH_MODE"
        assert (await denied(env.shots.update_shot(shot["id"], env.shots.ShotPatch(clip_id="brak"), await env.actor(A))))[0] == 404
        assert (await denied(env.shots.update_shot(shot["id"], env.shots.ShotPatch(attach_mode="x"), await env.actor(A))))[1] == "SHOT_ATTACH_MODE"

    env.run(go)


def test_usuniecie_klipu_zostawia_zrzut_samodzielny(env):
    async def go():
        await add_clip(env, "c1", 100, 120)
        await add_clip(env, "c2", 0, 500)
        auto = await new_shot(env, at=110)  # c1 (krótszy)
        manual = await new_shot(env, at=110, clip_id="c1")
        only = await new_shot(env, at=50)  # tylko c2
        await env.library.delete_clip("c1", await env.actor(A))
        got = {s["id"]: s for s in (await env.shots.list_shots(PAIR, match_id="m1", clip_id="", video_id="", category="", author="", q="", standalone=False,
                                                              actor=await env.actor(A)))["shots"]}
        assert got[auto["id"]]["clip_id"] == "c2" and got[auto["id"]]["attach_mode"] == "auto"  # inny klip w zakresie może go zgarnąć
        assert (got[manual["id"]]["clip_id"], got[manual["id"]]["attach_mode"]) == (None, "detached")  # ręczny staje się samodzielny
        assert got[only["id"]]["clip_id"] == "c2"
        await env.library.delete_clip("c2", await env.actor(A))
        got = {s["id"]: s for s in (await env.shots.list_shots(PAIR, match_id="m1", clip_id="", video_id="", category="", author="", q="", standalone=False,
                                                              actor=await env.actor(A)))["shots"]}
        assert all(s["clip_id"] is None for s in got.values()) and len(got) == 3

    env.run(go)


# ─── Obraz: przeglądarka ─────────────────────────────────────────────────────


def test_wgranie_obrazu_z_przegladarki_jpeg_webp_i_wymiana(env):
    async def go():
        shot = await new_shot(env, shapes=[ellipse()])
        up = await env.shots.upload_image(shot["id"], FakeRequest(jpeg(1280, 720)), await env.actor(A))
        assert up["image_status"] == "ready" and up["image_source"] == "browser" and (up["width"], up["height"]) == (1280, 720)
        assert up["image_url"].startswith("https://r2.example/mentor/") and up["thumb_url"].endswith("-thumb.jpg?sig=SECRET")
        assert up["image_reason"] is None and len(env.store.blobs) == 2
        first_keys = set(env.store.blobs)
        again = await env.shots.upload_image(shot["id"], FakeRequest(webp(800, 600), "image/webp"), await env.actor(A))
        assert (again["width"], again["height"]) == (800, 600)
        row = await env.core.one(select(env.T["mentor_shots"]))
        assert set(env.store.forgotten) == first_keys  # stare obiekty skasowane dopiero po udanym zapisie
        assert Image.open(io.BytesIO(env.store.blobs[row["image_key"]])).format == "JPEG"
        # błędy: typ, rozmiar, zawartość, wymiary
        bad = [(FakeRequest(jpeg(), "image/png"), "SHOT_IMAGE_TYPE"), (FakeRequest(webp(), "image/jpeg"), "SHOT_IMAGE_TYPE"),
               (FakeRequest(b""), "SHOT_IMAGE_EMPTY"), (FakeRequest(b"\xff\xd8\xff" + b"0" * 500), "SHOT_IMAGE_CORRUPT"),
               (FakeRequest(jpeg(20, 20)), "SHOT_IMAGE_SMALL"), (FakeRequest(jpeg(), declared=SR.MAX_IMAGE_BYTES + 1), "SHOT_IMAGE_TOO_LARGE")]
        for request, code in bad:
            assert (await denied(env.shots.upload_image(shot["id"], request, await env.actor(A))))[1] == code
        env.mp.setattr(SR, "MAX_IMAGE_BYTES", 1000)
        assert (await denied(env.shots.upload_image(shot["id"], FakeRequest(jpeg(640, 360)), await env.actor(A))))[1] == "SHOT_IMAGE_TOO_LARGE"
        env.mp.setattr(env.shots, "store_ready", lambda: False)
        env.mp.setattr(SR, "MAX_IMAGE_BYTES", 8 * 1024 * 1024)
        assert await denied(env.shots.upload_image(shot["id"], FakeRequest(jpeg()), await env.actor(A))) == (503, "STORAGE_OFF")

    env.run(go)


# ─── Obraz: serwer (plik, Veo, Bastion, YouTube) ─────────────────────────────


def fake_ffmpeg(env, calls, fail=None):
    def run(args, timeout):
        calls.append(args)
        if fail == "missing":
            raise FileNotFoundError("ffmpeg")
        if fail == "timeout":
            raise subprocess.TimeoutExpired(args, timeout)
        if fail == "rc":
            return subprocess.CompletedProcess(args, 1, b"", b"error")
        with open(args[-1], "wb") as handle:
            handle.write(jpeg(1920, 1080))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    env.mp.setattr(env.shots, "_run", run)


def test_klatka_z_wgranego_pliku_ffmpeg_co_do_klatki(env):
    async def go():
        await add_upload_video(env)
        calls = []
        fake_ffmpeg(env, calls)
        env.mp.setattr(env.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2.example/{key}?sig=SECRET")
        env.mp.setattr(env.media, "storage_ready", lambda: True)
        shot = await new_shot(env, video_id="vu", at=83.456, server_frame=True)
        assert shot["image_status"] == "ready" and shot["image_source"] == "server" and (shot["width"], shot["height"]) == (1920, 1080)
        args = calls[0]
        assert args[0] == "ffmpeg" and args[args.index("-ss") + 1] == "83.456" and args.index("-ss") < args.index("-i") and "-frames:v" in args
        assert "-protocol_whitelist" in args  # zdalne źródło tylko po https
        # ponowienie przez trasę zastępuje obraz
        again = await env.shots.request_server_frame(shot["id"], await env.actor(A))
        assert again["image_status"] == "ready" and len(calls) == 2
        # poza gotowością nagrania
        await env.db.execute(env.T["mentor_uploads"].update().values(status="processing"))
        fresh = await new_shot(env, video_id="vu", at=5, server_frame=True)
        assert (fresh["image_status"], fresh["image_reason"]) == ("failed", "VIDEO_NOT_READY")

    env.run(go)


@pytest.mark.parametrize("mode,code", [("missing", "FFMPEG_MISSING"), ("timeout", "FRAME_TIMEOUT"), ("rc", "FRAME_FAILED")])
def test_blad_ffmpeg_daje_failed_z_kodem_i_ponowienie_dziala(env, mode, code):
    async def go():
        await add_upload_video(env)
        env.mp.setattr(env.media, "presign_get", lambda key, expires=0, filename=None: "https://r2.example/x?sig=SECRET")
        env.mp.setattr(env.media, "storage_ready", lambda: True)
        fake_ffmpeg(env, [], fail=mode)
        shot = await new_shot(env, video_id="vu", server_frame=True)
        assert (shot["image_status"], shot["image_reason"]) == ("failed", code) and shot["image_message"]
        assert "SECRET" not in repr(shot["image_message"])
        fake_ffmpeg(env, [])
        assert (await env.shots.request_server_frame(shot["id"], await env.actor(A)))["image_status"] == "ready"

    env.run(go)


def test_klatka_z_veo_stany_i_adres_nie_wycieka(env):
    async def go():
        await add_video(env, "vv", provider="veo", url="https://app.veo.co/matches/abcdef-123456", normalized_url="https://app.veo.co/matches/abcdef-123456")
        calls = []
        fake_ffmpeg(env, calls)

        async def ok(row):
            return "https://c.veocdn.com/secret/video.mp4?token=SECRET"

        env.mp.setattr(env.veo, "resolve_media", ok)
        shot = await new_shot(env, video_id="vv", at=12.25, server_frame=True)
        assert shot["image_status"] == "ready" and shot["image_source"] == "server"
        assert calls[0][calls[0].index("-i") + 1].startswith("https://c.veocdn.com/") and "-reconnect" in calls[0]
        for status, code in (("private", "VEO_PRIVATE"), ("gone", "VEO_GONE"), ("processing", "VEO_PROCESSING"), ("unavailable", "VEO_UNAVAILABLE")):
            async def broken(row, status=status):
                raise env.veo.VeoError(status)

            env.mp.setattr(env.veo, "resolve_media", broken)
            failed = await new_shot(env, video_id="vv", at=20, server_frame=True)
            assert (failed["image_status"], failed["image_reason"]) == ("failed", code) and failed["image_message"]

    env.run(go)


def test_youtube_i_zwykly_link_nie_maja_obrazu_pobranie_i_teczka_dostaja_czytelny_blad(env):
    async def go():
        await add_video(env, "vl", provider="video", url="https://example.com/film.mp4", normalized_url="https://example.com/film.mp4")
        yt = await new_shot(env, server_frame=True)  # v1 = YouTube
        link = await new_shot(env, video_id="vl", server_frame=True)
        assert (yt["image_status"], yt["image_reason"]) == ("none", "YOUTUBE_NO_IMAGE")
        assert (link["image_status"], link["image_reason"]) == ("none", "LINK_NO_IMAGE")
        assert (await env.shots.request_server_frame(yt["id"], await env.actor(A)))["image_status"] == "none"
        err = await denied(env.shots.download_png(yt["id"], False, True, await env.actor(A)))
        assert err == (409, "SHOT_NO_IMAGE")
        try:
            await env.shots.download_png(yt["id"], False, True, await env.actor(A))
        except HTTPException as exc:
            assert "YouTube" in exc.detail["message"]
        assert not env.store.blobs

    env.run(go)


def bastion_env(env, monkeypatch_body):
    env.mp.setenv("BASTION_ENABLED", "true")
    env.mp.setenv("BASTION_CONNECTOR_URL", "https://connector.example")
    env.mp.setenv("BASTION_CONNECTOR_TOKEN", "tok")
    from app import mentor_bastion_client as CL

    calls = []

    class Client:
        async def request(self, method, path, *, params=None, json=None, timeout=None):
            calls.append((method, path, json))
            return monkeypatch_body(json)

    env.mp.setattr(CL, "get_client", lambda: Client())
    return CL, calls


def test_klatka_z_bastionu_przez_connector_i_jego_bledy(env):
    async def go():
        await add_video(env, "vb", provider="bastion", url="https://portal.handball-bastion.pl/game?bunny_item_id=77",
                        normalized_url="https://portal.handball-bastion.pl/game?bunny_item_id=77", external_id="77")
        import base64

        state = {"mode": "ok"}

        def reply(body):
            from app.mentor_bastion_client import Reply

            if state["mode"] == "ok":
                return Reply(200, {"jpeg_b64": base64.b64encode(jpeg(1280, 720)).decode(), "at_s": body["at_s"], "duration_s": 3000})
            if state["mode"] == "auth":
                return Reply(401, {"code": "BASTION_AUTH_REQUIRED"})
            if state["mode"] == "none":
                return Reply(409, {"code": "BASTION_NOT_CONNECTED"})
            return Reply(502, {"code": "BASTION_FRAME_FAILED"})

        CL, calls = bastion_env(env, reply)
        shot = await new_shot(env, video_id="vb", at=642.4, server_frame=True)
        assert shot["image_status"] == "ready" and shot["image_source"] == "server" and (shot["width"], shot["height"]) == (1280, 720)
        assert calls[0][1] == "/frame" and calls[0][2]["bunny_item_id"] == 77 and calls[0][2]["at_s"] == 642.4 and calls[0][2]["scope"] == "default"
        for mode, code in (("auth", "BASTION_AUTH_REQUIRED"), ("none", "BASTION_NOT_CONNECTED"), ("boom", "BASTION_FRAME_FAILED")):
            state["mode"] = mode
            failed = await new_shot(env, video_id="vb", at=10, server_frame=True)
            assert (failed["image_status"], failed["image_reason"]) == ("failed", code)
        env.mp.setenv("BASTION_ENABLED", "false")
        off = await new_shot(env, video_id="vb", at=11, server_frame=True)
        assert (off["image_status"], off["image_reason"]) == ("failed", "BASTION_OFF")

    env.run(go)


def test_przerwane_zadanie_obrazu_jest_widoczne_jako_failed_i_mozna_ponowic(env):
    async def go():
        await add_upload_video(env)
        shot = await new_shot(env, video_id="vu")
        old = datetime(2020, 1, 1, tzinfo=timezone.utc)
        await env.db.execute(env.T["mentor_shots"].update().values(image_status="processing", updated_at=old))
        view = await env.shots.get_shot(shot["id"], await env.actor(A))
        assert (view["image_status"], view["image_reason"]) == ("failed", "FRAME_TIMEOUT")
        fresh = await env.core.one(select(env.T["mentor_shots"]))
        await env.db.execute(env.T["mentor_shots"].update().values(image_status="processing", updated_at=datetime.now(timezone.utc)))
        assert (await denied(env.shots.download_png(shot["id"], False, True, await env.actor(A))))[1] == "SHOT_IMAGE_PROCESSING"
        assert fresh is not None

    env.run(go)


# ─── Pobranie PNG ────────────────────────────────────────────────────────────


def test_pobranie_png_z_wypalonymi_zaznaczeniami_i_paskiem(env):
    async def go():
        shot = await new_shot(env, title="Kara 2 min", shapes=[ellipse(color="#ff0000", width=0.012)], category_ids=[])
        await env.shots.upload_image(shot["id"], FakeRequest(jpeg(960, 540, (90, 90, 90))), await env.actor(A))
        plain = await env.shots.download_png(shot["id"], False, True, await env.actor(B))  # partner pobiera
        assert plain.media_type == "image/png" and "attachment" in plain.headers["Content-Disposition"] and plain.headers["Cache-Control"].startswith("private")
        assert ".png" in plain.headers["Content-Disposition"] and "SECRET" not in plain.headers["Content-Disposition"]
        image = png_pixels(plain.body)
        assert image.size == (960, 540)
        assert any(r > 200 and g < 80 and b < 80 for r, g, b in image.getdata())
        bare = png_pixels((await env.shots.download_png(shot["id"], False, False, await env.actor(A))).body)
        assert not any(r > 200 and g < 80 and b < 80 for r, g, b in bare.getdata())  # shapes=false: sama klatka
        bar = png_pixels((await env.shots.download_png(shot["id"], True, True, await env.actor(A))).body)
        assert bar.size[0] == 960 and bar.size[1] > 540

    env.run(go)


# ─── Kadr zrzutu i lupa ze źródłem ───────────────────────────────────────────


def test_kadr_walidacja_normalizacja_i_okno_przy_krawedzi():
    assert SR.clean_view(None) is None and SR.clean_view("") is None
    assert SR.clean_view({"cx": 0.5, "cy": 0.5, "zoom": 1}) is None  # zoom <= 1 = cała klatka
    assert SR.clean_view({"cx": 0.3, "cy": 0.7, "zoom": 2.5}) == {"cx": 0.3, "cy": 0.7, "zoom": 2.5}
    for bad in ({"cx": 1.2, "cy": 0.5, "zoom": 2}, {"cx": 0.5, "cy": 0.5, "zoom": 7}, {"cx": 0.5, "cy": 0.5, "zoom": 0.5},
                {"cx": 0.5, "cy": 0.5}, {"cx": "a", "cy": 0.5, "zoom": 2}, [1, 2], 5):
        with pytest.raises(R.RuleError) as exc:
            SR.clean_view(bad)
        assert exc.value.code == "SHOT_VIEW_INVALID"
    assert SR.view_window(None) == (0.0, 0.0, 1.0, 1.0)
    assert SR.view_window({"cx": 0.5, "cy": 0.5, "zoom": 2}) == (0.25, 0.25, 0.75, 0.75)
    assert SR.view_window({"cx": 0.02, "cy": 0.99, "zoom": 4}) == (0.0, 0.75, 0.25, 1.0)  # dosunięte do krawędzi, nie zmniejszone


def test_lupa_px_py_razem_albo_wcale():
    ok = SR.clean_shapes([{"type": "loupe", "cx": 0.3, "cy": 0.3, "px": 0.7, "py": 0.6}])[0]
    assert ok["px"] == 0.7 and ok["py"] == 0.6
    assert "px" not in SR.clean_shapes([{"type": "loupe", "cx": 0.3, "cy": 0.3}])[0]
    for bad in ({"px": 0.5}, {"py": 0.5}, {"px": 1.5, "py": 0.5}, {"px": "x", "py": 0.5}):
        with pytest.raises(R.RuleError) as exc:
            SR.clean_shapes([{"type": "loupe", "cx": 0.3, "cy": 0.3, **bad}])
        assert exc.value.code == "SHOT_SHAPES_INVALID"


def quadrant_frame():
    """Klatka 400x300: lewa połowa czerwona, prawa niebieska, w lewej górnej ćwiartce żółty znacznik 10x10 w (100,75)."""
    base = Image.new("RGB", (400, 300), (200, 0, 0))
    for x in range(200, 400):
        for y in range(300):
            base.putpixel((x, y), (0, 0, 200))
    for x in range(95, 105):
        for y in range(70, 80):
            base.putpixel((x, y), (255, 255, 0))
    buf = io.BytesIO()
    base.save(buf, "PNG")
    return buf.getvalue()


def quadrant_jpeg():
    out = io.BytesIO()
    Image.open(io.BytesIO(quadrant_frame())).convert("RGB").save(out, "JPEG", quality=95)
    return out.getvalue()


def test_png_z_kadrem_tnie_do_okna_skaluje_i_pasek_zostaje_pod_kadrem():
    frame = quadrant_frame()
    full = png_pixels(SH.render_png(frame, []))
    cut = png_pixels(SH.render_png(frame, [], None, {"cx": 0.25, "cy": 0.25, "zoom": 2}))  # lewa górna ćwiartka
    assert cut.size == full.size == (400, 300)
    assert full.getpixel((390, 10)) == (0, 0, 200) and cut.getpixel((390, 10)) == (200, 0, 0)
    assert cut.getpixel((200, 150))[0] > 240 and cut.getpixel((200, 150))[1] > 240  # znacznik (środek ćwiartki) w środku kadru
    yellow = sum(1 for p in cut.getdata() if p[0] > 240 and p[1] > 240 and p[2] < 40)
    assert 280 <= yellow <= 450  # 10x10 px -> ok. 20x20
    edge = png_pixels(SH.render_png(frame, [], None, {"cx": 0.99, "cy": 0.5, "zoom": 2}))  # okno dosunięte do prawej krawędzi
    assert edge.getpixel((5, 150)) == (0, 0, 200) and edge.getpixel((395, 150)) == (0, 0, 200)
    banner = png_pixels(SH.render_png(frame, [], ["Mecz", "01:10"], {"cx": 0.25, "cy": 0.25, "zoom": 2}))
    assert banner.size[0] == 400 and banner.size[1] > 300 and banner.getpixel((390, 10)) == (200, 0, 0)
    assert all(sum(banner.getpixel((x, banner.size[1] - 2))) < 120 for x in range(0, 400, 40))  # pasek pod kadrem


def test_lupa_ze_zrodlem_stozek_kolko_zrodla_i_tresc_z_oryginalu():
    frame = quadrant_frame()
    loupe = SR.clean_shapes([{"type": "loupe", "cx": 0.25, "cy": 0.25, "px": 0.8, "py": 0.5, "r": 0.12, "zoom": 3,
                              "color": "#00ff00", "width": 0.004}])
    out = png_pixels(SH.render_png(frame, loupe))
    # powiększenie wyrosło przy px,py (320,150) na niebieskiej połowie, a w środku ma żółty znacznik z oryginalnej klatki
    centre = out.getpixel((320, 150))
    assert centre[0] > 240 and centre[1] > 240 and centre[2] < 40
    assert any(g > 200 and r < 60 and b < 60 for r, g, b in out.crop((260, 90, 380, 210)).getdata())  # obwódka koła powiększenia
    # źródło zostaje na miejscu (100,75): kółko źródła o promieniu 0.12*400/3 = 16 px ma zieloną obwódkę
    assert any(g > 200 and r < 60 and b < 60 for r, g, b in (out.getpixel((100 + dx, 75)) for dx in range(13, 20)))
    # stożek: między kółkiem a kołem są zielone styczne, a poza nimi tło bez zmian
    assert any(g > 200 and r < 60 and b < 60 for r, g, b in out.crop((120, 70, 260, 150)).getdata())
    assert out.getpixel((10, 290)) == (200, 0, 0) and out.getpixel((390, 290)) == (0, 0, 200)
    # bez px,py lupa jak dziś: powiększenie w miejscu źródła, nic nie wyrasta obok
    plain = SR.clean_shapes([{"type": "loupe", "cx": 0.25, "cy": 0.25, "r": 0.12, "zoom": 3}])
    inplace = png_pixels(SH.render_png(frame, plain))
    assert inplace.getpixel((320, 150)) == (0, 0, 200) and inplace.getpixel((100, 75))[0] > 240


def test_zrzut_pamieta_kadr_post_patch_stare_wiersze_i_png_view(env):
    async def go():
        old = await new_shot(env)
        assert old["view"] is None  # bez pola = cała klatka
        framed = await new_shot(env, at=200, view={"cx": 0.25, "cy": 0.25, "zoom": 2})
        assert framed["view"] == {"cx": 0.25, "cy": 0.25, "zoom": 2}
        assert (await env.shots.get_shot(framed["id"], await env.actor(B)))["view"] == framed["view"]
        listed = await env.shots.list_shots(PAIR, match_id="m1", clip_id="", video_id="", category="", author="", q="", standalone=False,
                                            actor=await env.actor(A))
        assert {s["id"]: s["view"] for s in listed["shots"]}[framed["id"]] == framed["view"]
        flat = await new_shot(env, at=210, view={"cx": 0.5, "cy": 0.5, "zoom": 1})
        assert flat["view"] is None  # zoom <= 1 = null
        assert (await denied(new_shot(env, at=220, view={"cx": 2, "cy": 0.5, "zoom": 2})))[0] == 422
        await env.shots.upload_image(framed["id"], FakeRequest(quadrant_jpeg()), await env.actor(A))
        cut = png_pixels((await env.shots.download_png(framed["id"], False, True, await env.actor(A))).body)
        whole = png_pixels((await env.shots.download_png(framed["id"], False, True, await env.actor(A), view=False)).body)
        assert cut.getpixel((390, 10))[0] > 150 and whole.getpixel((390, 10))[2] > 150  # kadr tnie, view=false = cała klatka
        bare = png_pixels((await env.shots.download_png(framed["id"], False, False, await env.actor(A))).body)  # shapes=false też kadruje
        assert bare.getpixel((390, 10))[0] > 150
        patched = await env.shots.update_shot(framed["id"], env.shots.ShotPatch(view={"cx": 0.8, "cy": 0.5, "zoom": 3}), await env.actor(A))
        assert patched["view"] == {"cx": 0.8, "cy": 0.5, "zoom": 3}
        untouched = await env.shots.update_shot(framed["id"], env.shots.ShotPatch(title="x"), await env.actor(A))
        assert untouched["view"] == patched["view"]  # PATCH bez view nie rusza kadru
        assert (await env.shots.update_shot(framed["id"], env.shots.ShotPatch(view=None), await env.actor(A)))["view"] is None
        bad = env.shots.ShotPatch(view={"cx": 0.5, "cy": 0.5, "zoom": 9})
        assert (await denied(env.shots.update_shot(framed["id"], bad, await env.actor(A))))[0] == 422

    env.run(go)


# ─── Wątki przy zrzucie ──────────────────────────────────────────────────────


def test_watek_przy_zrzucie_przez_istniejacy_mechanizm(env):
    async def go():
        shot = await new_shot(env, at=110)
        L = env.library
        thread = await L.create_thread(PAIR, L.ThreadBody(target_kind="shot", target_id=shot["id"], kind="question", body="Czy to faul?"),
                                       await env.actor(MENTOR))
        assert thread["target_kind"] == "shot" and thread["match_id"] == "m1" and thread["shot"]["id"] == shot["id"] and thread["shot"]["at_s"] == 110.0
        assert thread["title"] is None
        await L.add_comment(thread["id"], L.CommentBody(body="Tak"), await env.actor(A))
        listed = await L.list_threads(PAIR, target_kind="shot", target_id=shot["id"], status="", actor=await env.actor(B))
        assert [t["id"] for t in listed["threads"]] == [thread["id"]]
        view = await env.shots.get_shot(shot["id"], await env.actor(A))
        assert view["threads"] == {"total": 1, "open": 1, "comments": 2}
        push = [p for p in env.sent if p.get("thread_id") == thread["id"]][0]
        assert push["extra"] == {"shotId": shot["id"]} and "zrzut=" in push["link"] and push["clip_id"] is None
        assert (await denied(L.create_thread(PAIR, L.ThreadBody(target_kind="shot", target_id="brak", body="x"), await env.actor(A))))[1] == "NOT_FOUND"
        room = await env.panel.match_room(PAIR, "m1", await env.actor(A))
        assert room["threads"][0]["shot"]["id"] == shot["id"]
        await env.shots.delete_shot(shot["id"], await env.actor(A))
        assert (await denied(L.create_thread(PAIR, L.ThreadBody(target_kind="shot", target_id=shot["id"], body="x"), await env.actor(A))))[1] == "NOT_FOUND"
        room = await env.panel.match_room(PAIR, "m1", await env.actor(A))
        assert room["threads"][0]["shot"]["deleted"] is True

    env.run(go)


# ─── Teczka ──────────────────────────────────────────────────────────────────


@pytest.fixture
def drive_env(env, monkeypatch):
    monkeypatch.setenv("MENTOR_DRIVE_ENABLED", "true")
    monkeypatch.delenv("MENTOR_DRIVE_TOKEN_KEY", raising=False)
    env.g = FakeGoogle()
    env.drive_google.set_api(env.g)
    monkeypatch.setattr(env.drive, "_secret", lambda: "test-secret")
    monkeypatch.setattr(env.drive, "_configured", lambda: True)
    monkeypatch.setattr(env.drive_google, "client_id", lambda: "cid")

    async def fake_push(pair_id, judge_id, title, body, kind):
        return None

    monkeypatch.setattr(env.drive, "send_push", fake_push)
    return env


def test_zapis_zrzutu_w_teczce_png_podfolder_dziennik_i_ponowienie(drive_env):
    env = drive_env

    async def go():
        actor, _ = await with_folder(env, A)
        shot = await new_shot(env, title="Faul", shapes=[ellipse(color="#ff0000", width=0.012)])
        no_image = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor)
        item = no_image["items"][0]
        assert no_image["accepted"] == 0 and item["status"] == "rejected" and item["reason"] == "SHOT_NO_IMAGE" and "YouTube" in item["hint"]
        await env.shots.upload_image(shot["id"], FakeRequest(jpeg(960, 540, (90, 90, 90))), actor)
        partner = await env.actor(B)
        out = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"], "brak"]), partner)
        assert out["accepted"] == 1 and [i["status"] for i in out["items"]] == ["queued", "rejected"] and out["items"][1]["reason"] == "NOT_FOUND"
        assert await env.drive.work_once("w1") is True
        row = await env.core.one(select(env.T["mentor_drive_files"]))
        assert row["state"] == "done" and row["variant"] == "shot" and row["clip_id"] == shot["id"] and row["author_judge_id"] == B
        assert row["name"].endswith(".png") and "Faul" in row["name"]
        conn = await env.drive.get_conn(PAIR)
        match_dir = env.g.folders[(conn["folder_id"], row["match_label"])]
        cat_dir = env.g.folders[(match_dir, row["category"])]  # ten sam układ podfolderów co klipy
        uploaded = env.g.files[row["drive_file_id"]]
        assert uploaded["parent"] == cat_dir
        png = png_pixels(uploaded["data"])
        assert png.size[0] == 960 and png.size[1] > 540  # pasek z meczem
        assert uploaded["data"][:8] == b"\x89PNG\r\n\x1a\n" and any(r > 200 and g < 80 and b < 80 for r, g, b in png.getdata())
        activity = await env.drive.drive_activity(PAIR, __import__("fastapi").Response(), 30, None, actor)
        kinds = [i["kind"] for i in activity["items"]]
        assert "shot_saved" in kinds and "clip_saved" not in kinds
        saved = next(i for i in activity["items"] if i["kind"] == "shot_saved")
        assert saved["details"]["shot_id"] == shot["id"] and saved["details"]["shot_title"] == "Faul" and saved["actor"]["judge_id"] == B
        tree = await env.drive.drive_tree(PAIR, __import__("fastapi").Response(), None, actor)
        assert tree["items"][0]["kind"] == "shot" and tree["items"][0]["shot_id"] == shot["id"] and tree["items"][0]["status"] == "saved"
        again = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor)
        assert again["items"][0]["status"] == "already_saved" and again["accepted"] == 0
        # plik skasowany na Dysku: kolejny zapis wykrywa to i zapisuje od nowa
        env.g.gone.add(row["drive_file_id"])
        await env.db.execute(env.T["mentor_drive_files"].update().values(verified_at=None))
        redo = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor)
        assert redo["items"][0]["status"] in ("requeued", "queued") and redo["accepted"] == 1

    env.run(go)


def test_teczka_zrzut_bez_polaczenia_w_przetwarzaniu_i_usuniety(drive_env):
    env = drive_env

    async def go():
        actor = await env.actor(A)
        shot = await new_shot(env)
        err = await denied(env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor))
        assert err == (409, "DRIVE_NOT_CONNECTED")
        actor, _ = await with_folder(env, A)
        await env.db.execute(env.T["mentor_shots"].update().values(image_status="processing", updated_at=datetime.now(timezone.utc)))
        out = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor)
        assert out["items"][0]["reason"] == "SHOT_IMAGE_PROCESSING" and out["items"][0]["hint"]
        await env.db.execute(env.T["mentor_shots"].update().values(image_status="failed", image_reason="FRAME_FAILED"))
        out = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor)
        assert out["items"][0]["reason"] == "SHOT_IMAGE_FAILED"
        await env.shots.delete_shot(shot["id"], actor)
        out = await env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), actor)
        assert out["items"][0]["reason"] == "NOT_FOUND"
        assert (await denied(env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), await env.actor(STRANGER))))[0] == 403
        assert (await denied(env.drive.save_shots(PAIR, env.drive.SaveShotsBody(shot_ids=[shot["id"]]), await env.actor(COMMITTEE))))[0] == 403

    env.run(go)


def test_najcienszy_obrys_przechodzi_walidacje():
    ok = SR.clean_shapes([ellipse(width=0.0015), ellipse(width=SR.MIN_WIDTH)])
    assert ok[0]["width"] == 0.0015 and ok[1]["width"] == SR.MIN_WIDTH
    with pytest.raises(Exception):
        SR.clean_shapes([ellipse(width=SR.MIN_WIDTH / 2)])
