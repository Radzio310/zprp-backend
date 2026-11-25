"""Kosz pary (25.11.2026): klipy, zrzuty, zestawienia, filmy i nagrania wracają przez 30 dni; film zestawienia wie, że jest
nieaktualny, a nowy gotowy film odkłada starszy do kosza."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.mentor_panel_support import ADMIN, JUDGES, PAIR, Env

A, B = JUDGES


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.forgotten = []
    monkeypatch.setattr(e.media, "forget_object", lambda *keys: e.forgotten.extend(k for k in keys if k))
    monkeypatch.setattr(e.media, "delete_objects", lambda keys: e.forgotten.extend(k for k in keys if k))
    monkeypatch.setattr(e.media, "presign_get", lambda key, *a, **k: f"https://r2/{key}" if key else None)

    async def no_discard(clip_id):
        e.forgotten.append(f"jobs:{clip_id}")

    monkeypatch.setattr(e.bastion_jobs, "discard_clip_media", no_discard)
    return e


async def denied(coro):
    with pytest.raises(HTTPException) as caught:
        await coro
    d = caught.value.detail
    return caught.value.status_code, d.get("code") if isinstance(d, dict) else d


def now():
    return datetime.now(timezone.utc)


async def clip(env, cid, *, author=A, start=100.0, end=110.0, title="Faul"):
    await env.ins("mentor_clips", id=cid, pair_id=PAIR, match_id="m1", video_id="v1", start_s=start, end_s=end, title=title,
                  author_id=author, created_at=now(), updated_at=now(), mp4_status="ready", mp4_key=f"clips/{cid}.mp4")


async def compilation(env, comp_id, clip_ids, *, author=A):
    await env.ins("mentor_compilations", id=comp_id, pair_id=PAIR, name="Obszar kołowego", created_by=author, created_at=now(),
                  updated_at=now())
    for n, cid in enumerate(clip_ids):
        await env.ins("mentor_compilation_items", compilation_id=comp_id, clip_id=cid, position=n)


async def ready_film(env, mid, comp_id, clip_ids, *, content_sig=None, when=None):
    when = when or now()
    items = [{"clip_id": c, "label": "", "note": None} for c in clip_ids]
    await env.ins("mentor_montages", id=mid, pair_id=PAIR, compilation_id=comp_id, name="Obszar kołowego",
                  items_json=env.core.dumps(items), status="ready", film_key=f"montages/{mid}.mp4", poster_key=f"montages/{mid}.jpg",
                  duration_s=42.0, content_sig=content_sig, created_by=A, created_at=when, updated_at=when, ready_at=when,
                  expires_at=when + timedelta(days=30))


def kinds(payload):
    return sorted((i["kind"], i["id"]) for i in payload["items"])


# ─── Klip ───────────────────────────────────────────────────────────────────


def test_klip_do_kosza_wraca_z_plikiem_a_po_30_dniach_znika(env):
    async def go():
        await clip(env, "c1")
        await compilation(env, "k1", ["c1"])
        a, b = await env.actor(A), await env.actor(B)
        assert (await env.library.delete_clip("c1", a))["ok"] is True
        assert env.forgotten == []  # plik MP4 czeka w koszu
        ctx = await env.core.pair_context(PAIR, a)
        trash = await env.trash.trash_payload(ctx)
        item = trash["items"][0]
        assert kinds(trash) == [("clip", "c1")] and trash["days"] == 30
        assert item["title"] == "Faul" and item["can_restore"] is True and item["deleted_by"]["judge_id"] == A
        assert item["duration_s"] == 10.0 and item["match"]["match_code"] == "ISM/1"
        partner = await env.trash.trash_payload(await env.core.pair_context(PAIR, b))
        assert partner["items"][0]["can_restore"] is False  # partner widzi, ale nie przywraca cudzego klipu
        assert await denied(env.trash.restore_item(PAIR, "clip", "c1", b)) == (403, "FORBIDDEN")
        back = await env.trash.restore_item(PAIR, "clip", "c1", a)
        assert back["ok"] is True and back["match_id"] == "m1"
        comp = await env.library.compilation_payload(ctx, "k1")
        assert [i["clip"]["id"] for i in comp["items"]] == ["c1"]  # wraca też w zestawieniu
        assert (await env.trash.trash_payload(ctx))["items"] == []
        assert await denied(env.trash.restore_item(PAIR, "clip", "c1", a)) == (404, "NOT_IN_TRASH")
        # Ponownie do kosza i 31 dni później: sprzątanie kasuje plik i pozycję z kosza.
        await env.library.delete_clip("c1", a)
        await env.db.execute(env.T["mentor_clips"].update().where(env.T["mentor_clips"].c.id == "c1")
                             .values(deleted_at=now() - timedelta(days=31)))
        swept = await env.trash.purge_expired(now())
        assert swept == {"clip": 1} and "clips/c1.mp4" in env.forgotten and "jobs:c1" in env.forgotten
        assert (await env.trash.trash_payload(ctx))["items"] == []

    env.run(go)


def test_dawniej_usuniety_klip_nie_trafia_do_kosza(env):
    async def go():
        await env.ins("mentor_clips", id="old", pair_id=PAIR, match_id="m1", video_id="v1", start_s=1, end_s=2, author_id=A,
                      created_at=now(), updated_at=now(), deleted_at=now())  # bez `deleted_by`: plik skasowano dawną drogą
        ctx = await env.core.pair_context(PAIR, await env.actor(A))
        assert (await env.trash.trash_payload(ctx))["items"] == []

    env.run(go)


# ─── Zrzut ──────────────────────────────────────────────────────────────────


def test_zrzut_do_kosza_trzyma_obraz_a_usuniety_na_zawsze_go_kasuje(env):
    async def go():
        await env.ins("mentor_shots", id="s1", pair_id=PAIR, match_id="m1", video_id="v1", at_s=120.0, title="Zostawiona noga",
                      author_id=A, image_status="ready", image_key="shots/s1.png", thumb_key="shots/s1_t.jpg",
                      created_at=now(), updated_at=now())
        a = await env.actor(A)
        assert (await env.shots.delete_shot("s1", a)) == {"ok": True, "trashed": True}
        assert env.forgotten == []
        ctx = await env.core.pair_context(PAIR, a)
        item = (await env.trash.trash_payload(ctx))["items"][0]
        assert (item["kind"], item["title"], item["thumb_url"]) == ("shot", "Zostawiona noga", "https://r2/shots/s1_t.jpg")
        await env.trash.restore_item(PAIR, "shot", "s1", a)
        listed = await env.shots.list_shots(PAIR, "", "", "", "", "", "", False, a)
        assert [s["id"] for s in listed["shots"]] == ["s1"] and listed["shots"][0]["image_status"] == "ready"
        await env.shots.delete_shot("s1", a)
        assert (await env.trash.purge_item(PAIR, "shot", "s1", a)) == {"ok": True}
        assert set(env.forgotten) == {"shots/s1.png", "shots/s1_t.jpg"}
        assert await denied(env.trash.restore_item(PAIR, "shot", "s1", a)) == (404, "NOT_IN_TRASH")

    env.run(go)


# ─── Zestawienie ────────────────────────────────────────────────────────────


def test_zestawienie_do_kosza_z_pozycjami_i_publicznym_linkiem(env):
    async def go():
        await clip(env, "c1")
        await clip(env, "c2", start=200, end=205)
        await compilation(env, "k1", ["c1", "c2"])
        await env.db.execute(env.T["mentor_compilations"].update().where(env.T["mentor_compilations"].c.id == "k1")
                             .values(public_token="tok", published_at=now()))
        a = await env.actor(A)
        assert (await env.library.delete_compilation("k1", a))["trashed"] is True
        assert (await env.library.list_compilations(PAIR, a))["compilations"] == []
        assert await denied(env.library.get_compilation("k1", a)) == (404, "NOT_FOUND")
        ctx = await env.core.pair_context(PAIR, a)
        item = (await env.trash.trash_payload(ctx))["items"][0]
        assert (item["kind"], item["items_count"]) == ("compilation", 2)
        await env.trash.restore_item(PAIR, "compilation", "k1", a)
        comp = await env.library.get_compilation("k1", a)
        assert [i["clip"]["id"] for i in comp["items"]] == ["c1", "c2"]
        row = await env.core.one(select(env.T["mentor_compilations"]).where(env.T["mentor_compilations"].c.id == "k1"))
        assert row["public_token"] is None  # link trzeba udostępnić ponownie
        await env.library.delete_compilation("k1", a)
        await env.trash.purge_item(PAIR, "compilation", "k1", a)
        assert await env.core.one(select(env.T["mentor_compilations"]).where(env.T["mentor_compilations"].c.id == "k1")) is None
        assert await env.core.rows(select(env.T["mentor_compilation_items"])) == []

    env.run(go)


# ─── Film z montażu ─────────────────────────────────────────────────────────


def test_film_wie_ze_zestawienie_sie_zmienilo(env):
    MR = env.montage.MR

    async def go():
        for n, cid in enumerate(("c1", "c2", "c3")):
            await clip(env, cid, start=100 + 20 * n, end=110 + 20 * n)
        await compilation(env, "k1", ["c1", "c2"])
        clips = await env.montage._clips(PAIR, ["c1", "c2"])
        items = [{"clip_id": "c1", "label": "", "note": None}, {"clip_id": "c2", "label": "", "note": None}]
        await ready_film(env, "f1", "k1", ["c1", "c2"], content_sig=MR.content_sig(items, clips))
        films = await env.montage.films_for(["k1"])
        assert films["k1"]["id"] == "f1" and films["k1"]["stale"] is False and "update" not in films["k1"]
        # Doszedł klip: film nieaktualny.
        await env.ins("mentor_compilation_items", compilation_id="k1", clip_id="c3", position=2)
        assert (await env.montage.films_for(["k1"]))["k1"]["stale"] is True
        await env.db.execute(env.T["mentor_compilation_items"].delete().where(env.T["mentor_compilation_items"].c.clip_id == "c3"))
        assert (await env.montage.films_for(["k1"]))["k1"]["stale"] is False
        # Zmieniony zakres klipu też.
        await env.db.execute(env.T["mentor_clips"].update().where(env.T["mentor_clips"].c.id == "c2").values(end_s=125))
        assert (await env.montage.films_for(["k1"]))["k1"]["stale"] is True
        # Klip do kosza = zestawienie się zmieniło.
        await env.db.execute(env.T["mentor_clips"].update().where(env.T["mentor_clips"].c.id == "c2").values(end_s=130))
        await env.library.delete_clip("c2", await env.actor(A))
        assert (await env.montage.films_for(["k1"]))["k1"]["stale"] is True

    env.run(go)


def test_starszy_film_bez_odcisku_porownuje_pozycje(env):
    async def go():
        await clip(env, "c1")
        await clip(env, "c2", start=200, end=205)
        await compilation(env, "k1", ["c1"])
        await ready_film(env, "f1", "k1", ["c1"])
        assert (await env.montage.films_for(["k1"]))["k1"]["stale"] is False
        await env.ins("mentor_compilation_items", compilation_id="k1", clip_id="c2", position=1)
        assert (await env.montage.films_for(["k1"]))["k1"]["stale"] is True

    env.run(go)


def test_aktualizacja_w_drodze_a_stary_film_dalej_gra_i_potem_idzie_do_kosza(env):
    async def go():
        await clip(env, "c1")
        await compilation(env, "k1", ["c1"])
        old = now() - timedelta(hours=2)
        await ready_film(env, "f1", "k1", ["c1"], when=old)
        await env.ins("mentor_montages", id="f2", pair_id=PAIR, compilation_id="k1", name="Obszar kołowego", items_json="[]",
                      status="rendering", progress=0.4, created_by=A, created_at=now(), updated_at=now())
        films = await env.montage.films_for(["k1"])
        assert films["k1"]["id"] == "f1" and films["k1"]["update"]["id"] == "f2" and films["k1"]["update"]["status"] == "rendering"
        # Render skończony: nowy film zastępuje stary, stary leży w koszu z plikiem.
        moved = await env.montage._supersede({"id": "f2", "compilation_id": "k1", "created_by": A})
        assert moved == 1
        await env.db.execute(env.T["mentor_montages"].update().where(env.T["mentor_montages"].c.id == "f2").values(status="ready"))
        films = await env.montage.films_for(["k1"])
        assert films["k1"]["id"] == "f2" and "update" not in films["k1"]
        ctx = await env.core.pair_context(PAIR, await env.actor(A))
        item = (await env.trash.trash_payload(ctx))["items"][0]
        assert (item["kind"], item["id"], item["thumb_url"]) == ("montage", "f1", "https://r2/montages/f1.jpg")
        assert env.forgotten == []

    env.run(go)


def test_usuniecie_filmu_do_kosza_i_przywrocenie(env):
    async def go():
        await clip(env, "c1")
        await compilation(env, "k1", ["c1"])
        await ready_film(env, "f1", "k1", ["c1"])
        a = await env.actor(A)
        assert (await env.montage.delete_montage("f1", a)) == {"ok": True, "trashed": True}
        assert env.forgotten == [] and (await env.montage.films_for(["k1"])) == {}
        assert (await env.montage.list_montages(PAIR, None, 20, a))["montages"] == []
        assert await denied(env.montage.get_montage("f1", a)) == (404, "NOT_FOUND")
        await env.trash.restore_item(PAIR, "montage", "f1", a)
        assert (await env.montage.films_for(["k1"]))["k1"]["id"] == "f1"
        await env.montage.delete_montage("f1", a)
        await env.trash.purge_item(PAIR, "montage", "f1", a)
        assert set(env.forgotten) == {"montages/f1.mp4", "montages/f1.jpg"}
        ctx = await env.core.pair_context(PAIR, a)
        assert (await env.trash.trash_payload(ctx))["items"] == []

    env.run(go)


def test_film_w_drodze_jest_anulowany_a_nie_w_koszu(env):
    async def go():
        await env.ins("mentor_montages", id="f9", pair_id=PAIR, compilation_id=None, name="Szybki", items_json="[]", status="queued",
                      created_by=A, created_at=now(), updated_at=now())
        a = await env.actor(A)
        assert (await env.montage.delete_montage("f9", a)) == {"ok": True, "trashed": False}
        ctx = await env.core.pair_context(PAIR, a)
        assert (await env.trash.trash_payload(ctx))["items"] == []

    env.run(go)


# ─── Nagranie i trasy HTTP ──────────────────────────────────────────────────


def test_nagranie_z_kosza_meczu_widac_w_koszu_pary_i_wraca_przez_trasy(env, monkeypatch):
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
        h = {"authorization": f"Bearer {A}"}
        assert client.get(f"/mentor-panel/pairs/{PAIR}/trash").status_code == 401
        assert client.delete(f"/mentor-panel/pairs/{PAIR}/matches/m1/videos/v1", headers=h).json()["trashed"] is True
        listed = client.get(f"/mentor-panel/pairs/{PAIR}/trash", headers=h).json()
        assert [(i["kind"], i["id"]) for i in listed["items"]] == [("video", "v1")]
        assert listed["items"][0]["expires_at"]
        assert client.post(f"/mentor-panel/pairs/{PAIR}/trash/bogus/v1/restore", headers=h).status_code == 404
        back = client.post(f"/mentor-panel/pairs/{PAIR}/trash/video/v1/restore", headers=h)
        assert back.status_code == 200 and back.json()["match_id"] == "m1"
        assert client.get(f"/mentor-panel/pairs/{PAIR}/trash", headers=h).json()["items"] == []


def test_administrator_przywraca_cudze(env):
    async def go():
        await clip(env, "c1", author=B)
        await env.library.delete_clip("c1", await env.actor(B))
        back = await env.trash.restore_item(PAIR, "clip", "c1", await env.actor(ADMIN))
        assert back["ok"] is True

    env.run(go)
