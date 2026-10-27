"""Handball Bastion - kolejka klipów MP4 (etap 4, handoff 14.1 pkt 7-10): restart, lease, rewizje, usunięcie, timeout po POST,
waiting_for_auth, inne konto, retry R2 bez ponownego cięcia, wirtualny klip vs MP4. Atrapa connectora i magazynu, bez sieci."""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, Env

A, B = JUDGES
URL = "https://portal.handball-bastion.pl/game?bunny_item_id=5632"
OK_PROBE = {"format": "mov,mp4,m4a,3gp,3g2,mj2", "duration_s": 10.02, "has_video": True, "has_audio": True,
            "video_codec": "h264", "audio_codec": "aac", "width": 1280, "height": 720}


class FakeConnector:
    def __init__(self):
        self.creates = []
        self.state_calls = 0
        self.download_calls = 0
        self.create_mode = "ok"  # ok | 202 | down
        self.state_mode = "ok"  # ok | auth
        self.ready = True
        self.match = {"home": "SPR Gliwice", "away": "KS Opole", "zprp_match_id": "m1"}
        self.playback_params = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/playback":
            self.playback_params = dict(request.url.params)
            return httpx.Response(200, json={"code": "OK", "video_state": "READY", "match": self.match})
        if path == "/clips" and method == "POST":
            body = json.loads(request.content)
            self.creates.append(body)
            if self.create_mode == "down":
                raise httpx.ConnectError("down")
            if self.create_mode == "202":
                return httpx.Response(202, json={"state": "needs_reconciliation", "code": "BASTION_SUBMIT_NO_RESPONSE", "remote_id": None})
            return httpx.Response(200, json={"state": "submitted", "remote_id": "77", "clip_code": "ZZ9"})
        if path == "/clips/77" and method == "GET":
            self.state_calls += 1
            if self.state_mode == "auth":
                return httpx.Response(409, json={"error": "BASTION_AUTH_REQUIRED"})
            return httpx.Response(200, json={"ready": self.ready, "download_available": self.ready})
        if path == "/clips/77/download-url" and method == "POST":
            self.download_calls += 1
            return httpx.Response(200, json={"url": "https://vz.b-cdn.net/f.mp4?token=SEKRET", "host": "vz.b-cdn.net"})
        return httpx.Response(404, json={"error": "NOT_FOUND"})


@pytest.fixture
def q(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    monkeypatch.setenv("BASTION_ENABLED", "true")
    monkeypatch.setenv("BASTION_CONNECTOR_URL", "http://connector")
    monkeypatch.setenv("BASTION_CONNECTOR_TOKEN", "t" * 40)
    monkeypatch.setenv("BASTION_FAST_RETRY", "1")
    e.mp = monkeypatch
    e.fake = FakeConnector()
    e.client = e.bastion_client.ConnectorClient("http://connector", "t" * 40, transport=httpx.MockTransport(e.fake.handler),
                                                breaker=e.bastion_client.Breaker(threshold=99))
    monkeypatch.setattr(e.bastion_client, "get_client", lambda: e.client)
    e.store = {}  # klucz R2 -> rozmiar
    e.put_fail = 0
    e.on_download = None
    import app.mentor_bastion_media as BM

    async def fake_download(url, folder, **kw):
        assert "SEKRET" in url  # adres idzie tylko do pobierania
        if e.on_download:
            await e.on_download()
        path = f"{folder}/dl.mp4"
        with open(path, "wb") as f:
            f.write(b"\x00" * 4096)
        return BM.Downloaded(path, 4096, "ab" * 32, "video/mp4", "vz.b-cdn.net", 0)

    def fake_thumb(path, target, duration):
        with open(target, "wb") as f:
            f.write(b"jpg")
        return True

    monkeypatch.setattr(BM, "download_signed", fake_download)
    monkeypatch.setattr(BM, "ffprobe_file", lambda path, timeout_s=60.0: dict(OK_PROBE))
    monkeypatch.setattr(BM, "make_thumbnail", fake_thumb)

    def put(path, key, ctype):
        if e.put_fail > 0:
            e.put_fail -= 1
            raise OSError("R2 down")
        e.store[key] = 4096
        return 4096

    monkeypatch.setattr(e.bastion_jobs, "put_and_verify", put)
    monkeypatch.setattr(e.media, "storage_ready", lambda: True)
    monkeypatch.setattr(e.media, "storage_config", lambda: {"endpoint": "x", "region": "auto", "bucket": "b", "access_key": "k",
                                                            "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(e.media, "delete_objects", lambda keys: [e.store.pop(k, None) for k in keys if k] and None)
    monkeypatch.setattr(e.media, "forget_object", lambda *keys: [e.store.pop(k, None) for k in keys if k] and None)
    monkeypatch.setattr(e.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2/{key}?sig=1" if key else None)
    return e


async def seed(e, *, conn_status="ready", identity="u-1", clip=True, start=628.2, end=637.5):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_match_videos", id="vb", match_id="m1", pair_key="|".join(sorted(JUDGES)), url=URL, normalized_url=URL,
                provider="bastion", external_id="5632", added_by=A, created_at=now, duration_s=6795, kind="link")
    conn = await e.bastion._ensure_connection("personal", A)
    conn = await e.bastion._set_connection(conn, status=conn_status, external_identity_id=identity)
    if clip:
        await e.ins("mentor_clips", id="clip1", pair_id=PAIR, match_id="m1", video_id="vb", start_s=start, end_s=end,
                    author_id=A, category_ids="[]", source="manual", created_at=now, updated_at=now, mp4_status="none", media_rev=1)
    return conn


async def make_job(e, conn, **kw):
    row = {"id": "clip1", "pair_id": PAIR, "match_id": "m1", "video_id": "vb", "start_s": 628.2, "end_s": 637.5, "media_rev": 1}
    return await e.bastion_jobs.enqueue_clip_job(clip=row, bunny_item_id=5632, revision=1, requested_by=A, connection=conn, **kw)


async def job_of(e, rev=1):
    T = e.T["mentor_bastion_clip_jobs"]
    return await e.core.one(select(T).where(T.c.clip_id == "clip1").where(T.c.clip_revision == rev))


async def due(e):
    T = e.T["mentor_bastion_clip_jobs"]
    await e.core.database.execute(T.update().values(next_attempt_at=None, lease_until=None))


async def drive(e, worker="w1", rounds=8):
    """Kilka przebiegów workera aż do końca pracy (pomija oczekiwanie na backoff)."""
    for _ in range(rounds):
        await due(e)
        if not await e.bastion_jobs.run_once(worker, client=e.client):
            break


async def clip_of(e):
    T = e.T["mentor_clips"]
    return await e.core.one(select(T).where(T.c.id == "clip1"))


async def assets(e):
    return await e.core.rows(select(e.T["mentor_clip_assets"]))


# ─── Szczęśliwa ścieżka ─────────────────────────────────────────────────────


def test_zlecenie_gotowosc_pobranie_upload_i_ready(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        await drive(q)
        return await job_of(q), await clip_of(q), await assets(q)

    job, clip, found = q.run(go, seed=True)
    assert job["state"] == "ready" and job["remote_clip_id"] == "77" and job["asset_id"]
    body = q.fake.creates[0]
    assert len(q.fake.creates) == 1 and body["fingerprint"] == job["request_fingerprint"] and body["correlation"] == job["id"]
    assert (body["start_s"], body["end_s"]) == (628, 638) and body["scope"] == "personal" and body["judge_id"] == A
    assert clip["mp4_status"] == "ready" and clip["mp4_key"] == "mentor/" + PAIR + "/clips/clip1/r1.mp4"
    assert len(found) == 1 and found[0]["status"] == "ready" and found[0]["origin_provider"] == "bastion"
    assert found[0]["source_start_s"] == 628 and found[0]["source_end_s"] == 638 and found[0]["duration_s"] == 10.02
    assert set(q.store) == {clip["mp4_key"], clip["mp4_key"].replace(".mp4", ".jpg")}


def test_plik_jeszcze_niegotowy_czeka_z_backoffem_i_jitterem(q):
    async def go():
        conn = await seed(q)
        q.fake.ready = False
        await make_job(q, conn)
        await q.bastion_jobs.run_once("w1", client=q.client)
        return await job_of(q)

    job = q.run(go)
    assert job["state"] == "waiting_for_remote" and job["poll_count"] == 1 and job["next_attempt_at"] and job["lease_until"] is None
    assert q.fake.download_calls == 0 and not q.store


# ─── Restart i lease ────────────────────────────────────────────────────────


def test_restart_w_trakcie_pobierania_wznawia_bez_ponownego_ciecia(q):
    async def go():
        conn = await seed(q)
        job = await make_job(q, conn)
        T = q.T["mentor_bastion_clip_jobs"]
        # proces padł w trakcie pobierania: zdalne id zapisane, dzierżawa dawno wygasła, inny worker
        await q.core.database.execute(T.update().where(T.c.id == job["id"]).values(
            state="downloading", remote_clip_id="77", submitted_at=datetime.now(timezone.utc), worker_id="martwy",
            lease_until=datetime.now(timezone.utc) - timedelta(minutes=10)))
        await drive(q, "nowy")
        return await job_of(q)

    job = q.run(go)
    assert job["state"] == "ready" and q.fake.creates == []  # zero nowych zleceń cięcia


def test_lease_chroni_przed_rownoleglym_wykonaniem(q):
    async def go():
        conn = await seed(q)
        job = await make_job(q, conn)
        T = q.T["mentor_bastion_clip_jobs"]
        await q.core.database.execute(T.update().where(T.c.id == job["id"]).values(
            worker_id="inny", lease_until=datetime.now(timezone.utc) + timedelta(minutes=4)))
        busy = await q.bastion_jobs.run_once("w2", client=q.client)
        mid = await job_of(q)
        # dwa workery naraz: dokładnie jeden przejmuje
        await q.core.database.execute(T.update().where(T.c.id == job["id"]).values(worker_id=None, lease_until=None))
        got = await __import__("asyncio").gather(q.bastion_jobs.claim_next("a"), q.bastion_jobs.claim_next("b"))
        return busy, mid, got

    busy, mid, got = q.run(go)
    assert busy is False and mid["worker_id"] == "inny" and q.fake.creates == []
    assert sorted(bool(x) for x in got) == [False, True]


# ─── Rewizje i usunięcie ────────────────────────────────────────────────────


def test_zmiana_zakresu_podczas_pracy_starego_zadania_nie_nadpisuje_nowej_rewizji(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        T = q.T["mentor_clips"]

        async def bump():  # w trakcie pobierania użytkownik zmienia zakres: rewizja 2
            await q.core.database.execute(T.update().where(T.c.id == "clip1").values(media_rev=2, start_s=700.0, end_s=710.0))

        q.on_download = bump
        await drive(q)
        return await job_of(q), await clip_of(q), await assets(q)

    job, clip, found = q.run(go)
    assert job["state"] == "cancelled" and found == [] and clip["mp4_key"] is None and clip["mp4_status"] == "none"
    assert q.store == {}  # to, co zdążyło się wgrać, posprzątane


def test_usuniecie_klipu_w_trakcie_nie_przywraca_go_i_sprzata(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        T = q.T["mentor_clips"]

        async def delete():
            await q.core.database.execute(T.update().where(T.c.id == "clip1").values(deleted_at=datetime.now(timezone.utc)))

        q.on_download = delete
        await drive(q)
        return await job_of(q), await clip_of(q), await assets(q)

    job, clip, found = q.run(go)
    assert job["state"] == "cancelled" and found == [] and clip["deleted_at"] is not None and clip["mp4_key"] is None
    assert q.store == {}


def test_discard_kasuje_pliki_i_anuluje_zadania(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        await drive(q)
        await q.bastion_jobs.discard_clip_media("clip1")
        return await assets(q)

    assert q.run(go) == [] and q.store == {}


# ─── Niepewny wynik i awarie ────────────────────────────────────────────────


def test_timeout_po_post_to_needs_reconciliation_bez_ponawiania(q):
    async def go():
        conn = await seed(q)
        q.fake.create_mode = "202"
        await make_job(q, conn)
        await drive(q)
        first = await job_of(q)
        await drive(q)  # kolejne przebiegi nic nie wysyłają
        return first, await job_of(q)

    first, later = q.run(go)
    assert first["state"] == "needs_reconciliation" and later["state"] == "needs_reconciliation"
    assert len(q.fake.creates) == 1 and first["last_error_code"] == "NEEDS_RECONCILIATION"


def test_utrata_odpowiedzi_connectora_ponawia_ten_sam_odcisk(q):
    async def go():
        conn = await seed(q)
        q.fake.create_mode = "down"
        await make_job(q, conn)
        await q.bastion_jobs.run_once("w1", client=q.client)
        failed = await job_of(q)
        q.fake.create_mode = "ok"
        await drive(q)
        return failed, await job_of(q)

    failed, done = q.run(go)
    assert failed["state"] == "retryable_failed" and failed["attempts"] == 1 and failed["next_attempt_at"]
    assert done["state"] == "ready" and len(q.fake.creates) == 2
    assert q.fake.creates[0]["fingerprint"] == q.fake.creates[1]["fingerprint"]  # connector zwróci ten sam wynik z księgi


def test_blad_r2_nie_zleca_ciecia_drugi_raz(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        q.put_fail = 3  # wszystkie próby uploadu w jednym przebiegu
        await q.bastion_jobs.run_once("w1", client=q.client)
        failed = await job_of(q)
        await drive(q)
        return failed, await job_of(q)

    failed, done = q.run(go)
    assert failed["state"] == "retryable_failed" and failed["remote_clip_id"] == "77" and failed["last_error_code"] == "STORAGE_UPLOAD_FAILED"
    assert done["state"] == "ready" and len(q.fake.creates) == 1 and q.fake.download_calls == 2


# ─── Sesja i konto ──────────────────────────────────────────────────────────


def test_utrata_sesji_waiting_for_auth_i_wznowienie_tym_samym_kontem(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        q.fake.ready = False
        await drive(q, rounds=2)  # zlecone, czeka na plik
        q.fake.state_mode = "auth"
        await drive(q, rounds=2)
        held = await job_of(q)
        conn_after = await q.bastion.get_connection("personal-" + A)
        # to samo konto wraca: zadanie samo wraca do kolejki
        q.fake.state_mode, q.fake.ready = "ok", True
        conn_after = await q.bastion._set_connection(conn_after, status="ready", external_identity_id="u-1")
        await drive(q)
        return held, conn_after, await job_of(q)

    held, conn_mid, done = q.run(go)
    assert held["state"] == "waiting_for_auth" and held["remote_clip_id"] == "77"
    assert done["state"] == "ready" and len(q.fake.creates) == 1


def test_inne_konto_nie_wznawia_cudzego_zadania(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        q.fake.ready = False
        await drive(q, rounds=2)
        conn = await q.bastion.get_connection("personal-" + A)
        await q.bastion._set_connection(conn, status="reauth_required")
        await q.bastion._set_connection(await q.bastion.get_connection("personal-" + A), status="ready", external_identity_id="u-INNE")
        await drive(q)
        stuck = await job_of(q)
        _, _, actor = await actor_for(q, A)
        clip, video = await clip_of(q), await video_of(q)
        err = None
        try:
            await q.bastion_jobs.resume_clip_media(clip, video, actor)
        except HTTPException as exc:
            err = exc.detail["code"]
        return stuck, err

    stuck, err = q.run(go)
    assert stuck["state"] == "waiting_for_auth" and stuck["last_error_code"] == "BASTION_WRONG_ACCOUNT" and len(q.fake.creates) == 1
    assert err == "BASTION_WRONG_ACCOUNT"


async def video_of(e):
    T = e.T["mentor_match_videos"]
    return await e.core.one(select(T).where(T.c.id == "vb"))


async def actor_for(e, judge):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return r, await e.auth.base_actor(r), await e.auth.mentor_actor(r)


def test_cudze_konto_osobiste_nie_jest_pozyczane_przy_wznowieniu(q):
    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        q.fake.ready = False
        await drive(q, rounds=2)
        T = q.T["mentor_bastion_clip_jobs"]
        await q.core.database.execute(T.update().values(state="waiting_for_auth"))
        _, _, actor_b = await actor_for(q, B)
        try:
            await q.bastion_jobs.resume_clip_media(await clip_of(q), await video_of(q), actor_b)
        except HTTPException as exc:
            return exc.detail["code"]

    assert q.run(go) == "BASTION_CONNECTION_FORBIDDEN"


# ─── Wirtualny klip kontra MP4 (decyzja: MP4 tylko na wybór) ────────────────


def test_zapis_klipu_domyslnie_wirtualny_a_mp4_true_zaklada_zadanie(q):
    async def go():
        conn = await seed(q, clip=False)
        _, _, actor = await actor_for(q, A)
        body = q.library.ClipBody(match_id="m1", video_id="vb", start_s=628.2, end_s=637.5)
        virt = await q.library.create_clip(PAIR, body, actor)
        jobs_virtual = await q.core.rows(select(q.T["mentor_bastion_clip_jobs"]))
        body2 = q.library.ClipBody(match_id="m1", video_id="vb", start_s=700, end_s=720, mp4=True)
        mp4 = await q.library.create_clip(PAIR, body2, actor)
        jobs = await q.core.rows(select(q.T["mentor_bastion_clip_jobs"]))
        return virt, jobs_virtual, mp4, jobs

    virt, jobs_virtual, mp4, jobs = q.run(go)
    assert jobs_virtual == [] and virt["media"]["kind"] == "virtual" and virt["media"]["can_order_mp4"] is True
    assert virt["media"]["mode"] == "source_range" and virt["media"]["status"] == "virtual"
    offer = virt["mp4_offer"]
    assert offer["estimated_s"] == 90 and (offer["min_s"], offer["max_s"]) == (2, 300) and offer["eligible"] is True
    assert offer["connection"] == {"ok": True, "scope": "personal", "account_label": "Twoje konto"}
    assert len(jobs) == 1 and mp4["media"]["kind"] == "mp4" and mp4["media"]["stage"] == "saved" and mp4["media"]["job"]["state"] == "queued"
    assert (jobs[0]["start_s"], jobs[0]["end_s"]) == (700, 720)


def test_zamowienie_pozniej_jest_idempotentne_a_anulowanie_dziala_tylko_przed_wyslaniem(q):
    async def go():
        conn = await seed(q)
        _, _, actor = await actor_for(q, A)
        clip, video, ctx = await clip_of(q), await video_of(q), await q.core.pair_context(PAIR, actor)
        one = await q.bastion.order_mp4(ctx, clip, video, actor)
        two = await q.bastion.order_mp4(ctx, clip, video, actor)
        n = len(await q.core.rows(select(q.T["mentor_bastion_clip_jobs"])))
        cancel = await q.bastion_jobs.cancel_clip_media(clip)
        after = (await q.bastion_jobs.media_for_clips([clip]))["clip1"]
        again = await q.bastion.order_mp4(ctx, clip, video, actor)  # po anulowaniu można zamówić ponownie
        # po wysłaniu do Bastionu anulować się nie da
        q.fake.ready = False
        await drive(q, rounds=2)
        late = None
        try:
            await q.bastion_jobs.cancel_clip_media(clip)
        except HTTPException as exc:
            late = exc.detail["code"]
        return one, two, n, cancel, after, again, late

    one, two, n, cancel, after, again, late = q.run(go)
    assert one["media"]["job"]["state"] == "queued" and two["media"]["job"]["state"] == "queued" and n == 1
    assert cancel["cancelled"] is True and after["kind"] == "virtual" and after["can_order_mp4"] is True
    assert again["media"]["kind"] == "mp4" and late == "MP4_CANCEL_TOO_LATE"


def test_zmiana_zakresu_klipu_z_mp4_tworzy_nowa_rewizje_a_wirtualny_zostaje_wirtualny(q):
    async def go():
        conn = await seed(q, clip=False)
        _, _, actor = await actor_for(q, A)
        mp4 = await q.library.create_clip(PAIR, q.library.ClipBody(match_id="m1", video_id="vb", start_s=628, end_s=638, mp4=True), actor)
        virt = await q.library.create_clip(PAIR, q.library.ClipBody(match_id="m1", video_id="vb", start_s=100, end_s=110), actor)
        await drive(q)  # pierwszy klip gotowy (rewizja 1)
        r1 = await assets(q)
        await q.library.update_clip(mp4["id"], q.library.ClipPatch(end_s=645), actor)
        await q.library.update_clip(virt["id"], q.library.ClipPatch(end_s=115), actor)
        T = q.T["mentor_clips"]
        clips = {c["id"]: c for c in await q.core.rows(select(T))}
        jobs = await q.core.rows(select(q.T["mentor_bastion_clip_jobs"]))
        media = await q.bastion_jobs.media_for_clips(list(clips.values()))
        return mp4, virt, r1, clips, jobs, media

    mp4, virt, r1, clips, jobs, media = q.run(go)
    assert len(r1) == 1 and clips[mp4["id"]]["media_rev"] == 2 and clips[virt["id"]]["media_rev"] == 2
    revs = sorted((j["clip_id"], j["clip_revision"]) for j in jobs)
    assert revs == sorted([(mp4["id"], 1), (mp4["id"], 2)])  # wirtualny nie dostał zadania
    m = media[mp4["id"]]
    assert m["mode"] == "source_range" and m["kind"] == "mp4" and m["stage"] == "saved" and m["asset"] is None  # stary plik nie udaje nowego
    assert media[virt["id"]]["kind"] == "virtual"
    assert clips[mp4["id"]]["mp4_key"] is None  # stary klucz nie jest już plikiem tego zakresu


# ─── Resolver i czyste reguły ───────────────────────────────────────────────


def test_resolver_gotowy_plik_zakres_oryginalu_i_oczekiwanie():
    from app import mentor_bastion_rules as BR

    clip = {"id": "c", "video_id": "v", "start_s": 628.4, "end_s": 637.6, "media_rev": 2}
    asset = {"id": "a", "status": "ready", "revision": 2, "duration_s": 10.02, "source_start_s": 628.0, "source_end_s": 638.0,
             "poster_key": "p", "origin_provider": "bastion"}
    ready = BR.resolve_clip_playback(clip=clip, asset=asset, video_provider="bastion", eligible=True)
    assert ready["mode"] == "asset" and ready["status"] == "ready" and ready["kind"] == "mp4" and ready["file_offset_s"] == 0.4
    assert BR.file_time(ready, 631.4) == 3.4 and BR.file_time(ready, 900) == 10.02 and BR.file_time(ready, 100) == 0.0
    stale = BR.resolve_clip_playback(clip=clip, asset={**asset, "revision": 1}, video_provider="bastion", eligible=True)
    assert stale["mode"] == "source_range" and stale["asset"] is None  # stara rewizja nie jest plikiem nowego zakresu
    job = {"state": "waiting_for_remote", "remote_clip_id": "7", "attempts": 0}
    cutting = BR.resolve_clip_playback(clip=clip, job=job, video_provider="bastion", eligible=True)
    assert cutting["mode"] == "source_range" and cutting["stage"] == "bastion_cutting" and cutting["range"] == {"start_s": 628.4, "end_s": 637.6}
    gone = BR.resolve_clip_playback(clip=clip, video_provider="bastion", video_present=False)
    assert gone["mode"] == "waiting"
    long = BR.resolve_clip_playback(clip={**clip, "end_s": 1000}, video_provider="bastion", eligible=False)
    assert long["status"] == "not_exported" and long["can_order_mp4"] is False and "300" in long["message"]


def test_backoff_jitter_kontrola_pliku_i_porownanie_meczu():
    from app import mentor_bastion_rules as BR

    assert BR.backoff_s(1, rng=lambda: 0.5) == 15.0 and BR.backoff_s(3, rng=lambda: 0.5) == 60.0
    assert BR.backoff_s(20, rng=lambda: 1.0) <= BR.BACKOFF_CAP_S * 1.25 and BR.backoff_s(2, rng=lambda: 0) < BR.backoff_s(2, rng=lambda: 1)
    assert BR.verify_media(OK_PROBE, 5_000_000, 10) is None
    assert BR.verify_media({**OK_PROBE, "has_video": False}, 5_000_000, 10) == "BASTION_FILE_INVALID"
    assert BR.verify_media({**OK_PROBE, "format": "matroska"}, 5_000_000, 10) == "BASTION_FILE_INVALID"
    assert BR.verify_media(OK_PROBE, 500, 10) == "BASTION_FILE_INVALID"  # strona HTML zamiast filmu
    assert BR.verify_media(OK_PROBE, 5_000_000, 40) == "BASTION_FILE_MISMATCH"
    card = {"match_id": "m1", "match_code": "ISM/1", "home": {"name": "SPR Gliwice"}, "away": {"name": "KS Opole"}}
    assert BR.same_match({"zprp_match_id": "m1"}, card) is True and BR.same_match({"zprp_match_id": "m9"}, card) is False
    assert BR.same_match({"home": "ks opole", "away": "SPR  Gliwice"}, card) is True
    assert BR.same_match({"home": "A", "away": "B"}, card) is False and BR.same_match({}, card) is None
    assert BR.can_cancel_job({"state": "queued"}) and not BR.can_cancel_job({"state": "waiting_for_remote", "remote_clip_id": "1"})


def test_resolve_linku_podsumowanie_meczu_bez_embedu_i_porownanie_z_pokojem(q):
    async def go():
        await seed(q, clip=False)
        _, real, acting = await actor_for(q, A)
        from fastapi import Response

        body = q.bastion.ResolveBody(url=URL + "&at=12")
        same = await q.bastion.resolve_link(PAIR, "m1", body, Response(), real, acting)
        q.fake.match = {"home": "Inna", "away": "Druzyna"}
        other = await q.bastion.resolve_link(PAIR, "m1", body, Response(), real, acting)
        q.fake.match = {}
        unknown = await q.bastion.resolve_link(PAIR, "m1", body, Response(), real, acting)
        try:
            await q.bastion.resolve_link(PAIR, "m1", q.bastion.ResolveBody(url="https://evil.example/game?bunny_item_id=1"), Response(), real, acting)
        except HTTPException as exc:
            bad = exc.detail["code"]
        return same, other, unknown, bad

    same, other, unknown, bad = q.run(go)
    assert same["bunny_item_id"] == 5632 and same["same_match"] is True and same["match_summary"]["home"] == "SPR Gliwice"
    assert q.fake.playback_params["include_embed"] == "false" and "embed" not in str(same)
    assert other["same_match"] is False and unknown["same_match"] is None and unknown["match_summary"] is None
    assert bad == "BAD_BASTION_URL" and q.bastion.CAPABILITIES == {"seek": True, "rate": False, "mute": False}


# ─── Push „Klip gotowy” ─────────────────────────────────────────────────────


def test_gotowy_klip_wysyla_jeden_cichy_push_do_zamawiajacego(q):
    import app.push.push as P

    sent = []

    async def fake_push(ids, title, body, data, **kw):
        sent.append({"ids": list(ids), "title": title, "body": body, "data": dict(data), **kw})
        return {"sent": len(ids)}

    q.mp.setattr(P, "send_push_to_judges_report", fake_push)

    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        await drive(q)
        await drive(q)  # kolejne przebiegi nie dosyłają drugiego pushu
        return await job_of(q)

    job = q.run(go, seed=True)
    assert job["state"] == "ready"
    assert len(sent) == 1
    msg = sent[0]
    assert msg["ids"] == [A] and msg["title"] == "Klip gotowy" and "10,0 s" in msg["body"] and "720p" in msg["body"]
    d = msg["data"]
    assert d["kind"] == "mentor_panel" and d["target"] == "clip" and d["clipId"] == "clip1" and d["matchId"] == "m1"
    assert d["pairId"] == PAIR and d["notificationSilent"] == "1" and d["tag"] == "mentor-clip-clip1"
    assert msg["preference_key"] == "mentorPanel" and msg["app_variant"] == "baza"
    assert all(isinstance(v, str) for v in d.values())


def test_blad_pushu_nie_cofa_gotowego_klipu(q):
    import app.push.push as P

    async def broken(*a, **kw):
        raise RuntimeError("FCM down")

    q.mp.setattr(P, "send_push_to_judges_report", broken)

    async def go():
        conn = await seed(q)
        await make_job(q, conn)
        await drive(q)
        return await job_of(q), await clip_of(q)

    job, clip = q.run(go, seed=True)
    assert job["state"] == "ready" and clip["mp4_status"] == "ready"


def test_tekst_pushu_klipu_gotowego():
    from app.mentor_bastion_jobs import clip_ready_text

    assert clip_ready_text("Faul w ataku", 10.02, 720) == ("Klip gotowy", "„Faul w ataku” wywołał się: MP4 · 10,0 s · 720p. Gra z pliku BAZY, także w zwolnieniu.")
    assert clip_ready_text(None, None, None)[1].startswith("„Klip” wywołał się: MP4.")
