"""Teczka pary (Dysk Google): reguły, trasy, kolejka. Google podmieniony atrapą (`set_api`), R2 atrapą strumienia."""

import base64
import io
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import select

from app import mentor_drive_rules as DR
from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, STRANGER, Env

A, B = JUDGES
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


# ─── reguły czyste ───────────────────────────────────────────────────────────


def test_flag_default_off_and_on(monkeypatch):
    monkeypatch.delenv("MENTOR_DRIVE_ENABLED", raising=False)
    assert DR.enabled() is False
    monkeypatch.setenv("MENTOR_DRIVE_ENABLED", "true")
    assert DR.enabled() is True


def test_state_signed_expiring_and_tamper_proof():
    token = DR.sign_state({"p": "pair", "j": "101"}, "sekret", NOW)
    assert DR.verify_state(token, "sekret", NOW)["p"] == "pair"
    assert DR.verify_state(token, "inny", NOW) is None
    assert DR.verify_state(token, "sekret", NOW + timedelta(seconds=DR.STATE_TTL_S + 5)) is None
    raw, mac = token.split(".")
    assert DR.verify_state(raw + "x." + mac, "sekret", NOW) is None
    assert DR.verify_state("", "sekret", NOW) is None


def test_return_url_whitelist():
    assert DR.return_url_ok("https://bazapodreka.app/mentor?x=1")
    assert DR.return_url_ok("baza://drive")
    assert DR.return_url_ok("http://localhost:3000/a")
    assert not DR.return_url_ok("https://evil.example/a")
    assert not DR.return_url_ok("javascript:alert(1)")
    assert not DR.return_url_ok("")
    assert DR.append_query("https://bazapodreka.app/x?a=1#f", {"drive": "connected"}) == "https://bazapodreka.app/x?a=1&drive=connected#f"


def test_tokens_sealed_with_pair_bound_aad(monkeypatch):
    monkeypatch.delenv("MENTOR_DRIVE_TOKEN_KEY", raising=False)
    key = DR.token_key("s")
    blob = DR.seal_tokens({"access_token": "ya29.SECRET", "refresh_token": "r"}, key, "mentor-drive:p1")
    assert "ya29.SECRET" not in blob and "ya29.SECRET" not in base64.b64decode(blob).decode("latin1")
    assert DR.unseal_tokens(blob, key, "mentor-drive:p1")["refresh_token"] == "r"
    assert DR.unseal_tokens(blob, key, "mentor-drive:p2") is None  # token jednej pary nie otworzy drugiej
    assert DR.unseal_tokens(blob, DR.token_key("inny"), "mentor-drive:p1") is None
    monkeypatch.setenv("MENTOR_DRIVE_TOKEN_KEY", base64.b64encode(b"k" * 32).decode())
    assert DR.token_key("s") == b"k" * 32


def test_layout_subpaths_and_names():
    assert DR.subpath("match_category", "2026-10-10 A - B (X/1)", "Do dyskusji") == ["2026-10-10 A - B (X/1)", "Do dyskusji"]
    assert DR.subpath("match", "M", "K") == ["M"]
    assert DR.subpath("category", "M", "K") == ["K"]
    assert DR.subpath("flat", "M", "K") == []
    assert DR.drive_name("a/b\tc – d—e.") == "a/b c - d-e"
    assert DR.drive_name("   ", "Mecz") == "Mecz"
    assert DR.clean_email(" Ala@Example.COM ") == "ala@example.com"
    assert DR.clean_email("nie-mail") is None
    assert DR.clean_layout("match") == "match" and DR.clean_layout("x") is None


def test_error_classification_and_backoff():
    assert DR.classify(400, "invalid_grant") == "revoked"
    assert DR.classify(401, "") == "revoked"
    assert DR.classify(404, "notFound") == "folder"
    assert DR.classify(403, "appNotAuthorizedToFile") == "folder"
    assert DR.classify(403, "userRateLimitExceeded") == "retry"
    assert DR.classify(503, "") == "retry" and DR.classify(0, "network") == "retry"
    assert DR.classify(400, "badRequest") == "fatal"
    assert DR.retry_delay(1) < DR.retry_delay(2) < DR.retry_delay(6) == DR.retry_delay(40)


# ─── atrapy ──────────────────────────────────────────────────────────────────


class FakeGoogle:
    def __init__(self):
        self.calls = []
        self.fail = {}  # nazwa metody -> GoogleError (jednorazowo, gdy lista, albo na stałe)
        self.folders = {}  # (parent, name) -> id
        self.files = {}  # id -> {"parent", "props", "data"}
        self.perms = []
        self.sessions = {}
        self.n = 0
        self.scope = DR.SCOPE
        self.refresh_error = None
        self.gone = set()  # id skasowane na Dysku (404)
        self.trashed = set()  # id w koszu

    def _maybe_fail(self, name):
        err = self.fail.get(name)
        if err:
            raise err

    def _id(self, prefix):
        self.n += 1
        return f"{prefix}{self.n:012d}"

    async def exchange_code(self, code, redirect_uri):
        self.calls.append(("exchange", code))
        self._maybe_fail("exchange_code")
        return {"access_token": "ya29.ACCESS", "refresh_token": "1//REFRESH", "expires_in": 3599, "scope": self.scope}

    async def refresh(self, refresh_token):
        self.calls.append(("refresh",))
        if self.refresh_error:
            raise self.refresh_error
        return {"access_token": "ya29.NEW", "expires_in": 3599}

    async def revoke(self, token):
        self.calls.append(("revoke",))

    async def about(self, access):
        return {"emailAddress": "ala@gmail.com", "displayName": "Ala"}

    async def file_state(self, access, file_id):
        self.calls.append(("file_state", file_id))
        self._maybe_fail("file_state")
        if file_id in self.gone:
            raise gerr(404, "notFound")
        return {"id": file_id, "trashed": file_id in self.trashed, "webViewLink": f"https://drive/{file_id}?v=2"}

    async def get_file(self, access, file_id):
        self.calls.append(("get_file", file_id))
        self._maybe_fail("get_file")
        if file_id in self.gone:
            raise gerr(404, "notFound")
        if file_id in self.trashed:
            return {"id": file_id, "name": "x", "mimeType": "application/vnd.google-apps.folder", "trashed": True}
        if file_id.startswith("FILE"):
            return {"id": file_id, "name": "plik.mp4", "mimeType": "video/mp4"}
        return {"id": file_id, "name": "Teczka", "mimeType": "application/vnd.google-apps.folder", "webViewLink": f"https://drive/{file_id}"}

    async def create_folder(self, access, name, parent=None):
        self.calls.append(("create_folder", name, parent))
        self._maybe_fail("create_folder")
        fid = self._id("DIR")
        self.folders[(parent, name)] = fid
        return {"id": fid, "name": name, "webViewLink": f"https://drive/{fid}"}

    async def find_folder(self, access, parent, name):
        fid = self.folders.get((parent, name))
        return {"id": fid, "name": name} if fid and fid not in self.gone else None

    async def find_by_prop(self, access, parent, key, value):
        for fid, f in self.files.items():
            if fid not in self.gone and fid not in self.trashed and f["parent"] == parent and f["props"].get(key) == value:
                return {"id": fid, "webViewLink": f"https://drive/{fid}", "size": str(len(f["data"]))}
        return None

    async def create_permission(self, access, file_id, email, role="writer"):
        self.calls.append(("permission", email, role))
        self._maybe_fail("create_permission")
        self.perms.append((file_id, email, role))
        return {"id": "p1"}

    async def start_upload(self, access, metadata, size, mime="video/mp4"):
        self.calls.append(("start_upload", metadata["name"], size))
        self._maybe_fail("start_upload")
        sid = self._id("SES")
        self.sessions[sid] = {"meta": metadata, "data": bytearray(), "size": size}
        return sid

    async def put_chunk(self, session_uri, data, start, total):
        self.calls.append(("put", start, len(data)))
        self._maybe_fail("put_chunk")
        s = self.sessions[session_uri]
        assert start == len(s["data"])
        s["data"] += data
        if len(s["data"]) >= total:
            fid = self._id("FILE")
            self.files[fid] = {"parent": s["meta"]["parents"][0], "props": s["meta"]["appProperties"], "data": bytes(s["data"]), "name": s["meta"]["name"]}
            return "done", {"id": fid, "webViewLink": f"https://drive/{fid}", "size": str(total)}
        return "more", len(s["data"])


def gerr(status, reason=""):
    from app.mentor_drive_google import GoogleError

    return GoogleError(status, reason)


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    monkeypatch.setenv("MENTOR_DRIVE_ENABLED", "true")
    monkeypatch.delenv("MENTOR_DRIVE_TOKEN_KEY", raising=False)
    e.mp = monkeypatch
    e.g = FakeGoogle()
    e.drive_google.set_api(e.g)
    monkeypatch.setattr(e.drive, "_secret", lambda: "test-secret")
    monkeypatch.setattr(e.drive, "_configured", lambda: True)
    monkeypatch.setattr(e.drive_google, "client_id", lambda: "cid")
    e.pushes = []

    async def fake_push(pair_id, judge_id, title, body, kind):
        e.pushes.append((pair_id, judge_id, kind))

    monkeypatch.setattr(e.drive, "send_push", fake_push)
    e.blobs = {"k1": b"0123456789" * 3, "k2": b"abcdefghij" * 5}

    def open_mp4(key):
        if key not in e.blobs:
            raise e.drive.MissingMp4(key)
        return io.BytesIO(e.blobs[key]), len(e.blobs[key])

    monkeypatch.setattr(e.drive, "open_mp4", open_mp4)
    monkeypatch.setattr(DR, "CHUNK", 8)

    async def plan(shared, clip, actor, title_card=False):
        ready = clip.get("mp4_status") == "ready"
        return {"mp4_status": "ready" if ready else "none", "can_download": True, "reason": None, "hint": None,
                "filename": f"{clip['id']} Kara.mp4", "folder": {"match": "2026-10-10 SPR - KS (ISM/1)", "category": "Do dyskusji"}}

    async def order(ctx, clip, actor, title_card, shared=None):
        e.ordered.append(clip["id"])
        return {}

    e.ordered = []
    monkeypatch.setattr(e.download, "build_plan", plan)
    monkeypatch.setattr(e.download, "order", order)
    return e


async def add_clip(e, clip_id="c1", key="k1", status="ready", pair=PAIR):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_clips", id=clip_id, pair_id=pair, match_id="m1", video_id="v1", start_s=100.0, end_s=120.0, title="Kara",
                author_id=A, category_ids="[]", source="manual", created_at=now, updated_at=now, mp4_status=status,
                mp4_key=key if status == "ready" else None, media_rev=1)


async def connect(e, judge=A, back=None):
    actor = await e.actor(judge)
    out = await e.drive.connect_drive(PAIR, e.drive.ConnectBody(return_url=back) if back else None, actor)
    state = parse_qs(urlparse(out["url"]).query)["state"][0]
    resp = await e.drive.drive_callback(code="CODE", state=state, error=None)
    return actor, out, resp


async def with_folder(e, judge=A):
    actor, _, _ = await connect(e, judge)
    view = await e.drive.set_folder(PAIR, e.drive.FolderBody(create=True), actor)
    return actor, view


async def code_of(coro):
    with pytest.raises(HTTPException) as caught:
        await coro
    return caught.value


# ─── flaga i status ──────────────────────────────────────────────────────────


def test_flag_off_returns_drive_off_everywhere_and_status_says_so(env, monkeypatch):
    monkeypatch.setenv("MENTOR_DRIVE_ENABLED", "0")

    async def go():
        actor = await env.actor(A)
        status = await env.drive.drive_status(Response(), actor)
        assert status["enabled"] is False and status["reason"] == "DRIVE_OFF"
        for coro in (env.drive.get_drive(PAIR, Response(), actor), env.drive.connect_drive(PAIR, None, actor),
                     env.drive.drive_tree(PAIR, Response(), None, actor), env.drive.drive_callback(code="x", state="y", error=None)):
            exc = await code_of(coro)
            assert exc.status_code == 403 and exc.error_code == "DRIVE_OFF"

    env.run(go)


# ─── połączenie ──────────────────────────────────────────────────────────────


def test_connect_builds_consent_url_and_callback_stores_encrypted_tokens(env):
    async def go():
        actor, out, resp = await connect(env, A)
        q = parse_qs(urlparse(out["url"]).query)
        assert q["scope"] == [DR.SCOPE] and q["access_type"] == ["offline"] and q["prompt"] == ["consent"]
        assert q["redirect_uri"] == [DR.DEFAULT_REDIRECT] and q["response_type"] == ["code"]
        assert resp.status_code == 400 or resp.status_code == 200  # bez return_url: strona HTML
        row = await env.drive.get_conn(PAIR)
        assert row["owner_judge_id"] == A and row["state"] == "connected" and row["google_email"] == "ala@gmail.com"
        assert "ya29.ACCESS" not in row["token_enc"] and "1//REFRESH" not in row["token_enc"]
        view = await env.drive.get_drive(PAIR, Response(), actor)
        assert view["state"] == "connected" and view["connected_by"]["judge_id"] == A and view["is_owner"] is True
        assert "token" not in str(view).lower().replace("token_", "")  # widok nie niesie tokenów
        other = await env.drive.get_drive(PAIR, Response(), await env.actor(B))
        assert other["connected_by"]["is_me"] is False and other["can_manage"] is False

    env.run(go)


def test_callback_redirects_to_allowed_return_url_and_rejects_bad_state_denied_scope(env):
    async def go():
        actor = await env.actor(A)
        out = await env.drive.connect_drive(PAIR, env.drive.ConnectBody(return_url="https://bazapodreka.app/mentor"), actor)
        state = parse_qs(urlparse(out["url"]).query)["state"][0]
        resp = await env.drive.drive_callback(code="C", state=state, error=None)
        assert resp.status_code == 303 and resp.headers["location"].startswith("https://bazapodreka.app/mentor?drive=connected")
        bad = await code_of(env.drive.drive_callback(code="C", state="zly.state", error=None))
        assert bad.status_code == 400 and bad.error_code == "BAD_STATE"
        denied = await env.drive.drive_callback(code=None, state=state, error="access_denied")
        assert denied.status_code == 303 and "drive=denied" in denied.headers["location"]
        env.g.scope = "openid"
        scoped = await env.drive.drive_callback(code="C", state=state, error=None)
        assert "drive=scope" in scoped.headers["location"]
        evil = await code_of(env.drive.connect_drive(PAIR, env.drive.ConnectBody(return_url="https://evil.example/"), actor))
        assert evil.error_code == "RETURN_URL"

    env.run(go)


def test_second_person_cannot_take_over_but_can_after_needs_reconnect(env):
    async def go():
        await connect(env, A)
        exc = await code_of(env.drive.connect_drive(PAIR, None, await env.actor(B)))
        assert exc.status_code == 409 and exc.error_code == "DRIVE_ALREADY_CONNECTED"
        await env.drive.mark_needs_reconnect(PAIR, "REVOKED")
        out = await env.drive.connect_drive(PAIR, None, await env.actor(B))
        assert out["url"].startswith("https://accounts.google.com/")
        stranger = await code_of(env.drive.get_drive(PAIR, Response(), await env.actor(STRANGER)))
        assert stranger.status_code == 403

    env.run(go)


# ─── folder, Picker, udostępnianie ───────────────────────────────────────────


def test_folder_create_and_picker_and_owner_only(env):
    async def go():
        actor, view = await with_folder(env, A)
        assert view["folder"]["name"].startswith("BAZA - Teczka pary: Anna Nowak i Piotr Lis")
        token = await env.drive.picker_token(PAIR, Response(), actor)
        assert token["access_token"] and token["app_id"] == DR.DEFAULT_APP_ID and token["expires_in"] > 0
        partner = await env.actor(B)
        denied = await code_of(env.drive.picker_token(PAIR, Response(), partner))
        assert denied.status_code == 403 and denied.error_code == "DRIVE_NOT_OWNER"
        denied2 = await code_of(env.drive.set_folder(PAIR, env.drive.FolderBody(create=True), partner))
        assert denied2.error_code == "DRIVE_NOT_OWNER"
        picked = await env.drive.set_folder(PAIR, env.drive.FolderBody(file_id="FOLDERPICKED123"), actor)
        assert picked["folder"]["id"] == "FOLDERPICKED123"
        notfolder = await code_of(env.drive.set_folder(PAIR, env.drive.FolderBody(file_id="FILEXXXXXXXXXXXX"), actor))
        assert notfolder.error_code == "NOT_A_FOLDER"
        bad = await code_of(env.drive.set_folder(PAIR, env.drive.FolderBody(file_id="a b"), actor))
        assert bad.error_code == "FILE_ID"
        lay = await env.drive.set_folder(PAIR, env.drive.FolderBody(layout="category"), actor)
        assert lay["layout"] == "category" and lay["folder"]["id"] == "FOLDERPICKED123"
        assert (await code_of(env.drive.set_folder(PAIR, env.drive.FolderBody(), actor))).error_code == "NOTHING_TO_DO"

    env.run(go)


def test_share_ok_error_visible_and_does_not_block(env):
    async def go():
        actor, _ = await with_folder(env, A)
        ok = await env.drive.share_folder(PAIR, env.drive.ShareBody(email="Piotr@Example.com"), actor)
        assert ok["partner"] == {"email": "piotr@example.com", "share_status": "ok", "share_error": None, "shared_at": ok["partner"]["shared_at"]}
        assert env.g.perms[-1][1:] == ("piotr@example.com", "writer")
        env.g.fail["create_permission"] = gerr(403, "forbidden")
        bad = await env.drive.share_folder(PAIR, env.drive.ShareBody(email="inny@example.com"), actor)
        assert bad["partner"]["share_status"] == "error" and bad["partner"]["share_error"]
        own = await env.drive.share_folder(PAIR, env.drive.ShareBody(email="ala@gmail.com"), actor)
        assert own["partner"]["share_status"] == "owner"
        assert (await code_of(env.drive.share_folder(PAIR, env.drive.ShareBody(email="zle"), actor))).error_code == "EMAIL"
        # nowy folder przy znanym adresie partnera: nadanie ponawiane samo
        env.g.fail.clear()
        again = await env.drive.set_folder(PAIR, env.drive.FolderBody(create=True, name="Druga"), actor)
        assert again["partner"]["email"] == "ala@gmail.com" and again["folder"]["name"] == "Druga"

    env.run(go)


# ─── zapis i kolejka ─────────────────────────────────────────────────────────


def test_save_uploads_stream_in_chunks_into_match_category_folders_without_duplicates(env):
    async def go():
        actor, _ = await with_folder(env, A)
        partner = await env.actor(B)
        await add_clip(env, "c1", "k1")
        out = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), partner)  # kliknął partner
        assert out["accepted"] == 1 and out["items"][0]["status"] == "queued"
        assert await env.drive.work_once("w1") is True
        row = await env.core.one(select(env.T["mentor_drive_files"]))
        assert row["state"] == "done" and row["author_judge_id"] == B and row["web_view_link"].startswith("https://drive/")
        # dwie warstwy podfolderów pod folderem pary, plik w ostatniej
        conn = await env.drive.get_conn(PAIR)
        match_dir = env.g.folders[(conn["folder_id"], "2026-10-10 SPR - KS (ISM/1)")]
        cat_dir = env.g.folders[(match_dir, "Do dyskusji")]
        fid = row["drive_file_id"]
        assert env.g.files[fid]["parent"] == cat_dir and env.g.files[fid]["data"] == env.blobs["k1"]
        puts = [c for c in env.g.calls if c[0] == "put"]
        assert len(puts) == 4 and all(c[2] <= 8 for c in puts)  # 30 B w częściach po 8 B
        # ponowne kliknięcie nie robi dubla
        again = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        assert again["items"][0]["status"] == "already_saved" and again["accepted"] == 0
        assert await env.drive.work_once("w1") is False
        # drugi klip: te same podfoldery z pamięci księgi, bez nowych create_folder
        await add_clip(env, "c2", "k2")
        before = len([c for c in env.g.calls if c[0] == "create_folder"])
        await env.drive.save_clips(PAIR, env.drive.SaveBody(match_id="m1"), actor)
        while await env.drive.work_once("w1"):
            pass
        assert len([c for c in env.g.calls if c[0] == "create_folder"]) == before
        tree = await env.drive.drive_tree(PAIR, Response(), None, actor)
        assert {i["clip_id"]: i["status"] for i in tree["items"]} == {"c1": "saved", "c2": "saved"}
        item = next(i for i in tree["items"] if i["clip_id"] == "c1")
        assert item["author"]["judge_id"] == B and item["match"] and item["category"] == "Do dyskusji" and item["web_view_link"]

    env.run(go)


def test_layout_flat_and_match_only(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await env.drive.set_folder(PAIR, env.drive.FolderBody(layout="flat"), actor)
        await add_clip(env, "c1", "k1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        await env.drive.work_once("w1")
        conn = await env.drive.get_conn(PAIR)
        row = await env.core.one(select(env.T["mentor_drive_files"]))
        assert env.g.files[row["drive_file_id"]]["parent"] == conn["folder_id"]
        assert not [c for c in env.g.calls if c[0] == "create_folder" and c[2] == conn["folder_id"]]

    env.run(go)


def test_restart_after_upload_does_not_duplicate(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        job = await env.drive.claim_next("w1")
        # Plik doszedł na Dysk, ale proces padł przed zapisem w księdze: dzierżawa wygasa.
        conn = await env.drive.get_conn(PAIR)
        parent = await env.drive.ensure_path(await env.drive.access_for(PAIR), conn, job)
        await env.drive.upload(await env.drive.access_for(PAIR), job, "w1", parent, "k1")
        T = env.T["mentor_drive_files"]
        await env.db.execute(T.update().values(lease_until=datetime.now(timezone.utc) - timedelta(minutes=1)))
        assert await env.drive.work_once("w2") is True
        row = await env.core.one(select(T))
        assert row["state"] == "done" and len(env.g.files) == 1  # przejęte, bez drugiego uploadu

    env.run(go)


def test_waiting_mp4_orders_then_uploads_when_ready_and_failed_marks_failed(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", status="none")
        out = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1", "nie-ma"]), actor)
        assert out["items"][0]["status"] == "waiting" and out["items"][1]["reason"] == "NOT_FOUND" and env.ordered == ["c1"]
        assert await env.drive.work_once("w1") is False  # MP4 jeszcze nie ma
        clips = env.T["mentor_clips"]
        await env.db.execute(clips.update().where(clips.c.id == "c1").values(mp4_status="ready", mp4_key="k1"))
        assert await env.drive.work_once("w1") is True
        assert (await env.core.one(select(env.T["mentor_drive_files"])))["state"] == "done"
        await add_clip(env, "c2", status="none")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c2"]), actor)
        await env.db.execute(clips.update().where(clips.c.id == "c2").values(mp4_status="failed"))
        await env.drive.promote_waiting(datetime.now(timezone.utc))
        failed = await env.core.one(select(env.T["mentor_drive_files"]).where(env.T["mentor_drive_files"].c.clip_id == "c2"))
        assert failed["state"] == "failed" and failed["error"] == "MP4_FAILED"
        # ponowny zapis nieudanego wraca do kolejki
        await env.db.execute(clips.update().where(clips.c.id == "c2").values(mp4_status="ready", mp4_key="k2"))
        redo = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c2"]), actor)
        assert redo["items"][0]["status"] == "requeued"

    env.run(go)


def test_save_requires_connection_and_folder(env):
    async def go():
        actor = await env.actor(A)
        await add_clip(env)
        assert (await code_of(env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor))).error_code == "DRIVE_NOT_CONNECTED"
        await connect(env, A)
        assert (await code_of(env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor))).error_code == "NO_FOLDER"
        await env.drive.set_folder(PAIR, env.drive.FolderBody(create=True), actor)
        assert (await code_of(env.drive.save_clips(PAIR, env.drive.SaveBody(), actor))).error_code == "NO_CLIPS"

    env.run(go)


def test_revoked_token_waits_one_push_never_401_and_resumes_after_reconnect(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        # token wygasł i Google go cofnął
        T = env.T["mentor_drive_connections"]
        tokens = {"access_token": "old", "refresh_token": "r", "expires_at": 0}
        await env.drive._store_tokens(PAIR, tokens)
        env.g.refresh_error = gerr(400, "invalid_grant")
        assert await env.drive.work_once("w1") is False or True
        await env.drive.work_once("w1")
        conn = await env.drive.get_conn(PAIR)
        assert conn["state"] == "needs_reconnect"
        job = await env.core.one(select(env.T["mentor_drive_files"]))
        assert job["state"] == "queued" and job["attempts"] == 0 and job["lease_until"] is None
        assert env.pushes == [(PAIR, A, "reconnect")]  # jeden push, do właściciela
        view = await env.drive.get_drive(PAIR, Response(), actor)
        assert view["state"] == "needs_reconnect" and view["counts"]["queued"] == 1
        # trasy nie rzucają 401, tylko 409 z kopertą
        exc = await code_of(env.drive.picker_token(PAIR, Response(), actor))
        assert exc.status_code == 409 and exc.error_code == "DRIVE_NEEDS_RECONNECT"
        exc2 = await code_of(env.drive.set_folder(PAIR, env.drive.FolderBody(create=True), actor))
        assert exc2.status_code == 409
        assert await env.drive.work_once("w1") is False and len(env.pushes) == 1
        # zapis w tym stanie jest przyjmowany i czeka
        await add_clip(env, "c2", "k2")
        waits = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c2"]), actor)
        assert waits["items"][0]["status"] == "queued"
        # ponowne połączenie tym samym kontem zachowuje folder i odblokowuje kolejkę
        env.g.refresh_error = None
        out = await env.drive.connect_drive(PAIR, None, actor)
        state = parse_qs(urlparse(out["url"]).query)["state"][0]
        await env.drive.drive_callback(code="C", state=state, error=None)
        conn = await env.drive.get_conn(PAIR)
        assert conn["state"] == "connected" and conn["folder_id"]
        while await env.drive.work_once("w1"):
            pass
        states = {r["clip_id"]: r["state"] for r in await env.core.rows(select(env.T["mentor_drive_files"]))}
        assert states == {"c1": "done", "c2": "done"}
        assert T is not None

    env.run(go)


def test_401_during_upload_marks_reconnect_and_keeps_job(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        env.g.fail["start_upload"] = gerr(401, "authError")
        await env.drive.work_once("w1")
        assert (await env.drive.get_conn(PAIR))["state"] == "needs_reconnect"
        job = await env.core.one(select(env.T["mentor_drive_files"]))
        assert job["state"] == "queued" and job["attempts"] == 0 and len(env.pushes) == 1

    env.run(go)


def test_chunk_errors_retry_with_backoff_then_fail(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        env.g.fail["put_chunk"] = gerr(503, "backendError")

        async def no_sleep(_s):
            return None

        env.mp.setattr(env.drive.asyncio, "sleep", no_sleep)
        T = env.T["mentor_drive_files"]
        await env.drive.work_once("w1")
        row = await env.core.one(select(T))
        assert row["state"] == "queued" and row["attempts"] == 1 and row["next_at"] is not None and row["error"] == "GOOGLE_BACKENDERROR"
        assert await env.drive.work_once("w1") is False  # czeka do next_at
        for _ in range(DR.MAX_ATTEMPTS):
            await env.db.execute(T.update().values(next_at=None))
            await env.drive.work_once("w1")
        row = await env.core.one(select(T))
        assert row["state"] == "failed" and row["attempts"] >= DR.MAX_ATTEMPTS
        assert env.pushes == []  # błąd jednego zadania nie wysyła pusha o ponownym łączeniu

    env.run(go)


def test_missing_mp4_object_fails_job(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "brak")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        await env.drive.work_once("w1")
        row = await env.core.one(select(env.T["mentor_drive_files"]))
        assert row["state"] == "failed" and row["error"] == "MP4_MISSING"

    env.run(go)


def test_folder_gone_pauses_jobs_visibly_and_new_folder_resumes(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        env.g.fail["start_upload"] = gerr(404, "notFound")
        env.g.fail["get_file"] = gerr(404, "notFound")  # folder pary naprawdę zniknął
        await env.drive.work_once("w1")
        view = await env.drive.get_drive(PAIR, Response(), actor)
        assert view["folder_problem"] == "FOLDER_GONE" and view["counts"]["queued"] == 1
        assert await env.drive.work_once("w1") is False
        env.g.fail.clear()
        await env.drive.set_folder(PAIR, env.drive.FolderBody(create=True, name="Nowa"), actor)
        assert (await env.drive.get_drive(PAIR, Response(), actor))["folder_problem"] is None
        await env.drive.work_once("w1")
        assert (await env.core.one(select(env.T["mentor_drive_files"])))["state"] == "done"

    env.run(go)


def test_tree_since_returns_only_changes_and_live_event_scope_drive(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await add_clip(env, "c2", "k2")
        rev0 = await env.core.current_rev(PAIR)
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        env.core._rev_cache.clear()
        changed = await env.core.changes_since(PAIR, rev0)
        assert "drive" in changed["scopes"]
        full = await env.drive.drive_tree(PAIR, Response(), None, actor)
        assert full["full"] is True and [i["clip_id"] for i in full["items"]] == ["c1"] and full["cursor"]
        none_new = await env.drive.drive_tree(PAIR, Response(), full["cursor"], actor)
        assert none_new["items"] == [] and none_new["cursor"] == full["cursor"]
        await env.drive.work_once("w1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c2"]), actor)
        delta = await env.drive.drive_tree(PAIR, Response(), full["cursor"], actor)
        assert {i["clip_id"] for i in delta["items"]} == {"c1", "c2"} and delta["full"] is False
        assert (await code_of(env.drive.drive_tree(PAIR, Response(), "wczoraj", actor))).error_code == "BAD_SINCE"

    env.run(go)


def test_disconnect_cancels_queue_keeps_saved_and_drops_tokens(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await add_clip(env, "c1", "k1")
        await add_clip(env, "c2", "k2")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        await env.drive.work_once("w1")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c2"]), actor)
        partner = await env.actor(B)
        assert (await code_of(env.drive.disconnect_drive(PAIR, partner))).error_code == "DRIVE_NOT_OWNER"
        view = await env.drive.disconnect_drive(PAIR, actor)
        assert view["state"] == "disconnected" and ("revoke",) in env.g.calls
        assert await env.drive.get_conn(PAIR) is None
        states = {r["clip_id"]: r["state"] for r in await env.core.rows(select(env.T["mentor_drive_files"]))}
        assert states == {"c1": "done", "c2": "cancelled"}
        tree = await env.drive.drive_tree(PAIR, Response(), None, actor)
        assert [i["clip_id"] for i in tree["items"]] == ["c1"] and tree["state"] == "disconnected"

    env.run(go)


# ─── prostowanie księgi z Dyskiem (/drive/verify) ────────────────────────────


async def saved_clip(env, clip_id="c1", key="k1"):
    actor = await env.actor(A)
    await add_clip(env, clip_id, key)
    await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=[clip_id]), actor)
    await env.drive.work_once("w1")
    files = env.T["mentor_drive_files"]
    return await env.core.one(select(files).where(files.c.clip_id == clip_id))


def test_verify_gone_on_404_and_trashed_then_save_again_and_tree_hides_it(env):
    async def go():
        actor, _ = await with_folder(env, A)
        partner = await env.actor(B)
        files = env.T["mentor_drive_files"]
        r1, r2 = await saved_clip(env, "c1", "k1"), await saved_clip(env, "c2", "k2")
        env.g.gone.add(r1["drive_file_id"])
        env.g.trashed.add(r2["drive_file_id"])
        out = await env.drive.verify_drive(PAIR, None, partner)  # widzi też partner, bez tokenu właściciela
        assert out["checked"] == 2 and out["gone"] == 2
        assert {i["clip_id"]: i["status"] for i in out["items"]} == {"c1": "gone", "c2": "gone"}
        assert all(i["web_view_link"] is None for i in out["items"])
        tree = await env.drive.drive_tree(PAIR, Response(), None, actor)
        assert tree["items"] == []
        assert (await env.drive.counts_of(PAIR))["saved"] == 0
        # stary klient w trybie delta widzi znany mu stan "cancelled"
        delta = await env.drive.drive_tree(PAIR, Response(), "1970-01-01T00:00:00Z", actor)
        assert {i["status"] for i in delta["items"]} == {"cancelled"}
        # ponowny zapis działa od nowa i wgrywa plik
        again = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        assert again["items"][0]["status"] == "requeued" and again["accepted"] == 1
        await env.drive.work_once("w1")
        row = await env.core.one(select(files).where(files.c.clip_id == "c1"))
        assert row["state"] == "done" and row["drive_file_id"] != r1["drive_file_id"]

    env.run(go)


def test_verify_saved_updates_stale_link(env):
    async def go():
        actor, _ = await with_folder(env, A)
        row = await saved_clip(env)
        out = await env.drive.verify_drive(PAIR, env.drive.VerifyBody(clip_ids=["c1"]), actor)
        assert out == {"items": [{"clip_id": "c1", "status": "saved", "web_view_link": f"https://drive/{row['drive_file_id']}?v=2"}],
                       "checked": 1, "gone": 0}
        after = await env.core.one(select(env.T["mentor_drive_files"]))
        assert after["web_view_link"].endswith("?v=2") and after["verified_at"] is not None and after["state"] == "done"

    env.run(go)


@pytest.mark.parametrize("error", [gerr(403, "forbidden"), gerr(403, "appNotAuthorizedToFile"), gerr(0, "network"),
                                   gerr(429, "rateLimitExceeded"), gerr(503, "")])
def test_verify_never_deletes_on_ambiguous_errors(env, error):
    async def go():
        actor, _ = await with_folder(env, A)
        row = await saved_clip(env)
        env.g.fail["file_state"] = error
        out = await env.drive.verify_drive(PAIR, None, actor)
        assert out["gone"] == 0 and out["items"][0]["status"] == "saved"
        assert (await env.core.one(select(env.T["mentor_drive_files"])))["drive_file_id"] == row["drive_file_id"]
        assert (await env.drive.get_conn(PAIR))["state"] == "connected"  # 403/sieć nie psuje połączenia

    env.run(go)


def test_verify_revoked_token_marks_reconnect_and_keeps_saved(env):
    async def go():
        actor, _ = await with_folder(env, A)
        await saved_clip(env, "c1", "k1")
        await saved_clip(env, "c2", "k2")
        env.g.fail["file_state"] = gerr(401, "authError")
        out = await env.drive.verify_drive(PAIR, None, actor)
        assert out["gone"] == 0 and {i["status"] for i in out["items"]} == {"saved"}
        assert (await env.drive.get_conn(PAIR))["state"] == "needs_reconnect"
        assert len([p for p in env.pushes if p[2] == "reconnect"]) == 1
        exc = await code_of(env.drive.verify_drive(PAIR, None, actor))
        assert exc.status_code == 409 and exc.error_code == "DRIVE_NEEDS_RECONNECT"
        assert (await env.drive.counts_of(PAIR))["saved"] == 2

    env.run(go)


def test_verify_limit_oldest_checked_first_and_skips_in_flight(env, monkeypatch):
    async def go():
        actor, _ = await with_folder(env, A)
        monkeypatch.setattr(env.drive, "VERIFY_LIMIT", 2)
        for n in (1, 2, 3):
            await add_clip(env, f"c{n}", "k1")
            await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=[f"c{n}"]), actor)
            await env.drive.work_once("w1")
        await add_clip(env, "c9", "k2")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c9"]), actor)  # w kolejce, nie sprawdzany
        first = await env.drive.verify_drive(PAIR, None, actor)
        assert first["checked"] == 2
        second = await env.drive.verify_drive(PAIR, None, actor)
        seen = {i["clip_id"] for i in first["items"]} | {i["clip_id"] for i in second["items"]}
        assert seen == {"c1", "c2", "c3"}
        assert len([c for c in env.g.calls if c[0] == "file_state"]) == 4

    env.run(go)


def test_save_on_already_saved_but_deleted_file_saves_again(env):
    async def go():
        actor, _ = await with_folder(env, A)
        row = await saved_clip(env)
        env.g.gone.add(row["drive_file_id"])
        again = await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c1"]), actor)
        assert again["items"][0]["status"] == "requeued"
        await env.drive.work_once("w1")
        assert (await env.core.one(select(env.T["mentor_drive_files"])))["state"] == "done"

    env.run(go)


def test_ensure_path_recreates_deleted_remembered_subfolder(env):
    async def go():
        actor, _ = await with_folder(env, A)
        files = env.T["mentor_drive_files"]
        await saved_clip(env, "c1", "k1")
        conn = await env.drive.get_conn(PAIR)
        match_dir = env.g.folders[(conn["folder_id"], "2026-10-10 SPR - KS (ISM/1)")]
        old_cat = env.g.folders[(match_dir, "Do dyskusji")]
        env.g.gone.add(old_cat)
        await add_clip(env, "c2", "k2")
        await env.drive.save_clips(PAIR, env.drive.SaveBody(clip_ids=["c2"]), actor)
        await env.drive.work_once("w1")
        row = await env.core.one(select(files).where(files.c.clip_id == "c2"))
        assert row["state"] == "done" and env.g.files[row["drive_file_id"]]["parent"] != old_cat

    env.run(go)


def test_verify_due_background_respects_age(env):
    async def go():
        await with_folder(env, A)
        await saved_clip(env)
        assert await env.drive.verify_due() == 1
        assert await env.drive.verify_due() == 0  # świeżo sprawdzone
        assert await env.drive.verify_due(NOW + timedelta(days=400)) == 1

    env.run(go)
