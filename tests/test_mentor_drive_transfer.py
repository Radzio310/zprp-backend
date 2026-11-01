"""Przenoszenie testujemy na SQLite i atrapach Google, nigdy na folderach użytkownika."""

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from tests import test_mentor_drive
from tests.test_mentor_drive import A, B, PAIR, STRANGER, FakeGoogle, gerr, with_folder

env = test_mentor_drive.env


ROOT = "ROOT0000000001"


class MoveGoogle(FakeGoogle):
    def __init__(self):
        super().__init__()
        self.meta = {ROOT: self.folder_meta(ROOT, "Mój Dysk")}
        self.after_move = False
        self.moves = []

    @staticmethod
    def folder_meta(fid, name, parent=None):
        return {"id": fid, "name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent] if parent else [],
                "webViewLink": f"https://drive.example/{fid}", "capabilities": {"canAddChildren": True, "canShare": True, "canMoveItemWithinDrive": True}}

    async def create_folder(self, access, name, parent=None):
        value = await super().create_folder(access, name, parent)
        self.meta[value["id"]] = self.folder_meta(value["id"], name, parent or ROOT)
        return dict(self.meta[value["id"]])

    async def get_file(self, access, file_id):
        if file_id in self.gone:
            raise gerr(404, "notFound")
        return dict(self.meta[file_id])

    async def create_transfer_folder(self, access, name, job_id, parent=None):
        value = await self.create_folder(access, name, parent)
        self.meta[value["id"]]["appProperties"] = {"baza_transfer": job_id}
        return value

    async def find_by_prop(self, access, parent, key, value):
        parent = ROOT if parent == "root" else parent
        for f in self.meta.values():
            if parent in f.get("parents", []) and f.get("appProperties", {}).get(key) == value:
                return dict(f)
        return None

    async def list_permissions(self, access, file_id):
        self._maybe_fail("list_permissions")
        permissions = [dict(p) for p in self._store(file_id)]
        for parent in self.meta[file_id].get("parents", []):
            for p in await self.list_permissions(access, parent):
                p = dict(p)
                if p["role"] == "owner":
                    p["role"] = "writer"
                key = (p["type"], p.get("emailAddress"))
                if not any((x["type"], x.get("emailAddress")) == key for x in permissions):
                    permissions.append(p)
        return permissions

    async def transfer_permission(self, access, file_id, permission, existing=None):
        self._maybe_fail("transfer_permission")
        if existing:
            return await self.update_permission(access, file_id, existing["id"], permission["role"])
        return await self.create_permission(access, file_id, permission["emailAddress"], permission["role"])

    async def move_file(self, access, file_id, source, destination):
        assert self.meta[file_id]["parents"] == [source]
        self.meta[file_id]["parents"] = [destination]
        self.moves.append((file_id, source, destination))
        if self.after_move:
            self.after_move = False
            raise gerr(503, "backendError")  # Google wykonało ruch, ale odpowiedź zaginęła.
        return dict(self.meta[file_id])


async def setup(e):
    e.g = MoveGoogle()
    e.drive_google.set_api(e.g)
    actor, view = await with_folder(e)
    return actor, view["folder"]["id"], e.drive.transfer


async def clip(e, parent, number=1):
    fid = f"FILE{number:012d}"
    e.g.meta[fid] = {"id": fid, "name": f"Klip {number}.mp4", "parents": [parent], "mimeType": "video/mp4",
                     "capabilities": {"canShare": True, "canMoveItemWithinDrive": True}}
    await e.ins("mentor_drive_files", id=f"record-{number}", pair_id=PAIR, clip_id=f"clip-{number}", variant="plain", match_id="m1",
                name=f"Klip {number}.mp4", author_judge_id=A, state="done", drive_file_id=fid,
                web_view_link=f"https://drive.example/{fid}")
    return fid


def person(email, role="reader", pid="GUEST"):
    return {"id": pid, "emailAddress": email, "role": role, "type": "user"}


async def until(e, service, state, worker="test-worker"):
    for _ in range(30):
        current = (await service.get_transfer(PAIR, await e.actor(A)))["transfer"]
        if current["state"] == state:
            return current
        if current["state"] == "failed" and state != "failed":
            pytest.fail(current["error"])
        await service.work_once(worker)
    pytest.fail(f"Nie osiągnięto stanu {state}")


def test_new_folder_confirmation_moves_only_baza_files_and_preserves_links_and_people(env):
    async def go():
        actor, source, service = await setup(env)
        env.g._store(source).append(person("guest@example.com", "reader"))
        sub = (await env.g.create_folder("test", "Mecz", source))["id"]
        env.g._store(sub).append(person("coach@example.com", "writer", "COACH"))
        fid = await clip(env, sub)
        env.g.meta["MANUAL00000001"] = {"id": "MANUAL00000001", "parents": [source], "mimeType": "video/mp4"}
        outside = (await env.g.create_folder("test", "Inny folder"))["id"]
        outside_file = await clip(env, outside, 2)
        count = len(env.g.folders)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True, name="Nowa Teczka"), actor)
        job = await until(env, service, "ready")
        assert len(env.g.folders) == count and not env.g.moves
        assert job["total"] == 1 and len(job["skipped"]) == 1
        assert {x["email"] for x in job["people"]} == {"guest@example.com", "coach@example.com"}
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)  # podwójny klik
        done = await until(env, service, "done")
        conn = await env.drive.get_conn(PAIR)
        target = conn["folder_id"]
        assert target != source and done["moved"] == 1
        new_sub = env.g.meta[fid]["parents"][0]
        assert env.g.meta[new_sub]["parents"] == [target] and env.g.meta[new_sub]["name"] == "Mecz"
        assert env.g.meta["MANUAL00000001"]["parents"] == [source]
        assert env.g.meta[outside_file]["parents"] == [outside]
        perms = await env.g.list_permissions("test", fid)
        assert {p["emailAddress"]: p["role"] for p in perms}["coach@example.com"] == "writer"
        assert not any(p.get("emailAddress") == "coach@example.com" for p in await env.g.list_permissions("test", target))
        stored = await env.core.one(select(env.drive.FILES).where(env.drive.FILES.c.drive_file_id == fid))
        assert stored["web_view_link"] == f"https://drive.example/{fid}"
        assert len(env.g.moves) == 1 and source in env.g.meta  # niczego nie usuwamy
    env.run(go)


def test_existing_destination_access_is_previewed_and_never_downgraded(env):
    async def go():
        actor, source, service = await setup(env)
        env.g._store(source).append(person("same@example.com", "reader"))
        target = (await env.g.create_folder("test", "Cel"))["id"]
        env.g._store(target).append(person("same@example.com", "writer", "SAME"))
        env.g._store(target).append(person("target@example.com", "reader", "TARGET"))
        await clip(env, source)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, file_id=target), actor)
        job = await until(env, service, "ready")
        assert "target@example.com" in {p["name"] for p in job["destination_people"]}
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        await until(env, service, "done")
        assert next(p for p in env.g._store(target) if p["emailAddress"] == "same@example.com")["role"] == "writer"
    env.run(go)


def test_lost_response_after_move_resumes_without_duplicate_move_or_folder(env):
    async def go():
        actor, source, service = await setup(env)
        fid = await clip(env, source)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True, name="Cel"), actor)
        await until(env, service, "ready")
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        env.g.after_move = True
        failed = await until(env, service, "failed")
        assert failed["moved"] == 0 and len(env.g.moves) == 1
        assert (await env.drive.get_conn(PAIR))["folder_id"] == source
        folder_count = len(env.g.folders)
        await service.resume_transfer(PAIR, result["transfer"]["id"], actor)
        await until(env, service, "done", worker="after-restart")
        assert len(env.g.moves) == 1 and len(env.g.folders) == folder_count
        assert env.g.meta[fid]["parents"] == [(await env.drive.get_conn(PAIR))["folder_id"]]
    env.run(go)


def test_destination_subfolder_with_extra_access_is_not_reused(env):
    async def go():
        actor, source, service = await setup(env)
        sub = (await env.g.create_folder("test", "Mecz", source))["id"]
        fid = await clip(env, sub)
        target = (await env.g.create_folder("test", "Cel"))["id"]
        foreign_sub = (await env.g.create_folder("test", "Mecz", target))["id"]
        env.g._store(foreign_sub).append(person("extra@example.com"))
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, file_id=target), actor)
        await until(env, service, "ready")
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        await until(env, service, "done")
        assert env.g.meta[fid]["parents"] != [foreign_sub]
        assert not any(p.get("emailAddress") == "extra@example.com" for p in await env.g.list_permissions("test", fid))
    env.run(go)


def test_preview_can_be_cancelled_without_google_writes_and_pauses_uploads(env):
    async def go():
        actor, source, service = await setup(env)
        await clip(env, source)
        await env.ins("mentor_drive_files", id="queued", pair_id=PAIR, clip_id="queued", match_id="m1", variant="plain", name="Nowy", author_judge_id=A, state="queued")
        count = len(env.g.folders)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        assert await env.drive.claim_next("upload") is None
        await until(env, service, "ready")
        await service.cancel_transfer(PAIR, result["transfer"]["id"], actor)
        assert len(env.g.folders) == count and not env.g.moves
        assert (await env.drive.claim_next("upload"))["id"] == "queued"
    env.run(go)


def test_nested_target_is_rejected_before_moving_or_sharing(env):
    async def go():
        actor, source, service = await setup(env)
        target = (await env.g.create_folder("test", "W środku", source))["id"]
        await clip(env, source)
        await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, file_id=target), actor)
        failed = await until(env, service, "failed")
        assert "wewnątrz" in failed["error"] and failed["can_cancel"]
        assert not env.g.moves and (await env.drive.get_conn(PAIR))["folder_id"] == source
    env.run(go)


def test_permissions_changed_after_preview_require_new_confirmation(env):
    async def go():
        actor, source, service = await setup(env)
        await clip(env, source)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        await until(env, service, "ready")
        env.g._store(source).append(person("new@example.com"))
        with pytest.raises(HTTPException) as exc:
            await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        assert exc.value.error_code == "TRANSFER_ACCESS_CHANGED" and not env.g.moves
    env.run(go)


def test_only_connection_owner_can_plan_or_confirm(env):
    async def go():
        actor, source, service = await setup(env)
        for judge in (B, STRANGER):
            with pytest.raises(HTTPException):
                await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), await env.actor(judge))
        assert (await env.drive.get_conn(PAIR)).get("folder_transfer_state") is None
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        await until(env, service, "ready")
        with pytest.raises(HTTPException):
            await service.start_transfer(PAIR, result["transfer"]["id"], await env.actor(B))
    env.run(go)


def test_active_transfer_blocks_folder_disconnect_and_access_changes(env):
    async def go():
        actor, source, service = await setup(env)
        await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        for action in (env.drive.set_folder(PAIR, env.drive.FolderBody(create=True), actor),
                       env.drive.disconnect_drive(PAIR, actor), env.drive._access_ctx(PAIR, actor)):
            with pytest.raises(HTTPException) as exc:
                await action
            assert exc.value.error_code == "TRANSFER_ACTIVE"
    env.run(go)


def test_public_or_domain_source_permissions_fail_in_preview_without_writes(env):
    async def go():
        actor, source, service = await setup(env)
        env.g._store(source).append({"id": "public", "type": "anyone", "role": "reader"})
        count = len(env.g.folders)
        await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        failed = await until(env, service, "failed")
        assert "link" in failed["error"] and len(env.g.folders) == count and not env.g.moves
    env.run(go)


def test_drive_http_move_keeps_file_id_and_uses_parent_update_without_upload():
    import asyncio
    import httpx
    from app.mentor_drive_google import GoogleApi
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"id": "same-file"})

    async def go():
        api = GoogleApi("test", "test", transport=httpx.MockTransport(respond))
        assert (await api.move_file("test-only", "same-file", "old-parent", "new-parent"))["id"] == "same-file"
        request = seen[0]
        assert request.method == "PATCH" and request.url.path.endswith("/same-file")
        assert request.url.params["addParents"] == "new-parent" and request.url.params["removeParents"] == "old-parent"
        assert request.content == b"{}"
    asyncio.run(go())


def test_stopping_failed_partial_transfer_requires_explicit_choice_and_keeps_files(env):
    async def go():
        actor, source, service = await setup(env)
        fid = await clip(env, source)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True, name="Cel"), actor)
        await until(env, service, "ready")
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        env.g.after_move = True
        failed = await until(env, service, "failed")
        parent_after_move = env.g.meta[fid]["parents"][:]
        with pytest.raises(HTTPException) as exc:
            await service.cancel_transfer(PAIR, failed["id"], actor)
        assert exc.value.error_code == "TRANSFER_STARTED"
        cancelled = await service.cancel_transfer(PAIR, failed["id"], actor, service.CancelBody(leave_partial=True))
        assert cancelled["transfer"]["state"] == "cancelled"
        assert env.g.meta[fid]["parents"] == parent_after_move
        assert (await env.drive.get_conn(PAIR))["folder_id"] == source
        assert not service.busy(await env.drive.get_conn(PAIR))
    env.run(go)


def test_two_workers_respect_lease_and_can_resume_after_expiry(env):
    from datetime import timedelta
    from sqlalchemy import update

    async def go():
        actor, source, service = await setup(env)
        await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        now = env.drive.C.now()
        await env.db.execute(update(env.drive.CONN).where(env.drive.CONN.c.pair_id == PAIR)
                             .values(folder_transfer_worker="crashed", folder_transfer_lease_until=now + timedelta(minutes=1)))
        assert await service.work_once("other", now) is False
        assert await service.work_once("other", now + timedelta(minutes=2)) is True
        await until(env, service, "ready")
    env.run(go)


def test_permission_failure_before_file_move_does_not_change_active_folder(env):
    async def go():
        actor, source, service = await setup(env)
        env.g._store(source).append(person("guest@example.com"))
        await clip(env, source)
        result = await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        await until(env, service, "ready")
        await service.start_transfer(PAIR, result["transfer"]["id"], actor)
        env.g.fail["transfer_permission"] = gerr(503, "backendError")
        await until(env, service, "failed")
        assert not env.g.moves and (await env.drive.get_conn(PAIR))["folder_id"] == source
        env.g.fail.clear()
        await service.resume_transfer(PAIR, result["transfer"]["id"], actor)
        await until(env, service, "done")
        assert len(env.g.moves) == 1
    env.run(go)


def test_google_permission_copy_supports_groups_and_preserves_higher_role_without_extending_expiry():
    import asyncio
    import json
    import httpx
    from app.mentor_drive_google import GoogleApi, GoogleError
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"id": "permission"})

    async def go():
        api = GoogleApi("test", "test", transport=httpx.MockTransport(respond))
        p = {"type": "group", "emailAddress": "group@example.com", "role": "reader"}
        await api.transfer_permission("test-only", "folder", p)
        assert json.loads(seen[-1].content) == p
        assert seen[-1].url.params["sendNotificationEmail"] == "true"
        await api.transfer_permission("test-only", "folder", {"type": "user", "emailAddress": "user@example.com", "role": "reader"},
                                      {"id": "old", "role": "writer"})
        assert json.loads(seen[-1].content)["role"] == "writer"
        assert "transferOwnership" not in seen[-1].url.params
        count = len(seen)
        with pytest.raises(GoogleError):
            await api.transfer_permission("test-only", "folder", p, {"id": "old", "role": "writer", "expirationTime": "2027-01-01T00:00:00Z"})
        assert len(seen) == count
    asyncio.run(go())


def test_temporary_access_is_rejected_before_any_folder_is_created(env):
    async def go():
        actor, source, service = await setup(env)
        env.g._store(source).append({**person("temporary@example.com"), "expirationTime": "2027-01-01T00:00:00Z"})
        count = len(env.g.folders)
        await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
        failed = await until(env, service, "failed")
        assert "wygaśnięcia" in failed["error"] and len(env.g.folders) == count
    env.run(go)


def test_folder_change_that_races_plan_cannot_overwrite_source(env, monkeypatch):
    async def go():
        actor, source, service = await setup(env)
        original = env.g.create_folder

        async def race(access, name, parent=None):
            value = await original(access, name, parent)
            await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, create=True), actor)
            return value

        monkeypatch.setattr(env.g, "create_folder", race)
        with pytest.raises(HTTPException) as exc:
            await env.drive.set_folder(PAIR, env.drive.FolderBody(create=True, name="Równoległy folder"), actor)
        assert exc.value.error_code == "TRANSFER_ACTIVE"
        assert (await env.drive.get_conn(PAIR))["folder_id"] == source
    env.run(go)


def test_drive_file_does_not_require_access_to_destination_ancestors(env, monkeypatch):
    async def go():
        actor, source, service = await setup(env)
        await clip(env, source)
        unknown = (await env.g.create_folder("test", "Nieudostępniony przodek"))["id"]
        target = (await env.g.create_folder("test", "Wybrany cel", unknown))["id"]
        await clip(env, unknown, 2)  # zapis historyczny poza obecną Teczką
        original = env.g.get_file

        async def restricted(access, fid):
            if fid == unknown:
                raise gerr(404, "notFound")
            return await original(access, fid)

        monkeypatch.setattr(env.g, "get_file", restricted)
        await service.plan_transfer(PAIR, service.PlanBody(source_folder_id=source, file_id=target), actor)
        ready = await until(env, service, "ready")
        assert ready["total"] == 1 and len(ready["skipped"]) == 1
    env.run(go)


def test_http_routes_parse_confirmation_and_keep_progress_private_from_caches(env):
    from fastapi import FastAPI
    import httpx

    async def go():
        actor, source, service = await setup(env)
        app = FastAPI()
        app.include_router(env.drive.router)
        app.dependency_overrides[env.drive.mentor_actor] = lambda: actor
        assert "PlanBody" in app.openapi()["components"]["schemas"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(f"/mentor-panel/pairs/{PAIR}/drive/transfer/plan", json={"source_folder_id": source, "create": True, "name": "Cel"})
            assert response.status_code == 200
            job_id = response.json()["transfer"]["id"]
            response = await client.get(f"/mentor-panel/pairs/{PAIR}/drive/transfer")
            assert response.headers["cache-control"] == "no-store"
            await until(env, service, "ready")
            response = await client.post(f"/mentor-panel/pairs/{PAIR}/drive/transfer/{job_id}/start", json={})
            assert response.status_code == 200 and response.json()["transfer"]["started"]
    env.run(go)
