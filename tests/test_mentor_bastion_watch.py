"""Bastion (05.11.2026): podtrzymanie sesji, push o rozłączeniu i sesja z okna logowania w aplikacji."""

import httpx
from fastapi import Response

from tests.mentor_panel_support import ADMIN, JUDGES
from tests.test_mentor_bastion_routes import AUTH_PB, OK_PB, FakeConnector, actors, conn_row, denied, env, stored  # noqa: F401

A, B = JUDGES


def pushes(env):
    sent = []

    async def fake(judges, title, body, data, **kw):
        sent.append((list(judges), title, data))
        return {}

    import app.push.push as P

    env.mp.setattr(P, "send_push_to_judges_report", fake)
    return sent


def with_import(env, verdict=200, auto_renew=False):
    """Atrapa connectora z `/connections/import`: 200 zapisuje sesję (status stored), inaczej odmowa."""
    fake = env.fake

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        if request.url.path == "/connections/import":
            body = _json.loads(request.content)
            fake.calls.append(("POST", "/connections/import", body))
            if verdict != 200:
                return httpx.Response(verdict, json={"error": "BASTION_AUTH_REQUIRED"})
            key = "default" if body["scope"] == "default" else f"personal-{body['judge_id']}"
            fake.status[key] = stored(key, generation=2)
            return httpx.Response(200, json={"connection": key, "generation": 2, "auto_renew": auto_renew})
        return fake.handler(request)

    env.client = env.bastion_client.ConnectorClient("http://connector", "t" * 40, transport=httpx.MockTransport(handler),
                                                    breaker=env.bastion_client.Breaker(threshold=99))
    env.mp.setattr(env.bastion_client, "get_client", lambda: env.client)


COOKIES = [{"name": "bastion_session", "value": "abc", "domain": "portal.handball-bastion.pl", "path": "/", "httpOnly": True, "secure": True}]


def test_rozlaczenie_osobistego_wysyla_jeden_push_wlascicielowi(env):
    sent = pushes(env)

    async def go():
        import asyncio

        row = await env.bastion._ensure_connection("personal", A)
        row = await env.bastion._set_connection(row, status="ready")
        row = await env.bastion._set_connection(row, status="reauth_required")
        await env.bastion._set_connection(row, status="reauth_required")  # bez drugiego pusha
        await asyncio.sleep(0.05)

    env.run(go)
    assert len(sent) == 1
    judges, title, data = sent[0]
    assert judges == [A] and data["target"] == "bastion" and data["tag"] == f"mentor-bastion-personal-{A}"


def test_rozlaczenie_domyslnego_trafia_do_adminow(env):
    sent = pushes(env)

    async def go():
        import asyncio

        row = await env.bastion._ensure_connection("default", None)
        row = await env.bastion._set_connection(row, status="ready")
        await env.bastion._set_connection(row, status="reauth_required")
        await asyncio.sleep(0.05)

    env.run(go)
    assert [s[0] for s in sent] == [[ADMIN]]


def test_import_z_okna_aplikacji_laczy_konto(env):
    with_import(env, auto_renew=False)

    async def go():
        _, real, _ = await actors(env, A)
        out = await env.bastion.import_app_session(env.bastion.ImportBody(scope="personal", cookies=COOKIES), Response(), real)
        return out, await conn_row(env, f"personal-{A}")

    out, row = env.run(go)
    assert out["connection"]["status"] == "ready" and row["status"] == "ready"
    call = next(c for c in env.fake.calls if c[1] == "/connections/import")
    assert call[2]["judge_id"] == A and call[2]["cookies"][0]["name"] == "bastion_session"


def test_import_nieudany_to_409_a_domyslne_tylko_admin(env):
    with_import(env, verdict=409)

    async def go():
        _, real, _ = await actors(env, A)
        bad = await denied(env.bastion.import_app_session(env.bastion.ImportBody(scope="personal", cookies=COOKIES), Response(), real))
        forbidden = await denied(env.bastion.import_app_session(env.bastion.ImportBody(scope="default", cookies=COOKIES), Response(), real))
        return bad, forbidden

    bad, forbidden = env.run(go)
    assert bad[:2] == (409, "BASTION_AUTH_REQUIRED")
    assert forbidden[:2] == (403, "BASTION_CONNECTION_FORBIDDEN")


def test_podtrzymanie_odswieza_zywe_i_oznacza_wygasle(env):
    sent = pushes(env)
    env.mp.setenv("BASTION_PROBE_BUNNY_ITEM_ID", "5632")
    env.fake.status["default"] = stored("default")
    # connector po nieudanej (i nieodnowionej) sesji pamięta stan z ostatnim błędem 401
    env.fake.status[f"personal-{A}"] = stored(f"personal-{A}", last_error_code="BASTION_AUTH_REQUIRED")
    env.fake.playback["default"] = OK_PB
    env.fake.playback[f"personal-{A}"] = AUTH_PB

    async def go():
        import asyncio

        from app import mentor_bastion_watch as W

        env.mp.setattr(W, "STAGGER_S", 0)
        for scope, owner in (("default", None), ("personal", A)):
            row = await env.bastion._ensure_connection(scope, owner)
            await env.bastion._set_connection(row, status="ready")
        n = await W.keepalive_once()
        await asyncio.sleep(0.05)
        return n, (await conn_row(env, "default"))["status"], (await conn_row(env, f"personal-{A}"))["status"]

    n, default_status, personal_status = env.run(go)
    assert n == 2 and default_status == "ready" and personal_status == "reauth_required"
    assert [s[0] for s in sent] == [[A]]  # jeden push, tylko właścicielowi wygasłego połączenia
    assert ("GET", "/playback", {"scope": "personal", "judge_id": A, "bunny_item_id": "5632", "include_embed": "false"}) in env.fake.calls


def test_podtrzymanie_bez_connectora_nic_nie_zmienia(env):
    env.fake.down = True

    async def go():
        from app import mentor_bastion_watch as W

        row = await env.bastion._ensure_connection("personal", A)
        await env.bastion._set_connection(row, status="ready")
        await W.keepalive_once()
        return (await conn_row(env, f"personal-{A}"))["status"]

    assert env.run(go) == "ready"
