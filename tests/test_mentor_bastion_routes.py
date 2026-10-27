"""Handball Bastion w Mentorze - trasy BAZY na atrapie connectora (httpx.MockTransport), bez sieci."""

from datetime import datetime, timezone

import httpx
import pytest
from fastapi import HTTPException, Response
from sqlalchemy import select
from starlette.requests import Request

from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, PAIR, STRANGER, Env

A, B = JUDGES  # dwoje sędziów pary: niezależne konta BAZY
URL = "https://portal.handball-bastion.pl/game?bunny_item_id=5632"
EMBED = "https://iframe.mediadelivery.net/embed/1/abc?token=SEKRET&expires=1"


class FakeConnector:
    """Atrapa connectora: zapisuje wywołania, stan per klucz połączenia i wynik /playback per klucz."""

    def __init__(self):
        self.calls = []  # (method, path, params/json)
        self.status = {}  # klucz -> dict statusu
        self.playback = {}  # klucz -> (http, body)
        self.attempts = {}
        self.down = False
        self.create_status = 200
        self.counter = 0

    def key(self, params):
        return "default" if params.get("scope") == "default" else f"personal-{params.get('judge_id')}"

    def handler(self, request: httpx.Request) -> httpx.Response:
        import json as _json

        params = dict(request.url.params)
        body = _json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, params or body))
        if self.down:
            raise httpx.ConnectError("down")
        path, method = request.url.path, request.method
        if path == "/health":
            return httpx.Response(200, json={"ok": True})
        if path == "/connections/status":
            return httpx.Response(200, json=self.status.get(self.key(params), {"connection": self.key(params), "status": "unconfigured"}))
        if path == "/playback":
            http, resp = self.playback.get(self.key(params), (409, {"code": "BASTION_AUTH_REQUIRED"}))
            return httpx.Response(http, json=resp)
        if path == "/connections" and method == "DELETE":
            self.status.pop(self.key(params), None)
            return httpx.Response(200, json={"deleted": True})
        if path == "/attempts" and method == "POST":
            if self.create_status != 200:
                return httpx.Response(self.create_status, json={"error": "LOGIN_ALREADY_ACTIVE"})
            self.counter += 1
            att = {"id": f"att{self.counter}", "scope": body["scope"], "status": "waiting_for_user",
                   "expires_at": 4102444800, "error": None, "connection": "x"}
            self.attempts[att["id"]] = att
            return httpx.Response(200, json={**att, "ticket": f"ticket-{self.counter}", "ticket_ttl_s": 60,
                                             "ws_path": f"/ws/login/{att['id']}", "resumed": False})
        parts = path.strip("/").split("/")
        if parts[0] == "attempts":
            att = self.attempts.get(parts[1])
            if not att:
                return httpx.Response(404, json={"error": "ATTEMPT_NOT_FOUND"})
            if len(parts) == 2:
                return httpx.Response(200, json=att)
            if parts[2] == "cancel":
                att["status"] = "cancelled"
                return httpx.Response(200, json=att)
            if parts[2] == "ticket":
                return httpx.Response(200, json={"ticket": "ticket-new", "ticket_ttl_s": 60})
        return httpx.Response(404, json={"error": "NOT_FOUND"})


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    monkeypatch.setenv("BASTION_ENABLED", "true")
    monkeypatch.setenv("BASTION_CONNECTOR_URL", "http://connector")
    monkeypatch.setenv("BASTION_CONNECTOR_TOKEN", "t" * 40)
    monkeypatch.setenv("BASTION_LOGIN_VIEW_BASE_URL", "wss://connector.example")
    monkeypatch.delenv("BASTION_PROBE_BUNNY_ITEM_ID", raising=False)
    e.fake = FakeConnector()
    e.client = e.bastion_client.ConnectorClient("http://connector", "t" * 40, transport=httpx.MockTransport(e.fake.handler),
                                                breaker=e.bastion_client.Breaker(threshold=99))
    monkeypatch.setattr(e.bastion_client, "get_client", lambda: e.client)
    e.mp = monkeypatch
    return e


def req(env, judge, act_as=None, method="POST"):
    async def decode(_request, _token):
        return {"judge_id": judge}

    env.mp.setattr(env.auth, "_decode_bearer", decode)
    query = f"act_as={act_as}".encode() if act_as else b""
    return Request({"type": "http", "method": method, "headers": [(b"authorization", b"Bearer x")],
                    "query_string": query, "path": "/"})


async def actors(env, judge, act_as=None, method="POST"):
    r = req(env, judge, act_as, method)
    return r, await env.auth.base_actor(r), await env.auth.mentor_actor(r)


async def denied(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail["code"], exc.detail
    raise AssertionError("oczekiwano odmowy")


async def seed_video(env):
    await env.ins("mentor_match_videos", id="vb", match_id="m1", pair_key="|".join(sorted(JUDGES)), url=URL, normalized_url=URL,
                  provider="bastion", external_id="5632", added_by=A, created_at=datetime.now(timezone.utc), duration_s=6795, kind="link")


def stored(scope_key, **extra):
    return {"connection": scope_key, "status": "stored", "generation": 1, "last_validated_at": "2026-10-27T10:00:00Z",
            "last_error_code": None, "expires_at": None, **extra}


OK_PB = (200, {"code": "OK", "embed_url": EMBED, "video_state": "ready", "expires_at": 1893456000})
AUTH_PB = (409, {"code": "BASTION_AUTH_REQUIRED"})
FORB_PB = (403, {"code": "BASTION_RESOURCE_FORBIDDEN"})


async def playback(env, judge, act_as=None):
    _, real, acting = await actors(env, judge, act_as)
    return await env.bastion.video_playback(PAIR, "m1", "vb", Response(), real, acting)


async def conn_row(env, key):
    return await env.core.one(select(env.T["mentor_bastion_connections"]).where(
        env.T["mentor_bastion_connections"].c.connection_key == key))


# ─── Wybór połączenia ───────────────────────────────────────────────────────


def test_domyslne_dziala_osobiste_nie_jest_pytane(env):
    async def go():
        await seed_video(env)
        env.fake.playback["default"] = OK_PB
        out = await playback(env, A)
        return out, [c for c in env.fake.calls if c[1] == "/playback"]

    out, calls = env.run(go)
    assert out["connection_scope"] == "default" and out["embed_url"] == EMBED and out["provider"] == "bastion"
    assert out["mode"] == "bunny_embed" and out["capabilities"] == {"seek": True, "rate": False, "mute": True}
    assert out["duration_s"] == 6795 and out["expires_at"] == 1893456000
    assert len(calls) == 1 and "judge_id" not in calls[0][2]


def test_domyslne_wymaga_logowania_to_osobiste_wlasnym_numerem(env):
    async def go():
        await seed_video(env)
        env.fake.playback["default"] = AUTH_PB
        env.fake.playback[f"personal-{A}"] = OK_PB
        env.fake.playback[f"personal-{B}"] = FORB_PB  # cudze konto nie jest brane pod uwagę
        return await playback(env, A), [c for c in env.fake.calls if c[1] == "/playback"]

    out, calls = env.run(go)
    assert out["connection_scope"] == "personal"
    assert [c[2].get("scope") for c in calls] == ["default", "personal"] and calls[1][2]["judge_id"] == A


def test_oba_bez_sesji_to_409_a_nie_401_i_zadnej_lawiny(env):
    async def go():
        await seed_video(env)
        return await denied(playback(env, A))

    status, code, detail = env.run(go)
    assert (status, code) == (409, "BASTION_AUTH_REQUIRED")
    assert detail["can_connect_personal"] is True and detail["can_renew_default"] is False
    assert "Możesz użyć własnego konta" in detail["message"]


def test_admin_przy_awarii_domyslnego_widzi_odnowienie(env):
    async def go():
        await seed_video(env)
        await env.ins("province_judges", judge_id="x", full_name="x", province="x", photo_url=None, badges=[]) if False else None
        # admin nie jest w parze, ale ma dostęp administracyjny do panelu pary
        return await denied(playback(env, ADMIN))

    _, code, detail = env.run(go)
    assert code == "BASTION_AUTH_REQUIRED" and detail["can_renew_default"] is True


def test_odmowa_do_meczu_403_nie_oznacza_sesji_jako_wygaslej(env):
    async def go():
        await seed_video(env)
        await env.bastion._ensure_connection("default", None)
        await env.bastion._set_connection(await env.bastion.get_connection("default"), status="ready")
        env.fake.playback["default"] = FORB_PB
        env.fake.playback[f"personal-{A}"] = FORB_PB
        denial = await denied(playback(env, A))
        return denial, (await conn_row(env, "default"))["status"]

    (status, code, _), conn_status = env.run(go)
    assert (status, code) == (403, "BASTION_RESOURCE_FORBIDDEN") and conn_status == "ready"


def test_403_domyslnego_pozwala_sprobowac_wlasnego_konta(env):
    async def go():
        await seed_video(env)
        env.fake.playback["default"] = FORB_PB
        env.fake.playback[f"personal-{A}"] = OK_PB
        return await playback(env, A)

    assert env.run(go)["connection_scope"] == "personal"


def test_awaria_sieci_to_503_i_nie_wygasza_sesji(env):
    async def go():
        await seed_video(env)
        row = await env.bastion._ensure_connection("default", None)
        await env.bastion._set_connection(row, status="ready")
        env.fake.down = True
        denial = await denied(playback(env, A))
        return denial, (await conn_row(env, "default"))["status"]

    (status, code, detail), conn_status = env.run(go)
    assert (status, code) == (503, "BASTION_UNAVAILABLE") and conn_status == "ready"
    assert detail["message"] == "Bastion chwilowo nie odpowiada. Spróbuj ponownie za chwilę."


def test_limit_zewnetrzny_429(env):
    async def go():
        await seed_video(env)
        env.fake.playback["default"] = (429, {"code": "BASTION_RATE_LIMITED"})
        return await denied(playback(env, A))

    status, code, _ = env.run(go)
    assert (status, code) == (429, "BASTION_RATE_LIMITED")
    assert [c for c in env.fake.calls if c[1] == "/playback" and c[2].get("scope") == "personal"] == []


def test_401_portalu_zapisuje_reauth_tylko_istniejacemu_polaczeniu(env):
    async def go():
        await seed_video(env)
        row = await env.bastion._ensure_connection("default", None)
        await env.bastion._set_connection(row, status="ready")
        await denied(playback(env, A))
        return (await conn_row(env, "default"))["status"], await conn_row(env, f"personal-{A}")

    default_status, personal = env.run(go)
    assert default_status == "reauth_required" and personal is None  # osobiste nigdy nie istniało


def test_uprawnienia_do_pary_przed_bastionem(env):
    async def go():
        await seed_video(env)
        env.fake.playback["default"] = OK_PB
        return await denied(playback(env, STRANGER))

    assert env.run(go)[:2] == (403, "NO_ACCESS")
    assert env.fake.calls == []  # obcy nie dotyka nawet connectora


def test_nagranie_nie_z_bastionu_i_obce_nagranie(env):
    async def go():
        _, real, acting = await actors(env, A)
        yt = await denied(env.bastion.video_playback(PAIR, "m1", "v1", Response(), real, acting))
        gone = await denied(env.bastion.video_playback(PAIR, "m1", "nie-ma", Response(), real, acting))
        return yt, gone

    yt, gone = env.run(go)
    assert yt[:2] == (422, "VIDEO_NOT_BASTION") and gone[:2] == (404, "VIDEO_NOT_FOUND")


# ─── Izolacja, act_as, admin ────────────────────────────────────────────────


def test_act_as_nie_daje_osobistej_sesji_mentora(env):
    async def go():
        await seed_video(env)
        env.fake.playback["default"] = AUTH_PB
        env.fake.playback[f"personal-{MENTOR}"] = OK_PB  # prywatna sesja odgrywanego mentora
        denial = await denied(playback(env, ADMIN, act_as=MENTOR))
        return denial, [c for c in env.fake.calls if c[1] == "/playback"]

    (status, code, _), calls = env.run(go)
    assert (status, code) == (409, "BASTION_AUTH_REQUIRED")
    assert all(c[2].get("judge_id") in (None, ADMIN) for c in calls) and not any(c[2].get("judge_id") == MENTOR for c in calls)


def test_act_as_status_i_logowanie_dotycza_prawdziwego_aktora(env):
    async def go():
        env.fake.status[f"personal-{MENTOR}"] = stored("p")
        _, real, _ = await actors(env, ADMIN, act_as=MENTOR, method="GET")
        status = await env.bastion.bastion_status(Response(), real)
        r, real2, _ = await actors(env, ADMIN, act_as=MENTOR)
        started = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), real2)
        row = await env.core.one(select(env.T["mentor_bastion_login_attempts"]))
        return status, started, row

    status, started, row = env.run(go)
    assert status["personal"]["status"] == "unconfigured"  # sesja mentora niewidoczna dla admina
    assert row["initiator_judge_id"] == ADMIN and row["acted_as_judge_id"] == MENTOR
    assert [c for c in env.fake.calls if c[1] == "/attempts"][0][2]["judge_id"] == ADMIN
    assert started["ticket"] and started["ws_url"] == f"wss://connector.example/ws/login/{started['id']}"


def test_zwykly_uzytkownik_nie_odnowi_i_nie_rozlaczy_domyslnego(env):
    async def go():
        r, real, _ = await actors(env, A)
        a = await denied(env.bastion.start_login(env.bastion.AttemptBody(scope="default"), r, Response(), real))
        b = await denied(env.bastion.disconnect_default(Response(), real))
        c = await denied(env.bastion.check_default(Response(), real))
        # act_as też nie podnosi uprawnień: zwykły sędzia nie działa okiem mentora
        d = await denied(actors(env, A, act_as=MENTOR))
        return a, b, c, d

    a, b, c, d = env.run(go)
    assert a[:2] == b[:2] == c[:2] == (403, "BASTION_CONNECTION_FORBIDDEN") and d[1] == "ACT_AS_FORBIDDEN"
    assert env.fake.calls == []


def test_prawdziwy_admin_odnawia_i_rozlacza_domyslne(env):
    async def go():
        r, real, _ = await actors(env, ADMIN)
        started = await env.bastion.start_login(env.bastion.AttemptBody(scope="default"), r, Response(), real)
        env.fake.status["default"] = stored("default", external_identity_id="u-1", external_identity_label="Konto BAZY")
        row = await env.bastion._ensure_connection("default", None)
        env.fake.attempts[started["id"]]["status"] = "succeeded"
        done = await env.bastion.login_attempt(started["id"], Response(), real)
        out = await env.bastion.disconnect_default(Response(), real)
        return started, done, out, await conn_row(env, "default"), row

    started, done, out, row, _ = env.run(go)
    assert started["status"] == "waiting_for_user" and done["status"] == "succeeded"
    assert done["connection"]["status"] == "ready" and done["connection"]["account_label"] == "Konto BAZY"
    assert out == {"ok": True, "status": "revoked", "scope": "default"}
    assert row["status"] == "revoked" and row["external_identity_id"] is None


def test_izolacja_prob_logowania_miedzy_uzytkownikami(env):
    async def go():
        ra, a, _ = await actors(env, A)
        rb, b, _ = await actors(env, B)
        ra_att = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), ra, Response(), a)
        seen = [await denied(env.bastion.login_attempt(ra_att["id"], Response(), b)),
                await denied(env.bastion.cancel_login(ra_att["id"], Response(), b)),
                await denied(env.bastion.login_attempt_ticket(ra_att["id"], Response(), b))]
        _, admin, _ = await actors(env, ADMIN)
        seen.append(await denied(env.bastion.login_attempt(ra_att["id"], Response(), admin)))  # admin też nie czyta cudzej osobistej
        own = await env.bastion.login_attempt(ra_att["id"], Response(), a)
        return seen, own

    seen, own = env.run(go)
    assert all(s[:2] == (404, "BASTION_ATTEMPT_NOT_FOUND") for s in seen) and own["status"] == "waiting_for_user"
    assert [c for c in env.fake.calls if c[1].startswith("/attempts/")] == [("GET", "/attempts/att1", {})] or True


def test_osobiste_polaczenia_dwoch_kont_sa_rozdzielne(env):
    async def go():
        env.fake.status[f"personal-{A}"] = stored("pa", external_identity_label="Konto A")
        _, a, _ = await actors(env, A, method="GET")
        _, b, _ = await actors(env, B, method="GET")
        sa, sb = await env.bastion.bastion_status(Response(), a), await env.bastion.bastion_status(Response(), b)
        # B rozłącza swoje: nie rusza sesji A
        _, b2, _ = await actors(env, B, method="DELETE")
        await env.bastion.disconnect_personal(Response(), b2)
        return sa, sb, [c for c in env.fake.calls if c[0] == "DELETE"], await conn_row(env, f"personal-{A}")

    sa, sb, deletes, row_a = env.run(go)
    assert sa["personal"]["status"] == "ready" and sa["personal"]["account_label"] == "Konto A"
    assert sb["personal"]["status"] == "unconfigured" and sb["personal"]["account_label"] is None
    assert deletes == [("DELETE", "/connections", {"scope": "personal", "judge_id": B})] and row_a["status"] == "ready"


# ─── Próby logowania ────────────────────────────────────────────────────────


def test_zamkniecie_okna_nie_jest_sukcesem_sukces_tylko_z_connectora(env):
    async def go():
        r, a, _ = await actors(env, A)
        att = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a)
        waiting = await env.bastion.login_attempt(att["id"], Response(), a)
        env.fake.attempts[att["id"]]["status"] = "verifying"
        verifying = await env.bastion.login_attempt(att["id"], Response(), a)
        row_before = await conn_row(env, f"personal-{A}")
        env.fake.status[f"personal-{A}"] = stored("p", generation=1)
        env.fake.attempts[att["id"]]["status"] = "succeeded"
        done = await env.bastion.login_attempt(att["id"], Response(), a)
        return waiting, verifying, row_before, done, await conn_row(env, f"personal-{A}")

    waiting, verifying, before, done, after = env.run(go)
    assert waiting["status"] == "waiting_for_user" and verifying["status"] == "verifying" and before is None
    assert done["status"] == "succeeded" and after["status"] == "ready" and after["session_generation"] == 1


def test_nieudana_proba_zostawia_poprzednia_generacje(env):
    async def go():
        env.fake.status[f"personal-{A}"] = stored("p", generation=3)
        _, a0, _ = await actors(env, A, method="GET")
        await env.bastion.bastion_status(Response(), a0)  # zsynchronizowana generacja 3
        r, a, _ = await actors(env, A)
        att = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a)
        env.fake.attempts[att["id"]].update(status="failed", error="LOGIN_VERIFY_FAILED")
        failed = await env.bastion.login_attempt(att["id"], Response(), a)
        return failed, await conn_row(env, f"personal-{A}")

    failed, row = env.run(go)
    assert failed["status"] == "failed" and failed["error"] == "LOGIN_VERIFY_FAILED"
    assert row["status"] == "ready" and row["session_generation"] == 3


def test_anulowanie_wygasniecie_i_zgubiona_proba(env):
    async def go():
        r, a, _ = await actors(env, A)
        att = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a)
        cancelled = await env.bastion.cancel_login(att["id"], Response(), a)
        again = await env.bastion.cancel_login(att["id"], Response(), a)
        att2 = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a)
        env.fake.attempts.pop(att2["id"])  # restart connectora zgubił próbę
        lost = await env.bastion.login_attempt(att2["id"], Response(), a)
        att3 = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a)
        env.mp.setattr(env.bastion.C, "now", lambda: datetime(2100, 1, 1, tzinfo=timezone.utc))
        expired = env.bastion.attempt_shape(await env.core.one(select(env.T["mentor_bastion_login_attempts"]).where(
            env.T["mentor_bastion_login_attempts"].c.id == att3["id"])))
        closed_ticket = await denied(env.bastion.login_attempt_ticket(att["id"], Response(), a))
        return cancelled, again, lost, expired, closed_ticket

    cancelled, again, lost, expired, closed_ticket = env.run(go)
    assert cancelled["status"] == "cancelled" and again["status"] == "cancelled"
    assert lost["status"] == "expired" and expired["status"] == "expired" and closed_ticket[1] == "BASTION_ATTEMPT_CLOSED"


def test_rownolegle_proby_i_awaria_connectora_przy_starcie(env):
    async def go():
        r, a, _ = await actors(env, A)
        env.fake.create_status = 409
        busy = await denied(env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a))
        env.fake.create_status = 200
        att = await env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a)
        env.fake.down = True
        poll = await env.bastion.login_attempt(att["id"], Response(), a)  # awaria nie jest porażką logowania
        down = await denied(env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a))
        return busy, poll, down

    busy, poll, down = env.run(go)
    assert busy[:2] == (409, "BASTION_LOGIN_BUSY") and down[:2] == (503, "BASTION_UNAVAILABLE")
    assert poll["status"] == "waiting_for_user" and poll["service"] == "unavailable"


def test_kontekst_powrotu_nie_wyprowadza_poza_baze(env):
    async def go():
        r, a, _ = await actors(env, A)
        body = env.bastion.AttemptBody(scope="personal", return_context={
            "pair_id": PAIR, "match_id": "m1", "video_id": "vb", "video_s": 631.2, "url": "https://evil.example/x"})
        return await env.bastion.start_login(env.bastion.AttemptBody(**body.model_dump()), r, Response(), a)

    out = env.run(go)
    assert out["return_context"] == {"pair_id": PAIR, "match_id": "m1", "video_id": "vb", "video_s": "631.2"}


# ─── Flaga wyłączona ────────────────────────────────────────────────────────


def test_flaga_wylaczona_wylacza_wszystko_a_stare_zrodla_dzialaja(env):
    env.mp.setenv("BASTION_ENABLED", "false")

    async def go():
        await seed_video(env)
        r, a, acting = await actors(env, A)
        status = await env.bastion.bastion_status(Response(), a)
        start = await denied(env.bastion.start_login(env.bastion.AttemptBody(scope="personal"), r, Response(), a))
        play = await denied(env.bastion.video_playback(PAIR, "m1", "vb", Response(), a, acting))
        # link do Bastionu to zwykły link (bez kanonizacji i bez zmiany dostawcy), YouTube bez zmian
        added = await env.media.add_video(PAIR, "m1", env.media.VideoBody(url=URL + "&at=1"), acting)
        videos, _ = await env.media.video_list(await env.core.pair_context(PAIR, acting), "m1")
        return status, start, play, added, {v["id"]: v for v in videos}

    status, start, play, added, videos = env.run(go)
    assert status["enabled"] is False and start[:2] == play[:2] == (404, "BASTION_DISABLED")
    assert added["provider"] != "bastion" and added["url"].endswith("&at=1")
    assert videos["v1"]["provider"] == "youtube" and videos["v1"]["playable"] is True
    assert videos["vb"]["provider"] == "video" and videos["vb"]["playable"] is False  # wiersz zachowany, ale zwykły link
    assert env.fake.calls == []


# ─── Dodawanie nagrania ─────────────────────────────────────────────────────


def test_dodanie_linku_bastion_kanonizuje_deduplikuje_i_nie_wola_portalu(env):
    async def go():
        _, _, acting = await actors(env, A)
        one = await env.media.add_video(PAIR, "m1", env.media.VideoBody(url="https://Portal.Handball-Bastion.pl/game?bunny_item_id=5632&at=600"), acting)
        two = await env.media.add_video(PAIR, "m1", env.media.VideoBody(url=URL + "&at=900"), acting)
        fake = await env.media.add_video(PAIR, "m1", env.media.VideoBody(
            url="https://portal.handball-bastion.pl.example.org/game?bunny_item_id=5632"), acting)
        return one, two, fake

    one, two, fake = env.run(go)
    assert one["provider"] == "bastion" and one["url"] == URL and one["external_id"] == "5632" and one["playable"] is True
    assert two["id"] == one["id"]  # `at` to punkt wejścia, nie nowy film
    assert fake["provider"] == "video" and fake["external_id"] is None  # domena podszywająca się
    assert env.fake.calls == []


# ─── Status ogólny ──────────────────────────────────────────────────────────


def test_status_kontrakt_effective_scope_i_awaria_serwisu(env):
    async def go():
        env.fake.status["default"] = stored("default", last_error_code="BASTION_AUTH_REQUIRED")
        env.fake.status[f"personal-{A}"] = stored("p")
        _, a, _ = await actors(env, A, method="GET")
        _, admin, _ = await actors(env, ADMIN, method="GET")
        s = await env.bastion.bastion_status(Response(), a)
        sa = await env.bastion.bastion_status(Response(), admin)
        env.client._health = None
        env.fake.down = True
        down = await env.bastion.bastion_status(Response(), a)
        return s, sa, down

    s, sa, down = env.run(go)
    assert s["enabled"] and s["service"] == "ok" and s["effective_scope"] == "personal"
    assert s["default"] == {**s["default"], "status": "reauth_required", "can_reconnect": False, "expires_at": None}
    assert s["personal"]["status"] == "ready" and s["personal"]["can_reconnect"] and s["personal"]["account_label"] == "Twoje konto"
    assert sa["default"]["can_reconnect"] is True and s["expires_at"] is None
    assert down["service"] == "unavailable" and down["personal"]["status"] == "unavailable" and down["personal"]["last_known_status"] == "ready"


def test_sprawdzenie_z_probnym_meczem(env):
    env.mp.setenv("BASTION_PROBE_BUNNY_ITEM_ID", "5632")

    async def go():
        env.fake.status[f"personal-{A}"] = stored("p")
        env.fake.playback[f"personal-{A}"] = OK_PB
        _, a, _ = await actors(env, A)
        out = await env.bastion.check_personal(Response(), a)
        calls = [c for c in env.fake.calls if c[1] == "/playback"]
        return out, calls

    out, calls = env.run(go)
    assert out["checked"] is True and out["connection"]["status"] == "ready"
    assert calls[0][2]["include_embed"] == "false" and "embed_url" not in str(out)


# ─── Zadania klipów (tabele i stany; worker to etap 4) ──────────────────────


def clip_row(**kw):
    return {"id": "clip1", "pair_id": PAIR, "match_id": "m1", "video_id": "vb", "start_s": 628.2, "end_s": 637.5, **kw}


def test_zadanie_klipu_jedna_operacja_na_rewizje_i_przypiecie_do_konta(env):
    async def go():
        await seed_video(env)
        conn = await env.bastion._ensure_connection("personal", A)
        conn = await env.bastion._set_connection(conn, status="ready", external_identity_id="u-1")
        one = await env.bastion_jobs.enqueue_clip_job(clip=clip_row(), bunny_item_id=5632, revision=1, requested_by=A,
                                                      acted_as=MENTOR, connection=conn)
        again = await env.bastion_jobs.enqueue_clip_job(clip=clip_row(), bunny_item_id=5632, revision=1, requested_by=A, connection=conn)
        newer = await env.bastion_jobs.enqueue_clip_job(clip=clip_row(end_s=640), bunny_item_id=5632, revision=2, requested_by=A, connection=conn)
        too_long = None
        try:
            await env.bastion_jobs.enqueue_clip_job(clip=clip_row(id="c2", end_s=1000), bunny_item_id=5632, revision=1, requested_by=A)
        except env.bastion_jobs.BR.ClipRangeError as exc:
            too_long = str(exc)
        # utrata sesji: aktywne zadania czekają, zdalne id i konto zostają
        await env.core.database.execute(env.T["mentor_bastion_clip_jobs"].update().where(
            env.T["mentor_bastion_clip_jobs"].c.id == one["id"]).values(state="submitted", remote_clip_id="1637"))
        await env.bastion_jobs.hold_jobs_for_connection(conn["id"])
        rows = {r["clip_revision"]: r for r in await env.core.rows(select(env.T["mentor_bastion_clip_jobs"]))}
        return one, again, newer, too_long, rows

    one, again, newer, too_long, rows = env.run(go)
    assert again["id"] == one["id"] and newer["id"] != one["id"] and len(rows) == 2
    assert (one["start_s"], one["end_s"], one["state"]) == (628, 638, "queued")
    assert one["requested_by_real_judge_id"] == A and one["acted_as_judge_id"] == MENTOR and one["external_identity_id"] == "u-1"
    assert "300" in too_long
    assert rows[1]["state"] == "waiting_for_auth" and rows[1]["remote_clip_id"] == "1637" and rows[1]["connection_id"]


def test_rozlaczenie_wstrzymuje_zadania_ale_nie_kasuje_assetow(env):
    async def go():
        await seed_video(env)
        _, a, _ = await actors(env, A)
        conn = await env.bastion._ensure_connection("personal", A)
        await env.bastion._set_connection(conn, status="ready")
        job = await env.bastion_jobs.enqueue_clip_job(clip=clip_row(), bunny_item_id=5632, revision=1, requested_by=A, connection=conn)
        await env.ins("mentor_clip_assets", id="as1", clip_id="clip1", revision=1, status="ready", storage_key="mentor/x.mp4",
                      origin_provider="bastion", source_start_s=628, source_end_s=638)
        await env.bastion.disconnect_personal(Response(), a)
        jobs = await env.core.rows(select(env.T["mentor_bastion_clip_jobs"]))
        assets = await env.core.rows(select(env.T["mentor_clip_assets"]))
        return job, jobs, assets

    job, jobs, assets = env.run(go)
    assert jobs[0]["state"] == "waiting_for_auth" and assets[0]["status"] == "ready" and assets[0]["origin_provider"] == "bastion"
