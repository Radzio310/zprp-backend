"""Handball Bastion w Mentorze - czyste reguły i klient connectora (bez bazy)."""

import asyncio

import httpx
import pytest

from app import mentor_bastion_rules as BR
from app.mentor_bastion_client import Breaker, ConnectorClient, ConnectorUnavailable

OK = "https://portal.handball-bastion.pl/game?bunny_item_id=5632"


@pytest.mark.parametrize("url,expected", [
    (OK, 5632),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=5632&at=600", 5632),
    ("https://PORTAL.Handball-Bastion.pl/game/?bunny_item_id=7", 7),
    ("https://portal.handball-bastion.pl/game?at=1&bunny_item_id=9", 9),
    # błędny identyfikator
    ("https://portal.handball-bastion.pl/game?bunny_item_id=0", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=-3", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=abc", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=01", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=1&bunny_item_id=2", None),
    ("https://portal.handball-bastion.pl/game", None),
    # podszywanie się domen
    ("https://portal.handball-bastion.pl.example.org/game?bunny_item_id=1", None),
    ("https://evilportal.handball-bastion.pl/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl.evil.com/game?bunny_item_id=1", None),
    ("https://handball-bastion.pl/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl./game?bunny_item_id=1", None),
    ("https://example.org/game?bunny_item_id=1&u=portal.handball-bastion.pl", None),
    # userinfo, port, schemat, backslash
    ("https://user@portal.handball-bastion.pl/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl@evil.com/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl\\@evil.com/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl:8443/game?bunny_item_id=1", None),
    ("http://portal.handball-bastion.pl/game?bunny_item_id=1", None),
    ("javascript://portal.handball-bastion.pl/game?bunny_item_id=1", None),
    # inna ścieżka / redirect / klip
    ("https://portal.handball-bastion.pl/clip?clip_id=1637", None),
    ("https://portal.handball-bastion.pl/redirect?to=/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl/game/../admin?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl/game/x?bunny_item_id=1", None),
    # sieć prywatna / IP
    ("https://127.0.0.1/game?bunny_item_id=1", None),
    ("https://10.0.0.5/game?bunny_item_id=1", None),
    ("https://[::1]/game?bunny_item_id=1", None),
    ("https://localhost/game?bunny_item_id=1", None),
    # białe znaki i śmieci
    (" https://portal.handball-bastion.pl/game?bunny_item_id=1", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=1\n", None),
    ("", None), (None, None), (123, None),
])
def test_rozpoznawanie_adresu_meczu(url, expected):
    assert BR.parse_game_url(url) == expected
    assert BR.is_bastion_url(url) is (expected is not None)


def test_adres_kanoniczny_odrzuca_at_i_smieci():
    assert BR.canonicalize(OK + "&at=600&utm=x") == OK
    assert BR.canonicalize("https://example.org/game?bunny_item_id=1") is None


def test_kontekst_powrotu_tylko_identyfikatory():
    raw = {"pair_id": "p-1", "match_id": "m1", "url": "https://evil.example/", "video_id": "https://evil", "video_s": 631.5,
           "start_s": -4, "end_s": "x"}
    assert BR.clean_return_context(raw) == {"pair_id": "p-1", "match_id": "m1", "video_s": "631.5"}
    assert BR.clean_return_context("x") == {}


def test_flagi_domyslnie_wylaczone_i_master_wylacza_reszte():
    off = BR.load_flags({})
    assert not off.enabled and not off.default_enabled and not off.personal_enabled and not off.scope_on("default")
    only_children = BR.load_flags({"BASTION_DEFAULT_ENABLED": "true", "BASTION_PERSONAL_ENABLED": "true"})
    assert not only_children.default_enabled and not only_children.personal_enabled
    on = BR.load_flags({"BASTION_ENABLED": "true", "BASTION_PERSONAL_ENABLED": "false", "BASTION_CONNECTOR_URL": "https://c/",
                        "BASTION_CONNECTOR_TOKEN": "t", "BASTION_PROBE_BUNNY_ITEM_ID": "5632"})
    assert on.enabled and on.default_enabled and not on.personal_enabled and on.configured
    assert on.connector_url == "https://c" and on.probe_bunny_item_id == 5632
    assert BR.candidate_scopes(on) == ["default"]
    assert BR.candidate_scopes(BR.load_flags({"BASTION_ENABLED": "1"})) == ["default", "personal"]


def test_klucz_polaczenia():
    assert BR.connection_key("default", "101") == "default"
    assert BR.connection_key("personal", "101") == "personal-101"


def test_werdykty_connectora_401_to_nigdy_wylogowanie():
    c = BR.classify_playback
    assert c(200, {"code": "OK", "embed_url": "x"}).kind == "ok"
    assert c(409, {"code": "BASTION_AUTH_REQUIRED"}).kind == "auth_required"
    assert c(403, {"code": "BASTION_RESOURCE_FORBIDDEN"}).kind == "forbidden"
    assert c(429, {"code": "BASTION_RATE_LIMITED"}).kind == "rate_limited"
    assert c(503, {"code": "BASTION_UNAVAILABLE"}).kind == "unavailable"
    assert c(502, {"code": "BASTION_BAD_RESPONSE"}).kind == "unavailable"
    assert c(500, {}).kind == "unavailable"
    for status in (200, 403, 409, 429, 503):
        assert BR.final_playback_error([("default", c(status, {"code": "BASTION_AUTH_REQUIRED"}))])[0] != 401


def test_koncowy_blad_priorytety():
    v = BR.PlaybackVerdict
    auth, forb, down, rate = v("auth_required", "a"), v("forbidden", "f"), v("unavailable", "u"), v("rate_limited", "r")
    assert BR.final_playback_error([("default", auth), ("personal", auth)]) == (409, "BASTION_AUTH_REQUIRED")
    assert BR.final_playback_error([("default", auth), ("personal", forb)]) == (403, "BASTION_RESOURCE_FORBIDDEN")
    assert BR.final_playback_error([("default", forb), ("personal", auth)]) == (403, "BASTION_RESOURCE_FORBIDDEN")
    assert BR.final_playback_error([("default", auth), ("personal", down)]) == (503, "BASTION_UNAVAILABLE")
    assert BR.final_playback_error([("default", rate)]) == (429, "BASTION_RATE_LIMITED")


def test_stan_polaczenia_ze_statusu_connectora():
    s = BR.connector_status_to_state
    assert s({"status": "unconfigured"}) == "unconfigured"
    assert s({"status": "stored", "last_error_code": None}) == "ready"
    assert s({"status": "stored", "last_error_code": "BASTION_AUTH_REQUIRED"}) == "reauth_required"
    assert s({}) == "unconfigured"


def test_zakres_klipu_calkowite_sekundy_na_zewnatrz():
    assert BR.bastion_clip_range(628, 638) == {"start_s": 628, "end_s": 638, "duration_s": 10, "rounded": False}
    r = BR.bastion_clip_range(628.4, 637.2)
    assert (r["start_s"], r["end_s"], r["rounded"]) == (628, 638, True)
    assert BR.bastion_clip_range(0, 2)["duration_s"] == 2
    assert BR.bastion_clip_range(10, 310)["duration_s"] == 300
    for bad in ((10, 11), (10, 311), (10.2, 10.9), (-1, 5), (float("nan"), 5)):
        with pytest.raises(BR.ClipRangeError):
            BR.bastion_clip_range(*bad)


def test_odcisk_zlecenia_i_przejscia_stanow():
    a = BR.clip_fingerprint(clip_id="c", revision=1, bunny_item_id=5, start_s=1, end_s=9)
    assert a == BR.clip_fingerprint(clip_id="c", revision=1, bunny_item_id=5, start_s=1, end_s=9)
    assert a != BR.clip_fingerprint(clip_id="c", revision=2, bunny_item_id=5, start_s=1, end_s=9)
    assert BR.can_transition("queued", "submitting") and BR.can_transition("submitted", "waiting_for_auth")
    assert not BR.can_transition("ready", "queued") and not BR.can_transition("queued", "ready")
    # niepewny wynik POST: tylko uzgodnienie, nie ślepe ponowienie
    assert not BR.can_transition("needs_reconciliation", "submitting")
    assert set(BR.JOB_TRANSITIONS) == set(BR.JOB_STATES)


def test_wznowienie_tylko_tym_samym_kontem():
    assert BR.may_resume_with("u1", "u1") and not BR.may_resume_with("u1", "u2")
    assert BR.may_resume_with(None, "u2") and BR.may_resume_with("u1", None)


# ─── Klient connectora ──────────────────────────────────────────────────────


def run(coro):
    return asyncio.run(coro)


def make_client(handler, **kw):
    return ConnectorClient("http://connector", "tok", transport=httpx.MockTransport(handler), **kw)


def test_klient_wysyla_token_i_parametry():
    seen = {}

    def handler(request):
        seen.update(auth=request.headers.get("authorization"), url=str(request.url))
        return httpx.Response(200, json={"code": "OK"})

    async def go():
        c = make_client(handler)
        try:
            return await c.playback("personal", "101", 5632, include_embed=False)
        finally:
            await c.aclose()

    reply = run(go())
    assert reply.status == 200 and seen["auth"] == "Bearer tok"
    assert "scope=personal" in seen["url"] and "judge_id=101" in seen["url"] and "bunny_item_id=5632" in seen["url"]
    assert "include_embed=false" in seen["url"]


def test_klient_4xx_connectora_to_odpowiedz_a_siec_i_5xx_to_niedostepnosc():
    def handler(request):
        path = request.url.path
        if path == "/a":
            return httpx.Response(409, json={"code": "BASTION_AUTH_REQUIRED"})
        if path == "/b":
            return httpx.Response(503, json={"code": "BASTION_UNAVAILABLE"})
        if path == "/c":
            return httpx.Response(500, text="boom")
        if path == "/d":
            return httpx.Response(401, json={"detail": "unauthorized"})
        raise httpx.ConnectTimeout("t")

    async def go(path):
        c = make_client(handler, breaker=Breaker(threshold=99))
        try:
            return await c.request("GET", path)
        finally:
            await c.aclose()

    assert run(go("/a")).status == 409
    assert run(go("/b")).body["code"] == "BASTION_UNAVAILABLE"
    for path in ("/c", "/d", "/e"):
        with pytest.raises(ConnectorUnavailable):
            run(go(path))


def test_bezpiecznik_otwiera_sie_i_wraca_po_czasie():
    now = [0.0]
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ConnectError("down")

    async def go():
        c = make_client(handler, breaker=Breaker(threshold=2, cooldown_s=20, clock=lambda: now[0]))
        try:
            for _ in range(2):
                with pytest.raises(ConnectorUnavailable):
                    await c.request("GET", "/x")
            n = len(calls)
            with pytest.raises(ConnectorUnavailable) as exc:
                await c.request("GET", "/x")
            assert exc.value.reason == "circuit_open" and len(calls) == n  # bez ruchu po sieci
            now[0] = 25.0  # po schłodzeniu jedna próba
            with pytest.raises(ConnectorUnavailable):
                await c.request("GET", "/x")
            assert len(calls) == n + 1
        finally:
            await c.aclose()

    run(go())


def test_cache_zdrowia():
    now = [0.0]
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    async def go():
        c = make_client(handler, clock=lambda: now[0], health_ttl_s=10)
        try:
            assert await c.healthy() and await c.healthy()
            assert calls == ["/health"]
            now[0] = 11.0
            assert await c.healthy()
            assert calls == ["/health", "/health"]
        finally:
            await c.aclose()

    run(go())
