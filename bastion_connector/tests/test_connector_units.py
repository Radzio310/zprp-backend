import base64
import json
import os

import pytest

from connector import crypto, tickets
from connector.bastion import classify, embed_expiry
from connector.store import StateStore, conn_key_for, cookie_summary, filter_state_to_host
from connector.urlrules import embed_url_ok, is_blocked_navigation, origin_allowed, parse_game_url


def key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


# ---------- szyfrowanie ----------
def test_crypto_roundtrip_and_aad():
    k = crypto.parse_key(key())
    blob = crypto.encrypt(k, b"tajne", b"default")
    assert b"tajne" not in blob
    assert crypto.decrypt([k], blob, b"default")[0] == b"tajne"
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt([k], blob, b"personal-x")  # AAD: stan innego polaczenia


def test_crypto_wrong_key_and_tamper_and_bad_key():
    k1, k2 = crypto.parse_key(key()), crypto.parse_key(key())
    blob = crypto.encrypt(k1, b"x" * 50, b"a")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt([k2], blob, b"a")
    bad = bytearray(blob)
    bad[-1] ^= 1
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt([k1], bytes(bad), b"a")
    for v in ("", "abc", base64.urlsafe_b64encode(b"short").decode()):
        with pytest.raises(crypto.CryptoError):
            crypto.parse_key(v)


def test_store_roundtrip_restart_rotation_and_no_plaintext(tmp_path):
    k1, k2 = key(), key()
    st = StateStore(str(tmp_path), k1)
    state = {"cookies": [{"name": "sid", "value": "SEKRET123", "domain": "portal.handball-bastion.pl", "expires": -1}], "origins": []}
    st.save("default", state, {"generation": 1})
    raw = (tmp_path / "states" / "default.enc").read_bytes()
    assert b"SEKRET123" not in raw and b"sid" not in raw
    # "restart": nowa instancja ze starym kluczem
    assert StateStore(str(tmp_path), k1).load("default") == (state, {"generation": 1})
    # rotacja: nowy klucz + stary jako poprzedni -> odczyt dziala i plik jest przepisany nowym
    rot = StateStore(str(tmp_path), k2, [k1])
    assert rot.load("default")[0] == state
    assert StateStore(str(tmp_path), k2).load("default")[0] == state
    # bez starego klucza po rotacji: blad, nie cichy brak
    with pytest.raises(crypto.CryptoError):
        StateStore(str(tmp_path), key()).load("default")


def test_store_isolation_between_connections(tmp_path):
    st = StateStore(str(tmp_path), key())
    st.save("personal-a", {"cookies": [], "origins": []}, {"generation": 1})
    # plik osoby A podstawiony pod osobe B nie odszyfruje sie (AAD)
    (tmp_path / "states" / "personal-b.enc").write_bytes((tmp_path / "states" / "personal-a.enc").read_bytes())
    with pytest.raises(crypto.CryptoError):
        st.load("personal-b")
    assert st.load("personal-c") is None
    assert st.delete("personal-a") and st.load("personal-a") is None


def test_conn_key_rules():
    assert conn_key_for("default", None) == "default"
    assert conn_key_for("personal", "j_1-A") == "personal-j_1-A"
    for bad in ("../x", "a/b", "", "a" * 65):
        with pytest.raises(ValueError):
            conn_key_for("personal", bad)
    with pytest.raises(ValueError):
        conn_key_for("other", "a")


def test_filter_state_keeps_only_portal():
    st = {"cookies": [
        {"name": "p", "domain": "portal.handball-bastion.pl", "expires": -1},
        {"name": "q", "domain": ".handball-bastion.pl", "expires": 1900000000},
        {"name": "d", "domain": ".discord.com", "expires": 1900000000},
        {"name": "t", "domain": ".pl", "expires": -1},
    ], "origins": [{"origin": "https://portal.handball-bastion.pl", "localStorage": []},
                   {"origin": "https://discord.com", "localStorage": []}]}
    f = filter_state_to_host(st, "portal.handball-bastion.pl")
    assert [c["name"] for c in f["cookies"]] == ["p", "q"]
    assert len(f["origins"]) == 1
    s = cookie_summary(f)
    assert s == {"count": 2, "session_only": 1, "earliest_expiry": 1900000000, "latest_expiry": 1900000000}


# ---------- bilety ----------
SECRET = "s" * 40


def test_ticket_ok_single_use_and_binding():
    reg = tickets.TicketRegistry()
    t = tickets.mint(SECRET, "j1", "att1", 60, now=1000)
    with pytest.raises(tickets.TicketError):
        reg.consume(SECRET, t, "att2", "j1", now=1001)  # inna proba
    with pytest.raises(tickets.TicketError):
        reg.consume(SECRET, t, "att1", "j2", now=1001)  # inny sedzia
    assert reg.consume(SECRET, t, "att1", "j1", now=1001)["a"] == "att1"
    with pytest.raises(tickets.TicketError, match="uzyty"):
        reg.consume(SECRET, t, "att1", "j1", now=1002)


def test_ticket_expiry_signature_and_garbage():
    reg = tickets.TicketRegistry()
    t = tickets.mint(SECRET, "j1", "a", 60, now=1000)
    with pytest.raises(tickets.TicketError, match="wygasl"):
        reg.consume(SECRET, t, "a", "j1", now=1061)
    with pytest.raises(tickets.TicketError):
        reg.consume("x" * 40, t, "a", "j1", now=1001)
    payload, sig = t.split(".")
    forged = base64.urlsafe_b64encode(json.dumps({"j": "j1", "a": "a", "n": "1", "e": 9999999999}).encode()).decode().rstrip("=")
    with pytest.raises(tickets.TicketError):
        reg.consume(SECRET, forged + "." + sig, "a", "j1", now=1001)
    for g in ("", "abc", "a.b", "....", "é.é"):
        with pytest.raises(tickets.TicketError):
            reg.consume(SECRET, g, "a", "j1", now=1001)
    with pytest.raises(tickets.TicketError):
        tickets.mint("krotki", "j", "a", 60)


# ---------- walidacja URL ----------
@pytest.mark.parametrize("url,expected", [
    ("https://portal.handball-bastion.pl/game?bunny_item_id=5632", 5632),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=5632&at=600", 5632),
    ("https://PORTAL.handball-bastion.pl/game/?bunny_item_id=7", 7),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=0", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=-3", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=abc", None),
    ("https://portal.handball-bastion.pl/game", None),
    ("https://portal.handball-bastion.pl/game?bunny_item_id=1&bunny_item_id=2", None),
    ("https://portal.handball-bastion.pl.example.org/game?bunny_item_id=5", None),
    ("https://evilportal.handball-bastion.pl/game?bunny_item_id=5", None),
    ("https://user:pw@portal.handball-bastion.pl/game?bunny_item_id=5", None),
    ("https://portal.handball-bastion.pl@evil.com/game?bunny_item_id=5", None),
    ("https://portal.handball-bastion.pl:8443/game?bunny_item_id=5", None),
    ("http://portal.handball-bastion.pl/game?bunny_item_id=5", None),
    ("https://portal.handball-bastion.pl/clip?bunny_item_id=5", None),
    ("https://127.0.0.1/game?bunny_item_id=5", None),
    ("javascript:alert(1)", None),
    ("", None),
])
def test_parse_game_url(url, expected):
    assert parse_game_url(url) == expected


@pytest.mark.parametrize("url,ok", [
    ("https://iframe.mediadelivery.net/embed/1/abc?token=x&expires=1", True),
    ("https://mediadelivery.net/embed", True),
    ("https://evilmediadelivery.net/embed", False),
    ("https://mediadelivery.net.evil.com/embed", False),
    ("http://iframe.mediadelivery.net/embed", False),
    ("https://iframe.mediadelivery.net:444/embed", False),
    ("https://u@iframe.mediadelivery.net/embed", False),
    ("https://127.0.0.1/embed", False),
    ("", False),
])
def test_embed_url_ok(url, ok):
    assert embed_url_ok(url, ["mediadelivery.net"]) is ok


def test_origin_and_navigation_rules():
    allowed = ["https://bazapodreka.app", "http://127.0.0.1:8770/"]
    assert origin_allowed("https://bazapodreka.app", allowed)
    assert origin_allowed("http://127.0.0.1:8770", allowed)
    assert not origin_allowed(None, allowed)
    assert not origin_allowed("https://bazapodreka.app.evil.com", allowed)
    assert not origin_allowed("https://bazapodreka.app", [])
    for u in ("http://localhost/x", "http://127.0.0.1/", "http://10.0.0.5/", "http://169.254.169.254/latest",
              "file:///etc/passwd", "ftp://x/", "http://[::1]/", "http://foo.internal/"):
        assert is_blocked_navigation(u), u
    for u in ("https://discord.com/login", "https://portal.handball-bastion.pl/", "about:blank"):
        assert not is_blocked_navigation(u), u


# ---------- mapowanie game-context ----------
def test_classify_codes_never_confuse_401_and_403():
    sfx = ["mediadelivery.net"]
    assert classify(401, None, sfx).code == "BASTION_AUTH_REQUIRED"
    assert classify(403, None, sfx).code == "BASTION_RESOURCE_FORBIDDEN"
    assert classify(429, None, sfx).code == "BASTION_RATE_LIMITED"
    assert classify(502, None, sfx).code == "BASTION_UNAVAILABLE"
    assert classify(200, [1], sfx).code == "BASTION_BAD_RESPONSE"
    ok = classify(200, {"video": {"embed_url": "https://iframe.mediadelivery.net/e?expires=1900000000", "state": "ready"}}, sfx)
    assert ok.code == "OK" and ok.expires_at == 1900000000 and ok.video_state == "ready"
    bad = classify(200, {"video": {"embed_url": "https://evil.example/e"}}, sfx)
    assert bad.code == "BASTION_EMBED_HOST_NOT_ALLOWED" and bad.embed_url is None


def test_embed_expiry_unknown_is_none():
    assert embed_expiry("https://x.mediadelivery.net/e?token=abc") is None
    assert embed_expiry("https://x.mediadelivery.net/e?expires=12") is None
    assert embed_expiry("https://x.mediadelivery.net/e?token_expires=1900000000") == 1900000000


def test_no_webauthn_script_in_real_chromium():
    """Przegladarka serwerowa uczciwie zglasza brak WebAuthn (MFA Discorda przechodzi na kod)."""
    sync_api = pytest.importorskip("playwright.sync_api")
    from connector.service import NO_WEBAUTHN_JS
    with sync_api.sync_playwright() as p:
        try:
            exe = os.environ.get("BASTION_CHROMIUM_PATH")
            browser = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"brak Chromium: {type(e).__name__}")
        try:
            ctx = browser.new_context()
            ctx.add_init_script(NO_WEBAUTHN_JS)
            page = ctx.new_page()
            # bezpieczny kontekst (https), bo navigator.credentials istnieje tylko w nim
            ctx.route("https://bastion.test/**", lambda r: r.fulfill(body="<p>x</p>", content_type="text/html"))
            page.goto("https://bastion.test/")
            res = page.evaluate("""async () => {
                const out = {pkc: typeof window.PublicKeyCredential, inWin: 'PublicKeyCredential' in window && !!window.PublicKeyCredential};
                for (const m of ['get', 'create']) {
                    try { await navigator.credentials[m]({publicKey: {challenge: new Uint8Array(8)}}); out[m] = 'resolved'; }
                    catch (e) { out[m] = e.name; }
                }
                return out;
            }""")
        finally:
            browser.close()
    assert res == {"pkc": "undefined", "inWin": False, "get": "NotAllowedError", "create": "NotAllowedError"}


# ---------- wznowienie proby i przejecie widoku (handoff 12: kilka kart oglada te sama probe) ----------
class _FakeCdp:
    def __init__(self):
        self.sent = []

    async def send(self, method, params=None):
        self.sent.append(method)


class _FakeWs:
    def __init__(self):
        self.msgs, self.closed = [], None

    async def send_json(self, m):
        self.msgs.append(m)

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


def _svc(tmp_path):
    from connector.config import Settings
    from connector.service import Service
    s = Settings(secrets_key=key(), ticket_secret="t" * 40, data_dir=str(tmp_path), probe_bunny_item_id=5632)
    return Service(s)


def _active(svc, judge="tester1", scope="default"):
    import time as _t
    from connector.service import Attempt
    a = Attempt(id="att1", conn_key=conn_key_for(scope, judge), scope=scope, judge_id=judge, probe_item_id=5632,
                created=_t.time(), expires=_t.time() + 600, status="waiting_for_user")
    a.cdp = _FakeCdp()
    svc.attempts[a.id] = a
    return a


async def test_same_person_resumes_attempt_with_fresh_ticket(tmp_path):
    svc = _svc(tmp_path)
    a = _active(svc)
    got, ticket, resumed = await svc.create_attempt("default", "tester1", 5632)
    assert got is a and resumed is True and len(svc.attempts) == 1
    svc.registry.consume("t" * 40, ticket, a.id, "tester1")  # bilet wazny dla tej proby i tej osoby


async def test_other_person_still_gets_409(tmp_path):
    from connector.service import ConnectorError
    svc = _svc(tmp_path)
    _active(svc, judge="tester1")
    with pytest.raises(ConnectorError) as e:
        await svc.create_attempt("default", "osoba2", 5632)
    assert e.value.code == "LOGIN_ALREADY_ACTIVE" and e.value.status == 409


async def test_new_viewer_takes_over_and_old_closes_cleanly(tmp_path):
    from connector.service import TAKEOVER_CODE
    svc = _svc(tmp_path)
    a = _active(svc)
    old, new = _FakeWs(), _FakeWs()
    await svc.attach_viewer(a, old)
    await svc.attach_viewer(a, new)
    assert a.viewer is new
    assert old.closed == (TAKEOVER_CODE, "Widok przejęła inna karta") and {"type": "takeover"} in old.msgs
    assert a.cdp.sent[-2:] == ["Page.stopScreencast", "Page.startScreencast"]
    await svc.detach_viewer(a, old)  # zamkniecie starego widoku nie odpina nowego
    assert a.viewer is new


# ---------- przekaznik klawiatury: tekst tylko przez insertText ----------
def _typed(events):
    from connector.service import key_to_cdp
    calls = [c for m in events for c in key_to_cdp(m)]
    assert not any(p.get("text") for meth, p in calls if meth == "Input.dispatchKeyEvent" and p["key"] != "Enter"), "znak wpisany zdarzeniem klawisza"
    return "".join(p["text"] for meth, p in calls if meth == "Input.insertText"), calls


def _press(key, code, mod=0, **kw):
    # tak jak wysyla widok: down + up, modyfikatory jako osobne klawisze
    return [{"t": "key", "a": "down", "key": key, "code": code, "mod": mod, **kw},
            {"t": "key", "a": "up", "key": key, "code": code, "mod": mod, **kw}]


def test_keyboard_polish_and_special_chars_exact():
    ev = []
    ev += _press("Shift", "ShiftLeft", 8)
    ev += _press("A", "KeyA", 8)                      # Shift + a
    ev += _press("ą", "KeyA", 3)                      # AltGr (Windows: Ctrl+Alt) + a
    ev += _press("!", "Digit1", 8)
    ev += _press("@", "Digit2", 8)
    ev += _press("#", "Digit3", 8)
    ev += _press("Ł", "KeyL", 11)                     # Shift + AltGr + l
    ev += _press("_", "Minus", 8)
    ev += _press("ź", "KeyX", 0, altgr=True)          # AltGr zgloszony jawnie
    text, _ = _typed(ev)
    assert text == "Aą!@#Ł_ź"


def test_keyboard_text_message_and_specials():
    text, calls = _typed([{"t": "text", "text": "Aą!@#Ł_ź"}] + _press("Backspace", "Backspace") + _press("Enter", "Enter"))
    assert text == "Aą!@#Ł_ź"
    kinds = [(p["type"], p["key"]) for m, p in calls if m == "Input.dispatchKeyEvent"]
    assert kinds == [("rawKeyDown", "Backspace"), ("keyUp", "Backspace"), ("keyDown", "Enter"), ("keyUp", "Enter")]


def test_keyboard_ctrl_shortcut_is_key_event_not_text():
    text, calls = _typed(_press("a", "KeyA", 2))
    assert text == "" and calls[0][1]["type"] == "rawKeyDown" and calls[0][1]["windowsVirtualKeyCode"] == 65


# ---------- P8: klip i pobranie ----------
import httpx  # noqa: E402

from connector import clips  # noqa: E402


@pytest.mark.parametrize("s,e", [(628, 638), (0, 2), (10, 310)])
def test_range_ok(s, e):
    assert clips.validate_range(s, e) == (s, e)


@pytest.mark.parametrize("s,e", [(10, 11), (10, 10), (20, 10), (0, 301), (-1, 5), (628.5, 640), (628, "640"), (True, 5), (0, 99999999)])
def test_range_rejected(s, e):
    with pytest.raises(clips.ClipError) as ex:
        clips.validate_range(s, e)
    assert ex.value.code == "BAD_RANGE"


def test_submit_body_is_neutral_private_and_explicit():
    b = clips.build_submit_body(5632, 628, 638)
    c = b["clips"][0]
    assert b["bunny_item_id"] == 5632 and len(b["clips"]) == 1
    assert (c["startTime"], c["endTime"]) == ("10:28", "10:38")
    assert c["audience_group_id"] is None and "audience_crew" not in c and c["privateId"] is None
    assert c["comment"] == "BAZA test P8" and c["situationType"] == "NORMAL" and c["videoTags"] == ["PLAY_ON"]
    assert clips.clock(3725) == "1:02:05" and clips.clock(59) == "0:59"
    assert clips.sent_summary(628, 638)["duration_s"] == 10


def test_download_host_allowlist():
    sfx = clips.DEFAULT_DOWNLOAD_SUFFIXES
    assert clips.download_host_ok("https://vz-abc.b-cdn.net/x/play.mp4?token=1", sfx)
    assert clips.download_host_ok("https://b-cdn.net/x", sfx)
    for bad in ("http://x.b-cdn.net/a", "https://evilb-cdn.net/a", "https://b-cdn.net.evil.com/a",
                "https://user@x.b-cdn.net/a", "https://x.b-cdn.net:8443/a", "https://10.0.0.5/a",
                "https://127.0.0.1/a", "https://[::1]/a", "https://portal.handball-bastion.pl/a", "ftp://x.b-cdn.net/a", ""):
        assert not clips.download_host_ok(bad, sfx), bad


def test_ip_public():
    assert clips.ip_is_public("8.8.8.8")
    for ip in ("10.1.2.3", "127.0.0.1", "169.254.169.254", "192.168.0.1", "::1", "0.0.0.0", "fe80::1"):
        assert not clips.ip_is_public(ip), ip


async def _public(_h):
    return ["93.184.216.34"]


async def _private(_h):
    return []


def _kw(tmp_path, **o):
    return dict(suffixes=clips.DEFAULT_DOWNLOAD_SUFFIXES, max_bytes=1000, dest_dir=str(tmp_path), resolver=_public, **o)


async def test_download_sends_no_cookies_or_auth_and_hashes(tmp_path):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=b"abc" * 10, headers={"content-type": "video/mp4"})

    d = await clips.safe_download("https://x.b-cdn.net/f.mp4?t=1", transport=httpx.MockTransport(handler), **_kw(tmp_path))
    import hashlib
    assert d.sha256 == hashlib.sha256(b"abc" * 10).hexdigest() and d.size == 30
    assert len(seen) == 1
    assert "cookie" not in seen[0].headers and "authorization" not in seen[0].headers
    assert open(d.path, "rb").read() == b"abc" * 10


async def test_download_redirect_chain_is_revalidated_and_clean(tmp_path):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["host"])
        assert "cookie" not in req.headers
        if req.headers["host"] == "a.b-cdn.net":
            return httpx.Response(302, headers={"location": "https://evil.example.com/steal"})
        return httpx.Response(200, content=b"x")

    with pytest.raises(clips.ClipError) as ex:
        await clips.safe_download("https://a.b-cdn.net/f", transport=httpx.MockTransport(handler), **_kw(tmp_path))
    assert ex.value.code == "DOWNLOAD_HOST_NOT_ALLOWED" and seen == ["a.b-cdn.net"]  # na zly host nie poszlo zadne zapytanie


async def test_download_allowed_redirect_followed_and_loops_cut(tmp_path):
    def ok(req):
        return httpx.Response(302, headers={"location": "https://b.b-cdn.net/z"}) if req.headers["host"] == "a.b-cdn.net" else httpx.Response(200, content=b"x")

    d = await clips.safe_download("https://a.b-cdn.net/f", transport=httpx.MockTransport(ok), **_kw(tmp_path))
    assert d.final_host == "b.b-cdn.net" and d.hops == 1
    loop = httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "https://a.b-cdn.net/f"}))
    with pytest.raises(clips.ClipError) as ex:
        await clips.safe_download("https://a.b-cdn.net/f", transport=loop, **_kw(tmp_path))
    assert ex.value.code == "DOWNLOAD_TOO_MANY_REDIRECTS"


async def test_download_rejects_private_address_and_oversize_and_cleans(tmp_path):
    t = httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 5000))
    with pytest.raises(clips.ClipError) as ex:
        await clips.safe_download("https://a.b-cdn.net/f", transport=t, **{**_kw(tmp_path), "resolver": _private})
    assert ex.value.code == "DOWNLOAD_ADDRESS_NOT_PUBLIC"
    with pytest.raises(clips.ClipError) as ex:
        await clips.safe_download("https://a.b-cdn.net/f", transport=t, **_kw(tmp_path))
    assert ex.value.code == "DOWNLOAD_TOO_LARGE"
    assert list(tmp_path.iterdir()) == []  # zadnych resztek


def test_classify_submit_never_retries_uncertain():
    ok = clips.classify_submit(200, {"clip_ids": [77], "clip_codes": ["ABC"]})
    assert (ok.state, ok.remote_id, ok.clip_code) == ("submitted", "77", "ABC")
    for status in (None, 500, 502, 504, 408):
        r = clips.classify_submit(status, None)
        assert r.state == "needs_reconciliation", status
    assert clips.classify_submit(200, {"clip_ids": []}).state == "needs_reconciliation"
    assert clips.classify_submit(200, {"clip_ids": [1, 2]}).state == "needs_reconciliation"
    assert clips.classify_submit(422, {"message": "x"}).state == "failed"
    assert clips.classify_submit(401, None).code == "BASTION_AUTH_REQUIRED"


def test_parse_ffprobe():
    d = {"format": {"format_name": "mov,mp4", "duration": "10.4"},
         "streams": [{"codec_type": "video", "codec_name": "h264", "width": 1280, "height": 720},
                     {"codec_type": "audio", "codec_name": "aac"}]}
    r = clips.parse_ffprobe(d, 10)
    assert r["has_video"] and r["width"] == 1280 and r["video_codec"] == "h264" and r["delta_s"] == 0.4
    assert not clips.parse_ffprobe({"streams": [{"codec_type": "audio"}]})["has_video"]


class _FakeResp:
    def __init__(self, status, body=None):
        self.status, self._b = status, body

    async def json(self):
        return self._b


class _FakeReq:
    def __init__(self, post):
        self.post_fn, self.posts = post, 0

    async def post(self, *a, **k):
        self.posts += 1
        return await self.post_fn()

    async def storage_state(self):
        return {"cookies": [], "origins": []}

    async def dispose(self):
        pass


async def _noop(*a, **k):
    return None


def _clipsvc(tmp_path, post):
    from connector.config import Settings
    from connector.service import Service
    s = Service(Settings(data_dir=str(tmp_path), secrets_key=key()))
    req = _FakeReq(post)

    async def fake(_key):
        return req, {"cookies": [], "origins": []}, {}

    s._with_state_request = fake
    s._persist_if_changed = _noop
    return s, req


async def test_timeout_after_post_is_needs_reconciliation_and_no_resubmit(tmp_path):
    async def boom():
        raise TimeoutError("timeout")

    s, req = _clipsvc(tmp_path, boom)
    rec, http = await s.clip_submit("default", "t1", 5632, 628, 638)
    assert http == 202 and rec["state"] == "needs_reconciliation" and rec["sent"]["startTime"] == "10:28"
    from connector.service import ConnectorError
    with pytest.raises(ConnectorError) as ex:  # ponowna proba tego samego: zero drugiego POST
        await s.clip_submit("default", "t1", 5632, 628, 638)
    assert ex.value.code == "CLIP_ALREADY_SUBMITTED" and req.posts == 1
    # restart: ksiega pamieta, wciaz zero ponowien
    s2, req2 = _clipsvc(tmp_path, boom)
    with pytest.raises(ConnectorError):
        await s2.clip_submit("default", "t1", 5632, 628, 638)
    assert req2.posts == 0


async def test_success_and_rejected_can_retry(tmp_path):
    async def good():
        return _FakeResp(200, {"clip_ids": [4321], "clip_codes": ["Q1"]})

    s, req = _clipsvc(tmp_path, good)
    rec, http = await s.clip_submit("default", "t1", 5632, 628, 638)
    assert http == 200 and rec["remote_id"] == "4321" and s._known_clip("4321")["clip_code"] == "Q1"

    async def bad():
        return _FakeResp(422, {"message": "nie"})

    s2, _ = _clipsvc(tmp_path / "b", bad)
    rec, http = await s2.clip_submit("default", "t1", 5632, 10, 20)
    assert http == 422 and rec["state"] == "failed"
    assert s2.ledger.get(clips.ClipLedger.fingerprint("default", 5632, 10, 20))["state"] == "failed"  # odrzucone: mozna poprawic i ponowic


async def test_bad_range_never_posts(tmp_path):
    async def good():
        return _FakeResp(200, {"clip_ids": [1]})

    s, req = _clipsvc(tmp_path, good)
    from connector.service import ConnectorError
    with pytest.raises(ConnectorError) as ex:
        await s.clip_submit("default", "t1", 5632, 0, 400)
    assert ex.value.code == "BAD_RANGE" and req.posts == 0


# ---------- etap 1 backendu: tozsamosc, check, trwale proby, pin DNS ----------
def test_extract_identity_shapes():
    from connector.bastion import extract_identity
    a = extract_identity({"viewer": {"display_name": "Jan Kowalski", "avatar_url": "x"}})
    assert a["label"] == "Jan Kowalski" and a["id"].startswith("dn:") and a["source"] == "viewer.display_name"
    assert a["viewer_keys"] == ["avatar_url", "display_name"]
    assert extract_identity({"viewer": {"display_name": "JAN KOWALSKI"}})["id"] == a["id"]
    b = extract_identity({"viewer": {"discord_user_id": 123, "display_name": "Jan"}})
    assert b["id"] == "123" and b["source"] == "viewer.discord_user_id"
    for body in ({}, {"viewer": {}}, {"viewer": None}, [], {"viewer": True}):
        assert extract_identity(body)["id"] is None


def test_merge_identity_same_account_keeps_other_flags_change():
    from connector.service import Service
    ident = {"id": "dn:a", "label": "Jan", "source": "viewer.display_name"}
    first = Service.merge_identity({}, ident)
    assert first["external_identity_id"] == "dn:a" and first["identity_changed"] is False
    assert Service.merge_identity(first, ident)["identity_changed"] is False
    other = Service.merge_identity(first, {"id": "dn:b", "label": "Ewa", "source": "viewer.display_name"})
    assert other["external_identity_id"] == "dn:b" and other["external_identity_label"] == "Ewa" and other["identity_changed"] is True
    unknown = Service.merge_identity(first, {})
    assert unknown["external_identity_id"] == "dn:a" and unknown["identity_changed"] is False


async def test_check_verdicts_and_no_embed(tmp_path):
    from connector.bastion import GameResult
    from connector.service import ConnectorError
    svc = _svc(tmp_path)
    key_ = conn_key_for("default", None)
    svc.store.save(key_, {"cookies": [], "origins": []}, {"generation": 1, "external_identity_id": None})
    out = {}

    async def fake(scope, judge, item):
        return out["res"], {"connection": key_, "generation": 1, "last_validated_at": "t"}

    svc.game_context = fake
    ident = {"id": "dn:a", "label": "Jan", "source": "viewer.display_name", "viewer_keys": []}
    out["res"] = GameResult("OK", 200, embed_url="https://x.mediadelivery.net/secret", identity=ident)
    r = await svc.check("default", None)
    assert r["verdict"] == "ok" and "embed_url" not in json.dumps(r) and "secret" not in json.dumps(r)
    assert r["external_identity_id"] == "dn:a" and r["external_identity_label"] == "Jan"  # dopelnienie starej generacji
    assert svc.status("default", None)["external_identity_label"] == "Jan"
    out["res"] = GameResult("BASTION_RESOURCE_FORBIDDEN", 403)
    assert (await svc.check("default", None))["verdict"] == "ok"
    out["res"] = GameResult("BASTION_AUTH_REQUIRED", 401)
    assert (await svc.check("default", None))["verdict"] == "auth_required"
    for code in ("BASTION_UNAVAILABLE", "BASTION_RATE_LIMITED", "BASTION_BAD_RESPONSE"):
        out["res"] = GameResult(code)
        assert (await svc.check("default", None))["verdict"] == "unavailable"

    async def not_conn(*a):
        raise ConnectorError("BASTION_NOT_CONNECTED", 409)

    svc.game_context = not_conn
    assert (await svc.check("default", None))["verdict"] == "auth_required"
    svc.s.probe_bunny_item_id = None
    with pytest.raises(ConnectorError) as e:
        await svc.check("default", None)
    assert e.value.code == "PROBE_ITEM_REQUIRED"


async def test_attempt_status_persists_and_restart_marks_interrupted(tmp_path):
    svc = _svc(tmp_path)
    a = _active(svc)
    a.on_change = svc._persist_attempt
    a.status = "verifying"
    assert json.loads((tmp_path / "attempts" / "att1.json").read_text(encoding="utf-8"))["status"] == "verifying"
    assert "tester1" in (tmp_path / "attempts" / "att1.json").read_text(encoding="utf-8")
    # drugi proces (restart): przegladarka zginela
    svc2 = _svc(tmp_path)
    svc2.recover_attempts()
    b = svc2.get_attempt("att1")
    pub = svc2.public_attempt(b)
    assert pub["status"] == "interrupted" and "zrestartowana" in pub["message"] and pub["error"] == "CONNECTOR_RESTARTED"
    assert not b.active
    # stan zapisany na dysku, kolejny restart go nie zmienia
    svc3 = _svc(tmp_path)
    svc3.recover_attempts()
    assert svc3.get_attempt("att1").status == "interrupted"


async def test_restart_keeps_terminal_states_and_expires_overdue(tmp_path):
    svc = _svc(tmp_path)
    for i, st in enumerate(("succeeded", "failed", "cancelled")):
        a = _active(svc)
        a.id = f"t{i}"
        a.status = st
        svc._persist_attempt(a)
    old = _active(svc)
    old.id = "old1"
    old.expires = 1.0
    svc._persist_attempt(old)
    svc2 = _svc(tmp_path)
    svc2.recover_attempts()
    assert [svc2.attempts[k].status for k in ("t0", "t1", "t2")] == ["succeeded", "failed", "cancelled"]
    assert svc2.attempts["old1"].status == "expired"


def test_pin_url_and_ipv6():
    assert clips.pin_url("https://a.b-cdn.net/f.mp4?t=1", "93.184.216.34") == "https://93.184.216.34/f.mp4?t=1"
    assert clips.pin_url("https://a.b-cdn.net/f", "2606:2800::1") == "https://[2606:2800::1]/f"


async def test_download_connects_to_resolved_ip_with_host_and_sni(tmp_path):
    seen = []
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.host, req.headers["host"], req.extensions.get("sni_hostname")))
        return httpx.Response(200, content=b"x")

    async def res(h):
        calls.append(h)
        return ["93.184.216.34", "93.184.216.35"]

    await clips.safe_download("https://a.b-cdn.net/f", transport=httpx.MockTransport(handler),
                              **{**_kw(tmp_path), "resolver": res})
    assert seen == [("93.184.216.34", "a.b-cdn.net", "a.b-cdn.net")] and calls == ["a.b-cdn.net"]  # DNS raz


# ---------- etap 4: produkcyjne /clips (idempotencja po odcisku, korelacja, adres pobrania) ----------
FP = "a" * 64


async def test_prod_create_is_idempotent_by_fingerprint_and_neutral_comment(tmp_path):
    bodies = []

    async def good():
        return _FakeResp(200, {"clip_ids": [901], "clip_codes": ["ZZ9"]})

    s, req = _clipsvc(tmp_path, good)
    orig = req.post

    async def spy(*a, **k):
        bodies.append(json.loads(k["data"]))
        return await orig(*a, **k)

    req.post = spy
    rec, http = await s.clip_create("personal", "101", 5632, 628, 638, FP, "job_1")
    assert http == 200 and rec["remote_id"] == "901" and "idempotent" not in rec
    c = bodies[0]["clips"][0]
    assert c["comment"] == "BAZA Mentor job_1" and c["audience_group_id"] is None
    assert c["situationType"] == "NORMAL" and c["videoTags"] == ["PLAY_ON"] and c["startTime"] == "10:28"
    again, http2 = await s.clip_create("personal", "101", 5632, 628, 638, FP, "job_1")
    assert http2 == 200 and again["remote_id"] == "901" and again["idempotent"] is True and req.posts == 1
    # restart: ksiega pamieta, nadal zero drugiego POST
    s2, req2 = _clipsvc(tmp_path, good)
    rec3, http3 = await s2.clip_create("personal", "101", 5632, 628, 638, FP, "job_1")
    assert http3 == 200 and rec3["remote_id"] == "901" and req2.posts == 0


async def test_prod_needs_reconciliation_not_retried_and_failed_can_retry(tmp_path):
    async def boom():
        raise TimeoutError("t")

    s, req = _clipsvc(tmp_path, boom)
    rec, http = await s.clip_create("default", None, 5632, 628, 638, FP, "job_2")
    assert http == 202 and rec["state"] == "needs_reconciliation"
    rec2, http2 = await s.clip_create("default", None, 5632, 628, 638, FP, "job_2")
    assert http2 == 202 and rec2["idempotent"] is True and req.posts == 1  # zero ponowien
    from connector.service import ConnectorError
    with pytest.raises(ConnectorError) as ex:  # ten sam odcisk, inny zakres
        await s.clip_create("default", None, 5632, 628, 640, FP, "job_2")
    assert ex.value.code == "FINGERPRINT_MISMATCH" and req.posts == 1

    async def rejected():
        return _FakeResp(422, {"message": "nie"})

    s3, req3 = _clipsvc(tmp_path / "r", rejected)
    _, h = await s3.clip_create("default", None, 5632, 10, 20, FP, "job_3")
    assert h == 422
    _, h = await s3.clip_create("default", None, 5632, 10, 20, FP, "job_3")  # odrzucone 4xx: wolno ponowic
    assert h == 422 and req3.posts == 2


async def test_prod_validates_input_before_any_post(tmp_path):
    async def good():
        return _FakeResp(200, {"clip_ids": [1]})

    s, req = _clipsvc(tmp_path, good)
    from connector.service import ConnectorError
    for args, code in (((0, 400, FP, "j"), "BAD_RANGE"), ((0, 10, "x", "j"), "BAD_FINGERPRINT"), ((0, 10, FP, "z z"), "BAD_CORRELATION")):
        with pytest.raises(ConnectorError) as ex:
            await s.clip_create("default", None, 5632, *args)
        assert ex.value.code == code
    assert req.posts == 0


async def test_download_url_validates_host_and_other_connection_cannot_use_clip(tmp_path):
    async def good():
        return _FakeResp(200, {"clip_ids": [55]})

    s, _ = _clipsvc(tmp_path, good)
    await s.clip_create("personal", "101", 5632, 628, 638, FP, "job_4")
    from connector.service import ConnectorError

    async def signed_ok(key, cid):
        return "https://vz.b-cdn.net/f.mp4?token=1"

    async def signed_bad(key, cid):
        return "https://evil.example.com/f.mp4"

    async def public(host):
        return ["93.184.216.34"]

    s._signed_location = signed_ok
    orig = clips.resolve_public_ips
    clips.resolve_public_ips = public
    try:
        out = await s.clip_download_url("personal", "101", "55")
        assert out["url"].startswith("https://vz.b-cdn.net/") and out["cookies"] is False and out["host"] == "vz.b-cdn.net"
        s._signed_location = signed_bad
        with pytest.raises(ConnectorError) as ex:
            await s.clip_download_url("personal", "101", "55")
        assert ex.value.code == "DOWNLOAD_HOST_NOT_ALLOWED"
        s._signed_location = signed_ok
        with pytest.raises(ConnectorError) as ex:  # klip nalezy do sesji 101, nie 102
            await s.clip_download_url("personal", "102", "55")
        assert ex.value.code == "CLIP_UNKNOWN"
        with pytest.raises(ConnectorError):
            await s.clip_context("personal", "102", "55", strict=True)
    finally:
        clips.resolve_public_ips = orig


def test_summarize_match_whitelist_and_shapes():
    from connector.bastion import classify, summarize_match
    m = summarize_match({"match": {"home_team": {"name": "SPR Gliwice"}, "away": "KS Opole", "date": "2026-10-20", "Mecz": 123,
                                   "Sezon": 9, "Rozgrywki": "K1", "secret_url": "https://x", "referees": [1, 2]}})
    assert m["home"] == "SPR Gliwice" and m["away"] == "KS Opole" and m["zprp_match_id"] == "123"
    assert m["zprp_season_id"] == "9" and m["zprp_competition_id"] == "K1" and "secret_url" in m["match_keys"]
    assert "https" not in str({k: v for k, v in m.items() if k != "match_keys"})
    assert summarize_match({}) == {} and summarize_match({"match": "x"}) == {}
    r = classify(200, {"video": {"state": "READY"}, "match": {"home": "A"}}, ["mediadelivery.net"])
    assert r.match["home"] == "A" and r.embed_url is None
