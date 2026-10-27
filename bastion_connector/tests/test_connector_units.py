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
