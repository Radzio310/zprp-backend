"""Usluga polaczen: playback/check z zapisanego stanu oraz proby interaktywnego logowania (CDP screencast)."""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import crypto, tickets
from .bastion import GameResult, fetch_game_context
from .config import Settings
from .store import StateStore, conn_key_for, cookie_summary, filter_state_to_host, now_iso
from .urlrules import is_blocked_navigation

log = logging.getLogger("bastion.connector")
VIEWPORT = {"width": 1100, "height": 700}
MAX_TEXT = 2000
TAKEOVER_CODE = 4409
TAKEOVER_REASON = "Widok przejęła inna karta"

# Przegladarka serwerowa nie ma zadnego uwierzytelniacza WebAuthn (klucz bezpieczenstwa, passkey).
# Discord przy MFA sam uruchamia navigator.credentials.get({publicKey}); w Chromium bez
# uwierzytelniacza konczy sie to bledem "Wystapil blad. Sprobuj ponownie." zamiast pola na kod.
# Uczciwie zglaszamy brak WebAuthn: PublicKeyCredential niedostepne, wywolania z publicKey
# odrzucane NotAllowedError. Strona przechodzi wtedy na kod z aplikacji / SMS / kod zapasowy.
# To NIE omija MFA - czlowiek nadal podaje drugi skladnik.
NO_WEBAUTHN_JS = r"""
(() => {
  try {
    const deny = () => Promise.reject(new DOMException(
      'WebAuthn niedostepne w przegladarce serwerowej', 'NotAllowedError'));
    try { delete window.PublicKeyCredential; } catch (e) {}
    try { Object.defineProperty(window, 'PublicKeyCredential',
      { value: undefined, configurable: true, writable: false, enumerable: false }); } catch (e) {}
    const c = navigator.credentials;
    if (c) {
      const wrap = (orig) => function (opts) {
        if (opts && opts.publicKey) return deny();
        return orig ? orig.call(c, opts) : deny();
      };
      const get = c.get, create = c.create;
      try { Object.defineProperty(c, 'get', { value: wrap(get), configurable: true }); } catch (e) {}
      try { Object.defineProperty(c, 'create', { value: wrap(create), configurable: true }); } catch (e) {}
    }
  } catch (e) {}
})();
"""


class ConnectorError(Exception):
    def __init__(self, code: str, status: int = 400, detail: str | None = None) -> None:
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail


@dataclass
class Attempt:
    id: str
    conn_key: str
    scope: str
    judge_id: str
    probe_item_id: int
    created: float
    expires: float
    status: str = "creating"  # creating | waiting_for_user | verifying | succeeded | failed | cancelled | expired
    error: str | None = None
    context: object | None = None
    page: object | None = None
    cdp: object | None = None
    viewer: object | None = None  # aktywny WebSocket
    task: asyncio.Task | None = None
    last_verify: float = 0.0
    identity: dict = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.status in ("creating", "waiting_for_user", "verifying")


class Service:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.store = StateStore(settings.data_dir, settings.secrets_key, settings.secrets_key_previous)
        self.registry = tickets.TicketRegistry()
        self.attempts: dict[str, Attempt] = {}
        self._pw = None
        self._browser = None
        self._browser_lock = asyncio.Lock()

    # ---------- infrastruktura ----------
    async def start(self) -> None:
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()

    async def stop(self) -> None:
        for a in list(self.attempts.values()):
            await self._close_attempt(a, "cancelled" if a.active else a.status)
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def _get_browser(self):
        async with self._browser_lock:
            if self._browser is None or not self._browser.is_connected():
                self._browser = await self._pw.chromium.launch(
                    headless=not self.s.headful,
                    executable_path=self.s.chromium_path or None,
                    args=["--disable-dev-shm-usage", "--no-first-run"])
            return self._browser

    # ---------- odczyt z zapisanego stanu (bez Chromium) ----------
    async def _with_state_request(self, conn_key: str):
        try:
            loaded = self.store.load(conn_key)
        except crypto.CryptoError as e:  # zly klucz/uszkodzony plik: jawny blad, stan nietkniety
            raise ConnectorError("BASTION_STATE_UNREADABLE", 500, str(e)) from e
        if loaded is None:
            raise ConnectorError("BASTION_NOT_CONNECTED", 409)
        state, meta = loaded
        try:
            req = await self._pw.request.new_context(storage_state=state)
        except Exception as e:  # noqa: BLE001
            log.warning("niepoprawny zapisany stan %s: %s", conn_key, str(e)[:200])
            raise ConnectorError("BASTION_STATE_INVALID", 500) from e
        return req, state, meta

    async def game_context(self, scope: str, judge_id: str | None, item_id: int) -> tuple[GameResult, dict]:
        key = conn_key_for(scope, judge_id)
        req, state, meta = await self._with_state_request(key)
        try:
            res = await fetch_game_context(req, self.s.portal_base_url, item_id, self.s.embed_host_suffixes)
            info = {"connection": key, "generation": meta.get("generation"), "last_validated_at": meta.get("validated_at")}
            if res.code == "OK" or res.code == "BASTION_RESOURCE_FORBIDDEN":
                fresh = filter_state_to_host(await req.storage_state(), self.s.portal_host)
                async with self.store.lock(key):
                    # odswiezone cookie (rotacja sesji) zapisujemy tylko gdy sie zmienily
                    if json.dumps(fresh, sort_keys=True) != json.dumps(state, sort_keys=True):
                        meta = {**meta, "validated_at": now_iso()}
                        self.store.save(key, fresh, meta)
                    else:
                        self.store.touch_meta(key, validated_at=now_iso())
                info["last_validated_at"] = now_iso()
            elif res.code == "BASTION_AUTH_REQUIRED":
                self.store.touch_meta(key, last_error_code=res.code)  # nie kasujemy stanu po jednym 401
            return res, info
        finally:
            await req.dispose()

    def status(self, scope: str, judge_id: str | None) -> dict:
        key = conn_key_for(scope, judge_id)
        loaded = self.store.load(key)
        if not loaded:
            return {"connection": key, "status": "unconfigured", "expires_at": None}
        state, meta = loaded
        return {"connection": key, "status": "stored", "generation": meta.get("generation"),
                "connected_at": meta.get("connected_at"), "last_validated_at": meta.get("validated_at"),
                "last_error_code": meta.get("last_error_code"), "expires_at": None,
                "cookies": cookie_summary(state)}

    def disconnect(self, scope: str, judge_id: str | None) -> bool:
        return self.store.delete(conn_key_for(scope, judge_id))

    # ---------- proby logowania ----------
    def _active_for(self, key: str) -> Attempt | None:
        return next((a for a in self.attempts.values() if a.conn_key == key and a.active), None)

    async def create_attempt(self, scope: str, judge_id: str, probe_item_id: int | None) -> tuple[Attempt, str, bool]:
        """Zwraca (proba, bilet, resumed). Handoff 12: jeden aktywny proces logowania na polaczenie,
        kilka kart oglada te sama probe. Ta sama osoba (conn_key + judge_id) z aktywna proba dostaje
        ISTNIEJACA probe i nowy bilet (odswiezenie karty nie gubi ekranu MFA); inna osoba - 409."""
        probe = probe_item_id or self.s.probe_bunny_item_id
        if not probe:
            raise ConnectorError("PROBE_ITEM_REQUIRED", 400, "brak bunny_item_id do weryfikacji logowania")
        key = conn_key_for(scope, judge_id)
        existing = self._active_for(key)
        if existing:
            if existing.judge_id != judge_id:
                raise ConnectorError("LOGIN_ALREADY_ACTIVE", 409, "na tym polaczeniu trwa proba logowania innej osoby")
            if existing.cdp is None:
                raise ConnectorError("LOGIN_STARTING", 409, "proba jeszcze sie uruchamia, sprobuj za kilka sekund")
            return existing, tickets.mint(self.s.ticket_secret, judge_id, existing.id, self.s.ticket_ttl_s), True
        if sum(1 for a in self.attempts.values() if a.active) >= self.s.max_active_logins:
            raise ConnectorError("LOGIN_CAPACITY", 429)
        now = time.time()
        a = Attempt(id=secrets.token_urlsafe(12), conn_key=key, scope=scope, judge_id=judge_id,
                    probe_item_id=probe, created=now, expires=now + self.s.attempt_ttl_s)
        self.attempts[a.id] = a
        try:
            browser = await self._get_browser()
            # izolowany kontekst kandydujacy: nie dotyka zapisanego stanu dzialajacej sesji
            a.context = await browser.new_context(viewport=VIEWPORT, locale="pl-PL", timezone_id="Europe/Warsaw")
            await a.context.add_init_script(NO_WEBAUTHN_JS)  # wszystkie ramki, przed skryptami strony
            await a.context.route("**/*", lambda route: route.abort() if is_blocked_navigation(route.request.url)
                                  else route.continue_())
            a.page = await a.context.new_page()
            a.cdp = await a.context.new_cdp_session(a.page)
            a.cdp.on("Page.screencastFrame", lambda p: asyncio.ensure_future(self._on_frame(a, p)))
            await a.page.goto(self.s.portal_base_url, wait_until="domcontentloaded", timeout=30000)
            a.status = "waiting_for_user"
        except Exception as e:  # noqa: BLE001
            log.warning("create_attempt failed: %s: %s", type(e).__name__, str(e)[:300])
            await self._close_attempt(a, "failed", f"{type(e).__name__}")
            raise ConnectorError("BASTION_UNAVAILABLE", 503) from e
        a.task = asyncio.create_task(self._watch(a))
        ticket = tickets.mint(self.s.ticket_secret, judge_id, a.id, self.s.ticket_ttl_s)
        return a, ticket, False

    def new_ticket(self, a: Attempt) -> str:
        if not a.active:
            raise ConnectorError("ATTEMPT_NOT_ACTIVE", 409)
        return tickets.mint(self.s.ticket_secret, a.judge_id, a.id, self.s.ticket_ttl_s)

    def get_attempt(self, attempt_id: str) -> Attempt:
        a = self.attempts.get(attempt_id)
        if not a:
            raise ConnectorError("ATTEMPT_NOT_FOUND", 404)
        return a

    def public_attempt(self, a: Attempt) -> dict:
        return {"id": a.id, "scope": a.scope, "status": a.status, "expires_at": int(a.expires),
                "error": a.error, "connection": a.conn_key}

    async def cancel(self, a: Attempt) -> None:
        if a.active:
            await self._close_attempt(a, "cancelled")

    async def _close_attempt(self, a: Attempt, status: str, error: str | None = None) -> None:
        a.status = status
        a.error = error or a.error
        if a.task and a.task is not asyncio.current_task():
            a.task.cancel()
        try:
            if a.cdp:
                await a.cdp.send("Page.stopScreencast")
        except Exception:  # noqa: BLE001
            pass
        try:
            if a.context:
                await a.context.close()
        except Exception:  # noqa: BLE001
            pass
        a.context = a.page = a.cdp = None
        v, a.viewer = a.viewer, None
        if v is not None:
            try:
                await v.send_json({"type": "status", "status": a.status, "error": a.error})
                await v.close(code=1000)
            except Exception:  # noqa: BLE001
                pass

    # ---------- widok: klatki i wejscie ----------
    async def attach_viewer(self, a: Attempt, ws) -> None:
        """Nowy widok przejmuje probe (np. odswiezona karta); poprzedni zamykany czysto kodem 4409."""
        if a.cdp is None:
            raise ConnectorError("LOGIN_STARTING", 409)
        old, a.viewer = a.viewer, ws
        if old is not None and old is not ws:
            try:
                await old.send_json({"type": "takeover"})
                await old.close(code=TAKEOVER_CODE, reason=TAKEOVER_REASON)
            except Exception:  # noqa: BLE001
                pass
            try:  # restart screencastu: nowy widok dostaje od razu pelna klatke, nawet gdy strona stoi
                await a.cdp.send("Page.stopScreencast")
            except Exception:  # noqa: BLE001
                pass
        await a.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 60, "maxWidth": VIEWPORT["width"],
                                                  "maxHeight": VIEWPORT["height"], "everyNthFrame": 1})

    async def detach_viewer(self, a: Attempt, ws) -> None:
        if a.viewer is ws:
            a.viewer = None
            try:
                if a.cdp:
                    await a.cdp.send("Page.stopScreencast")
            except Exception:  # noqa: BLE001
                pass

    async def _on_frame(self, a: Attempt, params: dict) -> None:
        try:
            if a.cdp:
                await a.cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
            v = a.viewer
            if v is not None:
                await v.send_bytes(base64.b64decode(params["data"]))
        except Exception:  # noqa: BLE001
            pass

    async def handle_input(self, a: Attempt, m: dict) -> None:
        if not a.cdp or a.status != "waiting_for_user":
            return
        t = m.get("t")
        num = lambda k: max(0, min(int(m.get(k, 0)), 5000))  # noqa: E731
        if t == "mouse":
            act = {"move": "mouseMoved", "down": "mousePressed", "up": "mouseReleased", "wheel": "mouseWheel"}.get(m.get("a"))
            if not act:
                return
            btn = m.get("b") if m.get("b") in ("left", "middle", "right") else "left"
            p = {"type": act, "x": num("x"), "y": num("y"), "modifiers": int(m.get("mod", 0)) & 15}
            if act in ("mousePressed", "mouseReleased"):
                p.update(button=btn, clickCount=1)
            if act == "mouseWheel":
                p.update(deltaX=max(-2000, min(int(m.get("dx", 0)), 2000)), deltaY=max(-2000, min(int(m.get("dy", 0)), 2000)))
            await a.cdp.send("Input.dispatchMouseEvent", p)
        elif t == "key":
            key = str(m.get("key", ""))[:32]
            down = m.get("a") == "down"
            p = {"type": "keyDown" if down else "keyUp", "key": key, "code": str(m.get("code", ""))[:32],
                 "windowsVirtualKeyCode": int(m.get("kc", 0)), "modifiers": int(m.get("mod", 0)) & 15}
            if down and len(key) == 1 and not (int(m.get("mod", 0)) & 3):  # bez Ctrl/Alt: znak drukowalny
                p["text"] = key
            elif down and key == "Enter":
                p["text"] = "\r"
            await a.cdp.send("Input.dispatchKeyEvent", p)
        elif t == "paste":
            await a.cdp.send("Input.insertText", {"text": str(m.get("text", ""))[:MAX_TEXT]})

    # ---------- obserwator proby ----------
    async def _watch(self, a: Attempt) -> None:
        try:
            while a.active:
                await asyncio.sleep(1)
                if time.time() > a.expires:
                    await self._close_attempt(a, "expired")
                    return
                if a.page is None or a.status != "waiting_for_user":
                    continue
                host = (urlsplit(a.page.url).hostname or "").lower()
                if host == self.s.portal_host and time.time() - a.last_verify >= 3:
                    a.last_verify = time.time()
                    await self._try_verify(a)
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            await self._close_attempt(a, "failed", type(e).__name__)

    async def _try_verify(self, a: Attempt) -> None:
        """Sukces = HTTP 200 (konto ma dostep) albo 403 (zalogowano, ale brak dostepu do meczu probnego).
        401 = jeszcze nie zalogowano. Zamkniecie okna nigdy nie jest sukcesem."""
        res = await fetch_game_context(a.context.request, self.s.portal_base_url, a.probe_item_id,
                                       self.s.embed_host_suffixes)
        if res.code not in ("OK", "BASTION_RESOURCE_FORBIDDEN", "BASTION_EMBED_HOST_NOT_ALLOWED"):
            return
        a.status = "verifying"
        state = filter_state_to_host(await a.context.storage_state(), self.s.portal_host)
        async with self.store.lock(a.conn_key):
            prev = self.store.load(a.conn_key)
            gen = (prev[1].get("generation", 0) if prev else 0) + 1
            meta = {"generation": gen, "connected_at": now_iso(), "validated_at": now_iso(),
                    "verified_with": "game-context", "game_context_code": res.code,
                    "external_identity_id": None}  # tozsamosc konta: brak potwierdzonego endpointu (do ustalenia)
            self.store.save(a.conn_key, state, meta)  # wymiana generacji dopiero po udanej weryfikacji
        a.identity = {"game_context_code": res.code}
        await self._close_attempt(a, "succeeded")

    def sweep(self) -> None:
        cutoff = time.time() - 3600
        for k in [k for k, a in self.attempts.items() if not a.active and a.expires < cutoff]:
            del self.attempts[k]
