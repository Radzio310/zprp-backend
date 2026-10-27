"""Usluga polaczen: playback/check z zapisanego stanu oraz proby interaktywnego logowania (CDP screencast)."""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import attempts_store, clips, crypto, tickets
from .attempts_store import AttemptStore
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


# Klawisze specjalne przekazywane jako zdarzenia klawisza (reszta = tekst przez Input.insertText).
SPECIAL_KEYS = {
    "Enter": 13, "Backspace": 8, "Tab": 9, "Escape": 27, "Delete": 46, "Home": 36, "End": 35,
    "PageUp": 33, "PageDown": 34, "ArrowLeft": 37, "ArrowUp": 38, "ArrowRight": 39, "ArrowDown": 40,
}


def key_to_cdp(m: dict) -> list[tuple[str, dict]]:
    """Wiadomosc wejscia z widoku -> wywolania CDP.

    Znaki drukowalne ida WYLACZNIE przez Input.insertText: niezaleznie od ukladu klawiatury
    po obu stronach (AltGr + a = "ą", Shift + 2 = "@"), bez dublowania (keyDown z polem text
    plus insertText wpisalyby znak dwa razy). Wczesniej AltGr (= Ctrl+Alt) gubil polskie litery.
    dispatchKeyEvent tylko dla klawiszy specjalnych i skrotow z Ctrl (bez AltGr).
    Bity mod: Alt=1, Ctrl=2, Meta=4, Shift=8."""
    t = m.get("t")
    if t in ("text", "paste"):
        text = str(m.get("text", ""))[:MAX_TEXT]
        return [("Input.insertText", {"text": text})] if text else []
    if t != "key":
        return []
    key = str(m.get("key", ""))[:32]
    mod = int(m.get("mod", 0)) & 15
    down = m.get("a") == "down"
    altgr = bool(m.get("altgr")) or (mod & 3) == 3  # Windows zglasza AltGr jako Ctrl+Alt
    shortcut = bool(mod & 6) and not altgr  # Ctrl/Meta bez AltGr = skrot (Ctrl+A, Ctrl+Z)
    if len(key) == 1 and not shortcut:
        return [("Input.insertText", {"text": key})] if down else []  # keyUp znaku: nic
    if key not in SPECIAL_KEYS and not (shortcut and len(key) == 1):
        return []  # Shift, Alt, CapsLock, F1... - nic do przekazania
    kc = SPECIAL_KEYS.get(key) or (ord(key.upper()) if len(key) == 1 and key.isascii() else 0)
    # jak Playwright: keyDown tylko z tekstem (Enter), inaczej rawKeyDown - bez wstawiania znaku
    p = {"type": "rawKeyDown" if down else "keyUp", "key": key, "code": str(m.get("code", ""))[:32],
         "windowsVirtualKeyCode": kc, "modifiers": mod}
    if down and key == "Enter" and not shortcut:
        p.update(type="keyDown", text=chr(13))
    return [("Input.dispatchKeyEvent", p)]


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
    status: str = "creating"  # creating | waiting_for_user | verifying | succeeded | failed | cancelled | expired | interrupted
    error: str | None = None
    context: object | None = None
    page: object | None = None
    cdp: object | None = None
    viewer: object | None = None  # aktywny WebSocket
    task: asyncio.Task | None = None
    last_verify: float = 0.0
    identity: dict = field(default_factory=dict)
    on_change: object | None = field(default=None, repr=False, compare=False)  # zapis trwałego stanu przy zmianie statusu

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if name in ("status", "error"):
            cb = self.__dict__.get("on_change")
            if cb:
                cb(self)

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
        self.attempt_store = AttemptStore(settings.data_dir)
        self.ledger = clips.ClipLedger(settings.data_dir)
        self._clip_locks: dict[str, asyncio.Lock] = {}

    # ---------- infrastruktura ----------
    async def start(self) -> None:
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        self.recover_attempts()

    def _persist_attempt(self, a: "Attempt") -> None:
        try:
            self.attempt_store.save({"id": a.id, "conn_key": a.conn_key, "scope": a.scope, "judge_id": a.judge_id,
                                     "probe_item_id": a.probe_item_id, "created": a.created, "expires": a.expires,
                                     "status": a.status, "error": a.error})
        except OSError as e:  # brak zapisu nie może przewrócić logowania
            log.warning("zapis stanu proby nie powiodl sie: %s", type(e).__name__)

    def recover_attempts(self) -> None:
        for d in self.attempt_store.recover():
            if d["id"] in self.attempts:
                continue
            a = Attempt(id=d["id"], conn_key=d["conn_key"], scope=d.get("scope") or "default",
                        judge_id=d.get("judge_id") or "", probe_item_id=int(d.get("probe_item_id") or 0),
                        created=float(d.get("created") or 0), expires=float(d.get("expires") or 0),
                        status=d["status"], error=d.get("error"))
            a.on_change = self._persist_attempt
            self.attempts[a.id] = a

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
                if self.s.headful and sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
                    raise ConnectorError("BROWSER_NO_DISPLAY", 503,
                                         "BASTION_HEADFUL=true, ale brak DISPLAY - uruchom pod xvfb-run (Dockerfile)")
                # headful = zwykly Chromium (UA bez "HeadlessChrome"); locale i strefa ustawiane na kontekscie
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

    # ---------- P8: ciecie klipu i pobranie MP4 (sesja tego polaczenia) ----------
    async def _persist_if_changed(self, req, key: str, state: dict, meta: dict) -> None:
        fresh = filter_state_to_host(await req.storage_state(), self.s.portal_host)
        async with self.store.lock(key):
            if json.dumps(fresh, sort_keys=True) != json.dumps(state, sort_keys=True):
                self.store.save(key, fresh, {**meta, "validated_at": now_iso()})
            else:
                self.store.touch_meta(key, validated_at=now_iso())

    @staticmethod
    def _auth_err(code: str) -> "ConnectorError | None":
        m = {"BASTION_AUTH_REQUIRED": 409, "BASTION_RESOURCE_FORBIDDEN": 403, "BASTION_RATE_LIMITED": 429}
        return ConnectorError(code, m[code]) if code in m else None

    async def clip_submit(self, scope: str, judge_id: str | None, item_id: int, start_s: int, end_s: int) -> tuple[dict, int]:
        """Probne zlecenie (P8): jedno na (polaczenie, film, zakres); drugie = 409 CLIP_ALREADY_SUBMITTED."""
        try:
            start_s, end_s = clips.validate_range(start_s, end_s)
        except clips.ClipError as e:
            raise ConnectorError(e.code, e.status, e.detail) from e
        key = conn_key_for(scope, judge_id)
        fp = clips.ClipLedger.fingerprint(key, item_id, start_s, end_s)
        return await self._submit(key, fp, scope, judge_id, item_id, start_s, end_s, clips.PROBE_COMMENT, None, idempotent=False)

    async def clip_create(self, scope: str, judge_id: str | None, item_id: int, start_s: int, end_s: int,
                          fingerprint: str, correlation: str) -> tuple[dict, int]:
        """Produkcja: idempotentne po odcisku zlecenia (ten sam odcisk = ten sam wynik, bez drugiego POST), takze po
        restarcie. needs_reconciliation zostaje bez ponowien. Odrzucenie 4xx (failed) mozna ponowic tym samym odciskiem."""
        try:
            start_s, end_s = clips.validate_range(start_s, end_s)
            comment = clips.prod_comment(correlation)
            ledger_key = clips.prod_key(conn_key_for(scope, judge_id), fingerprint)
        except clips.ClipError as e:
            raise ConnectorError(e.code, e.status, e.detail) from e
        return await self._submit(conn_key_for(scope, judge_id), ledger_key, scope, judge_id, item_id, start_s, end_s,
                                  comment, correlation, idempotent=True, fingerprint=fingerprint)

    async def _submit(self, key: str, fp: str, scope: str, judge_id: str | None, item_id: int, start_s: int, end_s: int,
                      comment: str, correlation: str | None, *, idempotent: bool,
                      fingerprint: str | None = None) -> tuple[dict, int]:
        """Wpis w ksiedze PRZED POST-em; po timeoucie lub 5xx stan needs_reconciliation i ZERO ponowien."""
        lock = self._clip_locks.setdefault(fp, asyncio.Lock())
        if lock.locked():
            raise ConnectorError("CLIP_SUBMIT_IN_PROGRESS", 409, "to samo zlecenie jest wlasnie wysylane")
        async with lock:
            prev = self.ledger.get(fp)
            if prev and prev.get("state") != "failed":
                if not idempotent:
                    raise ConnectorError("CLIP_ALREADY_SUBMITTED", 409,
                                         json.dumps({k: prev.get(k) for k in ("state", "code", "remote_id", "clip_code", "created_at")}))
                if (prev.get("bunny_item_id"), prev.get("start_s"), prev.get("end_s")) != (item_id, start_s, end_s):
                    raise ConnectorError("FINGERPRINT_MISMATCH", 409, "ten odcisk dotyczy innego filmu lub zakresu")
                if prev.get("state") == "submitting":  # wpis zostal po padzie procesu (konstruktor ksiegi go przeklasyfikuje)
                    raise ConnectorError("CLIP_SUBMIT_IN_PROGRESS", 409)
                out = {**prev, "sent": clips.sent_summary(start_s, end_s, comment), "connection": key, "idempotent": True}
                return out, 200 if prev.get("state") == "submitted" else 202
            req, state, meta = await self._with_state_request(key)  # brak sesji = blad zanim cokolwiek zapiszemy
            job = {"state": "submitting", "code": None, "remote_id": None, "clip_code": None, "scope": scope,
                   "judge_id": judge_id, "bunny_item_id": item_id, "start_s": start_s, "end_s": end_s,
                   "created_at": now_iso()}
            if idempotent:
                job.update(fingerprint=fingerprint, correlation=correlation)
            self.ledger.put(fp, job)
            try:
                try:
                    resp = await req.post(f"{self.s.portal_base_url}/api/game-submit",
                                          data=json.dumps(clips.build_submit_body(item_id, start_s, end_s, comment)),
                                          headers={"Content-Type": "application/json"}, timeout=30000, max_redirects=0)
                    try:
                        body = await resp.json()
                    except Exception:  # noqa: BLE001
                        body = None
                    res = clips.classify_submit(resp.status, body)
                except Exception as e:  # noqa: BLE001 - po wyslaniu POST timeout/siec to NIE dowod, ze nic nie powstalo
                    log.warning("game-submit bez odpowiedzi: %s", type(e).__name__)
                    res = clips.classify_submit(None, None)
                    res.detail = type(e).__name__
                job.update(state=res.state, code=res.code, remote_id=res.remote_id, clip_code=res.clip_code,
                           http_status=res.http_status, detail=res.detail)
                self.ledger.put(fp, job)
                if res.state == "submitted":
                    try:
                        await self._persist_if_changed(req, key, state, meta)
                    except Exception:  # noqa: BLE001
                        pass
            finally:
                await req.dispose()
        out = {**job, "sent": clips.sent_summary(start_s, end_s, comment), "connection": key}
        if res.state == "submitted":
            return out, 200
        if res.state == "needs_reconciliation":
            return out, 202
        err = self._auth_err(res.code)
        if err:
            raise err
        return out, 422

    def _known_clip(self, remote_id: str, key: str | None = None) -> dict:
        job = self.ledger.by_remote_id(remote_id)
        if not job:
            raise ConnectorError("CLIP_UNKNOWN", 404, "to zlecenie nie powstalo w tym connectorze")
        if key is not None and conn_key_for(job.get("scope") or "default", job.get("judge_id")) != key:
            # klip nalezy do sesji innego konta: nie uzywamy cudzej ani nie ujawniamy, ze istnieje
            raise ConnectorError("CLIP_UNKNOWN", 404, "to zlecenie nie powstalo na tym polaczeniu")
        return job

    async def clip_context(self, scope: str, judge_id: str | None, clip_id: str, strict: bool = False) -> dict:
        key = conn_key_for(scope, judge_id)
        job = self._known_clip(clip_id, key if strict else None)
        req, state, meta = await self._with_state_request(key)
        try:
            try:
                resp = await req.get(f"{self.s.portal_base_url}/api/clip-context", params={"clip_id": clip_id},
                                     timeout=15000, max_redirects=0)
                try:
                    body = await resp.json()
                except Exception:  # noqa: BLE001
                    body = None
                status = resp.status
            except Exception as e:  # noqa: BLE001
                raise ConnectorError("BASTION_UNAVAILABLE", 503, type(e).__name__) from e
            if status == 401:
                raise ConnectorError("BASTION_AUTH_REQUIRED", 409)
            if status == 403:
                raise ConnectorError("BASTION_RESOURCE_FORBIDDEN", 403)
            if status == 404:
                raise ConnectorError("BASTION_CLIP_NOT_FOUND", 404)
            if status != 200 or not isinstance(body, dict):
                raise ConnectorError("BASTION_UNAVAILABLE" if status >= 500 else "BASTION_BAD_RESPONSE",
                                     503 if status >= 500 else 502, f"HTTP {status}")
            await self._persist_if_changed(req, key, state, meta)
            return {"remote_id": clip_id, "job_state": job.get("state"), **clips.summarize_context(body)}
        finally:
            await req.dispose()

    async def _signed_location(self, key: str, clip_id: str) -> str:
        """Sesja tylko do pierwszego zapytania (302 bez podazania). Zwraca podpisany adres (wrazliwy: nie logujemy)."""
        from urllib.parse import urljoin
        req, state, meta = await self._with_state_request(key)
        try:
            try:
                resp = await req.get(f"{self.s.portal_base_url}/api/clip/{clip_id}/download", timeout=20000, max_redirects=0)
            except Exception as e:  # noqa: BLE001
                raise ConnectorError("BASTION_UNAVAILABLE", 503, type(e).__name__) from e
            status, loc = resp.status, resp.headers.get("location")
            if status == 401:
                raise ConnectorError("BASTION_AUTH_REQUIRED", 409)
            if status == 403:
                raise ConnectorError("BASTION_RESOURCE_FORBIDDEN", 403)
            if status == 404:
                raise ConnectorError("BASTION_DOWNLOAD_NOT_READY", 404, "portal nie ma jeszcze pliku (download_available=false?)")
            if status not in (301, 302, 303, 307, 308) or not loc:
                raise ConnectorError("BASTION_BAD_RESPONSE", 502, f"oczekiwano przekierowania, jest HTTP {status}")
            await self._persist_if_changed(req, key, state, meta)
        finally:
            await req.dispose()
        signed = urljoin(self.s.portal_base_url + "/", loc)
        if (urlsplit(signed).hostname or "").lower() == self.s.portal_host:
            raise ConnectorError("DOWNLOAD_HOST_NOT_ALLOWED", 502, "przekierowanie wraca na host portalu (sesja nie pojdzie dalej)")
        return signed

    async def clip_download_url(self, scope: str, judge_id: str | None, clip_id: str) -> dict:
        """Produkcja: krotko zyjacy podpisany adres pobrania po walidacji hosta i adresow. Plik pobiera BAZA osobnym
        klientem BEZ ciasteczek (connector nie przekazuje sesji Bastionu dalej). Adres = sekret: no-store, nigdy w logach."""
        key = conn_key_for(scope, judge_id)
        self._known_clip(clip_id, key)
        signed = await self._signed_location(key, clip_id)
        host = (urlsplit(signed).hostname or "").lower()
        if not clips.download_host_ok(signed, self.s.download_host_suffixes):
            raise ConnectorError("DOWNLOAD_HOST_NOT_ALLOWED", 502, f"host pobrania: {host or '?'} (poza lista dozwolonych sufiksow)")
        if not await clips.resolve_public_ips(host):
            raise ConnectorError("DOWNLOAD_ADDRESS_NOT_PUBLIC", 502, f"host {host} wskazuje na adres nie-publiczny albo sie nie rozwiazuje")
        return {"remote_id": clip_id, "url": signed, "host": host, "cookies": False, "max_age_s": 120,
                "max_bytes": self.s.max_download_mb * 1024 * 1024}

    async def clip_download(self, scope: str, judge_id: str | None, clip_id: str) -> dict:
        """Probne (P8): connector sam pobiera podpisany adres osobnym klientem bez ciasteczek, mierzy i kasuje plik."""
        import tempfile
        key = conn_key_for(scope, judge_id)
        job = self._known_clip(clip_id)
        signed = await self._signed_location(key, clip_id)
        with tempfile.TemporaryDirectory(prefix="p8-") as tmp:  # plik znika zawsze, takze po bledzie
            try:
                dl = await clips.safe_download(signed, suffixes=self.s.download_host_suffixes,
                                               max_bytes=self.s.max_download_mb * 1024 * 1024, dest_dir=tmp)
                probe = await clips.ffprobe_file(dl.path, job["end_s"] - job["start_s"])
            except clips.ClipError as e:
                raise ConnectorError(e.code, e.status, e.detail) from e
            except Exception as e:  # noqa: BLE001
                raise ConnectorError("DOWNLOAD_FAILED", 502, type(e).__name__) from e
        return {"remote_id": clip_id, "size_bytes": dl.size, "sha256": dl.sha256, "content_type": dl.content_type,
                "download_host": dl.final_host, "redirect_hops": dl.hops, "file_deleted": True, **probe,
                "requested": {"start_s": job["start_s"], "end_s": job["end_s"]}}

    # ---------- tożsamość konta zewnętrznego ----------
    @staticmethod
    def merge_identity(prev_meta: dict, ident: dict) -> dict:
        """To samo konto (to samo id) zachowuje tożsamość, inne daje nową wartość i identity_changed=True.
        Brak tożsamości w odpowiedzi nie kasuje poprzedniej i nie jest zmianą konta."""
        new_id = (ident or {}).get("id")
        if not new_id:
            return {"external_identity_id": prev_meta.get("external_identity_id"),
                    "external_identity_label": prev_meta.get("external_identity_label"),
                    "identity_source": prev_meta.get("identity_source"), "identity_changed": False}
        old_id = prev_meta.get("external_identity_id")
        return {"external_identity_id": new_id, "external_identity_label": ident.get("label"),
                "identity_source": ident.get("source"), "identity_changed": bool(old_id and old_id != new_id)}

    @staticmethod
    def _identity_view(meta: dict) -> dict:
        return {"external_identity_id": meta.get("external_identity_id"),
                "external_identity_label": meta.get("external_identity_label"),
                "identity_source": meta.get("identity_source"),
                "identity_changed": bool(meta.get("identity_changed"))}

    async def check(self, scope: str, judge_id: str | None, probe_item_id: int | None = None) -> dict:
        """Lekka weryfikacja sesji: jedno game-context dla elementu próbnego, BEZ wydawania embedu (adres
        zostaje w pamięci i nie wraca do wywołującego). Werdykt: ok | auth_required | unavailable."""
        key = conn_key_for(scope, judge_id)
        item = probe_item_id or self.s.probe_bunny_item_id
        if not item:
            raise ConnectorError("PROBE_ITEM_REQUIRED", 400, "brak bunny_item_id do weryfikacji sesji")
        try:
            res, info = await self.game_context(scope, judge_id, item)
        except ConnectorError as e:
            if e.code == "BASTION_NOT_CONNECTED":
                return {"connection": key, "verdict": "auth_required", "code": e.code, "checked_at": now_iso()}
            raise
        # 403 = zalogowano, ale konto nie ma dostępu do elementu próbnego: sesja żyje
        verdict = {"OK": "ok", "BASTION_RESOURCE_FORBIDDEN": "ok", "BASTION_EMBED_HOST_NOT_ALLOWED": "ok",
                   "BASTION_AUTH_REQUIRED": "auth_required"}.get(res.code, "unavailable")
        out = {"connection": key, "verdict": verdict, "code": res.code, "checked_at": now_iso(),
               "generation": info.get("generation"), "last_validated_at": info.get("last_validated_at")}
        if verdict == "ok":
            try:
                async with self.store.lock(key):
                    loaded = self.store.load(key)
                    if loaded:
                        meta = loaded[1]
                        cur = res.identity.get("id")
                        if cur and not meta.get("external_identity_id"):  # dopełnienie starej generacji
                            upd = self.merge_identity(meta, res.identity)
                            self.store.touch_meta(key, **upd)
                            meta = {**meta, **upd}
                        out.update(self._identity_view(meta))
                        stored = meta.get("external_identity_id")
                        out["identity_matches"] = (cur == stored) if cur and stored else None
            except crypto.CryptoError:
                pass
        return out

    def status(self, scope: str, judge_id: str | None) -> dict:
        key = conn_key_for(scope, judge_id)
        loaded = self.store.load(key)
        if not loaded:
            return {"connection": key, "status": "unconfigured", "expires_at": None}
        state, meta = loaded
        return {"connection": key, "status": "stored", "generation": meta.get("generation"),
                "connected_at": meta.get("connected_at"), "last_validated_at": meta.get("validated_at"),
                "last_error_code": meta.get("last_error_code"), "expires_at": None,
                **self._identity_view(meta), "cookies": cookie_summary(state)}

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
        a.on_change = self._persist_attempt
        self._persist_attempt(a)
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
        out = {"id": a.id, "scope": a.scope, "status": a.status, "expires_at": int(a.expires),
               "error": a.error, "connection": a.conn_key, "message": attempts_store.MESSAGES.get(a.status)}
        if a.status == "succeeded":
            ident = a.identity
            if not ident.get("external_identity_id"):  # po restarcie: z zaszyfrowanego stanu połączenia
                try:
                    loaded = self.store.load(a.conn_key)
                except Exception:  # noqa: BLE001
                    loaded = None
                ident = self._identity_view(loaded[1]) if loaded else {}
            out.update(ident)
        return out

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
        else:
            for method, params in key_to_cdp(m):
                await a.cdp.send(method, params)

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
                    **self.merge_identity(prev[1] if prev else {}, res.identity)}
            self.store.save(a.conn_key, state, meta)  # wymiana generacji dopiero po udanej weryfikacji
        a.identity = self._identity_view(meta)
        await self._close_attempt(a, "succeeded")

    def sweep(self) -> None:
        cutoff = time.time() - 3600
        for k in [k for k, a in self.attempts.items() if not a.active and a.expires < cutoff]:
            del self.attempts[k]
            self.attempt_store.delete(k)
