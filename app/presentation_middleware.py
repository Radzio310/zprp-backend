"""Tryb prezentacji - MIDDLEWARE (czysty ASGI, jak `app/client_key_guard.py`).

Montowany w main.py jako warstwa WEWNĄTRZ bramki klucza klienta (dodany przed
nią), więc bramka i CORS działają na udawanych odpowiedziach tak samo jak na
prawdziwych.

Droga żądania:

1. Tryb wyłączony (stan z pamięci, `presentation_state.current`) -> prosto do
   aplikacji. Zero czytania treści, zero kopii odpowiedzi.
2. Trasa spoza jawnej listy (`app/presentation_routes.py`) -> prosto do aplikacji.
3. Kto pyta: token BAZA (bez sprawdzania daty - wygasły token to nadal to
   konto), a dla tras z `identity="body"` także treść żądania (RSA `username`,
   `judge_id`, jawne `user`/`judge_id`). Treść buforujemy WYŁĄCZNIE w tym
   przypadku i oddajemy aplikacji nietkniętą, gdy pyta ktoś spoza trybu.
   `identity="synthetic"`: udawany numer w ścieżce wystarcza (wiersza i tak
   nie ma w bazie).
4. Konto prezentacji + trasa zapisu -> aplikacja NIE jest wołana; wpis w
   dzienniku, udawana odpowiedź (`app/presentation_sim.py`). Błąd symulatora
   też NIE przepuszcza zapisu - wraca zwykłe „ok".
5. Konto prezentacji + odczyt z nakładką -> prawdziwa odpowiedź, do której
   dokładamy udawane zmiany (tylko JSON 200).
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode

from app import presentation_routes as routes
from app import presentation_state as PS

log = logging.getLogger("presentation")

IDENTITY_FIELDS_RSA = ("username", "judge_id", "judgeId")
IDENTITY_FIELDS_PLAIN = ("user", "judge_id", "judgeId", "login")
MAX_BODY = 30 * 1024 * 1024


def _jwt_identity(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    auth = headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not token:
        return None
    try:
        from jose import jwt

        from app.client_key_guard import _jwt_secret

        secret, alg = _jwt_secret()
        payload = jwt.decode(token, secret, algorithms=[alg], options={"verify_exp": False, "verify_aud": False})
        return payload if isinstance(payload, dict) else None
    except Exception:  # noqa: BLE001 - nie nasz token = brak tożsamości z tokenu
        return None


_private_key: Any = None


def _rsa_key():
    global _private_key
    if _private_key is None:
        from app.deps import get_rsa_keys

        _private_key = get_rsa_keys()[0]
    return _private_key


def decrypt_candidates(value: Any) -> List[str]:
    """Możliwe odczyty pola: szyfrogram RSA (też z base64 w środku, jak w silesia)."""
    text = "" if value is None else str(value).strip()
    if len(text) < 40:
        return []
    try:
        from cryptography.hazmat.primitives.asymmetric import padding

        plain = _rsa_key().decrypt(base64.b64decode(text), padding.PKCS1v15())
        out = [plain.decode("utf-8", errors="strict").strip()]
    except Exception:  # noqa: BLE001 - to nie szyfrogram
        return []
    try:
        inner = base64.b64decode(out[0], validate=True).decode("utf-8", errors="strict").strip()
        if inner:
            out.append(inner)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    return [o for o in out if o]


def body_identities(body: Any, query: Dict[str, str], path_params: Dict[str, str]) -> List[str]:
    """Wszystkie napisy z treści, które mogą wskazywać pytającego."""
    found: List[str] = []
    sources: List[Dict[str, Any]] = []
    if isinstance(body, dict):
        sources.append(body)
    sources.append(query)
    for src in sources:
        for key in IDENTITY_FIELDS_PLAIN:
            v = src.get(key)
            if isinstance(v, (str, int)) and str(v).strip() and len(str(v)) <= 80:
                found.append(str(v).strip())
        for key in IDENTITY_FIELDS_RSA:
            found.extend(decrypt_candidates(src.get(key)))
    # DELETE /silesia/offtimes/{judge_id_enc}: numer zaszyfrowany w ścieżce.
    for v in path_params.values():
        found.extend(decrypt_candidates(v))
    return found


def parse_body(raw: bytes, content_type: str) -> Any:
    ct = (content_type or "").lower()
    if not raw:
        return None
    if "application/json" in ct or raw[:1] in (b"{", b"["):
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
    if "application/x-www-form-urlencoded" in ct:
        return dict(parse_qsl(raw.decode("latin-1"), keep_blank_values=True))
    return None


async def parse_multipart(scope: Dict[str, Any], raw: bytes) -> Dict[str, Any]:
    """Pola tekstowe formularza multipart (pliki pomijamy - podajemy samą nazwę)."""
    from starlette.datastructures import UploadFile
    from starlette.requests import Request

    sent = {"done": False}

    async def receive() -> Dict[str, Any]:
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": raw, "more_body": False}

    out: Dict[str, Any] = {}
    try:
        form = await Request(dict(scope), receive).form()
        for key, value in form.multi_items():
            if isinstance(value, UploadFile):
                out[key] = {"filename": value.filename}
            else:
                out[key] = value
        await form.close()
    except Exception:  # noqa: BLE001
        log.info("tryb prezentacji: formularz multipart nieczytelny", exc_info=True)
    return out


class Captured:
    def __init__(self) -> None:
        self.status = 500
        self.headers: List[Tuple[bytes, bytes]] = []
        self.body = bytearray()

    def header(self, name: str) -> str:
        n = name.lower().encode("latin-1")
        for k, v in self.headers:
            if k.lower() == n:
                return v.decode("latin-1")
        return ""

    def json(self) -> Any:
        raw = bytes(self.body)
        if "gzip" in self.header("content-encoding").lower():
            # Bootstrap Obsady pakuje się sam (gdy klient przyjmuje gzip).
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None


class PresentationMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            state = await PS.current()
        except Exception:  # noqa: BLE001
            state = PS.cached_state()
        if not state.active():
            await self.app(scope, receive, send)
            return
        method = (scope.get("method") or "GET").upper()
        path = scope.get("path") or "/"
        write = routes.match_write(method, path)
        read = None if write else routes.match_read(method, path)
        route = write[0] if write else (read[0] if read else None)
        if route is None or route.area not in state.areas:
            await self.app(scope, receive, send)
            return
        params = (write or read)[1]
        holder: Dict[str, Any] = {"replay": None}
        try:
            ctx = await self._identify(scope, receive, state, method, path, write, read, params, holder)
        except Exception:  # noqa: BLE001 - błąd rozpoznania nie może zepsuć zwykłego ruchu
            log.exception("tryb prezentacji: rozpoznanie pytającego nie zadziałało (%s %s)", method, path)
            ctx = None
            if write is not None and holder.get("account"):
                # Konto prezentacji już rozpoznane - zapis NIE może przejść.
                await send_json(send, write[0].status, {"ok": True, "success": True})
                return
        if ctx is None:
            await self.app(scope, holder["replay"] or receive, send)
            return
        if write is not None:
            await self._simulate(ctx, write[0], send)
            return
        await self._merge(ctx, read[0], scope, holder["replay"] or receive, send)

    async def _identify(self, scope, receive, state, method, path, write, read, params, holder):
        from app import presentation_sim as sim

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        query = dict(parse_qsl((scope.get("query_string") or b"").decode("latin-1"), keep_blank_values=True))
        payload = _jwt_identity(headers)
        account = None
        if payload:
            account = state.account_for(judge_id=payload.get("judge_id"), login=payload.get("sub"))
            if account:
                holder["account"] = account
                if payload.get("judge_id") and payload.get("sub"):
                    PS.learn(payload.get("sub"), payload.get("judge_id"))

        raw: Optional[bytes] = None
        body: Any = None
        route = write[0] if write is not None else read[0]
        # Token BAZA, jeśli jest, rozstrzyga sam: w treści bywa numer sędziego, któremu
        # ktoś INNY coś zapisuje (Calendar Master, partner) - to nie jest pytający.
        body_identity = payload is None and route.identity == "body"
        if account is None and route.identity == "synthetic" and PS.is_synthetic(params.get("id")):
            # Udawany numer w ścieżce: wiersza nie ma w bazie, więc to i tak sprawa nakładki.
            account = "synthetic"
        if (write is not None and account is not None) or body_identity:
            raw = await _read_body(receive)
            holder["replay"] = _replay(raw, receive)
            ctype = headers.get("content-type", "")
            body = await parse_multipart(scope, raw) if "multipart/form-data" in ctype.lower() else parse_body(raw, ctype)
            if account is None and body_identity:
                for candidate in body_identities(body, query, params):
                    account = state.account_for(judge_id=candidate, login=candidate)
                    if account:
                        break
        if account is None:
            return None
        holder["account"] = account
        return sim.Ctx(
            app=self.app,
            scope=scope,
            method=method,
            path=path,
            params=params,
            query=query,
            headers=headers,
            raw=raw,
            body=body,
            jwt=payload,
            account=account,
            state=state,
        )

    async def _simulate(self, ctx, route, send) -> None:
        from app import presentation_sim as sim

        fn = sim.SIMS.get(route.sim) or sim.SIMS["ok_success"]
        try:
            result = await fn(ctx, route)
        except Exception:  # noqa: BLE001 - zapis i tak NIE przechodzi
            log.exception("tryb prezentacji: symulator %s nie zadziałał (%s %s)", route.sim, ctx.method, ctx.path)
            result = sim.Result(route.status, {"ok": True, "success": True}, route.label)
        await PS.record_op(
            account=ctx.account,
            area=route.area,
            method=ctx.method,
            path=ctx.path,
            summary=result.summary or route.label,
            payload=ctx.body,
            extra=result.extra,
        )
        await send_json(send, result.status, result.body)

    async def _merge(self, ctx, route, scope, receive, send) -> None:
        from app import presentation_sim as sim

        fn = sim.MERGES.get(route.merge)
        if fn is None:
            await self.app(scope, receive, send)
            return
        try:
            replaced = await fn(ctx, None)
        except Exception:  # noqa: BLE001
            log.exception("tryb prezentacji: nakładka %s (przed) nie zadziałała", route.merge)
            replaced = None
        if isinstance(replaced, sim.Result):
            await send_json(send, replaced.status, replaced.body)
            return
        inner_scope = sim.strip_conditional(scope) if getattr(fn, "strip_etag", False) else scope
        captured = await call_capture(self.app, inner_scope, receive)
        data = captured.json() if captured.status == 200 and "json" in captured.header("content-type") else None
        if data is not None:
            try:
                merged = await fn(ctx, data)
                if merged is not None and not isinstance(merged, sim.Result):
                    await send_json(send, 200, merged, extra=_keep_headers(captured))
                    return
            except Exception:  # noqa: BLE001 - zostaje prawdziwa odpowiedź
                log.exception("tryb prezentacji: nakładka %s nie zadziałała", route.merge)
        await send_captured(send, captured)


async def _read_body(receive) -> bytes:
    chunks = bytearray()
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            break
        chunks.extend(message.get("body") or b"")
        if len(chunks) > MAX_BODY:
            break
        if not message.get("more_body"):
            break
    return bytes(chunks)


def _replay(raw: bytes, receive):
    state = {"sent": False}

    async def again() -> Dict[str, Any]:
        if not state["sent"]:
            state["sent"] = True
            return {"type": "http.request", "body": raw, "more_body": False}
        return await receive()

    return again


def _keep_headers(captured: "Captured") -> List[Tuple[bytes, bytes]]:
    keep = (b"etag", b"cache-control", b"vary")
    return [(k, v) for k, v in captured.headers if k.lower() in keep]


async def call_capture(app, scope: Dict[str, Any], receive) -> Captured:
    out = Captured()

    async def capture(message: Dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            out.status = int(message.get("status") or 500)
            out.headers = list(message.get("headers") or [])
        elif message["type"] == "http.response.body":
            out.body.extend(message.get("body") or b"")

    await app(scope, receive, capture)
    return out


async def send_captured(send, captured: Captured) -> None:
    await send({"type": "http.response.start", "status": captured.status, "headers": captured.headers})
    await send({"type": "http.response.body", "body": bytes(captured.body)})


async def send_json(send, status: int, body: Any, extra: Optional[List[Tuple[bytes, bytes]]] = None) -> None:
    headers = [(b"x-presentation", b"1"), (b"cache-control", b"no-store")]
    if status == 204 or body is None:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b""})
        return
    data = json.dumps(body, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())] + [
        h for h in (extra or []) if h[0].lower() != b"cache-control"
    ] + headers
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})


def subrequest_scope(
    scope: Dict[str, Any], method: str, path: str, query: Optional[Dict[str, Any]] = None, content_type: Optional[str] = None
) -> Dict[str, Any]:
    inner = dict(scope)
    inner["method"] = method.upper()
    inner["path"] = path
    inner["raw_path"] = path.encode("utf-8")
    inner["query_string"] = urlencode({k: v for k, v in (query or {}).items() if v is not None}).encode("latin-1")
    hdrs = [(k, v) for k, v in scope.get("headers") or [] if k.lower() not in (b"content-length", b"content-type", b"if-none-match")]
    if content_type:
        hdrs.append((b"content-type", content_type.encode("latin-1")))
    inner["headers"] = hdrs
    return inner


Receiver = Callable[[], Awaitable[Dict[str, Any]]]


def body_receiver(raw: bytes) -> Receiver:
    sent = {"done": False}

    async def receive() -> Dict[str, Any]:
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return receive
