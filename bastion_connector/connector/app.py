"""bastion-connector: HTTP (serwer-serwer, token) + WSS widoku logowania (bilet jednorazowy + Origin)."""
from __future__ import annotations

import asyncio
import hmac
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .config import Settings
from .service import ConnectorError, Service
from .tickets import TicketError
from .urlrules import JUDGE_ID_RE, origin_allowed, parse_game_url

settings = Settings.from_env()
svc: Service | None = None
STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global svc
    if len(settings.connector_token) < 32 or len(settings.ticket_secret) < 32:
        raise RuntimeError("BASTION_CONNECTOR_TOKEN i BASTION_TICKET_SECRET musza miec >= 32 znaki")
    svc = Service(settings)
    await svc.start()
    app.state.sweeper = asyncio.create_task(_sweeper())
    yield
    app.state.sweeper.cancel()
    await svc.stop()


async def _sweeper():
    while True:
        await asyncio.sleep(300)
        svc.sweep()


app = FastAPI(title="bastion-connector", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
# CORS tylko dla jawnie dozwolonych Origin (strona testowa na domenie BAZY wola /playback z tokenem).
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_methods=["GET", "POST", "DELETE"],
                   allow_headers=["Authorization", "Content-Type"], max_age=600)


@app.exception_handler(ConnectorError)
async def _ce(_: Request, e: ConnectorError):
    return JSONResponse({"error": e.code, "detail": e.detail}, status_code=e.status,
                        headers={"Cache-Control": "no-store"})


def auth(authorization: str = Header(default="")) -> None:
    scheme, _, tok = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(tok.encode(), settings.connector_token.encode()):
        raise HTTPException(401, "unauthorized")


def _judge(v: str | None) -> str | None:
    if v is not None and not JUDGE_ID_RE.match(v):
        raise ConnectorError("BAD_JUDGE_ID", 400)
    return v


def _scope(scope: str, judge_id: str | None) -> str | None:
    if scope not in ("default", "personal"):
        raise ConnectorError("BAD_SCOPE", 400)
    if scope == "personal" and not _judge(judge_id):
        raise ConnectorError("BAD_JUDGE_ID", 400)
    return judge_id


@app.get("/health")
async def health():
    return {"ok": True, "browser": svc._browser is not None and svc._browser.is_connected()}


class AttemptIn(BaseModel):
    scope: str
    judge_id: str  # prawdziwy judge_id inicjatora (backend BAZY ustala go z sesji, nie z act_as)
    probe_bunny_item_id: int | None = None


@app.post("/attempts", dependencies=[Depends(auth)])
async def create_attempt(body: AttemptIn):
    _judge(body.judge_id)
    _scope(body.scope, body.judge_id)
    a, ticket, resumed = await svc.create_attempt(body.scope, body.judge_id, body.probe_bunny_item_id)
    return JSONResponse({**svc.public_attempt(a), "ticket": ticket, "ticket_ttl_s": settings.ticket_ttl_s,
                         "ws_path": f"/ws/login/{a.id}", "resumed": resumed}, headers={"Cache-Control": "no-store"})


@app.get("/attempts/{attempt_id}", dependencies=[Depends(auth)])
async def get_attempt(attempt_id: str):
    return JSONResponse(svc.public_attempt(svc.get_attempt(attempt_id)), headers={"Cache-Control": "no-store"})


@app.post("/attempts/{attempt_id}/ticket", dependencies=[Depends(auth)])
async def new_ticket(attempt_id: str):
    a = svc.get_attempt(attempt_id)
    return JSONResponse({"ticket": svc.new_ticket(a), "ticket_ttl_s": settings.ticket_ttl_s},
                        headers={"Cache-Control": "no-store"})


@app.post("/attempts/{attempt_id}/cancel", dependencies=[Depends(auth)])
async def cancel_attempt(attempt_id: str):
    a = svc.get_attempt(attempt_id)
    await svc.cancel(a)
    return svc.public_attempt(a)


@app.get("/connections/status", dependencies=[Depends(auth)])
async def conn_status(scope: str, judge_id: str | None = None):
    _scope(scope, judge_id)
    return JSONResponse(svc.status(scope, judge_id), headers={"Cache-Control": "no-store"})


@app.get("/connections/check", dependencies=[Depends(auth)])
async def conn_check(scope: str, judge_id: str | None = None, probe_bunny_item_id: int | None = None):
    """Lekka weryfikacja sesji bez wydawania embedu. 200 + verdict: ok | auth_required | unavailable."""
    _scope(scope, judge_id)
    return JSONResponse(await svc.check(scope, judge_id, probe_bunny_item_id), headers={"Cache-Control": "no-store"})


@app.delete("/connections", dependencies=[Depends(auth)])
async def conn_delete(scope: str, judge_id: str | None = None):
    _scope(scope, judge_id)
    return {"deleted": svc.disconnect(scope, judge_id)}


class ClipIn(BaseModel):
    scope: str
    judge_id: str
    bunny_item_id: int
    start_s: int  # calkowite sekundy; ulamek = 422 (nic nie zaokraglamy po cichu)
    end_s: int


def _clip_id(v: str) -> str:
    if not v.isdigit() or len(v) > 12:
        raise ConnectorError("BAD_CLIP_ID", 400)
    return v


@app.post("/probe/clip", dependencies=[Depends(auth)])
async def probe_clip(body: ClipIn):
    """P8: JEDEN prywatny klip na koncie Bastionu tego polaczenia. Zlecenie wysylane raz; po timeoucie
    needs_reconciliation (202) i zero ponowien."""
    _judge(body.judge_id)
    _scope(body.scope, body.judge_id)
    if body.bunny_item_id < 1:
        raise ConnectorError("BAD_GAME_URL", 400)
    rec, http = await svc.clip_submit(body.scope, body.judge_id, body.bunny_item_id, body.start_s, body.end_s)
    return JSONResponse(rec, status_code=http, headers={"Cache-Control": "no-store"})


@app.get("/probe/clip/{clip_id}", dependencies=[Depends(auth)])
async def probe_clip_context(clip_id: str, scope: str, judge_id: str | None = None):
    _scope(scope, judge_id)
    return JSONResponse(await svc.clip_context(scope, judge_id, _clip_id(clip_id)), headers={"Cache-Control": "no-store"})


@app.post("/probe/clip/{clip_id}/download", dependencies=[Depends(auth)])
async def probe_clip_download(clip_id: str, scope: str, judge_id: str | None = None):
    _scope(scope, judge_id)
    return JSONResponse(await svc.clip_download(scope, judge_id, _clip_id(clip_id)), headers={"Cache-Control": "no-store"})


class ClipCreateIn(BaseModel):
    scope: str
    judge_id: str | None = None  # wymagane dla scope=personal
    bunny_item_id: int
    start_s: int  # calkowite sekundy 2-300; ulamek = 422 (nic nie zaokraglamy po cichu)
    end_s: int
    fingerprint: str  # odcisk zlecenia z BAZY: ten sam odcisk = ten sam wynik, zero drugiego POST
    correlation: str  # nieczytelny id zadania; trafia do tresci klipu w Bastionie ("BAZA Mentor <korelacja>")


@app.post("/clips", dependencies=[Depends(auth)])
async def create_clip(body: ClipCreateIn):
    """Produkcja: JEDEN prywatny klip (ONLY_ME, NORMAL, PLAY_ON). 200 = zlecono (remote_id), 202 = needs_reconciliation
    (bez ponowien), ten sam odcisk = ten sam wynik z ksiegi (`idempotent: true`)."""
    _scope(body.scope, body.judge_id)
    if body.bunny_item_id < 1:
        raise ConnectorError("BAD_GAME_URL", 400)
    rec, http = await svc.clip_create(body.scope, body.judge_id, body.bunny_item_id, body.start_s, body.end_s,
                                      body.fingerprint, body.correlation)
    return JSONResponse(rec, status_code=http, headers={"Cache-Control": "no-store"})


@app.get("/clips/{remote_id}", dependencies=[Depends(auth)])
async def clip_state(remote_id: str, scope: str, judge_id: str | None = None):
    _scope(scope, judge_id)
    ctx = await svc.clip_context(scope, judge_id, _clip_id(remote_id), strict=True)
    return JSONResponse({**ctx, "ready": bool(ctx.get("download_available"))}, headers={"Cache-Control": "no-store"})


@app.post("/clips/{remote_id}/download-url", dependencies=[Depends(auth)])
async def clip_download_url(remote_id: str, scope: str, judge_id: str | None = None):
    _scope(scope, judge_id)
    return JSONResponse(await svc.clip_download_url(scope, judge_id, _clip_id(remote_id)), headers={"Cache-Control": "no-store"})


@app.get("/playback", dependencies=[Depends(auth)])
async def playback(scope: str, bunny_item_id: int | None = None, game_url: str | None = None,
                   judge_id: str | None = None, include_embed: bool = True):
    """Zwraca game-context sesji. embed_url jest czasowym, wrazliwym adresem: no-store, nigdy do logow."""
    _scope(scope, judge_id)
    item = bunny_item_id or (parse_game_url(game_url) if game_url else None)
    if not item or item < 1:
        raise ConnectorError("BAD_GAME_URL", 400)
    res, info = await svc.game_context(scope, judge_id, item)
    http = {"OK": 200, "BASTION_AUTH_REQUIRED": 409, "BASTION_RESOURCE_FORBIDDEN": 403,
            "BASTION_RATE_LIMITED": 429}.get(res.code, 503 if res.code != "BASTION_BAD_RESPONSE" else 502)
    body = {"code": res.code, "bunny_item_id": item, "video_state": res.video_state, "expires_at": res.expires_at,
            "game_context_keys": res.top_keys, "detail": res.detail, "match": res.match, **info}
    if res.embed_url and include_embed:
        body["embed_url"] = res.embed_url
    return JSONResponse(body, status_code=http, headers={"Cache-Control": "no-store"})


@app.websocket("/ws/login/{attempt_id}")
async def ws_login(ws: WebSocket, attempt_id: str):
    # Origin sprawdzany PRZED zaakceptowaniem polaczenia
    if not origin_allowed(ws.headers.get("origin"), settings.allowed_origins):
        await ws.close(code=4403)
        return
    a = svc.attempts.get(attempt_id)
    if not a or not a.active:
        await ws.close(code=4404)
        return
    await ws.accept()
    try:
        first = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=10))
        if first.get("type") != "auth":
            raise TicketError("brak biletu")
        svc.registry.consume(settings.ticket_secret, str(first.get("ticket", "")), a.id, a.judge_id)
        await svc.attach_viewer(a, ws)
    except (TicketError, ConnectorError, asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        await ws.close(code=4401)
        return
    await ws.send_json({"type": "ready", "w": 1100, "h": 700, "status": a.status})
    try:
        while a.active and a.viewer is ws:
            raw = await ws.receive_text()
            if len(raw) > 4096 or a.viewer is not ws:  # widok przejety przez inna karte: wejscie ignorowane
                continue
            try:
                await svc.handle_input(a, json.loads(raw))
            except (ValueError, TypeError):
                continue
    except (WebSocketDisconnect, RuntimeError):  # RuntimeError: odbior po zamknieciu przy przejeciu widoku
        pass
    finally:
        await svc.detach_viewer(a, ws)  # rozlaczenie widoku NIE jest sukcesem ani anulowaniem; proba wygasa sama


if settings.test_page:
    @app.get("/test")
    async def test_page():
        return FileResponse(STATIC / "test.html", headers={"Cache-Control": "no-store"})
