"""
Egzamin na żywo - trasy HTTP, WebSocket i strony (etap 5, 16.10.2026).

Fabryka `build_router(deps)` nie importuje `app.db`: baza, uprawnienia i weryfikacja tokenu
przychodzą w `LiveDeps`. Produkcyjne wiązanie jest w `app/exam_live.py`, testy podają SQLite.

Model (wzorzec Communio „Śpiewajmy razem”): serwer trzyma stan, po każdej zmianie rozgłasza
MIGAWKĘ (nie różnice) przez WebSocket, a kto dołącza albo traci gniazdo, robi GET migawki
(`rev` pozwala odpytywać tanio: `?since_rev=` zwraca `{unchanged:true}`). Każda rola dostaje
własny widok z `exam_live_rules.view_for` - klucz poprawnych odpowiedzi jest tylko w reveal.

Gniazda: tylko w pamięci jednego procesu, granica opisana w `exam_live_hub.py`.

Trasy publiczne (bez logowania, dostęp przez nie do zgadnięcia token sesji z adresu):
rzutnik (`/projector/{token}`), jego migawka i kod QR, strona gościa (`/join`).
Gość odpowiada tylko z `guest_token` wydanym przy dołączeniu, i tylko gdy prowadzący włączył gości.
"""

from __future__ import annotations

import asyncio
import io
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app import exam_live_rules as L
from app import exam_live_service as V
from app import exam_service as S
from app.exam_live_hub import Conn, Hub
from app.exam_rules import ExamError

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent / "exam_live_web"
ASSETS = {"live.css": "text/css; charset=utf-8", "live.js": "application/javascript; charset=utf-8",
          "projector.js": "application/javascript; charset=utf-8", "guest.js": "application/javascript; charset=utf-8"}
PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'")

WS_BAD_AUTH = 4401
WS_FORBIDDEN = 4403
WS_GONE = 4404


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class LiveDeps:
    #: -> LiveStore (leniwie: app.db łączy się z bazą przy imporcie)
    store: Callable[[], V.LiveStore]
    #: zależność FastAPI zwracająca S.Who (zalogowany użytkownik)
    who: Callable[..., Any]
    #: async (token JWT) -> judge_id | None; do uwierzytelnienia gniazda
    identify: Callable[[str], Awaitable[Optional[str]]]
    now: Callable[[], datetime] = _utcnow
    hub: Hub = field(default_factory=Hub)


class _Throttle:
    """Ochrona przed zgadywaniem PIN-ów: ograniczona liczba nieudanych prób z jednego adresu na minutę."""

    def __init__(self, limit: int = 20, window_s: float = 60.0):
        self.limit, self.window_s = limit, window_s
        self.fails: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        q = self.fails[key]
        cutoff = time.monotonic() - self.window_s
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.limit:
            raise ExamError("LIVE_TOO_MANY_TRIES", "Za dużo błędnych kodów. Odczekaj minutę i spróbuj ponownie.", 429)

    def fail(self, key: str) -> None:
        self.fails[key].append(time.monotonic())
        if len(self.fails) > 5000:
            for k in [k for k, v in self.fails.items() if not v][:2500]:
                self.fails.pop(k, None)


class CreateBody(BaseModel):
    scope: Optional[str] = None
    province: Optional[str] = None
    exam_id: Optional[str] = None
    title: Optional[str] = None
    character: Optional[str] = None
    phone_view: Optional[str] = None
    guests_allowed: bool = False
    question_ids: Optional[List[str]] = None
    pool: Optional[Dict[str, Any]] = None
    shuffle: bool = False
    config: Dict[str, Any] = Field(default_factory=dict)


class ControlBody(BaseModel):
    action: str
    from_phase: Optional[str] = None
    from_index: Optional[int] = None


class PatchBody(BaseModel):
    guests_allowed: Optional[bool] = None
    phone_view: Optional[str] = None
    auto_reveal: Optional[bool] = None
    question_time_s: Optional[int] = None
    ranking: Optional[Dict[str, Any]] = None


class JoinBody(BaseModel):
    pin: Optional[str] = None
    token: Optional[str] = None
    nick: Optional[str] = None


class AnswerBody(BaseModel):
    selected: List[str] = Field(default_factory=list)
    gt: Optional[str] = None


def _http(error: ExamError) -> HTTPException:
    return HTTPException(error.status, detail={"code": error.code, "message": error.message, **error.extra})


async def _run(call: Awaitable[Any]) -> Any:
    try:
        return await call
    except ExamError as error:
        raise _http(error)


def _page(name: str) -> HTMLResponse:
    html = (WEB_DIR / name).read_text(encoding="utf-8")
    return HTMLResponse(html, headers={"Content-Security-Policy": PAGE_CSP, "Cache-Control": "no-store",
                                       "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"})


def _base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto.split(',')[0].strip()}://{host.split(',')[0].strip()}"


def build_router(deps: LiveDeps) -> APIRouter:
    router = APIRouter(prefix="/exam-live", tags=["ExamLive"])
    hub = deps.hub
    throttle = _Throttle()

    def ls() -> V.LiveStore:
        return deps.store()

    # -- widoki -----------------------------------------------------------

    def viewer_of(state: Dict[str, Any], pid: Optional[str]) -> Optional[Dict[str, Any]]:
        return next((p for p in state["participants"] if p["id"] == pid), None) if pid else None

    async def fresh_state(sid: str) -> Dict[str, Any]:
        """Stan po leniwym upływie czasu; uzbraja zegar terminu pytania."""
        now = deps.now()
        store = ls()
        if await V.tick(store, sid, now):
            hub.schedule(sid, render, immediate=True)
        state = await V.load_state(store, sid, now)
        arm_timer(state)
        return state

    def arm_timer(state: Dict[str, Any]) -> None:
        s = state["session"]
        if s["phase"] == "question" and s["deadline_at"] and s["config"]["auto_reveal"]:
            delay = (s["deadline_at"] - deps.now()).total_seconds() + 0.05

            async def fire() -> None:
                if await V.tick(ls(), s["id"], deps.now()):
                    await render(s["id"])

            hub.arm(s["id"], (s["q_index"], s["deadline_at"].isoformat()), delay, fire)
        elif s["phase"] != "question":
            hub.forget(s["id"])

    async def render(sid: str) -> None:
        """Rozsyła migawkę każdemu gniazdu (widok per rola; wspólny dla hosta i rzutnika)."""
        conns = hub.of(sid)
        if not conns:
            return
        state = await fresh_state(sid)
        now = deps.now()
        shared: Dict[str, Dict[str, Any]] = {}
        for conn in conns:
            if conn.role == "player":
                view = L.view_for("player", state, viewer_of(state, conn.participant_id), now)
            else:
                view = shared.get(conn.role) or shared.setdefault(conn.role, L.view_for(conn.role, state, None, now))
            await hub.send(sid, conn, {"type": "snapshot", "rev": view["rev"], "snapshot": view})

    def changed(sid: str, *, immediate: bool) -> None:
        hub.schedule(sid, render, immediate=immediate)

    def view_response(state: Dict[str, Any], role: str, pid: Optional[str], since_rev: Optional[int], response: Response) -> Dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        now = deps.now()
        if since_rev is not None and since_rev == state["session"]["rev"] and state["session"]["phase"] != "question":
            return {"unchanged": True, "rev": since_rev, "server_now": now.isoformat()}
        return L.view_for(role, state, viewer_of(state, pid), now)

    # -- prowadzący -------------------------------------------------------

    @router.post("", summary="Utwórz sesję na żywo (prowadzący)")
    async def create(body: CreateBody, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        state = await _run(V.create_session(ls(), who, body.model_dump(exclude_none=True), deps.now()))
        return L.view_for("host", state, None, deps.now())

    @router.get("/hosted", summary="Moje sesje na żywo")
    async def hosted(who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        return await _run(V.hosted_list(ls(), who, deps.now()))

    @router.post("/join", summary="Dołącz do sesji PIN-em albo tokenem z QR (zalogowany)")
    async def join(request: Request, body: JoinBody, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        key = request.client.host if request.client else "?"
        try:
            throttle.check(key)
        except ExamError as error:
            raise _http(error)
        try:
            joined = await V.join_user(ls(), who, body.model_dump(), deps.now())
        except ExamError as error:
            if error.code in ("LIVE_PIN_UNKNOWN", "LIVE_BAD_PIN", "LIVE_NOT_FOUND"):
                throttle.fail(key)
            raise _http(error)
        sid = joined["session"]["id"]
        changed(sid, immediate=False)
        state = await fresh_state(sid)
        return {"session_id": sid, "participant_id": joined["participant"]["id"], "rejoined": joined["rejoined"],
                "snapshot": L.view_for("player", state, viewer_of(state, joined["participant"]["id"]), deps.now())}

    @router.post("/guest/join", summary="Dołącz z przeglądarki jako gość (nick, tylko gdy prowadzący włączył gości)")
    async def guest_join(request: Request, body: JoinBody) -> Dict[str, Any]:
        key = request.client.host if request.client else "?"
        try:
            throttle.check(key)
        except ExamError as error:
            raise _http(error)
        try:
            joined = await V.join_guest(ls(), body.model_dump(), body.nick, deps.now())
        except ExamError as error:
            if error.code in ("LIVE_PIN_UNKNOWN", "LIVE_BAD_PIN", "LIVE_NOT_FOUND"):
                throttle.fail(key)
            raise _http(error)
        sid = joined["session"]["id"]
        changed(sid, immediate=False)
        state = await fresh_state(sid)
        p = joined["participant"]
        return {"session_id": sid, "participant_id": p["id"], "guest_token": p["guest_token"], "name": p["name"],
                "snapshot": L.view_for("player", state, viewer_of(state, p["id"]), deps.now())}

    @router.get("/guest/{sid}/state", summary="Migawka dla gościa")
    async def guest_state(sid: str, response: Response, gt: str = Query(""), since_rev: Optional[int] = Query(None)) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            p = await V.participant_by_guest(ls(), sid, gt)
            if not p:
                raise ExamError("LIVE_NOT_JOINED", "Nie rozpoznaję Cię w tej sesji. Dołącz ponownie kodem PIN.", 403)
            state = await fresh_state(sid)
            return view_response(state, "player", p["id"], since_rev, response)

        return await _run(go())

    @router.post("/guest/{sid}/answer", summary="Odpowiedź gościa")
    async def guest_answer(sid: str, body: AnswerBody) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            p = await V.participant_by_guest(ls(), sid, body.gt or "")
            if not p:
                raise ExamError("LIVE_NOT_JOINED", "Nie rozpoznaję Cię w tej sesji. Dołącz ponownie kodem PIN.", 403)
            return await answer_flow(sid, p["id"], body.selected)

        return await _run(go())

    async def answer_flow(sid: str, pid: str, selected: List[str]) -> Dict[str, Any]:
        result = await V.submit_answer(ls(), sid, pid, selected, deps.now())
        changed(sid, immediate=bool(result["everyone_answered"]))
        state = await fresh_state(sid)
        return {**result, "snapshot": L.view_for("player", state, viewer_of(state, pid), deps.now())}

    # -- rzutnik i strony (bez logowania) ---------------------------------

    @router.get("/projector/{token}/state", summary="Migawka rzutnika (dostęp przez token sesji)")
    async def projector_state(token: str, response: Response, since_rev: Optional[int] = Query(None)) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            s = await V.session_by_token(ls(), token)
            state = await fresh_state(s["id"])
            return view_response(state, "projector", None, since_rev, response)

        return await _run(go())

    @router.get("/projector/{token}/qr.svg", summary="Kod QR do dołączenia (SVG)")
    async def projector_qr(token: str, request: Request) -> Response:
        import qrcode
        import qrcode.image.svg

        await _run(V.session_by_token(ls(), token))
        url = f"{_base_url(request)}/exam-live/join/{token}"
        img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=1,
                          error_correction=qrcode.constants.ERROR_CORRECT_M)
        buf = io.BytesIO()
        img.save(buf)
        return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

    @router.get("/projector/{token}", summary="Strona rzutnika", response_class=HTMLResponse)
    async def projector_page(token: str) -> HTMLResponse:
        return _page("projector.html")

    @router.get("/join", summary="Strona gościa: PIN + nick", response_class=HTMLResponse)
    async def join_page() -> HTMLResponse:
        return _page("guest.html")

    @router.get("/join/{token}", summary="Strona gościa z kodu QR", response_class=HTMLResponse)
    async def join_page_token(token: str) -> HTMLResponse:
        return _page("guest.html")

    @router.get("/assets/{name}", summary="Style i skrypty stron rzutnika i gościa")
    async def asset(name: str) -> Response:
        if name not in ASSETS:
            raise HTTPException(404, detail={"code": "LIVE_ASSET", "message": "Nie ma takiego pliku."})
        return Response((WEB_DIR / name).read_bytes(), media_type=ASSETS[name], headers={"Cache-Control": "public, max-age=300"})

    # -- zalogowani: stan, sterowanie, odpowiedzi -------------------------

    @router.get("/{sid}/state", summary="Migawka dla prowadzącego albo uczestnika")
    async def state_route(sid: str, response: Response, since_rev: Optional[int] = Query(None),
                          who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            s = await V.session_row(ls(), sid)
            if s["host_id"] == who.judge_id:
                state = await fresh_state(sid)
                return view_response(state, "host", None, since_rev, response)
            p = await V.participant_by_judge(ls(), sid, who.judge_id)
            if not p:
                raise ExamError("LIVE_NOT_JOINED", "Nie dołączyłeś(-aś) do tej sesji. Wpisz kod PIN, żeby dołączyć.", 403)
            state = await fresh_state(sid)
            return view_response(state, "player", p["id"], since_rev, response)

        return await _run(go())

    @router.post("/{sid}/control", summary="Sterowanie fazami (tylko prowadzący): next | reveal | end")
    async def control(sid: str, body: ControlBody, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        state = await _run(V.control(ls(), who, sid, body.action, deps.now(),
                                     {"from_phase": body.from_phase, "from_index": body.from_index}))
        arm_timer(state)
        changed(sid, immediate=True)
        return L.view_for("host", state, None, deps.now())

    @router.patch("/{sid}", summary="Zmień ustawienia w trakcie (goście, widok telefonu, ranking)")
    async def patch(sid: str, body: PatchBody, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        state = await _run(V.patch_session(ls(), who, sid, body.model_dump(exclude_none=True), deps.now()))
        changed(sid, immediate=True)
        return L.view_for("host", state, None, deps.now())

    @router.post("/{sid}/answer", summary="Odpowiedz na bieżące pytanie")
    async def answer(sid: str, body: AnswerBody, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            p = await V.participant_by_judge(ls(), sid, who.judge_id)
            if not p:
                raise ExamError("LIVE_NOT_JOINED", "Nie dołączyłeś(-aś) do tej sesji. Wpisz kod PIN, żeby dołączyć.", 403)
            return await answer_flow(sid, p["id"], body.selected)

        return await _run(go())

    @router.get("/{sid}/results", summary="Trwałe wyniki zakończonej sesji (prowadzący albo komisja)")
    async def results(sid: str, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        return await _run(V.results(ls(), who, sid, deps.now()))

    # -- WebSocket --------------------------------------------------------

    @router.websocket("/ws/{ref}")
    async def ws_endpoint(websocket: WebSocket, ref: str, role: str = Query(...), token: Optional[str] = Query(None),
                          gt: Optional[str] = Query(None)) -> None:
        """Jedno gniazdo na urządzenie. `role`: host | player | guest | projector.
        host/player: `token` = JWT aplikacji. guest: `gt` = guest_token. projector: `ref` = token sesji.
        Ramki serwera: snapshot, ack, error, pong. Ramki klienta: ping, refresh, answer, control (host)."""
        await websocket.accept()

        async def refuse(code: int, err_code: str, message: str) -> None:
            try:
                await websocket.send_json({"type": "error", "code": err_code, "message": message})
                await websocket.close(code=code)
            except Exception:  # noqa: BLE001
                pass

        try:
            store = ls()
            if role == "projector":
                s = await V.session_by_token(store, ref)
                conn = Conn(websocket, "projector")
            else:
                s = await V.session_row(store, ref)
                if role == "host" or role == "player":
                    judge = await deps.identify(token or "")
                    if not judge:
                        return await refuse(WS_BAD_AUTH, "UNAUTHORIZED", "Sesja logowania wygasła. Zaloguj się ponownie.")
                    if role == "host":
                        if s["host_id"] != judge:
                            return await refuse(WS_FORBIDDEN, "LIVE_NOT_HOST", "Tę sesję prowadzi ktoś inny.")
                        conn = Conn(websocket, "host")
                    else:
                        p = await V.participant_by_judge(store, s["id"], judge)
                        if not p:
                            return await refuse(WS_FORBIDDEN, "LIVE_NOT_JOINED", "Najpierw dołącz do sesji kodem PIN.")
                        conn = Conn(websocket, "player", p["id"])
                elif role == "guest":
                    p = await V.participant_by_guest(store, s["id"], gt or "")
                    if not p:
                        return await refuse(WS_FORBIDDEN, "LIVE_NOT_JOINED", "Nie rozpoznaję Cię w tej sesji.")
                    conn = Conn(websocket, "player", p["id"])
                else:
                    return await refuse(WS_FORBIDDEN, "LIVE_BAD_ROLE", "Nieznana rola gniazda.")
        except ExamError as error:
            return await refuse(WS_GONE, error.code, error.message)
        sid = s["id"]
        if not hub.add(sid, conn):
            return await refuse(WS_FORBIDDEN, "LIVE_FULL", "Za dużo połączeń w tej sesji.")
        try:
            await send_snapshot(sid, conn)
            while True:
                data = await websocket.receive_json()
                await handle_frame(sid, conn, data if isinstance(data, dict) else {})
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001 - pojedyncza wadliwa ramka nie może zawalić procesu
            logger.warning("egzamin na żywo: gniazdo sesji %s zakończone błędem", sid, exc_info=True)
        finally:
            hub.remove(sid, conn)

    async def send_snapshot(sid: str, conn: Conn) -> None:
        state = await fresh_state(sid)
        now = deps.now()
        view = L.view_for(conn.role, state, viewer_of(state, conn.participant_id), now)
        await hub.send(sid, conn, {"type": "snapshot", "rev": view["rev"], "snapshot": view})

    async def handle_frame(sid: str, conn: Conn, data: Dict[str, Any]) -> None:
        kind = data.get("type")
        if kind == "ping":
            await hub.send(sid, conn, {"type": "pong", "server_now": deps.now().isoformat()})
        elif kind == "refresh":
            await send_snapshot(sid, conn)
        elif kind == "answer" and conn.role == "player":
            try:
                result = await V.submit_answer(ls(), sid, conn.participant_id or "", data.get("selected") or [], deps.now())
                changed(sid, immediate=bool(result["everyone_answered"]))
                await hub.send(sid, conn, {"type": "ack", "ok": True, "qid": result["qid"]})
                await send_snapshot(sid, conn)
            except ExamError as error:
                await hub.send(sid, conn, {"type": "error", "code": error.code, "message": error.message})
        elif kind == "control" and conn.role != "host":
            await hub.send(sid, conn, {"type": "error", "code": "LIVE_NOT_HOST", "message": "Fazami sesji steruje tylko prowadzący."})
        elif kind == "control":
            try:
                s = await V.session_row(ls(), sid)
                who = S.Who(judge_id=s["host_id"], name=s.get("host_name") or "", province="", is_admin=False, badges={})
                state = await V.control(ls(), who, sid, str(data.get("action") or ""), deps.now(),
                                        {"from_phase": data.get("from_phase"), "from_index": data.get("from_index")})
                arm_timer(state)
                changed(sid, immediate=True)
            except ExamError as error:
                await hub.send(sid, conn, {"type": "error", "code": error.code, "message": error.message, **error.extra})
        else:
            await hub.send(sid, conn, {"type": "error", "code": "LIVE_BAD_FRAME", "message": "Nieznana wiadomość."})

    return router
