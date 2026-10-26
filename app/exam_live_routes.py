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
migawka rzutnika i kod QR. Same strony (ekran sali, dołączanie z przeglądarki) są od 25.10.2026
w BAZA_web (`www.bazapodreka.app/sala/ekran/{token}`, `/sala/{PIN}`); stare adresy tutaj
(`/projector/{token}`, `/join`, `/join/{token}`, `/j/{token}`) odpowiadają 302 na nowe.
Gość odpowiada tylko z `guest_token` wydanym przy dołączeniu, i tylko gdy prowadzący włączył gości.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, List, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app import exam_live_brand as BR
from app import exam_live_rules as L
from app import exam_live_service as V
from app import exam_service as S
from app.exam_live_hub import Conn, Hub
from app.exam_rules import ExamError
from app.pod_reka_login_rules import client_key as _forwarded_key

logger = logging.getLogger(__name__)

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
    #: async (login, hasło) -> {access_token, judge_id, name, expires_in}; logowanie kontem BAZY ze strony WWW.
    #: Rzuca ExamError z kodem i zdaniem. `None` = logowanie WWW wyłączone (503).
    login: Optional[Callable[[str, str], Awaitable[Dict[str, Any]]]] = None


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
    #: tylko `extend`: ile sekund dołożyć (5-120, domyślnie 15)
    seconds: Optional[int] = None


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


class WebLoginBody(BaseModel):
    username: str = ""
    password: str = ""


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


def _ip(request: Request) -> str:
    """Klucz limitu prób: pierwszy adres z X-Forwarded-For (Railway), inaczej adres połączenia.
    Bez tego cała sala za proxy dzieliłaby jeden limit błędnych PIN-ów."""
    return _forwarded_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "?")


def _guest_from(request: Request, query_value: Optional[str] = None, body_value: Optional[str] = None) -> str:
    """guest_token: nagłówek X-Guest-Token (zalecany), ciało albo query `gt` (przestarzałe, zgodność)."""
    return request.headers.get("x-guest-token") or body_value or query_value or ""


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
            # Odsłonięcie po terminie + tolerancja: spóźnione auto-wysyłki z końca czasu jeszcze wchodzą.
            delay = (s["deadline_at"] - deps.now()).total_seconds() + L.ANSWER_GRACE_S + 0.05

            async def fire() -> None:
                if await V.tick(ls(), s["id"], deps.now()):
                    await render(s["id"])

            hub.arm(s["id"], (s["q_index"], s["deadline_at"].isoformat()), delay, fire)
        else:
            # Poza pytaniem albo w pauzie (termin pusty): stary zegar nie może odsłonić pytania.
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
                viewer = viewer_of(state, conn.participant_id)
                if viewer is None:
                    # Usunięty z sali przez prowadzącego: mówimy wprost i zamykamy gniazdo.
                    await hub.send(sid, conn, {"type": "error", "code": "LIVE_KICKED", "message": "Prowadzący usunął Cię z tej sesji."})
                    hub.remove(sid, conn)
                    try:
                        await conn.ws.close(code=WS_FORBIDDEN)
                    except Exception:  # noqa: BLE001 - gniazdo mogło już zniknąć
                        pass
                    continue
                view = await with_photos(L.view_for("player", state, viewer, now), state)
            elif conn.role == "projector":
                if "projector" not in shared:
                    shared["projector"] = await projector_view(state, now)
                view = shared["projector"]
            else:
                if conn.role not in shared:
                    shared[conn.role] = await with_photos(L.view_for(conn.role, state, None, now), state)
                view = shared[conn.role]
            await hub.send(sid, conn, {"type": "snapshot", "rev": view["rev"], "snapshot": view})

    photo_cache: Dict[str, tuple] = {}

    async def photos_of(state: Mapping[str, Any]) -> Dict[str, str]:
        """numer sędziego -> zdjęcie z listy okręgu (koszulki na rzutniku). Pamięć na sesję:
        nowa osoba odświeża listę najwyżej co 15 s, inaczej co 5 min. Błąd = inicjały, nie awaria."""
        s = state["session"]
        ids = {str(p.get("judge_id")).strip() for p in state["participants"] if p.get("judge_id")}
        if not ids:
            return {}
        now_m = time.monotonic()
        hit = photo_cache.get(s["id"])
        if hit and ((ids <= hit[1] and now_m - hit[0] < 300) or now_m - hit[0] < 15):
            return hit[2]
        out: Dict[str, str] = {}
        try:
            provinces = (list(S.ALL_PROVINCES) if s.get("scope") == "national" or not s.get("province")
                         else [S.display(s["province"])])
            lists = await asyncio.gather(*(ls().exam.judges(p) for p in provinces), return_exceptions=True)
            for judges in lists:
                if isinstance(judges, BaseException):
                    continue
                for j in judges or []:
                    jid = str(j.get("judge_id") or "").strip()
                    url = str(j.get("photo_url") or "").strip()
                    if jid in ids and url.startswith("http"):
                        out[jid] = url
        except Exception:  # noqa: BLE001 - lista okręgu niedostępna: koszulki z inicjałami
            logger.info("egzamin na żywo: brak zdjęć dla sesji %s", s["id"], exc_info=True)
        if len(photo_cache) > 200:
            photo_cache.clear()
        photo_cache[s["id"]] = (now_m, ids, out)
        return out

    def attach_photos(view: Dict[str, Any], state: Mapping[str, Any], photos: Mapping[str, str]) -> Dict[str, Any]:
        """Dokłada `photo` do wierszy z osobami: lista uczestników, ranking, podium i tabela końcowa
        (każda rola dostaje to samo zdjęcie, co rzutnik). Bez zdjęcia wiersz zostaje bez pola."""
        if not photos:
            return view
        judge_of = {L.public_key(p["id"]): str(p.get("judge_id") or "").strip() for p in state["participants"]}
        board = view.get("leaderboard") or {}
        final = view.get("final") or {}
        rows = (list(view.get("participants") or []) + list(board.get("top") or []) + list(board.get("full") or [])
                + list(final.get("board") or []) + list(final.get("ranking") or []) + ([view["me"]] if view.get("me") else []))
        for row in rows:
            key = row.get("key") or (L.public_key(row["participant_id"]) if row.get("participant_id") else "")
            url = photos.get(judge_of.get(key, ""))
            if url:
                row["photo"] = url
        return view

    def cached_photos(state: Mapping[str, Any]) -> Dict[str, str]:
        """Tylko z pamięci (ścieżki synchroniczne): pusto, dopóki nikt nie pobrał listy okręgu."""
        hit = photo_cache.get(state["session"]["id"])
        return hit[2] if hit else {}

    async def with_photos(view: Dict[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        has_rows = view.get("participants") or view.get("leaderboard") or view.get("final") or view.get("me")
        return attach_photos(view, state, await photos_of(state)) if has_rows else view

    async def projector_view(state: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        """Widok rzutnika + oprawa (herb, barwy, krótki adres) + zdjęcia na koszulkach."""
        view = L.view_for("projector", state, None, now)
        s = state["session"]
        brand = brand_of(s)
        view["brand"] = {"palette": brand["palette"], "crest_url": brand["crest_url"], "province_label": brand["province_label"],
                         "join_url": L.web_join_url(s.get("pin")), "short": L.WEB_SHORT}
        return await with_photos(view, state)

    def changed(sid: str, *, immediate: bool) -> None:
        hub.schedule(sid, render, immediate=immediate)

    def view_response(state: Dict[str, Any], role: str, pid: Optional[str], since_rev: Optional[int], response: Response) -> Dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        now = deps.now()
        if since_rev is not None and since_rev == state["session"]["rev"] and state["session"]["phase"] != "question":
            return {"unchanged": True, "rev": since_rev, "server_now": now.isoformat()}
        return attach_photos(L.view_for(role, state, viewer_of(state, pid), now), state, cached_photos(state))

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
        key = _ip(request)
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
        key = _ip(request)
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
    async def guest_state(sid: str, request: Request, response: Response, gt: str = Query(""),
                          since_rev: Optional[int] = Query(None)) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            token = _guest_from(request, gt)
            p = await V.participant_by_guest(ls(), sid, token)
            if not p:
                if V.was_kicked(await V.session_row(ls(), sid), guest_token=token):
                    raise ExamError("LIVE_KICKED", "Prowadzący usunął Cię z tej sesji.", 403)
                raise ExamError("LIVE_NOT_JOINED", "Nie rozpoznaję Cię w tej sesji. Dołącz ponownie kodem PIN.", 403)
            state = await fresh_state(sid)
            return view_response(state, "player", p["id"], since_rev, response)

        return await _run(go())

    @router.post("/guest/{sid}/answer", summary="Odpowiedź gościa")
    async def guest_answer(sid: str, body: AnswerBody, request: Request) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            p = await V.participant_by_guest(ls(), sid, _guest_from(request, None, body.gt))
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
            s = await V.session_by_projector(ls(), token)
            state = await fresh_state(s["id"])
            response.headers["Cache-Control"] = "no-store"
            if since_rev is not None and since_rev == state["session"]["rev"] and state["session"]["phase"] != "question":
                return {"unchanged": True, "rev": since_rev, "server_now": deps.now().isoformat()}
            return await projector_view(state, deps.now())

        return await _run(go())

    # -- oprawa marki: kod QR, karty, plakat ------------------------------

    def join_url_for(request: Request, s: Mapping[str, Any]) -> str:
        """Adres z kodu QR: `https://www.bazapodreka.app/sala/{PIN}` (25.10.2026). Krótki, więc kropki
        kodu są duże z końca sali; z aplikacją (App Links) telefon otwiera BAZĘ, bez niej stronę sali."""
        return L.web_join_url(s.get("pin"))

    def brand_of(s: Mapping[str, Any]) -> Dict[str, Any]:
        palette = BR.palette_for(s.get("scope"), s.get("province"))
        return {"palette": palette, "crest_url": f"/exam-live/assets/img/{BR.crest_name(palette)}",
                "province_label": BR.province_label(s.get("scope"), s.get("province"))}

    def qr_svg_response(request: Request, s: Mapping[str, Any], style: str) -> Response:
        url = join_url_for(request, s) if style == "brand" else f"{_base_url(request)}/exam-live/join/{s['token']}"
        if style == "brand":
            palette = BR.palette_for(s.get("scope"), s.get("province"))
            body = BR.brand_svg(url, palette, crest=BR.crest_data_uri(palette)).encode("utf-8")
        else:
            import qrcode
            import qrcode.image.svg

            img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=1,
                              error_correction=qrcode.constants.ERROR_CORRECT_M)
            buf = io.BytesIO()
            img.save(buf)
            body = buf.getvalue()
        return Response(body, media_type="image/svg+xml", headers={"Cache-Control": "private, max-age=600"})

    def qr_json_payload(request: Request, s: Mapping[str, Any]) -> Dict[str, Any]:
        brand = brand_of(s)
        extra: Dict[str, Any] = {"title": s.get("title") or "", "character": s.get("character"), "pin": s.get("pin"),
                                 "province_label": brand["province_label"],
                                 "join_page": L.web_join_url(None), "short": L.WEB_SHORT}
        return BR.qr_json(join_url_for(request, s), brand["palette"], brand["crest_url"], extra)

    async def hosted_session(sid: str, who: S.Who) -> Dict[str, Any]:
        """Kod, plakat i obraz sesji: jak linki w `session.links` - prowadzący (admin też)."""
        s = await V.session_row(ls(), sid)
        if s["host_id"] != who.judge_id and not who.is_admin:
            raise ExamError("LIVE_NOT_HOST", "Kod i plakat tej sesji ma tylko prowadzący.", 403)
        return s

    @router.get("/{sid}/qr.svg", summary="Kod QR sesji (SVG): style=brand (kropki w barwach okręgu, herb) albo plain")
    async def session_qr_svg(sid: str, request: Request, style: str = Query("brand"),
                             who: S.Who = Depends(deps.who)) -> Response:
        s = await _run(hosted_session(sid, who))
        return qr_svg_response(request, s, style)

    @router.get("/{sid}/qr.json", summary="Macierz kodu QR + barwy + herb (aplikacja rysuje animowany kod)")
    async def session_qr_json(sid: str, request: Request, response: Response, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        s = await _run(hosted_session(sid, who))
        response.headers["Cache-Control"] = "private, max-age=600"
        return qr_json_payload(request, s)

    @router.get("/{sid}/story.png", summary="Obraz 9:16 (1080x1920) do udostępnienia")
    async def session_story(sid: str, request: Request, who: S.Who = Depends(deps.who)) -> Response:
        return await story_response(request, await _run(hosted_session(sid, who)))

    @router.get("/projector/{token}/story.png", summary="Obraz 9:16 przez token rzutnika (jak link rzutnika)")
    async def projector_story(token: str, request: Request) -> Response:
        return await story_response(request, await _run(V.session_by_projector(ls(), token)))

    @router.get("/projector/{token}/poster.pdf", summary="Plakat A4 przez token rzutnika (jak link rzutnika)")
    async def projector_poster(token: str, request: Request) -> Response:
        return await poster_response(request, await _run(V.session_by_projector(ls(), token)))

    async def story_response(request: Request, s: Mapping[str, Any]) -> Response:
        brand = brand_of(s)
        png = await run_in_threadpool(
            lambda: BR.story_png(title=s.get("title") or "", pin=s["pin"], character=s.get("character") or "quiz",
                                 palette=brand["palette"], url=join_url_for(request, s), province_label=brand["province_label"],
                                 join_hint=f"albo {L.WEB_SHORT} i kod PIN"))
        return Response(png, media_type="image/png", headers={"Cache-Control": "private, max-age=300",
                                                              "Content-Disposition": f'inline; filename="egzamin-{s["pin"]}.png"'})

    def poster_html_for(request: Request, s: Mapping[str, Any]) -> str:
        from app.exam_report_html import seal_svg

        brand = brand_of(s)
        when = s.get("created_at") or deps.now()
        return BR.poster_html(title=s.get("title") or "Egzamin z przepisów", pin=s["pin"], character=s.get("character") or "quiz",
                              palette=brand["palette"], url=join_url_for(request, s),
                              join_page=L.web_join_url(None), province_label=brand["province_label"],
                              seal=seal_svg(132, brand["palette"]["from"], "NA ŻYWO", when.strftime("%d.%m.%Y")))

    @router.get("/{sid}/poster.pdf", summary="Plakat A4 do druku (weasyprint)")
    async def session_poster(sid: str, request: Request, who: S.Who = Depends(deps.who)) -> Response:
        return await poster_response(request, await _run(hosted_session(sid, who)))

    async def poster_response(request: Request, s: Mapping[str, Any]) -> Response:
        html = poster_html_for(request, s)
        try:
            from weasyprint import HTML  # ciężka zależność, ładowana dopiero tutaj
        except Exception:  # noqa: BLE001 - brak biblioteki albo jej natywnych zależności
            raise _http(ExamError("LIVE_PDF_UNAVAILABLE", "Serwer nie składa teraz PDF-ów. Udostępnij obraz albo spróbuj za chwilę.", 503))
        pdf = await run_in_threadpool(lambda: HTML(string=html).write_pdf())
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'inline; filename="plakat-{s["pin"]}.pdf"', "Cache-Control": "private, max-age=300"})

    card_cache: Dict[tuple, bytes] = {}

    async def card_png(request: Request, s: Optional[Mapping[str, Any]]) -> bytes:
        live = s is not None and s["phase"] != "end"
        key: tuple = (s["token"], s.get("title"), s.get("pin"), s.get("province"), s.get("scope"), s.get("character"),
                      _base_url(request)) if live else ("generic",)
        if key in card_cache:
            return card_cache[key]
        if live:
            brand = brand_of(s)
            png = await run_in_threadpool(
                lambda: BR.og_card_png(title=s.get("title") or "", pin=s.get("pin"), character=s.get("character") or "quiz",
                                       palette=brand["palette"], url=join_url_for(request, s), province_label=brand["province_label"]))
        else:
            png = await run_in_threadpool(
                lambda: BR.og_card_png(title="Egzamin z przepisów na żywo", pin=None, character="quiz",
                                       palette=BR.palette_for("national", None), url=None, province_label=""))
        if len(card_cache) > 64:
            card_cache.clear()
        card_cache[key] = png
        return png

    async def session_for_join(token: str) -> Optional[Dict[str, Any]]:
        try:
            return await V.session_by_token(ls(), token)
        except ExamError:
            return None

    @router.get("/card.png", summary="Ogólna karta podglądu linku (1200x630)")
    async def generic_card(request: Request) -> Response:
        return Response(await card_png(request, None), media_type="image/png", headers={"Cache-Control": "public, max-age=3600"})

    @router.get("/join/{token}/card.png", summary="Karta podglądu linku sesji (Open Graph, 1200x630)")
    async def join_card(token: str, request: Request) -> Response:
        s = await session_for_join(token)
        return Response(await card_png(request, s), media_type="image/png", headers={"Cache-Control": "public, max-age=300"})

    @router.get("/peek", summary="Co to za sesja (przed dołączeniem): nazwa, herb, czy wpuszcza gości")
    async def peek(request: Request, response: Response, pin: Optional[str] = Query(None),
                   token: Optional[str] = Query(None)) -> Dict[str, Any]:
        key = _ip(request)
        try:
            throttle.check(key)
            s = await V.session_by_ref(ls(), {"pin": pin, "token": token}, deps.now())
        except ExamError as error:
            if error.code in ("LIVE_PIN_UNKNOWN", "LIVE_BAD_PIN", "LIVE_NOT_FOUND"):
                throttle.fail(key)
            raise _http(error)
        response.headers["Cache-Control"] = "no-store"
        brand = brand_of(s)
        late = bool(s["config"].get("late_join"))
        locked = bool(s["config"].get("locked"))
        return {"session_id": s["id"], "title": s.get("title") or "", "character": s.get("character"), "scope": s.get("scope"),
                "province": s.get("province"), "province_label": brand["province_label"], "phase": s["phase"],
                "q_total": s["q_total"], "guests_allowed": bool(s["guests_allowed"]), "late_join": late,
                "locked": locked, "joinable": not locked and (s["phase"] == "lobby" or late), "brand": {"palette": brand["palette"], "crest_url": brand["crest_url"]}}

    login_throttle = _Throttle(limit=10)

    @router.post("/web-login", summary="Logowanie kontem BAZY ze strony uczestnika (te same dane co w aplikacji)")
    async def web_login(request: Request, body: WebLoginBody) -> Dict[str, Any]:
        key = _ip(request)
        try:
            login_throttle.check(key)
            if not deps.login:
                raise ExamError("LIVE_LOGIN_UNAVAILABLE", "Logowanie ze strony jest chwilowo wyłączone. Dołącz w aplikacji BAZA.", 503)
            if not body.username.strip() or not body.password:
                raise ExamError("LIVE_LOGIN_EMPTY", "Wpisz login i hasło - te same, co w aplikacji BAZA.")
            try:
                return await deps.login(body.username.strip(), body.password)
            except ExamError as error:
                if error.status in (401, 403):
                    login_throttle.fail(key)
                raise
        except ExamError as error:
            raise _http(error)

    @router.get("/projector/{token}/qr.svg", summary="Kod QR do dołączenia (SVG; style=brand dla markowego)")
    async def projector_qr(token: str, request: Request, style: str = Query("plain")) -> Response:
        s = await _run(V.session_by_projector(ls(), token))
        return qr_svg_response(request, s, style)

    @router.get("/projector/{token}/qr.json", summary="Macierz kodu QR dla rzutnika (animowane budowanie kodu)")
    async def projector_qr_json(token: str, request: Request, response: Response) -> Dict[str, Any]:
        s = await _run(V.session_by_projector(ls(), token))
        response.headers["Cache-Control"] = "private, max-age=600"
        return qr_json_payload(request, s)

    def moved(url: str) -> RedirectResponse:
        return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def web_join_for(token: str) -> str:
        """Stary link z tokenem dołączania -> `/sala/{PIN}` trwającej sesji, inaczej strona wpisywania PIN-u."""
        s = await session_for_join(token)
        return L.web_join_url(s.get("pin") if s is not None and s["phase"] != "end" else None)

    @router.get("/projector/{token}", summary="Stary adres rzutnika: 302 na ekran sali w BAZA_web")
    async def projector_page(token: str) -> RedirectResponse:
        await _run(V.session_by_projector(ls(), token))  # zły token: 404 jak dawniej, bez przekierowania donikąd
        return moved(L.web_projector_url(token))

    @router.get("/join", summary="Stary adres strony uczestnika: 302 na bazapodreka.app/sala")
    async def join_page() -> RedirectResponse:
        return moved(L.web_join_url(None))

    @router.get("/join/{token}", summary="Stary link uczestnika: 302 na bazapodreka.app/sala/{PIN}")
    async def join_page_token(token: str) -> RedirectResponse:
        return moved(await web_join_for(token))

    @router.get("/j/{token}", summary="Stary krótki adres z kodu QR: 302 na bazapodreka.app/sala/{PIN}")
    async def join_page_short(token: str) -> RedirectResponse:
        return moved(await web_join_for(token))

    @router.get("/assets/img/{name:path}", summary="Herby okręgów i znak ZPRP (kod QR, strony, karty)")
    async def asset_img(name: str) -> Response:
        if not re.fullmatch(r"(zprp|okregi/[a-z_]+)\.png", name) or not (BR.IMG_DIR / name).exists():
            raise HTTPException(404, detail={"code": "LIVE_ASSET", "message": "Nie ma takiego pliku."})
        return Response((BR.IMG_DIR / name).read_bytes(), media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})

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
                if V.was_kicked(s, judge_id=who.judge_id):
                    raise ExamError("LIVE_KICKED", "Prowadzący usunął Cię z tej sesji.", 403)
                raise ExamError("LIVE_NOT_JOINED", "Nie dołączyłeś(-aś) do tej sesji. Wpisz kod PIN, żeby dołączyć.", 403)
            state = await fresh_state(sid)
            return view_response(state, "player", p["id"], since_rev, response)

        return await _run(go())

    @router.post("/{sid}/control", summary="Sterowanie fazami (tylko prowadzący): next | reveal | end")
    async def control(sid: str, body: ControlBody, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        state = await _run(V.control(ls(), who, sid, body.action, deps.now(),
                                     {"from_phase": body.from_phase, "from_index": body.from_index, "seconds": body.seconds}))
        arm_timer(state)
        changed(sid, immediate=True)
        return L.view_for("host", state, None, deps.now())

    @router.delete("/{sid}/participants/{pid}", summary="Usuń osobę z sali (prowadzący) -> widok hosta")
    async def kick(sid: str, pid: str, who: S.Who = Depends(deps.who)) -> Dict[str, Any]:
        state = await _run(V.kick(ls(), who, sid, pid, deps.now()))
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
        host/player: JWT aplikacji, guest: guest_token - w pierwszej ramce {"type":"auth","token"|"gt"} albo w
        nagłówku (Authorization: Bearer / X-Guest-Token); query `token`/`gt` działa, ale jest przestarzałe.
        projector: `ref` = token RZUTNIKA (session.links.projector_url), nie token dołączania.
        Ramki serwera: snapshot, ack, error, pong. Ramki klienta: ping, refresh, answer, control (host)."""
        await websocket.accept()

        async def refuse(code: int, err_code: str, message: str) -> None:
            try:
                await websocket.send_json({"type": "error", "code": err_code, "message": message})
                await websocket.close(code=code)
            except Exception:  # noqa: BLE001
                pass

        async def ws_credentials(r: str, tok: Optional[str], guest: Optional[str]):
            """Sekret z query (przestarzałe), z nagłówka (Authorization: Bearer / X-Guest-Token)
            albo z pierwszej ramki `{"type":"auth","token"|"gt":...}` - adres nie trafia wtedy do logów."""
            auth = websocket.headers.get("authorization", "")
            tok = tok or (auth[7:].strip() if auth.lower().startswith("bearer ") else None)
            guest = guest or websocket.headers.get("x-guest-token")
            if (r == "guest" and not guest) or (r != "guest" and not tok):
                try:
                    frame = await asyncio.wait_for(websocket.receive_json(), timeout=10)
                except Exception:  # noqa: BLE001 - brak ramki, zła ramka, rozłączenie
                    frame = {}
                if isinstance(frame, dict) and frame.get("type") == "auth":
                    tok = tok or (str(frame.get("token") or "") or None)
                    guest = guest or (str(frame.get("gt") or "") or None)
            return tok, guest

        try:
            store = ls()
            if role == "projector":
                s = await V.session_by_projector(store, ref)
                conn = Conn(websocket, "projector")
            else:
                s = await V.session_row(store, ref)
                if role in ("host", "player", "guest"):
                    token, gt = await ws_credentials(role, token, gt)
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
        view = await with_photos(L.view_for(conn.role, state, viewer_of(state, conn.participant_id), now), state)
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
                                        {"from_phase": data.get("from_phase"), "from_index": data.get("from_index"),
                                         "seconds": data.get("seconds")})
                arm_timer(state)
                changed(sid, immediate=True)
            except ExamError as error:
                await hub.send(sid, conn, {"type": "error", "code": error.code, "message": error.message, **error.extra})
        else:
            await hub.send(sid, conn, {"type": "error", "code": "LIVE_BAD_FRAME", "message": "Nieznana wiadomość."})

    return router
