"""
Egzamin na komputerze (BAZA_web www.bazapodreka.app/egzamin, 24.10.2026) - trasy `/exam-web`.

Logowanie komputera:
  - kod QR zatwierdzony w aplikacji BAZA (telefon od razu zostaje STRAŻNIKIEM),
  - albo login i hasło ZPRP (strażnika można sparować później drugim kodem `purpose:"guard"`).
Komputer dostaje własny token (12 h, zakres `exam-web` - działa tylko na `/exam-web`, bez ciasteczek ZPRP).

Egzamin w przeglądarce to ZWYKŁE podejście (`exam_service`), z urządzenia `web:<przeglądarka>`.
Ponad to: jedna aktywna sesja na konto, sygnały ochrony, reakcja egzaminu (`anti.web`)
i telefon-strażnik (uderzenia serca co kilka sekund; wyjście z aplikacji = naruszenie).
Reguły: `app/exam_web_rules.py`. Kontrakt: BAZA/docs/egzamin-api.md, sekcja „Na komputerze”.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, select, update

from app import exam_rules as X
from app import exam_service as S
from app import exam_web_rules as R
from app.deps import EXAM_WEB_SCOPE, get_jwt_payload
from app.exam_rules import ExamError
from app.exams import _run, _store, _who
from app.mentor_panel_rules import QR_TTL, device_hint, new_qr_code, normalize_qr_code
from app.pod_reka_login_rules import AttemptLimiter, client_key

router = APIRouter(prefix="/exam-web", tags=["Exam web"])

APPROVE_WEB = "https://www.bazapodreka.app/egzamin/p"
APPROVE_APP = "refhandballapp://egzamin/p"
TOKEN_HOURS = 12
QR_POLL_MAX_S = 25

_QR_LIMITER = AttemptLimiter(limit=30)
_LOGIN_LIMITER = AttemptLimiter()
_qr_events: Dict[str, asyncio.Event] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: Any) -> Optional[str]:
    v = _aware(value)
    return v.isoformat() if v else None


def _tables():
    from app import db as D

    return D.database, D.exam_web_codes, D.exam_web_links, D.exam_web_sessions


async def _one(query) -> Optional[Dict[str, Any]]:
    database, *_ = _tables()
    row = await database.fetch_one(query)
    return dict(row._mapping) if row is not None and hasattr(row, "_mapping") else (dict(row) if row else None)


def _err(code: str, message: str, status: int = 400, **extra: Any) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message, **extra})


def _issue_token(judge_id: str, name: str, link_id: str) -> Dict[str, Any]:
    import jwt as pyjwt

    from app.deps import get_settings

    settings = get_settings()
    now = _now()
    payload = {"sub": f"exam-web:{judge_id}", "judge_id": judge_id, "account_type": "judge", "display_name": name,
               "scope": EXAM_WEB_SCOPE, "ewl": link_id, "iat": int(now.timestamp()),
               "exp": int((now + timedelta(hours=TOKEN_HOURS)).timestamp())}
    token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_HOURS * 3600, "judge_id": judge_id, "name": name}


def _web_link_id(payload: Dict[str, Any]) -> str:
    if payload.get("scope") != EXAM_WEB_SCOPE or not payload.get("ewl"):
        raise _err("EXAM_WEB_TOKEN", "Ta trasa jest dla komputera zalogowanego do egzaminu (kod QR albo login ZPRP).", 401)
    return str(payload["ewl"])


def _app_only(payload: Dict[str, Any]) -> None:
    if payload.get("scope") is not None:
        raise _err("EXAM_WEB_APP_ONLY", "To robi aplikacja BAZA na telefonie, nie strona.", 403)


async def _link(link_id: str, judge_id: str) -> Dict[str, Any]:
    _, _, links, _ = _tables()
    row = await _one(select(links).where(and_(links.c.id == link_id, links.c.judge_id == judge_id)))
    if not row or row.get("revoked_at") is not None:
        raise _err("EXAM_WEB_LOGGED_OUT", "Komputer został wylogowany. Zaloguj się ponownie.", 401)
    return row


# ─── Logowanie: kod QR ──────────────────────────────────────────────────────


class QrBody(BaseModel):
    purpose: str = Field("login", pattern="^(login|guard)$")


@router.post("/qr", summary="Kod QR: logowanie komputera albo parowanie telefonu-strażnika")
async def qr_start(body: QrBody, request: Request):
    database, codes, _, _ = _tables()
    address = client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")
    if _QR_LIMITER.blocked(f"ew:{address}"):
        raise _err("RATE_LIMITED", "Za dużo kodów naraz. Spróbuj za kilka minut.", 429)
    _QR_LIMITER.fail(f"ew:{address}")
    link_id = judge_id = None
    if body.purpose == "guard":
        payload = await _bearer_payload(request)
        link_id = _web_link_id(payload)
        judge_id = str(payload.get("judge_id") or "")
        await _link(link_id, judge_id)
    poll_token = secrets.token_urlsafe(24)
    stamp = _now()
    for _ in range(5):
        code = new_qr_code()
        try:
            await database.execute(codes.insert().values(
                code=code, purpose=body.purpose, poll_hash=_hash(poll_token), link_id=link_id, judge_id=judge_id,
                created_at=stamp, expires_at=stamp + QR_TTL, user_agent=(request.headers.get("user-agent") or "")[:300] or None))
            break
        except Exception:  # noqa: BLE001 - kolizja kodu: losujemy jeszcze raz
            continue
    else:
        raise _err("QR_UNAVAILABLE", "Nie udało się utworzyć kodu. Spróbuj ponownie.", 503)
    return {"code": code, "purpose": body.purpose, "poll_token": poll_token, "expires_at": (stamp + QR_TTL).isoformat(),
            "approve_url": f"{APPROVE_WEB}/{code}", "app_url": f"{APPROVE_APP}/{code}", "server_now": stamp.isoformat()}


async def _bearer_payload(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise _err("EXAM_WEB_TOKEN", "Najpierw zaloguj komputer.", 401)
    return await get_jwt_payload(request, auth.split(" ", 1)[1].strip())


def _code_status(row: Optional[Dict[str, Any]], now: datetime) -> str:
    if not row or row.get("consumed_at"):
        return "expired"
    if row.get("approved_at"):
        return "approved"
    exp = _aware(row.get("expires_at"))
    return "expired" if not exp or exp <= now else "waiting"


@router.get("/qr/{code}", summary="Długie odpytywanie: czy telefon zatwierdził kod")
async def qr_poll(code: str, poll_token: str = Query("", max_length=200), wait: int = Query(20, ge=0, le=QR_POLL_MAX_S)):
    database, codes, links, _ = _tables()
    code = normalize_qr_code(code)
    row = await _one(select(codes).where(codes.c.code == code)) if code else None
    if not row or not poll_token or not hmac.compare_digest(_hash(poll_token), str(row.get("poll_hash") or "")):
        raise _err("QR_NOT_FOUND", "Ten kod nie istnieje albo wygasł.", 404)
    deadline = time.monotonic() + wait
    status = _code_status(row, _now())
    while status == "waiting" and time.monotonic() < deadline:
        ev = _qr_events.setdefault(code, asyncio.Event())
        try:
            await asyncio.wait_for(ev.wait(), timeout=min(2.0, max(0.05, deadline - time.monotonic())))
        except asyncio.TimeoutError:
            pass
        row = await _one(select(codes).where(codes.c.code == code))
        status = _code_status(row, _now())
    if status != "approved":
        if status == "expired":
            _qr_events.pop(code, None)
        return {"status": status}
    await database.execute(update(codes).where(codes.c.code == code).where(codes.c.consumed_at.is_(None)).values(consumed_at=_now()))
    _qr_events.pop(code, None)
    link = await _one(select(links).where(links.c.id == row["link_id"]))
    guard = R.guard_state(link, _now())
    if row["purpose"] == "guard":
        return {"status": "approved", "purpose": "guard", "guard": guard}
    token = _issue_token(row["approved_by"], row.get("approved_name") or "", row["link_id"])
    return {"status": "approved", "purpose": "login", **token, "guard": guard}


class ApproveBody(BaseModel):
    device_id: str = Field(min_length=4, max_length=200)
    device_label: Optional[str] = Field(None, max_length=80)


@router.post("/qr/{code}/approve", summary="Telefon zatwierdza kod (zostaje strażnikiem)")
async def qr_approve(code: str, body: ApproveBody, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    _app_only(payload)
    database, codes, links, _ = _tables()
    code = normalize_qr_code(code)
    row = await _one(select(codes).where(codes.c.code == code)) if code else None
    status = _code_status(row, _now())
    if status != "waiting":
        raise _err("QR_USED" if status == "approved" else "QR_EXPIRED",
                   "Ten kod został już użyty." if status == "approved" else "Kod wygasł - odśwież stronę na komputerze i zeskanuj nowy.",
                   409 if status == "approved" else 404)
    now = _now()
    label = (body.device_label or "").strip()[:80] or "Telefon"
    if row["purpose"] == "guard":
        if row.get("judge_id") != who.judge_id:
            raise _err("EXAM_WEB_OTHER_JUDGE", "Na komputerze jest zalogowane inne konto. Strażnikiem może być tylko telefon tej samej osoby.", 403)
        link_id = row["link_id"]
        await database.execute(update(links).where(links.c.id == link_id).values(
            guard_device_id=body.device_id, guard_label=label, guard_seen_at=now, guard_state="ok"))
    else:
        link_id = uuid.uuid4().hex
        await database.execute(links.insert().values(
            id=link_id, judge_id=who.judge_id, judge_name=who.name or None, guard_device_id=body.device_id, guard_label=label,
            guard_seen_at=now, guard_state="ok", user_agent=row.get("user_agent"), created_at=now))
    await database.execute(update(codes).where(codes.c.code == code).where(codes.c.approved_at.is_(None)).values(
        approved_by=who.judge_id, approved_name=who.name or None, approved_at=now, link_id=link_id,
        device_id=body.device_id, device_label=label))
    ev = _qr_events.get(code)
    if ev:
        ev.set()
    return {"ok": True, "purpose": row["purpose"], "link_id": link_id, "device_hint": device_hint(row.get("user_agent"))}


# ─── Logowanie: login i hasło ZPRP ──────────────────────────────────────────


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)


@router.post("/login", summary="Login i hasło ZPRP (te same dane co w aplikacji)")
async def password_login(body: LoginBody, request: Request):
    from app.auth import LoginRequest, login
    from app.deps import get_settings

    database, _, links, _ = _tables()
    address = client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")
    keys = (f"ew-ip:{address}", f"ew-user:{body.username.strip().lower()}")
    if _LOGIN_LIMITER.blocked(*keys):
        raise _err("RATE_LIMITED", f"Za dużo nieudanych prób. Spróbuj za {max(1, _LOGIN_LIMITER.retry_after(*keys) // 60)} min.", 429)
    try:
        res = await login(LoginRequest(username=body.username.strip(), password=body.password), get_settings())
    except HTTPException as error:
        if error.status_code == 401:
            _LOGIN_LIMITER.fail(*keys)
            raise _err("BAD_CREDENTIALS", "Login albo hasło się nie zgadza. To te same dane, co w aplikacji BAZA.", 401)
        raise _err("LOGIN_DOWN", "Logowanie chwilowo nie działa. Spróbuj za moment.", 502)
    except Exception:  # noqa: BLE001 - serwer ZPRP nie odpowiada
        raise _err("LOGIN_DOWN", "Serwer ZPRP nie odpowiada. Spróbuj za moment.", 502)
    data = res if isinstance(res, dict) else res.model_dump()
    judge = str(data.get("judge_id") or "").strip()
    if not judge:
        _LOGIN_LIMITER.fail(*keys)
        raise _err("NOT_JUDGE", "To konto nie ma numeru sędziego. Egzaminy piszą konta sędziowskie.", 403)
    _LOGIN_LIMITER.success(*keys)
    name = str(data.get("display_name") or "").split("|")[0].strip()
    link_id = uuid.uuid4().hex
    await database.execute(links.insert().values(id=link_id, judge_id=judge, judge_name=name or None,
                                                 user_agent=(request.headers.get("user-agent") or "")[:300] or None, created_at=_now()))
    return {**_issue_token(judge, name, link_id), "guard": R.guard_state(None, _now())}


@router.get("/me", summary="Kto jest zalogowany na komputerze i stan strażnika")
async def me(payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    link = await _link(_web_link_id(payload), who.judge_id)
    return {"judge_id": who.judge_id, "name": who.name or link.get("judge_name"), "province": who.province,
            "guard": R.guard_state(link, _now()), "server_now": _now().isoformat()}


@router.post("/logout", summary="Wyloguj komputer (kończy sesję egzaminu tej przeglądarki)")
async def logout(payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    database, _, links, sessions = _tables()
    link_id = _web_link_id(payload)
    now = _now()
    await database.execute(update(links).where(and_(links.c.id == link_id, links.c.judge_id == who.judge_id)).values(revoked_at=now))
    await database.execute(update(sessions).where(and_(sessions.c.link_id == link_id, sessions.c.status == "active"))
                           .values(status="ended", ended_at=now, end_reason="logout"))
    return {"ok": True}


# ─── Egzaminy i sesja w przeglądarce ────────────────────────────────────────


@router.get("/exams", summary="Moje egzaminy (jak /exams/mine) z zasadami komputera")
async def exams(payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    await _link(_web_link_id(payload), who.judge_id)
    data = await _run(S.list_for_judge(_store(), who))
    for e in data.get("exams") or []:
        e["web_policy"] = R.web_policy({"anti": e.get("anti") or {}})
    return data


def _session_view(row: Dict[str, Any], policy: Dict[str, Any], guard: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": row["id"], "exam_id": row["exam_id"], "attempt_id": row.get("attempt_id"), "status": row["status"],
            "violations": row.get("violations") or 0, "policy": policy, "guard": guard, "started_at": _iso(row.get("started_at"))}


async def _web_violations(attempt_id: str) -> int:
    st = _store()
    rows = await st.database.fetch_all(select(st.t.events).where(st.t.events.c.attempt_id == attempt_id))
    count = 0
    for raw in rows:
        r = dict(raw._mapping) if hasattr(raw, "_mapping") else dict(raw)
        detail = S._loads(r.get("detail_json"), {})
        if detail.get("source") == "web" and detail.get("counted"):
            count += 1
    return count


async def _force_submit(attempt_id: str, now: datetime) -> None:
    st = _store()
    attempt = await S._attempt_row(st, attempt_id)
    exam = await S._exam(st, attempt["exam_id"], deleted_ok=True)
    answers = await S._load_answers(st, attempt_id)
    if attempt["status"] == "in_progress":
        X.settle(exam["config"], attempt, answers, now)
        X.finish_attempt(attempt, now, "web_violations")
    await S._save(st, attempt, answers)
    if attempt.get("score") is None:
        await S._finalize_score(st, exam, attempt, answers)
    await _persist_quietly(attempt_id)


async def _record(attempt: Dict[str, Any], signal: str, detail: Dict[str, Any], client_ts_ms: Any, now: datetime,
                  session: Optional[Dict[str, Any]] = None) -> bool:
    """Naruszenie -> `exam_events`; sygnał cichy -> licznik sesji (`quiet_json`). Zwraca, czy było naruszeniem."""
    shape = R.record_shape(signal, detail)
    if shape is None:
        return False
    if not shape["counted"]:
        if session is not None:
            database, _, _, sessions = _tables()
            quiet = R.merge_quiet(S._loads(session.get("quiet_json"), {}), shape["signal"], shape["detail"])
            session["quiet_json"] = json.dumps(quiet)
            await database.execute(update(sessions).where(sessions.c.id == session["id"]).values(quiet_json=session["quiet_json"]))
        if shape["signal"] == "resume" and float(shape["detail"].get("seconds") or 0) > 0:
            # Powrót niesie długość wyjścia: to pomiar czasu poza egzaminem (`exam_time_rules`), nie naruszenie.
            await S._record_event(_store(), attempt["exam_id"], attempt, "resume", {**shape["detail"], "source": "web"},
                                  client_ts_ms if isinstance(client_ts_ms, (int, float)) else None, now)
        return False
    st = _store()
    await S._record_event(st, attempt["exam_id"], attempt, shape["kind"], shape["detail"],
                          client_ts_ms if isinstance(client_ts_ms, (int, float)) else None, now)
    return True


async def _react(session: Dict[str, Any], attempt: Dict[str, Any], policy: Dict[str, Any], new: int, now: datetime) -> Dict[str, Any]:
    """Liczy naruszenia podejścia i stosuje reakcję egzaminu (także oddanie)."""
    database, _, _, sessions = _tables()
    total = await _web_violations(attempt["id"])
    decision = R.decide(policy, total, new)
    await database.execute(update(sessions).where(sessions.c.id == session["id"]).values(violations=total))
    session["violations"] = total
    if decision["action"] == "submitted" and attempt.get("status") == "in_progress":
        # Bez osobnego zdarzenia: oś komisji liczy każde zdarzenie jako naruszenie. Ślad = finish_reason.
        await _force_submit(attempt["id"], now)
        await database.execute(update(sessions).where(sessions.c.id == session["id"]).values(
            status="ended", ended_at=now, end_reason="violations"))
        session["status"] = "ended"
    return decision


async def _own_session(sid: str, payload: Dict[str, Any], who: S.Who, *, active: bool = True) -> Dict[str, Any]:
    _, _, _, sessions = _tables()
    link_id = _web_link_id(payload)
    row = await _one(select(sessions).where(sessions.c.id == sid))
    if not row or row["judge_id"] != who.judge_id or row["link_id"] != link_id:
        raise _err("EXAM_WEB_NO_SESSION", "Nie znaleziono tej sesji egzaminu na tym komputerze.", 404)
    if active and row["status"] == "replaced":
        raise _err("EXAM_WEB_REPLACED", "Egzamin otwarto w innym miejscu na tym koncie - ta karta została zamknięta. Zdarzenie trafiło do komisji.", 409)
    return row


class SessionBody(BaseModel):
    exam_id: str = Field(min_length=1, max_length=80)
    browser_id: str = Field(min_length=6, max_length=80)
    takeover: bool = False
    room_code: Optional[str] = Field(None, max_length=12)


@router.post("/sessions", summary="Zacznij albo wznów egzamin w przeglądarce (jedna sesja naraz)")
async def start_session(body: SessionBody, request: Request, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    database, _, links, sessions = _tables()
    link_id = _web_link_id(payload)
    link = await _link(link_id, who.judge_id)
    now = _now()
    rows = await database.fetch_all(select(sessions).where(and_(sessions.c.judge_id == who.judge_id, sessions.c.status == "active")))
    others = []
    for raw in rows:
        r = dict(raw._mapping) if hasattr(raw, "_mapping") else dict(raw)
        same_browser = r["link_id"] == link_id and r.get("browser_id") == body.browser_id
        beat = _aware(r.get("beat_at")) or _aware(r.get("started_at"))
        fresh = beat is not None and (now - beat).total_seconds() <= R.SESSION_STALE_S
        if same_browser or not fresh:
            await database.execute(update(sessions).where(sessions.c.id == r["id"]).values(
                status="ended", ended_at=now, end_reason="refresh" if same_browser else "stale"))
        else:
            others.append(r)
    if others and not body.takeover:
        other = others[0]
        raise _err("EXAM_WEB_BUSY", "Ten egzamin jest otwarty w innym miejscu na Twoim koncie. Możesz przenieść go tutaj - "
                   "komisja zobaczy zdarzenie „druga sesja”.", 409, device=device_hint(other.get("user_agent")),
                   since=_iso(other.get("started_at")))
    st = _store()
    state = await _run(S.start_attempt(st, who, body.exam_id, {"device_id": f"web:{body.browser_id}", "room_code": body.room_code}, now))
    attempt_id = state["attempt"]["id"]
    sid = uuid.uuid4().hex
    await database.execute(sessions.insert().values(
        id=sid, link_id=link_id, judge_id=who.judge_id, exam_id=body.exam_id, attempt_id=attempt_id, browser_id=body.browser_id,
        status="active", started_at=now, beat_at=now, violations=0, state_json="{}", quiet_json="{}",
        user_agent=(request.headers.get("user-agent") or "")[:300] or None))
    session = await _one(select(sessions).where(sessions.c.id == sid))
    exam = await S._exam(st, body.exam_id, deleted_ok=True)
    policy = R.web_policy(exam["config"])
    decision = None
    if others:
        attempt = await S._attempt_row(st, attempt_id)
        for other in others:
            await database.execute(update(sessions).where(sessions.c.id == other["id"]).values(
                status="replaced", ended_at=now, end_reason="takeover"))
        await _record(attempt, "second_session", {"device": device_hint(others[0].get("user_agent"))}, None, now)
        decision = await _react(session, attempt, policy, 1, now)
        if decision["action"] == "submitted":
            state = await _run(S.attempt_state(st, who, attempt_id, None, f"web:{body.browser_id}", now))
    else:
        session["violations"] = await _web_violations(attempt_id)
    return {"session": _session_view(session, policy, R.guard_state(link, now)), "state": state, "decision": decision,
            "exam": S.exam_view(exam, now, full=False)}


def _device(session: Dict[str, Any]) -> str:
    return f"web:{session.get('browser_id') or ''}"


@router.get("/sessions/{sid}/state", summary="Stan podejścia (pytanie) - jak /exams/attempts/{id}")
async def session_state(sid: str, index: Optional[int] = Query(None, ge=0, le=200),
                        payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    session = await _own_session(sid, payload, who)
    return await _run(S.attempt_state(_store(), who, session["attempt_id"], index, _device(session)))


@router.get("/sessions/{sid}/paper", summary="Cały arkusz podejścia (bez kluczy) - jak /exams/attempts/{id}/paper")
async def session_paper(sid: str, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    session = await _own_session(sid, payload, who)
    return await _run(S.attempt_paper(_store(), who, session["attempt_id"], _device(session)))


@router.post("/sessions/{sid}/answers", summary="Odpowiedzi z kolejki przeglądarki - jak /exams/attempts/{id}/answers")
async def session_answers(sid: str, body: Dict[str, Any], payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    session = await _own_session(sid, payload, who)
    data = {"answers": body.get("answers"), "client_now_ms": body.get("client_now_ms"), "buffered": bool(body.get("buffered")),
            "device_id": _device(session)}
    res = await _run(S.post_answers(_store(), who, session["attempt_id"], data))
    if ((res.get("state") or {}).get("attempt") or {}).get("status") not in (None, "in_progress"):
        await _persist_quietly(session["attempt_id"])
    return res


class EventItem(BaseModel):
    kind: str = Field(min_length=1, max_length=40)
    detail: Dict[str, Any] = Field(default_factory=dict)
    client_ts_ms: Optional[float] = None


class EventsBody(BaseModel):
    events: List[EventItem] = Field(min_length=1, max_length=R.MAX_CLIENT_EVENTS)


@router.post("/sessions/{sid}/events", summary="Sygnały ochrony z przeglądarki; reakcja egzaminu")
async def session_events(sid: str, body: EventsBody, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    session = await _own_session(sid, payload, who)
    st = _store()
    now = _now()
    attempt = await S._attempt_row(st, session["attempt_id"])
    exam = await S._exam(st, attempt["exam_id"], deleted_ok=True)
    policy = R.web_policy(exam["config"])
    recorded, new, ignored = 0, 0, []
    for item in body.events:
        if item.kind not in R.CLIENT_SIGNALS:
            ignored.append({"kind": item.kind, "reason": "Nieznany sygnał."})
            continue
        counted = await _record(attempt, item.kind, item.detail, item.client_ts_ms, now, session)
        recorded += 1
        new += 1 if counted else 0
    decision = await _react(session, attempt, policy, new, now) if attempt["status"] == "in_progress" else R.decide(policy, session.get("violations") or 0, 0)
    return {"recorded": recorded, "ignored": ignored, "decision": decision, "session_status": session["status"],
            "finished": decision["action"] == "submitted"}


class BeatBody(BaseModel):
    visible: bool = True
    fullscreen: bool = True
    index: Optional[int] = None
    total: Optional[int] = None
    answered: Optional[int] = None
    deadline_at: Optional[str] = Field(None, max_length=40)
    question_left_s: Optional[float] = None


@router.post("/sessions/{sid}/beat", summary="Uderzenie serca strony (co ~5 s): stan dla strażnika, kontrola strażnika")
async def session_beat(sid: str, body: BeatBody, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    database, _, _, sessions = _tables()
    session = await _own_session(sid, payload, who, active=False)
    now = _now()
    if session["status"] != "active":
        return {"status": session["status"], "violations": session.get("violations") or 0, "guard": None, "decision": None}
    await database.execute(update(sessions).where(sessions.c.id == sid).values(beat_at=now, state_json=json.dumps(body.model_dump())))
    link = await _link(session["link_id"], who.judge_id)
    guard = R.guard_state(link, now)
    decision = None
    st = _store()
    if guard["state"] != "none":
        attempt = await S._attempt_row(st, session["attempt_id"])
        exam = await S._exam(st, attempt["exam_id"], deleted_ok=True)
        if (guard["state"] == "silent" and not session.get("guard_alarm") and attempt["status"] == "in_progress"
                and R.guard_heard_since(link, session.get("started_at"))):
            await database.execute(update(sessions).where(sessions.c.id == sid).values(guard_alarm="lost"))
            await _record(attempt, "guard_lost", {"seen_s": guard.get("seen_s")}, None, now)
            decision = await _react(session, attempt, R.web_policy(exam["config"]), 1, now)
        elif guard["state"] == "ok" and session.get("guard_alarm"):
            await database.execute(update(sessions).where(sessions.c.id == sid).values(guard_alarm=None))
    return {"status": session["status"], "violations": session.get("violations") or 0, "guard": guard, "decision": decision,
            "server_now": now.isoformat()}


@router.post("/sessions/{sid}/finish", summary="Oddaj arkusz - jak /exams/attempts/{id}/finish")
async def session_finish(sid: str, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    database, _, _, sessions = _tables()
    session = await _own_session(sid, payload, who)
    res = await _run(S.finish_attempt(_store(), who, session["attempt_id"]))
    await _persist_quietly(session["attempt_id"])
    await database.execute(update(sessions).where(sessions.c.id == sid).values(status="ended", ended_at=_now(), end_reason="finished"))
    return res


@router.get("/sessions/{sid}/result", summary="Wynik wg polityki egzaminu + liczba naruszeń")
async def session_result(sid: str, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    session = await _own_session(sid, payload, who, active=False)
    res = await _run(S.attempt_result(_store(), who, session["attempt_id"]))
    res["violations"] = await _web_violations(session["attempt_id"])
    return res


@router.get("/sessions/{sid}/review", summary="Przegląd odpowiedzi z kluczem (wg answers_release) - jak /exams/attempts/{id}/review")
async def session_review(sid: str, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    # Ta sama bramka co w aplikacji: klucz nigdy nie wyprzedza wyniku; odmowa = EXAM_REVIEW_LOCKED z opens_at.
    session = await _own_session(sid, payload, who, active=False)
    return await _run(S.attempt_review(_store(), who, session["attempt_id"]))


# ─── Karta podejścia dla komisji (kontrakt 24.10: events[t_ms,kind,detail] + flags) ─


async def card_extras(attempt_id: str) -> Dict[str, Any]:
    """Flagi komputera (rytm, kliknięcia, blokady, strażnik, oddanie po naruszeniach) i etykiety osi.
    Liczone przy odczycie z zapisanych zdarzeń, czasów odpowiedzi i liczników sesji - nic nie jest utrwalane."""
    st = _store()
    database, _, _, sessions = _tables()
    attempt = await S._attempt_row(st, attempt_id)
    rows = await st.database.fetch_all(select(st.t.events).where(st.t.events.c.attempt_id == attempt_id).order_by(st.t.events.c.id))
    events = []
    for raw in rows:
        r = S._row(raw)
        events.append({"id": r["id"], "kind": r["kind"], "detail": S._loads(r["detail_json"], {}),
                       "client_ts_ms": r.get("client_ts_ms"), "at": _iso(r.get("created_at"))})
    answers = await S._load_answers(st, attempt_id)
    elapsed = [a.get("elapsed_ms") for a in sorted(answers.values(), key=lambda a: a.get("position") or 0)
               if a.get("answered_at") and not a.get("timed_out")]
    quiet: Dict[str, Any] = {}
    for raw in await database.fetch_all(select(sessions.c.quiet_json).where(sessions.c.attempt_id == attempt_id)):
        q = S._loads(S._row(raw).get("quiet_json"), {})
        for key, value in (q.get("counts") or {}).items():
            quiet.setdefault("counts", {})[key] = int(quiet.get("counts", {}).get(key, 0)) + int(value or 0)
        quiet["clicks"] = int(quiet.get("clicks") or 0) + int(q.get("clicks") or 0)
        quiet["longest_s"] = max(float(quiet.get("longest_s") or 0), float(q.get("longest_s") or 0))
        for zone, value in (q.get("zones") or {}).items():
            quiet.setdefault("zones", {})[zone] = int(quiet.get("zones", {}).get(zone, 0)) + int(value or 0)
    flags = R.attempt_flags(events, elapsed, quiet, attempt.get("finish_reason"))
    return {"flags": flags, "flag_labels": {f: R.FLAG_LABELS.get(f, f) for f in flags},
            "events": R.timeline_events(events, attempt.get("started_at")),
            "web": {"clicks_outside": int(quiet.get("clicks") or 0), "zones": quiet.get("zones") or {}, "blocked": quiet.get("counts") or {},
                    "violations": R.violation_count(events), "on_computer": str(attempt.get("device_id") or "").startswith("web:")}}


async def persist_flags(attempt_id: str) -> List[str]:
    """Flagi komputera do magazynu zdarzeń (uzgodnienie z przeglądem komisji 24.10): `time_flag`
    z `detail.flag` i `source:"web"` - oś komisji je pokazuje, a liczba naruszeń sędziego ich NIE
    liczy (`time_flag` jest w NOT_VIOLATIONS). Wołane przy oddaniu; bez powtórek tej samej flagi."""
    st = _store()
    attempt = await S._attempt_row(st, attempt_id)
    if attempt["status"] == "in_progress" or not str(attempt.get("device_id") or "").startswith("web:"):
        return []
    extras = await card_extras(attempt_id)
    have = {(e.get("detail") or {}).get("flag") for e in extras["events"] if e.get("kind") == "time_flag"}
    added = []
    for flag in extras["flags"]:
        if flag in have:
            continue
        await S._record_event(st, attempt["exam_id"], attempt, "time_flag",
                              {"flag": flag, "source": "web", "label": R.FLAG_LABELS.get(flag, flag)}, None, _now())
        added.append(flag)
    return added


async def _persist_quietly(attempt_id: str) -> None:
    try:
        await persist_flags(attempt_id)
    except Exception:  # noqa: BLE001 - flagi to sygnał dla komisji, nie mogą zepsuć oddania
        import logging

        logging.getLogger(__name__).warning("exam-web: zapis flag nieudany", exc_info=True)


def merge_card(body: Dict[str, Any], extras: Dict[str, Any]) -> Dict[str, Any]:
    """Dokleja dodatki do karty/przeglądu komisji: flagi łączone bez powtórzeń, etykiety na osi."""
    flags = list(dict.fromkeys([str(f) for f in (body.get("flags") or [])] + extras["flags"]))
    body["flags"] = flags
    body["flag_labels"] = {**(body.get("flag_labels") or {}), **extras["flag_labels"]}
    labels = {e.get("id"): e for e in extras["events"]}
    out = []
    for e in body.get("events") or []:
        hit = labels.get(e.get("id"))
        if hit is None:
            # Oś przeglądu nie niesie id - dopasowanie po chwili zapisu i rodzaju.
            hit = next((x for x in extras["events"] if x.get("at") == e.get("at") and x.get("kind") == e.get("kind")), None)
        out.append({**e, **({"t_ms": e.get("t_ms") if e.get("t_ms") is not None else hit.get("t_ms"), "label": hit["label"],
                             "signal": hit["signal"], "source": hit["source"]} if hit else {})})
    body["events"] = out if body.get("events") is not None else extras["events"]
    body["web"] = extras["web"]
    return body


# ─── Telefon-strażnik (aplikacja BAZA, zwykły token) ────────────────────────


class GuardBeat(BaseModel):
    device_id: str = Field(min_length=4, max_length=200)
    #: active = aplikacja na wierzchu, away = właśnie schodzi do tła
    state: str = Field("active", pattern="^(active|away)$")


async def _guard_link(device_id: str, judge_id: str) -> Optional[Dict[str, Any]]:
    _, _, links, _ = _tables()
    return await _one(select(links).where(and_(links.c.guard_device_id == device_id, links.c.judge_id == judge_id,
                                               links.c.revoked_at.is_(None))).order_by(desc(links.c.created_at)).limit(1))


async def _guard_view(link: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    if not link:
        return {"paired": False, "computer": None, "session": None, "server_now": now.isoformat()}
    database, _, _, sessions = _tables()
    row = await _one(select(sessions).where(sessions.c.link_id == link["id"]).order_by(desc(sessions.c.started_at)).limit(1))
    view = None
    if row:
        beat = _aware(row.get("beat_at"))
        st = _store()
        try:
            exam = await S._exam(st, row["exam_id"], deleted_ok=True)
            attempt = await S._attempt_row(st, row["attempt_id"])
            name, attempt_status, deadline = exam["name"], attempt["status"], _iso(attempt.get("deadline_at"))
        except ExamError:
            name, attempt_status, deadline = None, None, None
        view = {"id": row["id"], "status": row["status"], "end_reason": row.get("end_reason"), "exam_name": name,
                "attempt_status": attempt_status, "deadline_at": deadline, "violations": row.get("violations") or 0,
                "browser": S._loads(row.get("state_json"), {}),
                "beat_s": round((now - beat).total_seconds(), 1) if beat else None}
    return {"paired": True, "link_id": link["id"], "computer": device_hint(link.get("user_agent")), "session": view,
            "server_now": now.isoformat()}


@router.post("/guard/beat", summary="Telefon-strażnik: jestem (co ~4 s) albo schodzę do tła")
async def guard_beat(body: GuardBeat, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    _app_only(payload)
    database, _, links, sessions = _tables()
    now = _now()
    link = await _guard_link(body.device_id, who.judge_id)
    if not link:
        return await _guard_view(None, now)
    new_state = "away" if body.state == "away" else "ok"
    was = link.get("guard_state") or "ok"
    await database.execute(update(links).where(links.c.id == link["id"]).values(guard_seen_at=now, guard_state=new_state))
    link.update(guard_seen_at=now, guard_state=new_state)
    if new_state == "away" and was != "away":
        rows = await database.fetch_all(select(sessions).where(and_(sessions.c.link_id == link["id"], sessions.c.status == "active")))
        st = _store()
        for raw in rows:
            session = dict(raw._mapping) if hasattr(raw, "_mapping") else dict(raw)
            attempt = await S._attempt_row(st, session["attempt_id"])
            if attempt["status"] != "in_progress":
                continue
            exam = await S._exam(st, attempt["exam_id"], deleted_ok=True)
            await _record(attempt, "guard_left", {}, None, now)
            await _react(session, attempt, R.web_policy(exam["config"]), 1, now)
    return await _guard_view(link, now)


class GuardDevice(BaseModel):
    device_id: str = Field(min_length=4, max_length=200)


@router.post("/guard/unpair", summary="Telefon przestaje być strażnikiem tego komputera")
async def guard_unpair(body: GuardDevice, payload: Dict[str, Any] = Depends(get_jwt_payload), who: S.Who = Depends(_who)):
    _app_only(payload)
    database, _, links, sessions = _tables()
    link = await _guard_link(body.device_id, who.judge_id)
    if not link:
        return {"ok": True}
    active = await database.fetch_val(select(sessions.c.id).where(and_(sessions.c.link_id == link["id"], sessions.c.status == "active")).limit(1))
    if active:
        raise _err("EXAM_WEB_GUARD_BUSY", "Egzamin na komputerze trwa - strażnika nie da się odpiąć do jego końca.", 409)
    await database.execute(update(links).where(links.c.id == link["id"]).values(guard_device_id=None, guard_state=None))
    return {"ok": True}


async def cleanup(now: Optional[datetime] = None) -> None:
    """Sprzątanie: stare kody (doba) i sesje (30 dni)."""
    from sqlalchemy import delete

    database, codes, _, sessions = _tables()
    stamp = now or _now()
    await database.execute(delete(codes).where(codes.c.expires_at < stamp - timedelta(days=1)))
    await database.execute(delete(sessions).where(and_(sessions.c.status != "active", sessions.c.started_at < stamp - timedelta(days=30))))
