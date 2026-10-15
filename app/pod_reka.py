"""API funkcji produktowych BAZA pod RĘKĄ.

Publiczne dane rozgrywek obsługuje ``app.zprp_public``. Ten moduł odpowiada za
udostępnione raporty, bezpieczną sesję konta klubowego i workflow Talentów.
Nie wykonuje żadnych zapisów w ``baza.zprp.pl``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import and_, func, insert, select, update

from app.admin_guard import admin_write_guard
from app.db import (
    database,
    pod_reka_club_sessions,
    pod_reka_reports,
    pod_reka_push_subscriptions,
    pod_reka_talent_audit,
    pod_reka_talent_submissions,
    pod_reka_talent_templates,
    zprp_public_players,
    zprp_public_team_rosters,
    zprp_public_teams,
)
from app.deps import Settings, get_settings
from app.pod_reka_login_rules import (
    AttemptLimiter,
    LoginError,
    check_scope,
    client_key,
    decode_html,
    encode_login_form,
    classify_login_response,
    merge_cookies,
)
from app.pod_reka_rules import parse_club_scope, sanitize_public as _sanitize_public
from app.zprp_public.discord import webhook_configured

router = APIRouter(prefix="/api/v1/pod-reka", tags=["pod_reka"])
admin_router = APIRouter(
    prefix="/admin/pod-reka",
    tags=["pod_reka_admin"],
    dependencies=[Depends(admin_write_guard)],
)

SESSION_COOKIE = "baza_club_session"
CSRF_COOKIE = "baza_club_csrf"
SESSION_HOURS = 12
ALLOWED_STATUSES = {"draft", "submitted", "needs_changes", "under_review", "accepted", "published", "archived"}
_LOGIN_LIMITER = AttemptLimiter()


def _dict(row: Any) -> dict[str, Any]:
    return dict(row) if row else {}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fernet(settings: Settings) -> Fernet:
    raw = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def _encrypt_cookies(cookies: dict[str, str], settings: Settings) -> str:
    return _fernet(settings).encrypt(json.dumps(cookies, ensure_ascii=False).encode("utf-8")).decode("ascii")


def _decrypt_cookies(payload: str, settings: Settings) -> dict[str, str]:
    try:
        decoded = _fernet(settings).decrypt(payload.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(401, "Sesja klubowa jest nieprawidłowa") from exc
    if not isinstance(data, dict):
        raise HTTPException(401, "Sesja klubowa jest nieprawidłowa")
    return {str(k): str(v) for k, v in data.items()}


def _decode_response(response: httpx.Response) -> str:
    return decode_html(response.content, response.headers.get("content-type", ""))


class ReportCreate(BaseModel):
    title: str = Field(min_length=1, max_length=140)
    mode: Literal["snapshot", "live"] = "snapshot"
    config: dict[str, Any] = Field(default_factory=dict)
    snapshot: dict[str, Any] | None = None


class PushKeys(BaseModel):
    p256dh: str = Field(min_length=20, max_length=512)
    auth: str = Field(min_length=8, max_length=256)


class PushSubscriptionCreate(BaseModel):
    endpoint: str = Field(min_length=20, max_length=2048)
    keys: PushKeys
    topics: list[str] = Field(default_factory=list, max_length=50)


class ClubLogin(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=300)


class TalentCreate(BaseModel):
    player_id: str
    team_id: str
    season_id: str
    template_id: int
    data: dict[str, Any] = Field(default_factory=dict)
    photo_url: HttpUrl | None = None
    video_url: HttpUrl | None = None


class TalentUpdate(BaseModel):
    data: dict[str, Any] | None = None
    photo_url: HttpUrl | None = None
    video_url: HttpUrl | None = None


class TalentReview(BaseModel):
    status: Literal["needs_changes", "under_review", "accepted", "published", "archived"]
    public_fields: list[str] = Field(default_factory=list)
    # Wewnętrzna ocena admina (0-100); nigdy nie trafia do odpowiedzi publicznych ani trenera.
    private_score: float | None = Field(default=None, ge=0, le=100)
    note: str | None = Field(default=None, max_length=1000)


class TemplateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    active: bool | None = None
    schema: dict[str, Any] | None = None


class TemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    gender: str | None = None
    category: str | None = None
    position: str | None = None
    schema: dict[str, Any] = Field(default_factory=dict)


async def _session(
    baza_club_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if not baza_club_session:
        raise HTTPException(401, "Zaloguj się kontem klubowym")
    row = await database.fetch_one(
        select(pod_reka_club_sessions).where(
            and_(
                pod_reka_club_sessions.c.session_hash == _hash(baza_club_session),
                pod_reka_club_sessions.c.revoked_at.is_(None),
                pod_reka_club_sessions.c.expires_at > datetime.now(timezone.utc),
            )
        )
    )
    if not row:
        raise HTTPException(401, "Sesja klubowa wygasła")
    data = _dict(row)
    refreshed_at = data.get("scope_refreshed_at")
    if refreshed_at and refreshed_at.tzinfo is None:
        refreshed_at = refreshed_at.replace(tzinfo=timezone.utc)
    if not refreshed_at or refreshed_at <= datetime.now(timezone.utc) - timedelta(hours=1):
        cookies = _decrypt_cookies(data["upstream_cookies_encrypted"], settings)
        try:
            async with httpx.AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=20.0) as client:
                account_response = await client.get("/index.php?a=konto", cookies=cookies)
                teams_response = await client.get("/index.php?a=druzyny", cookies=cookies)
        except httpx.HTTPError:
            # baza.zprp.pl chwilowo nie odpowiada: sesja BAZY pod RĘKĄ nadal jest
            # ważna (do 12 h), więc zostajemy przy ostatnio potwierdzonym zakresie
            # zamiast wylogowywać użytkownika w trakcie awarii źródła.
            return data
        if account_response.status_code >= 500 or teams_response.status_code >= 500:
            return data
        account_html = _decode_response(account_response)
        scope = parse_club_scope(account_html, _decode_response(teams_response))
        try:
            check_scope(scope, relogin_html=account_html)
        except LoginError as exc:
            raise HTTPException(exc.status, exc.message) from exc
        if scope["club_id"] != data["club_id"]:
            raise HTTPException(403, "Nie udało się ponownie potwierdzić zakresu konta klubowego")
        now = datetime.now(timezone.utc)
        await database.execute(
            update(pod_reka_club_sessions)
            .where(pod_reka_club_sessions.c.session_hash == data["session_hash"])
            .values(team_ids_json=scope["team_ids"], display_name=scope["display_name"], scope_refreshed_at=now)
        )
        data.update(team_ids_json=scope["team_ids"], display_name=scope["display_name"], scope_refreshed_at=now)
    return data


async def _csrf_session(
    session: dict[str, Any] = Depends(_session),
    x_csrf_token: str = Header(default="", alias="X-CSRF-Token"),
) -> dict[str, Any]:
    if not x_csrf_token or not secrets.compare_digest(_hash(x_csrf_token), session["csrf_hash"]):
        raise HTTPException(403, "Nieprawidłowy token CSRF")
    return session


async def _audit(submission_id: str, actor: str, action: str, changes: dict[str, Any]) -> None:
    await database.execute(insert(pod_reka_talent_audit).values(submission_id=submission_id, actor=actor, action=action, changes_json=changes))


async def admin_read_guard(authorization: str | None = Header(default=None)) -> None:
    """Odczyty panelu admina. Bramka zapisów (`admin_write_guard`) odczytów nie
    sprawdza, a tu są dane zgłoszeń. Zachowanie jak w całej bramce: dopóki nie
    ma `ADMIN_WRITE_STRICT`, nic nie odrzucamy; po jego ustawieniu odczyt
    wymaga tokenu admina z listy `allowed_admins`."""
    from app import admin_guard as guard

    if not guard.strict_mode():
        return
    payload, reason = guard.decode_token(guard.bearer_token(authorization))
    if payload is None:
        raise guard._refusal(guard.TIER_ADMIN, reason, None)
    allowed, reason = await guard._authorize(guard.TIER_ADMIN, "", None, payload)
    if not allowed:
        raise guard._refusal(guard.TIER_ADMIN, reason, None)


@router.post("/reports", status_code=201)
async def create_report(payload: ReportCreate) -> dict[str, Any]:
    report_id = uuid.uuid4().hex[:18]
    manage_token = secrets.token_urlsafe(32)
    snapshot = _sanitize_public(payload.snapshot) if payload.mode == "snapshot" and payload.snapshot else None
    await database.execute(
        insert(pod_reka_reports).values(
            report_id=report_id,
            mode=payload.mode,
            title=payload.title,
            config_json=_sanitize_public(payload.config),
            snapshot_json=snapshot,
            manage_token_hash=_hash(manage_token),
        )
    )
    return {"report_id": report_id, "manage_token": manage_token, "url": f"/pod-reka/raport/{report_id}"}


@router.get("/reports/{report_id}")
async def get_report(report_id: str) -> dict[str, Any]:
    row = await database.fetch_one(select(pod_reka_reports).where(and_(pod_reka_reports.c.report_id == report_id, pod_reka_reports.c.deleted_at.is_(None))))
    if not row:
        raise HTTPException(404, "Nie znaleziono raportu")
    data = _dict(row)
    data.pop("manage_token_hash", None)
    return data


@router.delete("/reports/{report_id}", status_code=204)
async def delete_report(report_id: str, x_report_token: str = Header(default="", alias="X-Report-Token")) -> Response:
    row = await database.fetch_one(select(pod_reka_reports.c.manage_token_hash).where(and_(pod_reka_reports.c.report_id == report_id, pod_reka_reports.c.deleted_at.is_(None))))
    if not row or not x_report_token or not secrets.compare_digest(row["manage_token_hash"], _hash(x_report_token)):
        raise HTTPException(404, "Nie znaleziono raportu")
    await database.execute(update(pod_reka_reports).where(pod_reka_reports.c.report_id == report_id).values(deleted_at=datetime.now(timezone.utc)))


@router.post("/push-subscriptions", status_code=201)
async def save_push_subscription(payload: PushSubscriptionCreate, request: Request) -> dict[str, Any]:
    parsed = urlsplit(payload.endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Endpoint powiadomień musi być poprawnym adresem HTTPS")
    topics = sorted({str(value).strip()[:160] for value in payload.topics if str(value).strip()})
    subscription_id = uuid.uuid4().hex
    delete_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    existing = await database.fetch_one(
        select(pod_reka_push_subscriptions.c.subscription_id).where(
            pod_reka_push_subscriptions.c.endpoint == payload.endpoint
        )
    )
    values = {
        "p256dh": payload.keys.p256dh,
        "auth": payload.keys.auth,
        "topics_json": topics,
        "delete_token_hash": _hash(delete_token),
        "user_agent_hash": _hash(request.headers.get("user-agent", "")) if request.headers.get("user-agent") else None,
        "updated_at": now,
        "revoked_at": None,
    }
    if existing:
        subscription_id = str(existing["subscription_id"])
        await database.execute(
            update(pod_reka_push_subscriptions)
            .where(pod_reka_push_subscriptions.c.subscription_id == subscription_id)
            .values(**values)
        )
    else:
        await database.execute(
            insert(pod_reka_push_subscriptions).values(
                subscription_id=subscription_id,
                endpoint=payload.endpoint,
                created_at=now,
                **values,
            )
        )
    return {"subscription_id": subscription_id, "delete_token": delete_token, "topics": topics}


@router.delete("/push-subscriptions/{subscription_id}", status_code=204)
async def revoke_push_subscription(
    subscription_id: str,
    x_subscription_token: str = Header(default="", alias="X-Subscription-Token"),
) -> None:
    row = await database.fetch_one(
        select(pod_reka_push_subscriptions.c.delete_token_hash).where(
            pod_reka_push_subscriptions.c.subscription_id == subscription_id
        )
    )
    if not row or not secrets.compare_digest(str(row["delete_token_hash"]), _hash(x_subscription_token)):
        raise HTTPException(404, "Nie znaleziono subskrypcji")
    await database.execute(
        update(pod_reka_push_subscriptions)
        .where(pod_reka_push_subscriptions.c.subscription_id == subscription_id)
        .values(revoked_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
    )
    return Response(status_code=204)


@router.post("/auth/login")
async def club_login(payload: ClubLogin, response: Response, request: Request, settings: Settings = Depends(get_settings)) -> Any:
    """Logowanie kontem klubowym baza.zprp.pl (tylko odczyt, hasło nie jest zapisywane).

    Błędy mają `detail` (tekst) oraz `code`: bad_credentials, rate_limited,
    upstream_unavailable, unexpected_response, not_club_account,
    inactive_account, no_teams (opis w `app/pod_reka_login_rules.py`)."""
    address = client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")
    limit_keys = (f"ip:{address}", f"user:{payload.username.strip().lower()}")
    try:
        if _LOGIN_LIMITER.blocked(*limit_keys):
            raise LoginError("rate_limited")
        form = encode_login_form(payload.username, payload.password)
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2"}
        try:
            async with httpx.AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=25.0) as client:
                login_response = await client.post("/login.php", content=form, headers=headers)
                classify_login_response(login_response.url.path, login_response.status_code, _decode_response(login_response))
                cookies = merge_cookies(dict(client.cookies), dict(login_response.cookies))
                if not cookies:
                    raise LoginError("unexpected_response")
                account_response = await client.get("/index.php?a=konto", cookies=cookies)
                teams_response = await client.get("/index.php?a=druzyny", cookies=cookies)
        except httpx.HTTPError as exc:
            raise LoginError("upstream_unavailable") from exc
        if account_response.status_code >= 500 or teams_response.status_code >= 500:
            raise LoginError("upstream_unavailable")
        account_html = _decode_response(account_response)
        scope = parse_club_scope(account_html, _decode_response(teams_response))
        check_scope(scope, relogin_html=account_html)
    except LoginError as exc:
        if exc.code in {"bad_credentials", "not_club_account", "inactive_account", "no_teams"}:
            _LOGIN_LIMITER.fail(*limit_keys)
        return JSONResponse(status_code=exc.status, content=exc.body())
    _LOGIN_LIMITER.success(*limit_keys)

    raw_session = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    await database.execute(
        insert(pod_reka_club_sessions).values(
            session_hash=_hash(raw_session), username=payload.username, display_name=scope["display_name"],
            account_type="club", club_id=scope["club_id"], team_ids_json=scope["team_ids"],
            upstream_cookies_encrypted=_encrypt_cookies(cookies, settings), csrf_hash=_hash(csrf_token), expires_at=expires_at,
        )
    )
    secure = request.url.scheme == "https"
    same_site = "none" if secure else "lax"
    response.set_cookie(SESSION_COOKIE, raw_session, max_age=SESSION_HOURS * 3600, httponly=True, secure=secure, samesite=same_site, path="/")
    response.set_cookie(CSRF_COOKIE, csrf_token, max_age=SESSION_HOURS * 3600, httponly=False, secure=secure, samesite=same_site, path="/")
    return {"account_type": "club", "display_name": scope["display_name"], "club_id": scope["club_id"], "team_ids": scope["team_ids"], "expires_at": expires_at, "csrf_token": csrf_token}


@router.get("/auth/me")
async def club_me(session: dict[str, Any] = Depends(_session)) -> dict[str, Any]:
    return {key: session.get(key) for key in ("display_name", "account_type", "club_id", "team_ids_json", "scope_refreshed_at", "expires_at")}


@router.post("/auth/logout", status_code=204)
async def club_logout(response: Response, session: dict[str, Any] = Depends(_csrf_session)) -> Response:
    await database.execute(update(pod_reka_club_sessions).where(pod_reka_club_sessions.c.session_hash == session["session_hash"]).values(revoked_at=datetime.now(timezone.utc)))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    response.status_code = 204
    return response


@router.get("/trainer/roster")
async def trainer_roster(session: dict[str, Any] = Depends(_session)) -> dict[str, Any]:
    team_ids = [str(value) for value in session.get("team_ids_json") or []]
    rows = await database.fetch_all(
        select(
            zprp_public_players.c.player_id, zprp_public_players.c.first_name, zprp_public_players.c.last_name,
            zprp_public_players.c.birth_year, zprp_public_players.c.photo_url,
            zprp_public_team_rosters.c.team_id, zprp_public_team_rosters.c.season_id,
            zprp_public_team_rosters.c.position, zprp_public_team_rosters.c.shirt_number,
            zprp_public_teams.c.name.label("team_name"), zprp_public_teams.c.category,
        )
        .join(zprp_public_team_rosters, zprp_public_team_rosters.c.player_id == zprp_public_players.c.player_id)
        .join(zprp_public_teams, and_(zprp_public_teams.c.team_id == zprp_public_team_rosters.c.team_id, zprp_public_teams.c.season_id == zprp_public_team_rosters.c.season_id))
        .where(and_(zprp_public_team_rosters.c.team_id.in_(team_ids), zprp_public_team_rosters.c.active.is_(True)))
        .order_by(zprp_public_teams.c.name, zprp_public_players.c.last_name)
    )
    return {"items": [_dict(row) for row in rows], "count": len(rows)}


@router.get("/trainer/templates")
async def trainer_templates(session: dict[str, Any] = Depends(_session)) -> dict[str, Any]:
    rows = await database.fetch_all(select(pod_reka_talent_templates).where(pod_reka_talent_templates.c.active.is_(True)).order_by(pod_reka_talent_templates.c.name, pod_reka_talent_templates.c.version.desc()))
    return {"items": [_dict(row) for row in rows], "count": len(rows)}


@router.get("/trainer/talents")
async def trainer_talents(session: dict[str, Any] = Depends(_session)) -> dict[str, Any]:
    rows = await database.fetch_all(
        select(
            pod_reka_talent_submissions,
            zprp_public_players.c.first_name,
            zprp_public_players.c.last_name,
            zprp_public_teams.c.name.label("team_name"),
        )
        .join(zprp_public_players, zprp_public_players.c.player_id == pod_reka_talent_submissions.c.player_id)
        .join(
            zprp_public_teams,
            and_(
                zprp_public_teams.c.team_id == pod_reka_talent_submissions.c.team_id,
                zprp_public_teams.c.season_id == pod_reka_talent_submissions.c.season_id,
            ),
        )
        .where(pod_reka_talent_submissions.c.club_id == session["club_id"])
        .order_by(pod_reka_talent_submissions.c.updated_at.desc())
    )
    items = []
    for row in rows:
        data = _dict(row)
        data.pop("private_score", None)
        items.append(data)
    return {"items": items, "count": len(items)}


@router.post("/trainer/talents", status_code=201)
async def create_talent(payload: TalentCreate, session: dict[str, Any] = Depends(_csrf_session)) -> dict[str, Any]:
    team_ids = {str(value) for value in session.get("team_ids_json") or []}
    if payload.team_id not in team_ids:
        raise HTTPException(403, "Ta drużyna nie należy do zakresu zalogowanego konta")
    roster = await database.fetch_one(select(zprp_public_team_rosters.c.player_id).where(and_(zprp_public_team_rosters.c.team_id == payload.team_id, zprp_public_team_rosters.c.season_id == payload.season_id, zprp_public_team_rosters.c.player_id == payload.player_id, zprp_public_team_rosters.c.active.is_(True))))
    template = await database.fetch_one(select(pod_reka_talent_templates).where(and_(pod_reka_talent_templates.c.template_id == payload.template_id, pod_reka_talent_templates.c.active.is_(True))))
    if not roster:
        raise HTTPException(403, "Zawodnik nie znajduje się w dostępnym składzie")
    if not template:
        raise HTTPException(404, "Nie znaleziono aktywnego szablonu")
    submission_id = uuid.uuid4().hex
    await database.execute(insert(pod_reka_talent_submissions).values(submission_id=submission_id, player_id=payload.player_id, club_id=session["club_id"], team_id=payload.team_id, season_id=payload.season_id, coach_subject=session["username"], template_id=payload.template_id, template_version=template["version"], data_json=_sanitize_public(payload.data), photo_url=str(payload.photo_url) if payload.photo_url else None, video_url=str(payload.video_url) if payload.video_url else None))
    await _audit(submission_id, session["username"], "created", {"status": "draft"})
    return {"submission_id": submission_id, "status": "draft"}


@router.patch("/trainer/talents/{submission_id}")
async def update_talent(submission_id: str, payload: TalentUpdate, session: dict[str, Any] = Depends(_csrf_session)) -> dict[str, Any]:
    current = await database.fetch_one(select(pod_reka_talent_submissions).where(and_(pod_reka_talent_submissions.c.submission_id == submission_id, pod_reka_talent_submissions.c.club_id == session["club_id"], pod_reka_talent_submissions.c.status.in_(["draft", "needs_changes"]))))
    if not current:
        raise HTTPException(404, "Nie znaleziono edytowalnego zgłoszenia")
    values: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if payload.data is not None:
        values["data_json"] = _sanitize_public(payload.data)
    if payload.photo_url is not None:
        values["photo_url"] = str(payload.photo_url)
    if payload.video_url is not None:
        values["video_url"] = str(payload.video_url)
    await database.execute(update(pod_reka_talent_submissions).where(pod_reka_talent_submissions.c.submission_id == submission_id).values(**values))
    await _audit(submission_id, session["username"], "updated", values)
    return {"submission_id": submission_id, "status": current["status"]}


@router.post("/trainer/talents/{submission_id}/submit")
async def submit_talent(submission_id: str, session: dict[str, Any] = Depends(_csrf_session)) -> dict[str, Any]:
    current = await database.fetch_one(select(pod_reka_talent_submissions.c.status).where(and_(pod_reka_talent_submissions.c.submission_id == submission_id, pod_reka_talent_submissions.c.club_id == session["club_id"], pod_reka_talent_submissions.c.status.in_(["draft", "needs_changes"]))))
    if not current:
        raise HTTPException(404, "Nie znaleziono zgłoszenia gotowego do wysłania")
    now = datetime.now(timezone.utc)
    await database.execute(update(pod_reka_talent_submissions).where(pod_reka_talent_submissions.c.submission_id == submission_id).values(status="submitted", submitted_at=now, updated_at=now))
    await _audit(submission_id, session["username"], "submitted", {"from": current["status"], "to": "submitted"})
    return {"submission_id": submission_id, "status": "submitted"}


@router.get("/trainer/overview")
async def trainer_overview(session: dict[str, Any] = Depends(_session)) -> dict[str, Any]:
    """Strefa trenera: klub, drużyny z zakresu konta (najnowszy sezon) i liczniki zgłoszeń."""
    team_ids = [str(value) for value in session.get("team_ids_json") or []]
    rows = await database.fetch_all(
        select(
            zprp_public_teams.c.team_id, zprp_public_teams.c.season_id, zprp_public_teams.c.season_name,
            zprp_public_teams.c.name, zprp_public_teams.c.category, zprp_public_teams.c.gender,
        ).where(zprp_public_teams.c.team_id.in_(team_ids or [""]))
        .order_by(zprp_public_teams.c.season_name.desc())
    )
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        latest.setdefault(row["team_id"], _dict(row))
    statuses = await database.fetch_all(
        select(pod_reka_talent_submissions.c.status, func.count().label("count"))
        .where(pod_reka_talent_submissions.c.club_id == session["club_id"])
        .group_by(pod_reka_talent_submissions.c.status)
    )
    return {
        "display_name": session.get("display_name"),
        "club_id": session["club_id"],
        "teams": sorted(latest.values(), key=lambda t: t["name"]),
        "talents": {row["status"]: int(row["count"]) for row in statuses},
        "expires_at": session.get("expires_at"),
    }


@router.get("/trainer/talents/{submission_id}")
async def trainer_talent_detail(submission_id: str, session: dict[str, Any] = Depends(_session)) -> dict[str, Any]:
    row = await database.fetch_one(
        select(pod_reka_talent_submissions).where(and_(
            pod_reka_talent_submissions.c.submission_id == submission_id,
            pod_reka_talent_submissions.c.club_id == session["club_id"],
        ))
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono zgłoszenia")
    data = _dict(row)
    data.pop("private_score", None)
    audit = await database.fetch_all(
        select(pod_reka_talent_audit.c.actor, pod_reka_talent_audit.c.action, pod_reka_talent_audit.c.created_at)
        .where(pod_reka_talent_audit.c.submission_id == submission_id).order_by(pod_reka_talent_audit.c.created_at)
    )
    return {"submission": data, "history": [_dict(a) for a in audit]}


@router.delete("/trainer/talents/{submission_id}")
async def archive_talent_draft(submission_id: str, session: dict[str, Any] = Depends(_csrf_session)) -> dict[str, Any]:
    """Trener wycofuje własny szkic (lub zwrócone do poprawy zgłoszenie) - archiwizacja, nie kasowanie."""
    current = await database.fetch_one(select(pod_reka_talent_submissions.c.status).where(and_(
        pod_reka_talent_submissions.c.submission_id == submission_id,
        pod_reka_talent_submissions.c.club_id == session["club_id"],
        pod_reka_talent_submissions.c.status.in_(["draft", "needs_changes"]),
    )))
    if not current:
        raise HTTPException(404, "Nie znaleziono szkicu do wycofania")
    now = datetime.now(timezone.utc)
    await database.execute(update(pod_reka_talent_submissions).where(pod_reka_talent_submissions.c.submission_id == submission_id).values(status="archived", archived_at=now, updated_at=now))
    await _audit(submission_id, session["username"], "archived_by_trainer", {"from": current["status"]})
    return {"submission_id": submission_id, "status": "archived"}


@router.get("/talents/{submission_id}")
async def public_talent_detail(submission_id: str) -> dict[str, Any]:
    row = await database.fetch_one(
        select(pod_reka_talent_submissions, zprp_public_players.c.first_name, zprp_public_players.c.last_name, zprp_public_players.c.birth_year, zprp_public_players.c.photo_url.label("source_photo_url"), zprp_public_teams.c.name.label("team_name"), zprp_public_teams.c.category)
        .join(zprp_public_players, zprp_public_players.c.player_id == pod_reka_talent_submissions.c.player_id)
        .join(zprp_public_teams, and_(zprp_public_teams.c.team_id == pod_reka_talent_submissions.c.team_id, zprp_public_teams.c.season_id == pod_reka_talent_submissions.c.season_id))
        .where(and_(pod_reka_talent_submissions.c.submission_id == submission_id, pod_reka_talent_submissions.c.status == "published"))
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono opublikowanego profilu")
    data = _dict(row)
    public_fields = set(data.get("public_fields_json") or [])
    profile = {key: value for key, value in (data.get("data_json") or {}).items() if key in public_fields}
    return {"submission_id": data["submission_id"], "player_id": data["player_id"], "first_name": data.get("first_name"), "last_name": data.get("last_name"), "birth_year": data.get("birth_year"), "team_id": data["team_id"], "team_name": data.get("team_name"), "category": data.get("category"), "photo_url": data.get("photo_url") or data.get("source_photo_url"), "video_url": data.get("video_url"), "profile": profile, "published_at": data.get("published_at")}


@router.get("/talents")
async def public_talents(
    team_id: str | None = None,
    category: str | None = None,
    position: str | None = None,
    dominant_hand: str | None = None,
    min_height: int | None = Query(default=None, ge=100, le=250),
    max_height: int | None = Query(default=None, ge=100, le=250),
) -> dict[str, Any]:
    rows = await database.fetch_all(
        select(pod_reka_talent_submissions, zprp_public_players.c.first_name, zprp_public_players.c.last_name, zprp_public_players.c.birth_year, zprp_public_players.c.photo_url.label("source_photo_url"), zprp_public_teams.c.name.label("team_name"), zprp_public_teams.c.category)
        .join(zprp_public_players, zprp_public_players.c.player_id == pod_reka_talent_submissions.c.player_id)
        .join(zprp_public_teams, and_(zprp_public_teams.c.team_id == pod_reka_talent_submissions.c.team_id, zprp_public_teams.c.season_id == pod_reka_talent_submissions.c.season_id))
        .where(pod_reka_talent_submissions.c.status == "published")
        .order_by(pod_reka_talent_submissions.c.published_at.desc())
    )
    items = []
    for row in rows:
        data = _dict(row)
        public_fields = set(data.get("public_fields_json") or [])
        answers = data.get("data_json") or {}
        profile = {key: value for key, value in answers.items() if key in public_fields}
        if team_id and data["team_id"] != team_id:
            continue
        if category and str(data.get("category") or "").casefold() != category.casefold():
            continue
        if position and str(profile.get("position") or profile.get("second_position") or "").casefold() != position.casefold():
            continue
        if dominant_hand and str(profile.get("dominant_hand") or "").casefold() != dominant_hand.casefold():
            continue
        height = profile.get("height_cm")
        if min_height is not None and (not isinstance(height, (int, float)) or height < min_height):
            continue
        if max_height is not None and (not isinstance(height, (int, float)) or height > max_height):
            continue
        items.append({"submission_id": data["submission_id"], "player_id": data["player_id"], "first_name": data.get("first_name"), "last_name": data.get("last_name"), "birth_year": data.get("birth_year"), "team_id": data["team_id"], "team_name": data.get("team_name"), "category": data.get("category"), "photo_url": data.get("photo_url") or data.get("source_photo_url"), "profile": profile, "published_at": data.get("published_at")})
    return {"items": items, "count": len(items)}


@admin_router.get("/overview", dependencies=[Depends(admin_read_guard)])
async def admin_overview() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    reports = await database.fetch_val(select(func.count()).select_from(pod_reka_reports).where(pod_reka_reports.c.deleted_at.is_(None)))
    sessions = await database.fetch_val(select(func.count()).select_from(pod_reka_club_sessions).where(and_(pod_reka_club_sessions.c.revoked_at.is_(None), pod_reka_club_sessions.c.expires_at > now)))
    templates = await database.fetch_val(select(func.count()).select_from(pod_reka_talent_templates).where(pod_reka_talent_templates.c.active.is_(True)))
    status_rows = await database.fetch_all(select(pod_reka_talent_submissions.c.status, func.count().label("count")).group_by(pod_reka_talent_submissions.c.status))
    return {
        "generated_at": now,
        "reports": int(reports or 0),
        "active_club_sessions": int(sessions or 0),
        "active_templates": int(templates or 0),
        "discord_alerts_configured": webhook_configured(),
        "talents": {row["status"]: int(row["count"]) for row in status_rows},
    }


@admin_router.get("/talents", dependencies=[Depends(admin_read_guard)])
async def admin_talents(status: str | None = None, limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    statement = select(pod_reka_talent_submissions).order_by(pod_reka_talent_submissions.c.updated_at.desc()).limit(limit)
    if status:
        statement = statement.where(pod_reka_talent_submissions.c.status == status)
    rows = await database.fetch_all(statement)
    return {"items": [_dict(row) for row in rows], "count": len(rows)}


@admin_router.get("/talents/{submission_id}", dependencies=[Depends(admin_read_guard)])
async def admin_talent_detail(submission_id: str) -> dict[str, Any]:
    row = await database.fetch_one(
        select(pod_reka_talent_submissions, zprp_public_players.c.first_name, zprp_public_players.c.last_name, zprp_public_players.c.birth_year, zprp_public_teams.c.name.label("team_name"), zprp_public_teams.c.category)
        .join(zprp_public_players, zprp_public_players.c.player_id == pod_reka_talent_submissions.c.player_id)
        .join(zprp_public_teams, and_(zprp_public_teams.c.team_id == pod_reka_talent_submissions.c.team_id, zprp_public_teams.c.season_id == pod_reka_talent_submissions.c.season_id))
        .where(pod_reka_talent_submissions.c.submission_id == submission_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono zgłoszenia")
    audit = await database.fetch_all(select(pod_reka_talent_audit).where(pod_reka_talent_audit.c.submission_id == submission_id).order_by(pod_reka_talent_audit.c.created_at))
    return {"submission": _dict(row), "history": [_dict(a) for a in audit]}


@admin_router.get("/templates", dependencies=[Depends(admin_read_guard)])
async def admin_templates(include_inactive: bool = True) -> dict[str, Any]:
    statement = select(pod_reka_talent_templates).order_by(pod_reka_talent_templates.c.name, pod_reka_talent_templates.c.version.desc())
    if not include_inactive:
        statement = statement.where(pod_reka_talent_templates.c.active.is_(True))
    rows = await database.fetch_all(statement)
    return {"items": [_dict(row) for row in rows], "count": len(rows)}


@admin_router.patch("/templates/{template_id}")
async def update_template(template_id: int, payload: TemplateUpdate) -> dict[str, Any]:
    """Zmiana nazwy / włączenie-wyłączenie / nowy schemat (schemat podbija wersję;
    istniejące zgłoszenia zachowują wersję, na której powstały)."""
    current = await database.fetch_one(select(pod_reka_talent_templates).where(pod_reka_talent_templates.c.template_id == template_id))
    if not current:
        raise HTTPException(404, "Nie znaleziono szablonu")
    values: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if payload.name is not None:
        values["name"] = payload.name
    if payload.active is not None:
        values["active"] = payload.active
    if payload.schema is not None and payload.schema != current["schema_json"]:
        values["schema_json"] = payload.schema
        values["version"] = int(current["version"]) + 1
    await database.execute(update(pod_reka_talent_templates).where(pod_reka_talent_templates.c.template_id == template_id).values(**values))
    return {"template_id": template_id, "version": values.get("version", current["version"]), "active": values.get("active", current["active"])}


@admin_router.post("/templates", status_code=201)
async def create_template(payload: TemplateCreate, request: Request) -> dict[str, Any]:
    actor = request.headers.get("X-Admin-Actor", "admin")
    template_id = await database.execute(insert(pod_reka_talent_templates).values(name=payload.name, gender=payload.gender, category=payload.category, position=payload.position, schema_json=payload.schema, created_by=actor))
    return {"template_id": template_id, "version": 1}


@admin_router.patch("/talents/{submission_id}")
async def review_talent(submission_id: str, payload: TalentReview, request: Request) -> dict[str, Any]:
    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(400, "Nieprawidłowy status")
    current = await database.fetch_one(select(pod_reka_talent_submissions).where(pod_reka_talent_submissions.c.submission_id == submission_id))
    if not current:
        raise HTTPException(404, "Nie znaleziono zgłoszenia")
    now = datetime.now(timezone.utc)
    values: dict[str, Any] = {"status": payload.status, "public_fields_json": payload.public_fields, "updated_at": now}
    if payload.private_score is not None:
        values["private_score"] = payload.private_score
    if payload.status == "published":
        values["published_at"] = now
    if payload.status == "archived":
        values["archived_at"] = now
    await database.execute(update(pod_reka_talent_submissions).where(pod_reka_talent_submissions.c.submission_id == submission_id).values(**values))
    await _audit(submission_id, request.headers.get("X-Admin-Actor", "admin"), "reviewed", {"from": current["status"], "to": payload.status, "public_fields": payload.public_fields, "note": payload.note})
    return {"submission_id": submission_id, "status": payload.status}


async def ensure_pod_reka_defaults() -> int:
    """Tworzy wersjonowany szablon bazowy, jeśli panel nie ma jeszcze żadnego."""
    existing = await database.fetch_one(select(pod_reka_talent_templates.c.template_id).limit(1))
    if existing:
        return 0
    schema = {
        "fields": [
            "second_position", "dominant_hand", "height_cm", "training_years",
            "description", "strengths", "development_areas", "tests",
        ],
        "tests": [
            "sprint_seconds", "agility_seconds", "jump_cm", "medicine_ball_m",
            "endurance_level", "shot_speed_kmh", "accuracy_percent", "decisions_score",
        ],
        "public_by_default": [],
    }
    await database.execute(
        insert(pod_reka_talent_templates).values(
            name="Profil bazowy zawodnika", version=1, schema_json=schema, created_by="system",
        )
    )
    return 1
