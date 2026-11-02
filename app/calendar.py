import asyncio
import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import datetime

from app.deps import get_settings, get_current_user
from app.calendar_event_ids import google_event_id
from app.calendar_storage import (
    save_oauth_state,
    get_oauth_state,
    get_user_login_by_state,
    save_calendar_tokens,
    get_calendar_tokens,
    delete_calendar_tokens,
    save_event_mapping,
    get_event_mapping,
    delete_event_mapping,
)
from app.calendar_utils import create_flow  # Twój helper do Flow
from app.calendar_secondary_engine import (
    account_uses_secondary,
    cleanup_previous,
    finish_connection,
    plan_write,
    previous_placement,
    primary_body_extras,
    remove_event,
    require_primary_read,
    run_job,
    save_connection,
    write_event,
)
from app.calendar_secondary_engine import disconnect as secondary_disconnect
from app.calendar_secondary_google import build_deps as build_secondary_deps
from app.calendar_secondary_rules import (
    SecondaryError,
    email_from_id_token,
    flag_enabled,
    lacks_events_scope,
    make_state,
    missing_scopes,
    parse_tier,
    scope_to_string,
    tier_from_state,
)

router = APIRouter(prefix="/calendar", tags=["Calendar"])
logger = logging.getLogger(__name__)

# ── PKCE (RFC 7636) ──────────────────────────────────────────────────────
# Google wymaga code_verifier przy wymianie kodu na token, a /auth-url
# i /oauth2callback to osobne żądania. Verifier wyprowadzamy z state i sekretu
# klienta zamiast trzymać go w pamięci: trzymany ginął przy każdym wdrożeniu
# w trakcie zgody i dawał sędziemu „Missing code verifier".
def _pkce_verifier(settings, state: str) -> str:
    secret = str(getattr(settings, "GOOGLE_CLIENT_SECRET", "")).encode("utf-8")
    digest = hmac.new(secret, f"calendar-pkce:{state}".encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# Kod zgody jest jednorazowy, a przeglądarka potrafi wysłać go drugi raz
# (odświeżenie strony). Powtórka tego samego state nie idzie już do Google.
_exchanged_states: dict[str, float] = {}
_EXCHANGED_TTL_SECONDS = 600
_TOKEN_TIMEOUT_SECONDS = 20
_connect_tasks: set[asyncio.Task] = set()


def _claim_state(state: str) -> bool:
    now = time.time()
    for key in [k for k, ts in _exchanged_states.items() if now - ts > _EXCHANGED_TTL_SECONDS]:
        _exchanged_states.pop(key, None)
    if state in _exchanged_states:
        return False
    _exchanged_states[state] = now
    return True


async def _exchange_code(flow, code: str, state: str, settings) -> bool:
    """Wymiana kodu w wątku, żeby wolne Google nie stawało całego serwera."""
    try:
        await asyncio.to_thread(
            flow.fetch_token,
            code=code,
            code_verifier=_pkce_verifier(settings, state),
            timeout=_TOKEN_TIMEOUT_SECONDS,
        )
        return True
    except Exception as exc:  # noqa: BLE001 - sędzia dostaje ekran aplikacji, nie surowy JSON
        logger.warning("Wymiana kodu Google nieudana: %s", exc)
        _exchanged_states.pop(state, None)
        return False


def _back_to_app(settings, query: str) -> RedirectResponse:
    return RedirectResponse(f"{settings.FRONTEND_DEEP_LINK}?{query}")


class EventCreate(BaseModel):
    matchId: str
    summary: str
    start: datetime.datetime
    end: datetime.datetime
    location: str
    # ID klasycznego koloru ("1".."11", colorId) ALBO UUID własnej etykiety
    # (eventLabelId) — patrz _event_color_field niżej, które z dwóch pól
    # Google API dostanie ta wartość, rozpoznawane po formacie.
    colorId: str
    reminders: list[dict]  # np. [{"method":"popup","minutes":180}, ...]
    # Cel wpisu (whistle | stopwatch | primary). Bez pola decyduje SERWER po
    # prefiksie tytułu (⚽️ boiskowy, ⏱️ stolikowy, reszta główny). Działa tylko
    # przy włączonej fladze kalendarzy drugorzędnych.
    target: str | None = None


class EventLabelCreate(BaseModel):
    name: str | None = None
    hex: str


def _is_valid_hex(value: str) -> bool:
    return bool(re.fullmatch(r"#[0-9a-fA-F]{6}", value or ""))


def _is_label_id(color_id: str) -> bool:
    # Klasyczne colorId to zawsze krótkie cyfry ("1".."11"); UUID-y etykiet
    # zawsze mają myślniki — prosty, tani w utrzymaniu rozróżnik bez zmiany
    # kształtu JSON-a ustawień we froncie.
    return "-" in (color_id or "")


def _event_color_field(color_id: str | None) -> dict:
    if not color_id:
        return {}
    return {"eventLabelId": color_id} if _is_label_id(color_id) else {"colorId": color_id}


def _apply_event_label_version(request):
    """Google wymaga ?eventLabelVersion=1 w URL-u, żeby w ogóle PRZETWORZYĆ
    pole eventLabelId przy insert/update/patch — bez tego API po cichu (bez
    błędu) je ignoruje (dok.: "You must append ?eventLabelVersion=1 to your
    request URL to process this field"). Doklejamy ręcznie do request.uri
    zamiast przez kwarg metody, bo statyczny discovery.json spakowany w
    zainstalowanej wersji google-api-python-client może jeszcze nie znać
    tego parametru — wtedy kwarg rzuciłby TypeError; edycja URI działa
    zawsze, niezależnie od wersji biblioteki.
    """
    sep = "&" if "?" in request.uri else "?"
    request.uri = f"{request.uri}{sep}eventLabelVersion=1"
    return request


def _secondary_http(exc: SecondaryError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.detail())


async def _guard_primary_read(settings, user_login: str) -> None:
    """Flaga włączona: kalendarz główny tylko dla legacy i district (inaczej 403)."""
    if not flag_enabled(settings):
        return
    try:
        await require_primary_read(build_secondary_deps(settings), user_login)
    except SecondaryError as exc:
        raise _secondary_http(exc) from exc


async def _get_calendar_service(user_login: str, settings):
    """Credentials + odświeżenie tokena — ten sam wzorzec co w każdym
    endpoincie kalendarza niżej, wydzielony dla nowych endpointów etykiet,
    żeby nie dublować kolejny raz i nie ruszać już działających ścieżek."""
    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    expiry_dt = datetime.datetime.fromisoformat(tokens["expires_at"])
    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=expiry_dt,
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        await save_calendar_tokens(
            user_login,
            access_token=creds.token,
            refresh_token=creds.refresh_token,
            expires_at=creds.expiry.isoformat(),
        )
    return build("calendar", "v3", credentials=creds)


@router.get("/auth-url", summary="Wygeneruj URL do Google OAuth2")
async def get_auth_url(
    tier: str | None = Query(None, description="matches | district (przy włączonej fladze)"),
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    if flag_enabled(settings):
        try:
            level = parse_tier(tier)
        except SecondaryError as exc:
            raise _secondary_http(exc) from exc
        flow = create_flow(settings, level)
        # Poziom jedzie w state (state sprawdzamy w bazie, więc przedrostek jest
        # wiarygodny). matches: tylko kalendarze BAZY; district prosi o komplet wprost,
        # bo dawne zgody tego klienta dołożyłyby do tokenu kalendarza np. Dysk Mentora.
        new_state = make_state(level, secrets.token_urlsafe(32))
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="false",
            prompt="consent",
            state=new_state,
            code_challenge=_pkce_challenge(_pkce_verifier(settings, new_state)),
            code_challenge_method="S256",
        )
        await save_oauth_state(user_login, state)
        return JSONResponse({"url": auth_url})

    flow = create_flow(settings)
    new_state = secrets.token_urlsafe(32)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="false",
        prompt="consent",
        state=new_state,
        code_challenge=_pkce_challenge(_pkce_verifier(settings, new_state)),
        code_challenge_method="S256",
    )
    await save_oauth_state(user_login, state)
    return JSONResponse({"url": auth_url})


@router.get("/oauth2callback", summary="Callback OAuth2 z Google")
async def oauth2callback(
    code: str = Query(...),
    state: str = Query(...),
    settings=Depends(get_settings),
):
    if flag_enabled(settings):
        return await _secondary_callback(code, state, settings)

    user_login = await get_user_login_by_state(state)
    if not user_login:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    if not _claim_state(state):
        return _back_to_app(settings, "connected=true")
    flow = create_flow(settings)
    if not await _exchange_code(flow, code, state, settings):
        return _back_to_app(settings, "connected=false&calendar_error=exchange_failed")

    token = getattr(getattr(flow, "oauth2session", None), "token", None) or {}
    if lacks_events_scope(token.get("scope")):
        # Zgoda bez kalendarza nie nadpisuje działającego tokenu.
        return _back_to_app(settings, "connected=false&calendar_error=scope_missing")

    creds = flow.credentials
    refresh_token = creds.refresh_token or (await get_calendar_tokens(user_login))["refresh_token"]
    await save_calendar_tokens(
        user_login,
        access_token=creds.token,
        refresh_token=refresh_token,
        expires_at=creds.expiry.isoformat(),
    )

    return RedirectResponse(f"{settings.FRONTEND_DEEP_LINK}?connected=true")


async def _secondary_callback(code: str, state: str, settings):
    """Callback po włączeniu flagi: zapisuje przyznane zakresy, przejmuje albo
    zakłada kalendarze BAZY i (gdy trzeba) uruchamia przenoszenie w tle."""
    user_login = await get_user_login_by_state(state)
    if not user_login:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    if not _claim_state(state):
        return _back_to_app(settings, "connected=true")
    tier = tier_from_state(state) or "matches"
    flow = create_flow(settings, tier)
    if not await _exchange_code(flow, code, state, settings):
        return _back_to_app(settings, "connected=false&calendar_error=exchange_failed")

    creds = flow.credentials
    token = getattr(getattr(flow, "oauth2session", None), "token", None) or {}
    granted = scope_to_string(token.get("scope") or getattr(creds, "scopes", None))
    if missing_scopes(tier, granted):
        # Zgoda częściowa: nie nadpisujemy tokenu ani stanu, aplikacja dostaje powód.
        _exchanged_states.pop(state, None)
        return _back_to_app(settings, "connected=false&calendar_error=scope_missing")
    email =email_from_id_token(token.get("id_token") or getattr(creds, "id_token", None))
    existing = await get_calendar_tokens(user_login)
    previous = dict(getattr(existing, "_mapping", existing)) if existing else None
    refresh_token = creds.refresh_token or (previous or {}).get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "refresh_token_missing",
                "message": "Google nie przekazał tokenu odświeżania. Usuń dostęp BAZY w koncie Google i połącz ponownie.",
            },
        )
    deps = build_secondary_deps(settings)
    try:
        await save_connection(
            deps,
            user_login,
            previous=previous,
            new_tokens={
                "access_token": creds.token,
                "refresh_token": refresh_token,
                "expires_at": creds.expiry.isoformat(),
                "scope": granted,
            },
            email=email,
        )
    except SecondaryError as exc:
        raise _secondary_http(exc) from exc
    # Sędzia wraca od razu. Kalendarze i przenoszenie idą w tle, a ekran pokazuje
    # ich stan z /calendar/setup: czekanie na Google wisiało tu całą stronę.
    task = asyncio.create_task(_finish_connection_in_background(deps, user_login))
    _connect_tasks.add(task)
    task.add_done_callback(_connect_tasks.discard)
    return _back_to_app(settings, "connected=true")


async def _finish_connection_in_background(deps, user_login: str) -> None:
    try:
        start, warnings = await finish_connection(deps, user_login)
        for warning in warnings:
            logger.warning("Kalendarze BAZY po połączeniu: %s", warning)
        if start:
            await run_job(deps, user_login)
    except Exception:  # noqa: BLE001 - zadanie w tle, kalendarze powstaną przy pierwszym zapisie
        logger.exception("Kalendarze BAZY po połączeniu nie zostały dokończone")


@router.get("/status", summary="Sprawdź, czy kalendarz Google jest połączony")
async def calendar_status(
    user_login: str = Depends(get_current_user),
):
    tok = await get_calendar_tokens(user_login)
    return {"connected": bool(tok)}


@router.post("/disconnect", summary="Rozłącz konto Google Calendar")
async def disconnect_calendar(
    remove_calendars: bool | None = Query(
        None, description="true: usuń kalendarze BAZY w Google; false: zostaw wpisy"
    ),
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    if flag_enabled(settings):
        try:
            was_connected, warnings = await secondary_disconnect(
                build_secondary_deps(settings), user_login, remove_calendars
            )
        except SecondaryError as exc:
            raise _secondary_http(exc) from exc
        if not was_connected:
            return JSONResponse(
                {"detail": "Brak połączenia z kalendarzem"},
                status_code=status.HTTP_400_BAD_REQUEST
            )
        body = {"disconnected": True}
        if warnings:
            body["warnings"] = warnings
        return JSONResponse(body)

    existing = await get_calendar_tokens(user_login)
    if not existing:
        return JSONResponse(
            {"detail": "Brak połączenia z kalendarzem"},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    await delete_calendar_tokens(user_login)
    return JSONResponse({"disconnected": True})


@router.get("/colors", summary="Paleta kolorów wydarzeń Google Calendar")
async def event_colors(
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    """Zwraca AKTUALNĄ paletę kolorów wydarzeń z colors.get().

    Od czerwca 2026 Google rozszerzył kolory wydarzeń z 11 do 24 i mapowanie
    colorId→hex zależy od rolloutu na koncie użytkownika. Dlatego aplikacja
    nie zgaduje palety, tylko pyta o nią to konto, na którym faktycznie
    zapisuje wydarzenia — dzięki temu kolor wybrany w BAZIE zawsze wygląda
    identycznie w Kalendarzu Google.
    """
    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    expiry_dt = datetime.datetime.fromisoformat(tokens["expires_at"])
    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=expiry_dt,
    )
    try:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            await save_calendar_tokens(
                user_login,
                access_token=creds.token,
                refresh_token=creds.refresh_token,
                expires_at=creds.expiry.isoformat(),
            )

        palette = build("calendar", "v3", credentials=creds).colors().get().execute()
    except Exception as e:
        # Bez tego FastAPI zwraca gołe "Internal Server Error" bez śladu, co
        # naprawdę poszło nie tak (odświeżenie tokena? colors.get()? zły
        # zakres uprawnień?) — a to jedyny nowy kod na tej ścieżce.
        raise HTTPException(
            status_code=502,
            detail=f"Google colors.get() nie powiodło się: {type(e).__name__}: {e}",
        )

    event_palette = palette.get("event", {}) or {}
    return {
        "colors": [
            {"id": color_id, "hex": defn.get("background")}
            for color_id, defn in event_palette.items()
            if defn.get("background")
        ]
    }


@router.get(
    "/labels",
    summary="Etykiety wydarzeń (dowolny hex, do 200 na kalendarz) z konta",
)
async def list_event_labels(
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    """Nowszy system kolorów wydarzeń Google (labelProperties.eventLabels)
    — w przeciwieństwie do klasycznego colorId (zawsze 11) pozwala na
    DOWOLNY hex i istnieje per-kalendarz. To właśnie te kolory widać w
    natywnej apce Google Calendar przy wyborze koloru wydarzenia."""
    await _guard_primary_read(settings, user_login)
    try:
        service = await _get_calendar_service(user_login, settings)
        cal = service.calendars().get(calendarId="primary").execute()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Nie udało się pobrać etykiet: {type(e).__name__}: {e}",
        )

    labels = (cal.get("labelProperties") or {}).get("eventLabels") or []

    # Kolor kalendarza głównego = kafelek kategorii „domyślnej" niedyspozycji
    # (wydarzenie bez wybranego koloru nosi w Google kolor kalendarza).
    # Dodatek, nie warunek: bez niego etykiety i tak wracają.
    calendar_color = None
    try:
        entry = service.calendarList().get(calendarId="primary").execute()
        background = entry.get("backgroundColor") or ""
        calendar_color = background if _is_valid_hex(background) else None
    except Exception:
        calendar_color = None

    return {
        "labels": [
            {
                "id": label.get("id"),
                "name": label.get("name") or "",
                "hex": label.get("backgroundColor"),
            }
            for label in labels
            if label.get("id") and _is_valid_hex(label.get("backgroundColor") or "")
        ],
        "calendarColor": calendar_color,
    }


@router.post(
    "/labels",
    summary="Utwórz nową etykietę wydarzenia z dowolnym kolorem",
)
async def create_event_label(
    payload: EventLabelCreate,
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    if not _is_valid_hex(payload.hex):
        raise HTTPException(status_code=400, detail="Nieprawidłowy hex koloru")

    await _guard_primary_read(settings, user_login)
    try:
        service = await _get_calendar_service(user_login, settings)
        # Patch NADPISUJE całą listę etykiet — trzeba najpierw pobrać
        # istniejące i dopisać naszą, żeby nie skasować cudzych.
        cal = service.calendars().get(calendarId="primary").execute()
        existing = list((cal.get("labelProperties") or {}).get("eventLabels") or [])
        new_id = str(uuid.uuid4())
        existing.append(
            {
                "id": new_id,
                "name": (payload.name or "").strip()[:50],
                "backgroundColor": payload.hex,
            }
        )
        service.calendars().patch(
            calendarId="primary",
            body={"labelProperties": {"eventLabels": existing}},
        ).execute()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Nie udało się utworzyć etykiety: {type(e).__name__}: {e}",
        )

    return {"id": new_id, "name": (payload.name or "").strip()[:50], "hex": payload.hex}


@router.get("/events", summary="Pobierz nadchodzące wydarzenia")
async def list_events(
    days_ahead: int = Query(30, description="Ile dni do przodu pobrać"),
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    await _guard_primary_read(settings, user_login)
    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    # Konwersja string → datetime
    expiry_dt = datetime.datetime.fromisoformat(tokens["expires_at"])

    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=expiry_dt,
    )

    # Odświeżenie tokena, jeśli wygasł
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        await save_calendar_tokens(
            user_login,
            access_token=creds.token,
            refresh_token=creds.refresh_token,
            expires_at=creds.expiry.isoformat(),
        )

    now = datetime.datetime.utcnow()
    time_min = now.isoformat() + "Z"
    time_max = (now + datetime.timedelta(days=days_ahead)).isoformat() + "Z"

    service = build("calendar", "v3", credentials=creds)
    list_kwargs = dict(
        calendarId="primary",
        timeMin=time_min,
        timeMax=time_max,
        singleEvents=True,
        orderBy="startTime",
    )
    try:
        # eventLabelVersion=1: bez tego parametru Google pomija w odpowiedzi
        # pole eventLabelId i wydarzenie z własną etykietą wygląda jak bez
        # koloru - aplikacja wrzuciłaby je do kategorii domyślnej.
        events = (
            _apply_event_label_version(service.events().list(**list_kwargs))
            .execute()
            .get("items", [])
        )
    except HttpError as e:
        # Gdyby API odrzuciło parametr przy listowaniu: import ma działać
        # jak dotąd (bez etykiet), a nie stanąć.
        if getattr(getattr(e, "resp", None), "status", None) != 400:
            raise
        events = service.events().list(**list_kwargs).execute().get("items", [])
    return events


@router.post("/events", status_code=status.HTTP_201_CREATED, summary="Utwórz nowe wydarzenie")
async def create_event(
    payload: EventCreate,
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    # Kalendarze drugorzędne (flaga): trasuje SERWER. Przy wyłączonej fladze
    # i dla kont legacy `sec_plan` zostaje None i działa dotychczasowa ścieżka.
    sec_plan = None
    sec_deps = None
    prev_placement = None
    if flag_enabled(settings):
        sec_deps = build_secondary_deps(settings)
        try:
            sec_plan = await plan_write(sec_deps, user_login, payload.summary, payload.target)
            if sec_plan is not None and sec_plan.kind is not None:
                return await write_event(
                    sec_deps,
                    user_login,
                    sec_plan,
                    payload.matchId,
                    summary=payload.summary,
                    start=payload.start,
                    end=payload.end,
                    location=payload.location,
                    reminders=payload.reminders,
                )
            if sec_plan is not None:
                prev_placement = await previous_placement(sec_deps, user_login, payload.matchId)
        except SecondaryError as exc:
            raise _secondary_http(exc) from exc

    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    expiry_dt = datetime.datetime.fromisoformat(tokens["expires_at"])

    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=expiry_dt,
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        await save_calendar_tokens(
            user_login,
            access_token=creds.token,
            refresh_token=creds.refresh_token,
            expires_at=creds.expiry.isoformat(),
        )

    event_body = {
        "summary": payload.summary,
        "start": {"dateTime": payload.start.isoformat()},
        "end": {"dateTime": payload.end.isoformat()},
        "location": payload.location,
        **_event_color_field(payload.colorId),
        "reminders": {"useDefault": False, "overrides": payload.reminders},
    }
    if sec_plan is not None:
        try:
            event_body.update(
                await primary_body_extras(sec_deps, user_login, payload.reminders)
            )
        except SecondaryError as exc:
            raise _secondary_http(exc) from exc

    service = build("calendar", "v3", credentials=creds)
    events = service.events()
    mapped_id = await get_event_mapping(user_login, payload.matchId)
    if sec_plan is not None and prev_placement and prev_placement.get("calendar_id"):
        # Wpis leży w kalendarzu drugorzędnym: w głównym wstawiamy nowy,
        # a stary kasujemy dopiero po zapisie (cleanup_previous niżej).
        mapped_id = None
    if mapped_id:
        request = events.update(calendarId="primary", eventId=mapped_id, body=event_body)
        if _is_label_id(payload.colorId):
            request = _apply_event_label_version(request)
        try:
            updated = request.execute()
            return {"eventId": updated["id"]}
        except HttpError as exc:
            if exc.resp.status not in (404, 410):
                raise
            # Stare mapowanie wskazuje wpis ręcznie usunięty w Google.

    # Stałe ID powoduje, że ponowiony POST (także po timeout lub z innego
    # urządzenia) nie tworzy kolejnego wydarzenia. Google dopuszcza cyfry 0-9
    # i litery a-v w identyfikatorach; szesnastkowy SHA-256 spełnia ten wymóg.
    event_id = google_event_id(user_login, payload.matchId)
    request = events.insert(calendarId="primary", body={**event_body, "id": event_id})
    if _is_label_id(payload.colorId):
        request = _apply_event_label_version(request)
    try:
        saved = request.execute()
    except HttpError as exc:
        if exc.resp.status != 409:
            raise
        request = events.update(calendarId="primary", eventId=event_id, body=event_body)
        if _is_label_id(payload.colorId):
            request = _apply_event_label_version(request)
        saved = request.execute()

    if sec_plan is None:
        await save_event_mapping(user_login, payload.matchId, saved["id"])
        return {"eventId": saved["id"]}

    # Konto po przejściu, cel primary: wpis mógł leżeć w kalendarzu drugorzędnym.
    # Najpierw zapis w nowym miejscu (wyżej), dopiero teraz kasujemy stare.
    await save_event_mapping(user_login, payload.matchId, saved["id"], calendar_id=None)
    result = {"eventId": saved["id"]}
    warning = await cleanup_previous(sec_deps, user_login, prev_placement)
    if warning:
        result["warning"] = warning
    return result

@router.put(
    "/events/{match_id:path}",
    status_code=status.HTTP_200_OK,
    summary="Aktualizuj istniejące wydarzenie po match_id"
)
async def update_event(
    payload: EventCreate,
    match_id: str = Path(..., description="Numer meczu (matchId)"),
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    if flag_enabled(settings):
        sec_deps = build_secondary_deps(settings)
        try:
            plan = await plan_write(sec_deps, user_login, payload.summary, payload.target)
            if plan is not None and not await previous_placement(sec_deps, user_login, match_id):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Nie znaleziono powiązanego wydarzenia do edycji",
                )
        except SecondaryError as exc:
            raise _secondary_http(exc) from exc
        if plan is not None:
            # Kalendarze drugorzędne: ta sama logika trasowania co przy POST.
            return await create_event(
                payload.model_copy(update={"matchId": match_id}), settings, user_login
            )

    # 1) znajdź event_id z mapowania
    event_id = await get_event_mapping(user_login, match_id)
    if not event_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nie znaleziono powiązanego wydarzenia do edycji"
        )

    # 2) pobierz tokeny i odśwież jeśli trzeba
    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    expiry_dt = datetime.datetime.fromisoformat(tokens["expires_at"])
    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=expiry_dt,
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        await save_calendar_tokens(
            user_login,
            access_token=creds.token,
            refresh_token=creds.refresh_token,
            expires_at=creds.expiry.isoformat(),
        )

    # 3) przygotuj body do update
    event_body = {
        "summary": payload.summary,
        "start": {"dateTime": payload.start.isoformat()},
        "end": {"dateTime": payload.end.isoformat()},
        "location": payload.location,
        **_event_color_field(payload.colorId),
        "reminders": {"useDefault": False, "overrides": payload.reminders},
    }

    service = build("calendar", "v3", credentials=creds)
    try:
        request = service.events().update(
            calendarId="primary",
            eventId=event_id,
            body=event_body
        )
        if _is_label_id(payload.colorId):
            request = _apply_event_label_version(request)
        updated = request.execute()
    except HttpError as e:
        if e.resp.status in (404, 410):
            raise HTTPException(
                status_code=404,
                detail="Nie znaleziono powiązanego wydarzenia do edycji",
            ) from e
        raise HTTPException(
            status_code=502,
            detail=f"Błąd przy aktualizacji wydarzenia: {e}",
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Błąd przy aktualizacji wydarzenia: {e}"
        )

    # 4) nadpisz mapping (chociaż id zwykle nie zmienia się)
    await save_event_mapping(user_login, match_id, updated["id"])

    return {"eventId": updated["id"]}


@router.delete("/events/{match_id:path}", status_code=status.HTTP_204_NO_CONTENT, summary="Usuń wydarzenie po match_id")
async def delete_event(
    match_id: str,
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    if flag_enabled(settings):
        sec_deps = build_secondary_deps(settings)
        try:
            if await account_uses_secondary(sec_deps, user_login):
                await remove_event(sec_deps, user_login, match_id)
                return
        except SecondaryError as exc:
            raise _secondary_http(exc) from exc

    event_id = await get_event_mapping(user_login, match_id)
    if not event_id:
        # DELETE jest idempotentny: brak mapowania znaczy, że żądany stan już
        # został osiągnięty. 404 generowało niepotrzebne alarmy przy sprzątaniu
        # duplikatów i po ręcznym usunięciu wpisu przez użytkownika.
        return

    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    expiry_dt = datetime.datetime.fromisoformat(tokens["expires_at"])

    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=expiry_dt,
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        await save_calendar_tokens(
            user_login,
            access_token=creds.token,
            refresh_token=creds.refresh_token,
            expires_at=creds.expiry.isoformat(),
        )

    service = build("calendar", "v3", credentials=creds)
    try:
        service.events().delete(calendarId="primary", eventId=event_id).execute()
    except HttpError as e:
        if e.resp.status not in (404, 410):
            raise HTTPException(502, f"Błąd przy usuwaniu wydarzenia: {e}") from e
        # Wydarzenie usunięte ręcznie w Google: czyścimy tylko stare mapowanie.
    except Exception as e:
        raise HTTPException(500, f"Błąd przy usuwaniu wydarzenia: {e}") from e

    await delete_event_mapping(user_login, match_id)
    return
