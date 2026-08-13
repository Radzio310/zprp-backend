import base64
import hashlib
import re
import secrets
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import datetime

from app.deps import get_settings, get_current_user
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

router = APIRouter(prefix="/calendar", tags=["Calendar"])

# ── PKCE (RFC 7636) ──────────────────────────────────────────────────────
# Google zaczął wymagać code_verifier przy wymianie kodu na token
# ("invalid_grant: Missing code verifier"), a /auth-url i /oauth2callback
# tworzą DWIE OSOBNE instancje Flow (osobne requesty) — verifier
# wygenerowany przy pierwszej ginął, zanim doszło do wymiany kodu przy
# drugiej. Generujemy parę sami i trzymamy verifier w pamięci pod state
# (tak samo krótkotrwałe jak sam state — cały roundtrip trwa sekundy).
# UWAGA: działa tylko dla pojedynczej instancji procesu; przy skalowaniu
# do wielu replik trzeba by przenieść to do bazy/Redis, tak jak oauth_states.
_pkce_verifiers: dict[str, tuple[str, float]] = {}
_PKCE_TTL_SECONDS = 600


def _make_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _store_pkce_verifier(state: str, verifier: str) -> None:
    now = time.time()
    # przy okazji zamiatamy dawno wygasłe wpisy, żeby słownik nie rósł
    for k in [k for k, (_, ts) in _pkce_verifiers.items() if now - ts > _PKCE_TTL_SECONDS]:
        _pkce_verifiers.pop(k, None)
    _pkce_verifiers[state] = (verifier, now)


def _pop_pkce_verifier(state: str) -> str | None:
    entry = _pkce_verifiers.pop(state, None)
    if not entry:
        return None
    verifier, ts = entry
    if time.time() - ts > _PKCE_TTL_SECONDS:
        return None
    return verifier


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
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    flow = create_flow(settings)
    verifier, challenge = _make_pkce_pair()
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    await save_oauth_state(user_login, state)
    _store_pkce_verifier(state, verifier)
    return JSONResponse({"url": auth_url})


@router.get("/oauth2callback", summary="Callback OAuth2 z Google")
async def oauth2callback(
    code: str = Query(...),
    state: str = Query(...),
    settings=Depends(get_settings),
):
    user_login = await get_user_login_by_state(state)
    if not user_login:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    verifier = _pop_pkce_verifier(state)
    flow = create_flow(settings)
    try:
        if verifier:
            flow.fetch_token(code=code, code_verifier=verifier)
        else:
            flow.fetch_token(code=code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {e}")

    creds = flow.credentials
    refresh_token = creds.refresh_token or (await get_calendar_tokens(user_login))["refresh_token"]
    await save_calendar_tokens(
        user_login,
        access_token=creds.token,
        refresh_token=refresh_token,
        expires_at=creds.expiry.isoformat(),
    )

    return RedirectResponse(f"{settings.FRONTEND_DEEP_LINK}?connected=true")


@router.get("/status", summary="Sprawdź, czy kalendarz Google jest połączony")
async def calendar_status(
    user_login: str = Depends(get_current_user),
):
    tok = await get_calendar_tokens(user_login)
    return {"connected": bool(tok)}


@router.post("/disconnect", summary="Rozłącz konto Google Calendar")
async def disconnect_calendar(
    user_login: str = Depends(get_current_user)
):
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
    return {
        "labels": [
            {
                "id": label.get("id"),
                "name": label.get("name") or "",
                "hex": label.get("backgroundColor"),
            }
            for label in labels
            if label.get("id") and _is_valid_hex(label.get("backgroundColor") or "")
        ]
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

    events = (
        build("calendar", "v3", credentials=creds)
        .events()
        .list(
            calendarId="primary",
            timeMin=time_min,
            timeMax=time_max,
            singleEvents=True,
            orderBy="startTime",
        )
        .execute()
        .get("items", [])
    )
    return events


@router.post("/events", status_code=status.HTTP_201_CREATED, summary="Utwórz nowe wydarzenie")
async def create_event(
    payload: EventCreate,
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
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

    service = build("calendar", "v3", credentials=creds)
    created = service.events().insert(calendarId="primary", body=event_body).execute()

    await save_event_mapping(user_login, payload.matchId, created["id"])
    return {"eventId": created["id"]}

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
        updated = service.events().update(
            calendarId="primary",
            eventId=event_id,
            body=event_body
        ).execute()
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
    event_id = await get_event_mapping(user_login, match_id)
    if not event_id:
        raise HTTPException(status_code=404, detail="Nie znaleziono powiązanego wydarzenia")

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
    except Exception as e:
        raise HTTPException(500, f"Błąd przy usuwaniu wydarzenia: {e}")

    await delete_event_mapping(user_login, match_id)
    return
