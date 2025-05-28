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


class EventCreate(BaseModel):
    matchId: str
    summary: str
    start: datetime.datetime
    end: datetime.datetime
    location: str
    colorId: str
    reminders: list[dict]  # np. [{"method":"popup","minutes":180}, ...]


@router.get("/auth-url", summary="Wygeneruj URL do Google OAuth2")
async def get_auth_url(
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    flow = create_flow(settings)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    await save_oauth_state(user_login, state)
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

    flow = create_flow(settings)
    try:
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
        "colorId": payload.colorId,
        "reminders": {"useDefault": False, "overrides": payload.reminders},
    }

    service = build("calendar", "v3", credentials=creds)
    created = service.events().insert(calendarId="primary", body=event_body).execute()

    await save_event_mapping(user_login, payload.matchId, created["id"])
    return {"eventId": created["id"]}

@router.put(
    "/events/{match_id}",
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
        "colorId": payload.colorId,
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


@router.delete("/events/{match_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Usuń wydarzenie po match_id")
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
