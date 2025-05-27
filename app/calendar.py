# app/calendar.py

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, RedirectResponse
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import datetime

from app.deps import get_settings, get_current_user
from app.calendar_storage import (
    save_oauth_state,
    get_oauth_state,
    get_user_login_by_state,
    save_calendar_tokens,
    get_calendar_tokens,
    delete_calendar_tokens,
)

router = APIRouter(prefix="/calendar", tags=["Calendar"])


def create_flow(settings):
    client_config = {
        "web": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [f"{settings.BACKEND_URL}/calendar/oauth2callback"],
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=["https://www.googleapis.com/auth/calendar.events"],
    )
    flow.redirect_uri = f"{settings.BACKEND_URL}/calendar/oauth2callback"
    return flow


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
    # save CSRF state for this user
    await save_oauth_state(user_login, state)
    return JSONResponse({"url": auth_url})


@router.get("/oauth2callback", summary="Callback OAuth2 z Google")
async def oauth2callback(
    code: str = Query(...),
    state: str = Query(...),
    settings=Depends(get_settings),
):
    # identify user by saved state
    user_login = await get_user_login_by_state(state)
    if not user_login:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    flow = create_flow(settings)
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {e}")

    creds = flow.credentials
    # if Google didn't return a fresh refresh_token, reuse the old one
    if not creds.refresh_token:
        existing = await get_calendar_tokens(user_login)
        if existing and existing["refresh_token"]:
            refresh_token = existing["refresh_token"]
        else:
            raise HTTPException(
                status_code=400,
                detail="Brak refresh_token. Powtórz consent.",
            )
    else:
        refresh_token = creds.refresh_token

    # store new tokens
    await save_calendar_tokens(
        user_login,
        access_token=creds.token,
        refresh_token=refresh_token,
        expires_at=creds.expiry.isoformat(),
    )

    # redirect back into your app
    return RedirectResponse(f"{settings.FRONTEND_DEEP_LINK}?connected=true")


@router.get("/events", summary="Pobierz nadchodzące wydarzenia")
async def list_events(
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user),
):
    tokens = await get_calendar_tokens(user_login)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz nie połączony")

    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=tokens["expires_at"],
    )

    now_iso = datetime.datetime.utcnow().isoformat() + "Z"
    events = (
        build("calendar", "v3", credentials=creds)
        .events()
        .list(
            calendarId="primary",
            timeMin=now_iso,
            maxResults=20,
            singleEvents=True,
            orderBy="startTime",
        )
        .execute()
        .get("items", [])
    )
    return events

@router.get("/status", summary="Sprawdź, czy kalendarz Google jest połączony")
async def calendar_status(
    user_login: str = Depends(get_current_user),
):
    """
    Zwraca {"connected": true} jeśli mamy tokeny dla tego użytkownika,
    inaczej {"connected": false}.
    """
    tok = await get_calendar_tokens(user_login)
    return {"connected": bool(tok)}

@router.post("/disconnect", summary="Rozłącz konto Google Calendar")
async def disconnect_calendar(
    user_login: str = Depends(get_current_user)
):
    # sprawdź, czy faktycznie było połączenie
    existing = await get_calendar_tokens(user_login)
    if not existing:
        return JSONResponse(
            {"detail": "Brak połączenia z kalendarzem"},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    # usuń tokeny
    await delete_calendar_tokens(user_login)
    return JSONResponse({"disconnected": True})
