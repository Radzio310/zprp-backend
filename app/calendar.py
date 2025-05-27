from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, RedirectResponse
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import datetime

from app.deps import get_settings, get_current_user  # get_current_user zwraca login użytkownika (str)
from app.calendar_storage import (
    save_calendar_tokens,
    get_calendar_tokens,
    save_oauth_state,
    get_oauth_state,
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
        scopes=["https://www.googleapis.com/auth/calendar.events"]
    )
    flow.redirect_uri = f"{settings.BACKEND_URL}/calendar/oauth2callback"
    return flow

@router.get("/auth-url", summary="Wygeneruj URL do Google OAuth2")
async def get_auth_url(
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user)
):
    flow = create_flow(settings)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    # Zapisz stan CSRF w DB
    await save_oauth_state(user_login, state)
    return JSONResponse({"url": auth_url})

@router.get("/oauth2callback", summary="Callback OAuth2 z Google")
async def oauth2callback(
    code: str = Query(...),
    state: str = Query(None),
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user)
):
    # Weryfikacja state (CSRF)
    saved_state = await get_oauth_state(user_login)
    if not saved_state or state != saved_state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    flow = create_flow(settings)
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth2 token exchange failed: {e}")

    creds = flow.credentials
    # Refresh token fallback
    if not creds.refresh_token:
        existing = await get_calendar_tokens(user_login)
        if existing and existing["refresh_token"]:
            refresh_token = existing["refresh_token"]
        else:
            raise HTTPException(
                status_code=400,
                detail="Brak refresh_token. Usuń istniejące połączenie i spróbuj ponownie."
            )
    else:
        refresh_token = creds.refresh_token

    # Zapis tokenów w DB
    await save_calendar_tokens(
        user_login,
        access_token=creds.token,
        refresh_token=refresh_token,
        expires_at=creds.expiry.isoformat()
    )

    # Przekierowanie do aplikacji mobilnej przez deep link
    return RedirectResponse(f"{settings.FRONTEND_DEEP_LINK}?connected=true")

@router.get("/events", summary="Pobierz nadchodzące wydarzenia")
async def list_events(
    settings=Depends(get_settings),
    user_login: str = Depends(get_current_user)
):
    row = await get_calendar_tokens(user_login)
    if not row:
        raise HTTPException(status_code=404, detail="Kalendarz Google nie jest połączony")

    creds = Credentials(
        token=row["access_token"],
        refresh_token=row["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=row["expires_at"],
    )
    service = build("calendar", "v3", credentials=creds)
    now_iso = datetime.datetime.utcnow().isoformat() + "Z"
    resp = service.events().list(
        calendarId="primary",
        timeMin=now_iso,
        maxResults=20,
        singleEvents=True,
        orderBy="startTime",
    ).execute()
    return resp.get("items", [])