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
)

router = APIRouter(prefix="/calendar", tags=["Calendar"])

def create_flow(settings):
    conf = {
        "web": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [f"{settings.BACKEND_URL}/calendar/oauth2callback"],
        }
    }
    flow = Flow.from_client_config(conf, scopes=["https://www.googleapis.com/auth/calendar.events"])
    flow.redirect_uri = f"{settings.BACKEND_URL}/calendar/oauth2callback"
    return flow

@router.get("/auth-url", summary="Wygeneruj URL do Google OAuth2")
async def get_auth_url(
    settings = Depends(get_settings),
    user_login: str = Depends(get_current_user)
):
    flow = create_flow(settings)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    await save_oauth_state(user_login, state)
    return JSONResponse({"url": auth_url})

@router.get("/oauth2callback", summary="Callback OAuth2 z Google")
async def oauth2callback(
    code: str = Query(...),
    state: str = Query(...),
    settings = Depends(get_settings),
):
    # nie ma tu już Depends(get_current_user) — rozpoznajemy user_login po state
    user_login = await get_user_login_by_state(state)
    if not user_login:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    flow = create_flow(settings)
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {e}")

    creds = flow.credentials
    # gdy brak refresh_token, próbujemy wziąć stary
    if not creds.refresh_token:
        old = await get_calendar_tokens(user_login)
        if old and old["refresh_token"]:
            refresh_token = old["refresh_token"]
        else:
            raise HTTPException(400, "Brak refresh_token. Powtórz consent.")
    else:
        refresh_token = creds.refresh_token

    await save_calendar_tokens(
        user_login,
        access_token=creds.token,
        refresh_token=refresh_token,
        expires_at=creds.expiry.isoformat()
    )

    return RedirectResponse(f"{settings.FRONTEND_DEEP_LINK}?connected=true")

@router.get("/events", summary="Pobierz nadchodzące wydarzenia")
async def list_events(
    settings = Depends(get_settings),
    user_login: str = Depends(get_current_user)
):
    tok = await get_calendar_tokens(user_login)
    if not tok:
        raise HTTPException(404, "Kalendarz nie połączony")
    creds = Credentials(
        token=tok["access_token"],
        refresh_token=tok["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=tok["expires_at"],
    )
    now = datetime.datetime.utcnow().isoformat() + "Z"
    items = build("calendar", "v3", credentials=creds) \
        .events().list(calendarId="primary", timeMin=now,
                       maxResults=20, singleEvents=True,
                       orderBy="startTime").execute() \
        .get("items", [])
    return items
