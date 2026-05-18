from __future__ import annotations

import datetime
import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import JSONResponse, RedirectResponse
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from pydantic import BaseModel

from app.calendar_storage import (
    delete_calendar_tokens,
    delete_event_mapping,
    get_calendar_tokens,
    get_event_mapping,
    get_user_login_by_state,
    save_calendar_tokens,
    save_event_mapping,
    save_oauth_state,
)
from app.deps import beach_get_current_user_id, get_settings

router = APIRouter(prefix="/beach/calendar", tags=["Beach Calendar"])
logger = logging.getLogger(__name__)


def _beach_calendar_user_key(user_id: int) -> str:
    return f"beach:{int(user_id)}"


def _frontend_deep_link(settings: Any) -> str:
    return (
        os.getenv("BEACH_FRONTEND_DEEP_LINK", "").strip()
        or getattr(settings, "BEACH_FRONTEND_DEEP_LINK", None)
        or "bazabeach://more?openSettings=1&calendarConnected=1"
    )


def _create_beach_flow(settings: Any) -> Flow:
    backend_url = str(settings.BACKEND_URL).rstrip("/")
    redirect_uri = f"{backend_url}/beach/calendar/oauth2callback"
    client_config = {
        "web": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=["https://www.googleapis.com/auth/calendar.events"],
    )
    flow.redirect_uri = redirect_uri
    return flow


async def _google_service(user_key: str, settings: Any):
    tokens = await get_calendar_tokens(user_key)
    if not tokens:
        raise HTTPException(status_code=404, detail="Kalendarz Google nie jest polaczony")

    creds = Credentials(
        token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=datetime.datetime.fromisoformat(tokens["expires_at"]),
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        await save_calendar_tokens(
            user_key,
            access_token=creds.token,
            refresh_token=creds.refresh_token,
            expires_at=creds.expiry.isoformat(),
        )

    return build("calendar", "v3", credentials=creds)


class BeachCalendarReminder(BaseModel):
    method: str
    minutes: int


class BeachCalendarDateTime(BaseModel):
    date: str | None = None
    dateTime: datetime.datetime | None = None
    timeZone: str | None = None


class BeachCalendarEventUpsert(BaseModel):
    matchId: str
    summary: str
    start: BeachCalendarDateTime
    end: BeachCalendarDateTime
    location: str | None = None
    description: str | None = None
    colorId: str | None = None
    reminders: list[BeachCalendarReminder] = []


def _event_time_payload(value: BeachCalendarDateTime) -> dict[str, str]:
    if value.date:
        return {"date": value.date}
    if value.dateTime:
        payload = {"dateTime": value.dateTime.isoformat()}
        if value.timeZone:
            payload["timeZone"] = value.timeZone
        return payload
    raise HTTPException(status_code=400, detail="Brak daty wydarzenia")


def _event_body(payload: BeachCalendarEventUpsert) -> dict[str, Any]:
    body: dict[str, Any] = {
        "summary": payload.summary,
        "start": _event_time_payload(payload.start),
        "end": _event_time_payload(payload.end),
        "reminders": {
            "useDefault": False,
            "overrides": [r.model_dump() for r in payload.reminders],
        },
    }
    if payload.location:
        body["location"] = payload.location
    if payload.description:
        body["description"] = payload.description
    if payload.colorId:
        body["colorId"] = payload.colorId
    return body


@router.get("/auth-url")
async def get_auth_url(
    settings=Depends(get_settings),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    user_key = _beach_calendar_user_key(current_user_id)
    flow = _create_beach_flow(settings)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    await save_oauth_state(user_key, state)
    return JSONResponse({"url": auth_url})


@router.get("/oauth2callback")
async def oauth2callback(
    code: str = Query(...),
    state: str = Query(...),
    settings=Depends(get_settings),
):
    user_key = await get_user_login_by_state(state)
    if not user_key or not str(user_key).startswith("beach:"):
        logger.warning("Beach Google OAuth callback rejected invalid state")
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    flow = _create_beach_flow(settings)
    try:
        flow.fetch_token(code=code)
    except Exception as exc:
        logger.exception("Beach Google OAuth token exchange failed")
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {exc}")

    creds = flow.credentials
    existing = await get_calendar_tokens(user_key)
    refresh_token = creds.refresh_token or (existing["refresh_token"] if existing else None)
    if not refresh_token:
        logger.warning("Beach Google OAuth callback did not return refresh token")
        raise HTTPException(status_code=400, detail="Brak refresh token z Google")

    await save_calendar_tokens(
        user_key,
        access_token=creds.token,
        refresh_token=refresh_token,
        expires_at=creds.expiry.isoformat(),
    )
    return RedirectResponse(_frontend_deep_link(settings))


@router.get("/status")
async def calendar_status(current_user_id: int = Depends(beach_get_current_user_id)):
    user_key = _beach_calendar_user_key(current_user_id)
    return {"connected": bool(await get_calendar_tokens(user_key))}


@router.post("/disconnect")
async def disconnect_calendar(current_user_id: int = Depends(beach_get_current_user_id)):
    user_key = _beach_calendar_user_key(current_user_id)
    await delete_calendar_tokens(user_key)
    return {"disconnected": True}


@router.post("/events/upsert", status_code=status.HTTP_200_OK)
async def upsert_event(
    payload: BeachCalendarEventUpsert,
    settings=Depends(get_settings),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    user_key = _beach_calendar_user_key(current_user_id)
    service = await _google_service(user_key, settings)
    event_id = await get_event_mapping(user_key, payload.matchId)
    body = _event_body(payload)

    if event_id:
        try:
            updated = (
                service.events()
                .update(calendarId="primary", eventId=event_id, body=body)
                .execute()
            )
            await save_event_mapping(user_key, payload.matchId, updated["id"])
            return {"eventId": updated["id"], "action": "updated"}
        except Exception:
            await delete_event_mapping(user_key, payload.matchId)

    created = service.events().insert(calendarId="primary", body=body).execute()
    await save_event_mapping(user_key, payload.matchId, created["id"])
    return {"eventId": created["id"], "action": "created"}


@router.delete("/events/{match_id:path}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(
    match_id: str = Path(...),
    settings=Depends(get_settings),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    user_key = _beach_calendar_user_key(current_user_id)
    event_id = await get_event_mapping(user_key, match_id)
    if not event_id:
        return

    service = await _google_service(user_key, settings)
    try:
        service.events().delete(calendarId="primary", eventId=event_id).execute()
    except Exception:
        pass
    await delete_event_mapping(user_key, match_id)
    return
