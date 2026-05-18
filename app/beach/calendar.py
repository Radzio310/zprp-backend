from __future__ import annotations

import datetime
import json
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
BEACH_CALENDAR_TIME_ZONE = "Europe/Warsaw"


def _date_key(value: Any) -> str:
    return str(value or "")[:10]


def _add_days(date_value: str, days: int) -> str:
    base = datetime.date.fromisoformat(date_value)
    return (base + datetime.timedelta(days=days)).isoformat()


def _parse_hhmm(value: Any) -> int | None:
    if not isinstance(value, str) or ":" not in value:
        return None
    try:
        h, m = value.strip().split(":", 1)
        hour = int(h)
        minute = int(m)
    except Exception:
        return None
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return None
    return hour * 60 + minute


def _datetime_iso(date_value: str, minutes: int) -> str:
    return f"{date_value}T{minutes // 60:02d}:{minutes % 60:02d}:00"


def _schedule_window(tournament: dict[str, Any], data: dict[str, Any]) -> tuple[str, str] | None:
    schedule = data.get("schedule")
    if not isinstance(schedule, dict):
        return None
    matches = schedule.get("matches") or []
    config = schedule.get("config") or {}
    days = config.get("days") or []
    slot_interval = int(config.get("slotInterval") or 40)
    start_date = _date_key(tournament.get("event_date"))
    slots: list[tuple[str, int, int]] = []
    for match in matches:
        if not isinstance(match, dict) or match.get("kind") in ("court_break", "tournament_opening"):
            continue
        start_min = _parse_hhmm(match.get("startTime"))
        if start_min is None:
            continue
        day_index = int(match.get("dayIndex") or 0)
        date_value = None
        if day_index < len(days) and isinstance(days[day_index], dict):
            date_value = days[day_index].get("date")
        if not date_value and start_date:
            date_value = _add_days(start_date, day_index)
        if date_value:
            slots.append((_date_key(date_value), start_min, start_min + slot_interval))
    if not slots:
        return None
    slots.sort(key=lambda item: (item[0], item[1]))
    first = slots[0]
    last = max(slots, key=lambda item: (item[0], item[2]))
    return _datetime_iso(first[0], first[1]), _datetime_iso(last[0], last[2])


def _beach_tournament_payload(tournament: dict[str, Any]) -> BeachCalendarEventUpsert:
    data = tournament.get("data_json") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    start_date = _date_key(tournament.get("event_date"))
    end_date = _date_key(tournament.get("end_date") or tournament.get("event_date"))
    location = str(tournament.get("location") or "").split("|", 1)[0].strip()
    description = "\n".join(
        line
        for line in [
            f"Kategoria: {tournament.get('category')}" if tournament.get("category") else "",
            f"Typ rozgrywek: {tournament.get('competition_type')}" if tournament.get("competition_type") else "",
            f"Termin: {start_date}" + (f" - {end_date}" if end_date and end_date != start_date else ""),
            "",
            "Utworzone przez BAZA Beach",
        ]
        if line is not None
    )
    window = _schedule_window(tournament, data if isinstance(data, dict) else {})
    if window:
        return BeachCalendarEventUpsert(
            matchId=f"beach-tournament:{tournament['id']}",
            summary=f"BAZA Beach: {tournament.get('name') or 'Turniej'}",
            location=location,
            description=description,
            start=BeachCalendarDateTime(dateTime=window[0], timeZone=BEACH_CALENDAR_TIME_ZONE),
            end=BeachCalendarDateTime(dateTime=window[1], timeZone=BEACH_CALENDAR_TIME_ZONE),
            allDay=False,
            reminders=[
                BeachCalendarReminder(method="popup", minutes=24 * 60),
                BeachCalendarReminder(method="popup", minutes=120),
            ],
            colorId="6",
        )
    return BeachCalendarEventUpsert(
        matchId=f"beach-tournament:{tournament['id']}",
        summary=f"BAZA Beach: {tournament.get('name') or 'Turniej'}",
        location=location,
        description=description,
        start=BeachCalendarDateTime(date=start_date),
        end=BeachCalendarDateTime(date=_add_days(end_date, 1)),
        allDay=True,
        reminders=[BeachCalendarReminder(method="popup", minutes=24 * 60)],
        colorId="6",
    )


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
        autogenerate_code_verifier=False,
    )
    flow.code_verifier = None
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
        payload["timeZone"] = value.timeZone or BEACH_CALENDAR_TIME_ZONE
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


async def sync_beach_tournament_google_for_users(
    tournament: dict[str, Any],
    user_ids: list[int],
    settings: Any,
) -> None:
    """Best-effort server sync for Google Calendar users involved in a Beach tournament."""
    if not user_ids:
        return
    payload = _beach_tournament_payload(tournament)
    body = _event_body(payload)
    match_id = payload.matchId
    for user_id in sorted({int(uid) for uid in user_ids if uid is not None}):
        user_key = _beach_calendar_user_key(user_id)
        if not await get_calendar_tokens(user_key):
            continue
        try:
            service = await _google_service(user_key, settings)
            mapping = await get_event_mapping(user_key, match_id)
            event_id = mapping["event_id"] if mapping else None
            if event_id:
                try:
                    event = (
                        service.events()
                        .update(calendarId="primary", eventId=event_id, body=body)
                        .execute()
                    )
                except Exception:
                    await delete_event_mapping(user_key, match_id)
                    event = (
                        service.events()
                        .insert(calendarId="primary", body=body)
                        .execute()
                    )
            else:
                event = service.events().insert(calendarId="primary", body=body).execute()
            await save_event_mapping(user_key, match_id, event["id"])
        except Exception:
            logger.exception(
                "Failed to sync Beach tournament %s to Google Calendar for user %s",
                tournament.get("id"),
                user_id,
            )


async def delete_beach_tournament_google_for_users(
    tournament_id: int,
    user_ids: list[int],
    settings: Any,
) -> None:
    if not user_ids:
        return
    match_id = f"beach-tournament:{int(tournament_id)}"
    for user_id in sorted({int(uid) for uid in user_ids if uid is not None}):
        user_key = _beach_calendar_user_key(user_id)
        if not await get_calendar_tokens(user_key):
            continue
        try:
            mapping = await get_event_mapping(user_key, match_id)
            if not mapping:
                continue
            service = await _google_service(user_key, settings)
            try:
                service.events().delete(
                    calendarId="primary",
                    eventId=mapping["event_id"],
                ).execute()
            finally:
                await delete_event_mapping(user_key, match_id)
        except Exception:
            logger.exception(
                "Failed to delete Beach tournament %s from Google Calendar for user %s",
                tournament_id,
                user_id,
            )


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
