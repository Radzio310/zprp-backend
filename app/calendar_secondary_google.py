"""Kalendarze drugorzędne Google: klient API (port `api` silnika) i składanie `Deps`.

Biblioteki Google i `app.db` są importowane dopiero w funkcjach, żeby moduł
dał się zaimportować w testach bez nich.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from typing import Any, Awaitable, Callable

from app.calendar_secondary_rules import GoogleError

logger = logging.getLogger(__name__)


def _wrap(call: Callable[[], Any]) -> Callable[[], Any]:
    def run():
        from googleapiclient.errors import HttpError  # noqa: PLC0415

        try:
            return call()
        except HttpError as exc:
            status = getattr(getattr(exc, "resp", None), "status", 500)
            raise GoogleError(int(status)) from exc

    return run


class GoogleCalendarApi:
    """Cienka warstwa nad `googleapiclient`; wywołania synchroniczne idą do wątku."""

    def __init__(self, service: Any):
        self._service = service

    async def _call(self, call: Callable[[], Any]) -> Any:
        return await asyncio.to_thread(_wrap(call))

    async def get_calendar(self, calendar_id: str) -> dict:
        return await self._call(
            lambda: self._service.calendars().get(calendarId=calendar_id).execute()
        )

    async def insert_calendar(self, body: dict) -> dict:
        return await self._call(lambda: self._service.calendars().insert(body=body).execute())

    async def delete_calendar(self, calendar_id: str) -> None:
        await self._call(
            lambda: self._service.calendars().delete(calendarId=calendar_id).execute()
        )

    async def patch_calendar_list(self, calendar_id: str, body: dict) -> dict:
        return await self._call(
            lambda: self._service.calendarList()
            .patch(calendarId=calendar_id, body=body, colorRgbFormat=True)
            .execute()
        )

    async def get_event(self, calendar_id: str, event_id: str) -> dict:
        return await self._call(
            lambda: self._service.events().get(calendarId=calendar_id, eventId=event_id).execute()
        )

    async def insert_event(self, calendar_id: str, body: dict) -> dict:
        return await self._call(
            lambda: self._service.events().insert(calendarId=calendar_id, body=body).execute()
        )

    async def update_event(self, calendar_id: str, event_id: str, body: dict) -> dict:
        return await self._call(
            lambda: self._service.events()
            .update(calendarId=calendar_id, eventId=event_id, body=body)
            .execute()
        )

    async def delete_event(self, calendar_id: str, event_id: str) -> None:
        await self._call(
            lambda: self._service.events().delete(calendarId=calendar_id, eventId=event_id).execute()
        )

    async def list_events(
        self, calendar_id: str, max_results: int = 1, time_min: str | None = None
    ) -> list[dict]:
        """Z `time_min` zwraca wszystkie wydarzenia od tej chwili (strony po 250, do 20 stron)."""
        if time_min is None:
            data = await self._call(
                lambda: self._service.events()
                .list(calendarId=calendar_id, maxResults=max_results, singleEvents=True)
                .execute()
            )
            return list(data.get("items", []))
        items: list[dict] = []
        token = None
        for _ in range(20):
            kwargs = dict(
                calendarId=calendar_id, timeMin=time_min, singleEvents=True, maxResults=250
            )
            if token:
                kwargs["pageToken"] = token
            data = await self._call(lambda: self._service.events().list(**kwargs).execute())
            items.extend(data.get("items", []))
            token = data.get("nextPageToken")
            if not token:
                break
        return items


async def _api_from_tokens(
    settings: Any,
    access: str,
    refresh: str,
    expires_at: str,
    persist: Callable[[str, str, str], Awaitable[None]],
) -> GoogleCalendarApi:
    from google.auth.transport.requests import Request  # noqa: PLC0415
    from google.oauth2.credentials import Credentials  # noqa: PLC0415
    from googleapiclient.discovery import build  # noqa: PLC0415

    creds = Credentials(
        token=access,
        refresh_token=refresh,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        expiry=datetime.datetime.fromisoformat(expires_at),
    )
    if creds.expired and creds.refresh_token:
        try:
            await asyncio.to_thread(creds.refresh, Request())
        except Exception as exc:  # noqa: BLE001
            # 503 = chwilowo (RefreshError retryable, TransportError), 401 = zgoda odrzucona.
            transient = bool(getattr(exc, "retryable", False)) or type(exc).__name__ == "TransportError"
            raise GoogleError(503 if transient else 401, "Nie udało się odświeżyć dostępu do Google.") from exc
        await persist(creds.token, creds.refresh_token, creds.expiry.isoformat())
    return GoogleCalendarApi(build("calendar", "v3", credentials=creds, cache_discovery=False))


def build_deps(settings: Any):
    """`Deps` dla tras: baza i Google z prawdziwych implementacji."""
    from app.calendar_refresh_errors import (  # noqa: PLC0415
        RECONNECT_CODE,
        RECONNECT_MESSAGE,
        UNAVAILABLE_CODE,
        UNAVAILABLE_MESSAGE,
    )
    from app.calendar_secondary_engine import Deps  # noqa: PLC0415
    from app.calendar_secondary_rules import SecondaryError, flag_enabled  # noqa: PLC0415
    from app.calendar_secondary_store import SecondaryStore  # noqa: PLC0415

    store = SecondaryStore()

    async def api_current(user: str):
        tokens = await store.get_tokens(user)
        if not tokens:
            raise SecondaryError(404, "calendar_not_connected", "Kalendarz nie połączony")

        async def persist(access: str, refresh: str, expires_at: str) -> None:
            await store.save_tokens(user, access, refresh, expires_at, tokens.get("scope"))

        try:
            return await _api_from_tokens(
                settings, tokens["access_token"], tokens["refresh_token"], tokens["expires_at"], persist
            )
        except GoogleError as exc:
            # Te same kody co globalny handler (app/calendar_refresh_errors.py).
            if exc.status == 503:
                raise SecondaryError(503, UNAVAILABLE_CODE, UNAVAILABLE_MESSAGE) from exc
            raise SecondaryError(403, RECONNECT_CODE, RECONNECT_MESSAGE) from exc

    async def api_parked(user: str):
        setup = await store.get_setup(user)
        if not setup or not setup.get("park_access"):
            return None

        async def persist(access: str, refresh: str, expires_at: str) -> None:
            await store.park_tokens(
                user, access=access, refresh=refresh, expires_at=expires_at, scope=setup.get("park_scope")
            )

        try:
            return await _api_from_tokens(
                settings, setup["park_access"], setup["park_refresh"], setup["park_expires"], persist
            )
        except Exception as exc:  # noqa: BLE001 - zaparkowany token mógł zostać cofnięty
            logger.info("Zaparkowany token nieużyteczny: %s", type(exc).__name__)
            return None  # kontrolowany brak dostępu, wołający pokaże komunikat

    return Deps(
        store=store,
        flag=flag_enabled(settings),
        api_current=api_current,
        api_parked=api_parked,
    )
