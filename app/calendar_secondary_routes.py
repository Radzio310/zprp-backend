"""Trasy kalendarzy drugorzędnych: /calendar/setup i /calendar/migrate.

Router nie importuje `app.db` ani bibliotek Google (składanie zależności
dopiero w `get_secondary_deps`), więc testuje się go na atrapie Google.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from app.calendar_secondary_engine import (
    put_setup,
    run_job,
    setup_view,
    start_migration,
)
from app.calendar_secondary_rules import SecondaryError
from app.deps import get_current_user, get_settings

router = APIRouter(prefix="/calendar", tags=["Calendar"])


def get_secondary_deps(settings=Depends(get_settings)):
    from app.calendar_secondary_google import build_deps  # noqa: PLC0415

    return build_deps(settings)


def http_error(exc: SecondaryError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.detail())


class SetupPatch(BaseModel):
    mode: Optional[str] = None
    colors: Optional[dict] = None
    busy: Optional[bool] = None
    # Kalendarze, które aplikacja już uzupełniła po odtworzeniu (zdejmuje `missing`).
    refilled: Optional[list[str]] = None


@router.get("/setup", summary="Stan kalendarzy BAZY w Google")
async def get_setup(
    deps=Depends(get_secondary_deps),
    user_login: str = Depends(get_current_user),
):
    try:
        return await setup_view(deps, user_login)
    except SecondaryError as exc:
        raise http_error(exc) from exc


@router.put("/setup", summary="Układ, kolory i zajętość kalendarzy BAZY")
async def put_setup_route(
    patch: SetupPatch,
    background: BackgroundTasks,
    deps=Depends(get_secondary_deps),
    user_login: str = Depends(get_current_user),
):
    try:
        view, warnings, start = await put_setup(deps, user_login, patch.model_dump())
    except SecondaryError as exc:
        raise http_error(exc) from exc
    if start:
        background.add_task(run_job, deps, user_login)
    return {**view, "warnings": warnings}


@router.post("/migrate", summary="Start albo wznowienie przenoszenia meczów")
async def migrate(
    background: BackgroundTasks,
    deps=Depends(get_secondary_deps),
    user_login: str = Depends(get_current_user),
):
    try:
        job, start = await start_migration(deps, user_login)
    except SecondaryError as exc:
        raise http_error(exc) from exc
    if start:
        background.add_task(run_job, deps, user_login)
    return {"job": job, "started": start}
