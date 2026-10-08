"""
SMS z wynikiem meczu - trasy (08.10.2026).

  - GET  /sms-config                  - cała konfiguracja (aplikacja wczytuje ją
                                        przy starcie razem z resztą ustawień),
  - POST /sms-config/match-provinces  - okręg PROWADZĄCY mecze sędziego (żeby
                                        w hali, bez sieci, wiedzieć, do kogo SMS),
  - PUT  /admin/sms-config            - zapis całości z panelu admina.

Reguła w `app/sms_config_rules.py`. Numery to numery związków z ustaleń
rozgrywek, nie dane osobowe - odczyt jest publiczny jak lista modułów okręgów.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import sms_config_rules as S
from app.db import database, match_province_cache, sms_config
from app.extra_report_scope import fetch_match_province
from app.proel_admin_guard import proel_admin_guard
from app.proel_auth import Actor, is_admin, proel_actor
from app.zprp_accounts import normalize_province

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sms-config", tags=["SMS z wynikiem"])
admin_router = APIRouter(
    prefix="/admin/sms-config",
    tags=["SMS z wynikiem: admin"],
    dependencies=[Depends(proel_admin_guard)],
)

#: Ile meczów jedno zapytanie może dopytać w API rozgrywek (reszta - następnym razem).
LOOKUP_LIMIT = 40
LOOKUP_PARALLEL = 6
#: Pusty wynik (API milczało albo mecz centralny) sprawdzamy ponownie po dobie.
EMPTY_RETRY = timedelta(hours=24)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_scope(row: Any) -> dict:
    try:
        groups = json.loads(row["groups_json"] or "[]")
    except (TypeError, ValueError):
        groups = []
    return {
        "enabled": bool(row["enabled"]),
        "template": row["template"] or S.TEMPLATE_CENTRAL,
        "groups": [g for g in groups if isinstance(g, dict)],
        "updated_by": row["updated_by"],
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


async def load_config() -> dict:
    """Centralne + każdy okręg z zapisem albo z wartością domyślną."""
    rows = {r["scope"]: r for r in await database.fetch_all(select(sms_config))}
    central = _row_scope(rows[S.CENTRAL]) if S.CENTRAL in rows else S.default_scope(S.CENTRAL)
    provinces = []
    scopes = sorted({*rows.keys(), *S.DEFAULTS.keys()} - {S.CENTRAL})
    for scope in scopes:
        item = _row_scope(rows[scope]) if scope in rows else S.default_scope(scope)
        provinces.append({"province": scope, **item})
    stamps = [r["updated_at"] for r in rows.values() if r["updated_at"]]
    return {
        "central": central,
        "provinces": provinces,
        "updated_at": max(stamps).isoformat() if stamps else None,
    }


@router.get("", summary="Konfiguracja SMS z wynikiem - centralne i okręgi")
async def get_config():
    return await load_config()


class MatchProvincesBody(BaseModel):
    match_ids: list[str] = Field(default_factory=list, max_length=400)


@router.post("/match-provinces", summary="Okręg prowadzący mecze (do SMS w hali bez sieci)")
async def match_provinces(body: MatchProvincesBody):
    """
    Okręg PROWADZĄCY każdy mecz (`NazwaWZPR` z publicznego API rozgrywek).

    Telefon pyta o swoje nadchodzące mecze przy starcie aplikacji i zapisuje
    odpowiedź - w hali, często bez zasięgu, wie już, czy i dokąd idzie SMS.
    Ustalony okręg trzymamy na stałe (numer meczu nie zmienia związku);
    pusty wynik sprawdzamy ponownie po dobie.
    """
    ids = []
    for raw in body.match_ids:
        mid = str(raw or "").strip()
        if mid.isdigit() and mid not in ids:
            ids.append(mid)
    if not ids:
        return {"provinces": {}, "pending": 0}

    rows = await database.fetch_all(
        select(match_province_cache).where(match_province_cache.c.match_id.in_(ids))
    )
    known: dict[str, str] = {}
    stale: set[str] = set()
    now = _now()
    for row in rows:
        known[row["match_id"]] = row["province"] or ""
        if not row["province"] and (row["checked_at"] is None or now - row["checked_at"] > EMPTY_RETRY):
            stale.add(row["match_id"])
    missing = [mid for mid in ids if mid not in known or mid in stale][:LOOKUP_LIMIT]

    gate = asyncio.Semaphore(LOOKUP_PARALLEL)

    async def lookup(mid: str) -> tuple[str, str]:
        async with gate:
            return mid, await fetch_match_province(mid, timeout=8.0)

    for mid, province in await asyncio.gather(*(lookup(mid) for mid in missing)):
        known[mid] = province
        await database.execute(
            pg_insert(match_province_cache)
            .values(match_id=mid, province=province, checked_at=now)
            .on_conflict_do_update(
                index_elements=[match_province_cache.c.match_id],
                set_={"province": province, "checked_at": now},
            )
        )
    pending = len([mid for mid in ids if mid not in known])
    return {"provinces": {mid: known.get(mid, "") for mid in ids if mid in known}, "pending": pending}


class ScopeIn(BaseModel):
    enabled: bool = False
    template: str = S.TEMPLATE_CENTRAL
    groups: list[dict] = Field(default_factory=list)


class ProvinceScopeIn(ScopeIn):
    province: str


class ConfigIn(BaseModel):
    central: ScopeIn
    provinces: list[ProvinceScopeIn] = Field(default_factory=list)


@admin_router.put("", summary="Zapis konfiguracji SMS (całość)")
async def save_config(body: ConfigIn, actor: Actor = Depends(proel_actor)):
    """
    Podmienia całość - jak adresaci dodatkowego raportu. Okręg pominięty
    w zapisie traci swój wiersz i wraca do wartości domyślnej (dla większości
    okręgów: wyłączony).
    """
    if not await is_admin(actor.judge_id or ""):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Konfigurację SMS zmienia wyłącznie administrator.")
    prepared: dict[str, dict] = {}
    try:
        prepared[S.CENTRAL] = S.clean_scope(body.central.model_dump(), label="Mecze centralne")
        for item in body.provinces:
            scope = normalize_province(item.province)
            if not scope or scope in prepared:
                continue
            prepared[scope] = S.clean_scope(item.model_dump(), label=scope)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    now = _now()
    who = str(actor.judge_id or "")
    async with database.transaction():
        await database.execute(sms_config.delete())
        for scope, item in prepared.items():
            await database.execute(
                sms_config.insert().values(
                    scope=scope,
                    enabled=item["enabled"],
                    template=item["template"],
                    groups_json=json.dumps(item["groups"], ensure_ascii=False),
                    updated_by=who,
                    updated_at=now,
                )
            )
    return await load_config()
