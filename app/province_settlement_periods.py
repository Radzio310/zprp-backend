"""Konfigurowalne okresy wypłat sędziowskich per okręg i sezon."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_cache as SC
from app.db import database, province_settlement_period_settings as T
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate
from app.province_settlements import require_province
from app.settlement_province import display

router = APIRouter(prefix="/province/settlements/periods", tags=["province_settlements"])

KINDS = {"regular", "extra", "moved"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")

SILESIA_2026 = [
    ("sl-2026-10-05", "2026/2027", "2026-09-07", "2026-10-04", "2026-10-05", "regular"),
    ("sl-2026-11-02", "2026/2027", "2026-10-05", "2026-11-01", "2026-11-02", "regular"),
    ("sl-2026-12-07", "2026/2027", "2026-11-02", "2026-12-06", "2026-12-07", "regular"),
    ("sl-2026-12-29", "2026/2027", "2026-12-07", "2026-12-29", "2026-12-29", "extra"),
    ("sl-2027-02-01", "2026/2027", "2027-01-01", "2027-01-31", "2027-02-01", "regular"),
    ("sl-2027-03-01", "2026/2027", "2027-02-01", "2027-02-28", "2027-03-01", "regular"),
    ("sl-2027-04-05", "2026/2027", "2027-03-01", "2027-04-04", "2027-04-05", "regular"),
    ("sl-2027-05-04", "2026/2027", "2027-04-05", "2027-05-03", "2027-05-04", "moved"),
    ("sl-2027-06-07", "2026/2027", "2027-05-04", "2027-06-06", "2027-06-07", "regular"),
    ("sl-2027-07-05", "2026/2027", "2027-06-07", "2027-07-04", "2027-07-05", "regular"),
]


def _default_periods(key: str) -> list[dict]:
    if key != "SLASKIE":
        return []
    return [
        {
            "id": period_id,
            "season": season,
            "date_from": date_from,
            "date_to": date_to,
            "payout_date": payout,
            "kind": kind,
            "label": "",
            "enabled": True,
        }
        for period_id, season, date_from, date_to, payout, kind in SILESIA_2026
    ]


class PeriodInput(BaseModel):
    id: str
    season: str
    date_from: date
    date_to: date
    payout_date: date
    kind: str = "regular"
    label: str = ""
    enabled: bool = True


class PeriodsRequest(BaseModel):
    province: str
    periods: list[PeriodInput]
    updated_by: Optional[str] = None


def _clean(items: list[PeriodInput]) -> list[dict]:
    if len(items) > 80:
        raise HTTPException(400, "Jeden okręg może mieć najwyżej 80 okresów.")
    out: list[dict] = []
    seen: set[str] = set()
    for item in items:
        period_id = item.id.strip().lower()
        if not ID_RE.fullmatch(period_id) or period_id in seen:
            raise HTTPException(400, f"Niepoprawny albo powtórzony identyfikator okresu: {item.id}")
        if item.date_from > item.date_to:
            raise HTTPException(400, "Początek okresu nie może wypadać po jego końcu.")
        if (item.date_to - item.date_from).days > 92:
            raise HTTPException(400, "Okres rozliczeniowy nie może być dłuższy niż 93 dni.")
        if item.kind not in KINDS:
            raise HTTPException(400, "Rodzaj okresu musi być: regular, extra albo moved.")
        seen.add(period_id)
        out.append(
            {
                "id": period_id,
                "season": item.season.strip(),
                "date_from": item.date_from.isoformat(),
                "date_to": item.date_to.isoformat(),
                "payout_date": item.payout_date.isoformat(),
                "kind": item.kind,
                "label": item.label.strip()[:100],
                "enabled": bool(item.enabled),
            }
        )
    enabled = sorted((x for x in out if x["enabled"]), key=lambda x: (x["date_from"], x["date_to"]))
    for previous, current in zip(enabled, enabled[1:]):
        if current["date_from"] <= previous["date_to"]:
            raise HTTPException(400, "Aktywne okresy nie mogą na siebie nachodzić.")
    return sorted(out, key=lambda x: (x["date_from"], x["payout_date"], x["id"]))


async def periods_for(province: str) -> tuple[list[dict], bool]:
    key = require_province(province)
    row = await database.fetch_one(select(T).where(T.c.province == key))
    if row:
        raw = row["periods_json"] or []
        return ([dict(item) for item in raw if isinstance(item, dict)], True)
    return (_default_periods(key), False)


async def resolve_period(province: str, period_id: str) -> dict:
    periods, _saved = await periods_for(province)
    hit = next((item for item in periods if item.get("id") == period_id and item.get("enabled", True)), None)
    if not hit:
        raise HTTPException(404, "Nie znaleziono aktywnego okresu rozliczeniowego.")
    return hit


def _payload(key: str, periods: list[dict], saved: bool, updated_at=None) -> dict:
    return {
        "province": key,
        "display": display(key),
        "saved": saved,
        "mode": "periods" if periods else "months",
        "periods": periods,
        "updated_at": updated_at.isoformat() if updated_at else None,
    }


@router.get("", summary="Okresy rozliczeń sędziowskich okręgu")
async def get_periods(province: str = Query(...)):
    key = require_province(province)
    row = await database.fetch_one(select(T).where(T.c.province == key))
    periods = [dict(item) for item in (row["periods_json"] or []) if isinstance(item, dict)] if row else _default_periods(key)
    return _payload(key, periods, bool(row), row["updated_at"] if row else None)


@router.put("", summary="Zapisz okresy rozliczeń sędziowskich okręgu")
async def put_periods(
    body: PeriodsRequest,
    _access=Depends(panel_write_gate(PANEL_SETTLEMENTS, "Okresy rozliczeniowe")),
):
    key = require_province(body.province)
    periods = _clean(body.periods)
    now = datetime.now(timezone.utc)
    await database.execute(
        pg_insert(T)
        .values(province=key, periods_json=periods, updated_by=body.updated_by, updated_at=now)
        .on_conflict_do_update(
            index_elements=[T.c.province],
            set_={"periods_json": periods, "updated_by": body.updated_by, "updated_at": now},
        )
    )
    SC.bump(key, base=False, reason="okresy rozliczeniowe")
    return _payload(key, periods, True, now)
