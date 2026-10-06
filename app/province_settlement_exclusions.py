"""
Zdejmowanie meczu z rozliczeń z poziomu Rozliczeń - „Nie naliczaj",
„Przywróć" i „Zostaw" przy podpowiedzi (06.10.2026).

Reguła podpowiedzi w liściu `settlement_exclusion_rules`. Zdjęcie działa jak
„Nie obciążaj klubów" w Panelu klubów - ten sam wiersz w
`province_match_overrides` (`excluded`), więc mecz wypada CAŁY: wszystkim
sędziom i z obciążeń klubów (decyzja użytkownika). Tutaj zmieniamy wyłącznie
`excluded` i `kept` - przeniesienie na inną drużynę i potrójny ryczałt zostają.

Zapisy przez bramkę panelu Rozliczeń (`province_panel_guard`).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_cache as SC
from app import settlement_exclusion_rules as X
from app.db import database, province_match_overrides, province_settlement_matches
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/exclusions",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Zdjęcie meczu z rozliczeń"))],
)

OV = province_match_overrides


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def exclusion_hints(province: str) -> dict:
    """
    Z czego podpowiadać zdjęcie: rozgrywki innych okręgów, z których mecze
    zdjęto ({klucz: ile}), mecze z decyzją „Zostaw" i nasze przedrostki.
    """
    from app.province_settlement_sync import _own_prefixes

    try:
        rows = await database.fetch_all(
            select(OV.c.match_key, OV.c.excluded, OV.c.kept).where(OV.c.province == province)
        )
    except Exception as exc:  # pragma: no cover - kolumna `kept` przed migracją
        logger.warning("[exclusions] %s: odczyt wyjątków: %s", province, exc)
        return {"competitions": {}, "kept": set(), "own": set()}
    excluded = {_s(r["match_key"]) for r in rows if r["excluded"]}
    kept = {_s(r["match_key"]) for r in rows if r["kept"] and not r["excluded"]}
    if not excluded:
        return {"competitions": {}, "kept": kept, "own": set()}
    ids = {key.split(":", 1)[-1] for key in excluded}
    code_rows = await database.fetch_all(
        select(province_settlement_matches.c.match_key, province_settlement_matches.c.match_code).where(
            province_settlement_matches.c.province == province
        )
    )
    codes: dict[str, str] = {}
    for row in code_rows:
        match_id = _s(row["match_key"]).split(":", 1)[-1]
        if match_id in ids and row["match_code"]:
            codes.setdefault(match_id, _s(row["match_code"]))
    own = await _own_prefixes(province)
    return {
        "competitions": X.excluded_competitions(codes.values(), own),
        "kept": kept,
        "own": own,
    }


def apply_hints(entries: list, hints: dict) -> None:
    """Podpowiedź przy meczach rozliczenia - mecz zostaje, dostaje tylko zdanie."""
    competitions = hints.get("competitions") or {}
    if not competitions:
        return
    kept = hints.get("kept") or set()
    own = hints.get("own") or set()
    for entry in entries:
        for match in entry.matches:
            if match.match_key in kept:
                continue
            match.exclude_hint = X.hint(match.match_code, competitions, own)


class ExclusionBody(BaseModel):
    province: str
    match_key: str
    #: exclude = „Nie naliczaj" (cały mecz), restore = „Przywróć",
    #: keep = „Zostaw" przy podpowiedzi.
    action: Literal["exclude", "restore", "keep"]
    user: Optional[str] = None


@router.put("", summary="Nie naliczaj / Przywróć / Zostaw mecz w rozliczeniu")
async def set_exclusion(body: ExclusionBody):
    from app.province_settlements import require_province

    key = require_province(body.province)
    match_key = _s(body.match_key)
    if not match_key:
        raise HTTPException(400, "Brak meczu.")
    if body.action == "exclude":
        values = {"excluded": True, "kept": False, "note": "Nie naliczaj (Rozliczenia)"}
        message = "Mecz zdjęty z rozliczenia - wszystkim sędziom i z obciążeń klubów. Cofniesz go przyciskiem „Przywróć”."
    elif body.action == "restore":
        # Przywrócony mecz to też decyzja - podpowiedź już przy nim nie wraca.
        values = {"excluded": False, "kept": True}
        message = "Mecz wrócił do rozliczenia."
    else:
        values = {"kept": True}
        message = "Mecz zostaje w rozliczeniu - podpowiedź przy nim zniknie."
    values.update(updated_by=_s(body.user) or None, updated_at=_now())
    await database.execute(
        pg_insert(OV)
        .values(province=key, match_key=match_key, **values)
        .on_conflict_do_update(index_elements=[OV.c.province, OV.c.match_key], set_=values)
    )
    SC.bump(key, base=False, reason=f"wyjątek meczu: {body.action}")
    logger.info("[exclusions] %s %s: %s (%s)", key, match_key, body.action, body.user)
    return {"ok": True, "message": message}

