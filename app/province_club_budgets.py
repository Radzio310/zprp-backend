"""
Wspólny budżet klubów - baza, seed i trasy /province/clubs/budgets.

Reguła scalania siedzi w liściu `province_club_budgets_rules`; tutaj tylko
czytamy i zapisujemy grupy oraz wystawiamy `season_budgets` - saldo budżetu
dla każdego, kto potrzebuje salda „klubu tak, jak widzi go okręg" (panel
klubów, alerty).

⚠ `app.db` łączy się z bazą przy imporcie, więc importy bazy siedzą
w funkcjach. `province_clubs` importuje ten moduł, a ten sięga po
`province_clubs._season_clubs` dopiero w środku funkcji - bez cyklu.

⚠ Router trzeba dołączyć PRZED routerem `/province/clubs`: tam GET
`/{club_id}` połknąłby `/budgets`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app import province_club_budgets_rules as BR
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate
from app.settlement_province import canonical

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/clubs/budgets",
    tags=["province_clubs"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Zapis w panelu klubów"))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _key(province: str) -> str:
    key = canonical(province)
    if not key:
        raise HTTPException(400, f"Nieznane województwo: {province}")
    return key


# ---------------------------------------------------------------------------
# Odczyt
# ---------------------------------------------------------------------------

async def budget_groups(province: str) -> list[dict]:
    """Budżety okręgu: [{budget_id, name, primary_club_id, member_ids, ...}]."""
    from sqlalchemy import select

    from app.db import database, province_club_budgets

    key = canonical(province) or _s(province)
    rows = await database.fetch_all(
        select(province_club_budgets)
        .where(province_club_budgets.c.province == key)
        .order_by(province_club_budgets.c.id.asc())
    )
    out: list[dict] = []
    for row in rows:
        members = BR.parse_members(row["member_ids"])
        primary = _s(row["primary_club_id"])
        if primary and primary not in members:
            members.insert(0, primary)
        out.append(
            {
                "budget_id": int(row["id"]),
                "name": _s(row["name"]) or None,
                "primary_club_id": primary,
                "member_ids": members,
                "created_by": _s(row["created_by"]) or None,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "updated_by": _s(row["updated_by"]) or None,
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
            }
        )
    return out


async def club_names(province: str, club_ids: list[str]) -> dict[str, str]:
    """Nazwy klubów poza sezonem: nazwa z panelu, a bez niej najkrótsza nazwa drużyny."""
    from sqlalchemy import and_, select

    from app.db import database, province_club_teams, province_clubs

    key = canonical(province) or _s(province)
    ids = [club_id for club_id in dict.fromkeys(club_ids) if club_id]
    if not ids:
        return {}
    out: dict[str, str] = {}
    rows = await database.fetch_all(
        select(province_clubs.c.club_id, province_clubs.c.display_name).where(
            and_(province_clubs.c.province == key, province_clubs.c.club_id.in_(ids))
        )
    )
    for row in rows:
        if _s(row["display_name"]):
            out[_s(row["club_id"])] = _s(row["display_name"])
    missing = [club_id for club_id in ids if club_id not in out]
    if missing:
        rows = await database.fetch_all(
            select(province_club_teams.c.club_id, province_club_teams.c.team_name).where(
                and_(province_club_teams.c.province == key, province_club_teams.c.club_id.in_(missing))
            )
        )
        for row in rows:
            club_id, name = _s(row["club_id"]), _s(row["team_name"])
            if not name:
                continue
            current = out.get(club_id)
            if current is None or (len(name), name) < (len(current), current):
                out[club_id] = name
    return out


async def merged_clubs(province: str, clubs: dict[str, dict]) -> dict[str, dict]:
    """Słownik klubów z `_season_clubs` scalony w budżety (klucz = klub główny)."""
    groups = await budget_groups(province)
    if not groups:
        return BR.merge_budgets(clubs, [])
    wanted = [club_id for group in groups for club_id in group["member_ids"] if club_id not in clubs]
    names = await club_names(province, wanted) if wanted else {}
    return BR.merge_budgets(clubs, groups, names=names)


async def season_budgets(province: str, season: str, *, include_future: bool = False) -> dict[str, dict]:
    """
    Budżety sezonu z saldami - klucz = numer klubu GŁÓWNEGO.

    Kształt wartości jak klub z `province_clubs._season_clubs` (club_id, name,
    settles_via_district, settles_since, table_by_club, table_by_club_since,
    note, teams, paid_in, paid_out, settled, charged, matches, balance) plus:
    `budget_id` (None dla klubu bez wspólnego budżetu), `member_ids` (główny
    pierwszy), `members` ([{club_id, name, present, ...kwoty członka}]) oraz
    `mixed_settings` (członkowie mają różne przełączniki).
    """
    from app.province_clubs import _season_clubs

    key = _key(province)
    base = await _season_clubs(key, season, include_future=include_future)
    return await merged_clubs(key, base["clubs"])


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------

async def seed_default_budgets() -> int:
    """
    Budżety z decyzji użytkownika (23.09.2026) - raz na okręg.

    Ślad w `app_migrations` sprawia, że budżet rozłączony później w panelu nie
    wraca po restarcie. `seed_plan` dodatkowo pomija grupę, której klub jest
    już w jakimś budżecie, więc nawet powtórka nic nie zepsuje.
    """
    from sqlalchemy import insert

    from app.db import database, province_club_budgets
    from app.one_time import claim_once

    created = 0
    for key, defaults in BR.DEFAULT_BUDGETS.items():
        if not await claim_once(f"club-budgets-seed-{key}"):
            continue
        plan = BR.seed_plan(await budget_groups(key), defaults)
        now = _now()
        for item in plan:
            await database.execute(
                insert(province_club_budgets).values(
                    province=key,
                    name=item.get("name") or None,
                    primary_club_id=item["primary_club_id"],
                    member_ids=BR.dump_members(item["member_ids"]),
                    created_by="seed",
                    created_at=now,
                    updated_by="seed",
                    updated_at=now,
                )
            )
            created += 1
    return created


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

@router.get("", summary="Wspólne budżety klubów w okręgu")
async def list_budgets(province: str = Query(...)):
    key = _key(province)
    groups = await budget_groups(key)
    names = await club_names(key, [club_id for group in groups for club_id in group["member_ids"]])
    return {
        "province": key,
        "budgets": [
            {
                **group,
                "display_name": group["name"] or names.get(group["primary_club_id"]) or group["primary_club_id"],
                "members": [
                    {"club_id": club_id, "name": names.get(club_id) or club_id}
                    for club_id in group["member_ids"]
                ],
            }
            for group in groups
        ],
    }


class BudgetRequest(BaseModel):
    province: str
    #: Bez numeru - nowy budżet; z numerem - zmiana istniejącego.
    budget_id: Optional[int] = None
    name: Optional[str] = None
    primary_club_id: str
    member_ids: list[str] = []
    #: Zaznaczone kluby są już w innych budżetach - wchłoń te budżety w całości.
    merge_existing: bool = False
    updated_by: Optional[str] = None


@router.put("", summary="Utwórz albo zmień wspólny budżet klubów")
async def save_budget(payload: BudgetRequest):
    from sqlalchemy import and_, delete, insert, update

    from app.db import database, province_club_budgets

    key = _key(payload.province)
    try:
        members = BR.clean_members(payload.primary_club_id, payload.member_ids)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # Okręg jako płatnik ma własne konto poza klubami - nie łączy się w budżet.
    from app.district_payer import refuse_reason

    reason = refuse_reason(members, "Wspólny budżet")
    if reason:
        raise HTTPException(400, reason)

    groups = await budget_groups(key)
    current = None
    if payload.budget_id is not None:
        current = next((g for g in groups if g["budget_id"] == payload.budget_id), None)
        if current is None:
            raise HTTPException(404, "Nie ma takiego wspólnego budżetu - odśwież panel")

    clash = BR.conflicts(members, groups, budget_id=payload.budget_id)
    absorbed: list[dict] = []
    if clash:
        if not payload.merge_existing:
            names = await club_names(key, list(clash))
            first_id, budget = next(iter(clash.items()))
            others = await club_names(key, [budget["primary_club_id"]])
            label = budget.get("name") or others.get(budget["primary_club_id"]) or budget["primary_club_id"]
            more = f" (i {len(clash) - 1} kolejne)" if len(clash) > 1 else ""
            raise HTTPException(
                409,
                f"Klub {names.get(first_id) or first_id} (nr {first_id}){more} jest już we wspólnym "
                f"budżecie „{label}\". Klub może należeć tylko do jednego budżetu - rozłącz tamten "
                f"albo połącz oba budżety.",
            )
        # Wchłaniamy CAŁE budżety - zostawienie ich resztek jako osobnych
        # budżetów byłoby cichą zmianą, której nikt nie zamawiał.
        seen: set[int] = set()
        for budget in clash.values():
            if budget["budget_id"] in seen:
                continue
            seen.add(budget["budget_id"])
            absorbed.append(budget)
            for club_id in budget["member_ids"]:
                if club_id not in members:
                    members.append(club_id)
        if len(members) > BR.MAX_MEMBERS:
            raise HTTPException(400, f"Za dużo numerów w jednym budżecie - limit to {BR.MAX_MEMBERS}")

    now = _now()
    by = _s(payload.updated_by) or None
    name = _s(payload.name) or None
    async with database.transaction():
        for budget in absorbed:
            await database.execute(
                delete(province_club_budgets).where(
                    and_(
                        province_club_budgets.c.province == key,
                        province_club_budgets.c.id == budget["budget_id"],
                    )
                )
            )
        if current is not None:
            await database.execute(
                update(province_club_budgets)
                .where(
                    and_(
                        province_club_budgets.c.province == key,
                        province_club_budgets.c.id == current["budget_id"],
                    )
                )
                .values(
                    name=name,
                    primary_club_id=members[0],
                    member_ids=BR.dump_members(members),
                    updated_by=by,
                    updated_at=now,
                )
            )
            budget_id = current["budget_id"]
        else:
            budget_id = await database.execute(
                insert(province_club_budgets).values(
                    province=key,
                    name=name,
                    primary_club_id=members[0],
                    member_ids=BR.dump_members(members),
                    created_by=by,
                    created_at=now,
                    updated_by=by,
                    updated_at=now,
                )
            )
    return {
        "success": True,
        "budget_id": int(budget_id),
        "primary_club_id": members[0],
        "member_ids": members,
        "absorbed": [budget["budget_id"] for budget in absorbed],
    }


@router.delete("/{budget_id}", summary="Rozłącz wspólny budżet - kluby wracają do osobnych sald")
async def delete_budget(budget_id: int, province: str = Query(...)):
    """
    Wpisy i mecze zostają tam, gdzie były: każdy wpis ma numer klubu, na który
    go zapisano (nowe wpisy budżetu szły na klub główny), więc po rozłączeniu
    salda członków wynikają z ich własnych wpisów.
    """
    from sqlalchemy import and_, delete

    from app.db import database, province_club_budgets

    key = _key(province)
    # `databases` na asyncpg nie oddaje liczby usuniętych wierszy - sprawdzamy przed.
    if not any(group["budget_id"] == budget_id for group in await budget_groups(key)):
        raise HTTPException(404, "Nie ma takiego wspólnego budżetu - odśwież panel")
    await database.execute(
        delete(province_club_budgets).where(
            and_(province_club_budgets.c.province == key, province_club_budgets.c.id == budget_id)
        )
    )
    return {"success": True}
