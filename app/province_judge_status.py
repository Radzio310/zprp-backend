"""
Status "sedzia nieaktywny w okregu" - tabela, trasy, odczyt dla reszty serwera.

Reguly (kto moze, stan poczatkowy, ksztalt wiersza) w
`app/province_judge_status_rules.py`. Reszta serwera (wydarzenia, obsady,
alerty, listy sedziow) pyta tu o zbior numerow: `inactive_ids(province)`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import province_judge_status_rules as R
from app.board_rules import has_committee_badge
from app.db import (
    database,
    province_judge_inactive,
    province_judge_status_log,
    province_judges,
)
from app.deps import get_jwt_payload, get_optional_jwt_payload
from app.match_market import Actor
from app.proel_auth import is_admin
from app.settlement_province import display, spellings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province-judges", tags=["ProvinceJudgeStatus"])

_seeded: Set[str] = set()


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


# ---------------------------------------------------------------------------
# Odczyt dla reszty serwera
# ---------------------------------------------------------------------------


async def inactive_ids(province: Any) -> Set[str]:
    """Numery nieaktywnych sedziow okregu (pisownia okregu bez znaczenia)."""
    key = R.province_key(province)
    if not key:
        return set()
    await ensure_seed()
    rows = await database.fetch_all(
        select(province_judge_inactive.c.judge_id).where(province_judge_inactive.c.province_key == key)
    )
    return {_s(r["judge_id"]) for r in rows}


async def inactive_by_judge() -> Dict[str, str]:
    """judge_id -> klucz okregu dla wszystkich nieaktywnych (listy wielu okregow)."""
    await ensure_seed()
    rows = await database.fetch_all(
        select(province_judge_inactive.c.judge_id, province_judge_inactive.c.province_key)
    )
    return {_s(r["judge_id"]): _s(r["province_key"]) for r in rows}


def is_inactive_in(mapping: Dict[str, str], judge_id: Any, province: Any) -> bool:
    key = R.province_key(province)
    return bool(key) and mapping.get(_s(judge_id)) == key


# ---------------------------------------------------------------------------
# Stan poczatkowy
# ---------------------------------------------------------------------------


async def ensure_seed() -> None:
    """Jednorazowo oznacza nieaktywnych wg dzisiejszej listy aktywnych.

    Idempotentne: znacznik to wpis `source='seed'` w historii okregu, a wstawki
    maja ON CONFLICT DO NOTHING - pozniejsze reczne zmiany nigdy nie sa
    nadpisywane. Okreg bez ani jednego sedziego w rejestrze czeka na kolejna probe.
    """
    for key, names in R.SEED_ACTIVE.items():
        if key in _seeded:
            continue
        try:
            marker = await database.fetch_one(
                select(province_judge_status_log.c.id)
                .where(
                    and_(
                        province_judge_status_log.c.province_key == key,
                        province_judge_status_log.c.source == R.SEED_SOURCE,
                    )
                )
                .limit(1)
            )
            if marker:
                _seeded.add(key)
                continue
            rows = await database.fetch_all(
                select(province_judges.c.judge_id, province_judges.c.full_name).where(
                    province_judges.c.province.in_(spellings(key))
                )
            )
            judges = [{"judge_id": r["judge_id"], "full_name": r["full_name"]} for r in rows]
            if not judges:
                continue
            inactive, unmatched = R.plan_seed(judges, names)
            now = datetime.now(timezone.utc)
            async with database.transaction():
                for person in inactive:
                    await database.execute(
                        pg_insert(province_judge_inactive)
                        .values(
                            judge_id=person["judge_id"],
                            province_key=key,
                            name=person["name"],
                            since=now,
                            by_id=None,
                            by_name=None,
                            note=R.SEED_NOTE,
                        )
                        .on_conflict_do_nothing(index_elements=[province_judge_inactive.c.judge_id])
                    )
                    await database.execute(
                        insert(province_judge_status_log).values(
                            province_key=key,
                            judge_id=person["judge_id"],
                            name=person["name"],
                            inactive=True,
                            at=now,
                            note=R.SEED_NOTE,
                            source="seed-entry",
                        )
                    )
                summary = (
                    f"{R.SEED_NOTE}; oznaczono {len(inactive)}; bez dopasowania na liscie: "
                    + (", ".join(unmatched) or "brak")
                )
                await database.execute(
                    insert(province_judge_status_log).values(
                        province_key=key,
                        judge_id="",
                        name="",
                        inactive=False,
                        at=now,
                        note=summary[:2000],
                        source=R.SEED_SOURCE,
                    )
                )
            _seeded.add(key)
            logger.warning(
                "[judge_status] stan poczatkowy %s: nieaktywnych=%d, nazwiska z listy bez dopasowania=%s",
                key,
                len(inactive),
                unmatched,
            )
        except Exception:  # noqa: BLE001
            logger.exception("[judge_status] stan poczatkowy %s nie przeszedl", key)


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------


class StatusBody(BaseModel):
    province: str
    judge_ids: List[str]
    inactive: bool
    note: Optional[str] = None


async def _actor(payload: Optional[dict]) -> Optional[Actor]:
    judge_id = _s((payload or {}).get("judge_id"))
    if not judge_id:
        return None
    row = await database.fetch_one(
        select(
            province_judges.c.judge_id,
            province_judges.c.full_name,
            province_judges.c.province,
            province_judges.c.photo_url,
            province_judges.c.badges,
        ).where(province_judges.c.judge_id == judge_id)
    )
    return Actor(payload, dict(row._mapping) if row else None, await is_admin(judge_id))


def _can(actor: Optional[Actor], province: Any) -> bool:
    if actor is None:
        return False
    return R.may_manage(
        is_admin=actor.is_admin,
        has_committee_badge=has_committee_badge(actor.badges),
        own_province=actor.province,
        province=province,
    )


async def _view(province: str, can_manage: bool) -> Dict[str, Any]:
    key = R.province_key(province)
    rows = await database.fetch_all(
        select(province_judge_inactive)
        .where(province_judge_inactive.c.province_key == key)
        .order_by(province_judge_inactive.c.name.asc())
    )
    return {
        "province": display(province),
        "inactive": [R.item(dict(r._mapping)) for r in rows],
        "can_manage": can_manage,
    }


def _require_province(value: Any) -> str:
    if not R.province_key(value):
        raise HTTPException(400, "Nie znam takiego województwa")
    return _s(value)


@router.get("/status", summary="Nieaktywni sedziowie okregu (token opcjonalny)")
async def get_status(
    province: str = Query(""),
    payload: Optional[dict] = Depends(get_optional_jwt_payload),
) -> Dict[str, Any]:
    _require_province(province)
    await ensure_seed()
    return await _view(province, _can(await _actor(payload), province))


@router.post("/status", summary="Oznacz sedziow jako nieaktywnych albo ich przywroc")
async def set_status(body: StatusBody, payload: dict = Depends(get_jwt_payload)) -> Dict[str, Any]:
    _require_province(body.province)
    actor = await _actor(payload)
    if actor is None or not _can(actor, body.province):
        raise HTTPException(
            403, "Status sędziów zmienia komisja sędziowska własnego okręgu albo administrator"
        )
    try:
        ids = R.clean_ids(body.judge_ids)
    except R.Invalid as exc:
        raise HTTPException(400, str(exc))
    note = R.clean_note(body.note)
    key = R.province_key(body.province)
    await ensure_seed()

    people = {
        _s(r["judge_id"]): _s(r["full_name"])
        for r in await database.fetch_all(
            select(province_judges.c.judge_id, province_judges.c.full_name).where(
                and_(province_judges.c.judge_id.in_(ids), province_judges.c.province.in_(spellings(key)))
            )
        )
    }
    if body.inactive:
        missing = [i for i in ids if i not in people]
        if missing:
            raise HTTPException(400, "Nie ma na liście sędziów tego okręgu: " + ", ".join(missing))
    now = datetime.now(timezone.utc)
    by_id, by_name = actor.judge_id, actor.full_name or None
    current = await inactive_ids(key)
    async with database.transaction():
        for jid in ids:
            if body.inactive == (jid in current):
                continue  # nic sie nie zmienia - bez wpisu w historii
            name = people.get(jid, "")
            if body.inactive:
                await database.execute(
                    pg_insert(province_judge_inactive)
                    .values(
                        judge_id=jid, province_key=key, name=name, since=now,
                        by_id=by_id, by_name=by_name, note=note,
                    )
                    .on_conflict_do_update(
                        index_elements=[province_judge_inactive.c.judge_id],
                        set_={
                            "province_key": key, "name": name, "since": now,
                            "by_id": by_id, "by_name": by_name, "note": note,
                        },
                    )
                )
            else:
                await database.execute(
                    delete(province_judge_inactive).where(
                        and_(
                            province_judge_inactive.c.judge_id == jid,
                            province_judge_inactive.c.province_key == key,
                        )
                    )
                )
            await database.execute(
                insert(province_judge_status_log).values(
                    province_key=key, judge_id=jid, name=name, inactive=body.inactive, at=now,
                    by_id=by_id, by_name=by_name, note=note, source="manual",
                )
            )
    try:
        from app.assignment_board_cache import bump_all

        bump_all()
    except Exception:  # noqa: BLE001
        logger.exception("[judge_status] nie uniewazniono tablicy obsad")
    return await _view(body.province, True)
