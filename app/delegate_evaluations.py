"""Trwały, autoryzowany magazyn ocen sędziów wystawianych przez delegatów."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.admin_alerts import admin_judge_ids
from app.delegate_evaluation_utils import (
    GRADE_POINTS,
    MIN_SEASON_START,
    absorb_evaluation,
    allowed_season,
    canonical_hash,
    finalize_bucket,
    grade_values,
    new_bucket,
    pair_names,
    safe_source_fingerprint,
    season_start,
)
from app.admin_guard import admin_write_guard
from app.db import (
    database,
    delegate_evaluation_access,
    delegate_evaluation_versions,
    delegate_evaluations,
    baza_vips,
    province_judges,
)
from app.deps import get_jwt_payload
from app.province_access import normalize_province

router = APIRouter(prefix="/delegate-evaluations", tags=["Delegate evaluations"])
admin_router = APIRouter(
    prefix="/admin/delegate-evaluations",
    tags=["Delegate evaluations admin"],
    dependencies=[Depends(admin_write_guard)],
)

# Reguły skali, sezonów i odcisków mieszkają w `app/delegate_evaluation_utils.py`.
# Ten moduł miał ich WŁASNE kopie, więc poprawka w jednym miejscu nie docierała
# do drugiego - a testy sprawdzały akurat tę kopię, której API nie używało.


class EvaluationIn(BaseModel):
    match_id: str = Field(min_length=1, max_length=160)
    season: str = Field(min_length=4, max_length=24)
    province: str = Field(min_length=2, max_length=80)
    match_number: str = Field(default="", max_length=160)
    match_date: str = Field(default="", max_length=80)
    referee_ids: List[str] = Field(default_factory=list, max_length=4)
    referee_names: List[str] = Field(default_factory=list, max_length=4)
    delegate_name: str = Field(default="", max_length=240)
    source_kind: Literal["html", "legacy_pdf"] = "html"
    source_url: str = Field(default="", max_length=2048)
    evaluation: Dict[str, Any] = Field(default_factory=dict)


class SyncIn(BaseModel):
    evaluations: List[EvaluationIn] = Field(default_factory=list, max_length=100)


class AccessIn(BaseModel):
    can_view_stats: bool = False
    can_view_full: bool = False
    updated_by: str = ""


def _actor(payload: Dict[str, Any], judge_required: bool = False) -> str:
    judge_id = str(payload.get("judge_id") or "").strip()
    if judge_id:
        return judge_id
    if not judge_required and str(payload.get("account_type") or "") == "org":
        login = str(payload.get("sub") or "").strip()
        if login:
            return f"org:{login}"
    if not judge_id:
        raise HTTPException(403, "Konto nie ma numeru sędziego")
    return judge_id


async def _is_admin(judge_id: str) -> bool:
    if judge_id.startswith("org:"):
        return False
    return judge_id in await admin_judge_ids()


async def _access(judge_id: str, province: str) -> Dict[str, bool]:
    if judge_id.startswith("org:"):
        row = await database.fetch_one(
            select(baza_vips.c.province).where(baza_vips.c.username == judge_id[4:])
        )
        same_province = bool(
            row and normalize_province(row["province"]) == normalize_province(province)
        )
        return {"stats": same_province, "full": same_province, "admin": False, "commission": same_province}
    if await _is_admin(judge_id):
        return {"stats": True, "full": True, "admin": True}
    row = await database.fetch_one(
        select(delegate_evaluation_access).where(
            and_(
                delegate_evaluation_access.c.province == normalize_province(province),
                delegate_evaluation_access.c.judge_id == judge_id,
            )
        )
    )
    return {
        "stats": bool(row and row["can_view_stats"]),
        "full": bool(row and row["can_view_full"]),
        "admin": False,
    }


@router.post("/sync")
async def sync(req: SyncIn, payload: dict = Depends(get_jwt_payload)):
    actor = _actor(payload, judge_required=True)
    inserted = updated = unchanged = skipped = 0
    for item in req.evaluations:
        if not allowed_season(item.season) or actor not in {str(x).strip() for x in item.referee_ids}:
            skipped += 1
            continue
        source_key = canonical_hash([item.season, item.match_id, sorted(item.referee_ids)])
        content_hash = canonical_hash(item.evaluation)
        existing = await database.fetch_one(
            select(delegate_evaluations.c.id, delegate_evaluations.c.content_hash).where(
                delegate_evaluations.c.source_key == source_key
            )
        )
        values = {
            "source_key": source_key,
            "match_id": item.match_id,
            "season": item.season,
            "province": normalize_province(item.province),
            "match_number": item.match_number,
            "match_date": item.match_date,
            "referee_ids": [str(x).strip() for x in item.referee_ids if str(x).strip()],
            "referee_names": item.referee_names,
            "delegate_name": item.delegate_name,
            "source_kind": item.source_kind,
            "source_fingerprint": safe_source_fingerprint(item.source_url),
            "content_hash": content_hash,
            "evaluation_json": item.evaluation,
            "submitted_by": actor,
        }
        evaluation_id = await database.execute(
            pg_insert(delegate_evaluations).values(**values).on_conflict_do_update(
                index_elements=[delegate_evaluations.c.source_key], set_=values
            ).returning(delegate_evaluations.c.id)
        )
        await database.execute(
            pg_insert(delegate_evaluation_versions).values(
                evaluation_id=evaluation_id,
                content_hash=content_hash,
                evaluation_json=item.evaluation,
            ).on_conflict_do_nothing()
        )
        if not existing:
            inserted += 1
        elif existing["content_hash"] != content_hash:
            updated += 1
        else:
            unchanged += 1
    return {"ok": True, "inserted": inserted, "updated": updated, "unchanged": unchanged, "skipped": skipped}


async def _rows_for(judge_id: str, province: str, season: str = ""):
    conditions = []
    if province:
        conditions.append(delegate_evaluations.c.province == normalize_province(province))
    else:
        conditions.append(delegate_evaluations.c.referee_ids.contains([judge_id]))
    if season:
        conditions.append(delegate_evaluations.c.season == season)
    return await database.fetch_all(
        select(delegate_evaluations).where(and_(*conditions)).order_by(delegate_evaluations.c.match_date.desc())
    )


@router.get("/overview")
async def overview(
    province: str = Query(""), season: str = Query(""), payload: dict = Depends(get_jwt_payload)
):
    actor = _actor(payload)
    access = await _access(actor, province) if province else {"stats": True, "full": True, "admin": await _is_admin(actor)}
    if province and not access["stats"]:
        raise HTTPException(403, "Brak dostępu do statystyk ocen")
    rows = await _rows_for(actor, province, season)
    people: Dict[str, Dict[str, Any]] = {}
    pairs: Dict[str, Dict[str, Any]] = {}
    # Worek „Łącznie": WSZYSTKIE arkusze z tego zapytania w jednym zbiorze, więc
    # każdy oceniony element waży tyle samo co w średniej pojedynczej pary. Para
    # z dziesięcioma arkuszami wpływa na wynik okręgu mocniej niż para z jednym -
    # to nie „przeciętna para", to średnia sędziowania w okręgu.
    total = new_bucket()
    available_seasons = set()
    for row in rows:
        data = dict(row)
        available_seasons.add(str(data.get("season") or ""))
        evaluation = data.get("evaluation_json") or {}
        scores = grade_values(evaluation)
        ids, names = data.get("referee_ids") or [], data.get("referee_names") or []
        clean_ids = [str(value).strip() for value in ids if str(value).strip()]
        absorb_evaluation(total, evaluation, scores)
        if clean_ids:
            pair_key = "|".join(sorted(clean_ids))
            if pair_key not in pairs:
                pairs[pair_key] = new_bucket(
                    key=pair_key,
                    judge_ids=sorted(clean_ids),
                    names=pair_names(ids, names),
                )
            absorb_evaluation(pairs[pair_key], evaluation, scores)
        for index, judge_id in enumerate(ids):
            if not province and str(judge_id) != actor:
                continue
            key = str(judge_id)
            if key not in people:
                people[key] = new_bucket(
                    judge_id=key,
                    name=str(names[index]) if index < len(names) else key,
                )
            absorb_evaluation(people[key], evaluation, scores)

    output = [finalize_bucket(person) for person in people.values()]
    output.sort(key=lambda item: str(item["name"]))
    pair_output = [finalize_bucket(pair) for pair in pairs.values()]
    pair_output.sort(key=lambda item: " ".join(item.get("names") or []))
    result = {
        "access": access,
        "people": output,
        "pairs": pair_output,
        "total": finalize_bucket(total),
        "evaluations": len(rows),
        "seasons": sorted((value for value in available_seasons if value), reverse=True),
        "grade_scale": GRADE_POINTS,
    }
    if access.get("admin"):
        # Licznik arkuszy w każdym okręgu - z tego admin składa wybór województw.
        # Liczymy BEZ filtra sezonu: inaczej okręg mający arkusze tylko w innym
        # sezonie wyglądałby na pusty i admin nie miałby po co tam wchodzić.
        counted = await database.fetch_all(
            select(
                delegate_evaluations.c.province,
                func.count().label("sheets"),
            ).group_by(delegate_evaluations.c.province)
        )
        result["provinces"] = [
            {"province": str(row["province"] or ""), "sheets": int(row["sheets"] or 0)}
            for row in counted
            if str(row["province"] or "").strip()
        ]
    return result


@router.get("/access/me")
async def my_access(province: str = Query(""), payload: dict = Depends(get_jwt_payload)):
    actor = _actor(payload)
    if not province:
        return {"stats": True, "full": True, "self": True, "admin": await _is_admin(actor)}
    return await _access(actor, province)


@router.get("/forms")
async def forms(province: str = Query(""), season: str = Query(""), payload: dict = Depends(get_jwt_payload)):
    actor = _actor(payload)
    access = await _access(actor, province) if province else {"full": True}
    if province and not access["full"]:
        raise HTTPException(403, "Brak dostępu do pełnych arkuszy")
    return {"items": [dict(row) for row in await _rows_for(actor, province, season)]}


@admin_router.get("/access/{province}")
async def list_access(province: str, payload: dict = Depends(get_jwt_payload)):
    if not await _is_admin(_actor(payload)):
        raise HTTPException(403, "Tylko administrator może zarządzać dostępem")
    rows = await database.fetch_all(select(delegate_evaluation_access).where(delegate_evaluation_access.c.province == normalize_province(province)))
    return {"province": normalize_province(province), "items": [dict(row) for row in rows]}


@admin_router.put("/access/{province}/{judge_id}")
async def put_access(province: str, judge_id: str, req: AccessIn, payload: dict = Depends(get_jwt_payload)):
    actor = _actor(payload)
    if not await _is_admin(actor):
        raise HTTPException(403, "Tylko administrator moze zarzadzac dostepem")
    stats = bool(req.can_view_stats or req.can_view_full)
    await database.execute(
        pg_insert(delegate_evaluation_access).values(
            province=normalize_province(province), judge_id=judge_id,
            can_view_stats=stats, can_view_full=bool(req.can_view_full), updated_by=actor,
        ).on_conflict_do_update(
            index_elements=[delegate_evaluation_access.c.province, delegate_evaluation_access.c.judge_id],
            set_={"can_view_stats": stats, "can_view_full": bool(req.can_view_full), "updated_by": actor},
        )
    )
    return {"ok": True, "can_view_stats": stats, "can_view_full": bool(req.can_view_full)}


@admin_router.delete("/access/{province}/{judge_id}")
async def remove_access(province: str, judge_id: str, payload: dict = Depends(get_jwt_payload)):
    if not await _is_admin(_actor(payload)):
        raise HTTPException(403, "Tylko administrator moze zarzadzac dostepem")
    await database.execute(delete(delegate_evaluation_access).where(and_(delegate_evaluation_access.c.province == normalize_province(province), delegate_evaluation_access.c.judge_id == judge_id)))
    return {"ok": True}
