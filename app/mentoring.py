"""Administrative mentorship; separate from match participation and partner offtimes."""
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.db import (database, province_judges, province_matches, mentoring_config as config,
    mentoring_pairs as pairs, mentoring_members as members, mentoring_assignments as assignments,
    mentoring_audit as audit)
from app.match_market import market_actor, Actor
from app.match_market_access import badge_names
from app.mentoring_rules import may_manage, pair_matches, season_bounds, json_value

router = APIRouter(prefix="/mentoring", tags=["Mentoring"])


def now():
    return datetime.now(timezone.utc)


async def configuration(province):
    row = await database.fetch_one(select(config).where(config.c.province == province))
    return {**dict(row), "manager_ids": json_value(row["manager_ids"], [])} if row else {"province": province, "enabled": False, "manager_ids": []}


async def require_manager(actor, province):
    if not may_manage(actor.is_admin, actor.judge_id, actor.province, badge_names(actor.badges), province, await configuration(province)):
        raise HTTPException(403, "Brak uprawnień do zarządzania mentoringiem tego okręgu.")


async def log(actor, action, data, pair_id=None):
    await database.execute(audit.insert().values(actor_id=actor.judge_id, action=action, data=data, pair_id=pair_id))


class ConfigRequest(BaseModel):
    enabled: bool
    manager_ids: list[str] = Field(default_factory=list, max_length=100)


class PairRequest(BaseModel):
    province: str
    judge_ids: list[str] = Field(min_length=2, max_length=2)
    mentor_ids: list[str] = Field(min_length=1, max_length=30)


class MentorsRequest(BaseModel):
    mentor_ids: list[str] = Field(min_length=1, max_length=30)


class Preferences(BaseModel):
    show_home: bool
    notify: bool


async def validate_people(actor, province, judge_ids, mentor_ids):
    if len(set(judge_ids)) != 2 or len(set(mentor_ids)) != len(mentor_ids) or set(judge_ids) & set(mentor_ids):
        raise HTTPException(422, "Wybierz dwóch różnych podopiecznych i mentorów spoza tej pary.")
    ids = set(judge_ids + mentor_ids)
    rows = await database.fetch_all(select(province_judges).where(province_judges.c.judge_id.in_(ids)))
    if len(rows) != len(ids):
        raise HTTPException(422, "Nie znaleziono wszystkich wybranych sędziów.")
    if not actor.is_admin and any(str(r["province"]).strip().upper() != province for r in rows):
        raise HTTPException(403, "Komisja może wybierać wyłącznie osoby ze swojego okręgu.")


@router.get("/access")
async def access(actor: Actor = Depends(market_actor)):
    cfg = await configuration(actor.province)
    return {"isAdmin": actor.is_admin, "province": actor.province, "judgeId": actor.judge_id,
        "canManage": may_manage(actor.is_admin, actor.judge_id, actor.province, badge_names(actor.badges), actor.province, cfg)}


@router.get("/management")
async def management(province: str = "", actor: Actor = Depends(market_actor)):
    province = (province or actor.province).strip().upper()
    await require_manager(actor, province)
    query = select(province_judges).order_by(province_judges.c.full_name)
    if not actor.is_admin:
        query = query.where(province_judges.c.province == province)
    people = [{k: dict(r).get(k) for k in ("judge_id", "full_name", "province", "photo_url")} for r in await database.fetch_all(query)]
    records = await database.fetch_all(select(pairs).where(pairs.c.province == province).where(pairs.c.ended_at.is_(None)))
    links = await database.fetch_all(select(assignments).where(assignments.c.ended_at.is_(None)))
    occupied = await database.fetch_all(select(members.c.judge_id))
    return {"config": await configuration(province), "people": people,
        "occupied": [r["judge_id"] for r in occupied if actor.is_admin or r["judge_id"] in {p["judge_id"] for p in people}],
        "pairs": [{**dict(r), "judge_ids": json_value(r["judge_ids"], []), "mentor_ids": [a["mentor_id"] for a in links if a["pair_id"] == r["id"]]} for r in records]}


@router.put("/config/{province}")
async def set_config(province: str, req: ConfigRequest, actor: Actor = Depends(market_actor)):
    if not actor.is_admin:
        raise HTTPException(403, "Tylko administrator włącza zarządzanie okręgowe.")
    province = province.strip().upper()
    rows = await database.fetch_all(select(province_judges).where(province_judges.c.judge_id.in_(req.manager_ids)))
    if len(rows) != len(set(req.manager_ids)) or any(r["province"] != province for r in rows):
        raise HTTPException(422, "Zarządzający muszą należeć do tego okręgu.")
    async with database.transaction():
        await database.execute(text("SELECT pg_advisory_xact_lock(7419021)"))
        await database.execute(pg_insert(config).values(province=province, **req.model_dump()).on_conflict_do_update(index_elements=[config.c.province], set_=req.model_dump()))
        await log(actor, "configuration", {"province": province, **req.model_dump()})
    return {"ok": True}


@router.post("/pairs")
async def create_pair(req: PairRequest, actor: Actor = Depends(market_actor)):
    province = req.province.strip().upper()
    async with database.transaction():
        await database.execute(text("SELECT pg_advisory_xact_lock(7419021)"))
        await require_manager(actor, province)
        await validate_people(actor, province, req.judge_ids, req.mentor_ids)
        if await database.fetch_one(select(members).where(members.c.judge_id.in_(req.judge_ids))):
            raise HTTPException(409, "Jeden z sędziów należy już do aktywnej pary.")
        pair_id = str(uuid4())
        await database.execute(pairs.insert().values(id=pair_id, province=province, judge_ids=sorted(req.judge_ids), created_by=actor.judge_id))
        for judge in req.judge_ids:
            await database.execute(members.insert().values(judge_id=judge, pair_id=pair_id))
        for mentor in req.mentor_ids:
            await database.execute(assignments.insert().values(pair_id=pair_id, mentor_id=mentor, show_home=True, notify=True))
        await log(actor, "created", req.model_dump(), pair_id)
    return {"id": pair_id}


async def active_pair(pair_id):
    row = await database.fetch_one(select(pairs).where(pairs.c.id == pair_id).where(pairs.c.ended_at.is_(None)))
    if not row:
        raise HTTPException(404, "Para nie jest już aktywna.")
    return {**dict(row), "judge_ids": json_value(row["judge_ids"], [])}


@router.put("/pairs/{pair_id}/mentors")
async def replace_mentors(pair_id: str, req: MentorsRequest, actor: Actor = Depends(market_actor)):
    async with database.transaction():
        await database.execute(text("SELECT pg_advisory_xact_lock(7419021)"))
        pair = await active_pair(pair_id)
        await require_manager(actor, pair["province"])
        await validate_people(actor, pair["province"], pair["judge_ids"], req.mentor_ids)
        await database.execute(update(assignments).where(assignments.c.pair_id == pair_id).where(assignments.c.ended_at.is_(None)).where(assignments.c.mentor_id.notin_(req.mentor_ids)).values(ended_at=now()))
        for mentor in req.mentor_ids:
            old = await database.fetch_one(select(assignments).where(assignments.c.pair_id == pair_id).where(assignments.c.mentor_id == mentor))
            if old and old["ended_at"] is None:
                continue
            await database.execute(pg_insert(assignments).values(pair_id=pair_id, mentor_id=mentor, started_at=now(), show_home=True, notify=True).on_conflict_do_update(index_elements=[assignments.c.pair_id, assignments.c.mentor_id], set_={"ended_at": None, "started_at": now(), "show_home": True, "notify": True}))
        await log(actor, "mentors_changed", req.model_dump(), pair_id)
    return {"ok": True}


@router.delete("/pairs/{pair_id}")
async def end_pair(pair_id: str, actor: Actor = Depends(market_actor)):
    async with database.transaction():
        await database.execute(text("SELECT pg_advisory_xact_lock(7419021)"))
        pair = await active_pair(pair_id)
        await require_manager(actor, pair["province"])
        await database.execute(update(pairs).where(pairs.c.id == pair_id).values(ended_at=now()))
        await database.execute(update(assignments).where(assignments.c.pair_id == pair_id).where(assignments.c.ended_at.is_(None)).values(ended_at=now()))
        await database.execute(delete(members).where(members.c.pair_id == pair_id))
        await log(actor, "ended", {}, pair_id)
    return {"ok": True}


async def mentor_link(pair_id, judge_id):
    pair = await active_pair(pair_id)
    link = await database.fetch_one(select(assignments).where(assignments.c.pair_id == pair_id).where(assignments.c.mentor_id == judge_id).where(assignments.c.ended_at.is_(None)))
    if not link:
        raise HTTPException(403, "Opieka nad tą parą zakończyła się lub nie została przydzielona.")
    return pair, dict(link)


@router.get("/mine")
async def mine(actor: Actor = Depends(market_actor)):
    rows = await database.fetch_all(select(pairs, assignments.c.show_home, assignments.c.notify).select_from(pairs.join(assignments, pairs.c.id == assignments.c.pair_id)).where(assignments.c.mentor_id == actor.judge_id).where(assignments.c.ended_at.is_(None)).where(pairs.c.ended_at.is_(None)))
    ids = {j for r in rows for j in json_value(r["judge_ids"], [])}
    people = await database.fetch_all(select(province_judges).where(province_judges.c.judge_id.in_(ids))) if ids else []
    names = {r["judge_id"]: {k: dict(r).get(k) for k in ("judge_id", "full_name", "photo_url")} for r in people}
    return {"pairs": [{**dict(r), "judge_ids": json_value(r["judge_ids"], []), "judges": [names.get(j, {"judge_id": j, "full_name": j}) for j in json_value(r["judge_ids"], [])]} for r in rows]}


@router.put("/mine/{pair_id}/preferences")
async def preferences(pair_id: str, req: Preferences, actor: Actor = Depends(market_actor)):
    await mentor_link(pair_id, actor.judge_id)
    await database.execute(update(assignments).where(assignments.c.pair_id == pair_id).where(assignments.c.mentor_id == actor.judge_id).where(assignments.c.ended_at.is_(None)).values(**req.model_dump()))
    return {"ok": True}


@router.get("/mine/{pair_id}/matches")
async def matches(pair_id: str, actor: Actor = Depends(market_actor)):
    pair, _ = await mentor_link(pair_id, actor.judge_id)
    start, end = season_bounds()
    records = await database.fetch_all(select(province_matches).where(province_matches.c.active.is_(True)).where(province_matches.c.match_at >= start).where(province_matches.c.match_at < end).order_by(province_matches.c.updated_at.desc()))
    result = []
    seen = set()
    for row in records:
        if row["match_id"] in seen:
            continue
        seen.add(row["match_id"])
        state = json_value(row["state_json"], {})
        if not pair_matches(pair["judge_ids"], state):
            continue
        # Do not expose private notes/contacts in the mentoring feed.
        safe = {k: v for k, v in state.items() if k in {"Id", "RozgrywkiCode", "data_fakt", "data_prop", "season", "runda", "kolejka", "protocol_status", "host_swapped", "Nazwa", "Link", "Id_rozgrywki", "ID_sezon"} or k.startswith(("NrSedzia", "ID_zespoly", "Hala_", "wynik_", "dogrywka_", "karne_"))}
        safe.update({"Id": row["match_id"], "province": row["province"], "mentoringPairId": pair_id, "type": "mentoring", "isMyMatch": False})
        result.append(safe)
    result.sort(key=lambda m: str(m.get("data_fakt") or ""))
    return {"matches": result, "season": start.year, "checkedAt": now()}
