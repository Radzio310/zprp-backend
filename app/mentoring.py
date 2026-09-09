"""Administrative mentorship; separate from match participation and partner offtimes."""
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, text, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.db import (database, province_judges, province_matches, mentoring_config as config,
    mentoring_pairs as pairs, mentoring_members as members, mentoring_assignments as assignments,
    mentoring_audit as audit)
from app.match_market import market_actor, Actor
from app.match_market_access import badge_names
from app.mentoring_rules import CROSS_PROVINCE, may_manage, pair_matches, season_bounds, json_value

router = APIRouter(prefix="/mentoring", tags=["Mentoring"])

PROVINCES = (
    "DOLNOŚLĄSKIE", "KUJAWSKO-POMORSKIE", "LUBELSKIE", "LUBUSKIE",
    "ŁÓDZKIE", "MAŁOPOLSKIE", "MAZOWIECKIE", "OPOLSKIE",
    "PODKARPACKIE", "PODLASKIE", "POMORSKIE", "ŚLĄSKIE",
    "ŚWIĘTOKRZYSKIE", "WARMIŃSKO-MAZURSKIE", "WIELKOPOLSKIE",
    "ZACHODNIOPOMORSKIE",
)
ADMIN_SCOPES = (*PROVINCES, CROSS_PROVINCE)


def now():
    return datetime.now(timezone.utc)


async def configuration(province):
    if province == CROSS_PROVINCE:
        return {"province": CROSS_PROVINCE, "enabled": False, "manager_ids": []}
    row = await database.fetch_one(select(config).where(config.c.province == province))
    return {**dict(row), "manager_ids": json_value(row["manager_ids"], [])} if row else {"province": province, "enabled": False, "manager_ids": []}


async def require_manager(actor, province):
    if province == CROSS_PROVINCE:
        if not actor.is_admin:
            raise HTTPException(403, "Parami międzyokręgowymi zarządza wyłącznie administrator.")
        return
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
    return rows


def pair_scope(judge_ids, people):
    """Wspólny okręg pary albo specjalny, admin-only koszyk międzyokręgowy."""
    wanted = {str(value).strip() for value in judge_ids}
    judge_rows = [row for row in people if str(row["judge_id"]).strip() in wanted]
    if len(judge_rows) != len(wanted) or any(not str(row["province"] or "").strip() for row in judge_rows):
        raise HTTPException(422, "Każdy podopieczny musi mieć przypisany okręg.")
    provinces = {str(row["province"]).strip().upper() for row in judge_rows}
    return next(iter(provinces)) if len(provinces) == 1 else CROSS_PROVINCE


@router.get("/access")
async def access(actor: Actor = Depends(market_actor)):
    cfg = await configuration(actor.province)
    return {"isAdmin": actor.is_admin, "province": actor.province, "judgeId": actor.judge_id,
        "canManage": may_manage(actor.is_admin, actor.judge_id, actor.province, badge_names(actor.badges), actor.province, cfg)}


@router.get("/admin/overview")
async def admin_overview(actor: Actor = Depends(market_actor)):
    """Small country-wide dashboard; detailed people are fetched only on demand."""
    if not actor.is_admin:
        raise HTTPException(403, "Ten widok jest dostępny wyłącznie dla administratora.")
    config_rows = await database.fetch_all(select(config))
    pair_rows = await database.fetch_all(
        select(pairs.c.province, func.count(pairs.c.id).label("count"))
        .where(pairs.c.ended_at.is_(None)).group_by(pairs.c.province)
    )
    mentor_rows = await database.fetch_all(
        select(pairs.c.province, func.count(func.distinct(assignments.c.mentor_id)).label("count"))
        .select_from(pairs.join(assignments, assignments.c.pair_id == pairs.c.id))
        .where(pairs.c.ended_at.is_(None)).where(assignments.c.ended_at.is_(None))
        .group_by(pairs.c.province)
    )
    config_by = {row["province"]: row for row in config_rows}
    pair_by = {row["province"]: int(row["count"] or 0) for row in pair_rows}
    mentor_by = {row["province"]: int(row["count"] or 0) for row in mentor_rows}
    return {"provinces": [{
        "province": province,
        "enabled": bool(config_by.get(province) and config_by[province]["enabled"]),
        "manager_ids": json_value(config_by[province]["manager_ids"], []) if province in config_by else [],
        "active_pairs": pair_by.get(province, 0),
        "active_mentors": mentor_by.get(province, 0),
        "admin_only": province == CROSS_PROVINCE,
    } for province in ADMIN_SCOPES]}


@router.get("/management")
async def management(province: str = "", actor: Actor = Depends(market_actor)):
    province = (province or actor.province).strip().upper()
    await require_manager(actor, province)
    query = select(province_judges).order_by(province_judges.c.full_name)
    if not actor.is_admin:
        query = query.where(province_judges.c.province == province)
    people = [{k: dict(r).get(k) for k in ("judge_id", "full_name", "province", "photo_url")} for r in await database.fetch_all(query)]
    # Managers see the active configuration and the archive. Ending a pair revokes
    # access for mentors, but must not erase who was responsible for it.
    records = await database.fetch_all(select(pairs).where(pairs.c.province == province).order_by(pairs.c.created_at.desc()))
    links = await database.fetch_all(select(assignments).select_from(assignments.join(pairs, assignments.c.pair_id == pairs.c.id)).where(pairs.c.province == province))
    occupied = await database.fetch_all(select(members.c.judge_id))
    return {"config": await configuration(province), "people": people,
        "occupied": [r["judge_id"] for r in occupied if actor.is_admin or r["judge_id"] in {p["judge_id"] for p in people}],
        "pairs": [{**dict(r), "judge_ids": json_value(r["judge_ids"], []),
            "mentor_ids": [a["mentor_id"] for a in links if a["pair_id"] == r["id"] and a["ended_at"] is None],
            "mentor_history_ids": list(dict.fromkeys(a["mentor_id"] for a in links if a["pair_id"] == r["id"]))}
            for r in records]}


@router.put("/config/{province}")
async def set_config(province: str, req: ConfigRequest, actor: Actor = Depends(market_actor)):
    if not actor.is_admin:
        raise HTTPException(403, "Tylko administrator włącza zarządzanie okręgowe.")
    province = province.strip().upper()
    if province == CROSS_PROVINCE:
        raise HTTPException(422, "Pary międzyokręgowe nie mają uprawnień komisji.")
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
    requested_province = req.province.strip().upper()
    async with database.transaction():
        await database.execute(text("SELECT pg_advisory_xact_lock(7419021)"))
        await require_manager(actor, requested_province)
        people = await validate_people(actor, requested_province, req.judge_ids, req.mentor_ids)
        province = pair_scope(req.judge_ids, people)
        if province == CROSS_PROVINCE and not actor.is_admin:
            raise HTTPException(403, "Parę z dwóch okręgów może utworzyć wyłącznie administrator.")
        if await database.fetch_one(select(members).where(members.c.judge_id.in_(req.judge_ids))):
            raise HTTPException(409, "Jeden z sędziów należy już do aktywnej pary.")
        pair_id = str(uuid4())
        await database.execute(pairs.insert().values(id=pair_id, province=province, judge_ids=sorted(req.judge_ids), created_by=actor.judge_id))
        for judge in req.judge_ids:
            await database.execute(members.insert().values(judge_id=judge, pair_id=pair_id))
        for mentor in req.mentor_ids:
            await database.execute(assignments.insert().values(pair_id=pair_id, mentor_id=mentor, show_home=True, notify=True))
        await log(actor, "created", {**req.model_dump(), "province": province}, pair_id)
    return {"id": pair_id, "province": province}


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


@router.get("/my-pair")
async def my_pair(actor: Actor = Depends(market_actor)):
    """Read-only relation card for a judge's settings screen."""
    membership = await database.fetch_one(
        select(members).where(members.c.judge_id == actor.judge_id)
    )
    if not membership:
        return {"pair": None}

    pair_row = await database.fetch_one(
        select(pairs)
        .where(pairs.c.id == membership["pair_id"])
        .where(pairs.c.ended_at.is_(None))
    )
    if not pair_row:
        return {"pair": None}

    judge_ids = json_value(pair_row["judge_ids"], [])
    mentor_rows = await database.fetch_all(
        select(assignments.c.mentor_id)
        .where(assignments.c.pair_id == pair_row["id"])
        .where(assignments.c.ended_at.is_(None))
        .order_by(assignments.c.started_at)
    )
    mentor_ids = [str(row["mentor_id"]) for row in mentor_rows]
    person_ids = set(judge_ids + mentor_ids)
    person_rows = (
        await database.fetch_all(
            select(province_judges).where(province_judges.c.judge_id.in_(person_ids))
        )
        if person_ids
        else []
    )
    people = {
        str(row["judge_id"]): {
            key: dict(row).get(key)
            for key in ("judge_id", "full_name", "province", "photo_url")
        }
        for row in person_rows
    }

    def safe_person(judge_id):
        return people.get(
            str(judge_id),
            {"judge_id": str(judge_id), "full_name": f"Sędzia {judge_id}"},
        )

    return {
        "pair": {
            "id": pair_row["id"],
            "province": pair_row["province"],
            "created_at": pair_row["created_at"],
            "judge_ids": judge_ids,
            "mentor_ids": mentor_ids,
            "judges": [safe_person(judge_id) for judge_id in judge_ids],
            "mentors": [safe_person(mentor_id) for mentor_id in mentor_ids],
        }
    }


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
        safe = {k: v for k, v in state.items() if k in {"Id", "RozgrywkiCode", "data_fakt", "data_prop", "season", "runda", "kolejka", "protocol_status", "host_swapped", "Nazwa", "Id_rozgrywki", "ID_sezon"} or k.startswith(("NrSedzia", "ID_zespoly", "Hala_", "wynik_", "dogrywka_", "karne_"))}
        safe.update({"Id": row["match_id"], "province": row["province"], "mentoringPairId": pair_id, "type": "mentoring", "isMyMatch": False})
        result.append(safe)
    result.sort(key=lambda m: str(m.get("data_fakt") or ""))
    return {"matches": result, "season": start.year, "checkedAt": now()}
