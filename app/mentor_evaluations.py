"""
Oceny mentora (29.09.2026) - arkusz we wzorze arkusza delegata ZPRP,
wypełniany w aplikacji przez mentora pary.

Trasy (prefiks `/mentor-evaluations`):
  GET  /match/{match_id}          czy mogę ocenić + moja ocena + opublikowane,
  PUT  /match/{match_id}          szkic (zapis w tle z telefonu),
  POST /match/{match_id}/publish  publikacja - para widzi ocenę od tej chwili,
  GET  /province/{province}       opublikowane oceny okręgu (komisja, admin).

Reguły kto/kiedy/co w liściu `app/mentor_evaluation_rules.py`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.db import (
    database,
    mentor_evaluation_versions as versions,
    mentor_evaluations as evaluations,
    mentoring_assignments as assignments,
    mentoring_pairs as mentoring_pairs,
    province_judges,
    province_matches,
    province_mentor_pairs,
)
from app.match_market import Actor, market_actor
from app.mentor_evaluation_rules import (
    can_view_published,
    clean_sheet,
    eligibility,
    json_list,
    pair_key,
    pair_of,
    sheet_points,
)
from app.settlement_province import display as province_display, spellings

router = APIRouter(prefix="/mentor-evaluations", tags=["Mentor evaluations"])

MAX_SHEET_BYTES = 120_000


def now():
    return datetime.now(timezone.utc)


class SaveRequest(BaseModel):
    sheet: Dict[str, Any] = Field(default_factory=dict)
    together: bool = False
    co_author_id: Optional[str] = Field(default=None, max_length=40)


# ─── Dane z bazy ────────────────────────────────────────────────────────────


async def match_state(match_id: str) -> Dict[str, Any]:
    """Najświeższy stan meczu z list okręgów (mecz może leżeć w kilku)."""
    row = await database.fetch_one(
        select(province_matches.c.province, province_matches.c.season, province_matches.c.match_at, province_matches.c.state_json)
        .where(province_matches.c.match_id == str(match_id))
        .order_by(province_matches.c.active.desc(), province_matches.c.updated_at.desc())
        .limit(1)
    )
    if not row:
        raise HTTPException(404, "Nie znam tego meczu - odśwież listę meczów i spróbuj ponownie.")
    state = row["state_json"]
    if isinstance(state, str):
        try:
            state = json.loads(state)
        except ValueError:
            state = {}
    return {"province": row["province"], "season": row["season"], "match_at": row["match_at"], "state": state or {}}


async def mentors_of(pair: tuple, province: str) -> Dict[str, set]:
    """Mentorzy pary w obu systemach: program Mentoring i pary mentorskie Obsady."""
    wanted = set(pair)
    mentoring: set = set()
    rows = await database.fetch_all(
        select(mentoring_pairs.c.id, mentoring_pairs.c.judge_ids).where(mentoring_pairs.c.ended_at.is_(None))
    )
    pair_ids = [r["id"] for r in rows if set(json_list(r["judge_ids"])) == wanted]
    if pair_ids:
        links = await database.fetch_all(
            select(assignments.c.mentor_id)
            .where(assignments.c.pair_id.in_(pair_ids))
            .where(assignments.c.ended_at.is_(None))
        )
        mentoring = {str(r["mentor_id"]).strip() for r in links}
    obsada: set = set()
    board = await database.fetch_all(
        select(province_mentor_pairs.c.mentor_ids)
        .where(province_mentor_pairs.c.pair_key == pair_key(pair))
        .where(province_mentor_pairs.c.province.in_(spellings(province_display(province))))
    )
    for r in board:
        obsada |= set(json_list(r["mentor_ids"]))
    return {"mentoring": mentoring, "obsada": obsada}


async def people(ids) -> Dict[str, Dict[str, Any]]:
    ids = {str(i).strip() for i in ids if str(i or "").strip()}
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url).where(
            province_judges.c.judge_id.in_(ids)
        )
    )
    found = {str(r["judge_id"]): {"judge_id": str(r["judge_id"]), "full_name": r["full_name"], "photo_url": r["photo_url"]} for r in rows}
    return {i: found.get(i, {"judge_id": i, "full_name": f"Sędzia {i}", "photo_url": None}) for i in ids}


async def province_access(actor: Actor, province: str) -> bool:
    """Komisja / admin / VIP z dostępem do ocen okręgu - ta sama reguła co u delegatów."""
    if actor.is_admin:
        return True
    try:
        from app.delegate_evaluations import _access

        return bool((await _access(actor.judge_id, province)).get("stats"))
    except Exception:
        return False


def _loads(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


def shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]], *, working: bool) -> Dict[str, Any]:
    co = json_list(row["co_author_ids"])
    return {
        "id": row["id"],
        "match_id": row["match_id"],
        "status": row["status"],
        "source": row["source"],
        "author": names.get(row["author_id"], {"judge_id": row["author_id"], "full_name": row["author_id"]}),
        "co_authors": [names.get(c, {"judge_id": c, "full_name": c}) for c in co],
        "together": bool(co),
        # Autor dostaje wersję roboczą, reszta tylko opublikowaną.
        "sheet": _loads(row["sheet_json"] if working else row["published_json"]),
        "points": row["points"],
        "letter": row["letter"],
        "updated_at": row["updated_at"],
        "published_at": row["published_at"],
    }


async def context(match_id: str, actor: Actor) -> Dict[str, Any]:
    match = await match_state(match_id)
    state = match["state"]
    pair = pair_of(state)
    mentors = await mentors_of(pair, match["province"]) if pair else {"mentoring": set(), "obsada": set()}
    me = str(actor.judge_id)
    verdict = eligibility(
        actor_id=me,
        state=state,
        mentoring_mentor=me in mentors["mentoring"],
        obsada_mentor=me in mentors["obsada"],
    )
    co_mentors = sorted((mentors["mentoring"] | mentors["obsada"]) - {me})
    return {"match": match, "pair": pair, "mentors": mentors, "verdict": verdict, "co_mentors": co_mentors}


async def my_row(match_id: str, me: str) -> Optional[Dict[str, Any]]:
    rows = await database.fetch_all(select(evaluations).where(evaluations.c.match_id == str(match_id)))
    for r in rows:
        if r["author_id"] == me or me in json_list(r["co_author_ids"]):
            return dict(r)
    return None


# ─── Trasy ──────────────────────────────────────────────────────────────────


@router.get("/match/{match_id}")
async def for_match(match_id: str, actor: Actor = Depends(market_actor)):
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    pair = ctx["pair"] or ()
    rows = [dict(r) for r in await database.fetch_all(select(evaluations).where(evaluations.c.match_id == str(match_id)))]
    mine = next((r for r in rows if r["author_id"] == me or me in json_list(r["co_author_ids"])), None)
    is_pair_mentor = me in ctx["mentors"]["mentoring"] or me in ctx["mentors"]["obsada"]
    access = None
    published = []
    for r in rows:
        if r["status"] != "published" or not r["published_json"]:
            continue
        authors = [r["author_id"], *json_list(r["co_author_ids"])]
        if not can_view_published(actor_id=me, pair=pair, authors=authors, is_pair_mentor=is_pair_mentor, province_access=False):
            if access is None:
                access = await province_access(actor, ctx["match"]["province"])
            if not access:
                continue
        published.append(r)
    ids = set(pair) | set(ctx["co_mentors"])
    for r in rows:
        ids |= {r["author_id"], *json_list(r["co_author_ids"])}
    names = await people(ids)
    return {
        "can_rate": ctx["verdict"]["can_rate"] or mine is not None,
        "source": ctx["verdict"]["source"] or (mine["source"] if mine else None),
        "reason": ctx["verdict"]["reason"],
        "pair": [names[p] for p in pair],
        "co_mentors": [names[c] for c in ctx["co_mentors"]],
        "mine": shape(mine, names, working=True) if mine else None,
        "published": [shape(r, names, working=False) for r in published],
    }


async def save(match_id: str, req: SaveRequest, actor: Actor, publish: bool) -> Dict[str, Any]:
    raw = json.dumps(req.sheet, ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_SHEET_BYTES:
        raise HTTPException(413, "Arkusz jest za duży - skróć opisy.")
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    existing = await my_row(match_id, me)
    if not existing and not ctx["verdict"]["can_rate"]:
        raise HTTPException(403, ctx["verdict"]["reason"] or "Nie możesz ocenić tego meczu.")
    sheet = clean_sheet(req.sheet)
    points, letter = sheet_points(sheet)
    if publish and points is None:
        raise HTTPException(422, "Oceń przynajmniej jedną sekcję - ocena ogólna liczy się z liter sekcji.")
    co_ids: List[str] = []
    if req.together and req.co_author_id:
        if req.co_author_id not in ctx["co_mentors"]:
            raise HTTPException(422, "Wspólnie możesz oceniać tylko z innym mentorem tej pary.")
        co_ids = [req.co_author_id]
    body = json.dumps(sheet, ensure_ascii=False)
    stamp = now()
    match = ctx["match"]
    async with database.transaction():
        if existing:
            # Współautor nie zmienia składu autorów - robi to tylko zakładający.
            values: Dict[str, Any] = {"sheet_json": body, "points": points, "letter": letter, "updated_at": stamp}
            if existing["author_id"] == me:
                values["co_author_ids"] = json.dumps(co_ids)
            if publish:
                values.update(status="published", published_json=body, published_at=existing["published_at"] or stamp)
            await database.execute(update(evaluations).where(evaluations.c.id == existing["id"]).values(**values))
            evaluation_id = existing["id"]
        else:
            evaluation_id = uuid4().hex
            await database.execute(
                evaluations.insert().values(
                    id=evaluation_id,
                    match_id=str(match_id),
                    province=province_display(match["province"]),
                    season=match["season"],
                    match_number=str(match["state"].get("RozgrywkiCode") or ""),
                    match_at=match["match_at"],
                    pair_key=pair_key(ctx["pair"]),
                    author_id=me,
                    co_author_ids=json.dumps(co_ids),
                    source=ctx["verdict"]["source"],
                    status="published" if publish else "draft",
                    sheet_json=body,
                    published_json=body if publish else None,
                    points=points,
                    letter=letter,
                    created_at=stamp,
                    updated_at=stamp,
                    published_at=stamp if publish else None,
                )
            )
        if publish:
            await database.execute(
                versions.insert().values(
                    evaluation_id=evaluation_id, saved_by=me, sheet_json=body, points=points, letter=letter, saved_at=stamp
                )
            )
    return {"ok": True, "id": evaluation_id, "points": points, "letter": letter, "status": "published" if publish or (existing and existing["status"] == "published") else "draft"}


@router.put("/match/{match_id}")
async def save_draft(match_id: str, req: SaveRequest, actor: Actor = Depends(market_actor)):
    return await save(match_id, req, actor, publish=False)


@router.post("/match/{match_id}/publish")
async def publish(match_id: str, req: SaveRequest, actor: Actor = Depends(market_actor)):
    return await save(match_id, req, actor, publish=True)


@router.get("/province/{province}")
async def for_province(province: str, season: Optional[str] = Query(default=None), actor: Actor = Depends(market_actor)):
    """Opublikowane oceny okręgu - do ekranu „Oceny delegatów i mentorów"."""
    if not await province_access(actor, province):
        raise HTTPException(403, "Brak dostępu do ocen tego okręgu.")
    query = (
        select(evaluations)
        .where(evaluations.c.province.in_(spellings(province_display(province))))
        .where(evaluations.c.status == "published")
        .order_by(evaluations.c.match_at.desc())
    )
    if season:
        query = query.where(evaluations.c.season == season)
    rows = [dict(r) for r in await database.fetch_all(query)]
    ids = set()
    for r in rows:
        ids |= {r["author_id"], *json_list(r["co_author_ids"]), *r["pair_key"].split("|")}
    names = await people(ids)
    out = []
    for r in rows:
        item = shape(r, names, working=False)
        item["pair"] = [names[p] for p in r["pair_key"].split("|") if p in names]
        item["match_number"] = r["match_number"]
        item["match_at"] = r["match_at"]
        out.append(item)
    return {"evaluations": out}
