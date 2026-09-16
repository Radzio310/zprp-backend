"""
Analiza obsad - karta „Analiza" w module obsadowym (BAZA_web).

Decyzje użytkownika z 16.09.2026:
  - dane: archiwum meczów okręgu (`app/zprp_archive.py`) - te same sezony,
    z których żyją Statystyki; plus oceny delegatów i ręczne oznaczenia,
  - liczone nocą: fakty o meczach (składniki trudności) powstają po każdej
    budowie archiwum i raz na dobę; podgląd z innymi wagami składa się z nich
    od ręki (reguły: `app/insights_rules.py`),
  - wnioski tylko podglądane; obsadowy wybiera, których Automat ma się
    nauczyć (`app/insights_policy.py`), punkty albo twarda zasada,
  - widzi każdy, kto ma dostęp do panelu obsadowego.

OCENY DELEGATÓW (decyzja z 16.09.2026): w BAZA_web widzą je tylko admin i konta
VIP z uprawnieniem „Oceny delegatów”. Arkusze liczą się do trudności meczu dla
wszystkich, ale średnie ocen i słowa delegata dostaje tylko uprawniony token
(`can_view_province_evaluations`). Dlatego każda trasa wymaga logowania.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
from collections import OrderedDict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import insights_policy as P
from app import insights_rules as I
from app.assignment_scope import current_start
from app.delegate_evaluations import can_view_province_evaluations
from app.deps import get_jwt_payload
from app.db import (
    database,
    delegate_evaluations,
    province_insight_facts,
    province_insight_rules,
    province_insight_settings,
    province_match_difficulty,
    young_referees,
    zprp_archive_officials,
    zprp_archive_seasons,
)
from app.province_settlements import require_province
from app.settlement_province import spellings
from app.zprp_seasons import season_catalog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/assignment/insights", tags=["province_assignment_insights"])

#: Fakty starsze niż to liczymy od nowa, nawet gdy archiwum się nie zmieniło
#: (oznaczenia i oceny delegatów dochodzą w ciągu dnia).
FACTS_MAX_AGE = timedelta(hours=24)
#: Odczekanie po budowie archiwum - kilka sezonów kończy się jeden po drugim.
RECOMPUTE_DELAY = 90
ANALYSIS_CACHE = 24

_facts: Dict[str, Tuple[datetime, List[I.Fact]]] = {}
_analysis: "OrderedDict[Tuple, dict]" = OrderedDict()
_pending: set[str] = set()
_computing: set[str] = set()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


# ---------------------------------------------------------------------------
# Źródła
# ---------------------------------------------------------------------------


async def _archive_seasons(province: str) -> Dict[int, List[dict]]:
    """Mecze każdego zbudowanego sezonu - z gotowej paczki archiwum."""
    rows = await database.fetch_all(
        select(zprp_archive_seasons.c.season_start, zprp_archive_seasons.c.payload_gz).where(
            and_(zprp_archive_seasons.c.province == province, zprp_archive_seasons.c.payload_gz.is_not(None))
        )
    )
    out: Dict[int, List[dict]] = {}
    for row in rows:
        try:
            payload = json.loads(gzip.decompress(bytes(row["payload_gz"])))
        except Exception:
            continue
        out[int(row["season_start"])] = payload.get("matches") or []
    return out


async def _marks(province: str) -> Dict[str, str]:
    rows = await database.fetch_all(
        select(province_match_difficulty.c.match_id, province_match_difficulty.c.mark).where(
            province_match_difficulty.c.province == province
        )
    )
    return {_s(row["match_id"]): _s(row["mark"]) for row in rows}


async def _evaluations(province: str) -> Dict[str, List[dict]]:
    rows = await database.fetch_all(
        select(
            delegate_evaluations.c.match_id,
            delegate_evaluations.c.referee_ids,
            delegate_evaluations.c.evaluation_json,
        ).where(delegate_evaluations.c.province.in_(spellings(province)))
    )
    out: Dict[str, List[dict]] = {}
    for row in rows:
        out.setdefault(_s(row["match_id"]), []).append(
            {"referee_ids": _json(row["referee_ids"]) or [], "evaluation_json": _json(row["evaluation_json"]) or {}}
        )
    return out


def _fact_from(item: Mapping[str, Any]) -> I.Fact:
    data = dict(item)
    for key in ("field", "table", "delegate"):
        data[key] = tuple(data.get(key) or ())
    return I.Fact(**data)


async def recompute_facts(province: str) -> Tuple[datetime, List[I.Fact]]:
    """Fakty o meczach z archiwum, ocen i oznaczeń - drogie, więc nocą i po budowie."""
    if province in _computing:
        return _facts.get(province) or (_now(), [])
    _computing.add(province)
    try:
        seasons = await _archive_seasons(province)
        facts = I.build_facts(seasons, marks=await _marks(province), evaluations=await _evaluations(province))
        stamp = _now()
        packed = gzip.compress(
            json.dumps([asdict(fact) for fact in facts], ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            mtime=0,
        )
        statement = pg_insert(province_insight_facts).values(
            province=province,
            facts_gz=packed,
            matches=len(facts),
            seasons=",".join(str(year) for year in sorted(seasons)),
            computed_at=stamp,
        )
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[province_insight_facts.c.province],
                set_={
                    "facts_gz": packed,
                    "matches": len(facts),
                    "seasons": ",".join(str(year) for year in sorted(seasons)),
                    "computed_at": stamp,
                },
            )
        )
        _facts[province] = (stamp, facts)
        for key in [key for key in _analysis if key[0] == province]:
            _analysis.pop(key, None)
        logger.info("[insights] %s: %d faktów z %d sezonów", province, len(facts), len(seasons))
        return stamp, facts
    finally:
        _computing.discard(province)


async def load_facts(province: str) -> Tuple[Optional[datetime], List[I.Fact]]:
    cached = _facts.get(province)
    if cached:
        return cached
    row = await database.fetch_one(
        select(province_insight_facts.c.facts_gz, province_insight_facts.c.computed_at).where(
            province_insight_facts.c.province == province
        )
    )
    if row:
        try:
            items = json.loads(gzip.decompress(bytes(row["facts_gz"])))
            loaded = (row["computed_at"], [_fact_from(item) for item in items])
            _facts[province] = loaded
            return loaded
        except Exception:
            logger.exception("[insights] %s: uszkodzone fakty - liczę od nowa", province)
    if await database.fetch_one(
        select(zprp_archive_seasons.c.season_id).where(
            and_(zprp_archive_seasons.c.province == province, zprp_archive_seasons.c.payload_gz.is_not(None))
        )
    ):
        return await recompute_facts(province)
    return None, []


async def _people(province: str) -> Dict[str, I.Person]:
    from app.assignment_context import load_roster

    roster = await load_roster(province)
    young_rows = await database.fetch_all(
        select(young_referees.c.base_judge_id, young_referees.c.full_name).where(
            and_(young_referees.c.province.in_(spellings(province)), young_referees.c.is_active.is_(True))
        )
    )
    young_ids = {_s(row["base_judge_id"]) for row in young_rows if _s(row["base_judge_id"])}
    young_names = {I.team_key(row["full_name"]) for row in young_rows}
    young_names_sorted = {" ".join(sorted(name.split())) for name in young_names}
    people: Dict[str, I.Person] = {}
    for judge_id, judge in roster.judges.items():
        key = " ".join(sorted(I.team_key(judge.name).split()))
        people[judge_id] = I.Person(
            judge_id=judge_id,
            name=judge.name,
            young=judge.young or judge_id in young_ids or key in young_names_sorted,
            league=judge.league,
            letters=tuple(sorted(judge.letters)),
        )
    return people


async def _names(province: str) -> Dict[str, str]:
    """Nazwiska spoza obecnej listy (partnerzy, którzy odeszli) - z archiwum."""
    row = await database.fetch_one(
        select(zprp_archive_officials.c.officials_json).where(zprp_archive_officials.c.province == province)
    )
    officials = _json(row["officials_json"]) if row else None
    return {key: _s(value.get("name")) for key, value in (officials or {}).items() if isinstance(value, dict)}


async def saved_weights(province: str) -> Dict[str, int]:
    row = await database.fetch_one(
        select(province_insight_settings.c.weights_json).where(province_insight_settings.c.province == province)
    )
    return I.normalize_weights(_json(row["weights_json"]) if row else None)


async def saved_rules(province: str) -> Dict[str, dict]:
    rows = await database.fetch_all(select(province_insight_rules).where(province_insight_rules.c.province == province))
    out: Dict[str, dict] = {}
    for row in rows:
        out[_s(row["rule_key"])] = P.normalize_rule(
            {
                "enabled": row["enabled"],
                "mode": row["mode"],
                "strength": row["strength"],
                "params": _json(row["params_json"]) or {},
            }
        )
    return out


def _horizon(value: Any) -> str:
    text = _s(value) or "5"
    return text if text in I.HORIZONS else "5"


async def analysis_for(province: str, horizon: str, weights: Mapping[str, int]) -> dict:
    computed_at, facts = await load_facts(province)
    catalog = await season_catalog()
    current = current_start(catalog, _now().date())
    key = (province, horizon, tuple(weights.get(name, 0) for name in I.COMPONENTS), computed_at.isoformat() if computed_at else "")
    if key in _analysis:
        _analysis.move_to_end(key)
        return _analysis[key]
    result = I.analyze(
        facts,
        people=await _people(province),
        names=await _names(province),
        weights=weights,
        horizon=horizon,
        current=current,
    )
    result["meta"]["computed_at"] = computed_at.isoformat() if computed_at else None
    result["meta"]["archive_empty"] = not facts
    _analysis[key] = result
    while len(_analysis) > ANALYSIS_CACHE:
        _analysis.popitem(last=False)
    return result


# ---------------------------------------------------------------------------
# Dla Automatu
# ---------------------------------------------------------------------------


async def policy_for(province: str) -> Tuple[Optional[P.Policy], Dict[str, int], Optional[dict]]:
    """Wybrane wnioski gotowe dla Automatu. `None`, gdy nic nie wybrano."""
    rules = await saved_rules(province)
    if not any(rule.get("enabled") for rule in rules.values()):
        return None, {}, None
    weights = await saved_weights(province)
    analysis = await analysis_for(province, "5", weights)
    _, facts = await load_facts(province)
    current = max((fact.season for fact in facts), default=None)
    field = [
        (judge, fact.home, fact.away)
        for fact in facts
        if fact.season == current
        for judge in fact.field
    ]
    return P.build_policy(analysis, rules, current_season_field=field), weights, analysis


async def annotate_needs(province: str, items: Iterable[Tuple[Any, Mapping[str, Any]]], weights: Mapping[str, int]) -> None:
    """Przewidywana trudność meczów do obsadzenia (bez protokołu).

    `items` to pary (MatchNeed, stan meczu z migawki). Tabela i derby liczą się
    z bieżącego sezonu archiwum, oznaczenia obsadowego - z bazy.
    """
    seasons = await _archive_seasons(province)
    current = max(seasons) if seasons else None
    matches = seasons.get(current, []) if current is not None else []
    cities = I.team_cities(m for m in matches if m.get("origin") == "district")
    positions: Dict[str, Tuple[Optional[int], Optional[int], int, float]] = {}
    tables: Dict[Tuple[str, str], List[dict]] = {}
    for match in matches:
        tables.setdefault((_s(match.get("comp")), _s(match.get("round"))), []).append(match)
    for rows in tables.values():
        positions.update(I.standings_positions(rows))
    marks = await _marks(province)
    for need, state in items:
        value, why = I.predicted_difficulty(
            code=need.code,
            round_text=state.get("Runda") or state.get("runda"),
            series_text=state.get("Kolejka"),
            home=need.host,
            away=need.guest,
            cities=cities,
            positions=positions.get(_s(need.match_id)),
            mark=marks.get(_s(need.match_id)),
            weights=weights,
        )
        tier, category = I.tier_component(need.code)
        need.difficulty = round(value, 3)
        need.difficulty_why = why
        need.tier = tier
        need.category = category


# ---------------------------------------------------------------------------
# Harmonogram
# ---------------------------------------------------------------------------


def schedule_recompute(province: str) -> None:
    """Po budowie archiwum - z odczekaniem, bo sezony kończą się jeden po drugim."""
    if province in _pending:
        return
    _pending.add(province)

    async def job() -> None:
        try:
            await asyncio.sleep(RECOMPUTE_DELAY)
            await recompute_facts(province)
        except Exception:
            logger.exception("[insights] %s: przeliczenie po archiwum", province)
        finally:
            _pending.discard(province)

    asyncio.create_task(job())


async def run_insights_scheduler() -> None:
    """Raz na trzy godziny: fakty starsze niż doba albo archiwum nowsze niż fakty."""
    await asyncio.sleep(300)
    while True:
        try:
            from app.province_settlement_sync import enabled_provinces

            for province in await enabled_provinces("stats"):
                row = await database.fetch_one(
                    select(province_insight_facts.c.computed_at).where(province_insight_facts.c.province == province)
                )
                built = await database.fetch_one(
                    select(zprp_archive_seasons.c.built_at)
                    .where(zprp_archive_seasons.c.province == province)
                    .order_by(zprp_archive_seasons.c.built_at.desc().nulls_last())
                    .limit(1)
                )
                if not built or not built["built_at"]:
                    continue
                computed = row["computed_at"] if row else None
                if computed is None or computed < built["built_at"] or _now() - computed > FACTS_MAX_AGE:
                    await recompute_facts(province)
        except Exception:
            logger.exception("[insights] pętla harmonogramu")
        await asyncio.sleep(3 * 3600)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _rules_view(saved: Mapping[str, dict], analysis: Mapping[str, Any]) -> Dict[str, dict]:
    """Stan każdego wniosku: zapisany wybór albo domyślne „wyłączony, punkty 50"."""
    out: Dict[str, dict] = {}
    for key in P.RULE_KEYS:
        rule = dict(saved.get(key) or P.normalize_rule({}))
        conclusion = next((item for item in analysis.get("conclusions") or [] if item.get("key") == key), None)
        rule["available"] = conclusion is not None
        rule["suggested"] = ((conclusion or {}).get("rule") or {}).get("params", {})
        out[key] = rule
    return out


@router.get("", summary="Analiza obsad okręgu z zapisanymi wagami")
async def insights(
    province: str = Query(...), horizon: str = Query("5"), token: dict = Depends(get_jwt_payload)
):
    key = require_province(province)
    weights = await saved_weights(key)
    analysis = await analysis_for(key, _horizon(horizon), weights)
    marks = await _marks(key)
    visible = await can_view_province_evaluations(token, key)
    return {
        "province": key,
        "weights": weights,
        "default_weights": I.DEFAULT_WEIGHTS,
        "rules": _rules_view(await saved_rules(key), analysis),
        "marks": len(marks),
        "computing": key in _computing or key in _pending,
        "evaluations_visible": visible,
        **(analysis if visible else I.hide_evaluations(analysis)),
    }


@router.get("/rules", summary="Wnioski wybrane dla Automatu (bez liczenia analizy)")
async def rules_only(province: str = Query(...), token: dict = Depends(get_jwt_payload)):
    key = require_province(province)
    saved = await saved_rules(key)
    return {
        "province": key,
        "rules": {rule_key: saved[rule_key] for rule_key in P.RULE_KEYS if rule_key in saved},
        "enabled": sum(1 for rule in saved.values() if rule.get("enabled")),
    }


class PreviewRequest(BaseModel):
    province: str
    horizon: str = "5"
    weights: Dict[str, Any] = {}


@router.post("/preview", summary="Podgląd analizy z innymi wagami (bez zapisu)")
async def preview(payload: PreviewRequest, token: dict = Depends(get_jwt_payload)):
    key = require_province(payload.province)
    analysis = await analysis_for(key, _horizon(payload.horizon), I.normalize_weights(payload.weights))
    visible = await can_view_province_evaluations(token, key)
    return {"evaluations_visible": visible, **(analysis if visible else I.hide_evaluations(analysis))}


class WeightsRequest(BaseModel):
    province: str
    weights: Dict[str, Any]
    updated_by: Optional[str] = None


@router.put("/weights", summary="Zapisz wagi składników trudności")
async def save_weights(payload: WeightsRequest, token: dict = Depends(get_jwt_payload)):
    key = require_province(payload.province)
    weights = I.normalize_weights(payload.weights)
    statement = pg_insert(province_insight_settings).values(
        province=key, weights_json=weights, updated_by=_s(payload.updated_by) or None, updated_at=_now()
    )
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[province_insight_settings.c.province],
            set_={"weights_json": weights, "updated_by": _s(payload.updated_by) or None, "updated_at": _now()},
        )
    )
    return {"success": True, "weights": weights}


class RuleRequest(BaseModel):
    province: str
    enabled: bool
    mode: str = "points"
    strength: int = 50
    params: Dict[str, Any] = {}
    updated_by: Optional[str] = None


@router.put("/rules/{rule_key}", summary="Wniosek dla Automatu: włącz, punkty albo twarda zasada")
async def save_rule(rule_key: str, payload: RuleRequest, token: dict = Depends(get_jwt_payload)):
    key = require_province(payload.province)
    if rule_key not in P.RULE_KEYS:
        raise HTTPException(404, detail={"code": "UNKNOWN_RULE", "message": "Nie znam takiego wniosku"})
    rule = P.normalize_rule(payload.model_dump())
    values = {
        "enabled": rule["enabled"],
        "mode": rule["mode"],
        "strength": rule["strength"],
        "params_json": rule["params"],
        "updated_by": _s(payload.updated_by) or None,
        "updated_at": _now(),
    }
    statement = pg_insert(province_insight_rules).values(province=key, rule_key=rule_key, **values)
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[province_insight_rules.c.province, province_insight_rules.c.rule_key],
            set_=values,
        )
    )
    return {"success": True, "rule": rule}


def _weights_from_query(raw: Optional[str], fallback: Mapping[str, int]) -> Dict[str, int]:
    if not raw:
        return dict(fallback)
    parts = [part for part in raw.split(",")]
    if len(parts) != len(I.COMPONENTS):
        return dict(fallback)
    return I.normalize_weights(dict(zip(I.COMPONENTS, parts)))


@router.get("/judge/{judge_id}", summary="Mecze sędziego z trudnością i powodami")
async def judge_detail(
    judge_id: str,
    province: str = Query(...),
    horizon: str = Query("5"),
    weights: Optional[str] = Query(None, description="tier,stake,protocol,manual"),
    token: dict = Depends(get_jwt_payload),
):
    key = require_province(province)
    chosen = _weights_from_query(weights, await saved_weights(key))
    analysis = await analysis_for(key, _horizon(horizon), chosen)
    _, facts = await load_facts(key)
    matches = I.judge_matches(
        facts,
        _s(judge_id),
        weights=chosen,
        threshold=analysis["meta"]["hard_threshold"],
        seasons=analysis["meta"]["seasons"],
    )
    marks = await _marks(key)
    for item in matches:
        item["mark"] = marks.get(item["id"])
    profile = next((item for item in analysis["judges"] if item["judge_id"] == _s(judge_id)), None)
    visible = await can_view_province_evaluations(token, key)
    if not visible:
        profile = I.hide_judge_evaluations(profile)
        matches = I.hide_match_evaluations(matches)
    return {
        "province": key,
        "judge": profile,
        "matches": matches,
        "meta": analysis["meta"],
        "evaluations_visible": visible,
    }


class MatchesRequest(BaseModel):
    province: str
    ids: List[str]
    horizon: str = "5"
    weights: Dict[str, Any] = {}


@router.post("/matches", summary="Mecze-dowody wniosku (trudność i powody)")
async def matches(payload: MatchesRequest, token: dict = Depends(get_jwt_payload)):
    key = require_province(payload.province)
    weights = I.normalize_weights(payload.weights) if payload.weights else await saved_weights(key)
    analysis = await analysis_for(key, _horizon(payload.horizon), weights)
    _, facts = await load_facts(key)
    wanted = {_s(item) for item in payload.ids[:300]}
    names = await _names(key)
    people = await _people(key)
    marks = await _marks(key)
    out = []
    for fact in facts:
        if fact.id not in wanted:
            continue
        value = I.weighted(fact.components(), weights)
        out.append(
            {
                "id": fact.id,
                "season": fact.season,
                "ts": fact.ts,
                "code": fact.code,
                "category": fact.category,
                "home": fact.home,
                "away": fact.away,
                "difficulty": round(value, 3),
                "hard": value >= analysis["meta"]["hard_threshold"],
                "components": fact.components(),
                "why": fact.why,
                "grade": fact.grade,
                "mark": marks.get(fact.id),
                "field": [
                    {"judge_id": judge, "name": (people.get(judge).name if people.get(judge) else names.get(judge, judge))}
                    for judge in fact.field
                ],
            }
        )
    out.sort(key=lambda item: -(item["ts"] or 0))
    visible = await can_view_province_evaluations(token, key)
    return {
        "province": key,
        "matches": out if visible else I.hide_match_evaluations(out),
        "hard_threshold": analysis["meta"]["hard_threshold"],
        "evaluations_visible": visible,
    }


class MarkRequest(BaseModel):
    province: str
    mark: Optional[str] = None
    note: Optional[str] = None
    created_by: Optional[str] = None


@router.put("/marks/{match_id}", summary="Oznacz mecz jako trudny albo łatwy (pusty znak zdejmuje)")
async def set_mark(match_id: str, payload: MarkRequest, token: dict = Depends(get_jwt_payload)):
    key = require_province(payload.province)
    mark = _s(payload.mark).lower()
    if mark and mark not in ("hard", "easy"):
        raise HTTPException(400, detail={"code": "BAD_MARK", "message": 'Znak to „hard”, „easy” albo pusto'})
    if not mark:
        await database.execute(
            delete(province_match_difficulty).where(
                and_(province_match_difficulty.c.province == key, province_match_difficulty.c.match_id == _s(match_id))
            )
        )
    else:
        values = {"mark": mark, "note": _s(payload.note) or None, "created_by": _s(payload.created_by) or None, "created_at": _now()}
        statement = pg_insert(province_match_difficulty).values(province=key, match_id=_s(match_id), **values)
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[province_match_difficulty.c.province, province_match_difficulty.c.match_id],
                set_=values,
            )
        )
    # Oznaczenie działa w podglądzie od razu: poprawiamy fakt w pamięci, a pełne
    # przeliczenie (z oceną delegata pod spodem) idzie w tle.
    cached = _facts.get(key)
    if cached:
        for fact in cached[1]:
            if fact.id == _s(match_id):
                fact.manual, label = I.manual_component(mark or None, None)
                fact.why["manual"] = [label] if label else []
        for cache_key in [item for item in _analysis if item[0] == key]:
            _analysis.pop(cache_key, None)
    schedule_recompute(key)
    return {"success": True, "mark": mark or None}


@router.get("/marks", summary="Mecze oznaczone ręcznie")
async def list_marks(province: str = Query(...), token: dict = Depends(get_jwt_payload)):
    key = require_province(province)
    rows = await database.fetch_all(
        select(province_match_difficulty).where(province_match_difficulty.c.province == key)
    )
    return {
        "province": key,
        "marks": [
            {
                "match_id": _s(row["match_id"]),
                "mark": _s(row["mark"]),
                "note": _s(row["note"]),
                "created_by": _s(row["created_by"]),
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            }
            for row in rows
        ],
    }


class RecomputeRequest(BaseModel):
    province: str


@router.post("/recompute", summary="Przelicz fakty z archiwum (w tle)")
async def recompute(payload: RecomputeRequest, token: dict = Depends(get_jwt_payload)):
    key = require_province(payload.province)
    if key in _computing:
        return {"started": False, "computing": True}
    asyncio.create_task(recompute_facts(key))
    return {"started": True, "computing": True}
