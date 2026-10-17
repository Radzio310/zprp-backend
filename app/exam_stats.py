# app/exam_stats.py
"""
Egzamin z przepisów - statystyki łączne teczki i karta sędziego (17.10.2026). Trasy cienkie.

  GET /exam-stats/overview?province=&exams=&from=&to=&bucket=&metric=&source=&rules_limit=
      przegląd egzaminów, trend, rozkład czasu pisania, najsłabsze przepisy w czasie,
      grupy (odznaki, szczebel, pary, okręgi - okręgi tylko w zakresie krajowym)
  GET /exam-stats/judges?province=&exams=&from=&to=
      sędziowie zakresu z wynikiem, trendem i miejscem ex aequo
  GET /exam-stats/judges/{judge_id}?province=&exams=&from=&to=
      karta sędziego: seria wyników, czasy, pełna historia podejść, najsłabsze przepisy

Uprawnienia jak teczka: krajowy tylko admin, okręgowy admin / komisja / Teach Master
tego okręgu. Kontrakt: BAZA/docs/egzamin-api.md. Logika: `exam_stats_service.py`,
reguły bez bazy: `exam_stats_rules.py`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from app import exam_service as S
from app import exam_stats_service as SS
from app.exams import _run, _store, _who

router = APIRouter(prefix="/exam-stats", tags=["Exams"])


async def _roster(provinces: List[str]) -> Dict[str, Any]:
    """Sędziowie, odznaki (z wirtualną „Młodzi sędziowie okręgowi"), litery uprawnień i pary
    całego zakresu - po jednym zapytaniu na tabelę, nie na okręg ani na osobę."""
    from sqlalchemy import and_, select

    from app import province_event_rules as PR
    from app import province_events as PE
    from app.assignment_context import _json_list, merge_pairs
    from app.assignment_people import name_key
    from app.db import database, province_judge_pairs, province_judges, young_referees, zprp_judge_grades
    from app.match_market_access import badge_names
    from app.settlement_province import display

    names = sorted({n for p in provinces for n in PE._names(p)})
    rows = await database.fetch_all(select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.province,
                                           province_judges.c.badges).where(province_judges.c.province.in_(names)))
    young = {S._s(r["base_judge_id"]) for r in await database.fetch_all(
        select(young_referees.c.base_judge_id).where(and_(young_referees.c.province.in_(names), young_referees.c.is_active.is_(True))))}
    keys = {name_key(r["full_name"]): S._s(r["judge_id"]) for r in rows}
    grades: Dict[str, List[str]] = {}
    if keys:
        for g in await database.fetch_all(select(zprp_judge_grades.c.name_key, zprp_judge_grades.c.letters)
                                          .where(zprp_judge_grades.c.name_key.in_(list(keys)))):
            grades[S._s(g["name_key"])] = [str(x) for x in _json_list(g["letters"])]
    people: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        jid = S._s(r["judge_id"])
        if not jid:
            continue
        badges = list(dict.fromkeys(badge_names(r["badges"])))
        if jid in young:
            badges.append(PR.YOUNG_DISTRICT_BADGE)
        people[jid] = {"name": S._s(r["full_name"]), "province": display(r["province"]) or S._s(r["province"]),
                       "badges": list(dict.fromkeys(badges)), "letters": grades.get(name_key(r["full_name"]), [])}
    pair_rows = await database.fetch_all(select(province_judge_pairs).where(province_judge_pairs.c.province.in_(names)))
    pairs, _source = merge_pairs([(S._s(p["judge_id"]), S._s(p["partner_id"]), S._s(p["source"])) for p in pair_rows])
    return {"people": people, "pairs": pairs}


def _stats_store() -> SS.StatsStore:
    return SS.StatsStore(st=_store(), roster=_roster)


def _params(exams: Optional[str], date_from: Optional[str], date_to: Optional[str], **extra: Any) -> Dict[str, Any]:
    return {"exams": exams or "", "from": date_from, "to": date_to, **extra}


@router.get("/overview", summary="Statystyki łączne teczki: egzaminy, trend, czas, przepisy, grupy")
async def overview(
    province: Optional[str] = None,
    exams: Optional[str] = Query(None, description="id egzaminów po przecinku; pusto = wszystkie z okresu"),
    date_from: Optional[str] = Query(None, alias="from"),
    date_to: Optional[str] = Query(None, alias="to"),
    bucket: str = "exam",
    metric: str = "avg_percent",
    source: str = "national",
    rules_limit: int = 6,
    who: S.Who = Depends(_who),
) -> Dict[str, Any]:
    raw = _params(exams, date_from, date_to, bucket=bucket, metric=metric, source=source, rules_limit=rules_limit)
    return await _run(SS.stats_overview(_stats_store(), who, province, raw))


@router.get("/judges", summary="Sędziowie zakresu z wynikiem i trendem (miejsca ex aequo)")
async def judges(
    province: Optional[str] = None,
    exams: Optional[str] = None,
    date_from: Optional[str] = Query(None, alias="from"),
    date_to: Optional[str] = Query(None, alias="to"),
    source: str = "national",
    who: S.Who = Depends(_who),
) -> Dict[str, Any]:
    return await _run(SS.judges_list(_stats_store(), who, province, _params(exams, date_from, date_to, source=source)))


@router.get("/judges/{judge_id}", summary="Karta sędziego: wyniki w czasie, historia podejść, najsłabsze przepisy")
async def judge(
    judge_id: str,
    province: Optional[str] = None,
    exams: Optional[str] = None,
    date_from: Optional[str] = Query(None, alias="from"),
    date_to: Optional[str] = Query(None, alias="to"),
    source: str = "national",
    who: S.Who = Depends(_who),
) -> Dict[str, Any]:
    return await _run(SS.judge_card(_stats_store(), who, judge_id, province, _params(exams, date_from, date_to, source=source)))
