"""
Egzamin z przepisów - kosz teczki komisji (24.10.2026).

Egzamin albo wynik jednego sędziego trafia do kosza na `TRASH_DAYS` dni. Do tego
czasu komisja przywraca go jednym dotknięciem; potem `purge_trash` (wołane z
przejścia w tle `sweep_exam_reminders`) usuwa go trwale razem z odpowiedziami
i zdarzeniami.

Wynik w koszu znika OD RAZU ze wszystkiego, co ogląda komisja: listy teczki,
raportu, rankingu, statystyk łącznych i karty sędziego - każde z tych zapytań
ma warunek `exam_service._live` (`exam_attempts.deleted_at IS NULL`). Sędzia
w swojej aplikacji dalej widzi własne podejście (to jego arkusz) i nie dostaje
przez to drugiego podejścia - kosz nie jest furtką do poprawki.

Uprawnienia jak reszta teczki: `require_manage` okręgu egzaminu (krajowy = admin);
komisja okręgu oglądająca egzamin krajowy niczego tu nie usuwa.

Importy bazy tylko przez `Store` (app/db.py łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, case, delete, func, select, update

from app import exam_service as S
from app.exam_rules import ExamError
from app.settlement_province import DISPLAY, display

logger = logging.getLogger(__name__)

TRASH_DAYS = S.TRASH_DAYS


def _purge_at(deleted_at: Any) -> Optional[str]:
    d = S._dt(deleted_at)
    return (d + timedelta(days=TRASH_DAYS)).isoformat() if d else None


async def delete_result(st: S.Store, who: S.Who, exam_id: str, judge_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Wynik jednego sędziego do kosza: wszystkie jego podejścia w tym egzaminie."""
    now = now or S.utcnow()
    exam = await S._managed_exam(st, who, exam_id)
    jid = S._s(judge_id)
    a = st.t.attempts
    cond = and_(a.c.exam_id == exam_id, a.c.judge_id == jid, S._live(a))
    rows = await st.database.fetch_all(select(a.c.id, a.c.status).where(cond))
    if not rows:
        raise ExamError("RESULT_NOT_FOUND", "Ten sędzia nie ma w tym egzaminie wyniku, który można usunąć.", 404)
    if any(r["status"] == "in_progress" for r in rows):
        raise ExamError("RESULT_IN_PROGRESS", "Sędzia właśnie pisze ten egzamin - wynik usuniesz, gdy odda arkusz albo minie czas.", 409)
    await st.database.execute(update(a).where(cond).values(deleted_at=now, deleted_by=who.judge_id, deleted_by_name=who.name or None))
    return {"exam_id": exam_id, "exam_name": exam["name"], "judge_id": jid, "attempts": len(rows), "deleted": True,
            "purge_at": (now + timedelta(days=TRASH_DAYS)).isoformat()}


async def restore_result(st: S.Store, who: S.Who, exam_id: str, judge_id: str) -> Dict[str, Any]:
    exam = await S._exam(st, exam_id, deleted_ok=True)
    await S.require_manage(who, exam["scope"], exam.get("province"))
    a = st.t.attempts
    cond = and_(a.c.exam_id == exam_id, a.c.judge_id == S._s(judge_id), a.c.deleted_at.isnot(None))
    n = await st.database.fetch_val(select(func.count()).select_from(a).where(cond))
    if not n:
        raise ExamError("RESULT_NOT_IN_TRASH", "Tego wyniku nie ma w koszu - mógł już wrócić albo zniknąć na stałe.", 404)
    await st.database.execute(update(a).where(cond).values(deleted_at=None, deleted_by=None, deleted_by_name=None))
    return {"exam_id": exam_id, "judge_id": S._s(judge_id), "restored": True, "exam_in_trash": exam.get("deleted_at") is not None}


async def restore_exam(st: S.Store, who: S.Who, exam_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    exam = await S._exam(st, exam_id, deleted_ok=True)
    await S.require_manage(who, exam["scope"], exam.get("province"))
    if exam.get("deleted_at") is None:
        raise ExamError("EXAM_NOT_IN_TRASH", "Ten egzamin nie leży w koszu.", 409)
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam_id).values(
        deleted_at=None, deleted_by=None, deleted_by_name=None, updated_at=now))
    # Wydarzenia okręgowe egzaminu wracają z kosza okręgu razem z nim.
    await S._trash_events(st, exam, now, restore=True)
    exam["deleted_at"] = None
    return {**S.exam_view(exam, now, full=True), "restored": True}


def _scope(who: S.Who, province: Optional[str]) -> Tuple[str, Optional[str]]:
    scope = "province" if province or not who.is_admin else "national"
    prov = display(province or who.province) if scope == "province" else None
    if scope == "province" and (not prov or prov not in DISPLAY.values()):
        raise ExamError("BAD_CONFIG", "Podaj okręg, którego kosz chcesz zobaczyć.")
    return scope, prov


async def _people_all(st: S.Store, exam_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Osoby i najlepsze wyniki egzaminów w koszu - razem z wynikami, które same leżą w koszu."""
    if not exam_ids:
        return {}
    a = st.t.attempts
    done = a.c.status.in_(S._FINISHED)
    rows = await st.database.fetch_all(select(
        a.c.exam_id.label("exam_id"), a.c.judge_id.label("judge_id"),
        func.max(case((done, a.c.percent), else_=None)).label("best"),
    ).where(a.c.exam_id.in_(exam_ids)).group_by(a.c.exam_id, a.c.judge_id))
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        m = S._row(r)
        agg = out.setdefault(m["exam_id"], {"judges": set(), "best": []})
        agg["judges"].add(S._s(m["judge_id"]))
        if m["best"] is not None:
            agg["best"].append(float(m["best"]))
    return out


async def trash_list(st: S.Store, who: S.Who, province: Optional[str], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Kosz teczki: usunięte egzaminy i wyniki z ostatnich 30 dni, z datą trwałego usunięcia."""
    now = now or S.utcnow()
    scope, prov = _scope(who, province)
    await S.require_manage(who, scope, prov)
    d, a = st.t.definitions, st.t.attempts
    where_scope = d.c.scope == "national" if scope == "national" else and_(d.c.scope == "province", d.c.province == prov)
    since = now - timedelta(days=TRASH_DAYS)
    exam_rows, result_rows = await asyncio.gather(
        st.database.fetch_all(select(d).where(and_(where_scope, d.c.deleted_at.isnot(None), d.c.deleted_at > since))
                              .order_by(d.c.deleted_at.desc())),
        st.database.fetch_all(
            select(a.c.exam_id, a.c.judge_id, a.c.judge_name, a.c.province, a.c.percent, a.c.passed, a.c.deleted_at,
                   a.c.deleted_by_name, d.c.name.label("exam_name"))
            .select_from(a.join(d, d.c.id == a.c.exam_id))
            .where(and_(where_scope, d.c.deleted_at.is_(None), a.c.deleted_at.isnot(None), a.c.deleted_at > since))
            .order_by(a.c.deleted_at.desc())))
    exam_list = [S._row(r) for r in exam_rows]
    people = await _people_all(st, [e["id"] for e in exam_list])
    exams = []
    for e in exam_list:
        config = S._loads(e["config_json"], {})
        p = people.get(e["id"]) or {}
        best = p.get("best") or []
        exams.append({"id": e["id"], "name": e["name"], "scope": e["scope"], "province": e.get("province"),
                      "window_start": config.get("window_start"), "window_end": config.get("window_end"),
                      "pass_percent": config.get("pass_percent"),
                      "deleted_at": S._iso(e["deleted_at"]), "purge_at": _purge_at(e["deleted_at"]),
                      "deleted_by_name": e.get("deleted_by_name"), "people": len(p.get("judges") or ()),
                      "finished": len(best), "avg_percent": round(sum(best) / len(best), 2) if best else None})
    results: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for raw in result_rows:
        r = S._row(raw)
        key = (r["exam_id"], S._s(r["judge_id"]))
        pct = r.get("percent")
        cur = results.get(key)
        if cur is None:
            results[key] = {"exam_id": r["exam_id"], "exam_name": r["exam_name"], "judge_id": S._s(r["judge_id"]),
                            "judge_name": r.get("judge_name"), "province": r.get("province"),
                            "percent": float(pct) if pct is not None else None, "passed": bool(r.get("passed")),
                            "attempts": 1, "deleted_at": S._iso(r["deleted_at"]), "purge_at": _purge_at(r["deleted_at"]),
                            "deleted_by_name": r.get("deleted_by_name")}
        else:
            cur["attempts"] += 1
            if pct is not None and (cur["percent"] is None or float(pct) > cur["percent"]):
                cur["percent"], cur["passed"] = float(pct), bool(r.get("passed"))
    return {"scope": scope, "province": prov, "days": TRASH_DAYS, "server_now": now.isoformat(),
            "exams": exams, "results": list(results.values())}


async def _purge_attempts(st: S.Store, attempt_ids: List[str]) -> None:
    if not attempt_ids:
        return
    t = st.t
    await st.database.execute(delete(t.answers).where(t.answers.c.attempt_id.in_(attempt_ids)))
    await st.database.execute(delete(t.events).where(t.events.c.attempt_id.in_(attempt_ids)))
    await st.database.execute(delete(t.attempts).where(t.attempts.c.id.in_(attempt_ids)))


async def purge_trash(st: S.Store, now: Optional[datetime] = None) -> Dict[str, int]:
    """Po 30 dniach w koszu: egzamin z podejściami, odpowiedziami i zdarzeniami znika trwale;
    tak samo pojedynczy wynik. Wydarzenie okręgowe egzaminu zostaje w koszu okręgu (jego reguły)."""
    now = now or S.utcnow()
    t = st.t
    cutoff = now - timedelta(days=TRASH_DAYS)
    gone_exams = [r["id"] for r in await st.database.fetch_all(
        select(t.definitions.c.id).where(and_(t.definitions.c.deleted_at.isnot(None), t.definitions.c.deleted_at <= cutoff)).limit(100))]
    exam_attempts = [r["id"] for r in await st.database.fetch_all(
        select(t.attempts.c.id).where(t.attempts.c.exam_id.in_(gone_exams)))] if gone_exams else []
    lone = [r["id"] for r in await st.database.fetch_all(
        select(t.attempts.c.id).where(and_(t.attempts.c.deleted_at.isnot(None), t.attempts.c.deleted_at <= cutoff)).limit(2000))]
    ids = list(dict.fromkeys(exam_attempts + lone))
    if not gone_exams and not ids:
        return {"exams": 0, "attempts": 0}
    async with st.database.transaction():
        await _purge_attempts(st, ids)
        if gone_exams:
            await st.database.execute(delete(t.events).where(t.events.c.exam_id.in_(gone_exams)))
            await st.database.execute(delete(t.reminders).where(t.reminders.c.exam_id.in_(gone_exams)))
            await st.database.execute(delete(t.definitions).where(t.definitions.c.id.in_(gone_exams)))
    logger.info("egzamin: kosz teczki - trwale usunięto %s egzaminów i %s podejść", len(gone_exams), len(ids))
    return {"exams": len(gone_exams), "attempts": len(ids)}
