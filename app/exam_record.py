# app/exam_record.py
"""
Kartoteka sędziego (24.10.2026) - dane z bazy. Reguły: `exam_record_rules.py`.

  GET /exam-stats/me/record                         sędzia o sobie (bez prawa teczki)
  GET /exam-stats/judges/{judge_id}/record?province= komisja, bramka teczki (`resolve_scope`)

Trasy są w `app/exam_stats.py` (ten sam router). Filtr kosza: tylko egzaminy poza
koszem i wyniki poza koszem (`deleted_at IS NULL`) - u sędziego i u komisji tak samo.
Zapytania: podejścia osoby (1), egzaminy (1), zdarzenia jej podejść (1), średnie
egzaminów (1), banki raz na wersję (pamięć procesu). Bez N+1.

Importy bazy tylko przez `Store` albo w funkcji (app/db.py łączy się przy imporcie).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from sqlalchemy import and_, select

from app import exam_record_rules as RC
from app import exam_rules as X
from app import exam_service as S
from app import exam_stats_service as SS
from app.exam_rules import ExamError
from app.settlement_province import display


async def _exam_rows(st: S.Store, exam_ids: List[str], now: datetime) -> Dict[str, Dict[str, Any]]:
    if not exam_ids:
        return {}
    d = st.t.definitions
    out: Dict[str, Dict[str, Any]] = {}
    for raw in await st.database.fetch_all(select(d).where(and_(d.c.id.in_(exam_ids), d.c.deleted_at.is_(None)))):
        e = S._row(raw)
        e["config"] = S._loads(e["config_json"], {})
        e["opens_at"], e["closes_at"] = S._dt(e["opens_at"]), S._dt(e["closes_at"])
        out[e["id"]] = e
    return out


async def _violations(st: S.Store, attempt_ids: List[str]) -> Dict[str, int]:
    if not attempt_ids:
        return {}
    ev = st.t.events
    per: Dict[str, List[Dict[str, Any]]] = {}
    for raw in await st.database.fetch_all(select(ev.c.attempt_id, ev.c.kind).where(ev.c.attempt_id.in_(attempt_ids))):
        r = S._row(raw)
        per.setdefault(r["attempt_id"], []).append({"kind": r["kind"]})
    return {aid: X.violation_count(rows) for aid, rows in per.items()}


async def _scope_rows(st: S.Store, exam_ids: List[str]) -> List[Dict[str, Any]]:
    if not exam_ids:
        return []
    a = st.t.attempts
    rows = await st.database.fetch_all(select(a.c.exam_id, a.c.judge_id, a.c.province, a.c.percent).where(and_(
        a.c.exam_id.in_(exam_ids), a.c.status.in_(RC.FINISHED), S._live(a))))
    return [S._row(r) for r in rows]


def _rule_lookup(qinfo: Mapping[str, Mapping[str, Any]]):
    def rule_of(exam_id: str, qid: str) -> Any:
        return ((qinfo.get(exam_id) or {}).get(qid) or (None, None))[0]
    return rule_of


async def my_record(ss: SS.StatsStore, who: S.Who, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    st = ss.st
    jid = S._s(who.judge_id)
    if not jid:
        raise ExamError("NOT_IN_ROSTER", "Kartoteka egzaminów wymaga konta sędziego z numerem.", 403)
    attempts = await _attempts_of(st, jid)
    exams = await _exam_rows(st, sorted({a["exam_id"] for a in attempts}), now)
    attempts = [a for a in attempts if a["exam_id"] in exams]
    ids = [a["id"] for a in attempts]
    violations = await _violations(st, ids)
    avgs = RC.scope_averages(await _scope_rows(st, list(exams)))
    qinfo = await SS._qinfo(st, list(exams.values()))
    prov = display(who.province) if who.province else None
    # Zdjęcie z listy okręgu (to samo źródło co teczka); lista nie jest warunkiem kartoteki.
    person: Mapping[str, Any] = {}
    if prov:
        try:
            person = ((await ss.roster([prov])).get("people") or {}).get(jid) or {}
        except Exception:  # noqa: BLE001 - zdjęcie to ozdoba, kartoteka działa bez niego
            person = {}
    name = S._s(person.get("name")) or next((a.get("judge_name") for a in attempts if a.get("judge_name")), None) or who.name or jid
    judge = {"judge_id": jid, "name": name, "province": prov, "photo": person.get("photo")}
    return RC.build_record(judge, exams, attempts, viewer="self", now=now, violations=violations,
                           scope_avgs=avgs, rule_of=_rule_lookup(qinfo))


async def _attempts_of(st: S.Store, judge_id: str) -> List[Dict[str, Any]]:
    a = st.t.attempts
    q = select(a.c.id, a.c.exam_id, a.c.judge_id, a.c.judge_name, a.c.province, a.c.attempt_no, a.c.status,
               a.c.finish_reason, a.c.started_at, a.c.finished_at, a.c.percent, a.c.passed, a.c.score_json, a.c.time_json
               ).where(and_(a.c.judge_id == judge_id, S._live(a)))
    out = []
    for raw in await st.database.fetch_all(q):
        r = S._row(raw)
        r["score"] = S._loads(r.pop("score_json", None), None) or {}
        r["started_at"], r["finished_at"] = S._dt(r["started_at"]), S._dt(r["finished_at"])
        out.append(r)
    await S.fill_attempt_times(st, out)
    return out


async def judge_record(ss: SS.StatsStore, who: S.Who, judge_id: str, province: Optional[str],
                       now: Optional[datetime] = None) -> Dict[str, Any]:
    """Kartoteka dla komisji: egzaminy teczki (zakres jak statystyki), wyniki poza koszem."""
    now = now or S.utcnow()
    jid = S._s(judge_id)
    raw = {"exams": "", "from": None, "to": None, "source": "all"}
    _filters, scope, prov, _catalog, exams, people, _pairs = await SS._load(ss, who, province, raw, now)
    ids = [e["id"] for e in exams]
    attempts = SS._cut_attempts(await SS._attempts(ss.st, ids, judge_id=jid), exams, scope, prov, who)
    if jid not in people and not attempts:
        raise ExamError("STATS_JUDGE_UNKNOWN", "Tego sędziego nie ma na liście okręgu ani wśród zdających egzaminów tej teczki.", 404)
    by_id = {e["id"]: e for e in exams}
    violations = await _violations(ss.st, [a["id"] for a in attempts])
    scope_rows = SS._cut_attempts(await _scope_rows(ss.st, ids), exams, scope, prov, who)
    avgs = RC.scope_averages(scope_rows)
    qinfo = await SS._qinfo(ss.st, exams)
    p = people.get(jid) or {}
    name = S._s(p.get("name")) or next((a.get("judge_name") for a in attempts if a.get("judge_name")), None) or jid
    judge = {"judge_id": jid, "name": name, "province": S._s(p.get("province")) or None, "photo": p.get("photo"),
             "badges": sorted({S._s(b) for b in p.get("badges") or [] if S._s(b)}), "in_roster": jid in people}
    body = RC.build_record(judge, by_id, attempts, viewer="committee", now=now, violations=violations,
                           scope_avgs=avgs, rule_of=_rule_lookup(qinfo))
    body["scope"], body["province"] = scope, prov
    return body
