"""
Egzamin z przepisów - statystyki łączne teczki i karta sędziego: dane z bazy (17.10.2026).

Reguły (komórki, grupy, miejsca ex aequo) leżą w `exam_stats_rules.py`; tu tylko
uprawnienia i JEDNO pobranie na zapytanie, bez N+1:
  - egzaminy zakresu: jedno zapytanie,
  - podejścia wszystkich wybranych egzaminów: jedno zapytanie (bez odpowiedzi -
    punkty przepisów są w `score_json`),
  - banki pytań: raz na wersję (pamięć procesu `exam_service._BANK_CACHE`),
  - lista sędziów, odznaki, litery uprawnień i pary: `StatsStore.roster` - jedno
    pobranie na cały zakres (okręg albo kraj),
  - karta sędziego: dodatkowo zdarzenia jego podejść jednym zapytaniem (rzetelność).

Uprawnienia jak teczka (`exam_service.require_manage`): krajowy tylko admin,
okręgowy admin / komisja TEGO okręgu / Teach Master tego okręgu.
Zakres okręgowy obejmuje egzaminy okręgu oraz (dla nie-admina) krajowe, liczone wyłącznie dla osób z tego okręgu.

Importy bazy tylko przez `Store` (app/db.py łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple

from sqlalchemy import and_, or_, select

from app import exam_rules as X
from app import exam_service as S
from app import exam_stats_rules as SR
from app import province_event_rules as PR
from app.exam_rules import ExamError
from app.settlement_province import DISPLAY, display


@dataclass
class StatsStore:
    st: S.Store
    #: async (okręgi) -> {"people": {numer: {name, province, badges, letters}}, "pairs": {numer: partner}}
    roster: Callable[[List[str]], Awaitable[Dict[str, Any]]]


async def resolve_scope(who: S.Who, province: Optional[str]) -> Tuple[str, Optional[str]]:
    """Jak teczka: z okręgiem = okręgowy; bez okręgu admin dostaje kraj, reszta swój okręg."""
    scope = "province" if province or not who.is_admin else "national"
    prov = display(province or who.province) if scope == "province" else None
    if scope == "province" and (not prov or prov not in DISPLAY.values()):
        raise ExamError("BAD_FILTER", "Statystyki: podaj okręg, którego wyniki chcesz zobaczyć.", 400)
    await S.require_manage(who, scope, prov)
    return scope, prov


async def _exams(st: S.Store, scope: str, prov: Optional[str], source: str, now: datetime,
                 with_national: bool = False) -> List[Dict[str, Any]]:
    d = st.t.definitions
    q = select(d).where(d.c.deleted_at.is_(None))
    if scope == "province" and with_national:
        # Komisja okręgu widzi też krajowe - tylko osoby z jej okręgu (patrz `_cut_attempts`).
        q = q.where(or_(d.c.scope == "national", and_(d.c.scope == "province", d.c.province == prov)))
    elif scope == "province":
        q = q.where(and_(d.c.scope == "province", d.c.province == prov))
    elif source == "national":
        q = q.where(d.c.scope == "national")
    else:
        q = q.where(or_(d.c.scope == "national", d.c.scope == "province"))
    out = []
    for raw in await st.database.fetch_all(q.order_by(d.c.opens_at)):
        e = S._row(raw)
        e["config"] = S._loads(e["config_json"], {})
        e["opens_at"], e["closes_at"] = S._dt(e["opens_at"]), S._dt(e["closes_at"])
        e["pass_percent"] = e["config"].get("pass_percent")
        e["question_count"] = e["config"].get("question_count")
        e["state"] = S._window_state(e["config"], now) if e["config"].get("window_start") else "closed"
        out.append(e)
    return out


def _select(exams: List[Dict[str, Any]], filters: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Egzaminy po filtrze: już otwarte, w okresie (data = otwarcie okna), z listy wybranych."""
    chosen = set(filters.get("exams") or [])
    out = []
    for e in exams:
        if e["state"] == "upcoming":
            continue
        if filters.get("from") and e["opens_at"] < filters["from"]:
            continue
        if filters.get("to") and e["opens_at"] > filters["to"]:
            continue
        if chosen and e["id"] not in chosen:
            continue
        out.append(e)
    return out


async def _attempts(st: S.Store, exam_ids: List[str], judge_id: Optional[str] = None) -> List[Dict[str, Any]]:
    if not exam_ids:
        return []
    a = st.t.attempts
    q = select(a.c.id, a.c.exam_id, a.c.judge_id, a.c.judge_name, a.c.province, a.c.attempt_no, a.c.status,
               a.c.finish_reason, a.c.started_at, a.c.finished_at, a.c.percent, a.c.passed, a.c.score_json, a.c.time_json
               ).where(and_(a.c.exam_id.in_(exam_ids), S._live(a)))
    if judge_id is not None:
        q = q.where(a.c.judge_id == judge_id)
    out = []
    for raw in await st.database.fetch_all(q):
        r = S._row(raw)
        score = S._loads(r.pop("score_json", None), None) or {}
        r["score"] = score
        r["points"], r["max"] = score.get("points"), score.get("max")
        r["started_at"], r["finished_at"] = S._dt(r["started_at"]), S._dt(r["finished_at"])
        r["judge_id"] = S._s(r["judge_id"])
        out.append(r)
    await S.fill_attempt_times(st, out)
    return out


def _cut_attempts(attempts: List[Dict[str, Any]], exams: List[Dict[str, Any]], scope: str, prov: Optional[str],
                  who: S.Who) -> List[Dict[str, Any]]:
    """Egzaminy krajowe w zakresie okręgowym liczą tylko podejścia osób z tego okręgu."""
    if scope != "province" or who.is_admin:
        return attempts
    national = {e["id"] for e in exams if e["scope"] == "national"}
    return [a for a in attempts if a["exam_id"] not in national or (display(S._s(a.get("province"))) or S._s(a.get("province"))) == prov]


async def _qinfo(st: S.Store, exams: List[Dict[str, Any]]) -> Dict[str, Dict[str, Tuple[Any, Any]]]:
    banks: Dict[str, Dict[str, Tuple[Any, Any]]] = {}
    out = {}
    for e in exams:
        v = e["bank_version"]
        if v not in banks:
            bank = await S.load_bank(st, v)
            banks[v] = {qid: (q.get("rule"), q.get("number")) for qid, q in bank.items()}
        out[e["id"]] = banks[v]
    return out


def _attach_invited(exams: List[Dict[str, Any]], people: Mapping[str, Mapping[str, Any]]) -> None:
    """Zaproszeni wg odznak z listy okręgu - ta sama reguła co wydarzenie i teczka."""
    by_prov: Dict[str, List[Dict[str, Any]]] = {}
    for jid, p in people.items():
        by_prov.setdefault(display(p.get("province")) or S._s(p.get("province")), []).append({"judge_id": jid, "badges": p.get("badges") or []})
    everyone = [j for rows in by_prov.values() for j in rows]
    for e in exams:
        cfg = e["config"]
        data = {"target": cfg.get("target") or {}, "include_ids": cfg.get("include_ids") or [], "exclude_ids": cfg.get("exclude_ids") or []}
        judges = everyone if e["scope"] == "national" else by_prov.get(display(e.get("province")) or "", [])
        e["invited_ids"] = PR.invited_ids(judges, data)


async def _load(ss: StatsStore, who: S.Who, province: Optional[str], raw: Mapping[str, Any], now: datetime):
    filters = SR.clean_filters(raw)
    scope, prov = await resolve_scope(who, province)
    provinces = [prov] if scope == "province" else list(S.ALL_PROVINCES)
    # Egzaminy zakresu i lista sędziów naraz - nie zależą od siebie.
    catalog, roster = await asyncio.gather(
        _exams(ss.st, scope, prov, filters["source"], now, with_national=scope == "province" and not who.is_admin),
        ss.roster(provinces))
    exams = _select(catalog, filters)
    people = roster.get("people") or {}
    pairs = roster.get("pairs") or {}
    _attach_invited(exams, people)
    return filters, scope, prov, catalog, exams, people, pairs


def _head(scope: str, prov: Optional[str], catalog: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    return {"scope": scope, "province": prov, "generated_at": now.isoformat(),
            "catalog": [SR.exam_brief(e) for e in reversed(catalog)]}


async def stats_overview(ss: StatsStore, who: S.Who, province: Optional[str], raw: Mapping[str, Any],
                         now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    filters, scope, prov, catalog, exams, people, pairs = await _load(ss, who, province, raw, now)
    raw_attempts, qinfo = await asyncio.gather(_attempts(ss.st, [e["id"] for e in exams]), _qinfo(ss.st, exams))
    attempts = _cut_attempts(raw_attempts, exams, scope, prov, who)
    body = SR.overview(exams, attempts, people, pairs, qinfo, filters, national=scope == "national")
    return {**_head(scope, prov, catalog, now), **body}


async def judges_list(ss: StatsStore, who: S.Who, province: Optional[str], raw: Mapping[str, Any],
                      now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    filters, scope, prov, catalog, exams, people, pairs = await _load(ss, who, province, raw, now)
    attempts = _cut_attempts(await _attempts(ss.st, [e["id"] for e in exams]), exams, scope, prov, who)
    rows = SR.judge_rows(exams, attempts, people, pairs, now)
    for row in rows:
        row["photo"] = (people.get(row["judge_id"]) or {}).get("photo")
    badges = sorted({b for r in rows for b in r["badges"]}, key=str.lower)
    return {**_head(scope, prov, catalog, now), "exams": [SR.exam_brief(e) for e in exams], "judges": rows,
            "badges": badges, "levels": [{"key": k, "label": v} for k, v in SR.LEVELS]}


async def judge_card(ss: StatsStore, who: S.Who, judge_id: str, province: Optional[str], raw: Mapping[str, Any],
                     now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    jid = S._s(judge_id)
    filters, scope, prov, catalog, exams, people, pairs = await _load(ss, who, province, raw, now)
    attempts = _cut_attempts(await _attempts(ss.st, [e["id"] for e in exams]), exams, scope, prov, who)
    if jid not in people and not any(a["judge_id"] == jid for a in attempts):
        raise ExamError("STATS_JUDGE_UNKNOWN", "Tego sędziego nie ma na liście okręgu ani wśród zdających egzaminów tej teczki.", 404)
    qinfo = await _qinfo(ss.st, exams)

    mine = [a["id"] for a in attempts if a["judge_id"] == jid]
    events: Dict[str, List[Dict[str, Any]]] = {}
    if mine:
        ev = ss.st.t.events
        for raw_ev in await ss.st.database.fetch_all(select(ev).where(ev.c.attempt_id.in_(mine)).order_by(ev.c.id)):
            r = S._row(raw_ev)
            events.setdefault(r["attempt_id"], []).append({"id": r["id"], "kind": r["kind"], "detail": S._loads(r["detail_json"], {}),
                                                           "client_ts_ms": r.get("client_ts_ms"), "at": S._iso(r["created_at"])})
    cfg = {e["id"]: e["config"] for e in exams}

    def integrity(a: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        rep = X.integrity_report(events.get(a["id"], []), ((cfg.get(a["exam_id"]) or {}).get("anti") or {}).get("integrity"))
        return {"score": rep["score"], "level": rep["level"], "breakdown": rep["breakdown"]}

    card = SR.judge_card(jid, exams, attempts, people, pairs, qinfo, integrity, now)
    if isinstance(card.get("judge"), dict):
        card["judge"]["photo"] = (people.get(jid) or {}).get("photo")
    return {**_head(scope, prov, catalog, now), **card}
