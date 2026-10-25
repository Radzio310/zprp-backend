"""
Egzamin z przepisów - działania komisji na ekranie wyników (25.10.2026, czwarta odsłona).

  question_answers   kto jak odpowiedział na jedno pytanie (zakończone arkusze)
  signals            sygnały rzetelności z czasem: kto, co, kiedy (zakładka Rzetelność)
  reminder_status    ostatnie przypomnienie wysłane ręcznie przez komisję
  remind_missing     push do zaproszonych, którzy jeszcze nie pisali (okno otwarte)
  grant_attempt      kolejne podejście dla jednego sędziego ponad limit egzaminu

Odczyt przez bramkę `_managed_exam(read=True)` (komisja okręgu widzi tylko swój wycinek
egzaminu krajowego); zmiany (przypomnienie, podejście) wymagają prawa zarządzania.
Importy bazy tylko przez `Store` (app/db.py łączy się przy imporcie).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, select, update

from app import exam_rules as X
from app import exam_service as S
from app.exam_rules import ExamError

logger = logging.getLogger(__name__)

#: Ręczne przypomnienia: najwyżej jedno na kwadrans (pomyłkowe drugie dotknięcie nie wyśle drugi raz).
REMIND_COOLDOWN = timedelta(minutes=15)
REMIND_PREFIX = "manual:"


async def question_answers(st: S.Store, who: S.Who, exam_id: str, qid: str) -> Dict[str, Any]:
    exam = await S._managed_exam(st, who, exam_id, read=True)
    t = st.t
    bank = await S.load_bank(st, exam["bank_version"])
    q = bank.get(qid)
    if not q:
        raise ExamError("QUESTION_NOT_FOUND", "Nie ma takiego pytania w katalogu tego egzaminu.", 404)
    rows = await st.database.fetch_all(select(t.attempts).where(and_(
        t.attempts.c.exam_id == exam_id, t.attempts.c.status != "in_progress", S._live(t.attempts))))
    done = [S._attempt(r) for r in rows]
    done = [a for a in done if S._in_cut(a.get("province"), exam["cut_province"])]
    by_id = {a["id"]: a for a in done}
    out: List[Dict[str, Any]] = []
    if by_id:
        answers = await st.database.fetch_all(select(t.answers).where(and_(
            t.answers.c.attempt_id.in_(list(by_id)), t.answers.c.qid == qid)))
        mode = exam["config"].get("multi_scoring") or "all_or_nothing"
        void = exam["voided"].get(qid)
        for raw in answers:
            r = S._row(raw)
            a = by_id.get(r["attempt_id"])
            if not a:
                continue
            selected = S._loads(r["selected_json"], None) or []
            got = X.score_question(q, selected, mode) if selected else 0.0
            out.append({
                "attempt_id": a["id"], "judge_id": a["judge_id"], "judge_name": a.get("judge_name"),
                "province": a.get("province"), "attempt_no": a["attempt_no"],
                "selected": sorted(str(k) for k in selected),
                "correct": None if void else got >= 1.0,
                "partial": None if void else (0.0 < got < 1.0),
                "elapsed_ms": r.get("client_time_ms") or r.get("elapsed_ms"),
                "timed_out": bool(r.get("timed_out")),
                "answered_at": S._iso(r.get("answered_at")),
            })
    out.sort(key=lambda x: (str(x.get("judge_name") or "").lower(), x["attempt_no"]))
    return {"exam_id": exam_id, "qid": qid, "answers": out}


async def signals(st: S.Store, who: S.Who, exam_id: str) -> Dict[str, Any]:
    exam = await S._managed_exam(st, who, exam_id, read=True)
    t = st.t
    rows = await st.database.fetch_all(select(t.attempts.c.id, t.attempts.c.judge_id, t.attempts.c.judge_name,
                                              t.attempts.c.province, t.attempts.c.started_at)
                                       .where(and_(t.attempts.c.exam_id == exam_id, S._live(t.attempts))))
    people = {r["id"]: S._row(r) for r in rows if S._in_cut(r["province"], exam["cut_province"])}
    events = await S._events_by_attempt(st, exam_id)
    out: List[Dict[str, Any]] = []
    for aid, items in events.items():
        p = people.get(aid)
        if not p:
            continue
        for e in items:
            sig = X.integrity_signal(e)
            if not sig:
                continue
            detail = e.get("detail") or {}
            out.append({
                "attempt_id": aid, "judge_id": p["judge_id"], "judge_name": p.get("judge_name"),
                "province": p.get("province"), "kind": sig[0], "flag": sig[1], "at": e.get("at"),
                "seconds": detail.get("seconds"), "number": detail.get("number"),
            })
    out.sort(key=lambda x: (x["at"] or ""))
    return {"exam_id": exam_id, "signals": out}


async def reminder_status(st: S.Store, exam_id: str) -> Dict[str, Any]:
    """Ostatnie ręczne przypomnienie: kiedy i do ilu osób (do licznika przy przycisku)."""
    try:
        rows = await st.database.fetch_all(select(st.t.reminders.c.kind, st.t.reminders.c.sent_at).where(and_(
            st.t.reminders.c.exam_id == exam_id, st.t.reminders.c.kind.like(f"{REMIND_PREFIX}%"))))
    except Exception:  # noqa: BLE001 - licznik nie może położyć raportu
        return {"last_at": None, "last_count": 0, "times": 0}
    by_kind: Dict[str, int] = {}
    last_at: Optional[datetime] = None
    last_kind = ""
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        at = S._dt(r["sent_at"])
        if at and (last_at is None or at > last_at):
            last_at, last_kind = at, r["kind"]
    return {"last_at": S._iso(last_at), "last_count": by_kind.get(last_kind, 0), "times": len(by_kind)}


async def remind_missing(st: S.Store, who: S.Who, exam_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    exam = await S._managed_exam(st, who, exam_id)
    if S._window_state(exam["config"], now) != "open":
        raise ExamError("EXAM_NOT_OPEN", "Przypomnieć można tylko wtedy, gdy egzamin trwa - teraz nikt nie mógłby od razu pisać.", 409)
    status = await reminder_status(st, exam_id)
    last = S._dt(status["last_at"])
    if last and now - last < REMIND_COOLDOWN:
        wait = int((REMIND_COOLDOWN - (now - last)).total_seconds() // 60) + 1
        raise ExamError("REMIND_TOO_SOON", f"Przypomnienie poszło przed chwilą. Następne można wysłać za {wait} min.", 409,
                        {"last_at": status["last_at"], "wait_min": wait})
    missed = await S.missing(st, who, exam_id)
    by_prov: Dict[str, List[str]] = {}
    for m in missed["missing"]:
        by_prov.setdefault(m["province"], []).append(m["judge_id"])
    ids = sorted({j for js in by_prov.values() for j in js})
    if not ids:
        raise ExamError("REMIND_NOBODY", "Wszyscy zaproszeni już przystąpili - nie ma komu przypominać.", 409)
    kind = f"{REMIND_PREFIX}{now.isoformat()}"
    await S._mark_sent(st, exam_id, ids, kind, now)
    end = X.parse_time(exam["config"]["window_end"])
    until = X.local_label(end) if end else "zamknięcia okna"
    for prov, people in by_prov.items():
        await S._safe_push(st, sorted(set(people)), f"Egzamin czeka: {exam['name']}",
                           f"Komisja przypomina - egzamin trwa do {until}. Otwórz go w aplikacji.",
                           S._push_data(exam, prov, "exam_reminder"))
    return {"exam_id": exam_id, "sent": len(ids), "reminders": await reminder_status(st, exam_id)}


async def grant_attempt(st: S.Store, who: S.Who, exam_id: str, judge_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or S.utcnow()
    exam = await S._managed_exam(st, who, exam_id)
    jid = S._s(judge_id)
    if S._window_state(exam["config"], now) == "closed":
        raise ExamError("EXAM_CLOSED", "Okno egzaminu jest zamknięte - kolejne podejście nie dałoby się napisać. "
                        "Przedłuż okno w edycji egzaminu i spróbuj ponownie.", 409)
    config = dict(exam["config"])
    extra = X.clean_extra_attempts(config.get("extra_attempts"))
    if extra.get(jid, 0) >= X.MAX_EXTRA_ATTEMPTS:
        raise ExamError("EXTRA_LIMIT", f"Ten sędzia dostał już {X.MAX_EXTRA_ATTEMPTS} dodatkowych podejść - więcej nie dodamy.", 409)
    extra[jid] = extra.get(jid, 0) + 1
    config["extra_attempts"] = extra
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam_id).values(
        config_json=S._dumps(config), updated_at=now))
    used = len(await S._my_attempts(st, exam_id, jid))
    left = max(0, int(config.get("max_attempts") or 1) + extra[jid] - used)
    prov = ""
    for p in S._exam_provinces(exam):
        if jid in await S._invited_ids(st, exam, p):
            prov = p
            break
    await S._safe_push(st, [jid], f"Kolejne podejście: {exam['name']}",
                       "Komisja dała Ci jeszcze jedno podejście do egzaminu. Możesz pisać od razu.",
                       S._push_data(exam, prov or (exam.get("province") or ""), "exam_extra_attempt"))
    return {"exam_id": exam_id, "judge_id": jid, "extra": extra[jid], "attempts_left": left}
