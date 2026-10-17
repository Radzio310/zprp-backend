"""
Egzamin z przepisów - raport komisji z bazy (etap 4, 16.10.2026).

Składa gotowe kawałki z `exam_service` (lista podejść z rzetelnością, statystyki
pytań, nie przystąpili - każde przez bramkę `_managed_exam`) i liczy obraz
egzaminu regułami z `exam_report_rules`. Ten sam raport ogląda ekran wyników
w telefonie i z niego powstaje plik HTML/PDF.

Importy bazy tylko przez `Store` (app/db.py łączy się przy imporcie).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, select

from app import exam_report_rules as R
from app import exam_service as S
from app.exam_rules import ExamError


async def build_report(st: S.Store, who: S.Who, exam_id: str, now: Optional[datetime] = None, *,
                       with_scores: bool = False) -> Dict[str, Any]:
    """Pełny obraz egzaminu dla komisji. `with_scores` dokłada do podejść wiersze
    pytań (do kart zdających w eksporcie)."""
    now = now or S.utcnow()
    exam = await S._managed_exam(st, who, exam_id, read=True)
    cut = exam["cut_province"]  # egzamin krajowy oglądany przez komisję okręgu: tylko jej sędziowie
    attempts = (await S.attempts_list(st, who, exam_id))["attempts"]
    stats = await S.exam_stats(st, who, exam_id)
    missing = (await S.missing(st, who, exam_id))["missing"]
    bank = await S.load_bank(st, exam["bank_version"])

    questions = []
    for q in stats["questions"]:
        b = bank.get(q["qid"]) or {}
        questions.append({**q, "text": b.get("text"), "kind": b.get("kind"), "multi": b.get("multi"),
                          "answers": [{"key": a["key"], "text": a["text"]} for a in b.get("answers") or []]})
    # Pytania z puli, na które nikt jeszcze nie odpowiedział - heatmapa ma pokazać całą pulę.
    seen = {q["qid"] for q in questions}
    for qid in exam["question_ids"]:
        if qid in seen or qid not in bank:
            continue
        b = bank[qid]
        questions.append({"qid": qid, "number": b["number"], "rule": b.get("rule"), "total": 0, "answered": 0, "skipped": 0,
                          "timed_out": 0, "correct_rate": None, "avg_time_s": None,
                          "distribution": {a["key"]: 0 for a in b["answers"]},
                          "correct_keys": sorted(a["key"] for a in b["answers"] if a["correct"]),
                          "voided": exam["voided"].get(qid), "text": b.get("text"), "kind": b.get("kind"),
                          "multi": b.get("multi"), "answers": [{"key": a["key"], "text": a["text"]} for a in b["answers"]]})
    from app.exam_rules import number_key

    questions.sort(key=lambda q: number_key(q["number"]))

    if with_scores and attempts:
        ids = [a["attempt_id"] for a in attempts]
        rows = await st.database.fetch_all(select(st.t.attempts.c.id, st.t.attempts.c.score_json)
                                           .where(st.t.attempts.c.id.in_(ids)))
        scores = {r["id"]: S._loads(r["score_json"], None) for r in rows}
        for a in attempts:
            sc = scores.get(a["attempt_id"]) or {}
            a["questions"] = [{"qid": q["qid"], "number": (bank.get(q["qid"]) or {}).get("number"), "correct": q.get("correct"),
                               "voided": q.get("voided"), "points": q.get("points")} for q in sc.get("questions") or []]

    pass_percent = float(exam["config"]["pass_percent"])
    provinces_seen = {a.get("province") for a in attempts} | {m.get("province") for m in missing}
    national = exam["scope"] == "national" and not cut
    view = S.exam_view(exam, now, full=True)
    if cut:
        view.update(can_manage=False, read_only=True, cut_province=cut)
    return {
        "exam": view,
        "generated_at": now.isoformat(),
        "summary": R.summary(attempts, len(missing), pass_percent),
        "questions": questions,
        "hardest": R.hardest_questions(questions),
        "weakest_rules": R.weakest_rules(questions, limit=0),
        "violations": R.violation_map(attempts),
        "provinces": R.province_comparison(attempts, missing) if national or (not cut and len(provinces_seen) > 1) else [],
        "ranking": R.ranking(attempts),
        "missing": missing,
        "attempts": attempts,
    }


async def void_preview(st: S.Store, who: S.Who, exam_id: str, qid: str) -> Dict[str, Any]:
    """Skutki unieważnienia `qid` w obu trybach - zanim komisja zdecyduje."""
    exam = await S._managed_exam(st, who, exam_id)
    if qid not in exam["question_ids"]:
        raise ExamError("EXAM_UNKNOWN_QUESTION", "Tego pytania nie ma w puli egzaminu.", 404)
    if qid in exam["voided"]:
        raise ExamError("EXAM_ALREADY_VOIDED",
                        "To pytanie jest już unieważnione - najpierw cofnij unieważnienie, żeby porównać tryby.", 409)
    rows = await st.database.fetch_all(select(st.t.attempts.c.score_json).where(and_(
        st.t.attempts.c.exam_id == exam_id, st.t.attempts.c.status != "in_progress")))
    scores: List[Dict[str, Any]] = [s for s in (S._loads(r["score_json"], None) for r in rows) if s]
    return {"exam_id": exam_id, **R.void_preview(scores, qid, float(exam["config"]["pass_percent"]))}
