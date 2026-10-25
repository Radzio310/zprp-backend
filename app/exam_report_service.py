"""
Egzamin z przepisów - raport komisji z bazy (etap 4, 16.10.2026).

Składa gotowe kawałki z `exam_service` (lista podejść z rzetelnością, statystyki
pytań, nie przystąpili - każde przez bramkę `_managed_exam`) i liczy obraz
egzaminu regułami z `exam_report_rules`. Ten sam raport ogląda ekran wyników
w telefonie i z niego powstaje plik HTML/PDF.

Importy bazy tylko przez `Store` (app/db.py łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
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
    # Cztery niezależne odczyty naraz (raport otwiera się z teczki - ma nie czekać po kolei).
    listed, stats, missed, bank = await asyncio.gather(
        S.attempts_list(st, who, exam_id), S.exam_stats(st, who, exam_id), S.missing(st, who, exam_id),
        S.load_bank(st, exam["bank_version"]))
    attempts, missing = listed["attempts"], missed["missing"]
    # Zdjęcia także dla nieobecnych - kartoteka Zdających pokazuje twarze wszystkich zaproszonych.
    photos = await _photos(st, [cut] if cut else S._exam_provinces(exam),
                           {a["judge_id"] for a in attempts} | {S._s(m.get("judge_id")) for m in missing})

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
    summary = R.summary(attempts, len(missing), pass_percent)
    web = await _web_judges(st, exam_id, {a["judge_id"] for a in attempts})
    summary["web_people"] = None if web is None else len(web)
    from app import exam_results_actions as A

    reminders = await A.reminder_status(st, exam_id)
    return {
        "exam": view,
        "generated_at": now.isoformat(),
        "summary": summary,
        "questions": questions,
        "hardest": R.hardest_questions(questions),
        "weakest_rules": R.weakest_rules(questions, limit=0),
        "violations": R.violation_map(attempts),
        "provinces": R.province_comparison(attempts, missing) if national or (not cut and len(provinces_seen) > 1) else [],
        "ranking": R.ranking(attempts),
        "missing": missing,
        "attempts": attempts,
        #: Zdjęcia sędziów z listy okręgu (`province_judges.photo_url`) - podium, rozkład, kartoteka.
        "photos": photos,
        #: Numery osób, które pisały na komputerze (filtr Zdających); None = nie umiemy policzyć.
        "web_judges": None if web is None else sorted(web),
        #: Ostatnie ręczne przypomnienie komisji (licznik przy „Przypomnij niepiszącym").
        "reminders": reminders,
    }


async def _web_judges(st: S.Store, exam_id: str, judge_ids: set) -> Optional[set]:
    """Kto pisał na komputerze (sesja `exam_web_sessions` w tym egzaminie).
    Tylko osoby z podejściem w raporcie (komisja okręgu nie liczy cudzych). Brak tabeli
    albo błąd odczytu = None - pasek liczb pokaże wtedy myślnik, raport nie pada."""
    if not judge_ids:
        return set()
    try:
        from sqlalchemy import MetaData

        from app.exam_web_tables import define_tables

        _, _, ws = define_tables(MetaData())
        rows = await st.database.fetch_all(select(ws.c.judge_id).where(ws.c.exam_id == exam_id).distinct())
    except Exception:
        return None
    return {S._s(r["judge_id"]) for r in rows} & {S._s(j) for j in judge_ids}


async def _photos(st: S.Store, provinces: List[str], judge_ids: set) -> Dict[str, str]:
    """numer -> adres zdjęcia, tylko dla osób z wynikiem (lista okręgu ma zdjęcia z panelu okręgu)."""
    if not judge_ids:
        return {}
    out: Dict[str, str] = {}
    lists = await asyncio.gather(*(st.judges(p) for p in provinces), return_exceptions=True)
    for judges in lists:
        if isinstance(judges, BaseException):
            continue
        for j in judges:
            jid = S._s(j.get("judge_id"))
            url = S._s(j.get("photo_url"))
            if jid in judge_ids and url:
                out[jid] = url
    return out


async def void_preview(st: S.Store, who: S.Who, exam_id: str, qid: str) -> Dict[str, Any]:
    """Skutki unieważnienia `qid` w obu trybach - zanim komisja zdecyduje."""
    exam = await S._managed_exam(st, who, exam_id)
    if qid not in exam["question_ids"]:
        raise ExamError("EXAM_UNKNOWN_QUESTION", "Tego pytania nie ma w puli egzaminu.", 404)
    if qid in exam["voided"]:
        raise ExamError("EXAM_ALREADY_VOIDED",
                        "To pytanie jest już unieważnione - najpierw cofnij unieważnienie, żeby porównać tryby.", 409)
    rows = await st.database.fetch_all(select(st.t.attempts.c.score_json).where(and_(
        st.t.attempts.c.exam_id == exam_id, st.t.attempts.c.status != "in_progress", S._live(st.t.attempts))))
    scores: List[Dict[str, Any]] = [s for s in (S._loads(r["score_json"], None) for r in rows) if s]
    return {"exam_id": exam_id, **R.void_preview(scores, qid, float(exam["config"]["pass_percent"]))}
