# app/exam_record_rules.py
"""
Kartoteka sędziego (24.10.2026) - reguły bez bazy.

Jeden kształt dla dwóch widzów:
  - `self`      sędzia o sobie (zakładka Egzamin z przepisów): wynik i klucz tylko
                tak, jak pozwala polityka egzaminu (`result_visible`, `review_refusal`);
  - `committee` komisja z teczki: każdy zakończony wynik i przegląd zawsze.

Wynik (`totals`):
  tests          egzaminy z co najmniej jednym oddanym arkuszem,
  attempts       oddane arkusze,
  avg_percent    średnia NAJLEPSZYCH widocznych wyników egzaminów,
  best_percent   najlepszy widoczny wynik (+ `best_exam_id`),
  avg_duration_s średni czas pisania oddanych arkuszy (czas nie jest tajny),
  best_duration_s najkrótszy czas oddanego arkusza.
Forma (`form`): egzamin po egzaminie w czasie - najlepszy widoczny wynik, próg, średnia
egzaminu (tylko po zamknięciu okna, dla sędziego), czas.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from app import exam_report_rules as RR
from app import exam_rules as X

FINISHED = ("submitted", "expired")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _f(value: Any) -> Optional[float]:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: Any) -> Optional[str]:
    v = _aware(value)
    return v.isoformat() if v else None


def _mean(values: Sequence[float]) -> Optional[float]:
    return round(sum(values) / len(values), 2) if values else None


def duration_s(a: Mapping[str, Any]) -> Optional[float]:
    """Czas pisania: realny, gdy policzony (`real_s`), a na wierszu bez podziału - start do oddania."""
    if a.get("status") not in FINISHED:
        return None
    if "real_s" in a:
        return a["real_s"]
    start, end = _aware(a.get("started_at")), _aware(a.get("finished_at"))
    if start and end and end >= start:
        return round((end - start).total_seconds(), 1)
    return None


def tally(score: Mapping[str, Any]) -> Dict[str, int]:
    """Dobre / błędne / unieważnione z `score.questions` (bez treści pytań)."""
    right = wrong = voided = 0
    for q in score.get("questions") or []:
        if q.get("voided"):
            voided += 1
            continue
        mx = _f(q.get("max")) or 0.0
        if mx and (_f(q.get("points")) or 0.0) >= mx - 1e-9:
            right += 1
        else:
            wrong += 1
    return {"right": right, "wrong": wrong, "voided": voided}


def attempt_row(
    a: Mapping[str, Any],
    exam: Mapping[str, Any],
    viewer: str,
    now: datetime,
    violations: int,
) -> Dict[str, Any]:
    config = exam.get("config") or {}
    status = _s(a.get("status"))
    finished = status in FINISHED
    if viewer == "self":
        visible = finished and X.result_visible(config, status, now)
        refusal = X.review_refusal(config, status, now)
        opens = X.review_opens_at(config, status, now)
    else:
        visible = finished
        refusal = None if finished else "Sędzia jeszcze pisze - przegląd otworzy się po oddaniu arkusza."
        opens = None
    score = a.get("score") or {}
    row: Dict[str, Any] = {
        "attempt_id": a.get("id"), "attempt_no": a.get("attempt_no"), "status": status,
        "finish_reason": a.get("finish_reason"), "started_at": _iso(a.get("started_at")),
        "finished_at": _iso(a.get("finished_at")), "duration_s": duration_s(a),
        "away_s": a.get("away_s"), "total_s": a.get("total_s"),
        "visible": visible, "percent": None, "points": None, "max": None, "passed": None,
        "right": None, "wrong": None, "voided": None,
        "review_available": refusal is None, "review_reason": refusal, "review_opens_at": opens,
        "violations": int(violations),
    }
    if visible:
        row.update(percent=_f(a.get("percent", score.get("percent"))), points=score.get("points"), max=score.get("max"),
                   passed=a.get("passed", score.get("passed")), **tally(score))
    return row


def best_of(rows: Sequence[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    """Najlepszy widoczny wynik egzaminu (remis = wcześniejsze podejście)."""
    shown = [r for r in rows if r.get("visible") and r.get("percent") is not None]
    if not shown:
        return None
    return sorted(shown, key=lambda r: (-(r["percent"] or 0.0), int(r.get("attempt_no") or 0)))[0]


def build_record(
    judge: Mapping[str, Any],
    exams: Mapping[str, Mapping[str, Any]],
    attempts: Sequence[Mapping[str, Any]],
    *,
    viewer: str,
    now: datetime,
    violations: Mapping[str, int],
    scope_avgs: Mapping[str, Optional[float]],
    rule_of: Callable[[str, str], Any],
) -> Dict[str, Any]:
    """`rule_of(exam_id, qid)` -> numer przepisu (z banku egzaminu)."""
    by_exam: Dict[str, List[Mapping[str, Any]]] = {}
    for a in attempts:
        eid = _s(a.get("exam_id"))
        if eid in exams:
            by_exam.setdefault(eid, []).append(a)

    entries = []
    for eid, rows in by_exam.items():
        e = exams[eid]
        cfg = e.get("config") or {}
        shaped = [attempt_row(a, e, viewer, now, violations.get(_s(a.get("id")), 0))
                  for a in sorted(rows, key=lambda a: int(a.get("attempt_no") or 0), reverse=True)]
        best = best_of(shaped)
        closed = X.window_closed(cfg, now) if cfg.get("window_end") else True
        avg = scope_avgs.get(eid)
        entries.append({
            "exam_id": eid, "name": e.get("name"), "scope": e.get("scope"), "province": e.get("province"),
            "at": _iso(e.get("opens_at") or cfg.get("window_start")), "closes_at": _iso(e.get("closes_at") or cfg.get("window_end")),
            "closed": closed, "pass_percent": _f(cfg.get("pass_percent")), "question_count": cfg.get("question_count"),
            "answers_release": X.answers_release(cfg),
            "best": {"attempt_id": best["attempt_id"], "percent": best["percent"], "passed": best["passed"]} if best else None,
            "scope_avg": avg if (viewer == "committee" or closed) else None,
            "attempts": shaped,
        })
    entries.sort(key=lambda x: (_aware(x["at"]) or now), reverse=True)

    all_rows = [r for e in entries for r in e["attempts"]]
    done = [r for r in all_rows if r["status"] in FINISHED]
    bests = [e["best"] for e in entries if e["best"]]
    durations = [r["duration_s"] for r in done if r["duration_s"] is not None]
    top = max(bests, key=lambda b: b["percent"] or 0.0) if bests else None
    top_exam = next((e["exam_id"] for e in entries if e["best"] is top), None) if top else None
    totals = {
        "tests": sum(1 for e in entries if any(r["status"] in FINISHED for r in e["attempts"])),
        "attempts": len(done),
        "in_progress": sum(1 for r in all_rows if r["status"] == "in_progress"),
        "visible": len(bests),
        "passed": sum(1 for b in bests if b.get("passed")),
        "avg_percent": _mean([b["percent"] for b in bests]),
        "best_percent": top["percent"] if top else None,
        "best_exam_id": top_exam,
        "avg_duration_s": _mean(durations),
        "best_duration_s": min(durations) if durations else None,
        "violations": sum(r["violations"] for r in all_rows),
    }

    form = []
    for e in sorted(entries, key=lambda x: (_aware(x["at"]) or now)):
        if not e["best"]:
            continue
        fastest = [r["duration_s"] for r in e["attempts"] if r["duration_s"] is not None]
        form.append({"exam_id": e["exam_id"], "name": e["name"], "at": e["at"], "percent": e["best"]["percent"],
                     "passed": e["best"]["passed"], "pass_percent": e["pass_percent"], "scope_avg": e["scope_avg"],
                     "duration_s": min(fastest) if fastest else None})

    # Najsłabsze przepisy - tylko z widocznych wyników (klucz nie może wyciec przez statystykę).
    visible_ids = {r["attempt_id"] for r in done if r["visible"]}
    rules: Dict[Any, Dict[str, float]] = {}
    for a in attempts:
        if _s(a.get("id")) not in visible_ids:
            continue
        for q in (a.get("score") or {}).get("questions") or []:
            if q.get("voided") or not _f(q.get("max")):
                continue
            rule = rule_of(_s(a.get("exam_id")), _s(q.get("qid")))
            if rule is None:
                continue
            g = rules.setdefault(rule, {"points": 0.0, "max": 0.0, "answers": 0})
            g["points"] += _f(q.get("points")) or 0.0
            g["max"] += _f(q.get("max")) or 0.0
            g["answers"] += 1
    weak = [{"rule": rule, "label": RR.rule_label(rule), "correct_rate": round(v["points"] / v["max"], 4), "answers": int(v["answers"])}
            for rule, v in rules.items() if v["max"]]
    weak.sort(key=lambda r: (r["correct_rate"], -r["answers"]))

    return {"viewer": viewer, "judge": dict(judge), "totals": totals, "form": form, "exams": entries,
            "weak_rules": weak[:8], "generated_at": now.isoformat()}


def scope_averages(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Optional[float]]:
    """Średnia egzaminu z najlepszych wyników osób: rows = {exam_id, judge_id, percent}."""
    best: Dict[str, Dict[str, float]] = {}
    for r in rows:
        p = _f(r.get("percent"))
        if p is None:
            continue
        per = best.setdefault(_s(r.get("exam_id")), {})
        jid = _s(r.get("judge_id"))
        per[jid] = max(per.get(jid, -1.0), p)
    return {eid: _mean(list(v.values())) for eid, v in best.items()}
