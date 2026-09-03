# app/training_spk_report.py
#
# Raport wyników sprawdzianu SPK - liczby i tabele dla szablonu PDF.
#
# CZYSTY MODUŁ, jak wszystko przy tym szkoleniu: decyzje (kogo liczyć, jak
# grupować, co pokazać) zapadają tutaj i dają się sprawdzić testem; szablon
# HTML tylko rysuje, a WeasyPrint tylko drukuje.
#
# TE SAME REGUŁY CO ZESTAWIENIE W PANELU (`summarize_by_province`):
#   • liczy się NAJLEPSZE podejście sędziego, nie średnia z wszystkich prób -
#     wytrwałość w ćwiczeniu nie może obniżać wyniku,
#   • nauka w aplikacji (guided) nie wchodzi do liczb - prowadzenie za rękę
#     gwarantuje niemal komplet zdarzeń i w rankingu mówiłaby nieprawdę; w
#     raporcie widać ją osobno, jako liczbę podejść treningowych.
#
# RAPORT OKRĘGOWY TO TEN SAM RAPORT NA MNIEJSZYCH DANYCH - nie osobny szablon.
# Dwa szablony rozjadą się przy pierwszej poprawce; filtr wystarcza.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

MODE_LABEL = {
    "video": "pełne nagranie",
    "condensed": "skrót od 2. połowy",
    "slides": "prezentacja",
    "guided": "nauka w aplikacji",
}


def _best_scored_runs(runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Najlepsze OCENIANE podejście każdego sędziego (bez nauki w aplikacji)."""
    best: Dict[str, Dict[str, Any]] = {}
    for run in runs:
        if run.get("score") is None or run.get("mode") == "guided":
            continue
        key = str(run.get("judgeId") or run.get("runId"))
        current = best.get(key)
        if current is None or run["score"] > current["score"]:
            best[key] = run
    return sorted(best.values(), key=lambda r: (-r["score"], str(r.get("judgeName") or "")))


def _median(scores: List[float]) -> float:
    ordered = sorted(scores)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return round((ordered[middle - 1] + ordered[middle]) / 2, 1)


def _grade_buckets(scores: List[float]) -> List[Dict[str, Any]]:
    """Rozkład ocen - dokładnie progi `grade()` z oceny podejścia."""
    buckets = [
        ("wzorowo", lambda s: s >= 95),
        ("bardzo dobrze", lambda s: 85 <= s < 95),
        ("dobrze", lambda s: 70 <= s < 85),
        ("są braki", lambda s: 50 <= s < 70),
        ("do poprawy", lambda s: s < 50),
    ]
    total = len(scores) or 1
    out = []
    for label, match in buckets:
        count = sum(1 for s in scores if match(s))
        out.append(
            {
                "label": label,
                "count": count,
                "percent": round(100 * count / total),
            }
        )
    return out


def report_context(
    runs: List[Dict[str, Any]],
    *,
    province: Optional[str] = None,
    generated_by: str = "",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Wszystko, czego potrzebuje szablon raportu - i nic ponad to."""
    wanted = str(province or "").strip().upper()
    pool = [
        r
        for r in runs
        if not wanted or str(r.get("province") or "").strip().upper() == wanted
    ]

    best = _best_scored_runs(pool)
    scores = [r["score"] for r in best]
    guided_count = sum(1 for r in pool if r.get("mode") == "guided")
    scored_attempts = [r for r in pool if r.get("score") is not None and r.get("mode") != "guided"]

    ranking = [
        {
            "place": i + 1,
            "judgeName": str(r.get("judgeName") or "").strip() or "(bez nazwiska)",
            "province": str(r.get("province") or "").strip() or "—",
            "score": r["score"],
            "mode": MODE_LABEL.get(str(r.get("mode") or ""), str(r.get("mode") or "")),
            "attempt": r.get("attempt") or 1,
        }
        for i, r in enumerate(best)
    ]

    by_province: List[Dict[str, Any]] = []
    if not wanted:
        grouped: Dict[str, List[float]] = {}
        for run in best:
            grouped.setdefault(str(run.get("province") or "—"), []).append(run["score"])
        for name, values in grouped.items():
            by_province.append(
                {
                    "province": name,
                    "judges": len(values),
                    "avg": round(sum(values) / len(values), 1),
                    "median": _median(values),
                    "best": max(values),
                }
            )
        by_province.sort(key=lambda x: (-x["avg"], x["province"]))

    stamp = (now or datetime.now(timezone.utc)).astimezone()
    return {
        "title": "Sprawdzian SPK/1 - raport wyników",
        "scope": wanted or "cała Polska",
        "generatedAt": stamp.strftime("%d.%m.%Y %H:%M"),
        "generatedBy": str(generated_by or "").strip(),
        "judges": len(best),
        "attempts": len(scored_attempts),
        "guidedAttempts": guided_count,
        "avg": round(sum(scores) / len(scores), 1) if scores else None,
        "median": _median(scores) if scores else None,
        "best": max(scores) if scores else None,
        "gradeBuckets": _grade_buckets(scores) if scores else [],
        "ranking": ranking,
        "byProvince": by_province,
    }
