"""
Egzamin z przepisów - wyniki dla komisji: agregaty bez bazy (etap 4, 16.10.2026).

Kontrakt: BAZA/docs/egzamin-api.md (sekcja „Wyniki komisji i eksport").

Tu leży wszystko, co z gotowych danych (lista podejść, statystyki pytań,
nie przystąpili) liczy obraz egzaminu - i to SAMO liczy ekran w telefonie,
i raport HTML/PDF. Jedno źródło liczb, testy bez Postgresa.

  - ranking z remisami ex aequo (1, 2, 2, 4), najlepsze podejście na osobę,
  - porównanie okręgów (frekwencja, zdawalność, średnia - też z miejscami ex aequo),
  - najsłabszy przepis (ważona poprawność pytań przepisu, bez unieważnionych),
  - mapa naruszeń (rodzaje sygnałów rzetelności: ile osób, ile zdarzeń),
  - czasy (średni i mediana czasu podejścia, najwolniejsze pytania),
  - podgląd skutków unieważnienia pytania (drop / credit) - liczby, zanim komisja kliknie,
  - czyszczenie opcji eksportu (zero cichych blokad: zła wartość = zdanie po polsku).
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.exam_rules import INTEGRITY_RULES, ExamError, number_key

SEED_PATH = Path(__file__).resolve().parent / "data" / "exam_questions_default.json"

FINISHED = ("submitted", "expired")

EXPORT_FORMATS = ("html", "pdf")
EXPORT_RANGES = ("best", "all", "passed", "failed")
EXPORT_THEMES = ("paper", "night")
EXPORT_SECTIONS = ("summary", "histogram", "questions", "weakest", "violations", "ranking", "missing", "provinces", "cards")
DEFAULT_SECTIONS = ("summary", "histogram", "questions", "weakest", "violations", "ranking", "missing")
RANGE_LABELS = {
    "best": "najlepsze podejście każdej osoby",
    "all": "wszystkie podejścia",
    "passed": "tylko zaliczone",
    "failed": "tylko niezaliczone",
}
SECTION_LABELS = {
    "summary": "Podsumowanie",
    "histogram": "Rozkład wyników",
    "questions": "Trudność pytań",
    "weakest": "Najsłabsze przepisy",
    "violations": "Mapa naruszeń",
    "ranking": "Lista wyników",
    "missing": "Nie przystąpili",
    "provinces": "Porównanie okręgów",
    "cards": "Karty zdających",
}

_RULE_TITLES: Optional[Dict[int, str]] = None


def rule_titles() -> Dict[int, str]:
    """Tytuły przepisów z kopii katalogu w repozytorium (raz na proces)."""
    global _RULE_TITLES
    if _RULE_TITLES is None:
        try:
            data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
            _RULE_TITLES = {int(r["number"]): str(r["title"]) for r in data.get("rules") or [] if r.get("number") is not None}
        except Exception:  # noqa: BLE001 - brak pliku = same numery
            _RULE_TITLES = {}
    return _RULE_TITLES


def rule_label(rule: Any) -> str:
    try:
        n = int(rule)
    except (TypeError, ValueError):
        return "Bez przepisu"
    title = rule_titles().get(n)
    return f"Przepis {n}: {title}" if title else f"Przepis {n}"


def _pct(value: Any) -> Optional[float]:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Ranking ex aequo
# ---------------------------------------------------------------------------


def place_ex_aequo(values: Sequence[Optional[float]], *, digits: int = 2) -> List[Optional[int]]:
    """Miejsca dla wartości już POSORTOWANYCH malejąco: równe = wspólne miejsce,
    następne przeskakuje (1, 2, 2, 4). `None` (brak wyniku) nie dostaje miejsca."""
    out: List[Optional[int]] = []
    last: Optional[float] = None
    last_place = 0
    for i, v in enumerate(values):
        if v is None:
            out.append(None)
            continue
        r = round(float(v), digits)
        if last is None or r != last:
            last_place = i + 1
            last = r
        out.append(last_place)
    return out


def _attempt_sort_key(a: Mapping[str, Any]) -> Tuple[float, str]:
    return (-(_pct(a.get("percent")) or 0.0), str(a.get("judge_name") or "").lower())


def best_attempts(attempts: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Najlepsze ZAKOŃCZONE podejście każdej osoby (przy równym procencie - wcześniejsze)."""
    best: Dict[str, Dict[str, Any]] = {}
    for a in attempts:
        if a.get("status") not in FINISHED or a.get("percent") is None:
            continue
        jid = str(a.get("judge_id"))
        cur = best.get(jid)
        if cur is None or float(a["percent"]) > float(cur["percent"]) or (
                float(a["percent"]) == float(cur["percent"]) and int(a.get("attempt_no") or 0) < int(cur.get("attempt_no") or 0)):
            best[jid] = dict(a)
    return list(best.values())


def ranking(attempts: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Ranking najlepszych podejść z miejscem ex aequo i liczbą podejść osoby."""
    items = list(attempts)
    tries: Dict[str, int] = {}
    for a in items:
        jid = str(a.get("judge_id"))
        tries[jid] = tries.get(jid, 0) + 1
    rows = sorted(best_attempts(items), key=_attempt_sort_key)
    places = place_ex_aequo([r.get("percent") for r in rows])
    out = []
    for row, place in zip(rows, places):
        row["place"] = place
        row["attempts_used"] = tries.get(str(row.get("judge_id")), 1)
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Podsumowanie, czasy, histogram
# ---------------------------------------------------------------------------


def _median(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def durations_s(attempts: Iterable[Mapping[str, Any]]) -> List[float]:
    out = []
    for a in attempts:
        if a.get("status") not in FINISHED:
            continue
        start, end = _ts(a.get("started_at")), _ts(a.get("finished_at"))
        if start and end and end >= start:
            out.append((end - start).total_seconds())
    return out


def histogram_10(percents: Iterable[Optional[float]]) -> List[int]:
    hist = [0] * 10
    for p in percents:
        if p is None:
            continue
        hist[min(9, max(0, int(float(p) // 10)))] += 1
    return hist


def summary(attempts: Sequence[Mapping[str, Any]], missing_count: int, pass_percent: float) -> Dict[str, Any]:
    """Obraz egzaminu z najlepszych podejść (osoba liczy się raz)."""
    best = best_attempts(attempts)
    percents = [float(a["percent"]) for a in best]
    passed = sum(1 for a in best if a.get("passed"))
    in_progress = len({str(a.get("judge_id")) for a in attempts if a.get("status") == "in_progress"} - {str(a.get("judge_id")) for a in best})
    people = len({str(a.get("judge_id")) for a in attempts})
    invited = people + missing_count
    durs = durations_s(attempts)
    return {
        "people": people,
        "finished_people": len(best),
        "in_progress": in_progress,
        "attempts": len(attempts),
        "invited": invited,
        "missing": missing_count,
        "attendance_rate": round(people / invited, 4) if invited else None,
        "passed": passed,
        "failed": len(best) - passed,
        "pass_rate": round(passed / len(best), 4) if best else None,
        "avg_percent": round(sum(percents) / len(percents), 2) if percents else None,
        "median_percent": round(_median(percents), 2) if percents else None,
        "pass_percent": float(pass_percent),
        "histogram_10pct": histogram_10(percents),
        "avg_duration_s": round(sum(durs) / len(durs), 1) if durs else None,
        "median_duration_s": round(_median(durs), 1) if durs else None,
    }


# ---------------------------------------------------------------------------
# Przepisy, pytania, naruszenia, okręgi
# ---------------------------------------------------------------------------


def weakest_rules(questions: Iterable[Mapping[str, Any]], *, limit: int = 5) -> List[Dict[str, Any]]:
    """Przepisy od najsłabszego: poprawność ważona liczbą odpowiedzi, bez unieważnionych pytań."""
    agg: Dict[Any, Dict[str, Any]] = {}
    for q in questions:
        if q.get("voided") or not q.get("total") or q.get("correct_rate") is None:
            continue
        g = agg.setdefault(q.get("rule"), {"rule": q.get("rule"), "label": rule_label(q.get("rule")), "questions": 0,
                                           "answers": 0, "points": 0.0, "worst": None})
        g["questions"] += 1
        g["answers"] += int(q["total"])
        g["points"] += float(q["correct_rate"]) * int(q["total"])
        if g["worst"] is None or float(q["correct_rate"]) < g["worst"]["correct_rate"]:
            g["worst"] = {"qid": q.get("qid"), "number": q.get("number"), "correct_rate": float(q["correct_rate"])}
    out = []
    for g in agg.values():
        g["correct_rate"] = round(g.pop("points") / g["answers"], 4) if g["answers"] else None
        out.append(g)
    out.sort(key=lambda g: (g["correct_rate"] if g["correct_rate"] is not None else 2.0, -g["answers"]))
    return out[:limit] if limit else out


def hardest_questions(questions: Iterable[Mapping[str, Any]], *, limit: int = 5) -> List[Dict[str, Any]]:
    rows = [q for q in questions if not q.get("voided") and q.get("total") and q.get("correct_rate") is not None]
    rows.sort(key=lambda q: (float(q["correct_rate"]), number_key(q.get("number"))))
    return [dict(q) for q in rows[:limit]]


def violation_map(attempts: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sygnały rzetelności zebrane z całego egzaminu: rodzaj -> ile osób, ile zdarzeń, suma kar."""
    order = list(INTEGRITY_RULES.keys())
    kinds: Dict[Tuple[str, str], Dict[str, Any]] = {}
    levels = {"ok": 0, "warning": 0, "suspicious": 0}
    for a in attempts:
        integ = a.get("integrity") or {}
        level = integ.get("level")
        if level in levels:
            levels[level] += 1
        for b in integ.get("breakdown") or []:
            key = (str(b.get("kind") or ""), str(b.get("flag") or ""))
            g = kinds.setdefault(key, {"kind": key[0], "flag": key[1] or None, "label": b.get("label") or key[0],
                                       "people": 0, "events": 0, "penalty": 0})
            g["people"] += 1
            g["events"] += int(b.get("count") or 0)
            g["penalty"] += int(b.get("penalty") or 0)
    rows = sorted(kinds.values(), key=lambda g: (order.index((g["kind"], g["flag"] or "")) if (g["kind"], g["flag"] or "") in order else 99))
    return {"levels": levels, "kinds": rows, "clean": levels["ok"] == sum(levels.values())}


def province_comparison(attempts: Sequence[Mapping[str, Any]], missing: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Okręgi: zaproszeni (= przystąpili + nie przystąpili), frekwencja, zdawalność, średnia.
    Miejsce ex aequo po zdawalności, potem po średniej."""
    agg: Dict[str, Dict[str, Any]] = {}

    def g(prov: Any) -> Dict[str, Any]:
        name = str(prov or "Bez okręgu")
        return agg.setdefault(name, {"province": name, "invited": 0, "attended": 0, "finished": 0, "passed": 0, "_sum": 0.0})

    people: Dict[str, set] = {}
    for a in attempts:
        people.setdefault(str(a.get("province") or "Bez okręgu"), set()).add(str(a.get("judge_id")))
    for prov, ids in people.items():
        row = g(prov)
        row["attended"] = len(ids)
        row["invited"] += len(ids)
    for m in missing:
        g(m.get("province"))["invited"] += 1
    for a in best_attempts(attempts):
        row = g(a.get("province"))
        row["finished"] += 1
        row["passed"] += 1 if a.get("passed") else 0
        row["_sum"] += float(a["percent"])
    rows = []
    for row in agg.values():
        s = row.pop("_sum")
        row["attendance_rate"] = round(row["attended"] / row["invited"], 4) if row["invited"] else None
        row["pass_rate"] = round(row["passed"] / row["finished"], 4) if row["finished"] else None
        row["avg_percent"] = round(s / row["finished"], 2) if row["finished"] else None
        rows.append(row)
    rows.sort(key=lambda r: (-(r["pass_rate"] if r["pass_rate"] is not None else -1), -(r["avg_percent"] or 0), r["province"]))
    # Ex aequo po parze (zdawalność, średnia): klucz złożony -> jedna liczba porównywalna.
    keys = [None if r["pass_rate"] is None else r["pass_rate"] * 1000 + (r["avg_percent"] or 0) / 100 for r in rows]
    for row, place in zip(rows, place_ex_aequo(keys, digits=4)):
        row["place"] = place
    return rows


# ---------------------------------------------------------------------------
# Podgląd skutków unieważnienia
# ---------------------------------------------------------------------------


def void_preview(scores: Iterable[Mapping[str, Any]], qid: str, pass_percent: float) -> Dict[str, Any]:
    """Co się stanie z wynikami po unieważnieniu `qid` w trybie drop i credit.

    `scores`: score_json zakończonych podejść (`questions:[{qid,points,max,voided}]`, `passed`, `percent`).
    Liczone z tych samych wierszy, z których serwer przelicza - komisja widzi liczby, nie obietnice."""
    out: Dict[str, Any] = {"qid": qid}
    rows = [s for s in scores if s]
    for mode in ("drop", "credit"):
        newly_passed = newly_failed = 0
        before_sum = after_sum = 0.0
        affected = 0
        for s in rows:
            qs = s.get("questions") or []
            if not any(r.get("qid") == qid for r in qs):
                before_sum += float(s.get("percent") or 0)
                after_sum += float(s.get("percent") or 0)
                continue
            affected += 1
            points = maximum = 0.0
            for r in qs:
                if r.get("qid") == qid:
                    if mode == "credit":
                        points += 1.0
                        maximum += 1.0
                    continue
                points += float(r.get("points") or 0)
                maximum += float(r.get("max") or 0)
            percent = round(points / maximum * 100, 2) if maximum else 0.0
            passed = bool(maximum) and percent + 1e-9 >= float(pass_percent)
            before_sum += float(s.get("percent") or 0)
            after_sum += percent
            if passed and not s.get("passed"):
                newly_passed += 1
            elif s.get("passed") and not passed:
                newly_failed += 1
        n = len(rows)
        out[mode] = {
            "affected": affected,
            "newly_passed": newly_passed,
            "newly_failed": newly_failed,
            "avg_before": round(before_sum / n, 2) if n else None,
            "avg_after": round(after_sum / n, 2) if n else None,
        }
    out["finished"] = len(rows)
    return out


# ---------------------------------------------------------------------------
# Opcje eksportu
# ---------------------------------------------------------------------------


def clean_export_options(raw: Mapping[str, Any], *, national: bool) -> Dict[str, Any]:
    fmt = str(raw.get("format") or "pdf").lower()
    if fmt not in EXPORT_FORMATS:
        raise ExamError("BAD_EXPORT", f"Format pliku: dozwolone są {', '.join(EXPORT_FORMATS)}.")
    rng = str(raw.get("range") or "best")
    if rng not in EXPORT_RANGES:
        raise ExamError("BAD_EXPORT", "Zakres: najlepsze podejście, wszystkie, tylko zaliczone albo tylko niezaliczone.")
    theme = str(raw.get("theme") or "paper")
    if theme not in EXPORT_THEMES:
        raise ExamError("BAD_EXPORT", "Motyw pliku: papier (jasny) albo noc (ciemny).")
    sections_raw = raw.get("sections")
    sections = list(DEFAULT_SECTIONS) if sections_raw is None else [str(s) for s in sections_raw]
    unknown = [s for s in sections if s not in EXPORT_SECTIONS]
    if unknown:
        raise ExamError("BAD_EXPORT", f"Nie znam sekcji raportu: {', '.join(unknown)}.")
    if "provinces" in sections and not national:
        sections.remove("provinces")
    if not sections:
        raise ExamError("BAD_EXPORT", "Zaznacz co najmniej jedną sekcję raportu - pusty plik nikomu się nie przyda.")
    ordered = [s for s in EXPORT_SECTIONS if s in sections]
    anon = raw.get("anonymize")
    anonymize = ("cards" in ordered) if anon is None else bool(anon)
    return {"format": fmt, "range": rng, "theme": theme, "anonymize": anonymize,
            "seal": raw.get("seal") is not False, "sections": ordered}


def select_rows(attempts: Sequence[Mapping[str, Any]], rng: str) -> List[Dict[str, Any]]:
    """Wiersze listy wyników wg zakresu - zawsze z miejscem ex aequo w obrębie zakresu."""
    if rng == "all":
        rows = sorted([dict(a) for a in attempts if a.get("status") in FINISHED and a.get("percent") is not None],
                      key=_attempt_sort_key)
        for row, place in zip(rows, place_ex_aequo([r.get("percent") for r in rows])):
            row["place"] = place
        return rows
    rows = ranking(attempts)
    if rng == "passed":
        rows = [r for r in rows if r.get("passed")]
    elif rng == "failed":
        rows = [r for r in rows if not r.get("passed")]
    else:
        return rows
    for row, place in zip(rows, place_ex_aequo([r.get("percent") for r in rows])):
        row["place"] = place
    return rows


def anonymize(rows: Sequence[Dict[str, Any]], missing: Sequence[Dict[str, Any]]) -> None:
    """Nazwiska -> „Zdający 001" (ta sama osoba = ten sam numer w każdej sekcji).
    Numer z kolejności alfabetycznej, nie z rankingu - kod nie zdradza miejsca."""
    label: Dict[str, str] = {}
    for r in list(rows) + list(missing):
        jid = str(r.get("judge_id"))
        label.setdefault(jid, str(r.get("judge_name") or r.get("name") or jid).lower())
    names = sorted(label, key=lambda jid: (label[jid], jid))
    code = {jid: f"Zdający {i + 1:03d}" for i, jid in enumerate(names)}
    for r in rows:
        r["judge_name"] = code[str(r.get("judge_id"))]
    for m in missing:
        m["name"] = code[str(m.get("judge_id"))]


def export_filename(exam_name: str, fmt: str, when: datetime) -> str:
    base = unicodedata.normalize("NFKD", exam_name or "egzamin").encode("ascii", "ignore").decode("ascii")
    base = re.sub(r"[^A-Za-z0-9]+", "-", base).strip("-").lower()[:60] or "egzamin"
    return f"wyniki-{base}-{when.strftime('%Y-%m-%d')}.{fmt}"
