"""
Egzamin z przepisów - statystyki łączne teczki i karta sędziego: reguły bez bazy (17.10.2026).

Kontrakt: BAZA/docs/egzamin-api.md (sekcja „Statystyki łączne i karta sędziego").

Wszystko liczy się z KOMÓREK: jedna komórka = (egzamin, osoba), osoba
zaproszona albo taka, która podeszła. To ta sama definicja, co w raporcie
komisji (`exam_report_rules.summary`):
  - osoba liczy się w egzaminie RAZ - najlepszym zakończonym podejściem
    (przy równym procencie wcześniejszym),
  - `invited` = przystąpili + nie przystąpili,
  - czas pisania z KAŻDEGO zakończonego podejścia (jak `avg_duration_s` raportu),
więc liczby jednego egzaminu w statystykach i w raporcie są identyczne.

Grupy: odznaki okręgu (osoba z kilkoma odznakami jest w każdej), szczebel
z liter uprawnień ZPRP (najwyższa litera), pary sędziowskie (średnia pary =
średnia z dwóch średnich osób) i okręg. Miejsca ex aequo (1, 2, 2, 4) wg
wybranej miary; czas pisania krótszy = wyżej.

Najsłabsze przepisy: punkty / maksimum z pytań przepisu we wszystkich
zakończonych podejściach (unieważnione pytania odpadają), w kubełkach czasu.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app import exam_report_rules as RR
from app.assignment_people import letter_key
from app.exam_rules import ExamError

FINISHED = RR.FINISHED

METRICS = ("avg_percent", "pass_rate", "median_percent", "avg_duration_s", "attendance_rate")
METRIC_LABELS = {
    "avg_percent": "średni wynik",
    "pass_rate": "zdawalność",
    "median_percent": "mediana wyniku",
    "avg_duration_s": "czas pisania",
    "attendance_rate": "frekwencja",
}
#: Miary, w których mniej znaczy lepiej (miejsce 1 = najkrótszy czas).
LOWER_IS_BETTER = frozenset({"avg_duration_s"})
BUCKETS = ("exam", "month", "season")
GROUPINGS = ("badge", "level", "pair", "province")
SOURCES = ("national", "all")

#: Szczebel sędziego: najwyższa litera uprawnień z formularza obsady ZPRP.
LEVELS: List[Tuple[str, str]] = [
    ("SL", "Superliga"),
    ("LC", "Ligi centralne"),
    ("I", "I liga"),
    ("II", "II liga"),
    ("III", "III liga"),
    ("ML", "Młodzież"),
    ("none", "Bez uprawnień ZPRP"),
]
LEVEL_LABELS = dict(LEVELS)
LEVEL_ORDER = {key: i for i, (key, _) in enumerate(LEVELS)}
NO_BADGE = "Bez odznaki"
NO_PROVINCE = "Bez okręgu"

MONTHS_PL = ("sty", "lut", "mar", "kwi", "maj", "cze", "lip", "sie", "wrz", "paź", "lis", "gru")
#: Szerokości kubełków rozkładu czasu pisania (s) - pierwsza, przy której mieści się w 12 kubełkach.
DURATION_STEPS = (15, 30, 60, 120, 180, 300, 600, 900, 1800, 3600)
MAX_DURATION_BINS = 12
SPARK_LEN = 8


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
    value = _aware(value)
    return value.isoformat() if value else None


def _mean(values: Sequence[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


def _r(value: Optional[float], digits: int = 2) -> Optional[float]:
    return None if value is None else round(value, digits)


# ---------------------------------------------------------------------------
# Filtry (zero cichych blokad: zła wartość = zdanie po polsku)
# ---------------------------------------------------------------------------


def _bad(message: str) -> ExamError:
    return ExamError("BAD_FILTER", message, 400)


def clean_filters(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Parametry zapytania -> filtry. `exams` = lista id (pusta = wszystkie z okresu)."""
    bucket = _s(raw.get("bucket")) or "exam"
    if bucket not in BUCKETS:
        raise _bad("Statystyki: podział w czasie to „exam” (każdy egzamin), „month” (miesiące) albo „season” (sezony).")
    metric = _s(raw.get("metric")) or "avg_percent"
    if metric not in METRICS:
        raise _bad("Statystyki: nie znam takiej miary. Wybierz: " + ", ".join(METRIC_LABELS.values()) + ".")
    source = _s(raw.get("source")) or "national"
    if source not in SOURCES:
        raise _bad("Statystyki: źródło egzaminów kraju to „national” (krajowe) albo „all” (krajowe i okręgowe).")
    out: Dict[str, Any] = {"bucket": bucket, "metric": metric, "source": source}
    for key in ("from", "to"):
        text = _s(raw.get(key))
        if not text:
            out[key] = None
            continue
        try:
            out[key] = _aware(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError:
            raise _bad(f"Statystyki: data „{text}” jest nieczytelna (oczekuję RRRR-MM-DD).")
        if out[key] is None:
            raise _bad(f"Statystyki: data „{text}” jest nieczytelna (oczekuję RRRR-MM-DD).")
    if out["from"] and out["to"] and out["from"] > out["to"]:
        raise _bad("Statystyki: początek okresu jest późniejszy niż jego koniec.")
    exams = raw.get("exams")
    if isinstance(exams, str):
        exams = [x for x in exams.split(",")]
    out["exams"] = list(dict.fromkeys(_s(x) for x in exams or [] if _s(x)))
    try:
        out["rules_limit"] = max(1, min(30, int(raw.get("rules_limit") or 6)))
    except (TypeError, ValueError):
        raise _bad("Statystyki: liczba przepisów musi być liczbą od 1 do 30.")
    return out


# ---------------------------------------------------------------------------
# Kim jest sędzia
# ---------------------------------------------------------------------------


def level_of(letters: Iterable[Any]) -> str:
    """Najwyższa litera uprawnień: SL > LC > I > II > III > Mł; bez liter = „none"."""
    keys = {letter_key(x) for x in letters or () if _s(x)}
    for key, _ in LEVELS[:-1]:
        if key in keys:
            return key
    return "none"


def pair_key(a: Any, b: Any) -> str:
    x, y = sorted((_s(a), _s(b)))
    return f"{x}|{y}"


def clean_pairs(pairs: Mapping[str, str]) -> Dict[str, str]:
    """Tylko pary obustronne (A->B i B->A) - jednostronny wpis to nie para."""
    return {_s(a): _s(b) for a, b in (pairs or {}).items() if _s(a) and _s(b) and _s((pairs or {}).get(_s(b))) == _s(a)}


# ---------------------------------------------------------------------------
# Czas
# ---------------------------------------------------------------------------


def season_of(moment: datetime) -> str:
    """Sezon łamie się w sierpniu: 2026-08-01 .. 2027-07-31 = „2026/27"."""
    y = moment.year if moment.month >= 8 else moment.year - 1
    return f"{y}/{(y + 1) % 100:02d}"


def bucket_of(exam: Mapping[str, Any], bucket: str) -> Tuple[str, str, str]:
    """(klucz sortowalny, etykieta, początek ISO) kubełka egzaminu. Datą egzaminu jest otwarcie okna."""
    at = _aware(exam.get("opens_at"))
    if bucket == "exam" or at is None:
        when = at or datetime(1970, 1, 1, tzinfo=timezone.utc)
        return f"{when.isoformat()}#{exam['id']}", _s(exam.get("name")) or "Egzamin", when.isoformat()
    if bucket == "month":
        start = datetime(at.year, at.month, 1, tzinfo=timezone.utc)
        return start.strftime("%Y-%m"), f"{MONTHS_PL[at.month - 1]} {at.year}", start.isoformat()
    season = season_of(at)
    y = int(season[:4])
    return season, f"sezon {season}", datetime(y, 8, 1, tzinfo=timezone.utc).isoformat()


def duration_s(a: Mapping[str, Any]) -> Optional[float]:
    if a.get("status") not in FINISHED:
        return None
    start, end = _aware(a.get("started_at")), _aware(a.get("finished_at"))
    if start and end and end >= start:
        return (end - start).total_seconds()
    return None


# ---------------------------------------------------------------------------
# Komórki (egzamin, osoba)
# ---------------------------------------------------------------------------


def build_cells(
    exams: Sequence[Mapping[str, Any]],
    attempts: Sequence[Mapping[str, Any]],
    bucket: str,
) -> List[Dict[str, Any]]:
    """Komórka na (egzamin, osoba): zaproszeni (`exam["invited_ids"]`) + ci, którzy podeszli.

    Najlepsze zakończone podejście wybiera `exam_report_rules.best_attempts`
    (ta sama reguła co ranking raportu)."""
    by_exam: Dict[str, List[Mapping[str, Any]]] = {}
    for a in attempts:
        by_exam.setdefault(_s(a.get("exam_id")), []).append(a)
    cells: List[Dict[str, Any]] = []
    for exam in exams:
        eid = _s(exam["id"])
        key, label, start = bucket_of(exam, bucket)
        rows = by_exam.get(eid, [])
        best = {_s(b["judge_id"]): b for b in RR.best_attempts(rows)}
        per: Dict[str, List[Mapping[str, Any]]] = {}
        for a in rows:
            per.setdefault(_s(a.get("judge_id")), []).append(a)
        invited = {_s(j) for j in exam.get("invited_ids") or [] if _s(j)}
        for jid in sorted(invited | set(per)):
            mine = per.get(jid, [])
            b = best.get(jid)
            cells.append({
                "exam_id": eid,
                "judge_id": jid,
                "bucket": key,
                "bucket_label": label,
                "bucket_start": start,
                "attempted": bool(mine),
                "finished": b is not None,
                "percent": _f(b.get("percent")) if b else None,
                "passed": bool(b.get("passed")) if b else False,
                "durations": [d for d in (duration_s(a) for a in mine) if d is not None],
                "attempts": len(mine),
                "province": _s((b or (mine[0] if mine else {})).get("province")) or None,
                "name": _s((b or (mine[0] if mine else {})).get("judge_name")) or None,
            })
    return cells


def metrics(cells: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Liczby zbioru komórek - te same nazwy co `summary` raportu komisji."""
    finished = [c for c in cells if c["finished"]]
    percents = [float(c["percent"]) for c in finished]
    passed = sum(1 for c in finished if c["passed"])
    attended = sum(1 for c in cells if c["attempted"])
    durs = [d for c in cells for d in c["durations"]]
    return {
        "people": len({c["judge_id"] for c in cells if c["attempted"]}),
        "invited": len(cells),
        "attended": attended,
        "finished": len(finished),
        "passed": passed,
        "failed": len(finished) - passed,
        "pass_rate": round(passed / len(finished), 4) if finished else None,
        "avg_percent": _r(_mean(percents)),
        "median_percent": _r(RR._median(percents)),
        "attendance_rate": round(attended / len(cells), 4) if cells else None,
        "avg_duration_s": _r(_mean(durs), 1),
        "median_duration_s": _r(RR._median(durs), 1),
    }


def _series(cells: Sequence[Mapping[str, Any]], order: Sequence[str]) -> List[Dict[str, Any]]:
    groups: Dict[str, List[Mapping[str, Any]]] = {}
    for c in cells:
        groups.setdefault(c["bucket"], []).append(c)
    out = []
    for key in order:
        rows = groups.get(key)
        if not rows:
            continue
        m = metrics(rows)
        out.append({"bucket": key, "avg_percent": m["avg_percent"], "pass_rate": m["pass_rate"],
                    "median_percent": m["median_percent"], "avg_duration_s": m["avg_duration_s"],
                    "attendance_rate": m["attendance_rate"], "finished": m["finished"]})
    return out


def place_by(rows: List[Dict[str, Any]], metric: str) -> List[Dict[str, Any]]:
    """Sortuje wg miary i nadaje miejsca ex aequo; brak wartości na końcu bez miejsca."""
    low = metric in LOWER_IS_BETTER
    with_v = [r for r in rows if r.get(metric) is not None]
    without = [r for r in rows if r.get(metric) is None]
    with_v.sort(key=lambda r: ((r[metric] if low else -r[metric]), -int(r.get("finished") or 0), _s(r.get("label")).lower()))
    values = [(-r[metric] if low else r[metric]) for r in with_v]
    places = RR.place_ex_aequo(values)
    counts: Dict[int, int] = {}
    for p in places:
        if p is not None:
            counts[p] = counts.get(p, 0) + 1
    for r, p in zip(with_v, places):
        r["place"] = p
        r["shared"] = counts.get(p or 0, 0) > 1
    without.sort(key=lambda r: _s(r.get("label")).lower())
    for r in without:
        r["place"] = None
        r["shared"] = False
    return with_v + without


# ---------------------------------------------------------------------------
# Grupy
# ---------------------------------------------------------------------------


def _person(people: Mapping[str, Mapping[str, Any]], cell: Mapping[str, Any]) -> Mapping[str, Any]:
    return people.get(cell["judge_id"]) or {"name": cell.get("name"), "province": cell.get("province"), "badges": [], "letters": []}


def group_rows(
    cells: Sequence[Mapping[str, Any]],
    people: Mapping[str, Mapping[str, Any]],
    pairs: Mapping[str, str],
    grouping: str,
    metric: str,
    order: Sequence[str],
) -> List[Dict[str, Any]]:
    """Wiersze grupy z miarami, serią w czasie i miejscem ex aequo wg `metric`."""
    pairs = clean_pairs(pairs)
    members: Dict[str, Dict[str, Any]] = {}
    buckets: Dict[str, List[Mapping[str, Any]]] = {}

    def add(key: str, label: str, cell: Mapping[str, Any], extra: Optional[Dict[str, Any]] = None) -> None:
        g = members.setdefault(key, {"key": key, "label": label, "judges": set(), **(extra or {})})
        g["judges"].add(cell["judge_id"])
        buckets.setdefault(key, []).append(cell)

    for c in cells:
        p = _person(people, c)
        if grouping == "badge":
            badges = sorted({_s(b) for b in p.get("badges") or [] if _s(b)})
            for b in badges or [NO_BADGE]:
                add(b, b, c)
        elif grouping == "level":
            lv = level_of(p.get("letters") or [])
            add(lv, LEVEL_LABELS[lv], c, {"order": LEVEL_ORDER[lv]})
        elif grouping == "province":
            prov = _s(p.get("province")) or _s(c.get("province")) or NO_PROVINCE
            add(prov, prov, c)
        elif grouping == "pair":
            partner = pairs.get(c["judge_id"])
            if not partner:
                continue
            key = pair_key(c["judge_id"], partner)
            left, right = key.split("|")
            names = [_s((people.get(x) or {}).get("name")) or x for x in (left, right)]
            add(key, " - ".join(names), c, {"pair": [left, right]})

    out = []
    for key, g in members.items():
        rows = buckets[key]
        m = metrics(rows)
        row = {"key": key, "label": g["label"], "members": len(g["judges"]), **m, "series": _series(rows, order)}
        if "order" in g:
            row["order"] = g["order"]
        if grouping == "pair":
            persons = []
            for jid in g["pair"]:
                mine = [c for c in rows if c["judge_id"] == jid]
                pm = metrics(mine)
                persons.append({"judge_id": jid, "name": _s((people.get(jid) or {}).get("name")) or jid,
                                "avg_percent": pm["avg_percent"], "finished": pm["finished"], "passed": pm["passed"],
                                "avg_duration_s": pm["avg_duration_s"]})
            avgs = [x["avg_percent"] for x in persons if x["avg_percent"] is not None]
            durs = [x["avg_duration_s"] for x in persons if x["avg_duration_s"] is not None]
            # Średnia pary = średnia z dwóch średnich osób (każdy partner waży tyle samo,
            # nawet gdy jeden pisał więcej egzaminów).
            row["avg_percent"] = _r(_mean(avgs))
            row["avg_duration_s"] = _r(_mean(durs), 1)
            row["persons"] = persons
            row["complete"] = len(avgs) == 2
            row["series"] = _pair_series(rows, g["pair"], order)
        out.append(row)
    return place_by(out, metric)


def _pair_series(cells: Sequence[Mapping[str, Any]], pair: Sequence[str], order: Sequence[str]) -> List[Dict[str, Any]]:
    out = []
    for item in _series(cells, order):
        rows = [c for c in cells if c["bucket"] == item["bucket"]]
        avgs, durs = [], []
        for jid in pair:
            pm = metrics([c for c in rows if c["judge_id"] == jid])
            if pm["avg_percent"] is not None:
                avgs.append(pm["avg_percent"])
            if pm["avg_duration_s"] is not None:
                durs.append(pm["avg_duration_s"])
        out.append({**item, "avg_percent": _r(_mean(avgs)), "avg_duration_s": _r(_mean(durs), 1)})
    return out


# ---------------------------------------------------------------------------
# Rozkład czasu i przepisy
# ---------------------------------------------------------------------------


def duration_histogram(values: Sequence[float]) -> Dict[str, Any]:
    """Kubełki czasu pisania o „okrągłej" szerokości (15 s ... 1 h), najwyżej 12."""
    vals = sorted(v for v in values if v is not None and v >= 0)
    if not vals:
        return {"count": 0, "width_s": None, "bins": [], "avg_s": None, "median_s": None, "p90_s": None}
    top = vals[-1]
    width = next((w for w in DURATION_STEPS if top / w < MAX_DURATION_BINS), DURATION_STEPS[-1])
    n = min(MAX_DURATION_BINS, int(top // width) + 1)
    bins = [0] * n
    for v in vals:
        bins[min(n - 1, int(v // width))] += 1
    p90 = vals[min(len(vals) - 1, int(round(0.9 * (len(vals) - 1))))]
    return {
        "count": len(vals),
        "width_s": width,
        "bins": [{"from_s": i * width, "to_s": (i + 1) * width, "count": c} for i, c in enumerate(bins)],
        "avg_s": round(sum(vals) / len(vals), 1),
        "median_s": round(RR._median(vals), 1),
        "p90_s": round(p90, 1),
    }


def rule_points(
    attempts: Iterable[Mapping[str, Any]],
    qinfo: Mapping[str, Mapping[str, Tuple[Any, Any]]],
    bucket_by_exam: Mapping[str, str],
) -> Dict[Any, Dict[str, Dict[str, float]]]:
    """przepis -> kubełek -> {points, max, answers} z zakończonych podejść (bez unieważnionych)."""
    out: Dict[Any, Dict[str, Dict[str, float]]] = {}
    for a in attempts:
        if a.get("status") not in FINISHED:
            continue
        eid = _s(a.get("exam_id"))
        info = qinfo.get(eid) or {}
        bucket = bucket_by_exam.get(eid)
        if bucket is None:
            continue
        for q in (a.get("score") or {}).get("questions") or []:
            if q.get("voided") or not _f(q.get("max")):
                continue
            rule = (info.get(_s(q.get("qid"))) or (None, None))[0]
            g = out.setdefault(rule, {}).setdefault(bucket, {"points": 0.0, "max": 0.0, "answers": 0})
            g["points"] += float(q.get("points") or 0.0)
            g["max"] += float(q.get("max") or 0.0)
            g["answers"] += 1
    return out


def weak_rules(points: Mapping[Any, Mapping[str, Mapping[str, float]]], order: Sequence[str], limit: int) -> Dict[str, Any]:
    """Przepisy od najsłabszego (całość okresu), każdy z serią w kubełkach."""
    rows = []
    for rule, per in points.items():
        pts = sum(v["points"] for v in per.values())
        mx = sum(v["max"] for v in per.values())
        if not mx:
            continue
        series = [{"bucket": b, "correct_rate": round(per[b]["points"] / per[b]["max"], 4), "answers": int(per[b]["answers"])}
                  for b in order if b in per and per[b]["max"]]
        rows.append({"rule": rule, "label": RR.rule_label(rule), "correct_rate": round(pts / mx, 4),
                     "answers": int(sum(v["answers"] for v in per.values())), "series": series})
    rows.sort(key=lambda r: (r["correct_rate"], -r["answers"], RR._pct(r["rule"]) if r["rule"] is not None else 999))
    return {"total": len(rows), "rules": rows[:limit] if limit else rows}


# ---------------------------------------------------------------------------
# Przegląd teczki
# ---------------------------------------------------------------------------


def _bucket_order(exams: Sequence[Mapping[str, Any]], bucket: str) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
    meta: Dict[str, Dict[str, Any]] = {}
    for e in exams:
        key, label, start = bucket_of(e, bucket)
        m = meta.setdefault(key, {"bucket": key, "label": label, "start": start, "exams": []})
        m["exams"].append(_s(e["id"]))
    order = sorted(meta)
    return order, meta


def exam_brief(exam: Mapping[str, Any]) -> Dict[str, Any]:
    return {"id": exam["id"], "name": exam.get("name"), "scope": exam.get("scope"), "province": exam.get("province"),
            "opens_at": _iso(exam.get("opens_at")), "closes_at": _iso(exam.get("closes_at")),
            "pass_percent": _f(exam.get("pass_percent")), "question_count": exam.get("question_count"),
            "state": exam.get("state")}


def overview(
    exams: Sequence[Mapping[str, Any]],
    attempts: Sequence[Mapping[str, Any]],
    people: Mapping[str, Mapping[str, Any]],
    pairs: Mapping[str, str],
    qinfo: Mapping[str, Mapping[str, Tuple[Any, Any]]],
    filters: Mapping[str, Any],
    *,
    national: bool,
) -> Dict[str, Any]:
    """Statystyki łączne wybranych egzaminów: przegląd, trend, czas, przepisy, grupy."""
    bucket, metric = filters["bucket"], filters["metric"]
    exams = sorted(exams, key=lambda e: (_aware(e.get("opens_at")) or datetime.min.replace(tzinfo=timezone.utc), _s(e["id"])))
    ids = {_s(e["id"]) for e in exams}
    attempts = [a for a in attempts if _s(a.get("exam_id")) in ids]
    cells = build_cells(exams, attempts, bucket)
    order, meta = _bucket_order(exams, bucket)
    by_exam: Dict[str, List[Mapping[str, Any]]] = {}
    for c in cells:
        by_exam.setdefault(c["exam_id"], []).append(c)

    per_exam = []
    for e in exams:
        m = metrics(by_exam.get(_s(e["id"]), []))
        per_exam.append({**exam_brief(e), **m, "missing": m["invited"] - m["people"]})

    trend = []
    for key in order:
        rows = [c for c in cells if c["bucket"] == key]
        m = metrics(rows)
        trend.append({"bucket": key, "label": meta[key]["label"], "start": meta[key]["start"], "exams": meta[key]["exams"], **m})

    bucket_by_exam = {_s(e["id"]): bucket_of(e, bucket)[0] for e in exams}
    groups = {g: group_rows(cells, people, pairs, g, metric, order) for g in GROUPINGS if g != "province" or national}
    return {
        "filters": {"bucket": bucket, "metric": metric, "metric_label": METRIC_LABELS[metric], "source": filters.get("source"),
                    "from": _iso(filters.get("from")), "to": _iso(filters.get("to")), "exams": [e["id"] for e in exams]},
        "totals": {**metrics(cells), "exams": len(exams)},
        "exams": per_exam,
        "trend": trend,
        "durations": duration_histogram([d for c in cells for d in c["durations"]]),
        "weak_rules": weak_rules(rule_points(attempts, qinfo, bucket_by_exam), order, filters.get("rules_limit") or 6),
        "groups": groups,
        "levels": [{"key": k, "label": v} for k, v in LEVELS],
    }


# ---------------------------------------------------------------------------
# Sędziowie
# ---------------------------------------------------------------------------


def judge_rows(
    exams: Sequence[Mapping[str, Any]],
    attempts: Sequence[Mapping[str, Any]],
    people: Mapping[str, Mapping[str, Any]],
    pairs: Mapping[str, str],
    now: datetime,
) -> List[Dict[str, Any]]:
    """Lista sędziów zakresu: każdy z listy okręgu (także ci, którzy nic nie pisali)
    i każdy, kto podszedł spoza listy. Miejsce ex aequo wg średniego wyniku."""
    pairs = clean_pairs(pairs)
    exams = sorted(exams, key=lambda e: (_aware(e.get("opens_at")) or datetime.min.replace(tzinfo=timezone.utc), _s(e["id"])))
    ex = {_s(e["id"]): e for e in exams}
    cells = build_cells(exams, attempts, "exam")
    mine: Dict[str, List[Mapping[str, Any]]] = {}
    for c in cells:
        mine.setdefault(c["judge_id"], []).append(c)
    ids = set(people) | set(mine)
    rows = []
    for jid in ids:
        p = people.get(jid) or {}
        cs = mine.get(jid, [])
        m = metrics(cs)
        done = [c for c in cs if c["finished"]]  # chronologicznie, bo komórki idą wg egzaminów
        last = done[-1] if done else None
        prev = done[-2] if len(done) > 1 else None
        closed_missing = sum(1 for c in cs if not c["attempted"] and (_aware(ex[c["exam_id"]].get("closes_at")) or now) <= now)
        partner = pairs.get(jid)
        lv = level_of(p.get("letters") or [])
        name = _s(p.get("name")) or next((c["name"] for c in cs if c.get("name")), None) or jid
        rows.append({
            "judge_id": jid,
            "name": name,
            "label": name,
            "province": _s(p.get("province")) or next((c["province"] for c in cs if c.get("province")), None),
            "badges": sorted({_s(b) for b in p.get("badges") or [] if _s(b)}),
            "level": lv,
            "level_label": LEVEL_LABELS[lv],
            "partner_id": partner,
            "partner_name": _s((people.get(partner) or {}).get("name")) or None if partner else None,
            "in_roster": jid in people,
            "invited": m["invited"],
            "exams": m["finished"],
            "attempts": sum(c["attempts"] for c in cs),
            "passed": m["passed"],
            "pass_rate": m["pass_rate"],
            "avg_percent": m["avg_percent"],
            "finished": m["finished"],
            "avg_duration_s": m["avg_duration_s"],
            "missing": closed_missing,
            "last": {"exam_id": last["exam_id"], "exam_name": ex[last["exam_id"]].get("name"),
                     "at": _iso(ex[last["exam_id"]].get("opens_at")), "percent": last["percent"], "passed": last["passed"]} if last else None,
            "delta": _r(last["percent"] - prev["percent"]) if last and prev else None,
            "spark": [c["percent"] for c in done][-SPARK_LEN:],
            "in_progress": any(c["attempted"] and not c["finished"] for c in cs),
        })
    return place_by(rows, "avg_percent")


def judge_card(
    judge_id: str,
    exams: Sequence[Mapping[str, Any]],
    attempts: Sequence[Mapping[str, Any]],
    people: Mapping[str, Mapping[str, Any]],
    pairs: Mapping[str, str],
    qinfo: Mapping[str, Mapping[str, Tuple[Any, Any]]],
    integrity: Callable[[Mapping[str, Any]], Optional[Dict[str, Any]]],
    now: datetime,
) -> Dict[str, Any]:
    """Karta sędziego: seria wyników na tle zakresu, czasy, pełna historia podejść,
    najsłabsze przepisy osoby obok wyniku zakresu w tych samych przepisach."""
    jid = _s(judge_id)
    exams = sorted(exams, key=lambda e: (_aware(e.get("opens_at")) or datetime.min.replace(tzinfo=timezone.utc), _s(e["id"])))
    ex = {_s(e["id"]): e for e in exams}
    cells = build_cells(exams, attempts, "exam")
    scope_by_exam: Dict[str, List[Mapping[str, Any]]] = {}
    for c in cells:
        scope_by_exam.setdefault(c["exam_id"], []).append(c)
    mine_cells = [c for c in cells if c["judge_id"] == jid]
    mine_attempts = [a for a in attempts if _s(a.get("judge_id")) == jid]
    best_ids = {_s(b.get("id")) for e in exams for b in RR.best_attempts([a for a in mine_attempts if _s(a.get("exam_id")) == _s(e["id"])])}

    series = []
    for c in mine_cells:
        e = ex[c["exam_id"]]
        sm = metrics(scope_by_exam.get(c["exam_id"], []))
        series.append({"exam_id": c["exam_id"], "name": e.get("name"), "at": _iso(e.get("opens_at")),
                       "percent": c["percent"], "passed": c["passed"], "attempted": c["attempted"], "finished": c["finished"],
                       "pass_percent": _f(e.get("pass_percent")), "scope_avg": sm["avg_percent"], "scope_pass_rate": sm["pass_rate"],
                       "duration_s": round(min(c["durations"]), 1) if c["durations"] else None,
                       "scope_duration_s": sm["avg_duration_s"],
                       "missed": not c["attempted"] and (_aware(e.get("closes_at")) or now) <= now})

    history = []
    for a in sorted(mine_attempts, key=lambda a: (_aware(a.get("started_at")) or now, int(a.get("attempt_no") or 0)), reverse=True):
        e = ex.get(_s(a.get("exam_id"))) or {}
        info = qinfo.get(_s(a.get("exam_id"))) or {}
        voided = [{"qid": q.get("qid"), "number": (info.get(_s(q.get("qid"))) or (None, q.get("qid")))[1], "mode": q.get("voided")}
                  for q in (a.get("score") or {}).get("questions") or [] if q.get("voided")]
        history.append({
            "attempt_id": a.get("id"), "exam_id": a.get("exam_id"), "exam_name": e.get("name"), "exam_at": _iso(e.get("opens_at")),
            "attempt_no": a.get("attempt_no"), "status": a.get("status"), "finish_reason": a.get("finish_reason"),
            "started_at": _iso(a.get("started_at")), "finished_at": _iso(a.get("finished_at")), "duration_s": _r(duration_s(a), 1),
            "points": a.get("points"), "max": a.get("max"), "percent": _f(a.get("percent")), "passed": a.get("passed"),
            "pass_percent": _f(e.get("pass_percent")), "best": _s(a.get("id")) in best_ids,
            "voided": voided, "integrity": integrity(a),
        })

    bucket_by_exam = {_s(e["id"]): "all" for e in exams}
    own = rule_points(mine_attempts, qinfo, bucket_by_exam)
    scope_points = rule_points(attempts, qinfo, bucket_by_exam)
    rules = []
    for rule, per in own.items():
        v = per.get("all") or {}
        if not v.get("max"):
            continue
        sv = (scope_points.get(rule) or {}).get("all") or {}
        rules.append({"rule": rule, "label": RR.rule_label(rule), "correct_rate": round(v["points"] / v["max"], 4),
                      "answers": int(v["answers"]),
                      "scope_rate": round(sv["points"] / sv["max"], 4) if sv.get("max") else None})
    rules.sort(key=lambda r: (r["correct_rate"], -r["answers"]))

    p = people.get(jid) or {}
    cp = clean_pairs(pairs)
    partner = cp.get(jid)
    lv = level_of(p.get("letters") or [])
    m = metrics(mine_cells)
    name = _s(p.get("name")) or next((c["name"] for c in mine_cells if c.get("name")), None) or jid
    return {
        "judge": {"judge_id": jid, "name": name, "province": _s(p.get("province")) or next((c["province"] for c in mine_cells if c.get("province")), None),
                  "badges": sorted({_s(b) for b in p.get("badges") or [] if _s(b)}), "level": lv, "level_label": LEVEL_LABELS[lv],
                  "partner_id": partner, "partner_name": _s((people.get(partner) or {}).get("name")) or None if partner else None,
                  "in_roster": jid in people},
        "totals": {**m, "attempts": len(mine_attempts), "missing": sum(1 for s in series if s["missed"])},
        "series": series,
        "durations": [{"attempt_id": h["attempt_id"], "exam_name": h["exam_name"], "duration_s": h["duration_s"], "at": h["started_at"]}
                      for h in reversed(history) if h["duration_s"] is not None],
        "history": history,
        "weak_rules": rules,
    }
