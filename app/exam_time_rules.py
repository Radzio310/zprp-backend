"""Czas realny i czas poza egzaminem (decyzja 30.10.2026). Moduł-liść, bez bazy.

Samo „oddanie minus start" kłamie: arkusz otwarty w piątek i oddany automatycznie
w poniedziałek dawał „69 h" czasu pisania. Tu dzielimy podejście na dwie części:

  real_s  czas w egzaminie: główna liczba i sortowanie „czas pisania",
  away_s  czas poza nim, z rozbiciem na:
            measured_s  zmierzony: urządzenie zgłosiło wyjście i jego długość
                        (`app_background`/`resume` z `detail.seconds`),
            inferred_s  wywnioskowany z przerwy w arkuszu: między kolejnymi śladami
                        (pokazanie, odpowiedź) minęło więcej, niż dało się pisać.

Dlaczego to działa także dla starych podejść: `shown_at` i `answered_at` każdego pytania
są w bazie od początku. Limit na pytanie sam wyznacza górną granicę odcinka, a bez limitu
granicą jest `IDLE_CAP_S`. Bicie serca przeglądarki nie pomaga: trzymamy tylko ostatnie
(`beat_at`), historii przerw nie ma.

Bez ani jednego śladu pytania i przy podejściu dłuższym niż granica nie zgadujemy:
`known: False`, `real_s: None` - interfejs mówi wtedy wprost, że czasu nie znamy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

#: Bez limitu na pytanie: dłużej niż kwadrans nad jednym śladem to przerwa, nie czytanie.
IDLE_CAP_S = 900.0
#: Od odpowiedzi do pokazania następnego pytania mija tyle, ile idzie sieć.
BETWEEN_CAP_S = 45.0
#: Zapas ponad limit pytania (zegar telefonu i sieć).
LIMIT_GRACE_S = 5.0
#: Na osi pokazujemy przerwy od tej długości; krótsze liczą się tylko do sumy.
AXIS_MIN_GAP_S = 5.0
AXIS_MAX_GAPS = 30

#: Rodzaje zdarzeń niosące długość wyjścia w `detail.seconds`.
ABSENCE_KINDS = ("app_background", "resume")

Span = Tuple[datetime, datetime]


def _aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _merge(spans: Iterable[Span]) -> List[Span]:
    out: List[Span] = []
    for start, end in sorted(spans, key=lambda s: s[0]):
        if end <= start:
            continue
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def measured_spans(events: Iterable[Mapping[str, Any]], start: datetime, end: datetime) -> List[Span]:
    """Zgłoszone wyjścia jako odcinki: zgłoszenie idzie PO powrocie, więc kończy się w chwili zapisu."""
    spans: List[Span] = []
    for e in events:
        if e.get("kind") not in ABSENCE_KINDS:
            continue
        detail = e.get("detail") if isinstance(e.get("detail"), Mapping) else {}
        at = _aware(e.get("at"))
        try:
            seconds = float(detail.get("seconds") or 0)
        except (TypeError, ValueError):
            seconds = 0.0
        if at is None or seconds <= 0:
            continue
        spans.append((max(start, at - timedelta(seconds=seconds)), min(end, at)))
    return _merge(spans)


def _cut(start: datetime, end: datetime, spans: List[Span]) -> Tuple[List[Span], List[Span]]:
    """Dzieli odcinek na części poza zgłoszonymi wyjściami i części w ich trakcie."""
    free: List[Span] = []
    busy: List[Span] = []
    cursor = start
    for a, b in spans:
        if b <= cursor or a >= end:
            continue
        if a > cursor:
            free.append((cursor, a))
        busy.append((max(a, cursor), min(b, end)))
        cursor = min(b, end)
    if cursor < end:
        free.append((cursor, end))
    return free, busy


def _traces(answers: Iterable[Mapping[str, Any]], start: datetime, end: datetime) -> List[Tuple[datetime, str]]:
    """Ślady arkusza w czasie: `s` = pokazanie pytania, `a` = odpowiedź albo koniec jego czasu."""
    out: List[Tuple[datetime, str]] = []
    for row in answers:
        for key, tag in (("shown_at", "s"), ("answered_at", "a")):
            t = _aware(row.get(key))
            if t is not None:
                out.append((min(end, max(start, t)), tag))
    out.sort(key=lambda x: x[0])
    return out


def attempt_time(
    started_at: Any,
    finished_at: Any,
    answers: Iterable[Mapping[str, Any]],
    events: Iterable[Mapping[str, Any]],
    limit_s: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Podział czasu podejścia. None = podejście bez dwóch końców (jeszcze trwa)."""
    start, end = _aware(started_at), _aware(finished_at)
    if start is None or end is None or end < start:
        return None
    total = (end - start).total_seconds()
    measured = measured_spans(events, start, end)
    traces = _traces(answers, start, end)
    cap = float(limit_s) + LIMIT_GRACE_S if limit_s else IDLE_CAP_S

    if not traces and total > cap and not measured:
        return {"known": False, "total_s": round(total, 1), "real_s": None, "away_s": None,
                "measured_s": 0.0, "inferred_s": 0.0, "gaps": []}

    points = [(start, "start"), *traces, (end, "end")]
    real = 0.0
    gaps: List[Dict[str, Any]] = []
    for (u, ku), (v, kv) in zip(points, points[1:]):
        if v <= u:
            continue
        free, busy = _cut(u, v, measured)
        for a, b in busy:
            gaps.append({"from": a, "to": b, "source": "measured"})
        # Odpowiedź -> następne pytanie: tylko sieć. Reszta: ile da się siedzieć nad pytaniem.
        room = min(cap, BETWEEN_CAP_S) if ku == "a" and kv == "s" else cap
        for a, b in free:
            span = (b - a).total_seconds()
            used = min(span, room)
            room -= used
            real += used
            if span > used:
                gaps.append({"from": a + timedelta(seconds=used), "to": b, "source": "inferred"})

    merged = _merge_same_source(gaps)
    measured_s = sum((g["to"] - g["from"]).total_seconds() for g in merged if g["source"] == "measured")
    inferred_s = sum((g["to"] - g["from"]).total_seconds() for g in merged if g["source"] == "inferred")
    axis = [g for g in merged if (g["to"] - g["from"]).total_seconds() >= AXIS_MIN_GAP_S]
    axis = sorted(sorted(axis, key=lambda g: g["from"] - g["to"])[:AXIS_MAX_GAPS], key=lambda g: g["from"])
    return {
        "known": True,
        "total_s": round(total, 1),
        "real_s": round(real, 1),
        "away_s": round(max(0.0, total - real), 1),
        "measured_s": round(measured_s, 1),
        "inferred_s": round(inferred_s, 1),
        "gaps": [{"from_ms": int((g["from"] - start).total_seconds() * 1000), "to_ms": int((g["to"] - start).total_seconds() * 1000),
                  "seconds": round((g["to"] - g["from"]).total_seconds(), 1), "source": g["source"]} for g in axis],
    }


def _merge_same_source(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stykające się przerwy tego samego rodzaju to jedna przerwa (przerwa bywa pocięta śladami)."""
    out: List[Dict[str, Any]] = []
    for g in sorted(gaps, key=lambda x: x["from"]):
        if out and out[-1]["source"] == g["source"] and g["from"] <= out[-1]["to"] + timedelta(seconds=1):
            out[-1]["to"] = max(out[-1]["to"], g["to"])
        else:
            out.append(dict(g))
    return out


def active_ms(shown_at: Any, answered_at: Any, time_ms: Optional[float], gaps: Iterable[Mapping[str, Any]], started_at: Any) -> Optional[int]:
    """Czas na pytaniu bez przerw: pytanie otwarte w piątek i zamknięte w poniedziałek to nie 69 h na pytaniu."""
    if time_ms is None:
        return None
    start, shown, answered = _aware(started_at), _aware(shown_at), _aware(answered_at)
    if start is None or shown is None or answered is None:
        return int(time_ms)
    a = (shown - start).total_seconds() * 1000
    b = (answered - start).total_seconds() * 1000
    overlap = sum(max(0.0, min(b, float(g["to_ms"])) - max(a, float(g["from_ms"]))) for g in gaps)
    return max(0, int(time_ms - overlap))
