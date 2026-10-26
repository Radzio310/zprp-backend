"""
Egzamin - KARTA JEDNEGO SĘDZIEGO jako HTML (i PDF przez weasyprint), studio eksportu 26.10.2026.

Czysty moduł: dostaje raport komisji (`exam_report_service.build_report`), przegląd
podejścia komisji (`exam_service.committee_review`), kartotekę sędziego
(`exam_record.judge_record`, może być None) i zdjęcie jako data URI. Oddaje napis HTML.

Cztery układy (`layout`), każdy ze zdjęciem i wykresem:
  diploma   Świadectwo - dyplom w ramce, pieczęć okręgu ZALICZONY / NIEZALICZONY
  player    Karta zawodnika - pierścień wyniku, mapa arkusza, miejsce, czas, rozkład z kropką
  analysis  Raport analityczny - przepisy mocne i słabe, błędy z poprawną odpowiedzią,
            na tle egzaminu i okręgu, forma z kartoteki
  sheet     Arkusz odpowiedzi - dowodowy: pytanie po pytaniu, litery-pozycje jak
            widział zdający (a-d od góry), zaznaczenie, klucz, punkty, czas

Lustro w aplikacji (podgląd): `components/rulesExamResults/judgeSheet.ts` (`judgeFacts`)
i `JudgePage.tsx`. Liczby liczy `judge_facts` - te same reguły w obu miejscach.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from math import cos, pi, sin
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from app import exam_report_rules as R
from app.exam_print_theme import brand_logo_uri, theme_for

Progress = Callable[[str, int, int, Optional[str]], None]

LAYOUTS = ("diploma", "player", "analysis", "sheet")
BLOCKS = ("photo", "ring", "map", "place", "time", "rules", "mistakes", "average", "form", "integrity", "answers", "seal")
#: Co dany układ potrafi pokazać (kolejność = kolejność w studiu). Reszta odpada bez błędu.
LAYOUT_BLOCKS: Dict[str, Sequence[str]] = {
    "diploma": ("photo", "ring", "map", "place", "time", "seal"),
    "player": ("photo", "ring", "map", "place", "time", "average", "rules", "form"),
    "analysis": ("photo", "ring", "average", "rules", "mistakes", "form", "time", "integrity"),
    "sheet": ("photo", "answers", "map", "time", "integrity", "seal"),
}
LAYOUT_LABELS = {"diploma": "Świadectwo", "player": "Karta zawodnika", "analysis": "Raport analityczny", "sheet": "Arkusz odpowiedzi"}


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _pct(v: Any, digits: int = 0) -> str:
    if v is None:
        return "-"
    return f"{float(v):.{digits}f}".replace(".", ",") + "%"


def _dur(seconds: Any) -> str:
    if seconds is None:
        return "-"
    s = int(round(float(seconds)))
    return f"{s // 60} min {s % 60:02d} s" if s >= 60 else f"{s} s"


def _local(iso: Any) -> Optional[datetime]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo

        return dt.astimezone(ZoneInfo("Europe/Warsaw"))
    except Exception:  # noqa: BLE001
        return dt


def _when(iso: Any, with_time: bool = True) -> str:
    dt = _local(iso)
    if not dt:
        return "-"
    return dt.strftime("%d.%m.%Y %H:%M" if with_time else "%d.%m.%Y")


MONTHS = ("stycznia", "lutego", "marca", "kwietnia", "maja", "czerwca", "lipca", "sierpnia", "września",
          "października", "listopada", "grudnia")


def _long_date(iso: Any) -> str:
    dt = _local(iso)
    return f"{dt.day} {MONTHS[dt.month - 1]} {dt.year}" if dt else "-"


def initials(name: Any) -> str:
    parts = [p for p in str(name or "").replace("-", " ").split() if p]
    return "".join(p[0].upper() for p in parts[:2]) or "?"


# ---------------------------------------------------------------------------
# Liczby karty (lustro `judgeFacts` w aplikacji)
# ---------------------------------------------------------------------------


def question_state(q: Mapping[str, Any]) -> str:
    """good / partial / bad / skip / void - jedna litera na kratkę mapy arkusza."""
    if q.get("voided"):
        return "void"
    selected = q.get("selected") or []
    if not selected:
        return "skip"
    pts, mx = q.get("points"), q.get("max")
    if pts is None or mx is None:
        return "good" if sorted(selected) == sorted(q.get("correct_keys") or []) else "bad"
    if mx and float(pts) >= float(mx) - 1e-9:
        return "good"
    return "partial" if float(pts) > 0 else "bad"


def _letter(answers: Sequence[Mapping[str, Any]], key: str) -> str:
    keys = [a.get("key") for a in answers]
    return chr(97 + keys.index(key)) if key in keys else key


def judge_facts(report: Mapping[str, Any], review: Mapping[str, Any], record: Optional[Mapping[str, Any]],
                judge_id: str) -> Dict[str, Any]:
    exam = report.get("exam") or {}
    attempt = review.get("attempt") or {}
    result = review.get("result") or {}
    questions = list(review.get("questions") or [])
    ranking = list(report.get("ranking") or [])
    me = next((r for r in ranking if str(r.get("judge_id")) == str(judge_id)), None)
    province = (me or {}).get("province") or (record or {}).get("judge", {}).get("province")
    name = attempt.get("judge_name") or (me or {}).get("judge_name") or (record or {}).get("judge", {}).get("name") or str(judge_id)

    ranked = [r for r in ranking if r.get("percent") is not None]
    place = (me or {}).get("place")
    shared = bool(place) and sum(1 for r in ranked if r.get("place") == place) > 1
    percent = result.get("percent")
    below = sum(1 for r in ranked if percent is not None and float(r["percent"]) < float(percent) - 1e-9)
    beaten = round(below / max(1, len(ranked) - 1) * 100) if len(ranked) > 1 and percent is not None else None

    pkey = R.province_key(province)
    same = [float(r["percent"]) for r in ranked if pkey and R.province_key(r.get("province")) == pkey]
    province_avg = round(sum(same) / len(same), 2) if same else None
    exam_avg = (report.get("summary") or {}).get("avg_percent")

    cells: List[Dict[str, Any]] = []
    counts = {"good": 0, "partial": 0, "bad": 0, "skip": 0, "void": 0}
    by_rule: Dict[Any, Dict[str, Any]] = {}
    mistakes: List[Dict[str, Any]] = []
    answers: List[Dict[str, Any]] = []
    times: List[float] = []
    for q in questions:
        state = question_state(q)
        counts[state] += 1
        cells.append({"number": q.get("number"), "state": state, "rule": q.get("rule")})
        t_ms = q.get("time_ms") if q.get("time_ms") is not None else q.get("elapsed_ms")
        if t_ms is not None:
            times.append(float(t_ms) / 1000)
        if state != "void":
            g = by_rule.setdefault(q.get("rule"), {"rule": q.get("rule"), "label": R.rule_label(q.get("rule")), "right": 0.0, "total": 0})
            g["total"] += 1
            g["right"] += 1.0 if state == "good" else 0.5 if state == "partial" else 0.0
        opts = list(q.get("answers") or [])
        chosen = set(q.get("selected") or [])
        correct = set(q.get("correct_keys") or [])
        options = [{"letter": chr(97 + i), "text": a.get("text"), "chosen": a.get("key") in chosen, "correct": a.get("key") in correct}
                   for i, a in enumerate(opts)]
        answers.append({"number": q.get("number"), "text": q.get("text"), "state": state, "options": options,
                        "points": q.get("points"), "max": q.get("max"), "time_s": None if t_ms is None else round(float(t_ms) / 1000, 1),
                        "timed_out": bool(q.get("timed_out")), "changes": q.get("changes") or 0})
        if state in ("bad", "partial", "skip"):
            mistakes.append({
                "number": q.get("number"), "text": q.get("text"), "rule": R.rule_label(q.get("rule")), "state": state,
                "chosen": [(_letter(opts, k), next((a.get("text") for a in opts if a.get("key") == k), "")) for k in q.get("selected") or []],
                "correct": [(_letter(opts, k), next((a.get("text") for a in opts if a.get("key") == k), "")) for k in sorted(correct, key=lambda k: _letter(opts, k))],
                "difficulty": q.get("difficulty"), "timed_out": bool(q.get("timed_out")),
            })
    rules = []
    for g in by_rule.values():
        g["rate"] = round(g["right"] / g["total"], 4) if g["total"] else None
        rules.append(g)
    rules.sort(key=lambda g: (-(g["rate"] or 0), -g["total"], str(g["rule"])))
    strong = [g for g in rules if (g["rate"] or 0) >= 0.75][:3]
    weak = [g for g in reversed(rules) if (g["rate"] or 0) < 1][:3]

    form = []
    for f in list((record or {}).get("form") or [])[-6:]:
        form.append({"name": f.get("name"), "at": f.get("at"), "percent": f.get("percent"), "passed": f.get("passed"),
                     "pass_percent": f.get("pass_percent"), "current": str(f.get("exam_id")) == str(exam.get("id"))})

    integ = review.get("integrity") or {}
    duration = attempt.get("duration_s")
    answered = [t for t in times if t is not None]
    return {
        "judge_id": str(judge_id), "name": name, "initials": initials(name), "province": province,
        "exam": {"id": exam.get("id"), "name": exam.get("name"), "scope": exam.get("scope"), "province": exam.get("province"),
                 "cut_province": exam.get("cut_province"), "question_count": exam.get("question_count") or len(questions)},
        "percent": percent, "points": result.get("points"), "max": result.get("max"), "passed": bool(result.get("passed")),
        "pass_percent": result.get("pass_percent") if result.get("pass_percent") is not None else exam.get("pass_percent"),
        "attempt_no": attempt.get("attempt_no"), "attempt_id": review.get("attempt_id"),
        "started_at": attempt.get("started_at"), "finished_at": attempt.get("finished_at"), "finish_reason": attempt.get("finish_reason"),
        "duration_s": duration, "avg_q_s": round(sum(answered) / len(answered), 1) if answered else None,
        "place": place, "ranked": len(ranked), "shared": shared, "beaten": beaten,
        "exam_avg": exam_avg, "province_avg": province_avg,
        "histogram": list((report.get("summary") or {}).get("histogram_10pct") or [0] * 10),
        "map": cells, "counts": counts, "rules": rules, "strong": strong, "weak": weak,
        "mistakes": mistakes, "answers": answers, "form": form,
        "integrity": {"score": integ.get("score"), "level": integ.get("level"),
                      "items": [(b.get("label"), b.get("count")) for b in integ.get("breakdown") or [] if b.get("count")]},
    }


def clean_judge(raw: Any) -> Dict[str, Any]:
    """`judge` z ciała eksportu. Zła wartość = ValueError ze zdaniem (trasa zamienia na 400 BAD_EXPORT)."""
    if not isinstance(raw, Mapping):
        raise ValueError("Karta sędziego: brak danych sędziego (judge).")
    jid = str(raw.get("judge_id") or "").strip()
    aid = str(raw.get("attempt_id") or "").strip()
    if not jid or not aid:
        raise ValueError("Karta sędziego: podaj numer sędziego i podejście.")
    layout = str(raw.get("layout") or "player")
    if layout not in LAYOUTS:
        raise ValueError("Układ karty: świadectwo, karta zawodnika, raport analityczny albo arkusz odpowiedzi.")
    allowed = LAYOUT_BLOCKS[layout]
    blocks_raw = raw.get("blocks")
    if blocks_raw is None:
        blocks = list(allowed)
    else:
        if not isinstance(blocks_raw, (list, tuple)):
            raise ValueError("Elementy karty: oczekuję listy.")
        blocks = [b for b in allowed if b in {str(x) for x in blocks_raw}]
        if not blocks:
            raise ValueError("Zaznacz co najmniej jeden element karty - pusta kartka nikomu się nie przyda.")
    return {"judge_id": jid, "attempt_id": aid, "layout": layout, "blocks": blocks}


# ---------------------------------------------------------------------------
# Wykresy SVG
# ---------------------------------------------------------------------------


def _arc(c: float, r: float, value: float) -> str:
    a0 = -pi / 2
    a1 = a0 + 2 * pi * value
    x0, y0 = c + r * cos(a0), c + r * sin(a0)
    x1, y1 = c + r * cos(a1), c + r * sin(a1)
    return f"M {x0:.2f} {y0:.2f} A {r} {r} 0 {1 if value > 0.5 else 0} 1 {x1:.2f} {y1:.2f}"


def ring(percent: Any, pass_percent: Any, th: Mapping[str, Any], size: int = 150, label: str = "wynik") -> str:
    c, r, w = size / 2, size * 0.4, size * 0.085
    v = 0.0 if percent is None else max(0.0, min(1.0, float(percent) / 100))
    color = th["pass"] if (percent is not None and pass_percent is not None and float(percent) >= float(pass_percent)) else th["seal"]
    arc = (f'<circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{color}" stroke-width="{w}"/>' if v >= 0.9999 else
           f'<path d="{_arc(c, r, v)}" fill="none" stroke="{color}" stroke-width="{w}" stroke-linecap="round"/>' if v > 0 else "")
    tick = ""
    if pass_percent is not None:
        ang = -pi / 2 + 2 * pi * float(pass_percent) / 100
        x0, y0 = c + (r - w * 0.9) * cos(ang), c + (r - w * 0.9) * sin(ang)
        x1, y1 = c + (r + w * 0.9) * cos(ang), c + (r + w * 0.9) * sin(ang)
        tick = f'<line x1="{x0:.1f}" y1="{y0:.1f}" x2="{x1:.1f}" y2="{y1:.1f}" stroke="{th["ink"]}" stroke-width="{size * 0.014:.1f}"/>'
    return (f'<svg class="ring" width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">'
            f'<circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{th["track"]}" stroke-width="{w}"/>{arc}{tick}'
            f'<text x="{c}" y="{c + size * 0.07:.1f}" fill="{th["ink"]}" font-size="{size * 0.21:.1f}" font-weight="900" text-anchor="middle">{_pct(percent)}</text>'
            f'<text x="{c}" y="{c + size * 0.2:.1f}" fill="{th["soft"]}" font-size="{size * 0.072:.1f}" font-weight="700" text-anchor="middle">{_e(label)}</text></svg>')


def sheet_map(cells: Sequence[Mapping[str, Any]], th: Mapping[str, Any], cols: int = 10, cell: int = 30) -> str:
    """Mapa arkusza: kratka na pytanie w kolejności arkusza (zielona / żółta / czerwona / pusta / przekreślona)."""
    if not cells:
        return ""
    gap = 4
    rows = (len(cells) + cols - 1) // cols
    w, h = cols * (cell + gap) - gap, rows * (cell + gap) - gap
    fill = {"good": th["pass"], "partial": th["warn"], "bad": th["seal"], "skip": "none", "void": "none"}
    out = []
    for i, c in enumerate(cells):
        x, y = (i % cols) * (cell + gap), (i // cols) * (cell + gap)
        st = c["state"]
        stroke = th["line"] if st in ("skip", "void") else fill[st]
        out.append(f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" rx="{cell * 0.22:.1f}" fill="{fill[st]}" stroke="{stroke}" stroke-width="1.4"'
                   + (' stroke-dasharray="3 3"' if st == "skip" else "") + "/>")
        if st == "void":
            out.append(f'<line x1="{x + 5}" y1="{y + cell - 5}" x2="{x + cell - 5}" y2="{y + 5}" stroke="{th["soft"]}" stroke-width="1.4"/>')
        ink = th["soft"] if st in ("skip", "void") else ("#FFFFFF" if not th.get("dark") or st != "good" else th["bg"])
        out.append(f'<text x="{x + cell / 2}" y="{y + cell / 2 + 3.6:.1f}" fill="{ink}" font-size="{cell * 0.33:.1f}" font-weight="800" text-anchor="middle">{_e(c["number"])}</text>')
    return f'<svg class="map" width="{w}" height="{h}" viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">{"".join(out)}</svg>'


def dist_marker(hist: Sequence[int], percent: Any, pass_percent: Any, th: Mapping[str, Any], width: int = 300, height: int = 92) -> str:
    """Rozkład wyników egzaminu z kropką „tu jesteś"."""
    top, bottom = 18, 16
    inner = height - top - bottom
    peak = max(1, max(hist or [0]))
    bw = width / 10
    out = []
    for i, n in enumerate(hist):
        h = inner * n / peak
        color = th["pass"] if pass_percent is not None and (i + 1) * 10 > float(pass_percent) else th["fail"]
        out.append(f'<rect x="{i * bw + bw * 0.12:.1f}" y="{top + inner - max(h, 1.5):.1f}" width="{bw * 0.76:.1f}" height="{max(h, 1.5):.1f}" rx="3" fill="{color}" opacity="0.55"/>')
    if percent is not None:
        x = min(width - 4, max(4, width * float(percent) / 100))
        out.append(f'<line x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{top + inner}" stroke="{th["ink"]}" stroke-width="1.6"/>')
        out.append(f'<circle cx="{x:.1f}" cy="{top - 8}" r="5.5" fill="{th["accent"]}" stroke="{th["bg"]}" stroke-width="2"/>')
    out.append(f'<text x="0" y="{height - 3}" fill="{th["soft"]}" font-size="8.5">0%</text>'
               f'<text x="{width}" y="{height - 3}" fill="{th["soft"]}" font-size="8.5" text-anchor="end">100%</text>')
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">{"".join(out)}</svg>'


def form_chart(form: Sequence[Mapping[str, Any]], th: Mapping[str, Any], width: int = 320, height: int = 110) -> str:
    pts = [f for f in form if f.get("percent") is not None]
    if len(pts) < 2:
        return ""
    top, bottom, side = 14, 18, 14
    inner_w, inner_h = width - side * 2, height - top - bottom
    step = inner_w / (len(pts) - 1)
    xy = [(side + i * step, top + inner_h * (1 - float(f["percent"]) / 100)) for i, f in enumerate(pts)]
    path = "M " + " L ".join(f"{x:.1f} {y:.1f}" for x, y in xy)
    out = [f'<path d="{path}" fill="none" stroke="{th["accent"]}" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>']
    pp = next((f.get("pass_percent") for f in reversed(pts) if f.get("pass_percent") is not None), None)
    if pp is not None:
        y = top + inner_h * (1 - float(pp) / 100)
        out.insert(0, f'<line x1="{side}" y1="{y:.1f}" x2="{width - side}" y2="{y:.1f}" stroke="{th["seal"]}" stroke-width="1" stroke-dasharray="4 4"/>')
    for (x, y), f in zip(xy, pts):
        col = th["pass"] if f.get("passed") else th["seal"]
        r = 5.5 if f.get("current") else 3.8
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{col}" stroke="{th["bg"]}" stroke-width="1.6"/>')
        out.append(f'<text x="{x:.1f}" y="{height - 4}" fill="{th["soft"]}" font-size="8" text-anchor="middle">{_e(_when(f.get("at"), False)[:5])}</text>')
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">{"".join(out)}</svg>'


def seal(size: int, color: str, center: str, ring_text: str, sub: str = "", crest: str = "") -> str:
    c = size / 2
    r = size * 0.36
    fs = (2 * pi * r) / (max(24, len(ring_text)) * 0.76)
    cfs = min(size * 0.13, (size * 0.5) / (max(4, len(center)) * 0.7))
    pid = f"jsp{size}{sum(map(ord, ring_text)) % 9973}"
    return f"""<svg class="seal" width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
<defs><path id="{pid}" d="M {c - r},{c} a {r},{r} 0 1,1 {r * 2},0 a {r},{r} 0 1,1 {-r * 2},0"/></defs>
<circle cx="{c}" cy="{c}" r="{size * 0.47}" fill="none" stroke="{color}" stroke-width="{size * 0.03}"/>
<circle cx="{c}" cy="{c}" r="{size * 0.43}" fill="none" stroke="{color}" stroke-width="{size * 0.01}"/>
<circle cx="{c}" cy="{c}" r="{size * 0.29}" fill="none" stroke="{color}" stroke-width="{size * 0.012}"/>
<text fill="{color}" font-size="{fs:.2f}" font-weight="900" letter-spacing="{fs * 0.06:.2f}"><textPath href="#{pid}">{_e(ring_text)}</textPath></text>
{f'<image href="{crest}" x="{c - size * 0.11:.1f}" y="{c - size * 0.25:.1f}" width="{size * 0.22:.1f}" height="{size * 0.17:.1f}" preserveAspectRatio="xMidYMid meet" opacity="0.9"/>' if crest else ""}
<text x="{c}" y="{c + cfs * 0.36 + (size * 0.05 if crest else 0):.1f}" fill="{color}" font-size="{cfs:.2f}" font-weight="900" text-anchor="middle">{_e(center)}</text>
<text x="{c}" y="{c + cfs * 0.36 + (size * 0.05 if crest else 0) + fs * 1.6:.1f}" fill="{color}" font-size="{fs * 1.05:.2f}" font-weight="800" text-anchor="middle">{_e(sub)}</text>
</svg>"""


# ---------------------------------------------------------------------------
# Klocki
# ---------------------------------------------------------------------------


def _photo(f: Mapping[str, Any], photo: str, size_mm: int, cls: str = "") -> str:
    if photo:
        return f'<div class="photo {cls}" style="width:{size_mm}mm;height:{size_mm}mm"><img src="{photo}" alt=""/></div>'
    return (f'<div class="photo mono {cls}" style="width:{size_mm}mm;height:{size_mm}mm;font-size:{size_mm * 0.9:.1f}pt">'
            f'{_e(f["initials"])}</div>')


def _brand(crest: str) -> str:
    logo = brand_logo_uri()
    return ('<div class="brand">' + (f'<img class="logo" src="{logo}" alt="BAZA"/>' if logo else "")
            + (f'<img class="crest" src="{crest}" alt=""/>' if crest else "") + "</div>")


def _scope_line(f: Mapping[str, Any]) -> str:
    ex = f["exam"]
    if ex.get("cut_province"):
        return f"Egzamin ogólnopolski · okręg {ex['cut_province']}"
    return "Egzamin ogólnopolski" if ex.get("scope") == "national" else f"Egzamin okręgowy · {ex.get('province') or ''}"


def _ring_text(f: Mapping[str, Any]) -> str:
    ex = f["exam"]
    prov = ex.get("province") if ex.get("scope") != "national" else None
    if prov:
        return f"KOLEGIUM SĘDZIÓW • WOJEWÓDZTWO {str(prov).upper()} • EGZAMIN Z PRZEPISÓW • "
    return "ZWIĄZEK PIŁKI RĘCZNEJ W POLSCE • KOLEGIUM SĘDZIÓW • EGZAMIN • "


def _place_text(f: Mapping[str, Any]) -> str:
    if not f.get("place"):
        return "-"
    return f'{f["place"]}{" ex aequo" if f.get("shared") else ""} z {f["ranked"]}'


def _stat(value: str, label: str, cls: str = "") -> str:
    return f'<div class="stat {cls}"><b>{_e(value)}</b><span>{_e(label)}</span></div>'


def _rules_bars(rules: Sequence[Mapping[str, Any]], th: Mapping[str, Any], limit: int = 8) -> str:
    rows = []
    for g in list(rules)[:limit]:
        rate = g.get("rate") or 0
        color = th["pass"] if rate >= 0.75 else th["warn"] if rate >= 0.5 else th["seal"]
        right = f'{g["right"]:.1f}'.rstrip("0").rstrip(".").replace(".", ",")
        rows.append(f'<div class="rb"><div class="rl">{_e(g["label"])}</div><div class="rt"><i style="width:{rate * 100:.1f}%;background:{color}"></i></div>'
                    f'<div class="rv">{right}/{g["total"]}</div></div>')
    return "".join(rows)


def _versus(f: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    rows = [("Ten wynik", f.get("percent"), th["accent"]), ("Średnia egzaminu", f.get("exam_avg"), th["soft"])]
    if f.get("province_avg") is not None and f.get("province"):
        rows.append((f"Średnia okręgu {str(f['province']).lower()}", f.get("province_avg"), th["band2"]))
    out = []
    for label, v, color in rows:
        w = 0 if v is None else max(0.0, min(100.0, float(v)))
        out.append(f'<div class="vs"><div class="vl">{_e(label)}</div><div class="vt"><i style="width:{w:.1f}%;background:{color}"></i>'
                   + (f'<em style="left:{float(f["pass_percent"]):.1f}%"></em>' if f.get("pass_percent") is not None else "")
                   + f'</div><div class="vv">{_pct(v, 1)}</div></div>')
    return "".join(out)


def _mistakes(f: Mapping[str, Any], limit: Optional[int] = None) -> str:
    items = list(f["mistakes"])[:limit] if limit else list(f["mistakes"])
    if not items:
        return '<p class="note good">Bez jednego błędu - każde pytanie dobrze.</p>'
    out = []
    for m in items:
        chosen = ", ".join(f"{l}) {_e(t)}" for l, t in m["chosen"]) or ("brak odpowiedzi - minął czas" if m["timed_out"] else "brak odpowiedzi")
        correct = ", ".join(f"{l}) {_e(t)}" for l, t in m["correct"])
        diff = f' · poprawnie odpowiedziało {_pct(float(m["difficulty"]) * 100)}' if m.get("difficulty") is not None else ""
        out.append(f'<div class="mk"><div class="mh"><b>{_e(m["number"])}</b><span>{_e(m["rule"])}{diff}</span></div>'
                   f'<div class="mq">{_e(m["text"])}</div>'
                   f'<div class="ma no"><span>Zaznaczono</span>{chosen}</div><div class="ma ok"><span>Poprawnie</span>{correct}</div></div>')
    return "".join(out)


# ---------------------------------------------------------------------------
# Układy
# ---------------------------------------------------------------------------


def _diploma(f: Mapping[str, Any], th: Mapping[str, Any], blocks: Sequence[str], photo: str, crest: str) -> str:
    passed = f["passed"]
    title = "Świadectwo zdania egzaminu" if passed else "Zaświadczenie o przystąpieniu do egzaminu"
    verb = "zdał(a) egzamin z przepisów gry" if passed else "przystąpił(a) do egzaminu z przepisów gry"
    facts = []
    if "ring" in blocks:
        facts.append(f'<div class="dring">{ring(f["percent"], f["pass_percent"], th, 132)}</div>')
    stats = [_stat(f'{f.get("points") if f.get("points") is not None else "-"} / {f.get("max") or "-"}', "punkty"),
             _stat(_pct(f["pass_percent"]), "próg zaliczenia")]
    if "place" in blocks:
        stats.append(_stat(_place_text(f), "miejsce"))
    if "time" in blocks:
        stats.append(_stat(_dur(f.get("duration_s")), "czas pisania"))
    stamp = ""
    if "seal" in blocks:
        color = th["pass"] if passed else th["seal"]
        stamp = f'<div class="dseal">{seal(170, color, "ZALICZONY" if passed else "NIEZALICZONY", _ring_text(f), _when(f.get("finished_at"), False), crest)}</div>'
    mp = f'<div class="dmap"><div class="cap">Mapa arkusza</div>{sheet_map(f["map"], th, cols=15, cell=22)}</div>' if "map" in blocks else ""
    who = _photo(f, photo, 34, "dphoto") if "photo" in blocks else ""
    return f"""<section class="diploma">
<div class="frame"><div class="frame2">
{_brand(crest)}
<div class="dkick">{_e(_scope_line(f))}</div>
<h1 class="dtitle">{_e(title)}</h1>
<div class="dline"></div>
<p class="dlead">Kolegium Sędziów potwierdza, że</p>
{who}
<div class="dname">{_e(f["name"])}</div>
<div class="dprov">{_e(f.get("province") or "")}</div>
<p class="dlead">{verb}</p>
<div class="dexam">„{_e(f["exam"]["name"])}”</div>
<p class="dlead small">dnia {_e(_long_date(f.get("finished_at")))}, podejście {_e(f.get("attempt_no") or 1)}</p>
<div class="dfacts">{"".join(facts)}<div class="dstats">{"".join(stats)}</div></div>
{mp}
<div class="dfoot"><div class="sig"><i></i><span>przewodniczący komisji</span></div>{stamp}<div class="sig"><i></i><span>data i miejsce</span></div></div>
</div></div></section>"""


def _player(f: Mapping[str, Any], th: Mapping[str, Any], blocks: Sequence[str], photo: str, crest: str) -> str:
    passed = f["passed"]
    who = _photo(f, photo, 44, "pphoto") if "photo" in blocks else ""
    stats = []
    if "place" in blocks:
        stats.append(_stat(_place_text(f), "miejsce", "big"))
    stats.append(_stat(f'{f["counts"]["good"]}/{len(f["map"]) - f["counts"]["void"]}', "dobrze", "big"))
    if "time" in blocks:
        stats.append(_stat(_dur(f.get("duration_s")), "czas", "big"))
        stats.append(_stat(f'{f["avg_q_s"]:.0f} s'.replace(".", ",") if f.get("avg_q_s") is not None else "-", "na pytanie"))
    stats.append(_stat(str(f.get("attempt_no") or 1), "podejście"))
    if f.get("beaten") is not None and "place" in blocks:
        stats.append(_stat(f'{f["beaten"]}%', "wyprzedzonych"))
    left = []
    if "ring" in blocks:
        left.append(f'<div class="pring">{ring(f["percent"], f["pass_percent"], th, 168, "zaliczony" if passed else "niezaliczony")}</div>')
    body = []
    if "map" in blocks:
        body.append(f'<div class="card"><div class="cap">Mapa arkusza · kolejność pytań jak u zdającego</div>{sheet_map(f["map"], th, cols=10, cell=34)}'
                    f'<div class="legend"><i class="g"></i>dobrze <i class="p"></i>częściowo <i class="b"></i>źle <i class="s"></i>bez odpowiedzi</div></div>')
    body.append(f'<div class="card"><div class="cap">Na tle egzaminu</div>{dist_marker(f["histogram"], f["percent"], f["pass_percent"], th, 300, 92)}</div>')
    if "average" in blocks:
        body.append(f'<div class="card"><div class="cap">Porównanie</div>{_versus(f, th)}</div>')
    if "rules" in blocks and f["rules"]:
        body.append(f'<div class="card"><div class="cap">Przepisy</div>{_rules_bars(f["rules"], th, 6)}</div>')
    if "form" in blocks and form_chart(f["form"], th):
        body.append(f'<div class="card"><div class="cap">Forma · ostatnie egzaminy</div>{form_chart(f["form"], th, 300, 100)}</div>')
    return f"""<section class="player">
<div class="hero"><div class="stripes"></div>
{_brand(crest)}
<div class="prow">{who}<div class="pid"><div class="pkick">{_e(_scope_line(f))}</div><div class="pname">{_e(f["name"])}</div>
<div class="pprov">{_e(f.get("province") or "")}</div><div class="pexam">{_e(f["exam"]["name"])} · {_e(_when(f.get("finished_at"), False))}</div></div></div>
</div>
<div class="pmain"><div class="pleft">{"".join(left)}<div class="pstats">{"".join(stats)}</div></div><div class="pright">{"".join(body)}</div></div>
</section>"""


def _analysis(f: Mapping[str, Any], th: Mapping[str, Any], blocks: Sequence[str], photo: str, crest: str) -> str:
    who = _photo(f, photo, 22, "aphoto") if "photo" in blocks else ""
    kpis = [_stat(_pct(f["percent"], 1), "wynik"), _stat("zaliczony" if f["passed"] else "niezaliczony", f"próg {_pct(f['pass_percent'])}"),
            _stat(_place_text(f), "miejsce")]
    if "time" in blocks:
        kpis.append(_stat(_dur(f.get("duration_s")), "czas pisania"))
    parts = []
    top = []
    if "ring" in blocks:
        top.append(f'<div class="aring">{ring(f["percent"], f["pass_percent"], th, 120)}</div>')
    if "average" in blocks:
        top.append(f'<div class="avs"><div class="cap">Na tle egzaminu i okręgu</div>{_versus(f, th)}'
                   f'{dist_marker(f["histogram"], f["percent"], f["pass_percent"], th, 330, 70)}</div>')
    if top:
        parts.append(f'<div class="arow">{"".join(top)}</div>')
    if "rules" in blocks and f["rules"]:
        strong = "".join(f'<li><b>{_pct((g["rate"] or 0) * 100)}</b>{_e(g["label"])}</li>' for g in f["strong"]) or "<li>-</li>"
        weak = "".join(f'<li><b>{_pct((g["rate"] or 0) * 100)}</b>{_e(g["label"])}</li>' for g in f["weak"]) or "<li>-</li>"
        parts.append(f'<div class="arow"><div class="sw ok"><div class="cap">Mocne przepisy</div><ul>{strong}</ul></div>'
                     f'<div class="sw no"><div class="cap">Do powtórki</div><ul>{weak}</ul></div></div>'
                     f'<div class="block"><div class="cap">Wszystkie przepisy z arkusza</div>{_rules_bars(f["rules"], th, 14)}</div>')
    if "form" in blocks:
        chart = form_chart(f["form"], th, 520, 120)
        parts.append(f'<div class="block"><div class="cap">Forma · ostatnie egzaminy z kartoteki</div>'
                     + (chart or '<p class="note">To pierwszy egzamin w kartotece - forma pojawi się po kolejnym.</p>') + "</div>")
    if "integrity" in blocks:
        it = f["integrity"]
        items = "".join(f"<li>{_e(l)}: {c}×</li>" for l, c in it["items"]) or "<li>bez sygnałów</li>"
        parts.append(f'<div class="block"><div class="cap">Rzetelność {_e(it.get("score") if it.get("score") is not None else "-")}/100</div><ul class="flat">{items}</ul>'
                     '<p class="note">Wskaźnik jest sygnałem dla komisji. Nic nie dyskwalifikuje automatycznie.</p></div>')
    if "mistakes" in blocks:
        parts.append(f'<div class="block mistakes"><div class="cap">Błędy i poprawne odpowiedzi ({len(f["mistakes"])})</div>{_mistakes(f)}</div>')
    return f"""<section class="analysis">
<div class="ahead">{who}<div class="aid"><div class="akick">Raport analityczny · {_e(_scope_line(f))}</div><div class="aname">{_e(f["name"])}</div>
<div class="asub">{_e(f["exam"]["name"])} · {_e(_when(f.get("finished_at")))} · podejście {_e(f.get("attempt_no") or 1)}</div></div>{_brand(crest)}</div>
<div class="kpis">{"".join(kpis)}</div>
{"".join(parts)}
</section>"""


def _sheet(f: Mapping[str, Any], th: Mapping[str, Any], blocks: Sequence[str], photo: str, crest: str) -> str:
    who = _photo(f, photo, 20, "sphoto") if "photo" in blocks else ""
    meta = [("Zdający", f["name"]), ("Numer sędziego", f["judge_id"]), ("Okręg", f.get("province") or "-"),
            ("Egzamin", f["exam"]["name"]), ("Podejście", f"{f.get('attempt_no') or 1} · id {f.get('attempt_id') or '-'}"),
            ("Start", _when(f.get("started_at"))), ("Oddano", _when(f.get("finished_at"))),
            ("Wynik", f'{_pct(f["percent"], 1)} ({f.get("points")}/{f.get("max")} pkt) · {"zaliczony" if f["passed"] else "niezaliczony"}')]
    if "time" in blocks:
        meta.append(("Czas pisania", _dur(f.get("duration_s"))))
    if "integrity" in blocks:
        it = f["integrity"]
        meta.append(("Rzetelność", f'{it.get("score") if it.get("score") is not None else "-"}/100'
                     + (" · " + ", ".join(f"{l} {c}×" for l, c in it["items"]) if it["items"] else " · bez sygnałów")))
    table = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in meta)
    mp = f'<div class="smap">{sheet_map(f["map"], th, cols=20, cell=22)}</div>' if "map" in blocks else ""
    qs = []
    if "answers" in blocks:
        for q in f["answers"]:
            opts = "".join(
                f'<li class="{"c" if o["correct"] else ""} {"x" if o["chosen"] else ""}"><span class="box">{"■" if o["chosen"] else "□"}</span>'
                f'<b>{o["letter"]})</b> {_e(o["text"])}<em>{"klucz" if o["correct"] else ""}</em></li>' for o in q["options"])
            pts = "unieważnione" if q["state"] == "void" else f'{q.get("points") if q.get("points") is not None else 0}/{q.get("max") or 0} pkt'
            extra = []
            if q.get("time_s") is not None and "time" in blocks:
                extra.append(f'{str(q["time_s"]).replace(".", ",")} s')
            if q.get("timed_out"):
                extra.append("minął czas")
            if q.get("changes"):
                extra.append(f'zmiany: {q["changes"]}')
            qs.append(f'<article class="sq {q["state"]}"><header><b>{_e(q["number"])}</b><span class="st">{pts}</span>'
                      f'<span class="ex">{_e(" · ".join(extra))}</span></header><p>{_e(q["text"])}</p><ol>{opts}</ol></article>')
    stamp = seal(110, th["seal"], "KOMISJA", _ring_text(f), _when(datetime.now(timezone.utc).isoformat(), False)) if "seal" in blocks else ""
    return f"""<section class="sheet">
<div class="shead">{who}<div class="sid"><div class="skick">Arkusz odpowiedzi · dokument z zapisu serwera</div><div class="sname">{_e(f["name"])}</div></div>{_brand(crest)}</div>
<table class="meta">{table}</table>
{mp}
<p class="note">Litery a, b, c... to pozycje odpowiedzi w kolejności, w jakiej widział je zdający (kolejność bywa losowana). ■ = zaznaczone przez zdającego, „klucz" = poprawna odpowiedź.</p>
{"".join(qs)}
<div class="sfoot"><div class="sig"><i></i><span>podpis członka komisji</span></div>{stamp}<div class="sig"><i></i><span>podpis zdającego</span></div></div>
</section>"""


# ---------------------------------------------------------------------------
# Dokument
# ---------------------------------------------------------------------------


def _css(th: Mapping[str, Any], layout: str) -> str:
    serif = '"DejaVu Serif", Georgia, serif' if th.get("serif") else '"DejaVu Sans", "Noto Sans", Arial, sans-serif'
    title_font = '"DejaVu Serif", Georgia, serif' if th.get("serif") or layout == "diploma" else serif
    margin = "0" if layout in ("diploma", "player") else "13mm 13mm 15mm"
    return f"""
@page {{ size: A4 portrait; margin: {margin}; background: {th['bg']};
  @bottom-center {{ content: {'none' if layout in ('diploma', 'player') else '"Strona " counter(page) " z " counter(pages)'}; font-size: 8pt; color: {th['soft']}; }} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: {th['bg']}; color: {th['ink']}; font-family: "DejaVu Sans", "Noto Sans", Arial, sans-serif; font-size: 9.6pt; line-height: 1.4; }}
.cap {{ font-size: 7.6pt; font-weight: 900; letter-spacing: 1.4px; text-transform: uppercase; color: {th['accent']}; margin: 0 0 6px; }}
.note {{ color: {th['soft']}; font-size: 8.4pt; margin: 4px 0 8px; }}
.note.good {{ color: {th['pass']}; font-weight: 800; }}
.brand {{ display: flex; align-items: center; gap: 8px; }}
.brand .logo {{ height: 16mm; width: auto; }}
.brand .crest {{ height: 16mm; width: auto; }}
.photo {{ border-radius: 50%; overflow: hidden; border: 2.5px solid {th['band']}; background: {th['track']}; flex: none; }}
.photo img {{ width: 100%; height: 100%; object-fit: cover; }}
.photo.mono {{ display: flex; align-items: center; justify-content: center; color: {th['accent']}; font-weight: 900; font-family: {title_font}; }}
.stat b {{ display: block; font-size: 12pt; font-weight: 900; color: {th['ink']}; }}
.stat span {{ display: block; font-size: 7.4pt; text-transform: uppercase; letter-spacing: 1px; color: {th['soft']}; }}
.stat.big b {{ font-size: 13.5pt; white-space: nowrap; }}
.rb, .vs {{ display: flex; align-items: center; gap: 8px; margin-bottom: 5px; }}
.rl, .vl {{ width: 50%; font-size: 8.4pt; font-weight: 700; }}
.rt, .vt {{ flex: 1; height: 8px; border-radius: 4px; background: {th['track']}; position: relative; overflow: hidden; }}
.rt i, .vt i {{ display: block; height: 8px; border-radius: 4px; }}
.vt em {{ position: absolute; top: -2px; width: 1.5px; height: 12px; background: {th['seal']}; }}
.rv, .vv {{ width: 46px; text-align: right; font-weight: 900; font-size: 8.6pt; }}
.legend {{ font-size: 7.6pt; color: {th['soft']}; margin-top: 6px; }}
.legend i {{ display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin: 0 3px 0 8px; }}
.legend i.g {{ background: {th['pass']}; }} .legend i.p {{ background: {th['warn']}; }} .legend i.b {{ background: {th['seal']}; }}
.legend i.s {{ border: 1px dashed {th['soft']}; }}
.sig {{ width: 52mm; text-align: center; }}
.sig i {{ display: block; border-bottom: 1px solid {th['soft']}; height: 12mm; }}
.sig span {{ font-size: 7.4pt; color: {th['soft']}; text-transform: uppercase; letter-spacing: 1px; }}

/* Świadectwo */
.diploma {{ width: 210mm; height: 296mm; padding: 9mm; background: {th['bg']}; }}
.diploma .frame {{ height: 100%; border: 2.4mm solid {th['band']}; padding: 1.6mm; }}
.diploma .frame2 {{ height: 100%; border: 0.5mm solid {th['gold']}; padding: 10mm 14mm 8mm; text-align: center; display: flex; flex-direction: column; align-items: center; }}
.diploma .brand {{ width: 100%; justify-content: space-between; }}
.dkick {{ font-size: 8pt; letter-spacing: 2.4px; text-transform: uppercase; color: {th['soft']}; margin-top: 4mm; }}
.dtitle {{ font-family: {title_font}; font-size: 25pt; font-weight: 700; margin: 3mm 0 2mm; color: {th['accent']}; letter-spacing: 0.4px; }}
.dline {{ width: 40mm; height: 0.6mm; background: {th['gold']}; margin: 1mm auto 5mm; }}
.dlead {{ font-family: {title_font}; font-style: italic; color: {th['soft']}; margin: 1mm 0; font-size: 11pt; }}
.dlead.small {{ font-size: 9.5pt; }}
.dphoto {{ margin: 3mm auto 2mm; }}
.dname {{ font-family: {title_font}; font-size: 28pt; font-weight: 700; margin: 2mm 0 0; color: {th['ink']}; }}
.dprov {{ font-size: 8.5pt; letter-spacing: 2px; text-transform: uppercase; color: {th['soft']}; margin-bottom: 3mm; }}
.dexam {{ font-family: {title_font}; font-size: 14pt; font-weight: 700; margin: 1mm 0; }}
.dfacts {{ display: flex; align-items: center; justify-content: center; gap: 10mm; margin-top: 6mm; }}
.dstats {{ display: flex; flex-wrap: wrap; gap: 4mm 8mm; width: 82mm; text-align: left; }}
.dstats .stat {{ width: 36mm; }}
.dmap {{ margin-top: 6mm; }}
.dfoot {{ margin-top: auto; width: 100%; display: flex; align-items: flex-end; justify-content: space-between; }}
.dseal {{ transform: rotate(-11deg); margin-bottom: -2mm; }}

/* Karta zawodnika */
.player {{ width: 210mm; min-height: 296mm; background: {th['bg']}; }}
.hero {{ position: relative; background: {th['cover']}; color: {th['cover_ink']}; padding: 10mm 12mm 12mm; overflow: hidden; }}
.stripes {{ position: absolute; right: -30mm; top: -20mm; width: 120mm; height: 120mm; transform: rotate(28deg);
  background: repeating-linear-gradient(90deg, {th['band2']} 0, {th['band2']} 7mm, transparent 7mm, transparent 14mm); opacity: 0.28; }}
.hero .brand {{ position: relative; justify-content: space-between; }}
.prow {{ position: relative; display: flex; align-items: center; gap: 7mm; margin-top: 6mm; }}
.pphoto {{ border: 3px solid {th['cover_ink']}; }}
.pkick {{ font-size: 7.6pt; letter-spacing: 2px; text-transform: uppercase; color: {th['cover_soft']}; }}
.pname {{ font-family: {title_font}; font-size: 27pt; font-weight: 900; line-height: 1.05; margin: 2mm 0 1mm; }}
.pprov {{ font-size: 9pt; letter-spacing: 2px; text-transform: uppercase; color: {th['cover_soft']}; }}
.pexam {{ font-size: 9.5pt; margin-top: 2mm; color: {th['cover_soft']}; }}
.pmain {{ display: flex; gap: 7mm; padding: 8mm 12mm 10mm; }}
.pleft {{ width: 66mm; }}
.pring {{ text-align: center; margin-bottom: 4mm; }}
.pstats {{ display: flex; flex-wrap: wrap; gap: 4mm; }}
.pstats .stat {{ width: 31mm; background: {th['card']}; border: 1px solid {th['line']}; border-radius: 3mm; padding: 2.4mm 3mm; }}
.pright {{ flex: 1; }}
.card {{ background: {th['card']}; border: 1px solid {th['line']}; border-radius: 3.5mm; padding: 3.5mm 4mm; margin-bottom: 4mm; page-break-inside: avoid; }}

/* Raport analityczny */
.ahead, .shead {{ display: flex; align-items: center; gap: 5mm; border-bottom: 2px solid {th['band']}; padding-bottom: 4mm; margin-bottom: 4mm; }}
.aid, .sid {{ flex: 1; }}
.akick, .skick {{ font-size: 7.6pt; letter-spacing: 1.6px; text-transform: uppercase; color: {th['accent']}; font-weight: 900; }}
.aname, .sname {{ font-family: {title_font}; font-size: 20pt; font-weight: 900; }}
.asub {{ color: {th['soft']}; font-size: 8.6pt; }}
.kpis {{ display: flex; gap: 4mm; margin-bottom: 5mm; }}
.kpis .stat {{ flex: 1; background: {th['card']}; border: 1px solid {th['line']}; border-left: 3px solid {th['band']}; border-radius: 2.5mm; padding: 2.5mm 3.5mm; }}
.arow {{ display: flex; gap: 6mm; align-items: flex-start; margin-bottom: 5mm; page-break-inside: avoid; }}
.avs {{ flex: 1; }}
.sw {{ flex: 1; border: 1px solid {th['line']}; border-radius: 3mm; padding: 3mm 4mm; background: {th['card']}; }}
.sw ul {{ margin: 0; padding: 0; list-style: none; }}
.sw li {{ margin-bottom: 2mm; font-size: 8.6pt; }}
.sw li b {{ display: inline-block; width: 13mm; }}
.sw.ok li b {{ color: {th['pass']}; }} .sw.no li b {{ color: {th['seal']}; }}
.block {{ margin-bottom: 5mm; page-break-inside: avoid; }}
.block.mistakes {{ page-break-inside: auto; }}
ul.flat {{ margin: 0; padding-left: 14px; font-size: 8.6pt; }}
.mk {{ border: 1px solid {th['line']}; border-radius: 3mm; padding: 3mm 4mm; margin-bottom: 3mm; background: {th['card']}; page-break-inside: avoid; }}
.mh {{ display: flex; gap: 3mm; align-items: baseline; }}
.mh b {{ color: {th['accent']}; font-size: 10.5pt; }}
.mh span {{ color: {th['soft']}; font-size: 7.8pt; }}
.mq {{ margin: 1.5mm 0 2mm; font-weight: 700; }}
.ma {{ font-size: 8.6pt; margin-top: 1mm; }}
.ma span {{ display: inline-block; width: 24mm; font-size: 7.2pt; text-transform: uppercase; letter-spacing: 1px; font-weight: 900; }}
.ma.no span {{ color: {th['seal']}; }} .ma.ok span {{ color: {th['pass']}; }}

/* Arkusz odpowiedzi */
table.meta {{ width: 100%; border-collapse: collapse; font-size: 8.6pt; margin-bottom: 4mm; }}
table.meta th {{ text-align: left; width: 34mm; color: {th['soft']}; font-weight: 700; padding: 1.2mm 2mm; border-bottom: 1px solid {th['line']}; }}
table.meta td {{ padding: 1.2mm 2mm; border-bottom: 1px solid {th['line']}; font-weight: 700; }}
.smap {{ margin-bottom: 3mm; }}
.sq {{ border: 1px solid {th['line']}; border-left: 3px solid {th['line']}; border-radius: 2mm; padding: 2.4mm 3.5mm; margin-bottom: 2.6mm; page-break-inside: avoid; background: {th['card']}; }}
.sq.good {{ border-left-color: {th['pass']}; }} .sq.bad {{ border-left-color: {th['seal']}; }} .sq.partial {{ border-left-color: {th['warn']}; }}
.sq header {{ display: flex; gap: 3mm; align-items: baseline; }}
.sq header b {{ color: {th['accent']}; font-size: 10pt; }}
.sq .st {{ font-weight: 900; font-size: 8.4pt; }}
.sq .ex {{ margin-left: auto; color: {th['soft']}; font-size: 7.8pt; }}
.sq p {{ margin: 1mm 0 1.6mm; font-weight: 700; }}
.sq ol {{ list-style: none; margin: 0; padding: 0; }}
.sq li {{ font-size: 8.6pt; padding: 0.6mm 0; }}
.sq li .box {{ display: inline-block; width: 5mm; color: {th['soft']}; }}
.sq li.x .box {{ color: {th['ink']}; }}
.sq li.c {{ color: {th['pass']}; font-weight: 700; }}
.sq li.x:not(.c) {{ color: {th['seal']}; }}
.sq li em {{ font-style: normal; font-size: 7pt; text-transform: uppercase; letter-spacing: 1px; margin-left: 2mm; }}
.sfoot {{ display: flex; justify-content: space-between; align-items: flex-end; margin-top: 8mm; page-break-inside: avoid; }}
.sfoot .seal {{ transform: rotate(-8deg); }}
@media screen {{ body {{ padding: 16px 0; }} section {{ margin: 0 auto; max-width: 210mm; }} .diploma, .player {{ height: auto; min-height: 0; }} }}
"""


RENDERERS = {"diploma": _diploma, "player": _player, "analysis": _analysis, "sheet": _sheet}


def render_judge(report: Mapping[str, Any], review: Mapping[str, Any], record: Optional[Mapping[str, Any]],
                 options: Mapping[str, Any], *, photo: str = "", crest: str = "", progress: Optional[Progress] = None) -> str:
    """HTML karty sędziego. `options` po `clean_export_options` (`judge` po `clean_judge`)."""
    from app.exam_report_html import THEMES

    progress = progress or (lambda *_: None)
    judge = options["judge"]
    f = judge_facts(report, review, record, judge["judge_id"])
    progress("cards", 1, 1, f["name"])
    exam = report.get("exam") or {}
    province = None if exam.get("scope") == "national" and not exam.get("cut_province") else (exam.get("province") or exam.get("cut_province") or f.get("province"))
    th = theme_for(options.get("theme") or "province", province, THEMES)
    body = RENDERERS[judge["layout"]](f, th, judge["blocks"], photo, crest)
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(f["name"])} - {_e(LAYOUT_LABELS[judge["layout"]])}</title><style>{_css(th, judge["layout"])}</style></head>
<body>{body}</body></html>"""


def judge_filename(name: str, exam_name: str, fmt: str, when: datetime) -> str:
    base = R.export_filename(f"{name} {exam_name}", fmt, when)
    return "karta-" + base[len("wyniki-"):]
