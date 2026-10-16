"""
Egzamin z przepisów - raport komisji jako HTML (i źródło PDF przez weasyprint).

Czysty moduł: dostaje gotowy raport (`exam_report_service.build_report`) i opcje
(`exam_report_rules.clean_export_options`), oddaje napis HTML. Bez bazy, bez sieci,
bez CDN - wykresy to inline SVG, czcionki systemowe (w Dockerze DejaVu).

Postęp jest PRAWDZIWY: `progress(stage, done, total, name)` woła się przy każdym
wierszu listy wyników i każdej karcie zdającego - telefon pokazuje te nazwiska
w scenie (kartki wpadają do teczki).

Motywy: `paper` (kartka, tusz, pieczęć ZPRP) i `night` (ciemne szkło, neon).
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from math import cos, pi, sin
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from app.exam_report_rules import RANGE_LABELS, SECTION_LABELS

Progress = Callable[[str, int, int, Optional[str]], None]

THEMES = {
    "paper": {
        "bg": "#FFFBF3", "card": "#FFFFFF", "ink": "#2A1D15", "soft": "#7D6656", "line": "#E7D9C4",
        "accent": "#8A5A44", "seal": "#B8322A", "pass": "#2F8F5B", "fail": "#8C6E5E", "warn": "#C7811A",
        "track": "#F1E7D8", "glow": "none", "heat_lo": (184, 50, 42), "heat_hi": (47, 143, 91),
    },
    "night": {
        "bg": "#14110F", "card": "#1E1916", "ink": "#F3EBE2", "soft": "#B3A396", "line": "#3A302A",
        "accent": "#E7B68F", "seal": "#FF5A4F", "pass": "#69E6AA", "fail": "#B9A193", "warn": "#F2C14E",
        "track": "#2A231F", "glow": "drop-shadow(0 0 4px {c})", "heat_lo": (255, 90, 79), "heat_hi": (105, 230, 170),
    },
}

RING_TEXT = "ZWIĄZEK PIŁKI RĘCZNEJ W POLSCE • KOLEGIUM SĘDZIÓW • "


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _pct(v: Any, digits: int = 0) -> str:
    if v is None:
        return "-"
    return f"{float(v):.{digits}f}".replace(".", ",") + "%"


def _rate(v: Any) -> str:
    return "-" if v is None else _pct(float(v) * 100)


def _dur(seconds: Any) -> str:
    if seconds is None:
        return "-"
    s = int(round(float(seconds)))
    return f"{s // 60} min {s % 60:02d} s" if s >= 60 else f"{s} s"


def _when(iso: Any) -> str:
    if not iso:
        return "-"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return _e(iso)
    try:
        from zoneinfo import ZoneInfo

        dt = dt.astimezone(ZoneInfo("Europe/Warsaw"))
    except Exception:  # noqa: BLE001
        pass
    return dt.strftime("%d.%m.%Y %H:%M")


def _mix(lo: Sequence[int], hi: Sequence[int], t: float) -> str:
    t = max(0.0, min(1.0, t))
    r, g, b = (round(lo[i] + (hi[i] - lo[i]) * t) for i in range(3))
    return f"#{r:02X}{g:02X}{b:02X}"


# ---------------------------------------------------------------------------
# Wykresy SVG
# ---------------------------------------------------------------------------


def seal_svg(size: int, color: str, center: str, sub: str = "") -> str:
    c = size / 2
    r = size * 0.36
    fs = (2 * pi * r) / (len(RING_TEXT) * 0.7)
    cfs = min(size * 0.15, (size * 0.5) / (max(4, len(center)) * 0.66))
    return f"""<svg class="seal" width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
<defs><path id="sealpath" d="M {c - r},{c} a {r},{r} 0 1,1 {r * 2},0 a {r},{r} 0 1,1 {-r * 2},0"/></defs>
<circle cx="{c}" cy="{c}" r="{size * 0.47}" fill="none" stroke="{color}" stroke-width="{size * 0.028}"/>
<circle cx="{c}" cy="{c}" r="{size * 0.43}" fill="none" stroke="{color}" stroke-width="{size * 0.01}"/>
<circle cx="{c}" cy="{c}" r="{size * 0.285}" fill="none" stroke="{color}" stroke-width="{size * 0.012}" stroke-dasharray="{size * 0.012} {size * 0.028}"/>
<text fill="{color}" font-size="{fs:.2f}" font-weight="900" letter-spacing="{fs * 0.08:.2f}"><textPath href="#sealpath">{_e(RING_TEXT)}</textPath></text>
<text x="{c}" y="{c - cfs * 0.85:.1f}" fill="{color}" font-size="{fs * 1.1:.2f}" font-weight="900" text-anchor="middle">★ ZPRP ★</text>
<text x="{c}" y="{c + cfs * 0.18:.1f}" fill="{color}" font-size="{cfs:.2f}" font-weight="900" text-anchor="middle">{_e(center)}</text>
<text x="{c}" y="{c + cfs * 0.18 + fs * 1.7:.1f}" fill="{color}" font-size="{fs * 1.05:.2f}" font-weight="800" text-anchor="middle">{_e(sub)}</text>
</svg>"""


def ring_svg(rate: Optional[float], th: Mapping[str, Any], size: int = 132) -> str:
    c = size / 2
    r = size * 0.4
    w = size * 0.1
    value = 0.0 if rate is None else max(0.0, min(1.0, float(rate)))
    arc = ""
    if value >= 0.9999:
        arc = f'<circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{th["pass"]}" stroke-width="{w}"/>'
    elif value > 0:
        a0 = -pi / 2
        a1 = a0 + 2 * pi * value
        x0, y0 = c + r * cos(a0), c + r * sin(a0)
        x1, y1 = c + r * cos(a1), c + r * sin(a1)
        large = 1 if value > 0.5 else 0
        arc = (f'<path d="M {x0:.2f} {y0:.2f} A {r} {r} 0 {large} 1 {x1:.2f} {y1:.2f}" fill="none" '
               f'stroke="{th["pass"]}" stroke-width="{w}" stroke-linecap="round"/>')
    label = "-" if rate is None else _rate(rate)
    return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
<circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{th["track"]}" stroke-width="{w}"/>{arc}
<text x="{c}" y="{c + size * 0.06:.1f}" fill="{th["ink"]}" font-size="{size * 0.2:.1f}" font-weight="900" text-anchor="middle">{label}</text>
<text x="{c}" y="{c + size * 0.2:.1f}" fill="{th["soft"]}" font-size="{size * 0.075:.1f}" font-weight="700" text-anchor="middle">zdawalność</text>
</svg>"""


def histogram_svg(hist: Sequence[int], pass_percent: float, th: Mapping[str, Any], width: int = 640, height: int = 180) -> str:
    top, bottom, left = 14, 26, 8
    inner_h = height - top - bottom
    peak = max(1, max(hist or [0]))
    bw = (width - left * 2) / 10
    bars = []
    for i, n in enumerate(hist):
        h = inner_h * n / peak
        x = left + i * bw + bw * 0.14
        y = top + inner_h - h
        color = th["pass"] if (i + 1) * 10 > pass_percent else th["fail"]
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw * 0.72:.1f}" height="{max(h, 1.5):.1f}" rx="4" fill="{color}"/>')
        if n:
            bars.append(f'<text x="{x + bw * 0.36:.1f}" y="{y - 4:.1f}" fill="{th["ink"]}" font-size="11" font-weight="800" text-anchor="middle">{n}</text>')
        bars.append(f'<text x="{left + i * bw + bw / 2:.1f}" y="{height - 8}" fill="{th["soft"]}" font-size="10" text-anchor="middle">{i * 10}-{i * 10 + 10}</text>')
    tx = left + (width - left * 2) * min(100.0, max(0.0, float(pass_percent))) / 100
    line = (f'<line x1="{tx:.1f}" y1="{top - 6}" x2="{tx:.1f}" y2="{top + inner_h}" stroke="{th["seal"]}" stroke-width="2" stroke-dasharray="5 4"/>'
            f'<text x="{tx + 4:.1f}" y="{top + 2}" fill="{th["seal"]}" font-size="10.5" font-weight="900">próg {_pct(pass_percent)}</text>')
    return (f'<svg width="100%" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
            f'<line x1="{left}" y1="{top + inner_h}" x2="{width - left}" y2="{top + inner_h}" stroke="{th["line"]}" stroke-width="1"/>'
            + "".join(bars) + line + "</svg>")


# ---------------------------------------------------------------------------
# Sekcje
# ---------------------------------------------------------------------------


def _section(title: str, body: str, *, cls: str = "") -> str:
    return f'<section class="block {cls}"><h2>{_e(title)}</h2>{body}</section>'


def _summary(report: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    s = report["summary"]
    tiles = [
        ("Przystąpili", f'{s["people"]} z {s["invited"]}'), ("Zaliczyli", f'{s["passed"]}'),
        ("Nie zaliczyli", f'{s["failed"]}'), ("Średni wynik", _pct(s["avg_percent"], 1)),
        ("Mediana", _pct(s["median_percent"], 1)), ("Średni czas", _dur(s["avg_duration_s"])),
        ("Nie przystąpili", f'{s["missing"]}'), ("Podejścia", f'{s["attempts"]}'),
    ]
    grid = "".join(f'<div class="tile"><div class="tv">{_e(v)}</div><div class="tl">{_e(k)}</div></div>' for k, v in tiles)
    return _section(SECTION_LABELS["summary"],
                    f'<div class="summary"><div class="ring">{ring_svg(s["pass_rate"], th)}</div><div class="tiles">{grid}</div></div>')


def _histogram(report: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    s = report["summary"]
    return _section(SECTION_LABELS["histogram"],
                    f'<p class="note">Najlepsze podejście każdej osoby, przedziały co 10 punktów procentowych. '
                    f'Linia przerywana to próg zaliczenia.</p>{histogram_svg(s["histogram_10pct"], s["pass_percent"], th)}')


def _questions(report: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    cells = []
    for q in report["questions"]:
        rate = q.get("correct_rate")
        if q.get("voided"):
            cells.append(f'<div class="cell void"><b>{_e(q["number"])}</b><span>unieważn.</span></div>')
            continue
        color = th["line"] if rate is None else _mix(th["heat_lo"], th["heat_hi"], float(rate))
        cells.append(f'<div class="cell" style="background:{color}"><b>{_e(q["number"])}</b><span>{_rate(rate)}</span></div>')
    hard = "".join(
        f'<tr><td class="num">{_e(q["number"])}</td><td>{_e(q.get("text") or "")}</td><td class="r">{_rate(q.get("correct_rate"))}</td>'
        f'<td class="r">{_e(q.get("avg_time_s") if q.get("avg_time_s") is not None else "-")} s</td></tr>'
        for q in report.get("hardest") or [])
    table = (f'<h3>Najtrudniejsze pytania</h3><table><thead><tr><th>Nr</th><th>Treść</th><th class="r">Poprawnie</th>'
             f'<th class="r">Śr. czas</th></tr></thead><tbody>{hard}</tbody></table>') if hard else ""
    return _section(SECTION_LABELS["questions"],
                    f'<p class="note">Kolor = odsetek poprawnych odpowiedzi (czerwony: nikt, zielony: wszyscy).</p>'
                    f'<div class="heat">{"".join(cells)}</div>{table}')


def _weakest(report: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    rows = report.get("weakest_rules") or []
    if not rows:
        return _section(SECTION_LABELS["weakest"], '<p class="note">Brak odpowiedzi - nie ma czego porównać.</p>')
    body = "".join(
        f'<div class="bar"><div class="bl">{_e(r["label"])}<small>{r["questions"]} pyt., {r["answers"]} odp.</small></div>'
        f'<div class="bt"><div class="bf" style="width:{(r["correct_rate"] or 0) * 100:.1f}%;background:{_mix(th["heat_lo"], th["heat_hi"], r["correct_rate"] or 0)}"></div></div>'
        f'<div class="bv">{_rate(r["correct_rate"])}</div></div>' for r in rows)
    return _section(SECTION_LABELS["weakest"], body)


def _violations(report: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    v = report["violations"]
    lv = v["levels"]
    head = (f'<div class="levels"><span class="lv ok">bez uwag: {lv["ok"]}</span><span class="lv warn">do sprawdzenia: {lv["warning"]}</span>'
            f'<span class="lv bad">podejrzane: {lv["suspicious"]}</span></div>')
    if not v["kinds"]:
        return _section(SECTION_LABELS["violations"], head + '<p class="note">Żadnych sygnałów - egzamin przebiegł czysto.</p>')
    rows = "".join(f'<tr><td>{_e(k["label"])}</td><td class="r">{k["people"]}</td><td class="r">{k["events"]}</td></tr>' for k in v["kinds"])
    return _section(SECTION_LABELS["violations"],
                    head + f'<table><thead><tr><th>Sygnał</th><th class="r">Osoby</th><th class="r">Zdarzenia</th></tr></thead><tbody>{rows}</tbody></table>'
                    '<p class="note">Wskaźnik rzetelności jest sygnałem dla komisji. Nic nie dyskwalifikuje automatycznie.</p>')


def _ranking(rows: Sequence[Mapping[str, Any]], options: Mapping[str, Any], th: Mapping[str, Any], progress: Progress) -> str:
    out = []
    total = len(rows)
    for i, r in enumerate(rows):
        progress("rows", i + 1, total, r.get("judge_name"))
        badge = '<span class="ok">zaliczony</span>' if r.get("passed") else '<span class="no">niezaliczony</span>'
        integ = (r.get("integrity") or {})
        out.append(
            f'<tr><td class="num">{_e(r.get("place") or "-")}</td><td>{_e(r.get("judge_name"))}</td>'
            f'<td>{_e(r.get("province") or "")}</td><td class="r">{_pct(r.get("percent"), 1)}</td><td>{badge}</td>'
            f'<td class="r">{_e(integ.get("score", "-"))}</td><td class="r">{_e(r.get("attempt_no"))}</td></tr>')
    if not out:
        return _section(SECTION_LABELS["ranking"], '<p class="note">Nikt w tym zakresie nie oddał jeszcze arkusza.</p>')
    head = '<tr><th>Miejsce</th><th>Zdający</th><th>Okręg</th><th class="r">Wynik</th><th>Ocena</th><th class="r">Rzetelność</th><th class="r">Podejście</th></tr>'
    return _section(SECTION_LABELS["ranking"],
                    f'<p class="note">Zakres: {_e(RANGE_LABELS[options["range"]])}. Równe wyniki = wspólne miejsce.</p>'
                    f'<table class="list"><thead>{head}</thead><tbody>{"".join(out)}</tbody></table>')


def _missing(report: Mapping[str, Any]) -> str:
    rows = report.get("missing") or []
    if not rows:
        return _section(SECTION_LABELS["missing"], '<p class="note">Przystąpili wszyscy zaproszeni.</p>')
    body = "".join(f'<li>{_e(m["name"])}<small>{_e(m.get("province") or "")}</small></li>' for m in rows)
    return _section(SECTION_LABELS["missing"], f'<p class="note">{len(rows)} os.</p><ul class="cols">{body}</ul>')


def _provinces(report: Mapping[str, Any], th: Mapping[str, Any]) -> str:
    rows = report.get("provinces") or []
    body = "".join(
        f'<tr><td class="num">{_e(r.get("place") or "-")}</td><td>{_e(r["province"])}</td><td class="r">{r["attended"]} / {r["invited"]}</td>'
        f'<td class="r">{_rate(r["attendance_rate"])}</td><td class="r">{_rate(r["pass_rate"])}</td><td class="r">{_pct(r["avg_percent"], 1)}</td></tr>'
        for r in rows)
    return _section(SECTION_LABELS["provinces"],
                    '<table><thead><tr><th>Miejsce</th><th>Okręg</th><th class="r">Przystąpili</th><th class="r">Frekwencja</th>'
                    f'<th class="r">Zdawalność</th><th class="r">Średnia</th></tr></thead><tbody>{body}</tbody></table>')


def _cards(rows: Sequence[Mapping[str, Any]], th: Mapping[str, Any], progress: Progress) -> str:
    out = []
    total = len(rows)
    for i, r in enumerate(rows):
        progress("cards", i + 1, total, r.get("judge_name"))
        integ = r.get("integrity") or {}
        strip = "".join(
            f'<i class="{"v" if q.get("voided") else "y" if q.get("correct") else "n"}" title="{_e(q.get("number"))}"></i>'
            for q in r.get("questions") or [])
        br = "".join(f'<li>{_e(b["label"])}: {b["count"]}× <b>-{b["penalty"]}</b></li>' for b in integ.get("breakdown") or [])
        out.append(
            f'<article class="card"><header><b>{_e(r.get("judge_name"))}</b><span>{_e(r.get("province") or "")}</span>'
            f'<span class="score">{_pct(r.get("percent"), 1)}</span></header>'
            f'<div class="meta">Podejście {_e(r.get("attempt_no"))} · start {_when(r.get("started_at"))} · oddano {_when(r.get("finished_at"))}'
            f' · rzetelność {_e(integ.get("score", "-"))}/100</div><div class="strip">{strip}</div>'
            + (f'<ul class="br">{br}</ul>' if br else "") + "</article>")
    return _section(SECTION_LABELS["cards"], "".join(out) or '<p class="note">Brak kart w tym zakresie.</p>', cls="cards")


# ---------------------------------------------------------------------------
# Dokument
# ---------------------------------------------------------------------------


def _css(th: Mapping[str, Any], theme: str) -> str:
    glow = "" if theme == "paper" else f"svg rect, svg path {{ filter: drop-shadow(0 0 3px {th['pass']}); }}"
    return f"""
@page {{ size: A4; margin: 14mm 13mm 16mm; background: {th['bg']};
  @bottom-center {{ content: "Strona " counter(page) " z " counter(pages); font-size: 8.5pt; color: {th['soft']}; }} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: {th['bg']}; color: {th['ink']}; font-family: "DejaVu Sans", "Noto Sans", Arial, sans-serif; font-size: 10pt; line-height: 1.4; }}
.page {{ max-width: 860px; margin: 0 auto; padding: 18px; }}
.head {{ display: flex; align-items: center; gap: 18px; border-bottom: 2px solid {th['line']}; padding-bottom: 12px; margin-bottom: 10px; }}
.head h1 {{ margin: 0; font-size: 19pt; letter-spacing: -0.2px; }}
.head .kick {{ font-size: 8pt; font-weight: 900; letter-spacing: 1.6px; color: {th['accent']}; text-transform: uppercase; }}
.head .sub {{ color: {th['soft']}; font-size: 9pt; margin-top: 3px; }}
.head .seal {{ margin-left: auto; transform: rotate(-9deg); }}
.block {{ margin-top: 14px; page-break-inside: avoid; }}
.block.cards {{ page-break-inside: auto; }}
h2 {{ font-size: 9pt; letter-spacing: 1.4px; text-transform: uppercase; color: {th['accent']}; margin: 0 0 8px; border-bottom: 1px solid {th['line']}; padding-bottom: 4px; }}
h3 {{ font-size: 10pt; margin: 12px 0 6px; }}
.note {{ color: {th['soft']}; font-size: 8.6pt; margin: 0 0 8px; }}
.summary {{ display: flex; gap: 16px; align-items: center; }}
.tiles {{ display: flex; flex-wrap: wrap; gap: 8px; flex: 1; }}
.tile {{ width: 23%; background: {th['card']}; border: 1px solid {th['line']}; border-radius: 10px; padding: 8px 10px; }}
.tv {{ font-size: 13pt; font-weight: 900; }}
.tl {{ font-size: 7.6pt; color: {th['soft']}; text-transform: uppercase; letter-spacing: 0.8px; }}
.heat {{ display: flex; flex-wrap: wrap; gap: 4px; }}
.cell {{ width: 56px; border-radius: 7px; padding: 4px 5px; color: #fff; font-size: 7.6pt; }}
.cell b {{ display: block; font-size: 8.4pt; }}
.cell.void {{ background: transparent; color: {th['soft']}; border: 1px dashed {th['line']}; }}
table {{ width: 100%; border-collapse: collapse; font-size: 9pt; }}
th {{ text-align: left; font-size: 7.6pt; text-transform: uppercase; letter-spacing: 0.8px; color: {th['soft']}; border-bottom: 1px solid {th['line']}; padding: 4px 6px; }}
td {{ border-bottom: 1px solid {th['line']}; padding: 4px 6px; vertical-align: top; }}
tr {{ page-break-inside: avoid; }}
td.r, th.r {{ text-align: right; }}
td.num {{ font-weight: 900; color: {th['accent']}; white-space: nowrap; }}
.ok {{ color: {th['pass']}; font-weight: 800; }}
.no {{ color: {th['fail']}; font-weight: 800; }}
.bar {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
.bl {{ width: 46%; font-weight: 700; }}
.bl small {{ display: block; color: {th['soft']}; font-weight: 400; font-size: 7.8pt; }}
.bt {{ flex: 1; height: 10px; border-radius: 5px; background: {th['track']}; overflow: hidden; }}
.bf {{ height: 10px; border-radius: 5px; }}
.bv {{ width: 46px; text-align: right; font-weight: 900; }}
.levels {{ display: flex; gap: 8px; margin-bottom: 8px; }}
.lv {{ border-radius: 20px; padding: 2px 10px; font-size: 8.4pt; font-weight: 800; border: 1px solid {th['line']}; }}
.lv.ok {{ color: {th['pass']}; }} .lv.warn {{ color: {th['warn']}; }} .lv.bad {{ color: {th['seal']}; }}
ul.cols {{ columns: 3; padding-left: 16px; margin: 0; }}
ul.cols li {{ margin-bottom: 2px; }}
ul.cols small {{ color: {th['soft']}; margin-left: 5px; }}
.card {{ border: 1px solid {th['line']}; background: {th['card']}; border-radius: 10px; padding: 8px 10px; margin-bottom: 8px; page-break-inside: avoid; }}
.card header {{ display: flex; gap: 10px; align-items: baseline; }}
.card header span {{ color: {th['soft']}; font-size: 8.4pt; }}
.card .score {{ margin-left: auto; font-weight: 900; color: {th['ink']}; font-size: 11pt; }}
.card .meta {{ color: {th['soft']}; font-size: 8pt; margin: 2px 0 6px; }}
.strip {{ display: flex; flex-wrap: wrap; gap: 2px; }}
.strip i {{ display: inline-block; width: 9px; height: 9px; border-radius: 2px; }}
.strip i.y {{ background: {th['pass']}; }} .strip i.n {{ background: {th['seal']}; }} .strip i.v {{ background: {th['line']}; }}
ul.br {{ margin: 6px 0 0; padding-left: 16px; font-size: 8.4pt; color: {th['soft']}; }}
.foot {{ margin-top: 18px; color: {th['soft']}; font-size: 8pt; border-top: 1px solid {th['line']}; padding-top: 6px; }}
{glow}
@media screen {{ body {{ padding: 12px 0; }} .tile {{ min-width: 120px; }} }}
"""


def render_report(report: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], options: Mapping[str, Any],
                  progress: Optional[Progress] = None, *, generated_at: Optional[datetime] = None) -> str:
    """HTML całego raportu. `rows` = wiersze listy wyników po zakresie i anonimizacji."""
    progress = progress or (lambda *_: None)
    th = THEMES[options["theme"]]
    exam = report["exam"]
    when = generated_at or datetime.now(timezone.utc)
    sections = options["sections"]
    parts: List[str] = []
    for key in sections:
        if key == "summary":
            parts.append(_summary(report, th))
        elif key == "histogram":
            parts.append(_histogram(report, th))
        elif key == "questions":
            parts.append(_questions(report, th))
        elif key == "weakest":
            parts.append(_weakest(report, th))
        elif key == "violations":
            parts.append(_violations(report, th))
        elif key == "ranking":
            parts.append(_ranking(rows, options, th, progress))
        elif key == "missing":
            parts.append(_missing(report))
        elif key == "provinces":
            parts.append(_provinces(report, th))
        elif key == "cards":
            parts.append(_cards(rows, th, progress))
    scope = "Egzamin ogólnopolski" if exam.get("scope") == "national" else f"Egzamin okręgowy · {exam.get('province') or ''}"
    seal = seal_svg(96, th["seal"], "KOMISJA", when.strftime("%d.%m.%Y")) if options.get("seal") else ""
    anon = " · dane zanonimizowane" if options.get("anonymize") else ""
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(exam.get('name'))} - wyniki</title><style>{_css(th, options['theme'])}</style></head>
<body><div class="page">
<div class="head"><div><div class="kick">Wyniki egzaminu z przepisów</div><h1>{_e(exam.get('name'))}</h1>
<div class="sub">{_e(scope)} · okno {_when(exam.get('window_start'))} - {_when(exam.get('window_end'))} · próg {_pct(exam.get('pass_percent'))} · {_e(exam.get('question_count'))} pytań{anon}</div></div>{seal}</div>
{''.join(parts)}
<div class="foot">Wygenerowano w BAZIE {_when(when.isoformat())}. Ocena i czas liczone wyłącznie na serwerze. Wskaźnik rzetelności to sygnał dla komisji - decyzje podejmuje komisja.</div>
</div></body></html>"""
