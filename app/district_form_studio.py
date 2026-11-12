"""
Formularze okręgowe - STUDIO EKSPORTU wyników (12.11.2026). Moduł czysty: zero bazy, zero sieci.

Wzór: studio eksportu wyników egzaminu (`exam_report_html`, `exam_print_theme`) i drukarnia
Communio. Telefon wysyła PLAN pliku zbudowany z bieżącego widoku listy:

  format     pdf | xlsx | html (jeden plik z wyszukiwarką i sortowaniem w środku)
  layout     checklist (lista do odhaczania - kratki, do druku)
             report    (raport: pierścień wypełnienia, rozkład odpowiedzi, lejek wpłat,
                        narastanie, potem tabela)
  theme      province (barwy okręgu z herbu) | elegant | premium - te same co egzamin
  scope      view (dokładnie to, co na ekranie) | all (cały formularz)
  keys       kolejność wierszy widoku (judge_id albo „g:<gość>") - telefon liczy ją tą samą
             funkcją co lista (`viewLogic.viewOrder`), więc plik ma DOKŁADNIE ten porządek
  groups     grupy widoku z etykietami (albo null)
  columns    kolumny w kolejności widoku, bez ukrytych
  lenses     opis widoku po ludzku („Obecność: Będę", „Nazwisko A-Z") - nagłówek pliku
             mówi wprost, czego plik NIE zawiera

Strona publiczna (`/public/forms/results/<kod>`) jest ŻYWA: przy każdym otwarciu serwer
nakłada zapamiętany widok (filtr, sortowanie, grupy, kolumny, zaznaczenie) na bieżące dane
lustrem `viewLogic.ts` (`apply_view`) i przycina do poziomu jawności:

  stats     same liczby i wykresy, zero osób
  initials  „J. K." i kolumna statusu
  names     imiona i nazwiska i kolumna statusu
  full      imiona i nazwiska i kolumny jawne (widoczność „wszyscy")

Kolumny „tylko komisja" i „tylko sędzia" nigdy nie trafiają na stronę publiczną.
"""
from __future__ import annotations

import html
import io
import json
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from app import district_forms_rules as R
from app.exam_print_theme import brand_logo_uri, mix, theme_for

FORMATS = ("pdf", "xlsx", "html")
LAYOUTS = ("checklist", "report")
THEMES = ("province", "elegant", "premium")
SCOPES = ("view", "all")
PUBLIC_LEVELS = ("stats", "initials", "names", "full")
MAX_KEYS = 5000
MAX_LENSES = 12
SORT_NAME = "__name"
SORT_UPDATED = "__updated"

esc = html.escape


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _choice(value: Any, allowed: Sequence[str], default: str) -> str:
    text = _s(value)
    return text if text in allowed else default


def _str_list(raw: Any, limit: int, size: int = 200) -> List[str]:
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for item in raw[:limit]:
        text = _s(item)[:size]
        if text and text not in out:
            out.append(text)
    return out


# ---------------------------------------------------------------------------
# Plan pliku i widok strony
# ---------------------------------------------------------------------------


def clean_plan(raw: Any, columns: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Plan z telefonu po sprawdzeniu: znane kolumny, rozsądne długości, tony z listy."""
    body = raw if isinstance(raw, Mapping) else {}
    known = [c["id"] for c in columns]
    scope = _choice(body.get("scope"), SCOPES, "view")
    cols = [c for c in _str_list(body.get("columns"), 64, 40) if c in known] if "columns" in body else list(known)
    groups = None
    if scope == "view" and isinstance(body.get("groups"), list) and body["groups"]:
        groups = []
        for g in body["groups"][:60]:
            if not isinstance(g, Mapping):
                continue
            groups.append({
                "label": _s(g.get("label"))[:80] or "Grupa",
                "tone": _choice(g.get("tone"), ("positive", "negative", "warning", "neutral"), ""),
                "keys": _str_list(g.get("keys"), MAX_KEYS),
            })
    return {
        "format": _choice(body.get("format"), FORMATS, "pdf"),
        "layout": _choice(body.get("layout"), LAYOUTS, "checklist"),
        "theme": _choice(body.get("theme"), THEMES, "province"),
        "scope": scope,
        "keys": _str_list(body.get("keys"), MAX_KEYS) if scope == "view" and isinstance(body.get("keys"), list) else None,
        "groups": groups,
        "columns": cols if scope == "view" else list(known),
        "lenses": _str_list(body.get("lenses"), MAX_LENSES, 120) if scope == "view" else [],
    }


def clean_view(raw: Any, columns: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Widok zapamiętany przy stronie publicznej (lustro `ResultsView` bez gęstości i przypięć)."""
    body = raw if isinstance(raw, Mapping) else {}
    known = {c["id"] for c in columns}
    flt: Dict[str, List[str]] = {}
    if isinstance(body.get("filter"), Mapping):
        for cid, wanted in list(body["filter"].items())[:40]:
            if cid in known or cid == "__filled":
                values = _str_list(wanted, 40, 40)
                if values:
                    flt[cid] = values
    sort = None
    if isinstance(body.get("sort"), Mapping):
        col = _s(body["sort"].get("col"))
        if col in known or col in (SORT_NAME, SORT_UPDATED):
            sort = {"col": col, "dir": "desc" if body["sort"].get("dir") == "desc" else "asc"}
    group_by = _s(body.get("groupBy")) or None
    return {
        "query": _s(body.get("query"))[:80],
        "filter": flt,
        "onlyReview": bool(body.get("onlyReview")),
        "sort": sort,
        "groupBy": group_by if group_by in known else None,
        "selectedIds": _str_list(body.get("selectedIds"), MAX_KEYS),
    }


# ---------------------------------------------------------------------------
# Lustro `viewLogic.ts` (strona publiczna jest żywa)
# ---------------------------------------------------------------------------

_PL = "aąbcćdeęfghijklłmnńoópqrsśtuvwxyzźż"
_PL_RANK = {ch: i for i, ch in enumerate(_PL)}


def pl_key(text: str) -> Tuple[int, ...]:
    """Klucz sortowania po polsku (ą po a, ł po l...) - jak `Intl.Collator("pl")` dla nazwisk."""
    return tuple(_PL_RANK.get(ch, 100 + ord(ch)) for ch in _s(text).casefold())


def js_has_value(v: Any) -> bool:
    """`hasValue` z `logic.ts`: puste to null, "", false i pusta lista."""
    return not (v is None or v == "" or v is False or (isinstance(v, list) and not v))


def value_key(column: Mapping[str, Any], v: Any) -> List[str]:
    if not js_has_value(v):
        return ["none"]
    if column.get("type") == "check":
        return ["yes" if v is True else "none"]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def filter_options(column: Mapping[str, Any]) -> List[Dict[str, str]]:
    ctype = column.get("type")
    if ctype in ("status", "choice"):
        out = [{"key": o["id"], "label": o.get("label") or o["id"], "tone": o.get("tone") or ""} for o in column.get("options") or []]
        out.append({"key": "none", "label": "Brak głosu" if ctype == "status" else "Brak", "tone": ""})
        return out
    if ctype == "confirm":
        return [
            {"key": "confirmed", "label": "Otrzymano", "tone": "positive"},
            {"key": "declared", "label": "Zapłaciłem", "tone": "warning"},
            {"key": "none", "label": "Nie zapłacono", "tone": "negative"},
        ]
    if ctype == "check":
        return [{"key": "yes", "label": "Tak", "tone": "positive"}, {"key": "none", "label": "Brak", "tone": ""}]
    return [{"key": "none", "label": "Puste", "tone": ""}]


def _rank(column: Mapping[str, Any], v: Any) -> Any:
    if not js_has_value(v):
        return None
    ctype = column.get("type")
    if ctype in ("status", "choice"):
        first = v[0] if isinstance(v, list) else v
        ids = [o["id"] for o in column.get("options") or []]
        return ids.index(first) if first in ids else 999
    if ctype == "confirm":
        return 0 if v == "confirmed" else 1 if v == "declared" else None
    if ctype == "check":
        return 0 if v is True else None
    if ctype == "number":
        try:
            return float(v)
        except (TypeError, ValueError):
            return None
    return pl_key(str(v))


def apply_view(rows: Sequence[Mapping[str, Any]], columns: Sequence[Mapping[str, Any]], view: Mapping[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[List[Dict[str, Any]]]]:
    """(wiersze w kolejności widoku, grupy albo None). Wiersz: key, name, cells {id: v}, filled, web_review, updated_at."""
    by_id = {c["id"]: c for c in columns}
    needle = _s(view.get("query")).casefold()
    out: List[Dict[str, Any]] = []
    for row in rows:
        if needle and needle not in f"{row.get('name', '')} {row.get('guest') or ''}".casefold():
            continue
        if view.get("onlyReview") and not row.get("web_review"):
            continue
        keep = True
        for cid, wanted in (view.get("filter") or {}).items():
            if not wanted:
                continue
            if cid == "__filled":
                if bool(row.get("filled")) != (wanted[0] == "yes"):
                    keep = False
                continue
            column = by_id.get(cid)
            if column and not any(k in wanted for k in value_key(column, (row.get("cells") or {}).get(cid))):
                keep = False
        if keep:
            out.append(dict(row))
    selected = set(view.get("selectedIds") or [])
    if selected:
        out = [r for r in out if r.get("key") in selected]
    out = sort_rows(out, columns, view.get("sort"))
    groups = group_rows(out, columns, view.get("groupBy"))
    if groups:
        out = [r for g in groups for r in g["rows"]]
    return out, groups


def sort_rows(rows: List[Dict[str, Any]], columns: Sequence[Mapping[str, Any]], sort: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    by_name = sorted(rows, key=lambda r: pl_key(r.get("name", "")))
    if not sort:
        return rows
    desc = sort.get("dir") == "desc"
    col = sort.get("col")
    if col == SORT_NAME:
        return list(reversed(by_name)) if desc else by_name
    if col == SORT_UPDATED:
        dated = [r for r in by_name if r.get("updated_at")]
        undated = [r for r in by_name if not r.get("updated_at")]
        dated.sort(key=lambda r: _s(r.get("updated_at")), reverse=desc)
        return dated + undated
    column = next((c for c in columns if c["id"] == col), None)
    if not column:
        return rows
    ranked = [(r, _rank(column, (r.get("cells") or {}).get(column["id"]))) for r in by_name]
    present = [x for x in ranked if x[1] is not None]
    present.sort(key=lambda x: x[1], reverse=desc)
    return [r for r, _ in present] + [r for r, v in ranked if v is None]


def group_rows(rows: List[Dict[str, Any]], columns: Sequence[Mapping[str, Any]], group_by: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    column = next((c for c in columns if c["id"] == group_by), None) if group_by else None
    if not column:
        return None
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        v = (row.get("cells") or {}).get(column["id"])
        if column.get("type") == "number":
            key = _num_text(v) if js_has_value(v) else "none"
        else:
            key = value_key(column, v)[0]
        buckets.setdefault(key, []).append(row)
    if column.get("type") == "number":
        order = [{"key": k, "label": k, "tone": ""} for k in sorted((k for k in buckets if k != "none"), key=lambda k: float(k))]
        order.append({"key": "none", "label": "Puste", "tone": ""})
    else:
        order = filter_options(column)
        for k in buckets:
            if not any(o["key"] == k for o in order):
                order.insert(len(order) - 1, {"key": k, "label": k, "tone": ""})
    return [{"label": o["label"], "tone": o["tone"], "rows": buckets[o["key"]], "keys": [r["key"] for r in buckets[o["key"]]]}
            for o in order if buckets.get(o["key"])]


def _num_text(v: Any) -> str:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return _s(v)
    return str(int(n)) if n == int(n) else str(n)


def order_by_keys(rows: Sequence[Mapping[str, Any]], keys: Optional[Sequence[str]]) -> List[Mapping[str, Any]]:
    """Wiersze w kolejności z telefonu; klucze spoza formularza (ktoś zniknął z listy) odpadają."""
    if keys is None:
        return list(rows)
    by_key = {r["key"]: r for r in rows}
    return [by_key[k] for k in keys if k in by_key]


# ---------------------------------------------------------------------------
# Dokument (wspólny dla PDF, HTML, Excela i strony publicznej)
# ---------------------------------------------------------------------------


def _cell_tone(column: Mapping[str, Any], value: Any) -> str:
    if column.get("type") == "status":
        options = {o["id"]: o.get("tone") for o in column.get("options") or []}
        return (options.get(value) or "") if js_has_value(value) else "neutral"
    if column.get("type") == "confirm":
        return {"confirmed": "positive", "declared": "warning"}.get(value, "negative")
    if column.get("type") == "check":
        return "positive" if value is True else ""
    return ""


def cell_text(column: Mapping[str, Any], value: Any) -> str:
    if column.get("type") == "confirm":
        return {"confirmed": "Otrzymano", "declared": "Zapłaciłem"}.get(value, "Nie zapłacono")
    if column.get("type") == "status" and not js_has_value(value):
        return "Brak głosu"
    if not R.has_value(column, value):
        return ""
    return R.value_label(column, value)


def initials(name: Any) -> str:
    parts = [p for p in re.split(r"[\s-]+", _s(name)) if p]
    return " ".join(f"{p[0].upper()}." for p in parts[:2]) or "?"


def list_stats_for(columns: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Statystyki widoku (te same co `/stats`, ale dla wierszy pliku)."""
    entries = {r["key"]: {"cells_json": {cid: {"v": v} for cid, v in (r.get("cells") or {}).items()},
                          "submitted_at": r.get("submitted_at"), "web_review": r.get("web_review")} for r in rows}
    return R.list_stats(columns, [r["key"] for r in rows], entries)


def charts_for_list(columns: Sequence[Mapping[str, Any]], stats: Mapping[str, Any]) -> Dict[str, Any]:
    by_id = {c["id"]: c for c in columns}
    dists, funnels, numbers = [], [], []
    for col in stats.get("columns") or []:
        column = by_id.get(col["id"])
        if not column:
            continue
        if col["type"] in ("status", "choice"):
            items = [{"label": o.get("label") or o["id"], "count": int((col.get("counts") or {}).get(o["id"], 0)), "tone": o.get("tone") or "neutral"}
                     for o in column.get("options") or []]
            items.append({"label": "Brak głosu" if col["type"] == "status" else "Brak", "count": int(col.get("none") or 0), "tone": "empty"})
            dists.append({"title": column["title"], "items": items})
        elif col["type"] == "check":
            dists.append({"title": column["title"], "items": [
                {"label": "Tak", "count": int(col.get("yes") or 0), "tone": "positive"},
                {"label": "Brak", "count": int(col.get("no") or 0), "tone": "empty"}]})
        elif col["type"] == "confirm":
            funnels.append({"title": column["title"], "amount": col.get("amount"), "none": int(col.get("none") or 0),
                            "declared": int(col.get("declared") or 0), "confirmed": int(col.get("confirmed") or 0),
                            "expected_total": col.get("expected_total"), "declared_total": col.get("declared_total"),
                            "confirmed_total": col.get("confirmed_total")})
        elif col["type"] == "number" and col.get("count"):
            numbers.append({"title": column["title"], "sum": col.get("sum"), "avg": col.get("avg"), "count": col.get("count")})
    return {"dists": dists, "funnels": funnels, "numbers": numbers}


def charts_for_form(question_stats: Sequence[Mapping[str, Any]], titles: Mapping[str, str]) -> Dict[str, Any]:
    dists = []
    for q in question_stats:
        title = titles.get(q.get("question_id"), "Pytanie")
        if q.get("kind") == "choice":
            dists.append({"title": title, "items": [{"label": o["label"], "count": int(o["count"]), "tone": "neutral"} for o in q.get("options") or []]})
        elif q.get("kind") == "scale":
            dists.append({"title": title, "items": [{"label": str(b["value"]), "count": int(b["count"]), "tone": "neutral"} for b in q.get("buckets") or []]})
    return {"dists": dists, "funnels": [], "numbers": []}


def build_doc(
    *,
    form: Mapping[str, Any],
    province: str,
    generated: str,
    kind: str,
    header: Sequence[str],
    table: Sequence[Sequence[str]],
    tones: Optional[Sequence[Sequence[str]]],
    names: Sequence[str],
    groups: Optional[Sequence[Mapping[str, Any]]],
    stats: Mapping[str, Any],
    charts: Mapping[str, Any],
    lenses: Sequence[str],
    scope: str,
    payment: Sequence[Tuple[str, str]] = (),
) -> Dict[str, Any]:
    """Model pliku. `groups[i]` = {label, tone, size, aggs}; wiersze tabeli idą w kolejności grup."""
    participants = int(stats.get("participants") or 0)
    filled = int(stats.get("filled") or 0)
    return {
        "title": _s(form.get("title")) or "Formularz",
        "province": province,
        "generated": generated,
        "closes": _s(form.get("closes_at")),
        "kind": kind,
        "header": list(header),
        "table": [list(r) for r in table],
        "tones": [list(t) for t in tones] if tones else None,
        "names": list(names),
        "groups": [dict(g) for g in groups] if groups else None,
        "participants": participants,
        "filled": filled,
        "timeline": list(stats.get("timeline") or []),
        "charts": dict(charts),
        "lenses": list(lenses),
        "scope": scope,
        "payment": list(payment),
    }


def group_aggs(columns: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]) -> List[str]:
    """Sumy w nagłówku grupy (lustro `aggregates` z `viewLogic.ts`): kwoty wpłat, sumy liczb, znaczniki."""
    out: List[str] = []
    for c in columns:
        values = [(r.get("cells") or {}).get(c["id"]) for r in rows]
        if c.get("type") == "confirm":
            got = sum(1 for v in values if v == "confirmed")
            declared = sum(1 for v in values if v == "declared")
            if c.get("amount"):
                out.append(f"{c['title']}: {_money(got * float(c['amount']))}")
                if declared:
                    out.append(f"zgłoszone {_money(declared * float(c['amount']))}")
            else:
                out.append(f"{c['title']}: {got}/{len(rows)}")
        elif c.get("type") == "number":
            nums = []
            for v in values:
                try:
                    if js_has_value(v):
                        nums.append(float(v))
                except (TypeError, ValueError):
                    pass
            if nums:
                total = sum(nums)
                out.append(f"{c['title']}: Σ {int(total) if total == int(total) else round(total, 1)}")
        elif c.get("type") == "check":
            out.append(f"{c['title']}: {sum(1 for v in values if v is True)}/{len(rows)}")
    return out


def _money(n: Optional[float]) -> str:
    if n is None:
        return "-"
    whole = int(round(float(n)))
    return f"{whole:,}".replace(",", " ") + " zł"


# ---------------------------------------------------------------------------
# Wykresy (inline SVG - działa w weasyprint i w przeglądarce, bez CDN)
# ---------------------------------------------------------------------------


def tone_color(th: Mapping[str, Any], tone: str) -> str:
    return {
        "positive": th["pass"], "negative": th["seal"], "warning": th["warn"],
        "neutral": th["accent"], "empty": th["line"],
    }.get(tone or "", th["soft"])


def svg_ring(th: Mapping[str, Any], share: float, size: int = 120, label: str = "") -> str:
    r = size / 2 - 9
    c = 2 * 3.14159265 * r
    on = max(0.0, min(1.0, share)) * c
    pct = round(share * 100)
    return (
        f'<svg class="ring" width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="{th["track"]}" stroke-width="12"/>'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="{th["accent"]}" stroke-width="12" stroke-linecap="round" '
        f'stroke-dasharray="{on:.1f} {c:.1f}" transform="rotate(-90 {size/2} {size/2})"/>'
        f'<text x="50%" y="50%" text-anchor="middle" dy="0.1em" font-size="{size*0.24:.0f}" font-weight="800" fill="{th["ink"]}">{pct}%</text>'
        f'<text x="50%" y="50%" text-anchor="middle" dy="1.7em" font-size="{size*0.09:.0f}" fill="{th["soft"]}">{esc(label)}</text>'
        "</svg>"
    )


def svg_bars(th: Mapping[str, Any], items: Sequence[Mapping[str, Any]], width: int = 300) -> str:
    total = max(1, sum(int(i["count"]) for i in items))
    peak = max([1] + [int(i["count"]) for i in items])
    row_h = 22
    label_w = 112
    bar_w = width - label_w - 44
    parts = [f'<svg class="bars" width="{width}" height="{row_h * len(items) + 4}" viewBox="0 0 {width} {row_h * len(items) + 4}">']
    for i, it in enumerate(items):
        y = i * row_h + 2
        w = max(2.0, bar_w * int(it["count"]) / peak) if it["count"] else 0
        label = esc(_s(it["label"])[:22])
        parts.append(f'<text x="0" y="{y + 14}" font-size="10" fill="{th["ink"]}">{label}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{bar_w}" height="12" rx="6" fill="{th["track"]}"/>')
        if w:
            parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{w:.1f}" height="12" rx="6" fill="{tone_color(th, it.get("tone", ""))}"/>')
        share = round(100 * int(it["count"]) / total)
        parts.append(f'<text x="{width - 2}" y="{y + 14}" font-size="10" font-weight="700" text-anchor="end" fill="{th["ink"]}">{int(it["count"])} · {share}%</text>')
    parts.append("</svg>")
    return "".join(parts)


def svg_funnel(th: Mapping[str, Any], f: Mapping[str, Any], base: int, width: int = 300) -> str:
    steps = [
        ("Wszyscy", base, None),
        ("Zgłosili wpłatę", f["declared"] + f["confirmed"], f.get("declared_total")),
        ("Otrzymano", f["confirmed"], f.get("confirmed_total")),
    ]
    peak = max(1, base)
    h = 26
    parts = [f'<svg class="funnel" width="{width}" height="{h * 3 + 6}" viewBox="0 0 {width} {h * 3 + 6}">']
    colors = [th["track"], th["warn"], th["pass"]]
    for i, (label, n, money) in enumerate(steps):
        w = max(36.0, (width - 8) * n / peak)
        x = (width - w) / 2
        ink = th["ink"] if i == 0 else "#FFFFFF"
        extra = f" · {_money(money)}" if money is not None and f.get("amount") else ""
        parts.append(f'<rect x="{x:.1f}" y="{i * h + 2}" width="{w:.1f}" height="{h - 4}" rx="6" fill="{colors[i]}"/>')
        parts.append(f'<text x="{width / 2}" y="{i * h + 17}" text-anchor="middle" font-size="10" font-weight="700" fill="{ink}">{esc(label)}: {n}{esc(extra)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def svg_timeline(th: Mapping[str, Any], points: Sequence[Mapping[str, Any]], total: int, width: int = 300, height: int = 96) -> str:
    if not points:
        return ""
    top = max(1, total, max(int(p["filled"]) for p in points))
    n = len(points)
    xs = [8 + (width - 16) * (i / max(1, n - 1)) for i in range(n)] if n > 1 else [width / 2]
    ys = [height - 18 - (height - 30) * int(p["filled"]) / top for p in points]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    area = f"{xs[0]:.1f},{height - 18} {line} {xs[-1]:.1f},{height - 18}"
    first, last = _s(points[0]["date"])[5:], _s(points[-1]["date"])[5:]
    return (
        f'<svg class="timeline" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<polygon points="{area}" fill="{th["track"]}"/>'
        f'<polyline points="{line}" fill="none" stroke="{th["accent"]}" stroke-width="2.4" stroke-linejoin="round"/>'
        f'<circle cx="{xs[-1]:.1f}" cy="{ys[-1]:.1f}" r="3.6" fill="{th["accent"]}"/>'
        f'<text x="8" y="{height - 4}" font-size="9" fill="{th["soft"]}">{esc(first[3:] + "." + first[:2] if len(first) == 5 else first)}</text>'
        f'<text x="{width - 8}" y="{height - 4}" font-size="9" text-anchor="end" fill="{th["soft"]}">{esc(last[3:] + "." + last[:2] if len(last) == 5 else last)} · {int(points[-1]["filled"])}</text>'
        "</svg>"
    )


# ---------------------------------------------------------------------------
# HTML (PDF przez weasyprint, plik HTML i strona publiczna)
# ---------------------------------------------------------------------------

_JS = """
(function(){
  var q=document.getElementById('q'); if(!q) return;
  var tables=[].slice.call(document.querySelectorAll('table.data'));
  var count=document.getElementById('count');
  function norm(s){return (s||'').toLowerCase();}
  q.addEventListener('input',function(){
    var n=norm(q.value), shown=0;
    tables.forEach(function(t){
      [].slice.call(t.tBodies).forEach(function(tb){
        var vis=0;
        [].slice.call(tb.rows).forEach(function(tr){
          if(tr.classList.contains('grp')) return;
          var ok=!n||norm(tr.textContent).indexOf(n)>=0; tr.style.display=ok?'':'none'; if(ok){vis++;shown++;}
        });
        var g=tb.querySelector('tr.grp'); if(g){ g.style.display=vis?'':'none'; var c=g.querySelector('.gcount'); if(c) c.textContent=vis; }
      });
    });
    if(count) count.textContent=shown;
  });
  tables.forEach(function(t){
    [].slice.call(t.tHead.rows[0].cells).forEach(function(th,i){
      if(th.classList.contains('nosort')) return;
      th.addEventListener('click',function(){
        var dir=th.getAttribute('data-dir')==='asc'?'desc':'asc';
        [].slice.call(t.tHead.rows[0].cells).forEach(function(o){o.removeAttribute('data-dir');});
        th.setAttribute('data-dir',dir);
        [].slice.call(t.tBodies).forEach(function(tb){
          var rows=[].slice.call(tb.rows).filter(function(r){return !r.classList.contains('grp');});
          rows.sort(function(a,b){
            var x=(a.cells[i]||{}).getAttribute?a.cells[i].getAttribute('data-v')||a.cells[i].textContent:'';
            var y=(b.cells[i]||{}).getAttribute?b.cells[i].getAttribute('data-v')||b.cells[i].textContent:'';
            var nx=parseFloat(x.replace(',','.')), ny=parseFloat(y.replace(',','.'));
            var c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y,'pl',{sensitivity:'base'});
            return dir==='asc'?c:-c;
          });
          rows.forEach(function(r){tb.appendChild(r);});
        });
      });
    });
  });
})();
"""


def _local_date(iso_text: str) -> str:
    try:
        moment = R.parse_iso(iso_text)
    except R.FormError:
        moment = None
    return moment.astimezone(R.WARSAW).strftime("%d.%m.%Y %H:%M") if moment else ""


def render_html(
    doc: Mapping[str, Any],
    *,
    theme: str,
    province_key: Optional[str],
    layout: str,
    mode: str,
    crest: str = "",
    level: str = "full",
) -> str:
    """`mode`: print (PDF) | file (HTML z wyszukiwarką) | public (strona z linku, przycięta do `level`)."""
    th = theme_for(theme, province_key, {"paper": theme_for("elegant", None, {})})
    interactive = mode in ("file", "public")
    report = layout == "report"
    checklist = layout == "checklist" and mode == "print"
    show_table = not (mode == "public" and level == "stats")
    show_charts = report or (mode == "public" and level == "stats")
    logo = brand_logo_uri(160)
    serif = "Georgia, 'DejaVu Serif', serif" if th.get("serif") else "'DejaVu Sans', 'Segoe UI', system-ui, sans-serif"
    tint = mix(th["accent"], th["bg"], 0.88) if not th.get("dark") else mix(th["accent"], th["bg"], 0.82)
    participants, filled = int(doc["participants"]), int(doc["filled"])
    share = filled / participants if participants else 0.0

    # ── nagłówek ──
    brand = (f'<img class="logo" src="{logo}" alt="BAZA"/>' if logo else "") + (f'<img class="crest" src="{crest}" alt=""/>' if crest else "")
    meta = []
    if doc.get("closes"):
        meta.append(f"Termin: {_local_date(doc['closes'])}")
    meta.append(("Stan na " if mode == "public" else "Wygenerowano ") + esc(doc["generated"]))
    lens_html = ""
    if doc["lenses"]:
        lens_html = '<div class="lenses">' + "".join(f'<span class="lens">{esc(x)}</span>' for x in doc["lenses"]) + "</div>"
    elif doc["scope"] == "all":
        lens_html = '<div class="lenses"><span class="lens">Cały formularz</span></div>'
    head = (
        f'<header class="band"><div class="brand">{brand}</div><div class="htext">'
        f'<div class="prov">{esc(doc["province"])}</div><h1>{esc(doc["title"])}</h1>'
        f'<div class="meta">{" · ".join(meta)}</div></div></header>{lens_html}'
    )

    # ── liczby i wykresy ──
    kpis = [("Wierszy w pliku", str(len(doc["table"]))), ("Wypełnione", f"{filled} z {participants}")]
    for f in doc["charts"].get("funnels") or []:
        if f.get("amount"):
            kpis.append((f"{f['title']}: otrzymano", _money(f.get("confirmed_total"))))
    for n in doc["charts"].get("numbers") or []:
        kpis.append((f"{n['title']}: suma", _s(n.get("sum"))))
    kpi_html = '<div class="kpis">' + "".join(f'<div class="kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in kpis[:6]) + "</div>"
    charts_html = ""
    if show_charts:
        cards = [f'<div class="card ring-card">{svg_ring(th, share, 128, "wypełnienia")}<div class="cap">Wypełnione {filled} z {participants}</div></div>']
        for d in doc["charts"].get("dists") or []:
            cards.append(f'<div class="card"><h3>{esc(d["title"])}</h3>{svg_bars(th, d["items"])}</div>')
        for f in doc["charts"].get("funnels") or []:
            cards.append(f'<div class="card"><h3>{esc(f["title"])}</h3>{svg_funnel(th, f, f["none"] + f["declared"] + f["confirmed"])}</div>')
        tl = svg_timeline(th, doc["timeline"], participants)
        if tl:
            cards.append(f'<div class="card"><h3>Narastanie odpowiedzi</h3>{tl}</div>')
        charts_html = f'<section class="charts">{"".join(cards)}</section>'

    # ── tabela ──
    header = list(doc["header"])
    table = doc["table"]
    tones = doc["tones"]
    names = doc["names"]
    name_col = header.index("Sędzia") if "Sędzia" in header else (header.index("Osoba") if "Osoba" in header else -1)
    table_html = ""
    if show_table:
        heads = ""
        if checklist:
            heads += '<th class="tick nosort">✓</th>'
        heads += "".join(f'<th>{esc(h)}</th>' for h in header)
        bodies: List[str] = []
        spans = doc["groups"] or [{"label": None, "size": len(table), "tone": "", "aggs": []}]
        start = 0
        for g in spans:
            size = int(g.get("size") or 0)
            rows_html = []
            if g.get("label") is not None:
                aggs = " · ".join(esc(a) for a in g.get("aggs") or [])
                rows_html.append(
                    f'<tr class="grp"><td colspan="{len(header) + (1 if checklist else 0)}">'
                    f'<span class="gdot" style="background:{tone_color(th, g.get("tone") or "neutral")}"></span>'
                    f'<b>{esc(g["label"])}</b> <span class="gcount">{size}</span>'
                    f'{f"<span class=gaggs>{aggs}</span>" if aggs else ""}</td></tr>'
                )
            for i in range(start, min(len(table), start + size)):
                row = table[i]
                cells = []
                if checklist:
                    cells.append('<td class="tick"><span class="box"></span></td>')
                for j, value in enumerate(row):
                    text = value
                    if j == name_col and mode == "public" and level == "initials":
                        text = initials(names[i] if i < len(names) else value)
                    tone = (tones[i][j] if tones and i < len(tones) and j < len(tones[i]) else "") or ""
                    if tone and _s(text):
                        color = tone_color(th, tone)
                        cells.append(f'<td data-v="{esc(_s(text))}"><span class="pill" style="color:{color};border-color:{color}">{esc(_s(text))}</span></td>')
                    else:
                        cells.append(f'<td>{esc(_s(text))}</td>')
                rows_html.append("<tr>" + "".join(cells) + "</tr>")
            start += size
            bodies.append("<tbody>" + "".join(rows_html) + "</tbody>")
        if not table:
            bodies = [f'<tbody><tr><td class="empty" colspan="{len(header) + (1 if checklist else 0)}">'
                      "Nikt nie pasuje do tego widoku - plik jest pusty, ale gotowy do uzupełnienia.</td></tr></tbody>"]
        search = ""
        if interactive and table:
            search = (f'<div class="search"><input id="q" type="search" placeholder="Szukaj w {len(table)} wierszach…" autocomplete="off"/>'
                      f'<span class="found"><b id="count">{len(table)}</b> wierszy</span></div>')
        table_html = f'<section class="tablewrap">{search}<table class="data"><thead><tr>{heads}</tr></thead>{"".join(bodies)}</table></section>'
        if checklist:
            table_html += '<div class="sign"><span>Sprawdził(a): ............................................</span><span>Data i podpis: ............................................</span></div>'

    pay = ""
    if doc["payment"] and mode != "public":
        pay = '<div class="pay">' + "".join(f'<div><span>{esc(k)}</span><b>{esc(v)}</b></div>' for k, v in doc["payment"]) + "</div>"

    wide = len(header) > 6
    page = "A4 landscape" if wide else "A4"
    css = f"""
@page {{ size: {page}; margin: 12mm 11mm 14mm 11mm;
  @bottom-left {{ content: "BAZA · {esc(doc['title'][:60])}"; font-size: 7pt; color: {th['soft']}; }}
  @bottom-right {{ content: "Strona " counter(page) " z " counter(pages); font-size: 7pt; color: {th['soft']}; }} }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ background: {th['bg']}; }}
body {{ font-family: 'DejaVu Sans', 'Segoe UI', system-ui, -apple-system, sans-serif; color: {th['ink']}; background: {th['bg']};
  font-size: {'13px' if interactive else '8.6pt'}; line-height: 1.4; {'max-width: 1080px; margin: 0 auto; padding: 18px 14px 40px;' if interactive else ''} }}
.band {{ display: flex; align-items: center; gap: 14px; background: {th['cover']}; color: {th['cover_ink']}; border-radius: 12px; padding: 14px 16px;
  border-bottom: 4px solid {th['band2']}; }}
.brand {{ display: flex; gap: 8px; align-items: center; }}
.brand img.logo {{ height: {'40px' if interactive else '13mm'}; width: auto; }}
.brand img.crest {{ height: {'44px' if interactive else '14mm'}; width: auto; }}
.prov {{ font-size: 0.78em; font-weight: 700; color: {th['cover_soft']}; letter-spacing: .04em; }}
h1 {{ font-family: {serif}; font-size: {'24px' if interactive else '17pt'}; line-height: 1.15; margin: 2px 0; }}
.meta {{ font-size: .82em; color: {th['cover_soft']}; }}
.lenses {{ display: flex; flex-wrap: wrap; gap: 5px; margin: 9px 0 0; }}
.lens {{ font-size: .78em; border: 1px solid {th['line']}; background: {tint}; color: {th['ink']}; border-radius: 99px; padding: 2px 9px; }}
.kpis {{ display: flex; flex-wrap: wrap; gap: 7px; margin: 12px 0; }}
.kpi {{ flex: 1 1 120px; background: {th['card']}; border: 1px solid {th['line']}; border-radius: 10px; padding: 7px 10px; }}
.kpi b {{ display: block; font-size: 1.35em; color: {th['accent']}; }}
.kpi span {{ font-size: .78em; color: {th['soft']}; }}
.charts {{ display: flex; flex-wrap: wrap; gap: 9px; margin: 4px 0 14px; page-break-inside: avoid; }}
.card {{ flex: 1 1 300px; background: {th['card']}; border: 1px solid {th['line']}; border-radius: 12px; padding: 10px 12px; page-break-inside: avoid; }}
.card h3 {{ font-family: {serif}; font-size: 1em; margin-bottom: 6px; }}
.ring-card {{ display: flex; flex-direction: column; align-items: center; justify-content: center; flex: 0 1 180px; }}
.cap {{ font-size: .8em; color: {th['soft']}; margin-top: 4px; }}
svg {{ max-width: 100%; height: auto; }}
.search {{ display: flex; align-items: center; gap: 10px; margin: 8px 0 10px; position: sticky; top: 0; background: {th['bg']}; padding: 6px 0; z-index: 2; }}
.search input {{ flex: 1; font-size: 15px; padding: 10px 14px; border-radius: 12px; border: 1.5px solid {th['line']}; background: {th['card']}; color: {th['ink']}; outline: none; }}
.search input:focus {{ border-color: {th['accent']}; }}
.found {{ font-size: .85em; color: {th['soft']}; white-space: nowrap; }}
.tablewrap {{ {'overflow-x: auto;' if interactive else ''} }}
table.data {{ width: 100%; border-collapse: collapse; background: {th['card']}; }}
th {{ text-align: left; font-size: .76em; font-weight: 800; color: {th['accent']}; border-bottom: 1.5px solid {th['accent']}; padding: 6px 6px;
  {'cursor: pointer; user-select: none; position: sticky; top: 52px; background: ' + th['card'] + ';' if interactive else ''} }}
th[data-dir=asc]::after {{ content: " ▲"; }} th[data-dir=desc]::after {{ content: " ▼"; }}
td {{ padding: {'7px 6px' if interactive else '4.6pt 5pt'}; border-bottom: 1px solid {th['line']}; vertical-align: middle; }}
tr.grp td {{ background: {tint}; font-size: .92em; padding-top: 8px; border-bottom: 1.5px solid {th['line']}; }}
.gdot {{ display: inline-block; width: 9px; height: 9px; border-radius: 5px; margin-right: 6px; vertical-align: middle; }}
.gcount {{ display: inline-block; min-width: 18px; text-align: center; font-weight: 800; color: {th['accent']}; margin-left: 4px; }}
.gaggs {{ float: right; font-size: .85em; color: {th['soft']}; }}
.pill {{ display: inline-block; border: 1px solid; border-radius: 99px; padding: 0 7px; font-weight: 700; font-size: .9em; white-space: nowrap; }}
th.tick, td.tick {{ width: 26px; text-align: center; }}
.box {{ display: inline-block; width: 13px; height: 13px; border: 1.2px solid {th['ink']}; border-radius: 3px; }}
td.empty {{ text-align: center; color: {th['soft']}; padding: 22px; }}
.sign {{ display: flex; justify-content: space-between; margin-top: 18px; font-size: .85em; color: {th['soft']}; }}
.pay {{ display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 10px 0; font-size: .82em; }}
.pay span {{ color: {th['soft']}; margin-right: 5px; }}
.foot {{ margin-top: 22px; font-size: .78em; color: {th['soft']}; text-align: center; }}
@media (max-width: 640px) {{ .band {{ flex-direction: column; align-items: flex-start; }} h1 {{ font-size: 20px; }} th {{ top: 58px; }} }}
@media print {{ .search {{ display: none; }} body {{ max-width: none; padding: 0; }} }}
"""
    foot = ""
    if interactive:
        foot = ('<div class="foot">BAZA · Formularze okręgu' + (" · strona publiczna, dane na żywo" if mode == "public" else " · plik z wyszukiwarką: kliknij nagłówek kolumny, żeby sortować") + "</div>")
    robots = '<meta name="robots" content="noindex,nofollow"/>' if mode == "public" else ""
    body = head + (kpi_html if report or mode == "public" else "") + pay + charts_html + table_html + foot
    script = f"<script>{_JS}</script>" if interactive and show_table and table else ""
    return (f'<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"/>'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"/>{robots}'
            f'<title>{esc(doc["title"])}</title><style>{css}</style></head><body>{body}{script}</body></html>')


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------


def _xl(hex_: str) -> str:
    return hex_.lstrip("#").upper()[:6]


def to_xlsx(doc: Mapping[str, Any], *, theme: str, province_key: Optional[str], layout: str) -> bytes:
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, Reference
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    th = theme_for(theme, province_key, {"paper": theme_for("elegant", None, {})})
    light = theme_for("province", province_key, {}) if th.get("dark") else th
    accent = _xl(light["accent"])
    tint = _xl(mix(light["accent"], "#FFFFFF", 0.86))
    fills = {
        "positive": "C6F6D5", "negative": "FED7D7", "warning": "FEEBC8", "neutral": "E2E8F0",
    }
    checklist = layout == "checklist"
    header = (["✓"] if checklist else []) + list(doc["header"])
    book = Workbook()
    sheet = book.active
    sheet.title = "Lista" if doc["kind"] == "list" else "Odpowiedzi"
    sheet.append([doc["title"]])
    sheet["A1"].font = Font(bold=True, size=15, color=accent)
    sheet.append([" · ".join(x for x in [doc["province"], f"Wygenerowano {doc['generated']}"] if x)])
    sheet.append(["Widok: " + (", ".join(doc["lenses"]) if doc["lenses"] else ("cały formularz" if doc["scope"] == "all" else "bez filtrów"))])
    sheet["A3"].font = Font(italic=True, color="666666")
    sheet.append([])
    sheet.append(header)
    head_row = sheet.max_row
    for cell in sheet[head_row]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=accent)
    thin = Side(style="thin", color="999999")
    spans = doc["groups"] or [{"label": None, "size": len(doc["table"]), "aggs": []}]
    start = 0
    for g in spans:
        size = int(g.get("size") or 0)
        if g.get("label") is not None:
            label = f"{g['label']} ({size})" + (f"  ·  {' · '.join(g.get('aggs') or [])}" if g.get("aggs") else "")
            sheet.append([label])
            r = sheet.max_row
            sheet.merge_cells(start_row=r, start_column=1, end_row=r, end_column=len(header))
            sheet.cell(row=r, column=1).font = Font(bold=True)
            sheet.cell(row=r, column=1).fill = PatternFill("solid", fgColor=tint)
        for i in range(start, min(len(doc["table"]), start + size)):
            sheet.append(([""] if checklist else []) + list(doc["table"][i]))
            r = sheet.max_row
            if checklist:
                sheet.cell(row=r, column=1).border = Border(left=thin, right=thin, top=thin, bottom=thin)
            if doc["tones"] and i < len(doc["tones"]):
                for j, tone in enumerate(doc["tones"][i]):
                    if tone in fills and _s(doc["table"][i][j]):
                        sheet.cell(row=r, column=j + 1 + (1 if checklist else 0)).fill = PatternFill("solid", fgColor=fills[tone])
        start += size
    sheet.freeze_panes = sheet.cell(row=head_row + 1, column=1)
    if not doc["groups"]:
        sheet.auto_filter.ref = f"A{head_row}:{get_column_letter(len(header))}{max(head_row, sheet.max_row)}"
    for idx, name in enumerate(header, start=1):
        width = max([len(_s(name))] + [len(_s(r[idx - 1 - (1 if checklist else 0)])) for r in doc["table"]
                                        if 0 <= idx - 1 - (1 if checklist else 0) < len(r)] + [4])
        sheet.column_dimensions[get_column_letter(idx)].width = min(46, width + 2)
    for row in sheet.iter_rows(min_row=head_row, max_row=sheet.max_row):
        for cell in row:
            cell.alignment = Alignment(vertical="center")

    totals = book.create_sheet("Podsumowanie")
    totals.append([doc["title"]])
    totals["A1"].font = Font(bold=True, size=14, color=accent)
    totals.append([])
    totals.append(["Wierszy w pliku", len(doc["table"])])
    totals.append(["Wypełnione", f"{doc['filled']} z {doc['participants']}"])
    for k, v in doc["payment"]:
        totals.append([k, v])
    totals.column_dimensions["A"].width = 40
    totals.column_dimensions["B"].width = 18
    if layout == "report":
        for d in doc["charts"].get("dists") or []:
            totals.append([])
            totals.append([d["title"], "Liczba"])
            first = totals.max_row
            totals.cell(row=first, column=1).font = Font(bold=True, color=accent)
            for it in d["items"]:
                totals.append([it["label"], int(it["count"])])
            last = totals.max_row
            if last > first:
                chart = BarChart()
                chart.type = "bar"
                chart.title = d["title"][:60]
                chart.legend = None
                chart.height = 4 + 0.6 * (last - first)
                chart.width = 14
                chart.add_data(Reference(totals, min_col=2, min_row=first, max_row=last), titles_from_data=True)
                chart.set_categories(Reference(totals, min_col=1, min_row=first + 1, max_row=last))
                totals.add_chart(chart, f"D{first}")
        for f in doc["charts"].get("funnels") or []:
            totals.append([])
            totals.append([f["title"], "Osoby", "Kwota"])
            totals.cell(row=totals.max_row, column=1).font = Font(bold=True, color=accent)
            totals.append(["Zgłoszone", f["declared"], _money(f.get("declared_total")) if f.get("amount") else ""])
            totals.append(["Otrzymano", f["confirmed"], _money(f.get("confirmed_total")) if f.get("amount") else ""])
            totals.append(["Bez wpłaty", f["none"], ""])
    buffer = io.BytesIO()
    book.save(buffer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Strona publiczna - link
# ---------------------------------------------------------------------------


def clean_link_settings(raw: Any, columns: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    body = raw if isinstance(raw, Mapping) else {}
    public_cols = {c["id"] for c in columns if (c.get("visibility") or "all") == "all"}
    scope = _choice(body.get("scope"), SCOPES, "view")
    return {
        "level": _choice(body.get("level"), PUBLIC_LEVELS, "stats"),
        "theme": _choice(body.get("theme"), THEMES, "province"),
        "layout": _choice(body.get("layout"), LAYOUTS, "report"),
        "scope": scope,
        "view": clean_view(body.get("view"), columns) if scope == "view" else clean_view({}, columns),
        "columns": [c for c in _str_list(body.get("columns"), 64, 40) if c in public_cols] if "columns" in body else sorted(public_cols),
        "lenses": _str_list(body.get("lenses"), MAX_LENSES, 120) if scope == "view" else [],
    }


def link_view(stored: Optional[Mapping[str, Any]], url_for: Callable[[str], str]) -> Dict[str, Any]:
    if not stored or not stored.get("code"):
        return {"enabled": False, "code": None, "url": None, "views": 0}
    return {
        "enabled": not stored.get("disabled_at"),
        "code": stored["code"],
        "url": url_for(stored["code"]),
        "level": stored.get("level", "stats"),
        "theme": stored.get("theme", "province"),
        "layout": stored.get("layout", "report"),
        "scope": stored.get("scope", "view"),
        "views": int(stored.get("views") or 0),
        "last_view_at": stored.get("last_view_at"),
        "created_at": stored.get("created_at"),
        "updated_at": stored.get("updated_at"),
        "disabled_at": stored.get("disabled_at"),
    }


def gone_page(message: str) -> str:
    return ('<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>'
            '<meta name="robots" content="noindex"/><title>BAZA</title><style>body{font-family:system-ui,sans-serif;background:#F4EFE9;color:#1A1210;'
            'display:flex;min-height:90vh;align-items:center;justify-content:center;text-align:center;padding:24px}b{font-size:20px;display:block;margin-bottom:8px}</style>'
            f'</head><body><div><b>Strony nie ma</b>{esc(message)}</div></body></html>')


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
