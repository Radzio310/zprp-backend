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
from app.exam_print_theme import brand_logo_uri, contrast, mix, theme_for

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
# Wykresy (HTML + inline SVG - działa w weasyprint i w przeglądarce, bez CDN)
#
# Zasada składu (13.11.2026, wzór: podsumowanie sezonu Beach, okładka egzaminu):
#   - druk bez CSS grid i bez flex w układzie stron (weasyprint): kolumny z inline-block,
#     paski z div-ów, krzywa narastania w SVG;
#   - jedna liczba-bohater na okładce, reszta cicha;
#   - zero nadtytułów nad nagłówkami.
# ---------------------------------------------------------------------------


def tone_color(th: Mapping[str, Any], tone: str) -> str:
    return {
        "positive": th["pass"], "negative": th["seal"], "warning": th["warn"],
        "neutral": th["accent"], "empty": th["line"],
    }.get(tone or "", th["soft"])


def _rgba(hex_: str, alpha: float) -> str:
    h = hex_.lstrip("#")
    if len(h) < 6:
        return hex_
    return f"rgba({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)},{alpha})"


def _soft_fill(th: Mapping[str, Any], color: str) -> str:
    """Tło pigułki statusu: barwa tonu rozpuszczona w papierze (na ciemnym mocniej)."""
    return mix(color, th["card"], 0.78 if th.get("dark") else 0.86)


def _pct_text(n: int, total: int) -> str:
    return f"{round(100 * n / total)}%" if total else "0%"


def _dm(day: Any) -> str:
    text = _s(day)
    return f"{text[8:10]}.{text[5:7]}" if len(text) >= 10 else text


def _on(color: str) -> str:
    """Napis na pełnej barwie: biały, jeśli czytelny, inaczej grafit."""
    return "#FFFFFF" if contrast(color, "#FFFFFF") >= 2.6 else "#1E1A17"


def planes(th: Mapping[str, Any], theme: str) -> Dict[str, str]:
    """Druga płaszczyzna kompozycji (skos okładki): barwa herbu nr 2, espresso albo błękit premium."""
    if theme == "elegant":
        return {"plane": "#2B2118", "ink": "#F3EAD8", "num": "#D9BE84", "soft": "#BFAF96"}
    if theme == "premium":
        return {"plane": th["accent"], "ink": "#0A0C10", "num": "#0A0C10", "soft": "#1E2A3A"}
    b1, b2 = th.get("band") or th["accent"], th.get("band2") or th["accent"]
    plane = b2 if b2.upper() != b1.upper() else mix(b1, "#000000", 0.38)
    ink = _on(plane)
    return {"plane": plane, "ink": ink, "num": ink, "soft": _rgba(ink, 0.78)}


def people(doc: Mapping[str, Any], *, initials_ok: bool) -> Dict[str, Any]:
    """Osoby jako wzór: kropka na osobę w barwie pierwszej kolumny ze statusem; pusta kropka = bez odpowiedzi."""
    header, table, tones, names = doc["header"], doc["table"], doc["tones"], doc["names"]
    col = None
    if tones:
        for j in range(len(header)):
            if any(j < len(t) and t[j] in ("positive", "negative", "warning") for t in tones):
                col = j
                break
    rank = {"positive": 0, "warning": 1, "negative": 2}
    items = []
    for i, row in enumerate(table):
        if col is not None:
            tone = (tones[i][col] if i < len(tones) and col < len(tones[i]) else "") or ""
            label = _s(row[col]) if col < len(row) else ""
        else:
            tone, label = "fill", ""
        hollow = tone in ("", "neutral")
        ini = initials(names[i]).replace(".", "").replace(" ", "") if initials_ok and i < len(names) else ""
        items.append({"tone": tone, "label": label, "hollow": hollow, "ini": ini,
                      "rank": rank.get(tone, 4 if hollow else 3), "i": i})
    items.sort(key=lambda x: (x["rank"], x["i"]))
    legend: List[Dict[str, Any]] = []
    for it in items:
        if col is None:
            break
        hit = next((g for g in legend if g["label"] == it["label"] and g["tone"] == it["tone"]), None)
        if hit:
            hit["count"] += 1
        else:
            legend.append({"label": it["label"] or "Brak", "tone": it["tone"], "hollow": it["hollow"], "count": 1})
    return {"items": items, "legend": legend, "title": header[col] if col is not None else ""}


def svg_dots(th: Mapping[str, Any], items: Sequence[Mapping[str, Any]], w: float, h: float, *, ink: str, fill: str,
             max_cell: float = 13.0) -> str:
    """Siatka osób w milimetrach: komórka tak duża, jak pozwala pudełko (do `max_cell`), inicjały od 6,5 mm."""
    n = len(items)
    if not n:
        return ""
    best = (0.0, 1, 1)
    for cols in range(1, n + 1):
        rows = -(-n // cols)
        s = min(w / cols, h / rows, max_cell)
        if s > best[0] + 1e-6:
            best = (s, cols, rows)
    s, cols, rows = best
    r = s * 0.42
    parts = []
    for k, it in enumerate(items):
        cx, cy = (k % cols + 0.5) * s, (k // cols + 0.5) * s
        if it["hollow"]:
            parts.append(f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r - s * 0.04:.2f}" fill="none" stroke="{ink}" stroke-opacity="0.5" stroke-width="{s * 0.07:.2f}"/>')
            text_c = ink
        else:
            color = fill if it["tone"] == "fill" else tone_color(th, it["tone"])
            parts.append(f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" fill="{color}"/>')
            text_c = _on(color)
        if it["ini"] and s >= 6.5:
            parts.append(f'<text x="{cx:.2f}" y="{cy + s * 0.105:.2f}" text-anchor="middle" font-size="{s * 0.3:.2f}" font-weight="700" '
                         f'fill="{text_c}"{" fill-opacity=" + chr(34) + "0.7" + chr(34) if it["hollow"] else ""}>{esc(it["ini"])}</text>')
    W, H = cols * s, rows * s
    return (f'<svg class="dots" width="{W:.1f}mm" height="{H:.1f}mm" viewBox="0 0 {W:.2f} {H:.2f}" '
            f'font-family="DejaVu Sans, Segoe UI, sans-serif">{"".join(parts)}</svg>')


def dots_legend(th: Mapping[str, Any], pp: Mapping[str, Any], ink: str) -> str:
    if not pp["legend"]:
        return ""
    out = []
    for g in pp["legend"]:
        dot = (f'<i class="ho" style="border-color:{ink}"></i>' if g["hollow"]
               else f'<i style="background:{tone_color(th, g["tone"])}"></i>')
        out.append(f'<span class="lg">{dot}<b>{g["count"]}</b> {esc(g["label"])}</span>')
    return '<div class="legend">' + "".join(out) + "</div>"


def money_track(th: Mapping[str, Any], f: Mapping[str, Any]) -> str:
    """Tor wpłat - bohater środka: kwota wielką cyfrą, tor do oczekiwanej sumy, segmenty z liczbą osób w środku."""
    confirmed, declared, none = int(f["confirmed"]), int(f["declared"]), int(f["none"])
    amount = float(f["amount"]) if f.get("amount") else 0.0
    if amount:
        expected_people = round(float(f.get("expected_total") or 0) / amount)
        denom = max(expected_people, confirmed + declared, 1)
        missing = max(0, denom - confirmed - declared)
        big = _money(f.get("confirmed_total"))
        of = f"z {_money(f.get('expected_total'))}"
    else:
        denom = max(1, confirmed + declared + none)
        missing = none
        big = f"{confirmed}"
        of = f"z {denom}"
    segs = [(confirmed, th["pass"]), (declared, th["warn"])]
    shown = [(n, c) for n, c in segs if n]
    html_segs = []
    for k, (n, color) in enumerate(shown):
        width = 100 * n / denom
        full = abs(sum(x for x, _ in shown) - denom) < 1e-9 and k == len(shown) - 1
        radius = ("99px 0 0 99px" if k == 0 else "0") if not full else ("99px" if k == 0 else "0 99px 99px 0")
        label = f"<span>{n}</span>" if width >= 5 else ""
        html_segs.append(f'<div class="seg" style="width:{width:.2f}%;background:{color};color:{_on(color)};border-radius:{radius}">{label}</div>')
    if missing and 100 * missing / denom >= 5:
        html_segs.append(f'<div class="seg rest" style="width:{100 * missing / denom:.2f}%"><span>{missing}</span></div>')
    def m(n: int) -> str:
        return f" · {_money(n * amount)}" if amount and n else ""
    legend = [
        f'<span class="lg"><i style="background:{th["pass"]}"></i>Otrzymano <b>{confirmed}</b>{esc(m(confirmed))}</span>',
        f'<span class="lg"><i style="background:{th["warn"]}"></i>Zgłoszone <b>{declared}</b>{esc(m(declared))}</span>',
        f'<span class="lg"><i class="ho"></i>{"Brakuje" if amount else "Bez wpłaty"} <b>{missing}</b>{esc(m(missing))}</span>',
    ]
    return (f'<section class="money funnel"><div class="mline"><span class="mname">{esc(f["title"])}</span>'
            f'<span class="mbig">{esc(big)}</span><span class="mof">{esc(of)}</span></div>'
            f'<div class="mtrack">{"".join(html_segs)}</div><div class="legend">{"".join(legend)}</div></section>')


def strips(th: Mapping[str, Any], dists: Sequence[Mapping[str, Any]], skip: str) -> str:
    """Rozkłady jako pasy 100%: pytanie po lewej, jeden pas z liczbami w środku, opis barw pod spodem."""
    out = []
    skipped = False
    for d in dists:
        if not skipped and skip and d["title"] == skip:
            skipped = True
            continue
        items = [it for it in d["items"]]
        total = sum(int(i["count"]) for i in items)
        if not total:
            continue
        shades = [th["accent"], mix(th["accent"], th["card"], 0.3), mix(th["accent"], th["card"], 0.5),
                  mix(th["accent"], th["card"], 0.65), mix(th["accent"], th["card"], 0.78)]
        colors, k = [], 0
        for it in items:
            if it.get("tone") == "empty":
                colors.append(th["track"])
            elif it.get("tone") in ("positive", "negative", "warning"):
                colors.append(tone_color(th, it["tone"]))
            else:
                colors.append(shades[k % len(shades)])
                k += 1
        live = [idx for idx, it in enumerate(items) if int(it["count"])]
        segs, leg = [], []
        for pos, idx in enumerate(live):
            it, color = items[idx], colors[idx]
            n = int(it["count"])
            width = 100 * n / total
            first, last = pos == 0, pos == len(live) - 1
            radius = "99px" if first and last else ("99px 0 0 99px" if first else ("0 99px 99px 0" if last else "0"))
            ink = th["soft"] if it.get("tone") == "empty" else _on(color)
            label = f"<span>{n}</span>" if width >= 6 else ""
            segs.append(f'<div class="seg" style="width:{width:.2f}%;background:{color};color:{ink};border-radius:{radius}">{label}</div>')
        for idx, it in enumerate(items):
            n = int(it["count"])
            if not n:
                continue
            leg.append(f'<span class="lg"><i style="background:{colors[idx]}"></i>{esc(_s(it["label"])[:40])} <b>{n}</b>'
                       f'<em>{_pct_text(n, total)}</em></span>')
        out.append(f'<div class="strip"><div class="sq">{esc(d["title"])}</div><div class="sb"><div class="sbar">{"".join(segs)}</div>'
                   f'<div class="legend">{"".join(leg)}</div></div></div>')
    return f'<section class="strips">{"".join(out)}</section>' if out else ""


def numbers_line(numbers: Sequence[Mapping[str, Any]]) -> str:
    if not numbers:
        return ""
    out = []
    for n in numbers:
        avg = n.get("avg")
        extra = f"<br/>średnio {esc(_num_text(round(float(avg), 1)).replace('.', ','))}" if avg is not None else ""
        out.append(f'<span class="nu"><b>{esc(_num_text(n.get("sum")))}</b><span>{esc(n["title"])}{extra}</span></span>')
    return f'<section class="nums">{"".join(out)}</section>'


def svg_timeline(th: Mapping[str, Any], points: Sequence[Mapping[str, Any]], total: int, width: int = 640, height: int = 150) -> str:
    """Narastanie odpowiedzi: schodki dzień po dniu, linia „wszyscy" u góry, wartość na końcu."""
    if not points:
        return ""
    top = max(1, total, max(int(p["filled"]) for p in points))
    left, right, ceil, floor = 6, width - 56, 18, height - 22
    n = len(points)
    xs = [left + (right - left) * (i / (n - 1)) for i in range(n)] if n > 1 else [(left + right) / 2]
    ys = [floor - (floor - ceil) * int(p["filled"]) / top for p in points]
    path = [f"{left:.1f},{floor:.1f}"]
    for i, (x, y) in enumerate(zip(xs, ys)):
        if i:
            path.append(f"{x:.1f},{ys[i - 1]:.1f}")
        path.append(f"{x:.1f},{y:.1f}")
    path.append(f"{right:.1f},{ys[-1]:.1f}")
    line = " ".join(path)
    area = f"{line} {right:.1f},{floor:.1f}"
    full_y = floor - (floor - ceil) * total / top if total else ceil
    labels = [(xs[0], "start", _dm(points[0]["date"]))]
    if n > 2:
        labels.append((xs[n // 2], "middle", _dm(points[n // 2]["date"])))
    if n > 1:
        labels.append((xs[-1], "end", _dm(points[-1]["date"])))
    ticks = "".join(f'<text x="{x:.1f}" y="{height - 6}" font-size="10" text-anchor="{a}" fill="{th["soft"]}">{esc(t)}</text>' for x, a, t in labels)
    return (
        f'<svg class="timeline" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<line x1="{left}" y1="{floor}" x2="{right}" y2="{floor}" stroke="{th["line"]}" stroke-width="1"/>'
        f'<line x1="{left}" y1="{full_y:.1f}" x2="{right}" y2="{full_y:.1f}" stroke="{th["soft"]}" stroke-width="0.8" stroke-dasharray="3 4"/>'
        f'<text x="{right + 6}" y="{full_y + 3.5:.1f}" font-size="10" fill="{th["soft"]}">{int(total)}</text>'
        f'<polygon points="{area}" fill="{th["accent"]}" fill-opacity="0.14"/>'
        f'<polyline points="{line}" fill="none" stroke="{th["accent"]}" stroke-width="2.4" stroke-linejoin="round"/>'
        f'<circle cx="{right:.1f}" cy="{ys[-1]:.1f}" r="4.2" fill="{th["accent"]}"/>'
        f'<text x="{right + 6}" y="{ys[-1] + 4:.1f}" font-size="22" font-weight="800" fill="{th["ink"]}">{int(points[-1]["filled"])}</text>'
        f"{ticks}</svg>"
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
    document.body.classList.toggle('nohit', !shown);
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

_NUM_RE = re.compile(r"^-?\d+(?:[.,]\d+)?$")
_WHEN_RE = re.compile(r"^\d{2}\.\d{2}\.\d{4}( \d{2}:\d{2})?$")
_SEARCH_ICON = ('<svg class="sicon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" '
                'stroke-linecap="round"><circle cx="11" cy="11" r="7"/><line x1="16.5" y1="16.5" x2="21" y2="21"/></svg>')


def _local_date(iso_text: str) -> str:
    try:
        moment = R.parse_iso(iso_text)
    except R.FormError:
        moment = None
    return moment.astimezone(R.WARSAW).strftime("%d.%m.%Y %H:%M") if moment else ""


def column_kinds(header: Sequence[str], table: Sequence[Sequence[str]]) -> List[str]:
    """Rodzaj kolumny do składu: lp | num (do prawej, cyfry tabelaryczne) | when (data) | txt."""
    kinds: List[str] = []
    for j, title in enumerate(header):
        values = [_s(r[j]) for r in table if j < len(r) and _s(r[j])]
        if title == "Lp.":
            kinds.append("lp")
        elif values and all(_NUM_RE.match(v) for v in values):
            kinds.append("num")
        elif values and all(_WHEN_RE.match(v) for v in values):
            kinds.append("when")
        else:
            kinds.append("txt")
    return kinds


def doc_facts(doc: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """Liczby okładki: osoby w pliku, główna odpowiedź „na tak", pieniądze, sumy - najwyżej cztery."""
    facts: List[Tuple[str, str]] = [
        (str(len(doc["table"])), "osób w pliku" if doc["kind"] == "list" else "odpowiedzi w pliku"),
    ]
    charts = doc["charts"]
    for d in charts.get("dists") or []:
        yes = next((i for i in d["items"] if i.get("tone") == "positive"), None)
        if yes:
            facts.append((str(int(yes["count"])), f'{d["title"]}: {yes["label"]}'))
            break
    for f in charts.get("funnels") or []:
        if f.get("amount"):
            facts.append((_money(f.get("confirmed_total")), f"{f['title']}: otrzymano"))
        else:
            facts.append((f'{f["confirmed"]} z {f["none"] + f["declared"] + f["confirmed"]}', f"{f['title']}: potwierdzone"))
    for n in charts.get("numbers") or []:
        facts.append((_num_text(n.get("sum")), f"{n['title']}: razem"))
    return facts[:4]


def empty_state(doc: Mapping[str, Any]) -> Optional[Dict[str, str]]:
    """Pusty widok zamiast zer: nikt nie pasuje (filtr) albo nikt jeszcze nie odpowiedział."""
    if not doc["table"] or not int(doc["participants"]):
        if doc["lenses"]:
            hint = f"Widok zawęża: {', '.join(doc['lenses'])}. Poluzuj filtr w aplikacji albo wygeneruj cały formularz."
        else:
            hint = "Na liście formularza nie ma jeszcze nikogo. Plik uzupełni się sam, gdy pojawią się osoby."
        return {"kind": "nomatch", "title": "Nikt nie pasuje do tego widoku", "hint": hint}
    if not int(doc["filled"]):
        until = f" Zapisy trwają do {_local_date(doc['closes'])}." if doc.get("closes") else ""
        return {"kind": "waiting", "title": "Nikt jeszcze nie odpowiedział",
                "hint": f"Formularz czeka na pierwsze odpowiedzi.{until}"}
    return None


def empty_art(kind: str) -> str:
    """Spokojna grafika pustego stanu w barwie napisu okładki (currentColor): pusta kartka z lupą albo z klepsydrą."""
    lines = "".join(
        f'<line x1="25" y1="{y}" x2="{60 if i % 2 else 66}" y2="{y}" stroke="currentColor" stroke-opacity="0.35" '
        f'stroke-width="2.4" stroke-linecap="round" stroke-dasharray="2 5"/>'
        for i, y in enumerate((32, 44, 56, 68))
    )
    sheet = ('<rect x="14" y="10" width="62" height="80" rx="8" fill="currentColor" fill-opacity="0.10" '
             'stroke="currentColor" stroke-opacity="0.55" stroke-width="2.4"/>'
             '<rect x="32" y="5" width="26" height="11" rx="4" fill="currentColor" fill-opacity="0.55"/>' + lines)
    if kind == "waiting":
        badge = ('<circle cx="80" cy="76" r="18" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="2.4"/>'
                 '<path d="M73 66 h14 M73 86 h14 M75 66 c0 7 10 7 10 10 c0 3 -10 3 -10 10 M85 66 c0 7 -10 7 -10 10 c0 3 10 3 10 10" '
                 'fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>')
    else:
        badge = ('<circle cx="76" cy="72" r="14" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="3"/>'
                 '<line x1="86" y1="82" x2="96" y2="92" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>')
    return f'<svg class="eart" width="104" height="100" viewBox="0 0 104 100" fill="none">{sheet}{badge}</svg>'


def _view_text(doc: Mapping[str, Any]) -> List[str]:
    if doc["lenses"]:
        return list(doc["lenses"])
    return ["Cały formularz"] if doc["scope"] == "all" else ["Bez filtrów"]


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
    """`mode`: print (PDF) | file (HTML z wyszukiwarką) | public (strona z linku, przycięta do `level`).

    Kompozycja (13.11.2026, druga runda): zero kafli. Okładka to dwie płaszczyzny barw herbu ze skosem,
    osoby jako siatka kropek w barwach statusu, odsetek wielką cyfrą na skosie, duże logo na białym krążku.
    Środek: tor wpłat jako bohater, rozkłady jako pasy 100%, sumy wielką cyfrą, narastanie na całą szerokość.
    """
    th = theme_for(theme, province_key, {"paper": theme_for("elegant", None, {})})
    pl = planes(th, theme)
    interactive = mode in ("file", "public")
    printing = not interactive
    report = layout == "report"
    checklist = layout == "checklist" and printing
    show_table = not (mode == "public" and level == "stats") and bool(doc["table"])
    show_charts = report or (mode == "public" and level == "stats")
    cover_page = printing and report
    logo = brand_logo_uri(420)
    title_font = "Georgia, 'DejaVu Serif', serif" if th.get("serif") else "'DejaVu Sans', 'Segoe UI', system-ui, -apple-system, sans-serif"
    tint = mix(th["accent"], th["card"], 0.82 if th.get("dark") else 0.9)
    zebra = mix(th["ink"], th["card"], 0.95 if th.get("dark") else 0.975)
    participants, filled = int(doc["participants"]), int(doc["filled"])
    share = filled / participants if participants else 0.0
    header, table, tones, names = list(doc["header"]), doc["table"], doc["tones"], doc["names"]
    wide = len(header) > 6
    page_w, page_h = (297, 210) if wide else (210, 297)
    cover_ink = th["cover_ink"] if th["cover_ink"].startswith("#") else "#FFFFFF"
    view_text = _view_text(doc)
    empty = empty_state(doc)
    if empty:
        show_charts = False
    pct = f"{round(share * 100)}"
    cap = f"{filled} z {participants} " + ("odpowiedziało" if doc["kind"] == "list" else "wysłało odpowiedź")
    when_bits = [f"zapisy do {_local_date(doc['closes'])}"] if doc.get("closes") else []
    stamp = ("Stan na " if mode == "public" else "Wygenerowano ") + doc["generated"]
    sub = " · ".join([x for x in [doc["province"], *when_bits] if x])
    crest_img = f'<img class="crest" src="{crest}" alt="Herb okręgu"/>' if crest else ""
    # Logo na białym krążku: czytelne na żółtym, kremowym, granatowym i grafitowym tle tak samo.
    logo_img = f'<span class="lpad"><img class="logo" src="{logo}" alt="BAZA"/></span>' if logo else ""
    pp = people(doc, initials_ok=not (mode == "public" and level == "stats"))
    empty_html = ""
    if empty:
        empty_html = (f'<div class="estate">{empty_art(empty["kind"])}<div class="etext"><b>{esc(empty["title"])}</b>'
                      f'<span>{esc(empty["hint"])}</span></div></div>')
    big_pct = f'<div class="pct"><b>{pct}</b><i>%</i></div><div class="pcap">{esc(cap)}</div>'

    # ── okładka druku / pas listy / scena pliku ──
    if cover_page:
        W, H = page_w, page_h
        slab = ([(W * 0.66, 0), (W, 0), (W, H), (W * 0.5, H)] if wide else [(0, 0), (W, 0), (W, H * 0.33), (0, H * 0.42)])
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in slab)
        box_w, box_h = ((W * 0.5) - 24, H - 130) if wide else (W - 32, 64)
        dots = svg_dots(th, pp["items"], box_w, box_h, ink=cover_ink, fill=cover_ink, max_cell=14.0)
        body_left = empty_html if empty else f'<div class="cdots">{dots}{dots_legend(th, pp, cover_ink)}</div>'
        head = (
            f'<section class="cover {"land" if wide else "port"}">'
            f'<svg class="slab" width="{W}mm" height="{H}mm" viewBox="0 0 {W} {H}"><polygon points="{poly}" fill="{pl["plane"]}"/></svg>'
            f'<div class="clogo">{logo_img}</div>'
            f'<div class="ctitle">{crest_img}<h1>{esc(doc["title"])}</h1><div class="csub">{esc(sub)}</div></div>'
            f'<div class="cbody">{body_left}</div>'
            f'{"" if empty else f"<div class=cpct>{big_pct}</div>"}'
            f'<div class="cfoot">{esc(" · ".join(view_text))}<br/>{esc(stamp)}</div></section>'
        )
    elif printing:
        cw = page_w - 24
        bh = 44
        poly = f"{cw * 0.62:.1f},0 {cw:.1f},0 {cw:.1f},{bh} {cw * 0.55:.1f},{bh}"
        right = "" if empty else f'<div class="bpct"><b>{filled}</b><i>/{participants}</i><span>odpowiedzi</span></div>'
        head = (
            f'<header class="band"><svg class="slab" width="{cw}mm" height="{bh}mm" viewBox="0 0 {cw} {bh}">'
            f'<polygon points="{poly}" fill="{pl["plane"]}"/></svg>'
            f'<div class="btitle">{crest_img}<div class="bt"><h1>{esc(doc["title"])}</h1><div class="bsub">{esc(sub)}</div></div></div>'
            f'{right}<div class="blogo">{logo_img}</div></header>'
            + (f'<div class="bempty">{empty_html}</div>' if empty else "")
            + f'<div class="viewline">{esc(" · ".join(view_text))}<span class="vstamp">{esc(stamp)}</span></div>'
        )
    else:
        dots = svg_dots(th, pp["items"], 170, 70, ink=cover_ink, fill=cover_ink, max_cell=13.0)
        left = empty_html if empty else f'<div class="hdots">{dots}{dots_legend(th, pp, cover_ink)}</div>'
        head = (
            f'<header class="hero"><svg class="hslab" viewBox="0 0 100 100" preserveAspectRatio="none">'
            f'<polygon points="63,0 100,0 100,100 54,100" fill="{pl["plane"]}"/></svg>'
            f'<div class="hl"><div class="htitle">{crest_img}<h1>{esc(doc["title"])}</h1><div class="hsub">{esc(sub)}</div></div>{left}</div>'
            f'<div class="hr"><div class="hlogo">{logo_img}</div>{"" if empty else big_pct}</div></header>'
            f'<div class="viewline">{esc(" · ".join(view_text))}<span class="vstamp">{esc(stamp)}</span></div>'
        )

    # ── przelew ──
    pay = ""
    if doc["payment"] and mode != "public":
        cells = []
        for k, v in doc["payment"]:
            cls = " acct" if re.fullmatch(r"[\d ]{16,}", _s(v)) else ""
            cells.append(f'<div class="pc{cls}"><span>{esc(k)}</span><b>{esc(v)}</b></div>')
        pay = f'<section class="pay">{"".join(cells)}</section>'

    # ── środek: dane jako grafika ──
    middle = ""
    if show_charts:
        charts = doc["charts"]
        money = "".join(money_track(th, f) for f in charts.get("funnels") or [])
        tl = svg_timeline(th, doc["timeline"], participants, *((1040, 210) if interactive else (1000, 136)))
        tl_html = f'<section class="tl"><div class="tlabel">Narastanie odpowiedzi</div>{tl}</section>' if tl else ""
        middle = (f'<div class="middle{" newpage" if cover_page else ""}">{money}{pay if printing else ""}'
                  f'{strips(th, charts.get("dists") or [], pp["title"])}<div class="duo">{numbers_line(charts.get("numbers") or [])}{tl_html}</div></div>')
        if interactive:
            middle += pay
    else:
        middle = pay

    # ── tabela ──
    name_col = header.index("Sędzia") if "Sędzia" in header else (header.index("Osoba") if "Osoba" in header else -1)
    kinds = column_kinds(header, table)
    table_html = ""
    if show_table:
        span_all = len(header) + (1 if checklist else 0)
        heads = '<th class="tick nosort"></th>' if checklist else ""
        for j, h in enumerate(header):
            cls = [kinds[j]] + (["name"] if j == name_col else [])
            heads += f'<th class="{" ".join(cls)}">{esc(h)}</th>'
        bodies: List[str] = []
        spans = doc["groups"] or [{"label": None, "size": len(table), "tone": "", "aggs": []}]
        start = 0
        for g in spans:
            size = int(g.get("size") or 0)
            rows_html = []
            if g.get("label") is not None:
                aggs = "".join(f'<span class="agg">{esc(a)}</span>' for a in g.get("aggs") or [])
                gc = tone_color(th, g.get("tone") or "neutral")
                rows_html.append(
                    f'<tr class="grp"><td colspan="{span_all}" style="border-left-color:{gc}">'
                    f'<b class="glabel">{esc(g["label"])}</b><span class="gcount" style="color:{gc}">{size}</span>'
                    f'{f"<span class=gaggs>{aggs}</span>" if aggs else ""}</td></tr>'
                )
            for i in range(start, min(len(table), start + size)):
                row = table[i]
                cells = ['<td class="tick"><span class="box"></span></td>'] if checklist else []
                for j, value in enumerate(row):
                    text = _s(value)
                    if j == name_col and mode == "public" and level == "initials":
                        text = initials(names[i] if i < len(names) else value)
                    kind = kinds[j] if j < len(kinds) else "txt"
                    cls = kind + (" name" if j == name_col else "")
                    tone = (tones[i][j] if tones and i < len(tones) and j < len(tones[i]) else "") or ""
                    if tone and text:
                        color = tone_color(th, tone)
                        cells.append(f'<td class="{cls}" data-v="{esc(text)}"><span class="pill" style="color:{color};background:{_soft_fill(th, color)}">'
                                     f'<i style="background:{color}"></i>{esc(text)}</span></td>')
                    else:
                        cells.append(f'<td class="{cls}">{esc(text)}</td>')
                rows_html.append("<tr>" + "".join(cells) + "</tr>")
            start += size
            bodies.append("<tbody>" + "".join(rows_html) + "</tbody>")
        search = ""
        if interactive:
            search = (f'<div class="search"><label class="sbox">{_SEARCH_ICON}<input id="q" type="search" '
                      f'placeholder="Szukaj w {len(table)} wierszach" autocomplete="off"/></label>'
                      f'<span class="found"><b id="count">{len(table)}</b> z {len(table)}</span></div>'
                      '<div class="nohit-msg">Nic nie pasuje do wpisanego tekstu.</div>')
        table_html = (f'<section class="tablewrap">{search}'
                      f'<div class="tscroll"><table class="data"><thead><tr>{heads}</tr></thead>{"".join(bodies)}</table></div></section>')
        if checklist:
            table_html += (
                '<section class="sign">'
                f'<div class="sg"><div class="sline"><b>______</b> z {len(table)}</div><span>Obecnych na liście</span></div>'
                '<div class="sg"><div class="sline"></div><span>Sprawdził(a)</span></div>'
                '<div class="sg"><div class="sline"></div><span>Data i podpis</span></div></section>'
            )

    foot = ""
    if interactive:
        note = "Strona publiczna, dane na żywo." if mode == "public" else "Stuknij nagłówek kolumny, żeby sortować."
        foot = f'<footer class="foot">{logo_img}<span>BAZA · Formularze okręgu · {esc(note)}</span></footer>'

    css = _css(th, pl, theme=theme, interactive=interactive, checklist=checklist, wide=wide, page_w=page_w, page_h=page_h,
               title_font=title_font, tint=tint, zebra=zebra, cover_ink=cover_ink,
               foot_left=f"{doc['province']} · {doc['title'][:70]}")
    robots = '<meta name="robots" content="noindex,nofollow"/>' if mode == "public" else ""
    body = head + middle + table_html + foot
    script = f"<script>{_JS}</script>" if interactive and show_table else ""
    return (f'<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"/>'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"/>{robots}'
            f'<title>{esc(doc["title"])}</title><style>{css}</style></head><body class="{mode} {layout}">{body}{script}</body></html>')


def _css(th: Mapping[str, Any], pl: Mapping[str, str], *, theme: str, interactive: bool, checklist: bool, wide: bool,
         page_w: int, page_h: int, title_font: str, tint: str, zebra: str, cover_ink: str, foot_left: str) -> str:
    """Arkusz stylów. Druk: pozycje bezwzględne na okładce, inline-block i float w środku (weasyprint: bez grid i flex)."""
    px = interactive

    def u(screen: str, paper: str) -> str:
        return screen if px else paper

    heavy = "800"
    track_c = _rgba(cover_ink, 0.22)
    page = "A4 landscape" if wide else "A4"
    foot_txt = esc(foot_left.replace('"', "'"))
    row_pad = u("9px 10px", "6.2pt 5pt" if checklist else "4.4pt 5pt")
    title_track = "-0.3pt" if th.get("serif") else "-1pt"
    land = wide
    return f"""
@page {{ size: {page}; margin: 13mm 12mm 15mm 12mm; background: {th['bg']};
  @bottom-left {{ content: "{foot_txt}"; font-size: 7pt; color: {th['soft']}; font-family: 'DejaVu Sans', sans-serif; }}
  @bottom-right {{ content: counter(page) " / " counter(pages); font-size: 7pt; color: {th['soft']}; font-family: 'DejaVu Sans', sans-serif; }} }}
@page cover {{ margin: 0; background: {th['cover']}; @bottom-left {{ content: none; }} @bottom-right {{ content: none; }} }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ background: {th['bg']}; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
body {{ font-family: 'DejaVu Sans', 'Segoe UI', system-ui, -apple-system, sans-serif; color: {th['ink']}; background: {th['bg']};
  font-size: {u('14px', '8.4pt' if wide else '8.6pt')}; line-height: 1.38; {'max-width: 1160px; margin: 0 auto; padding: 20px 16px 48px;' if px else ''} }}
h1 {{ font-family: {title_font}; font-weight: {heavy}; letter-spacing: {title_track}; line-height: 1.02; }}
b {{ font-weight: {heavy}; }}
.lpad {{ display: inline-block; background: #FFFFFF; border-radius: 50%; line-height: 0; }}
.lpad img {{ display: block; width: auto; }}
.legend {{ font-size: 0; }}
.lg {{ display: inline-block; margin: 0 {u('18px', '5mm')} {u('6px', '1.4mm')} 0; font-size: {u('14px', '8.6pt')}; white-space: nowrap; }}
.lg i {{ display: inline-block; width: {u('12px', '2.8mm')}; height: {u('12px', '2.8mm')}; border-radius: 50%; margin-right: {u('7px', '1.6mm')}; vertical-align: -1px; }}
.lg i.ho {{ border: 1.4px solid {th['soft']}; background: transparent; }}
.lg b {{ margin-right: 2px; }}
.lg em {{ font-style: normal; color: {th['soft']}; margin-left: 4px; }}

/* ── okładka druku: dwie płaszczyzny, skos, kropki osób, odsetek wielką cyfrą ── */
.cover {{ page: cover; position: relative; overflow: hidden; width: {page_w}mm; height: {page_h - 0.6}mm; page-break-after: always;
  color: {cover_ink}; background: {th['cover']}; }}
.cover .slab {{ position: absolute; left: 0; top: 0; }}
.clogo {{ position: absolute; {'right: 16mm; top: 14mm' if land else 'right: 15mm; top: 13mm'}; }}
.clogo .lpad {{ padding: {'3.5mm' if land else '3mm'}; }}
.clogo .logo {{ height: {'58mm' if land else '50mm'}; }}
.ctitle {{ position: absolute; left: 16mm; {'top: 16mm; width: 128mm' if land else 'top: 18mm; width: 112mm'}; {'' if land else 'color: ' + pl['ink'] + ';'} }}
.ctitle .crest {{ height: {'19mm' if land else '17mm'}; width: auto; display: block; margin-bottom: 6mm; }}
.ctitle h1 {{ font-size: {'34pt' if land else '32pt'}; }}
.csub {{ margin-top: 3.5mm; font-size: 10.5pt; color: {th['cover_soft'] if land else pl['soft']}; }}
.cbody {{ position: absolute; left: 16mm; {'top: 90mm; width: 130mm' if land else 'top: 192mm; right: 16mm'}; }}
.cdots svg {{ display: block; }}
.cdots .legend {{ margin-top: 4mm; }}
.cover .lg {{ color: {cover_ink}; }}
.cover .lg i.ho {{ border-color: {track_c}; }}
.cpct {{ position: absolute; {'right: 14mm; bottom: 22mm; width: 150mm; text-align: right; color: ' + pl['num'] if land else 'left: 13mm; top: 132mm; color: ' + cover_ink}; }}
.pct {{ line-height: 0.8; white-space: nowrap; }}
.pct b {{ font-size: {u('150px', '150pt' if land else '120pt')}; letter-spacing: {u('-8px', '-7pt')}; }}
.pct i {{ font-style: normal; font-weight: {heavy}; font-size: {u('64px', '58pt' if land else '48pt')}; margin-left: {u('4px', '1.5mm')}; }}
.pcap {{ margin-top: {u('10px', '3mm')}; font-size: {u('16px', '12pt')}; font-weight: 700; opacity: 0.86; }}
.cfoot {{ position: absolute; left: 16mm; bottom: 11mm; {'width: 130mm' if land else 'right: 16mm'}; font-size: 8pt; line-height: 1.5; color: {th['cover_soft']}; }}

/* ── pas listy do odhaczania ── */
.band {{ position: relative; height: 44mm; overflow: hidden; background: {th['cover']}; color: {cover_ink}; border-radius: 3mm; }}
.band .slab {{ position: absolute; left: 0; top: 0; }}
.btitle {{ position: absolute; left: 7mm; top: 7mm; width: {'150mm' if wide else '96mm'}; }}
.btitle .crest {{ float: left; height: 15mm; width: auto; margin-right: 4.5mm; }}
.bt {{ overflow: hidden; }}
.bt h1 {{ font-size: {'21pt' if wide else '17pt'}; }}
.bsub {{ margin-top: 1.6mm; font-size: 8.6pt; color: {th['cover_soft']}; }}
.bpct {{ position: absolute; right: 47mm; bottom: 6mm; text-align: right; color: {pl['num']}; line-height: 0.9; }}
.bpct b {{ font-size: 34pt; letter-spacing: -1.5pt; }}
.bpct i {{ font-style: normal; font-weight: {heavy}; font-size: 15pt; }}
.bpct span {{ display: block; font-size: 7.6pt; color: {pl['soft']}; margin-top: 1.2mm; }}
.blogo {{ position: absolute; right: 6mm; top: 5mm; }}
.blogo .lpad {{ padding: 1.6mm; }}
.blogo .logo {{ height: 30.5mm; }}
.bempty {{ margin-top: 6mm; color: {th['ink']}; }}
.bempty .estate svg {{ color: {th['accent']}; }}
.bempty .etext span {{ color: {th['soft']}; }}

/* ── scena pliku i strony publicznej ── */
.hero {{ position: relative; overflow: hidden; background: {th['cover']}; color: {cover_ink}; border-radius: 28px; padding: 34px 34px 30px; font-size: 0; }}
.hslab {{ position: absolute; left: 0; top: 0; width: 100%; height: 100%; }}
.hl {{ position: relative; display: inline-block; vertical-align: top; width: 56%; font-size: 14px; }}
.hr {{ position: relative; display: inline-block; vertical-align: top; width: 44%; text-align: right; color: {pl['num']}; font-size: 14px; }}
.htitle .crest {{ height: 58px; width: auto; display: block; margin-bottom: 18px; }}
.htitle h1 {{ font-size: 40px; }}
.hsub {{ margin-top: 10px; font-size: 15px; color: {th['cover_soft']}; }}
.hdots {{ margin-top: 30px; }}
.hdots svg {{ display: block; width: 100%; height: auto; max-width: 620px; }}
.hdots .legend {{ margin-top: 16px; }}
.hero .lg {{ color: {cover_ink}; }}
.hero .lg i.ho {{ border-color: {track_c}; }}
.hlogo .lpad {{ padding: 10px; }}
.hlogo .logo {{ height: 150px; }}
.hr .pct {{ margin-top: 60px; }}
.hr .pcap {{ color: {pl['ink']}; }}
.hero .estate {{ margin-top: 34px; }}
.viewline {{ margin: {u('14px 4px 0', '3mm 0.5mm 0')}; overflow: hidden; font-size: {u('13px', '7.8pt')}; color: {th['soft']}; }}
.vstamp {{ float: right; }}

/* ── pusty stan ── */
.estate {{ overflow: hidden; }}
.estate svg {{ float: left; width: {u('104px', '40mm')}; height: auto; margin-right: {u('24px', '7mm')}; color: currentColor; }}
.etext {{ overflow: hidden; padding-top: {u('12px', '5mm')}; }}
.etext b {{ display: block; font-family: {title_font}; font-size: {u('28px', '22pt')}; line-height: 1.12; letter-spacing: -0.4px; }}
.etext span {{ display: block; margin-top: {u('8px', '2.4mm')}; max-width: {u('520px', '120mm')}; opacity: 0.82; font-size: {u('15px', '10.5pt')}; line-height: 1.45; }}

/* ── środek ── */
.newpage {{ page-break-before: always; }}
.middle {{ {'margin-top: 40px;' if px else 'margin-bottom: 8mm;'} }}
.money {{ margin-bottom: {u('40px', '11mm')}; page-break-inside: avoid; }}
.mline {{ line-height: 1; }}
.mname {{ float: right; font-weight: 700; color: {th['soft']}; font-size: {u('15px', '10pt')}; margin-top: {u('34px', '9mm')}; }}
.mbig {{ font-family: {title_font}; font-weight: {heavy}; font-size: {u('84px', '62pt')}; letter-spacing: {u('-4px', '-2.6pt')}; color: {th['pass']}; }}
.mof {{ font-weight: {heavy}; font-size: {u('34px', '24pt')}; letter-spacing: -1px; color: {th['soft']}; margin-left: {u('16px', '4mm')}; }}
.mtrack {{ margin: {u('18px 0 14px', '5mm 0 4mm')}; height: {u('54px', '14mm')}; border-radius: 99px; background: {th['track']}; font-size: 0; }}
.seg {{ float: left; height: 100%; text-align: center; font-weight: {heavy}; font-size: {u('20px', '14pt')}; }}
.seg span {{ display: block; line-height: {u('54px', '14mm')}; }}
.money .seg span {{ font-size: {u('20px', '14pt')}; }}
.seg.rest {{ color: {th['soft']}; }}
.strips {{ margin-bottom: {u('30px', '8mm')}; }}
.strip {{ font-size: 0; padding: {u('18px 0 10px', '4.6mm 0 2.4mm')}; border-top: 1px solid {th['line']}; page-break-inside: avoid; }}
.sq {{ display: inline-block; vertical-align: top; width: 24%; padding-right: {u('16px', '4mm')}; font-family: {title_font}; font-weight: {heavy};
  font-size: {u('19px', '13pt')}; line-height: 1.15; letter-spacing: -0.3px; }}
.sb {{ display: inline-block; vertical-align: top; width: 76%; }}
.sbar {{ height: {u('34px', '9mm')}; border-radius: 99px; background: {th['track']}; margin-bottom: {u('10px', '2.6mm')}; }}
.sbar .seg {{ border-right: {u('3px', '0.8mm')} solid {th['bg']}; font-size: {u('15px', '10pt')}; }}
.sbar .seg span {{ line-height: {u('34px', '9mm')}; }}
.sbar .seg:last-child {{ border-right: 0; }}
.nums {{ font-size: 0; padding: {u('20px 0', '4mm 0 5mm')}; border-top: 1px solid {th['line']}; page-break-inside: avoid; }}
.nu {{ display: inline-block; vertical-align: bottom; margin-right: {u('44px', '13mm')}; }}
.nu b {{ font-family: {title_font}; font-size: {u('72px', '50pt')}; line-height: 0.9; letter-spacing: -2px; color: {th['accent']}; vertical-align: bottom; }}
.nu span {{ display: inline-block; vertical-align: bottom; margin-left: {u('10px', '3mm')}; font-size: {u('14px', '9pt')}; color: {th['soft']}; line-height: 1.35; }}
.tl {{ padding-top: {u('18px', '4mm')}; border-top: 1px solid {th['line']}; page-break-inside: avoid; }}
{'' if px else '.duo { font-size: 0; border-top: 1px solid ' + th['line'] + '; page-break-inside: avoid; } .duo .nums, .duo .tl { display: inline-block; vertical-align: top; border-top: 0; font-size: 8.6pt; } .duo .nums { width: 30%; padding-right: 5mm; } .duo .nums .nu { display: block; margin: 0 0 4mm; } .duo .tl { width: 70%; } .duo .nums + .tl { border-left: 1px solid ' + th['line'] + '; padding-left: 5mm; }'}
.tlabel {{ font-family: {title_font}; font-weight: {heavy}; font-size: {u('19px', '13pt')}; margin-bottom: {u('8px', '2mm')}; }}
svg {{ max-width: 100%; }}
svg.timeline {{ width: 100%; height: auto; display: block; }}

/* ── przelew ── */
.pay {{ margin: {u('30px 0 6px', '0 0 8mm')}; border-left: {u('6px', '1.6mm')} solid {th['accent']}; padding: {u('6px 0 6px 18px', '1mm 0 1mm 5mm')}; font-size: 0; page-break-inside: avoid; }}
.pc {{ display: inline-block; vertical-align: top; margin-right: {u('30px', '9mm')}; margin-bottom: 4px; }}
.pc span {{ display: block; font-size: {u('12px', '7pt')}; color: {th['soft']}; }}
.pc b {{ display: block; font-size: {u('16px', '10pt')}; }}
.pc.acct b {{ font-family: 'DejaVu Sans Mono', Consolas, monospace; letter-spacing: 0.4px; }}
.band ~ .pay {{ margin-top: 4mm; margin-bottom: 0; }}

/* ── tabela ── */
.tscroll {{ {'overflow-x: auto; border: 1px solid ' + th['line'] + '; border-radius: 18px; background: ' + th['card'] + ';' if px else ''} }}
table.data {{ width: 100%; border-collapse: collapse; background: {th['card']}; {'margin-top: 4mm;' if checklist else ''} }}
thead {{ display: table-header-group; }}
th {{ text-align: left; font-size: 0.86em; font-weight: {heavy}; color: {th['ink']}; padding: {u('12px 10px', '3.2pt 5pt 3.6pt')};
  border-bottom: {u('2px', '1.3pt')} solid {th['ink']}; white-space: nowrap;
  {'cursor: pointer; user-select: none; position: sticky; top: 0; z-index: 2; background: ' + th['card'] + ';' if px else ''} }}
th[data-dir=asc]::after {{ content: " ▲"; color: {th['accent']}; }} th[data-dir=desc]::after {{ content: " ▼"; color: {th['accent']}; }}
td {{ padding: {row_pad}; border-bottom: {u('1px', '0.5pt')} solid {th['line']}; vertical-align: middle; }}
tbody tr:nth-child(even) td {{ background: {zebra}; }}
tr {{ page-break-inside: avoid; }}
td.lp, th.lp {{ width: {u('34px', '7mm')}; color: {th['soft']}; }}
td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
td.when {{ color: {th['soft']}; white-space: nowrap; font-size: 0.92em; }}
td.name {{ font-weight: 700; white-space: nowrap; }}
td.txt {{ max-width: {u('280px', '60mm')}; }}
.pill {{ display: inline-block; border-radius: 99px; padding: {u('2px 10px 2px 8px', '0.3mm 2.4mm 0.3mm 1.8mm')}; font-weight: 700; font-size: 0.9em; white-space: nowrap; }}
.pill i {{ display: inline-block; width: {u('7px', '1.5mm')}; height: {u('7px', '1.5mm')}; border-radius: 50%; margin-right: {u('6px', '1.3mm')}; vertical-align: 1px; }}
tr.grp td {{ background: {th['card']} !important; padding: {u('22px 12px 8px', '7pt 5pt 3pt')}; border-bottom: {u('2px', '1pt')} solid {th['line']};
  border-left: {u('6px', '1.6mm')} solid {th['accent']}; }}
tr.grp {{ page-break-after: avoid; }}
.glabel {{ font-family: {title_font}; font-size: {u('22px', '14pt')}; letter-spacing: -0.4px; }}
.gcount {{ font-weight: {heavy}; font-size: {u('22px', '14pt')}; margin-left: {u('10px', '2.4mm')}; }}
.gaggs {{ float: right; color: {th['soft']}; font-size: 0.92em; margin-top: {u('8px', '2.4mm')}; }}
.agg {{ margin-left: 12px; }}
th.tick, td.tick {{ width: {u('34px', '8mm')}; text-align: center; }}
.box {{ display: inline-block; width: 4.4mm; height: 4.4mm; border: 1.2pt solid {th['ink']}; border-radius: 1mm; background: {th['card']}; vertical-align: middle; }}
.sign {{ margin-top: 10mm; font-size: 0; page-break-inside: avoid; }}
.sg {{ display: inline-block; vertical-align: bottom; width: 30%; margin-right: 5%; font-size: 8pt; color: {th['soft']}; }}
.sg:last-child {{ margin-right: 0; }}
.sline {{ height: 9mm; border-bottom: 0.9pt solid {th['ink']}; margin-bottom: 1.4mm; color: {th['ink']}; font-size: 10pt; padding-top: 3mm; }}
.sline b {{ color: {th['line']}; letter-spacing: 1px; }}

/* ── ekran ── */
.search {{ position: sticky; top: 0; z-index: 5; display: flex; align-items: center; gap: 12px; padding: 30px 0 12px; background: {th['bg']}; }}
.sbox {{ flex: 1; position: relative; display: block; }}
.sicon {{ position: absolute; left: 16px; top: 50%; margin-top: -9px; color: {th['soft']}; }}
.search input {{ width: 100%; font-size: 16px; padding: 14px 16px 14px 46px; border-radius: 99px; border: 1.5px solid {th['line']};
  background: {th['card']}; color: {th['ink']}; outline: none; font-family: inherit; }}
.search input:focus {{ border-color: {th['accent']}; }}
.found {{ font-size: 13px; color: {th['soft']}; white-space: nowrap; }}
.found b {{ color: {th['ink']}; font-size: 18px; }}
.nohit-msg {{ display: none; text-align: center; color: {th['soft']}; padding: 30px 0; }}
body.nohit .nohit-msg {{ display: block; }}
body.nohit .tscroll {{ display: none; }}
.foot {{ margin-top: 44px; padding-top: 22px; border-top: 1px solid {th['line']}; font-size: 12.5px; color: {th['soft']}; text-align: center; }}
.foot .lpad {{ display: block; width: 76px; margin: 0 auto 10px; padding: 6px; border: 1px solid {th['line']}; }}
.foot .lpad img {{ height: 64px; }}
@media (max-width: 760px) {{
  body {{ padding: 12px 10px 40px; }}
  .hero {{ padding: 22px 20px; border-radius: 22px; }}
  .hslab {{ display: none; }}
  .hl, .hr {{ display: block; width: 100%; }}
  .hr {{ margin: 22px -20px -22px; width: auto; padding: 22px 20px 24px; background: {pl['plane']}; text-align: left; }}
  .hlogo {{ float: right; }} .hlogo .logo {{ height: 92px; }} .hlogo .lpad {{ padding: 6px; }}
  .hr .pct {{ margin-top: 6px; }} .pct b {{ font-size: 104px; }} .pct i {{ font-size: 44px; }}
  .htitle h1 {{ font-size: 28px; }} .htitle .crest {{ height: 44px; }}
  .mbig {{ font-size: 54px; }} .mof {{ font-size: 24px; }} .mname {{ float: none; display: block; margin: 0 0 8px; }}
  .sq, .sb {{ display: block; width: 100%; }} .sq {{ margin-bottom: 10px; }}
  .nu b {{ font-size: 54px; }}
  .vstamp {{ float: none; display: block; }}
  td.name, th.name {{ position: sticky; left: 0; z-index: 1; background: {th['card']}; }}
  th.name {{ z-index: 3; }}
}}
@media print {{ .search, .nohit-msg {{ display: none; }} body {{ max-width: none; padding: 0; }} th {{ position: static; }} }}
"""


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------


def _xl(hex_: str) -> str:
    return hex_.lstrip("#").upper()[:6]


def _xl_number(text: str) -> Optional[float]:
    t = _s(text)
    if not _NUM_RE.match(t):
        return None
    n = float(t.replace(",", "."))
    return int(n) if n == int(n) else n


def to_xlsx(doc: Mapping[str, Any], *, theme: str, province_key: Optional[str], layout: str) -> bytes:
    """Arkusz: tytuł, widok, nagłówek w barwie motywu, zamrożone nazwisko, liczby jako liczby, daty jako daty,
    statusy w kolorach tonu, grupy jako pasy z sumami; Podsumowanie z kwotami w złotych i wykresami."""
    from datetime import datetime as _dt

    from openpyxl import Workbook
    from openpyxl.chart import BarChart, Reference
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.page import PageMargins

    th = theme_for(theme, province_key, {"paper": theme_for("elegant", None, {})})
    light = theme_for("province", province_key, {}) if th.get("dark") else th
    accent = _xl(light["accent"])
    head_fill = accent
    head_ink = "FFFFFF" if luminance_ok(light["accent"]) else "1E1A17"
    tint = _xl(mix(light["accent"], "#FFFFFF", 0.88))
    zebra = "F7F6F4"
    soft = "6B625B"
    tone_ink = {"positive": "1F7A4A", "negative": "A3302A", "warning": "9A6212", "neutral": "4A5568"}
    tone_fill = {"positive": "E3F3EA", "negative": "FBE5E3", "warning": "FCF0DC", "neutral": "EDF0F4"}
    money_fmt = '#,##0" zł"'
    checklist = layout == "checklist"
    shift = 1 if checklist else 0
    header = (["✓"] if checklist else []) + list(doc["header"])
    ncol = len(header)
    kinds = (["tick"] if checklist else []) + column_kinds(doc["header"], doc["table"])
    name_idx = next((i for i, h in enumerate(header) if h in ("Sędzia", "Osoba")), None)
    book = Workbook()
    sheet = book.active
    sheet.title = "Lista" if doc["kind"] == "list" else "Odpowiedzi"
    sheet.sheet_view.showGridLines = False
    hair = Side(style="thin", color="E4E0DA")
    strong = Side(style="medium", color=accent)
    box = Side(style="thin", color="555555")

    sheet.append([doc["title"]])
    sheet["A1"].font = Font(bold=True, size=18, color=accent)
    sheet.row_dimensions[1].height = 30
    meta = [doc["province"], f"Wygenerowano {doc['generated']}"]
    if doc.get("closes"):
        meta.insert(1, f"zapisy do {_local_date(doc['closes'])}")
    sheet.append([" · ".join(x for x in meta if x)])
    sheet["A2"].font = Font(size=11, color=soft)
    sheet.append(["Widok: " + " · ".join(_view_text(doc)) + f"   ·   {len(doc['table'])} wierszy, wypełnione {doc['filled']} z {doc['participants']}"])
    sheet["A3"].font = Font(italic=True, size=10, color=soft)
    sheet.append([])
    sheet.append(header)
    head_row = sheet.max_row
    sheet.row_dimensions[head_row].height = 24
    for idx, cell in enumerate(sheet[head_row], start=1):
        cell.font = Font(bold=True, color=head_ink, size=11)
        cell.fill = PatternFill("solid", fgColor=head_fill)
        cell.alignment = Alignment(vertical="center", horizontal="right" if kinds[idx - 1] == "num" else ("center" if kinds[idx - 1] == "tick" else "left"))
    spans = doc["groups"] or [{"label": None, "size": len(doc["table"]), "aggs": [], "tone": ""}]
    start = 0
    data_rows = 0
    for g in spans:
        size = int(g.get("size") or 0)
        if g.get("label") is not None:
            label = f"{g['label']} ({size})" + (f"  ·  {' · '.join(g.get('aggs') or [])}" if g.get("aggs") else "")
            sheet.append([label])
            r = sheet.max_row
            sheet.merge_cells(start_row=r, start_column=1, end_row=r, end_column=ncol)
            c = sheet.cell(row=r, column=1)
            tone = g.get("tone") or ""
            c.font = Font(bold=True, size=12, color=tone_ink.get(tone, accent))
            c.fill = PatternFill("solid", fgColor=tone_fill.get(tone, tint))
            c.alignment = Alignment(vertical="center", indent=1)
            c.border = Border(left=Side(style="thick", color=tone_ink.get(tone, accent)))
            sheet.row_dimensions[r].height = 22
            data_rows = 0
        for i in range(start, min(len(doc["table"]), start + size)):
            src = list(doc["table"][i])
            values: List[Any] = [""] if checklist else []
            for j, text in enumerate(src):
                kind = kinds[j + shift]
                if kind in ("num", "lp"):
                    n = _xl_number(text)
                    values.append(n if n is not None else _s(text) or None)
                elif kind == "when" and _s(text):
                    try:
                        values.append(_dt.strptime(_s(text), "%d.%m.%Y %H:%M"))
                    except ValueError:
                        values.append(_s(text))
                else:
                    values.append(_s(text) or None)
            sheet.append(values)
            r = sheet.max_row
            data_rows += 1
            if checklist:
                sheet.row_dimensions[r].height = 21
            for col in range(1, ncol + 1):
                cell = sheet.cell(row=r, column=col)
                kind = kinds[col - 1]
                cell.border = Border(bottom=hair)
                cell.alignment = Alignment(vertical="center", horizontal="right" if kind == "num" else ("center" if kind in ("tick", "lp") else "left"),
                                           wrap_text=kind == "txt" and col - 1 != name_idx)
                if data_rows % 2 == 0:
                    cell.fill = PatternFill("solid", fgColor=zebra)
                if kind == "when":
                    cell.number_format = "dd.mm.yyyy hh:mm"
                    cell.font = Font(color=soft)
                elif kind == "lp":
                    cell.font = Font(color=soft)
                if col - 1 == name_idx:
                    cell.font = Font(bold=True)
            if checklist:
                sheet.cell(row=r, column=1).border = Border(left=box, right=box, top=box, bottom=box)
            if doc["tones"] and i < len(doc["tones"]):
                for j, tone in enumerate(doc["tones"][i]):
                    if tone in tone_fill and _s(src[j] if j < len(src) else ""):
                        cell = sheet.cell(row=r, column=j + 1 + shift)
                        cell.fill = PatternFill("solid", fgColor=tone_fill[tone])
                        cell.font = Font(bold=True, color=tone_ink[tone])
        start += size
    last_row = max(head_row, sheet.max_row)
    for cell in sheet[head_row]:
        cell.border = Border(bottom=strong)
    freeze_col = (name_idx + 2) if name_idx is not None else 1
    sheet.freeze_panes = f"{get_column_letter(freeze_col)}{head_row + 1}"
    if not doc["groups"]:
        sheet.auto_filter.ref = f"A{head_row}:{get_column_letter(ncol)}{last_row}"
    for idx, name in enumerate(header, start=1):
        kind = kinds[idx - 1]
        j = idx - 1 - shift
        lengths = [len(_s(r[j])) for r in doc["table"] if 0 <= j < len(r)]
        if kind == "tick":
            width = 5
        elif kind == "lp":
            width = 6
        elif kind == "when":
            width = 17
        else:
            longest = max([len(_s(name)) + 2] + lengths + [6])
            width = min(44 if kind == "txt" else 16, longest + 3)
        sheet.column_dimensions[get_column_letter(idx)].width = width
    sheet.print_title_rows = f"{head_row}:{head_row}"
    sheet.page_setup.orientation = "landscape" if ncol > 7 else "portrait"
    sheet.page_setup.paperSize = sheet.PAPERSIZE_A4
    sheet.page_setup.fitToWidth = 1
    sheet.page_setup.fitToHeight = 0
    sheet.sheet_properties.pageSetUpPr.fitToPage = True
    sheet.page_margins = PageMargins(left=0.4, right=0.4, top=0.5, bottom=0.6)
    sheet.oddFooter.left.text = f"{doc['province']} · {doc['title'][:60]}"
    sheet.oddFooter.right.text = "Strona &P z &N"

    totals = book.create_sheet("Podsumowanie")
    totals.sheet_view.showGridLines = False
    totals.append([doc["title"]])
    totals["A1"].font = Font(bold=True, size=16, color=accent)
    totals.row_dimensions[1].height = 26
    totals.append([" · ".join(x for x in [doc["province"], f"Wygenerowano {doc['generated']}"] if x)])
    totals["A2"].font = Font(size=10, color=soft)
    totals.append([])

    def section(title: str, *cols: str) -> int:
        totals.append([title, *cols])
        r = totals.max_row
        for c in range(1, 2 + len(cols)):
            cell = totals.cell(row=r, column=c)
            cell.font = Font(bold=True, color=head_ink)
            cell.fill = PatternFill("solid", fgColor=head_fill)
            cell.alignment = Alignment(horizontal="left" if c == 1 else "right", vertical="center")
        totals.row_dimensions[r].height = 20
        return r

    def line(values: Sequence[Any], fmt: Sequence[Optional[str]] = ()) -> None:
        totals.append(list(values))
        r = totals.max_row
        for c in range(1, len(values) + 1):
            cell = totals.cell(row=r, column=c)
            cell.border = Border(bottom=hair)
            if c > 1:
                cell.alignment = Alignment(horizontal="right")
            if c - 2 < len(fmt) and c > 1 and fmt[c - 2]:
                cell.number_format = fmt[c - 2]

    section("W skrócie", "Wartość")
    line(["Wierszy w pliku", len(doc["table"])])
    line(["Wypełnione", doc["filled"]])
    line(["Wszyscy w widoku", doc["participants"]])
    line(["Odsetek wypełnienia", (doc["filled"] / doc["participants"]) if doc["participants"] else 0], ["0%"])
    for k, v in doc["payment"]:
        line([k, v])
    for f in doc["charts"].get("funnels") or []:
        totals.append([])
        section(f["title"], "Osoby", "Kwota")
        amt = bool(f.get("amount"))
        line(["Otrzymano", f["confirmed"], f.get("confirmed_total") if amt else None], [None, money_fmt])
        line(["Zgłoszone, czeka na potwierdzenie", f["declared"], f["declared"] * float(f["amount"]) if amt else None], [None, money_fmt])
        line(["Bez wpłaty", f["none"], None])
        if amt:
            line(["Oczekiwane razem", round(float(f.get("expected_total") or 0) / float(f["amount"])), f.get("expected_total")], [None, money_fmt])
            totals.cell(row=totals.max_row, column=1).font = Font(bold=True)
        totals.cell(row=totals.max_row - (3 if amt else 2), column=1).font = Font(bold=True, color=tone_ink["positive"])
    for n in doc["charts"].get("numbers") or []:
        totals.append([])
        section(n["title"], "Wartość")
        line(["Suma", n.get("sum")])
        line(["Średnio", round(float(n["avg"]), 2) if n.get("avg") is not None else None], ["0.0"])
        line(["Odpowiedzi", n.get("count")])
    if layout == "report":
        for d in doc["charts"].get("dists") or []:
            totals.append([])
            first = section(d["title"], "Liczba", "Udział")
            total = sum(int(it["count"]) for it in d["items"]) or 1
            for it in d["items"]:
                line([it["label"], int(it["count"]), int(it["count"]) / total], [None, "0%"])
            last = totals.max_row
            if last > first:
                chart = BarChart()
                chart.type = "bar"
                chart.style = 10
                chart.title = d["title"][:60]
                chart.legend = None
                chart.height = 3.6 + 0.62 * (last - first)
                chart.width = 13
                chart.y_axis.majorGridlines = None
                chart.y_axis.delete = True
                chart.x_axis.scaling.orientation = "maxMin"
                chart.add_data(Reference(totals, min_col=2, min_row=first, max_row=last), titles_from_data=True)
                chart.set_categories(Reference(totals, min_col=1, min_row=first + 1, max_row=last))
                chart.series[0].graphicalProperties.solidFill = accent
                chart.series[0].graphicalProperties.line.solidFill = accent
                chart.gapWidth = 60
                totals.add_chart(chart, f"E{first}")
    totals.column_dimensions["A"].width = 40
    totals.column_dimensions["B"].width = 14
    totals.column_dimensions["C"].width = 14
    buffer = io.BytesIO()
    book.save(buffer)
    return buffer.getvalue()


def luminance_ok(hex_: str) -> bool:
    """Biały napis na tej barwie jest czytelny (kontrast co najmniej 3:1)."""
    from app.exam_print_theme import contrast

    return contrast(hex_, "#FFFFFF") >= 3.0


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
