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


def svg_ring(th: Mapping[str, Any], share: float, size: int = 120, label: str = "") -> str:
    r = size / 2 - 10
    c = 2 * 3.14159265 * r
    on = max(0.0, min(1.0, share)) * c
    pct = round(share * 100)
    cx = size / 2
    arc = (f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="{th["accent"]}" stroke-width="13" stroke-linecap="round" '
           f'stroke-dasharray="{on:.1f} {c:.1f}" transform="rotate(-90 {cx} {cx})"/>') if on > 0.5 else ""
    return (
        f'<svg class="ring" width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        f'<circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="{th["track"]}" stroke-width="13"/>{arc}'
        f'<text x="{cx}" y="{cx}" text-anchor="middle" dy="0.12em" font-size="{size * 0.25:.0f}" font-weight="800" letter-spacing="-1" fill="{th["ink"]}">{pct}%</text>'
        f'<text x="{cx}" y="{cx}" text-anchor="middle" dy="1.75em" font-size="{size * 0.085:.0f}" fill="{th["soft"]}">{esc(label)}</text>'
        "</svg>"
    )


def html_bars(th: Mapping[str, Any], items: Sequence[Mapping[str, Any]]) -> str:
    """Rozkład odpowiedzi: etykieta i liczba nad cienkim torem (jak słupki raportu sezonu Beach)."""
    total = sum(int(i["count"]) for i in items)
    out = ['<div class="bars">']
    for it in items:
        n = int(it["count"])
        width = max(1.6, 100 * n / total) if total and n else 0
        color = tone_color(th, it.get("tone", ""))
        muted = " muted" if it.get("tone") == "empty" else ""
        fill = f'<div class="bf" style="width:{width:.1f}%;background:{color}"></div>' if width else ""
        out.append(
            f'<div class="bar{muted}"><div class="bh"><span class="bv"><b>{n}</b> {_pct_text(n, total)}</span>'
            f'<span class="bl">{esc(_s(it["label"])[:48])}</span></div><div class="bt">{fill}</div></div>'
        )
    out.append("</div>")
    return "".join(out)


def html_money(th: Mapping[str, Any], f: Mapping[str, Any]) -> str:
    """Wpłaty: jeden tor podzielony na otrzymane / zgłoszone / brak, kwota-bohater nad nim."""
    confirmed, declared, none = int(f["confirmed"]), int(f["declared"]), int(f["none"])
    base = confirmed + declared + none
    has_amount = bool(f.get("amount"))
    seg = []
    for n, color in ((confirmed, th["pass"]), (declared, th["warn"])):
        if base and n:
            seg.append(f'<div class="ms" style="width:{100 * n / base:.2f}%;background:{color}"></div>')
    amount = float(f["amount"]) if has_amount else 0.0
    if has_amount:
        missing = max(0.0, float(f.get("expected_total") or 0) - float(f.get("confirmed_total") or 0))
        rest = f" · do zebrania {_money(missing)}" if missing else " · komplet"
        hero = (f'<div class="mhero"><b>{esc(_money(f.get("confirmed_total")))}</b>'
                f'<span>z {esc(_money(f.get("expected_total")))} oczekiwanych{esc(rest)}</span></div>')
    else:
        hero = f'<div class="mhero"><b>{confirmed} z {base}</b><span>potwierdzonych wpłat</span></div>'
    legend = [
        (th["pass"], "Otrzymano", confirmed, f.get("confirmed_total")),
        (th["warn"], "Zgłoszone, czeka na potwierdzenie", declared, declared * amount),
        (th["line"], "Bez wpłaty", none, None),
    ]
    rows = "".join(
        f'<div class="ml"><span class="mv">{n} os.'
        f'{(" · " + esc(_money(money))) if has_amount and money is not None and n else ""}</span>'
        f'<i style="background:{color}"></i>{esc(label)}</div>'
        for color, label, n, money in legend
    )
    return f'<div class="funnel">{hero}<div class="mt">{"".join(seg)}</div>{rows}</div>'


def svg_timeline(th: Mapping[str, Any], points: Sequence[Mapping[str, Any]], total: int, width: int = 640, height: int = 150) -> str:
    """Narastanie odpowiedzi: schodki dzień po dniu, linia „wszyscy" u góry, wartość na końcu."""
    if not points:
        return ""
    top = max(1, total, max(int(p["filled"]) for p in points))
    left, right, ceil, floor = 6, width - 46, 14, height - 22
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
        f'<text x="{right + 6}" y="{ys[-1] + 4:.1f}" font-size="12" font-weight="800" fill="{th["ink"]}">{int(points[-1]["filled"])}</text>'
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
    """`mode`: print (PDF) | file (HTML z wyszukiwarką) | public (strona z linku, przycięta do `level`)."""
    th = theme_for(theme, province_key, {"paper": theme_for("elegant", None, {})})
    dark = bool(th.get("dark"))
    interactive = mode in ("file", "public")
    printing = not interactive
    report = layout == "report"
    checklist = layout == "checklist" and printing
    show_table = not (mode == "public" and level == "stats")
    show_charts = report or (mode == "public" and level == "stats")
    cover_page = printing and report
    logo = brand_logo_uri(240)
    title_font = "Georgia, 'DejaVu Serif', serif" if th.get("serif") else "'DejaVu Sans', 'Segoe UI', system-ui, -apple-system, sans-serif"
    tint = mix(th["accent"], th["card"], 0.82 if dark else 0.9)
    zebra = mix(th["ink"], th["card"], 0.95 if dark else 0.975)
    participants, filled = int(doc["participants"]), int(doc["filled"])
    share = filled / participants if participants else 0.0
    header = list(doc["header"])
    table = doc["table"]
    tones = doc["tones"]
    names = doc["names"]
    wide = len(header) > 6
    page_w, page_h = (297, 210) if wide else (210, 297)
    cover_end = {"province": mix(th["cover"], "#000000", 0.16), "elegant": mix(th["cover"], th["gold"], 0.22),
                 "premium": mix(th["cover"], th["accent"], 0.16)}.get(theme, th["cover"])
    ink_c = th["cover_ink"] if th["cover_ink"].startswith("#") else "#FFFFFF"
    facts = doc_facts(doc)
    view_text = _view_text(doc)

    # ── liczba-bohater i fakty (okładka druku, nagłówek pliku) ──
    if participants:
        hero_num = f"{round(share * 100)}%"
        hero_cap = f"{filled} z {participants} " + ("odpowiedziało" if doc["kind"] == "list" else "wysłało odpowiedź")
    else:
        hero_num = "0"
        hero_cap = "W tym widoku nie ma jeszcze nikogo"
    fact_html = "".join(f'<div class="f"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for v, k in facts)
    when_bits = []
    if doc.get("closes"):
        when_bits.append(f"zapisy do {_local_date(doc['closes'])}")
    stamp = ("Stan na " if mode == "public" else "Wygenerowano ") + doc["generated"]
    sub = " · ".join([x for x in [doc["province"], *when_bits] if x])
    crest_img = f'<img class="crest" src="{crest}" alt="Herb okręgu"/>' if crest else ""
    logo_img = f'<img class="logo" src="{logo}" alt="BAZA"/>' if logo else ""
    lens_html = '<div class="lenses">' + "".join(f'<span class="lens">{esc(x)}</span>' for x in view_text) + "</div>"

    if cover_page:
        head = (
            f'<section class="cover"><div class="cstripes"></div>'
            f'<div class="ctop">{crest_img}{logo_img}</div>'
            f'<div class="ctitle"><h1>{esc(doc["title"])}</h1><div class="csub">{esc(sub)}</div></div>'
            f'<div class="chero"><div class="cnum">{esc(hero_num)}</div><div class="ccap">{esc(hero_cap)}</div>'
            f'<div class="crule"><div style="width:{max(0.0, min(1.0, share)) * 100:.1f}%"></div></div></div>'
            f'<div class="cfacts">{fact_html}</div>'
            f'<div class="cfoot"><span class="cview">Widok: {esc(" · ".join(view_text))}</span>'
            f'<span class="cstamp">{esc(stamp)} · BAZA</span></div></section>'
        )
    else:
        head = (
            f'<header class="mast"><div class="mstripes"></div><div class="mrow">'
            f'<div class="mid">{crest_img}<div class="mtext"><h1>{esc(doc["title"])}</h1><div class="msub">{esc(sub)}</div></div></div>'
            f'<div class="mlogo">{logo_img}</div></div>'
            f'<div class="mhero"><div class="mnum"><b>{esc(hero_num)}</b><span>{esc(hero_cap)}</span>'
            f'<div class="mrule"><div style="width:{max(0.0, min(1.0, share)) * 100:.1f}%"></div></div></div>'
            f'<div class="mfacts">{fact_html}</div></div></header>'
            f'<div class="viewline"><span class="vlabel">Widok</span>{lens_html}<span class="vstamp">{esc(stamp)}</span></div>'
        )

    # ── przelew ──
    pay = ""
    if doc["payment"] and mode != "public":
        cells = []
        for k, v in doc["payment"]:
            cls = " acct" if re.fullmatch(r"[\d ]{16,}", _s(v)) else ""
            cells.append(f'<div class="pc{cls}"><span>{esc(k)}</span><b>{esc(v)}</b></div>')
        pay = f'<section class="pay"><div class="ptitle">Dane do przelewu</div>{"".join(cells)}</section>'

    # ── wykresy ──
    charts_html = ""
    if show_charts:
        cards = [
            f'<div class="card ringcard"><h3>Wypełnienie</h3><div class="ringbox">{svg_ring(th, share, 132, "wypełnienia")}</div>'
            f'<div class="cap"><b>{filled}</b> z {participants} odpowiedziało'
            f'{f"<br/><b>{participants - filled}</b> bez odpowiedzi" if participants - filled > 0 else ""}</div></div>'
        ]
        for f in doc["charts"].get("funnels") or []:
            cards.append(f'<div class="card"><h3>{esc(f["title"])}</h3>{html_money(th, f)}</div>')
        for d in doc["charts"].get("dists") or []:
            cards.append(f'<div class="card"><h3>{esc(d["title"])}</h3>{html_bars(th, d["items"])}</div>')
        for n in doc["charts"].get("numbers") or []:
            avg = n.get("avg")
            cards.append(
                f'<div class="card numcard"><h3>{esc(n["title"])}</h3><div class="big">{esc(_num_text(n.get("sum")))}</div>'
                f'<div class="cap">razem z {int(n.get("count") or 0)} odpowiedzi'
                f'{f" · średnio {esc(_num_text(round(float(avg), 1)))}" if avg is not None else ""}</div></div>'
            )
        tl = svg_timeline(th, doc["timeline"], participants, *((1040, 200) if interactive else (560, 190)))
        if tl:
            cards.append(f'<div class="card tlcard"><h3>Narastanie odpowiedzi</h3>{tl}</div>')
        title = "Odpowiedzi w liczbach"
        charts_html = (f'<section class="charts{" newpage" if cover_page else ""}"><h2>{title}</h2>'
                       f'<div class="cards">{"".join(cards)}</div></section>')

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
                rows_html.append(
                    f'<tr class="grp"><td colspan="{span_all}">'
                    f'<span class="gdot" style="background:{tone_color(th, g.get("tone") or "neutral")}"></span>'
                    f'<b class="glabel">{esc(g["label"])}</b><span class="gcount">{size}</span>'
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
        if not table:
            bodies = [f'<tbody><tr><td class="empty" colspan="{span_all}"><b>Nikt nie pasuje do tego widoku</b>'
                      "Plik jest pusty, ale gotowy do uzupełnienia - zmień filtr w aplikacji albo wygeneruj cały formularz.</td></tr></tbody>"]
        search = ""
        if interactive and table:
            search = (f'<div class="search"><label class="sbox">{_SEARCH_ICON}<input id="q" type="search" '
                      f'placeholder="Szukaj w {len(table)} wierszach" autocomplete="off"/></label>'
                      f'<span class="found"><b id="count">{len(table)}</b> z {len(table)}</span></div>'
                      '<div class="nohit-msg">Nic nie pasuje do wpisanego tekstu.</div>')
        list_title = f'<h2 class="ltitle">Lista <span>{len(table)}</span></h2>' if report or interactive else ""
        table_html = (f'<section class="tablewrap{" newpage" if cover_page and not show_charts else ""}">{list_title}{search}'
                      f'<div class="tscroll"><table class="data"><thead><tr>{heads}</tr></thead>{"".join(bodies)}</table></div></section>')
        if checklist:
            table_html += (
                '<section class="sign">'
                f'<div class="sg"><div class="sline"><b>______</b> z {len(table)}</div><span>Obecnych na liście</span></div>'
                '<div class="sg"><div class="sline"></div><span>Sprawdził(a)</span></div>'
                '<div class="sg"><div class="sline"></div><span>Data i podpis</span></div></section>'
            )

    # ── stopka pliku (ekran) ──
    foot = ""
    if interactive:
        note = "Strona publiczna, dane na żywo." if mode == "public" else "Plik z wyszukiwarką: stuknij nagłówek kolumny, żeby sortować."
        foot = (f'<footer class="foot">{f"<img src={chr(34)}{logo}{chr(34)} alt=BAZA/>" if logo else ""}'
                f'<span>BAZA · Formularze okręgu · {esc(note)}</span></footer>')

    css = _css(th, theme=theme, mode=mode, interactive=interactive, checklist=checklist, cover_page=cover_page, wide=wide,
               page_w=page_w, page_h=page_h, title_font=title_font, tint=tint, zebra=zebra, cover_end=cover_end, ink_c=ink_c,
               foot_left=f"{doc['province']} · {doc['title'][:70]}")
    robots = '<meta name="robots" content="noindex,nofollow"/>' if mode == "public" else ""
    body = head + (pay if not cover_page else "") + charts_html + (pay if cover_page else "") + table_html + foot
    if cover_page and not show_charts and not show_table:
        body = head
    script = f"<script>{_JS}</script>" if interactive and show_table and table else ""
    return (f'<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"/>'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"/>{robots}'
            f'<title>{esc(doc["title"])}</title><style>{css}</style></head><body class="{mode} {layout}">{body}{script}</body></html>')


def _css(th: Mapping[str, Any], *, theme: str, mode: str, interactive: bool, checklist: bool, cover_page: bool, wide: bool,
         page_w: int, page_h: int, title_font: str, tint: str, zebra: str, cover_end: str, ink_c: str, foot_left: str) -> str:
    """Arkusz stylów. Druk: inline-block zamiast grid/flex w układzie (weasyprint), jednostki pt/mm."""
    dark = bool(th.get("dark"))
    px = interactive
    base = "14px" if px else ("8.4pt" if wide else "8.6pt")
    heavy = "800"
    track_c = _rgba(ink_c, 0.22)
    page = "A4 landscape" if wide else "A4"
    foot_txt = foot_left.replace('"', "'")
    row_pad = ("9px 10px" if px else ("6.2pt 5pt" if checklist else "4.4pt 5pt"))
    title_track = "-0.3pt" if th.get("serif") else "-0.9pt"
    return f"""
@page {{ size: {page}; margin: 13mm 12mm 15mm 12mm; background: {th['bg']};
  @bottom-left {{ content: "{esc(foot_txt)}"; font-size: 7pt; color: {th['soft']}; font-family: 'DejaVu Sans', sans-serif; }}
  @bottom-right {{ content: "Strona " counter(page) " z " counter(pages); font-size: 7pt; color: {th['soft']}; font-family: 'DejaVu Sans', sans-serif; }} }}
@page cover {{ margin: 0; background: {th['cover']}; @bottom-left {{ content: none; }} @bottom-right {{ content: none; }} }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ background: {th['bg']}; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
body {{ font-family: 'DejaVu Sans', 'Segoe UI', system-ui, -apple-system, sans-serif; color: {th['ink']}; background: {th['bg']};
  font-size: {base}; line-height: 1.38; {'max-width: 1120px; margin: 0 auto; padding: 20px 16px 48px;' if px else ''} }}
h1, h2, h3 {{ font-family: {title_font}; }}
b {{ font-weight: {heavy}; }}

/* ── okładka druku (raport) ── */
.cover {{ page: cover; position: relative; overflow: hidden; width: {page_w}mm; height: {page_h - 0.6}mm; page-break-after: always;
  color: {th['cover_ink']}; background: {th['cover']}; background: linear-gradient(155deg, {th['cover']} 0%, {th['cover']} 45%, {cover_end} 100%); }}
.cstripes {{ position: absolute; right: -46mm; top: -52mm; width: 150mm; height: 150mm; transform: rotate(28deg);
  background: repeating-linear-gradient(90deg, {th['band2']} 0, {th['band2']} 7mm, transparent 7mm, transparent 15mm); opacity: {0.2 if theme == 'province' else 0.16}; }}
.ctop {{ position: absolute; top: {16 if wide else 20}mm; left: 20mm; right: 20mm; height: 34mm; }}
.ctop .crest {{ height: {30 if wide else 34}mm; width: auto; float: left; }}
.ctop .logo {{ height: {17 if wide else 19}mm; width: auto; float: right; margin-top: 2mm; }}
.ctitle {{ position: absolute; left: 20mm; right: {110 if wide else 20}mm; top: {58 if wide else 74}mm; }}
.ctitle h1 {{ font-size: {32 if wide else 36}pt; font-weight: {heavy}; line-height: 1.04; letter-spacing: {title_track}; }}
.csub {{ margin-top: 4mm; font-size: 11pt; color: {th['cover_soft']}; }}
.chero {{ position: absolute; left: 20mm; {'right: 20mm; top: 118mm' if not wide else 'width: 120mm; top: 104mm'}; }}
.cnum {{ font-size: {96 if wide else 120}pt; font-weight: {heavy}; line-height: 0.9; letter-spacing: -5pt; }}
.ccap {{ margin-top: 3mm; font-size: 12pt; font-weight: 700; color: {th['cover_soft']}; }}
.crule {{ margin-top: 5mm; height: 2.2mm; border-radius: 1.1mm; background: {track_c}; {'width: 120mm;' if not wide else ''} overflow: hidden; }}
.crule div {{ height: 2.2mm; border-radius: 1.1mm; background: {th['cover_ink']}; }}
.cfacts {{ position: absolute; {'left: 20mm; right: 20mm; bottom: 42mm' if not wide else 'left: 158mm; right: 20mm; top: 104mm'}; font-size: 0; }}
.cfacts .f {{ display: inline-block; vertical-align: top; {'width: 25%; padding: 0 3mm 0 4mm; border-left: 0.8pt solid ' + track_c + ';' if not wide else 'width: 50%; padding: 0 3mm 7mm 4mm; border-left: 0.8pt solid ' + track_c + ';'} }}
.cfacts .f b {{ display: block; font-size: 21pt; font-weight: {heavy}; letter-spacing: -0.8pt; line-height: 1.1; }}
.cfacts .f span {{ display: block; font-size: 8pt; color: {th['cover_soft']}; margin-top: 1mm; }}
.cfoot {{ position: absolute; left: 20mm; right: 20mm; bottom: 16mm; padding-top: 4mm; border-top: 0.8pt solid {track_c};
  font-size: 8.4pt; color: {th['cover_soft']}; }}
.cfoot .cstamp {{ float: right; }}

/* ── nagłówek (lista do odhaczania i plik na ekranie) ── */
.mast {{ position: relative; overflow: hidden; color: {th['cover_ink']}; background: {th['cover']};
  background: linear-gradient(150deg, {th['cover']} 0%, {th['cover']} 50%, {cover_end} 100%);
  border-radius: {'22px' if px else '4mm'}; padding: {'26px 28px 24px' if px else '6mm 7mm 5.5mm'}; }}
.mstripes {{ position: absolute; right: {'-120px' if px else '-30mm'}; top: {'-170px' if px else '-50mm'}; width: {'420px' if px else '110mm'}; height: {'420px' if px else '110mm'};
  transform: rotate(28deg); background: repeating-linear-gradient(90deg, {th['band2']} 0, {th['band2']} {'22px' if px else '5mm'}, transparent {'22px' if px else '5mm'}, transparent {'46px' if px else '11mm'});
  opacity: {(0.12 if px else 0.2) if theme == 'province' else (0.09 if px else 0.15)}; }}
.mrow {{ position: relative; overflow: hidden; }}
.mid {{ float: left; width: 78%; }}
.mid .crest {{ float: left; height: {'64px' if px else '17mm'}; width: auto; margin-right: {'16px' if px else '4.5mm'}; }}
.mtext {{ overflow: hidden; }}
.mtext h1 {{ font-size: {'34px' if px else '20pt'}; font-weight: {heavy}; line-height: 1.06; letter-spacing: {title_track}; }}
.msub {{ margin-top: {'6px' if px else '1.5mm'}; color: {th['cover_soft']}; font-size: {'15px' if px else '9pt'}; }}
.mlogo {{ float: right; text-align: right; }}
.mlogo .logo {{ height: {'48px' if px else '12mm'}; width: auto; }}
.mhero {{ position: relative; margin-top: {'24px' if px else '4.5mm'}; overflow: hidden; }}
.mnum {{ float: left; width: {'34%' if px else '30%'}; }}
.mnum b {{ display: block; font-size: {'64px' if px else '30pt'}; line-height: 0.95; letter-spacing: {'-3px' if px else '-1.4pt'}; }}
.mnum span {{ display: block; margin-top: {'6px' if px else '1.2mm'}; color: {th['cover_soft']}; font-size: {'14px' if px else '8.4pt'}; font-weight: 700; }}
.mrule {{ margin-top: {'10px' if px else '2mm'}; height: {'6px' if px else '1.6mm'}; border-radius: 4px; background: {track_c}; width: 88%; overflow: hidden; }}
.mrule div {{ height: 100%; border-radius: 4px; background: {th['cover_ink']}; }}
.mfacts {{ float: left; width: {'66%' if px else '70%'}; font-size: 0; padding-top: {'6px' if px else '1mm'}; }}
.mfacts .f {{ display: inline-block; vertical-align: top; width: 25%; padding: 0 {'10px' if px else '2.5mm'}; border-left: 1px solid {track_c}; }}
.mfacts .f b {{ display: block; font-size: {'26px' if px else '15pt'}; line-height: 1.1; letter-spacing: -0.6px; }}
.mfacts .f span {{ display: block; font-size: {'12.5px' if px else '7.4pt'}; color: {th['cover_soft']}; margin-top: 2px; }}
.viewline {{ margin: {'14px 2px 4px' if px else '3mm 0.5mm 1mm'}; overflow: hidden; font-size: {'13px' if px else '7.8pt'}; color: {th['soft']}; }}
.vlabel {{ float: left; font-weight: 700; color: {th['ink']}; margin: {'4px 8px 0 0' if px else '0.6mm 2mm 0 0'}; }}
.viewline .lenses {{ float: left; }}
.vstamp {{ float: right; margin-top: {'4px' if px else '0.6mm'}; }}
.lens {{ display: inline-block; margin: 0 4px 4px 0; font-size: 0.95em; border: 1px solid {th['line']}; background: {tint}; color: {th['ink']};
  border-radius: 99px; padding: {'3px 11px' if px else '0.5mm 2.6mm'}; }}

/* ── dane do przelewu ── */
.pay {{ margin: {'14px 0 4px' if px else '3.5mm 0 1mm'}; border: 1px dashed {th['line']}; border-radius: {'14px' if px else '3mm'};
  padding: {'12px 16px' if px else '2.6mm 4mm'}; background: {th['card']}; font-size: 0; page-break-inside: avoid; }}
.ptitle {{ font-size: {'13px' if px else '8pt'}; font-weight: {heavy}; color: {th['accent']}; margin-bottom: {'6px' if px else '1.2mm'}; }}
.pc {{ display: inline-block; vertical-align: top; margin-right: {'26px' if px else '7mm'}; margin-bottom: 2px; }}
.pc span {{ display: block; font-size: {'11.5px' if px else '6.8pt'}; color: {th['soft']}; }}
.pc b {{ display: block; font-size: {'14px' if px else '8.6pt'}; }}
.pc.acct b {{ font-family: 'DejaVu Sans Mono', Consolas, monospace; letter-spacing: 0.4px; }}

/* ── wykresy ── */
.newpage {{ page-break-before: always; }}
h2 {{ font-size: {'22px' if px else '15pt'}; font-weight: {heavy}; letter-spacing: {'-0.5px' if px else '-0.4pt'}; margin: {'26px 0 12px' if px else '5mm 0 3mm'}; }}
.charts.newpage h2 {{ margin-top: 0; }}
.cards {{ font-size: 0; orphans: 1; widows: 1; }}  /* rząd kart to linia - domyślne widows: 2 spychało dwa rzędy naraz */
.card {{ display: inline-block; vertical-align: top; width: {'calc(50% - 7px)' if px else '48.8%'}; margin: 0 {'14px 14px 0' if px else '2.4% 3.2mm 0'};
  background: {th['card']}; border: 1px solid {th['line']}; border-radius: {'16px' if px else '3.2mm'}; padding: {'16px 18px' if px else '3.6mm 4.2mm'};
  font-size: {base}; page-break-inside: avoid; }}
.card:nth-child(2n) {{ margin-right: 0; }}
.card.full {{ display: block; width: 100%; margin-right: 0; }}
{'.card.tlcard, body.' + mode + ' .card.tlcard { display: block; width: 100%; margin-right: 0; }' if px else ''}
.card h3 {{ font-size: {'16px' if px else '10.5pt'}; font-weight: {heavy}; margin-bottom: {'12px' if px else '2.6mm'}; letter-spacing: -0.2px; }}
.ringcard .ringbox {{ float: left; margin-right: {'16px' if px else '4mm'}; }}
.ringcard .cap {{ padding-top: {'34px' if px else '8mm'}; font-size: {'14px' if px else '9pt'}; color: {th['soft']}; line-height: 1.6; }}
.ringcard .cap b {{ color: {th['ink']}; font-size: 1.25em; }}
.ringcard:after {{ content: ""; display: block; clear: both; }}
.numcard .big {{ font-size: {'40px' if px else '26pt'}; font-weight: {heavy}; color: {th['accent']}; letter-spacing: -1px; line-height: 1.05; }}
.cap {{ color: {th['soft']}; font-size: 0.92em; margin-top: 4px; }}
.bar {{ margin-bottom: {'10px' if px else '2.2mm'}; page-break-inside: avoid; }}
.bh {{ overflow: hidden; margin-bottom: {'4px' if px else '0.9mm'}; }}
.bl {{ display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; font-weight: 600; }}
.bv {{ float: right; margin-left: 8px; color: {th['soft']}; font-variant-numeric: tabular-nums; }}
.bv b {{ color: {th['ink']}; margin-right: 3px; }}
.bt {{ height: {'8px' if px else '2.1mm'}; border-radius: 99px; background: {th['track']}; overflow: hidden; }}
.bf {{ height: 100%; border-radius: 99px; }}
.bar.muted .bl {{ color: {th['soft']}; font-weight: 400; }}
.funnel .mhero b {{ display: block; font-size: {'34px' if px else '22pt'}; letter-spacing: -1px; line-height: 1.05; color: {th['pass']}; }}
.funnel .mhero span {{ color: {th['soft']}; }}
.funnel .mt {{ margin: {'12px 0 10px' if px else '2.6mm 0 2.4mm'}; height: {'12px' if px else '3mm'}; border-radius: 99px; background: {th['track']}; overflow: hidden; font-size: 0; }}
.funnel .ms {{ float: left; height: 100%; }}
.funnel .ml {{ overflow: hidden; padding: {'3px 0' if px else '0.7mm 0'}; border-top: 1px solid {th['line']}; }}
.funnel .ml i {{ display: inline-block; width: {'10px' if px else '2.4mm'}; height: {'10px' if px else '2.4mm'}; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }}
.funnel .mv {{ float: right; font-weight: 700; font-variant-numeric: tabular-nums; }}
svg {{ max-width: 100%; height: auto; display: block; }}
svg.timeline {{ width: 100%; }}

/* ── tabela ── */
.ltitle span {{ font-size: 0.6em; color: {th['soft']}; font-weight: 700; margin-left: 4px; letter-spacing: 0; }}
.tscroll {{ {'overflow-x: auto; border: 1px solid ' + th['line'] + '; border-radius: 16px; background: ' + th['card'] + ';' if px else ''} }}
table.data {{ width: 100%; border-collapse: collapse; background: {th['card']}; {'margin-top: 3mm;' if checklist else ''} }}
thead {{ display: table-header-group; }}
th {{ text-align: left; font-size: 0.86em; font-weight: {heavy}; color: {th['ink']}; padding: {'11px 10px' if px else '3.2pt 5pt 3.6pt'};
  border-bottom: {'2px' if px else '1.3pt'} solid {th['ink']}; white-space: nowrap;
  {'cursor: pointer; user-select: none; position: sticky; top: 0; z-index: 2; background: ' + th['card'] + ';' if px else ''} }}
th[data-dir=asc]::after {{ content: " ▲"; color: {th['accent']}; }} th[data-dir=desc]::after {{ content: " ▼"; color: {th['accent']}; }}
td {{ padding: {row_pad}; border-bottom: {'1px' if px else '0.5pt'} solid {th['line']}; vertical-align: middle; }}
tbody tr:nth-child(even) td {{ background: {zebra}; }}
tr {{ page-break-inside: avoid; }}
td.lp, th.lp {{ width: {'34px' if px else '7mm'}; color: {th['soft']}; font-variant-numeric: tabular-nums; }}
td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
td.when {{ color: {th['soft']}; white-space: nowrap; font-size: 0.92em; font-variant-numeric: tabular-nums; }}
td.name {{ font-weight: 700; white-space: nowrap; }}
td.txt {{ max-width: {'280px' if px else '60mm'}; }}
.pill {{ display: inline-block; border-radius: 99px; padding: {'2px 10px 2px 8px' if px else '0.3mm 2.4mm 0.3mm 1.8mm'}; font-weight: 700; font-size: 0.9em; white-space: nowrap; }}
.pill i {{ display: inline-block; width: {'7px' if px else '1.5mm'}; height: {'7px' if px else '1.5mm'}; border-radius: 50%; margin-right: {'6px' if px else '1.3mm'}; vertical-align: 1px; }}
tr.grp td {{ background: {tint} !important; padding: {'12px 10px 10px' if px else '4.6pt 5pt 4pt'}; border-bottom: 1px solid {th['line']}; border-top: {'10px' if px else '2.4mm'} solid {th['card']}; }}
tbody:first-of-type tr.grp td {{ border-top: 0; }}
tr.grp {{ page-break-after: avoid; }}
.gdot {{ display: inline-block; width: {'11px' if px else '2.6mm'}; height: {'11px' if px else '2.6mm'}; border-radius: 50%; margin-right: {'8px' if px else '2mm'}; vertical-align: -1px; }}
.glabel {{ font-size: 1.12em; }}
.gcount {{ display: inline-block; margin-left: 7px; padding: 0 7px; border-radius: 99px; background: {th['card']}; color: {th['accent']}; font-weight: {heavy}; font-size: 0.9em; }}
.gaggs {{ float: right; color: {th['soft']}; font-size: 0.9em; }}
.agg {{ margin-left: 12px; }}
th.tick, td.tick {{ width: {'34px' if px else '8mm'}; text-align: center; }}
.box {{ display: inline-block; width: 4.2mm; height: 4.2mm; border: 1.1pt solid {th['ink']}; border-radius: 1mm; background: {th['card']}; vertical-align: middle; }}
td.empty {{ text-align: center; color: {th['soft']}; padding: {'48px 20px' if px else '14mm 6mm'}; background: {th['card']} !important; }}
td.empty b {{ display: block; color: {th['ink']}; font-size: 1.3em; margin-bottom: 6px; }}
.sign {{ margin-top: 10mm; font-size: 0; page-break-inside: avoid; }}
.sg {{ display: inline-block; vertical-align: bottom; width: 30%; margin-right: 5%; font-size: 8pt; color: {th['soft']}; }}
.sg:last-child {{ margin-right: 0; }}
.sline {{ height: 9mm; border-bottom: 0.9pt solid {th['ink']}; margin-bottom: 1.4mm; color: {th['ink']}; font-size: 10pt; padding-top: 3mm; }}
.sline b {{ color: {th['line']}; letter-spacing: 1px; }}

/* ── ekran: plik z wyszukiwarką i strona publiczna ── */
.search {{ position: sticky; top: 0; z-index: 5; display: flex; align-items: center; gap: 12px; padding: 10px 0 12px; background: {th['bg']}; }}
.sbox {{ flex: 1; position: relative; display: block; }}
.sicon {{ position: absolute; left: 14px; top: 50%; margin-top: -9px; color: {th['soft']}; }}
.search input {{ width: 100%; font-size: 16px; padding: 13px 16px 13px 44px; border-radius: 99px; border: 1.5px solid {th['line']};
  background: {th['card']}; color: {th['ink']}; outline: none; font-family: inherit; }}
.search input:focus {{ border-color: {th['accent']}; }}
.found {{ font-size: 13px; color: {th['soft']}; white-space: nowrap; }}
.found b {{ color: {th['ink']}; font-size: 16px; }}
.nohit-msg {{ display: none; text-align: center; color: {th['soft']}; padding: 30px 0; }}
body.nohit .nohit-msg {{ display: block; }}
body.nohit .tscroll {{ display: none; }}
.foot {{ margin-top: 36px; padding-top: 16px; border-top: 1px solid {th['line']}; font-size: 12.5px; color: {th['soft']}; text-align: center; }}
.foot img {{ height: 28px; width: auto; display: block; margin: 0 auto 8px; opacity: {0.9 if dark else 1}; }}
@media (min-width: 900px) {{ body.{mode} .card {{ width: calc(33.33% - 10px); }} body.{mode} .card:nth-child(2n) {{ margin-right: 14px; }}
  body.{mode} .card:nth-child(3n) {{ margin-right: 0; }} }}
@media (max-width: 720px) {{
  body {{ padding: 12px 10px 40px; }}
  .mast {{ padding: 20px 18px 18px; border-radius: 18px; }}
  .mid {{ width: 100%; }} .mlogo {{ position: absolute; right: 0; top: 0; }} .mlogo .logo {{ height: 34px; }}
  .mid .crest {{ height: 44px; margin-right: 12px; }}
  .mtext h1 {{ font-size: 25px; padding-right: 30px; }} .msub {{ font-size: 13.5px; }}
  .mnum, .mfacts {{ float: none; width: 100%; }} .mnum b {{ font-size: 54px; }}
  .mfacts {{ margin-top: 16px; }} .mfacts .f {{ width: 50%; margin-bottom: 12px; }}
  .vstamp {{ float: none; display: block; clear: both; }}
  .card, body.{mode} .card {{ width: 100%; margin-right: 0; }}
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
