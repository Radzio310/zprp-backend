"""
Formularze okręgowe - eksport (§14): xlsx (openpyxl), CSV (średnik, UTF-8 z BOM), PDF (WeasyPrint).

Pliki lądują w katalogu tymczasowym pod losowym tokenem i są do pobrania przez
`GET /district-forms/file/{token}` (otwarta ścieżka, jak `/province-events/pdf/{token}`)
przez 15 minut. Budowanie tabel jest czyste (bez bazy) i pod testem.
"""
from __future__ import annotations

import csv
import html
import io
import os
import re
import tempfile
import time
import uuid
from datetime import datetime
from typing import Any, List, Mapping, Optional, Sequence, Tuple

from app import district_form_schema as SC
from app import district_forms_rules as R

EXPORT_DIR = os.path.join(tempfile.gettempdir(), "district_form_exports")
FORMATS = ("xlsx", "csv", "pdf")
MEDIA = {
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "csv": "text/csv; charset=utf-8",
    "pdf": "application/pdf",
}
_TOKEN = re.compile(r"^[a-f0-9]{32}$")

#: Kolory statusów w arkuszu: zielony, czerwony, szary (i bursztyn dla „może").
TONE_FILL = {"positive": "C6F6D5", "negative": "FED7D7", "warning": "FEEBC8", "neutral": "E2E8F0"}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _local(moment: Any) -> str:
    stamp = R.aware(moment) if isinstance(moment, datetime) else None
    if stamp is None and moment:
        try:
            stamp = R.parse_iso(moment)
        except R.FormError:
            stamp = None
    return stamp.astimezone(R.WARSAW).strftime("%d.%m.%Y %H:%M") if stamp else ""


def _latest_source(cells: Mapping[str, Any]) -> str:
    best = ("", "")
    for cell in (cells or {}).values():
        if isinstance(cell, Mapping) and cell.get("src") in R.SOURCES and _s(cell.get("at")) >= best[0]:
            best = (_s(cell.get("at")), cell["src"])
    return R.SOURCE_LABELS.get(best[1], "")


# ---------------------------------------------------------------------------
# Tabele (czyste)
# ---------------------------------------------------------------------------


def list_table(
    columns: Sequence[Mapping[str, Any]],
    people: Sequence[Tuple[str, str]],
    entries: Mapping[str, Mapping[str, Any]],
) -> Tuple[List[str], List[List[str]], List[List[Optional[str]]]]:
    """(nagłówek, wiersze tekstu, tony komórek). `people`: [(judge_id, imię i nazwisko)]."""
    header = ["Lp.", "Sędzia", "Numer"] + [c["title"] for c in columns] + ["Źródło", "Zmiana"]
    rows: List[List[str]] = []
    tones: List[List[Optional[str]]] = []
    for index, (jid, name) in enumerate(people, start=1):
        entry = entries.get(jid) or {}
        cells = R.loads(entry.get("cells_json"), {})
        row = [str(index), name, jid]
        tone_row: List[Optional[str]] = [None, None, None]
        for column in columns:
            cell = cells.get(column["id"]) if isinstance(cells, Mapping) else None
            value = cell.get("v") if isinstance(cell, Mapping) else None
            row.append("" if not R.has_value(column, value) else R.value_label(column, value))
            tone = None
            if column.get("type") == "status":
                options = {o["id"]: o.get("tone") for o in column.get("options") or []}
                tone = options.get(value) or ("neutral" if value is None else None)
            elif column.get("type") == "confirm":
                tone = {"confirmed": "positive", "declared": "warning"}.get(value)
            tone_row.append(tone)
        row += [_latest_source(cells), _local(entry.get("updated_at"))]
        tone_row += [None, None]
        rows.append(row)
        tones.append(tone_row)
    return header, rows, tones


def form_table(
    schema: Mapping[str, Any],
    responses: Sequence[Mapping[str, Any]],
    *,
    with_person: bool,
) -> Tuple[List[str], List[List[str]]]:
    """Wiersz = odpowiedź, kolumna = pytanie (siatka rozkłada się na kolumnę na wiersz siatki)."""
    sections = SC.sections_of(schema)
    plan: List[Tuple[str, str, Optional[str]]] = [("Wysłano", "", None)]
    if with_person:
        plan.append(("Osoba", "", None))
    plan.append(("Źródło", "", None))
    for q in SC.questions(sections):
        if q.type == "grid":
            for r in q.rows:
                plan.append((f"{q.title} - {r.label}", q.id, r.id))
        else:
            plan.append((q.title, q.id, None))
    by_id = {q.id: q for q in SC.questions(sections)}
    rows: List[List[str]] = []
    for response in responses:
        answers = response.get("answers") or {}
        row: List[str] = []
        for title, qid, grid_row in plan:
            if title == "Wysłano":
                row.append(_local(response.get("submitted_at")))
            elif title == "Osoba" and not qid:
                row.append(_s(response.get("name")))
            elif title == "Źródło" and not qid:
                row.append(R.SOURCE_LABELS.get(_s(response.get("self_source")), ""))
            elif grid_row is not None:
                value = (answers.get(qid) or {}).get(grid_row) if isinstance(answers.get(qid), Mapping) else None
                q = by_id[qid]
                labels = {c.id: c.label for c in q.columns}
                row.append(", ".join(labels.get(x, "") for x in value) if isinstance(value, list) else labels.get(value, "") if value else "")
            else:
                row.append(SC.answer_text(by_id[qid], answers.get(qid)))
        rows.append(row)
    return [p[0] for p in plan], rows


def summary_rows(kind: str, stats: Mapping[str, Any], columns: Sequence[Mapping[str, Any]]) -> List[Tuple[str, str]]:
    """Arkusz „Podsumowanie": liczby, kwoty i procenty."""
    participants = int(stats.get("participants") or 0)
    filled = int(stats.get("filled") or 0)
    share = f"{round(100 * filled / participants)}%" if participants else "-"
    out: List[Tuple[str, str]] = [("Uczestnicy", str(participants)), ("Wypełnione", f"{filled} ({share})")]
    if kind != "list":
        return out
    by_id = {c["id"]: c for c in columns}
    for col in stats.get("columns") or []:
        column = by_id.get(col["id"]) or {}
        title = column.get("title") or col["id"]
        if col["type"] in ("status", "choice"):
            labels = {o["id"]: o["label"] for o in column.get("options") or []}
            for oid, count in (col.get("counts") or {}).items():
                out.append((f"{title}: {labels.get(oid, oid)}", str(count)))
            out.append((f"{title}: brak", str(col.get("none") or 0)))
        elif col["type"] == "check":
            out.append((f"{title}: tak", str(col.get("yes") or 0)))
        elif col["type"] == "confirm":
            out.append((f"{title}: zgłoszone", str(col.get("declared") or 0)))
            out.append((f"{title}: potwierdzone", str(col.get("confirmed") or 0)))
            if col.get("amount") is not None:
                out.append((f"{title}: oczekiwana kwota", f"{col.get('expected_total')} zł"))
                out.append((f"{title}: zgłoszone wpłaty", f"{col.get('declared_total')} zł"))
                out.append((f"{title}: potwierdzone wpłaty", f"{col.get('confirmed_total')} zł"))
        elif col["type"] == "number":
            out.append((f"{title}: suma", str(col.get("sum"))))
    return out


# ---------------------------------------------------------------------------
# Pliki
# ---------------------------------------------------------------------------


def to_csv(header: Sequence[str], rows: Sequence[Sequence[str]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(header)
    writer.writerows(rows)
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def to_xlsx(
    *,
    sheet_title: str,
    title: str,
    meta_line: str,
    header: Sequence[str],
    rows: Sequence[Sequence[str]],
    tones: Optional[Sequence[Sequence[Optional[str]]]],
    summary: Sequence[Tuple[str, str]],
) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    book = Workbook()
    sheet = book.active
    sheet.title = sheet_title
    sheet.append([title])
    sheet["A1"].font = Font(bold=True, size=14)
    sheet.append([meta_line])
    sheet.append([])
    sheet.append(list(header))
    for cell in sheet[4]:
        cell.font = Font(bold=True)
    for index, row in enumerate(rows):
        sheet.append(list(row))
        if tones:
            for col_index, tone in enumerate(tones[index]):
                if tone in TONE_FILL:
                    sheet.cell(row=5 + index, column=col_index + 1).fill = PatternFill("solid", fgColor=TONE_FILL[tone])
    sheet.freeze_panes = "A5"
    for col_index, name in enumerate(header, start=1):
        width = max([len(_s(name))] + [len(_s(r[col_index - 1])) for r in rows if len(r) >= col_index] + [6])
        sheet.column_dimensions[get_column_letter(col_index)].width = min(48, width + 2)
    totals = book.create_sheet("Podsumowanie")
    totals.append([title])
    totals["A1"].font = Font(bold=True, size=14)
    totals.append([])
    for label, value in summary:
        totals.append([label, value])
    totals.column_dimensions["A"].width = 42
    totals.column_dimensions["B"].width = 18
    buffer = io.BytesIO()
    book.save(buffer)
    return buffer.getvalue()


def pdf_html(
    *,
    title: str,
    province: str,
    meta_line: str,
    header: Sequence[str],
    rows: Sequence[Sequence[str]],
    summary: Sequence[Tuple[str, str]],
    printed_at: str,
) -> str:
    """Lista do druku: podsumowanie i kwoty na górze, tabela z polem do odhaczenia, stopka z datą."""
    esc = html.escape
    stats = "".join(f"<div class='stat'><b>{esc(value)}</b>{esc(label)}</div>" for label, value in summary[:8])
    head = "".join(f"<th>{esc(h)}</th>" for h in header) + "<th>✓</th>"
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(_s(v))}</td>" for v in row) + "<td class='tick'></td></tr>" for row in rows
    )
    return f"""<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><style>
@page {{ size: A4 landscape; margin: 14mm 12mm 16mm 12mm;
  @bottom-left {{ content: "Wydrukowano {esc(printed_at)}"; font-size: 7.5pt; color: #888; font-family: "DejaVu Sans", sans-serif; }}
  @bottom-right {{ content: "Strona " counter(page) " z " counter(pages); font-size: 7.5pt; color: #888; font-family: "DejaVu Sans", sans-serif; }} }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: "DejaVu Sans", "Noto Sans", sans-serif; font-size: 8.5pt; color: #1d1d1f; }}
.head {{ border-bottom: 2pt solid #c38e70; padding-bottom: 8pt; margin-bottom: 10pt; }}
.province {{ color: #8a5a44; font-size: 8pt; font-weight: bold; }}
h1 {{ font-size: 16pt; margin: 3pt 0 2pt; }}
.meta {{ color: #555; font-size: 8.5pt; }}
.stats {{ display: flex; flex-wrap: wrap; gap: 6pt; margin: 8pt 0 12pt; }}
.stat {{ border: 1pt solid #e6d5c6; border-radius: 6pt; padding: 5pt 8pt; }}
.stat b {{ font-size: 11pt; display: block; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ text-align: left; font-size: 7.5pt; color: #8a5a44; border-bottom: 1pt solid #c38e70; padding: 4pt 5pt; }}
td {{ padding: 5pt; border-bottom: .6pt solid #eee; vertical-align: middle; }}
td.tick {{ width: 22pt; border: .8pt solid #bbb; }}
</style></head><body>
<div class="head"><div class="province">{esc(province)}</div><h1>{esc(title)}</h1><div class="meta">{esc(meta_line)}</div></div>
<div class="stats">{stats}</div>
<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>
</body></html>"""


def safe_filename(title: str, ext: str) -> str:
    table = str.maketrans("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ", "acelnoszzACELNOSZZ")
    base = re.sub(r"[^A-Za-z0-9_-]+", "_", _s(title).translate(table)).strip("_")[:60] or "formularz"
    return f"{base}.{ext}"


def store(data: bytes, ext: str) -> str:
    os.makedirs(EXPORT_DIR, exist_ok=True)
    token = uuid.uuid4().hex
    with open(os.path.join(EXPORT_DIR, f"{token}.{ext}"), "wb") as handle:
        handle.write(data)
    return token


def find(token: str) -> Optional[Tuple[str, str]]:
    """(ścieżka, rozszerzenie) świeżego pliku albo None (nieznany albo starszy niż 15 minut)."""
    safe = _s(token).lower()
    if not _TOKEN.match(safe):
        return None
    for ext in FORMATS:
        path = os.path.join(EXPORT_DIR, f"{safe}.{ext}")
        if os.path.exists(path):
            if time.time() - os.path.getmtime(path) > R.EXPORT_TTL.total_seconds():
                return None
            return path, ext
    return None


def sweep_files(now: Optional[float] = None) -> int:
    moment = time.time() if now is None else now
    removed = 0
    try:
        names = os.listdir(EXPORT_DIR)
    except FileNotFoundError:
        return 0
    for name in names:
        path = os.path.join(EXPORT_DIR, name)
        try:
            if moment - os.path.getmtime(path) > R.EXPORT_TTL.total_seconds():
                os.remove(path)
                removed += 1
        except OSError:
            pass
    return removed


def render_pdf(markup: str) -> bytes:
    import weasyprint

    return weasyprint.HTML(string=markup).write_pdf()


def meta_line(form: Mapping[str, Any], generated: str) -> str:
    parts = []
    if form.get("closes_at"):
        parts.append(f"Termin: {_local(form.get('closes_at'))}")
    parts.append(f"Eksport: {generated}")
    return " · ".join(parts)


def build(
    fmt: str,
    *,
    form: Mapping[str, Any],
    province: str,
    header: Sequence[str],
    rows: Sequence[Sequence[str]],
    tones: Optional[Sequence[Sequence[Optional[str]]]],
    summary: Sequence[Tuple[str, str]],
    generated: str,
) -> bytes:
    if fmt == "csv":
        return to_csv(header, rows)
    line = meta_line(form, generated)
    if fmt == "xlsx":
        return to_xlsx(
            sheet_title="Lista" if form.get("kind") == "list" else "Odpowiedzi",
            title=form["title"],
            meta_line=line,
            header=header,
            rows=rows,
            tones=tones,
            summary=summary,
        )
    return render_pdf(pdf_html(title=form["title"], province=province, meta_line=line, header=header, rows=rows,
                               summary=summary, printed_at=generated))

