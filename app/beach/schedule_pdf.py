"""
Generuje PDF terminarza turnieju beach handball z szablonu HTML.

Używa Jinja2 + WeasyPrint (tak jak komunikat końcowy).
Automatycznie wybiera orientację:
  • pionową  (portrait)  — max. 20 meczów dziennie
  • poziomą  (landscape) — powyżej 20 meczów dziennie
"""
from __future__ import annotations

import base64
import io
import logging
import os
import shutil
import tempfile
import urllib.parse
import uuid
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Path as ApiPath, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from starlette.background import BackgroundTask

from app.db import database, beach_tournaments, beach_users

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach Schedule PDF"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "terminarz.html"
DOWNLOAD_DIR = "/tmp/schedule_pdf_downloads"

WEEKDAYS_PL = [
    "poniedziałek", "wtorek", "środa",
    "czwartek", "piątek", "sobota", "niedziela",
]
_ROMAN = {
    1: "I", 2: "II", 3: "III", 4: "IV", 5: "V",
    6: "VI", 7: "VII", 8: "VIII", 9: "IX", 10: "X",
}

CATEGORY_COLORS = {
    "Senior": "#E85A30",
    "Junior": "#3A7FBF",
    "Junior mł.": "#2BA8A0",
    "Kadet": "#7A5FC7",
}
DEFAULT_ACCENT = "#E85A30"

# Matches per day above which landscape is used
LANDSCAPE_THRESHOLD = 20


# ─── request model ────────────────────────────────────────────────────────────

class SchedulePdfRequest(BaseModel):
    schedule: Dict[str, Any]
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""  # optional override; computed from days if empty
    tournament_id: Optional[int] = None   # used to look up judge/host emails
    exclude_user_id: Optional[int] = None  # current user — excluded from recipients
    category: str = ""


# ─── helpers ──────────────────────────────────────────────────────────────────

def _roman(n: int) -> str:
    return _ROMAN.get(n, str(n))


def _day_header(day_index: int, date_str: Optional[str]) -> str:
    roman = _roman(day_index + 1)
    if date_str:
        try:
            d = date.fromisoformat(date_str)
            weekday = WEEKDAYS_PL[d.weekday()]
            formatted = d.strftime("%d.%m.%Y")
            return f"DZIEŃ {roman} | {formatted} ({weekday})"
        except Exception:
            pass
    return f"DZIEŃ {roman}"


def _compute_date_range(days: List[Dict[str, Any]]) -> str:
    dates = sorted(d.get("date", "") for d in days if d.get("date"))
    if not dates:
        return ""
    try:
        d0 = date.fromisoformat(dates[0])
        d1 = date.fromisoformat(dates[-1])
        if d0 == d1:
            return d0.strftime("%d.%m.%Y")
        return f"{d0.strftime('%d.%m.%Y')} \u2013 {d1.strftime('%d.%m.%Y')}"
    except Exception:
        return f"{dates[0]} \u2013 {dates[-1]}" if len(dates) > 1 else dates[0]


def _stage_label(m: Dict[str, Any]) -> str:
    stage = m.get("stage", "")
    group = m.get("group") or ""
    if stage == "group":
        return f"Grupa {group}" if group else "Każdy z każdym"
    return {
        "quarterfinal": "Ćwierćfinał",
        "semifinal": "Półfinał",
        "final": "Finał",
        "third_place": "3. miejsce",
        "fifth_place": "5. miejsce",
        "seventh_place": "7. miejsce",
        "fifth_semifinal": "Półfinał o 5.",
    }.get(stage, stage)


def _category_label(m: Dict[str, Any]) -> str:
    g = m.get("gender", "")
    return "M" if g == "M" else "K" if g == "K" else ""


def _team_name(team: Optional[Dict[str, Any]]) -> str:
    if team and team.get("name"):
        return str(team["name"])
    return ""


def _score_str(m: Dict[str, Any]) -> str:
    a, b = m.get("scoreA"), m.get("scoreB")
    if a is None or b is None:
        return ""
    base = f"{a}:{b}"
    sets = m.get("sets") or []
    if sets:
        parts = [
            f"{s.get('ptA', '')}:{s.get('ptB', '')}"
            for s in sets
            if isinstance(s, dict)
        ]
        if parts:
            return f"{base} ({', '.join(parts)})"
    return base


def _ensure_footer_row(ws, footer_row: int) -> None:
    """
    After row deletion the footer row may have lost its merge.
    Re-apply merge A:G and center alignment explicitly.
    """
    merge_str = f"A{footer_row}:G{footer_row}"
    # Remove any conflicting merge that covers this row
    for existing in list(ws.merged_cells.ranges):
        if existing.min_row == footer_row:
            ws.unmerge_cells(str(existing))
    ws.merge_cells(merge_str)
    ws[f"A{footer_row}"].alignment = Alignment(
        horizontal="center", vertical="center", wrapText=True
    )


def _patch_drawings_into_xlsx(saved_xlsx_path: str, template_path: str) -> None:
    """
    openpyxl strips all drawing/media files when it loads and re-saves a workbook.
    This function re-injects the drawing XML (both images) and media files from the
    original template into every sheet of the saved file via ZIP surgery.

    Both images in the template are anchored in the header rows (0-5, 0-indexed)
    so deleting match rows (row 10+) does not move the anchors.
    """
    DRAWING_REL_TYPE = (
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing"
    )
    DRAWING_CONTENT_TYPE = (
        "application/vnd.openxmlformats-officedocument.drawing+xml"
    )
    R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

    # ── read template drawing + media ──
    with zipfile.ZipFile(template_path, "r") as zt:
        tmpl_drawing_xml = zt.read("xl/drawings/drawing1.xml")
        tmpl_drawing_rels_xml = zt.read("xl/drawings/_rels/drawing1.xml.rels")
        media_files = {
            name: zt.read(name)
            for name in zt.namelist()
            if name.startswith("xl/media/")
        }

    # ── read all files from saved workbook ──
    with zipfile.ZipFile(saved_xlsx_path, "r") as zs:
        saved_files = {name: zs.read(name) for name in zs.namelist()}

    new_files = dict(saved_files)
    new_files.update(media_files)

    # ── find all sheet XMLs ──
    sheet_paths = sorted(
        name
        for name in saved_files
        if re.match(r"xl/worksheets/sheet\d+\.xml$", name)
    )

    new_drawing_part_names: List[str] = []

    for idx, sheet_path in enumerate(sheet_paths, start=1):
        drawing_xml_path = f"xl/drawings/drawing{idx}.xml"
        drawing_rels_path = f"xl/drawings/_rels/drawing{idx}.xml.rels"
        drawing_target = f"../drawings/drawing{idx}.xml"

        new_files[drawing_xml_path] = tmpl_drawing_xml
        new_files[drawing_rels_path] = tmpl_drawing_rels_xml
        new_drawing_part_names.append(f"/xl/drawings/drawing{idx}.xml")

        # ── patch sheet _rels: add drawing relationship ──
        rels_path = (
            sheet_path
            .replace("xl/worksheets/", "xl/worksheets/_rels/")
            .replace(".xml", ".xml.rels")
        )
        rels_xml = saved_files.get(rels_path, b"").decode("utf-8")
        if not rels_xml:
            rels_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                "</Relationships>"
            )

        # find a free rId (avoid collisions with printerSettings etc.)
        existing_rids = set(re.findall(r'Id="(rId\d+)"', rels_xml))
        rid_n = 1
        while f"rId{rid_n}" in existing_rids:
            rid_n += 1
        drawing_rid = f"rId{rid_n}"

        rels_xml = rels_xml.replace(
            "</Relationships>",
            f'<Relationship Id="{drawing_rid}" Type="{DRAWING_REL_TYPE}"'
            f' Target="{drawing_target}"/></Relationships>',
        )
        new_files[rels_path] = rels_xml.encode("utf-8")

        # ── patch sheet XML: add <drawing r:id="..."/> before </worksheet> ──
        sheet_xml = saved_files[sheet_path].decode("utf-8")
        if "<drawing" not in sheet_xml:
            # Ensure r: namespace is declared at root (openpyxl usually includes it)
            if 'xmlns:r=' not in sheet_xml:
                sheet_xml = sheet_xml.replace(
                    "<worksheet ",
                    f'<worksheet xmlns:r="{R_NS}" ',
                    1,
                )
            sheet_xml = sheet_xml.replace(
                "</worksheet>",
                f'<drawing r:id="{drawing_rid}"/></worksheet>',
            )
        new_files[sheet_path] = sheet_xml.encode("utf-8")

    # ── patch [Content_Types].xml ──
    ct_xml = saved_files["[Content_Types].xml"].decode("utf-8")
    if 'Extension="png"' not in ct_xml:
        ct_xml = ct_xml.replace(
            "</Types>",
            '<Default Extension="png" ContentType="image/png"/></Types>',
        )
    for part_name in new_drawing_part_names:
        if part_name not in ct_xml:
            ct_xml = ct_xml.replace(
                "</Types>",
                f'<Override PartName="{part_name}" ContentType="{DRAWING_CONTENT_TYPE}"/></Types>',
            )
    new_files["[Content_Types].xml"] = ct_xml.encode("utf-8")

    # ── write patched zip ──
    tmp_path = saved_xlsx_path + ".patched"
    with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name, data in new_files.items():
            zout.writestr(name, data)
    os.replace(tmp_path, saved_xlsx_path)


def _fill_header(
    ws, *, name: str, dates: str, location: str, day_hdr: str
) -> None:
    ws["C2"] = name
    ws["C4"] = dates
    ws["C5"] = location
    ws["E8"] = day_hdr


def _fill_match_row(ws, row: int, m: Dict[str, Any]) -> None:
    ws.cell(row=row, column=1).value = m.get("startTime") or ""   # A – Godzina
    ws.cell(row=row, column=2).value = m.get("court") or ""        # B – Boisko
    ws.cell(row=row, column=3).value = _category_label(m)          # C – Kategoria
    ws.cell(row=row, column=4).value = _stage_label(m)             # D – Etap/Grupa
    ws.cell(row=row, column=5).value = _team_name(m.get("teamA"))  # E – Drużyna A
    ws.cell(row=row, column=6).value = _team_name(m.get("teamB"))  # F – Drużyna B
    ws.cell(row=row, column=7).value = _score_str(m)               # G – Wynik


def _convert_xlsx_to_pdf(xlsx_path: str, out_dir: str) -> str:
    """Convert xlsx → pdf using LibreOffice. Returns the pdf path."""
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        raise RuntimeError(
            "Brak LibreOffice (soffice) w środowisku. Doinstaluj libreoffice w Dockerfile."
        )

    env = os.environ.copy()
    env.setdefault("HOME", "/tmp")
    env.setdefault("XDG_CACHE_HOME", "/tmp")
    env.setdefault("XDG_CONFIG_HOME", "/tmp")

    profile_dir = os.path.join(out_dir, "lo_profile")
    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        soffice,
        "--headless", "--nologo", "--nolockcheck",
        "--nodefault", "--norestore",
        f"-env:UserInstallation=file://{profile_dir}",
        "--convert-to", "pdf",
        "--outdir", out_dir,
        xlsx_path,
    ]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=90,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"LibreOffice convert failed (code={proc.returncode}). "
            f"stderr={proc.stderr[:500]}"
        )

    base = os.path.splitext(os.path.basename(xlsx_path))[0]
    pdf_path = os.path.join(out_dir, base + ".pdf")

    if not os.path.exists(pdf_path):
        pdfs = [p for p in os.listdir(out_dir) if p.lower().endswith(".pdf")]
        if len(pdfs) == 1:
            pdf_path = os.path.join(out_dir, pdfs[0])
        elif pdfs:
            cand = [p for p in pdfs if os.path.splitext(p)[0] == base]
            pdf_path = os.path.join(out_dir, (cand or pdfs)[0])
        else:
            raise RuntimeError("PDF nie znaleziony po konwersji LibreOffice.")

    return pdf_path


# ─── endpoint ─────────────────────────────────────────────────────────────────

def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


async def _get_judge_host_emails(
    tournament_id: int,
    exclude_user_id: Optional[int],
) -> List[str]:
    """Return emails of all judges + hosts for the tournament, excluding exclude_user_id."""
    try:
        row = await database.fetch_one(
            select(beach_tournaments.c.data_json).where(
                beach_tournaments.c.id == tournament_id
            )
        )
        if not row:
            return []
        data_json = row["data_json"]
        if isinstance(data_json, str):
            import json as _json
            data_json = _json.loads(data_json)
        if not isinstance(data_json, dict):
            return []

        host_ids = {
            int(h["id"])
            for h in (data_json.get("hosts") or [])
            if isinstance(h, dict) and h.get("id") is not None
        }
        judge_ids = {
            int(j["id"])
            for j in (data_json.get("judges") or [])
            if isinstance(j, dict) and j.get("id") is not None
        }
        head_judge_id = data_json.get("head_judge_id")
        if isinstance(head_judge_id, int):
            judge_ids.add(head_judge_id)

        all_ids = host_ids | judge_ids
        if exclude_user_id is not None:
            all_ids.discard(int(exclude_user_id))

        if not all_ids:
            return []

        rows = await database.fetch_all(
            select(beach_users.c.email).where(
                beach_users.c.id.in_(list(all_ids))
            )
        )
        return [r["email"] for r in rows if r["email"]]
    except Exception:
        logger.warning("Could not fetch judge/host emails for tournament %s", tournament_id, exc_info=True)
        return []


@router.post("/beach/schedule/pdf", summary="Generuj PDF terminarza turnieju")
async def generate_schedule_pdf(req: SchedulePdfRequest):
    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(500, detail=f"Brak szablonu terminarza: {TEMPLATE_PATH}")

    schedule = req.schedule
    matches: List[Dict[str, Any]] = schedule.get("matches") or []
    config: Dict[str, Any] = schedule.get("config") or {}
    days: List[Dict[str, Any]] = config.get("days") or []

    tournament_name = req.tournament_name.strip()
    date_range = req.tournament_dates.strip() or _compute_date_range(days)
    location = req.tournament_location.strip()

    # ── group matches by day, sort by time ──
    by_day: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for m in matches:
        by_day[int(m.get("dayIndex") or 0)].append(m)
    for idx in by_day:
        by_day[idx].sort(
            key=lambda m: (m.get("startTime") or "99:99", m.get("order") or 0)
        )

    day_indices = sorted(by_day.keys()) or [0]

    # ── load template ──
    wb = load_workbook(TEMPLATE_PATH)
    template_ws = wb.active

    # ── build (day_idx, chunk_idx, total_chunks, match_list) tuples ──
    all_chunks: List[tuple] = []
    for day_idx in day_indices:
        day_matches = by_day.get(day_idx, [])
        if day_matches:
            chunks = [
                day_matches[i: i + MAX_ROWS_PER_SHEET]
                for i in range(0, len(day_matches), MAX_ROWS_PER_SHEET)
            ]
        else:
            chunks = [[]]  # empty day still gets one sheet
        for ci, chunk in enumerate(chunks):
            all_chunks.append((day_idx, ci, len(chunks), chunk))

    # ── create sheets: reuse template_ws as first, copy for the rest ──
    created: List[tuple] = []  # (ws, day_idx, ci, total, chunk)
    for i, (day_idx, ci, total, chunk) in enumerate(all_chunks):
        ws = template_ws if i == 0 else wb.copy_worksheet(template_ws)
        created.append((ws, day_idx, ci, total, chunk))

    # ── fill sheets ──
    for ws, day_idx, ci, total, chunk in created:
        day_cfg = days[day_idx] if day_idx < len(days) else {}
        day_hdr = _day_header(day_idx, day_cfg.get("date"))
        if total > 1:
            day_hdr += f" cz. {ci + 1}"

        roman = _roman(day_idx + 1)
        ws.title = f"Dzień {roman}" + (f" ({ci + 1})" if total > 1 else "")

        _fill_header(
            ws,
            name=tournament_name,
            dates=date_range,
            location=location,
            day_hdr=day_hdr,
        )
        # repeat header rows on each printed page
        ws.print_title_rows = f"1:{FIRST_MATCH_ROW - 1}"

        for row_i, m in enumerate(chunk):
            _fill_match_row(ws, FIRST_MATCH_ROW + row_i, m)

        # Delete unused empty rows so footer moves up dynamically
        unused = TEMPLATE_MATCH_ROWS - len(chunk)
        if unused > 0:
            ws.delete_rows(FIRST_MATCH_ROW + len(chunk), unused)
            # Re-apply footer merge + centering (openpyxl may lose it after deletion)
            _ensure_footer_row(ws, FIRST_MATCH_ROW + len(chunk))

    # ── save xlsx and convert to pdf ──
    tmp_dir = tempfile.mkdtemp()
    try:
        xlsx_path = os.path.join(tmp_dir, "terminarz.xlsx")
        wb.save(xlsx_path)
        # Re-inject drawing + media (openpyxl strips them on load+save)
        _patch_drawings_into_xlsx(xlsx_path, TEMPLATE_PATH)
        pdf_path = _convert_xlsx_to_pdf(xlsx_path, tmp_dir)

        safe_name = (
            "".join(c if c.isalnum() or c in " _-" else "_" for c in tournament_name)[:40]
            or "terminarz"
        )
        download_name = f"terminarz_{safe_name}.pdf"

        # ── save to download dir with a one-time token ──
        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)  # clean working dir

        encoded_name = urllib.parse.quote(download_name)

        # ── fetch judge/host emails if tournament_id provided ──
        judge_host_emails: List[str] = []
        if req.tournament_id:
            judge_host_emails = await _get_judge_host_emails(
                req.tournament_id, req.exclude_user_id
            )

        return {
            "success": True,
            "download_url": f"/beach/schedule/pdf/download/{token}?filename={encoded_name}",
            "judge_host_emails": judge_host_emails,
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Schedule PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/tournament/{tournament_id}/judge-host-emails",
    summary="Adresy e-mail sędziów i gospodarzy turnieju",
)
async def get_tournament_judge_host_emails(
    tournament_id: int,
    exclude_user_id: Optional[int] = Query(None),
):
    emails = await _get_judge_host_emails(tournament_id, exclude_user_id)
    return {"emails": emails}


@router.get(
    "/beach/schedule/pdf/download/{token}",
    summary="Pobierz wygenerowany PDF terminarza (attachment)",
)
async def download_schedule_pdf(
    token: str = ApiPath(...),
    filename: str = Query("terminarz.pdf"),
):
    _ensure_download_dir()
    # Validate token is a UUID to prevent path traversal
    try:
        uuid.UUID(token)
    except ValueError:
        raise HTTPException(400, "Nieprawidłowy token")
    file_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
    if not os.path.exists(file_path):
        raise HTTPException(404, "Plik wygasł lub nie istnieje")
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename,
        background=BackgroundTask(
            lambda: os.remove(file_path) if os.path.exists(file_path) else None
        ),
    )
