"""
Beach Disqualifications Report — "Dyskwalifikacje" PDF generation.

Renders an HTML template with Jinja2 and converts to PDF via WeasyPrint,
mirroring the BAZA Beach final-report styling. The frontend sends a fully
prepared list of disqualification items (already grouped/derived), so this
module only has to lay them out.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import shutil
import tempfile
import unicodedata
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach: Disqualifications Report"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "dyskwalifikacje.html"
DOWNLOAD_DIR = "/tmp/disq_report_downloads"

_PL_TRANS = str.maketrans("łŁżŻ", "lLzZ")

# Gender accent colors (mirror final report / ScheduleView)
GENDER_HEADER_COLORS = {"M": "#2BA8A0", "K": "#E85A78"}
GENDER_LABELS = {"M": "Mężczyźni", "K": "Kobiety"}
DISQ_ACCENT = "#E85A78"

CATEGORY_COLORS = {
    "Senior": "#E85A30",
    "Junior": "#3A7FBF",
    "Junior mł.": "#2BA8A0",
    "Kadet": "#7A5FC7",
}
DEFAULT_ACCENT = "#E85A30"


def _safe_filename_part(s: str, max_len: int = 40) -> str:
    s = s.translate(_PL_TRANS)
    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(c if c.isalnum() or c in " _-" else "_" for c in s)
    return s[:max_len]


def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _load_logo_b64() -> str:
    logo_path = TEMPLATE_DIR / "baza_beach_logo.png"
    if not logo_path.exists():
        return ""
    try:
        from PIL import Image as PILImage
        img = PILImage.open(logo_path)
        img.thumbnail((300, 300), PILImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:  # pragma: no cover
        logger.warning(f"Could not load logo: {e}")
        return ""


def _now_pl_str() -> str:
    if ZoneInfo is not None:
        try:
            return datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            pass
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S")


def _ban_pl(n: int) -> str:
    if n == 1:
        return "mecz"
    if 2 <= n <= 4:
        return "mecze"
    return "meczów"


# ──────────── Models ────────────

class DisqItem(BaseModel):
    player_name: str = ""
    team_name: str = ""
    jersey: int = 0
    companion_role: Optional[str] = None
    match_id: Optional[str] = None
    ban_matches: int = 0
    description: str = ""
    decided: bool = True
    gender: Optional[str] = None  # "M" | "K" | None
    banned_matches: List[str] = []


class DisqReportRequest(BaseModel):
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""
    tournament_id: Optional[int] = None
    category: str = ""
    generated_by: str = ""
    multi_gender: bool = False
    items: List[DisqItem] = []


# ──────────── Context ────────────

def _build_context(req: DisqReportRequest) -> Dict[str, Any]:
    accent = CATEGORY_COLORS.get(req.category, DEFAULT_ACCENT)
    logo_b64 = _load_logo_b64()

    def _fmt_item(it: DisqItem) -> Dict[str, Any]:
        if it.companion_role:
            suffix = f" [{it.companion_role}]"
        elif it.jersey:
            suffix = f" #{it.jersey}"
        else:
            suffix = ""
        if it.ban_matches > 0:
            ban_label = f"-{it.ban_matches} {_ban_pl(it.ban_matches)}"
        else:
            ban_label = "Tylko ostrzeżenie"
        return {
            "player_name": it.player_name,
            "name_suffix": suffix,
            "team_name": it.team_name,
            "match_id": it.match_id or "",
            "ban_matches": it.ban_matches,
            "ban_label": ban_label,
            "decided": it.decided,
            "description": it.description.strip(),
            "banned_matches": list(it.banned_matches or []),
        }

    # Group items by gender. Order: M, K, then "Inne" (unknown gender).
    groups: List[Dict[str, Any]] = []
    order = ["M", "K", None]
    buckets: Dict[Any, List[Dict[str, Any]]] = {"M": [], "K": [], None: []}
    for it in req.items:
        g = it.gender if it.gender in ("M", "K") else None
        buckets[g].append(_fmt_item(it))

    for g in order:
        bucket = buckets.get(g) or []
        if not bucket:
            continue
        # Pending first, then by team name
        bucket.sort(key=lambda x: (x["decided"], x["team_name"].lower(), x["player_name"].lower()))
        groups.append({
            "gender": g or "X",
            "gender_label": GENDER_LABELS.get(g, "Pozostałe") if g else "Pozostałe",
            "gender_color": GENDER_HEADER_COLORS.get(g, accent) if g else accent,
            "items": bucket,
            "count": len(bucket),
        })

    total = len(req.items)
    pending_total = sum(1 for it in req.items if not it.decided)

    return {
        "tournament_name": req.tournament_name.strip() or "Turniej",
        "location": req.tournament_location.strip(),
        "date_range": req.tournament_dates.strip(),
        "accent": accent,
        "logo_b64": logo_b64,
        "groups": groups,
        "multi_gender": req.multi_gender and len(groups) > 1,
        "total": total,
        "pending_total": pending_total,
        "generated_at": _now_pl_str(),
        "generated_by": req.generated_by.strip(),
    }


# ──────────── Endpoints ────────────

@router.post(
    "/beach/report/disqualifications",
    summary="Generuj zestawienie dyskwalifikacji (PDF)",
)
async def generate_disqualifications_report(req: DisqReportRequest):
    from jinja2 import Environment, FileSystemLoader
    import weasyprint

    template_path = TEMPLATE_DIR / TEMPLATE_NAME
    if not template_path.exists():
        raise HTTPException(500, detail=f"Brak szablonu: {TEMPLATE_NAME}")

    ctx = _build_context(req)

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template(TEMPLATE_NAME)
    html_str = template.render(**ctx)

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "disq.html")
        pdf_path = os.path.join(tmp_dir, "disq.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.tournament_name) or "dyskwalifikacje"
        download_name = f"dyskwalifikacje_{safe_name}.pdf"
        encoded_name = urllib.parse.quote(download_name)

        return {
            "success": True,
            "download_url": f"/beach/report/disqualifications/download/{token}?filename={encoded_name}",
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Disqualifications PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/report/disqualifications/download/{token}",
    summary="Pobierz wygenerowane zestawienie dyskwalifikacji (PDF)",
)
async def download_disqualifications_report(
    token: str,
    filename: str = Query("dyskwalifikacje.pdf"),
):
    _ensure_download_dir()
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
