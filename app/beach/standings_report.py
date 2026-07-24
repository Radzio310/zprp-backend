"""
Beach Standings Report — "Raport miejsc" PDF generation.

Renders the current tournament classification (final places) split by gender.
Places already decided are filled with the team name; undecided places are left
blank. Top 3 are subtly highlighted with medal colors.

The frontend computes the classification (it owns the full place-resolution
logic for every play system) and sends a ready `sections` structure; this module
only styles it into a one-page PDF matching the other tournament documents.
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
from typing import List, Optional

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach: Standings Report"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "raport_miejsc.html"
DOWNLOAD_DIR = "/tmp/standings_report_downloads"

_PL_TRANS = str.maketrans("łŁżŻ", "lLzZ")

CATEGORY_COLORS = {
    "Senior": "#E85A30",
    "Junior": "#3A7FBF",
    "Junior mł.": "#2BA8A0",
    "Kadet": "#7A5FC7",
}
DEFAULT_ACCENT = "#E85A30"

# Kolory medali (spójne z podium na ekranie Wyników w aplikacji).
MEDAL_COLORS = {1: "#D4A843", 2: "#9BA4B5", 3: "#A0785A"}

# Akcenty płci — spójne z resztą aplikacji (kafelki drużyn, MVP itd.).
GENDER_COLORS = {"M": "#3ACCBF", "K": "#FF6482"}


class StandingsPlace(BaseModel):
    place: int
    team: Optional[str] = None
    # Dopisek dla nierozstrzygniętego miejsca, np. „Zwycięzca meczu M22".
    hint: Optional[str] = None


class StandingsSection(BaseModel):
    gender: str = ""
    label: str = ""
    places: List[StandingsPlace] = []


class StandingsReportRequest(BaseModel):
    tournament_name: str = ""
    category: str = ""
    tournament_dates: str = ""
    generated_by: str = ""
    sections: List[StandingsSection] = []


def _safe_filename_part(s: str, max_len: int = 40) -> str:
    s = s.translate(_PL_TRANS)
    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(c if c.isalnum() or c in " _-" else "_" for c in s)
    return s[:max_len]


def _ensure_download_dir() -> None:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _now_pl_str() -> str:
    if ZoneInfo is not None:
        try:
            return datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M")
        except Exception:
            pass
    return datetime.now().strftime("%d.%m.%Y %H:%M")


def _load_image_b64(path: Path, max_size: Optional[tuple[int, int]] = None) -> str:
    if not path.exists():
        return ""
    try:
        from PIL import Image as PILImage
        img = PILImage.open(path)
        if max_size:
            img.thumbnail(max_size, PILImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:  # pragma: no cover
        logger.warning("Could not load image %s: %s", path, e)
        try:
            return base64.b64encode(path.read_bytes()).decode()
        except Exception:
            return ""


def _load_logo_b64() -> str:
    candidates = [
        TEMPLATE_DIR / "baza_beach_logo.png",
        TEMPLATE_DIR / "baza_beach.png",
        Path(__file__).resolve().parent.parent.parent / "baza_beach.png",
    ]
    for path in candidates:
        if path.exists():
            return _load_image_b64(path, (300, 300))
    return ""


def _build_context(req: StandingsReportRequest) -> dict:
    accent = CATEGORY_COLORS.get(req.category, DEFAULT_ACCENT)
    sections = []
    for sec in req.sections:
        places = [
            {
                "place": p.place,
                "team": (p.team or "").strip() or None,
                "hint": (p.hint or "").strip() or None,
            }
            for p in sorted(sec.places, key=lambda x: x.place)
        ]
        if not places:
            continue
        sections.append({
            "gender": sec.gender,
            "label": sec.label.strip() or ("Mężczyźni" if sec.gender == "M" else "Kobiety"),
            "color": GENDER_COLORS.get(sec.gender, accent),
            "places": places,
        })

    return {
        "tournament_name": req.tournament_name.strip() or "Turniej",
        "category": req.category.strip(),
        "date_range": req.tournament_dates.strip(),
        "generated_by": req.generated_by.strip(),
        "generated_at": _now_pl_str(),
        "accent": accent,
        "medal_colors": MEDAL_COLORS,
        "logo_b64": _load_logo_b64(),
        "sections": sections,
    }


@router.post(
    "/beach/report/standings",
    summary="Generuj raport miejsc turnieju (PDF)",
)
async def generate_standings_report(req: StandingsReportRequest):
    from jinja2 import Environment, FileSystemLoader
    import weasyprint

    template_path = TEMPLATE_DIR / TEMPLATE_NAME
    if not template_path.exists():
        raise HTTPException(500, detail=f"Brak szablonu: {TEMPLATE_NAME}")

    ctx = _build_context(req)
    if not ctx["sections"]:
        raise HTTPException(400, detail="Brak drużyn do wygenerowania raportu miejsc.")

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template(TEMPLATE_NAME)
    html_str = template.render(**ctx)

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "standings.html")
        pdf_path = os.path.join(tmp_dir, "standings.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.tournament_name) or "raport_miejsc"
        download_name = f"raport_miejsc_{safe_name}.pdf"
        encoded_name = urllib.parse.quote(download_name)

        return {
            "success": True,
            "download_url": f"/beach/report/standings/download/{token}?filename={encoded_name}",
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Standings PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/report/standings/download/{token}",
    summary="Pobierz wygenerowany raport miejsc (PDF)",
)
async def download_standings_report(
    token: str,
    filename: str = Query("raport_miejsc.pdf"),
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
