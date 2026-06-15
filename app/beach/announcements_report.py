"""
Beach Announcements Report — "Ogłoszenia" PDF generation.

Renders an HTML template with Jinja2 and converts to PDF via WeasyPrint,
mirroring the BAZA Beach disqualifications-report styling. The frontend sends a
prepared list of announcements (already filtered by audience), so this module
only lays them out and — when an announcement carries a link — generates a small
QR code on the backend that replaces the raw URL in the document.
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

router = APIRouter(tags=["Beach: Announcements Report"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "ogloszenia.html"
DOWNLOAD_DIR = "/tmp/announcements_report_downloads"

_PL_TRANS = str.maketrans("łŁżŻ", "lLzZ")

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


def _make_qr_b64(url: str) -> str:
    """Render a clean QR code for `url` and return it as base64 PNG (no prefix)."""
    url = (url or "").strip()
    if not url:
        return ""
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=1,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#1A2050", back_color="white")
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:  # pragma: no cover
        logger.warning(f"Could not generate QR code: {e}")
        return ""


# ──────────── Models ────────────

class AnnItem(BaseModel):
    text: str = ""
    author: str = ""
    date_label: str = ""
    audience_labels: List[str] = []
    button_label: str = ""
    button_url: str = ""


class AnnReportRequest(BaseModel):
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""
    tournament_id: Optional[int] = None
    category: str = ""
    generated_by: str = ""
    audience_label: str = ""  # e.g. "Wszyscy" / "Drużyny" / "Sędziowie"
    items: List[AnnItem] = []


# ──────────── Context ────────────

def _build_context(req: AnnReportRequest) -> Dict[str, Any]:
    accent = CATEGORY_COLORS.get(req.category, DEFAULT_ACCENT)
    logo_b64 = _load_logo_b64()

    def _fmt_item(it: AnnItem) -> Dict[str, Any]:
        url = (it.button_url or "").strip()
        label = (it.button_label or "").strip()
        return {
            "text": (it.text or "").strip(),
            "author": (it.author or "").strip(),
            "date_label": (it.date_label or "").strip(),
            "audience_labels": [s for s in (it.audience_labels or []) if s],
            "button_label": label or "Otwórz link",
            "button_url": url,
            "qr_b64": _make_qr_b64(url) if url else "",
        }

    items = [_fmt_item(it) for it in req.items]
    total = len(items)

    return {
        "tournament_name": req.tournament_name.strip() or "Turniej",
        "location": req.tournament_location.strip(),
        "date_range": req.tournament_dates.strip(),
        "accent": accent,
        "logo_b64": logo_b64,
        "items": items,
        "total": total,
        "audience_label": req.audience_label.strip(),
        "generated_at": _now_pl_str(),
        "generated_by": req.generated_by.strip(),
    }


# ──────────── Endpoints ────────────

@router.post(
    "/beach/report/announcements",
    summary="Generuj zestawienie ogłoszeń (PDF)",
)
async def generate_announcements_report(req: AnnReportRequest):
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
        html_path = os.path.join(tmp_dir, "ann.html")
        pdf_path = os.path.join(tmp_dir, "ann.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.tournament_name) or "ogloszenia"
        download_name = f"ogloszenia_{safe_name}.pdf"
        encoded_name = urllib.parse.quote(download_name)

        return {
            "success": True,
            "download_url": f"/beach/report/announcements/download/{token}?filename={encoded_name}",
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Announcements PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/report/announcements/download/{token}",
    summary="Pobierz wygenerowane zestawienie ogłoszeń (PDF)",
)
async def download_announcements_report(
    token: str,
    filename: str = Query("ogloszenia.pdf"),
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
