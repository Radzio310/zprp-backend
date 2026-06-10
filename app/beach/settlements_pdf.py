from __future__ import annotations

import base64
import io
import os
import re
import shutil
import tempfile
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

router = APIRouter(tags=["Beach: Settlements PDF"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
ACCENT = "#7b2d8e"


def _load_logo_b64() -> str:
    candidates = [
        TEMPLATE_DIR / "baza_beach_logo.png",
        TEMPLATE_DIR / "baza_beach.png",
        Path(__file__).resolve().parent.parent.parent / "baza_beach.png",
    ]
    logo_path = next((p for p in candidates if p.exists()), None)
    if not logo_path:
        return ""
    try:
        from PIL import Image as PILImage
        img = PILImage.open(logo_path)
        img.thumbnail((300, 300), PILImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        try:
            return base64.b64encode(logo_path.read_bytes()).decode()
        except Exception:
            return ""
TEMPLATE_NAME = "rozliczenia_sedziow.html"
DOWNLOAD_DIR = "/tmp/beach_settlements_downloads"


class SettlementTournament(BaseModel):
    id: Optional[int] = None
    name: str = ""
    date_from: str = ""
    date_to: Optional[str] = None
    location: str = ""
    category: str = ""
    competition_type: str = ""


class SettlementPdfRequest(BaseModel):
    mode: str = "single"
    tournament: SettlementTournament
    judges: List[Dict[str, Any]]


def _ensure_download_dir() -> None:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _money(value: Any) -> str:
    try:
        n = round(float(value or 0))
    except Exception:
        n = 0
    return f"{n:,.0f}".replace(",", " ") + " zł"


def _money_n(value: Any) -> str:
    """Number only, no currency unit."""
    try:
        n = round(float(value or 0))
    except Exception:
        n = 0
    return f"{n:,.0f}".replace(",", " ")


def _km(value: Any) -> str:
    try:
        n = float(value or 0)
    except Exception:
        n = 0
    return f"{n:.1f}".replace(".", ",") + " km"


def _km_n(value: Any) -> str:
    """Number only, no km unit."""
    try:
        n = float(value or 0)
    except Exception:
        n = 0
    return f"{n:.1f}".replace(".", ",")


def _bank_account(value: Any) -> str:
    digits = re.sub(r"\D", "", str(value or ""))[:26]
    if not digits:
        return ""
    parts = [digits[:2]]
    parts.extend(digits[i : i + 4] for i in range(2, len(digits), 4))
    return " ".join(part for part in parts if part)


def _safe_filename_part(s: str, max_len: int = 44) -> str:
    import unicodedata

    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(c if c.isalnum() or c in " _-" else "_" for c in s)
    return (s.strip() or "rozliczenie")[:max_len]


def _build_context(req: SettlementPdfRequest) -> Dict[str, Any]:
    judges = req.judges or []
    summary = {
        "travel": sum((j.get("result") or {}).get("travel", 0) for j in judges),
        "brutto": sum((j.get("result") or {}).get("brutto", 0) for j in judges),
        "costs": sum((j.get("result") or {}).get("costs", 0) for j in judges),
        "tax": sum((j.get("result") or {}).get("tax", 0) for j in judges),
        "netto": sum((j.get("result") or {}).get("netto", 0) for j in judges),
        "total": sum((j.get("result") or {}).get("total", 0) for j in judges),
    }
    for j in judges:
        result = j.get("result") or {}
        j["result_fmt"] = {k: _money(result.get(k, 0)) for k in ("travel", "brutto", "costs", "tax", "netto", "total")}
        j["result_fmt_n"] = {k: _money_n(result.get(k, 0)) for k in ("travel", "brutto", "costs", "tax", "netto", "total")}
        j["distance_fmt"] = _km(j.get("distance_km", 0))
        j["distance_fmt_n"] = _km_n(j.get("distance_km", 0))
        j["bank_account_fmt"] = _bank_account(j.get("bank_account"))
        for day in j.get("days") or []:
            day["brutto_fmt"] = _money(day.get("brutto", 0))
    return {
        "mode": req.mode,
        "is_bulk": req.mode == "bulk",
        "tournament": req.tournament.model_dump(),
        "judges": judges,
        "summary": {k: _money(v) for k, v in summary.items()},
        "generated_at": datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M"),
        "accent": ACCENT,
        "logo_b64": _load_logo_b64(),
        "disclaimer": (
            "Wyliczenia zostały przygotowane automatycznie przez aplikację BAZA Beach na podstawie "
            "wprowadzonych danych i obowiązujących w aplikacji tabel pomocniczych. Dokument ma "
            "charakter informacyjny i nie stanowi samodzielnej podstawy prawnej do wypłaty "
            "wynagrodzenia ani rozstrzygania sporów rozliczeniowych."
        ),
    }


@router.post("/beach/settlements/pdf", summary="Generuj PDF rozliczen sedziowskich")
async def generate_settlements_pdf(req: SettlementPdfRequest):
    from jinja2 import Environment, FileSystemLoader
    import weasyprint

    if not req.judges:
        raise HTTPException(422, "Brak sedziow do rozliczenia")
    template_path = TEMPLATE_DIR / TEMPLATE_NAME
    if not template_path.exists():
        raise HTTPException(500, detail=f"Brak szablonu: {TEMPLATE_NAME}")

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    env.filters["money"] = _money
    env.filters["km"] = _km
    template = env.get_template(TEMPLATE_NAME)
    html_str = template.render(**_build_context(req))

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "settlements.html")
        pdf_path = os.path.join(tmp_dir, "settlements.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.tournament.name)
        base = "rozliczenie_zbiorcze" if req.mode == "bulk" else "rachunek_sedziowski"
        encoded_name = urllib.parse.quote(f"{base}_{safe_name}.pdf")
        return {"success": True, "download_url": f"/beach/settlements/pdf/download/{token}?filename={encoded_name}"}
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(500, detail=str(e))


@router.get("/beach/settlements/pdf/download/{token}", summary="Pobierz PDF rozliczen sedziowskich")
async def download_settlements_pdf(token: str, filename: str = Query("rozliczenia_sedziowskie.pdf")):
    _ensure_download_dir()
    try:
        uuid.UUID(token)
    except ValueError:
        raise HTTPException(400, "Nieprawidlowy token")
    file_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
    if not os.path.exists(file_path):
        raise HTTPException(404, "Plik wygasl lub nie istnieje")
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename,
        background=BackgroundTask(lambda: os.remove(file_path) if os.path.exists(file_path) else None),
    )
