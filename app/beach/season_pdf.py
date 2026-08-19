from __future__ import annotations

import base64
import io
import os
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

router = APIRouter(tags=["Beach: Season PDF"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "podsumowanie_sezonu.html"
DOWNLOAD_DIR = "/tmp/beach_season_downloads"

ACCENT = "#8A30D0"
ACCENT_2 = "#FF7A2F"


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


# ─────────────────────────── model wejsciowy ───────────────────────────


class SeasonTotals(BaseModel):
    judges: int = 0
    tournaments: int = 0
    tournaments_mp: int = 0
    tournaments_regional: int = 0
    assignments: int = 0
    days: int = 0
    hours: float = 0
    km: float = 0
    matches: int = 0
    sets: int = 0
    points: int = 0
    finals: int = 0
    cities: int = 0
    provinces: int = 0
    earnings_total: float = 0
    earnings_travel: float = 0
    earnings_netto: float = 0


class SeasonBar(BaseModel):
    label: str = ""
    value: float = 0
    display: str = ""
    color: Optional[str] = None


class SeasonRankingEntry(BaseModel):
    place: int = 0
    name: str = ""
    value: str = ""
    share: float = 0


class SeasonRankingBlock(BaseModel):
    key: str = ""
    label: str = ""
    unit: str = ""
    entries: List[SeasonRankingEntry] = []


class SeasonJudgeRow(BaseModel):
    place: int = 0
    name: str = ""
    judge_id: Optional[str] = None
    city: Optional[str] = None
    title: Optional[str] = None
    tournaments: int = 0
    mp: int = 0
    regional: int = 0
    days: int = 0
    hours: float = 0
    km: float = 0
    matches: int = 0
    sets: int = 0
    finals: int = 0
    earnings_total: float = 0
    earnings_travel: float = 0
    earnings_netto: float = 0


class SeasonPdfRequest(BaseModel):
    season: str = ""
    season_label: str = ""
    generated_by: str = ""
    totals: SeasonTotals = SeasonTotals()
    categories: List[SeasonBar] = []
    months: List[SeasonBar] = []
    cities: List[SeasonBar] = []
    rankings: List[SeasonRankingBlock] = []
    judges: List[SeasonJudgeRow] = []


# ─────────────────────────── formatery ───────────────────────────


def _int(value: Any) -> str:
    try:
        n = round(float(value or 0))
    except Exception:
        n = 0
    return f"{n:,.0f}".replace(",", " ")


def _money(value: Any) -> str:
    return _int(value) + " zł"


def _km(value: Any) -> str:
    try:
        n = float(value or 0)
    except Exception:
        n = 0
    return f"{n:,.0f}".replace(",", " ") + " km"


def _hours(value: Any) -> str:
    try:
        n = float(value or 0)
    except Exception:
        n = 0
    return f"{n:.1f}".replace(".", ",") + " h"


def _dec1(value: Any) -> str:
    try:
        n = float(value or 0)
    except Exception:
        n = 0
    return f"{n:.1f}".replace(".", ",")


def _safe_filename_part(s: str, max_len: int = 44) -> str:
    import unicodedata

    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(c if c.isalnum() or c in " _-" else "_" for c in s)
    return (s.strip() or "sezon")[:max_len]


def _ensure_download_dir() -> None:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _normalize_bars(bars: List[SeasonBar]) -> List[Dict[str, Any]]:
    """Dokłada procentową szerokość słupka względem największej wartości."""
    raw = [b.model_dump() for b in bars]
    peak = max((b["value"] or 0) for b in raw) if raw else 0
    for b in raw:
        b["pct"] = round((b["value"] or 0) / peak * 100, 2) if peak > 0 else 0
        if not b.get("display"):
            b["display"] = _int(b["value"])
    return raw


def _build_context(req: SeasonPdfRequest) -> Dict[str, Any]:
    t = req.totals
    judges = [j.model_dump() for j in req.judges]
    for j in judges:
        j["hours_fmt"] = _dec1(j["hours"])
        j["km_fmt"] = _int(j["km"])
        j["earnings_total_fmt"] = _int(j["earnings_total"])
        j["earnings_travel_fmt"] = _int(j["earnings_travel"])
        j["earnings_netto_fmt"] = _int(j["earnings_netto"])

    rankings = []
    for block in req.rankings:
        entries = [e.model_dump() for e in block.entries]
        for e in entries:
            e["pct"] = round(max(0.0, min(1.0, e.get("share") or 0)) * 100, 2)
        rankings.append({**block.model_dump(), "entries": entries})

    kpis = [
        {"label": "Turniejów w sezonie", "value": _int(t.tournaments), "hint": f"MP: {_int(t.tournaments_mp)} · wojewódzkie: {_int(t.tournaments_regional)}"},
        {"label": "Sędziów w obsadach", "value": _int(t.judges), "hint": f"{_int(t.assignments)} obsad łącznie"},
        {"label": "Dni na turniejach", "value": _int(t.days), "hint": "suma dni wszystkich sędziów"},
        {"label": "Godzin przy boisku", "value": _dec1(t.hours), "hint": "czas realnie przepracowany"},
        {"label": "Kilometrów", "value": _int(t.km), "hint": "tam i z powrotem, z trasami nierozliczonych"},
        {"label": "Meczów", "value": _int(t.matches), "hint": f"{_int(t.sets)} setów"},
        {"label": "Punktów", "value": _int(t.points), "hint": "zdobytych w tych meczach"},
        {"label": "Finałów", "value": _int(t.finals), "hint": "wraz z meczami o 3. miejsce"},
        {"label": "Miejscowości", "value": _int(t.cities), "hint": f"{_int(t.provinces)} województw"},
        {"label": "Wynagrodzenia brutto", "value": _money(t.earnings_total), "hint": "ryczałty + dojazdy"},
        {"label": "W tym dojazdy", "value": _money(t.earnings_travel), "hint": "zwrot kosztów podróży"},
        {"label": "Do wypłaty netto", "value": _money(t.earnings_netto), "hint": "po kosztach i podatku"},
    ]

    return {
        "season": req.season,
        "season_label": req.season_label or req.season,
        "generated_by": req.generated_by,
        "generated_at": datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M"),
        "accent": ACCENT,
        "accent2": ACCENT_2,
        "logo_b64": _load_logo_b64(),
        "kpis": kpis,
        "categories": _normalize_bars(req.categories),
        "months": _normalize_bars(req.months),
        "cities": _normalize_bars(req.cities),
        "rankings": rankings,
        "judges": judges,
        "disclaimer": (
            "Zestawienie przygotowane automatycznie przez aplikację BAZA Beach na podstawie obsad, "
            "terminarzy i tabel pomocniczych obowiązujących w aplikacji. Kwoty mają charakter "
            "informacyjny i nie stanowią samodzielnej podstawy do wypłaty wynagrodzenia."
        ),
    }


# ─────────────────────────── endpointy ───────────────────────────


@router.post("/beach/season/pdf", summary="Generuj PDF podsumowania sezonu sedziow")
async def generate_season_pdf(req: SeasonPdfRequest):
    from jinja2 import Environment, FileSystemLoader
    import weasyprint

    if not req.judges:
        raise HTTPException(422, "Brak danych sedziow do zestawienia")
    template_path = TEMPLATE_DIR / TEMPLATE_NAME
    if not template_path.exists():
        raise HTTPException(500, detail=f"Brak szablonu: {TEMPLATE_NAME}")

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    env.filters["money"] = _money
    env.filters["km"] = _km
    env.filters["hours"] = _hours
    env.filters["int_pl"] = _int
    env.filters["dec1"] = _dec1
    template = env.get_template(TEMPLATE_NAME)
    html_str = template.render(**_build_context(req))

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "season.html")
        pdf_path = os.path.join(tmp_dir, "season.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.season_label or req.season)
        encoded_name = urllib.parse.quote(f"podsumowanie_sezonu_{safe_name}.pdf")
        return {
            "success": True,
            "download_url": f"/beach/season/pdf/download/{token}?filename={encoded_name}",
        }
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(500, detail=str(e))


@router.get("/beach/season/pdf/download/{token}", summary="Pobierz PDF podsumowania sezonu")
async def download_season_pdf(token: str, filename: str = Query("podsumowanie_sezonu.pdf")):
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
        background=BackgroundTask(
            lambda: os.remove(file_path) if os.path.exists(file_path) else None
        ),
    )
