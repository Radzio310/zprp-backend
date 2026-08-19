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
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

router = APIRouter(tags=["Beach: Season PDF"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "podsumowanie_sezonu.html"
DOWNLOAD_DIR = "/tmp/beach_season_downloads"

ACCENT = "#8A30D0"
ACCENT_2 = "#FF7A2F"
INK = "#1B1826"

MEDAL_COLORS = {1: "#D9A400", 2: "#98A2B3", 3: "#B4703C"}
METRIC_SHORT = {
    "tournaments": "Turnieje",
    "matches": "Mecze",
    "hours": "Godziny",
    "km": "Kilometry",
    "days": "Dni",
    "finals": "Finały",
    "earnings": "Wynagr.",
}
TIER_LABEL = {"gold": "ZŁOTO", "silver": "SREBRO", "bronze": "BRĄZ"}


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
    entries: List[SeasonRankingEntry] = Field(default_factory=list)


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
    # "full_photos" | "full" | "no_cards"
    variant: str = "full"
    season: str = ""
    season_label: str = ""
    generated_by: str = ""
    totals: SeasonTotals = Field(default_factory=SeasonTotals)
    records: List[Dict[str, Any]] = Field(default_factory=list)
    categories: List[SeasonBar] = Field(default_factory=list)
    months: List[SeasonBar] = Field(default_factory=list)
    cities: List[SeasonBar] = Field(default_factory=list)
    poland: Dict[str, Any] = Field(default_factory=dict)
    calendar: Dict[str, Any] = Field(default_factory=dict)
    workload: Dict[str, Any] = Field(default_factory=dict)
    medals: Dict[str, Any] = Field(default_factory=dict)
    rankings: List[SeasonRankingBlock] = Field(default_factory=list)
    titles: List[Dict[str, Any]] = Field(default_factory=list)
    duets: List[Dict[str, Any]] = Field(default_factory=list)
    cards: List[Dict[str, Any]] = Field(default_factory=list)
    judges: List[SeasonJudgeRow] = Field(default_factory=list)


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
    return _int(value) + " km"


def _hours(value: Any) -> str:
    return _dec1(value) + " h"


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


def _chunk(items: List[Any], size: int) -> List[List[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _chunk_first(items: List[Any], first: int, rest: int) -> List[List[Any]]:
    """
    Pierwsza strona mieści mniej kart, bo dzieli miejsce z nagłówkiem sekcji.
    Resztę rozkładamy RÓWNO na potrzebną liczbę stron, żeby ostatnia nie
    kończyła się jedną samotną kartą i połacią pustki.
    """
    if not items:
        return []
    head, tail = items[:first], items[first:]
    if not tail:
        return [head]
    pages = -(-len(tail) // rest)  # sufit z dzielenia
    per = -(-len(tail) // pages)
    out = [head]
    i = 0
    for p in range(pages):
        # ostatnie strony dostają o jedną kartę mniej, gdy podział jest nierówny
        take = per if len(tail) - i - per >= pages - p - 1 else per - 1
        take = max(1, min(take, len(tail) - i))
        out.append(tail[i : i + take])
        i += take
    return out


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

    # ── medale ──
    medal_metrics = [
        {"key": m.get("key"), "label": METRIC_SHORT.get(m.get("key"), m.get("label", ""))}
        for m in (req.medals.get("metrics") or [])
    ]
    medal_rows = list(req.medals.get("rows") or [])

    # ── obciążenie kadry ──
    workload = dict(req.workload or {})
    buckets = list(workload.get("buckets") or [])
    peak_bucket = max([b.get("count", 0) for b in buckets], default=0)
    for b in buckets:
        b["pct"] = round(b.get("count", 0) / peak_bucket * 100, 2) if peak_bucket else 0
    workload["buckets"] = buckets
    workload["median_fmt"] = _dec1(workload.get("median", 0))
    workload["mean_fmt"] = _dec1(workload.get("mean", 0))

    # ── karty sędziów: po 3 na stronę, ze skalą sparkline ──
    cards = list(req.cards or [])
    for c in cards:
        months = c.get("months") or []
        peak = max(months) if months else 0
        c["spark"] = [
            {
                "label": (c.get("month_labels") or [])[i] if i < len(c.get("month_labels") or []) else "",
                "value": v,
                "pct": round(v / peak * 100, 1) if peak else 0,
            }
            for i, v in enumerate(months)
        ]
        c["hours_fmt"] = _dec1(c.get("hours", 0))
        c["km_fmt"] = _int(c.get("km", 0))
        c["earnings_fmt"] = _int(c.get("earnings_total", 0))
        c["tier_label"] = TIER_LABEL.get(c.get("tier") or "", "")
        c["spark_w"] = round(100 / len(c["spark"]), 3) if c["spark"] else 100
    # Karty idą po dwie w rzędzie: 6 na pierwszej stronie (dzieli miejsce
    # z nagłówkiem rozdziału), po 8 na kolejnych — bez pustych przestrzeni.
    card_pages = _chunk_first(cards, 6, 8)

    # ── kalendarium: kadr liczony z faktycznego zasięgu bąbli ──
    #
    # Stały margines nie wystarczał: przy wielu turniejach w jednym tygodniu
    # bąble rozchodzą się na kolejne pasy w pionie i wyjeżdżały poza kadr.
    calendar = dict(req.calendar or {})
    cal_w = float(calendar.get("width") or 700)
    cal_h = float(calendar.get("height") or 150)
    cal_pad = float(calendar.get("pad") or 24)
    bubbles = list(calendar.get("bubbles") or [])
    if bubbles:
        left = min(float(b.get("x", 0)) - float(b.get("r", 0)) for b in bubbles)
        right = max(float(b.get("x", 0)) + float(b.get("r", 0)) for b in bubbles)
        top = min(float(b.get("y", 0)) - float(b.get("r", 0)) for b in bubbles)
        bottom = max(float(b.get("y", 0)) + float(b.get("r", 0)) for b in bubbles)
    else:
        left, right, top, bottom = 0.0, cal_w, 0.0, cal_h
    # oś i podpisy miesięcy muszą się zmieścić niezależnie od bąbli
    vb_x = min(left, 0.0) - 8
    vb_y = min(top, 0.0) - 8
    vb_w = max(right, cal_w) + 8 - vb_x
    vb_h = max(bottom, cal_h + 40) + 8 - vb_y
    calendar["viewbox"] = f"{vb_x:g} {vb_y:g} {vb_w:g} {vb_h:g}"

    # ── tytuły ──
    titles = list(req.titles or [])
    for x in titles:
        x["tier_label"] = TIER_LABEL.get(x.get("tier") or "", "")

    kpis_big = [
        {"label": "Turniejów w sezonie", "value": _int(t.tournaments),
         "hint": f"MP: {_int(t.tournaments_mp)} · wojewódzkie: {_int(t.tournaments_regional)}"},
        {"label": "Sędziów w obsadach", "value": _int(t.judges),
         "hint": f"{_int(t.assignments)} obsad łącznie"},
        {"label": "Dni pracy sędziów", "value": _int(t.days),
         "hint": f"{_hours(t.hours)} realnie przy boisku"},
    ]
    kpis_small = [
        {"label": "Kilometrów", "value": _int(t.km), "hint": "tam i z powrotem"},
        {"label": "Meczów", "value": _int(t.matches), "hint": f"{_int(t.sets)} setów"},
        {"label": "Punktów", "value": _int(t.points), "hint": "zdobytych w tych meczach"},
        {"label": "Finałów", "value": _int(t.finals), "hint": "z meczami o 3. miejsce"},
        {"label": "Miejscowości", "value": _int(t.cities), "hint": f"{_int(t.provinces)} województw"},
        {"label": "Brutto", "value": _money(t.earnings_total), "hint": "ryczałty + dojazdy"},
        {"label": "Dojazdy", "value": _money(t.earnings_travel), "hint": "zwrot kosztów podróży"},
        {"label": "Netto", "value": _money(t.earnings_netto), "hint": "po kosztach i podatku"},
    ]

    hero = [
        {"value": _int(t.tournaments), "label": "turniejów"},
        {"value": _int(t.judges), "label": "sędziów"},
        {"value": _int(t.km), "label": "kilometrów"},
        {"value": _int(t.matches), "label": "meczów"},
    ]

    return {
        "variant": req.variant,
        "show_cards": req.variant in ("full", "full_photos") and len(cards) > 0,
        "season": req.season,
        "season_label": req.season_label or req.season,
        "generated_by": req.generated_by,
        "generated_at": datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M"),
        "accent": ACCENT,
        "accent2": ACCENT_2,
        "ink": INK,
        "medal_colors": MEDAL_COLORS,
        "logo_b64": _load_logo_b64(),
        "hero": hero,
        "kpis_big": kpis_big,
        "kpis_small": kpis_small,
        "records": list(req.records or []),
        "categories": _normalize_bars(req.categories),
        "months": _normalize_bars(req.months),
        "cities": _normalize_bars(req.cities),
        "poland": dict(req.poland or {}),
        "calendar": calendar,
        "workload": workload,
        "medal_metrics": medal_metrics,
        "medal_rows": medal_rows,
        "rankings": rankings,
        "titles": titles,
        "duets": list(req.duets or []),
        "card_pages": card_pages,
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
