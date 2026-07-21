"""
Beach Organizational Report — "Komunikat organizacyjny" PDF generation.

Renders an editable pre-tournament organizational notice with venue QR,
app-download QR, invited teams, schedule, and general information items.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import re
import shutil
import tempfile
import unicodedata
import urllib.parse
import uuid
from collections import defaultdict
from datetime import date, datetime
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

from app.beach import schedule_pdf

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach: Organizational Report"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "komunikat_organizacyjny.html"
DOWNLOAD_DIR = "/tmp/organizational_report_downloads"

_PL_TRANS = str.maketrans("łŁżŻ", "lLzZ")

CATEGORY_COLORS = {
    "Senior": "#E85A30",
    "Junior": "#3A7FBF",
    "Junior mł.": "#2BA8A0",
    "Kadet": "#7A5FC7",
}
DEFAULT_ACCENT = "#E85A30"

WEEKDAYS_PL = [
    "poniedziałek", "wtorek", "środa",
    "czwartek", "piątek", "sobota", "niedziela",
]


class OrganizerInfo(BaseModel):
    name: str = ""
    phone: str = ""
    email: str = ""


class GeneralInfoItem(BaseModel):
    text: str = ""
    link_label: str = ""
    link_url: str = ""


class OrganizationalReportRequest(BaseModel):
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""
    category: str = ""
    generated_by: str = ""
    venue_address: str = ""
    venue_lat: Optional[float] = None
    venue_lng: Optional[float] = None
    maps_url: str = ""
    organizer: Optional[OrganizerInfo] = None
    schedule: Dict[str, Any] = {}
    custom_teams: Optional[List[Dict[str, Any]]] = None
    general_info: List[GeneralInfoItem] = []


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
            return datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            pass
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S")


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


def _load_app_qr_b64() -> str:
    return _load_image_b64(TEMPLATE_DIR / "beach_qr.png", (220, 220))


def _make_qr_b64(url: str) -> str:
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
        logger.warning("Could not generate QR code: %s", e)
        return ""


def _compute_date_range(days: List[Dict[str, Any]]) -> str:
    dates = sorted(d.get("date", "") for d in days if d.get("date"))
    if not dates:
        return ""
    fmt = lambda iso: f"{iso[8:10]}.{iso[5:7]}.{iso[:4]}" if len(iso) >= 10 else iso
    if len(dates) == 1:
        return fmt(dates[0])
    return f"{fmt(dates[0])}–{fmt(dates[-1])}"


def _day_label(day_index: int, date_str: Optional[str]) -> str:
    label = f"Dzień {day_index + 1}"
    if not date_str:
        return label
    try:
        d = date.fromisoformat(date_str[:10])
        return f"{label} · {d.strftime('%d.%m.%Y')} ({WEEKDAYS_PL[d.weekday()]})"
    except Exception:
        return f"{label} · {date_str}"


def _team_name(team: Optional[Dict[str, Any]]) -> str:
    if team and team.get("name"):
        return str(team["name"])
    return "TBD"


def _team_id(team: Optional[Dict[str, Any]]) -> Optional[int]:
    try:
        if team and team.get("id") is not None:
            return int(team["id"])
    except Exception:
        return None
    return None


def _custom_team_name_map(custom_teams: Optional[List[Dict[str, Any]]]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for idx, team in enumerate(custom_teams or []):
        name = str(team.get("name") or "").strip()
        if name:
            out[-(idx + 1)] = name
    return out


def _stage_label(m: Dict[str, Any]) -> str:
    stage = m.get("stage", "")
    group = m.get("group") or ""
    if stage == "group":
        return f"Grupa {group}" if group else "Grupa"
    if stage == "placement_rr":
        range_match = re.search(r"O msc\.\s*([^:]+)", m.get("knockoutLabel") or "", re.IGNORECASE)
        if range_match and not group.startswith("placement_quad_"):
            return f"Grupa {range_match.group(1).strip()}"
        if range_match:
            return f"o {range_match.group(1).strip()}"
        return "Grupa o miejsca"
    return {
        "playoff": "Baraż",
        "quarterfinal": "Ćwierćfinał",
        "semifinal": "Półfinał",
        "fifth_semifinal": "PF o V.",
        "ninth_semifinal": "PF o IX.",
        "thirteenth_semifinal": "PF o XIII.",
        "third_place": "3. miejsce",
        "fifth_place": "5. miejsce",
        "seventh_place": "7. miejsce",
        "ninth_place": "9. miejsce",
        "eleventh_place": "11. miejsce",
        "thirteenth_place": "13. miejsce",
        "fifteenth_place": "15. miejsce",
        "final": "Finał",
    }.get(stage, stage or "")


def _gender_label(gender: str) -> str:
    return "Mężczyźni" if gender == "M" else "Kobiety" if gender == "K" else "Drużyny"


def _time_sort_key(m: Dict[str, Any]) -> tuple:
    day_index = int(m.get("dayIndex") or 0)
    slot = int(m.get("slotIndex") or 0)
    court = int(m.get("court") or 0)
    seq = int(m.get("sequence") or 0)
    return day_index, slot, court, seq, str(m.get("matchNumber") or "")


def _build_maps_url(req: OrganizationalReportRequest) -> str:
    if req.maps_url.strip():
        return req.maps_url.strip()
    if req.venue_lat is not None and req.venue_lng is not None:
        return f"https://www.google.com/maps/dir/?api=1&destination={req.venue_lat},{req.venue_lng}"
    return ""


def _build_context(req: OrganizationalReportRequest) -> Dict[str, Any]:
    schedule = req.schedule or {}
    config = schedule.get("config") or {}
    days: List[Dict[str, Any]] = config.get("days") or []
    matches = [
        m for m in (schedule.get("matches") or [])
        if isinstance(m, dict) and (m.get("kind") in (None, "", "match"))
    ]
    matches.sort(key=_time_sort_key)

    custom_names = _custom_team_name_map(req.custom_teams)
    for m in matches:
        for side in ("teamA", "teamB"):
            team = m.get(side)
            tid = _team_id(team)
            if tid is not None and tid < 0 and tid in custom_names:
                m[side] = {**(team or {}), "name": custom_names[tid]}

    teams_by_gender: Dict[str, Dict[str, str]] = defaultdict(dict)
    groups: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
    for m in matches:
        gender = str(m.get("gender") or "")
        for side in ("teamA", "teamB"):
            team = m.get(side)
            tid = _team_id(team)
            name = _team_name(team)
            if tid is None or name == "TBD":
                continue
            teams_by_gender[gender][str(tid)] = name
            if m.get("stage") == "group" and m.get("group"):
                groups[gender][str(m.get("group"))][str(tid)] = name

    team_sections = []
    for gender in sorted(teams_by_gender.keys(), key=lambda g: {"K": 0, "M": 1}.get(g, 2)):
        group_map = groups.get(gender) or {}
        is_global_tour = schedule_pdf._resolve_mode(config, gender) == "globalTour"
        if group_map:
            team_sections.append({
                "gender": gender,
                "label": _gender_label(gender),
                "groups": [
                    {
                        "name": group,
                        "display_name": "Global" if is_global_tour else f"Grupa {group}",
                        "teams": sorted(team_map.values(), key=lambda x: x.lower()),
                    }
                    for group, team_map in sorted(group_map.items())
                ],
                "teams": [],
            })
        else:
            team_sections.append({
                "gender": gender,
                "label": _gender_label(gender),
                "groups": [],
                "teams": sorted(teams_by_gender[gender].values(), key=lambda x: x.lower()),
            })

    # Bogaty terminarz — budowany identycznie jak w generatorze terminarza
    # (kolumny, numeracja meczów M/K, etapy, wyniki, podpowiedzi pucharowe,
    # przerwy i otwarcie turnieju). Dzięki temu pola są wypełnione tak samo.
    sched_ctx = schedule_pdf._build_context(
        schedule_pdf.SchedulePdfRequest(
            schedule=req.schedule or {},
            tournament_name=req.tournament_name,
            tournament_location=req.tournament_location,
            tournament_dates=req.tournament_dates,
            category=req.category,
            include_groups=True,
            split_by_courts=False,
            custom_teams=req.custom_teams,
        )
    )
    schedule_days = sched_ctx.get("days") or []

    maps_url = _build_maps_url(req)
    organizer = req.organizer
    organizer_ctx = None
    if organizer and any([organizer.name.strip(), organizer.phone.strip(), organizer.email.strip()]):
        organizer_ctx = {
            "name": organizer.name.strip(),
            "phone": organizer.phone.strip(),
            "email": organizer.email.strip(),
        }

    general_info = []
    for item in req.general_info or []:
        text = (item.text or "").strip()
        url = (item.link_url or "").strip()
        if not text and not url:
            continue
        general_info.append({
            "text": text,
            "link_label": (item.link_label or "").strip() or "Otwórz link",
            "link_url": url,
            "qr_b64": _make_qr_b64(url) if url else "",
        })

    accent = CATEGORY_COLORS.get(req.category, DEFAULT_ACCENT)
    date_range = req.tournament_dates.strip() or _compute_date_range(days)
    location = req.tournament_location.strip()
    venue_address = req.venue_address.strip() or location

    return {
        "tournament_name": req.tournament_name.strip() or "Turniej",
        "date_range": date_range,
        "location": location,
        "venue_address": venue_address,
        "maps_url": maps_url,
        "maps_qr_b64": _make_qr_b64(maps_url),
        "organizer": organizer_ctx,
        "team_sections": team_sections,
        "days": schedule_days,
        "general_info": general_info,
        "accent": accent,
        "logo_b64": _load_logo_b64(),
        "app_qr_b64": _load_app_qr_b64(),
        "generated_at": _now_pl_str(),
        "generated_by": req.generated_by.strip(),
    }


@router.post(
    "/beach/report/organizational",
    summary="Generuj komunikat organizacyjny turnieju (PDF)",
)
async def generate_organizational_report(req: OrganizationalReportRequest):
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
        html_path = os.path.join(tmp_dir, "organizational.html")
        pdf_path = os.path.join(tmp_dir, "organizational.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.tournament_name) or "komunikat_organizacyjny"
        download_name = f"komunikat_organizacyjny_{safe_name}.pdf"
        encoded_name = urllib.parse.quote(download_name)

        return {
            "success": True,
            "download_url": f"/beach/report/organizational/download/{token}?filename={encoded_name}",
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Organizational PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/report/organizational/download/{token}",
    summary="Pobierz wygenerowany komunikat organizacyjny (PDF)",
)
async def download_organizational_report(
    token: str,
    filename: str = Query("komunikat_organizacyjny.pdf"),
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
