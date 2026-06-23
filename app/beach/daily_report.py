"""
Beach Daily Report — "Komunikat po X. dniu zawodów" PDF generation.

Hybrid of final report (match cards) and schedule PDF (remaining terminarz).
Includes: header, summary, match cards up to target day, disqualifications,
additional notes, and remaining schedule for future days.
"""
from __future__ import annotations

import base64
import html as html_mod
import io
import logging
import os
import re
import unicodedata
import shutil
import tempfile
import urllib.parse
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach: Daily Report"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "komunikat_dzienny.html"
DOWNLOAD_DIR = "/tmp/daily_report_downloads"

_PL_TRANS = str.maketrans("łŁżŻ", "lLzZ")


def _safe_filename_part(s: str, max_len: int = 40) -> str:
    """Transliteruje polskie znaki, zamienia / na _, zachowuje resztę dozwolonych."""
    s = s.translate(_PL_TRANS)
    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(c if c.isalnum() or c in " _-" else "_" for c in s)
    return s[:max_len]


STAGE_LABELS = {
    "group": "Grupa",
    "playoff": "Baraż",
    "quarterfinal": "1/4",
    "semifinal": "1/2",
    "fifth_semifinal": "SM5",
    "ninth_semifinal": "PF IX",
    "thirteenth_semifinal": "PF XIII",
    "final": "Finał",
    "third_place": "o 3. miejsce",
    "fifth_place": "o 5. miejsce",
    "seventh_place": "o 7. miejsce",
    "ninth_place": "o 9. miejsce",
    "eleventh_place": "o 11. miejsce",
    "thirteenth_place": "o 13. miejsce",
    "fifteenth_place": "o 15. miejsce",
    "placement_rr": "O miejsca",
}

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

_ROMAN = {
    1: "I", 2: "II", 3: "III", 4: "IV", 5: "V",
    6: "VI", 7: "VII", 8: "VIII", 9: "IX", 10: "X",
}

import math as _math

# ──────────── Models ────────────


class DisqualificationEntry(BaseModel):
    match_number: str = ""
    player_name: str = ""
    player_number: Optional[int] = None
    team_name: str = ""
    gender: str = ""
    moment: str = ""        # e.g. "Set 1, 08:24"
    comment: str = ""
    is_companion: bool = False
    companion_role: str = ""  # "A"-"D"


class DailyReportRequest(BaseModel):
    schedule: Dict[str, Any]
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""
    category: str = ""
    competition_type: str = ""
    day_index: int = 0
    disqualifications: List[DisqualificationEntry] = []
    additional_notes: str = ""
    custom_summary: Optional[str] = None


# ──────────── Helpers ────────────


def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _get_accent(category: str) -> str:
    return CATEGORY_COLORS.get(category, DEFAULT_ACCENT)


def _roman(n: int) -> str:
    return _ROMAN.get(n, str(n))


def _load_logo_b64() -> str:
    logo_path = TEMPLATE_DIR.parent / "templates" / "baza_beach_logo.png"
    if not logo_path.exists():
        alt_paths = [
            Path(__file__).resolve().parent.parent.parent / "baza_beach.png",
            TEMPLATE_DIR / "baza_beach_logo.png",
        ]
        for p in alt_paths:
            if p.exists():
                logo_path = p
                break
        else:
            return ""
    try:
        from PIL import Image as PILImage
        img = PILImage.open(logo_path)
        img.thumbnail((300, 300), PILImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        logger.warning(f"Could not load logo: {e}")
        return ""


def _compute_date_range(days: List[Dict[str, Any]]) -> str:
    dates = sorted(d.get("date", "") for d in days if d.get("date"))
    if not dates:
        return ""
    fmt = lambda iso: f"{iso[8:10]}.{iso[5:7]}.{iso[:4]}" if len(iso) >= 10 else iso
    if len(dates) == 1:
        return fmt(dates[0])
    return f"{fmt(dates[0])}–{fmt(dates[-1])}"


def _day_header(day_index: int, date_str: Optional[str]) -> str:
    roman = _roman(day_index + 1)
    if date_str:
        try:
            from datetime import date
            d = date.fromisoformat(date_str[:10])
            weekday = WEEKDAYS_PL[d.weekday()]
            formatted = f"{d.day:02d}.{d.month:02d}.{d.year}"
            return f"Dzień {roman}  ·  {formatted}  ({weekday})"
        except Exception:
            pass
    return f"Dzień {roman}"


def _score_display(m: Dict[str, Any]) -> str:
    sa, sb = m.get("scoreA"), m.get("scoreB")
    if sa is not None and sb is not None:
        return f"{sa}:{sb}"
    return "–"


def _winner(m: Dict[str, Any]) -> Optional[str]:
    sa, sb = m.get("scoreA"), m.get("scoreB")
    if sa is not None and sb is not None:
        if sa > sb:
            return "A"
        elif sb > sa:
            return "B"
    return None


def _team_name(team: Optional[Dict[str, Any]]) -> str:
    if team and team.get("name"):
        return str(team["name"])
    return "TBD"


def _is_real_match(m: Dict[str, Any]) -> bool:
    kind = m.get("kind") or "match"
    if kind in {"court_break", "tournament_opening"}:
        return False
    return kind == "match" or bool(m.get("matchNumber") or m.get("teamA") or m.get("teamB"))


def _resolve_mode(config: Optional[Dict[str, Any]], gender: str) -> str:
    """Per-gender play system, falling back to the shared `mode`."""
    config = config or {}
    per = config.get("modeM") if gender == "M" else config.get("modeK")
    return per or config.get("mode") or "roundRobin"


def _stage_label(m: Dict[str, Any], is_global_tour: bool = False) -> str:
    stage = m.get("stage", "")
    group = m.get("group")
    label = STAGE_LABELS.get(stage, "")
    if stage == "group" and is_global_tour:
        label = "Global"
    elif stage == "group" and group:
        label = f"gr. {group}"
    elif stage == "placement_rr" and group:
        tier_match = re.match(r"placement_(\d+)", group)
        if tier_match:
            label = f"o {tier_match.group(1)}. miejsce"
        else:
            label = "O miejsca"
    return label


def _sets_display(m: Dict[str, Any]) -> str:
    sets = _sets_with_third_set(m)
    if not sets:
        return ""
    return ", ".join(f"{s.get('ptA', 0)}:{s.get('ptB', 0)}" for s in sets)


def _sets_with_third_set(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    sets = [dict(s) for s in (m.get("sets") or []) if isinstance(s, dict)]
    shootout = m.get("shootout")
    if len(sets) < 3 and isinstance(shootout, dict):
        sets.append({
            "ptA": shootout.get("a", 0),
            "ptB": shootout.get("b", 0),
        })
    return sets


def _score_parts(m: Dict[str, Any]) -> tuple:
    a, b = m.get("scoreA"), m.get("scoreB")
    if a is None or b is None:
        return "", ""
    score_main = f"{a}:{b}"
    sets = _sets_with_third_set(m)
    score_sets = ""
    if sets:
        parts = [
            f"{s.get('ptA', '')}:{s.get('ptB', '')}"
            for s in sets if isinstance(s, dict)
        ]
        if parts:
            score_sets = ", ".join(parts)
    return score_main, score_sets


def _knockout_hints(m: Dict[str, Any]) -> tuple:
    team_a = m.get("teamA")
    team_b = m.get("teamB")
    label = m.get("knockoutLabel") or ""
    if not label:
        return "", ""
    parts = label.split(" vs ", 1)
    hint_a = parts[0].strip() if not (team_a and team_a.get("name")) else ""
    hint_b = (parts[1].strip() if len(parts) > 1 else "") if not (team_b and team_b.get("name")) else ""
    for prefix in ("Baraż: ",):
        if hint_a.startswith(prefix):
            hint_a = hint_a[len(prefix):]
        if hint_b.startswith(prefix):
            hint_b = hint_b[len(prefix):]
    hint_a = re.sub(r"^Bara\u017c\s+\d+\.\s*miejsc:\s*", "", hint_a)
    hint_b = re.sub(r"^Bara\u017c\s+\d+\.\s*miejsc:\s*", "", hint_b)
    hint_a = re.sub(r"^O msc\.\s*[^:]+:\s*", "", hint_a)
    hint_b = re.sub(r"^O msc\.\s*[^:]+:\s*", "", hint_b)
    return hint_a, hint_b


# ──────────── Build template context ────────────


def _build_context(req: DailyReportRequest) -> Dict[str, Any]:
    schedule = req.schedule
    config = schedule.get("config") or {}
    all_matches: List[Dict[str, Any]] = schedule.get("matches") or []
    days: List[Dict[str, Any]] = config.get("days") or []
    mode = config.get("mode", "roundRobin")
    accent = _get_accent(req.category)
    day_index = req.day_index
    total_days = len(days)

    logo_b64 = _load_logo_b64()
    date_range = req.tournament_dates.strip() or _compute_date_range(days)

    # Separate matches: played (days 0..day_index) vs remaining (days > day_index)
    # Only real matches (not breaks/openings)
    played_matches = []
    remaining_entries = []
    for m in all_matches:
        di = int(m.get("dayIndex") or 0)
        if di <= day_index and _is_real_match(m):
            played_matches.append(m)
        elif di > day_index:
            remaining_entries.append(m)

    # ── Summary ──
    finished_matches = [m for m in played_matches if m.get("scoreA") is not None]
    match_count = len(finished_matches)

    genders_present = set(m.get("gender", "M") for m in played_matches)
    multi_gender = len(genders_present) > 1

    # Gdy jeden rodzaj płci — kolor akcentu odpowiada tej płci
    if not multi_gender:
        only_gender = next(iter(genders_present), "M")
        accent = "#2BA8A0" if only_gender == "M" else "#E85A78"

    system_name = "każdy z każdym" if mode == "roundRobin" else "grupowym z fazą pucharową"

    day_date = ""
    if day_index < len(days) and days[day_index].get("date"):
        ds = days[day_index]["date"]
        if len(ds) >= 10:
            day_date = f"{ds[8:10]}.{ds[5:7]}.{ds[:4]}"

    summary_parts = [
        f"Podsumowanie {day_index + 1}. dnia zawodów"
        + (f" ({day_date})" if day_date else "")
        + ".",
        f"Rozegrano dotychczas {match_count} "
        f"{'mecz' if match_count == 1 else 'mecze' if 2 <= match_count <= 4 else 'meczów'} "
        f"w systemie {system_name}.",
    ]
    if total_days > day_index + 1:
        remaining_count = total_days - day_index - 1
        summary_parts.append(
            f"Do końca turnieju {'pozostał' if remaining_count == 1 else 'pozostały' if 2 <= remaining_count <= 4 else 'pozostało'} "
            f"{remaining_count} {'dzień' if remaining_count == 1 else 'dni'} rozgrywek."
        )
    summary_parts.append("Poniżej szczegółowe wyniki i plan dalszych rozgrywek.")
    auto_summary = " ".join(summary_parts)
    summary_text = req.custom_summary.strip() if req.custom_summary else auto_summary

    # ── Match cards by day (days 0..day_index, grouped by gender) ──
    match_days = []
    by_day: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for m in played_matches:
        by_day[int(m.get("dayIndex") or 0)].append(m)

    def _match_num_sort_key(x: Dict[str, Any]):
        mn = x.get("matchNumber") or ""
        parts = mn.rsplit("/", 1)
        try:
            num = int(parts[-1])
        except (ValueError, IndexError):
            num = 999999
        prefix = parts[0] if len(parts) > 1 else ""
        return (prefix, num, x.get("order", 0))

    for di in sorted(by_day.keys()):
        day_matches_list = sorted(by_day[di], key=_match_num_sort_key)
        day_cfg = days[di] if di < len(days) else {}
        day_date_str = day_cfg.get("date", "")
        if day_date_str and len(day_date_str) >= 10:
            day_label = f"Dzień {di + 1} — {day_date_str[8:10]}.{day_date_str[5:7]}.{day_date_str[:4]}"
        elif len(by_day) > 1:
            day_label = f"Dzień {di + 1}"
        else:
            day_label = ""

        cards = []
        for m in day_matches_list:
            w = _winner(m)
            cards.append({
                "time": m.get("startTime", ""),
                "match_number": m.get("matchNumber", ""),
                "team_a": _team_name(m.get("teamA")),
                "team_b": _team_name(m.get("teamB")),
                "score_a": m.get("scoreA"),
                "score_b": m.get("scoreB"),
                "score_display": _score_display(m),
                "sets": _sets_with_third_set(m),
                "shootout": None,
                "winner": w,
                "stage_label": _stage_label(m, _resolve_mode(config, m.get("gender") or "") == "globalTour") if mode != "roundRobin" else "",
                "gender": m.get("gender", ""),
            })
        match_days.append({"label": day_label, "matches": cards})

    # ── Remaining schedule rows (days > day_index) ──
    remaining_days = []
    remaining_by_day: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for m in remaining_entries:
        remaining_by_day[int(m.get("dayIndex") or 0)].append(m)
    for idx in remaining_by_day:
        remaining_by_day[idx].sort(
            key=lambda m: (m.get("startTime") or "99:99", m.get("order") or 0)
        )

    # Assign match numbers for remaining entries
    gender_counters: Dict[str, int] = {"M": 0, "K": 0}
    # Count already-played matches per gender for numbering continuity
    for m in all_matches:
        kind = m.get("kind") or "match"
        if kind in ("court_break", "tournament_opening"):
            continue
        di = int(m.get("dayIndex") or 0)
        g = m.get("gender") or ""
        if g in gender_counters:
            gender_counters[g] += 1
            if di > day_index:
                # This is a remaining match — store its number
                m["_num_label"] = f"{g}{gender_counters[g]}"

    for di in sorted(remaining_by_day.keys()):
        day_entries = remaining_by_day[di]
        day_cfg = days[di] if di < len(days) else {}
        day_label = _day_header(di, day_cfg.get("date"))

        rows = []
        for m in day_entries:
            kind = m.get("kind") or "match"
            if kind == "court_break":
                rows.append({
                    "type": "court_break",
                    "time": m.get("startTime") or "",
                    "court": str(m.get("court") or ""),
                    "label": m.get("label") or "Przerwa",
                    "duration": m.get("durationMinutes") or 0,
                })
                continue
            if kind == "tournament_opening":
                rows.append({
                    "type": "tournament_opening",
                    "time": m.get("startTime") or "",
                    "label": m.get("label") or "Otwarcie turnieju",
                    "duration": m.get("durationMinutes") or 0,
                })
                continue

            gender = m.get("gender") or ""
            match_num = m.get("_num_label", "")
            sm, ss = _score_parts(m)
            ha, hb = _knockout_hints(m)

            rows.append({
                "type": "match",
                "time": m.get("startTime") or "",
                "court": str(m.get("court") or ""),
                "match_num": match_num,
                "gender": gender,
                "stage": _stage_label(m, _resolve_mode(config, gender) == "globalTour"),
                "team_a": _team_name(m.get("teamA")),
                "team_b": _team_name(m.get("teamB")),
                "hint_a": ha,
                "hint_b": hb,
                "score_main": sm,
                "score_sets": ss,
            })
        remaining_days.append({"label": day_label, "matches": rows})

    # ── Disqualifications ──
    disqualifications = []
    for dq in req.disqualifications:
        disqualifications.append({
            "match_number": dq.match_number,
            "player_name": dq.player_name,
            "player_number": dq.player_number,
            "team_name": dq.team_name,
            "gender": dq.gender,
            "moment": dq.moment,
            "comment": dq.comment,
            "is_companion": dq.is_companion,
            "companion_role": dq.companion_role,
        })

    now = datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M")

    return {
        "tournament_name": req.tournament_name.strip() or "Turniej",
        "date_range": date_range,
        "location": req.tournament_location.strip(),
        "accent": accent,
        "logo_b64": logo_b64,
        "day_number": day_index + 1,
        "day_date": day_date,
        "summary_text": summary_text,
        "match_days": match_days,
        "multi_gender": multi_gender,
        "has_remaining": len(remaining_days) > 0,
        "remaining_days": remaining_days,
        "disqualifications": disqualifications,
        "has_disqualifications": len(disqualifications) > 0,
        "additional_notes": req.additional_notes.strip(),
        "has_additional_notes": bool(req.additional_notes.strip()),
        "generated_at": now,
    }


# ──────────── Endpoints ────────────


@router.post(
    "/beach/report/daily",
    summary="Generuj komunikat po dniu zawodów (PDF)",
)
async def generate_daily_report(req: DailyReportRequest):
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
        html_path = os.path.join(tmp_dir, "report.html")
        pdf_path = os.path.join(tmp_dir, "report.pdf")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        doc = weasyprint.HTML(filename=html_path)
        doc.write_pdf(pdf_path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = _safe_filename_part(req.tournament_name) or "komunikat"
        download_name = f"komunikat_dzien_{req.day_index + 1}_{safe_name}.pdf"
        encoded_name = urllib.parse.quote(download_name)

        return {
            "success": True,
            "download_url": f"/beach/report/daily/download/{token}?filename={encoded_name}",
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Daily report PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/report/daily/download/{token}",
    summary="Pobierz wygenerowany komunikat dzienny (PDF)",
)
async def download_daily_report(
    token: str,
    filename: str = Query("komunikat_dzienny.pdf"),
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
