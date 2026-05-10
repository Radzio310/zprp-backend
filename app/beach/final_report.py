"""
Beach Final Report — "Komunikat Końcowy" PDF generation.

Renders an HTML template with Jinja2 and converts to PDF via WeasyPrint.
Contains: header, summary, group/round-robin tables, knockout bracket,
match cards, and standings summary.
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
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach: Final Report"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "komunikat_koncowy.html"
DOWNLOAD_DIR = "/tmp/final_report_downloads"

STAGE_LABELS = {
    "group": "Grupa",
    "playoff": "Baraż",
    "quarterfinal": "Ćwierćfinał",
    "semifinal": "Półfinał",
    "fifth_semifinal": "Pf. 5-8",
    "final": "Finał",
    "third_place": "O 3. miejsce",
    "fifth_place": "O 5. miejsce",
    "seventh_place": "O 7. miejsce",
}

CATEGORY_COLORS = {
    "Senior": "#E85A30",
    "Junior": "#3A7FBF",
    "Junior mł.": "#2BA8A0",
    "Kadet": "#7A5FC7",
}
DEFAULT_ACCENT = "#E85A30"


# ──────────── Models ────────────

class StandingRow(BaseModel):
    pos: int
    team_name: str
    total_points: float
    tournament_points: Optional[float] = None


class GenderStandingsData(BaseModel):
    gender: str  # "M" | "K"
    rows: List[StandingRow]
    tournament_count: int = 1


class FinalReportRequest(BaseModel):
    schedule: Dict[str, Any]
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""
    tournament_id: Optional[int] = None
    category: str = ""
    competition_type: str = ""
    standings: Optional[List[GenderStandingsData]] = None


# ──────────── Helpers ────────────

def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _load_logo_b64() -> str:
    """Load and resize the BAZA Beach logo, return base64 PNG."""
    logo_path = TEMPLATE_DIR.parent / "templates" / "baza_beach_logo.png"
    if not logo_path.exists():
        # Try loading from bundled assets
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


def _sets_display(m: Dict[str, Any]) -> str:
    sets = m.get("sets") or []
    if not sets:
        return ""
    parts = [f"{s.get('ptA', 0)}:{s.get('ptB', 0)}" for s in sets]
    result = ", ".join(parts)
    shootout = m.get("shootout")
    if shootout:
        result += f" (rz.k. {shootout.get('a', 0)}:{shootout.get('b', 0)})"
    return result


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
        return team["name"]
    return "TBD"


def _stage_label(m: Dict[str, Any]) -> str:
    stage = m.get("stage", "")
    group = m.get("group")
    label = STAGE_LABELS.get(stage, "")
    if stage == "group" and group:
        label = f"Grupa {group}"
    return label


def _get_accent(category: str) -> str:
    return CATEGORY_COLORS.get(category, DEFAULT_ACCENT)


# ──────────── Group table computation (server-side) ────────────

def _compute_group_table(
    matches: List[Dict[str, Any]],
    advancing_count: int = 0,
) -> List[Dict[str, Any]]:
    """Compute group/round-robin standings from match results.
    Scoring: Win = 2 pts, Loss = 0 pts (matches ResultsView.tsx)."""
    teams: Dict[int, Dict[str, Any]] = {}

    for m in matches:
        ta, tb = m.get("teamA"), m.get("teamB")
        if not ta or not tb:
            continue
        sa, sb = m.get("scoreA"), m.get("scoreB")
        for t in (ta, tb):
            tid = t["id"]
            if tid not in teams:
                teams[tid] = {
                    "team_name": t.get("name", "?"),
                    "played": 0, "won": 0, "lost": 0,
                    "sets_won": 0, "sets_lost": 0,
                    "brk_plus": 0, "brk_minus": 0,
                    "pts": 0,
                }
        if sa is None or sb is None:
            continue

        aid, bid = ta["id"], tb["id"]
        teams[aid]["played"] += 1
        teams[bid]["played"] += 1

        # Win = 2 pts, Loss = 0 pts
        if sa > sb:
            teams[aid]["pts"] += 2
            teams[aid]["won"] += 1
            teams[bid]["lost"] += 1
        else:
            teams[bid]["pts"] += 2
            teams[bid]["won"] += 1
            teams[aid]["lost"] += 1

        teams[aid]["sets_won"] += sa
        teams[aid]["sets_lost"] += sb
        teams[bid]["sets_won"] += sb
        teams[bid]["sets_lost"] += sa

        for s in (m.get("sets") or []):
            pa, pb = s.get("ptA", 0), s.get("ptB", 0)
            teams[aid]["brk_plus"] += pa
            teams[aid]["brk_minus"] += pb
            teams[bid]["brk_plus"] += pb
            teams[bid]["brk_minus"] += pa

    # Sort: pts desc, set diff desc, brk diff desc
    rows = sorted(
        teams.values(),
        key=lambda r: (
            r["pts"],
            r["sets_won"] - r["sets_lost"],
            r["brk_plus"] - r["brk_minus"],
        ),
        reverse=True,
    )

    for i, r in enumerate(rows):
        r["pos"] = i + 1
        r["advancing"] = i < advancing_count

    return rows


# ──────────── Bracket computation ────────────

BRACKET_STAGE_ORDER = [
    "quarterfinal", "semifinal", "final",
]

BRACKET_STAGE_LABELS = {
    "quarterfinal": "Ćwierćfinały",
    "semifinal": "Półfinały",
    "final": "Finał",
}


def _build_bracket_rounds(
    matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build bracket rounds from knockout matches for PDF rendering."""
    by_stage: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for m in matches:
        stage = m.get("stage", "")
        if stage in BRACKET_STAGE_ORDER:
            by_stage[stage].append(m)

    rounds = []
    for stage in BRACKET_STAGE_ORDER:
        stage_matches = by_stage.get(stage, [])
        if not stage_matches:
            continue
        stage_matches.sort(key=lambda x: x.get("order", 0))
        bms = []
        for m in stage_matches:
            w = _winner(m)
            bms.append({
                "team_a": _team_name(m.get("teamA")),
                "team_b": _team_name(m.get("teamB")),
                "score_a": m.get("scoreA"),
                "score_b": m.get("scoreB"),
                "winner": w,
                "label": m.get("knockoutLabel", ""),
            })
        rounds.append({
            "label": BRACKET_STAGE_LABELS.get(stage, stage),
            "matches": bms,
        })
    return rounds


def _build_placement_matches(
    matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extract placement matches (3rd, 5th, 7th place)."""
    placement_stages = {"third_place", "fifth_place", "seventh_place"}
    result = []
    for m in sorted(matches, key=lambda x: x.get("order", 0)):
        if m.get("stage") in placement_stages:
            w = _winner(m)
            result.append({
                "team_a": _team_name(m.get("teamA")),
                "team_b": _team_name(m.get("teamB")),
                "score_a": m.get("scoreA"),
                "score_b": m.get("scoreB"),
                "score_display": _score_display(m),
                "sets": m.get("sets") or [],
                "shootout": m.get("shootout"),
                "match_number": m.get("matchNumber", ""),
                "winner": w,
                "stage_label": STAGE_LABELS.get(m.get("stage", ""), ""),
                "time": m.get("startTime", ""),
            })
    return result


# ──────────── Build template context ────────────

def _build_context(req: FinalReportRequest) -> Dict[str, Any]:
    schedule = req.schedule
    config = schedule.get("config") or {}
    matches: List[Dict[str, Any]] = schedule.get("matches") or []
    days: List[Dict[str, Any]] = config.get("days") or []
    mode = config.get("mode", "roundRobin")
    accent = _get_accent(req.category)

    # Logo
    logo_b64 = _load_logo_b64()

    # Date range
    date_range = req.tournament_dates.strip() or _compute_date_range(days)

    # Summary
    total_matches = len([m for m in matches if m.get("scoreA") is not None])
    all_team_ids: set = set()
    for m in matches:
        for slot in ("teamA", "teamB"):
            t = m.get(slot)
            if t and t.get("id"):
                all_team_ids.add(t["id"])

    genders_present = set(m.get("gender", "M") for m in matches)
    men_count = len(set(
        t["id"] for m in matches if m.get("gender") == "M"
        for slot in ("teamA", "teamB")
        if (t := m.get(slot)) and t.get("id")
    ))
    women_count = len(set(
        t["id"] for m in matches if m.get("gender") == "K"
        for slot in ("teamA", "teamB")
        if (t := m.get(slot)) and t.get("id")
    ))

    system_name = "każdy z każdym" if mode == "roundRobin" else "grupowym z fazą pucharową"
    summary_parts = [
        f"Turniej zakończony. Rozegrano {total_matches} "
        f"{'mecz' if total_matches == 1 else 'mecze' if 2 <= total_matches <= 4 else 'meczów'} "
        f"w systemie {system_name}.",
    ]
    team_parts = []
    if "M" in genders_present and men_count:
        team_parts.append(f"{men_count} {'drużyna' if men_count == 1 else 'drużyny' if 2 <= men_count <= 4 else 'drużyn'} męskich")
    if "K" in genders_present and women_count:
        team_parts.append(f"{women_count} {'drużyna' if women_count == 1 else 'drużyny' if 2 <= women_count <= 4 else 'drużyn'} żeńskich")
    if team_parts:
        summary_parts.append(f"W turnieju udział wzięło {' oraz '.join(team_parts)}.")
    summary_parts.append("Poniżej przedstawiono szczegółowe wyniki.")
    summary_text = " ".join(summary_parts)

    # Standings lookup by gender
    standings_by_gender: Dict[str, GenderStandingsData] = {}
    if req.standings:
        for sd in req.standings:
            standings_by_gender[sd.gender] = sd

    # Build per-gender sections
    gender_sections = []
    for gender in ["M", "K"]:
        g_matches = [m for m in matches if m.get("gender") == gender]
        if not g_matches:
            continue

        gs: Dict[str, Any] = {
            "gender": gender,
            "gender_label": "Mężczyźni" if gender == "M" else "Kobiety",
            "mode": mode,
            "tables": [],
            "bracket_rounds": [],
            "placement_matches": [],
            "match_days": [],
            "standings": None,
            "standings_is_multi_tournament": False,
            "standings_tournament_count": 1,
        }

        # ── Tables ──
        if mode == "roundRobin":
            group_matches = [m for m in g_matches if m.get("stage") == "group"]
            if group_matches:
                rows = _compute_group_table(group_matches)
                gs["tables"].append({"group_label": None, "rows": rows})
        else:
            # Groups + knockout
            groups_config = (config.get("groups") or {}).get(gender, {})
            group_teams = groups_config.get("teams", {})
            group_names = sorted(group_teams.keys()) if group_teams else []

            if group_names:
                advancing_per_group = 2  # default: top 2 advance
                for gn in group_names:
                    gm = [
                        m for m in g_matches
                        if m.get("stage") == "group" and m.get("group") == gn
                    ]
                    if gm:
                        rows = _compute_group_table(gm, advancing_per_group)
                        gs["tables"].append({
                            "group_label": f"Grupa {gn}",
                            "rows": rows,
                        })
            else:
                # No explicit groups config — try to detect from match data
                groups_in_matches = sorted(set(
                    m.get("group") for m in g_matches
                    if m.get("stage") == "group" and m.get("group")
                ))
                for gn in groups_in_matches:
                    gm = [
                        m for m in g_matches
                        if m.get("stage") == "group" and m.get("group") == gn
                    ]
                    if gm:
                        rows = _compute_group_table(gm, 2)
                        gs["tables"].append({
                            "group_label": f"Grupa {gn}",
                            "rows": rows,
                        })

            # Bracket
            knockout_matches = [
                m for m in g_matches
                if m.get("stage") in BRACKET_STAGE_ORDER
            ]
            if knockout_matches:
                gs["bracket_rounds"] = _build_bracket_rounds(knockout_matches)

            # Placement
            gs["placement_matches"] = _build_placement_matches(g_matches)

        # ── Match cards by day ──
        by_day: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for m in g_matches:
            by_day[m.get("dayIndex", 0)].append(m)

        for di in sorted(by_day.keys()):
            day_matches = sorted(by_day[di], key=lambda x: (x.get("startTime") or "99:99", x.get("order", 0)))
            day_cfg = days[di] if di < len(days) else {}
            day_date = day_cfg.get("date", "")
            if day_date and len(day_date) >= 10:
                day_label = f"Dzień {di + 1} — {day_date[8:10]}.{day_date[5:7]}.{day_date[:4]}"
            elif len(by_day) > 1:
                day_label = f"Dzień {di + 1}"
            else:
                day_label = ""

            cards = []
            for m in day_matches:
                w = _winner(m)
                cards.append({
                    "time": m.get("startTime", ""),
                    "match_number": m.get("matchNumber", ""),
                    "team_a": _team_name(m.get("teamA")),
                    "team_b": _team_name(m.get("teamB")),
                    "score_a": m.get("scoreA"),
                    "score_b": m.get("scoreB"),
                    "score_display": _score_display(m),
                    "sets": m.get("sets") or [],
                    "shootout": m.get("shootout"),
                    "winner": w,
                    "stage_label": _stage_label(m) if mode != "roundRobin" else "",
                })
            gs["match_days"].append({"label": day_label, "matches": cards})

        # ── Standings ──
        sd = standings_by_gender.get(gender)
        if sd and sd.rows:
            gs["standings"] = [
                {
                    **r.dict(),
                    "total_points": int(r.total_points),
                    "tournament_points": int(r.tournament_points) if r.tournament_points is not None else None,
                }
                for r in sd.rows
            ]
            gs["standings_is_multi_tournament"] = sd.tournament_count > 1
            gs["standings_tournament_count"] = sd.tournament_count

        gender_sections.append(gs)

    now = datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M")

    return {
        "tournament_name": req.tournament_name.strip() or "Turniej",
        "date_range": date_range,
        "location": req.tournament_location.strip(),
        "accent": accent,
        "logo_b64": logo_b64,
        "summary_text": summary_text,
        "gender_sections": gender_sections,
        "generated_at": now,
    }


# ──────────── Endpoints ────────────

@router.post(
    "/beach/report/final",
    summary="Generuj komunikat końcowy turnieju (PDF)",
)
async def generate_final_report(req: FinalReportRequest):
    from jinja2 import Environment, FileSystemLoader
    import weasyprint

    template_path = TEMPLATE_DIR / TEMPLATE_NAME
    if not template_path.exists():
        raise HTTPException(500, detail=f"Brak szablonu: {TEMPLATE_NAME}")

    # Build context
    ctx = _build_context(req)

    # Render HTML
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template(TEMPLATE_NAME)
    html_str = template.render(**ctx)

    # Convert to PDF
    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "report.html")
        pdf_path = os.path.join(tmp_dir, "report.pdf")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        doc = weasyprint.HTML(filename=html_path)
        doc.write_pdf(pdf_path)

        # Save to download dir with token
        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        safe_name = (
            "".join(c if c.isalnum() or c in " _-" else "_" for c in req.tournament_name)[:40]
            or "komunikat"
        )
        download_name = f"komunikat_koncowy_{safe_name}.pdf"
        encoded_name = urllib.parse.quote(download_name)

        return {
            "success": True,
            "download_url": f"/beach/report/final/download/{token}?filename={encoded_name}",
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Final report PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/report/final/download/{token}",
    summary="Pobierz wygenerowany komunikat końcowy (PDF)",
)
async def download_final_report(
    token: str,
    filename: str = Query("komunikat_koncowy.pdf"),
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
