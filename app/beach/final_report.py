"""
Beach Final Report — "Komunikat Końcowy" PDF generation.

Renders an HTML template with Jinja2 and converts to PDF via WeasyPrint.
Contains: header, summary, group/round-robin tables, knockout bracket,
match cards, and standings summary.
"""
from __future__ import annotations

import base64
import html as html_mod
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
    "ninth_semifinal": "Pf. 9-12",
    "thirteenth_semifinal": "Pf. 13-16",
    "final": "Finał",
    "third_place": "O 3. miejsce",
    "fifth_place": "O 5. miejsce",
    "seventh_place": "O 7. miejsce",
    "ninth_place": "O 9. miejsce",
    "eleventh_place": "O 11. miejsce",
    "thirteenth_place": "O 13. miejsce",
    "fifteenth_place": "O 15. miejsce",
    "placement_rr": "O miejsca",
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
    custom_summary: Optional[str] = None


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


def _render_bracket_svg(
    bracket_rounds: List[Dict[str, Any]],
    color: str,
    third_place: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate an inline SVG bracket tree with proper connecting lines.
    Optionally includes a 3rd-place match below the final with dashed connectors."""
    if not bracket_rounds:
        return ""

    # Layout constants (unitless, mapped to pt via viewBox)
    CARD_W = 155
    CARD_H = 44
    CONN_W = 28          # horizontal space for connector lines
    LABEL_H = 18         # space for round label at top
    MATCH_GAP = 14       # vertical gap between first-round matches
    PAD = 6

    num_rounds = len(bracket_rounds)
    first_count = len(bracket_rounds[0]["matches"])

    slot_h = CARD_H + MATCH_GAP

    # Y-centers for first round (evenly spaced)
    y_start = LABEL_H + PAD + CARD_H / 2
    first_centers = [y_start + i * slot_h for i in range(first_count)]

    # Y-centers for subsequent rounds: midpoint of their two source matches
    all_centers: List[List[float]] = [first_centers]
    for r in range(1, num_rounds):
        prev = all_centers[r - 1]
        new_c: List[float] = []
        for m in range(len(bracket_rounds[r]["matches"])):
            a, b = m * 2, m * 2 + 1
            if b < len(prev):
                new_c.append((prev[a] + prev[b]) / 2)
            else:
                new_c.append(prev[a])
        all_centers.append(new_c)

    # X position of each round column
    round_x: List[float] = [0.0]
    for i in range(1, num_rounds):
        round_x.append(round_x[-1] + CARD_W + CONN_W)

    total_w = round_x[-1] + CARD_W
    max_y = max(max(c) for c in all_centers) + CARD_H / 2 + PAD
    total_h = max(LABEL_H + PAD + first_count * slot_h + PAD, max_y)

    parts: List[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{total_w}pt" height="{total_h}pt" '
        f'viewBox="0 0 {total_w} {total_h}" '
        f'style="font-family: DejaVu Sans, sans-serif; display: block;">'
    )

    # ── Connector lines (drawn first, behind cards) ──
    for r_idx in range(num_rounds - 1):
        curr = all_centers[r_idx]
        nxt = all_centers[r_idx + 1]
        x_right = round_x[r_idx] + CARD_W   # right edge of current cards
        x_left = round_x[r_idx + 1]          # left edge of next cards
        x_mid = (x_right + x_left) / 2

        for ni in range(len(nxt)):
            ai, bi = ni * 2, ni * 2 + 1
            y_a = curr[ai]
            y_b = curr[bi] if bi < len(curr) else y_a
            y_m = nxt[ni]

            if bi < len(curr):
                # Horizontal from match A (right edge) to midpoint
                parts.append(
                    f'<line x1="{x_right}" y1="{y_a}" '
                    f'x2="{x_mid}" y2="{y_a}" stroke="#bbb" stroke-width="1"/>'
                )
                # Horizontal from match B (right edge) to midpoint
                parts.append(
                    f'<line x1="{x_right}" y1="{y_b}" '
                    f'x2="{x_mid}" y2="{y_b}" stroke="#bbb" stroke-width="1"/>'
                )
                # Vertical connecting A-center to B-center at midpoint
                parts.append(
                    f'<line x1="{x_mid}" y1="{y_a}" '
                    f'x2="{x_mid}" y2="{y_b}" stroke="#bbb" stroke-width="1"/>'
                )
                # Horizontal from midpoint to next round card
                parts.append(
                    f'<line x1="{x_mid}" y1="{y_m}" '
                    f'x2="{x_left}" y2="{y_m}" stroke="#bbb" stroke-width="1"/>'
                )
            else:
                # Single source → straight horizontal
                parts.append(
                    f'<line x1="{x_right}" y1="{y_a}" '
                    f'x2="{x_left}" y2="{y_m}" stroke="#bbb" stroke-width="1"/>'
                )

    # ── Round labels and match cards ──
    for r_idx, rnd in enumerate(bracket_rounds):
        rx = round_x[r_idx]

        # Round label
        parts.append(
            f'<text x="{rx + CARD_W / 2}" y="{LABEL_H - 4}" '
            f'text-anchor="middle" font-size="7" font-weight="900" '
            f'fill="{color}" letter-spacing="0.5">'
            f'{html_mod.escape(rnd["label"].upper())}</text>'
        )

        for m_idx, match in enumerate(rnd["matches"]):
            cy = all_centers[r_idx][m_idx]
            y = cy - CARD_H / 2

            has_label = bool(match.get("label"))
            label_h = 13 if has_label else 0
            team_area_h = CARD_H - label_h
            team_h = team_area_h / 2
            name_max_w = CARD_W - 32

            # Card background
            parts.append(
                f'<rect x="{rx}" y="{y}" width="{CARD_W}" height="{CARD_H}" '
                f'rx="3" fill="#fafafa" stroke="#ccc" stroke-width="0.5"/>'
            )

            # Label bar (colored header)
            if has_label:
                esc_lbl = html_mod.escape(match["label"])
                parts.append(
                    f'<rect x="{rx}" y="{y}" width="{CARD_W}" height="{label_h}" '
                    f'rx="3" fill="{color}"/>'
                )
                # Square-off bottom corners under label
                parts.append(
                    f'<rect x="{rx}" y="{y + label_h - 3}" '
                    f'width="{CARD_W}" height="3" fill="{color}"/>'
                )
                parts.append(
                    f'<text x="{rx + CARD_W / 2}" y="{y + label_h - 3.5}" '
                    f'text-anchor="middle" font-size="5" font-weight="800" '
                    f'fill="white" letter-spacing="0.2">{esc_lbl}</text>'
                )

            # Clip paths for team name overflow
            cid_a = f"c{r_idx}{m_idx}a"
            cid_b = f"c{r_idx}{m_idx}b"
            ta_y = y + label_h
            tb_y = ta_y + team_h
            parts.append(
                f'<clipPath id="{cid_a}">'
                f'<rect x="{rx + 5}" y="{ta_y}" width="{name_max_w}" height="{team_h}"/>'
                f'</clipPath>'
            )
            parts.append(
                f'<clipPath id="{cid_b}">'
                f'<rect x="{rx + 5}" y="{tb_y}" width="{name_max_w}" height="{team_h}"/>'
                f'</clipPath>'
            )

            # Team A
            is_wa = match.get("winner") == "A"
            name_a = html_mod.escape(match.get("team_a") or "?")
            sa = match.get("score_a")
            sa_s = str(sa) if sa is not None else ""
            fill_a = color if is_wa else "#333"
            fw_a = "900" if is_wa else "600"
            parts.append(
                f'<text x="{rx + 6}" y="{ta_y + team_h / 2 + 3}" '
                f'font-size="7.5" font-weight="{fw_a}" fill="{fill_a}" '
                f'clip-path="url(#{cid_a})">{name_a}</text>'
            )
            parts.append(
                f'<text x="{rx + CARD_W - 6}" y="{ta_y + team_h / 2 + 3}" '
                f'text-anchor="end" font-size="8" font-weight="900" '
                f'fill="{fill_a}">{sa_s}</text>'
            )

            # Separator line
            parts.append(
                f'<line x1="{rx + 2}" y1="{tb_y}" '
                f'x2="{rx + CARD_W - 2}" y2="{tb_y}" '
                f'stroke="#e0e0e0" stroke-width="0.5"/>'
            )

            # Team B
            is_wb = match.get("winner") == "B"
            name_b = html_mod.escape(match.get("team_b") or "?")
            sb = match.get("score_b")
            sb_s = str(sb) if sb is not None else ""
            fill_b = color if is_wb else "#333"
            fw_b = "900" if is_wb else "600"
            parts.append(
                f'<text x="{rx + 6}" y="{tb_y + team_h / 2 + 3}" '
                f'font-size="7.5" font-weight="{fw_b}" fill="{fill_b}" '
                f'clip-path="url(#{cid_b})">{name_b}</text>'
            )
            parts.append(
                f'<text x="{rx + CARD_W - 6}" y="{tb_y + team_h / 2 + 3}" '
                f'text-anchor="end" font-size="8" font-weight="900" '
                f'fill="{fill_b}">{sb_s}</text>'
            )

    # ── 3rd place match (below final, dashed connectors from SF losers) ──
    if third_place and num_rounds >= 2:
        tp_w = _winner(third_place)
        tp_match = {
            "team_a": _team_name(third_place.get("teamA")),
            "team_b": _team_name(third_place.get("teamB")),
            "score_a": third_place.get("scoreA"),
            "score_b": third_place.get("scoreB"),
            "winner": tp_w,
            "label": "O 3. MIEJSCE",
        }

        # Position: below the final in the final column
        final_col_x = round_x[-1]
        sf_col_idx = num_rounds - 2
        sf_centers = all_centers[sf_col_idx]
        final_center = all_centers[-1][0]

        tp_gap = 20
        final_bottom = final_center + CARD_H / 2
        tp_cy = final_bottom + tp_gap + CARD_H / 2
        tp_y = tp_cy - CARD_H / 2

        # Extend SVG height
        new_h = tp_cy + CARD_H / 2 + PAD
        if new_h > total_h:
            total_h = new_h
            # Update SVG dimensions in the opening tag
            parts[0] = (
                f'<svg xmlns="http://www.w3.org/2000/svg" '
                f'width="{total_w}pt" height="{total_h}pt" '
                f'viewBox="0 0 {total_w} {total_h}" '
                f'style="font-family: DejaVu Sans, sans-serif; display: block;">'
            )

        # Dashed connectors from last SF column to 3rd place
        sf_right = round_x[sf_col_idx] + CARD_W
        final_left = final_col_x
        trunk_x = (sf_right + final_left) / 2
        last_sf_mid = sf_centers[-1] if sf_centers else final_center

        # Vertical dashed trunk from last SF midpoint down to 3rd-place midpoint
        dash_len, gap_len = 3, 3
        dy = last_sf_mid
        while dy < tp_cy:
            seg_end = min(dy + dash_len, tp_cy)
            parts.append(
                f'<line x1="{trunk_x}" y1="{dy}" x2="{trunk_x}" y2="{seg_end}" '
                f'stroke="#bbb" stroke-width="0.8" stroke-dasharray="3,3"/>'
            )
            dy += dash_len + gap_len

        # Horizontal dashed branch from trunk to 3rd-place card
        dx = trunk_x
        while dx < final_col_x:
            seg_end = min(dx + dash_len, final_col_x)
            parts.append(
                f'<line x1="{dx}" y1="{tp_cy}" x2="{seg_end}" y2="{tp_cy}" '
                f'stroke="#bbb" stroke-width="0.8" stroke-dasharray="3,3"/>'
            )
            dx += dash_len + gap_len

        # Render the 3rd place card
        has_label = True
        label_h_tp = 13
        team_area_h = CARD_H - label_h_tp
        team_h = team_area_h / 2
        name_max_w = CARD_W - 32

        parts.append(
            f'<rect x="{final_col_x}" y="{tp_y}" width="{CARD_W}" height="{CARD_H}" '
            f'rx="3" fill="#fafafa" stroke="#ccc" stroke-width="0.5"/>'
        )
        # Label bar
        parts.append(
            f'<rect x="{final_col_x}" y="{tp_y}" width="{CARD_W}" height="{label_h_tp}" '
            f'rx="3" fill="{color}"/>'
        )
        parts.append(
            f'<rect x="{final_col_x}" y="{tp_y + label_h_tp - 3}" '
            f'width="{CARD_W}" height="3" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{final_col_x + CARD_W / 2}" y="{tp_y + label_h_tp - 3.5}" '
            f'text-anchor="middle" font-size="5" font-weight="800" '
            f'fill="white" letter-spacing="0.2">O 3. MIEJSCE</text>'
        )

        # Clip paths
        cid_a = "ctp0a"
        cid_b = "ctp0b"
        ta_y = tp_y + label_h_tp
        tb_y = ta_y + team_h
        parts.append(
            f'<clipPath id="{cid_a}">'
            f'<rect x="{final_col_x + 5}" y="{ta_y}" width="{name_max_w}" height="{team_h}"/>'
            f'</clipPath>'
        )
        parts.append(
            f'<clipPath id="{cid_b}">'
            f'<rect x="{final_col_x + 5}" y="{tb_y}" width="{name_max_w}" height="{team_h}"/>'
            f'</clipPath>'
        )

        # Team A
        is_wa = tp_match["winner"] == "A"
        name_a = html_mod.escape(tp_match["team_a"])
        sa = tp_match["score_a"]
        sa_s = str(sa) if sa is not None else ""
        fill_a = color if is_wa else "#333"
        fw_a = "900" if is_wa else "600"
        parts.append(
            f'<text x="{final_col_x + 6}" y="{ta_y + team_h / 2 + 3}" '
            f'font-size="7.5" font-weight="{fw_a}" fill="{fill_a}" '
            f'clip-path="url(#{cid_a})">{name_a}</text>'
        )
        parts.append(
            f'<text x="{final_col_x + CARD_W - 6}" y="{ta_y + team_h / 2 + 3}" '
            f'text-anchor="end" font-size="8" font-weight="900" '
            f'fill="{fill_a}">{sa_s}</text>'
        )

        # Separator
        parts.append(
            f'<line x1="{final_col_x + 2}" y1="{tb_y}" '
            f'x2="{final_col_x + CARD_W - 2}" y2="{tb_y}" '
            f'stroke="#e0e0e0" stroke-width="0.5"/>'
        )

        # Team B
        is_wb = tp_match["winner"] == "B"
        name_b = html_mod.escape(tp_match["team_b"])
        sb = tp_match["score_b"]
        sb_s = str(sb) if sb is not None else ""
        fill_b = color if is_wb else "#333"
        fw_b = "900" if is_wb else "600"
        parts.append(
            f'<text x="{final_col_x + 6}" y="{tb_y + team_h / 2 + 3}" '
            f'font-size="7.5" font-weight="{fw_b}" fill="{fill_b}" '
            f'clip-path="url(#{cid_b})">{name_b}</text>'
        )
        parts.append(
            f'<text x="{final_col_x + CARD_W - 6}" y="{tb_y + team_h / 2 + 3}" '
            f'text-anchor="end" font-size="8" font-weight="900" '
            f'fill="{fill_b}">{sb_s}</text>'
        )

    parts.append('</svg>')
    return '\n'.join(parts)


def _build_placement_matches(
    matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extract placement matches (semis and finals for 3rd-15th place, plus placement round-robins)."""
    placement_stages = {
        "fifth_semifinal", "ninth_semifinal", "thirteenth_semifinal",
        "third_place", "fifth_place", "seventh_place",
        "ninth_place", "eleventh_place", "thirteenth_place", "fifteenth_place",
        "placement_rr",
    }
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
    multi_gender = len(genders_present) > 1
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
    summary_text = req.custom_summary.strip() if req.custom_summary else " ".join(summary_parts)

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
            "gender_color": ("#2BA8A0" if gender == "M" else "#E85A78") if multi_gender else accent,
            "mode": mode,
            "tables": [],
            "bracket_rounds": [],
            "bracket_svg": "",
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
            third_place_match = next(
                (m for m in g_matches if m.get("stage") == "third_place"), None
            )
            if knockout_matches:
                gs["bracket_rounds"] = _build_bracket_rounds(knockout_matches)
                gs["bracket_svg"] = _render_bracket_svg(
                    gs["bracket_rounds"], gs["gender_color"],
                    third_place=third_place_match,
                )

        # ── Match cards by day ──
        by_day: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for m in g_matches:
            by_day[m.get("dayIndex", 0)].append(m)

        def _match_num_sort_key(x: Dict[str, Any]):
            mn = x.get("matchNumber") or ""
            # Extract trailing number after last '/'
            parts = mn.rsplit("/", 1)
            try:
                num = int(parts[-1])
            except (ValueError, IndexError):
                num = 999999
            prefix = parts[0] if len(parts) > 1 else ""
            return (prefix, num, x.get("order", 0))

        for di in sorted(by_day.keys()):
            day_matches = sorted(by_day[di], key=_match_num_sort_key)
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
            standing_rows = [
                {
                    **r.dict(),
                    "total_points": int(r.total_points),
                    "tournament_points": int(r.tournament_points) if r.tournament_points is not None else None,
                }
                for r in sd.rows
            ]
            # Only include standings if at least one team has points > 0
            if any(sr["total_points"] > 0 for sr in standing_rows):
                gs["standings"] = standing_rows
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
        "multi_gender": multi_gender,
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

    # Diagnostic logging for page-break debugging
    for gs in ctx.get("gender_sections", []):
        g = gs.get("gender", "?")
        n_days = len(gs.get("match_days", []))
        day_details = []
        for d in gs.get("match_days", []):
            day_details.append(f"{d.get('label', 'no-label')}:{len(d.get('matches', []))} matches")
        logger.info(
            f"[FinalReport] gender={g} tables={len(gs.get('tables', []))} "
            f"bracket={'yes' if gs.get('bracket_svg') else 'no'} "
            f"match_days={n_days} [{', '.join(day_details)}] "
            f"standings={'yes' if gs.get('standings') else 'no'}"
        )

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
