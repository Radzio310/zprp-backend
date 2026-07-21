"""
Generuje PDF terminarza turnieju beach handball z szablonu HTML.

Używa Jinja2 + WeasyPrint (tak jak komunikat końcowy).
Automatycznie wybiera orientację:
  • pionową  (portrait)  — max. 20 meczów dziennie
  • poziomą  (landscape) — powyżej 20 meczów dziennie
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
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Path as ApiPath, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from starlette.background import BackgroundTask

from app.db import database, beach_tournaments, beach_users

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach Schedule PDF"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "terminarz.html"
DOWNLOAD_DIR = "/tmp/schedule_pdf_downloads"

_PL_TRANS = str.maketrans("łŁżŻ", "lLzZ")


def _safe_filename_part(s: str, max_len: int = 40) -> str:
    """Transliteruje polskie znaki, zamienia / na _, zachowuje resztę dozwolonych."""
    s = s.translate(_PL_TRANS)
    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(c if c.isalnum() or c in " _-" else "_" for c in s)
    return s[:max_len]


WEEKDAYS_PL = [
    "poniedziałek", "wtorek", "środa",
    "czwartek", "piątek", "sobota", "niedziela",
]
_ROMAN = {
    1: "I", 2: "II", 3: "III", 4: "IV", 5: "V",
    6: "VI", 7: "VII", 8: "VIII", 9: "IX", 10: "X",
}

CATEGORY_COLORS = {
    "Senior": "#E85A30",
    "Junior": "#3A7FBF",
    "Junior mł.": "#2BA8A0",
    "Kadet": "#7A5FC7",
}
DEFAULT_ACCENT = "#E85A30"

# Matches per day above which landscape is used
LANDSCAPE_THRESHOLD = 20


# ─── request model ────────────────────────────────────────────────────────────

class SchedulePdfRequest(BaseModel):
    schedule: Dict[str, Any]
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_dates: str = ""  # optional override; computed from days if empty
    tournament_id: Optional[int] = None   # used to look up judge/host emails
    exclude_user_id: Optional[int] = None  # current user — excluded from recipients
    category: str = ""
    include_groups: bool = True
    split_by_courts: bool = False
    custom_teams: Optional[List[Dict[str, Any]]] = None  # for resolving negative-ID custom teams


# ─── helpers ──────────────────────────────────────────────────────────────────

def _roman(n: int) -> str:
    if n <= 0:
        return str(n)
    vals = [(1000,"M"),(900,"CM"),(500,"D"),(400,"CD"),(100,"C"),(90,"XC"),
            (50,"L"),(40,"XL"),(10,"X"),(9,"IX"),(5,"V"),(4,"IV"),(1,"I")]
    s, rem = "", n
    for v, sym in vals:
        while rem >= v:
            s += sym
            rem -= v
    return s


def _get_accent(category: str) -> str:
    return CATEGORY_COLORS.get(category, DEFAULT_ACCENT)


def _load_logo_b64() -> str:
    """Load the BAZA Beach logo and return as base64 PNG."""
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
    except Exception as e:
        logger.warning("Could not resize logo: %s — using raw bytes", e)
        try:
            return base64.b64encode(logo_path.read_bytes()).decode()
        except Exception:
            return ""


def _load_qr_b64() -> str:
    """Load the BAZA Beach QR code and return as base64 PNG."""
    qr_path = TEMPLATE_DIR / "beach_qr.png"
    if not qr_path.exists():
        return ""
    try:
        from PIL import Image as PILImage
        img = PILImage.open(qr_path)
        # Keep QR square, resize to 200×200 px
        img = img.resize((200, 200), PILImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        logger.warning("Could not load QR: %s — using raw bytes", e)
        try:
            return base64.b64encode(qr_path.read_bytes()).decode()
        except Exception:
            return ""


def _day_header(day_index: int, date_str: Optional[str]) -> str:
    roman = _roman(day_index + 1)
    if date_str:
        try:
            d = date.fromisoformat(date_str)
            weekday = WEEKDAYS_PL[d.weekday()]
            formatted = d.strftime("%d.%m.%Y")
            return f"Dzień {roman}  ·  {formatted}  ({weekday})"
        except Exception:
            pass
    return f"Dzień {roman}"


# Font PDF-ów (DejaVu Sans) nie zawiera glifów emoji — renderują się jako
# prostokąt (tofu). Mapujemy emoji zdarzeń na monochromatyczne symbole, które
# DejaVu Sans zawiera. Działa też dla już zapisanych zdarzeń (mapowanie przy
# renderowaniu). Nieznane emoji → punktor "•".
_PDF_EVENT_SYMBOLS: Dict[str, str] = {
    "🎯": "◎",  # shoot-out contest — bullseye
    "🏆": "★", "🏅": "★", "⭐": "★", "🌟": "★",
    "✨": "◆", "🎁": "◆", "📣": "◆", "📢": "◆",
    "📷": "◆", "📸": "◆", "🍽️": "◆", "🍽": "◆",
    "🎵": "♪", "🎶": "♪", "🎤": "♪",
    "☀️": "☀", "☀": "☀",
    "👥": "●", "🤝": "●",
    "🎉": "★", "🎊": "★",
}


def _pdf_event_symbol(emoji: Optional[str]) -> str:
    """Emoji → symbol renderowalny w DejaVu Sans (pusty string, gdy brak)."""
    if not emoji:
        return ""
    return _PDF_EVENT_SYMBOLS.get(emoji, "•")


def _compute_date_range(days: List[Dict[str, Any]]) -> str:
    dates = sorted(d.get("date", "") for d in days if d.get("date"))
    if not dates:
        return ""
    fmt = lambda iso: f"{iso[8:10]}.{iso[5:7]}.{iso[:4]}" if len(iso) >= 10 else iso
    if len(dates) == 1:
        return fmt(dates[0])
    return f"{fmt(dates[0])}–{fmt(dates[-1])}"


def _resolve_mode(config: Optional[Dict[str, Any]], gender: str) -> str:
    """Per-gender play system, falling back to the shared `mode`."""
    config = config or {}
    per = config.get("modeM") if gender == "M" else config.get("modeK")
    return per or config.get("mode") or "groupsPlusKnockout"


def _stage_label(
    m: Dict[str, Any],
    placement_rr_labels: Optional[Dict[str, str]] = None,
    is_global_tour: bool = False,
) -> str:
    stage = m.get("stage", "")
    group = m.get("group") or ""
    if stage == "group":
        # Global Tour uses a single group → label it "Global" instead of "Grupa A".
        if is_global_tour:
            return "Global"
        return f"Grupa {group}" if group else "Każdy z każdym"
    if stage == "placement_rr":
        if placement_rr_labels and group in placement_rr_labels:
            return placement_rr_labels[group]
        return "O miejsca"
    return {
        "quarterfinal": "Ćwierćfinał",
        "semifinal": "Półfinał",
        "final": "Finał",
        "third_place": "3. miejsce",
        "fifth_place": "5. miejsce",
        "seventh_place": "7. miejsce",
        "fifth_semifinal": "PF o V.",
        "ninth_semifinal": "PF o IX.",
        "ninth_place": "9. miejsce",
        "eleventh_place": "11. miejsce",
        "thirteenth_semifinal": "PF o XIII.",
        "thirteenth_place": "13. miejsce",
        "fifteenth_place": "15. miejsce",
        "playoff": "Baraż",
    }.get(stage, stage)


import math as _math


def _compute_placement_rr_labels(
    matches: List[Dict[str, Any]],
) -> Dict[str, str]:
    """Return a dict mapping placement_rr group name → place range label.

    E.g. "placement_7_K" → "O msc. VII-IX"
    """
    labels: Dict[str, str] = {}

    for m in matches:
        if m.get("stage") != "placement_rr":
            continue
        g = m.get("group") or ""
        if g in labels:
            continue
        # Matches both "placement_12_M" (RR) and "placement_quad_12_M" (bracket)
        gm = re.match(r"placement_(?:quad_)?(\d+)", g)
        if not gm:
            continue
        tier = int(gm.group(1))
        is_quad = "quad" in g

        if is_quad:
            # 4-team mini-bracket — always 4 teams regardless of match count
            num_teams = 4
        else:
            # Round-robin: derive team count from match count via triangular formula
            n_matches = sum(
                1
                for m2 in matches
                if m2.get("stage") == "placement_rr"
                and m2.get("group") == g
            )
            num_teams = round((1 + _math.sqrt(1 + 8 * n_matches)) / 2) if n_matches > 0 else 3

        start_place = tier
        end_place = tier + num_teams - 1

        start_r = _roman(start_place)
        end_r = _roman(end_place)
        labels[g] = f"O msc. {start_r}-{end_r}" if start_place != end_place else f"O msc. {start_r}"

    return labels


def _category_label(m: Dict[str, Any]) -> str:
    g = m.get("gender", "")
    return "M" if g == "M" else "K" if g == "K" else ""


def _team_name(team: Optional[Dict[str, Any]]) -> str:
    if team and team.get("name"):
        return str(team["name"])
    return ""


def _knockout_hints(m: Dict[str, Any]) -> tuple:
    """Extract per-slot knockout hints from knockoutLabel ('X vs Y').

    Returns (hint_a, hint_b) — empty strings when team is already known.
    """
    team_a = m.get("teamA")
    team_b = m.get("teamB")
    label = m.get("knockoutLabel") or ""
    if not label:
        return "", ""
    parts = label.split(" vs ", 1)
    hint_a = parts[0].strip() if not (team_a and team_a.get("name")) else ""
    hint_b = (parts[1].strip() if len(parts) > 1 else "") if not (team_b and team_b.get("name")) else ""
    # Strip stage prefix from hints — the stage column already identifies the round.
    # Handles: "Baraż: 2. z gr. A" and "Baraż N. miejsc: 3. z gr. B"
    for prefix in ("Baraż: ", ):
        if hint_a.startswith(prefix):
            hint_a = hint_a[len(prefix):]
        if hint_b.startswith(prefix):
            hint_b = hint_b[len(prefix):]
    # "Baraż N. miejsc: X" → strip everything up to and including ": "
    hint_a = re.sub(r"^Bara\u017c\s+\d+\.\s*miejsc:\s*", "", hint_a)
    hint_b = re.sub(r"^Bara\u017c\s+\d+\.\s*miejsc:\s*", "", hint_b)
    # Strip placement RR prefix: "O msc. VII-IX: 3. z gr. A" → "3. z gr. A"
    hint_a = re.sub(r"^O msc\.\s*[^:]+:\s*", "", hint_a)
    hint_b = re.sub(r"^O msc\.\s*[^:]+:\s*", "", hint_b)
    return hint_a, hint_b


# Stage abbreviation → stage key mapping for resolving knockout references
_STAGE_ABBREV = {
    "ĆF": "quarterfinal",
    "PF": "semifinal",
    "SM5": "fifth_semifinal",
    "9PF": "ninth_semifinal",
    "13PF": "thirteenth_semifinal",
}


def _resolve_hint_with_match_nums(hint: str, stage_num_map: Dict[str, Dict[int, str]]) -> str:
    """Replace stage-based references like 'Zwycięzca ĆF #1' → 'Zwycięzca M15'.

    Also handles tier-specific placement references like 'Zwycięzca 12PF #1' → 'Zwycięzca M21'.
    Group-position references ('1. z gr. A') are left as-is.
    """
    if not hint:
        return hint
    def _replacer(match_obj):
        prefix = match_obj.group(1)   # e.g. "Zwycięzca " or "Przegrany "
        abbrev = match_obj.group(2)   # e.g. "ĆF", "PF", "SM5", "12PF"
        num_str = match_obj.group(3)  # e.g. "1", "2"
        num = int(num_str)
        # Handle tier-specific placement references like "12PF" (not in _STAGE_ABBREV)
        tier_m = re.match(r'^(\d+)PF$', abbrev, re.IGNORECASE)
        if tier_m and abbrev.upper() not in _STAGE_ABBREV:
            tier = tier_m.group(1)
            stage_key = f"placement_rr_{tier}"
            match_label = stage_num_map.get(stage_key, {}).get(num)
            if match_label:
                return f"{prefix}{match_label}"
            return match_obj.group(0)
        stage_key = _STAGE_ABBREV.get(abbrev)
        if not stage_key:
            return match_obj.group(0)
        match_label = stage_num_map.get(stage_key, {}).get(num)
        if match_label:
            return f"{prefix}{match_label}"
        return match_obj.group(0)
    # Pattern: (Zwycięzca|Przegrany) (ĆF|PF|SM5|9PF|13PF|12PF|…) #(\d+)
    return re.sub(r'(Zwycięzca |Przegrany )(ĆF|PF|SM5|\d+PF) #(\d+)', _replacer, hint)


def _gender_label(gender: str) -> str:
    return "Mężczyźni" if gender == "M" else "Kobiety" if gender == "K" else gender


def _build_group_previews(
    matches: List[Dict[str, Any]],
    config: Dict[str, Any],
    custom_teams: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    knockout_stages = {
        "quarterfinal",
        "semifinal",
        "fifth_semifinal",
        "ninth_semifinal",
        "thirteenth_semifinal",
        "final",
        "third_place",
        "fifth_place",
        "seventh_place",
        "ninth_place",
        "eleventh_place",
        "thirteenth_place",
        "fifteenth_place",
    }
    has_knockout = any(m.get("stage") in knockout_stages for m in matches)
    if not has_knockout:
        return []

    team_names: Dict[int, str] = {}
    fallback_groups: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    seen_fallback = set()

    # Pre-populate names for custom teams (negative IDs) from the custom_teams list
    if custom_teams:
        for idx, ct in enumerate(custom_teams):
            if not isinstance(ct, dict):
                continue
            ct_name = ct.get("name")
            if ct_name:
                team_names[-(idx + 1)] = str(ct_name)

    for m in matches:
        gender = m.get("gender") or ""
        group = m.get("group") or ""
        for team in (m.get("teamA"), m.get("teamB")):
            if not isinstance(team, dict) or team.get("id") is None:
                continue
            try:
                team_id = int(team["id"])
            except (TypeError, ValueError):
                continue
            name = _team_name(team)
            if name:
                # For custom teams (negative IDs) already pre-seeded from the
                # custom_teams list, prefer the pre-seeded name (it's up-to-date).
                # For positive (real) IDs, always take the match name.
                if team_id >= 0 or team_id not in team_names:
                    team_names[team_id] = name
            if m.get("stage") == "group" and gender and group:
                key = (gender, group, team_id)
                if key not in seen_fallback:
                    resolved_name = team_names.get(team_id) or name or f"#{team_id}"
                    fallback_groups[gender][group].append(
                        {"id": team_id, "name": resolved_name}
                    )
                    seen_fallback.add(key)

    previews: List[Dict[str, Any]] = []
    groups_cfg = config.get("groups") or {}

    for gender in ("M", "K"):
        is_global_tour = _resolve_mode(config, gender) == "globalTour"
        gender_cfg = groups_cfg.get(gender) or {}
        cfg_teams = gender_cfg.get("teams") or {}
        group_names = sorted(
            set(cfg_teams.keys()) | set(fallback_groups.get(gender, {}).keys())
        )
        groups_out: List[Dict[str, Any]] = []

        for group_name in group_names:
            teams_out: List[Dict[str, Any]] = []
            configured_ids = cfg_teams.get(group_name) or []
            fallback = fallback_groups.get(gender, {}).get(group_name, [])

            # If config.groups has the seeded order, use it as the authoritative ordering.
            # Names come from match data (fallback) — which has patched custom team names.
            # If config.groups is missing, fall back to match-derived order.
            if configured_ids:
                fallback_by_id = {entry["id"]: entry["name"] for entry in fallback}
                configured_set: set[int] = set()
                for raw_id in configured_ids:
                    try:
                        team_id = int(raw_id)
                    except (TypeError, ValueError):
                        continue
                    configured_set.add(team_id)
                    name = (
                        fallback_by_id.get(team_id)
                        or team_names.get(team_id)
                        or f"#{team_id}"
                    )
                    teams_out.append({"id": team_id, "name": name})
                # Append any teams present in matches but missing from config (e.g. extras)
                for entry in fallback:
                    if entry["id"] not in configured_set:
                        teams_out.append(entry)
            elif fallback:
                teams_out = fallback

            if teams_out:
                display_name = "Global" if is_global_tour else f"Grupa {group_name}"
                groups_out.append(
                    {"name": group_name, "display_name": display_name, "teams": teams_out}
                )

        if groups_out:
            previews.append(
                {
                    "gender": gender,
                    "label": _gender_label(gender),
                    "groups": groups_out,
                }
            )

    return previews


def _score_parts(m: Dict[str, Any]) -> tuple:
    """Return (score_main, score_sets) as separate strings."""
    a, b = m.get("scoreA"), m.get("scoreB")
    if a is None or b is None:
        return "", ""
    score_main = f"{a}:{b}"
    sets = m.get("sets") or []
    score_sets = ""
    parts = [
        f"{s.get('ptA', '')}:{s.get('ptB', '')}"
        for s in sets
        if isinstance(s, dict)
    ]
    shootout = m.get("shootout")
    if (
        len(parts) < 3
        and isinstance(shootout, dict)
        and shootout.get("a") is not None
        and shootout.get("b") is not None
    ):
        shootout_score = f"{shootout.get('a', '')}:{shootout.get('b', '')}"
        parts.append(shootout_score)
    if parts:
        score_sets = ", ".join(parts)
    return score_main, score_sets


# ─── context builder ──────────────────────────────────────────────────────────

def _build_context(req: SchedulePdfRequest) -> Dict[str, Any]:
    schedule = req.schedule
    matches: List[Dict[str, Any]] = schedule.get("matches") or []
    config: Dict[str, Any] = schedule.get("config") or {}
    days_cfg: List[Dict[str, Any]] = config.get("days") or []
    courts_count: int = int(config.get("courts") or 1)

    tournament_name = req.tournament_name.strip() or "Turniej"
    date_range = req.tournament_dates.strip() or _compute_date_range(days_cfg)
    location = req.tournament_location.strip()
    accent = _get_accent(req.category)
    logo_b64 = _load_logo_b64()
    qr_b64 = _load_qr_b64()
    group_previews = _build_group_previews(matches, config, req.custom_teams) if req.include_groups else []
    placement_rr_labels = _compute_placement_rr_labels(matches)

    # Group entries by day, sort by time then order
    by_day: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for m in matches:
        by_day[int(m.get("dayIndex") or 0)].append(m)
    for idx in by_day:
        by_day[idx].sort(
            key=lambda m: (m.get("startTime") or "99:99", m.get("order") or 0)
        )

    day_indices = sorted(by_day.keys()) or [0]

    # ── First pass: assign per-gender match numbers (M1, M2, K1, K2…) ──
    gender_counters: Dict[str, int] = {"M": 0, "K": 0}
    # match_id → match_num_label (e.g. "M3", "K12")
    match_num_labels: Dict[str, str] = {}
    # stage_num_map: stage_key → { ordinal_within_gender_stage → match_num_label }
    # e.g. { "quarterfinal": { 1: "M15", 2: "M16", 3: "K13", 4: "K14" } }
    # We track per (stage, gender) ordinals separately
    stage_gender_ordinals: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # stage_key → { (gender, ordinal) → match_num_label }
    stage_num_map_full: Dict[str, Dict[str, Dict[int, str]]] = defaultdict(lambda: defaultdict(dict))

    all_matches_ordered: List[Dict[str, Any]] = []
    for day_idx in day_indices:
        for m in by_day.get(day_idx, []):
            kind = m.get("kind") or "match"
            if kind not in ("court_break", "tournament_opening", "special_event"):
                all_matches_ordered.append(m)

    seq_counter = 0
    seq_num_labels: Dict[str, str] = {}

    for m in all_matches_ordered:
        m_id = m.get("id") or ""
        seq_counter += 1
        if m_id:
            seq_num_labels[m_id] = str(seq_counter)

        gender = m.get("gender") or ""
        if gender in gender_counters:
            gender_counters[gender] += 1
            num = gender_counters[gender]
            label = f"{gender}{num}"
            if m_id:
                match_num_labels[m_id] = label

            stage = m.get("stage") or ""
            if stage:
                stage_gender_ordinals[stage][gender] += 1
                ordinal = stage_gender_ordinals[stage][gender]
                stage_num_map_full[stage][gender][ordinal] = label

    # Build per-gender stage_num_map for hint resolution
    # For each gender, map stage → { ordinal → match_num_label }
    stage_num_map_M: Dict[str, Dict[int, str]] = {
        stage: genders.get("M", {})
        for stage, genders in stage_num_map_full.items()
    }
    stage_num_map_K: Dict[str, Dict[int, str]] = {
        stage: genders.get("K", {})
        for stage, genders in stage_num_map_full.items()
    }

    # Build per-tier placement maps for "12PF", "9PF"-style references in knockoutLabels.
    # These point to round=1 matches within "placement_quad_{tier}_{gender}" groups.
    # Key added to stage_num_map_M/K: "placement_rr_{tier}" → { ordinal → label }
    tier_semis: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for m in all_matches_ordered:
        if (m.get("stage") == "placement_rr"
                and isinstance(m.get("group"), str)
                and m["group"].startswith("placement_quad_")
                and m.get("round") == 1):
            # group format: "placement_quad_{tier}_{gender}"  e.g. "placement_quad_12_M"
            parts = m["group"].split("_")
            if len(parts) >= 4:
                tier_gender_key = f"{parts[2]}:{m.get('gender', '')}"
                tier_semis[tier_gender_key].append(m)
    for tier_gender_key, semis in tier_semis.items():
        tier, gender = tier_gender_key.split(":", 1)
        sorted_semis = sorted(semis, key=lambda x: x.get("order") or 0)
        tier_map: Dict[int, str] = {}
        for idx, sm in enumerate(sorted_semis):
            lbl = match_num_labels.get(sm.get("id") or "")
            if lbl:
                tier_map[idx + 1] = lbl
        stage_key = f"placement_rr_{tier}"
        if gender == "M":
            stage_num_map_M[stage_key] = tier_map
        elif gender == "K":
            stage_num_map_K[stage_key] = tier_map

    # ── Second pass: build day sections with match numbers ──
    days_out: List[Dict[str, Any]] = []
    for day_idx in day_indices:
        day_matches = by_day.get(day_idx, [])
        day_cfg_item = days_cfg[day_idx] if day_idx < len(days_cfg) else {}
        day_label = _day_header(day_idx, day_cfg_item.get("date"))

        match_rows = []
        for m in day_matches:
            kind = m.get("kind") or "match"

            if kind == "court_break":
                match_rows.append({
                    "type": "court_break",
                    "time": m.get("startTime") or "",
                    "end_time": m.get("endTime") or "",
                    "court": str(m.get("court") or ""),
                    "label": m.get("label") or "Przerwa",
                    "duration": m.get("durationMinutes") or 0,
                })
                continue

            if kind == "tournament_opening":
                match_rows.append({
                    "type": "tournament_opening",
                    "time": m.get("startTime") or "",
                    "end_time": m.get("endTime") or "",
                    "label": m.get("label") or "Otwarcie turnieju",
                    "duration": m.get("durationMinutes") or 0,
                })
                continue

            if kind == "special_event":
                court_val = m.get("court")
                all_courts = court_val in (0, "0", None, "")
                match_rows.append({
                    "type": "special_event",
                    "time": m.get("startTime") or "",
                    "end_time": m.get("endTime") or "",
                    "court": "" if all_courts else str(court_val),
                    "all_courts": all_courts,
                    "label": m.get("label") or "Wydarzenie",
                    "symbol": _pdf_event_symbol(m.get("emoji")),
                    "duration": m.get("durationMinutes") or 0,
                })
                continue

            gender = m.get("gender") or ""
            m_id = m.get("id") or ""
            match_num = match_num_labels.get(m_id, "")

            sm, ss = _score_parts(m)
            ha, hb = _knockout_hints(m)
            # Resolve knockout references (ĆF #1 → M15) using same-gender map
            snm = stage_num_map_M if gender == "M" else stage_num_map_K
            ha = _resolve_hint_with_match_nums(ha, snm)
            hb = _resolve_hint_with_match_nums(hb, snm)

            match_rows.append({
                "type": "match",
                "time": m.get("startTime") or "",
                "court": str(m.get("court") or ""),
                "match_num": match_num,
                "seq_num": seq_num_labels.get(m_id, ""),
                "gender": gender,
                "stage": _stage_label(m, placement_rr_labels, _resolve_mode(config, gender) == "globalTour"),
                "team_a": _team_name(m.get("teamA")),
                "team_b": _team_name(m.get("teamB")),
                "hint_a": ha,
                "hint_b": hb,
                "score_main": sm,
                "score_sets": ss,
            })

        days_out.append({"label": day_label, "matches": match_rows, "row_count": len(match_rows)})

    # ── Smart page-break: don't force a new page if the next day fits on remaining space ──
    # Uses a heuristic: ~30 match rows fit on one A4 portrait continuation page.
    _ROWS_PER_PAGE = 30
    _HDR_OVERHEAD = 2  # day header + table header in row-equivalents
    for i, day in enumerate(days_out):
        if i == 0:
            day["force_page_break"] = bool(group_previews)
        else:
            prev = days_out[i - 1]
            prev_total = prev["row_count"] + _HDR_OVERHEAD
            overflow = prev_total % _ROWS_PER_PAGE
            if overflow == 0:
                overflow = _ROWS_PER_PAGE
            remaining = _ROWS_PER_PAGE - overflow
            needed = day["row_count"] + _HDR_OVERHEAD
            day["force_page_break"] = needed > remaining

    # If split_by_courts, build per-day sections where each day lists per-court sub-sections
    split_by_courts = req.split_by_courts and courts_count >= 2
    court_sections: List[Dict[str, Any]] = []
    if split_by_courts:
        for day in days_out:
            # Otwarcia i zdarzenia na wszystkie boiska (court 0) idą nad podziałem na boiska
            opening_rows = [
                r for r in day["matches"]
                if r.get("type") == "tournament_opening"
                or (r.get("type") == "special_event" and r.get("all_courts"))
            ]
            courts_out: List[Dict[str, Any]] = []
            for court_num in range(1, courts_count + 1):
                court_matches = [
                    r for r in day["matches"]
                    if r.get("type") != "tournament_opening"
                    and not (r.get("type") == "special_event" and r.get("all_courts"))
                    and str(r.get("court", "")) == str(court_num)
                ]
                if court_matches:
                    courts_out.append({
                        "court_label": f"Boisko {court_num}",
                        "matches": court_matches,
                    })
            if opening_rows or courts_out:
                court_sections.append({
                    "day_label": day["label"],
                    "openings": opening_rows,
                    "courts": courts_out,
                })

    # Always use portrait orientation.
    use_landscape = False

    now = datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M")

    return {
        "tournament_name": tournament_name,
        "date_range": date_range,
        "location": location,
        "accent": accent,
        "logo_b64": logo_b64,
        "qr_b64": qr_b64,
        "use_landscape": use_landscape,
        "days": days_out,
        "group_previews": group_previews,
        "generated_at": now,
        "category": req.category,
        "split_by_courts": split_by_courts,
        "court_sections": court_sections,
    }


# ─── endpoint ─────────────────────────────────────────────────────────────────

def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


async def _get_judge_host_emails(
    tournament_id: int,
    exclude_user_id: Optional[int],
) -> List[str]:
    """Return emails of all judges + hosts for the tournament, excluding exclude_user_id."""
    try:
        row = await database.fetch_one(
            select(beach_tournaments.c.data_json).where(
                beach_tournaments.c.id == tournament_id
            )
        )
        if not row:
            return []
        data_json = row["data_json"]
        if isinstance(data_json, str):
            import json as _json
            data_json = _json.loads(data_json)
        if not isinstance(data_json, dict):
            return []

        host_ids = {
            int(h["id"])
            for h in (data_json.get("hosts") or [])
            if isinstance(h, dict) and h.get("id") is not None
        }
        judge_ids = {
            int(j["id"])
            for j in (data_json.get("judges") or [])
            if isinstance(j, dict) and j.get("id") is not None
        }
        head_judge_id = data_json.get("head_judge_id")
        if isinstance(head_judge_id, int):
            judge_ids.add(head_judge_id)

        all_ids = host_ids | judge_ids
        if exclude_user_id is not None:
            all_ids.discard(int(exclude_user_id))

        if not all_ids:
            return []

        rows = await database.fetch_all(
            select(beach_users.c.email).where(
                beach_users.c.id.in_(list(all_ids))
            )
        )
        return [r["email"] for r in rows if r["email"]]
    except Exception:
        logger.warning(
            "Could not fetch judge/host emails for tournament %s",
            tournament_id,
            exc_info=True,
        )
        return []


@router.post("/beach/schedule/pdf", summary="Generuj PDF terminarza turnieju")
async def generate_schedule_pdf(req: SchedulePdfRequest):
    from jinja2 import Environment, FileSystemLoader
    import weasyprint

    template_path = TEMPLATE_DIR / TEMPLATE_NAME
    if not template_path.exists():
        raise HTTPException(500, detail=f"Brak szablonu terminarza: {TEMPLATE_NAME}")

    ctx = _build_context(req)

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template(TEMPLATE_NAME)
    html_str = template.render(**ctx)

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "terminarz.html")
        pdf_path = os.path.join(tmp_dir, "terminarz.pdf")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)

        doc = weasyprint.HTML(filename=html_path)
        doc.write_pdf(pdf_path)

        safe_name = _safe_filename_part(req.tournament_name) or "terminarz"
        download_name = f"terminarz_{safe_name}.pdf"

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)

        encoded_name = urllib.parse.quote(download_name)

        judge_host_emails: List[str] = []
        if req.tournament_id:
            judge_host_emails = await _get_judge_host_emails(
                req.tournament_id, req.exclude_user_id
            )

        return {
            "success": True,
            "download_url": f"/beach/schedule/pdf/download/{token}?filename={encoded_name}",
            "judge_host_emails": judge_host_emails,
        }
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.exception("Schedule PDF generation failed")
        raise HTTPException(500, detail=str(e))


@router.get(
    "/beach/tournament/{tournament_id}/judge-host-emails",
    summary="Adresy e-mail sędziów i gospodarzy turnieju",
)
async def get_tournament_judge_host_emails(
    tournament_id: int,
    exclude_user_id: Optional[int] = Query(None),
):
    emails = await _get_judge_host_emails(tournament_id, exclude_user_id)
    return {"emails": emails}


@router.get(
    "/beach/schedule/pdf/download/{token}",
    summary="Pobierz wygenerowany PDF terminarza (attachment)",
)
async def download_schedule_pdf(
    token: str = ApiPath(...),
    filename: str = Query("terminarz.pdf"),
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

