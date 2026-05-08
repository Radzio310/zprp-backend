"""
Generuje surowe protokoły meczowe beach handball z szablonu xlsx.

Szablon (app/templates/beach_protocol_template.xlsx):
  Kategoria (krzyżyk "X"):
    Senior M → M5,  Senior K → P5
    Junior M → M6,  Junior K → P6
    Junior mł. M → M7,  Junior mł. K → P7
    Młodzik M → M8,  Młodzik K → P8
  S6  – numer meczu
  B10 – nazwa drużyny gospodarzy
  G10 – nazwa drużyny gości
  B12 – miejsce zawodów (miasto)
  C12 – data (DD.MM.YYYY)
  F12 – godzina meczu
  Zawodnicy gospodarzy: wiersze 15-30  (A=numer, B=NAZWISKO Imię)  max 16
  Zawodnicy gości:      wiersze 38-53  (A=numer, B=NAZWISKO Imię)  max 16
  Osoby towarzyszące gospodarzy: wiersze 31-34 (B=pełne imię i nazwisko)
  Osoby towarzyszące gości:      wiersze 54-57 (B=pełne imię i nazwisko)
  Sędzia boiskowy 1:  B61 (Nazwisko Imię), C61 (miasto)
  Sędzia boiskowy 2:  B62 (Nazwisko Imię), C62 (miasto)
  Sekretarz:           B64 (Nazwisko Imię), C64 (miasto)
  Mierzący czas:       B65 (Nazwisko Imię), C65 (miasto)
  Sędzia główny/delegat: B67 (Nazwisko Imię), C67 (miasto)
"""
import json as _json
import logging
import os
import shutil
import tempfile
import urllib.parse
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Path as ApiPath, Query
from fastapi.responses import FileResponse
from openpyxl import load_workbook
from pydantic import BaseModel
from sqlalchemy import select
from starlette.background import BackgroundTask

from app.db import database, beach_teams, beach_tournaments, beach_users
from app.beach.schedule_pdf import _convert_xlsx_to_pdf

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Beach Protocol"])

TEMPLATE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "templates", "beach_protocol_template.xlsx")
)

DOWNLOAD_DIR = "/tmp/beach_protocol_downloads"

# ── category → cell mapping ──────────────────────────────────────────────────

CATEGORY_CELL: Dict[Tuple[str, str], str] = {
    ("Senior", "M"):       "M5",
    ("Senior", "K"):       "P5",
    ("Junior", "M"):       "M6",
    ("Junior", "K"):       "P6",
    ("Junior mł.", "M"):   "M7",
    ("Junior mł.", "K"):   "P7",
    ("Młodzik", "M"):      "M8",
    ("Młodzik", "K"):      "P8",
}

# ── host player rows 15-30, guest 38-53 ──
HOST_PLAYER_ROWS = list(range(15, 31))     # 15..30 inclusive (16 slots)
GUEST_PLAYER_ROWS = list(range(38, 54))    # 38..53 inclusive (16 slots)
HOST_COMPANION_ROWS = list(range(31, 35))  # 31..34 inclusive (4 slots)
GUEST_COMPANION_ROWS = list(range(54, 58)) # 54..57 inclusive (4 slots)


# ── request models ────────────────────────────────────────────────────────────

class ProtocolBulkRequest(BaseModel):
    schedule: Dict[str, Any]
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_id: Optional[int] = None
    category: str = ""               # "Senior", "Junior", "Junior mł", "Młodzik"
    format: str = "xlsx"             # "xlsx" | "pdf"


class ProtocolSingleRequest(BaseModel):
    match: Dict[str, Any]
    schedule_config: Dict[str, Any]  # config with days
    tournament_name: str = ""
    tournament_location: str = ""
    tournament_id: Optional[int] = None
    category: str = ""
    format: str = "xlsx"


# ── helpers ───────────────────────────────────────────────────────────────────

def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _parse_data_json(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return _json.loads(raw)
        except Exception:
            return {}
    return {}


async def _fetch_tournament_data(tournament_id: int) -> dict:
    """Fetch data_json from beach_tournaments."""
    row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(
            beach_tournaments.c.id == tournament_id
        )
    )
    if not row:
        return {}
    return _parse_data_json(row["data_json"])


async def _fetch_team_rosters(team_ids: List[int]) -> Dict[int, dict]:
    """Fetch roster_json, companions_json, jersey_overrides, team_name for given team IDs."""
    if not team_ids:
        return {}
    rows = await database.fetch_all(
        select(
            beach_teams.c.id,
            beach_teams.c.team_name,
            beach_teams.c.roster_json,
            beach_teams.c.companions_json,
            beach_teams.c.jersey_overrides,
        ).where(beach_teams.c.id.in_(team_ids))
    )
    return {
        r["id"]: {
            "team_name": r["team_name"],
            "roster_json": r["roster_json"] or [],
            "companions_json": r["companions_json"] or [],
            "jersey_overrides": r["jersey_overrides"] or {},
        }
        for r in rows
    }


async def _fetch_user_cities(user_ids: List[int]) -> Dict[int, Tuple[str, str]]:
    """Fetch full_name and city for users by IDs. Returns {id: (full_name, city)}."""
    if not user_ids:
        return {}
    rows = await database.fetch_all(
        select(
            beach_users.c.id,
            beach_users.c.full_name,
            beach_users.c.city,
        ).where(beach_users.c.id.in_(user_ids))
    )
    return {
        r["id"]: (r["full_name"] or "", r["city"] or "")
        for r in rows
    }


def _format_name_protocol(full_name: str) -> str:
    """Format name as 'Nazwisko Imię' for referee cells."""
    parts = full_name.strip().split()
    if len(parts) >= 2:
        return f"{parts[-1]} {' '.join(parts[:-1])}"
    return full_name


def _format_player_name(last_name: str, first_name: str) -> str:
    """Format as 'NAZWISKO Imię'."""
    ln = (last_name or "").strip().upper()
    fn = (first_name or "").strip()
    return f"{ln} {fn}".strip()


def _safe_filename(s: str, max_len: int = 40) -> str:
    return "".join(c if c.isalnum() or c in " _-" else "_" for c in s)[:max_len].strip("_") or "protokol"


def _match_sort_key(m: Dict[str, Any]) -> tuple:
    return (m.get("dayIndex") or 0, m.get("startTime") or "99:99", m.get("order") or 0)


def _match_file_label(m: Dict[str, Any], idx: int) -> str:
    """Generate a filename label for a match protocol."""
    mn = m.get("matchNumber")
    if mn:
        return mn.replace("/", "_").replace("\\", "_")
    # fallback: day + order
    day = (m.get("dayIndex") or 0) + 1
    order = m.get("order", idx)
    team_a = (m.get("teamA") or {}).get("name", "")
    team_b = (m.get("teamB") or {}).get("name", "")
    if team_a and team_b:
        return _safe_filename(f"{team_a}_vs_{team_b}", 50)
    return f"mecz_{idx + 1:03d}"


# ── core: fill a single protocol sheet ────────────────────────────────────────

def _fill_protocol_sheet(
    ws,
    match: Dict[str, Any],
    *,
    tournament_name: str,
    tournament_location: str,
    category: str,
    days: List[Dict[str, Any]],
    team_squads: Dict[str, Any],
    custom_teams: List[Dict[str, Any]],
    team_rosters: Dict[int, dict],
    user_cities: Dict[int, Tuple[str, str]],
    head_judge_id: Optional[int],
) -> None:
    """Fill all protocol cells for a single match."""

    gender = match.get("gender", "")

    # ── Category checkbox ──
    # Normalize category: strip whitespace, ensure "Junior mł." has dot
    cat_norm = category.strip()
    if cat_norm.lower().startswith("junior m") and "mł" in cat_norm.lower():
        cat_norm = "Junior mł."
    cell_key = (cat_norm, gender)
    cell_ref = CATEGORY_CELL.get(cell_key)
    if not cell_ref:
        # fallback: try without dot
        cell_ref = CATEGORY_CELL.get((cat_norm.rstrip("."), gender))
    if cell_ref:
        ws[cell_ref] = "X"

    # ── Match number ──
    match_number = match.get("matchNumber") or ""
    ws["S6"] = match_number

    # ── Team names ──
    team_a = match.get("teamA") or {}
    team_b = match.get("teamB") or {}
    ws["B10"] = team_a.get("name", "")
    ws["G10"] = team_b.get("name", "")

    # ── Venue, date, time ──
    ws["B12"] = tournament_location

    day_index = match.get("dayIndex") or 0
    day_cfg = days[day_index] if day_index < len(days) else {}
    date_str = day_cfg.get("date", "")
    if date_str:
        # Convert YYYY-MM-DD → DD.MM.YYYY
        try:
            parts = date_str.split("-")
            ws["C12"] = f"{parts[2]}.{parts[1]}.{parts[0]}"
        except (IndexError, ValueError):
            ws["C12"] = date_str
    else:
        ws["C12"] = ""

    ws["F12"] = match.get("startTime") or ""

    # ── Players & companions ──
    _fill_team_squad(
        ws,
        team_ref=team_a,
        player_rows=HOST_PLAYER_ROWS,
        companion_rows=HOST_COMPANION_ROWS,
        match_id=match.get("id", ""),
        team_squads=team_squads,
        custom_teams=custom_teams,
        team_rosters=team_rosters,
    )
    _fill_team_squad(
        ws,
        team_ref=team_b,
        player_rows=GUEST_PLAYER_ROWS,
        companion_rows=GUEST_COMPANION_ROWS,
        match_id=match.get("id", ""),
        team_squads=team_squads,
        custom_teams=custom_teams,
        team_rosters=team_rosters,
    )

    # ── Referees ──
    referees = match.get("referees") or {}
    _fill_referee(ws, "B61", "C61", referees.get("fieldA"), user_cities)
    _fill_referee(ws, "B62", "C62", referees.get("fieldB"), user_cities)
    _fill_referee(ws, "B64", "C64", referees.get("tableSecretary"), user_cities)
    _fill_referee(ws, "B65", "C65", referees.get("tableTimer"), user_cities)

    # ── Head judge / delegat ──
    if head_judge_id and head_judge_id in user_cities:
        name, city = user_cities[head_judge_id]
        ws["B67"] = _format_name_protocol(name)
        ws["C67"] = city


def _fill_referee(
    ws, name_cell: str, city_cell: str,
    ref: Optional[Dict[str, Any]],
    user_cities: Dict[int, Tuple[str, str]],
) -> None:
    if not ref:
        return
    ref_id = ref.get("id")
    if ref_id and ref_id in user_cities:
        name, city = user_cities[ref_id]
        ws[name_cell] = _format_name_protocol(name)
        ws[city_cell] = city
    elif ref.get("name"):
        ws[name_cell] = _format_name_protocol(ref["name"])


def _fill_team_squad(
    ws,
    *,
    team_ref: Dict[str, Any],
    player_rows: List[int],
    companion_rows: List[int],
    match_id: str,
    team_squads: Dict[str, Any],
    custom_teams: List[Dict[str, Any]],
    team_rosters: Dict[int, dict],
) -> None:
    """Fill player and companion rows for one team."""
    team_id = team_ref.get("id")
    if not team_id:
        return  # TBD team in knockout — leave empty

    team_id_str = str(team_id)

    # Check if it's a custom team (string ID starting with "ct_" or negative int)
    is_custom = isinstance(team_id, str) and team_id.startswith("ct_")
    if not is_custom:
        try:
            is_custom = int(team_id) < 0
        except (ValueError, TypeError):
            pass

    if is_custom:
        _fill_custom_team_squad(ws, team_id_str, player_rows, companion_rows, custom_teams)
    else:
        _fill_regular_team_squad(
            ws, int(team_id), team_id_str, player_rows, companion_rows,
            match_id, team_squads, team_rosters,
        )


def _fill_custom_team_squad(
    ws,
    team_id: str,
    player_rows: List[int],
    companion_rows: List[int],
    custom_teams: List[Dict[str, Any]],
) -> None:
    """Fill squad from custom_teams data (for manually created teams)."""
    ct = None
    for t in custom_teams:
        if str(t.get("id")) == team_id:
            ct = t
            break
    if not ct:
        return

    # Players: filter by defaultPlayers selection
    all_players = ct.get("players") or []
    default_ids = set(ct.get("defaultPlayers") or [])
    if default_ids:
        selected = [p for p in all_players if p.get("id") in default_ids]
    else:
        selected = all_players

    for i, row in enumerate(player_rows):
        if i < len(selected):
            p = selected[i]
            jersey = p.get("jerseyNumber", "")
            ws.cell(row=row, column=1).value = jersey
            ws.cell(row=row, column=2).value = _format_player_name(
                p.get("lastName", ""), p.get("firstName", "")
            )

    # Companions: filter by defaultCompanions selection
    all_companions = ct.get("companions") or []
    default_comp_ids = set(ct.get("defaultCompanions") or [])
    if default_comp_ids:
        selected_comp = [c for c in all_companions if c.get("id") in default_comp_ids]
    else:
        selected_comp = all_companions

    for i, row in enumerate(companion_rows):
        if i < len(selected_comp):
            c = selected_comp[i]
            ln = (c.get("lastName") or "").strip()
            fn = (c.get("firstName") or "").strip()
            ws.cell(row=row, column=2).value = f"{ln} {fn}".strip()


def _fill_regular_team_squad(
    ws,
    team_id_int: int,
    team_id_str: str,
    player_rows: List[int],
    companion_rows: List[int],
    match_id: str,
    team_squads: Dict[str, Any],
    team_rosters: Dict[int, dict],
) -> None:
    """Fill squad from team_squads selection + roster_json data.

    Analogous to BeachNewMatchScreen.tsx buildPlayers/buildCompanions:
    1. Load ALL players from roster_json
    2. Apply jersey_overrides
    3. If squad selection exists (default_players / match_overrides) → only selected
    4. If no selection → all players from roster (capped at row slots)
    """
    squad_entry = team_squads.get(team_id_str) or {}
    roster_data = team_rosters.get(team_id_int)
    if not roster_data:
        return  # no roster data at all

    roster = roster_data.get("roster_json") or []
    jersey_overrides = roster_data.get("jersey_overrides") or {}
    companions = roster_data.get("companions_json") or []

    # Determine selected player IDs (match override → default → fallback all)
    match_overrides = squad_entry.get("match_overrides") or {}
    match_override = match_overrides.get(match_id) or {}
    selected_player_ids = match_override.get("players") or squad_entry.get("default_players") or []
    selected_companion_ids = match_override.get("companions") or squad_entry.get("default_companions") or []

    # ── Players ──
    if selected_player_ids:
        # Use only selected players, preserving selection order (only those in_squad)
        selected_id_set = set(selected_player_ids)
        id_to_player = {}
        for p in roster:
            pid = p.get("player_id")
            if pid is not None and pid in selected_id_set and pid not in id_to_player and p.get("in_squad", True):
                id_to_player[pid] = p
        ordered_players = [id_to_player[pid] for pid in selected_player_ids if pid in id_to_player]
    else:
        # No selection → fill all in-squad roster players (like BeachNewMatchScreen shows all)
        ordered_players = [p for p in roster if p.get("in_squad", True)]

    for i, row in enumerate(player_rows):
        if i < len(ordered_players):
            p = ordered_players[i]
            pid_str = str(p.get("player_id", ""))
            jersey = jersey_overrides.get(pid_str) or p.get("jersey_number") or ""
            ws.cell(row=row, column=1).value = jersey
            ws.cell(row=row, column=2).value = _format_player_name(
                p.get("last_name", ""), p.get("first_name", "")
            )

    # ── Companions ──
    if selected_companion_ids:
        selected_comp_set = set(selected_companion_ids)
        id_to_comp = {}
        for c in companions:
            cid = c.get("person_id")
            if cid is not None and cid in selected_comp_set and cid not in id_to_comp:
                id_to_comp[cid] = c
        ordered_comps = [id_to_comp[cid] for cid in selected_companion_ids if cid in id_to_comp]
    else:
        # No selection → fill all companions
        ordered_comps = list(companions)

    for i, row in enumerate(companion_rows):
        if i < len(ordered_comps):
            c = ordered_comps[i]
            ws.cell(row=row, column=2).value = c.get("full_name", "")


# ── collect all referee IDs from matches ──────────────────────────────────────

def _collect_referee_ids(matches: List[Dict[str, Any]], head_judge_id: Optional[int]) -> List[int]:
    ids = set()
    for m in matches:
        refs = m.get("referees") or {}
        for slot in ("fieldA", "fieldB", "tableSecretary", "tableTimer"):
            ref = refs.get(slot)
            if ref and ref.get("id"):
                ids.add(int(ref["id"]))
    if head_judge_id:
        ids.add(int(head_judge_id))
    return list(ids)


def _collect_team_ids(matches: List[Dict[str, Any]]) -> List[int]:
    """Collect numeric team IDs (skip custom teams with string/negative IDs)."""
    ids = set()
    for m in matches:
        for slot in ("teamA", "teamB"):
            team = m.get(slot) or {}
            tid = team.get("id")
            if tid is None:
                continue
            try:
                tid_int = int(tid)
                if tid_int > 0:
                    ids.add(tid_int)
            except (ValueError, TypeError):
                pass
    return list(ids)


# ── generate protocol for a single match ──────────────────────────────────────

async def _generate_single_protocol(
    match: Dict[str, Any],
    *,
    tournament_name: str,
    tournament_location: str,
    category: str,
    days: List[Dict[str, Any]],
    team_squads: Dict[str, Any],
    custom_teams: List[Dict[str, Any]],
    team_rosters: Dict[int, dict],
    user_cities: Dict[int, Tuple[str, str]],
    head_judge_id: Optional[int],
    output_format: str,
    out_dir: str,
    file_label: str,
) -> str:
    """Generate a single protocol file (xlsx or pdf). Returns file path."""
    wb = load_workbook(TEMPLATE_PATH)
    ws = wb.active

    _fill_protocol_sheet(
        ws,
        match,
        tournament_name=tournament_name,
        tournament_location=tournament_location,
        category=category,
        days=days,
        team_squads=team_squads,
        custom_teams=custom_teams,
        team_rosters=team_rosters,
        user_cities=user_cities,
        head_judge_id=head_judge_id,
    )

    safe_label = _safe_filename(file_label, 60)
    xlsx_name = f"protokol_{safe_label}.xlsx"
    xlsx_path = os.path.join(out_dir, xlsx_name)
    wb.save(xlsx_path)

    if output_format == "pdf":
        pdf_path = _convert_xlsx_to_pdf(xlsx_path, out_dir)
        return pdf_path
    return xlsx_path


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.post("/beach/protocol/bulk", summary="Generuj surowe protokoły dla wszystkich meczy turnieju")
async def generate_bulk_protocols(req: ProtocolBulkRequest):
    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(500, detail=f"Brak szablonu protokołu: {TEMPLATE_PATH}")

    output_format = req.format.lower()
    if output_format not in ("xlsx", "pdf"):
        raise HTTPException(400, detail="format musi być 'xlsx' lub 'pdf'")

    schedule = req.schedule
    matches: List[Dict[str, Any]] = schedule.get("matches") or []
    config: Dict[str, Any] = schedule.get("config") or {}
    days: List[Dict[str, Any]] = config.get("days") or []

    if not matches:
        raise HTTPException(400, detail="Brak meczy w terminarzu")

    # Sort matches
    matches = sorted(matches, key=_match_sort_key)

    # Fetch tournament data
    data_json: dict = {}
    if req.tournament_id:
        data_json = await _fetch_tournament_data(req.tournament_id)

    team_squads = data_json.get("team_squads") or {}
    custom_teams = data_json.get("custom_teams") or []
    head_judge_id = data_json.get("head_judge_id")

    # Batch-fetch team rosters and referee cities
    team_ids = _collect_team_ids(matches)
    referee_ids = _collect_referee_ids(matches, head_judge_id)

    team_rosters = await _fetch_team_rosters(team_ids)
    user_cities = await _fetch_user_cities(referee_ids)

    tournament_name = req.tournament_name.strip()
    tournament_location = req.tournament_location.strip()
    category = req.category.strip()

    tmp_dir = tempfile.mkdtemp()
    try:
        protocols_dir = os.path.join(tmp_dir, "protocols")
        os.makedirs(protocols_dir)

        file_paths: List[Tuple[str, str]] = []  # (path, filename)

        for idx, m in enumerate(matches):
            file_label = _match_file_label(m, idx)
            path = await _generate_single_protocol(
                m,
                tournament_name=tournament_name,
                tournament_location=tournament_location,
                category=category,
                days=days,
                team_squads=team_squads,
                custom_teams=custom_teams,
                team_rosters=team_rosters,
                user_cities=user_cities,
                head_judge_id=head_judge_id,
                output_format=output_format,
                out_dir=protocols_dir,
                file_label=file_label,
            )
            file_paths.append((path, os.path.basename(path)))

        # Pack into ZIP
        safe_name = _safe_filename(tournament_name, 40) or "protokoly"
        zip_name = f"protokoly_{safe_name}.zip"
        zip_path = os.path.join(tmp_dir, zip_name)

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fpath, fname in file_paths:
                zf.write(fpath, fname)

        # Store with download token
        _ensure_download_dir()
        token = str(uuid.uuid4())
        ext = "zip"
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.{ext}")
        shutil.copyfile(zip_path, download_path)

        encoded_name = urllib.parse.quote(zip_name)
        return {
            "success": True,
            "download_url": f"/beach/protocol/download/{token}?filename={encoded_name}&ext={ext}",
            "match_count": len(file_paths),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Bulk protocol generation failed")
        raise HTTPException(500, detail=str(e))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/beach/protocol/single", summary="Generuj surowy protokół dla jednego meczu")
async def generate_single_protocol(req: ProtocolSingleRequest):
    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(500, detail=f"Brak szablonu protokołu: {TEMPLATE_PATH}")

    output_format = req.format.lower()
    if output_format not in ("xlsx", "pdf"):
        raise HTTPException(400, detail="format musi być 'xlsx' lub 'pdf'")

    match = req.match
    days: List[Dict[str, Any]] = (req.schedule_config or {}).get("days") or []

    # Fetch tournament data
    data_json: dict = {}
    if req.tournament_id:
        data_json = await _fetch_tournament_data(req.tournament_id)

    team_squads = data_json.get("team_squads") or {}
    custom_teams = data_json.get("custom_teams") or []
    head_judge_id = data_json.get("head_judge_id")

    # Fetch rosters and cities
    team_ids = _collect_team_ids([match])
    referee_ids = _collect_referee_ids([match], head_judge_id)

    team_rosters = await _fetch_team_rosters(team_ids)
    user_cities = await _fetch_user_cities(referee_ids)

    tmp_dir = tempfile.mkdtemp()
    try:
        file_label = _match_file_label(match, 0)
        path = await _generate_single_protocol(
            match,
            tournament_name=req.tournament_name.strip(),
            tournament_location=req.tournament_location.strip(),
            category=req.category.strip(),
            days=days,
            team_squads=team_squads,
            custom_teams=custom_teams,
            team_rosters=team_rosters,
            user_cities=user_cities,
            head_judge_id=head_judge_id,
            output_format=output_format,
            out_dir=tmp_dir,
            file_label=file_label,
        )

        ext = "pdf" if output_format == "pdf" else "xlsx"
        download_name = os.path.basename(path)

        _ensure_download_dir()
        token = str(uuid.uuid4())
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.{ext}")
        shutil.copyfile(path, download_path)

        encoded_name = urllib.parse.quote(download_name)
        return {
            "success": True,
            "download_url": f"/beach/protocol/download/{token}?filename={encoded_name}&ext={ext}",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Single protocol generation failed")
        raise HTTPException(500, detail=str(e))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@router.get(
    "/beach/protocol/download/{token}",
    summary="Pobierz wygenerowany protokół/y (attachment)",
)
async def download_protocol(
    token: str = ApiPath(...),
    filename: str = Query("protokol.xlsx"),
    ext: str = Query("xlsx"),
):
    _ensure_download_dir()
    try:
        uuid.UUID(token)
    except ValueError:
        raise HTTPException(400, "Nieprawidłowy token")

    if ext not in ("xlsx", "pdf", "zip"):
        ext = "xlsx"

    file_path = os.path.join(DOWNLOAD_DIR, f"{token}.{ext}")
    if not os.path.exists(file_path):
        raise HTTPException(404, "Plik wygasł lub nie istnieje")

    media_types = {
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pdf": "application/pdf",
        "zip": "application/zip",
    }

    return FileResponse(
        path=file_path,
        media_type=media_types.get(ext, "application/octet-stream"),
        filename=filename,
        background=BackgroundTask(
            lambda: os.remove(file_path) if os.path.exists(file_path) else None
        ),
    )
