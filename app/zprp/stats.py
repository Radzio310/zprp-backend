# app/zprp/stats.py
from __future__ import annotations

import base64
import datetime
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from httpx import AsyncClient

from app.deps import Settings, get_settings, get_rsa_keys
from app.schemas import ZprpStatsScrapeRequest
from app.utils import fetch_with_correct_encoding

router = APIRouter()

logger = logging.getLogger("app.zprp.stats")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ====================
# Helpers
# ====================
_RE_INT = re.compile(r"(\d+)")
_RE_FLOAT = re.compile(r"(\d+[,.]?\d*)")
_RE_LP_DOT = re.compile(r"^\s*(\d+)\.\s*$")


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _clean(s: Any) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()


def _safe_int(s: Any, default: int = 0) -> int:
    m = _RE_INT.search(str(s or ""))
    return int(m.group(1)) if m else default


def _safe_float(s: Any, default: float = 0.0) -> float:
    txt = str(s or "").replace(",", ".")
    m = _RE_FLOAT.search(txt)
    return float(m.group(1)) if m else default


def _decrypt_field(private_key, enc_b64: str) -> str:
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")


async def _login_zprp_and_get_cookies(
    client: AsyncClient, username: str, password: str
) -> Dict[str, str]:
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
    )
    if "/index.php" not in resp_login.url.path:
        raise HTTPException(401, "Logowanie nie powiodło się")
    return dict(resp_login.cookies)


def _parse_select_options(sel) -> List[Tuple[str, str, bool]]:
    out: List[Tuple[str, str, bool]] = []
    if not sel:
        return out
    for opt in sel.find_all("option"):
        val = _clean(opt.get("value", ""))
        lab = _clean(opt.get_text(strip=True))
        if not val and not lab:
            continue
        out.append((val, lab, bool(opt.has_attr("selected"))))
    return out


def _pick_selected(opts: List[Tuple[str, str, bool]]) -> str:
    return next((v for (v, _, sel) in opts if sel and v), "") or next(
        (v for (v, _, _) in opts if v), ""
    )

# ====================
# Meta parsing — shared between sub-pages
# ====================

def _parse_meta_from_strzelec_page(html: str) -> Dict[str, Any]:
    """
    Parse season selector + competition selector from any stats page.
    Returns dict with: seasons, competitions_by_season, current_season_id, current_id_rozgr
    """
    soup = BeautifulSoup(html, "html.parser")

    # --- Season select ---
    season_sel = None
    for sel in soup.find_all("select"):
        name = _clean(sel.get("name", ""))
        if name in ("Filtr_sezon",):
            season_sel = sel
            break
    seasons_raw = _parse_select_options(season_sel) if season_sel else []
    seasons = [{"id": v, "label": lab, "selected": sel} for (v, lab, sel) in seasons_raw if v]

    current_season_id = _pick_selected(seasons_raw)

    # --- Competition select ---
    rozgr_sel = None
    for sel in soup.find_all("select"):
        name = _clean(sel.get("name", ""))
        if name == "IdRozgr":
            rozgr_sel = sel
            break
    rozgr_raw = _parse_select_options(rozgr_sel) if rozgr_sel else []
    competitions = [{"id": v, "label": lab, "selected": sel} for (v, lab, sel) in rozgr_raw if v and lab and lab != "----"]

    current_id_rozgr = _pick_selected(rozgr_raw)

    # Try to extract competition name from bold text before the table
    comp_title = ""
    for tag in soup.find_all(["b", "strong"]):
        txt = _clean(tag.get_text())
        if len(txt) > 5 and not re.match(r"^\d", txt):
            comp_title = txt
            break

    return {
        "seasons": seasons,
        "competitions": competitions,
        "current_season_id": current_season_id,
        "current_id_rozgr": current_id_rozgr,
        "competition_title": comp_title,
    }


# ====================
# Scorers parsing
# ====================

def _parse_scorers_table(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table", attrs={"border": "1"})

    # Find the big data table (has many columns)
    data_table = None
    for tbl in tables:
        headers = [_clean(th.get_text()) for th in tbl.find_all("td")[:5]]
        merged = " ".join(headers)
        if "Nazwisko" in merged or "Bramki" in merged or "Mecze" in merged:
            data_table = tbl
            break

    if data_table is None:
        return []

    scorers = []
    for tr in data_table.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 8:
            continue
        lp_txt = _clean(tds[0].get("title", "") or tds[0].get_text())
        if not re.search(r"\d", lp_txt) and not _RE_LP_DOT.match(_clean(tds[0].get_text())):
            continue
        if "Lp" in lp_txt or "Nazwisko" in _clean(tds[1].get_text()):
            continue

        try:
            lp = _safe_int(lp_txt)
            name = _clean(tds[1].get_text())
            dob = _clean(tds[2].get_text())
            category = _clean(tds[3].get_text())
            position = _clean(tds[4].get_text())
            team = _clean(tds[5].get_text())
            bramki = _safe_int(tds[6].get_text())
            mecze = _safe_int(tds[7].get_text())
            srednia = _safe_float(tds[8].get_text()) if len(tds) > 8 else 0.0
            u = _safe_int(tds[9].get_text()) if len(tds) > 9 else 0
            min2 = _safe_int(tds[10].get_text()) if len(tds) > 10 else 0
            d = _safe_int(tds[11].get_text()) if len(tds) > 11 else 0
            kd = _safe_int(tds[12].get_text()) if len(tds) > 12 else 0
            karne_liczba = _safe_int(tds[13].get_text()) if len(tds) > 13 else 0
            karne_bramki = _safe_int(tds[14].get_text()) if len(tds) > 14 else 0
            karne_skutecznosc = _safe_float(tds[15].get_text()) if len(tds) > 15 else 0.0
            karne_seria_liczba = _safe_int(tds[16].get_text()) if len(tds) > 16 else 0
            karne_seria_bramki = _safe_int(tds[17].get_text()) if len(tds) > 17 else 0
            karne_seria_skutecznosc = _safe_float(tds[18].get_text()) if len(tds) > 18 else 0.0
        except (IndexError, ValueError):
            continue

        if not name:
            continue

        scorers.append({
            "lp": lp,
            "name": name,
            "birth_date": dob,
            "category": category,
            "position": position,
            "team": team,
            "bramki": bramki,
            "mecze": mecze,
            "srednia": srednia,
            "u": u,
            "min2": min2,
            "d": d,
            "kd": kd,
            "karne_liczba": karne_liczba,
            "karne_bramki": karne_bramki,
            "karne_skutecznosc": karne_skutecznosc,
            "karne_seria_liczba": karne_seria_liczba,
            "karne_seria_bramki": karne_seria_bramki,
            "karne_seria_skutecznosc": karne_seria_skutecznosc,
        })

    return scorers


def _parse_teams_filter(html: str) -> List[Dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    for sel in soup.find_all("select"):
        name = _clean(sel.get("name", ""))
        if name == "ID_zespoly":
            opts = _parse_select_options(sel)
            return [
                {"id": v, "label": lab, "selected": s}
                for (v, lab, s) in opts
                if v
            ]
    return []


# ====================
# Team stats parsing
# ====================

def _parse_team_stats_table(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table", attrs={"border": "1"})

    data_table = None
    for tbl in tables:
        tds_txt = [_clean(td.get_text()) for td in tbl.find_all("td")[:8]]
        merged = " ".join(tds_txt)
        if "Mecze" in merged and ("Wygrane" in merged or "Gosp" in merged):
            data_table = tbl
            break

    if data_table is None:
        return []

    teams = []
    for tr in data_table.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 12:
            continue
        lp_txt = _clean(tds[0].get("title", "") or tds[0].get_text())
        try:
            lp = _safe_int(lp_txt)
        except Exception:
            continue
        if lp == 0:
            continue

        try:
            name = _clean(tds[1].get_text())
            mecze = _safe_int(tds[2].get_text())
            mecze_gosp = _safe_int(tds[3].get_text())
            mecze_gosc = _safe_int(tds[4].get_text())
            wygrane = _safe_int(tds[5].get_text())
            wygrane_gosp = _safe_int(tds[6].get_text())
            wygrane_gosc = _safe_int(tds[7].get_text())
            wygrane_rem = _safe_int(tds[8].get_text())
            wygrane_rem_gosp = _safe_int(tds[9].get_text())
            wygrane_rem_gosc = _safe_int(tds[10].get_text())
            bz = _safe_int(tds[11].get_text())
            bz_gosp = _safe_int(tds[12].get_text()) if len(tds) > 12 else 0
            bz_gosc = _safe_int(tds[13].get_text()) if len(tds) > 13 else 0
            bz_srednia = _safe_float(tds[14].get_text()) if len(tds) > 14 else 0.0
            bs = _safe_int(tds[15].get_text()) if len(tds) > 15 else 0
            bs_gosp = _safe_int(tds[16].get_text()) if len(tds) > 16 else 0
            bs_gosc = _safe_int(tds[17].get_text()) if len(tds) > 17 else 0
            bs_srednia = _safe_float(tds[18].get_text()) if len(tds) > 18 else 0.0
            karne_liczba = _safe_int(tds[19].get_text()) if len(tds) > 19 else 0
            karne_liczba_gosp = _safe_int(tds[20].get_text()) if len(tds) > 20 else 0
            karne_liczba_gosc = _safe_int(tds[21].get_text()) if len(tds) > 21 else 0
            karne_bramki = _safe_int(tds[22].get_text()) if len(tds) > 22 else 0
            karne_gosp = _safe_int(tds[23].get_text()) if len(tds) > 23 else 0
            karne_gosc = _safe_int(tds[24].get_text()) if len(tds) > 24 else 0
            karne_skutecznosc = _safe_float(tds[25].get_text()) if len(tds) > 25 else 0.0
        except (IndexError, ValueError):
            continue

        if not name:
            continue

        # Extract team_id from title attribute of lp cell
        team_id = _clean(tds[0].get("title", ""))

        teams.append({
            "lp": lp,
            "team_id": team_id,
            "name": name,
            "mecze": mecze,
            "mecze_gosp": mecze_gosp,
            "mecze_gosc": mecze_gosc,
            "wygrane": wygrane,
            "wygrane_gosp": wygrane_gosp,
            "wygrane_gosc": wygrane_gosc,
            "wygrane_rem": wygrane_rem,
            "wygrane_rem_gosp": wygrane_rem_gosp,
            "wygrane_rem_gosc": wygrane_rem_gosc,
            "bz": bz,
            "bz_gosp": bz_gosp,
            "bz_gosc": bz_gosc,
            "bz_srednia": bz_srednia,
            "bs": bs,
            "bs_gosp": bs_gosp,
            "bs_gosc": bs_gosc,
            "bs_srednia": bs_srednia,
            "karne_liczba": karne_liczba,
            "karne_liczba_gosp": karne_liczba_gosp,
            "karne_liczba_gosc": karne_liczba_gosc,
            "karne_bramki": karne_bramki,
            "karne_gosp": karne_gosp,
            "karne_gosc": karne_gosc,
            "karne_skutecznosc": karne_skutecznosc,
        })

    return teams


# ====================
# League table parsing
# ====================

def _parse_league_table(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")

    # id="table" is the table meant for Excel export
    data_table = soup.find("table", attrs={"id": "table"})
    if data_table is None:
        tables = soup.find_all("table", attrs={"border": "1"})
        for tbl in tables:
            tds_txt = [_clean(td.get_text()) for td in tbl.find_all("td")[:8]]
            merged = " ".join(tds_txt)
            if ("Lp" in merged or "Zw" in merged) and "Bramki" in merged:
                data_table = tbl
                break

    if data_table is None:
        return []

    rows = []
    for tr in data_table.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 8:
            continue

        lp_txt = _clean(tds[0].get_text())
        try:
            lp = _safe_int(lp_txt)
        except Exception:
            continue
        if lp == 0:
            continue

        try:
            name = _clean(tds[1].get_text())

            # Logo: check if tds[2] has an img
            logo_href = ""
            img = tds[2].find("img") if len(tds) > 2 else None
            if img:
                logo_href = _clean(img.get("src", ""))
                td_idx_shift = 1
            else:
                td_idx_shift = 0

            # Adjust column indices based on logo presence
            base = 2 + td_idx_shift
            M = _safe_int(tds[base].get_text()) if len(tds) > base else 0
            Zw = _safe_int(tds[base + 1].get_text()) if len(tds) > base + 1 else 0
            P = _safe_int(tds[base + 2].get_text()) if len(tds) > base + 2 else 0
            Rw = _safe_int(tds[base + 3].get_text()) if len(tds) > base + 3 else 0
            Rp = _safe_int(tds[base + 4].get_text()) if len(tds) > base + 4 else 0
            Zd = _safe_int(tds[base + 5].get_text()) if len(tds) > base + 5 else 0
            St = _safe_int(tds[base + 6].get_text()) if len(tds) > base + 6 else 0
            diff = Zd - St
            # HTML has Zd-St diff at base+7, so pts start at base+8
            pts_zd = _safe_int(tds[base + 8].get_text()) if len(tds) > base + 8 else 0
            pts_st = _safe_int(tds[base + 9].get_text()) if len(tds) > base + 9 else 0

            # Mała tabela columns (may not exist for all rows)
            P_Ex = _safe_int(tds[base + 10].get_text()) if len(tds) > base + 10 else 0
            B_Ex = _safe_int(tds[base + 11].get_text()) if len(tds) > base + 11 else 0
            Zd_Ex = _safe_int(tds[base + 12].get_text()) if len(tds) > base + 12 else 0
            M_Ex = _safe_int(tds[base + 13].get_text()) if len(tds) > base + 13 else 0

        except (IndexError, ValueError):
            continue

        if not name:
            continue

        rows.append({
            "lp": lp,
            "name": name,
            "logo_href": logo_href,
            "M": M,
            "Zw": Zw,
            "P": P,
            "Rw": Rw,
            "Rp": Rp,
            "Zd": Zd,
            "St": St,
            "diff": diff,
            "pts_zd": pts_zd,
            "pts_st": pts_st,
            "P_Ex": P_Ex,
            "B_Ex": B_Ex,
            "Zd_Ex": Zd_Ex,
            "M_Ex": M_Ex,
        })

    return rows


# ====================
# Table type parsing (TabTyp select)
# ====================

def _parse_table_type_select(html: str) -> List[Dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    for sel in soup.find_all("select"):
        if _clean(sel.get("name", "")) == "TabTyp":
            opts = _parse_select_options(sel)
            return [{"id": v, "label": lab, "selected": s} for (v, lab, s) in opts if v]
    return []


# ====================
# Player match history parsing
# ====================

def _parse_player_matches(html: str) -> Dict[str, Any]:
    """
    Parse the player match history page (?a=statystyki&b=zawodnik&NrZawodnika=XXX).
    Returns player info + matches list.
    """
    soup = BeautifulSoup(html, "html.parser")

    # --- Try to find the data table ---
    data_table = None
    for tbl in soup.find_all("table", attrs={"border": "1"}):
        tds_txt = " ".join(_clean(td.get_text()) for td in tbl.find_all("td")[:10])
        if any(kw in tds_txt for kw in ["Sezon", "Mecz", "Wynik", "Gospodarz"]):
            data_table = tbl
            break

    # --- Parse season/competition selects for filter options ---
    filter_seasons: List[Dict] = []
    for sel in soup.find_all("select"):
        if _clean(sel.get("name", "")) == "Filtr_sezon":
            opts = _parse_select_options(sel)
            filter_seasons = [{"id": v, "label": lab} for (v, lab, _) in opts if v]
            break

    if data_table is None:
        return {"player": {}, "filter_seasons": filter_seasons, "matches": []}

    matches = []
    for tr in data_table.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 8:
            continue

        # Detect header rows
        first_txt = _clean(tds[0].get_text())
        if "Sezon" in first_txt or "Lp" in first_txt:
            continue

        # Column detection — the table has variable structure; best-effort parse
        # Typical columns: Sezon/RozgrywkiCode | Data | Gospodarz | Wynik | Gość | B | U | 2' | D | Kd | N
        try:
            season_or_rozgr = _clean(tds[0].get_text())
            if not season_or_rozgr or not re.search(r"\d", season_or_rozgr):
                continue

            date_str = _clean(tds[1].get_text()) if len(tds) > 1 else ""
            home_team = _clean(tds[2].get_text()) if len(tds) > 2 else ""
            result_txt = _clean(tds[3].get_text()) if len(tds) > 3 else ""
            away_team = _clean(tds[4].get_text()) if len(tds) > 4 else ""

            # Extract score: "15 : 20 ( 7 : 10 )" or similar
            score_m = re.search(r"(\d+)\s*:\s*(\d+)", result_txt)
            score_home = _safe_int(score_m.group(1)) if score_m else None
            score_away = _safe_int(score_m.group(2)) if score_m else None
            half_m = re.search(r"\(\s*(\d+)\s*:\s*(\d+)\s*\)", result_txt)
            score_home_half = _safe_int(half_m.group(1)) if half_m else None
            score_away_half = _safe_int(half_m.group(2)) if half_m else None

            # Stats columns at the end
            b = _safe_int(tds[5].get_text()) if len(tds) > 5 else 0
            u = _safe_int(tds[6].get_text()) if len(tds) > 6 else 0
            min2 = _safe_int(tds[7].get_text()) if len(tds) > 7 else 0
            d = _safe_int(tds[8].get_text()) if len(tds) > 8 else 0
            n = _safe_int(tds[9].get_text()) if len(tds) > 9 else 0

        except (IndexError, ValueError):
            continue

        if not home_team and not away_team:
            continue

        matches.append({
            "rozgr": season_or_rozgr,
            "date": date_str,
            "home": home_team,
            "away": away_team,
            "score_home": score_home,
            "score_away": score_away,
            "score_home_half": score_home_half,
            "score_away_half": score_away_half,
            "b": b,
            "u": u,
            "min2": min2,
            "d": d,
            "n": n,
        })

    return {
        "player": {},
        "filter_seasons": filter_seasons,
        "matches": matches,
    }


def _parse_player_search_results_pipe(text: str) -> List[Dict[str, str]]:
    """
    Parse the statystyki_NrZawodnika.php response.
    Format per line: DISPLAY_NAME|PLAYER_ID
    """
    players = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 2:
            continue
        name = _clean(parts[0])
        pid = _clean(parts[1])
        if not name or not pid or not pid.isdigit():
            continue
        # Try to extract birth_date from name, e.g. "KOWALSKI Jan (1990-01-01)"
        dob = ""
        m = re.search(r"\((\d{4}-\d{2}-\d{2})\)", name)
        if m:
            dob = m.group(1)
            name = name[:m.start()].strip()
        players.append({"id": pid, "name": name, "birth_date": dob})
    return players


# ====================
# Sub-page title helper
# ====================

def _extract_competition_title(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for b in soup.find_all("b"):
        txt = _clean(b.get_text())
        # Typical: "II Liga Kobiet gr. 4 (2025/2026)"
        if len(txt) > 5 and re.search(r"[A-Za-zĄ-ź]", txt) and not txt.startswith("<"):
            return txt
    return ""


# ====================
# XLSX proxy helper
# ====================

def _build_xlsx_url(page_type: str, season_id: str, id_rozgr: str) -> str:
    """Build XLSX export URL for a given stats page type."""
    mapping = {
        "strzelec": f"statystyki_strzelec_XLSX.php?Filtr_sezon={season_id}&IdRozgr={id_rozgr}",
        "druzyn": f"statystyki_druzyn_XLSX.php?Filtr_sezon={season_id}&IdRozgr={id_rozgr}",
        "tabela": f"statystyki_tabela_XLSX.php?Filtr_sezon={season_id}&IdRozgr={id_rozgr}",
    }
    return mapping.get(page_type, "")


# ====================
# URL Builder
# ====================

def _stats_url(subpage: str, season_id: str = "", id_rozgr: str = "", extra: Dict[str, str] | None = None) -> str:
    params: Dict[str, str] = {"a": "statystyki", "b": subpage}
    if season_id:
        params["Filtr_sezon"] = season_id
    if id_rozgr:
        params["IdRozgr"] = id_rozgr
    if extra:
        params.update(extra)
    return "/index.php?" + urlencode(params)


# =================================
# Endpoint: POST /zprp/statystyki/meta
# =================================

@router.post("/zprp/statystyki/meta")
async def get_statystyki_meta(
    payload: ZprpStatsScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Returns seasons list + competitions list.
    Uses b=strzelec page as it always has the season + IdRozgr selects.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    season_id = _clean(payload.season_id or "")
    id_rozgr = _clean(payload.id_rozgr or "")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        url = _stats_url("strzelec", season_id=season_id, id_rozgr=id_rozgr)
        _, html = await fetch_with_correct_encoding(client, url, method="GET", cookies=cookies)
        meta = _parse_meta_from_strzelec_page(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            **meta,
        }


# =================================
# Endpoint: POST /zprp/statystyki/zawodnik/search
# =================================

@router.post("/zprp/statystyki/zawodnik/search")
async def search_player(
    payload: ZprpStatsScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Search players by name/surname.
    Proxies to ?a=statystyki&b=zawodnik&szukaj=<query> and parses results.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    query = _clean(payload.search_query or "")
    if not query:
        raise HTTPException(400, "search_query is required")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        # ZPRP uses a dedicated AJAX endpoint for autocomplete
        # POST statystyki_NrZawodnika.php with body s=QUERY
        autocomplete_url = "/statystyki_NrZawodnika.php"
        _, response_text = await fetch_with_correct_encoding(
            client, autocomplete_url, method="POST",
            data={"s": query}, cookies=cookies
        )
        players = _parse_player_search_results_pipe(response_text)

        return {
            "fetched_at": _now_iso(),
            "query": query,
            "players": players,
            "count": len(players),
        }


# =================================
# Endpoint: POST /zprp/statystyki/zawodnik/mecze
# =================================

@router.post("/zprp/statystyki/zawodnik/mecze")
async def get_player_matches(
    payload: ZprpStatsScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Returns match history for a given player (NrZawodnika).
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    zawodnik_id = _clean(payload.zawodnik_id or "")
    if not zawodnik_id:
        raise HTTPException(400, "zawodnik_id is required")

    season_id = _clean(payload.season_id or "")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        extra: Dict[str, str] = {"NrZawodnika": zawodnik_id}
        if season_id:
            extra["Filtr_sezon"] = season_id
        url = "/index.php?" + urlencode({"a": "statystyki", "b": "zawodnik", "NrZawodnika": zawodnik_id})
        _, html = await fetch_with_correct_encoding(client, url, method="GET", cookies=cookies)
        result = _parse_player_matches(html)

        return {
            "fetched_at": _now_iso(),
            "zawodnik_id": zawodnik_id,
            **result,
        }


# =================================
# Endpoint: POST /zprp/statystyki/strzelec
# =================================

@router.post("/zprp/statystyki/strzelec")
async def get_top_scorers(
    payload: ZprpStatsScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Top scorers classification for a given competition.
    Optional team filter via id_team.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    season_id = _clean(payload.season_id or "")
    id_rozgr = _clean(payload.id_rozgr or "")
    id_team = _clean(payload.id_team or "")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        # First load meta page to get valid season/rozgr
        meta_url = _stats_url("strzelec", season_id=season_id, id_rozgr=id_rozgr)
        _, html_meta = await fetch_with_correct_encoding(client, meta_url, method="GET", cookies=cookies)
        meta = _parse_meta_from_strzelec_page(html_meta)

        effective_season = season_id or meta["current_season_id"]
        effective_rozgr = id_rozgr or meta["current_id_rozgr"]

        # Build URL with team filter if given
        extra: Dict[str, str] = {}
        if id_team:
            extra["ID_zespoly"] = id_team

        url = _stats_url("strzelec", season_id=effective_season, id_rozgr=effective_rozgr, extra=extra or None)
        _, html = await fetch_with_correct_encoding(client, url, method="GET", cookies=cookies)

        scorers = _parse_scorers_table(html)
        teams_filter = _parse_teams_filter(html)
        competition_title = _extract_competition_title(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "season_id": effective_season,
            "id_rozgr": effective_rozgr,
            "competition_title": competition_title,
            "meta": meta,
            "teams_filter": teams_filter,
            "scorers": scorers,
            "count": len(scorers),
        }


# =================================
# Endpoint: POST /zprp/statystyki/druzyn
# =================================

@router.post("/zprp/statystyki/druzyn")
async def get_team_stats(
    payload: ZprpStatsScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Team statistics for a given competition.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    season_id = _clean(payload.season_id or "")
    id_rozgr = _clean(payload.id_rozgr or "")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        # Load meta first for season/rozgr discovery
        meta_url = _stats_url("strzelec", season_id=season_id, id_rozgr=id_rozgr)
        _, html_meta = await fetch_with_correct_encoding(client, meta_url, method="GET", cookies=cookies)
        meta = _parse_meta_from_strzelec_page(html_meta)

        effective_season = season_id or meta["current_season_id"]
        effective_rozgr = id_rozgr or meta["current_id_rozgr"]

        url = _stats_url("druzyn", season_id=effective_season, id_rozgr=effective_rozgr)
        _, html = await fetch_with_correct_encoding(client, url, method="GET", cookies=cookies)

        teams = _parse_team_stats_table(html)
        competition_title = _extract_competition_title(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "season_id": effective_season,
            "id_rozgr": effective_rozgr,
            "competition_title": competition_title,
            "meta": meta,
            "teams": teams,
            "count": len(teams),
        }


# =================================
# Endpoint: POST /zprp/statystyki/tabela
# =================================

@router.post("/zprp/statystyki/tabela")
async def get_league_table(
    payload: ZprpStatsScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    League standings table for a given competition.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    season_id = _clean(payload.season_id or "")
    id_rozgr = _clean(payload.id_rozgr or "")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        # Load meta first
        meta_url = _stats_url("strzelec", season_id=season_id, id_rozgr=id_rozgr)
        _, html_meta = await fetch_with_correct_encoding(client, meta_url, method="GET", cookies=cookies)
        meta = _parse_meta_from_strzelec_page(html_meta)

        effective_season = season_id or meta["current_season_id"]
        effective_rozgr = id_rozgr or meta["current_id_rozgr"]

        url = _stats_url("tabela", season_id=effective_season, id_rozgr=effective_rozgr)
        _, html = await fetch_with_correct_encoding(client, url, method="GET", cookies=cookies)

        table_rows = _parse_league_table(html)
        competition_title = _extract_competition_title(html)
        table_types = _parse_table_type_select(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "season_id": effective_season,
            "id_rozgr": effective_rozgr,
            "competition_title": competition_title,
            "meta": meta,
            "table_types": table_types,
            "rows": table_rows,
            "count": len(table_rows),
        }


# =================================
# Endpoint: POST /zprp/statystyki/xlsx
# =================================

from pydantic import BaseModel as PydanticBaseModel

class XlsxProxyRequest(PydanticBaseModel):
    username: str
    password: str
    page_type: str   # "strzelec" | "druzyn" | "tabela"
    season_id: str
    id_rozgr: str


@router.post("/zprp/statystyki/xlsx")
async def download_stats_xlsx(
    payload: XlsxProxyRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Download Excel export from ZPRP stats pages.
    Returns the binary XLSX file as a streaming response.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    page_type = _clean(payload.page_type).lower()
    if page_type not in ("strzelec", "druzyn", "tabela"):
        raise HTTPException(400, "page_type must be one of: strzelec, druzyn, tabela")

    season_id = _clean(payload.season_id)
    id_rozgr = _clean(payload.id_rozgr)

    xlsx_path = _build_xlsx_url(page_type, season_id, id_rozgr)

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        resp = await client.get(xlsx_path, cookies=cookies)
        if resp.status_code != 200:
            raise HTTPException(502, f"ZPRP returned HTTP {resp.status_code} for XLSX export")

        content = resp.content
        content_type = resp.headers.get("content-type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        fname = f"statystyki_{page_type}_{id_rozgr}.xlsx"

        import io
        return StreamingResponse(
            io.BytesIO(content),
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
