# app/zprp/assignments.py
"""
Moduł obsadowego — scraping formularzy przypisywania sędziów i hal
z baza.zprp.pl + zapis zmian (write-back).
"""
from __future__ import annotations

import base64
import datetime
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel

from app.deps import Settings, get_settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding
from app.zprp.schedule import _parse_matches_table

router = APIRouter()

logger = logging.getLogger("app.zprp.assignments")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

_RE_INT = re.compile(r"(\d+)")
_RE_KM = re.compile(r"\[(\d+)\s*km\]")
_RE_MECZ = re.compile(r"\[MECZ\]")
_RE_BADGES = re.compile(r"\(([^)]+)\)")


# =====================
# Helpers
# =====================

def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def _safe_int(s: str, default: int = 0) -> int:
    if not s:
        return default
    m = _RE_INT.search(s)
    return int(m.group(1)) if m else default


def _decrypt_field(private_key, enc_b64: str) -> str:
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")


async def _login_zprp(client: AsyncClient, username: str, password: str) -> Dict[str, str]:
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
    )
    if "/index.php" not in resp_login.url.path:
        raise HTTPException(401, "Logowanie ZPRP nie powiodło się")
    return dict(resp_login.cookies)


def _log_html(prefix: str, html: str) -> None:
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = _clean((soup.title.get_text(strip=True) if soup.title else ""))[:80]
    except Exception:
        title = ""
    logger.info("%s html_len=%s title='%s'", prefix, len(html or ""), title)


# =====================
# Parsers — referee form (edytuj_obsade)
# =====================

def _parse_option(opt) -> Dict[str, Any]:
    """Parse single <option> from referee <select>."""
    value = _clean(opt.get("value", ""))
    raw_text = _clean(opt.get_text(strip=True))
    selected = bool(opt.has_attr("selected"))

    # Extract [MECZ] tag
    has_match_tag = bool(_RE_MECZ.search(raw_text))

    # Extract [XX km] distance
    km_m = _RE_KM.search(raw_text)
    distance_km: Optional[int] = int(km_m.group(1)) if km_m else None

    # Extract badges like (MP)(II)(III)(Mł)
    badges_raw: List[str] = _RE_BADGES.findall(raw_text)

    # Clean name: remove badges, distance, [MECZ], &nbsp;
    name = raw_text
    name = _RE_MECZ.sub("", name)
    name = _RE_KM.sub("", name)
    for b in badges_raw:
        name = name.replace(f"({b})", "")
    name = name.replace("\xa0", " ")
    name = _clean(name)

    return {
        "value": value,
        "name": name,
        "badges": badges_raw,
        "distance_km": distance_km,
        "has_match_tag": has_match_tag,
        "selected": selected,
    }


def _parse_select_options(soup: BeautifulSoup, select_name: str) -> Tuple[List[Dict], Optional[str]]:
    """Parse all options from a named <select>, return (options, selected_value)."""
    sel = soup.find("select", attrs={"name": select_name})
    if not sel:
        return [], None

    options: List[Dict] = []
    selected_value: Optional[str] = None

    for opt in sel.find_all("option"):
        val = _clean(opt.get("value", ""))
        if not val:
            continue
        parsed = _parse_option(opt)
        options.append(parsed)
        if parsed["selected"]:
            selected_value = val

    return options, selected_value


def _parse_radio_value(soup: BeautifulSoup, radio_name: str) -> str:
    """Get the checked radio button value."""
    checked = soup.find("input", attrs={"name": radio_name, "checked": True})
    if checked:
        return _clean(checked.get("value", ""))
    return ""


def _parse_checkbox_checked(soup: BeautifulSoup, checkbox_name: str) -> bool:
    """Check if a checkbox is checked."""
    cb = soup.find("input", attrs={"name": checkbox_name, "type": "checkbox"})
    if not cb:
        return False
    return bool(cb.has_attr("checked"))


def _parse_match_header(soup: BeautifulSoup) -> Dict[str, str]:
    """Parse match info from the form header rows."""
    header: Dict[str, str] = {
        "match_code": "",
        "teams": "",
        "date_time": "",
        "hall_city": "",
    }

    table = soup.find("table")
    if not table:
        return header

    rows = table.find_all("tr")
    for tr in rows:
        tds = tr.find_all("td")
        for td in tds:
            text = _clean(td.get_text(" ", strip=True))

            # Match code: e.g. "IIK4/55"
            title_attr = td.get("title", "")
            if title_attr and not header["hall_city"]:
                header["hall_city"] = _clean(title_attr)

            if re.match(r"^[A-Z]+\d*[/]\d+$", text):
                header["match_code"] = text

            # Teams: contains "vs" and is reasonably short (not a referee list)
            if "vs" in text.lower() and 10 < len(text) < 150:
                header["teams"] = text

            # Date: contains day-of-week pattern
            small = td.find("small")
            if small:
                italic = td.find("i")
                if italic:
                    header["date_time"] = _clean(italic.get_text(strip=True))

    return header


def _parse_referee_form(html: str) -> Dict[str, Any]:
    """Full parse of zawody_UstawSedziow.php HTML."""
    soup = BeautifulSoup(html, "html.parser")

    header = _parse_match_header(soup)

    # Parse hidden fields
    id_zawody_input = soup.find("input", attrs={"name": "IdZawody"})
    id_zawody = _clean(id_zawody_input.get("value", "")) if id_zawody_input else ""

    # Parse 6 referee selects
    select_names = [
        "NrSedzia_pierwszy",
        "NrSedzia_drugi",
        "NrSedzia_delegat",
        "NrSedzia_delegat2",
        "NrSedzia_sekretarz",
        "NrSedzia_czas",
    ]
    slot_labels = [
        "sedzia1",
        "sedzia2",
        "delegat",
        "delegat2",
        "sekretarz",
        "czas",
    ]

    slots: Dict[str, Any] = {}
    for sel_name, label in zip(select_names, slot_labels):
        options, selected = _parse_select_options(soup, sel_name)
        slots[label] = {
            "select_name": sel_name,
            "options": options,
            "selected_value": selected,
        }

    # Parse filter radios
    filters = {
        "TypR": _parse_radio_value(soup, "TypR"),
        "Odl": _parse_radio_value(soup, "Odl"),
        "off": _parse_radio_value(soup, "off"),
    }

    # Parse checkboxes
    hide_obsada_s = _parse_checkbox_checked(soup, "ukryjObsade")
    hide_obsada_d = _parse_checkbox_checked(soup, "ukryjObsadeD")

    return {
        "IdZawody": id_zawody,
        "header": header,
        "slots": slots,
        "filters": filters,
        "hide_obsada_s": hide_obsada_s,
        "hide_obsada_d": hide_obsada_d,
    }


# =====================
# Parsers — hall form (ustaw_hale)
# =====================

def _parse_hall_form(html: str) -> Dict[str, Any]:
    """Parse zawody_UstawHale.php HTML."""
    soup = BeautifulSoup(html, "html.parser")

    id_zawody_input = soup.find("input", attrs={"name": "IdZawody"})
    id_zawody = _clean(id_zawody_input.get("value", "")) if id_zawody_input else ""

    sel = soup.find("select")
    halls: List[Dict[str, str]] = []
    selected_id: Optional[str] = None

    if sel:
        for opt in sel.find_all("option"):
            val = _clean(opt.get("value", ""))
            if not val:
                continue
            label = _clean(opt.get_text(strip=True))
            is_selected = bool(opt.has_attr("selected"))
            if is_selected:
                selected_id = val

            # Try to split "Name, City, Address"
            parts = [_clean(p) for p in label.split(",") if _clean(p)]
            name = parts[0] if parts else label
            city = parts[1] if len(parts) > 1 else ""
            address = ", ".join(parts[2:]) if len(parts) > 2 else ""

            halls.append({
                "id": val,
                "name": name,
                "city": city,
                "address": address,
                "full_label": label,
                "selected": is_selected,
            })

    return {
        "IdZawody": id_zawody,
        "halls": halls,
        "selected_id": selected_id,
    }


# =====================
# Parsers — schedule with assignment info
# =====================

def _parse_schedule_assignment_info(html: str) -> Dict[str, Any]:
    """
    Parse schedule page extracting assignment metadata per match.
    
    Instead of relying on fragile row/column positions, we find ALL
    relevant forms on the page ('Sędziowie' and 'Ustaw halę') and
    extract IdZawody + user from their hidden inputs.
    Then we look at the surrounding cell content for each match to
    detect assigned officials.
    """
    soup = BeautifulSoup(html, "html.parser")
    matches: Dict[str, Dict[str, Any]] = {}

    # 1) Find ALL "Sędziowie" forms — each contains IdZawody + user
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if not re.search(r"UstawSedziow", action, re.I):
            continue

        id_input = form.find("input", attrs={"name": "IdZawody"})
        user_input = form.find("input", attrs={"name": "user"})
        if not id_input:
            continue

        id_zawody = (id_input.get("value") or "").strip()
        user_val = (user_input.get("value") or "").strip() if user_input else ""
        if not id_zawody:
            continue

        # Find the containing TD to extract officials info
        parent_td = form.find_parent("td")
        officials_names: List[str] = []
        has_field_refs = False
        has_table_officials = False
        has_delegate = False
        hide_obsada_s = False
        hide_obsada_d = False

        if parent_td:
            lines = [_clean(ln) for ln in parent_td.get_text("\n", strip=True).split("\n") if _clean(ln)]

            def _looks_like_name(line: str) -> bool:
                if "@" in line or re.fullmatch(r"[\d\s\-+()]+", line):
                    return False
                if re.search(r"Sędziowie|Ustaw|ukryj", line, re.I):
                    return False
                if " " in line and len(line) > 3 and re.search(r"[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]", line):
                    return True
                return False

            officials_names = [ln for ln in lines if _looks_like_name(ln)][:6]

            # Count <hr> separators to determine which sections exist
            hrs = parent_td.find_all("hr")
            hr_count = len(hrs)

            # Heuristic: 2+ names = field refs assigned
            has_field_refs = len(officials_names) >= 2
            # 3+ names = table officials too
            has_table_officials = len(officials_names) >= 3
            # 5+ names = delegate assigned
            has_delegate = len(officials_names) >= 5

            # Check ukryjObsade checkboxes
            hide_s_cb = parent_td.find("input", attrs={"name": "ukryjObsade", "type": "checkbox"})
            hide_d_cb = parent_td.find("input", attrs={"name": "ukryjObsadeD", "type": "checkbox"})
            hide_obsada_s = bool(hide_s_cb and hide_s_cb.has_attr("checked")) if hide_s_cb else False
            hide_obsada_d = bool(hide_d_cb and hide_d_cb.has_attr("checked")) if hide_d_cb else False

        matches[id_zawody] = {
            "IdZawody": id_zawody,
            "user": user_val,
            "has_sedzia_btn": True,
            "has_hall_btn": False,  # will be updated below
            "has_field_refs": has_field_refs,
            "has_table_officials": has_table_officials,
            "has_delegate": has_delegate,
            "has_hall": False,  # will be updated below
            "hide_obsada_s": hide_obsada_s,
            "hide_obsada_d": hide_obsada_d,
            "officials_names": officials_names,
        }

    # 2) Find ALL "Ustaw halę" forms
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if not re.search(r"UstawHale", action, re.I):
            continue

        id_input = form.find("input", attrs={"name": "IdZawody"})
        if not id_input:
            continue

        id_zawody = (id_input.get("value") or "").strip()
        if not id_zawody:
            continue

        if id_zawody in matches:
            matches[id_zawody]["has_hall_btn"] = True
        else:
            # Match has hall button but no referee button
            matches[id_zawody] = {
                "IdZawody": id_zawody,
                "user": "",
                "has_sedzia_btn": False,
                "has_hall_btn": True,
                "has_field_refs": False,
                "has_table_officials": False,
                "has_delegate": False,
                "has_hall": False,
                "hide_obsada_s": False,
                "hide_obsada_d": False,
                "officials_names": [],
            }

    # 3) Detect existing hall assignments (Google Maps links near each match)
    #    A hall TD with a maps link means a hall is already set
    for a_tag in soup.find_all("a", href=re.compile(r"maps\.google|google.*maps", re.I)):
        parent_td = a_tag.find_parent("td")
        if not parent_td:
            continue
        # Find the nearest form to associate with an IdZawody
        parent_tr = parent_td.find_parent("tr")
        if not parent_tr:
            continue
        # Look for UstawHale form in the same row
        hall_form = parent_tr.find("form", attrs={"action": re.compile(r"UstawHale", re.I)})
        if hall_form:
            h_input = hall_form.find("input", attrs={"name": "IdZawody"})
            if h_input:
                hid = (h_input.get("value") or "").strip()
                if hid and hid in matches:
                    matches[hid]["has_hall"] = True
        # Also check for UstawSedziow form to get IdZawody
        ref_form = parent_tr.find("form", attrs={"action": re.compile(r"UstawSedziow", re.I)})
        if ref_form:
            r_input = ref_form.find("input", attrs={"name": "IdZawody"})
            if r_input:
                rid = (r_input.get("value") or "").strip()
                if rid and rid in matches:
                    matches[rid]["has_hall"] = True

    return {"matches": matches}


# =====================
# Request models
# =====================

class ObsadaMatchFormRequest(BaseModel):
    username: str       # RSA-encrypted
    password: str       # RSA-encrypted
    judge_id: Optional[str] = None
    IdZawody: str
    user: str           # ZPRP user (e.g. "ks_slzpr")
    # Optional filter params for filtered endpoint
    TypR: Optional[str] = None
    Odl: Optional[str] = None
    off: Optional[str] = None


class ObsadaSaveRequest(BaseModel):
    username: str
    password: str
    judge_id: Optional[str] = None
    IdZawody: str
    user: str
    NrSedzia_pierwszy: Optional[str] = None
    NrSedzia_drugi: Optional[str] = None
    NrSedzia_delegat: Optional[str] = None
    NrSedzia_delegat2: Optional[str] = None
    NrSedzia_sekretarz: Optional[str] = None
    NrSedzia_czas: Optional[str] = None
    ukryjObsade: Optional[bool] = False
    ukryjObsadeD: Optional[bool] = False


class ObsadaHallFormRequest(BaseModel):
    username: str
    password: str
    judge_id: Optional[str] = None
    IdZawody: str
    user: str


class ObsadaSaveHallRequest(BaseModel):
    username: str
    password: str
    judge_id: Optional[str] = None
    IdZawody: str
    user: str
    hall_id: str


class ObsadaScheduleRequest(BaseModel):
    username: str
    password: str
    judge_id: Optional[str] = None
    season_id: Optional[str] = None
    filtr_kategoria: Optional[str] = None
    id_rozgr: Optional[str] = None
    IdRundy: Optional[str] = "ALL"
    sort: Optional[str] = None


# =====================
# Endpoints
# =====================

@router.post("/zprp/obsada/match-form")
async def obsada_match_form(
    payload: ObsadaMatchFormRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Scrape referee assignment form for a match."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/match-form: login ok IdZawody=%s", payload.IdZawody)

        form_data = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawSedziow",
            "user": payload.user,
        }

        # Add filter params if provided
        if payload.TypR is not None:
            form_data["TypR"] = payload.TypR
        if payload.Odl is not None:
            form_data["Odl"] = payload.Odl
        if payload.off is not None:
            form_data["off"] = payload.off

        resp, html = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawSedziow.php",
            method="POST",
            data=form_data,
            cookies=cookies,
        )
        _log_html("obsada/match-form", html)

        parsed = _parse_referee_form(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            **parsed,
        }


@router.post("/zprp/obsada/match-form-filtered")
async def obsada_match_form_filtered(
    payload: ObsadaMatchFormRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Scrape referee form with active filters (distance, type, unavailability)."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/match-form-filtered: login ok IdZawody=%s TypR=%s Odl=%s off=%s",
                     payload.IdZawody, payload.TypR, payload.Odl, payload.off)

        form_data: Dict[str, str] = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawSedziow",
            "user": payload.user,
        }
        if payload.TypR is not None:
            form_data["TypR"] = payload.TypR
        if payload.Odl is not None:
            form_data["Odl"] = payload.Odl
        if payload.off is not None:
            form_data["off"] = payload.off

        resp, html = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawSedziow.php",
            method="POST",
            data=form_data,
            cookies=cookies,
        )
        _log_html("obsada/match-form-filtered", html)

        parsed = _parse_referee_form(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            **parsed,
        }


@router.post("/zprp/obsada/save")
async def obsada_save(
    payload: ObsadaSaveRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Save referee assignment to ZPRP."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/save: login ok IdZawody=%s", payload.IdZawody)

        form_data: Dict[str, str] = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawSedziow",
            "user": payload.user,
        }

        # Set referee values — must send ALL selects to ZPRP form
        field_map = {
            "NrSedzia_pierwszy": payload.NrSedzia_pierwszy or "",
            "NrSedzia_drugi": payload.NrSedzia_drugi or "",
            "NrSedzia_delegat": payload.NrSedzia_delegat or "",
            "NrSedzia_delegat2": payload.NrSedzia_delegat2 or "",
            "NrSedzia_sekretarz": payload.NrSedzia_sekretarz or "",
            "NrSedzia_czas": payload.NrSedzia_czas or "",
        }
        for k, v in field_map.items():
            form_data[k] = v

        if payload.ukryjObsade:
            form_data["ukryjObsade"] = "1"
        if payload.ukryjObsadeD:
            form_data["ukryjObsadeD"] = "1"

        resp, html = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawSedziow.php",
            method="POST",
            data=form_data,
            cookies=cookies,
        )
        _log_html("obsada/save response", html)

        # Verify: re-parse the form to check if assignment took effect
        parsed = _parse_referee_form(html)

        # Check if the selected values match what we sent
        verification_ok = True
        for slot_label, sel_name in [
            ("sedzia1", "NrSedzia_pierwszy"),
            ("sedzia2", "NrSedzia_drugi"),
            ("delegat", "NrSedzia_delegat"),
            ("delegat2", "NrSedzia_delegat2"),
            ("sekretarz", "NrSedzia_sekretarz"),
            ("czas", "NrSedzia_czas"),
        ]:
            sent_val = (field_map.get(sel_name) or "").strip()
            got_val = (parsed["slots"].get(slot_label, {}).get("selected_value") or "").strip()
            if sent_val and sent_val != got_val:
                logger.warning("Verification mismatch slot=%s sent=%r got=%r", slot_label, sent_val, got_val)
                verification_ok = False

        return {
            "success": verification_ok,
            "fetched_at": _now_iso(),
            "verified_slots": {
                label: parsed["slots"].get(label, {}).get("selected_value")
                for label in ["sedzia1", "sedzia2", "delegat", "delegat2", "sekretarz", "czas"]
            },
            "error": None if verification_ok else "Verification failed — selected values don't match sent values",
        }


@router.post("/zprp/obsada/hall-form")
async def obsada_hall_form(
    payload: ObsadaHallFormRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Scrape hall assignment form."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/hall-form: login ok IdZawody=%s", payload.IdZawody)

        form_data = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawHale",
            "user": payload.user,
        }

        resp, html = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawHale.php",
            method="POST",
            data=form_data,
            cookies=cookies,
        )
        _log_html("obsada/hall-form", html)

        parsed = _parse_hall_form(html)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            **parsed,
        }


@router.post("/zprp/obsada/save-hall")
async def obsada_save_hall(
    payload: ObsadaSaveHallRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Save hall assignment to ZPRP."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/save-hall: login ok IdZawody=%s hall=%s", payload.IdZawody, payload.hall_id)

        form_data = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawHale",
            "user": payload.user,
        }

        # The hall select name varies — try common patterns
        # We'll send it as the first select's name from the form
        # For ZPRP, the hall select is typically named after a pattern
        form_data["IdHala"] = payload.hall_id

        resp, html = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawHale.php",
            method="POST",
            data=form_data,
            cookies=cookies,
        )
        _log_html("obsada/save-hall response", html)

        # Re-parse to verify
        parsed = _parse_hall_form(html)
        success = parsed.get("selected_id") == payload.hall_id

        return {
            "success": success,
            "fetched_at": _now_iso(),
            "selected_id": parsed.get("selected_id"),
            "error": None if success else "Hall verification failed",
        }


@router.post("/zprp/obsada/schedule-for-assignment")
async def obsada_schedule_for_assignment(
    payload: ObsadaScheduleRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Scrape schedule page with enriched assignment metadata (IdZawody, buttons, status)."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/schedule: login ok")

        # Navigate to the schedule page (Terminarz) with filters
        qs: Dict[str, str] = {"a": "terminarz"}
        if payload.season_id:
            qs["Filtr_sezon"] = payload.season_id
        if payload.filtr_kategoria:
            qs["Filtr_kategoria"] = payload.filtr_kategoria
        if payload.id_rozgr:
            qs["IdRozgr"] = payload.id_rozgr
        if payload.IdRundy:
            qs["IdRundy"] = payload.IdRundy
        if payload.sort:
            qs["sort"] = payload.sort

        path = "/index.php?" + urlencode(qs, doseq=True)

        resp, html = await fetch_with_correct_encoding(
            client,
            path,
            method="GET",
            cookies=cookies,
        )
        _log_html("obsada/schedule page", html)

        parsed = _parse_schedule_assignment_info(html)
        full_matches = _parse_matches_table(html, context_prefix="obsada")

        # Merge: use full match data as base, overlay assignment metadata
        merged: List[Dict[str, Any]] = []
        assignment_meta = parsed.get("matches", {})

        for match_id, match_data in full_matches.items():
            entry = dict(match_data)
            id_zawody = entry.get("IdZawody", "")
            if id_zawody and id_zawody in assignment_meta:
                entry["_assignment"] = assignment_meta[id_zawody]
            elif match_id in assignment_meta:
                entry["_assignment"] = assignment_meta[match_id]
            else:
                entry["_assignment"] = None
            merged.append(entry)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "filters": qs,
            "matches": merged,
        }
