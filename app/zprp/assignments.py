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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel

from app.deps import Settings, get_settings, get_rsa_keys
from app.match_market_rules import TRADEABLE_SLOTS as _TRADEABLE_SLOTS
from app.match_market_rules import names_match
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
    """Parse zawody_UstawHale.php HTML.
    
    Returns:
        IdZawody, halls list, selected_id, select_name (actual <select name=...>),
        hidden_inputs (all hidden inputs for re-submission), submit_btn (name+value of submit button).
    """
    soup = BeautifulSoup(html, "html.parser")

    id_zawody_input = soup.find("input", attrs={"name": "IdZawody"})
    id_zawody = _clean(id_zawody_input.get("value", "")) if id_zawody_input else ""

    # Collect all hidden inputs for full form re-submission
    hidden_inputs: Dict[str, str] = {}
    for inp in soup.find_all("input", attrs={"type": "hidden"}):
        n = _clean(inp.get("name", ""))
        v = _clean(inp.get("value", ""))
        if n:
            hidden_inputs[n] = v

    # Find the submit button (its name+value must be included in POST, like akcja_edycja)
    submit_btn: Dict[str, str] = {}
    for inp in soup.find_all("input", attrs={"type": "submit"}):
        n = _clean(inp.get("name", ""))
        v = _clean(inp.get("value", ""))
        if n:
            submit_btn = {"name": n, "value": v}
            break  # take the first save/submit button

    sel = soup.find("select")
    halls: List[Dict[str, str]] = []
    selected_id: Optional[str] = None
    select_name: str = "IdHala"  # fallback default

    if sel:
        # Read the actual select name attribute — critical for correct form submission
        actual_name = _clean(sel.get("name", ""))
        if actual_name:
            select_name = actual_name

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
        "select_name": select_name,
        "hidden_inputs": hidden_inputs,
        "submit_btn": submit_btn,
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
    NrSedzia_pierwszy_name: Optional[str] = None
    NrSedzia_drugi: Optional[str] = None
    NrSedzia_drugi_name: Optional[str] = None
    NrSedzia_delegat: Optional[str] = None
    NrSedzia_delegat_name: Optional[str] = None
    NrSedzia_delegat2: Optional[str] = None
    NrSedzia_delegat2_name: Optional[str] = None
    NrSedzia_sekretarz: Optional[str] = None
    NrSedzia_sekretarz_name: Optional[str] = None
    NrSedzia_czas: Optional[str] = None
    NrSedzia_czas_name: Optional[str] = None
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


def _norm_name(s: str) -> str:
    """Nazwisko sprowadzone do porównania - jedna reguła na cały moduł."""
    return " ".join((s or "").lower().strip().split())


def _same_person(a: str, b: str) -> bool:
    """Czy dwa zapisy nazwiska wskazuja tego samego czlowieka.

    Formularz ZPRP podpisuje opcje "WITKOWICZ Krzysztof", a lista sedziow
    okregu (skad gielda bierze nazwisko biorcy) bywa prowadzona jako
    "Krzysztof WITKOWICZ". Doslowne porownanie wstrzymywalo zapis z kodem
    NAME_NOT_IN_OPTIONS, choc sedzia stal na liscie 811 opcji - stad porownanie
    zbioru czlonow, to samo, ktorym gielda rozpoznaje "moj mecz".
    """
    if _norm_name(a) == _norm_name(b):
        return True
    return names_match(a, b)


def _resolve_option(options: List[Dict[str, Any]], wanted_name: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Opcja formularza dla nazwiska: (trafienie, kandydaci).

    Doslowne trafienie wygrywa zawsze. Bez niego liczy sie zbior czlonow -
    ale JEDNO trafienie: gdy pasuje kilku ("NOWAK Jan Pawel" i "NOWAK Jan
    Piotr" dla "Jan Nowak"), nie zgadujemy, bo zapisalibysmy do obsady nie
    tego czlowieka. Wtedy wraca pusta para i pelna lista kandydatow.
    """
    wanted = _norm_name(wanted_name)
    exact = next((o for o in options if _norm_name(o.get("name", "")) == wanted), None)
    if exact:
        return exact, [exact]
    candidates = [o for o in options if names_match(o.get("name", ""), wanted_name)]
    if len(candidates) == 1:
        return candidates[0], candidates
    return None, candidates


def _find_option_name(slot_data: dict, value: str) -> str:
    """Nazwa opcji o tej wartości albo pusty string."""
    for o in (slot_data.get("options") or []):
        if str(o.get("value", "")).strip() == str(value or "").strip():
            return (o.get("name") or "").strip()
    return ""


def _selected_name(slot_data: dict) -> str:
    """Nazwa aktualnie wybranej opcji albo pusty string."""
    sel_val = (slot_data.get("selected_value") or "").strip()
    return _find_option_name(slot_data, sel_val) if sel_val else ""


#: Gniazdo protokołu → nazwa pola w formularzu ZPRP. Pełna szóstka, bo moduł
#: obsadowego zmienia każde pole. Giełda meczów używa węższego podzbioru -
#: patrz `app.match_market_rules.TRADEABLE_SLOTS`.
SLOT_TO_SELECT: Dict[str, str] = {
    "sedzia1": "NrSedzia_pierwszy",
    "sedzia2": "NrSedzia_drugi",
    "delegat": "NrSedzia_delegat",
    "delegat2": "NrSedzia_delegat2",
    "sekretarz": "NrSedzia_sekretarz",
    "czas": "NrSedzia_czas",
}
SELECT_TO_SLOT: Dict[str, str] = {v: k for k, v in SLOT_TO_SELECT.items()}


#: Gniazda, o które pyta sonda uprawnień. Ta sama czwórka, którą wymienia
#: giełda - import zamiast kopii, bo rozjazd tych dwóch list oznaczałby, że
#: sonda przepuszcza mecz, którego zatwierdzenie i tak nie ma jak zapisać.
_PROBE_SLOTS: Tuple[str, ...] = tuple(_TRADEABLE_SLOTS)


async def probe_assignment_rights(
    client: AsyncClient,
    cookies: Dict[str, str],
    id_zawody: str,
    *,
    slot: str = "",
    user: str = "",
    log_prefix: str = "obsada/probe",
) -> Dict[str, Any]:
    """Czy TO konto może ustawić obsadę TEGO meczu - pytanie zadane wprost ZPRP.

    Sędzia widzi w aplikacji wszystkie swoje mecze, ale okręg obsadza tylko
    część z nich. Superligę, ligi centralne i turnieje młodzieżowe obsadza
    związek i konto wojewódzkie nie ma tam czego kliknąć. Bez tego sprawdzenia
    sędzia wystawiłby taki mecz na giełdę, ktoś by się zgłosił, obsadowy by
    zatwierdził - i dopiero wtedy okazałoby się, że zapisu nie ma jak wykonać.
    Cała umowa dwóch osób poszłaby w niwecz na ostatnim kroku.

    Odpowiedź bierzemy z tego samego formularza, którym zapisujemy obsadę, więc
    pytanie i wykonanie chodzą tą samą drogą. Brak listy sędziów znaczy brak
    uprawnień: ZPRP nie renderuje wtedy pól wyboru w ogóle.

    Zwraca `assignable`, kod powodu i zdanie dla człowieka. NIE rzuca wyjątkiem
    przy odmowie - odmowa jest tu odpowiedzią, nie awarią.
    """
    _, html = await fetch_with_correct_encoding(
        client,
        "/zawody_UstawSedziow.php",
        method="POST",
        data={"IdZawody": id_zawody, "akcja": "UstawSedziow", "user": user},
        cookies=cookies,
    )
    _log_html(f"{log_prefix} (probe form)", html)
    parsed = _parse_referee_form(html)
    slots = parsed.get("slots") or {}

    wanted = str(slot or "").strip()
    labels = (wanted,) if wanted in _PROBE_SLOTS else _PROBE_SLOTS

    rendered = _select_names_in(html)
    present = [
        label for label in labels
        if slots.get(label, {}).get("select_name") in rendered
    ]
    counts = {label: len(slots.get(label, {}).get("options") or []) for label in labels}
    holder = _selected_name(slots.get(wanted, {})) if wanted else ""

    if not present:
        logger.info("%s: mecz %s poza zasiegiem tego konta", log_prefix, id_zawody)
        return {
            "assignable": False,
            "reason": "NO_FORM",
            "message": (
                "Tego meczu nie obsadza okręg - obsadę ustala związek, więc giełda nie "
                "ma jak przekazać go innemu sędziemu."
            ),
            "holder": "",
            "option_count": 0,
            "fetched_at": _now_iso(),
        }

    if not any(counts.values()):
        logger.info("%s: mecz %s ma puste listy sedziow", log_prefix, id_zawody)
        return {
            "assignable": False,
            "reason": "NO_OPTIONS",
            "message": (
                "Konto obsadowe okręgu otwiera ten mecz, ale nie widzi przy nim żadnego "
                "sędziego do wyboru - takiej zmiany nie da się zapisać."
            ),
            "holder": holder,
            "option_count": 0,
            "fetched_at": _now_iso(),
        }

    return {
        "assignable": True,
        "reason": "OK",
        "message": "",
        "holder": holder,
        "option_count": max(counts.values()),
        "fetched_at": _now_iso(),
    }


def _select_names_in(html: str) -> Set[str]:
    """Nazwy pól `<select>` obecnych na stronie.

    Puste `<select>` i brak `<select>` to dwie różne odpowiedzi ZPRP - pierwsza
    znaczy „mecz jest Twój, ale nie ma kogo wybrać", druga „ten mecz nie jest
    Twój". `_parse_select_options` zwraca w obu wypadkach pustą listę, więc
    rozróżnienie musi przyjść stąd.
    """
    return set(re.findall(r'<select[^>]*?\s+name\s*=\s*["\']([^"\']+)', html or "", re.I))


async def apply_referee_assignment(
    client: AsyncClient,
    cookies: Dict[str, str],
    id_zawody: str,
    changes: Dict[str, Tuple[Optional[str], Optional[str]]],
    *,
    user: str = "",
    keep_hide_s: bool = False,
    keep_hide_d: bool = False,
    expect: Optional[Tuple[str, str]] = None,
    require_name_match: bool = False,
    log_prefix: str = "obsada/save",
) -> Dict[str, Any]:
    """Zapisuje obsadę meczu w ZPRP. JEDYNA droga zapisu w całej aplikacji.

    `changes` to `{nazwa_pola: (wartość, nazwisko)}`; wartość `None` znaczy „nie
    ruszaj tego gniazda" i wtedy jedzie to, co stoi w formularzu.

    Trzy rzeczy, bez których ta funkcja nie działa, a wygląda, jakby działała:

    1. **`akcja_edycja=ZAPISZ ZMIANY`**. Bez tego pola ZPRP traktuje wysyłkę jak
       odświeżenie filtra: oddaje poprawną stronę, status 200, i nie zapisuje
       nic.
    2. **Rozwiązanie po NAZWISKU.** `value` opcji nie jest stałym numerem
       sędziego - ZPRP przenumerowuje opcje zależnie od aktywnego filtra, więc
       wartość wzięta z jednego widoku wskazuje kogo innego w drugim. Dlatego
       numer wyliczamy z nazwiska na formularzu wczytanym przed chwilą.
    3. **Weryfikacja po zapisie.** Sprawdzamy, czy w odpowiedzi siedzi ten
       sędzia, o którego chodziło. Sukces bez tego sprawdzenia jest zgadywaniem.

    `expect` to `(nazwa_pola, oczekiwane_nazwisko)` - strażnik dla giełdy
    meczów: jeżeli gniazdo nie należy już do osoby, która wystawiła mecz, nie
    zapisujemy NICZEGO. Ktoś zmienił obsadę poza aplikacją i jego decyzja jest
    świeższa niż nasza.

    `require_name_match` zamienia zapas „jedzie przysłana wartość" w odmowę.
    Moduł obsadowego podaje wartość wziętą z formularza, który sam przed chwilą
    oglądał, więc zapas ma tam sens. Giełda podaje SAMO nazwisko - wartości nie
    zna i wysyła pustą - a pusta wartość w tym formularzu nie znaczy „zostaw",
    tylko „wyczyść gniazdo". Sędzia, którego ZPRP nie dopuszcza do tych
    rozgrywek, skasowałby w ten sposób obsadę zamiast ją przejąć.
    """
    # Krok 1: wczytanie formularza, dokładnie tak jak zrobiłaby przeglądarka.
    # Stąd biorą się aktualne wartości i poprawne numery opcji.
    _, load_html = await fetch_with_correct_encoding(
        client,
        "/zawody_UstawSedziow.php",
        method="POST",
        data={"IdZawody": id_zawody, "akcja": "UstawSedziow", "user": user},
        cookies=cookies,
    )
    _log_html(f"{log_prefix} step1 (load form)", load_html)
    current = _parse_referee_form(load_html)

    if expect:
        expect_select, expect_name = expect
        slot_label = SELECT_TO_SLOT.get(expect_select, expect_select)
        holder = _selected_name(current["slots"].get(slot_label, {}))
        # `_same_person`, nie porownanie tekstow: ta sama osoba przychodzi tu w
        # dwoch kolejnosciach czlonow. Formularz ZPRP podpisuje opcje "NAZWISKO
        # Imie", a lista sedziow okregu bywa prowadzona jako "Imie NAZWISKO" -
        # i to z niej bierze sie nazwisko w migawce meczu, na ktorej stoi
        # `expect`. Doslowne porownanie wstrzymywalo wiec zapis komunikatem
        # "jest teraz WITKOWICZ Krzysztof, a nie Krzysztof WITKOWICZ", czyli
        # sprzeciwem wobec tej samej osoby. Ta sama miara, co przy wyborze opcji
        # i przy weryfikacji po zapisie - trzy kroki, jedno pojecie tozsamosci.
        if not _same_person(holder, expect_name):
            logger.warning(
                "%s: gniazdo %s nalezy do %r, oczekiwano %r - zapis wstrzymany",
                log_prefix, slot_label, holder, expect_name,
            )
            return {
                "success": False,
                "code": "SLOT_CHANGED",
                "fetched_at": _now_iso(),
                "current_name": holder,
                "verified_slots": {},
                "error": (
                    f"Obsada zmieniła się w bazie związku - w tym gnieździe jest teraz "
                    f"{holder or 'nikt'}, a nie {expect_name}."
                ),
            }

    # Krok 2: komplet pól, tak jak wysyła formularz - sześć selectów, radia
    # filtrów i checkboxy. Wysłanie samego zmienionego pola kasuje resztę.
    form_data: Dict[str, str] = {
        "IdZawody": current["IdZawody"] or id_zawody,
        "akcja": "UstawSedziow",
        "akcja_edycja": "ZAPISZ ZMIANY",
    }

    for sel_name, slot_label in SELECT_TO_SLOT.items():
        new_val, new_name = changes.get(sel_name, (None, None))
        if new_val is None:
            form_data[sel_name] = (
                current["slots"].get(slot_label, {}).get("selected_value") or ""
            )
            continue

        resolved_val = new_val
        if new_name:
            options = current["slots"].get(slot_label, {}).get("options", [])
            match, candidates = _resolve_option(options, new_name)
            if match:
                resolved_val = match["value"]
                logger.info(
                    "%s: %s %r -> value=%r jako %r (przyszlo %r)",
                    log_prefix, slot_label, new_name, resolved_val,
                    match.get("name"), new_val,
                )
            elif len(candidates) > 1:
                # Kilku pasuje - to nie jest brak na liscie, tylko niejasnosc, i
                # ma sie tak nazwac. Zgadywanie zapisaloby do obsady kogos innego.
                names = ", ".join(str(o.get("name", "")) for o in candidates[:5])
                logger.warning(
                    "%s: nazwisko %r pasuje do %d opcji gniazda %s (%s) - zapis wstrzymany",
                    log_prefix, new_name, len(candidates), slot_label, names,
                )
                return {
                    "success": False,
                    "code": "NAME_AMBIGUOUS",
                    "fetched_at": _now_iso(),
                    "verified_slots": {},
                    "error": (
                        f"{new_name} pasuje do kilku sędziów na liście ZPRP dla roli "
                        f"{slot_label} ({names}). Wskaż w bazie związku ręcznie."
                    ),
                }
            elif require_name_match:
                logger.warning(
                    "%s: nazwiska %r nie ma wsrod %d opcji gniazda %s - zapis wstrzymany",
                    log_prefix, new_name, len(options), slot_label,
                )
                return {
                    "success": False,
                    "code": "NAME_NOT_IN_OPTIONS",
                    "fetched_at": _now_iso(),
                    "verified_slots": {},
                    "error": (
                        f"{new_name} nie występuje na liście sędziów, których ZPRP "
                        f"dopuszcza do tego meczu w roli {slot_label}."
                    ),
                }
            else:
                logger.warning(
                    "%s: nazwiska %r nie ma wsrod %d opcji gniazda %s - jedzie wartosc %r",
                    log_prefix, new_name, len(options), slot_label, new_val,
                )
        form_data[sel_name] = resolved_val

    for filt_name in ("TypR", "Odl", "off"):
        filt_val = current["filters"].get(filt_name, "")
        if filt_val:
            form_data[filt_name] = filt_val

    if keep_hide_s or current.get("hide_obsada_s"):
        form_data["ukryjObsade"] = "1"
    if keep_hide_d or current.get("hide_obsada_d"):
        form_data["ukryjObsadeD"] = "1"

    # Krok 3: wysyłka.
    _, html = await fetch_with_correct_encoding(
        client,
        "/zawody_UstawSedziow.php",
        method="POST",
        data=form_data,
        cookies=cookies,
    )
    _log_html(f"{log_prefix} step3 (submit)", html)
    parsed = _parse_referee_form(html)

    # Krok 4: weryfikacja. Porównujemy NAZWISKA, bo numery opcji w odpowiedzi
    # mogą być przenumerowane względem tych, które wysłaliśmy. Ta sama miara,
    # co przy wyborze opcji - inaczej "Krzysztof WITKOWICZ" zapisałby się jako
    # "WITKOWICZ Krzysztof" i zaraz potem oblał własną weryfikację.
    verification_ok = True
    for sel_name, slot_label in SELECT_TO_SLOT.items():
        sent_val, sent_name = changes.get(sel_name, (None, None))
        if sent_val is None:
            continue
        got_name = _selected_name(parsed["slots"].get(slot_label, {}))
        if sent_name:
            if not _same_person(got_name, sent_name):
                logger.warning(
                    "%s: weryfikacja gniazda %s - oczekiwano %r, jest %r",
                    log_prefix, slot_label, sent_name, got_name,
                )
                verification_ok = False
        elif not got_name and sent_val:
            logger.warning("%s: gniazdo %s puste po zapisie", log_prefix, slot_label)
            verification_ok = False

    return {
        "success": verification_ok,
        "code": None if verification_ok else "VERIFICATION_FAILED",
        "fetched_at": _now_iso(),
        "verified_slots": {
            label: {
                "value": parsed["slots"].get(label, {}).get("selected_value"),
                "name": _selected_name(parsed["slots"].get(label, {})),
            }
            for label in SELECT_TO_SLOT.values()
        },
        "error": None if verification_ok else "Zapis nie potwierdził się w bazie związku.",
    }


@router.post("/zprp/obsada/save")
async def obsada_save(
    payload: ObsadaSaveRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """Zapis obsady z modułu obsadowego - dane logowania z telefonu."""
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    changes: Dict[str, Tuple[Optional[str], Optional[str]]] = {
        "NrSedzia_pierwszy": (payload.NrSedzia_pierwszy, payload.NrSedzia_pierwszy_name),
        "NrSedzia_drugi": (payload.NrSedzia_drugi, payload.NrSedzia_drugi_name),
        "NrSedzia_delegat": (payload.NrSedzia_delegat, payload.NrSedzia_delegat_name),
        "NrSedzia_delegat2": (payload.NrSedzia_delegat2, payload.NrSedzia_delegat2_name),
        "NrSedzia_sekretarz": (payload.NrSedzia_sekretarz, payload.NrSedzia_sekretarz_name),
        "NrSedzia_czas": (payload.NrSedzia_czas, payload.NrSedzia_czas_name),
    }

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/save: login ok IdZawody=%s", payload.IdZawody)
        return await apply_referee_assignment(
            client,
            cookies,
            payload.IdZawody,
            changes,
            user=payload.user,
            keep_hide_s=bool(payload.ukryjObsade),
            keep_hide_d=bool(payload.ukryjObsadeD),
        )


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
    """Save hall assignment to ZPRP.
    
    2-step process:
      1. Fetch the hall form to discover the real <select name=...> attribute
         and any submit button field (name+value) that ZPRP requires.
      2. Submit the complete form with the correct field names.
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp(client, user_plain, pass_plain)
        logger.info("ZPRP obsada/save-hall: login ok IdZawody=%s hall=%s", payload.IdZawody, payload.hall_id)

        # --- Step 1: Fetch the form to get real select name + submit button ---
        step1_data = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawHale",
            "user": payload.user,
        }
        resp1, html1 = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawHale.php",
            method="POST",
            data=step1_data,
            cookies=cookies,
        )
        parsed1 = _parse_hall_form(html1)
        select_name = parsed1.get("select_name") or "IdHala"
        submit_btn = parsed1.get("submit_btn") or {}
        hidden_inputs = parsed1.get("hidden_inputs") or {}
        logger.info("ZPRP obsada/save-hall: step1 select_name=%s submit_btn=%s", select_name, submit_btn)

        # --- Step 2: Submit with correct field names ---
        form_data: Dict[str, str] = {
            "IdZawody": payload.IdZawody,
            "akcja": "UstawHale",
        }
        # Re-include hidden inputs from the form (token, session fields, etc.)
        for k, v in hidden_inputs.items():
            if k not in form_data:
                form_data[k] = v

        # Set the selected hall using the real select name
        form_data[select_name] = payload.hall_id

        # Include submit button field — ZPRP uses this to distinguish save vs filter refresh
        if submit_btn.get("name") and submit_btn.get("value"):
            form_data[submit_btn["name"]] = submit_btn["value"]
            logger.info("ZPRP obsada/save-hall: adding submit btn %s=%s", submit_btn["name"], submit_btn["value"])

        resp2, html2 = await fetch_with_correct_encoding(
            client,
            "/zawody_UstawHale.php",
            method="POST",
            data=form_data,
            cookies=cookies,
        )
        _log_html("obsada/save-hall response", html2)

        # Verify: re-parse and check selected_id
        parsed2 = _parse_hall_form(html2)
        success = parsed2.get("selected_id") == payload.hall_id

        # Find hall name for response
        hall_name = ""
        for h in parsed2.get("halls", []):
            if h["id"] == payload.hall_id:
                hall_name = h.get("full_label") or h.get("name") or ""
                break

        logger.info(
            "ZPRP obsada/save-hall: step2 success=%s selected=%s wanted=%s",
            success, parsed2.get("selected_id"), payload.hall_id
        )

        return {
            "success": success,
            "fetched_at": _now_iso(),
            "select_name_used": select_name,
            "selected_id": parsed2.get("selected_id"),
            "hall_name": hall_name,
            "error": None if success else f"Hall verification failed: selected={parsed2.get('selected_id')} wanted={payload.hall_id}",
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
