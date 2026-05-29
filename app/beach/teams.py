import asyncio
import os
import re
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse

from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from httpx import AsyncClient
from pydantic import BaseModel
from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import beach_teams, database
from app.deps import Settings, get_settings
from app.beach.verification import expand_roles_for_squad_sync
from app.schemas import (
    BeachTeamContact,
    BeachTeamCreateRequest,
    BeachTeamItem,
    BeachTeamPutRequest,
    BeachTeamsFiltersResponse,
    BeachTeamsListResponse,
    BeachTeamsSyncRequest,
    BeachTeamsSyncResponse,
    BeachTeamUpdateRequest,
)

router = APIRouter(prefix="/beach/teams", tags=["Beach Teams"])
logger = logging.getLogger(__name__)


# =========================================================
# Helpers: basic
# =========================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def _abs_index_url(path_or_query: str) -> str:
    s = (path_or_query or "").strip()
    if not s:
        return "/index.php"
    if s.startswith("http://") or s.startswith("https://"):
        m = re.match(r"^https?://[^/]+(?P<path>/.*)$", s)
        return m.group("path") if m else s
    if s.startswith("/index.php"):
        return s
    if s.startswith("index.php"):
        return "/" + s
    if s.startswith("/"):
        return s
    if s.startswith("?"):
        return f"/index.php{s}"
    return f"/index.php?{s}"


def _mask_secret(value: str, visible_prefix: int = 2, visible_suffix: int = 2) -> str:
    v = value or ""
    if not v:
        return ""
    if len(v) <= visible_prefix + visible_suffix:
        return "*" * len(v)
    return f"{v[:visible_prefix]}***{v[-visible_suffix:]}"


def _table_has_column(col_name: str) -> bool:
    return col_name in getattr(beach_teams.c, "keys", lambda: [])()


def _season_end_year_from_label(season_label: Optional[str]) -> Optional[int]:
    s = _norm_space(season_label or "")
    m = re.search(r"(\d{4})\s*/\s*(\d{4})", s)
    if m:
        return int(m.group(2))
    return None


def _extract_year_highlight_validity(td, season_end_year: Optional[int]) -> Tuple[Optional[str], Optional[bool]]:
    """
    Z kolumny licencji pobiera:
    - numer licencji
    - ważność dla sezonu:
      True  -> jeśli rok końcowy sezonu jest zaznaczony na zielono
      False -> jeśli znamy rok końcowy sezonu, ale nie ma zielonego oznaczenia tego roku
      None  -> jeśli nie udało się ustalić roku końcowego sezonu
    """
    text = _norm_space(td.get_text(" ", strip=True))
    if not text:
        return None, None

    license_number = None

    # zawodnik: P/0118/24
    # osoba towarzysząca: 0046/24
    m_num = re.search(r"\b([A-Z]/\d{3,}/\d{2}|\d{3,}/\d{2})\b", text, re.I)
    if m_num:
        license_number = m_num.group(1)

    if season_end_year is None:
        return license_number, None

    target_year = str(season_end_year)

    # szukamy zielonego highlightu z datą końca sezonu
    for font in td.find_all("font"):
        year_txt = _norm_space(font.get_text(" ", strip=True))
        style = (font.get("style") or "").lower()
        style_compact = re.sub(r"\s+", "", style)

        is_green = (
            "#00ff00" in style_compact
            or "rgb(0,255,0)" in style_compact
        )

        if year_txt == target_year and is_green:
            return license_number, True

    return license_number, False


def _extract_text_lines_from_cell(td) -> List[str]:
    text = td.get_text("\n", strip=True)
    lines = [_norm_space(x) for x in text.split("\n")]
    return [x for x in lines if x]


def _extract_email_from_text(value: Optional[str]) -> Optional[str]:
    s = _norm_space(value or "")
    if not s:
        return None
    m = re.search(r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", s, re.I)
    return m.group(1) if m else None


def _looks_like_email(value: Optional[str]) -> bool:
    return _extract_email_from_text(value) is not None


def _clean_postal_code(value: Optional[str]) -> Optional[str]:
    s = _norm_space(value or "")
    if not s:
        return None
    m = re.search(r"\b\d{2}-\d{3}\b", s)
    return m.group(0) if m else None


def _clean_city_candidate(value: Optional[str]) -> Optional[str]:
    s = _norm_space(value or "")
    if not s:
        return None

    if _looks_like_email(s):
        return None

    s = re.sub(r"^\s*\d{2}-\d{3}\s*", "", s).strip()
    s = re.sub(r"^\s*\d{5}\s+", "", s).strip()

    if not s:
        return None

    low = s.lower().strip(" :")
    if low in {"mail", "www", "tel", "tel2", "uwagi"}:
        return None

    if re.fullmatch(r"[\d\s\-.,/]+", s):
        return None

    return s or None


def _split_postal_and_city_from_line(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    s = _norm_space(value or "")
    if not s:
        return None, None

    m = re.search(r"\b(?P<postal>\d{2}-\d{3})\b\s+(?P<city>.+)$", s)
    if m:
        return _clean_postal_code(m.group("postal")), _clean_city_candidate(m.group("city"))

    m2 = re.search(r"^\s*(?P<postal>\d{5})\s+(?P<city>.+)$", s)
    if m2:
        return None, _clean_city_candidate(m2.group("city"))

    return None, _clean_city_candidate(s)


# =========================================================
# Helpers: login
# =========================================================

async def _login_beach_client(settings: Settings) -> AsyncClient:
    raw_username = settings.ZPRP_BEACH_USERNAME or ""
    raw_password = settings.ZPRP_BEACH_PASSWORD or ""

    username = raw_username.strip()
    password = raw_password.strip()

    logger.warning(
        "BEACH login env debug | base_url=%r | username=%r | username_raw=%r | username_len=%d | "
        "password_masked=%r | password_raw_masked=%r | password_len=%d | "
        "username_changed_by_strip=%r | password_changed_by_strip=%r",
        settings.ZPRP_BASE_URL,
        username,
        raw_username,
        len(username),
        _mask_secret(password),
        _mask_secret(raw_password),
        len(password),
        raw_username != username,
        raw_password != password,
    )

    if not username or not password:
        raise HTTPException(
            status_code=500,
            detail="Brak ZPRP_BEACH_USERNAME lub ZPRP_BEACH_PASSWORD w settings/env.",
        )

    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=45.0,
    )

    try:
        login_payload = {
            "login": username,
            "haslo": password,
            "from": "/index.php?",
        }

        encoded_body = urlencode(
            login_payload,
            encoding="iso-8859-2",
            errors="strict",
        )

        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2",
        }

        logger.warning(
            "BEACH login request payload | login=%r | haslo_masked=%r | from=%r | body=%r",
            login_payload["login"],
            _mask_secret(login_payload["haslo"]),
            login_payload["from"],
            encoded_body,
        )

        resp_login = await client.request(
            "POST",
            "/login.php",
            content=encoded_body.encode("ascii"),
            headers=headers,
        )

        html_login = resp_login.content.decode("iso-8859-2", errors="replace")
        html_norm = html_login.lower()

        final_path = (resp_login.url.path or "").strip()
        final_url = str(resp_login.url)
        snippet = html_login[:1200]

        login_ok = (
            "zalogowany:" in html_norm
            or "sesja wygaśnie za" in html_norm
            or "wyloguj" in html_norm
        )

        invalid_credentials = (
            "nieznany użytkownik lub hasło" in html_norm
            or "spróbuj ponownie" in html_norm
            or "sprobuj ponownie" in html_norm
        )

        logger.warning(
            "BEACH login response | final_path=%r | final_url=%r | status=%r | login_ok=%r | invalid_credentials=%r",
            final_path,
            final_url,
            getattr(resp_login, "status_code", None),
            login_ok,
            invalid_credentials,
        )

        if invalid_credentials:
            logger.error(
                "BEACH login rejected by ZPRP | login=%r | password_masked=%r | final_path=%r | final_url=%r | snippet=%r",
                username,
                _mask_secret(password),
                final_path,
                final_url,
                snippet,
            )
            await client.aclose()
            raise HTTPException(
                status_code=401,
                detail=(
                    "Logowanie do baza.zprp.pl nie powiodło się: "
                    "ZPRP zwróciło 'Nieznany użytkownik lub hasło'. "
                    f"final_path={final_path!r}, final_url={final_url!r}, snippet={snippet!r}"
                ),
            )

        if not login_ok:
            logger.error(
                "BEACH login failed without success markers | login=%r | password_masked=%r | final_path=%r | final_url=%r | snippet=%r",
                username,
                _mask_secret(password),
                final_path,
                final_url,
                snippet,
            )
            await client.aclose()
            raise HTTPException(
                status_code=401,
                detail=(
                    "Logowanie do baza.zprp.pl nie powiodło się. "
                    f"final_path={final_path!r}, final_url={final_url!r}, snippet={snippet!r}"
                ),
            )

        client.cookies.update(resp_login.cookies)

        logger.warning(
            "BEACH login success | login=%r | password_masked=%r | final_url=%r",
            username,
            _mask_secret(password),
            final_url,
        )

        return client

    except HTTPException:
        raise
    except Exception as e:
        await client.aclose()
        logger.exception(
            "BEACH login unexpected error | login=%r | password_masked=%r",
            username,
            _mask_secret(password),
        )
        raise HTTPException(
            status_code=500,
            detail=f"Błąd podczas logowania do baza.zprp.pl: {e}",
        )


# =========================================================
# Helpers: filters / list URLs
# =========================================================

def _build_beach_teams_url(
    *,
    season_id: Optional[str] = None,
    province_id: Optional[str] = None,
    gender: Optional[str] = None,
    category_id: Optional[str] = None,
    club_id: Optional[str] = None,
    name: Optional[str] = None,
    sort: Optional[str] = None,
) -> str:
    params = {
        "a": "zespolyP",
        "Filtr_sezon": season_id or "",
        "Filtr_woj": province_id or "",
        "Filtr_plec": gender or "",
        "Filtr_kategoria": category_id or "",
        "Filtr_klub": club_id or "",
        "Nazwa": name or "",
        "sort": sort or "",
    }
    return f"/index.php?{urlencode(params)}"


def _parse_select_options(select_tag) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not select_tag:
        return out

    for opt in select_tag.find_all("option"):
        value = (opt.get("value") or "").strip()
        if not value:
            continue
        text = _norm_space(opt.get_text(" ", strip=True))
        text = re.sub(r"\s*\(\d+\)\s*$", "", text).strip()
        out[value] = text
    return out


def _extract_filters_meta(soup: BeautifulSoup) -> Dict[str, Dict[str, str]]:
    selects = soup.find_all("select")

    season_map: Dict[str, str] = {}
    province_map: Dict[str, str] = {}
    category_map: Dict[str, str] = {}
    club_map: Dict[str, str] = {}
    gender_map: Dict[str, str] = {}

    for sel in selects:
        name = (sel.get("name") or "").strip()
        if name == "Filtr_sezon":
            season_map = _parse_select_options(sel)
        elif name == "Filtr_woj":
            province_map = _parse_select_options(sel)
        elif name == "Filtr_kategoria":
            category_map = _parse_select_options(sel)
        elif name == "Filtr_klub":
            club_map = _parse_select_options(sel)
        elif name == "Filtr_plec":
            gender_map = _parse_select_options(sel)

    return {
        "season_map": season_map,
        "province_map": province_map,
        "category_map": category_map,
        "club_map": club_map,
        "gender_map": gender_map,
    }


def _extract_selected_options_map(select_tag) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "selected_id": None,
        "selected_label": None,
        "options": [],
    }
    if not select_tag:
        return out

    for opt in select_tag.find_all("option"):
        value = (opt.get("value") or "").strip()
        if not value:
            continue

        label = _norm_space(opt.get_text(" ", strip=True))
        label = re.sub(r"\s*\(\d+\)\s*$", "", label).strip()

        item = {
            "id": value,
            "label": label,
            "selected": opt.has_attr("selected"),
        }
        out["options"].append(item)

        if opt.has_attr("selected"):
            out["selected_id"] = value
            out["selected_label"] = label

    return out


def _parse_beach_filters_html(html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    season_sel = soup.find("select", attrs={"name": "Filtr_sezon"})
    province_sel = soup.find("select", attrs={"name": "Filtr_woj"})
    category_sel = soup.find("select", attrs={"name": "Filtr_kategoria"})
    club_sel = soup.find("select", attrs={"name": "Filtr_klub"})
    gender_sel = soup.find("select", attrs={"name": "Filtr_plec"})

    seasons = _extract_selected_options_map(season_sel)
    provinces = _extract_selected_options_map(province_sel)
    categories = _extract_selected_options_map(category_sel)
    clubs = _extract_selected_options_map(club_sel)
    genders = _extract_selected_options_map(gender_sel)

    return {
        "seasons": seasons,
        "provinces": provinces,
        "categories": categories,
        "clubs": clubs,
        "genders": genders,
    }


# =========================================================
# Helpers: teams list parsing
# =========================================================

def _find_beach_teams_table(soup: BeautifulSoup):
    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        if not rows:
            continue

        whole_text = _norm_space(table.get_text(" ", strip=True)).lower()
        if (
            "nazwa drużyny" in whole_text
            and "dane teleadresowe" in whole_text
            and "skład" in whole_text
            and "woj" in whole_text
            and "sezon" in whole_text
        ):
            return table
    return None


def _parse_contact_cell(td) -> Dict[str, Any]:
    lines = _extract_text_lines_from_cell(td)

    email = None
    notes = None
    website = None
    phone = None
    phone2 = None
    address = None
    postal_code = None
    city = None

    for a in td.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        txt = _norm_space(a.get_text(" ", strip=True))

        if href.lower().startswith("mailto:") and not email:
            email = txt or href.replace("mailto:", "").strip()
        elif txt and ("http://" in href or "https://" in href or href.startswith("http")):
            website = txt or href

    for idx, line in enumerate(lines):
        ll = line.lower()

        if ll.startswith("tel2:"):
            phone2 = line.split(":", 1)[1].strip() if ":" in line else line.replace("Tel2", "").strip()
            continue

        if ll.startswith("tel :") or ll.startswith("tel:"):
            phone = line.split(":", 1)[1].strip() if ":" in line else line.replace("Tel", "").strip()
            continue

        if ll.startswith("mail:"):
            rhs = line.split(":", 1)[1].strip() if ":" in line else ""
            if rhs and not email:
                email = _extract_email_from_text(rhs) or rhs
            elif not rhs and not email and idx + 1 < len(lines):
                maybe = _extract_email_from_text(lines[idx + 1])
                if maybe:
                    email = maybe
            continue

        if ll.startswith("uwagi:"):
            notes = line.split(":", 1)[1].strip() if ":" in line else ""
            continue

        if ll.startswith("www:"):
            rhs = line.split(":", 1)[1].strip() if ":" in line else ""
            website = rhs or None
            continue

        if not email:
            maybe = _extract_email_from_text(line)
            if maybe:
                email = maybe

    normal_lines: List[str] = []
    for line in lines:
        ll = line.lower()
        if ll.startswith(("tel", "mail:", "uwagi:", "www:")):
            continue
        if _looks_like_email(line):
            continue
        normal_lines.append(line)

    if normal_lines:
        address = normal_lines[0]

    for line in normal_lines[1:]:
        found_postal, found_city = _split_postal_and_city_from_line(line)

        if found_postal and not postal_code:
            postal_code = found_postal

        if found_city and not city:
            city = found_city

    if address and not postal_code:
        found_postal, found_city = _split_postal_and_city_from_line(address)
        if found_postal:
            postal_code = found_postal
            if found_city and not city:
                city = found_city
            address = None

    if not city and address and len(normal_lines) == 1:
        if not re.search(r"\d", address):
            city = _clean_city_candidate(address)
            address = None

    city = _clean_city_candidate(city)
    if city and _looks_like_email(city):
        city = None

    return {
        "address": address,
        "postal_code": postal_code,
        "city": city,
        "phone": phone,
        "phone2": phone2,
        "email": email,
        "notes": notes,
        "website": website,
        "raw_lines": lines,
    }


def _extract_squad_url(td) -> Optional[str]:
    a = td.find("a", href=True)
    if not a:
        return None
    href = (a.get("href") or "").strip()
    return _abs_index_url(href)


def _extract_selected_filter_value(soup: BeautifulSoup, select_name: str) -> Optional[str]:
    sel = soup.find("select", attrs={"name": select_name})
    if not sel:
        return None
    opt = sel.find("option", selected=True)
    if not opt:
        return None
    val = (opt.get("value") or "").strip()
    return val or None


def _parse_team_row(
    tds,
    *,
    season_map: Dict[str, str],
    province_map: Dict[str, str],
    category_map: Dict[str, str],
    club_map: Dict[str, str],
    gender_map: Dict[str, str],
    selected_season_id: Optional[str],
    selected_province_id: Optional[str],
    selected_category_id: Optional[str],
    selected_gender: Optional[str],
    selected_club_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    if len(tds) < 10:
        return None

    team_id_txt = _norm_space(tds[1].get_text(" ", strip=True))
    if not re.fullmatch(r"\d+", team_id_txt):
        return None

    team_id = int(team_id_txt)
    team_name = _norm_space(tds[2].get_text(" ", strip=True))
    gender = _norm_space(tds[3].get_text(" ", strip=True)) or None
    category = _norm_space(tds[4].get_text(" ", strip=True)) or None
    club = _norm_space(tds[5].get_text(" ", strip=True)) or None
    province = _norm_space(tds[6].get_text(" ", strip=True)) or None
    season = _norm_space(tds[7].get_text(" ", strip=True)) or None

    contact = _parse_contact_cell(tds[8])
    squad_url = _extract_squad_url(tds[9])

    category_id = selected_category_id
    season_id = selected_season_id
    province_id = selected_province_id
    club_id = selected_club_id
    gender_id = selected_gender

    if not category_id and category:
        for k, v in category_map.items():
            if v.strip().lower() == category.strip().lower():
                category_id = k
                break

    if not season_id and season:
        for k, v in season_map.items():
            if v.strip().lower() == season.strip().lower():
                season_id = k
                break

    if not province_id and province:
        for k, v in province_map.items():
            if v.strip().lower() == province.strip().lower():
                province_id = k
                break

    if not club_id and club:
        for k, v in club_map.items():
            if v.strip().lower() == club.strip().lower():
                club_id = k
                break

    gender_label = gender_map.get(gender_id or "", None) if gender_id else None
    if not gender_label and gender:
        if gender == "K":
            gender_label = "Kobiety"
        elif gender == "M":
            gender_label = "Mężczyźni"

    return {
        "id": team_id,
        "team_name": team_name,
        "gender": gender,
        "gender_label": gender_label,
        "category_id": category_id,
        "category": category,
        "club_id": club_id,
        "club": club,
        "province_id": province_id,
        "province": province,
        "season_id": season_id,
        "season": season,
        "contact": contact,
        "squad_url": squad_url,
    }


def _parse_beach_teams_html(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")

    filters_meta = _extract_filters_meta(soup)
    season_map = filters_meta["season_map"]
    province_map = filters_meta["province_map"]
    category_map = filters_meta["category_map"]
    club_map = filters_meta["club_map"]
    gender_map = filters_meta["gender_map"]

    selected_season_id = _extract_selected_filter_value(soup, "Filtr_sezon")
    selected_province_id = _extract_selected_filter_value(soup, "Filtr_woj")
    selected_category_id = _extract_selected_filter_value(soup, "Filtr_kategoria")
    selected_gender = _extract_selected_filter_value(soup, "Filtr_plec")
    selected_club_id = _extract_selected_filter_value(soup, "Filtr_klub")

    table = _find_beach_teams_table(soup)
    if not table:
        return []

    items: List[Dict[str, Any]] = []

    for tr in table.find_all("tr"):
        tds = tr.find_all("td", recursive=False)
        if not tds:
            continue

        parsed = _parse_team_row(
            tds,
            season_map=season_map,
            province_map=province_map,
            category_map=category_map,
            club_map=club_map,
            gender_map=gender_map,
            selected_season_id=selected_season_id,
            selected_province_id=selected_province_id,
            selected_category_id=selected_category_id,
            selected_gender=selected_gender,
            selected_club_id=selected_club_id,
        )
        if parsed:
            items.append(parsed)

    return items


# =========================================================
# Helpers: squad parsing
# =========================================================

def _extract_photo_url_from_img(img_tag) -> Optional[str]:
    if not img_tag:
        return None

    onmouseover = img_tag.get("onMouseOver") or img_tag.get("onmouseover") or ""
    m = re.search(r"foto/[^'\"<> ]+\.(?:jpg|jpeg|png|webp)", onmouseover, re.I)
    if m:
        return m.group(0)

    src = (img_tag.get("src") or "").strip()
    if src:
        return src
    return None


def _extract_query_param_from_href(href: str, key: str) -> Optional[str]:
    try:
        parsed = urlparse(href)
        q = parse_qs(parsed.query)
        vals = q.get(key) or []
        if vals:
            return vals[0]
    except Exception:
        return None
    return None


def _extract_player_details_url(td) -> Optional[str]:
    for a in td.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if "a=zawodnicy" in href and "b=szczegoly" in href and "NrZawodnika=" in href:
            return _abs_index_url(href)
    return None


def _extract_person_details_url(td) -> Optional[str]:
    for a in td.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if "a=osoba" in href and "b=szczegoly" in href and "NrOsoby=" in href:
            return _abs_index_url(href)
    return None


def _extract_player_id_from_details_url(details_url: Optional[str]) -> Optional[int]:
    if not details_url:
        return None
    val = _extract_query_param_from_href(details_url, "NrZawodnika")
    if val and val.isdigit():
        return int(val)
    return None


def _extract_person_id_from_details_url(details_url: Optional[str]) -> Optional[int]:
    if not details_url:
        return None
    val = _extract_query_param_from_href(details_url, "NrOsoby")
    if val and val.isdigit():
        return int(val)
    return None


def _extract_team_title_and_meta_from_squad_table(table) -> Dict[str, Any]:
    rows = table.find_all("tr", recursive=False)

    title = ""
    if rows:
        first_tds = rows[0].find_all("td", recursive=False)
        if first_tds:
            title = _norm_space(first_tds[0].get_text(" ", strip=True))

    season_label = None
    category_label = None
    team_display = None
    club_display = None

    # np. "Akademia Handballu Ruch Chorzów (Akademia Handballu Ruch Chorzów) 2024/2025 - Junior mł."
    m = re.search(r"^(.*?)\s+\((.*?)\)\s+(\d{4}/\d{4})\s*-\s*(.+?)(?:\s+OSIĄGNIĘTO.*)?$", title, re.I)
    if m:
        team_display = _norm_space(m.group(1))
        club_display = _norm_space(m.group(2))
        season_label = _norm_space(m.group(3))
        category_label = _norm_space(m.group(4))

    return {
        "title": title,
        "team_display": team_display,
        "club_display": club_display,
        "season_label": season_label,
        "category_label": category_label,
    }


def _row_text(tr) -> str:
    return _norm_space(tr.get_text(" ", strip=True)).lower()


def _find_beach_menu_anchor(soup: BeautifulSoup):
    """
    Znajdź kotwicę menu PLAŻA. Interesuje nas link 'Drużyny PLAŻA',
    bo dopiero po tym menu zaczyna się właściwa treść składu.
    """
    for a in soup.find_all("a", href=True):
        text = _norm_space(a.get_text(" ", strip=True)).lower()
        href = (a.get("href") or "").lower()
        if (
            "drużyny plaża" in text
            or "druzyny plaza" in text
            or "a=zespolyp" in href
        ):
            return a
    return None


def _collect_tables_after_menu(soup: BeautifulSoup) -> List[Any]:
    menu_anchor = _find_beach_menu_anchor(soup)
    if not menu_anchor:
        return soup.find_all("table")

    tables: List[Any] = []
    for table in menu_anchor.find_all_next("table"):
        tables.append(table)

    return tables


def _find_main_squad_table(soup: BeautifulSoup):
    player_href_re = re.compile(r"[?&]a=zawodnicy(?:P)?[&].*b=szczegoly.*NrZawodnika=\d+", re.I)

    candidates = []

    for table in _collect_tables_after_menu(soup):
        # tu MUSI być bez recursive=False, bo header siedzi w <form>
        rows = table.find_all("tr")
        if len(rows) < 3:
            continue

        first_row = rows[0]
        first_row_tds = first_row.find_all("td", recursive=False)
        first_row_text = _row_text(first_row)

        has_team_title_row = False
        if first_row_tds:
            first_td = first_row_tds[0]
            colspan = (first_td.get("colspan") or "").strip()
            if colspan == "20" and first_td.find("b"):
                has_team_title_row = True

        if not has_team_title_row:
            continue

        # header może siedzieć w <form>, więc szukamy w całej tabeli
        header_row = None
        for tr in rows[:8]:
            txt = _row_text(tr)
            if (
                "lp" in txt
                and "foto" in txt
                and "nazwisko" in txt
                and ("imię" in txt or "imie" in txt)
                and "nr koszulki" in txt
                and "licencja zprp" in txt
            ):
                header_row = tr
                break

        if header_row is None:
            continue

        has_direct_player_row = False
        for tr in rows:
            if tr.find("a", href=player_href_re):
                has_direct_player_row = True
                break

        if not has_direct_player_row:
            continue

        score = 0
        if re.search(r"\b\d{4}/\d{4}\b", first_row_text):
            score += 5
        if "(" in first_row_text and ")" in first_row_text:
            score += 2
        if any(x in first_row_text for x in ["senior", "junior", "mł", "ml"]):
            score += 2

        candidates.append((score, table))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _find_companions_table(soup: BeautifulSoup, main_table=None):
    person_href_re = re.compile(r"[?&]a=osoba(?:P)?[&].*b=szczegoly.*NrOsoby=\d+", re.I)

    tables = _collect_tables_after_menu(soup)

    if main_table is not None:
        try:
            start_idx = tables.index(main_table) + 1
            tables = tables[start_idx:]
        except ValueError:
            pass

    for table in tables:
        rows = table.find_all("tr")
        if len(rows) < 2:
            continue

        first_row = rows[0]
        first_row_tds = first_row.find_all("td", recursive=False)
        first_row_text = _row_text(first_row)

        if not first_row_tds:
            continue

        first_td = first_row_tds[0]
        colspan = (first_td.get("colspan") or "").strip()

        if colspan != "6":
            continue

        if "osoby towarzyszące" not in first_row_text:
            continue

        has_direct_person_row = any(tr.find("a", href=person_href_re) for tr in rows[1:])
        if not has_direct_person_row:
            continue

        return table

    return None


def _extract_first_jersey_number(text: str) -> Optional[str]:
    s = _norm_space(text or "")
    m = re.search(r"nr\s+koszulki\s+(\d+)", s, re.I)
    if m:
        return m.group(1)
    return None


def _extract_transfer_context(text: str) -> Dict[str, Any]:
    s = _norm_space(text or "")

    parent_club_name = None
    loan_to_club_name = None

    m_club = re.search(r"Klub:\s*(.+?)(?:użyczenie szkoleniowe do:|uzyczenie szkoleniowe do:|$)", s, re.I)
    if m_club:
        parent_club_name = _norm_space(m_club.group(1))

    m_loan = re.search(r"(?:użyczenie szkoleniowe do:|uzyczenie szkoleniowe do:)\s*(.+?)$", s, re.I)
    if m_loan:
        loan_to_club_name = _norm_space(m_loan.group(1))

    return {
        "parent_club_name": parent_club_name,
        "loan_to_club_name": loan_to_club_name,
        "is_transferred": bool(parent_club_name or loan_to_club_name),
    }


def _extract_other_team_url(td) -> Optional[str]:
    for a in td.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if "a=zespolyP" in href and "b=sklad" in href and "Filtr_zespol=" in href:
            return _abs_index_url(href)
    return None


def _parse_player_row(
    tr,
    *,
    season_end_year: Optional[int],
) -> Optional[Dict[str, Any]]:
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 13:
        return None

    lp = _norm_space(tds[0].get_text(" ", strip=True))
    if not re.fullmatch(r"\d+", lp):
        return None

    img_tag = tds[1].find("img")
    photo_url = _extract_photo_url_from_img(img_tag)

    last_name = _norm_space(tds[2].get_text(" ", strip=True)) or None
    first_name = _norm_space(tds[3].get_text(" ", strip=True)) or None
    country = _norm_space(tds[4].get_text(" ", strip=True)) or None

    birth_text = _norm_space(tds[5].get_text(" ", strip=True))
    birth_date = None
    m_birth = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", birth_text)
    if m_birth:
        birth_date = m_birth.group(1)

    position = _norm_space(tds[7].get_text(" ", strip=True)) or None

    jersey_text = _norm_space(tds[8].get_text(" ", strip=True))
    jersey_number = _extract_first_jersey_number(jersey_text)

    license_number, license_valid = _extract_year_highlight_validity(tds[9], season_end_year)

    status_td = tds[10]
    status_text = _norm_space(status_td.get_text(" ", strip=True)).lower()
    status_bg = (status_td.get("bgcolor") or "").strip().lower()

    other_team_url = _extract_other_team_url(tds[11])
    details_url = _extract_player_details_url(tds[12])
    player_id = _extract_player_id_from_details_url(details_url)

    transfer_ctx = _extract_transfer_context(jersey_text)
    status_links = [
        (a.get("href") or "").strip().lower()
        for a in status_td.find_all("a", href=True)
    ]

    is_transferred = (
        transfer_ctx["is_transferred"]
        or any("z=dopisz2" in href or "z=usun2" in href for href in status_links)
        or status_bg == "#ffff00"
    )

    # Green bgcolor = player is added to squad (checkbox checked + "Usuń" link)
    in_squad = status_bg == "#00ff00"

    return {
        "player_id": player_id,
        "lp": int(lp),
        "photo_url": photo_url,
        "last_name": last_name,
        "first_name": first_name,
        "country": country,
        "birth_date": birth_date,
        "position": position,
        "jersey_number": jersey_number,
        "zprp_license_number": license_number,
        "zprp_license_valid_for_season": license_valid,
        "is_transferred": is_transferred,
        "in_squad": in_squad,
        "parent_club_name": transfer_ctx["parent_club_name"],
        "loan_to_club_name": transfer_ctx["loan_to_club_name"],
        "other_team_url": other_team_url,
        "details_url": details_url,
    }


def _parse_historical_player_row(tr) -> Optional[Dict[str, Any]]:
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 12:
        return None

    lp = _norm_space(tds[0].get_text(" ", strip=True))
    if not re.fullmatch(r"\d+", lp):
        return None

    img_tag = tds[1].find("img")
    photo_url = _extract_photo_url_from_img(img_tag)

    last_name = _norm_space(tds[2].get_text(" ", strip=True)) or None
    first_name = _norm_space(tds[3].get_text(" ", strip=True)) or None
    country = _norm_space(tds[4].get_text(" ", strip=True)) or None

    birth_text = _norm_space(tds[5].get_text(" ", strip=True))
    birth_date = None
    m_birth = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", birth_text)
    if m_birth:
        birth_date = m_birth.group(1)

    source_club = _norm_space(tds[7].get_text(" ", strip=True)) or None
    other_team_url = _extract_other_team_url(tds[10])
    details_url = _extract_player_details_url(tds[11])
    player_id = _extract_player_id_from_details_url(details_url)

    return {
        "player_id": player_id,
        "lp": int(lp),
        "photo_url": photo_url,
        "last_name": last_name,
        "first_name": first_name,
        "country": country,
        "birth_date": birth_date,
        "source_club_name": source_club,
        "other_team_url": other_team_url,
        "details_url": details_url,
        "is_historical": True,
    }


def _parse_companion_row(
    tr,
    *,
    season_end_year: Optional[int],
) -> Optional[Dict[str, Any]]:
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 5:
        return None

    full_name = _norm_space(tds[0].get_text(" ", strip=True))
    role = _norm_space(tds[1].get_text(" ", strip=True))
    if not full_name or not role:
        return None

    beach_license = _norm_space(tds[2].get_text(" ", strip=True)) or None
    license_number, license_valid = _extract_year_highlight_validity(tds[3], season_end_year)
    details_url = _extract_person_details_url(tds[4])
    person_id = _extract_person_id_from_details_url(details_url)

    return {
        "person_id": person_id,
        "full_name": full_name,
        "role": role,
        "beach_license": beach_license,
        "license_number": license_number,
        "license_valid_for_season": license_valid,
        "details_url": details_url,
    }


def _parse_beach_team_squad_html(
    html: str,
    *,
    squad_url: Optional[str] = None,
) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    main_table = _find_main_squad_table(soup)
    if not main_table:
        raise HTTPException(status_code=404, detail="Nie znaleziono tabeli składu drużyny")

    meta = _extract_team_title_and_meta_from_squad_table(main_table)
    season_end_year = _season_end_year_from_label(meta.get("season_label"))
    if season_end_year is None:
        title = meta.get("title") or ""
        m_year = re.search(r"\b(\d{4})/(\d{4})\b", title)
        if m_year:
            season_end_year = int(m_year.group(2))
    logger.warning(
        "BEACH squad parse | squad_url=%r | meta_title=%r | season_label=%r | season_end_year=%r",
        squad_url,
        meta.get("title"),
        meta.get("season_label"),
        season_end_year,
    )

    # fallback: spróbuj ustalić sezon po parametrze Filtr_sezon z URL i z ukrytych inputów,
    # ale tylko jeśli z tytułu nie udało się go odczytać
    if season_end_year is None:
        hidden_season = soup.find("input", attrs={"name": "Filtr_sezon"})
        hidden_season_val = (hidden_season.get("value") or "").strip() if hidden_season else None
        if hidden_season_val:
            # tutaj nie znamy mapy id->etykieta sezonu, więc zostawiamy tylko fallback miękki
            # sezon_end_year zostaje None, ale meta nadal będzie poprawne jeśli title został odczytany
            pass

    players: List[Dict[str, Any]] = []
    historical_players: List[Dict[str, Any]] = []
    companions: List[Dict[str, Any]] = []

    seen_player_ids: set[int] = set()

    rows = main_table.find_all("tr", recursive=False)
    historical_mode = False

    for tr in rows:
        txt = _norm_space(tr.get_text(" ", strip=True))

        if "Zawodnicy historycznie związani z klubem drużyny" in txt:
            historical_mode = True
            continue

        if not historical_mode:
            player = _parse_player_row(tr, season_end_year=season_end_year)
            if player:
                pid = player.get("player_id")
                if pid is None or pid not in seen_player_ids:
                    if pid is not None:
                        seen_player_ids.add(pid)
                    players.append(player)
        else:
            hist = _parse_historical_player_row(tr)
            if hist:
                historical_players.append(hist)

    companions_table = _find_companions_table(soup, main_table=main_table)
    if companions_table:
        for tr in companions_table.find_all("tr", recursive=False):
            comp = _parse_companion_row(tr, season_end_year=season_end_year)
            if comp:
                companions.append(comp)

    return {
        "team_meta": {
            **meta,
            "season_end_year": season_end_year,
            "squad_url": squad_url,
        },
        "players": players,
        "historical_players": historical_players,
        "companions": companions,
    }


# =========================================================
# Helpers: DB conversion / update
# =========================================================

def _row_to_item(row) -> BeachTeamItem:
    data = dict(row)
    return BeachTeamItem(
        id=data["id"],
        team_name=data["team_name"],
        gender=data.get("gender"),
        gender_label=data.get("gender_label"),
        category_id=data.get("category_id"),
        category=data.get("category"),
        club_id=data.get("club_id"),
        club=data.get("club"),
        province_id=data.get("province_id"),
        province=data.get("province"),
        season_id=data.get("season_id"),
        season=data.get("season"),
        contact=BeachTeamContact(**(data.get("contact_json") or {})),
        squad_url=data.get("squad_url"),
        source=data.get("source") or "zprp",
        last_synced_at=data.get("last_synced_at"),
        created_at=data.get("created_at"),
        updated_at=data.get("updated_at"),
    )


def _build_local_filters(
    *,
    season_id: Optional[str],
    province_id: Optional[str],
    gender: Optional[str],
    category_id: Optional[str],
    club_id: Optional[str],
    name: Optional[str],
) -> List[Any]:
    clauses = []

    if season_id:
        clauses.append(beach_teams.c.season_id == season_id)
    if province_id:
        clauses.append(beach_teams.c.province_id == province_id)
    if gender:
        clauses.append(beach_teams.c.gender == gender)
    if category_id:
        clauses.append(beach_teams.c.category_id == category_id)
    if club_id:
        clauses.append(beach_teams.c.club_id == club_id)
    if name:
        clauses.append(func.lower(beach_teams.c.team_name).contains(name.strip().lower()))

    return clauses


async def _maybe_save_team_squad_to_db(team_id: int, squad_data: Dict[str, Any]) -> bool:
    values: Dict[str, Any] = {}
    if _table_has_column("roster_json"):
        values["roster_json"] = squad_data.get("players") or []
    if _table_has_column("companions_json"):
        values["companions_json"] = squad_data.get("companions") or []
    if _table_has_column("historical_players_json"):
        values["historical_players_json"] = squad_data.get("historical_players") or []
    if _table_has_column("squad_last_synced_at"):
        values["squad_last_synced_at"] = _now_utc()

    if not values:
        logger.warning(
            "BEACH team squad save skipped | team_id=%r | reason=%r",
            team_id,
            "missing roster_json/companions_json/historical_players_json/squad_last_synced_at columns",
        )
        return False

    await database.execute(
        update(beach_teams)
        .where(beach_teams.c.id == team_id)
        .values(**values)
    )
    return True


# =========================================================
# Helpers: live fetch
# =========================================================

async def _fetch_squad_for_team(
    client: AsyncClient,
    *,
    squad_url: str,
) -> Dict[str, Any]:
    resp = await client.get(squad_url, cookies=client.cookies)
    html = resp.content.decode("iso-8859-2", errors="replace")
    return _parse_beach_team_squad_html(html, squad_url=squad_url)


async def _fetch_teams_from_zprp(
    settings: Settings,
    *,
    season_id: Optional[str] = None,
    province_id: Optional[str] = None,
    gender: Optional[str] = None,
    category_id: Optional[str] = None,
    club_id: Optional[str] = None,
    name: Optional[str] = None,
    sort: Optional[str] = None,
    include_squads: bool = False,
) -> List[Dict[str, Any]]:
    client = await _login_beach_client(settings)
    try:
        url = _build_beach_teams_url(
            season_id=season_id,
            province_id=province_id,
            gender=gender,
            category_id=category_id,
            club_id=club_id,
            name=name,
            sort=sort,
        )
        resp = await client.get(url, cookies=client.cookies)
        html = resp.content.decode("iso-8859-2", errors="replace")
        teams = _parse_beach_teams_html(html)

        if include_squads:
            for team in teams:
                squad_url = team.get("squad_url")
                if not squad_url:
                    team["squad"] = None
                    continue
                try:
                    team["squad"] = await _fetch_squad_for_team(client, squad_url=squad_url)
                except Exception as e:
                    logger.exception("BEACH squad fetch failed | team_id=%r | squad_url=%r", team.get("id"), squad_url)
                    team["squad_error"] = str(e)
                    team["squad"] = None

        return teams
    finally:
        await client.aclose()


async def _fetch_filters_from_zprp(
    settings: Settings,
    *,
    season_id: Optional[str] = None,
    province_id: Optional[str] = None,
    gender: Optional[str] = None,
    category_id: Optional[str] = None,
    club_id: Optional[str] = None,
) -> Dict[str, Any]:
    client = await _login_beach_client(settings)
    try:
        url = _build_beach_teams_url(
            season_id=season_id,
            province_id=province_id,
            gender=gender,
            category_id=category_id,
            club_id=club_id,
            name=None,
            sort=None,
        )
        resp = await client.get(url, cookies=client.cookies)
        html = resp.content.decode("iso-8859-2", errors="replace")
        return _parse_beach_filters_html(html)
    finally:
        await client.aclose()


async def _fetch_single_team_from_zprp(
    settings: Settings,
    *,
    team_id: int,
    season_id: Optional[str] = None,
) -> Dict[str, Any]:
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if row and dict(row).get("squad_url"):
        team = _row_to_item(row)
        client = await _login_beach_client(settings)
        try:
            squad = await _fetch_squad_for_team(client, squad_url=team.squad_url)
            return {
                "team": team.model_dump(),
                "squad": squad,
            }
        finally:
            await client.aclose()

    fetched = await _fetch_teams_from_zprp(
        settings,
        season_id=season_id,
        include_squads=False,
    )
    match = next((t for t in fetched if t["id"] == team_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Nie znaleziono drużyny w ZPRP")

    client = await _login_beach_client(settings)
    try:
        squad = await _fetch_squad_for_team(client, squad_url=match["squad_url"])
        return {
            "team": match,
            "squad": squad,
        }
    finally:
        await client.aclose()


# =========================================================
# Local DB CRUD
# =========================================================

@router.get("/local", response_model=BeachTeamsListResponse)
async def list_local_beach_teams(
    season_id: Optional[str] = Query(None),
    province_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    category_id: Optional[str] = Query(None),
    club_id: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
):
    clauses = _build_local_filters(
        season_id=season_id,
        province_id=province_id,
        gender=gender,
        category_id=category_id,
        club_id=club_id,
        name=name,
    )

    q = select(beach_teams)
    if clauses:
        q = q.where(and_(*clauses))
    q = q.order_by(beach_teams.c.team_name.asc(), beach_teams.c.id.asc())

    rows = await database.fetch_all(q)
    return BeachTeamsListResponse(teams=[_row_to_item(r) for r in rows])


def _normalize_for_search(s: str) -> str:
    """Lowercase + remove Polish diacritics for fuzzy matching."""
    import unicodedata
    return unicodedata.normalize("NFD", s.lower()).encode("ascii", "ignore").decode("ascii").strip()


def _tokens_match(tokens: List[str], text: str) -> bool:
    """All query tokens must appear somewhere in the normalized text (order-independent)."""
    normalized = _normalize_for_search(text)
    return all(t in normalized for t in tokens)


@router.get("/local/squad-search")
async def search_local_teams_by_squad_member(q: str = Query(..., min_length=2)):
    """Return teams whose roster or companions contain a person matching *q*.

    Matching is token-based and order-independent: 'Damian Wieczorek'
    matches 'WIECZOREK DAMIAN' and vice versa.
    """
    import json as _json

    tokens = [t for t in _normalize_for_search(q).split() if t]
    if not tokens:
        return {"results": []}

    rows = await database.fetch_all(select(beach_teams))
    results = []

    for row in rows:
        data = dict(row)
        matches = []

        raw_companions = data.get("companions_json")
        if isinstance(raw_companions, str):
            try:
                raw_companions = _json.loads(raw_companions)
            except Exception:
                raw_companions = []
        companions = raw_companions or []

        raw_players = data.get("roster_json")
        if isinstance(raw_players, str):
            try:
                raw_players = _json.loads(raw_players)
            except Exception:
                raw_players = []
        players = raw_players or []

        for p in players:
            if not isinstance(p, dict):
                continue
            last = p.get("last_name", "") or ""
            first = p.get("first_name", "") or ""
            combined = f"{last} {first} {first} {last}".strip()
            if _tokens_match(tokens, combined):
                matches.append({"name": f"{last} {first}".strip(), "role": "player"})

        for c in companions:
            if not isinstance(c, dict):
                continue
            full = c.get("full_name", "") or ""
            if _tokens_match(tokens, full):
                matches.append({"name": full.strip(), "role": "coach"})

        if matches:
            results.append({
                "team": _row_to_item(row).model_dump(),
                "matches": matches,
            })

    return {"results": results}


@router.get("/local/{team_id}", response_model=BeachTeamItem)
async def get_local_beach_team(team_id: int):
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(status_code=404, detail="Drużyna nie istnieje")
    return _row_to_item(row)


@router.get("/local/{team_id}/squad")
async def get_local_beach_team_squad(team_id: int):
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(status_code=404, detail="Drużyna nie istnieje")

    data = dict(row)
    # Merge medical exam data into each player record
    medical_exams = {}
    if _table_has_column("medical_exams_json"):
        medical_exams = data.get("medical_exams_json") or {}
        if not isinstance(medical_exams, dict):
            medical_exams = {}

    players = data.get("roster_json") if _table_has_column("roster_json") else None
    if players and medical_exams:
        for p in players:
            pid = str(p.get("player_id", ""))
            exam = medical_exams.get(pid)
            if exam and isinstance(exam, dict):
                p["medical_exam_valid_until"] = exam.get("valid_until")
                p["medical_exam_has_check"] = exam.get("has_check", False)
                p["medical_exam_has_wzpr"] = exam.get("has_wzpr", False)
                # backward compat: source field
                p["medical_exam_source"] = "WZPR" if exam.get("has_wzpr") else None
            else:
                p["medical_exam_valid_until"] = None
                p["medical_exam_has_check"] = False
                p["medical_exam_has_wzpr"] = False
                p["medical_exam_source"] = None

    return {
        "team": _row_to_item(row).model_dump(),
        "players": players,
        "companions": data.get("companions_json") if _table_has_column("companions_json") else None,
        "historical_players": data.get("historical_players_json") if _table_has_column("historical_players_json") else None,
        "squad_last_synced_at": data.get("squad_last_synced_at") if _table_has_column("squad_last_synced_at") else None,
        "medical_exams_checked_at": data.get("medical_exams_checked_at") if _table_has_column("medical_exams_checked_at") else None,
        "db_has_squad_columns": {
            "roster_json": _table_has_column("roster_json"),
            "companions_json": _table_has_column("companions_json"),
            "historical_players_json": _table_has_column("historical_players_json"),
            "squad_last_synced_at": _table_has_column("squad_last_synced_at"),
        },
    }


class JerseyOverridesUpdateRequest(BaseModel):
    overrides: Dict[str, str]  # player_id (as string) -> jersey number string


@router.get("/local/{team_id}/jersey-overrides", summary="Pobierz nadpisania numerów zawodników")
async def get_team_jersey_overrides(team_id: int):
    if not _table_has_column("jersey_overrides"):
        return {"overrides": {}}

    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(404, "Drużyna nie istnieje")

    raw = dict(row).get("jersey_overrides")
    if raw is None:
        return {"overrides": {}}
    overrides = raw if isinstance(raw, dict) else {}
    return {"overrides": overrides}


@router.patch("/local/{team_id}/jersey-overrides", summary="Zaktualizuj nadpisania numerów zawodników")
async def patch_team_jersey_overrides(
    team_id: int,
    req: JerseyOverridesUpdateRequest,
):
    if not _table_has_column("jersey_overrides"):
        return {"overrides": {}}

    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(404, "Drużyna nie istnieje")

    raw = dict(row).get("jersey_overrides")
    current_overrides: Dict[str, str] = raw if isinstance(raw, dict) else {}

    if req.overrides:
        current_overrides.update(req.overrides)
    else:
        current_overrides = {}

    await database.execute(
        update(beach_teams)
        .where(beach_teams.c.id == team_id)
        .values(jersey_overrides=current_overrides, updated_at=_now_utc())
    )

    return {"overrides": current_overrides}


@router.post("/local", response_model=BeachTeamItem)
async def create_local_beach_team(req: BeachTeamCreateRequest):
    exists = await database.fetch_one(select(beach_teams.c.id).where(beach_teams.c.id == req.id))
    if exists:
        raise HTTPException(status_code=409, detail="Drużyna o takim id już istnieje")

    payload = {
        "id": req.id,
        "team_name": req.team_name,
        "gender": req.gender,
        "gender_label": req.gender_label,
        "category_id": req.category_id,
        "category": req.category,
        "club_id": req.club_id,
        "club": req.club,
        "province_id": req.province_id,
        "province": req.province,
        "season_id": req.season_id,
        "season": req.season,
        "contact_json": (req.contact.model_dump() if req.contact else {}),
        "squad_url": req.squad_url,
        "source": req.source or "manual",
        "last_synced_at": None,
    }

    await database.execute(beach_teams.insert().values(**payload))
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == req.id))
    if not row:
        raise HTTPException(status_code=500, detail="Nie udało się utworzyć drużyny")
    return _row_to_item(row)


@router.patch("/local/{team_id}", response_model=BeachTeamItem)
async def patch_local_beach_team(team_id: int, req: BeachTeamUpdateRequest):
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(status_code=404, detail="Drużyna nie istnieje")

    patch = req.model_dump(exclude_unset=True)

    values: Dict[str, Any] = {}
    for key, value in patch.items():
        if key == "contact":
            values["contact_json"] = value.model_dump() if isinstance(value, BeachTeamContact) else value
        else:
            values[key] = value

    if values:
        await database.execute(
            update(beach_teams)
            .where(beach_teams.c.id == team_id)
            .values(**values)
        )

    row2 = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row2:
        raise HTTPException(status_code=500, detail="Nie udało się zaktualizować drużyny")
    return _row_to_item(row2)


@router.put("/local/{team_id}", response_model=BeachTeamItem)
async def put_local_beach_team(team_id: int, req: BeachTeamPutRequest):
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(status_code=404, detail="Drużyna nie istnieje")

    values = {
        "team_name": req.team_name,
        "gender": req.gender,
        "gender_label": req.gender_label,
        "category_id": req.category_id,
        "category": req.category,
        "club_id": req.club_id,
        "club": req.club,
        "province_id": req.province_id,
        "province": req.province,
        "season_id": req.season_id,
        "season": req.season,
        "contact_json": req.contact.model_dump(),
        "squad_url": req.squad_url,
        "source": req.source or "manual",
    }

    await database.execute(
        update(beach_teams)
        .where(beach_teams.c.id == team_id)
        .values(**values)
    )

    row2 = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row2:
        raise HTTPException(status_code=500, detail="Nie udało się nadpisać drużyny")
    return _row_to_item(row2)


@router.delete("/local/{team_id}")
async def delete_local_beach_team(team_id: int):
    row = await database.fetch_one(select(beach_teams.c.id).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(status_code=404, detail="Drużyna nie istnieje")

    await database.execute(delete(beach_teams).where(beach_teams.c.id == team_id))
    return {"success": True, "id": team_id}


# =========================================================
# Live endpoints from ZPRP
# =========================================================

@router.get("/zprp")
async def list_beach_teams_from_zprp(
    season_id: Optional[str] = Query(None),
    province_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    category_id: Optional[str] = Query(None),
    club_id: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    include_squads: bool = Query(False, description="Czy pobierać też składy drużyn"),
    settings: Settings = Depends(get_settings),
):
    teams = await _fetch_teams_from_zprp(
        settings,
        season_id=season_id,
        province_id=province_id,
        gender=gender,
        category_id=category_id,
        club_id=club_id,
        name=name,
        sort=sort,
        include_squads=include_squads,
    )

    if include_squads:
        return {"teams": teams}

    items = [
        BeachTeamItem(
            id=t["id"],
            team_name=t["team_name"],
            gender=t.get("gender"),
            gender_label=t.get("gender_label"),
            category_id=t.get("category_id"),
            category=t.get("category"),
            club_id=t.get("club_id"),
            club=t.get("club"),
            province_id=t.get("province_id"),
            province=t.get("province"),
            season_id=t.get("season_id"),
            season=t.get("season"),
            contact=BeachTeamContact(**(t.get("contact") or {})),
            squad_url=t.get("squad_url"),
            source="zprp",
            last_synced_at=None,
        )
        for t in teams
    ]
    return BeachTeamsListResponse(teams=items)


@router.get("/zprp/full")
async def list_beach_teams_full_from_zprp(
    season_id: Optional[str] = Query(None),
    province_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    category_id: Optional[str] = Query(None),
    club_id: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    include_squads: bool = Query(False),
    settings: Settings = Depends(get_settings),
):
    teams = await _fetch_teams_from_zprp(
        settings,
        season_id=season_id,
        province_id=province_id,
        gender=gender,
        category_id=category_id,
        club_id=club_id,
        name=name,
        sort=sort,
        include_squads=include_squads,
    )
    return {"teams": teams}


@router.get("/zprp/filters", response_model=BeachTeamsFiltersResponse)
async def get_beach_teams_filters_from_zprp(
    season_id: Optional[str] = Query(None),
    province_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    category_id: Optional[str] = Query(None),
    club_id: Optional[str] = Query(None),
    settings: Settings = Depends(get_settings),
):
    data = await _fetch_filters_from_zprp(
        settings,
        season_id=season_id,
        province_id=province_id,
        gender=gender,
        category_id=category_id,
        club_id=club_id,
    )
    return BeachTeamsFiltersResponse(**data)


@router.get("/zprp/squad")
async def get_beach_team_squad_from_zprp(
    team_id: Optional[int] = Query(None),
    squad_url: Optional[str] = Query(None),
    season_id: Optional[str] = Query(None),
    province_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    category_id: Optional[str] = Query(None),
    club_id: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    settings: Settings = Depends(get_settings),
):
    if squad_url:
        client = await _login_beach_client(settings)
        try:
            squad = await _fetch_squad_for_team(client, squad_url=_abs_index_url(squad_url))
            return {"team": None, "squad": squad}
        finally:
            await client.aclose()

    if team_id is not None:
        return await _fetch_single_team_from_zprp(
            settings,
            team_id=team_id,
            season_id=season_id,
        )

    teams = await _fetch_teams_from_zprp(
        settings,
        season_id=season_id,
        province_id=province_id,
        gender=gender,
        category_id=category_id,
        club_id=club_id,
        name=name,
        sort=sort,
        include_squads=False,
    )

    if len(teams) != 1:
        raise HTTPException(
            status_code=400,
            detail="Podaj team_id albo taki zestaw filtrów, który zwraca dokładnie 1 drużynę.",
        )

    match = teams[0]
    client = await _login_beach_client(settings)
    try:
        squad = await _fetch_squad_for_team(client, squad_url=match["squad_url"])
        return {"team": match, "squad": squad}
    finally:
        await client.aclose()


# =========================================================
# Sync ZPRP -> local DB
# =========================================================

async def _do_sync_teams(
    settings: Settings,
    *,
    season_id: Optional[str] = None,
    province_id: Optional[str] = None,
    gender: Optional[str] = None,
    category_id: Optional[str] = None,
    club_id: Optional[str] = None,
    name: Optional[str] = None,
    sort: Optional[str] = None,
    include_squads: bool = False,
) -> Tuple[int, int]:
    """Pobiera drużyny z ZPRP i zapisuje je lokalnie. Zwraca (fetched, upserted)."""
    fetched = await _fetch_teams_from_zprp(
        settings,
        season_id=season_id,
        province_id=province_id,
        gender=gender,
        category_id=category_id,
        club_id=club_id,
        name=name,
        sort=sort,
        include_squads=include_squads,
    )

    now = _now_utc()
    upserted = 0

    save_squad_columns = {
        "roster_json": _table_has_column("roster_json"),
        "companions_json": _table_has_column("companions_json"),
        "historical_players_json": _table_has_column("historical_players_json"),
        "squad_last_synced_at": _table_has_column("squad_last_synced_at"),
    }

    for item in fetched:
        values = {
            "id": item["id"],
            "team_name": item["team_name"],
            "gender": item.get("gender"),
            "gender_label": item.get("gender_label"),
            "category_id": item.get("category_id"),
            "category": item.get("category"),
            "club_id": item.get("club_id"),
            "club": item.get("club"),
            "province_id": item.get("province_id"),
            "province": item.get("province"),
            "season_id": item.get("season_id"),
            "season": item.get("season"),
            "contact_json": item.get("contact") or {},
            "squad_url": item.get("squad_url"),
            "source": "zprp",
            "last_synced_at": now,
        }

        set_values = {
            "team_name": item["team_name"],
            "gender": item.get("gender"),
            "gender_label": item.get("gender_label"),
            "category_id": item.get("category_id"),
            "category": item.get("category"),
            "club_id": item.get("club_id"),
            "club": item.get("club"),
            "province_id": item.get("province_id"),
            "province": item.get("province"),
            "season_id": item.get("season_id"),
            "season": item.get("season"),
            "contact_json": item.get("contact") or {},
            "squad_url": item.get("squad_url"),
            "source": "zprp",
            "last_synced_at": now,
            "updated_at": func.now(),
        }

        squad = item.get("squad")
        if include_squads and squad:
            if save_squad_columns["roster_json"]:
                values["roster_json"] = squad.get("players") or []
                set_values["roster_json"] = squad.get("players") or []
            if save_squad_columns["companions_json"]:
                values["companions_json"] = squad.get("companions") or []
                set_values["companions_json"] = squad.get("companions") or []
            if save_squad_columns["historical_players_json"]:
                values["historical_players_json"] = squad.get("historical_players") or []
                set_values["historical_players_json"] = squad.get("historical_players") or []
            if save_squad_columns["squad_last_synced_at"]:
                values["squad_last_synced_at"] = now
                set_values["squad_last_synced_at"] = now

        stmt = pg_insert(beach_teams).values(**values).on_conflict_do_update(
            index_elements=[beach_teams.c.id],
            set_=set_values,
        )

        await database.execute(stmt)
        upserted += 1

        if include_squads and squad:
            roster = squad.get("players") or []
            companions = squad.get("companions") or []
            if roster or companions:
                roles_updated = await expand_roles_for_squad_sync(
                    team_id=item["id"],
                    roster=roster,
                    companions=companions,
                )
                if roles_updated:
                    logger.info(
                        "sync: zaktualizowano role dla %d użytkowników (team_id=%s)",
                        roles_updated, item["id"],
                    )

    return len(fetched), upserted


@router.post("/local/sync", response_model=BeachTeamsSyncResponse)
async def sync_beach_teams_to_local(
    req: BeachTeamsSyncRequest,
    include_squads: bool = Query(False, description="Czy podczas sync pobierać też składy"),
    settings: Settings = Depends(get_settings),
):
    save_squad_columns = {
        "roster_json": _table_has_column("roster_json"),
        "companions_json": _table_has_column("companions_json"),
        "historical_players_json": _table_has_column("historical_players_json"),
        "squad_last_synced_at": _table_has_column("squad_last_synced_at"),
    }
    fetched_count, upserted = await _do_sync_teams(
        settings,
        season_id=req.season_id,
        province_id=req.province_id,
        gender=req.gender,
        category_id=req.category_id,
        club_id=req.club_id,
        name=req.name,
        sort=req.sort,
        include_squads=include_squads,
    )
    return BeachTeamsSyncResponse(
        success=True,
        fetched=fetched_count,
        upserted=upserted,
        filters={
            "season_id": req.season_id,
            "province_id": req.province_id,
            "gender": req.gender,
            "category_id": req.category_id,
            "club_id": req.club_id,
            "name": req.name,
            "sort": req.sort,
            "include_squads": include_squads,
            "db_squad_columns": save_squad_columns,
        },
    )


@router.post("/local/sync/squad")
async def sync_single_beach_team_squad_to_local(
    team_id: int = Query(...),
    season_id: Optional[str] = Query(None),
    settings: Settings = Depends(get_settings),
):
    payload = await _fetch_single_team_from_zprp(
        settings,
        team_id=team_id,
        season_id=season_id,
    )

    team = payload["team"]
    squad = payload["squad"]

    exists = await database.fetch_one(select(beach_teams.c.id).where(beach_teams.c.id == team_id))
    if not exists:
        base_values = {
            "id": team["id"],
            "team_name": team["team_name"],
            "gender": team.get("gender"),
            "gender_label": team.get("gender_label"),
            "category_id": team.get("category_id"),
            "category": team.get("category"),
            "club_id": team.get("club_id"),
            "club": team.get("club"),
            "province_id": team.get("province_id"),
            "province": team.get("province"),
            "season_id": team.get("season_id"),
            "season": team.get("season"),
            "contact_json": team.get("contact") or {},
            "squad_url": team.get("squad_url"),
            "source": "zprp",
            "last_synced_at": _now_utc(),
        }
        await database.execute(pg_insert(beach_teams).values(**base_values).on_conflict_do_nothing())

    saved = await _maybe_save_team_squad_to_db(team_id, squad)

    # Po zapisaniu składu — zaktualizuj role zarejestrowanych użytkowników
    roster = squad.get("players") or []
    companions = squad.get("companions") or []
    if roster or companions:
        roles_updated = await expand_roles_for_squad_sync(
            team_id=team_id,
            roster=roster,
            companions=companions,
        )
        if roles_updated:
            logger.info(
                "sync /local/sync/squad: zaktualizowano role dla %d użytkowników (team_id=%s)",
                roles_updated, team_id,
            )

    return {
        "success": True,
        "team_id": team_id,
        "saved_to_db": saved,
        "team": team,
        "squad_counts": {
            "players": len(squad.get("players") or []),
            "companions": len(squad.get("companions") or []),
            "historical_players": len(squad.get("historical_players") or []),
        },
    }


# =========================================================
# Registration list PDF download (lista zgłoszeniowa)
# =========================================================

import os
import shutil
import tempfile
import uuid
import zipfile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

REGLIST_DOWNLOAD_DIR = "/tmp/beach_reglist_downloads"
REGLIST_DOWNLOAD_TTL = 10 * 60  # 10 min


def _ensure_reglist_dir():
    os.makedirs(REGLIST_DOWNLOAD_DIR, exist_ok=True)


def _cleanup_expired_reglist():
    try:
        _ensure_reglist_dir()
        import time
        now = time.time()
        for fn in os.listdir(REGLIST_DOWNLOAD_DIR):
            p = os.path.join(REGLIST_DOWNLOAD_DIR, fn)
            if os.path.isfile(p):
                if now - os.stat(p).st_mtime > REGLIST_DOWNLOAD_TTL:
                    os.remove(p)
    except Exception:
        pass


class RegistrationListRequest(BaseModel):
    team_ids: List[int]
    season_id: str = "8"


@router.post("/registration-list", summary="Pobierz listy zgłoszeniowe drużyn z baza.zprp.pl (PDF)")
async def generate_registration_list(
    req: RegistrationListRequest,
    settings: Settings = Depends(get_settings),
):
    if not req.team_ids:
        raise HTTPException(400, detail="Brak team_ids")

    _cleanup_expired_reglist()

    client = await _login_beach_client(settings)
    try:
        tmp_dir = tempfile.mkdtemp()
        try:
            pdf_paths: List[Tuple[str, str]] = []  # (local_path, filename)

            for tid in req.team_ids:
                url = f"/zespolyP_PDF.php?ID_sezonP={req.season_id}&ID_zespol={tid}"
                resp = await client.get(url, cookies=client.cookies)
                if resp.status_code != 200:
                    logger.warning("Registration list download failed for team %d: HTTP %d", tid, resp.status_code)
                    continue

                # Resolve team name for filename
                row = await database.fetch_one(
                    select(beach_teams.c.team_name).where(beach_teams.c.id == tid)
                )
                team_name = row["team_name"] if row else str(tid)
                safe_name = re.sub(r"[^\w\s\-]", "", team_name).strip().replace(" ", "_")[:50]
                fname = f"lista_zgloszeniowa_{safe_name}_{tid}.pdf"

                local_path = os.path.join(tmp_dir, fname)
                with open(local_path, "wb") as f:
                    f.write(resp.content)
                pdf_paths.append((local_path, fname))

            if not pdf_paths:
                raise HTTPException(404, detail="Nie udało się pobrać żadnej listy zgłoszeniowej")

            _ensure_reglist_dir()
            token = str(uuid.uuid4())

            if len(pdf_paths) == 1:
                # Single PDF — serve directly
                ext = "pdf"
                download_path = os.path.join(REGLIST_DOWNLOAD_DIR, f"{token}.{ext}")
                shutil.copyfile(pdf_paths[0][0], download_path)
                filename = pdf_paths[0][1]
            else:
                # Multiple — ZIP
                ext = "zip"
                zip_name = f"listy_zgloszeniowe_{len(pdf_paths)}_druzyn.zip"
                zip_path = os.path.join(tmp_dir, zip_name)
                with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for fpath, fname in pdf_paths:
                        zf.write(fpath, fname)
                download_path = os.path.join(REGLIST_DOWNLOAD_DIR, f"{token}.{ext}")
                shutil.copyfile(zip_path, download_path)
                filename = zip_name

            from urllib.parse import quote
            return {
                "success": True,
                "download_url": f"/beach/teams/registration-list/download/{token}?filename={quote(filename)}&ext={ext}",
                "filename": filename,
                "count": len(pdf_paths),
            }
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    finally:
        await client.aclose()


@router.get(
    "/registration-list/download/{token}",
    summary="Pobierz wygenerowaną listę zgłoszeniową (PDF lub ZIP)",
)
async def download_registration_list(
    token: str,
    filename: str = Query("lista_zgloszeniowa.pdf"),
    ext: str = Query("pdf"),
):
    _ensure_reglist_dir()
    try:
        uuid.UUID(token)
    except ValueError:
        raise HTTPException(400, "Nieprawidłowy token")

    if ext not in ("pdf", "zip"):
        ext = "pdf"

    file_path = os.path.join(REGLIST_DOWNLOAD_DIR, f"{token}.{ext}")
    if not os.path.exists(file_path):
        raise HTTPException(404, "Plik wygasł lub nie istnieje")

    media_types = {"pdf": "application/pdf", "zip": "application/zip"}

    return FileResponse(
        path=file_path,
        media_type=media_types.get(ext, "application/octet-stream"),
        filename=filename,
        background=BackgroundTask(
            lambda: os.remove(file_path) if os.path.exists(file_path) else None
        ),
    )


# =========================================================
# Medical exams — PDF parsing & check
# =========================================================

import fitz  # pymupdf


def _parse_registration_list_pdf(pdf_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Parse a registration-list PDF (lista zgłoszeniowa) from baza.zprp.pl.

    Phase 1: plain-text extraction for player names, license numbers, dates.
    Phase 2: image / drawing / colored-text analysis to detect approval
             checkmarks (green ✓).  Only players with at least one green
             approval mark get their medical date stored.

    Returns list of dicts with keys:
        last_name, first_name, license_number, medical_valid_until, source
    """
    results: List[Dict[str, Any]] = []

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        logger.warning("Medical exams PDF: failed to open PDF: %s", e)
        return results

    try:
        # ── Phase 1: plain-text extraction ──
        full_text = ""
        for page in doc:
            full_text += page.get_text("text") + "\n"

        # Truncate at companions section
        for marker in ["osoby towarzysz", "lp osoby"]:
            idx = full_text.lower().find(marker)
            if idx > 0:
                full_text = full_text[:idx]
                break

        entry_starts = list(re.finditer(
            r'(?:^|\n)\s*(\d+)\.\s+([A-ZĄĆĘŁŃÓŚŹŻ])',
            full_text,
        ))

        if not entry_starts:
            logger.warning("Medical exams PDF: no player entries found in text")
            return results

        players: List[Dict[str, Any]] = []
        for i, match in enumerate(entry_starts):
            start = match.start()
            end = entry_starts[i + 1].start() if i + 1 < len(entry_starts) else len(full_text)
            block = full_text[start:end].strip()

            lp = int(match.group(1))
            name_m = re.match(r'\d+\.\s+(\S+)\s+(\S+)', block)
            if not name_m:
                continue

            lic_m = re.search(r'\b([A-Z]/\d{3,}/\d{2})\b', block, re.I)
            dates = re.findall(r'\d{4}-\d{2}-\d{2}', block)
            med_date = dates[-1] if len(dates) >= 3 else (dates[-1] if len(dates) == 2 else None)

            players.append({
                "lp": lp,
                "last_name": name_m.group(1),
                "first_name": name_m.group(2),
                "license_number": lic_m.group(1) if lic_m else None,
                "medical_valid_until": med_date,
                "approved": False,
                "has_wzpr": False,
            })

        # ── Phase 2: detect approval checkmarks ──
        for page in doc:
            _detect_approvals_on_page(page, doc, players)

        # ── Build output — always include dates; approval flags separate ──
        for p in players:
            results.append({
                "last_name": p["last_name"],
                "first_name": p["first_name"],
                "license_number": p["license_number"],
                "medical_valid_until": p["medical_valid_until"],
                "has_check": p["approved"],
                "has_wzpr": p["has_wzpr"],
            })
    finally:
        doc.close()

    return results


# ── helpers for approval detection ──


def _detect_approvals_on_page(
    page, doc, players: List[Dict[str, Any]],
) -> None:
    """Scan a single page for green approval marks and tag matching players."""

    # Step 1 — find y-positions of Lp numbers on this page
    lp_y: List[Tuple[float, int]] = []
    companion_y: float = page.rect.height

    text_dict = page.get_text("dict")
    for block in text_dict.get("blocks", []):
        for line in block.get("lines", []):
            line_text = "".join(s.get("text", "") for s in line.get("spans", []))
            lt = line_text.strip().lower()

            if "osoby towarzysz" in lt:
                spans = line.get("spans", [])
                if spans:
                    companion_y = spans[0]["bbox"][1]
                continue

            for span in line.get("spans", []):
                bbox = span.get("bbox", [0, 0, 0, 0])
                txt = span.get("text", "").strip().rstrip(".")
                # Lp numbers sit in the leftmost column (x < 55)
                if bbox[0] < 55 and re.fullmatch(r"\d{1,2}", txt):
                    n = int(txt)
                    if 1 <= n <= 50 and bbox[1] < companion_y:
                        lp_y.append((bbox[1], n))

    lp_y.sort()
    if not lp_y:
        return

    page_width = page.rect.width
    # Approval marks live in the rightmost area of the page
    approval_x_min = page_width * 0.75

    def _set_approved(y_pos: float, is_wzpr: bool = False) -> None:
        best_lp = None
        for row_y, lp in lp_y:
            if row_y <= y_pos + 5:
                best_lp = lp
            else:
                break
        if best_lp is not None:
            for p in players:
                if p["lp"] == best_lp:
                    p["approved"] = True
                    if is_wzpr:
                        p["has_wzpr"] = True
                    break

    # ── Method A: colored text spans (checkmarks as font glyphs) ──
    for block in text_dict.get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                bbox = span.get("bbox", [0, 0, 0, 0])
                if bbox[0] < approval_x_min or bbox[1] > companion_y:
                    continue

                text = span.get("text", "").strip()
                color = span.get("color", 0)
                if not text:
                    continue

                is_green = False
                if isinstance(color, int) and color != 0:
                    r = (color >> 16) & 0xFF
                    g = (color >> 8) & 0xFF
                    b = color & 0xFF
                    is_green = g > 80 and g > r * 1.2 and g > b * 1.2

                if is_green:
                    _set_approved(bbox[1], "WZPR" in text.upper())
                elif text in ("\u2713", "\u2714", "\u2611"):  # ✓ ✔ ☑
                    _set_approved(bbox[1])

    # ── Method B: embedded images (checkmarks as PNG/GIF) ──
    try:
        img_infos = page.get_image_info(xrefs=True)
        xref_class: Dict[int, str] = {}

        for info in img_infos:
            xref = info.get("xref", 0)
            if xref == 0:
                continue

            bbox = info.get("bbox", (0, 0, 0, 0))
            x0, y0, x1, y1 = bbox
            w, h = abs(x1 - x0), abs(y1 - y0)

            if w > 60 or h > 60 or w < 2 or h < 2:
                continue
            if x0 < approval_x_min or y0 > companion_y:
                continue

            if xref not in xref_class:
                xref_class[xref] = _classify_image_color(doc, xref)

            if xref_class[xref] == "green":
                y_center = (y0 + y1) / 2
                # WZPR label images are wider than simple checkmarks
                _set_approved(y_center, is_wzpr=(w > 20))
    except Exception as e:
        logger.debug("Medical exams: image analysis unavailable: %s", e)

    # ── Method C: vector drawings (checkmarks as paths) ──
    try:
        for d in page.get_drawings():
            fill = d.get("fill")
            rect = d.get("rect")
            if not fill or not rect:
                continue

            x0, y0, x1, y1 = rect
            if x0 < approval_x_min or y0 > companion_y:
                continue
            w, h = abs(x1 - x0), abs(y1 - y0)
            if w > 60 or h > 60:
                continue

            r, g, b = fill
            if g > 0.4 and g > r * 1.2 and g > b * 1.2:
                _set_approved((y0 + y1) / 2)
    except Exception as e:
        logger.debug("Medical exams: drawings analysis unavailable: %s", e)


def _classify_image_color(doc, xref: int) -> str:
    """Classify a PDF image by its dominant non-white color."""
    try:
        pix = fitz.Pixmap(doc, xref)
        if pix.colorspace and pix.colorspace.n == 1:
            pix = fitz.Pixmap(fitz.csRGB, pix)

        samples = pix.samples
        n = pix.n
        if not samples or n < 3:
            return "other"

        total_r = total_g = total_b = count = 0
        step = max(1, len(samples) // (n * 500))  # sample ≤500 pixels
        for i in range(0, len(samples), n * step):
            r, g, b = samples[i], samples[i + 1], samples[i + 2]
            if r > 230 and g > 230 and b > 230:
                continue
            if n >= 4 and samples[i + 3] < 50:
                continue
            total_r += r
            total_g += g
            total_b += b
            count += 1

        if count < 3:
            return "other"

        ar, ag, ab = total_r / count, total_g / count, total_b / count
        if ag > 80 and ag > ar * 1.2 and ag > ab * 1.2:
            return "green"
        if ar > 80 and ar > ag * 1.2 and ar > ab * 1.2:
            return "red"
        return "other"
    except Exception:
        return "other"


class MedicalExamsCheckRequest(BaseModel):
    team_ids: List[int]
    season_id: str = "8"


@router.post("/check-medical-exams", summary="Sprawdź badania lekarskie drużyn (parsowanie listy zgłoszeniowej PDF)")
async def check_medical_exams(
    req: MedicalExamsCheckRequest,
    settings: Settings = Depends(get_settings),
):
    """
    For each team:
    1. Sync squad from ZPRP
    2. Download registration list PDF
    3. Parse PDF for medical exam dates
    4. Match to stored players and save medical_exams_json
    """
    if not req.team_ids:
        raise HTTPException(400, detail="Brak team_ids")

    client = await _login_beach_client(settings)
    team_results = []

    try:
        for tid in req.team_ids:
            try:
                result = await _check_medical_exams_for_team(client, tid, req.season_id, settings)
                team_results.append(result)
            except Exception as e:
                logger.warning("Medical exams check failed for team %d: %s", tid, e)
                team_results.append({
                    "team_id": tid,
                    "team_name": None,
                    "total_players": 0,
                    "valid_exams": 0,
                    "exams": {},
                    "error": str(e),
                })
    finally:
        await client.aclose()

    return {"teams": team_results}


async def _check_medical_exams_for_team(
    client: AsyncClient,
    team_id: int,
    season_id: str,
    settings: Settings,
) -> Dict[str, Any]:
    """Check medical exams for a single team."""

    # 1. Sync squad from ZPRP
    try:
        row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
        if row and dict(row).get("squad_url"):
            squad = await _fetch_squad_for_team(client, squad_url=dict(row)["squad_url"])
            await _maybe_save_team_squad_to_db(team_id, squad)
    except Exception as e:
        logger.warning("Medical exams: squad sync failed for team %d: %s", team_id, e)

    # 2. Download registration list PDF
    url = f"/zespolyP_PDF.php?ID_sezonP={season_id}&ID_zespol={team_id}"
    try:
        resp = await client.get(url, cookies=client.cookies)
    except Exception as e:
        logger.warning("Medical exams: PDF download failed for team %d: %s", team_id, e)
        raise HTTPException(500, detail=f"Nie udało się pobrać listy zgłoszeniowej dla drużyny {team_id}")

    if resp.status_code != 200:
        logger.warning("Medical exams: PDF download HTTP %d for team %d", resp.status_code, team_id)
        raise HTTPException(500, detail=f"Błąd pobierania listy zgłoszeniowej (HTTP {resp.status_code})")

    pdf_bytes = resp.content
    if len(pdf_bytes) < 100:
        logger.warning("Medical exams: PDF too small (%d bytes) for team %d", len(pdf_bytes), team_id)
        raise HTTPException(500, detail="Otrzymano pustą lub uszkodzoną listę zgłoszeniową")

    # 3. Parse PDF
    parsed_players = _parse_registration_list_pdf(pdf_bytes)
    logger.info("Medical exams: parsed %d players from PDF for team %d", len(parsed_players), team_id)

    # 4. Match parsed players to stored roster
    row = await database.fetch_one(select(beach_teams).where(beach_teams.c.id == team_id))
    if not row:
        raise HTTPException(404, detail=f"Drużyna {team_id} nie istnieje")

    data = dict(row)
    team_name = data.get("team_name", str(team_id))
    roster = data.get("roster_json") or [] if _table_has_column("roster_json") else []
    in_squad_players = [p for p in roster if p.get("in_squad") is not False]

    medical_exams: Dict[str, Dict[str, Any]] = {}
    matched = 0

    for parsed in parsed_players:
        if not parsed.get("medical_valid_until"):
            continue

        # Try matching by license number (primary)
        player_id = None
        if parsed.get("license_number"):
            for rp in roster:
                if rp.get("zprp_license_number") and rp["zprp_license_number"] == parsed["license_number"]:
                    player_id = str(rp["player_id"])
                    break

        # Fallback: match by last_name + first_name
        if not player_id and parsed.get("last_name"):
            p_last = (parsed["last_name"] or "").strip().upper()
            p_first = (parsed.get("first_name") or "").strip().upper()
            for rp in roster:
                r_last = (rp.get("last_name") or "").strip().upper()
                r_first = (rp.get("first_name") or "").strip().upper()
                if r_last == p_last and r_first == p_first:
                    player_id = str(rp["player_id"])
                    break

        if player_id:
            medical_exams[player_id] = {
                "valid_until": parsed["medical_valid_until"],
                "has_check": parsed.get("has_check", False),
                "has_wzpr": parsed.get("has_wzpr", False),
            }
            matched += 1

    # 5. Save to DB
    if _table_has_column("medical_exams_json"):
        update_values: Dict[str, Any] = {
            "medical_exams_json": medical_exams,
        }
        if _table_has_column("medical_exams_checked_at"):
            update_values["medical_exams_checked_at"] = _now_utc()

        await database.execute(
            update(beach_teams)
            .where(beach_teams.c.id == team_id)
            .values(**update_values)
        )

    # Count only exams that are approved (has_check or has_wzpr) AND not expired
    now_date = _now_utc().date()
    valid_count = 0
    for exam in medical_exams.values():
        if not (exam.get("has_check") or exam.get("has_wzpr")):
            continue
        vu = exam.get("valid_until")
        if vu:
            try:
                exp = datetime.strptime(vu, "%Y-%m-%d").date()
                if exp >= now_date:
                    valid_count += 1
            except (ValueError, TypeError):
                pass

    return {
        "team_id": team_id,
        "team_name": team_name,
        "total_players": len(in_squad_players),
        "valid_exams": valid_count,
        "exams": medical_exams,
    }


# =========================================================
# Excel squad import — helpers
# =========================================================

import io as _io
import unicodedata as _unicodedata
from difflib import SequenceMatcher as _SequenceMatcher


# Characters that NFD cannot decompose canonically — must be pre-mapped.
# Polish ł/Ł, Scandinavian ø/Ø, South-Slavic đ/Đ, etc.
_EXCEL_STROKE_MAP = str.maketrans("łŁøØđĐ", "lLoOdD")


def _excel_normalize(text: str) -> str:
    """Lowercase, strip whitespace, remove diacritics.

    Polish ą/ć/ę/ń/ó/ś/ź/ż all decompose via NFD and are handled automatically.
    ł/Ł has no canonical NFD decomposition, so it is pre-mapped explicitly.
    ß is expanded to 'ss'. Other stroke letters (ø, đ) are also pre-mapped.
    """
    if not text:
        return ""
    # Pre-map stroke letters that NFD cannot decompose.
    mapped = str(text).strip().translate(_EXCEL_STROKE_MAP).replace("ß", "ss")
    nfd = _unicodedata.normalize("NFD", mapped.lower())
    return "".join(c for c in nfd if _unicodedata.category(c) != "Mn")


def _excel_name_similarity(a: str, b: str) -> float:
    return _SequenceMatcher(None, a, b).ratio()


def _best_name_match(raw: str, candidates: list, key_fn) -> tuple:
    """Return (best_candidate, best_score). Tries both word orderings of raw."""
    if not raw or not candidates:
        return None, 0.0
    norm_raw = _excel_normalize(raw)
    parts = norm_raw.split()
    variants = [norm_raw]
    if len(parts) >= 2:
        variants.append(" ".join(reversed(parts)))

    best_score = 0.0
    best_cand = None
    for cand in candidates:
        cand_norm = _excel_normalize(key_fn(cand))
        for v in variants:
            score = _excel_name_similarity(v, cand_norm)
            if score > best_score:
                best_score = score
                best_cand = cand
    return best_cand, best_score


def _read_excel_cells(file_bytes: bytes, filename: str) -> dict:
    """Read squad protocol cells from an .xls or .xlsx file.

    Cells:
        B10  – team name
        A15–A29 / B15–B29 – jersey numbers and player names
        A30–A33 / B30–B33 – companion letters (A-D) and names
    """
    name_lower = (filename or "").lower()

    if name_lower.endswith(".xls") and not name_lower.endswith(".xlsx"):
        import xlrd
        wb = xlrd.open_workbook(file_contents=file_bytes)
        ws = wb.sheet_by_index(0)

        def get_cell(row1: int, col1: int):
            try:
                val = ws.cell_value(row1 - 1, col1 - 1)
                return val if val != "" else None
            except Exception:
                return None
    else:
        import openpyxl
        wb = openpyxl.load_workbook(_io.BytesIO(file_bytes), data_only=True)
        ws = wb.active

        def get_cell(row1: int, col1: int):
            return ws.cell(row=row1, column=col1).value

    team_name_raw = get_cell(10, 2)  # B10
    if team_name_raw is not None:
        team_name_raw = str(team_name_raw).strip() or None

    players_raw = []
    for row in range(15, 30):  # rows 15–29
        num_val = get_cell(row, 1)
        name_val = get_cell(row, 2)
        jersey = None
        if num_val is not None:
            try:
                n = int(float(str(num_val)))
                if 1 <= n <= 99:
                    jersey = n
            except (ValueError, TypeError):
                pass
        name_str = str(name_val).strip() if name_val is not None else None
        if name_str:
            players_raw.append({"row": row, "raw_name": name_str, "raw_number": jersey})

    companions_raw = []
    seen_letters: set = set()
    valid_letters = {"A", "B", "C", "D"}
    for row in range(30, 34):  # rows 30–33
        letter_val = get_cell(row, 1)
        name_val = get_cell(row, 2)
        letter = None
        if letter_val is not None:
            ltr = str(letter_val).strip().upper()
            if ltr in valid_letters and ltr not in seen_letters:
                letter = ltr
                seen_letters.add(ltr)
        name_str = str(name_val).strip() if name_val is not None else None
        if name_str:
            # If the protocol sheet doesn't have A/B/C/D in column A,
            # fall back to assigning the letter by row position.
            if letter is None:
                letter = {30: "A", 31: "B", 32: "C", 33: "D"}.get(row)
            companions_raw.append({"row": row, "raw_name": name_str, "raw_letter": letter})

    return {
        "team_name_raw": team_name_raw,
        "players_raw": players_raw,
        "companions_raw": companions_raw,
    }


# ── Excel squad import — endpoints ────────────────────────────────────────────

class ApplyExcelSquadRequest(BaseModel):
    tournament_id: int
    team_id: int
    protocol_player_ids: List[int]
    companion_ids: List[int]
    companion_roles: Dict[str, str]  # str(person_id) → "A"|"B"|"C"|"D"
    also_update_default: bool = False


@router.post("/parse-excel-squad", summary="Parsuj plik Excel i dopasuj skład drużyny")
async def parse_excel_squad(
    file: UploadFile = File(...),
    tournament_id: int = Query(...),
    team_id: Optional[int] = Query(None),
    mode: str = Query("user"),
):
    """Parse an Excel protocol file (B10=team, A/B 15-29=players, A/B 30-33=companions)
    and fuzzy-match names against the tournament's team rosters."""
    import json as _json

    content_length = 0
    file_bytes = await file.read()
    if len(file_bytes) > 10 * 1024 * 1024:
        raise HTTPException(413, "Plik za duży (max 10 MB)")

    filename = file.filename or "upload.xlsx"

    try:
        cells = _read_excel_cells(file_bytes, filename)
    except Exception as e:
        raise HTTPException(422, f"Nie udało się odczytać pliku Excel: {e}")

    team_name_raw = cells["team_name_raw"]
    players_raw = cells["players_raw"]
    companions_raw = cells["companions_raw"]

    # ── 1. Resolve tournament ──────────────────────────────────────────────
    from app.db import beach_tournaments as _bt

    tour_row = await database.fetch_one(
        select(_bt).where(_bt.c.id == tournament_id)
    )
    if not tour_row:
        raise HTTPException(404, "Turniej nie istnieje")

    tour_data = tour_row["data_json"] or {}
    if isinstance(tour_data, str):
        try:
            tour_data = _json.loads(tour_data)
        except Exception:
            tour_data = {}

    invited_ids = [int(x) for x in (tour_data.get("invited_team_ids") or []) if x]

    # ── 2. Determine team_id ───────────────────────────────────────────────
    matched_team_id: Optional[int] = team_id
    match_method: Optional[str] = "provided" if team_id else None
    match_confidence: float = 1.0 if team_id else 0.0
    matched_team_name: Optional[str] = None

    if not matched_team_id and mode == "admin" and invited_ids:
        team_rows = await database.fetch_all(
            select(beach_teams.c.id, beach_teams.c.team_name).where(
                beach_teams.c.id.in_(invited_ids)
            )
        )
        team_list = [{"id": r["id"], "name": r["team_name"] or ""} for r in team_rows]

        # Method A — collect all name candidates (score ≥ 0.55)
        name_candidates: List[Tuple[float, dict]] = []
        if team_name_raw:
            for t in team_list:
                score = _excel_name_similarity(
                    _excel_normalize(team_name_raw), _excel_normalize(t["name"])
                )
                if score >= 0.55:
                    name_candidates.append((score, t))
            name_candidates.sort(key=lambda x: x[0], reverse=True)

        # Method A result — clear winner if top score is ≥ 0.15 ahead of runner-up
        # (or only one candidate). Ambiguous when e.g. "KPR Lubliniec" matches both
        # men's AND women's teams with the same name → need player disambiguation.
        ambiguous: List[Tuple[float, dict]] = []
        if name_candidates:
            top_score = name_candidates[0][0]
            close = [(s, t) for s, t in name_candidates if top_score - s <= 0.15]
            if len(close) == 1:
                # Unambiguous
                matched_team_id = close[0][1]["id"]
                matched_team_name = close[0][1]["name"]
                match_method = "name"
                match_confidence = top_score
            else:
                # Multiple teams with near-identical name scores → player disambiguation
                ambiguous = close

        # Method B — player matching
        # Runs either: (a) no name match at all (pure fallback), or
        #              (b) multiple name candidates need gender disambiguation.
        check_list: List[Tuple[float, dict]] = ambiguous or (
            [(0.0, t) for t in team_list] if not matched_team_id and players_raw else []
        )
        # Lower threshold when disambiguating (name already matched); higher for discovery
        min_matches = 2 if ambiguous else 5

        if check_list and players_raw:
            player_norms = [_excel_normalize(p["raw_name"]) for p in players_raw]
            best_count = -1
            best_team = None
            best_name_score = 0.0

            for name_score, t in check_list:
                t_row = await database.fetch_one(
                    select(beach_teams.c.roster_json).where(beach_teams.c.id == t["id"])
                )
                if not t_row:
                    continue
                roster = t_row["roster_json"] or []
                if isinstance(roster, str):
                    try:
                        roster = _json.loads(roster)
                    except Exception:
                        roster = []

                count = 0
                for pn in player_norms:
                    for player in roster:
                        if not isinstance(player, dict):
                            continue
                        last = _excel_normalize(player.get("last_name") or "")
                        first = _excel_normalize(player.get("first_name") or "")
                        for variant in [f"{last} {first}", f"{first} {last}"]:
                            if _excel_name_similarity(pn, variant) >= 0.75:
                                count += 1
                                break
                if count > best_count or (count == best_count and name_score > best_name_score):
                    best_count = count
                    best_team = t
                    best_name_score = name_score

            if best_team and best_count >= min_matches:
                matched_team_id = best_team["id"]
                matched_team_name = best_team["name"]
                match_method = "name+players" if ambiguous else "players"
                match_confidence = min(1.0, best_count / 10)
            elif ambiguous and name_candidates:
                # Still ambiguous after player check (0 matches both) — fallback to top name score
                matched_team_id = name_candidates[0][1]["id"]
                matched_team_name = name_candidates[0][1]["name"]
                match_method = "name"
                match_confidence = name_candidates[0][0]

    # ── 3. Fetch roster & companions ───────────────────────────────────────
    roster: list = []
    companions_db: list = []

    if matched_team_id:
        t_row = await database.fetch_one(
            select(beach_teams).where(beach_teams.c.id == matched_team_id)
        )
        if t_row:
            t_data = dict(t_row)
            if not matched_team_name:
                matched_team_name = t_data.get("team_name")
            raw_roster = t_data.get("roster_json") or []
            if isinstance(raw_roster, str):
                try:
                    raw_roster = _json.loads(raw_roster)
                except Exception:
                    raw_roster = []
            roster = [p for p in raw_roster if isinstance(p, dict)]
            raw_comp = t_data.get("companions_json") or []
            if isinstance(raw_comp, str):
                try:
                    raw_comp = _json.loads(raw_comp)
                except Exception:
                    raw_comp = []
            companions_db = [c for c in raw_comp if isinstance(c, dict)]

    # ── 4. Match players ───────────────────────────────────────────────────
    matched_players = []
    for p in players_raw:
        best_p, score = _best_name_match(
            p["raw_name"],
            roster,
            lambda r: f"{r.get('last_name', '')} {r.get('first_name', '')}",
        )
        matched_players.append({
            "row": p["row"],
            "raw_name": p["raw_name"],
            "raw_number": p["raw_number"],
            "matched_player_id": best_p.get("player_id") if best_p and score >= 0.75 else None,
            "matched_player_name": (
                f"{best_p.get('last_name', '')} {best_p.get('first_name', '')}".strip()
                if best_p and score >= 0.75 else None
            ),
            "match_confidence": round(score, 3),
        })

    # ── 5. Match companions ────────────────────────────────────────────────
    matched_companions = []
    for c in companions_raw:
        best_c, score = _best_name_match(
            c["raw_name"],
            companions_db,
            lambda r: r.get("full_name", ""),
        )
        matched_companions.append({
            "row": c["row"],
            "raw_name": c["raw_name"],
            "raw_letter": c["raw_letter"],
            "matched_person_id": best_c.get("person_id") if best_c and score >= 0.70 else None,
            "matched_person_name": best_c.get("full_name") if best_c and score >= 0.70 else None,
            "match_confidence": round(score, 3),
        })

    return {
        "team_name_raw": team_name_raw,
        "matched_team_id": matched_team_id,
        "matched_team_name": matched_team_name,
        "match_method": match_method,
        "match_confidence": round(match_confidence, 3),
        "players": matched_players,
        "companions": matched_companions,
    }


@router.post("/apply-excel-squad", summary="Zastosuj skład z Excela do turnieju")
async def apply_excel_squad(body: ApplyExcelSquadRequest):
    """Apply parsed Excel squad: sets protocol_players and optionally default_players (first 10)."""
    import json as _json
    from app.db import beach_tournaments as _bt

    tour_row = await database.fetch_one(
        select(_bt).where(_bt.c.id == body.tournament_id)
    )
    if not tour_row:
        raise HTTPException(404, "Turniej nie istnieje")

    tour_data = tour_row["data_json"] or {}
    if isinstance(tour_data, str):
        try:
            tour_data = _json.loads(tour_data)
        except Exception:
            tour_data = {}

    team_squads: dict = dict(tour_data.get("team_squads") or {})
    team_key = str(body.team_id)
    squad_entry: dict = dict(team_squads.get(team_key) or {})

    squad_entry["protocol_players"] = body.protocol_player_ids
    if body.companion_ids:
        squad_entry["default_companions"] = body.companion_ids
    if body.companion_roles:
        squad_entry["default_companion_roles"] = body.companion_roles
    if body.also_update_default:
        squad_entry["default_players"] = body.protocol_player_ids[:10]

    team_squads[team_key] = squad_entry
    tour_data["team_squads"] = team_squads

    await database.execute(
        update(_bt)
        .where(_bt.c.id == body.tournament_id)
        .values(data_json=tour_data, updated_at=_now_utc())
    )

    return {"success": True}


# =========================================================
# Auto-sync scheduler (uruchamiany jako asyncio.Task)
# =========================================================

BEACH_SYNC_INTERVAL = int(os.getenv("BEACH_TEAMS_SYNC_INTERVAL_SECONDS", str(60 * 60)))


def _current_beach_season_id() -> str:
    """Zwraca aktualne season_id na podstawie daty.

    Sezon plażowy startuje w sierpniu — przed sierpniem wciąż trwa sezon
    z poprzedniego roku (np. maj 2026 → sezon 2025/2026 → id=8).
    Można nadpisać zmienną BEACH_TEAMS_SYNC_SEASON_ID w środowisku.
    """
    override = os.getenv("BEACH_TEAMS_SYNC_SEASON_ID", "").strip()
    if override:
        return override
    now = datetime.now(timezone.utc)
    start_year = now.year if now.month >= 9 else now.year - 1
    return str(start_year - 2017)


async def run_beach_teams_sync_scheduler() -> None:
    """Synchronizuje wszystkie drużyny + składy z bieżącego sezonu co godzinę."""
    settings = get_settings()
    logger.info("🔄 BeachTeams auto-sync started (interval=%ds)", BEACH_SYNC_INTERVAL)
    while True:
        season_id = _current_beach_season_id()
        try:
            fetched, upserted = await _do_sync_teams(
                settings,
                season_id=season_id,
                include_squads=True,
            )
            logger.info(
                "🔄 BeachTeams auto-sync OK: season_id=%s fetched=%d upserted=%d",
                season_id, fetched, upserted,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "❌ BeachTeams auto-sync failed (season_id=%s) — retrying in %ds",
                season_id, BEACH_SYNC_INTERVAL,
            )
        await asyncio.sleep(BEACH_SYNC_INTERVAL)
