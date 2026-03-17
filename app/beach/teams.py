import re
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse

from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, HTTPException, Query
from httpx import AsyncClient
from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import beach_teams, database
from app.deps import Settings, get_settings
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
    m_num = re.search(r"\b([A-Z]?/?\d{4,}/\d{2})\b", text, re.I)
    if m_num:
        license_number = m_num.group(1)

    if season_end_year is None:
        return license_number, None

    target_year = str(season_end_year)
    valid = False

    for font in td.find_all("font"):
        year_txt = _norm_space(font.get_text(" ", strip=True))
        style = (font.get("style") or "").replace(" ", "").lower()

        is_green = (
            "background:#00ff00" in style
            or "background-color:#00ff00" in style
        )

        if year_txt == target_year and is_green:
            valid = True
            break

    return license_number, valid


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

    m = re.search(r"^(.*?)\s+\((.*?)\)\s+(\d{4}/\d{4})\s*-\s*(.+)$", title)
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


def _find_main_squad_table(soup: BeautifulSoup):
    player_href_re = re.compile(r"[?&]a=zawodnicy(?:P)?[&].*b=szczegoly.*NrZawodnika=\d+", re.I)

    candidates = []

    for table in soup.find_all("table"):
        rows = table.find_all("tr", recursive=False)
        if len(rows) < 3:
            continue

        first_row_text = _row_text(rows[0])

        header_row = None
        for tr in rows[:6]:
            txt = _row_text(tr)
            if (
                "nazwisko" in txt
                and "imię" in txt
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
            score += 3
        if "senior" in first_row_text or "junior" in first_row_text:
            score += 1
        if rows and rows[0].find("td", attrs={"colspan": True}):
            score += 1

        candidates.append((score, table))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _find_companions_table(soup: BeautifulSoup):
    person_href_re = re.compile(r"[?&]a=osoba(?:P)?[&].*b=szczegoly.*NrOsoby=\d+", re.I)

    candidates = []

    for table in soup.find_all("table"):
        rows = table.find_all("tr", recursive=False)
        if len(rows) < 2:
            continue

        first_row_text = _row_text(rows[0])

        if "osoby towarzyszące" not in first_row_text:
            continue

        has_direct_person_row = False
        for tr in rows[1:]:
            if tr.find("a", href=person_href_re):
                has_direct_person_row = True
                break

        if not has_direct_person_row:
            continue

        candidates.append(table)

    return candidates[0] if candidates else None


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

    companions_table = _find_companions_table(soup)
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
    return {
        "team": _row_to_item(row).model_dump(),
        "players": data.get("roster_json") if _table_has_column("roster_json") else None,
        "companions": data.get("companions_json") if _table_has_column("companions_json") else None,
        "historical_players": data.get("historical_players_json") if _table_has_column("historical_players_json") else None,
        "squad_last_synced_at": data.get("squad_last_synced_at") if _table_has_column("squad_last_synced_at") else None,
        "db_has_squad_columns": {
            "roster_json": _table_has_column("roster_json"),
            "companions_json": _table_has_column("companions_json"),
            "historical_players_json": _table_has_column("historical_players_json"),
            "squad_last_synced_at": _table_has_column("squad_last_synced_at"),
        },
    }


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

@router.post("/local/sync", response_model=BeachTeamsSyncResponse)
async def sync_beach_teams_to_local(
    req: BeachTeamsSyncRequest,
    include_squads: bool = Query(False, description="Czy podczas sync pobierać też składy"),
    settings: Settings = Depends(get_settings),
):
    fetched = await _fetch_teams_from_zprp(
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

    return BeachTeamsSyncResponse(
        success=True,
        fetched=len(fetched),
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