import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
import logging

from bs4 import BeautifulSoup
from databases import Database
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
from app.utils import fetch_with_correct_encoding

router = APIRouter(prefix="/beach/teams", tags=["Beach Teams"])


# =========================================================
# Helpers: login / URL / normalize
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

logger = logging.getLogger(__name__)
async def _login_beach_client(settings: Settings) -> AsyncClient:
    username = (settings.ZPRP_BEACH_USERNAME or "").strip()
    password = (settings.ZPRP_BEACH_PASSWORD or "").strip()

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
        resp_login, html_login = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={
                "login": username,
                "haslo": password,
                "from": "/index.php?",
            },
        )

        html_norm = (html_login or "").lower()

        # sukces logowania rozpoznajemy po treści strony po zalogowaniu
        login_ok = (
            "zalogowany:" in html_norm
            or "sesja wygaśnie za" in html_norm
            or "wyloguj" in html_norm
        )

        if not login_ok:
            final_path = (resp_login.url.path or "").strip()
            final_url = str(resp_login.url)
            snippet = (html_login or "")[:700]

            logger.error(
                "BEACH login failed: final_path=%r final_url=%r snippet=%r",
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
        return client

    except HTTPException:
        raise
    except Exception as e:
        await client.aclose()
        logger.exception("BEACH login unexpected error")
        raise HTTPException(
            status_code=500,
            detail=f"Błąd podczas logowania do baza.zprp.pl: {e}",
        )


# =========================================================
# Helpers: filters metadata from page
# =========================================================

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
# Helpers: table parsing
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


def _extract_text_lines_from_cell(td) -> List[str]:
    text = td.get_text("\n", strip=True)
    lines = [_norm_space(x) for x in text.split("\n")]
    return [x for x in lines if x]


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

    # fallback email / website z linii tekstowych
    for line in lines:
        ll = line.lower()

        if ll.startswith("tel2:"):
            phone2 = line.split(":", 1)[1].strip() if ":" in line else line.replace("Tel2", "").strip()
            continue

        if ll.startswith("tel :") or ll.startswith("tel:"):
            phone = line.split(":", 1)[1].strip() if ":" in line else line.replace("Tel", "").strip()
            continue

        if ll.startswith("mail:"):
            if not email:
                email = line.split(":", 1)[1].strip() if ":" in line else None
            continue

        if ll.startswith("uwagi:"):
            notes = line.split(":", 1)[1].strip() if ":" in line else ""
            continue

        if ll.startswith("www:"):
            website = line.split(":", 1)[1].strip() if ":" in line else None
            continue

    # adres + kod + miasto
    normal_lines: List[str] = []
    for line in lines:
        ll = line.lower()
        if ll.startswith(("tel", "mail:", "uwagi:", "www:")):
            continue
        normal_lines.append(line)

    if normal_lines:
        address = normal_lines[0]

    for line in normal_lines[1:]:
        m = re.search(r"(?P<postal>\d{2}-\d{3})\s+(?P<city>.+)", line)
        if m:
            postal_code = _norm_space(m.group("postal"))
            city = _norm_space(m.group("city"))
            break

    if not city and len(normal_lines) >= 2:
        city = normal_lines[1]

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

    # ID-e filtrów najpewniej znamy tylko z aktywnych filtrów albo map nazw.
    category_id = selected_category_id
    season_id = selected_season_id
    province_id = selected_province_id
    club_id = selected_club_id
    gender_id = selected_gender

    # jeśli filtr nie był ustawiony, spróbuj znaleźć po labelach
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
            # mapy mają np. "WP", "SL", ...
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
# Helpers: item conversion / local query filters
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


# =========================================================
# Live fetch from ZPRP
# =========================================================

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
        _, html = await fetch_with_correct_encoding(
            client,
            url,
            method="GET",
            cookies=client.cookies,
        )
        return _parse_beach_teams_html(html)
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
        _, html = await fetch_with_correct_encoding(
            client,
            url,
            method="GET",
            cookies=client.cookies,
        )
        return _parse_beach_filters_html(html)
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

@router.get("/zprp", response_model=BeachTeamsListResponse)
async def list_beach_teams_from_zprp(
    season_id: Optional[str] = Query(None),
    province_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    category_id: Optional[str] = Query(None),
    club_id: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
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
    )

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

# =========================================================
# Sync ZPRP -> local DB
# =========================================================

@router.post("/local/sync", response_model=BeachTeamsSyncResponse)
async def sync_beach_teams_to_local(
    req: BeachTeamsSyncRequest,
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
    )

    now = _now_utc()
    upserted = 0

    for item in fetched:
        stmt = pg_insert(beach_teams).values(
            id=item["id"],
            team_name=item["team_name"],
            gender=item.get("gender"),
            gender_label=item.get("gender_label"),
            category_id=item.get("category_id"),
            category=item.get("category"),
            club_id=item.get("club_id"),
            club=item.get("club"),
            province_id=item.get("province_id"),
            province=item.get("province"),
            season_id=item.get("season_id"),
            season=item.get("season"),
            contact_json=item.get("contact") or {},
            squad_url=item.get("squad_url"),
            source="zprp",
            last_synced_at=now,
        ).on_conflict_do_update(
            index_elements=[beach_teams.c.id],
            set_={
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
            },
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
        },
    )