# app/zprp/competitions.py
from __future__ import annotations

import base64
import datetime
import logging
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient

from app.deps import Settings, get_settings, get_rsa_keys
from app.schemas import ZprpScheduleScrapeRequest
from app.utils import fetch_with_correct_encoding

router = APIRouter()

# =========================
# Logger (Railway -> stdout)
# =========================
logger = logging.getLogger("app.zprp.competitions")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# =========================
# Regex / helpers
# =========================
_RE_INT = re.compile(r"(\d+)")
_RE_LP_DOT = re.compile(r"^\s*(\d+)\.\s*$")


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _clean_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _safe_int(s: str, default: int = 0) -> int:
    if not s:
        return default
    m = _RE_INT.search(s)
    return int(m.group(1)) if m else default


def _decrypt_field(private_key, enc_b64: str) -> str:
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")


async def _login_zprp_and_get_cookies(client: AsyncClient, username: str, password: str) -> Dict[str, str]:
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
        val = _clean_spaces(opt.get("value", ""))
        lab = _clean_spaces(opt.get_text(strip=True))
        if not val and not lab:
            continue
        out.append((val, lab, bool(opt.has_attr("selected"))))
    return out


def _absorb_href_keep_relative(href: str) -> str:
    href = (href or "").strip()
    if not href:
        return ""
    try:
        u = urlparse(href)
        if u.scheme and u.netloc:
            return (u.path or "/") + (("?" + u.query) if u.query else "")
    except Exception:
        pass
    return href


def _extract_rogrywki_link_from_home(html: str) -> Tuple[str, str, str]:
    soup = BeautifulSoup(html, "html.parser")

    a = soup.find("a", string=re.compile(r"^\s*Rozgrywki\s*$", re.I))
    if not a:
        a = soup.find("a", href=re.compile(r"\ba=rozgrywki\b", re.I))

    href = _absorb_href_keep_relative(a.get("href", "") if a else "")
    if not href:
        raise HTTPException(500, "Nie znaleziono linku do zakładki 'Rozgrywki' na stronie głównej.")

    try:
        u = urlparse(
            href if href.startswith("http")
            else ("http://x" + href if href.startswith("?") else "http://x/" + href)
        )
        qs = parse_qs(u.query)
        filtr_woj = _clean_spaces((qs.get("Filtr_woj", [""]) or [""])[0])
        filtr_sezon = _clean_spaces((qs.get("Filtr_sezon", [""]) or [""])[0])
    except Exception:
        filtr_woj = ""
        filtr_sezon = ""

    return href, filtr_woj, filtr_sezon


def _find_competitions_table(soup: BeautifulSoup):
    return soup.find("table", attrs={"id": "tabelka"}) if soup else None


def _row_is_data_tr(tr) -> bool:
    if not tr:
        return False
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 10:
        return False
    t0 = _clean_spaces(tds[0].get_text(" ", strip=True))
    if not _RE_LP_DOT.match(t0):
        return False
    title = _clean_spaces(tds[0].get("title", ""))
    return bool(title and re.fullmatch(r"\d+", title))


def _parse_regulamin_cell(td) -> Dict[str, Any]:
    out = {"text": "", "links": []}  # type: ignore[dict-item]
    if not td:
        return out

    out["text"] = _clean_spaces(td.get_text(" ", strip=True))
    links = []
    for a in td.find_all("a"):
        href = _absorb_href_keep_relative(a.get("href", ""))
        lab = _clean_spaces(a.get_text(" ", strip=True))
        if href or lab:
            links.append({"label": lab, "href": href})
    out["links"] = links
    return out


def _parse_actions_cell(td) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not td:
        return out

    for a in td.find_all("a"):
        href = _absorb_href_keep_relative(a.get("href", ""))
        txt = _clean_spaces(a.get_text(" ", strip=True))
        if not href and not txt:
            continue

        item: Dict[str, Any] = {"label": txt, "href": href}

        try:
            u = urlparse(
                href if href.startswith("http")
                else ("http://x" + href if href.startswith("?") else "http://x/" + href)
            )
            qs = parse_qs(u.query)
            a_param = _clean_spaces((qs.get("a", [""]) or [""])[0])
            b_param = _clean_spaces((qs.get("b", [""]) or [""])[0])
            if a_param:
                item["a"] = a_param
            if b_param:
                item["b"] = b_param
        except Exception:
            pass

        if re.search(r"\bRundy\b", txt, re.I):
            item["rounds_count"] = _safe_int(txt, default=0)

        out.append(item)

    return out


def _pick_action_href(actions: List[Dict[str, Any]], label_regex: str) -> str:
    rx = re.compile(label_regex, re.I)
    for a in actions or []:
        if rx.search(_clean_spaces(a.get("label", ""))):
            return _clean_spaces(a.get("href", ""))
    return ""


def _parse_competitions_page(html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    table = _find_competitions_table(soup)
    if not table:
        raise HTTPException(500, "Nie znaleziono tabeli rozgrywek (id='tabelka').")

    sel_season = table.find("select", attrs={"name": "Filtr_sezon"})
    sel_kat = table.find("select", attrs={"name": "Filtr_kategoria"})
    sel_plec = table.find("select", attrs={"name": "Filtr_plec"})
    sel_typ = table.find("select", attrs={"name": "Filtr_typ"})
    sel_woj = table.find("select", attrs={"name": "Filtr_woj"})

    seasons = _parse_select_options(sel_season)
    categories = _parse_select_options(sel_kat)
    plec = _parse_select_options(sel_plec)
    typ = _parse_select_options(sel_typ)
    woj = _parse_select_options(sel_woj)

    hidden: Dict[str, str] = {}
    for inp in table.find_all("input", attrs={"type": "hidden"}):
        name = _clean_spaces(inp.get("name", ""))
        val = _clean_spaces(inp.get("value", ""))
        if name:
            hidden[name] = val

    competitions: Dict[str, Dict[str, Any]] = {}

    for tr in table.find_all("tr", recursive=False):
        if not _row_is_data_tr(tr):
            continue

        tds = tr.find_all("td", recursive=False)

        id_rozgr = _clean_spaces(tds[0].get("title", ""))
        lp = _safe_int(_clean_spaces(tds[0].get_text(" ", strip=True)), default=0)

        name = _clean_spaces(tds[1].get_text(" ", strip=True))
        sex = _clean_spaces(tds[2].get_text(" ", strip=True))
        kat = _clean_spaces(tds[3].get_text(" ", strip=True))
        woj_txt = _clean_spaces(tds[4].get_text(" ", strip=True))
        code = _clean_spaces(tds[5].get_text(" ", strip=True))
        typ_txt = _clean_spaces(tds[6].get_text(" ", strip=True))
        season_label = _clean_spaces(tds[7].get_text(" ", strip=True))
        status = _clean_spaces(tds[8].get_text(" ", strip=True))

        regulamin = _parse_regulamin_cell(tds[9])
        teams_required = _safe_int(_clean_spaces(tds[10].get_text(" ", strip=True)), default=0)
        teams_declared = _safe_int(_clean_spaces(tds[11].get_text(" ", strip=True)), default=0)

        actions = _parse_actions_cell(tds[12])
        teams_href = _pick_action_href(actions, r"^Drużyny\b")

        competitions[id_rozgr] = {
            "IdRozgr": id_rozgr,
            "Lp": lp,
            "Nazwa": name,
            "Plec": sex,
            "Kategoria": kat,
            "Woj": woj_txt,
            "Kod": code,
            "Typ": typ_txt,
            "SezonLabel": season_label,
            "Stan": status,
            "Regulamin": regulamin,
            "teams_required": teams_required,
            "teams_declared": teams_declared,
            "actions": actions,
            "teams_href": teams_href,
        }

    return {
        "filters": {
            "hidden": hidden,
            "Filtr_sezon": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in seasons],
            "Filtr_kategoria": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in categories],
            "Filtr_plec": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in plec],
            "Filtr_typ": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in typ],
            "Filtr_woj": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in woj],
        },
        "competitions": competitions,
    }


def _pick_selected_value(opts: List[Tuple[str, str, bool]]) -> str:
    return next((v for (v, _, sel) in opts if sel and v), "") or next((v for (v, _, _) in opts if v), "")


# =========================
# Teams (Drużyny) parsing
# =========================

def _strip_team_name(raw: str) -> str:
    s = _clean_spaces(raw)
    s = re.sub(r"\s*\([A-Z]{1,3}\)\s*$", "", s).strip()
    return s


def _looks_like_participants_header(tr) -> bool:
    if not tr:
        return False
    tds = tr.find_all("td", recursive=False)
    if not tds:
        return False
    txt = _clean_spaces(" ".join(td.get_text(" ", strip=True) for td in tds))
    return "Drużyny uczestniczące w rozgrywkach" in txt


def _parse_competition_teams_from_teams_page(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")

    teams: List[str] = []
    trs = soup.find_all("tr")
    target_nested_table = None

    for i, tr in enumerate(trs):
        if _looks_like_participants_header(tr):
            for j in range(i + 1, min(i + 6, len(trs))):
                tds = trs[j].find_all("td", recursive=False)
                if not tds:
                    continue
                nested = tds[0].find("table")
                if nested:
                    target_nested_table = nested
                    break
            break

    if target_nested_table is None:
        candidates = []
        for tbl in soup.find_all("table"):
            txt = _clean_spaces(tbl.get_text(" ", strip=True))
            if not txt:
                continue
            has_sklad_links = bool(tbl.find("a", href=re.compile(r"\ba=zespoly\b.*\bb=sklad\b", re.I)))
            has_pdf = bool(tbl.find("img", src=re.compile(r"pdf2\.png", re.I)))
            if has_sklad_links and has_pdf:
                candidates.append((len(tbl.find_all("tr")), tbl))
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            target_nested_table = candidates[0][1]

    if target_nested_table is None:
        return teams

    for tr in target_nested_table.find_all("tr"):
        tds = tr.find_all("td", recursive=False)
        if len(tds) < 3:
            continue
        lp_txt = _clean_spaces(tds[0].get_text(" ", strip=True))
        if not _RE_LP_DOT.match(lp_txt):
            continue

        name_td = tds[2]
        a = name_td.find("a", href=True)
        name_txt = _clean_spaces(a.get_text(" ", strip=True) if a else name_td.get_text(" ", strip=True))
        name_txt = _strip_team_name(name_txt)
        if name_txt:
            teams.append(name_txt)

    return teams


# =========================
# Shared scrape helper
# =========================

async def _scrape_one_season(
    *,
    client: AsyncClient,
    cookies: Dict[str, str],
    season_id: str,
    season_label: str,
    filtr_woj: str,
) -> Dict[str, Any]:
    """
    Pobiera rozgrywki tylko dla jednego sezonu + dopina teams dla każdej rozgrywki.
    """
    qs = {
        "a": "rozgrywki",
        "Filtr_sezon": season_id,
        "Filtr_woj": filtr_woj,
        "Filtr_klub": "",
        "Filtr_kategoria": "",
        "Filtr_plec": "",
        "Filtr_typ": "",
        "Nazwa": "",
        "sort": "",
    }
    path = "/index.php?" + urlencode(qs, doseq=True)

    _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
    parsed = _parse_competitions_page(html)
    comps = parsed["competitions"]

    for cid, comp in comps.items():
        teams_href = _clean_spaces(comp.get("teams_href", "")) or _pick_action_href(comp.get("actions", []), r"^Drużyny\b")
        if not teams_href:
            comp["teams"] = []
            comp["teams_count"] = 0
            continue

        try:
            _, html_teams = await fetch_with_correct_encoding(client, teams_href, method="GET", cookies=cookies)
            teams = _parse_competition_teams_from_teams_page(html_teams)
            comp["teams"] = teams
            comp["teams_count"] = len(teams)
            comp["teams_page_href"] = teams_href
        except Exception as e:
            logger.warning("Teams scrape failed IdRozgr=%s href=%s err=%s", cid, teams_href, e)
            comp["teams"] = []
            comp["teams_count"] = 0
            comp["teams_page_href"] = teams_href
            comp["teams_error"] = str(e)

    return {
        "season_id": season_id,
        "season_label": season_label,
        "url": path,
        "count": len(comps),
        "competitions": comps,
    }


# =========================
# Endpoints
# =========================

@router.post("/zprp/rozgrywki/meta")
async def get_rozgrywki_meta(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        rozgrywki_href, filtr_woj, filtr_sezon = _extract_rogrywki_link_from_home(html_home)

        _, html0 = await fetch_with_correct_encoding(client, rozgrywki_href, method="GET", cookies=cookies)
        parsed0 = _parse_competitions_page(html0)

        filters = parsed0["filters"]
        seasons_opts = [(x["value"], x["label"], bool(x.get("selected"))) for x in filters.get("Filtr_sezon", [])]
        woj_opts = [(x["value"], x["label"], bool(x.get("selected"))) for x in filters.get("Filtr_woj", [])]

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "rozgrywki_entry_href": rozgrywki_href,
            "Filtr_woj_from_home": filtr_woj,
            "Filtr_sezon_from_home": filtr_sezon,
            "Filtr_woj_selected": _pick_selected_value(woj_opts) if woj_opts else filtr_woj,
            "Filtr_sezon_selected": _pick_selected_value(seasons_opts) if seasons_opts else filtr_sezon,
            "filters": filters,
        }


@router.post("/zprp/rozgrywki/scrape_lite")
async def scrape_rozgrywki_lite(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Lite scrape:
    - pobiera TYLKO wybrany sezon (payload.season_id albo domyślnie zaznaczony na stronie)
    - dopina teams (uczestniczące) dla rozgrywek z tego sezonu
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    # oczekujemy, że ZprpScheduleScrapeRequest ma opcjonalne pole season_id (string)
    requested_season_id = _clean_spaces(getattr(payload, "season_id", "") or "")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        rozgrywki_href, filtr_woj_home, _ = _extract_rogrywki_link_from_home(html_home)

        _, html0 = await fetch_with_correct_encoding(client, rozgrywki_href, method="GET", cookies=cookies)
        parsed0 = _parse_competitions_page(html0)
        filters0 = parsed0["filters"]

        seasons_list = filters0.get("Filtr_sezon", []) or []
        woj_list = filters0.get("Filtr_woj", []) or []

        filtr_woj = _pick_selected_value([(x["value"], x["label"], bool(x.get("selected"))) for x in woj_list]) or _clean_spaces(filtr_woj_home)
        if not filtr_woj:
            filtr_woj = _clean_spaces((filters0.get("hidden", {}) or {}).get("Filtr_woj", ""))

        # sezon: payload.season_id -> jeśli pusty, bierzemy zaznaczony na stronie
        selected_from_page = _pick_selected_value([(x.get("value", ""), x.get("label", ""), bool(x.get("selected"))) for x in seasons_list])
        season_id = requested_season_id or selected_from_page
        if not season_id:
            raise HTTPException(400, "Brak season_id w payload i nie udało się wykryć zaznaczonego sezonu.")

        season_label = next((x.get("label", "") for x in seasons_list if _clean_spaces(x.get("value", "")) == season_id), "")

        one = await _scrape_one_season(
            client=client,
            cookies=cookies,
            season_id=season_id,
            season_label=season_label,
            filtr_woj=filtr_woj,
        )

        comps = one["competitions"]
        summary = {
            "seasons": 1,
            "competitions_total": int(one.get("count", 0)),
            "teams_total": sum(int(c.get("teams_count", 0)) for c in comps.values()),
        }

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "rozgrywki_entry_href": rozgrywki_href,
            "Filtr_woj": filtr_woj,
            "season_id": season_id,
            "season_label": season_label,
            "filters_snapshot": filters0,
            "by_season": {season_id: one},
            "competitions": comps,  # tylko ten sezon
            "summary": summary,
        }


@router.post("/zprp/rozgrywki/scrape")
async def scrape_rozgrywki_full(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Full scrape + TEAMS:
    - iteruje po wszystkich sezonach
    - pobiera rozgrywki
    - dla każdej rozgrywki wchodzi w akcję "Drużyny" i zczytuje listę drużyn uczestniczących
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        rozgrywki_href, filtr_woj_home, filtr_sezon_home = _extract_rogrywki_link_from_home(html_home)

        _, html0 = await fetch_with_correct_encoding(client, rozgrywki_href, method="GET", cookies=cookies)
        parsed0 = _parse_competitions_page(html0)

        filters0 = parsed0["filters"]
        seasons_list = filters0.get("Filtr_sezon", []) or []
        woj_list = filters0.get("Filtr_woj", []) or []

        filtr_woj = _pick_selected_value([(x["value"], x["label"], bool(x.get("selected"))) for x in woj_list]) or _clean_spaces(filtr_woj_home)
        if not filtr_woj:
            filtr_woj = _clean_spaces((filters0.get("hidden", {}) or {}).get("Filtr_woj", ""))

        season_values = [x.get("value", "") for x in seasons_list if _clean_spaces(x.get("value", ""))]
        season_values = [v for v in season_values if v not in ("---", "0", "")]
        if not season_values:
            raise HTTPException(500, "Nie znaleziono listy sezonów na stronie 'Rozgrywki'.")

        competitions_by_season: Dict[str, Dict[str, Any]] = {}
        competitions_all: Dict[str, Dict[str, Any]] = {}

        for season_id in season_values:
            season_label = next((x.get("label", "") for x in seasons_list if x.get("value") == season_id), "")
            one = await _scrape_one_season(
                client=client,
                cookies=cookies,
                season_id=season_id,
                season_label=season_label,
                filtr_woj=filtr_woj,
            )

            comps = one["competitions"]
            competitions_by_season[season_id] = one

            for k, v in comps.items():
                competitions_all[k] = v

            logger.info(
                "ZPRP rozgrywki: fetched season=%s woj=%s competitions=%d",
                season_id,
                filtr_woj,
                len(comps),
            )

        summary = {
            "seasons": len(competitions_by_season),
            "competitions_total": sum(int(x.get("count", 0)) for x in competitions_by_season.values()),
            "teams_total": sum(int(c.get("teams_count", 0)) for c in competitions_all.values()),
        }

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "rozgrywki_entry_href": rozgrywki_href,
            "Filtr_woj": filtr_woj,
            "Filtr_woj_from_home": filtr_woj_home,
            "Filtr_sezon_from_home": filtr_sezon_home,
            "filters_snapshot": filters0,
            "by_season": competitions_by_season,
            "competitions": competitions_all,
            "summary": summary,
        }
