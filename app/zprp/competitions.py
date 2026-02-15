# app/zprp/competitions.py
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
_RE_STATUS = re.compile(r"^(aktywny|nieaktywny|archiwalny)\b", re.I)


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
    # sukces = po redirect lądujemy na /index.php
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
    """
    Na ZPRP href zwykle jest relatywny typu '?a=rozgrywki...'
    Zwracamy relatywny path (bez hosta), żeby front/back mógł go użyć w ramach base_url.
    """
    href = (href or "").strip()
    if not href:
        return ""
    # czasem ktoś wklei pełny URL - redukujemy do path+query
    try:
        u = urlparse(href)
        if u.scheme and u.netloc:
            return (u.path or "/") + (("?" + u.query) if u.query else "")
    except Exception:
        pass
    return href


def _extract_rogrywki_link_from_home(html: str) -> Tuple[str, str, str]:
    """
    Z głównej strony po zalogowaniu bierzemy link do zakładki "Rozgrywki".
    To ważne, bo zawiera Filtr_woj (związany z kontem wojewódzkim).
    Zwraca: (href, filtr_woj, filtr_sezon)
    """
    soup = BeautifulSoup(html, "html.parser")

    a = soup.find("a", string=re.compile(r"^\s*Rozgrywki\s*$", re.I))
    if not a:
        # fallback: po class="przycisk" i href zawiera a=rozgrywki
        a = soup.find("a", href=re.compile(r"\ba=rozgrywki\b", re.I))

    href = _absorb_href_keep_relative(a.get("href", "") if a else "")
    if not href:
        raise HTTPException(500, "Nie znaleziono linku do zakładki 'Rozgrywki' na stronie głównej.")

    # wyciągamy Filtr_woj i Filtr_sezon z query
    try:
        u = urlparse(href if href.startswith("http") else ("http://x" + href if href.startswith("?") else "http://x/" + href))
        qs = parse_qs(u.query)
        filtr_woj = _clean_spaces((qs.get("Filtr_woj", [""]) or [""])[0])
        filtr_sezon = _clean_spaces((qs.get("Filtr_sezon", [""]) or [""])[0])
    except Exception:
        filtr_woj = ""
        filtr_sezon = ""

    return href, filtr_woj, filtr_sezon


def _find_competitions_table(soup: BeautifulSoup):
    """
    Strona rozgrywek ma tabelę id="tabelka".
    """
    if not soup:
        return None
    table = soup.find("table", attrs={"id": "tabelka"})
    return table


def _row_is_data_tr(tr) -> bool:
    if not tr:
        return False
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 10:
        return False
    # pierwsza komórka: "N." + title=IdRozgr
    t0 = _clean_spaces(tds[0].get_text(" ", strip=True))
    if not _RE_LP_DOT.match(t0):
        return False
    title = _clean_spaces(tds[0].get("title", ""))
    return bool(title and re.fullmatch(r"\d+", title))


def _parse_regulamin_cell(td) -> Dict[str, Any]:
    """
    Kolumna "Regulamin" bywa pusta (&nbsp;) albo zawiera link(i).
    Zwracamy: {text, links:[{label, href}]}
    """
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
    """
    Ostatnia kolumna zawiera linki-akcje: Rundy, Kolejki, Zawody, Drużyny, Tabela, Terminarz, Edycja.
    Parsujemy wszystkie <a>.
    Dodatkowo dla "Rundy" wyciągamy liczbę (np. "Rundy  2").
    """
    out: List[Dict[str, Any]] = []
    if not td:
        return out

    for a in td.find_all("a"):
        href = _absorb_href_keep_relative(a.get("href", ""))
        txt = _clean_spaces(a.get_text(" ", strip=True))

        if not href and not txt:
            continue

        item: Dict[str, Any] = {"label": txt, "href": href}

        # heurystyki: typ akcji po parametrze a/b lub label
        try:
            u = urlparse(href if href.startswith("http") else ("http://x" + href if href.startswith("?") else "http://x/" + href))
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


def _parse_competitions_page(html: str) -> Dict[str, Any]:
    """
    Parsuje JEDNĄ stronę rozgrywek (dla konkretnego Filtr_sezon) i zwraca:
    - filters meta (sezony/kategorie/plec/typ/woj)
    - competitions list/map
    """
    soup = BeautifulSoup(html, "html.parser")
    table = _find_competitions_table(soup)
    if not table:
        raise HTTPException(500, "Nie znaleziono tabeli rozgrywek (id='tabelka').")

    # filtry są w header row w <form method="get"> wewnątrz tabeli
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

    # hidden inputs też bywają przydatne (np. Filtr_woj zablokowany disabled)
    hidden = {}
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
        # Oczekiwany układ (z przykładu):
        # 0 Lp (title=IdRozgr)
        # 1 Nazwa
        # 2 Płeć
        # 3 Kategoria
        # 4 Woj
        # 5 Kod
        # 6 Typ
        # 7 Sezon (label)
        # 8 Stan
        # 9 Regulamin
        # 10 liczba wymaganych
        # 11 liczba zgłoszonych
        # 12 akcje
        id_rozgr = _clean_spaces(tds[0].get("title", ""))
        lp_txt = _clean_spaces(tds[0].get_text(" ", strip=True))
        lp = _safe_int(lp_txt, default=0)

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


@router.post("/zprp/rozgrywki/meta")
async def get_rozgrywki_meta(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Meta endpoint:
    - loguje się
    - wchodzi na /index.php (home)
    - znajduje link do zakładki Rozgrywki (z Filtr_woj / Filtr_sezon)
    - pobiera stronę rozgrywek i zwraca dostępne filtry (w tym listę sezonów)
    """
    private_key, _ = keys

    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=60.0,
    ) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        # home po zalogowaniu
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


@router.post("/zprp/rozgrywki/scrape")
async def scrape_rozgrywki_full(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Full scrape:
    - logowanie identyczne jak schedule.py
    - wejście na home -> bierzemy link do "Rozgrywki" (właściwy Filtr_woj)
    - pobieramy stronę rozgrywek
    - wyciągamy listę sezonów z selecta
    - iterujemy po WSZYSTKICH sezonach (bez filtrowania po backendzie)
    - składamy jeden JSON zawierający całą tabelę rozgrywek (per sezon) + linki akcji
    """
    private_key, _ = keys

    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=60.0,
    ) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        # home po zalogowaniu
        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        rozgrywki_href, filtr_woj_home, filtr_sezon_home = _extract_rogrywki_link_from_home(html_home)

        # strona rozgrywek (domyślnie sezon aktualny)
        _, html0 = await fetch_with_correct_encoding(client, rozgrywki_href, method="GET", cookies=cookies)
        parsed0 = _parse_competitions_page(html0)

        filters0 = parsed0["filters"]
        seasons_list = filters0.get("Filtr_sezon", []) or []
        woj_list = filters0.get("Filtr_woj", []) or []

        # bieżące wartości (pomocniczo)
        filtr_woj = _pick_selected_value([(x["value"], x["label"], bool(x.get("selected"))) for x in woj_list]) or _clean_spaces(filtr_woj_home)
        if not filtr_woj:
            # last resort: hidden input
            filtr_woj = _clean_spaces((filters0.get("hidden", {}) or {}).get("Filtr_woj", ""))

        # wszystkie sezony do pobrania
        season_values = [x.get("value", "") for x in seasons_list if _clean_spaces(x.get("value", ""))]
        season_values = [v for v in season_values if v != "---" and v != "0"]

        if not season_values:
            raise HTTPException(500, "Nie znaleziono listy sezonów na stronie 'Rozgrywki'.")

        # iteracja po sezonach
        competitions_by_season: Dict[str, Dict[str, Any]] = {}
        competitions_all: Dict[str, Dict[str, Any]] = {}

        for season_id in season_values:
            qs = {
                "a": "rozgrywki",
                "Filtr_sezon": season_id,
                "Filtr_woj": filtr_woj,
                # resztę zostawiamy pustą (jak w formie)
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

            comps = parsed["competitions"]  # map IdRozgr -> record
            competitions_by_season[season_id] = {
                "season_id": season_id,
                "season_label": next((x.get("label", "") for x in seasons_list if x.get("value") == season_id), ""),
                "url": path,
                "count": len(comps),
                "competitions": comps,
            }

            # global map (IdRozgr jest globalnie unikalne w praktyce; jeśli nie, to „ostatni wygrywa”)
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
