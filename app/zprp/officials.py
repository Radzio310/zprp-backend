# app/zprp/officials.py
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
logger = logging.getLogger("app.zprp.officials")
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
_RE_CITY_SUFFIX = re.compile(r"\s*\([A-Z]{1,3}\)\s*$")  # (SL), (MA) etc.
_RE_PARA_Z = re.compile(r"Para\s+z\s*:?\s*(.+)$", re.I)


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _clean_spaces(s: str) -> str:
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


def _absorb_href_keep_relative(href: str) -> str:
    """
    Na ZPRP href zwykle jest relatywny typu '?a=sedzia...'
    Zwracamy relatywny path+query (bez hosta).
    """
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


def _log_html_fingerprint(prefix: str, html: str) -> None:
    """
    Lekki fingerprint do logów (bez wypluwania HTML): długość + pierwsze znaki title.
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = _clean_spaces((soup.title.get_text(strip=True) if soup.title else ""))[:80]
    except Exception:
        title = ""
    logger.info("%s html_len=%s title='%s'", prefix, len(html or ""), title)


def _extract_menu_href_from_page(html: str, label_regex: str, href_regex: str) -> str:
    """
    Z dowolnej strony po zalogowaniu bierzemy link z menu po labelu lub po href-regexie.
    Przydatne bo link może nieść parametry (np. Filtr_woj2 / Filtr_archiwum).
    """
    soup = BeautifulSoup(html, "html.parser")
    rx_label = re.compile(label_regex, re.I)
    rx_href = re.compile(href_regex, re.I)

    a = soup.find("a", string=rx_label)
    if not a:
        a = soup.find("a", href=rx_href)

    href = _absorb_href_keep_relative(a.get("href", "") if a else "")
    if not href:
        raise HTTPException(500, f"Nie znaleziono linku menu: {label_regex}")

    # INFO: co dokładnie znaleźliśmy
    logger.info("Menu link found label_regex='%s' href='%s'", label_regex, href)
    return href


def _find_table(soup: BeautifulSoup):
    return soup.find("table", attrs={"id": "tabelka"}) if soup else None


def _row_is_data_tr(tr) -> bool:
    """
    Dane sędziego: pierwszy td ma title=<NrSedzia> i tekst '1.'
    """
    if not tr:
        return False
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 8:
        return False
    t0 = _clean_spaces(tds[0].get_text(" ", strip=True))
    if not _RE_LP_DOT.match(t0):
        return False
    title = _clean_spaces(tds[0].get("title", ""))
    return bool(title and re.fullmatch(r"\d+", title))


def _strip_city(raw: str) -> str:
    # "Ruda Śląska  (SL)" -> "Ruda Śląska"
    s = _clean_spaces(raw)
    s = _RE_CITY_SUFFIX.sub("", s).strip()
    return s


def _parse_photo_src(td) -> str:
    """
    W kolumnie Foto bywa <img src="foto_sedzia/5689.jpg?m=...">.
    Zwracamy src (relatywny) albo "".
    """
    if not td:
        return ""
    img = td.find("img", src=True)
    if not img:
        return ""
    return _absorb_href_keep_relative(_clean_spaces(img.get("src", "")))


def _parse_name_and_phone(td) -> Tuple[str, str]:
    """
    Z kolumny "Nazwisko Imię ... Telefon" chcemy:
    - name: z pierwszej linii
    - phone: po ikonie telefonu (telefon.png) albo fallback po cyfrach
    """
    if not td:
        return "", ""

    strings = [s for s in (td.stripped_strings or [])]
    name = _clean_spaces(strings[0]) if strings else ""

    phone = ""
    tel_img = td.find("img", src=re.compile(r"telefon\.png", re.I))
    if tel_img:
        parent = tel_img.parent
        if parent:
            tail = parent.get_text(" ", strip=True)
            m = re.search(r"(\+?\d[\d\s-]{6,})", tail)
            if m:
                phone = _clean_spaces(m.group(1))
    if not phone:
        txt = _clean_spaces(td.get_text(" ", strip=True))
        m = re.search(r"(\+?\d[\d\s-]{6,})", txt)
        if m:
            phone = _clean_spaces(m.group(1))

    return name, phone


def _parse_city(td) -> str:
    if not td:
        return ""
    txt = _clean_spaces(td.get_text(" ", strip=True))
    return _strip_city(txt)


def _parse_roles_and_partner(td) -> Tuple[str, List[str], str, List[str]]:
    """
    Kolumna: "Sędzia / Delegat / Stolikowy" zawiera <br>.
    Zwraca:
      - roles_text: role w nowych liniach (tylko sędzia/delegat/stolikowy)
      - roles_list: lista canonical ["sedzia","stolikowy","delegat"]
      - partner: jeśli "Para z : X" -> X
      - raw_lines: wszystkie niepuste linie z komórki (do logów/diagnostyki)
    """
    if not td:
        return "", [], "", []

    parts = []
    for chunk in td.decode_contents().split("<br"):
        txt = _clean_spaces(BeautifulSoup(chunk, "html.parser").get_text(" ", strip=True))
        if txt:
            parts.append(txt)

    roles: List[str] = []
    roles_text_lines: List[str] = []
    partner = ""

    def add_role(canon: str, label: str):
        if canon not in roles:
            roles.append(canon)
            roles_text_lines.append(label)

    for p in parts:
        m = _RE_PARA_Z.search(p)
        if m and not partner:
            partner = _clean_spaces(m.group(1))
            continue

        if re.search(r"\bSędzia\b", p, re.I):
            add_role("sedzia", "Sędzia")
            continue
        if re.search(r"\bDelegat\b", p, re.I):
            add_role("delegat", "Delegat")
            continue
        if re.search(r"\bStolikowy\b", p, re.I):
            add_role("stolikowy", "Stolikowy")
            continue

    roles_text = "\n".join(roles_text_lines).strip()
    return roles_text, roles, partner, parts


def _parse_actions_links(tr) -> Tuple[str, str, str]:
    """
    Z wiersza:
    - edycja: link z przycisku EDYTUJ
    - matches: link z "POKAŻ MECZE"
    - offtime: link z "POKAŻ OFFTIME"
    """
    edit_href = ""
    matches_href = ""
    offtime_href = ""

    for a in tr.find_all("a", href=True):
        label = _clean_spaces(a.get_text(" ", strip=True))
        href = _absorb_href_keep_relative(a.get("href", ""))

        if not href:
            continue

        if re.search(r"\bEDYTUJ\b", label, re.I) and not edit_href:
            edit_href = href
        elif re.search(r"\bPOKAŻ\s+MECZE\b", label, re.I) and not matches_href:
            matches_href = href
        elif re.search(r"\bPOKAŻ\s+OFFTIME\b", label, re.I) and not offtime_href:
            offtime_href = href

    return edit_href, matches_href, offtime_href


def _extract_paging_state(table: Any) -> Tuple[int, int]:
    """
    Z paska paginacji bierzemy:
    - count (np. 10/20/50/100) z <select name="count"> wybranej opcji
    - max_offset (największy offset z linków STRONA)
    """
    if not table:
        return 10, 0

    # count
    count = 10
    sel = table.find("select", attrs={"name": "count"})
    if sel:
        opt_sel = sel.find("option", selected=True)
        if opt_sel and _clean_spaces(opt_sel.get("value", "")):
            count = _safe_int(opt_sel.get("value", ""), default=10)

    # max_offset: weź wszystkie linki z offset=...
    max_offset = 0
    for a in table.find_all("a", href=True):
        href = a.get("href", "")
        if "offset=" not in href:
            continue
        try:
            u = urlparse(
                href if href.startswith("http")
                else ("http://x" + href if href.startswith("?") else "http://x/" + href)
            )
            qs = parse_qs(u.query)
            off = _safe_int((qs.get("offset", ["0"]) or ["0"])[0], default=0)
            max_offset = max(max_offset, off)
        except Exception:
            continue

    return count, max_offset


def _parse_officials_page(html: str, *, current_offset: int = 0) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    table = _find_table(soup)
    if not table:
        raise HTTPException(500, "Nie znaleziono tabeli sędziów (id='tabelka').")

    count, max_offset = _extract_paging_state(table)

    # INFO: paginacja wykryta na stronie
    logger.info(
        "Officials page parsed offset=%s count=%s max_offset=%s",
        current_offset,
        count,
        max_offset,
    )

    officials: Dict[str, Dict[str, Any]] = {}
    sample_rows: List[Dict[str, Any]] = []

    data_rows = 0
    skipped_rows = 0

    for tr in table.find_all("tr", recursive=False):
        if not _row_is_data_tr(tr):
            skipped_rows += 1
            continue

        data_rows += 1
        tds = tr.find_all("td", recursive=False)

        nr = _clean_spaces(tds[0].get("title", ""))  # NrSedzia
        lp = _safe_int(_clean_spaces(tds[0].get_text(" ", strip=True)), default=0)

        photo = _parse_photo_src(tds[1])
        name, phone = _parse_name_and_phone(tds[2])
        city = _parse_city(tds[3])

        roles_text, roles, partner, roles_raw_lines = _parse_roles_and_partner(tds[7])
        edit_href, matches_href, offtime_href = _parse_actions_links(tr)

        rec = {
            "NrSedzia": nr,
            "Lp": lp,
            "name": name,
            "photo_href": photo,
            "phone": phone,
            "city": city,
            "roles_text": roles_text,
            "roles": roles,
            "partner": partner,
            "edit_href": edit_href,
            "matches_href": matches_href,
            "offtime_href": offtime_href,
        }
        officials[nr] = rec

        # log-sample: zbieramy kilka pierwszych rekordów z tej strony
        if len(sample_rows) < 3:
            sample_rows.append(
                {
                    "NrSedzia": nr,
                    "name": name,
                    "city": city,
                    "roles_raw": roles_raw_lines,
                    "roles_text": roles_text,
                    "partner": partner,
                    "has_photo": bool(photo),
                    "has_edit": bool(edit_href),
                    "has_matches": bool(matches_href),
                    "has_offtime": bool(offtime_href),
                }
            )

    # INFO: ile wierszy danych na stronie i próbka
    logger.info(
        "Officials page summary offset=%s rows_data=%s rows_skipped=%s unique_officials_in_page=%s",
        current_offset,
        data_rows,
        skipped_rows,
        len(officials),
    )
    if sample_rows:
        logger.info("Officials page sample offset=%s sample=%s", current_offset, sample_rows)

    return {
        "paging": {
            "count": count,
            "offset": current_offset,
            "max_offset": max_offset,
        },
        "officials": officials,
    }


def _merge_officials(dst: Dict[str, Dict[str, Any]], src: Dict[str, Dict[str, Any]]) -> Tuple[int, int]:
    """
    Merge src -> dst. Zwraca (added, overwritten)
    """
    added = 0
    overwritten = 0
    for k, v in (src or {}).items():
        if k in dst:
            overwritten += 1
        else:
            added += 1
        dst[k] = v
    return added, overwritten


def _summarize_roles(officials: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    sedzia = 0
    delegat = 0
    stolikowy = 0
    para = 0
    phone = 0
    photo = 0
    city = 0

    for o in (officials or {}).values():
        roles = o.get("roles") or []
        if "sedzia" in roles:
            sedzia += 1
        if "delegat" in roles:
            delegat += 1
        if "stolikowy" in roles:
            stolikowy += 1
        if _clean_spaces(o.get("partner", "")):
            para += 1
        if _clean_spaces(o.get("phone", "")):
            phone += 1
        if _clean_spaces(o.get("photo_href", "")):
            photo += 1
        if _clean_spaces(o.get("city", "")):
            city += 1

    return {
        "with_role_sedzia": sedzia,
        "with_role_delegat": delegat,
        "with_role_stolikowy": stolikowy,
        "with_partner": para,
        "with_phone": phone,
        "with_photo": photo,
        "with_city": city,
    }


# =========================
# Endpoints
# =========================

@router.post("/zprp/sedziowie/scrape")
async def scrape_officials_full(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Full scrape "Sędziowie i Delegaci":
    - loguje się
    - wchodzi na /index.php (home)
    - z menu wyciąga href do "Sędziowie i Delegaci" (z parametrami konta)
    - pobiera wszystkie strony (offset=0..max_offset) dla aktualnego 'count' (domyślnie 10)
    - zwraca JSON keyed po NrSedzia
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)
        logger.info("ZPRP officials: login ok base_url=%s", settings.ZPRP_BASE_URL)

        # home po zalogowaniu (żeby pobrać menu link z parametrami)
        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        _log_html_fingerprint("Home fetched", html_home)

        sedzia_href = _extract_menu_href_from_page(
            html_home,
            label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
            href_regex=r"\ba=sedzia\b",
        )

        # pierwsza strona
        _, html0 = await fetch_with_correct_encoding(client, sedzia_href, method="GET", cookies=cookies)
        _log_html_fingerprint("Officials page[0] fetched", html0)

        parsed0 = _parse_officials_page(html0, current_offset=0)

        all_officials: Dict[str, Dict[str, Any]] = {}
        added0, overwritten0 = _merge_officials(all_officials, parsed0["officials"])

        paging0 = parsed0["paging"]
        count = int(paging0.get("count", 10))
        max_offset = int(paging0.get("max_offset", 0))

        logger.info(
            "ZPRP officials: page0 merged added=%s overwritten=%s officials_total=%s count=%s max_offset=%s",
            added0,
            overwritten0,
            len(all_officials),
            count,
            max_offset,
        )

        # bazowe parametry do kolejnych stron: bierzemy z sedzia_href (np. Filtr_archiwum, Filtr_woj2, count)
        try:
            u0 = urlparse(
                sedzia_href
                if sedzia_href.startswith("http")
                else ("http://x" + sedzia_href if sedzia_href.startswith("?") else "http://x/" + sedzia_href)
            )
            base_qs = parse_qs(u0.query)
        except Exception:
            base_qs = {}

        base_qs["a"] = ["sedzia"]
        base_qs["count"] = [str(count)]  # spójnie z tym co zdekodowała strona

        # INFO: pokaż bazowe parametry paginacji
        logger.info("ZPRP officials: paging base_qs=%s", {k: (v[0] if isinstance(v, list) and v else v) for k, v in base_qs.items()})

        # iteruj po kolejnych stronach
        for offset in range(1, max_offset + 1):
            qs = {k: (v[:] if isinstance(v, list) else [str(v)]) for k, v in base_qs.items()}
            qs["offset"] = [str(offset)]
            path = "/index.php?" + urlencode(qs, doseq=True)

            logger.info("ZPRP officials: fetching offset=%s path='%s'", offset, path)
            _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
            _log_html_fingerprint(f"Officials page[{offset}] fetched", html)

            parsed = _parse_officials_page(html, current_offset=offset)
            added, overwritten = _merge_officials(all_officials, parsed["officials"])

            logger.info(
                "ZPRP officials: merged offset=%s added=%s overwritten=%s officials_total=%s",
                offset,
                added,
                overwritten,
                len(all_officials),
            )

        role_stats = _summarize_roles(all_officials)
        logger.info("ZPRP officials: FINAL total=%s stats=%s", len(all_officials), role_stats)

        # INFO: próbka końcowa (max 5) żeby widzieć "co dokładnie znalazł"
        sample_final: List[Dict[str, Any]] = []
        for i, (nr, o) in enumerate(all_officials.items()):
            if i >= 5:
                break
            sample_final.append(
                {
                    "NrSedzia": nr,
                    "name": o.get("name", ""),
                    "city": o.get("city", ""),
                    "roles_text": o.get("roles_text", ""),
                    "partner": o.get("partner", ""),
                    "phone": bool(_clean_spaces(o.get("phone", ""))),
                    "photo": bool(_clean_spaces(o.get("photo_href", ""))),
                    "edit": bool(_clean_spaces(o.get("edit_href", ""))),
                    "matches": bool(_clean_spaces(o.get("matches_href", ""))),
                    "offtime": bool(_clean_spaces(o.get("offtime_href", ""))),
                }
            )
        if sample_final:
            logger.info("ZPRP officials: FINAL sample=%s", sample_final)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "entry_href": sedzia_href,
            "paging": {
                "count": count,
                "offset_min": 0,
                "offset_max": max_offset,
                "pages": max_offset + 1,
            },
            "officials": all_officials,
            "summary": {
                "officials_total": len(all_officials),
                **role_stats,
            },
        }


@router.post("/zprp/sedziowie/scrape_lite")
async def scrape_officials_lite(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Lite scrape:
    - loguje się
    - wchodzi na home, bierze href do "Sędziowie i Delegaci"
    - pobiera TYLKO pierwszą stronę (offset=0)
    """
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)
        logger.info("ZPRP officials(lite): login ok base_url=%s", settings.ZPRP_BASE_URL)

        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        _log_html_fingerprint("Home fetched(lite)", html_home)

        sedzia_href = _extract_menu_href_from_page(
            html_home,
            label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
            href_regex=r"\ba=sedzia\b",
        )

        _, html0 = await fetch_with_correct_encoding(client, sedzia_href, method="GET", cookies=cookies)
        _log_html_fingerprint("Officials page[0] fetched(lite)", html0)

        parsed0 = _parse_officials_page(html0, current_offset=0)
        officials = parsed0["officials"]
        paging0 = parsed0["paging"]
        role_stats = _summarize_roles(officials)

        logger.info(
            "ZPRP officials(lite): DONE officials_total=%s paging=%s stats=%s",
            len(officials),
            paging0,
            role_stats,
        )

        # próbka
        sample: List[Dict[str, Any]] = []
        for i, (nr, o) in enumerate(officials.items()):
            if i >= 5:
                break
            sample.append(
                {
                    "NrSedzia": nr,
                    "name": o.get("name", ""),
                    "city": o.get("city", ""),
                    "roles_text": o.get("roles_text", ""),
                    "partner": o.get("partner", ""),
                }
            )
        if sample:
            logger.info("ZPRP officials(lite): sample=%s", sample)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "entry_href": sedzia_href,
            "paging": paging0,
            "officials": officials,
            "summary": {
                "officials_total": len(officials),
                **role_stats,
            },
        }
