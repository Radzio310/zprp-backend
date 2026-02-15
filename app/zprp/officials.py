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

logger = logging.getLogger("app.zprp.officials")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

_RE_INT = re.compile(r"(\d+)")
_RE_LP_DOT = re.compile(r"^\s*(\d+)\.\s*$")
_RE_CITY_SUFFIX = re.compile(r"\s*\([A-Z]{1,3}\)\s*$")  # (SL)
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
    if "/index.php" not in resp_login.url.path:
        raise HTTPException(401, "Logowanie nie powiodło się")
    return dict(resp_login.cookies)


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


def _log_html_fingerprint(prefix: str, html: str) -> None:
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = _clean_spaces((soup.title.get_text(strip=True) if soup.title else ""))[:80]
    except Exception:
        title = ""
    logger.info("%s html_len=%s title='%s'", prefix, len(html or ""), title)


def _extract_menu_href_from_page(html: str, label_regex: str, href_regex: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    rx_label = re.compile(label_regex, re.I)
    rx_href = re.compile(href_regex, re.I)

    a = soup.find("a", string=rx_label)
    if not a:
        a = soup.find("a", href=rx_href)

    href = _absorb_href_keep_relative(a.get("href", "") if a else "")
    if not href:
        raise HTTPException(500, f"Nie znaleziono linku menu: {label_regex}")

    logger.info("Menu link found label_regex='%s' href='%s'", label_regex, href)
    return href


def _find_table(soup: BeautifulSoup):
    return soup.find("table", attrs={"id": "tabelka"}) if soup else None


def _row_is_data_tr(tr) -> bool:
    """
    Dane sędziego: pierwszy td ma title=<NrSedzia> (cyfry)
    i tekst typu '1.'
    """
    if not tr:
        return False

    tds = tr.find_all("td")  # UWAGA: bez recursive=False (HTML ma formy w środku)
    if len(tds) < 8:
        return False

    t0 = _clean_spaces(tds[0].get_text(" ", strip=True))
    if not _RE_LP_DOT.match(t0):
        return False

    title = _clean_spaces(tds[0].get("title", ""))
    return bool(title and re.fullmatch(r"\d+", title))


def _strip_city(raw: str) -> str:
    s = _clean_spaces(raw)
    return _RE_CITY_SUFFIX.sub("", s).strip()


def _parse_photo_src(td) -> str:
    if not td:
        return ""
    img = td.find("img", src=True)
    if not img:
        return ""
    return _absorb_href_keep_relative(_clean_spaces(img.get("src", "")))


def _parse_name_and_phone(td) -> Tuple[str, str]:
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
    return _strip_city(_clean_spaces(td.get_text(" ", strip=True)))


def _parse_roles_and_partner(td) -> Tuple[str, List[str], str, List[str]]:
    if not td:
        return "", [], "", []

    # bierzemy linie po <br> bez polegania na strukturze DOM
    parts: List[str] = []
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


def _extract_base_qs_from_paging_form(table: Any) -> Dict[str, str]:
    """
    Najpewniejsze źródło parametrów filtrów (Filtr_woj2 itp.)
    jest w formularzu paginacji, w hidden inputach.
    """
    if not table:
        return {}

    # szukamy formy, która ma select name="count"
    paging_form = None
    for f in table.find_all("form"):
        if f.find("select", attrs={"name": "count"}):
            paging_form = f
            break

    if not paging_form:
        return {}

    qs: Dict[str, str] = {}
    for inp in paging_form.find_all("input", attrs={"type": "hidden", "name": True}):
        name = _clean_spaces(inp.get("name", ""))
        val = _clean_spaces(inp.get("value", ""))
        if name:
            qs[name] = val

    # count z select
    sel = paging_form.find("select", attrs={"name": "count"})
    if sel:
        opt_sel = sel.find("option", selected=True)
        if opt_sel:
            qs["count"] = _clean_spaces(opt_sel.get("value", "")) or qs.get("count", "")

    return qs


def _extract_paging_state(table: Any) -> Tuple[int, int]:
    """
    - count: zaznaczona opcja
    - max_offset: najwyższy offset=... w linkach
    """
    if not table:
        return 10, 0

    count = 10
    sel = table.find("select", attrs={"name": "count"})
    if sel:
        opt_sel = sel.find("option", selected=True)
        if opt_sel and _clean_spaces(opt_sel.get("value", "")):
            count = _safe_int(opt_sel.get("value", ""), default=10)

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
    base_qs = _extract_base_qs_from_paging_form(table)

    # DIAGNOSTYKA: ile tr w ogóle widzimy
    all_trs = table.find_all("tr")  # <--- KLUCZOWA ZMIANA (bez recursive=False)
    logger.info(
        "Officials page parsed offset=%s count=%s max_offset=%s trs_seen=%s base_qs_keys=%s",
        current_offset,
        count,
        max_offset,
        len(all_trs),
        sorted(list(base_qs.keys()))[:20],
    )

    officials: Dict[str, Dict[str, Any]] = {}
    sample_rows: List[Dict[str, Any]] = []

    data_rows = 0
    skipped_rows = 0

    for tr in all_trs:
        if not _row_is_data_tr(tr):
            skipped_rows += 1
            continue

        data_rows += 1
        tds = tr.find_all("td")  # bez recursive=False

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
        "paging": {"count": count, "offset": current_offset, "max_offset": max_offset},
        "base_qs": base_qs,  # <--- NOWE: weźmiemy to do budowania kolejnych requestów
        "officials": officials,
    }


def _merge_officials(dst: Dict[str, Dict[str, Any]], src: Dict[str, Dict[str, Any]]) -> Tuple[int, int]:
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
    sedzia = delegat = stolikowy = para = phone = photo = city = 0
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


@router.post("/zprp/sedziowie/scrape")
async def scrape_officials_full(
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
        logger.info("ZPRP officials: login ok base_url=%s", settings.ZPRP_BASE_URL)

        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        _log_html_fingerprint("Home fetched", html_home)

        sedzia_href = _extract_menu_href_from_page(
            html_home,
            label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
            href_regex=r"\ba=sedzia\b",
        )

        _, html0 = await fetch_with_correct_encoding(client, sedzia_href, method="GET", cookies=cookies)
        _log_html_fingerprint("Officials page[0] fetched", html0)

        parsed0 = _parse_officials_page(html0, current_offset=0)

        all_officials: Dict[str, Dict[str, Any]] = {}
        added0, overwritten0 = _merge_officials(all_officials, parsed0["officials"])

        paging0 = parsed0["paging"]
        count = int(paging0.get("count", 10))
        max_offset = int(paging0.get("max_offset", 0))

        # KLUCZOWE: bazę do kolejnych requestów bierzemy z hidden inputów strony
        base_qs0 = parsed0.get("base_qs") or {}
        base_qs: Dict[str, str] = dict(base_qs0)

        # wymuszenia
        base_qs["a"] = "sedzia"
        base_qs["Filtr_archiwum"] = base_qs.get("Filtr_archiwum", "1") or "1"
        base_qs["count"] = str(count)

        logger.info(
            "ZPRP officials: page0 merged added=%s overwritten=%s officials_total=%s count=%s max_offset=%s",
            added0,
            overwritten0,
            len(all_officials),
            count,
            max_offset,
        )
        logger.info("ZPRP officials: paging base_qs=%s", base_qs)

        for offset in range(1, max_offset + 1):
            qs = dict(base_qs)
            qs["offset"] = str(offset)
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

        # próbka końcowa (max 5)
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
            "paging": {"count": count, "offset_min": 0, "offset_max": max_offset, "pages": max_offset + 1},
            "officials": all_officials,
            "summary": {"officials_total": len(all_officials), **role_stats},
        }


@router.post("/zprp/sedziowie/scrape_lite")
async def scrape_officials_lite(
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
        role_stats = _summarize_roles(officials)

        logger.info(
            "ZPRP officials(lite): DONE officials_total=%s paging=%s stats=%s",
            len(officials),
            parsed0["paging"],
            role_stats,
        )

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "entry_href": sedzia_href,
            "paging": parsed0["paging"],
            "officials": officials,
            "summary": {"officials_total": len(officials), **role_stats},
        }
