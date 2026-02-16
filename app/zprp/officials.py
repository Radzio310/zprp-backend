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
_RE_PARA_Z = re.compile(r"Para\s+z\s*:\s*(.+)$", re.I)  # "Para z : XYZ"
_RE_PARENS = re.compile(r"\s*\([^)]*\)\s*")  # usuwa "(...)"


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

    tds = tr.find_all("td")
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


def _smart_title_token(tok: str) -> str:
    """
    Lepsze niż .title() dla nazwisk z myślnikami i polskimi znakami.
    """
    tok = _clean_spaces(tok)
    if not tok:
        return ""
    if "-" in tok:
        parts = [p for p in tok.split("-") if p]
        return "-".join(_smart_title_token(p) for p in parts)
    return tok[:1].upper() + tok[1:].lower()


def _format_name_last_first_to_first_last(s: str) -> str:
    """
    ZPRP zwykle ma "NAZWISKO Imię".
    Zwracamy "Imię Nazwisko" i normalizujemy wielkość liter.
    """
    s = _clean_spaces(s)
    if not s:
        return ""

    parts = [p for p in s.split(" ") if p]
    if len(parts) == 1:
        return _smart_title_token(parts[0])

    last = parts[0]
    first = " ".join(parts[1:])

    first_fmt = " ".join(_smart_title_token(p) for p in first.split(" ") if p)
    last_fmt = " ".join(_smart_title_token(p) for p in last.split(" ") if p)
    return _clean_spaces(f"{first_fmt} {last_fmt}")


def _looks_allcaps_word(w: str) -> bool:
    w = _clean_spaces(w)
    if not w:
        return False
    # ALLCAPS dla liter (zostawiamy diakrytyki); ignorujemy myślniki
    letters = re.sub(r"[^A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]", "", w)
    return bool(letters) and letters == letters.upper()


def _normalize_partner_name(raw: str) -> str:
    """
    Partner w ZPRP często jest w formacie "NAZWISKO Imię".
    - jeśli pierwszy token wygląda na ALLCAPS => zamień na "Imię Nazwisko"
    - inaczej tylko skapitalizuj tokeny w oryginalnej kolejności
    """
    s = _clean_spaces(_RE_PARENS.sub(" ", raw or ""))
    if not s:
        return ""

    parts = [p for p in s.split(" ") if p]
    if not parts:
        return ""

    if _looks_allcaps_word(parts[0]):
        return _format_name_last_first_to_first_last(s)

    # zostaw kolejność, ale uładź wielkość liter
    return _clean_spaces(" ".join(_smart_title_token(p) for p in parts))


def _parse_name_and_phone(td) -> Tuple[str, str]:
    """
    Kolumna zawiera:
      NAZWISKO Imię (NazwiskoRodowe)
      (DrugieImię)
      ... telefon ...
    Chcemy: "Imię Nazwisko", bez nawiasów.
    """
    if not td:
        return "", ""

    raw_lines: List[str] = []
    for chunk in td.decode_contents().split("<br"):
        txt = _clean_spaces(BeautifulSoup(chunk, "html.parser").get_text(" ", strip=True))
        if txt:
            raw_lines.append(txt)

    first_line = raw_lines[0] if raw_lines else _clean_spaces(td.get_text(" ", strip=True))

    first_line_no_parens = _clean_spaces(_RE_PARENS.sub(" ", first_line))
    name = _format_name_last_first_to_first_last(first_line_no_parens)

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
    """
    Kolumna ma np.:
      "Sędzia<br>Para z : KASZNIA Wojciech<br><br>Stolikowy"
    albo:
      "Delegat<br>Stolikowy"
    albo:
      "<br>Stolikowy"
    """
    if not td:
        return "", [], "", []

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
            partner = _normalize_partner_name(m.group(1))
            continue

        if re.search(r"\bSędzia\b", p, re.I):
            add_role("sedzia", "Sędzia")
        if re.search(r"\bDelegat\b", p, re.I):
            add_role("delegat", "Delegat")
        if re.search(r"\bStolikowy\b", p, re.I):
            add_role("stolikowy", "Stolikowy")

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


def _pick_roles_td(tds: List[Any]) -> Any:
    """
    Na tej stronie role są w tds[6], ale robimy to odporne:
    wybieramy komórkę, która zawiera Sędzia/Delegat/Stolikowy albo "Para z :".
    """
    if not tds:
        return None

    # Najpierw szybki strzał: standardowy układ z tej strony.
    if len(tds) > 6:
        txt6 = _clean_spaces(tds[6].get_text(" ", strip=True))
        if re.search(r"\b(Sędzia|Delegat|Stolikowy)\b", txt6, re.I) or _RE_PARA_Z.search(txt6):
            return tds[6]

    # Fallback: przeszukaj wszystkie td
    for td in tds:
        txt = _clean_spaces(td.get_text(" ", strip=True))
        if not txt:
            continue
        if re.search(r"\b(Sędzia|Delegat|Stolikowy)\b", txt, re.I) or _RE_PARA_Z.search(txt):
            return td

    return None


def _parse_officials_page(html: str, *, current_offset: int = 0) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    table = _find_table(soup)
    if not table:
        raise HTTPException(500, "Nie znaleziono tabeli sędziów (id='tabelka').")

    count, max_offset = _extract_paging_state(table)
    base_qs = _extract_base_qs_from_paging_form(table)

    all_trs = table.find_all("tr")
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
        tds = tr.find_all("td")

        nr = _clean_spaces(tds[0].get("title", ""))  # NrSedzia
        lp = _safe_int(_clean_spaces(tds[0].get_text(" ", strip=True)), default=0)

        photo = _parse_photo_src(tds[1])
        name, phone = _parse_name_and_phone(tds[2])
        city = _parse_city(tds[3])

        roles_td = _pick_roles_td(tds)
        roles_text, roles, partner, roles_raw_lines = _parse_roles_and_partner(roles_td)

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
        "base_qs": base_qs,
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

        base_qs0 = parsed0.get("base_qs") or {}
        base_qs: Dict[str, str] = dict(base_qs0)

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


# ============================
# OFFICIAL EDIT: READ + SAVE
# (wklej na sam koniec officials.py)
# ============================

from pydantic import BaseModel, Field
from typing import Optional, Union


def _ensure_index_php_prefix(path: str) -> str:
    """
    ZPRP często zwraca href jako:
      - "?a=sedzia&b=edycja&NrSedzia=5124"
      - "index.php?a=sedzia&b=edycja&NrSedzia=5124"
      - "/index.php?a=sedzia&b=edycja&NrSedzia=5124"
    Tu normalizujemy do ścieżki względnej z wiodącym "/" i z /index.php gdy zaczyna się od '?'.
    """
    p = (path or "").strip()
    if not p:
        return ""

    p = _absorb_href_keep_relative(p)

    if p.startswith("?"):
        return "/index.php" + p
    if p.startswith("index.php"):
        return "/" + p
    if p.startswith("/index.php"):
        return p
    if p.startswith("/"):
        return p

    # fallback
    return "/" + p

def _form_urlencoded_bytes(data: Dict[str, str], *, charset: str = "iso-8859-2") -> bytes:
    """
    Buduje body application/x-www-form-urlencoded z kontrolą charsetu.
    ZPRP działa na iso-8859-2, więc MUSIMY wysłać bajty w tym kodowaniu.
    """
    # urlencode zwraca str z %XX, które są ASCII – bezpiecznie kodujemy do ASCII
    qs = urlencode(data, doseq=True, encoding=charset, errors="strict")
    return qs.encode("ascii")


def _build_edit_path_from_nr(nr_sedzia: Union[str, int]) -> str:
    nr = _clean_spaces(str(nr_sedzia))
    return f"/index.php?a=sedzia&b=edycja&NrSedzia={nr}"


def _parse_select(td_or_select, *, include_options: bool) -> Dict[str, Any]:
    """
    Zwraca:
      {
        "selected": {"value": "...", "label": "..."} | None,
        "options": [{"value": "...", "label": "...", "selected": bool}, ...]  # opcjonalnie
      }
    """
    sel = td_or_select
    if td_or_select and getattr(td_or_select, "name", None) != "select":
        sel = td_or_select.find("select")
    if not sel:
        return {"selected": None, "options": [] if include_options else None}

    selected_val = None
    selected_label = None
    opts_payload = [] if include_options else None

    for opt in sel.find_all("option"):
        val = _clean_spaces(opt.get("value", ""))
        lab = _clean_spaces(opt.get_text(" ", strip=True))

        # --- FIX: usuń placeholder typu "Wybierz województwo" / "Wybierz ..." ---
        if val == "" or re.search(r"^\s*Wybierz\b", lab, re.I):
            continue

        is_sel = bool(opt.has_attr("selected"))
        if is_sel and selected_val is None:
            selected_val = val
            selected_label = lab
        if include_options:
            opts_payload.append({"value": val, "label": lab, "selected": is_sel})

    # czasem selected nie jest oznaczony, ale wartość jest ustawiona JS-em; tu nie mamy tego,
    # więc zostawiamy None jeśli brak selected.

    return {
        "selected": ({"value": selected_val, "label": selected_label} if selected_val is not None else None),
        "options": opts_payload,
    }


def _parse_official_edit_page(html: str, *, include_select_options: bool = False) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    # formularz edycji - w przykładzie: <form method='POST' name='edycja' action='?a=sedzia&b=edycja&NrSedzia=...'>
    form = soup.find("form", attrs={"name": "edycja"})
    if not form:
        # fallback: pierwszy form z action zawierającym a=sedzia i b=edycja
        for f in soup.find_all("form"):
            act = _clean_spaces(f.get("action", ""))
            if "a=sedzia" in act and "b=edycja" in act:
                form = f
                break

    if not form:
        raise HTTPException(500, "Nie znaleziono formularza edycji sędziego (form name='edycja').")

    method = _clean_spaces(form.get("method", "GET")).upper() or "POST"
    action_raw = _clean_spaces(form.get("action", ""))
    action = _ensure_index_php_prefix(action_raw) if action_raw else ""

    # NrSedzia - zwykle hidden w formie + w query string
    nr_from_hidden = ""
    nr_inp = form.find("input", attrs={"name": "NrSedzia"})
    if nr_inp:
        nr_from_hidden = _clean_spaces(nr_inp.get("value", ""))

    nr_from_qs = ""
    if action:
        try:
            u = urlparse("http://x" + action if action.startswith("/") else "http://x/" + action)
            qs = parse_qs(u.query)
            nr_from_qs = _clean_spaces((qs.get("NrSedzia", [""]) or [""])[0])
        except Exception:
            nr_from_qs = ""

    nr_sedzia = nr_from_hidden or nr_from_qs

    # foto (pierwsze sensowne img w sekcji "Foto :" - w przykładzie <img ... src="foto_sedzia/5124.jpg?...">)
    photo_src = ""
    try:
        # heurystyka: pierwsze img z "foto_sedzia/"
        img = soup.find("img", src=re.compile(r"\bfoto_sedzia\/", re.I))
        if img:
            photo_src = _absorb_href_keep_relative(_clean_spaces(img.get("src", "")))
    except Exception:
        photo_src = ""

    # --- inputs ---
    fields_text: Dict[str, str] = {}
    fields_hidden: Dict[str, str] = {}
    fields_radio: Dict[str, str] = {}
    fields_checkbox: Dict[str, bool] = {}
    fields_submit: List[Dict[str, str]] = []

    for inp in form.find_all("input", attrs={"name": True}):
        name = _clean_spaces(inp.get("name", ""))
        if not name:
            continue
        itype = _clean_spaces(inp.get("type", "text")).lower()
        val = _clean_spaces(inp.get("value", ""))

        if itype in ("hidden",):
            fields_hidden[name] = val
        elif itype in ("text", "email", "number", "tel", "date"):
            fields_text[name] = val
        elif itype == "radio":
            if inp.has_attr("checked"):
                fields_radio[name] = val
        elif itype == "checkbox":
            # checkbox wysyła się tylko gdy zaznaczony
            fields_checkbox[name] = bool(inp.has_attr("checked"))
        elif itype in ("submit", "button"):
            # ZAPISZ: <input class="przycisk3" name="akcja" type="submit" value="ZAPISZ" />
            fields_submit.append({"name": name, "value": val})
        else:
            # inne typy też trzymajmy jako "text-like"
            if val:
                fields_text[name] = val

    # --- textarea (na wypadek innych pól) ---
    fields_textarea: Dict[str, str] = {}
    for ta in form.find_all("textarea", attrs={"name": True}):
        name = _clean_spaces(ta.get("name", ""))
        if not name:
            continue
        fields_textarea[name] = _clean_spaces(ta.get_text("", strip=True))

    # --- select ---
    selects: Dict[str, Any] = {}
    for sel in form.find_all("select", attrs={"name": True}):
        sname = _clean_spaces(sel.get("name", ""))
        if not sname:
            continue
        parsed = _parse_select(sel, include_options=include_select_options)
        selects[sname] = parsed

    # wyciągnij definicję przycisku "ZAPISZ" (preferuj value=ZAPISZ, inaczej pierwszy submit)
    save_submit = None
    for s in fields_submit:
        if _clean_spaces(s.get("value", "")).upper() == "ZAPISZ":
            save_submit = s
            break
    if not save_submit and fields_submit:
        save_submit = fields_submit[0]

    # dodatkowo: czy jest "ANULUJ" jako link (żeby UI mógł pokazać)
    cancel_href = ""
    try:
        a_cancel = soup.find("a", string=re.compile(r"^\s*ANULUJ\s*$", re.I))
        if a_cancel and a_cancel.get("href"):
            cancel_href = _ensure_index_php_prefix(_clean_spaces(a_cancel.get("href", "")))
    except Exception:
        cancel_href = ""

    return {
        "NrSedzia": nr_sedzia,
        "photo_src": photo_src,
        "form": {
            "method": method,
            "action": action,
            "save_submit": save_submit,  # np. {"name":"akcja","value":"ZAPISZ"}
            "cancel_href": cancel_href,
        },
        "values": {
            "text": fields_text,
            "hidden": fields_hidden,
            "radio": fields_radio,
            "checkbox": fields_checkbox,
            "textarea": fields_textarea,
            "select": selects,
        },
    }


def _build_post_data_for_save(
    parsed_form: Dict[str, Any],
    patch: Dict[str, Any],
) -> Dict[str, str]:
    """
    Buduje finalny payload POST do ZPRP:
      - bierze wszystkie aktualne wartości z formularza
      - nadpisuje polami z patch
      - checkboxy: True => wysyłamy "1" (albo wartość z HTML jeśli była); False => NIE wysyłamy
      - radio/select: wysyłamy value
      - zawsze dokleja save_submit (np. akcja=ZAPISZ) jeśli jest
    """
    values = (parsed_form or {}).get("values") or {}
    text = dict(values.get("text") or {})
    hidden = dict(values.get("hidden") or {})
    radio = dict(values.get("radio") or {})
    checkbox = dict(values.get("checkbox") or {})
    textarea = dict(values.get("textarea") or {})
    select = dict(values.get("select") or {})

    # patch: pozwalamy podać:
    # - wartości pól tekstowych/hidden/radio/textarea jako string
    # - checkbox jako bool
    # - select jako {"value": "..."} lub bezpośrednio string
    # - dowolny klucz, który pasuje do name=... w form
    patch = patch or {}

    # 1) nadpisz proste stringi (text/hidden/textarea/radio)
    for k, v in patch.items():
        if v is None:
            continue
        if isinstance(v, bool):
            # checkbox
            checkbox[k] = v
            continue

        # select w formie {"value": "..."}
        if isinstance(v, dict) and "value" in v:
            val = _clean_spaces(str(v.get("value", "")))
            if val:
                # select
                if k in select:
                    select[k] = {"selected": {"value": val, "label": None}, "options": None}
                else:
                    # jeśli nie rozpoznaliśmy jako select, potraktuj jak text
                    text[k] = val
            continue

        # zwykły string/number
        sval = _clean_spaces(str(v))
        if k in text:
            text[k] = sval
        elif k in hidden:
            hidden[k] = sval
        elif k in textarea:
            textarea[k] = sval
        elif k in radio:
            radio[k] = sval
        elif k in select:
            select[k] = {"selected": {"value": sval, "label": None}, "options": None}
        else:
            # nieznane pole - dodaj jako text (ZPRP raczej zignoruje, ale to bezpieczne)
            text[k] = sval

    # 2) złóż dane
    data: Dict[str, str] = {}

    # hidden + text + textarea
    for src in (hidden, text, textarea):
        for k, v in src.items():
            k = _clean_spaces(k)
            if not k:
                continue
            data[k] = _clean_spaces(str(v))

    # radio (tylko zaznaczone)
    for k, v in radio.items():
        k = _clean_spaces(k)
        if not k:
            continue
        data[k] = _clean_spaces(str(v))

    # select (selected.value)
    for k, obj in select.items():
        k = _clean_spaces(k)
        if not k:
            continue
        selected = (obj or {}).get("selected") if isinstance(obj, dict) else None
        if isinstance(obj, str):
            data[k] = _clean_spaces(obj)
        elif isinstance(selected, dict):
            vv = _clean_spaces(str(selected.get("value", "")))
            if vv != "":
                data[k] = vv

    # checkbox (wysyłamy tylko gdy True)
    # w HTML zwykle value="1" - my wysyłamy "1"
    for k, is_on in checkbox.items():
        k = _clean_spaces(k)
        if not k:
            continue
        if bool(is_on):
            data[k] = "1"

    # 3) submit save (akcja=ZAPISZ)
    save_submit = ((parsed_form or {}).get("form") or {}).get("save_submit") or None
    if isinstance(save_submit, dict):
        sn = _clean_spaces(save_submit.get("name", ""))
        sv = _clean_spaces(save_submit.get("value", ""))
        if sn and sv:
            data[sn] = sv

    # 4) upewnij się, że NrSedzia istnieje
    nr = _clean_spaces((parsed_form or {}).get("NrSedzia", "")) or _clean_spaces(data.get("NrSedzia", ""))
    if nr:
        data["NrSedzia"] = nr

    return data


class ZprpOfficialEditReadRequest(BaseModel):
    username: str
    password: str
    # jedno z poniższych:
    edit_href: Optional[str] = Field(default=None, description="Link do edycji (z listy), np. '?a=sedzia&b=edycja&NrSedzia=5124'")
    NrSedzia: Optional[Union[str, int]] = Field(default=None, description="Numer sędziego jeśli nie masz edit_href")
    include_select_options: bool = Field(default=False, description="Jeśli True, zwraca pełne listy option dla selectów (UWAGA: może być bardzo duże).")


class ZprpOfficialEditSaveRequest(BaseModel):
    username: str
    password: str
    # jedno z poniższych:
    edit_href: Optional[str] = None
    NrSedzia: Optional[Union[str, int]] = None
    # pola do nadpisania (może być tylko telefon itp.)
    patch: Dict[str, Any] = Field(default_factory=dict)


@router.post("/zprp/sedziowie/edit/read")
async def read_official_edit_page(
    payload: ZprpOfficialEditReadRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    # ustal URL edycji
    edit_path = ""
    if payload.edit_href:
        edit_path = _ensure_index_php_prefix(payload.edit_href)
    elif payload.NrSedzia is not None:
        edit_path = _build_edit_path_from_nr(payload.NrSedzia)
    else:
        raise HTTPException(400, "Brak edit_href i NrSedzia.")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)
        logger.info("ZPRP official edit(read): login ok base_url=%s", settings.ZPRP_BASE_URL)

        _, html = await fetch_with_correct_encoding(client, edit_path, method="GET", cookies=cookies)
        _log_html_fingerprint("Official edit page fetched", html)

        parsed = _parse_official_edit_page(html, include_select_options=bool(payload.include_select_options))

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "edit_path": edit_path,
            "official": parsed,
            "save_action": {
                "method": parsed.get("form", {}).get("method", ""),
                "action": parsed.get("form", {}).get("action", ""),
                "submit": parsed.get("form", {}).get("save_submit", None),
            },
        }


@router.post("/zprp/sedziowie/edit/save")
async def save_official_edit_page(
    payload: ZprpOfficialEditSaveRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    # ustal URL edycji (żeby pobrać aktualne wartości i action)
    edit_path = ""
    if payload.edit_href:
        edit_path = _ensure_index_php_prefix(payload.edit_href)
    elif payload.NrSedzia is not None:
        edit_path = _build_edit_path_from_nr(payload.NrSedzia)
    else:
        raise HTTPException(400, "Brak edit_href i NrSedzia.")

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)
        logger.info("ZPRP official edit(save): login ok base_url=%s", settings.ZPRP_BASE_URL)

        # 1) pobierz formularz, żeby mieć komplet pól i action
        _, html_before = await fetch_with_correct_encoding(client, edit_path, method="GET", cookies=cookies)
        _log_html_fingerprint("Official edit page(before save) fetched", html_before)

        parsed_before = _parse_official_edit_page(html_before, include_select_options=False)

        # 2) zbuduj POST data: komplet + patch
        post_data = _build_post_data_for_save(parsed_before, payload.patch or {})

        # 3) target action
        form = parsed_before.get("form") or {}
        action = _ensure_index_php_prefix(form.get("action", "")) if form.get("action") else edit_path
        method = _clean_spaces(form.get("method", "POST")).upper() or "POST"
        if method != "POST":
            # na ZPRP realnie jest POST, ale jakby kiedyś dali GET to i tak wymuszamy POST
            method = "POST"

        logger.info(
            "ZPRP official edit(save): submitting method=%s action='%s' NrSedzia=%s patch_keys=%s",
            method,
            action,
            parsed_before.get("NrSedzia", ""),
            sorted(list((payload.patch or {}).keys()))[:50],
        )

        # 4) wykonaj zapis
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2"}
        body = _form_urlencoded_bytes(post_data, charset="iso-8859-2")

        resp = await client.post(
            action,
            content=body,
            headers=headers,
            cookies=cookies,
        )

        # Teraz zdecyduj jak dekodujesz odpowiedź:
        # - jeżeli fetch_with_correct_encoding robi Ci też wykrycie charsetu i poprawne .text,
        #   to możesz go rozszerzyć o obsługę `content=...` zamiast `data=...`.
        # - minimalnie:
        html_after = resp.content.decode("iso-8859-2", errors="replace")

        _log_html_fingerprint("Official edit page(after save) fetched", html_after)

        # 5) spróbuj wyciągnąć komunikat (w przykładzie <div id="info_edit"...>)
        soup_after = BeautifulSoup(html_after, "html.parser")
        info_msg = ""
        try:
            div_info = soup_after.find(id="info_edit")
            if div_info:
                info_msg = _clean_spaces(div_info.get_text(" ", strip=True))
        except Exception:
            info_msg = ""

        # 6) zwróć też odświeżone wartości (żebyś mógł porównać / potwierdzić zapis)
        parsed_after = None
        try:
            parsed_after = _parse_official_edit_page(html_after, include_select_options=False)
        except Exception:
            parsed_after = None

        return {
            "saved_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "edit_path": edit_path,
            "submit": {
                "method": method,
                "action": action,
                "sent_fields_count": len(post_data),
                "sent_keys_sample": sorted(list(post_data.keys()))[:40],
            },
            "result": {
                "info_edit": info_msg,
                "parsed_after": parsed_after,
            },
        }
