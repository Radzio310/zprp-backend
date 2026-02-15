# app/zprp/officials.py
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
    - name: z pierwszej linii (najczęściej "NAZWISKO  Imię", czasem z nawiasem jak "BREHMER Joanna (KACZOROWSKA)")
    - phone: po ikonie telefonu (pliki/telefon.png) zwykle tekst z numerem
    """
    if not td:
        return "", ""

    # name: bierzemy pierwszy sensowny fragment tekstu do pierwszego <br>
    # (bo potem są nazwisko rodowe / drugie imię / telefon)
    # BeautifulSoup: możemy wyciągnąć "stripped_strings" i wziąć pierwszy
    strings = [s for s in (td.stripped_strings or [])]
    name = _clean_spaces(strings[0]) if strings else ""

    # phone: po img telefon.png (lub tekst zawierający 9-11 cyfr)
    phone = ""
    tel_img = td.find("img", src=re.compile(r"telefon\.png", re.I))
    if tel_img:
        # Weź tekst po img w obrębie rodzica, często jest " 696575338"
        parent = tel_img.parent
        if parent:
            tail = parent.get_text(" ", strip=True)
            # tail zawiera czasem też nazwę; filtrujemy do cyfr
            m = re.search(r"(\+?\d[\d\s-]{6,})", tail)
            if m:
                phone = _clean_spaces(m.group(1))
    if not phone:
        # fallback: szukaj ciągu cyfr w całej komórce
        txt = _clean_spaces(td.get_text(" ", strip=True))
        m = re.search(r"(\+?\d[\d\s-]{6,})", txt)
        if m:
            phone = _clean_spaces(m.group(1))

    return name, phone


def _parse_city(td) -> str:
    if not td:
        return ""
    # zwykle <div align="center">Ruda Śląska  (SL)</div>
    txt = _clean_spaces(td.get_text(" ", strip=True))
    return _strip_city(txt)


def _parse_roles_and_partner(td) -> Tuple[str, List[str], str]:
    """
    Kolumna: "Sędzia / Delegat Stolikowy" zawiera <br>.
    Chcemy:
    - roles_text: role w nowych liniach (tylko: sędzia, stolikowy, delegat) w kolejności jak na stronie
    - roles_list: lista ról (canonical: sedzia|stolikowy|delegat)
    - partner: jeśli występuje "Para z : X" -> X
    """
    if not td:
        return "", [], ""

    # rozbij po <br> zachowując kolejność
    parts = []
    for chunk in td.decode_contents().split("<br"):
        # chunk może mieć ">" + tekst albo HTML
        # najprościej: zrób soup z chunk i wyciągnij tekst
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
        # partner?
        m = _RE_PARA_Z.search(p)
        if m and not partner:
            partner = _clean_spaces(m.group(1))
            continue

        # rola?
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
    return roles_text, roles, partner


def _parse_actions_links(tds: List[Any]) -> Tuple[str, str, str]:
    """
    Z wiersza:
    - edycja: link z przycisku EDYTUJ
    - matches: link z "POKAŻ MECZE"
    - offtime: link z "POKAŻ OFFTIME"
    """
    edit_href = ""
    matches_href = ""
    offtime_href = ""

    # w HTML: edycja jest w osobnej kolumnie, a pozostałe dwa w kolejnej
    for td in tds:
        for a in td.find_all("a", href=True):
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


def _extract_paging_state(table: Any) -> Tuple[int, int, int]:
    """
    Z paska paginacji bierzemy:
    - count (np. 10/20/50/100) z <select name="count"> wybranej opcji
    - current_offset (zwykle brak w aktualnej stronie -> 0)
    - max_offset (największy offset z linków STRONA, np. 6 dla strony 7 przy count=10)
    """
    if not table:
        return 10, 0, 0

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
            if off > max_offset:
                max_offset = off
        except Exception:
            continue

    # current_offset: na tej stronie zwykle nie ma jawnego offset w URL (bo to już jest HTML),
    # ale endpoint ma go w path. My będziemy go znać w pętli i przekazywać wyżej.
    return count, 0, max_offset


def _parse_officials_page(html: str, *, current_offset: int = 0) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    table = _find_table(soup)
    if not table:
        raise HTTPException(500, "Nie znaleziono tabeli sędziów (id='tabelka').")

    count, _, max_offset = _extract_paging_state(table)

    officials: Dict[str, Dict[str, Any]] = {}

    for tr in table.find_all("tr", recursive=False):
        if not _row_is_data_tr(tr):
            continue

        tds = tr.find_all("td", recursive=False)
        nr = _clean_spaces(tds[0].get("title", ""))  # NrSedzia
        lp = _safe_int(_clean_spaces(tds[0].get_text(" ", strip=True)), default=0)

        photo = _parse_photo_src(tds[1])
        name, phone = _parse_name_and_phone(tds[2])
        city = _parse_city(tds[3])

        roles_text, roles, partner = _parse_roles_and_partner(tds[7])

        edit_href, matches_href, offtime_href = _parse_actions_links(tds)

        officials[nr] = {
            "NrSedzia": nr,
            "Lp": lp,
            "name": name,
            "photo_href": photo,
            "phone": phone,
            "city": city,
            "roles_text": roles_text,   # role w nowych liniach
            "roles": roles,             # ["sedzia","stolikowy","delegat"]
            "partner": partner,         # np. "SOLECKI Michał"
            "edit_href": edit_href,
            "matches_href": matches_href,
            "offtime_href": offtime_href,
        }

    return {
        "paging": {
            "count": count,
            "offset": current_offset,
            "max_offset": max_offset,
        },
        "officials": officials,
    }


def _merge_officials(dst: Dict[str, Dict[str, Any]], src: Dict[str, Dict[str, Any]]) -> None:
    for k, v in (src or {}).items():
        dst[k] = v


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

        # home po zalogowaniu (żeby pobrać menu link z parametrami)
        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)

        # link do zakładki
        sedzia_href = _extract_menu_href_from_page(
            html_home,
            label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
            href_regex=r"\ba=sedzia\b",
        )

        # pierwsza strona
        _, html0 = await fetch_with_correct_encoding(client, sedzia_href, method="GET", cookies=cookies)
        parsed0 = _parse_officials_page(html0, current_offset=0)

        all_officials: Dict[str, Dict[str, Any]] = {}
        _merge_officials(all_officials, parsed0["officials"])

        paging0 = parsed0["paging"]
        count = int(paging0.get("count", 10))
        max_offset = int(paging0.get("max_offset", 0))

        # bazowe parametry do kolejnych stron: bierzemy z sedzia_href (np. Filtr_archiwum, Filtr_woj2, count)
        try:
            u0 = urlparse(
                sedzia_href if sedzia_href.startswith("http")
                else ("http://x" + sedzia_href if sedzia_href.startswith("?") else "http://x/" + sedzia_href)
            )
            base_qs = parse_qs(u0.query)
        except Exception:
            base_qs = {}

        # normalizujemy bazowe: zawsze a=sedzia
        # (parse_qs daje listy)
        base_qs["a"] = ["sedzia"]
        # count: trzymaj spójnie z tym co zwróciła strona
        base_qs["count"] = [str(count)]
        # offset będziemy nadpisywać

        # iteruj po kolejnych stronach
        for offset in range(1, max_offset + 1):
            qs = {k: (v[:] if isinstance(v, list) else [str(v)]) for k, v in base_qs.items()}
            qs["offset"] = [str(offset)]
            path = "/index.php?" + urlencode(qs, doseq=True)

            _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
            parsed = _parse_officials_page(html, current_offset=offset)
            _merge_officials(all_officials, parsed["officials"])

            logger.info("ZPRP sedzia: fetched offset=%s count=%s officials_total=%s", offset, count, len(all_officials))

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

        _, html_home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)

        sedzia_href = _extract_menu_href_from_page(
            html_home,
            label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
            href_regex=r"\ba=sedzia\b",
        )

        _, html0 = await fetch_with_correct_encoding(client, sedzia_href, method="GET", cookies=cookies)
        parsed0 = _parse_officials_page(html0, current_offset=0)

        officials = parsed0["officials"]
        paging0 = parsed0["paging"]

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "entry_href": sedzia_href,
            "paging": paging0,
            "officials": officials,
            "summary": {
                "officials_total": len(officials),
            },
        }
