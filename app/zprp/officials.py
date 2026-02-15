# app/zprp/officials.py
from __future__ import annotations

import base64
import datetime
import logging
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

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
_RE_CITY_PAREN = re.compile(r"^(.*?)(\s*\([A-Z]{1,3}\)\s*)?$")  # "Ruda Śląska (SL)" -> "Ruda Śląska"
_RE_PHONE = re.compile(r"(\+?\d[\d\s-]{6,}\d)")
_RE_WS = re.compile(r"\s+")
_RE_PAGER_NUM = re.compile(r"^\s*(\d+)\s*$")


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _clean_spaces(s: str) -> str:
    return _RE_WS.sub(" ", s or "").strip()


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
    Zwraca relatywny path+query (bez hosta).
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


def _normalize_city(city: str) -> str:
    s = _clean_spaces(city)
    m = _RE_CITY_PAREN.match(s)
    if not m:
        return s
    return _clean_spaces(m.group(1) or "")


def _extract_sedzia_link_from_home(html: str) -> str:
    """
    Z głównej strony po zalogowaniu bierzemy link do zakładki "Sędziowie i Delegaci".
    """
    soup = BeautifulSoup(html, "html.parser")
    a = soup.find("a", string=re.compile(r"^\s*Sędziowie i Delegaci\s*$", re.I))
    if not a:
        a = soup.find("a", href=re.compile(r"\ba=sedzia\b", re.I))
    href = _absorb_href_keep_relative(a.get("href", "") if a else "")
    if not href:
        raise HTTPException(500, "Nie znaleziono linku do zakładki 'Sędziowie i Delegaci' na stronie głównej.")
    return href


def _text_lines_from_cell(td) -> List[str]:
    """
    Zwraca “linie” z komórki: respektuje <br>, <hr>, nowe linie.
    """
    if not td:
        return []
    # zamień br/hr na newline
    for br in td.find_all(["br"]):
        br.replace_with("\n")
    for hr in td.find_all(["hr"]):
        hr.replace_with("\n")
    txt = td.get_text("\n", strip=True)
    lines = [_clean_spaces(x) for x in txt.split("\n")]
    return [x for x in lines if x]


def _extract_partner_and_roles(lines: List[str]) -> Tuple[str, List[str]]:
    """
    roles: linie typu "sędzia", "stolikowy", "delegat" itd.
    partner: jeśli występuje "Para z:" (różne warianty).
    """
    partner = ""
    roles: List[str] = []

    for ln in lines:
        # partner
        m = re.search(r"\bPara\s*z\s*:\s*(.+)\s*$", ln, flags=re.I)
        if m:
            partner = _clean_spaces(m.group(1) or "")
            continue

        # typowe separatory / technikalia
        if not ln or ln in ("-", "—", "–"):
            continue

        roles.append(ln)

    # oczyszczenie: często w roli potrafi być "Para z: ..." wklejone obok
    roles = [r for r in roles if not re.search(r"\bPara\s*z\s*:", r, flags=re.I)]
    return partner, roles


def _extract_phone_from_cell(td) -> str:
    if not td:
        return ""
    txt = _clean_spaces(td.get_text(" ", strip=True))
    m = _RE_PHONE.search(txt)
    return _clean_spaces(m.group(1)) if m else txt


def _find_officials_table(soup: BeautifulSoup):
    """
    Heurystyka: tabela, w której występują przyciski/linki typu:
      - "Edytuj"
      - "Pokaż mecze"
      - "Pokaż offtime"
    """
    if not soup:
        return None

    candidates = []
    for tbl in soup.find_all("table"):
        # szybkie odrzucenie: zbyt mało wierszy
        trs = tbl.find_all("tr")
        if len(trs) < 3:
            continue

        text = _clean_spaces(tbl.get_text(" ", strip=True))
        score = 0
        if re.search(r"\bEdytuj\b", text, re.I):
            score += 2
        if re.search(r"\bPokaż\s+mecze\b", text, re.I):
            score += 2
        if re.search(r"\bPokaż\s+offtime\b", text, re.I):
            score += 2
        if re.search(r"\btelefon\b", text, re.I):
            score += 1
        if re.search(r"\bmiasto\b", text, re.I):
            score += 1

        if score >= 3:
            candidates.append((score, len(trs), tbl))

    if not candidates:
        return None

    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return candidates[0][2]


def _row_is_data_row(tr) -> bool:
    """
    Odrzuć nagłówki. Zakładamy, że wiersz danych ma przynajmniej jeden przycisk/link akcji.
    """
    if not tr:
        return False
    tds = tr.find_all("td", recursive=False)
    if len(tds) < 4:
        return False

    # header często ma <th> albo krótkie etykiety
    if tr.find_all("th"):
        return False

    txt = _clean_spaces(tr.get_text(" ", strip=True))
    if not txt:
        return False

    has_action = bool(tr.find("a", string=re.compile(r"\bEdytuj\b|\bPokaż\s+mecze\b|\bPokaż\s+offtime\b", re.I)))
    return has_action


def _extract_action_links(tr) -> Dict[str, str]:
    """
    Z wiersza bierze linki do:
      - edit
      - matches
      - offtime
    """
    out = {"edit_href": "", "matches_href": "", "offtime_href": ""}

    for a in tr.find_all("a", href=True):
        label = _clean_spaces(a.get_text(" ", strip=True))
        href = _absorb_href_keep_relative(a.get("href", ""))

        if not href:
            continue

        if re.search(r"\bEdytuj\b", label, re.I):
            out["edit_href"] = href
        elif re.search(r"\bPokaż\s+mecze\b", label, re.I):
            out["matches_href"] = href
        elif re.search(r"\bPokaż\s+offtime\b", label, re.I):
            out["offtime_href"] = href

    return out


def _extract_photo_href(tr) -> str:
    """
    Link do zdjęcia: zwykle <img src="..."> w komórce (czasem w <a>).
    """
    img = tr.find("img", src=True)
    if not img:
        return ""
    src = _absorb_href_keep_relative(img.get("src", ""))
    return src


def _parse_officials_page(html: str) -> Dict[str, Any]:
    """
    Parsuje jedną stronę listy sędziów/delegatów.
    Zwraca:
      - items: lista rekordów
      - pager: dane do paginacji (na podstawie linków)
    """
    soup = BeautifulSoup(html, "html.parser")
    tbl = _find_officials_table(soup)
    if not tbl:
        # nie wywalamy 500 od razu, bo pierwsza strona "menu" sedzia może nie mieć tabeli
        return {"items": [], "pager": {"pages": [], "page_param": "", "max_page": 0}}

    items: List[Dict[str, Any]] = []

    for tr in tbl.find_all("tr", recursive=False):
        if not _row_is_data_row(tr):
            continue

        tds = tr.find_all("td", recursive=False)

        # Heurystyka mapowania kolumn:
        # Ponieważ layout może się różnić między województwami/wersjami,
        # robimy mapowanie “po treści”:
        # - name: najdłuższy tekst przypominający imię i nazwisko (bez etykiet przycisków)
        # - phone: komórka z numerem
        # - city: komórka z "(XX)" albo z nazwą miasta
        # - roles: komórka z wieloma liniami, często zawiera "sędzia" / "delegat" / "stolikowy" / "Para z:"
        name = ""
        phone = ""
        city = ""
        partner = ""
        roles: List[str] = []

        # candidate strings per cell
        cell_lines = [_text_lines_from_cell(td) for td in tds]
        cell_texts = [_clean_spaces(" ".join(lines)) for lines in cell_lines]

        # usuń typowe etykiety przycisków
        def _without_action_words(s: str) -> str:
            s2 = re.sub(r"\b(Edytuj|Pokaż\s+mecze|Pokaż\s+offtime)\b", "", s, flags=re.I)
            return _clean_spaces(s2)

        cleaned_texts = [_without_action_words(t) for t in cell_texts]

        # name: komórka o największej “literowej” zawartości
        best_i = -1
        best_score = -1
        for i, t in enumerate(cleaned_texts):
            if not t:
                continue
            # odrzuć czyste cyfry
            if re.fullmatch(r"[\d\.\s]+", t):
                continue
            # scoring: litery + spacje, preferuj 2-4 wyrazy
            words = [w for w in t.split(" ") if w]
            letters = sum(1 for ch in t if ch.isalpha())
            score = letters + (10 if 1 < len(words) <= 5 else 0)
            if score > best_score:
                best_score = score
                best_i = i
        if best_i >= 0:
            name = cleaned_texts[best_i]

        # phone: szukamy regexem
        for i, td in enumerate(tds):
            cand = _extract_phone_from_cell(td)
            if cand and _RE_PHONE.search(cand):
                phone = cand
                break

        # city: komórka zawierająca "(XX)" albo wygląda jak miasto
        for i, t in enumerate(cleaned_texts):
            if not t or t == name:
                continue
            if re.search(r"\([A-Z]{1,3}\)\s*$", t):
                city = _normalize_city(t)
                break
        if not city:
            # fallback: krótka komórka tekstowa bez cyfr, 1-3 słowa
            for i, t in enumerate(cleaned_texts):
                if not t or t == name:
                    continue
                if any(ch.isdigit() for ch in t):
                    continue
                words = t.split(" ")
                if 1 <= len(words) <= 4 and len(t) <= 40:
                    city = _normalize_city(t)
                    break

        # roles + partner: komórka z wieloma liniami lub zawierająca słowa kluczowe
        role_cell_lines: List[str] = []
        for i, lines in enumerate(cell_lines):
            joined = " ".join(lines).lower()
            if (
                "sędz" in joined
                or "sedz" in joined
                or "deleg" in joined
                or "stolik" in joined
                or "para z" in joined
                or len(lines) >= 2
            ):
                # odfiltruj oczywiste: komórki z przyciskami
                if re.search(r"\bEdytuj\b|\bPokaż\s+mecze\b|\bPokaż\s+offtime\b", " ".join(lines), re.I):
                    continue
                # preferuj komórkę nie będącą name/phone/city
                role_cell_lines = lines
                # jeśli bardzo pasuje, przerwij
                if "para z" in joined or "sędz" in joined or "deleg" in joined or "stolik" in joined:
                    break

        partner, roles = _extract_partner_and_roles(role_cell_lines)

        actions = _extract_action_links(tr)
        photo_href = _extract_photo_href(tr)

        # klucz deduplikacji (w razie powtórek między stronami)
        key = _clean_spaces(f"{name}|{phone}|{city}")

        items.append(
            {
                "key": key,
                "name": name,
                "photo_href": photo_href,
                "phone": phone,
                "city": city,
                "roles": roles,         # lista (frontend może join("\n"))
                "partner": partner,     # string
                "edit_href": actions.get("edit_href", ""),
                "matches_href": actions.get("matches_href", ""),
                "offtime_href": actions.get("offtime_href", ""),
            }
        )

    pager = _detect_pagination(soup)
    return {"items": items, "pager": pager}


def _detect_pagination(soup: BeautifulSoup) -> Dict[str, Any]:
    """
    Heurystycznie wykrywa paginację:
    - zbiera wszystkie <a href> z a=sedzia
    - szuka parametru, który ma wiele wartości numerycznych (np. page/strona)
    - wyciąga max_page
    """
    hrefs: List[str] = []
    for a in soup.find_all("a", href=True):
        href = _absorb_href_keep_relative(a.get("href", ""))
        if not href:
            continue
        if re.search(r"\ba=sedzia\b", href, re.I):
            hrefs.append(href)

    if not hrefs:
        return {"pages": [], "page_param": "", "max_page": 0}

    # zbuduj mapę: param -> set(values)
    values_by_param: Dict[str, set] = {}
    for href in hrefs:
        try:
            u = urlparse("http://x" + href if href.startswith("?") else ("http://x/" + href))
            qs = parse_qs(u.query)
            for k, vals in qs.items():
                for v in vals:
                    v2 = _clean_spaces(v)
                    if not v2:
                        continue
                    if v2.isdigit():
                        values_by_param.setdefault(k, set()).add(int(v2))
        except Exception:
            continue

    # wybierz parametr “stronicowania”: ma >=2 różne wartości, min=1 zwykle
    best_param = ""
    best_score = -1
    best_vals: List[int] = []
    preferred = ["strona", "page", "Page", "p", "nr", "start"]

    for k, svals in values_by_param.items():
        vals = sorted(list(svals))
        if len(vals) < 2:
            continue
        score = len(vals)
        if (vals and vals[0] == 1):
            score += 5
        if k in preferred:
            score += 10
        if score > best_score:
            best_score = score
            best_param = k
            best_vals = vals

    if not best_param:
        # fallback: numeryczne linki w pagerze (tekst "1 2 3")
        nums = []
        for a in soup.find_all("a"):
            t = _clean_spaces(a.get_text(" ", strip=True))
            m = _RE_PAGER_NUM.match(t)
            if m:
                nums.append(int(m.group(1)))
        nums = sorted(set(nums))
        return {"pages": nums, "page_param": "", "max_page": (max(nums) if nums else 0)}

    return {"pages": best_vals, "page_param": best_param, "max_page": (max(best_vals) if best_vals else 0)}


def _set_query_param(href: str, key: str, value: str) -> str:
    """
    Ustawia/zmienia query param w relatywnym href (?a=...).
    """
    href = _absorb_href_keep_relative(href)
    if not href:
        return href

    # znormalizuj do URL z hostem
    u = urlparse("http://x" + href if href.startswith("?") else ("http://x/" + href))
    qs = parse_qs(u.query)
    qs[key] = [value]
    query = urlencode(qs, doseq=True)

    # zachowaj relatywną postać: jeśli oryginał był "?...", zwróć "?..."
    path = u.path if u.path else "/index.php"
    rebuilt = urlunparse(("", "", path, "", query, ""))
    if href.startswith("?"):
        return "?" + query
    return path + ("?" + query if query else "")


async def _scrape_all_pages(
    *,
    client: AsyncClient,
    cookies: Dict[str, str],
    entry_href: str,
    max_pages_hard_limit: int = 200,
) -> List[Dict[str, Any]]:
    """
    Przechodzi wszystkie strony listy sędziów/delegatów.
    """
    seen_keys = set()
    out: List[Dict[str, Any]] = []

    # pobierz pierwszą stronę
    _, html0 = await fetch_with_correct_encoding(client, entry_href, method="GET", cookies=cookies)
    parsed0 = _parse_officials_page(html0)
    items0 = parsed0.get("items", []) or []
    pager0 = parsed0.get("pager", {}) or {}

    for it in items0:
        k = _clean_spaces(it.get("key", ""))
        if k and k not in seen_keys:
            seen_keys.add(k)
            out.append(it)

    page_param = _clean_spaces(pager0.get("page_param", ""))
    max_page = int(pager0.get("max_page", 0) or 0)

    # Jeśli wykryliśmy page_param i max_page, idziemy 2..max_page
    if page_param and max_page >= 2:
        max_page = min(max_page, max_pages_hard_limit)
        for p in range(2, max_page + 1):
            href_p = _set_query_param(entry_href, page_param, str(p))
            _, htmlp = await fetch_with_correct_encoding(client, href_p, method="GET", cookies=cookies)
            parsedp = _parse_officials_page(htmlp)
            for it in parsedp.get("items", []) or []:
                k = _clean_spaces(it.get("key", ""))
                if k and k not in seen_keys:
                    seen_keys.add(k)
                    out.append(it)
        return out

    # Fallback: próbuj iść “następna strona” jeśli jest link > / Następna
    current_href = entry_href
    for _ in range(max_pages_hard_limit - 1):
        _, htmlc = await fetch_with_correct_encoding(client, current_href, method="GET", cookies=cookies)
        soupc = BeautifulSoup(htmlc, "html.parser")

        next_href = ""
        for a in soupc.find_all("a", href=True):
            lab = _clean_spaces(a.get_text(" ", strip=True)).lower()
            if lab in (">", ">>", "następna", "nastepna", "dalej"):
                cand = _absorb_href_keep_relative(a.get("href", ""))
                if cand and re.search(r"\ba=sedzia\b", cand, re.I):
                    next_href = cand
                    break
        if not next_href or next_href == current_href:
            break

        current_href = next_href
        _, htmln = await fetch_with_correct_encoding(client, current_href, method="GET", cookies=cookies)
        parsedn = _parse_officials_page(htmln)
        new_any = False
        for it in parsedn.get("items", []) or []:
            k = _clean_spaces(it.get("key", ""))
            if k and k not in seen_keys:
                seen_keys.add(k)
                out.append(it)
                new_any = True
        if not new_any:
            break

    return out


# =========================
# Endpoints
# =========================

@router.post("/zprp/sedziowie/meta")
async def get_officials_meta(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Meta:
    - loguje się
    - wchodzi na /index.php
    - wyciąga link do "Sędziowie i Delegaci"
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
        sedzia_href = _extract_sedzia_link_from_home(html_home)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "sedzia_entry_href": sedzia_href,
        }


@router.post("/zprp/sedziowie/scrape")
async def scrape_officials(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Scrape:
    - logowanie
    - home -> link "Sędziowie i Delegaci"
    - wejście na listę i przejście po stronach (domyślnie 10/strona)
    - zwrot listy rekordów:
        name, photo_href, phone, city, roles[], partner, edit_href, matches_href, offtime_href
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
        sedzia_href = _extract_sedzia_link_from_home(html_home)

        # Ważne: z menu często jest "?a=sedzia&Filtr_archiwum=1" (jak w Twoim przykładzie),
        # więc startujemy dokładnie od tego href.
        items = await _scrape_all_pages(client=client, cookies=cookies, entry_href=sedzia_href)

        # usuń pomocniczy "key"
        for it in items:
            it.pop("key", None)

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "sedzia_entry_href": sedzia_href,
            "count": len(items),
            "officials": items,
        }
