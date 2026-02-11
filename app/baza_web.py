# app/baza_web.py

import re
import html as html_lib
from urllib.parse import urlencode
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from bs4 import BeautifulSoup

from app.deps import get_settings, Settings

# VIP DB (u Ciebie już istnieje)
from datetime import datetime
from sqlalchemy import select
from app.db import database, baza_vips

router = APIRouter(prefix="/baza_web", tags=["BAZA Web"])


# -------------------------
# Models
# -------------------------

class BazaWebLoginRequest(BaseModel):
    username: str
    password: str


class VipSummary(BaseModel):
    created: bool = False
    record: dict | None = None  # surowy rekord (permissions/province itd.)


class BazaWebLoginResponse(BaseModel):
    success: bool
    judge_id: str | None = None
    error: str | None = None

    # NOWE (jak auth.py):
    account_type: str | None = None  # "judge" | "org" | "unknown"
    display_name: str | None = None
    available_tabs: list[str] | None = None

    # NOWE: VIP
    vip: VipSummary | None = None


class BazaWebProfileRequest(BaseModel):
    username: str
    password: str
    judge_id: str | None = None


class JudgeProfile(BaseModel):
    photoUrl: str | None = None
    firstName: str = ""
    middleName: str = ""
    lastName: str = ""
    maidenName: str = ""
    gender: str = ""  # "M" / "K" / ""
    birthDate: str = ""
    street: str = ""
    postalCode: str = ""
    city: str = ""
    voivodeship: str = ""
    voivodeshipCode: str = ""
    phone: str = ""
    email: str = ""


class BazaWebProfileResponse(BaseModel):
    success: bool
    judge_id: str | None = None
    profile: JudgeProfile | None = None
    error: str | None = None


# -------------------------
# Encoding helpers (ISO-8859-2)
# -------------------------

def _detect_encoding(resp: httpx.Response, default: str = "iso-8859-2") -> str:
    ct = resp.headers.get("content-type", "") or ""
    m = re.search(r"charset=([^;]+)", ct, re.I)
    if m:
        return m.group(1).strip().lower()

    head = resp.content[:4096]
    try:
        head_txt = head.decode("ascii", errors="ignore")
    except Exception:
        head_txt = ""

    mm = re.search(
        r'<meta\s+[^>]*charset=["\']?([a-zA-Z0-9\-_]+)["\']?',
        head_txt,
        re.I,
    )
    if mm:
        return mm.group(1).strip().lower()

    mm2 = re.search(
        r'content=["\'][^"\']*charset=([a-zA-Z0-9\-_]+)[^"\']*["\']',
        head_txt,
        re.I,
    )
    if mm2:
        return mm2.group(1).strip().lower()

    return default


def _decode_html(resp: httpx.Response) -> str:
    enc = _detect_encoding(resp)
    try:
        return resp.content.decode(enc, errors="replace")
    except Exception:
        return resp.content.decode("iso-8859-2", errors="replace")


# -------------------------
# General helpers
# -------------------------

def _clean(s: str | None) -> str:
    if not s:
        return ""
    s = html_lib.unescape(s)
    s = s.replace("\xa0", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _abs_url(base: str, maybe_rel: str) -> str:
    if not maybe_rel:
        return ""
    if maybe_rel.startswith("http://") or maybe_rel.startswith("https://"):
        return maybe_rel
    if maybe_rel.startswith("//"):
        return "https:" + maybe_rel
    if maybe_rel.startswith("/"):
        return base.rstrip("/") + maybe_rel
    return base.rstrip("/") + "/" + maybe_rel.lstrip("./")


def _extract_judge_id_from_html(html: str) -> str:
    m = re.search(r"NrSedzia=(\d+)", html)
    return m.group(1) if m else ""


def _looks_like_login_page(html: str) -> bool:
    low = (html or "").lower()
    has_login_input = ('name="login"' in low) or ("name='login'" in low)
    has_pass_input = ('name="haslo"' in low) or ("name='haslo'" in low)
    has_form_action = re.search(r"<form[^>]+action=['\"]?login\.php", low) is not None
    has_login_words = ("zalog" in low) and (has_login_input or has_pass_input)
    return (has_login_input and has_pass_input) or has_form_action or has_login_words


def _extract_voivodeship_from_td_text(td_text: str) -> str:
    t = _clean(td_text)
    if not t:
        return ""

    tokens = t.split()
    out: list[str] = []

    lower_re = re.compile(r"[a-ząćęłńóśźż]")
    allowed_re = re.compile(r"^[A-ZĄĆĘŁŃÓŚŹŻ\-]+$")

    for tok in tokens:
        if lower_re.search(tok):
            break
        if allowed_re.match(tok):
            out.append(tok)
        else:
            if out:
                break

    return _clean(" ".join(out))


def _parse_profile_from_edit_form(html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    form = soup.find("form", {"name": "edycja"})
    if not form:
        form = soup.find(lambda tag: tag.name == "form" and (tag.get("name") or "").lower() == "edycja")
    if not form:
        return {}

    values: dict[str, str] = {}

    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        typ = (inp.get("type") or "text").lower()

        if typ in ("hidden", "text", "password"):
            values[name] = _clean(inp.get("value", ""))
        elif typ == "radio":
            if inp.has_attr("checked"):
                values[name] = _clean(inp.get("value", ""))

    for sel in form.find_all("select"):
        name = sel.get("name")
        if not name:
            continue
        opt = sel.find("option", selected=True)
        if opt:
            values[name] = _clean(opt.get("value") or opt.get_text())
        else:
            values[name] = ""

    photo_src = ""
    img = soup.select_one('img[src^="foto_sedzia/"]')
    if img and img.get("src"):
        photo_src = img.get("src", "").strip()

    voivodeship_name = ""
    voj_input = form.find("input", {"name": "woj"})
    if voj_input:
        td = voj_input.find_parent("td")
        if td:
            voivodeship_name = _extract_voivodeship_from_td_text(td.get_text(" ", strip=True))

    return {"values": values, "photo_src": photo_src, "voivodeship_name": voivodeship_name}


# -------------------------
# auth.py-compatible "new" extractors
# -------------------------

def _extract_logged_label(html: str) -> str:
    m = re.search(
        r"<small>\s*Zalogowany:\s*</small>\s*([^<]+?)\s*\|\s*<a\s+href=\"\?a=konto\">konto</a>",
        html,
        re.I,
    )
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()

    m2 = re.search(
        r"Zalogowany:\s*</small>\s*([^<]+?)\s*\|\s*<a\s+href=\"\?a=konto\"",
        html,
        re.I,
    )
    if m2:
        return re.sub(r"\s+", " ", m2.group(1)).strip()

    return ""


def _extract_menu_tabs(html: str) -> list[str]:
    labels = re.findall(r'class="przycisk"\s*>\s*([^<]+?)\s*</a>', html, flags=re.I)
    out = []
    for lab in labels:
        lab2 = re.sub(r"\s+", " ", lab).strip()
        if lab2:
            out.append(lab2)

    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _detect_account_type(judge_id: str, tabs: list[str]) -> str:
    if judge_id:
        return "judge"

    tabs_set = set(t.lower() for t in tabs)

    if ("terminarz" in tabs_set and "rozgrywki" in tabs_set) or any("sędziowie i delegaci" in t.lower() for t in tabs):
        return "org"

    if any(t.lower() in {"zawody", "niedyspozycyjność", "dokumenty", "edycja danych"} for t in tabs):
        return "judge"

    return "unknown"


# -------------------------
# VIP upsert (local helper)
# -------------------------

def _norm_username(u: str) -> str:
    return (u or "").strip()


async def _vip_upsert_from_login(
    *,
    username: str,
    judge_id: str | None,
    province: str | None,
    login_info_json: dict | None,
) -> tuple[bool, dict | None]:
    """
    Minimalny odpowiednik /baza_vips/upsert_from_login,
    bez ruszania Twoich routerów.
    """
    u = _norm_username(username)
    if not u:
        return False, None

    now = datetime.utcnow()

    row = await database.fetch_one(select(baza_vips).where(baza_vips.c.username == u))
    if not row:
        ins = {
            "username": u,
            "judge_id": (judge_id or None),
            "province": (province or None),
            "permissions_json": {},  # puste na start
            "login_info_json": login_info_json or {},
            "created_at": now,
            "updated_at": now,
            "last_login_at": now,
        }
        new_id = await database.execute(baza_vips.insert().values(**ins))
        row = await database.fetch_one(select(baza_vips).where(baza_vips.c.id == int(new_id)))
        return True, dict(row) if row else None

    upd = {"updated_at": now, "last_login_at": now}
    if judge_id is not None and str(judge_id).strip():
        upd["judge_id"] = str(judge_id).strip()
    if province is not None:
        upd["province"] = (province or None)
    if login_info_json is not None:
        upd["login_info_json"] = login_info_json or {}

    await database.execute(
        baza_vips.update().where(baza_vips.c.username == u).values(**upd)
    )
    row2 = await database.fetch_one(select(baza_vips).where(baza_vips.c.username == u))
    return False, dict(row2) if row2 else None


# -------------------------
# Login helper (cookies session)
# -------------------------

async def _login_get_session(
    *,
    client: httpx.AsyncClient,
    username: str,
    password: str,
) -> tuple[dict, str, str, list[str], str]:
    """
    Logowanie zgodne z auth.py:
    - body urlencoded w ISO-8859-2
    - follow_redirects=True
    - cookies z resp.cookies
    - judge_id może być pusty (konto org)
    - dodatkowo: display_name, available_tabs, account_type
    """
    form = {"login": username, "haslo": password, "from": "/index.php?"}
    body_str = urlencode(form, encoding="iso-8859-2", errors="strict")
    body_bytes = body_str.encode("ascii")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2",
        "User-Agent": "Mozilla/5.0 (compatible; zprp-backend/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
    }

    resp = await client.post("/login.php", content=body_bytes, headers=headers)
    html = _decode_html(resp)

    if "/index.php" not in resp.url.path:
        low = (html or "").lower()
        if "nieznany" in low or "tkownik" in low:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawny użytkownik lub hasło")
        if "ponownie" in low:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawny użytkownik lub hasło")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Logowanie nie powiodło się")

    cookies = dict(resp.cookies)

    judge_id = _extract_judge_id_from_html(html)  # może być ""
    display_name = _extract_logged_label(html)
    available_tabs = _extract_menu_tabs(html)
    account_type = _detect_account_type(judge_id, available_tabs)

    return cookies, judge_id, display_name, available_tabs, account_type


# -------------------------
# Endpoints
# -------------------------

@router.post("/login", response_model=BazaWebLoginResponse)
async def baza_web_login(
    data: BazaWebLoginRequest,
    settings: Settings = Depends(get_settings),
):
    """
    UWAGA: judge_id może być None (konto org).
    Zwracamy też: account_type, display_name, available_tabs + vip.
    """
    try:
        async with httpx.AsyncClient(
            base_url=settings.ZPRP_BASE_URL,
            follow_redirects=True,
            timeout=httpx.Timeout(60.0),
        ) as client:
            _, judge_id, display_name, available_tabs, account_type = await _login_get_session(
                client=client,
                username=data.username,
                password=data.password,
            )

        vip_payload = None

        # zapis do VIP TYLKO jeśli brak judge_id
        if not (judge_id or "").strip():
            created, vip_record = await _vip_upsert_from_login(
                username=data.username,
                judge_id=None,          # specjalnie None
                province=None,
                login_info_json={
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "account_type": account_type,
                    "display_name": display_name,
                    "tabs": available_tabs,
                },
            )
            vip_payload = {"created": created, "record": vip_record}

        return {
            "success": True,
            "judge_id": judge_id or None,
            "error": None,
            "account_type": account_type,
            "display_name": display_name or "",
            "available_tabs": available_tabs or [],
            "vip": vip_payload,         # <-- dla kont z judgeId będzie null
        }


        return {
            "success": True,
            "judge_id": judge_id or None,
            "error": None,
            "account_type": account_type,
            "display_name": display_name or "",
            "available_tabs": available_tabs or [],
            "vip": {"created": created, "record": vip_record},
        }

    except HTTPException as e:
        return {
            "success": False,
            "judge_id": None,
            "error": str(e.detail),
            "account_type": None,
            "display_name": None,
            "available_tabs": None,
            "vip": None,
        }
    except Exception as e:
        return {
            "success": False,
            "judge_id": None,
            "error": f"Błąd serwera: {e}",
            "account_type": None,
            "display_name": None,
            "available_tabs": None,
            "vip": None,
        }


@router.post("/profile", response_model=BazaWebProfileResponse)
async def baza_web_profile(
    data: BazaWebProfileRequest,
    settings: Settings = Depends(get_settings),
):
    """
    PROFIL jest tylko dla kont z NrSedzia.
    Jeśli konto org -> zwracamy 400 z jasnym komunikatem.
    """
    try:
        async with httpx.AsyncClient(
            base_url=settings.ZPRP_BASE_URL,
            follow_redirects=True,
            timeout=httpx.Timeout(60.0),
        ) as client:
            cookies, judge_id_from_login, _, _, _ = await _login_get_session(
                client=client,
                username=data.username,
                password=data.password,
            )

            judge_id = (data.judge_id or "").strip() or (judge_id_from_login or "").strip()
            if not judge_id:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Brak judge_id (NrSedzia). To konto prawdopodobnie nie jest kontem sędziego – nie można pobrać profilu.",
                )

            # warm-up
            try:
                resp_warm = await client.get("/index.php", cookies=cookies)
                cookies.update(dict(resp_warm.cookies))
            except Exception:
                pass

            path = f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_id}"
            resp_get = await client.get(path, cookies=cookies)
            html_get = _decode_html(resp_get)

        if resp_get.url.path.endswith("/login.php") or _looks_like_login_page(html_get):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Sesja do bazy nieaktywna lub przekierowanie do logowania",
            )

        parsed = _parse_profile_from_edit_form(html_get)
        if not parsed:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "Nie udało się pobrać strony profilu (nie znaleziono formularza edycji).",
            )

        values: dict[str, str] = parsed.get("values", {}) or {}

        if not any(_clean(values.get(k)) for k in ("Imie", "Nazwisko", "DataUr", "Miasto", "KodPocztowy", "Ulica", "Email")):
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "Nie udało się pobrać danych profilu (formularz nie zawiera oczekiwanych pól).",
            )

        base = settings.ZPRP_BASE_URL.rstrip("/") + "/"

        photo_src = (parsed.get("photo_src") or "").strip()
        photoUrl = _abs_url(base, photo_src) if photo_src else None

        profile = JudgeProfile(
            photoUrl=photoUrl,
            firstName=_clean(values.get("Imie")),
            middleName=_clean(values.get("Imie2")),
            lastName=_clean(values.get("Nazwisko")),
            maidenName=_clean(values.get("NazwiskoRodowe")),
            gender=_clean(values.get("Plec")),
            birthDate=_clean(values.get("DataUr")),
            street=_clean(values.get("Ulica")),
            postalCode=_clean(values.get("KodPocztowy")),
            city=_clean(values.get("Miasto")),
            voivodeship=_clean(parsed.get("voivodeship_name") or ""),
            voivodeshipCode=_clean(values.get("woj")),
            phone=_clean(values.get("Telefon")),
            email=_clean(values.get("Email")),
        )

        return {"success": True, "judge_id": judge_id, "profile": profile, "error": None}

    except HTTPException as e:
        return {"success": False, "judge_id": None, "profile": None, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "judge_id": None, "profile": None, "error": f"Błąd serwera: {e}"}
