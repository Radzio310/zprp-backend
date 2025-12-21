# app/baza_web.py

import re
import html as html_lib
from urllib.parse import urlencode
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from bs4 import BeautifulSoup

from app.deps import get_settings, Settings

router = APIRouter(prefix="/baza_web", tags=["BAZA Web"])


# -------------------------
# Models
# -------------------------

class BazaWebLoginRequest(BaseModel):
    username: str
    password: str


class BazaWebLoginResponse(BaseModel):
    success: bool
    judge_id: str | None = None
    error: str | None = None


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

    # w Twoim HTML jest: <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-2" />
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
    """
    NIE sprawdzamy "login.php" literalnie (bo na stronie po zalogowaniu jest login.php?def=logout).
    Szukamy cech formularza logowania.
    """
    low = (html or "").lower()
    has_login_input = ('name="login"' in low) or ("name='login'" in low)
    has_pass_input = ('name="haslo"' in low) or ("name='haslo'" in low)
    has_form_action = re.search(r"<form[^>]+action=['\"]?login\.php", low) is not None
    has_login_words = ("zalog" in low) and (has_login_input or has_pass_input)
    return (has_login_input and has_pass_input) or has_form_action or has_login_words


def _extract_voivodeship_from_td_text(td_text: str) -> str:
    """
    W <td> masz np.:
      "ŚLĄSKIE Zmiana możliwa z panelu WZPR lub ZPRP"
    Chcemy wyciągnąć tylko "ŚLĄSKIE" (albo np. "KUJAWSKO-POMORSKIE").
    Bierzemy pierwszy ciąg tokenów będących w całości uppercase (z PL znakami i myślnikiem).
    """
    t = _clean(td_text)
    if not t:
        return ""

    tokens = t.split()
    out: list[str] = []

    # token jest "uppercase-ish" jeśli nie zawiera żadnych małych liter
    # (uwzględniamy polskie znaki)
    lower_re = re.compile(r"[a-ząćęłńóśźż]")
    allowed_re = re.compile(r"^[A-ZĄĆĘŁŃÓŚŹŻ\-]+$")

    for tok in tokens:
        # zatrzymaj się na pierwszym tokenie, który wygląda jak normalne zdanie (małe litery)
        if lower_re.search(tok):
            break
        # w praktyce województwa są z dużych liter i myślników
        if allowed_re.match(tok):
            out.append(tok)
        else:
            # np. przecinki/kropki — jeśli już coś mamy, kończ
            if out:
                break

    return _clean(" ".join(out))


def _parse_profile_from_edit_form(html: str) -> dict[str, Any]:
    """
    Parsuje wartości z <form name="edycja"> tak jak w edit_judge.py:
    - input hidden/text + radio checked
    - select option[selected] (fallback)
    - img foto_sedzia/*
    - województwo: input[name=woj] + tekst w tym samym <td>
    """
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
            # czasem ważniejszy jest value, a czasem tekst — tu trzymamy value, ale możesz zmienić
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
# Login helper (cookies session)
# -------------------------

async def _login_get_cookies_and_judge_id(
    *,
    client: httpx.AsyncClient,
    username: str,
    password: str,
) -> tuple[dict, str, str]:
    """
    Logowanie identyczne w skutkach jak auth.py:
    - body urlencoded w ISO-8859-2
    - follow_redirects=True
    - cookies z resp.cookies
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

    # auth.py sprawdza /index.php w resp.url.path
    if "/index.php" not in resp.url.path:
        low = (html or "").lower()
        if "nieznany" in low or "tkownik" in low:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawny użytkownik")
        if "ponownie" in low:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawne hasło")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Logowanie nie powiodło się")

    cookies = dict(resp.cookies)
    judge_id = _extract_judge_id_from_html(html)
    if not judge_id:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            "Zalogowano, ale nie udało się odczytać judgeId (NrSedzia) z odpowiedzi",
        )

    return cookies, judge_id, html


# -------------------------
# Endpoints
# -------------------------

@router.post("/login", response_model=BazaWebLoginResponse)
async def baza_web_login(
    data: BazaWebLoginRequest,
    settings: Settings = Depends(get_settings),
):
    try:
        async with httpx.AsyncClient(
            base_url=settings.ZPRP_BASE_URL,
            follow_redirects=True,
            timeout=httpx.Timeout(60.0),
        ) as client:
            _, judge_id, _ = await _login_get_cookies_and_judge_id(
                client=client,
                username=data.username,
                password=data.password,
            )
        return {"success": True, "judge_id": judge_id, "error": None}
    except HTTPException as e:
        return {"success": False, "judge_id": None, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "judge_id": None, "error": f"Błąd serwera: {e}"}


@router.post("/profile", response_model=BazaWebProfileResponse)
async def baza_web_profile(
    data: BazaWebProfileRequest,
    settings: Settings = Depends(get_settings),
):
    try:
        async with httpx.AsyncClient(
            base_url=settings.ZPRP_BASE_URL,
            follow_redirects=True,
            timeout=httpx.Timeout(60.0),
        ) as client:
            cookies, judge_id_from_login, _ = await _login_get_cookies_and_judge_id(
                client=client,
                username=data.username,
                password=data.password,
            )

            judge_id = (data.judge_id or judge_id_from_login).strip() or judge_id_from_login

            # warm-up (czasem serwis ustawia/utwierdza sesję po wejściu na index)
            try:
                resp_warm = await client.get("/index.php", cookies=cookies)
                # zaktualizuj cookies o ewentualne nowe set-cookie
                cookies.update(dict(resp_warm.cookies))
            except Exception:
                pass

            path = f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_id}"
            resp_get = await client.get(path, cookies=cookies)
            html_get = _decode_html(resp_get)

        # realne przekierowanie do loginu
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

        # walidacja: czy mamy cokolwiek sensownego
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
