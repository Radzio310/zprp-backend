# app/baza_web.py

import re
import html as html_lib
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from bs4 import BeautifulSoup

from app.deps import get_settings, Settings
from app.utils import fetch_with_correct_encoding

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
# Helpers
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


def _looks_like_login_or_no_session(html: str) -> bool:
    """
    Heurystyka identyczna w duchu do Twoich problemów:
    - jeśli baza zwraca login / brak sesji, zwykle w HTML pojawią się elementy logowania
      albo samo login.php w linkach.
    """
    low = (html or "").lower()
    if "login.php" in low:
        return True
    if ("name=\"login\"" in low or "name='login'" in low) and ("haslo" in low or "password" in low):
        return True
    if "logowanie" in low and ("haslo" in low or "login" in low):
        return True
    return False


def _parse_profile_from_edit_form(html: str) -> dict[str, Any]:
    """
    Parsuje dokładnie z <form name="edycja"> tak jak edit_judge.py.
    """
    soup = BeautifulSoup(html, "html.parser")

    form = soup.find("form", {"name": "edycja"})
    if not form:
        # fallback: czasem bywa FORM uppercase albo inny parser – spróbuj po atrybucie name case-insensitive
        form = soup.find(lambda tag: tag.name == "form" and (tag.get("name") or "").lower() == "edycja")

    if not form:
        return {}

    values: dict[str, str] = {}

    # inputy
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        typ = (inp.get("type") or "text").lower()

        if typ in ("hidden", "text", "password"):
            values[name] = _clean(inp.get("value", ""))
        elif typ == "radio":
            # tylko checked
            if inp.has_attr("checked"):
                values[name] = _clean(inp.get("value", ""))

    # selecty (gdyby kiedyś były)
    for sel in form.find_all("select"):
        name = sel.get("name")
        if not name:
            continue
        opt = sel.find("option", selected=True)
        if opt:
            # czasem interesuje value, czasem text — w RN gender brałeś text dla select,
            # ale tu i tak prawie zawsze masz radio. Zostawiamy value jako domyślne.
            values[name] = _clean(opt.get("value") or opt.get_text())
        else:
            values[name] = ""

    # photo
    photo_src = ""
    img = soup.select_one('img[src^="foto_sedzia/"]')
    if img and img.get("src"):
        photo_src = img.get("src", "").strip()

    # województwo: input[name=woj] jest hidden, a nazwa jest w tekście w tym samym <td>
    voivodeship_name = ""
    woj_input = form.find("input", {"name": "woj"})
    if woj_input:
        td = woj_input.find_parent("td")
        if td:
            td_text = _clean(td.get_text(" ", strip=True))
            # w przykładzie: "ŚLĄSKIE Zmiana możliwa z panelu WZPR lub ZPRP"
            m = re.search(r"([A-ZĄĆĘŁŃÓŚŹŻ][A-ZĄĆĘŁŃÓŚŹŻ\- ]{2,})", td_text)
            voivodeship_name = _clean(m.group(1)) if m else td_text

    return {
        "values": values,
        "photo_src": photo_src,
        "voivodeship_name": voivodeship_name,
    }


async def _login_get_cookies_and_judge_id(
    *,
    client: httpx.AsyncClient,
    username: str,
    password: str,
) -> tuple[dict, str, str]:
    """
    Logowanie 1:1 jak w auth.py / edit_judge.py:
    - POST /login.php przez fetch_with_correct_encoding
    - sprawdzenie resp.url.path
    - cookies = dict(resp.cookies)
    - judge_id z HTML
    Zwraca: (cookies, judge_id, html_login)
    """
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

    if "/index.php" not in resp_login.url.path:
        # zachowanie jak w auth.py
        low = (html_login or "").lower()
        if "nieznany" in low or "tkownik" in low:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawny użytkownik")
        if "ponownie" in low:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawne hasło")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Logowanie nie powiodło się")

    cookies = dict(resp_login.cookies)

    judge_id = _extract_judge_id_from_html(html_login)
    if not judge_id:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            "Zalogowano, ale nie udało się odczytać judgeId (NrSedzia) z odpowiedzi",
        )

    return cookies, judge_id, html_login


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
    """
    Pobieranie profilu w 100% analogicznie do Twojego działającego przepływu:
    - AsyncClient
    - login przez fetch_with_correct_encoding -> cookies
    - GET edycji przez fetch_with_correct_encoding z cookies
    - parsowanie z form[name=edycja]
    """
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

            path = f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_id}"
            resp_get, html_get = await fetch_with_correct_encoding(
                client,
                path,
                method="GET",
                cookies=cookies,
            )

        # Jeśli baza przekierowała mimo follow_redirects, to nadal wyjdzie w HTML.
        if _looks_like_login_or_no_session(html_get) or "login.php" in resp_get.url.path:
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

        # sygnał, że to realnie formularz profilu
        if not any(values.get(k) for k in ("Imie", "Nazwisko", "DataUr", "Email", "Miasto", "Ulica", "KodPocztowy")):
            # często to znaczy, że HTML nie był tym, czego oczekujemy
            if _looks_like_login_or_no_session(html_get):
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    "Sesja do bazy nieaktywna lub przekierowanie do logowania",
                )
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "Nie udało się pobrać strony profilu (HTML nie zawiera danych formularza).",
            )

        base = settings.ZPRP_BASE_URL.rstrip("/") + "/"

        photo_src = (parsed.get("photo_src") or "").strip()
        photoUrl = _abs_url(base, photo_src) if photo_src else None

        voivodeship = _clean(parsed.get("voivodeship_name") or "")

        profile = JudgeProfile(
            photoUrl=photoUrl,
            firstName=_clean(values.get("Imie")),
            middleName=_clean(values.get("Imie2")),
            lastName=_clean(values.get("Nazwisko")),
            maidenName=_clean(values.get("NazwiskoRodowe")),
            gender=_clean(values.get("Plec")),  # radio checked
            birthDate=_clean(values.get("DataUr")),
            street=_clean(values.get("Ulica")),
            postalCode=_clean(values.get("KodPocztowy")),
            city=_clean(values.get("Miasto")),
            voivodeship=voivodeship,
            voivodeshipCode=_clean(values.get("woj")),
            phone=_clean(values.get("Telefon")),
            email=_clean(values.get("Email")),
        )

        return {"success": True, "judge_id": judge_id, "profile": profile, "error": None}

    except HTTPException as e:
        return {"success": False, "judge_id": None, "profile": None, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "judge_id": None, "profile": None, "error": f"Błąd serwera: {e}"}
