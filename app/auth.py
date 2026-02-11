# app/auth.py

import datetime
from typing import List, Optional
from urllib.parse import urlencode
import jwt
import re
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import httpx

from app.deps import get_settings, Settings
from app.utils import fetch_with_correct_encoding

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # w sekundach
    account_type: str  # "judge" | "org" | "unknown"
    display_name: str = ""  # np. "Artur JĘDRYCHA | Śląski Związek Piłki Ręcznej"
    available_tabs: List[str] = []
    judge_id: str = ""  # zostawiamy jawnie, żeby appka nie musiała dekodować JWT

def _extract_logged_label(html: str) -> str:
    """
    Wyciąga tekst po "Zalogowany:" do pierwszego " | <a href="?a=konto">konto</a>"
    (w praktyce stabilne w ZPRP).
    """
    m = re.search(
        r"<small>\s*Zalogowany:\s*</small>\s*([^<]+?)\s*\|\s*<a\s+href=\"\?a=konto\">konto</a>",
        html,
        re.I,
    )
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()

    # fallback: trochę luźniej, do "| konto"
    m2 = re.search(r"Zalogowany:\s*</small>\s*([^<]+?)\s*\|\s*<a\s+href=\"\?a=konto\"", html, re.I)
    if m2:
        return re.sub(r"\s+", " ", m2.group(1)).strip()

    return ""


def _extract_menu_tabs(html: str) -> list[str]:
    """
    Zbiera etykiety w menu głównym: <a ... class="przycisk" >Etykieta</a>
    """
    labels = re.findall(r'class="przycisk"\s*>\s*([^<]+?)\s*</a>', html, flags=re.I)
    out = []
    for lab in labels:
        lab2 = re.sub(r"\s+", " ", lab).strip()
        if lab2:
            out.append(lab2)
    # dedupe zachowując kolejność
    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _detect_account_type(judge_id: str, tabs: list[str]) -> str:
    """
    account_type:
    - "judge" gdy mamy NrSedzia albo menu typowe dla sędziego/delegata
    - "org" gdy menu typowe dla konta wojewódzkiego (Terminarz/Rozgrywki/Sędziowie i Delegaci)
    - "unknown" inaczej
    """
    if judge_id:
        return "judge"

    tabs_set = set(t.lower() for t in tabs)
    # konto wojewódzkie:
    if ("terminarz" in tabs_set and "rozgrywki" in tabs_set) or any("sędziowie i delegaci" in t.lower() for t in tabs):
        return "org"

    # konto sędziego bez NrSedzia (rzadkie, ale w razie czego):
    if any(t.lower() in {"zawody", "niedyspozycyjność", "dokumenty", "edycja danych"} for t in tabs):
        return "judge"

    return "unknown"


@router.post("/auth/login", response_model=LoginResponse)
async def login(data: LoginRequest, settings: Settings = Depends(get_settings)):
    form = {
        "login": data.username,
        "haslo": data.password,
        "from": "/index.php?",
    }
    body = urlencode(form, encoding="iso-8859-2", errors="strict")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2"
    }

    async with httpx.AsyncClient(
        base_url=settings.ZPRP_BASE_URL, follow_redirects=True
    ) as client:
        resp = await client.post("/login.php", content=body, headers=headers)

    # Dekoduj HTML zgodnie z deklarowanym charsetem (fallback na iso-8859-2)
    ct = resp.headers.get("content-type", "")
    m = re.search(r"charset=([^;]+)", ct, re.I)
    enc = (m.group(1).strip().lower() if m else "iso-8859-2")
    html = resp.content.decode(enc, errors="replace")

    if "/index.php" not in resp.url.path:
        if "Nieznany" in html or "tkownik" in html:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawny użytkownik")
        if "ponownie" in html:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawne hasło")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Logowanie nie powiodło się")

    cookies = dict(resp.cookies)
    # 1) stara logika: jeśli da się znaleźć NrSedzia -> konto sędziego
    m = re.search(r"NrSedzia=(\d+)", html)
    judge_id = m.group(1) if m else ""

    # 2) nowa logika: nazwa + zakładki + typ konta
    display_name = _extract_logged_label(html)  # np. "Artur JĘDRYCHA | Śląski Związek Piłki Ręcznej"
    available_tabs = _extract_menu_tabs(html)   # np. ["Terminarz","Rozgrywki","Statystyki","Sędziowie i Delegaci"]
    account_type = _detect_account_type(judge_id, available_tabs)


    expire = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": data.username,
        "exp": expire,
        "cookies": cookies,

        # stare:
        "judge_id": judge_id,

        # nowe:
        "account_type": account_type,
        "display_name": display_name,
        "available_tabs": available_tabs,
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {
        "access_token": token,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "account_type": account_type,
        "display_name": display_name,
        "available_tabs": available_tabs,
        "judge_id": judge_id,
    }



async def get_current_cookies(
    token: str = Depends(oauth2_scheme), settings: Settings = Depends(get_settings)
) -> dict:
    """
    Dependency do pobierania ciasteczek z zakodowanego tokena.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        cookies = payload.get("cookies")
        if not isinstance(cookies, dict):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Brak ciasteczek w tokenie")
        return cookies
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token wygasł")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Nieprawidłowy token")
