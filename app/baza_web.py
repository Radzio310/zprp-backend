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


def _looks_like_login_page(html: str) -> bool:
    """
    UWAGA: nie wolno tu sprawdzać samego "login.php" w HTML, bo na stronach po zalogowaniu
    jest link "login.php?def=logout" (wyloguj).
    Detekcja musi być po FORMULARZU logowania.
    """
    low = (html or "").lower()

    # typowe pola formularza logowania
    has_login_input = ('name="login"' in low) or ("name='login'" in low)
    has_pass_input = ('name="haslo"' in low) or ("name='haslo'" in low)

    # form action do login.php
    has_form_action = re.search(r"<form[^>]+action=['\"]?login\.php", low) is not None

    # bardzo często na stronie logowania jest też "Zaloguj" / "Logowanie"
    has_login_words = ("zalog" in low) and (has_login_input or has_pass_input)

    return (has_login_input and has_pass_input) or has_form_action or has_login_words


def _parse_profile_from_edit_form(html: str) -> dict[str, Any]:
    """
    Parsuje z <form name="edycja"> analogicznie do edit_judge.py.
    """
    soup = BeautifulSoup(html, "html.parser")

    form = soup.find("form", {"name": "edycja"})
    if not form:
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
            if inp.has_attr("checked"):
                values[name] = _clean(inp.get("value", ""))

    # selecty (gdyby kiedyś wróciły)
    for sel in form.find_all("select"):
        name = sel.get("name")
        if not name:
            continue
        opt = sel.find("option", selected=True)
        values[name] = _clean(opt.get("value") or opt.get_text() if opt else "")

    # foto
    photo_src = ""
    img = soup.select_one('img[src^="foto_sedzia/"]')
    if img and img.get("src"):
        photo_src = img.get("src", "").strip()

    # województwo: hidden input + tekst w tym samym <td>
    voivodeship_name = ""
    woj_input = form.find("input", {"name": "woj"})
    if woj_input:
        td = woj_input.find_parent("td")
        if td:
            td_text = _clean(td.get_text(" ", strip=True))
            # np. "ŚLĄSKIE Zmiana możliwa z panelu WZPR lub ZPRP"
            # bierz pierwsze "DUŻE LITERY" (z polskimi znakami)
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
    Pobiera dane profilu analogicznie do fetchJudgeProfile (RN):
    - GET /index.php?a=sedzia&b=edycja&NrSedzia=...
    - foto: img[src^="foto_sedzia/"]
    - pola: input[name=Imie], Imie2, Nazwisko, ...
    - Plec: RADIO checked
    - woj: input hidden + tekst w tym samym TD
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

            # (opcjonalnie, ale bywa krytyczne) warm-up: wejście na index po zalogowaniu
            # żeby baza "dopieściła" sesję i ewentualne dodatkowe cookies.
            try:
                await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
            except Exception:
                # nie blokuj – to tylko dopalacz
                pass

            path = f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_id}"
            resp_get, html_get = await fetch_with_correct_encoding(
                client,
                path,
                method="GET",
                cookies=cookies,
            )

        # Jeśli baza przekierowała do logowania, resp_get.url.path będzie zwykle /login.php
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

        # sygnał, że to realnie formularz profilu (jakiekolwiek istotne pola)
        signal = any(_clean(values.get(k)) for k in ("Imie", "Nazwisko", "DataUr", "Miasto", "KodPocztowy", "Ulica", "Email"))
        if not signal:
            # jeśli to jednak login page (np. HTML bez formularza edycji) – zgłoś jasno
            if _looks_like_login_page(html_get) or resp_get.url.path.endswith("/login.php"):
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

        profile = JudgeProfile(
            photoUrl=photoUrl,
            firstName=_clean(values.get("Imie")),
            middleName=_clean(values.get("Imie2")),
            lastName=_clean(values.get("Nazwisko")),
            maidenName=_clean(values.get("NazwiskoRodowe")),
            gender=_clean(values.get("Plec")),  # radio checked => "M"/"K"
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
