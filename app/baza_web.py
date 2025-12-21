# app/baza_web.py

import re
import html as html_lib
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

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
    # opcjonalnie: jeśli klient już ma judgeId i chce wymusić
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
# Helpers (encoding + parse)
# -------------------------

def _detect_encoding(resp: httpx.Response, default: str = "iso-8859-2") -> str:
    ct = resp.headers.get("content-type", "") or ""
    m = re.search(r"charset=([^;]+)", ct, re.I)
    if m:
        return m.group(1).strip().lower()
    return default


def _decode_html(resp: httpx.Response) -> str:
    enc = _detect_encoding(resp)
    try:
        return resp.content.decode(enc, errors="replace")
    except Exception:
        return resp.content.decode("iso-8859-2", errors="replace")


def _clean(s: str | None) -> str:
    if not s:
        return ""
    # decode encji HTML + normalizacja białych znaków
    s = html_lib.unescape(s)
    s = s.replace("\xa0", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _abs_url(base: str, maybe_rel: str) -> str:
    # base np. "https://baza.zprp.pl/"
    if not maybe_rel:
        return ""
    if maybe_rel.startswith("http://") or maybe_rel.startswith("https://"):
        return maybe_rel
    if maybe_rel.startswith("/"):
        return base.rstrip("/") + maybe_rel
    return base.rstrip("/") + "/" + maybe_rel


def _extract_input_value(html: str, name: str) -> str:
    """
    Szuka <input ... name="X" ... value="Y">
    W bazie zwykle są inputy tekstowe i ukryte.
    """
    # dopuszczamy dowolną kolejność atrybutów
    # 1) znajdź tag input z name="name"
    pattern = re.compile(
        r'<input\b[^>]*\bname\s*=\s*["\']'
        + re.escape(name)
        + r'["\'][^>]*>',
        re.I,
    )
    m = pattern.search(html)
    if not m:
        return ""
    tag = m.group(0)

    # 2) wyciągnij value="..."
    mv = re.search(r'\bvalue\s*=\s*["\']([^"\']*)["\']', tag, re.I)
    return _clean(mv.group(1) if mv else "")


def _extract_select_selected_text(html: str, name: str) -> str:
    """
    Szuka <select name="X"> ... <option selected>TEXT</option> ...
    """
    sel_pat = re.compile(
        r'<select\b[^>]*\bname\s*=\s*["\']'
        + re.escape(name)
        + r'["\'][^>]*>(.*?)</select>',
        re.I | re.S,
    )
    ms = sel_pat.search(html)
    if not ms:
        return ""

    inner = ms.group(1)
    # najpierw option selected
    opt_sel = re.search(r"<option\b[^>]*\bselected\b[^>]*>(.*?)</option>", inner, re.I | re.S)
    if opt_sel:
        return _clean(opt_sel.group(1))

    # fallback: pierwszy option
    opt_first = re.search(r"<option\b[^>]*>(.*?)</option>", inner, re.I | re.S)
    return _clean(opt_first.group(1) if opt_first else "")


def _extract_voivodeship_name_from_td(html: str) -> str:
    """
    W Twoim RN było:
      <td> <input name="woj" value="..."> ŚLĄSKIE </td>
    Tu wyciągamy tekst po inputcie aż do </td>.
    """
    # znajdź TD zawierające input name="woj"
    td_pat = re.compile(r"<td\b[^>]*>.*?\bname\s*=\s*['\"]woj['\"].*?</td>", re.I | re.S)
    mtd = td_pat.search(html)
    if not mtd:
        return ""

    td_html = mtd.group(0)
    # usuń tagi input i inne tagi, zostaw tekst
    # najpierw wytnij wszystko do końca inputa
    after_input = re.split(r"</?input\b[^>]*>", td_html, flags=re.I | re.S)
    # po inputach zwykle tekst w węźle tekstowym, bierzemy sklejone resztki
    joined = " ".join(after_input[1:]) if len(after_input) > 1 else td_html
    # usuń wszystkie tagi HTML z tego fragmentu
    joined = re.sub(r"<[^>]+>", " ", joined)
    return _clean(joined)


def _extract_photo_url(html: str, base: str) -> str:
    m = re.search(r'<img\b[^>]*\bsrc\s*=\s*["\'](foto_sedzia/[^"\']+)["\']', html, re.I)
    if not m:
        return ""
    return _abs_url(base, m.group(1))


def _extract_judge_id_from_html(html: str) -> str:
    m = re.search(r"NrSedzia=(\d+)", html)
    return m.group(1) if m else ""


def _looks_like_bad_credentials(html: str) -> bool:
    t = (html or "").lower()
    return (
        "nieznany" in t
        or "użytkownik" in t
        or "uzytkownik" in t
        or "hasło" in t
        or "haslo" in t
        or "spróbuj ponownie" in t
        or "sprobuj ponownie" in t
    )


async def _baza_login_and_get_cookies(
    *,
    username: str,
    password: str,
    settings: Settings,
) -> tuple[dict, str]:
    """
    Loguje się do baza.zprp.pl i zwraca (cookies_dict, judge_id).
    """
    form = {"login": username, "haslo": password, "from": "/index.php?"}
    body = urlencode(form, encoding="iso-8859-2", errors="strict")
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2"}

    async with httpx.AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
    ) as client:
        resp = await client.post("/login.php", content=body, headers=headers)

    html = _decode_html(resp)

    # Sukces: finalnie jesteśmy na /index.php (albo przynajmniej nie na login.php)
    if "/index.php" not in str(resp.url):
        # ujednolicona obsługa błędów
        if _looks_like_bad_credentials(html):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Niepoprawny użytkownik lub hasło",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logowanie nie powiodło się",
        )

    cookies = dict(resp.cookies)
    judge_id = _extract_judge_id_from_html(html)

    if not judge_id:
        # w praktyce bez tego dalej nic sensownie nie zrobisz
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Zalogowano, ale nie udało się odczytać judgeId (NrSedzia) z odpowiedzi",
        )

    return cookies, judge_id


# -------------------------
# BAZA Web endpoints
# -------------------------

@router.post("/login", response_model=BazaWebLoginResponse)
async def baza_web_login(data: BazaWebLoginRequest, settings: Settings = Depends(get_settings)):
    """
    Web-friendly login: backend loguje się do baza.zprp.pl i zwraca success + judge_id.
    Bez CORS, bo to nie jest wywołanie z przeglądarki do baza.zprp.pl, tylko do Twojego backendu.
    """
    try:
        _, judge_id = await _baza_login_and_get_cookies(
            username=data.username,
            password=data.password,
            settings=settings,
        )
        return {"success": True, "judge_id": judge_id}
    except HTTPException as e:
        # ważne: zgodnie z Twoim wymaganiem nie zwracamy judge_id przy błędzie
        return {"success": False, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "error": f"Błąd serwera: {e}"}


@router.post("/profile", response_model=BazaWebProfileResponse)
async def baza_web_profile(data: BazaWebProfileRequest, settings: Settings = Depends(get_settings)):
    """
    Pobiera podstawowe dane profilu analogicznie do fetchJudgeProfile (frontend),
    ale wykonywane na backendzie.
    """
    try:
        cookies, judge_id_from_login = await _baza_login_and_get_cookies(
            username=data.username,
            password=data.password,
            settings=settings,
        )
        judge_id = (data.judge_id or judge_id_from_login).strip() or judge_id_from_login

        # Pobierz stronę edycji profilu sędziego
        path = f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_id}"
        async with httpx.AsyncClient(
            base_url=settings.ZPRP_BASE_URL,
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
            cookies=cookies,
        ) as client:
            resp = await client.get(path)

        html = _decode_html(resp)

        # zrób minimalną walidację, czy to wygląda jak strona profilu
        if "NrSedzia" not in html and "Imie" not in html and "Nazwisko" not in html:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Nie udało się pobrać strony profilu (nieoczekiwany HTML).",
            )

        base = settings.ZPRP_BASE_URL.rstrip("/") + "/"

        photoUrl = _extract_photo_url(html, base) or None

        # pola jak w fetchJudgeProfile (frontend)
        firstName = _extract_input_value(html, "Imie")
        middleName = _extract_input_value(html, "Imie2")
        lastName = _extract_input_value(html, "Nazwisko")
        maidenName = _extract_input_value(html, "NazwiskoRodowe")

        # Plec bywa selectem
        gender = _extract_select_selected_text(html, "Plec") or _extract_input_value(html, "Plec")
        gender = _clean(gender)

        birthDate = _extract_input_value(html, "DataUr")
        street = _extract_input_value(html, "Ulica")
        postalCode = _extract_input_value(html, "KodPocztowy")
        city = _extract_input_value(html, "Miasto")
        phone = _extract_input_value(html, "Telefon")
        email = _extract_input_value(html, "Email")

        voivodeshipCode = _extract_input_value(html, "woj")
        voivodeship = _extract_voivodeship_name_from_td(html)

        # fallback: jeśli jednak kiedyś woj będzie selectem
        if not voivodeship and voivodeshipCode:
            # próbuj znaleźć option o danym value w select[name="woj"]
            sel_pat = re.compile(
                r'<select\b[^>]*\bname\s*=\s*["\']woj["\'][^>]*>(.*?)</select>',
                re.I | re.S,
            )
            ms = sel_pat.search(html)
            if ms:
                inner = ms.group(1)
                opt = re.search(
                    r'<option\b[^>]*\bvalue\s*=\s*["\']'
                    + re.escape(voivodeshipCode)
                    + r'["\'][^>]*>(.*?)</option>',
                    inner,
                    re.I | re.S,
                )
                voivodeship = _clean(opt.group(1) if opt else "")

        profile = JudgeProfile(
            photoUrl=photoUrl,
            firstName=firstName,
            middleName=middleName,
            lastName=lastName,
            maidenName=maidenName,
            gender=gender,
            birthDate=birthDate,
            street=street,
            postalCode=postalCode,
            city=city,
            voivodeship=voivodeship,
            voivodeshipCode=voivodeshipCode,
            phone=phone,
            email=email,
        )

        return {"success": True, "judge_id": judge_id, "profile": profile}

    except HTTPException as e:
        return {"success": False, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "error": f"Błąd serwera: {e}"}
