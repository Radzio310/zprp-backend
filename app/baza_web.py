# app/baza_web.py

import re
import html as html_lib
from urllib.parse import urlencode
from html.parser import HTMLParser
from typing import Any

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
    judge_id: str | None = None  # opcjonalnie: klient może wymusić


class JudgeProfile(BaseModel):
    photoUrl: str | None = None
    firstName: str = ""
    middleName: str = ""
    lastName: str = ""
    maidenName: str = ""
    gender: str = ""  # "M" / "K" / "" (u Ciebie RN bierze tekst option:selected)
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
# Helpers (encoding + clean)
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


def _detect_encoding(resp: httpx.Response, default: str = "iso-8859-2") -> str:
    """
    1) charset z nagłówka
    2) fallback: meta charset z początku dokumentu
    3) default: iso-8859-2 (w bazie bardzo częste)
    """
    ct = resp.headers.get("content-type", "") or ""
    m = re.search(r"charset=([^;]+)", ct, re.I)
    if m:
        return m.group(1).strip().lower()

    # meta charset – spróbuj odczytać pierwsze bajty jako utf-8 i wyłapać deklarację
    head = resp.content[:2048]
    try:
        head_txt = head.decode("utf-8", errors="ignore")
    except Exception:
        head_txt = ""

    mm = re.search(r'<meta\s+[^>]*charset=["\']?([a-zA-Z0-9\-_]+)["\']?', head_txt, re.I)
    if mm:
        return mm.group(1).strip().lower()

    return default


def _decode_html(resp: httpx.Response) -> str:
    enc = _detect_encoding(resp)
    try:
        return resp.content.decode(enc, errors="replace")
    except Exception:
        return resp.content.decode("iso-8859-2", errors="replace")


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


def _extract_judge_id_from_html(html: str) -> str:
    m = re.search(r"NrSedzia=(\d+)", html)
    return m.group(1) if m else ""


# -------------------------
# HTML form parser (robust; zamiast regexów)
# -------------------------

class _BazaProfileFormParser(HTMLParser):
    """
    Parsuje:
    - input[name] -> value (value może być bez cudzysłowów, HTMLParser to ogarnia)
    - textarea[name] -> inner text
    - select[name] -> tekst option selected (jak Cheerio option:selected).text()
    - img src "foto_sedzia/..."
    Dodatkowo zbiera surowy tekst wewnątrz <td> zawierającego input[name=woj],
    aby odtworzyć voivodeship (jak w RN: tekst obok ukrytego inputa).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)

        self.inputs: dict[str, str] = {}
        self.textareas: dict[str, str] = {}

        # select parsing
        self._in_select: bool = False
        self._select_name: str | None = None
        self._in_option: bool = False
        self._option_selected: bool = False
        self._option_text_buf: list[str] = []
        self.select_selected_text: dict[str, str] = {}

        # textarea parsing
        self._in_textarea: bool = False
        self._textarea_name: str | None = None
        self._textarea_buf: list[str] = []

        # photo
        self.photo_src: str = ""

        # voivodeship-from-td parsing
        self._td_depth: int = 0
        self._td_has_woj_input: bool = False
        self._td_text_buf: list[str] = []
        self.woj_td_text: str = ""

    @staticmethod
    def _attrs_to_dict(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in attrs:
            if not k:
                continue
            out[k.lower()] = (v if v is not None else "")
        return out

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        a = self._attrs_to_dict(attrs)

        if tag_l == "td":
            self._td_depth += 1
            # reset bufora dla nowego <td>
            self._td_has_woj_input = False
            self._td_text_buf = []

        if tag_l == "img" and not self.photo_src:
            src = (a.get("src") or "").strip()
            # baza bywa: foto_sedzia/... albo ./foto_sedzia/... albo /foto_sedzia/...
            if "foto_sedzia/" in src:
                self.photo_src = src

        if tag_l == "input":
            name = (a.get("name") or "").strip()
            if name:
                val = (a.get("value") or "")
                self.inputs[name] = _clean(val)

                if name == "woj":
                    # jesteśmy w <td> zawierającym input woj
                    if self._td_depth > 0:
                        self._td_has_woj_input = True

        if tag_l == "textarea":
            name = (a.get("name") or "").strip()
            if name:
                self._in_textarea = True
                self._textarea_name = name
                self._textarea_buf = []

        if tag_l == "select":
            name = (a.get("name") or "").strip()
            if name:
                self._in_select = True
                self._select_name = name

        if tag_l == "option" and self._in_select and self._select_name:
            self._in_option = True
            # selected może być "selected", "selected=selected", itd.
            self._option_selected = ("selected" in a)
            self._option_text_buf = []

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()

        if tag_l == "option" and self._in_option:
            opt_text = _clean("".join(self._option_text_buf))
            if self._select_name and self._option_selected:
                # zapisujemy tekst selected
                self.select_selected_text[self._select_name] = opt_text
            self._in_option = False
            self._option_selected = False
            self._option_text_buf = []

        if tag_l == "select":
            self._in_select = False
            self._select_name = None

        if tag_l == "textarea" and self._in_textarea:
            txt = _clean("".join(self._textarea_buf))
            if self._textarea_name:
                self.textareas[self._textarea_name] = txt
            self._in_textarea = False
            self._textarea_name = None
            self._textarea_buf = []

        if tag_l == "td":
            if self._td_depth > 0:
                self._td_depth -= 1
            # jeśli to był <td> z woj – zapamiętaj tekst (bez HTML)
            if self._td_has_woj_input:
                self.woj_td_text = _clean("".join(self._td_text_buf))
            self._td_has_woj_input = False
            self._td_text_buf = []

    def handle_data(self, data: str) -> None:
        # option text
        if self._in_option:
            self._option_text_buf.append(data)

        # textarea text
        if self._in_textarea:
            self._textarea_buf.append(data)

        # td text after input woj (chcemy tekst obok inputa)
        if self._td_depth > 0 and self._td_has_woj_input:
            self._td_text_buf.append(data)

    def handle_entityref(self, name: str) -> None:
        self.handle_data(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.handle_data(f"&#{name};")


def _parse_profile_fields(html: str) -> dict[str, Any]:
    p = _BazaProfileFormParser()
    p.feed(html)

    def get_input(name: str) -> str:
        return _clean(p.inputs.get(name, ""))

    def get_textarea(name: str) -> str:
        return _clean(p.textareas.get(name, ""))

    def get_select_selected_text(name: str) -> str:
        return _clean(p.select_selected_text.get(name, ""))

    # gender w RN: select option:selected text (fallback: input)
    gender = get_select_selected_text("Plec") or get_input("Plec")

    # voivodeshipCode: value ukrytego inputa "woj"
    voiv_code = get_input("woj")

    # voivodeship: tekst obok inputa w tym samym TD
    # parser zbiera cały tekst z td, ale może zawierać też inne śmieci; spróbuj wyciągnąć sensowny token
    woj_td = _clean(p.woj_td_text)
    voiv_name = ""

    # często to jest po prostu "ŚLĄSKIE" / "MAZOWIECKIE" itd.
    # jeśli w td są dodatkowe słowa, bierz pierwsze "wielkimi literami"
    if woj_td:
        # usuń ewentualne resztki typu "Województwo" itp.
        # i wyciągnij pierwsze słowo/ciąg liter (z polskimi znakami) w caps
        m = re.search(r"([A-ZĄĆĘŁŃÓŚŹŻ][A-ZĄĆĘŁŃÓŚŹŻ\- ]{2,})", woj_td)
        voiv_name = _clean(m.group(1)) if m else woj_td

    # fallback: gdyby wrócili do select[name=woj], spróbuj wyłuskać selected text
    if not voiv_name:
        voiv_name = get_select_selected_text("woj")

    # photo src
    photo_src = (p.photo_src or "").strip()

    return {
        "photo_src": photo_src,
        "firstName": get_input("Imie") or get_textarea("Imie"),
        "middleName": get_input("Imie2") or get_textarea("Imie2"),
        "lastName": get_input("Nazwisko") or get_textarea("Nazwisko"),
        "maidenName": get_input("NazwiskoRodowe") or get_textarea("NazwiskoRodowe"),
        "gender": gender,
        "birthDate": get_input("DataUr"),
        "street": get_input("Ulica"),
        "postalCode": get_input("KodPocztowy"),
        "city": get_input("Miasto"),
        "phone": get_input("Telefon"),
        "email": get_input("Email"),
        "voivodeshipCode": voiv_code,
        "voivodeship": voiv_name,
    }


# -------------------------
# Login helper
# -------------------------

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
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2",
        "User-Agent": "Mozilla/5.0 (compatible; zprp-backend/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
    }

    async with httpx.AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
        headers=headers,
    ) as client:
        resp = await client.post("/login.php", content=body)

    html = _decode_html(resp)

    # Sukces: finalnie jesteśmy na /index.php (albo przynajmniej nie na login.php)
    if "/index.php" not in str(resp.url):
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
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Zalogowano, ale nie udało się odczytać judgeId (NrSedzia) z odpowiedzi",
        )

    return cookies, judge_id


# -------------------------
# Endpoints
# -------------------------

@router.post("/login", response_model=BazaWebLoginResponse)
async def baza_web_login(data: BazaWebLoginRequest, settings: Settings = Depends(get_settings)):
    try:
        _, judge_id = await _baza_login_and_get_cookies(
            username=data.username,
            password=data.password,
            settings=settings,
        )
        return {"success": True, "judge_id": judge_id}
    except HTTPException as e:
        return {"success": False, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "error": f"Błąd serwera: {e}"}


@router.post("/profile", response_model=BazaWebProfileResponse)
async def baza_web_profile(data: BazaWebProfileRequest, settings: Settings = Depends(get_settings)):
    """
    Pobiera dane profilu analogicznie do fetchJudgeProfile (frontend):
    - GET /index.php?a=sedzia&b=edycja&NrSedzia=...
    - wyciąga foto + pola formularza
    - województwo: code z input[name=woj], nazwa z tekstu w tym samym TD
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

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; zprp-backend/1.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
        }

        async with httpx.AsyncClient(
            base_url=settings.ZPRP_BASE_URL,
            follow_redirects=True,
            timeout=httpx.Timeout(60.0),
            cookies=cookies,
            headers=headers,
        ) as client:
            resp = await client.get(path)

        html = _decode_html(resp)

        # minimalna walidacja: czy to wygląda jak strona edycji profilu
        # (w praktyce zawiera pola Imie/Nazwisko/woj itd.)
        low = (html or "").lower()
        if ("name=imie" not in low and 'name="imie"' not in low) or ("name=nazwisko" not in low and 'name="nazwisko"' not in low):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Nie udało się pobrać strony profilu (nieoczekiwany HTML / brak pól formularza).",
            )

        base = settings.ZPRP_BASE_URL.rstrip("/") + "/"

        parsed = _parse_profile_fields(html)

        photo_src = parsed.get("photo_src", "") or ""
        photoUrl = _abs_url(base, photo_src) if photo_src else None

        profile = JudgeProfile(
            photoUrl=photoUrl,
            firstName=parsed.get("firstName", ""),
            middleName=parsed.get("middleName", ""),
            lastName=parsed.get("lastName", ""),
            maidenName=parsed.get("maidenName", ""),
            gender=parsed.get("gender", ""),
            birthDate=parsed.get("birthDate", ""),
            street=parsed.get("street", ""),
            postalCode=parsed.get("postalCode", ""),
            city=parsed.get("city", ""),
            voivodeship=parsed.get("voivodeship", ""),
            voivodeshipCode=parsed.get("voivodeshipCode", ""),
            phone=parsed.get("phone", ""),
            email=parsed.get("email", ""),
        )

        return {"success": True, "judge_id": judge_id, "profile": profile, "error": None}

    except HTTPException as e:
        return {"success": False, "error": str(e.detail), "judge_id": None, "profile": None}
    except Exception as e:
        return {"success": False, "error": f"Błąd serwera: {e}", "judge_id": None, "profile": None}
