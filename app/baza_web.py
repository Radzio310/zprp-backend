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
    # np. "foto_sedzia/5124.jpg?m=..."
    return base.rstrip("/") + "/" + maybe_rel.lstrip("./")


def _detect_encoding(resp: httpx.Response, default: str = "iso-8859-2") -> str:
    ct = resp.headers.get("content-type", "") or ""
    m = re.search(r"charset=([^;]+)", ct, re.I)
    if m:
        return m.group(1).strip().lower()

    head = resp.content[:4096]
    try:
        head_txt = head.decode("utf-8", errors="ignore")
    except Exception:
        head_txt = ""

    mm = re.search(
        r'<meta\s+[^>]*charset=["\']?([a-zA-Z0-9\-_]+)["\']?',
        head_txt,
        re.I,
    )
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
# Robust HTML parser (radio/select/hidden + woj TD text)
# -------------------------

class _BazaProfileFormParser(HTMLParser):
    """
    Parsuje:
    - input[name] -> value (UWAGA: radio: bierzemy TYLKO checked)
    - select[name] -> tekst option selected (gdyby kiedyś było)
    - img src zawierające "foto_sedzia/"
    - tekst w <td> zawierającym input[name=woj] (żeby wyciągnąć "ŚLĄSKIE")
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)

        self.inputs: dict[str, str] = {}
        self.select_selected_text: dict[str, str] = {}

        self._in_select = False
        self._select_name: str | None = None
        self._in_option = False
        self._option_selected = False
        self._option_text_buf: list[str] = []

        self.photo_src: str = ""

        # voivodeship: TD containing input[name=woj]
        self._td_depth = 0
        self._td_has_woj_input = False
        self._td_text_buf: list[str] = []
        self.woj_td_text: str = ""

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in attrs:
            if not k:
                continue
            out[k.lower()] = v if v is not None else ""
        return out

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        a = self._attrs(attrs)

        if tag_l == "td":
            self._td_depth += 1
            self._td_has_woj_input = False
            self._td_text_buf = []

        if tag_l == "img" and not self.photo_src:
            src = (a.get("src") or "").strip()
            if "foto_sedzia/" in src:
                self.photo_src = src

        if tag_l == "input":
            name = (a.get("name") or "").strip()
            if not name:
                return

            itype = (a.get("type") or "").strip().lower()
            val = _clean(a.get("value") or "")

            # RADIO: zapisuj tylko jeśli checked, a jeśli już mamy checked – nie nadpisuj
            if itype == "radio":
                is_checked = "checked" in a
                if is_checked:
                    self.inputs[name] = val
                else:
                    # jeśli jeszcze nie ma nic dla tej grupy – nie ustawiaj na siłę,
                    # bo RN bierze faktycznie zaznaczone (checked)
                    pass
            else:
                # normalne inputy (text/hidden itd.) – można nadpisywać
                self.inputs[name] = val

            if name == "woj" and self._td_depth > 0:
                self._td_has_woj_input = True

        if tag_l == "select":
            name = (a.get("name") or "").strip()
            if name:
                self._in_select = True
                self._select_name = name

        if tag_l == "option" and self._in_select and self._select_name:
            self._in_option = True
            self._option_selected = "selected" in a
            self._option_text_buf = []

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()

        if tag_l == "option" and self._in_option:
            opt_text = _clean("".join(self._option_text_buf))
            if self._select_name and self._option_selected:
                self.select_selected_text[self._select_name] = opt_text
            self._in_option = False
            self._option_selected = False
            self._option_text_buf = []

        if tag_l == "select":
            self._in_select = False
            self._select_name = None

        if tag_l == "td":
            if self._td_depth > 0:
                self._td_depth -= 1

            if self._td_has_woj_input:
                self.woj_td_text = _clean("".join(self._td_text_buf))

            self._td_has_woj_input = False
            self._td_text_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_option:
            self._option_text_buf.append(data)

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

    def get_select_selected_text(name: str) -> str:
        return _clean(p.select_selected_text.get(name, ""))

    # gender: w Twoim HTML to RADIO, więc będzie w inputs["Plec"] jeśli zaznaczone
    gender = get_input("Plec") or get_select_selected_text("Plec")

    voivodeshipCode = get_input("woj")

    # voivodeship name z tekstu w tym samym TD po input[name=woj]
    woj_td = _clean(p.woj_td_text)
    voivodeship = ""
    if woj_td:
        # W przykładzie: "ŚLĄSKIE Zmiana możliwa z panelu ..."
        # weź pierwsze "caps" słowo/ciąg (ŚLĄSKIE, MAZOWIECKIE, itp.)
        m = re.search(r"([A-ZĄĆĘŁŃÓŚŹŻ][A-ZĄĆĘŁŃÓŚŹŻ\- ]{2,})", woj_td)
        voivodeship = _clean(m.group(1)) if m else woj_td

    # fallback: gdyby kiedyś woj było selectem
    if not voivodeship:
        voivodeship = get_select_selected_text("woj")

    return {
        "photo_src": (p.photo_src or "").strip(),
        "firstName": get_input("Imie"),
        "middleName": get_input("Imie2"),
        "lastName": get_input("Nazwisko"),
        "maidenName": get_input("NazwiskoRodowe"),
        "gender": gender,
        "birthDate": get_input("DataUr"),
        "street": get_input("Ulica"),
        "postalCode": get_input("KodPocztowy"),
        "city": get_input("Miasto"),
        "phone": get_input("Telefon"),
        "email": get_input("Email"),
        "voivodeship": voivodeship,
        "voivodeshipCode": voivodeshipCode,
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
async def baza_web_login(
    data: BazaWebLoginRequest,
    settings: Settings = Depends(get_settings),
):
    try:
        _, judge_id = await _baza_login_and_get_cookies(
            username=data.username,
            password=data.password,
            settings=settings,
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
    Pobiera dane profilu analogicznie do fetchJudgeProfile z RN:
    - GET /index.php?a=sedzia&b=edycja&NrSedzia=...
    - foto: img[src^="foto_sedzia/"]
    - pola: input[name=Imie], Imie2, Nazwisko, ... itd.
    - Plec: RADIO -> bierz checked
    - województwo: input[name=woj] (hidden) + tekst w tym samym TD
    """
    try:
        cookies, judge_id_from_login = await _baza_login_and_get_cookies(
            username=data.username,
            password=data.password,
            settings=settings,
        )
        judge_id = (data.judge_id or judge_id_from_login).strip() or judge_id_from_login

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

        # Zamiast wadliwej walidacji "name=imie" (case/quote sensitive),
        # parsujemy i walidujemy wynik.
        parsed = _parse_profile_fields(html)

        # twarda walidacja: jeśli nic sensownego nie przyszło, to to nie jest strona profilu
        # (np. logout, błąd sesji, jakaś strona pośrednia).
        signal_fields = [
            parsed.get("firstName", ""),
            parsed.get("lastName", ""),
            parsed.get("birthDate", ""),
            parsed.get("email", ""),
            parsed.get("city", ""),
            parsed.get("street", ""),
            parsed.get("postalCode", ""),
        ]
        if not any(_clean(x) for x in signal_fields):
            # Dodatkowo: jeśli HTML wygląda jak ekran logowania/wylogowania
            low = (html or "").lower()
            if "login.php" in low or "wyloguj" in low and "haslo" in low:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Sesja do bazy nieaktywna lub przekierowanie do logowania",
                )

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Nie udało się pobrać strony profilu (HTML nie zawiera danych formularza).",
            )

        base = settings.ZPRP_BASE_URL.rstrip("/") + "/"

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
        return {"success": False, "judge_id": None, "profile": None, "error": str(e.detail)}
    except Exception as e:
        return {"success": False, "judge_id": None, "profile": None, "error": f"Błąd serwera: {e}"}
