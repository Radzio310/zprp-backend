# app/password_change.py

import logging
from typing import Optional
from urllib.parse import urlencode
import base64

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from bs4 import BeautifulSoup
from httpx import AsyncClient

from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import get_settings, get_rsa_keys, Settings
from app.utils import fetch_with_correct_encoding

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Account"])


class ChangePasswordRequest(BaseModel):
    # wszystkie pola RSA+Base64 (tak jak w short_result)
    username: str       # Base64-RSA (login)
    password: str       # Base64-RSA (stare hasło – do zalogowania)
    new_password: str   # Base64-RSA (NOWE hasło – do ustawienia na koncie)
    # opcjonalnie: podmiana telefonu/email; jeśli brak → użyj tego, co jest już w formularzu
    phone: Optional[str] = None
    email: Optional[str] = None


def _decrypt_field(enc_b64: str, private_key) -> str:
    """
    Odszyfrowuje pole zaszyfrowane RSA+Base64.
    """
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding.PKCS1v15())
        return plain.decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Błąd deszyfrowania: {e}")


def _is_login_page(html: str) -> bool:
    """
    Rozpoznaje klasyczny ekran logowania baza.zprp.pl (ten z formularzem login/haslo).

    Używane:
    - przy próbie logowania,
    - przy sprawdzaniu, czy po POST zmiany hasła nie wróciliśmy na ekran logowania.
    """
    soup = BeautifulSoup(html, "html.parser")
    # dokładnie taki formularz, jak wkleiłeś: <form method='POST' action='login.php'>
    form = soup.find("form", {"action": "login.php"})
    if not form:
        return False

    has_login_input = bool(form.find("input", {"name": "login"}))
    has_password_input = bool(
        form.find("input", {"name": "haslo", "type": "password"})
    )
    return has_login_input and has_password_input


async def _login_and_client(user: str, pwd: str, settings: Settings) -> AsyncClient:
    """
    Loguje do baza.zprp.pl i zwraca AsyncClient z ustawioną sesją.

    Sukces = HTML NIE jest stroną logowania (_is_login_page(html) == False),
    co pokrywa zarówno:
    - zwykłe wejście na /index.php,
    - przypadek wymuszonej zmiany hasła (index.php?a=konto).
    """
    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
    )

    resp_login, html = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user, "haslo": pwd, "from": "/index.php?"},
    )

    logger.info(
        "ZPRP login attempt user=%s -> final_url=%s status=%s",
        user,
        resp_login.url,
        resp_login.status_code,
    )

    # Jeśli po POST dalej widzimy ekran logowania → hasło/login złe / brak sesji
    if _is_login_page(html):
        await client.aclose()
        logger.error(
            "Logowanie nie powiodło się (pozostał ekran logowania) dla user %s",
            user,
        )
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")

    # W tym miejscu zakładamy, że jesteśmy już zalogowani
    client.cookies.update(resp_login.cookies)
    return client


async def _submit_password_change(
    client: AsyncClient,
    new_password: str,
    phone: Optional[str],
    email: Optional[str],
) -> bool:
    """
    Otwiera stronę ?a=konto, parsuje formularz i wysyła POST z nowym hasłem
    (i ewentualnie zaktualizowanym telefonem/email).

    Sukces rozpoznajemy po TYM, ŻE PO POST dostajemy HTML ekranu logowania
    (czyli użytkownik został wylogowany, a przeglądarka pokazuje formularz login/haslo),
    niezależnie od tego, jaki dokładnie jest URL (może to być 'baza.zprp.pl', '/index.php', itd.).
    """
    # 1) Pobierz stronę konta
    resp, html = await fetch_with_correct_encoding(
        client,
        "/index.php?a=konto",
        method="GET",
        cookies=client.cookies,
    )
    soup = BeautifulSoup(html, "html.parser")

    # 2) Znajdź formularz z akcją '?a=konto'
    form = soup.find("form", {"action": "?a=konto"})
    if not form:
        # fallback: pierwszy formularz zawierający pole 'haslo'
        for candidate in soup.find_all("form"):
            if candidate.find("input", {"name": "haslo"}):
                form = candidate
                break

    if not form:
        logger.error("Nie znaleziono formularza zmiany hasła na stronie konta")
        return False

    # 3) Zbuduj słownik pól formularza, emulując przeglądarkę (bez disabled)
    form_fields = {}

    for inp in form.find_all(["input", "select", "textarea"]):
        name = inp.get("name")
        if not name:
            continue

        # emulate HTML: disabled pola NIE są wysyłane
        if inp.has_attr("disabled"):
            continue

        tag_name = inp.name

        if tag_name == "select":
            opt = inp.find("option", selected=True)
            form_fields[name] = opt.get("value", "") if opt else ""
        elif tag_name == "textarea":
            form_fields[name] = inp.text or ""
        else:
            input_type = (inp.get("type") or "").lower()

            # checkbox/radio – tylko jeśli checked
            if input_type in ["checkbox", "radio"]:
                if inp.has_attr("checked"):
                    form_fields[name] = inp.get("value", "on")
                continue
            else:
                form_fields[name] = inp.get("value", "") or ""

    # 4) Nadpisz pola, które nas interesują:
    #    • nowe hasło w polu 'haslo'
    #    • Telefon / Email, jeśli zostały przekazane z requestu
    form_fields["haslo"] = new_password

    if phone is not None:
        form_fields["Telefon"] = phone

    if email is not None:
        form_fields["Email"] = email

    # 5) Wyślij POST dokładnie tak, jak robi to short_result (ISO-8859-2 + ASCII)
    body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"
    }

    resp_post = await client.request(
        "POST",
        "/index.php?a=konto",
        content=body.encode("ascii", errors="replace"),
        headers=headers,
        cookies=client.cookies,
    )

    text = resp_post.content.decode("iso-8859-2", errors="replace")

    if resp_post.status_code != 200:
        raise RuntimeError(f"Błąd HTTP {resp_post.status_code}: {text[:200]}")

    # 6) Heurystyka sukcesu:
    #    ✅ Sukces: po POST dostajemy ekran logowania (ten, którego HTML wkleiłeś),
    #       niezależnie od tego, czy URL to 'baza.zprp.pl', '/', '/index.php', itd.
    if _is_login_page(text):
        logger.info(
            "Hasło zmienione – po POST wylądowaliśmy na ekranie logowania (formularz login/haslo)"
        )
        return True

    # jeżeli nie wylądowaliśmy na login page, uznaj jako failure;
    # w razie czego w logach masz finalny URL + kawałek HTML do diagnostyki
    logger.warning(
        "Nie udało się jednoznacznie potwierdzić zmiany hasła. "
        "final_url=%s status=%s",
        resp_post.url,
        resp_post.status_code,
    )
    return False


@router.post(
    "/judge/password/change",
    summary="Zmień hasło użytkownika w baza.zprp.pl",
)
async def change_password(
    req: ChangePasswordRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),  # (private_key, public_key)
):
    private_key, _ = keys

    # 1) Odszyfruj po stronie backendu login, stare hasło i nowe hasło
    user_plain = _decrypt_field(req.username, private_key)
    old_pass_plain = _decrypt_field(req.password, private_key)
    new_pass_plain = _decrypt_field(req.new_password, private_key)

    try:
        # 2) Zaloguj się do baza.zprp.pl na stare dane
        client = await _login_and_client(user_plain, old_pass_plain, settings)

        try:
            # 3) Zmień hasło (i ew. telefon/email)
            ok = await _submit_password_change(
                client,
                new_password=new_pass_plain,
                phone=req.phone,
                email=req.email,
            )
        finally:
            await client.aclose()

        if not ok:
            return {"success": False, "error": "Zmiana hasła nie powiodła się"}

        return {"success": True}

    except HTTPException:
        # przepuść dalej 401 itp.
        raise
    except Exception as e:
        logger.error("change_password error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Nie udało się zmienić hasła: {e}",
        )
