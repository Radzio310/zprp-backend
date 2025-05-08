# app/results.py

import logging
from typing import Optional, Dict
from urllib.parse import urlencode, parse_qs
import base64

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from bs4 import BeautifulSoup
from httpx import AsyncClient

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from app.deps import get_settings, get_rsa_keys, Settings
from app.utils import fetch_with_correct_encoding

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Results"])


class ShortResultRequest(BaseModel):
    username: str    # Base64-RSA
    password: str    # Base64-RSA
    details_path: str
    wynik_gosp_pol: str
    wynik_gosc_pol: str
    wynik_gosp_full: str
    wynik_gosc_full: str
    dogrywka_karne_gosp: str
    dogrywka_karne_gosc: str
    karne_ile_gosp: str
    karne_bramki_gosp: str
    karne_ile_gosc: str
    karne_bramki_gosc: str
    timeout1_gosp_ii: str
    timeout1_gosp_ss: str
    timeout2_gosp_ii: str
    timeout2_gosp_ss: str
    timeout3_gosp_ii: str
    timeout3_gosp_ss: str
    timeout1_gosc_ii: str
    timeout1_gosc_ss: str
    timeout2_gosc_ii: str
    timeout2_gosc_ss: str
    timeout3_gosc_ii: str
    timeout3_gosc_ss: str
    widzowie: Optional[str] = ""


def _decrypt_field(enc_b64: str, private_key) -> str:
    """
    Odszyfrowuje pole zaszyfrowane RSA+Base64.
    """
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(
            cipher,
            padding.PKCS1v15()
        )
        return plain.decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Błąd deszyfrowania: {e}")


async def _login_and_client(user: str, pwd: str, settings: Settings) -> AsyncClient:
    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    )
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user, "haslo": pwd, "from": "/index.php?"},
    )
    if "/index.php" not in resp_login.url.path:
        await client.aclose()
        logger.error("Logowanie nie powiodło się dla user %s", user)
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    client.cookies.update(resp_login.cookies)
    return client


async def _submit_short_result(
    client: AsyncClient,
    match_id: str,
    user: str,
    overrides: Dict[str, str],
) -> bool:
    # 1) Otwórz modal 'Wynik skrócony'
    initial_data = {
        "IdZawody": match_id,
        "akcja": "WynikSkrocony",
        "user": user,
    }
    _, html = await fetch_with_correct_encoding(
        client,
        "/zawody_WynikSkrocony.php",
        method="POST",
        data=initial_data,
    )
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"name": "zawody_WynikSkrocony"})
    if not form:
        return False

    # 2) Parsowanie pól formularza
    form_fields: Dict[str, str] = {}
    for inp in form.find_all(["input", "select", "textarea"]):
        name = inp.get("name")
        if not name:
            continue
        if inp.name == "select":
            opt = inp.find("option", selected=True)
            form_fields[name] = opt.get("value", "") if opt else ""
        elif inp.name == "textarea":
            form_fields[name] = inp.text or ""
        else:
            form_fields[name] = inp.get("value", "") or ""

    # 3) Nadpisanie wybranych pól
    form_fields.update(overrides)

    # 4) Zatwierdzenie zmian
    body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"}
    resp = await client.request(
        "POST",
        "/zawody_WynikSkrocony.php",
        content=body.encode("ascii"),
        headers=headers,
        cookies=client.cookies,
    )

    text = resp.content.decode("iso-8859-2", errors="replace")
    if resp.status_code != 200:
        raise RuntimeError(f"Błąd HTTP {resp.status_code}: {text[:200]}")

    # jeżeli pojawił się komunikat „Zapisano zmiany” → sukces
    return "Zapisano zmiany" in text


@router.post(
    "/judge/results/short",
    summary="Zapisz wynik skrócony meczu",
)
async def short_result(
    req: ShortResultRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),       # tu pobieramy (private_key, public_key)
):
    private_key, _ = keys
    # 1) odszyfruj login i hasło
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)

    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            # 2) Wejdź na stronę szczegółów meczu
            details_url = f"/index.php?{req.details_path}"
            resp, html = await fetch_with_correct_encoding(
                client,
                details_url,
                method="GET",
                cookies=client.cookies,
            )
            soup = BeautifulSoup(html, "html.parser")

            # 3) sprawdź dostępność przycisku/modalu
            if not soup.find("button", class_="przycisk3", string="Wynik skrócony"):
                return {"success": False, "error": "Wynik skrócony niedostępny"}

            # 4) Wyciągnij IdZawody
            params = parse_qs(req.details_path)
            match_id = params.get("IdZawody", [None])[0]
            if not match_id:
                raise HTTPException(400, "Brak parametru IdZawody w details_path")

            # 5) Przygotuj overrides (w tym wynik_bramki_* z wynik_*_full)
            overrides = {
                "wynik_gosp_pol": req.wynik_gosp_pol,
                "wynik_gosc_pol": req.wynik_gosc_pol,
                "wynik_gosp_full": req.wynik_gosp_full,
                "wynik_gosc_full": req.wynik_gosc_full,
                "wynik_bramki_gosp": req.wynik_gosp_full,
                "wynik_bramki_gosc": req.wynik_gosc_full,
                "dogrywka_karne_gosp": req.dogrywka_karne_gosp,
                "dogrywka_karne_gosc": req.dogrywka_karne_gosc,
                "karne_ile_gosp": req.karne_ile_gosp,
                "karne_bramki_gosp": req.karne_bramki_gosp,
                "karne_ile_gosc": req.karne_ile_gosc,
                "karne_bramki_gosc": req.karne_bramki_gosc,
                "timeout1_gosp_ii": req.timeout1_gosp_ii,
                "timeout1_gosp_ss": req.timeout1_gosp_ss,
                "timeout2_gosp_ii": req.timeout2_gosp_ii,
                "timeout2_gosp_ss": req.timeout2_gosp_ss,
                "timeout3_gosp_ii": req.timeout3_gosp_ii,
                "timeout3_gosp_ss": req.timeout3_gosp_ss,
                "timeout1_gosc_ii": req.timeout1_gosc_ii,
                "timeout1_gosc_ss": req.timeout1_gosc_ss,
                "timeout2_gosc_ii": req.timeout2_gosc_ii,
                "timeout2_gosc_ss": req.timeout2_gosc_ss,
                "timeout3_gosc_ii": req.timeout3_gosc_ii,
                "timeout3_gosc_ss": req.timeout3_gosc_ss,
                "widzowie": req.widzowie or ""
            }

            ok = await _submit_short_result(
                client,
                match_id=match_id,
                user=user_plain,
                overrides=overrides,
            )
        finally:
            await client.aclose()

        if not ok:
            return {"success": False, "error": "Zapis nie powiódł się"}
        return {"success": True}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("short_result error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się zapisać wyniku skróconego: {e}")
