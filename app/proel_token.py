# app/proel_token.py
#
# Włączanie i wyłączanie tokenu ProEl dla pojedynczego meczu.
#
# Na stronie ZPRP (lista meczów sędziego) przy numerze meczu stoi checkbox
# „Włącz / Wyłącz ProEl". Jego `onclick` woła `zapiszProtok3(IdZawody,'ProEl',
# this.value, this.checked)` z `zawody_zapisz3.js`, a ta funkcja robi zwykły
# POST formularzowy:
#
#     POST /zawody_zapisz3.php
#     ad1=<IdZawody>&ad2=ProEl&ad3=1&ad4=<true|false>&sid=<losowe>
#
# Odpowiedź jest tekstowa: "OK|<TOKEN>" przy powodzeniu (przy wyłączeniu token
# jest pusty), "ERROR..." przy odmowie. Strona rozcina ją po „|" i wstawia
# drugą część do <span id="token_proel_<IdZawody>">.
#
# Robimy to po stronie serwera, tak samo jak edycję danych sędziego i zapis
# niedyspozycyjności: aplikacja przysyła zaszyfrowane RSA poświadczenia, serwer
# loguje się do ZPRP i wykonuje akcję. Dzięki temu telefon nie musi trzymać
# żywej sesji ZPRP, a uprawnienia rozstrzyga sam ZPRP - jeśli sędzia nie ma
# prawa ruszyć tego meczu, dostaniemy stamtąd ERROR i tak to zwrócimy.

import base64
import random

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import get_settings, Settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding

router = APIRouter()


class ProelTokenRequest(BaseModel):
    #: Base64-RSA, jak w pozostałych akcjach idących przez serwer.
    username: str
    password: str
    judge_id: str
    #: `IdZawody` z listy meczów - jawne, to nie jest tajemnica.
    match_id: str
    #: Czy token ma być włączony.
    enabled: bool


@router.post("/match/proel")
async def set_match_proel(
    data: ProelTokenRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    def decrypt_field(enc_b64: str) -> str:
        cipher = base64.b64decode(enc_b64)
        return private_key.decrypt(cipher, padding.PKCS1v15()).decode("utf-8")

    try:
        user_plain = decrypt_field(data.username)
        pass_plain = decrypt_field(data.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    match_id = (data.match_id or "").strip()
    if not match_id.isdigit():
        raise HTTPException(400, "match_id musi być numerem IdZawody")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
    ) as client:
        resp_login, _ = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={
                "login": user_plain,
                "haslo": pass_plain,
                "from": "/index.php?",
            },
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        cookies = dict(resp_login.cookies)

        # `ad4` jedzie jako "true"/"false", bo strona wysyła tam wprost
        # javascriptowy `this.checked`. `sid` to cache-buster oryginału -
        # zostaje, żeby żądanie było nieodróżnialne od tego z przeglądarki.
        _, body = await fetch_with_correct_encoding(
            client,
            "/zawody_zapisz3.php",
            method="POST",
            data={
                "ad1": match_id,
                "ad2": "ProEl",
                "ad3": "1",
                "ad4": "true" if data.enabled else "false",
                "sid": str(random.random()),
            },
            cookies=cookies,
        )

    text = (body or "").strip()
    if not text.upper().startswith("OK"):
        # ZPRP odmówił - oddajemy jego własną odpowiedź, zamiast zgadywać.
        raise HTTPException(
            502,
            f"ZPRP nie przyjął zmiany ProEl: {text[:200] or 'pusta odpowiedź'}",
        )

    parts = text.split("|")
    token = parts[1].strip() if len(parts) > 1 else ""

    # Token przychodzi TYLKO przy włączaniu. Przy wyłączaniu strona czyści
    # miejsce na token, więc pusty ciąg jest tu poprawną odpowiedzią, a nie
    # brakiem danych.
    return {
        "success": True,
        "enabled": bool(data.enabled),
        "token": token if data.enabled else "",
    }
