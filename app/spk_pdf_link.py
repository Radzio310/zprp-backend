# app/spk_pdf_link.py
#
# Podpisany adres materiału szkoleniowego - żeby PDF pobierał się tak, jak
# pobiera się protokół meczu.
#
# PO CO TO POWSTAŁO. Trasa materiału jest dla administratora i sprawdza
# nagłówki aktora. Przeglądarka ani systemowy menedżer pobierania żadnych
# nagłówków nie niosą, więc `Linking.openURL` dostałby 403 - i dlatego aplikacja
# ściągała plik sama, do własnej pamięci podręcznej, a potem musiała pytać
# użytkownika o katalog. Cała reszta aplikacji robi to inaczej: protokół PDF
# oddaje ADRES, a plik ląduje w Pobranych bez jednego pytania.
#
# CO ZMIENIA TOKEN. Uprawnienie przestaje siedzieć w nagłówku, a zaczyna w
# adresie: panel prosi o link (i tam nagłówki są), serwer sprawdza, że prosi
# administrator, i podpisuje adres ważny przez kilka minut. Menedżer pobierania
# nie musi już nic wiedzieć o tożsamości.
#
# DLACZEGO TO NIE JEST DZIURA. Token żyje minuty, nie godziny, i otwiera
# WYŁĄCZNIE ten jeden materiał - nie jest tożsamością i nie da się nim zrobić
# nic poza pobraniem prezentacji, która i tak jest przeznaczona do pokazania
# całej sali. Osobna publiczność (`aud`) pilnuje, żeby token konta ProEl ani
# token sesji podniesionej nie otwierał tej trasy, i odwrotnie.
#
# TTL JEST KRÓTKI Z ROZMYSŁU. Adres trafia do systemowego menedżera pobierania,
# a stamtąd do historii pobrań i schowka - ma przestać działać, zanim ktokolwiek
# zdąży go wkleić gdzie indziej.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

#: Publiczność tokenu. MUSI być inna niż publiczność kont ProEl i sesji
#: podniesionej - wszystkie trzy podpisy schodzą tym samym sekretem.
TOKEN_AUDIENCE = "spk-pdf"

#: Dziesięć minut. Tyle, żeby starczyło na kliknięcie i pobranie na słabej
#: sieci, i nie więcej - adres zostaje potem w historii pobrań.
_DEFAULT_TTL_SECONDS = 10 * 60


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _secret() -> str:
    """Ten sam łańcuch co przy pozostałych tokenach - świadomie.

    Osobny sekret znaczyłby osobną zmienną do ustawienia na produkcji, a jej
    brak objawiłby się dopiero przy pierwszym pobraniu materiału. Rozdzielenie
    zapewnia `aud`, sprawdzane twardo przy weryfikacji.
    """
    for key in ("PROEL_AUTH_SECRET", "SECRET_KEY"):
        value = os.getenv(key, "").strip()
        if value:
            return value
    return "CHANGE_ME_PROEL_AUTH_SECRET"


def _ttl_seconds() -> int:
    raw = os.getenv("SPK_PDF_LINK_TTL_SECONDS", "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else _DEFAULT_TTL_SECONDS


def create_pdf_token(issued_by: str = "", *, ttl_seconds: Optional[int] = None) -> str:
    """Token = payload_b64.sig_b64; payload {by, iat, exp, v, aud}.

    `by` jest ZAPISEM AUDYTOWYM, nie warunkiem - mówi, kto poprosił o adres.
    Trasa materiału nie pyta o nic więcej, bo token otwiera jeden konkretny
    plik i nic poza nim.
    """
    now = int(time.time())
    payload = {
        "by": str(issued_by or "").strip(),
        "iat": now,
        "exp": now + int(ttl_seconds or _ttl_seconds()),
        "v": 1,
        "aud": TOKEN_AUDIENCE,
    }
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    sig = hmac.new(
        _secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
    ).digest()
    return payload_b64 + "." + _b64url_encode(sig)


def token_expires_at(token: str) -> int:
    """`exp` bez weryfikacji podpisu - do pokazania, nie do decydowania."""
    try:
        payload_b64, _ = token.split(".", 1)
        return int(json.loads(_b64url_decode(payload_b64).decode("utf-8"))["exp"])
    except Exception:  # noqa: BLE001
        return 0


def verify_pdf_token(token: str) -> Optional[Dict[str, Any]]:
    """Payload przy ważnym tokenie, `None` przy każdym innym.

    Tu `None` znaczy odmowę na serio - inaczej niż przy sesji podniesionej,
    gdzie token jest dodatkiem do tożsamości. Ten token JEST całym
    uprawnieniem, więc wygasły nie ma na co spaść.
    """
    raw = str(token or "").strip()
    if not raw:
        return None
    try:
        payload_b64, sig_b64 = raw.split(".", 1)
    except ValueError:
        return None

    expected = hmac.new(
        _secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(_b64url_encode(expected), sig_b64):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None

    if not isinstance(payload, dict):
        return None
    if payload.get("aud") != TOKEN_AUDIENCE:
        return None
    if int(time.time()) >= int(payload.get("exp") or 0):
        return None
    return payload
