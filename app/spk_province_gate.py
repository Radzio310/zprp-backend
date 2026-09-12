# app/spk_province_gate.py
#
# Rygiel na wynikach okręgu: hasło, którym sędzia otwiera wyniki SWOJEGO
# okręgu w aplikacji.
#
# PO CO TO W OGÓLE. Do tej pory wyniki sprawdzianu widział wyłącznie
# administrator - taka była pierwotna decyzja i była słuszna, bo lista niesie
# nazwiska i liczby, które da się czytać jak ranking. Okręgi jednak same o nie
# pytają: to ICH sędziowie i ich szkolenie. Rygiel jest odpowiedzią pośrednią:
# okręg decyduje, czy jego wyniki są otwarte, a hasło rozstrzyga, czy stoi
# przed nimi ktoś, komu je podano.
#
# HASŁO JEST LOSOWE, NIE Z WZORU. Wzór w rodzaju „slug okręgu + rok" byłby
# wygodny, ale każdy, kto raz go zobaczy, wchodzi do wszystkich szesnastu
# okręgów bez pytania - czyli rygiel udawałby zamek. Sześć znaków z alfabetu
# bez znaków mylących (bez O/0 i I/1/l, bo hasło podaje się przez telefon)
# daje ponad miliard kombinacji i nie da się go wydedukować. Administrator
# może je nadpisać własnym - to jego okręg i jego decyzja.
#
# PORÓWNANIE JEST NIECZUŁE NA WIELKOŚĆ LITER i na spacje. Hasło wędruje SMS-em,
# w wiadomości na grupie i przez telefon, a potem ktoś wpisuje je na klawiaturze
# telefonu z włączoną wielką literą na starcie. Odmowa za sam kształt zapisu
# byłaby odmową za nic.
#
# TOKEN ZAMIAST HASŁA W KAŻDYM ZAPYTANIU. Po sprawdzeniu hasła aplikacja dostaje
# podpisany token z nazwą okręgu w środku i nim pyta o wyniki. Dzięki temu hasło
# nie krąży przy każdym odświeżeniu listy, a okręgu nie da się podmienić w
# adresie - siedzi w podpisie. Osobna publiczność (`aud`) pilnuje, żeby token
# raportu PDF ani token konta ProEl nie otwierały tej trasy.
#
# TTL DŁUŻSZY NIŻ PRZY PDF-ie, I TO Z ROZMYSŁU. Adres PDF-a idzie do menedżera
# pobierania i historii przeglądarki, więc ma wygasnąć w minutach. Ten token
# siedzi w pamięci aplikacji i zastępuje hasło na czas oglądania wyników -
# wygaśnięcie po dwunastu godzinach znaczy „jutro wpisz jeszcze raz", a nie
# „wpisuj co dziesięć minut".

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional

#: Publiczność tokenu. MUSI być inna niż przy PDF-ach i przy kontach ProEl -
#: wszystkie podpisy schodzą tym samym sekretem, a rozdziela je właśnie `aud`.
TOKEN_AUDIENCE = "spk-province"

#: Dwanaście godzin - patrz nagłówek pliku.
_DEFAULT_TTL_SECONDS = 12 * 60 * 60

#: Alfabet bez znaków, które w podyktowanym haśle znaczą dwie rzeczy naraz:
#: O i zero, I oraz jedynka i małe L. Sześć znaków z tego zbioru to ponad
#: miliard kombinacji - nikt tego nie zgadnie, a da się to przeczytać przez
#: telefon bez literowania.
PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PASSWORD_LENGTH = 6


def generate_password() -> str:
    """Nowe hasło okręgu - losowe, nie z wzoru."""
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH))


def normalize_password(value: Any) -> str:
    """Hasło sprowadzone do postaci, w której je porównujemy.

    Wielkie litery i bez białych znaków w środku: hasło przechodzi przez SMS,
    grupę i rozmowę telefoniczną, więc „k7m2qx" i „K7M 2QX" to ten sam napis.
    """
    return "".join(str(value or "").split()).upper()


def passwords_match(given: Any, stored: Any) -> bool:
    """Czy podane hasło otwiera okręg. Puste zapisane = nie otwiera nic."""
    left = normalize_password(given)
    right = normalize_password(stored)
    if not left or not right:
        return False
    return hmac.compare_digest(left, right)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _secret() -> str:
    """Ten sam łańcuch co przy pozostałych tokenach - patrz `spk_pdf_link`."""
    for key in ("PROEL_AUTH_SECRET", "SECRET_KEY"):
        value = os.getenv(key, "").strip()
        if value:
            return value
    return "CHANGE_ME_PROEL_AUTH_SECRET"


def _ttl_seconds() -> int:
    raw = os.getenv("SPK_PROVINCE_TTL_SECONDS", "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else _DEFAULT_TTL_SECONDS


def create_province_token(
    province: str,
    issued_by: str = "",
    *,
    ttl_seconds: Optional[int] = None,
) -> str:
    """Token = payload_b64.sig_b64; payload {prov, by, iat, exp, v, aud}.

    `prov` JEST całym uprawnieniem: mówi, czyje wyniki wolno pokazać. `by` to
    zapis audytowy - kto poprosił - a nie warunek.
    """
    now = int(time.time())
    payload = {
        "prov": str(province or "").strip().upper(),
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


def verify_province_token(token: str) -> Optional[Dict[str, Any]]:
    """Payload przy ważnym tokenie, `None` przy każdym innym.

    `None` znaczy odmowę na serio: ten token JEST całym uprawnieniem do cudzych
    wyników, więc wygasły nie ma na co spaść.
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
    if not str(payload.get("prov") or "").strip():
        return None
    if int(time.time()) >= int(payload.get("exp") or 0):
        return None
    return payload
