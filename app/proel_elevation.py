# app/proel_elevation.py
#
# Dowód, że przy TYM urządzeniu stoi TEN sędzia - na czas dokończenia protokołu.
#
# PO CO TO POWSTAŁO. Tożsamość piszącego rozstrzyga `proel_actor`: para
# `X-Judge-Id` + `X-Installation-Id` porównana z rejestrem urządzeń
# (`push_tokens`). Reguła jest asymetryczna i celowo ostra w jedną stronę - gdy
# instalacja jest zapisana na KOGO INNEGO, żądanie leci z 401 `ACTOR_MISMATCH`.
#
# I właśnie w to wpadała sesja podniesiona. Sędzia boiskowy kończy protokół na
# telefonie stolikowego: przedstawia się swoim numerem, ale instalacja należy do
# stolikowego, więc każdy jego zapis serwer odrzucał jako podszycie. Z punktu
# widzenia rejestru urządzeń wyglądało to dokładnie tak samo jak nadużycie -
# bo rejestr nie wiedział o niczym, co zaszło pomiędzy.
#
# CO ZMIENIA TOKEN. `/match/official-role` wydaje go dopiero po tym, jak sędzia
# zalogował się do baza.zprp.pl własnym hasłem. To jest dowód MOCNIEJSZY niż
# rejestr urządzeń, który token zastępuje: rejestr mówi „ten telefon kiedyś
# należał do tego numeru", a token mówi „ten numer podał przed chwilą swoje
# hasło do ZPRP". Dlatego przy ważnym tokenie pomijamy porównanie z rejestrem,
# zamiast osłabiać je dla wszystkich.
#
# CZEGO TOKEN NIE ROBI. Nie nadaje roli w meczu ani praw administratora -
# `roles_for` i `is_admin` liczą swoje dalej, tyle że od numeru, który token
# potwierdza. Token odpowiada WYŁĄCZNIE na pytanie „czy ten numer jest tu
# naprawdę", a nie „co temu numerowi wolno".
#
# ŻYCIE TOKENU jest krótkie z rozmysłu. Sesja podniesiona i tak ginie razem z
# ekranem podsumowania; token ma jej starczyć na jedno posiedzenie przy
# protokole, a nie zostać na telefonie stolikowego na resztę sezonu.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

#: Publiczność tokenu. MUSI być inna niż `TOKEN_AUDIENCE` kont ProEl: oba
#: podpisy schodzą (fallbackiem) tym samym sekretem, więc bez rozdzielenia
#: publiczności token konta ProEl uwierzytelniałby sesję podniesioną.
TOKEN_AUDIENCE = "proel-elev"

#: Sześć godzin. Tyle, żeby starczyło na dokończenie protokołu razem z przerwą
#: na dojazd i poprawki - i nie więcej, bo token zostaje na cudzym urządzeniu.
_DEFAULT_TTL_SECONDS = 6 * 60 * 60


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _secret() -> str:
    """Ten sam łańcuch co przy tokenach kont ProEl - świadomie.

    Osobny sekret znaczyłby osobną zmienną do ustawienia na produkcji, a jej
    brak objawiłby się dopiero w hali, przy pierwszej sesji podniesionej.
    Rozdzielenie zapewnia `aud`, sprawdzane twardo przy weryfikacji.
    """
    for key in ("PROEL_AUTH_SECRET", "SECRET_KEY"):
        value = os.getenv(key, "").strip()
        if value:
            return value
    # Ostatnia deska w dev — na produkcji `SECRET_KEY` jest wymagany przez
    # `Settings`, więc tu nie trafimy.
    return "CHANGE_ME_PROEL_AUTH_SECRET"


def _ttl_seconds() -> int:
    raw = os.getenv("PROEL_ELEVATION_TTL_SECONDS", "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else _DEFAULT_TTL_SECONDS


def create_elevation_token(
    judge_id: str,
    *,
    admin: bool = False,
    match_id: str = "",
    ttl_seconds: Optional[int] = None,
) -> str:
    """Token = payload_b64.sig_b64; payload {jid, adm, mid, iat, exp, v, aud}.

    `mid` jest ZAPISEM AUDYTOWYM, nie warunkiem: mówi, przy którym meczu ten
    numer się potwierdził, i tyle. Uprawnienie w innym meczu i tak liczy
    `roles_for` od nowa, a ten sam człowiek mógłby w każdej chwili potwierdzić
    się jeszcze raz - więc sprawdzanie `mid` przy zapisie niczego by nie
    zamykało, a kosztowało przepięcie numeru meczu przez wszystkie trasy.
    """
    now = int(time.time())
    payload = {
        "jid": str(judge_id or "").strip(),
        "adm": bool(admin),
        "mid": str(match_id or "").strip(),
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
    return f"{payload_b64}.{_b64url_encode(sig)}"


def token_expires_at(token: str) -> int:
    """`exp` bez weryfikacji podpisu - do pokazania, nie do decydowania."""
    try:
        payload_b64, _ = token.split(".", 1)
        return int(json.loads(_b64url_decode(payload_b64).decode("utf-8"))["exp"])
    except Exception:  # noqa: BLE001
        return 0


def verify_elevation_token(token: str) -> Optional[Dict[str, Any]]:
    """Payload przy ważnym tokenie, `None` przy każdym innym.

    ŚWIADOMIE BEZ WYJĄTKU. Ten token jest DODATKIEM do tożsamości, nie jej
    jedyną postacią: żądanie z tokenem wygasłym ma spaść do zwykłej ścieżki
    (numer sędziego + rejestr urządzeń), a nie polec na 401. Sędzia, któremu
    token wygasł przy własnym telefonie, nie ma prawa zobaczyć odmowy.
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
    jid = str(payload.get("jid") or "").strip()
    if not jid:
        return None
    if int(time.time()) >= int(payload.get("exp") or 0):
        return None
    return payload
