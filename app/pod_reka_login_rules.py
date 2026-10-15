"""Czyste reguły logowania BAZA pod RĘKĄ do baza.zprp.pl (bez sieci i bazy).

Taksonomia błędów (pole `code` w odpowiedzi, obok dotychczasowego `detail`):

* `bad_credentials`      401 - zły login/hasło (także hasło spoza ISO-8859-2),
* `rate_limited`         429 - za dużo prób z jednego adresu / dla jednego loginu,
* `upstream_unavailable` 503 - baza.zprp.pl nie odpowiada / zwraca 5xx,
* `unexpected_response`  502 - odpowiedź, której nie umiemy zinterpretować,
* `not_club_account`     403 - konto poprawne, ale nie klubowe (np. sędzia),
* `inactive_account`     403 - konto klubowe wyłączone,
* `no_teams`             403 - konto klubowe bez drużyn w zakresie,
* `session_expired`      401 - sesja BAZY wygasła po stronie ZPRP.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional
from urllib.parse import urlencode

LOGIN_ENCODING = "iso-8859-2"

STATUS_BY_CODE = {
    "bad_credentials": 401,
    "rate_limited": 429,
    "upstream_unavailable": 503,
    "unexpected_response": 502,
    "not_club_account": 403,
    "inactive_account": 403,
    "no_teams": 403,
    "session_expired": 401,
}

MESSAGES = {
    "bad_credentials": "Nieprawidłowy login lub hasło",
    "rate_limited": "Zbyt wiele prób logowania. Spróbuj ponownie za kilka minut",
    "upstream_unavailable": "baza.zprp.pl jest chwilowo niedostępna. Spróbuj ponownie za chwilę",
    "unexpected_response": "baza.zprp.pl odpowiedziała w nieoczekiwany sposób. Spróbuj ponownie lub zgłoś problem",
    "not_club_account": "To konto nie jest kontem klubowym. Zaloguj się kontem klubu lub trenera",
    "inactive_account": "Konto klubowe jest nieaktywne w bazie ZPRP",
    "no_teams": "Konto klubowe nie ma przypisanych drużyn",
    "session_expired": "Sesja w bazie ZPRP wygasła. Zaloguj się ponownie",
}


class LoginError(Exception):
    def __init__(self, code: str, message: Optional[str] = None):
        self.code = code
        self.status = STATUS_BY_CODE[code]
        self.message = message or MESSAGES[code]
        super().__init__(self.message)

    def body(self) -> dict[str, str]:
        # `detail` zostaje jak w całym API (string), `code` jest dodatkiem.
        return {"detail": self.message, "code": self.code}


def encode_login_form(username: str, password: str) -> str:
    """Formularz logowania w ISO-8859-2. Znak spoza strony kodowej to na pewno
    zły login/hasło (ZPRP i tak by go nie przyjęło), a nie błąd serwera."""
    try:
        return urlencode(
            {"login": username, "haslo": password, "from": "/index.php?"},
            encoding=LOGIN_ENCODING,
            errors="strict",
        )
    except UnicodeEncodeError as exc:
        raise LoginError("bad_credentials") from exc


def decode_html(content: bytes, content_type: str = "") -> str:
    """HTML wg deklarowanego charsetu; nieznana nazwa -> ISO-8859-2."""
    match = re.search(r"charset=([^;]+)", content_type or "", re.I)
    encoding = match.group(1).strip().strip("\"'") if match else LOGIN_ENCODING
    try:
        return content.decode(encoding, errors="replace")
    except LookupError:
        return content.decode(LOGIN_ENCODING, errors="replace")


def looks_like_login_page(html: str) -> bool:
    low = (html or "").lower()
    has_login = 'name="login"' in low or "name='login'" in low
    has_pass = 'name="haslo"' in low or "name='haslo'" in low
    return (has_login and has_pass) or re.search(r"<form[^>]+action=['\"]?login\.php", low) is not None


def classify_login_response(final_path: str, status_code: int, html: str) -> None:
    """Rzuca `LoginError`, gdy odpowiedź na POST /login.php nie jest sukcesem.

    Sukces = po przekierowaniach lądujemy w `/index.php` (tak samo jak w
    `app/auth.py` i `app/baza_web.py`)."""
    if status_code >= 500:
        raise LoginError("upstream_unavailable")
    if "/index.php" in (final_path or "") and not looks_like_login_page(html):
        return
    low = (html or "").lower()
    if (
        "nieznany" in low
        or "tkownik" in low
        or "ponownie" in low
        or (final_path or "").endswith("/login.php")
        or looks_like_login_page(html)
    ):
        raise LoginError("bad_credentials")
    raise LoginError("unexpected_response")


def merge_cookies(*sources: Mapping[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for source in sources:
        for key, value in dict(source).items():
            merged[str(key)] = str(value)
    return merged


def check_scope(scope: Mapping[str, Any], *, relogin_html: str = "") -> None:
    """Zakres konta (z `parse_club_scope`) musi być aktywnym kontem klubowym."""
    if relogin_html and looks_like_login_page(relogin_html):
        raise LoginError("session_expired")
    if scope.get("account_type") != "club":
        raise LoginError("not_club_account")
    if not scope.get("active"):
        raise LoginError("inactive_account")
    if not scope.get("club_id") or not scope.get("team_ids"):
        raise LoginError("no_teams")


class AttemptLimiter:
    """Okno przesuwne nieudanych prób (po adresie i po loginie)."""

    def __init__(self, limit: int = 5, window: timedelta = timedelta(minutes=10), max_keys: int = 5000):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._attempts: dict[str, list[datetime]] = {}

    def _recent(self, key: str, now: datetime) -> list[datetime]:
        return [t for t in self._attempts.get(key, []) if t > now - self.window]

    def blocked(self, *keys: str, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return any(len(self._recent(k, now)) >= self.limit for k in keys if k)

    def fail(self, *keys: str, now: Optional[datetime] = None) -> None:
        now = now or datetime.now(timezone.utc)
        if len(self._attempts) > self.max_keys:
            self._attempts = {k: v for k in list(self._attempts) if (v := self._recent(k, now))}
        for key in keys:
            if key:
                self._attempts[key] = [*self._recent(key, now), now]

    def success(self, *keys: str) -> None:
        for key in keys:
            self._attempts.pop(key, None)


def client_key(forwarded_for: str, peer: str) -> str:
    """Adres klienta: pierwszy hop z X-Forwarded-For (Railway), inaczej peer."""
    first = (forwarded_for or "").split(",")[0].strip()
    return first or peer or "unknown"
