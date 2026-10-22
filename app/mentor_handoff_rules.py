"""
Panel „Mentor" - przesiadka z telefonu na komputer (reguły bez bazy i sieci).

Ekran „Mentor najlepiej działa na komputerze" (BAZA_web, telefon w przeglądarce)
daje trzy drogi na duży ekran:
  - mail z linkiem na adres z konta (`POST /mentor-panel/handoff/email`),
  - krótki adres do przepisania: `bazapodreka.app/m/7K2Q`
    (`POST /mentor-panel/handoff/short`, `GET /mentor-panel/handoff/short/{kod}`),
  - zwykły pełny link (bez serwera).

Kod: 4 znaki z alfabetu bez znaków mylących przy przepisywaniu (0/O, 1/I/L),
ważny 24 h. Skrót prowadzi WYŁĄCZNIE do panelu pary (`/mentor/...`) - nigdy do
publicznego klipu (`/mentor/k|z|r/...`) ani do zatwierdzania logowania, więc
odgadnięty kod nie odsłania niczego bez zalogowania.
"""

from __future__ import annotations

import re
import secrets
from datetime import timedelta
from typing import Optional

ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_LEN = 4
SHORT_TTL = timedelta(hours=24)
#: Ten sam adres w tym oknie dostaje ten sam kod (odświeżenie ekranu nie mnoży kodów).
REUSE_WINDOW = timedelta(hours=12)
WEB_HOST = "bazapodreka.app"
WEB_ORIGIN = "https://www.bazapodreka.app"
MAX_PATH = 400

_RESERVED = {"k", "z", "r", "zaloguj"}
_PATH_RE = re.compile(r"^/mentor(?:/[A-Za-z0-9._~%-]+)*/?(?:\?[A-Za-z0-9._~%&=-]*)?$")


class HandoffError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def new_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN))


def normalize_code(raw: object) -> Optional[str]:
    """Kod wpisany ręcznie: wielkość liter i spacje bez znaczenia. Zły kształt = None."""
    text = re.sub(r"[\s-]+", "", str(raw or "")).upper()
    if len(text) != CODE_LEN:
        return None
    if any(ch not in ALPHABET for ch in text):
        return None
    return text


def clean_path(raw: object) -> str:
    """Ścieżka panelu do skrótu albo maila. Tylko panel pary, bez domeny."""
    path = str(raw or "").strip()
    if not path or len(path) > MAX_PATH or "//" in path or not _PATH_RE.match(path):
        raise HandoffError(400, "BAD_PATH", "Tego adresu nie da się przenieść na komputer.")
    parts = path.split("?", 1)[0].split("/")
    if len(parts) > 2 and parts[2] in _RESERVED:
        raise HandoffError(400, "BAD_PATH", "Publiczne strony otwierają się na telefonie - nie trzeba ich przenosić.")
    return path.rstrip("/") if path.endswith("/") and "?" not in path else path


def full_url(path: str) -> str:
    return f"{WEB_ORIGIN}{path}"


def short_label(code: str) -> str:
    """To, co człowiek przepisuje: bez https i www."""
    return f"{WEB_HOST}/m/{code}"


def mask_email(address: str) -> str:
    """`radoslaw@ovoo.pl` -> `r•••••w@ovoo.pl` - telefon pokazuje, DOKĄD poszło, nie cały adres."""
    address = (address or "").strip()
    if "@" not in address:
        return ""
    local, domain = address.split("@", 1)
    if len(local) <= 2:
        return f"{local[:1]}•••@{domain}"
    return f"{local[0]}{'•' * min(5, len(local) - 2)}{local[-1]}@{domain}"


def email_content(path: str, code: Optional[str], name: str) -> tuple[str, str, str]:
    """Temat, HTML i tekst listu „link na komputer". Kolory = koral Mentora (mentorCoral)."""
    import html

    url = full_url(path)
    hello = f"Cześć {name.split()[0]}," if name.strip() else "Cześć,"
    subject = "Mentor - otwórz panel na komputerze"
    short = short_label(code) if code else ""
    text = (
        f"{hello}\n\nPanel Mentor najlepiej działa na komputerze. Otwórz ten adres w przeglądarce:\n{url}\n"
        + (f"\nAlbo wpisz krótko: {short} (ważne 24 h)\n" if short else "")
        + "\nList wysłany z telefonu na Twoją prośbę."
    )
    e = lambda v: html.escape(str(v), quote=True)  # noqa: E731
    short_html = (
        f'<p style="margin:18px 0 0;color:#665A56;font-size:13px">Albo wpisz krótko: '
        f'<b style="color:#1B1716;letter-spacing:1px">{e(short)}</b> (ważne 24 h)</p>'
        if short
        else ""
    )
    body = (
        '<div style="background:#FAF6F4;padding:28px 12px;font-family:Arial,Helvetica,sans-serif">'
        '<div style="max-width:520px;margin:auto;background:#FFFFFF;border:1px solid #ECE2DE;border-radius:16px;padding:28px">'
        '<div style="height:4px;width:56px;background:#FF7A59;border-radius:4px;margin-bottom:18px"></div>'
        f'<h2 style="margin:0 0 6px;color:#C2410C;font-size:22px">Mentor na dużym ekranie</h2>'
        f'<p style="margin:0 0 18px;color:#1B1716;font-size:15px;line-height:1.5">{e(hello)} oto link do miejsca, '
        "które było otwarte na telefonie. Wideo, oś zdarzeń i skróty klawiszowe czekają na komputerze.</p>"
        f'<a href="{e(url)}" style="display:inline-block;padding:13px 20px;background:#C2410C;color:#FFFFFF;'
        'text-decoration:none;border-radius:12px;font-weight:bold">Otwórz panel Mentor</a>'
        f'<p style="margin:16px 0 0;color:#A2938E;font-size:12px;word-break:break-all">{e(url)}</p>'
        f"{short_html}"
        "</div></div>"
    )
    return subject, body, text
