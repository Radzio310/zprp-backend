"""Grafiki i nadawcy maili BAZY (Brevo).

Szary ludzik obok nadawcy w Gmailu to zdjęcie przypisane do ADRESU nadawcy -
treść maila go nie zmieni. Decyzja (30.09.2026): zamiast tego grafika w samej
treści maila, w nagłówku:
  - kolizja niedyspozycyjności z obsadą centralną: `obsi.png`,
  - pozostałe maile BAZY: `bazus.png`.

Pliki leżą w repozytorium (`app/mail_assets`), a nie w `/static` - ten na
Railway jest wolumenem i nie widzi plików z wdrożenia. Trasa ma listę
dozwolonych nazw, więc nie da się nią czytać innych plików.

Nadawcy: niedyspozycje centralne domyślnie z `niedyspo@catchapp.com.pl`
(adres i tak ustawia admin w panelu), reszta BAZY z `BAZA_SENDER_EMAIL`,
a bez niej - dotychczasowym `BREVO_FROM_EMAIL`. Adres musi być zweryfikowany
w Brevo, dlatego nowy nadawca wchodzi dopiero po ustawieniu zmiennej.

Moduł-liść: bez `app.db`, testowalny bez bazy.
"""

from __future__ import annotations

import html
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

ASSETS_DIR = Path(__file__).resolve().parent / "mail_assets"
ALLOWED_ASSETS = frozenset({"obsi.png", "bazus.png"})
DEFAULT_BACKEND_URL = "https://zprp-backend-production.up.railway.app"

NIEDYSPO_SENDER_EMAIL = "niedyspo@catchapp.com.pl"
BAZA_SENDER_ENV = "BAZA_SENDER_EMAIL"

router = APIRouter(tags=["Maile: grafiki"])


def backend_url() -> str:
    return (os.getenv("BACKEND_URL") or DEFAULT_BACKEND_URL).strip().rstrip("/")


def mail_asset_url(name: str) -> str:
    if name not in ALLOWED_ASSETS:
        raise ValueError(f"Nieznana grafika maila: {name}")
    return f"{backend_url()}/mail-assets/{name}"


def brand_image(name: str, size: int = 56, alt: str = "BAZA", radius: int | None = None) -> str:
    """`<img>` do nagłówka maila - wymiary w atrybutach, bo Outlook ignoruje CSS."""
    r = size // 4 if radius is None else radius
    return (
        f'<img src="{html.escape(mail_asset_url(name))}" width="{size}" height="{size}" '
        f'alt="{html.escape(alt)}" style="display:block;width:{size}px;height:{size}px;'
        f'border:0;border-radius:{r}px;">'
    )


def brand_cell(name: str, size: int = 56, alt: str = "BAZA") -> str:
    """Komórka tabeli z grafiką - wstawiana przed tytułem w nagłówku."""
    return (
        f'<td width="{size + 14}" valign="middle" style="padding-right:14px;">'
        f"{brand_image(name, size, alt)}</td>"
    )


def baza_signature(color: str = "#8A96A8", label: str = "BAZA") -> str:
    """Mała sygnatura z Bazusem pod kartą maila (tam, gdzie nagłówek zajmuje herb okręgu)."""
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:12px auto 0 auto;"><tr>'
        f'<td valign="middle" style="padding-right:8px;">{brand_image("bazus.png", 28, "BAZA", 8)}</td>'
        f'<td valign="middle" style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:{color};">'
        f"{html.escape(label)}</td></tr></table>"
    )


def baza_sender_email(fallback: str) -> str:
    """Nadawca maili BAZY: `BAZA_SENDER_EMAIL`, a bez niej dotychczasowy adres."""
    return (os.getenv(BAZA_SENDER_ENV) or "").strip() or (fallback or "").strip()


@router.get("/mail-assets/{name}", include_in_schema=False)
async def mail_asset(name: str):
    if name not in ALLOWED_ASSETS:
        raise HTTPException(404, "Nie ma takiej grafiki")
    path = ASSETS_DIR / name
    if not path.is_file():
        raise HTTPException(404, "Nie ma takiej grafiki")
    return FileResponse(
        path,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=604800"},
    )
