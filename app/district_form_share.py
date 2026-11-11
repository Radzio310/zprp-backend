"""
Podgląd linku formularza okręgowego - znaczniki Open Graph i mała strona dla czytników kart
(docs/formularze-okregowe.md §19). Bez bazy i bez sieci: trasy w `district_forms_public.py`
podają gotowy formularz, a ten moduł składa z niego kartę (`district_form_card.CardData`),
opis i HTML.

Vercel (`BAZA_web/vercel.json`) kieruje roboty komunikatorów z `https://www.bazapodreka.app/f/<kod>`
na `GET /public/forms/<kod>/share`; obrazek to `GET /public/forms/<kod>/card.jpg?v=<skrót>`.
Skrót zmienia się razem z treścią karty, więc nowy tytuł czy grafika nie utkną w pamięci
komunikatora.

Co wolno pokazać: tyle, ile daje `GET /public/forms/<kod>` przy wyłączonym webie (tytuł, termin)
plus rodzaj, województwo i okładka. Żadnych nazwisk ani odpowiedzi; opis formularza tylko przy
włączonym webie (wtedy i tak stoi na stronie).
"""
from __future__ import annotations

import os
from datetime import datetime
from html import escape
from typing import Any, Mapping, Optional
from urllib.parse import quote

from app import district_forms_rules as R
from app.district_form_card import H, W, CardData, version
from app.province_event_rules import WARSAW

DEFAULT_API_HOST = "https://api.bazapodreka.app"
SITE_NAME = "BAZA"
THEME_COLOR = "#0F0E0C"
DESCRIPTION_MAX = 160

KIND_LABELS = {"list": "Lista deklaracji", "form": "Formularz"}
_MONTHS = (
    "stycznia", "lutego", "marca", "kwietnia", "maja", "czerwca",
    "lipca", "sierpnia", "września", "października", "listopada", "grudnia",
)
_WEEKDAYS = ("pon.", "wt.", "śr.", "czw.", "pt.", "sob.", "niedz.")

CTA_WEB = "Kliknij i odpowiedz"
CTA_APP = "Odpowiedz w aplikacji BAZA"
CLOSED = "Zamknięte"
BRAND_TITLE = "Formularze i listy okręgowe"
BRAND_DESCRIPTION = "Listy deklaracji i formularze komisji sędziowskich w aplikacji BAZA pod RĘKĄ."


def api_host() -> str:
    """Publiczny adres API (obrazek karty). `PUBLIC_API_HOST` nadpisuje, z `https://` albo bez."""
    host = (os.getenv("PUBLIC_API_HOST") or "").strip().rstrip("/") or DEFAULT_API_HOST
    return host if host.startswith(("https://", "http://")) else f"https://{host}"


def _code_path(code: str) -> str:
    return quote(str(code or ""), safe="")


def page_url(code: str) -> str:
    """Kanoniczny adres formularza (to, co ludzie wklejają) - `og:url`."""
    return f"{R.WEB_HOST}/f/{_code_path(code)}"


def card_url(code: str, card: CardData) -> str:
    return f"{api_host()}/public/forms/{_code_path(code)}/card.jpg?v={version(card)}"


def deadline_label(kind: str, closes_at: Any, now: datetime) -> str:
    """„Zapisy do wt. 9 grudnia, 23:59" (lista) / „Odpowiedzi do …" (formularz); rok tylko, gdy inny niż bieżący."""
    moment = R.aware(closes_at)
    if moment is None:
        return ""
    local = moment.astimezone(WARSAW)
    year = f" {local.year}" if local.year != R.aware(now).astimezone(WARSAW).year else ""
    prefix = "Odpowiedzi do" if kind == "form" else "Zapisy do"
    return f"{prefix} {_WEEKDAYS[local.weekday()]} {local.day} {_MONTHS[local.month - 1]}{year}, {local:%H:%M}"


def is_closed(form: Mapping[str, Any], now: datetime) -> bool:
    return R.form_status(form, now) in ("closed", "archived") or R.is_closed(form, now)


def event_photo_url(event: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Grafika tytułowa spiętego wydarzenia - tylko plik serwera albo https (jak `_event` strony)."""
    url = R.event_image_url(event.get("data_json")) if event else None
    return url if url and (url.startswith("/static/") or url.startswith("https://")) else None


def form_card(form: Mapping[str, Any], *, province_label: str, now: datetime,
              photo: Optional[str] = None) -> CardData:
    """Karta formularza. `photo` - tożsamość grafiki (`district_form_card.photo_key`) albo None."""
    kind = str(form.get("kind") or "list")
    cover = form.get("cover_json") if isinstance(form.get("cover_json"), Mapping) else {}
    tone = str(cover.get("tone") or "gold")
    closed = is_closed(form, now)
    meta = " · ".join(x for x in (KIND_LABELS.get(kind, KIND_LABELS["form"]), province_label) if x)
    return CardData(
        title=str(form.get("title") or "").strip() or KIND_LABELS.get(kind, "Formularz"),
        kind=kind,
        meta=meta,
        status=CLOSED if closed else deadline_label(kind, form.get("closes_at"), now),
        closed=closed,
        cta="" if closed else (CTA_WEB if form.get("web_enabled") else CTA_APP),
        tone=tone if tone in R.COVER_TONES else "gold",
        emoji=str(cover.get("emoji") or "").strip() or None,
        photo=photo,
    )


def brand_card() -> CardData:
    """Nieznany kod (literówka w linku): karta samej marki - link i tak się ładnie rozwija."""
    return CardData(title=BRAND_TITLE, meta="bazapodreka.app", brand=True)


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,.;:-–")
    return (cut or text[:limit]) + "…"


def description(form: Mapping[str, Any], card: CardData) -> str:
    """Jedno-dwa zdania pod tytułem w komunikatorze: rodzaj i województwo, termin, opis albo aplikacja."""
    parts = [card.meta]
    if card.closed:
        parts.append("Zapisy są zamknięte" if card.kind == "list" else "Formularz jest zamknięty")
    elif card.status:
        parts.append(card.status)
    if not form.get("web_enabled"):
        parts.append("Odpowiedz w aplikacji BAZA")
    elif form.get("description"):
        parts.append(_clip(str(form["description"]), DESCRIPTION_MAX))
    return ". ".join(p.rstrip(".") for p in parts if p) + "."


def _meta(attr: str, name: str, content: str) -> str:
    return f'<meta {attr}="{escape(name)}" content="{escape(content)}">'


def page(code: str, card: CardData, desc: str) -> str:
    """HTML dla czytnika kart: komplet `og:` i `twitter:`, bez przekierowania i bez skryptów."""
    url = page_url(code)
    image = card_url(code, card)
    title = card.title
    alt = f"{title} - {card.meta}" if card.meta else title
    tags = [
        _meta("property", "og:type", "website"),
        _meta("property", "og:site_name", SITE_NAME),
        _meta("property", "og:locale", "pl_PL"),
        _meta("property", "og:url", url),
        _meta("property", "og:title", title),
        _meta("property", "og:description", desc),
        _meta("property", "og:image", image),
        _meta("property", "og:image:secure_url", image),
        _meta("property", "og:image:type", "image/jpeg"),
        _meta("property", "og:image:width", str(W)),
        _meta("property", "og:image:height", str(H)),
        _meta("property", "og:image:alt", alt),
        _meta("name", "description", desc),
        _meta("name", "twitter:card", "summary_large_image"),
        _meta("name", "twitter:title", title),
        _meta("name", "twitter:description", desc),
        _meta("name", "twitter:image", image),
        _meta("name", "twitter:image:alt", alt),
        _meta("name", "theme-color", THEME_COLOR),
        _meta("name", "robots", "noindex"),
    ]
    head = "\n".join(tags)
    action = "Otwórz formularz" if not card.brand else "Otwórz BAZĘ"
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} · BAZA</title>
<link rel="canonical" href="{escape(url)}">
{head}
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0F0E0C;color:#F3EBDD;
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:24px;box-sizing:border-box}}
main{{max-width:600px;width:100%}}
img{{display:block;width:100%;height:auto;border-radius:18px;box-shadow:0 18px 40px rgba(0,0,0,.45)}}
h1{{font-size:24px;line-height:1.25;margin:22px 0 6px}}
p{{margin:0 0 20px;color:#B3A792}}
a{{display:inline-block;padding:12px 22px;border-radius:999px;background:#D9B45A;color:#0F0E0C;font-weight:700;text-decoration:none}}
</style>
</head><body><main>
<img src="{escape(image)}" width="{W}" height="{H}" alt="{escape(alt)}">
<h1>{escape(title)}</h1>
<p>{escape(desc)}</p>
<a href="{escape(url)}">{action}</a>
</main></body></html>
"""
