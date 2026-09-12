"""Reguły kalendarzy sędziego: adres, maskowanie, terminy synchronizacji.

Czysty liść - bez sieci i bez bazy, więc wszystko da się tu sprawdzić testami.

DLACZEGO ADRES JEST SPRAWĄ BEZPIECZEŃSTWA. Link do planu zajęć zawiera KLUCZ
(`...upcoming_ical?user_id=...&key=...`), czyli kto go ma, ten widzi plan
właściciela. Trzymamy go więc wyłącznie po stronie serwera, a do aplikacji
oddajemy zamaskowany.

Druga strona tej samej sprawy: serwer pobiera adres PODANY PRZEZ UŻYTKOWNIKA.
Bez zawężenia można by nim kazać backendowi odpytać jego własną sieć
wewnętrzną (SSRF). Stąd twarda lista dozwolonych schematów i odrzucanie
adresów lokalnych.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse, urlunparse

#: `webcal://` to ten sam plik co `https://` - tak podają go kalendarze Apple.
ALLOWED_SCHEMES = ("http", "https", "webcal")

MAX_URL_LENGTH = 2000

#: Ile kalendarzy może mieć jeden sędzia. Nie limit techniczny, tylko zdrowy
#: rozsądek: każdy to osobne pobranie co kilka godzin.
MAX_FEEDS_PER_JUDGE = 5

#: Jak często odświeżamy. Plan zajęć zmienia się rzadko, a odpytywanie cudzego
#: serwera co kwadrans byłoby nieuprzejme.
DEFAULT_INTERVAL_SECONDS = 6 * 3600

#: Okno wpisów: kilka dni wstecz (żeby dzisiejsze zajęcia nie znikały w nocy)
#: i pół roku do przodu - tyle, ile obejmuje semestr.
WINDOW_PAST_DAYS = 3
WINDOW_FUTURE_DAYS = 190


class FeedUrlError(ValueError):
    """Adres, którego nie przyjmiemy. Treść trafia wprost do użytkownika."""


def _is_local_host(host: str) -> bool:
    lowered = host.strip().lower().strip("[]")
    if not lowered:
        return True
    if lowered in ("localhost", "localhost.localdomain") or lowered.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )


def normalize_feed_url(raw: str) -> str:
    """Adres gotowy do pobrania albo wyjątek z polskim powodem."""
    value = (raw or "").strip()
    if not value:
        raise FeedUrlError("Podaj adres kalendarza (link iCal).")
    if len(value) > MAX_URL_LENGTH:
        raise FeedUrlError("Ten adres jest zbyt długi - sprawdź, czy się nie skleił.")

    parsed = urlparse(value)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise FeedUrlError(
            "Adres musi zaczynać się od https:// (albo webcal://). "
            "Skopiuj link do kalendarza w formacie iCal."
        )
    if not parsed.netloc:
        raise FeedUrlError("W tym adresie brakuje nazwy serwera.")
    if _is_local_host(parsed.hostname or ""):
        raise FeedUrlError("Adres wskazuje na sieć lokalną - podaj publiczny link.")

    # `webcal` to zwyczaj, nie protokół; pobieramy po https.
    if scheme == "webcal":
        parsed = parsed._replace(scheme="https")
    return urlunparse(parsed)


def mask_feed_url(url: str) -> str:
    """Adres do pokazania w aplikacji: bez kluczy, z samą końcówką.

    `https://usosapps.ue.katowice.pl/services/tt/upcoming_ical?...&key=HET...KC`
    staje się `usosapps.ue.katowice.pl/services/tt/upcoming_ical · …UKC`.
    Właściciel rozpozna swój link, a zrzut ekranu nie wydaje klucza.
    """
    value = (url or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    host = parsed.netloc or ""
    path = parsed.path or ""
    tail = re.sub(r"[^A-Za-z0-9]", "", parsed.query or "")[-4:]
    base = f"{host}{path}"
    return f"{base} · …{tail}" if tail else base


def feed_due(
    last_sync_at: Optional[datetime],
    *,
    now: Optional[datetime] = None,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
) -> bool:
    """Czy ten kalendarz trzeba odświeżyć w tym przebiegu."""
    if last_sync_at is None:
        return True
    moment = now or datetime.now(timezone.utc)
    stamp = last_sync_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return (moment - stamp) >= timedelta(seconds=max(60, interval_seconds))


def sync_window(today) -> tuple:
    """(od, do) - zakres dat, z którego bierzemy wydarzenia."""
    return (
        today - timedelta(days=WINDOW_PAST_DAYS),
        today + timedelta(days=WINDOW_FUTURE_DAYS),
    )
