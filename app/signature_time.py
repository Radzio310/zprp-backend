# app/signature_time.py
"""Kiedy podpis został ZŁOŻONY, a kiedy tylko dotarł.

Do 15.09.2026 istniał jeden stempel: `signatures.created_at`, czyli moment
wysyłki. Dopóki podpis leciał na serwer w sekundę po narysowaniu, obie chwile
były tym samym. Odkąd aplikacja umie zebrać podpis bez zasięgu i dosłać go
później, przestały nią być - i stempel wysyłki zacząłby twierdzić, że kierownik
drużyny podpisał protokół w samochodzie w drodze powrotnej.

Dlatego czas złożenia podaje URZĄDZENIE, a nie serwer. To znaczy, że jest tak
wiarygodny jak zegar telefonu, i właśnie dlatego ta reguła istnieje: przyjmujemy
tylko wartości, które mogą być prawdziwe.

  * Przyszłość poza drobnym luzem to zegar ustawiony źle, nie podpis złożony
    jutro. Odrzucamy - `created_at` zostaje i niczego nie tracimy.
  * Głęboka przeszłość to albo zegar cofnięty, albo wpis, który przeleżał
    w kolejce dłużej, niż żyje jakikolwiek protokół.
  * Brak wartości jest poprawną odpowiedzią: starsze wydania aplikacji nie
    wysyłają tego pola i mają dalej działać bez zmian.

Reguła siedzi w osobnym module, bo `app/db.py` łączy się z bazą przy imporcie -
tutaj da się ją przetestować bez Postgresa.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

#: Luz na rozjechany zegar telefonu. Kilka minut w przód to normalny dryf,
#: godzina to już zła strefa czasowa albo ustawienie ręczne.
FUTURE_TOLERANCE = timedelta(minutes=5)

#: Poza tym oknem wartość przestaje cokolwiek znaczyć. Kolejka dosyłkowa ma
#: żyć godzinami, najwyżej dniami; miesiąc to znak, że coś poszło nie tak.
MAX_AGE = timedelta(days=30)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(raw: str) -> Optional[datetime]:
    """ISO 8601 w takiej postaci, w jakiej wysyła je aplikacja.

    `fromisoformat` w Pythonie 3.11+ przyjmuje już „Z", ale podmieniamy je
    ręcznie, bo ten backend bywa uruchamiany na starszym runtime i cicha
    odmowa parsowania wyglądałaby jak brak pola.
    """
    text = raw.strip()
    if not text:
        return None
    if text.endswith(("z", "Z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # Bez strefy przyjmujemy UTC. Aplikacja zawsze wysyła ze strefą, więc
        # ta gałąź dotyczy cudzych klientów - a zgadywanie strefy lokalnej
        # serwera przesunęłoby im podpis o kilka godzin.
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_signed_at(raw: Any, *, now: Optional[datetime] = None) -> Optional[datetime]:
    """Czas złożenia podpisu albo `None`, gdy nie da się go uznać za prawdziwy.

    `None` NIE jest błędem i nigdy nie blokuje wysyłki podpisu: obrazek jest
    wart więcej niż stempel, a moment dotarcia i tak zapisuje `created_at`.
    """
    if raw is None:
        return None
    if isinstance(raw, datetime):
        parsed: Optional[datetime] = (
            raw.replace(tzinfo=timezone.utc)
            if raw.tzinfo is None
            else raw.astimezone(timezone.utc)
        )
    elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
        # Milisekundy - tak liczy czas `Date.now()` w aplikacji.
        try:
            parsed = datetime.fromtimestamp(float(raw) / 1000.0, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(raw, str):
        parsed = _parse_iso(raw)
    else:
        return None

    if parsed is None:
        return None

    moment = now or now_utc()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    if parsed > moment + FUTURE_TOLERANCE:
        return None
    if parsed < moment - MAX_AGE:
        return None
    return parsed
