"""Kolejki terminarza: jedna nazwa „Kolejka N" i zakres dat (czyste reguły, bez bazy).

ZPRP nazywa kolejki różnie: Superliga „Seria 8", inne ligi „Kolejka 8",
„8. kolejka", „8" albo nic (sam `Nr`). Portal ma mówić wszędzie tak samo:
„Kolejka 8". Nazwy niebędące numerem („Finał", „Turniej Bystra",
„1/2 finału") zostają, jak są - to nie kolejka ligowa.

Pola dokładane do kolejki są ADDYTYWNE (`label`, `date_from`, `date_to`,
`matches_played`, `matches_total`); surowe `name`, `number`, `starts_on`,
`ends_on` zostają dla zgodności ze starszymi klientami.

Zakres dat: okno kolejki ze ZPRP (`DataStart`/`DataKoniec`), a gdy go nie
ma - pierwszy i ostatni dzień meczów kolejki. Okno ma pierwszeństwo, bo mecz
przełożony o miesiąc rozciągałby kolejkę „24 paź - 9 gru".
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Iterable, Optional, Tuple

LABEL_WORD = "Kolejka"

# „Seria 8", „Kolejka 8", „Kolejka nr 8", „kol. 8", „8. kolejka", „8 seria", „8".
_GENERIC = re.compile(
    r"^\s*(?:(?:seria|kolejka|kol\.?)\s*(?:nr\.?\s*)?(\d{1,3})|(\d{1,3})\s*\.?\s*(?:seria|kolejka|kol\.?)?)\s*\.?\s*$",
    re.IGNORECASE,
)
_DAY = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})")
_DAY_PL = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})")


def _clean(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _positive(value: Any) -> Optional[int]:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def is_generic_name(name: Any) -> bool:
    """Czy nazwa to sam numer kolejki („Seria 8", „8. kolejka", pusta)."""
    raw = _clean(name)
    return not raw or bool(_GENERIC.match(raw))


def matchday_number(number: Any, name: Any) -> Optional[int]:
    """Numer kolejki: z nazwy numerowej (tak ją widzi ZPRP), potem z `Nr`."""
    hit = _GENERIC.match(_clean(name))
    if hit:
        return _positive(hit.group(1) or hit.group(2))
    return _positive(number)


def matchday_label(number: Any, name: Any) -> str:
    """„Kolejka 8" dla nazw numerowych i pustych; inna nazwa zostaje („Finał")."""
    raw = _clean(name)
    if raw and not _GENERIC.match(raw):
        return raw
    n = matchday_number(number, raw)
    return f"{LABEL_WORD} {n}" if n else (raw or LABEL_WORD)


def card_matchday_label(matchday_name: Any) -> Optional[str]:
    """Etykieta kolejki na karcie meczu (karta zna tylko nazwę). None = brak nazwy."""
    raw = _clean(matchday_name)
    if not raw:
        return None
    return matchday_label(None, raw)


def iso_day(value: Any) -> Optional[str]:
    """„RRRR-MM-DD" z daty, datetime albo napisu ZPRP („2026-10-24 00:00:00", „24.10.2026")."""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    raw = _clean(value)
    hit = _DAY.match(raw)
    try:
        if hit:
            return date(int(hit.group(1)), int(hit.group(2)), int(hit.group(3))).isoformat()
        hit = _DAY_PL.match(raw)
        if hit:
            return date(int(hit.group(3)), int(hit.group(2)), int(hit.group(1))).isoformat()
    except ValueError:
        return None
    return None


def matchday_range(starts_on: Any, ends_on: Any, kickoffs: Iterable[Any] = ()) -> Tuple[Optional[str], Optional[str]]:
    """(date_from, date_to) kolejki jako „RRRR-MM-DD"; okno ZPRP przed datami meczów."""
    first, last = iso_day(starts_on), iso_day(ends_on)
    if first or last:
        first, last = first or last, last or first
    else:
        days = sorted(d for d in (iso_day(k) for k in kickoffs) if d)
        first, last = (days[0], days[-1]) if days else (None, None)
    if first and last and last < first:
        first, last = last, first
    return first, last


def _played(card: dict) -> bool:
    return card.get("score_home") is not None and card.get("score_away") is not None


def decorate_matchday(day: dict, matches: Optional[list] = None) -> dict:
    """Dokłada do kolejki `label`, `date_from`, `date_to` i liczniki (mutuje i zwraca).

    `number` uzupełniamy z nazwy tylko, gdy ZPRP go nie podał (dawniej null -
    zgodne wstecz). Liczniki tylko, gdy znamy mecze kolejki.
    """
    if day.get("number") is None:
        day["number"] = matchday_number(None, day.get("name"))
    day["label"] = matchday_label(day.get("number"), day.get("name"))
    kickoffs = [m.get("scheduled_at") for m in (matches or []) if isinstance(m, dict)]
    day["date_from"], day["date_to"] = matchday_range(day.get("starts_on"), day.get("ends_on"), kickoffs)
    if matches is not None:
        live = [m for m in matches if isinstance(m, dict) and not m.get("withdrawn")]
        day["matches_total"] = len(live)
        day["matches_played"] = sum(1 for m in live if _played(m))
    return day
