"""Opisy meczów w powiadomieniu o kolizji niedyspozycyjności (liść, bez bazy).

Mecz bez daty (ZPRP nie podał jeszcze dnia) aplikacja zgłasza jako MOŻLIWĄ
kolizję: jego kolejka - okno dni z kalendarza rozgrywek, to samo, które widać
na liście meczów - nachodzi na zakres niedyspozycji. W mailu i na Discordzie
pokazujemy wtedy termin kolejki zamiast godziny meczu.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _iso_day(value: Any) -> date | None:
    try:
        return date.fromisoformat(_clean(value)[:10])
    except ValueError:
        return None


def is_tentative(match: dict[str, Any]) -> bool:
    return bool(match.get("tentative")) and bool(_iso_day(match.get("windowStart")))


def window_label(start: Any, end: Any) -> str:
    """„03-05.10.2026", „30.09-02.10.2026", „03.10.2026"."""
    a, b = _iso_day(start), _iso_day(end)
    if not a:
        return ""
    if not b or b <= a:
        return a.strftime("%d.%m.%Y")
    if a.year == b.year and a.month == b.month:
        return f"{a:%d}-{b:%d.%m.%Y}"
    if a.year == b.year:
        return f"{a:%d.%m}-{b:%d.%m.%Y}"
    return f"{a:%d.%m.%Y}-{b:%d.%m.%Y}"


def match_time(value: str) -> str:
    text = _clean(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%d.%m.%Y · %H:%M")
    except ValueError:
        return text


def conflict_when(match: dict[str, Any], exact_time=match_time) -> str:
    """Termin meczu do wiadomości: godzina albo termin kolejki meczu bez daty."""
    if is_tentative(match):
        label = window_label(match.get("windowStart"), match.get("windowEnd"))
        return f"możliwy termin: kolejka {label}, dokładny dzień nieznany"
    return exact_time(_clean(match.get("startAt")))


def subject_prefix(matches: list[dict[str, Any]]) -> str:
    """Temat łagodnieje, gdy wszystkie mecze są tylko możliwe."""
    if matches and all(is_tentative(m) for m in matches):
        return "Niedyspozycyjność może nachodzić na obsadę ZPRP"
    return "Niedyspozycyjność nachodzi na obsadę ZPRP"
