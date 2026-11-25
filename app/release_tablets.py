# app/release_tablets.py
#
# Reguły automatycznego objęcia tabletów wersją wymaganą. Czyste funkcje, bez
# importu bazy (app/db.py łączy się z Postgresem przy imporcie), więc dają się
# testować bez niej.
#
# Decyzja właściciela (25.11): wersja wymagana na OBU platformach (required,
# available_ios, available_android) staje się obowiązkowa także na tabletach
# automatycznie, w pierwszy poniedziałek o 12:00 czasu polskiego, który wypada
# co najmniej 7 pełnych dób po chwili, gdy warunek stał się prawdziwy.

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")
GRACE = timedelta(days=7)
CLEAR = object()  # znacznik: wyczyść required_since


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def on_both_platforms(row: Mapping[str, Any]) -> bool:
    """Warunek startu zegara: wymagana i dostępna na iOS oraz Androidzie."""
    return bool(row.get("required")) and bool(row.get("available_ios")) and bool(row.get("available_android"))


def tablets_due_at(required_since: datetime) -> datetime:
    """Pierwszy poniedziałek 12:00 Warszawy nie wcześniej niż 7 dób po `required_since`."""
    threshold = _aware(required_since) + GRACE
    local = threshold.astimezone(WARSAW)
    days_ahead = (7 - local.weekday()) % 7  # poniedziałek = 0
    day = local.date() + timedelta(days=days_ahead)
    due = datetime(day.year, day.month, day.day, 12, 0, tzinfo=WARSAW)
    if due < threshold:
        day = day + timedelta(days=7)
        due = datetime(day.year, day.month, day.day, 12, 0, tzinfo=WARSAW)
    return due


def pending_due_at(row: Mapping[str, Any]) -> Optional[datetime]:
    """Termin automatu, gdy jeszcze oczekuje; None, gdy nie dotyczy lub już objęto."""
    if not on_both_platforms(row):
        return None
    if row.get("required_tablets"):
        return None
    if row.get("required_tablets_auto") is False:
        return None
    since = row.get("required_since")
    if not since:
        return None
    return tablets_due_at(since)


def effective_required_tablets(row: Mapping[str, Any], now: datetime) -> bool:
    """Wartość skuteczna liczona przy każdym odczycie, niezależnie od utrwalenia."""
    if not row.get("required"):
        return False
    if row.get("required_tablets"):
        return True
    due = pending_due_at(row)
    return due is not None and _aware(now) >= due


def auto_promotion_due(row: Mapping[str, Any], now: datetime) -> bool:
    """Czy trzeba teraz utrwalić required_tablets=true, source='auto'."""
    due = pending_due_at(row)
    return due is not None and _aware(now) >= due


def since_transition(
    old: Mapping[str, Any], new: Mapping[str, Any], now: datetime
) -> Any:
    """Zmiana required_since po edycji: datetime (ustaw), CLEAR albo None (bez zmian)."""
    if not on_both_platforms(new):
        return CLEAR if old.get("required_since") else None
    if old.get("required_since") and on_both_platforms(old):
        return None
    return _aware(now)


def tablet_fields(row: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    """Pola do odpowiedzi API (GET /admin/versions, release-meta)."""
    eff = effective_required_tablets(row, now)
    due = pending_due_at(row)
    since = row.get("required_since")
    required = bool(row.get("required"))
    return {
        "required_tablets": eff,
        "required_tablets_auto": row.get("required_tablets_auto") is not False,
        "required_tablets_source": (row.get("required_tablets_source") or None) if required else None,
        "required_since": _aware(since).isoformat() if since and required else None,
        "tablets_due_at": due.isoformat() if due is not None and not eff else None,
    }


def backfill_values(row: Mapping[str, Any], now: datetime) -> Optional[dict[str, Any]]:
    """Jednorazowy backfill starych wymaganych wersji (bez powiadomień).

    Dotyczy tylko wierszy bez required_since, wymaganych na obu platformach. Ustawia
    required_since = updated_at; jeśli termin już minął, a automat nie jest wstrzymany,
    od razu required_tablets=true, source="auto". None = nie ruszaj wiersza.
    """
    if row.get("required_since") or not on_both_platforms(row):
        return None
    since = row.get("updated_at") or row.get("created_at") or now
    values: dict[str, Any] = {"required_since": _aware(since)}
    if (
        not row.get("required_tablets")
        and row.get("required_tablets_auto") is not False
        and _aware(now) >= tablets_due_at(since)
    ):
        values.update(required_tablets=True, required_tablets_source="auto")
    return values
