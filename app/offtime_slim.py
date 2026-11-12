"""Odchudzanie odpowiedzi `GET /silesia/offtimes/all` (`?from=&to=`, `?lite=1`).

MODUŁ-LIŚĆ: czysta logika bez bazy i sieci. Bez parametrów odpowiedź zostaje
dokładnie taka, jak była - z tej trasy korzystają inne ekrany i starsze wersje
aplikacji. Lite jest dla Calendar Mastera (BAZA: `master/masterModel.ts`,
`slimRecords`) i zostawia tylko pola, które ten ekran czyta.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from app.province_match_offtimes import _id_key, parse_match_moment

ASSIGNED_SOURCE = "OBSADOWY_ASSIGNED"

#: Pola zwykłego wpisu czytane przez masterModel (jak KEEP_KEYS w kliencie).
KEEP_KEYS = (
    "id",
    "entry_type",
    "info",
    "location",
    "category_id",
    "category_name",
    "category_color",
    "color",
    "is_global",
    "isGlobal",
    "series_id",
    "source",
    "source_feed",
    "source_feed_name",
    "temp_city",
    "temp_city_name",
    "is_temp_location",
)


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def parse_window(
    date_from: Optional[str], date_to: Optional[str]
) -> Optional[tuple[Optional[datetime], Optional[datetime]]]:
    """Okno z ISO-dat. Zapas dnia z każdej strony (strefy). None = bez okna."""
    lo = hi = None
    if _clean(date_from):
        try:
            d = date.fromisoformat(_clean(date_from)[:10])
        except ValueError:
            d = None
        if d:
            lo = datetime(d.year, d.month, d.day, tzinfo=timezone.utc) - timedelta(days=1)
    if _clean(date_to):
        try:
            d = date.fromisoformat(_clean(date_to)[:10])
        except ValueError:
            d = None
        if d:
            hi = datetime(d.year, d.month, d.day, tzinfo=timezone.utc) + timedelta(days=2)
    if lo is None and hi is None:
        return None
    return lo, hi


def _bounds(item: dict[str, Any]) -> tuple[Optional[datetime], Optional[datetime]]:
    start = parse_match_moment(item.get("from") or item.get("dateFrom"))
    end = parse_match_moment(item.get("to") or item.get("dateTo")) or start
    return start, end


def in_window(item: Any, window) -> bool:
    """Czy wpis zahacza o okno. Wpis bez daty początku zostaje (nie zgadujemy)."""
    if not isinstance(item, dict):
        return False
    if window is None:
        return True
    lo, hi = window
    start, end = _bounds(item)
    if start is None:
        return True
    if lo is not None and end is not None and end < lo:
        return False
    if hi is not None and start > hi:
        return False
    return True


def _is_assigned(item: dict[str, Any]) -> bool:
    return item.get("locked") is True or _clean(item.get("source")) == ASSIGNED_SOURCE


def _is_temp_city(item: dict[str, Any]) -> bool:
    return (
        item.get("entry_type") == "TEMP_CITY"
        or item.get("is_temp_location") is True
        or isinstance(item.get("temp_city"), str)
        or isinstance(item.get("temp_city_name"), str)
        or item.get("category_name") == "TEMP_CITY"
    )


def _is_match(item: dict[str, Any]) -> bool:
    return bool(item.get("isMatch") or item.get("is_match")) or (
        _clean(item.get("category_name")).upper() == "MECZ"
    )


def _match_key(item: dict[str, Any], start: Optional[datetime]) -> str:
    raw = _clean(item.get("source_match_id"))
    if not raw:
        ident = _clean(item.get("id"))
        raw = ident.split(":", 1)[-1] if ":" in ident else ident
    key = _id_key(raw) if raw else ""
    return key or (start.isoformat() if start else "")


def slim_entries(
    items: Iterable[Any], window=None, *, lite: bool = False
) -> list[dict[str, Any]]:
    """Wpisy z okna; w trybie lite mecze minimalne i bez powtórek."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not in_window(item, window):
            continue
        if not lite:
            out.append(item)
            continue
        if _is_assigned(item):
            out.append(item)  # z nich otwiera się formularz zmiany
            continue
        start, _ = _bounds(item)
        if _is_match(item) and not _is_temp_city(item):
            key = _match_key(item, start)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "id": _clean(item.get("id")),
                    "source_match_id": key,
                    "from": item.get("from") or item.get("dateFrom"),
                    "isMatch": True,
                }
            )
            continue
        slim: dict[str, Any] = {}
        for name in ("from", "to"):
            value = item.get(name) or item.get("date" + name.capitalize())
            if value not in (None, ""):
                slim[name] = value
        for name in KEEP_KEYS:
            value = item.get(name)
            if value is not None and value != "":
                slim[name] = value
        out.append(slim)
    return out
