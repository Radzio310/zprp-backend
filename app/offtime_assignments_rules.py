"""
Niedyspozycje wpisane sędziom przez obsadowego / Calendar Mastera / admina.

Liść bez bazy i bez sieci (wzór: `province_access.py`) - reguły chodzą w teście
bez Postgresa. Decyzje właściciela 12.11.2026: wpisują odznaka „Obsadowy" w swoim
okręgu, Calendar Master okręgu i admin wszędzie; sędzia widzi wpis z kłódką.
"""
from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Iterable, List, Optional
from zoneinfo import ZoneInfo

from app.match_market_access import APPROVER_BADGE, has_approver_badge
from app.province_access import is_app_admin, judge_ids, normalize_province

WARSAW = ZoneInfo("Europe/Warsaw")

ROLE_ADMIN = "admin"
ROLE_CALENDAR_MASTER = "calendar_master"
ROLE_OBSADOWY = "obsadowy"
ROLES = (ROLE_OBSADOWY, ROLE_CALENDAR_MASTER, ROLE_ADMIN)

#: Rola w zdaniu push-a (mianownik).
ROLE_LABEL = {
    ROLE_OBSADOWY: "Obsadowy",
    ROLE_CALENDAR_MASTER: "Calendar Master",
    ROLE_ADMIN: "Administrator",
}

#: Znacznik wpisu przypisanego w `data_json` - telefon nie ma prawa go odsyłać.
ASSIGNED_SOURCE = "OBSADOWY_ASSIGNED"


def assigner_role(
    *,
    judge_id: Any,
    province: Any,
    admin_ids: Optional[Iterable[Any]] = None,
    calendar_master_ids: Optional[Iterable[Any]] = None,
    judge_province: Any = None,
    badges_raw: Any = None,
) -> Optional[str]:
    """Rola, w jakiej człowiek może wpisywać niedyspozycje w tym okręgu, albo None.

    Admin wszędzie; Calendar Master tylko z listy TEGO okręgu (wołający podaje
    już odczytaną listę); obsadowy tylko, gdy jego własny okręg w
    `province_judges` (nie ten z żądania ani tokenu) jest okręgiem wpisu.
    """
    actor = str(judge_id or "").strip()
    if not actor:
        return None
    if is_app_admin(actor, admin_ids):
        return ROLE_ADMIN
    if actor in judge_ids(list(calendar_master_ids or [])):
        return ROLE_CALENDAR_MASTER
    prov = normalize_province(province)
    if (
        prov
        and normalize_province(judge_province) == prov
        and has_approver_badge(badges_raw, (APPROVER_BADGE,))
    ):
        return ROLE_OBSADOWY
    return None


def short_name(full_name: Any) -> str:
    """„J. Kowalski" z „Jan Kowalski", „KOWALSKI Jan" albo „Kowalski"."""
    parts = [p for p in re.split(r"\s+", str(full_name or "").strip()) if p]
    if not parts:
        return ""
    if len(parts) == 1:
        word = parts[0]
        return word.capitalize() if word.isupper() else word
    upper = [p for p in parts if len(p) > 1 and p.isupper()]
    surname = upper[0] if upper else parts[-1]
    given = next((p for p in parts if p != surname), parts[0])
    pretty = surname.capitalize() if surname.isupper() else surname
    return f"{given[0].upper()}. {pretty}"


def parse_moment(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _local_day(moment: datetime) -> date:
    if moment.tzinfo is None:
        return moment.date()
    return moment.astimezone(WARSAW).date()


def day_key(value: Any) -> str:
    """Dzień (Warszawa) z ISO jako `YYYY-MM-DD` - cel deep-linku. Pusty, gdy nie da się."""
    moment = parse_moment(value)
    return _local_day(moment).isoformat() if moment else ""


def date_range_label(start: Any, end: Any) -> str:
    """„15.11", „15-16.11", „30.11-2.12" albo z rokiem, gdy zakres przechodzi na inny rok."""
    a = parse_moment(start)
    if a is None:
        return ""
    d1 = _local_day(a)
    b = parse_moment(end)
    d2 = _local_day(b) if b else d1
    if d2 < d1:
        d2 = d1
    if d1 == d2:
        return f"{d1.day}.{d1.month:02d}"
    if d1.year != d2.year:
        return f"{d1.day}.{d1.month:02d}.{d1.year}-{d2.day}.{d2.month:02d}.{d2.year}"
    if d1.month == d2.month:
        return f"{d1.day}-{d2.day}.{d1.month:02d}"
    return f"{d1.day}.{d1.month:02d}-{d2.day}.{d2.month:02d}"


def push_text(
    action: str,
    *,
    role: str,
    start: Any,
    end: Any,
    category: Any,
    author_name: Any,
) -> tuple[str, str]:
    """(tytuł, treść): „Obsadowy wpisał Ci niedyspozycję 15-16.11 · kategoria · J. Kowalski"."""
    verb = {"created": "wpisał", "updated": "zmienił", "deleted": "usunął"}.get(action, "zmienił")
    title = {
        "created": "Nowa niedyspozycja",
        "updated": "Zmiana niedyspozycji",
        "deleted": "Usunięta niedyspozycja",
    }.get(action, "Niedyspozycja")
    label = ROLE_LABEL.get(role, "Obsadowy")
    head = f"{label} {verb} Ci niedyspozycję {date_range_label(start, end)}".strip()
    cat = str(category or "").strip()
    who = short_name(author_name)
    body = " · ".join(p for p in (head, cat, who) if p)
    return title, body


def push_data(*, item_id: str, province: str, start: Any, action: str) -> dict[str, str]:
    """Ładunek FCM (same napisy). `kind` rozpoznaje dispatcher w apce, `day` to cel."""
    return {
        "kind": "offtime_assigned",
        "type": "offtime_assigned",
        "assignmentId": str(item_id),
        "province": str(province or ""),
        "day": day_key(start),
        "action": action,
        "notificationThread": f"offtime-assigned-{item_id}",
    }


def _clean(value: Any) -> Optional[str]:
    text = str(value).strip() if value is not None else ""
    return text or None


def normalize_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Pola wpisu z żądania. Rzuca ValueError z polskim zdaniem, gdy zakres jest zły."""
    start = parse_moment(data.get("from"))
    if start is None:
        raise ValueError("Podaj początek niedyspozycji.")
    end_raw = data.get("to")
    end = parse_moment(end_raw) if _clean(end_raw) else None
    if _clean(end_raw) and end is None:
        raise ValueError("Koniec niedyspozycji ma zły format.")
    if end is not None:
        try:
            before = end < start
        except TypeError:  # jedna data ze strefą, druga bez
            before = False
        if before:
            raise ValueError("Koniec niedyspozycji jest przed początkiem.")
    return {
        "from": str(data.get("from")).strip(),
        "to": _clean(end_raw),
        "info": _clean(data.get("info")),
        "category_id": _clean(data.get("category_id")),
        "category_name": _clean(data.get("category_name")),
        "category_color": _clean(data.get("category_color")),
    }


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


def build_item(row: Any) -> dict[str, Any]:
    """Item kontraktu: kształt wpisu `data_json` + id, judge_id, locked, assigned_by, znaczniki czasu."""
    g = row if isinstance(row, dict) else dict(getattr(row, "_mapping", row))
    color = g.get("category_color")
    return {
        "entry_type": "UNAVAIL",
        "source": ASSIGNED_SOURCE,
        "id": str(g["id"]),
        "judge_id": str(g["judge_id"]),
        "series_id": None,
        "original_series_id": None,
        "is_exception": False,
        "from": g["from"],
        "to": g.get("to"),
        "info": g.get("info") or "",
        "location": "",
        "category_id": g.get("category_id"),
        "category_name": g.get("category_name"),
        "category_color": color,
        "color": color,
        "is_manual": False,
        "is_global": False,
        "isMatch": False,
        "locked": True,
        "assigned_by": {
            "judge_id": str(g.get("created_by") or ""),
            "name": str(g.get("created_by_name") or ""),
            "role": str(g.get("created_by_role") or ROLE_OBSADOWY),
        },
        "assigned_at": _iso(g.get("created_at")),
        "updated_at": _iso(g.get("updated_at")),
    }


def strip_assigned(entries: Any, assigned_ids: Iterable[Any]) -> list[Any]:
    """Wycina z bloba z telefonu wpisy `locked` i te o id przypisanych wpisów (także usuniętych)."""
    ids = {str(i) for i in assigned_ids if i}
    out: list[Any] = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict):
            if entry.get("locked") or entry.get("source") == ASSIGNED_SOURCE:
                continue
            if str(entry.get("id") or "") in ids:
                continue
        out.append(entry)
    return out


def clean_judge_ids(values: Any) -> List[str]:
    out: List[str] = []
    for value in values if isinstance(values, (list, tuple)) else []:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out
