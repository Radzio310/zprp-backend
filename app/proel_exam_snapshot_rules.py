"""Czyste reguły współdzielonej migawki badań ProEla."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VALID_MARKS = {"none", "manual", "wzpr", "zprp"}
MAX_PLAYERS_PER_TEAM = 64


def polish_day(now: datetime) -> str:
    """Dzień kalendarzowy w Polsce, także dla czasu UTC z bazy."""
    aware = now if now.tzinfo is not None else now.replace(tzinfo=WARSAW)
    return aware.astimezone(WARSAW).date().isoformat()


def valid_date_key(value: Any) -> str:
    key = str(value or "").strip()
    if not DATE_RE.fullmatch(key):
        raise ValueError("Nieprawidłowy dzień meczu")
    # `fromisoformat` odrzuca np. 2026-02-31.
    datetime.fromisoformat(key)
    return key


def snapshot_is_frozen(date_key: str, now: datetime) -> bool:
    """Po polskiej północy migawki z zakończonego dnia są niezmienne."""
    return valid_date_key(date_key) < polish_day(now)


def _clean_player(raw: Any) -> Dict[str, Any]:
    value = raw if isinstance(raw, dict) else {}
    name = str(value.get("fullName") or "").strip()[:180]
    surname = str(value.get("surname") or "").strip()[:120]
    photo = str(value.get("photoUrl") or "").strip()[:1000]
    mark = str(value.get("exam") or "none").strip().lower()
    if mark not in VALID_MARKS:
        mark = "none"

    out: Dict[str, Any] = {"fullName": name, "exam": mark}
    try:
        number = int(value.get("number"))
        if 0 <= number <= 999:
            out["number"] = number
    except (TypeError, ValueError):
        pass
    if surname:
        out["surname"] = surname
    if photo.startswith(("https://", "http://")):
        out["photoUrl"] = photo
    return out


def clean_players(values: Iterable[Any]) -> List[Dict[str, Any]]:
    return [_clean_player(item) for item in list(values or [])[:MAX_PLAYERS_PER_TEAM]]


def clean_snapshot(host: Iterable[Any], guest: Iterable[Any]) -> Dict[str, Any]:
    return {
        "hostPlayers": clean_players(host),
        "guestPlayers": clean_players(guest),
    }


def snapshot_hash(date_key: str, snapshot: Dict[str, Any]) -> str:
    body = json.dumps(
        {"dateKey": valid_date_key(date_key), **snapshot},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()
