"""Miejsce oglądania nagrania (17.11.2026) - czyste reguły bez bazy.

CZAS GRY serwer NIE liczy (poprawka z 17.11): zegar meczu staje przy przerwach w grze, więc liniowo z gwizdków
rozjeżdża się o minuty (30:00 zamiast 28:30). Dokładny czas gry zna tylko klient ze śladu zegara ProEla
(`matchAtVideoSecond` i spółka). Serwer trzyma wyłącznie czas w nagraniu.

Koniec oglądania (`finished`):
  1. klient, który zna dokładny czas gry, wysyła `reached_end: true`, gdy jego zegar gry >= 2 x połowa - 150 s
     (domyślnie 57:30; próg liczy klient przez `WATCH_END_MARGIN_S`); serwer zapamiętuje to w `finished_at` (lepkie),
  2. reguła zastępcza (klient bez śladu zegara, kalibracja nieznana, stary klient): najdalsze miejsce >= 95% długości
     nagrania albo do końca <= 180 s; bez znanej długości nigdy (zostaje „odrzuć").
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional

SAVE_MIN_S = 5.0            # wcześniejszy zapis (otwarcie filmu) niczego nie nadpisuje
PROPOSE_MIN_S = 20.0        # poniżej tego nie ma co wznawiać
FALLBACK_FRACTION = 0.95
FALLBACK_TAIL_S = 180.0
MAX_VIDEO_S = 6 * 3600
FUTURE_SLACK_S = 300        # zapis z „przyszłości" (zły zegar) przycinamy do teraz
DEVICES = ("phone", "tablet", "desktop")
#: Zapisujemy tylko z odtwarzacza; kreator kalibracji i podgląd klipu przysyłają inne `source` i są ignorowane.
SAVE_SOURCES = ("player",)


def _num(value: Any) -> Optional[float]:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if n == n else None


def aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value) / 1000.0, tz=timezone.utc)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def is_finished(furthest_s: float, duration_s: Optional[float], finished_at: Any = None) -> bool:
    if finished_at is not None:
        return True
    if duration_s and duration_s > 0:
        return furthest_s >= duration_s * FALLBACK_FRACTION or duration_s - furthest_s <= FALLBACK_TAIL_S
    return False


def percent(position_s: float, duration_s: Optional[float], finished: bool) -> int:
    """Postęp do cienkiego paska (0-100) w NAGRANIU (nie w czasie gry); 100 = obejrzane do końca."""
    if finished:
        return 100
    if duration_s and duration_s > 0:
        return max(0, min(99, int(position_s / duration_s * 100)))
    return 0


def clean_save(body: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """Zapis od klienta: kształt i granice. `ignored` = powód, dla którego nic nie zapisujemy."""
    source = str(body.get("source") or "player")
    if source not in SAVE_SOURCES:
        return {"ignored": "source"}
    position = _num(body.get("position_s"))
    if position is None or position < 0:
        return {"ignored": "position"}
    position = min(position, MAX_VIDEO_S)
    duration = _num(body.get("duration_s"))
    duration = min(duration, MAX_VIDEO_S) if duration and duration > 0 else None
    device = str(body.get("device") or "")
    saved = aware(body.get("saved_at")) or now
    saved = min(saved, now + timedelta(seconds=FUTURE_SLACK_S))
    return {"position_s": position, "duration_s": duration, "device": device if device in DEVICES else None, "saved_at": saved,
            "reached_end": body.get("reached_end") is True}


def merge_save(existing: Optional[Mapping[str, Any]], save: Mapping[str, Any]) -> Dict[str, Any]:
    """Ostatni wygrywa po `saved_at`; `furthest_s` i `finished_at` scalają się niezależnie od kolejności zapisów.

    Zwraca {"apply": bool, "values": {...}|None}: `apply` False = zapis jest starszy (miejsce zostaje), ale
    `values` może nieść wyższe `furthest_s` albo `finished_at`. Zapis przed `SAVE_MIN_S` nic nie tworzy ani nie nadpisuje.
    """
    pos = float(save["position_s"])
    reached = {"finished_at": save["saved_at"]} if save.get("reached_end") else {}
    if existing is None:
        if pos < SAVE_MIN_S:
            return {"apply": False, "values": None}
        return {"apply": True, "values": {"position_s": pos, "furthest_s": pos, "duration_s": save.get("duration_s"),
                                          "device": save.get("device"), "saved_at": save["saved_at"], "dismissed_saved_at": None, **reached}}
    if existing.get("finished_at") is not None:
        reached = {}                                            # lepkie: raz stwierdzony koniec zostaje
    old_furthest = float(existing.get("furthest_s") or 0)
    furthest = max(old_furthest, pos)
    old_saved = aware(existing.get("saved_at"))
    if old_saved is not None and save["saved_at"] <= old_saved:
        extra = {**({"furthest_s": furthest} if furthest > old_furthest else {}), **reached}
        return {"apply": False, "values": extra or None}
    if pos < SAVE_MIN_S:
        return {"apply": False, "values": reached or None}
    return {"apply": True, "values": {"position_s": pos, "furthest_s": furthest, "duration_s": save.get("duration_s") or existing.get("duration_s"),
                                      "device": save.get("device"), "saved_at": save["saved_at"], **reached}}


def shape(row: Mapping[str, Any], video_duration: Optional[float] = None) -> Dict[str, Any]:
    """Kształt odpowiedzi: miejsce, koniec, odrzucenie i gotowa decyzja `propose`."""
    position = float(row.get("position_s") or 0)
    furthest = max(float(row.get("furthest_s") or 0), position)
    duration = row.get("duration_s") or video_duration
    duration = float(duration) if duration else None
    finished = is_finished(furthest, duration, row.get("finished_at"))
    saved = aware(row.get("saved_at"))
    dismissed_at = aware(row.get("dismissed_saved_at"))
    dismissed = bool(saved and dismissed_at and abs((saved - dismissed_at).total_seconds()) < 0.001)
    near_end = bool(duration and duration - position < 10)
    return {
        "video_id": row.get("video_id"), "match_id": row.get("match_id"), "pair_id": row.get("pair_id"),
        "position_s": round(position, 1), "furthest_s": round(furthest, 1), "duration_s": duration,
        "percent": percent(position, duration, finished),
        "device": row.get("device"), "saved_at": saved.isoformat() if saved else None,
        "finished": finished, "dismissed": dismissed,
        "propose": (not finished) and (not dismissed) and position >= PROPOSE_MIN_S and not near_end,
    }
