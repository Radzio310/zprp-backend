"""Miejsce oglądania nagrania (17.11.2026) - czyste reguły bez bazy.

Koniec oglądania liczymy z CZASU GRY (przez synchronizację nagrania `sync_json`), nie z długości pliku:
  próg = 2 x czas połowy (domyślnie 30 min => 60:00) minus zapas `END_MARGIN_S` (150 s => 57:30).
Reguła zastępcza (nagranie bez kalibracji `match_start_s`): koniec, gdy najdalsze miejsce >= 95% długości nagrania
albo do końca zostało <= 180 s; bez znanej długości nigdy nie uznajemy za obejrzane (zostaje „odrzuć").
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

SAVE_MIN_S = 5.0            # wcześniejszy zapis (otwarcie filmu) niczego nie nadpisuje
PROPOSE_MIN_S = 20.0        # poniżej tego nie ma co wznawiać
END_MARGIN_S = 150          # zapas przed końcem meczu (2-3 min)
DEFAULT_HALF_MIN = 30
DEFAULT_BREAK_MIN = 10
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


def _sync_numbers(sync: Optional[Mapping[str, Any]]) -> Tuple[Optional[float], Optional[float], float, float]:
    src = sync or {}
    start, second = _num(src.get("match_start_s")), _num(src.get("second_half_s"))
    half = _num(src.get("half_minutes"))
    brk = _num(src.get("break_minutes"))
    half = half if half and 5 <= half <= 60 else DEFAULT_HALF_MIN
    brk = brk if brk is not None and 0 <= brk <= 60 else DEFAULT_BREAK_MIN
    return start, second, half * 60.0, brk * 60.0


def game_seconds(video_s: float, sync: Optional[Mapping[str, Any]]) -> Optional[float]:
    """Czas gry (s) w sekundzie nagrania; None bez kalibracji początku meczu. Przerwa liczy się jak koniec połowy."""
    start, second, half_s, brk_s = _sync_numbers(sync)
    if start is None:
        return None
    if second is not None and video_s >= second:
        return half_s + (video_s - second)
    rel = video_s - start
    if rel <= half_s:
        return rel
    if second is None and rel > half_s + brk_s:
        return half_s + (rel - half_s - brk_s)
    return half_s


def end_threshold_s(sync: Optional[Mapping[str, Any]]) -> float:
    """Próg końca w czasie gry: 2 połowy minus zapas (domyślnie 57:30)."""
    _, _, half_s, _ = _sync_numbers(sync)
    return 2 * half_s - END_MARGIN_S


def is_finished(furthest_s: float, duration_s: Optional[float], sync: Optional[Mapping[str, Any]]) -> bool:
    g = game_seconds(furthest_s, sync)
    if g is not None:
        return g >= end_threshold_s(sync)
    if duration_s and duration_s > 0:
        return furthest_s >= duration_s * FALLBACK_FRACTION or duration_s - furthest_s <= FALLBACK_TAIL_S
    return False


def percent(position_s: float, duration_s: Optional[float], sync: Optional[Mapping[str, Any]], finished: bool) -> int:
    """Postęp do cienkiego paska (0-100): z czasu gry, a bez kalibracji z długości nagrania."""
    if finished:
        return 100
    g = game_seconds(position_s, sync)
    if g is not None:
        total = 2 * _sync_numbers(sync)[2]
        return max(0, min(99, int(g / total * 100)))
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
    return {"position_s": position, "duration_s": duration, "device": device if device in DEVICES else None, "saved_at": saved}


def merge_save(existing: Optional[Mapping[str, Any]], save: Mapping[str, Any]) -> Dict[str, Any]:
    """Ostatni wygrywa po `saved_at`; `furthest_s` scala się przez max niezależnie od kolejności.

    Zwraca {"apply": bool, "values": {...}|None}: `apply` False = zapis jest starszy (miejsce zostaje), ale
    `values` może nieść wyższe `furthest_s`. Zapis przed `SAVE_MIN_S` nic nie tworzy ani nie nadpisuje.
    """
    pos = float(save["position_s"])
    if existing is None:
        if pos < SAVE_MIN_S:
            return {"apply": False, "values": None}
        return {"apply": True, "values": {"position_s": pos, "furthest_s": pos, "duration_s": save.get("duration_s"),
                                          "device": save.get("device"), "saved_at": save["saved_at"], "dismissed_saved_at": None}}
    old_furthest = float(existing.get("furthest_s") or 0)
    furthest = max(old_furthest, pos)
    old_saved = aware(existing.get("saved_at"))
    if old_saved is not None and save["saved_at"] <= old_saved:
        return {"apply": False, "values": {"furthest_s": furthest} if furthest > old_furthest else None}
    if pos < SAVE_MIN_S:
        return {"apply": False, "values": None}
    return {"apply": True, "values": {"position_s": pos, "furthest_s": furthest, "duration_s": save.get("duration_s") or existing.get("duration_s"),
                                      "device": save.get("device"), "saved_at": save["saved_at"]}}


def shape(row: Mapping[str, Any], sync: Optional[Mapping[str, Any]], video_duration: Optional[float] = None) -> Dict[str, Any]:
    """Kształt odpowiedzi: miejsce, koniec, odrzucenie i gotowa decyzja `propose`."""
    position = float(row.get("position_s") or 0)
    furthest = max(float(row.get("furthest_s") or 0), position)
    duration = row.get("duration_s") or video_duration
    duration = float(duration) if duration else None
    finished = is_finished(furthest, duration, sync)
    saved = aware(row.get("saved_at"))
    dismissed_at = aware(row.get("dismissed_saved_at"))
    dismissed = bool(saved and dismissed_at and abs((saved - dismissed_at).total_seconds()) < 0.001)
    near_end = bool(duration and duration - position < 10)
    match_s = game_seconds(position, sync)
    return {
        "video_id": row.get("video_id"), "match_id": row.get("match_id"), "pair_id": row.get("pair_id"),
        "position_s": round(position, 1), "furthest_s": round(furthest, 1), "duration_s": duration,
        "match_s": None if match_s is None else round(match_s, 1),
        "percent": percent(position, duration, sync, finished),
        "device": row.get("device"), "saved_at": saved.isoformat() if saved else None,
        "finished": finished, "dismissed": dismissed,
        "propose": (not finished) and (not dismissed) and position >= PROPOSE_MIN_S and not near_end,
    }
