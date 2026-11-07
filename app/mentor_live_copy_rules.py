"""Automatyczna kopia transmisji YouTube na serwer (07.11.2026) - reguły czyste (bez bazy, sieci i yt-dlp).

Decyzja właściciela (07.11.2026, wersja ostateczna): link do transmisji NA ŻYWO (albo zapowiedzi) dodany do meczu
w panelu „Mentor” uzbraja automatyczną „Kopię na serwer”. Harmonogram leży w kolumnach `mentor_match_videos.auto_*`
(przeżywa restart serwera):

  - KONIEC MECZU = co nastąpi pierwsze: YouTube mówi, że transmisja się skończyła (`actualEndTime`, stan inny niż
    live/upcoming), albo ProEl zgłasza koniec meczu (przejście statusu na finished/approved);
  - pierwsza próba 5 minut po końcu meczu, potem przez 30 minut od końca meczu próba co 5 minut (+5, +10, ... +30);
    każda udana kopia NADPISUJE poprzednią (ten sam wiersz `mentor_uploads`, te same klucze R2, to samo
    nagranie-kopia) - wygrywa najnowsza wersja zapisu, który YouTube dopracowuje po transmisji;
  - nieudana próba w oknie to spokojne czekanie na następną piątkę minut (nie czerwony błąd); nieudane nadpisanie
    nigdy nie psuje dobrej kopii;
  - jeśli w oknie 30 minut nie udała się ŻADNA kopia: dokładnie jedna próba 60 minut po końcu meczu i koniec;
  - jeśli choć jedna się udała: koniec po próbie z +30 minut (bez dodatkowej próby po godzinie).

Stany (`auto_copy_state`, takie same w API `auto_copy.state`):
  waiting_end   transmisja trwa albo jest zapowiedzią - czekamy na koniec meczu (YouTube albo ProEl)
  scheduled     następna próba w oknie 30 minut o `next_at` (pierwsza albo nadpisanie; `reason` = czemu poprzednia nie wyszła)
  copying       próba trwa, kopii jeszcze nie ma
  refreshing    próba trwa, dobra kopia jest i gra (nadpisanie)
  last_try      w oknie nic się nie udało: ostatnia próba o `next_at` (= koniec meczu + 60 min); `next_at` null = trwa
  done          koniec automatu, kopia jest
  gave_up       koniec automatu bez kopii (`reason`)
  off           automat wyłączony ręcznie (anulowanie kopii, kopia do kosza) - w API `auto_copy: null`
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional

FIRST_AFTER = timedelta(minutes=5)
EVERY = timedelta(minutes=5)
WINDOW = timedelta(minutes=30)
LAST_TRY_AFTER = timedelta(minutes=60)
#: Transmisja, która przez tyle czasu się nie skończyła (zapowiedź na za tydzień, porzucony link) - automat odpuszcza.
STALE_AFTER = timedelta(days=3)

WAITING = ("waiting_end",)
RUNNING = ("copying", "refreshing")
ACTIVE = ("waiting_end", "scheduled", "copying", "refreshing", "last_try")
FINAL = ("done", "gave_up", "off")
STATES = ACTIVE + FINAL

#: Kody błędów kopii (`mentor_youtube_copy_rules.MESSAGES`), których ponawianie nie naprawi.
PERMANENT = frozenset({"TOO_LONG", "TOO_BIG", "NOT_YOUTUBE", "MEMBERS", "AGE", "NO_TOOL", "CANCELLED"})

REASONS: Dict[str, str] = {
    "GAVE_UP": "Nie udało się zrobić kopii transmisji ani w pół godziny po meczu, ani godzinę po nim. Ostatni powód: {last}",
    "PERMANENT": "Kopii tej transmisji nie da się zrobić: {last}",
    "STALE": "Transmisja nie skończyła się przez 3 dni - automatyczna kopia odpuściła. Kopię zrobisz ręcznie.",
    "NO_PAIR": "Nie znalazłem pary tego nagrania - automatyczna kopia nie ruszy.",
}

#: Spokojny powód między próbami automatu (zamiast czerwonego komunikatu ręcznej kopii).
CALM: Dict[str, str] = {
    "LIVE": "Transmisja jeszcze trwa.",
    "UPCOMING": "Transmisja jeszcze się nie zaczęła.",
    "POST_LIVE": "YouTube jeszcze przetwarza zapis transmisji.",
    "BLOCKED": "YouTube chwilowo nie pozwala pobrać filmu.",
    "BLOCKED_PROXY": "YouTube chwilowo nie pozwala pobrać filmu.",
    "PRIVATE": "Film jest chwilowo niedostępny (prywatny).",
    "GONE": "YouTube chwilowo nie pokazuje filmu.",
    "FAILED": "Pobieranie przerwało się.",
}


def calm_reason(code: str, message: str) -> str:
    return CALM.get(str(code or ""), "") or str(message or "").strip()


def aware(value: Any) -> Optional[datetime]:
    if isinstance(value, str) and value:
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def iso(value: Any) -> Optional[str]:
    found = aware(value)
    return found.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if found else None


def state_of(row: Mapping[str, Any]) -> Optional[str]:
    state = str(row.get("auto_copy_state") or "").strip()
    return state if state in STATES else None


def armed(row: Mapping[str, Any]) -> bool:
    return state_of(row) in ACTIVE


def running(row: Mapping[str, Any]) -> bool:
    """Próba w toku: kopia/nadpisanie w oknie albo ostatnia próba (bez terminu = już ruszyła)."""
    state = state_of(row)
    return state in RUNNING or (state == "last_try" and aware(row.get("auto_next_at")) is None)


# ─── Uzbrojenie ─────────────────────────────────────────────────────────────


def live_now(info: Optional[Mapping[str, Any]]) -> bool:
    """Czy YouTube mówi, że to transmisja trwająca albo zapowiedziana (`state` z `page_live_info`/`api_live_info`)."""
    return bool(info) and info.get("state") in ("live", "upcoming")  # type: ignore[union-attr]


def arm_values(now: datetime) -> Dict[str, Any]:
    """Kolumny świeżo uzbrojonego filmu: czekamy na koniec meczu."""
    return {"auto_copy_state": "waiting_end", "auto_armed_at": now, "auto_next_at": None, "auto_attempts": 0,
            "auto_end_at": None, "auto_reason": None, "live_ended_at": None, "proel_finished_at": None}


# ─── Koniec meczu: YouTube albo ProEl ───────────────────────────────────────


def _match_end(row: Mapping[str, Any], end: datetime) -> Dict[str, Any]:
    """Pierwszy sygnał końca meczu ustawia okno: pierwsza próba 5 minut później."""
    if state_of(row) not in WAITING:
        return {}
    return {"auto_copy_state": "scheduled", "auto_end_at": end, "auto_next_at": end + FIRST_AFTER, "auto_reason": None}


def on_live_info(row: Mapping[str, Any], info: Optional[Mapping[str, Any]], now: datetime) -> Dict[str, Any]:
    """Zmiany po sprawdzeniu transmisji w YouTube: koniec transmisji = koniec meczu (gdy ProEl nie był pierwszy)."""
    if not armed(row) or not info or info.get("state") != "vod" or row.get("live_ended_at"):
        return {}
    ended = min(aware(info.get("ended_at")) or now, now)
    return {"live_ended_at": ended, **_match_end(row, ended)}


def on_proel_finished(row: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """ProEl: koniec meczu (gdy YouTube nie był pierwszy)."""
    if not armed(row) or row.get("proel_finished_at"):
        return {}
    return {"proel_finished_at": now, **_match_end(row, now)}


def housekeeping(row: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """Transmisja bez końca (zapowiedź na za tydzień, porzucony link): po 3 dniach automat odpuszcza."""
    armed_at = aware(row.get("auto_armed_at")) or now
    if state_of(row) in WAITING and now - armed_at >= STALE_AFTER:
        return {"auto_copy_state": "gave_up", "auto_next_at": None, "auto_reason": REASONS["STALE"]}
    return {}


# ─── Próby ──────────────────────────────────────────────────────────────────


def next_slot(end: Any, now: datetime) -> Optional[datetime]:
    """Najbliższa „piątka” w oknie 30 minut po końcu meczu, późniejsza niż `now` (None = okno minęło)."""
    base = aware(end)
    if base is None:
        return None
    step = FIRST_AFTER
    while step <= WINDOW:
        slot = base + step
        if slot > now:
            return slot
        step += EVERY
    return None


def due(row: Mapping[str, Any], now: datetime) -> Optional[str]:
    """Co zrobić teraz: `window` (próba w oknie), `last` (ostatnia próba po godzinie) albo None."""
    state = state_of(row)
    at = aware(row.get("auto_next_at"))
    if at is None or at > now:
        return None
    if state == "scheduled":
        return "window"
    if state == "last_try":
        return "last"
    return None


def on_start(row: Mapping[str, Any], now: datetime, has_copy: bool) -> Dict[str, Any]:
    """Próba rusza (`has_copy` = dobra kopia już jest, więc to nadpisanie). Ostatnia próba zostaje `last_try` bez terminu."""
    state = "last_try" if state_of(row) == "last_try" else ("refreshing" if has_copy else "copying")
    return {"auto_copy_state": state, "auto_next_at": None, "auto_attempts": int(row.get("auto_attempts") or 0) + 1}


def _after(row: Mapping[str, Any], now: datetime, has_copy: bool, reason: Optional[str]) -> Dict[str, Any]:
    """Po próbie (udanej albo nie): następna piątka w oknie, a po oknie koniec albo ostatnia próba po godzinie."""
    if state_of(row) != "last_try":
        slot = next_slot(row.get("auto_end_at"), now)
        if slot is not None:
            return {"auto_copy_state": "scheduled", "auto_next_at": slot, "auto_reason": reason}
        if not has_copy:
            end = aware(row.get("auto_end_at")) or now
            return {"auto_copy_state": "last_try", "auto_next_at": max(end + LAST_TRY_AFTER, now), "auto_reason": reason}
    if has_copy:
        return {"auto_copy_state": "done", "auto_next_at": None, "auto_reason": None}
    return {"auto_copy_state": "gave_up", "auto_next_at": None,
            "auto_reason": REASONS["GAVE_UP"].format(last=reason or "nieznany błąd.")[:500]}


def on_success(row: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """Udana kopia (albo nadpisanie): dalej co 5 minut do końca okna, potem koniec."""
    if not armed(row) or state_of(row) == "waiting_end":
        return {}
    return _after(row, now, True, None)


def on_failure(row: Mapping[str, Any], now: datetime, code: str, message: str, has_copy: bool) -> Dict[str, Any]:
    """Nieudana próba automatu. Spokojnie: następna piątka (albo ostatnia próba); błąd, którego ponawianie nie naprawi,
    kończy od razu (`done`, gdy dobra kopia jest; inaczej `gave_up`)."""
    if not armed(row) or state_of(row) == "waiting_end":
        return {}
    if code in PERMANENT:
        if has_copy:
            return {"auto_copy_state": "done", "auto_next_at": None, "auto_reason": None}
        return {"auto_copy_state": "gave_up", "auto_next_at": None,
                "auto_reason": REASONS["PERMANENT"].format(last=str(message or "").strip())[:500]}
    if state_of(row) == "last_try" and not has_copy:
        return _after(row, now, False, str(message or "").strip() or None)
    return _after(row, now, has_copy, calm_reason(code, message) or None)


def off_values() -> Dict[str, Any]:
    return {"auto_copy_state": "off", "auto_next_at": None, "auto_reason": None}


# ─── API ────────────────────────────────────────────────────────────────────


def auto_shape(row: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Pole `auto_copy` nagrania (i `mirror.auto`): null = film nie jest uzbrojony (albo automat wyłączono)."""
    if not row:
        return None
    state = state_of(row)
    if state is None or state == "off":
        return None
    end = aware(row.get("auto_end_at"))
    return {
        "state": state,
        #: następna próba (scheduled, last_try czekający); null = trwa albo koniec
        "next_at": iso(row.get("auto_next_at")) if state in ("scheduled", "last_try") else None,
        "attempt": int(row.get("auto_attempts") or 0),
        #: koniec okna prób co 5 minut (koniec meczu + 30 min)
        "until": iso(end + WINDOW) if end else None,
        #: ostatnia próba, gdy w oknie nic się nie uda (koniec meczu + 60 min)
        "last_try_at": iso(end + LAST_TRY_AFTER) if end else None,
        "reason": row.get("auto_reason") or None,
        "ended_at": iso(end),
        "live_ended_at": iso(row.get("live_ended_at")),
        "proel_finished_at": iso(row.get("proel_finished_at")),
    }


# ─── Stan transmisji ze strony filmu (bez klucza API) ───────────────────────

_LIVE_DETAILS = re.compile(r'"liveBroadcastDetails"\s*:\s*\{([^{}]*)\}')
_IS_LIVE_NOW = re.compile(r'"isLiveNow"\s*:\s*(true|false)')
_START = re.compile(r'"startTimestamp"\s*:\s*"([^"]+)"')
_END = re.compile(r'"endTimestamp"\s*:\s*"([^"]+)"')
_UPCOMING = re.compile(r'"isUpcoming"\s*:\s*true')
_LIVE_CONTENT = re.compile(r'"isLiveContent"\s*:\s*(true|false)')


def _ms(value: Any) -> Optional[int]:
    found = aware(value)
    return int(found.timestamp() * 1000) if found else None


def page_live_info(text: Any) -> Optional[Dict[str, Any]]:
    """Strona filmu YouTube -> {state: live|upcoming|vod, started_ms, ended_at} albo None (strona bez danych).

    `liveBroadcastDetails` niesie `isLiveNow`, `startTimestamp` i `endTimestamp` (po końcu transmisji).
    Zwykły film (`isLiveContent: false`) = `vod` od razu."""
    page = str(text or "")
    block = _LIVE_DETAILS.search(page)
    if block:
        body = block.group(1)
        now_flag = _IS_LIVE_NOW.search(body)
        start = _START.search(body)
        end = _END.search(body)
        if end:
            return {"state": "vod", "started_ms": _ms(start.group(1)) if start else None, "ended_at": aware(end.group(1))}
        if now_flag and now_flag.group(1) == "true":
            return {"state": "live", "started_ms": _ms(start.group(1)) if start else None, "ended_at": None}
        return {"state": "upcoming", "started_ms": None, "ended_at": None}
    if _UPCOMING.search(page):
        return {"state": "upcoming", "started_ms": None, "ended_at": None}
    content = _LIVE_CONTENT.search(page)
    if content and content.group(1) == "false":
        return {"state": "vod", "started_ms": None, "ended_at": None}
    return None


def api_live_info(item: Mapping[str, Any]) -> Dict[str, Any]:
    """Wiersz `app/streams/parsers.parse_api_videos` -> ten sam kształt co `page_live_info`.
    `starts_at` jest faktycznym startem, gdy transmisja trwa albo się skończyła (zapowiedź ma tylko planowany)."""
    state = str(item.get("state") or "vod")
    ended = aware(item.get("ended_at"))
    started = _ms(item.get("starts_at")) if state == "live" or (item.get("is_broadcast") and ended) else None
    return {"state": state, "started_ms": started, "ended_at": ended}
