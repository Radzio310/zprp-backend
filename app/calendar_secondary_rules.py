"""Kalendarze drugorzędne Google: czyste reguły (bez bazy, bez sieci).

Moduł NIE importuje `app.db` (łączy się przy imporcie) ani bibliotek Google,
więc cała decyzja daje się sprawdzić testem jednostkowym. Wołający podaje dane.

Model (kontrakt 02.11.2026):

* poziom "matches" (każdy sędzia): zakres `calendar.app.created`, BAZA widzi
  tylko kalendarze, które sama założyła (BAZA - Boiskowy / Stolikowy / Mecze),
* poziom "district" (moduł okręgowy): dokłada `calendar.events` i odczyt list,
  czyli kalendarz główny z niedyspozycjami,
* token bez zapisanych zakresów (scope NULL) = "legacy": działa jak dotąd.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
from typing import Any, Iterable

# ── Zakresy ────────────────────────────────────────────────────────────────
_G = "https://www.googleapis.com/auth/"
SCOPE_APP_CREATED = _G + "calendar.app.created"
SCOPE_EVENTS = _G + "calendar.events"
SCOPE_READONLY = _G + "calendar.readonly"
SCOPE_CALENDARS_RO = _G + "calendar.calendars.readonly"
SCOPE_CALENDARLIST_RO = _G + "calendar.calendarlist.readonly"
SCOPE_EMAIL = _G + "userinfo.email"

MATCHES_SCOPES = [SCOPE_APP_CREATED, "openid", "email"]
DISTRICT_SCOPES = MATCHES_SCOPES + [
    SCOPE_EVENTS,
    SCOPE_CALENDARS_RO,
    SCOPE_CALENDARLIST_RO,
]

TIERS = ("matches", "district")

# ── Stałe kalendarzy ───────────────────────────────────────────────────────
KINDS = ("whistle", "stopwatch", "shared")
CALENDAR_NAMES = {
    "whistle": "BAZA - Boiskowy",
    "stopwatch": "BAZA - Stolikowy",
    "shared": "BAZA - Mecze",
}
CALENDAR_TIMEZONE = "Europe/Warsaw"
DEFAULT_COLORS = {
    "whistle": "#33b679",
    "stopwatch": "#f6bf26",
    "shared": "#039be5",
}
MODES = ("two", "one")
TARGETS = ("whistle", "stopwatch", "primary")
MAX_REMINDERS = 5
MAX_REMINDER_MINUTES = 40320  # 4 tygodnie, limit Google

# Znaczniki tytułu meczu (utils/calendarHelpers.ts): ⚽️ = boiskowy, ⏱️ = stolikowy.
# Wariant z selektorem emoji (U+FE0F) i bez niego traktujemy tak samo.
_BALL = "⚽"
_STOPWATCH = "⏱"

JOB_KINDS = ("migrate", "mode")
JOB_STATES = ("running", "done", "failed")
# Zadanie "running" bez bicia serca dłużej niż tyle uznajemy za porzucone.
JOB_STALE_SECONDS = 90


class SecondaryError(Exception):
    """Błąd z kodem i polskim komunikatem; trasy zamieniają go na HTTPException."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def detail(self) -> dict:
        return {"code": self.code, "message": self.message}


class GoogleError(Exception):
    """Odpowiedź błędu z Google (adapter zamienia HttpError na ten wyjątek)."""

    def __init__(self, status: int, message: str = ""):
        super().__init__(message or f"Google zwrócił błąd {status}")
        self.status = status
        self.message = message or f"Google zwrócił błąd {status}"

    @property
    def gone(self) -> bool:
        return self.status in (404, 410)


# ── Flaga ──────────────────────────────────────────────────────────────────
def flag_enabled(settings: Any) -> bool:
    """Flaga GOOGLE_CALENDAR_SECONDARY_ENABLED. Tylko prawdziwy bool True.

    Atrapa ustawień (MagicMock) ani brak pola nie włączają funkcji: bez flagi
    zachowanie jest w 100% jak dotąd.
    """
    return getattr(settings, "GOOGLE_CALENDAR_SECONDARY_ENABLED", False) is True


def flag_from_env(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def env_flag() -> bool:
    return flag_from_env(os.getenv("GOOGLE_CALENDAR_SECONDARY_ENABLED"))


# ── Klucze i poziomy dostępu ───────────────────────────────────────────────
def is_beach_key(user_login: str | None) -> bool:
    """Beach (`beach:` w kluczu) nigdy nie jest legacy i nie zmienia się."""
    return (user_login or "").startswith("beach:")


def normalize_scope_name(name: str) -> str:
    name = (name or "").strip()
    if name == "email":
        return SCOPE_EMAIL
    return name


def granted_scopes(raw: str | Iterable[str] | None) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, str):
        parts = list(raw)
    else:
        parts = raw.replace(",", " ").split()
    return frozenset(normalize_scope_name(p) for p in parts if p and p.strip())


def scope_to_string(raw: str | Iterable[str] | None) -> str | None:
    scopes = granted_scopes(raw)
    return " ".join(sorted(scopes)) if scopes else None


def access_level(raw_scope: str | None) -> str:
    """"legacy" | "matches" | "district" | "none".

    legacy = brak zapisanych zakresów (stary token: calendar.events + readonly).
    """
    scopes = granted_scopes(raw_scope)
    if not scopes:
        return "legacy"
    if SCOPE_EVENTS in scopes:
        return "district"
    if SCOPE_APP_CREATED in scopes:
        return "matches"
    return "none"


def uses_secondary(flag: bool, user_login: str, raw_scope: str | None) -> bool:
    """Czy zapisy tego konta idą do kalendarzy drugorzędnych."""
    if not flag or is_beach_key(user_login):
        return False
    return access_level(raw_scope) in ("matches", "district")


def has_primary_access(raw_scope: str | None) -> bool:
    return access_level(raw_scope) in ("legacy", "district")


def needs_migration(
    flag: bool, token_exists: bool, user_login: str, migrated: bool
) -> bool:
    return bool(flag and token_exists and not is_beach_key(user_login) and not migrated)


def required_scopes(tier: str) -> frozenset[str]:
    """Zakresy, bez których zgoda danego poziomu jest niepełna (openid/email są dodatkiem)."""
    needed = {SCOPE_APP_CREATED}
    if tier == "district":
        needed |= {SCOPE_EVENTS, SCOPE_CALENDARS_RO, SCOPE_CALENDARLIST_RO}
    return frozenset(needed)


def missing_scopes(tier: str, raw_granted: str | Iterable[str] | None) -> frozenset[str]:
    return required_scopes(tier) - granted_scopes(raw_granted)


LEFTOVER_NOTE = (
    "Dawne wpisy z meczami mogły zostać w Twoim kalendarzu głównym Google. "
    "BAZA nie ma już do niego dostępu, więc ich nie przeniosła ani nie usunęła. "
    "Możesz je usunąć ręcznie w Kalendarzu Google."
)


def district_access_error() -> SecondaryError:
    return SecondaryError(
        403,
        "district_access_required",
        "Ta funkcja wymaga dostępu do kalendarza głównego Google. "
        "Połącz kalendarz główny w module okręgowym (Ustawienia > Kalendarz).",
    )


# ── OAuth: poziom w state ──────────────────────────────────────────────────
def make_state(tier: str, raw: str) -> str:
    return f"{tier[0]}~{raw}"


def tier_from_state(state: str | None) -> str | None:
    s = state or ""
    if s.startswith("d~"):
        return "district"
    if s.startswith("m~"):
        return "matches"
    return None


def parse_tier(value: str | None) -> str:
    tier = (value or "matches").strip().lower()
    if tier not in TIERS:
        raise SecondaryError(
            400, "invalid_tier", "Nieznany poziom zgody. Dozwolone: matches albo district."
        )
    return tier


def lacks_events_scope(raw: str | Iterable[str] | None) -> bool:
    """Stara ścieżka zapisuje do kalendarza głównego. Brak informacji o zakresach
    nie jest odmową: Google podaje je zawsze, gdy zgoda była niepełna."""
    scopes = granted_scopes(raw)
    return bool(scopes) and SCOPE_EVENTS not in scopes


def scopes_for_tier(tier: str) -> list[str]:
    return list(DISTRICT_SCOPES if tier == "district" else MATCHES_SCOPES)


def email_from_id_token(id_token: str | None) -> str | None:
    """Adres z id_token. Token dostajemy prosto z punktu wymiany kodu przez TLS,
    więc podpisu tu nie sprawdzamy: pole służy tylko do pokazania konta."""
    if not id_token or id_token.count(".") != 2:
        return None
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return None
    email = data.get("email") if isinstance(data, dict) else None
    return email if isinstance(email, str) and "@" in email else None


# ── Trasowanie wydarzeń ────────────────────────────────────────────────────
def target_from_title(title: str | None) -> str:
    t = (title or "").lstrip()
    if t.startswith(_BALL):
        return "whistle"
    if t.startswith(_STOPWATCH):
        return "stopwatch"
    return "primary"


def resolve_target(title: str | None, target: str | None) -> str:
    """Jawne `target` wygrywa; bez niego decyduje prefiks tytułu."""
    if target is None or target == "":
        return target_from_title(title)
    if target not in TARGETS:
        raise SecondaryError(
            400,
            "invalid_target",
            "Nieznany cel wydarzenia. Dozwolone: whistle, stopwatch albo primary.",
        )
    return target


def kind_for_target(target: str, mode: str) -> str | None:
    """Rodzaj kalendarza drugorzędnego dla celu (None = kalendarz główny)."""
    if target == "primary":
        return None
    if mode == "one":
        return "shared"
    return "whistle" if target == "whistle" else "stopwatch"


def kinds_for_mode(mode: str) -> tuple[str, ...]:
    return ("shared",) if mode == "one" else ("whistle", "stopwatch")


def is_match_title(title: str | None) -> bool:
    return target_from_title(title) != "primary"


# ── Kolory ─────────────────────────────────────────────────────────────────
def normalize_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if len(v) == 7 and v[0] == "#" and all(c in "0123456789abcdef" for c in v[1:]):
        return v
    return None


def foreground_for(hex_color: str) -> str:
    """Czarny albo biały napis wg jasności tła (jasny Banan z bielą jest nieczytelny)."""
    h = normalize_hex(hex_color)
    if h is None:
        return "#ffffff"
    r, g, b = int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)
    return "#000000" if (0.299 * r + 0.587 * g + 0.114 * b) > 170 else "#ffffff"


def sanitize_colors(colors: Any) -> dict[str, str]:
    """{kind: hex}; zły hex = błąd z kodem, nie ciche pominięcie."""
    out: dict[str, str] = {}
    if colors is None:
        return out
    if not isinstance(colors, dict):
        raise SecondaryError(400, "invalid_color", "Kolory mają mieć postać {kalendarz: #rrggbb}.")
    for kind, value in colors.items():
        if value is None:
            continue
        if kind not in KINDS:
            raise SecondaryError(400, "invalid_color", f"Nieznany kalendarz: {kind}.")
        hx = normalize_hex(value)
        if hx is None:
            raise SecondaryError(
                400, "invalid_color", f"Kolor kalendarza {kind} ma mieć postać #rrggbb."
            )
        out[kind] = hx
    return out


# ── Przypomnienia, zajętość ────────────────────────────────────────────────
def sanitize_reminders(items: Any) -> list[dict]:
    """Do 5 przypomnień, metoda popup albo email, minuty 0..40320."""
    if items is None:
        return []
    if not isinstance(items, list):
        raise SecondaryError(400, "invalid_reminders", "Przypomnienia mają być listą.")
    if len(items) > MAX_REMINDERS:
        raise SecondaryError(
            400,
            "invalid_reminders",
            f"Google przyjmuje najwyżej {MAX_REMINDERS} przypomnień na wydarzenie.",
        )
    out: list[dict] = []
    for item in items:
        method = item.get("method") if isinstance(item, dict) else None
        minutes = item.get("minutes") if isinstance(item, dict) else None
        if method not in ("popup", "email"):
            raise SecondaryError(
                400, "invalid_reminders", "Metoda przypomnienia: popup albo email."
            )
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not (
            0 <= minutes <= MAX_REMINDER_MINUTES
        ):
            raise SecondaryError(
                400,
                "invalid_reminders",
                f"Czas przypomnienia to liczba minut od 0 do {MAX_REMINDER_MINUTES}.",
            )
        out.append({"method": method, "minutes": minutes})
    return out


def transparency(busy: bool | None) -> str:
    """Zajęty = opaque (domyślnie w Google), Wolny = transparent."""
    return "transparent" if busy is False else "opaque"


def match_event_body(
    *,
    summary: str,
    start: str,
    end: str,
    location: str,
    reminders: list[dict],
    busy: bool | None,
) -> dict:
    """Treść wydarzenia w kalendarzu drugorzędnym: bez koloru (kolor ma kalendarz)."""
    return {
        "summary": summary,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
        "location": location,
        "reminders": {"useDefault": False, "overrides": reminders},
        "transparency": transparency(busy),
    }


# ── Przenoszenie ───────────────────────────────────────────────────────────
def _parse_moment(value: Any) -> datetime.datetime | None:
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        if len(value) == 10:
            d = datetime.date.fromisoformat(value)
            return datetime.datetime(d.year, d.month, d.day, tzinfo=datetime.timezone.utc)
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def event_start(event: dict) -> datetime.datetime | None:
    start = event.get("start") or {}
    return _parse_moment(start.get("dateTime") or start.get("date"))


def is_movable_match_event(event: dict, now: datetime.datetime) -> bool:
    """Do przeniesienia: wydarzenie z przyszłości z tytułem meczu (⚽️/⏱️).

    Niedyspozycje (bez prefiksu) i wpisy historyczne zostają w kalendarzu głównym.
    """
    if event.get("status") == "cancelled":
        return False
    if not is_match_title(event.get("summary")):
        return False
    start = event_start(event)
    return bool(start and start > now)


def clean_reminders_lenient(reminders: Any) -> list[dict]:
    """Przy przenoszeniu cudzych wpisów: zostaw, co poprawne, nie przerywaj zadania."""
    overrides = (reminders or {}).get("overrides") if isinstance(reminders, dict) else None
    out: list[dict] = []
    for item in overrides or []:
        try:
            out.extend(sanitize_reminders([item]))
        except SecondaryError:
            continue
    return out[:MAX_REMINDERS]


def converted_event_body(event: dict, busy: bool | None) -> dict:
    """Wydarzenie z kalendarza głównego -> treść do nowego kalendarza (bez koloru)."""
    body: dict = {
        "summary": event.get("summary") or "",
        "start": event.get("start"),
        "end": event.get("end"),
        "location": event.get("location") or "",
        "reminders": {"useDefault": False, "overrides": clean_reminders_lenient(event.get("reminders"))},
        "transparency": transparency(busy),
    }
    if event.get("description"):
        body["description"] = event["description"]
    return body


def job_public(row: dict | None) -> dict | None:
    if not row or not row.get("job_kind") or not row.get("job_state"):
        return None
    return {
        "kind": row["job_kind"],
        "state": row["job_state"],
        "total": int(row.get("job_total") or 0),
        "done": int(row.get("job_done") or 0),
        "skipped": int(row.get("job_skipped") or 0),
        "failed": int(row.get("job_failed") or 0),
        "error": row.get("job_error") or None,
        "kept_calendars": list(row.get("job_kept") or []),
        "note": row.get("job_note") or None,
    }


def job_is_stale(row: dict, now: datetime.datetime) -> bool:
    if row.get("job_state") != "running":
        return False
    beat = row.get("job_heartbeat")
    if not isinstance(beat, datetime.datetime):
        return True
    if beat.tzinfo is None:
        beat = beat.replace(tzinfo=datetime.timezone.utc)
    return (now - beat).total_seconds() > JOB_STALE_SECONDS


def google_error_message(exc: GoogleError, doing: str) -> str:
    """Polski komunikat dla błędu Google (bez surowej treści odpowiedzi)."""
    if exc.status in (401, 403):
        return (
            f"Google odmówił dostępu przy czynności: {doing}. "
            "Połącz konto Google ponownie w Ustawieniach > Kalendarz."
        )
    if exc.status == 429:
        return f"Google chwilowo ogranicza zapytania ({doing}). Spróbuj za chwilę."
    return f"Google zwrócił błąd {exc.status} przy czynności: {doing}."
