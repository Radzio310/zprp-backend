"""Handball Bastion w Mentorze - czyste reguły (etap 1, `docs/mentor-panel.md` sekcja Bastion).

Bez bazy i bez sieci: flagi, rozpoznawanie adresu meczu, wybór połączenia, mapowanie
odpowiedzi connectora na błędy BAZY, zakres klipu, odcisk zlecenia i stany zadania.

Trzy różne rzeczy (handoff 4.1): sesja BAZY, sesja Bastionu (connector) i czasowy adres Bunny.
Zewnętrzny 401 Bastionu NIGDY nie wraca do klienta jako 401 BAZY (to wylogowałoby z Mentora).
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

BASTION_HOST = "portal.handball-bastion.pl"
PROVIDER = "bastion"
GAME_PATH = "/game"

SCOPES = ("default", "personal")
JUDGE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: Stany połączenia (handoff 7.2). `unavailable` to stan odpowiedzi, nie dowód wygaśnięcia sesji.
CONNECTION_STATES = ("unconfigured", "checking", "ready", "reauth_required", "unavailable", "revoked")
#: Stany próby logowania (lustro connectora).
ATTEMPT_STATES = ("creating", "waiting_for_user", "verifying", "succeeded", "failed", "cancelled", "expired")
ATTEMPT_ACTIVE = ("creating", "waiting_for_user", "verifying")
#: Stany zadania klipu (handoff 7.2). Worker to etap 4 - tu tylko tabele i przejścia.
JOB_STATES = ("queued", "submitting", "submitted", "waiting_for_remote", "downloading", "uploading", "ready",
              "waiting_for_auth", "needs_reconciliation", "retryable_failed", "failed", "cancelled")
JOB_TERMINAL = ("ready", "failed", "cancelled")
JOB_ACTIVE = tuple(s for s in JOB_STATES if s not in JOB_TERMINAL)
JOB_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "queued": ("submitting", "waiting_for_auth", "cancelled", "failed"),
    "submitting": ("submitted", "needs_reconciliation", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "submitted": ("waiting_for_remote", "downloading", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "waiting_for_remote": ("downloading", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "downloading": ("uploading", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "uploading": ("ready", "retryable_failed", "failed", "cancelled"),
    "waiting_for_auth": ("queued", "submitting", "submitted", "waiting_for_remote", "downloading", "cancelled", "failed"),
    "needs_reconciliation": ("submitted", "queued", "failed", "cancelled"),
    "retryable_failed": ("queued", "submitted", "waiting_for_remote", "downloading", "uploading", "failed", "cancelled"),
    "ready": (),
    "failed": ("queued",),
    "cancelled": (),
}

#: Eksport klipu do Bastionu w pierwszej wersji: 2-300 s (publiczny skrypt portalu; BAZA pozwala na 600 s).
MIN_CLIP_S = 2
MAX_CLIP_S = 300

# ─── Komunikaty (handoff 11.6) ──────────────────────────────────────────────

MSG_AUTH_REQUIRED = "Potrzebne połączenie z Bastionem, aby odtworzyć to nagranie."
MSG_DEFAULT_DOWN = "Połączenie domyślne jest niedostępne. Możesz użyć własnego konta."
MSG_FORBIDDEN = "To konto nie ma dostępu do tego nagrania."
MSG_UNAVAILABLE = "Bastion chwilowo nie odpowiada. Spróbuj ponownie za chwilę."
MSG_RATE_LIMITED = "Bastion ogranicza liczbę zapytań. Spróbuj ponownie za chwilę."
MSG_CONNECTION_FORBIDDEN = "Tylko administrator może zarządzać połączeniem domyślnym."
MSG_DISABLED = "Integracja z Handball Bastion jest wyłączona."
MSG_SCOPE_OFF = {
    "default": "Połączenie domyślne z Bastionem jest wyłączone.",
    "personal": "Połączenia osobiste z Bastionem są wyłączone.",
}
MSG_LOGIN_BUSY = "Na tym połączeniu trwa już logowanie. Dokończ je albo poczekaj chwilę."


# ─── Flagi ──────────────────────────────────────────────────────────────────


def _truthy(value: Optional[str], default: bool = False) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on", "tak")


@dataclass(frozen=True)
class Flags:
    enabled: bool
    default_enabled: bool
    personal_enabled: bool
    connector_url: str
    connector_token: str
    login_view_base_url: str
    login_attempt_ttl_s: int
    probe_bunny_item_id: Optional[int]
    timeout_s: float

    @property
    def configured(self) -> bool:
        return bool(self.connector_url and self.connector_token)

    def scope_on(self, scope: str) -> bool:
        return self.enabled and (self.default_enabled if scope == "default" else self.personal_enabled)


def _int(value: Optional[str], default: int, lo: int, hi: int) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def load_flags(env: Optional[Mapping[str, str]] = None) -> Flags:
    """`BASTION_ENABLED=false` (domyślnie) wyłącza wszystko: pozostałe flagi są wtedy bez znaczenia."""
    e = os.environ if env is None else env
    enabled = _truthy(e.get("BASTION_ENABLED"), False)
    probe = _int(e.get("BASTION_PROBE_BUNNY_ITEM_ID"), 0, 0, 10**12)
    try:
        timeout = max(1.0, min(30.0, float(e.get("BASTION_CONNECTOR_TIMEOUT_S") or 8)))
    except ValueError:
        timeout = 8.0
    return Flags(
        enabled=enabled,
        default_enabled=enabled and _truthy(e.get("BASTION_DEFAULT_ENABLED"), True),
        personal_enabled=enabled and _truthy(e.get("BASTION_PERSONAL_ENABLED"), True),
        connector_url=(e.get("BASTION_CONNECTOR_URL") or "").strip().rstrip("/"),
        connector_token=(e.get("BASTION_CONNECTOR_TOKEN") or "").strip(),
        login_view_base_url=(e.get("BASTION_LOGIN_VIEW_BASE_URL") or "").strip().rstrip("/"),
        login_attempt_ttl_s=_int(e.get("BASTION_LOGIN_ATTEMPT_TTL_SECONDS"), 600, 60, 3600),
        probe_bunny_item_id=probe or None,
        timeout_s=timeout,
    )


def enabled() -> bool:
    return load_flags().enabled


# ─── Adres meczu ────────────────────────────────────────────────────────────

_ITEM_RE = re.compile(r"[1-9][0-9]{0,11}")


def parse_game_url(value: Any) -> Optional[int]:
    """`bunny_item_id` z adresu meczu albo None. Dokładny host, https, ścieżka `/game`, jedno dodatnie
    `bunny_item_id`; bez userinfo, portu, białych znaków i znaków sterujących. Parametr `at` i inne
    są pomijane (to punkt wejścia, nie tożsamość filmu)."""
    text = str(value or "")
    if not text or text != text.strip() or any(ord(c) < 33 or ord(c) == 127 or c == "\\" for c in text):
        return None
    try:
        u = urlsplit(text)
        if u.scheme.lower() != "https" or u.username is not None or u.password is not None or u.port is not None:
            return None
        if u.hostname is None or u.hostname != BASTION_HOST:
            return None
        if "@" in u.netloc or ":" in u.netloc or u.path.rstrip("/") != GAME_PATH:
            return None
        values = [v for key, v in _query_pairs(u.query) if key == "bunny_item_id"]
        if len(values) != 1 or not _ITEM_RE.fullmatch(values[0]):
            return None
        return int(values[0])
    except ValueError:
        return None


def _query_pairs(query: str) -> List[Tuple[str, str]]:
    out = []
    for part in query.split("&"):
        if part:
            key, _, val = part.partition("=")
            out.append((key, val))
    return out


def canonical_game_url(item_id: int) -> str:
    return f"https://{BASTION_HOST}{GAME_PATH}?bunny_item_id={int(item_id)}"


def canonicalize(value: Any) -> Optional[str]:
    item = parse_game_url(value)
    return canonical_game_url(item) if item else None


def is_bastion_url(value: Any) -> bool:
    return parse_game_url(value) is not None


# ─── Kontekst powrotu ───────────────────────────────────────────────────────


def clean_return_context(raw: Any) -> Dict[str, str]:
    """Zakres powrotu do pokoju: wyłącznie identyfikatory BAZY i liczby. Nigdy dowolny URL poza BAZĄ."""
    if not isinstance(raw, Mapping):
        return {}
    out: Dict[str, str] = {}
    for key in ("pair_id", "match_id", "video_id", "clip_id"):
        v = raw.get(key)
        if isinstance(v, str) and ID_RE.fullmatch(v):
            out[key] = v
    for key in ("video_s", "start_s", "end_s"):
        v = raw.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and 0 <= v <= 6 * 3600:
            out[key] = repr(round(float(v), 3))
    return out


# ─── Wybór połączenia ───────────────────────────────────────────────────────


def connection_key(scope: str, judge_id: Optional[str]) -> str:
    return "default" if scope == "default" else f"personal-{judge_id}"


def candidate_scopes(flags: Flags) -> List[str]:
    """Kolejność prób przy nowej operacji: domyślne -> osobiste (tylko włączone)."""
    return [s for s in SCOPES if flags.scope_on(s)]


def connector_status_to_state(body: Mapping[str, Any]) -> str:
    """Stan połączenia ze statusu connectora. `stored` + ostatni błąd 401 = reauth_required.
    Niedostępność connectora NIE przechodzi tędy (to nie jest stan sesji)."""
    raw = str(body.get("status") or "")
    if raw == "unconfigured" or not raw:
        return "unconfigured"
    if raw in CONNECTION_STATES and raw != "unavailable":
        return raw
    if str(body.get("last_error_code") or "") == "BASTION_AUTH_REQUIRED":
        return "reauth_required"
    return "ready"


@dataclass(frozen=True)
class PlaybackVerdict:
    kind: str  # ok | auth_required | forbidden | rate_limited | unavailable
    code: str


def classify_playback(http_status: int, body: Optional[Mapping[str, Any]]) -> PlaybackVerdict:
    """Odpowiedź `/playback` connectora -> werdykt. 401 portalu to `auth_required` (409 BAZY), 403 to odmowa
    do zasobu (sesja zostaje), 429 limit, wszystko inne (5xx, zła odpowiedź, timeout) to niedostępność."""
    code = str((body or {}).get("code") or (body or {}).get("error") or "")
    if http_status == 200 and code in ("OK", ""):
        return PlaybackVerdict("ok", "OK")
    if code == "BASTION_AUTH_REQUIRED" or http_status == 409:
        return PlaybackVerdict("auth_required", "BASTION_AUTH_REQUIRED")
    if code == "BASTION_RESOURCE_FORBIDDEN" or http_status == 403:
        return PlaybackVerdict("forbidden", "BASTION_RESOURCE_FORBIDDEN")
    if code == "BASTION_RATE_LIMITED" or http_status == 429:
        return PlaybackVerdict("rate_limited", "BASTION_RATE_LIMITED")
    return PlaybackVerdict("unavailable", code or "BASTION_UNAVAILABLE")


def final_playback_error(verdicts: Iterable[Tuple[str, PlaybackVerdict]]) -> Tuple[int, str]:
    """(status HTTP BAZY, kod) gdy żadne z połączeń nie otworzyło nagrania.
    Awaria/limit wygrywa (nie wiemy nic o dostępie), potem 403 (konto bez dostępu), na końcu 409 (brak sesji)."""
    kinds = [v.kind for _, v in verdicts]
    if "rate_limited" in kinds:
        return 429, "BASTION_RATE_LIMITED"
    if "unavailable" in kinds:
        return 503, "BASTION_UNAVAILABLE"
    if "forbidden" in kinds:
        return 403, "BASTION_RESOURCE_FORBIDDEN"
    return 409, "BASTION_AUTH_REQUIRED"


def embed_expiry_hint(expires_at: Any) -> Optional[Any]:
    """Termin zwracamy tylko, gdy connector go zna. Nigdy nie zgadujemy ważności sesji."""
    return expires_at if expires_at not in ("", 0) else None


def embed_url_ok(url: Any) -> bool:
    """Ostatnia bariera po stronie BAZY: embed to https bez userinfo i portu (hosty sprawdza connector)."""
    try:
        u = urlsplit(str(url or ""))
        return u.scheme == "https" and bool(u.hostname) and u.username is None and u.password is None and u.port is None
    except ValueError:
        return False


# ─── Klip -> zlecenie ───────────────────────────────────────────────────────


class ClipRangeError(ValueError):
    pass


def bastion_clip_range(start_s: float, end_s: float) -> Dict[str, Any]:
    """Zakres wysyłany do Bastionu: całe sekundy, zaokrąglone NA ZEWNĄTRZ (początek w dół, koniec w górę),
    żeby nie ucinać akcji. Zwraca też `rounded`, by UI pokazało dokładny zakres wysyłany do źródła.
    Długość po zaokrągleniu 2-300 s; nic nie jest dzielone ani przesuwane po cichu."""
    if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (start_s, end_s)) or start_s < 0:
        raise ClipRangeError("Niepoprawny zakres klipu.")
    a, b = int(math.floor(start_s + 1e-9)), int(math.ceil(end_s - 1e-9))
    length = b - a
    if length < MIN_CLIP_S:
        raise ClipRangeError(f"Bastion przyjmuje klipy od {MIN_CLIP_S} s.")
    if length > MAX_CLIP_S:
        raise ClipRangeError(f"Bastion przyjmuje klipy do {MAX_CLIP_S} s (zaznaczono {length} s).")
    return {"start_s": a, "end_s": b, "duration_s": length, "rounded": (a != start_s or b != end_s)}


def clip_fingerprint(*, clip_id: str, revision: int, bunny_item_id: int, start_s: int, end_s: int) -> str:
    """Odcisk zlecenia: ten sam klip, rewizja i zakres dają ten sam odcisk (idempotencja kolejki)."""
    raw = f"{clip_id}|{int(revision)}|{int(bunny_item_id)}|{int(start_s)}|{int(end_s)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def can_transition(current: str, new: str) -> bool:
    return new == current or new in JOB_TRANSITIONS.get(current, ())


def may_resume_with(job_identity: Optional[str], connection_identity: Optional[str]) -> bool:
    """Zadanie wznawiamy tylko tym samym zewnętrznym kontem. Nieznana tożsamość po obu stronach
    (connector jej jeszcze nie zwraca) przepuszcza; znana i różna blokuje."""
    if job_identity and connection_identity:
        return job_identity == connection_identity
    return True
