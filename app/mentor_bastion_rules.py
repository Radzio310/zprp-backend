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
    "queued": ("submitting", "submitted", "waiting_for_remote", "downloading", "waiting_for_auth", "retryable_failed",
               "needs_reconciliation", "cancelled", "failed"),
    "submitting": ("submitted", "needs_reconciliation", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "submitted": ("waiting_for_remote", "downloading", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "waiting_for_remote": ("downloading", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "downloading": ("uploading", "waiting_for_remote", "waiting_for_auth", "retryable_failed", "failed", "cancelled"),
    "uploading": ("ready", "downloading", "waiting_for_remote", "retryable_failed", "failed", "cancelled"),
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


# ─── Etap 4: kolejka klipów MP4 (czyste reguły) ─────────────────────────────

#: Dzierżawa zadania w bazie: po jej upływie inny worker (albo ten sam po restarcie) może je przejąć.
LEASE_S = 300
MAX_ATTEMPTS = 8
#: Ile razy pytamy Bastion o gotowość (odstępy 10-45 s, razem ok. 20-25 min), zanim uznamy zlecenie za zawieszone.
MAX_POLLS = 40
#: Przewidywany czas przygotowania pliku po stronie Bastionu (P8: ok. 90 s) - tylko podpowiedź do dialogu.
ESTIMATED_CUT_S = 90
BACKOFF_BASE_S = 15.0
BACKOFF_CAP_S = 15 * 60.0
#: Tolerancja długości pliku względem zakresu (P8: różnica 0,02 s).
DURATION_TOLERANCE_S = 2.0
MIN_FILE_BYTES = 2048

#: Stany, które worker podejmuje sam (reszta czeka na człowieka albo na połączenie).
JOB_RUNNABLE = ("queued", "submitting", "submitted", "waiting_for_remote", "downloading", "uploading", "retryable_failed")
#: Etapy widoczne dla klienta (`media.stage`).
STAGES = ("saved", "bastion_cutting", "storing", "ready", "waiting_for_auth", "failed")

MSG_STAGE = {
    "saved": "Klip zapisany. Przygotowuję plik MP4.",
    "bastion_cutting": "Bastion przygotowuje klip.",
    "storing": "Zapisuję klip w BAZIE.",
    "ready": "Klip zapisany w BAZIE",
    "waiting_for_auth": "Połącz się z Bastionem tym samym kontem, aby dokończyć klip.",
    "failed": "Nie udało się przygotować pliku MP4.",
}
MSG_WRONG_ACCOUNT = "Zaloguj się do Bastionu kontem, na którym zlecono ten klip."
MSG_RECONCILE = ("Nie wiadomo, czy Bastion przyjął klip. Sprawdź listę klipów w Bastionie. "
                 "Wznowienie może utworzyć drugi, prywatny klip.")
MSG_TOO_LONG = "Bastion przyjmuje klipy od %d do %d s. Plik MP4 nie zostanie przygotowany." % (MIN_CLIP_S, MAX_CLIP_S)
ERROR_MESSAGES = {
    "BASTION_RESOURCE_FORBIDDEN": MSG_FORBIDDEN,
    "BASTION_SUBMIT_REJECTED": "Bastion odrzucił zlecenie klipu.",
    "BASTION_CLIP_NOT_FOUND": "Klip zniknął z Bastionu. Wznów, aby zlecić go ponownie.",
    "BASTION_REMOTE_TIMEOUT": "Bastion nie przygotował klipu w rozsądnym czasie. Możesz wznowić.",
    "BASTION_RETRIES_EXHAUSTED": "Nie udało się po kilku próbach. Możesz wznowić.",
    "BASTION_FILE_INVALID": "Pobrany plik nie jest poprawnym filmem MP4.",
    "BASTION_FILE_MISMATCH": "Pobrany plik ma inną długość niż zaznaczony zakres.",
    "DOWNLOAD_TOO_LARGE": "Plik klipu jest większy niż dopuszczalny limit.",
    "DOWNLOAD_HOST_NOT_ALLOWED": "Adres pobrania z Bastionu nie jest na liście dozwolonych.",
    "DOWNLOAD_ADDRESS_NOT_PUBLIC": "Adres pobrania z Bastionu wskazuje na sieć nieobsługiwaną.",
    "STORAGE_OFF": "Magazyn nagrań nie jest skonfigurowany.",
    "STORAGE_UPLOAD_FAILED": "Nie udało się zapisać pliku w magazynie BAZY. Spróbuję ponownie.",
    "BASTION_WRONG_ACCOUNT": MSG_WRONG_ACCOUNT,
    "BASTION_UNAVAILABLE": MSG_UNAVAILABLE,
    "BASTION_RATE_LIMITED": MSG_RATE_LIMITED,
    "NEEDS_RECONCILIATION": MSG_RECONCILE,
}
#: Błędy bez sensu ponawiania (konfiguracja, odmowa, zły plik): zadanie od razu `failed`.
FATAL_CODES = ("BASTION_RESOURCE_FORBIDDEN", "BASTION_SUBMIT_REJECTED", "BASTION_FILE_INVALID", "BASTION_FILE_MISMATCH",
               "DOWNLOAD_TOO_LARGE", "DOWNLOAD_HOST_NOT_ALLOWED", "DOWNLOAD_ADDRESS_NOT_PUBLIC", "BASTION_CLIP_NOT_FOUND",
               "BASTION_REMOTE_TIMEOUT")


def backoff_s(attempts: int, rng=None) -> float:
    """Opóźnienie przed kolejną próbą po błędzie: 15 s, 30 s, 60 s... do 15 min, z jitterem +-25%."""
    import random

    r = (rng or random.random)()
    base = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** max(0, int(attempts) - 1)))
    return round(base * (0.75 + 0.5 * r), 2)


def poll_delay_s(poll_count: int, rng=None) -> float:
    """Odstęp między pytaniami o gotowość pliku: ok. 10 s na początku, rośnie do 45 s, z jitterem +-20%."""
    import random

    r = (rng or random.random)()
    base = min(45.0, 10.0 * (1.35 ** max(0, int(poll_count))))
    return round(base * (0.8 + 0.4 * r), 2)


def job_stage(state: str, has_remote: bool) -> Optional[str]:
    """Stan zadania -> etap dla klienta. `cancelled` nie ma etapu (klip nie ma już zadania na tej rewizji)."""
    if state == "queued":
        return "saved"
    if state == "ready":
        return "ready"
    if state == "waiting_for_auth":
        return "waiting_for_auth"
    if state in ("failed", "needs_reconciliation"):
        return "failed"
    if state in ("downloading", "uploading"):
        return "storing"
    if state in ("submitting", "submitted", "waiting_for_remote"):
        return "bastion_cutting"
    if state == "retryable_failed":
        return "storing" if has_remote else "bastion_cutting"
    return None


def job_message(state: str, error_code: Optional[str], stored: Optional[str] = None) -> str:
    if state == "needs_reconciliation":
        return MSG_RECONCILE
    if state == "waiting_for_auth" and error_code == "BASTION_WRONG_ACCOUNT":
        return MSG_WRONG_ACCOUNT
    if state in ("failed", "retryable_failed") and error_code:
        return ERROR_MESSAGES.get(error_code) or stored or MSG_STAGE["failed"]
    return MSG_STAGE.get(job_stage(state, True) or "", "")


def can_resume_job(state: str) -> bool:
    """Ręczne „Wznów”: tylko tam, gdzie człowiek coś zmienia (połączenie, awaria, niepewny wynik)."""
    return state in ("waiting_for_auth", "failed", "needs_reconciliation", "retryable_failed")


def can_cancel_job(job: Optional[Mapping[str, Any]]) -> bool:
    """Anulować można przed wysłaniem do Bastionu (nic nie wyszło) albo gdy zadanie leży w błędzie / niepewnym wyniku."""
    if not job:
        return False
    state = job.get("state")
    if state in ("failed", "needs_reconciliation"):
        return True
    if state in ("queued", "waiting_for_auth", "retryable_failed"):
        return job.get("submitted_at") is None and not job.get("remote_clip_id")
    return False


def verify_media(probe: Mapping[str, Any], size: int, expected_s: float) -> Optional[str]:
    """Kontrola pobranego pliku: mały rozmiar, brak obrazu, zły kontener albo zła długość = kod błędu (inaczej None).
    Strona HTML logowania zapisana jako .mp4 nie przechodzi: nie ma strumienia wideo."""
    if size < MIN_FILE_BYTES or not probe.get("has_video"):
        return "BASTION_FILE_INVALID"
    fmt = str(probe.get("format") or "")
    if "mp4" not in fmt and "mov" not in fmt:
        return "BASTION_FILE_INVALID"
    dur = probe.get("duration_s")
    if dur is None or dur <= 0:
        return "BASTION_FILE_INVALID"
    if abs(float(dur) - float(expected_s)) > DURATION_TOLERANCE_S:
        return "BASTION_FILE_MISMATCH"
    return None


def asset_key(prefix: str, pair_id: str, clip_id: str, revision: int, ext: str) -> str:
    """Klucz w magazynie Mentora: z rewizją, więc plik starej rewizji nigdy nie nadpisze nowej."""
    return "/".join([prefix.strip("/"), str(pair_id), "clips", str(clip_id), f"r{int(revision)}.{ext}"])


def file_time(playback: Mapping[str, Any], source_s: Optional[float]) -> Optional[float]:
    """Sekunda oryginału -> sekunda lokalnego pliku (0..duration). Poza plikiem = przycięte, nigdy dalej niż plik."""
    if source_s is None or playback.get("mode") != "asset":
        return None
    asset = playback.get("asset") or {}
    try:
        t = float(source_s) - float(asset.get("source_start_s") or 0)
    except (TypeError, ValueError):
        return None
    dur = asset.get("duration_s")
    t = max(0.0, t)
    return round(min(t, float(dur)) if dur else t, 2)


def resolve_clip_playback(*, clip: Mapping[str, Any], asset: Optional[Mapping[str, Any]] = None,
                          job: Optional[Mapping[str, Any]] = None, video_provider: Optional[str] = None,
                          video_present: bool = True, eligible: Optional[bool] = None) -> Dict[str, Any]:
    """JEDEN resolver odtwarzania klipu (pokój, biblioteka, kino, kolejki, zestawienia, publiczny klip). Bez URL-i
    (te powstają na żądanie po kontroli dostępu).

      mode "asset"        - gotowy plik BAZY dla BIEŻĄCEJ rewizji; gra 0..duration, `file_offset_s` mapuje czas oryginału
                            (`file_s = video_s - asset.source_start_s`, patrz `file_time`),
      mode "source_range" - wirtualny zakres oryginału `range` (plik w przygotowaniu / niepowodzenie) + `status`,
      mode "waiting"      - brak źródła i brak pliku: stan oczekiwania, nie gotowy pusty klip.
    `status`: "ready" albo etap zadania (`STAGES`), "virtual" (klip bez MP4, można zamówić) albo "not_exported" (zakres poza 2-300 s).
    Plik starej rewizji NIGDY nie jest oznaczany jako gotowy plik nowego zakresu."""
    rev = int(clip.get("media_rev") or 1)
    base: Dict[str, Any] = {
        "revision": rev, "video_id": clip.get("video_id"),
        "range": {"start_s": clip.get("start_s"), "end_s": clip.get("end_s")}, "asset": None, "file_offset_s": 0.0,
        "stage": None, "message": "", "eligible": eligible, "can_resume": False, "job": None,
        #: "mp4" = klip ma (lub zamówiony ma) plik w BAZIE; "virtual" = tylko znaczniki czasu, gra z pełnego meczu.
        "kind": "virtual", "can_order_mp4": False, "can_cancel": False,
    }
    if job:
        has_remote = bool(job.get("remote_clip_id"))
        base["stage"] = job_stage(job.get("state"), has_remote)
        base["message"] = job_message(job.get("state"), job.get("last_error_code"), job.get("last_error_message"))
        base["can_resume"] = can_resume_job(job.get("state"))
        base["kind"] = "mp4"
        base["can_cancel"] = can_cancel_job(job)
        base["job"] = {"state": job.get("state"), "attempts": int(job.get("attempts") or 0), "error_code": job.get("last_error_code"),
                       "next_attempt_at": job.get("next_attempt_at"), "updated_at": job.get("updated_at"),
                       "sent_range": {"start_s": job.get("start_s"), "end_s": job.get("end_s")}}
    ready_asset = asset if asset and asset.get("status") == "ready" and int(asset.get("revision") or 0) == rev else None
    if ready_asset:
        start = clip.get("start_s") or 0
        src_start = float(ready_asset["source_start_s"] if ready_asset.get("source_start_s") is not None else start)
        src_end = float(ready_asset["source_end_s"] if ready_asset.get("source_end_s") is not None else clip.get("end_s") or 0)
        base.update(mode="asset", status="ready", stage="ready", message=MSG_STAGE["ready"], can_resume=False, kind="mp4",
                    can_cancel=False,
                    file_offset_s=round(max(0.0, float(start) - src_start), 3),
                    asset={"id": ready_asset.get("id"), "revision": rev, "duration_s": ready_asset.get("duration_s"),
                           "width": ready_asset.get("width"), "height": ready_asset.get("height"), "size": ready_asset.get("size"),
                           "has_poster": bool(ready_asset.get("poster_key")), "source_start_s": src_start, "source_end_s": src_end,
                           "origin_provider": ready_asset.get("origin_provider")})
        return base
    if not video_present:
        base.update(mode="waiting", status="waiting_for_source", message=base["message"] or "Brak źródła tego klipu.")
        return base
    if video_provider == PROVIDER:
        if job:
            base.update(mode="source_range", status=base["stage"] or "saved")
        elif eligible is False:
            base.update(mode="source_range", status="not_exported", message=MSG_TOO_LONG)
        else:
            base.update(mode="source_range", status="virtual", can_order_mp4=True)
        return base
    base.update(mode="source_range", status="source")
    return base


# ─── Bilet meczu: czy link z Bastionu to mecz tego pokoju ───────────────────


def _fold(v: Any) -> str:
    return "".join(ch for ch in str(v or "").casefold() if ch.isalnum())


def same_match(summary: Optional[Mapping[str, Any]], card: Mapping[str, Any]) -> Optional[bool]:
    """True/False/None (brak danych do porównania). Najpierw identyfikator ZPRP meczu, potem para drużyn (w obu
    kolejnościach, bez wielkości liter i znaków specjalnych), potem kod rozgrywek. Nigdy nie zgadujemy przy braku danych."""
    if not summary:
        return None
    mid = _fold(summary.get("zprp_match_id"))
    if mid and _fold(card.get("match_id")):
        return mid == _fold(card.get("match_id"))
    h, a = _fold(summary.get("home")), _fold(summary.get("away"))
    ch, ca = _fold((card.get("home") or {}).get("name")), _fold((card.get("away") or {}).get("name"))
    if h and a and ch and ca:
        return (h == ch and a == ca) or (h == ca and a == ch)
    code, ccode = _fold(summary.get("code")), _fold(card.get("match_code"))
    if code and ccode:
        return code == ccode
    return None


def public_match_summary(summary: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not summary:
        return None
    keep = ("home", "away", "date", "competition", "code", "zprp_match_id", "zprp_season_id", "zprp_competition_id")
    out = {k: summary.get(k) for k in keep if summary.get(k)}
    return out or None
