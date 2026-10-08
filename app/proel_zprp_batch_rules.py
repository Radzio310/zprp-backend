"""Pakiet „Zapisz pełne dane meczu" na serwerze - same reguły, bez sieci i bazy.

MODUŁ-LIŚĆ. Nie importuje ani `app.db` (łączy się z bazą już przy imporcie),
ani pośrednika do ZPRP - wołający podaje dane, a tutaj zapada wyłącznie
decyzja. Dzięki temu cała polityka ponowień i liczenie postępu dają się
sprawdzić testem jednostkowym bez Postgresa i bez baza.zprp.pl.

SKĄD PAKIET
Telefon wysyłał pełne dane po jednym żądaniu na zawodnika i osobę
towarzyszącą, ściśle po kolei: telefon -> nasz serwer -> ZPRP, i z powrotem,
zanim mógł ruszyć następny. Na hali to kilkadziesiąt okrążeń przez słabe wifi,
każde z własnym ryzykiem zgubienia. Teraz telefon oddaje serwerowi cały plan
jednym żądaniem, serwer przechodzi go sam (jedno żywe połączenie do ZPRP, bez
czekania na dziennik), a telefon tylko podgląda postęp i zapala pozycje.

POLITYKA PONOWIEŃ = POLITYKA TELEFONU
Reguły niżej są przepisane 1:1 z `utils/zprpPlayerStats.ts` (`runOne`)
i `utils/zprpSessionRetry.ts`. To ta sama wysyłka, tylko wykonywana w innym
miejscu - sędzia nie może dostać innego wyniku zależnie od tego, czy jego
serwer zna już pakiet, czy jeszcze nie. Zmiana tutaj wymaga zmiany tam.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

# ─────────────────────────── rodzaje pozycji ───────────────────────────

#: Kolejność w pakiecie jest kolejnością wysyłki - ta sama co w telefonie:
#: najpierw numery dopisane na hali (numer jest adresem zawodnika
#: w protokole), potem statystyki zawodników, na końcu osoby towarzyszące.
KINDS = ("number", "player", "official")

#: „Nie ma go w kadrze" - pomijamy TĘ pozycję i idziemy dalej. Każdy rodzaj
#: ma swój kod, a drugi rodzaj cudzego kodu nie rozpoznaje (jak w telefonie).
SKIP_CODE = {
    "number": "PLAYER_NOT_IN_SQUAD",
    "player": "PLAYER_NOT_IN_SQUAD",
    "official": "OFFICIAL_NOT_IN_SQUAD",
}

#: Kody, po których dalsza wysyłka nie ma sensu: zamknięty protokół i
#: wyłączony ProEl blokują KAŻDE kolejne żądanie tego meczu.
STOP_CODES = ("PROTOCOL_LOCKED", "PROEL_INACTIVE")

#: Wpis w dzienniku meczu na rodzaj - te same zdarzenia, które zostawiają
#: pojedyncze trasy (`/player-stats`, `/officials-stats`).
JOURNAL_EVENT = {
    "number": "zprp.players_sent",
    "player": "zprp.players_sent",
    "official": "zprp.officials_sent",
}

# ─────────────────────────── fazy pozycji ───────────────────────────

PENDING = "pending"
ACTIVE = "active"
SENT = "sent"
SKIPPED = "skipped"
FAILED = "failed"
#: Pozycja, na której stanęła cała wysyłka (zamknięty protokół, wyłączony
#: ProEl). Osobna faza, bo telefon nie zapala jej ani na zielono, ani na
#: czerwono - tak samo jak dotąd, gdy pętla kończyła się na niej bez wyniku.
STOPPED = "stopped"

TERMINAL_PHASES = frozenset({SENT, SKIPPED, FAILED, STOPPED})

# ─────────────────────────── stany pakietu ───────────────────────────

RUNNING = "running"
DONE = "done"
STOPPED_JOB = "stopped"

#: Kod zatrzymania przy awarii samej pętli - telefon dośle resztę po staremu.
STOP_INTERNAL = "INTERNAL"

# ─────────────────────────── limity ───────────────────────────

#: Ile razy ponawiamy TYM SAMYM kluczem, zanim uwierzymy w „sesja wygasła".
#: Patrz `SESSION_SOFT_RETRIES` w `utils/zprpSessionRetry.ts`.
SESSION_SOFT_RETRIES = 3
#: Łączny limit prób na pozycję: miękkie ponowienia, odnowienie, ostatnia próba.
SESSION_MAX_ATTEMPTS = SESSION_SOFT_RETRIES + 2

#: Jak długo pakiet żyje w pamięci od ostatniego ruchu. Telefon pyta co
#: ~350 ms, więc kwadrans to zapas na wszystko poza porzuceniem.
JOB_TTL_S = 15 * 60

#: Górna granica pozycji w pakiecie. Mecz to dwa składy po kilkanaście osób,
#: numery i osoby towarzyszące - dwieście to sufit na pomyłkę, nie na mecz.
MAX_ITEMS = 200

#: Ile pakietów naraz trzyma proces. Ochrona pamięci, nie limit ruchu.
MAX_JOBS = 500


def retry_delay_s(attempt: int) -> float:
    """Przerwa przed kolejną próbą - ta sama co `sessionRetryDelayMs` w telefonie.

    Krótka, bo „sesja wygasła" z ZPRP to zwykle trafienie w węzeł, który nie
    widzi jeszcze sesji, a nie przeciążenie - sekundy czekania nic nie dadzą.
    """
    return (160 + 120 * max(0, int(attempt))) / 1000.0


def session_retry_plan(attempt: int, renewed: bool) -> str:
    """Co zrobić po SESSION_EXPIRED przy danej próbie (`sessionRetryPlan`)."""
    if attempt <= SESSION_SOFT_RETRIES:
        return "retry"
    if not renewed:
        return "renew"
    if attempt < SESSION_MAX_ATTEMPTS:
        return "retry"
    return "give-up"


def is_transient(status: Optional[int], code: Optional[str]) -> bool:
    """Awaria przejściowa - kopia `transient()` z telefonu.

    Telefon liczy tak również 502 PROEL_CONFIG (każde >= 500), więc tu też -
    inaczej pakiet poddawałby się szybciej niż wysyłka, którą zastępuje.
    """
    c = str(code or "").upper()
    if c in ("UPSTREAM_TIMEOUT", "UPSTREAM_ERROR"):
        return True
    s = int(status or 0)
    return s == 0 or s == 429 or s >= 500


def next_step(
    kind: str,
    *,
    status: Optional[int],
    code: Optional[str],
    attempt: int,
    renewed: bool,
) -> str:
    """Decyzja po nieudanej próbie jednej pozycji.

    Zwraca jedno z:
      • "stop"  - cały pakiet staje (kod w `STOP_CODES`),
      • "skip"  - tej pozycji nie ma w składzie ZPRP, idziemy dalej,
      • "retry" - po krótkiej przerwie ta sama pozycja jeszcze raz,
      • "renew" - sesja naprawdę wygasła, odnów i ponów,
      • "fail"  - pozycja nieudana, idziemy dalej.

    Kolejność sprawdzeń jest kolejnością z telefonu i ma znaczenie: zamknięty
    protokół wygrywa ze wszystkim, „nie ma w kadrze" z ponowieniem.
    """
    c = str(code or "").upper()
    if c in STOP_CODES:
        return "stop"
    if c == SKIP_CODE.get(kind):
        return "skip"
    if c == "SESSION_EXPIRED":
        plan = session_retry_plan(attempt, renewed)
        if plan == "retry":
            return "retry"
        if plan == "renew":
            return "renew"
        # "give-up" spada niżej, jak w telefonie.
    return step_after_failed_renew(status=status, code=code, attempt=attempt)


def step_after_failed_renew(
    *, status: Optional[int], code: Optional[str], attempt: int
) -> str:
    """Ostatnia furtka: awaria przejściowa w limicie miękkich ponowień.

    W telefonie nieudane odnowienie sesji „spada" do tego samego sprawdzenia
    - a ponieważ odnowienie zdarza się dopiero po trzech próbach, w praktyce
    kończy się to porażką pozycji.
    """
    if is_transient(status, code) and attempt <= SESSION_SOFT_RETRIES:
        return "retry"
    return "fail"


# ─────────────────────────── pozycje i pakiet ───────────────────────────


@dataclass
class BatchItem:
    """Jedno żądanie do ZPRP w pakiecie i to, co się z nim stało."""

    key: str
    kind: str
    #: Treść żądania bez `hash_sesji` - klucz dokłada pętla, bo sesja bywa
    #: odnawiana w trakcie pakietu.
    payload: Dict[str, Any]
    phase: str = PENDING
    status: Optional[int] = None
    code: Optional[str] = None
    message: Optional[str] = None
    #: Odpowiedź związku słowo w słowo przy odmowie „nie ma w kadrze".
    upstream: Optional[str] = None
    sent: Optional[Dict[str, Any]] = None
    attempts: int = 0

    def public(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "phase": self.phase,
            "status": self.status,
            "code": self.code,
            "message": self.message,
            "upstream": self.upstream,
            "sent": self.sent,
            "attempts": self.attempts,
        }


@dataclass
class BatchJob:
    """Pakiet w pamięci procesu. Czyste dane - pętlę prowadzi `proel_zprp_batch`."""

    job_id: str
    id_zawody: int
    hash_sesji: str
    items: List[BatchItem]
    #: Ciało `POST /proel/zprp/auth` - tym samym serwer odnawia sesję sam.
    auth: Optional[Dict[str, Any]] = None
    client_ip: str = ""
    #: Nagłówki tożsamości wysyłającego - do podpisu wpisów w dzienniku.
    actor: Dict[str, Optional[str]] = field(default_factory=dict)
    state: str = RUNNING
    stop_code: Optional[str] = None
    stop_message: Optional[str] = None
    renewed: int = 0
    created_at: float = field(default_factory=time.monotonic)
    touched_at: float = field(default_factory=time.monotonic)
    finished_at: Optional[float] = None
    #: Zdarzenia dziennika już zapisane przez ten pakiet - jeden wpis na rodzaj.
    journaled: Set[str] = field(default_factory=set)
    #: Odnowienie, które odbiło się trwale (zły token, brak w obsadzie) - kolejne
    #: pozycje nie pukają już do `auth.php` z tym samym materiałem.
    renew_error: Optional[Dict[str, Any]] = None


def build_items(
    numbers: Sequence[Any],
    players: Sequence[Any],
    officials: Sequence[Any],
) -> List[BatchItem]:
    """Plan pakietu w kolejności wysyłki. Rzuca `ValueError` ze zdaniem dla logu.

    Wejście to pary {key, payload} (słownik albo obiekt z tymi polami).
    Klucz nadaje telefon i po nim zapala pozycje - musi być niepusty
    i jedyny w pakiecie.
    """
    out: List[BatchItem] = []
    seen: Set[str] = set()
    for kind, rows in zip(KINDS, (numbers, players, officials)):
        for row in rows or []:
            key = _get(row, "key")
            payload = _get(row, "payload")
            key = str(key or "").strip()
            if not key:
                raise ValueError("Pozycja pakietu bez klucza.")
            if key in seen:
                raise ValueError(f"Powtórzony klucz pozycji: {key}.")
            if not isinstance(payload, dict):
                raise ValueError(f"Pozycja {key} bez treści żądania.")
            seen.add(key)
            clean = {k: v for k, v in payload.items() if k != "hash_sesji"}
            out.append(BatchItem(key=key, kind=kind, payload=clean))
    if len(out) > MAX_ITEMS:
        raise ValueError(f"Za dużo pozycji w pakiecie ({len(out)} > {MAX_ITEMS}).")
    return out


def _get(row: Any, name: str) -> Any:
    if isinstance(row, dict):
        return row.get(name)
    return getattr(row, name, None)


def progress(items: Sequence[BatchItem]) -> Dict[str, int]:
    """Liczniki pakietu. `done` = pozycje z rozstrzygnięciem, także zatrzymana."""
    counts = {"done": 0, "total": len(items), SENT: 0, SKIPPED: 0, FAILED: 0}
    for item in items:
        if item.phase in TERMINAL_PHASES:
            counts["done"] += 1
        if item.phase in (SENT, SKIPPED, FAILED):
            counts[item.phase] += 1
    return counts


def snapshot(job: BatchJob) -> Dict[str, Any]:
    """Odpowiedź `GET /proel/zprp/full-batch/{job_id}`."""
    counts = progress(job.items)
    return {
        "job_id": job.job_id,
        "state": job.state,
        "stop_code": job.stop_code,
        "stop_message": job.stop_message,
        "done": counts["done"],
        "total": counts["total"],
        "sent": counts[SENT],
        "skipped": counts[SKIPPED],
        "failed": counts[FAILED],
        # Najświeższy klucz - po odnowieniu w trakcie pakietu telefon ma nim
        # dalej pisać uwagi, zamiast trafić starym w „sesja wygasła".
        "hash_sesji": job.hash_sesji,
        "renewed": job.renewed > 0,
        "items": [item.public() for item in job.items],
    }


def is_expired(job: BatchJob, now: float, ttl_s: float = JOB_TTL_S) -> bool:
    """Pakiet do wyrzucenia z pamięci - liczone od ostatniego ruchu."""
    last = job.finished_at if job.finished_at is not None else job.touched_at
    return now - last > ttl_s


def oldest_first(jobs: Sequence[BatchJob]) -> List[BatchJob]:
    """Kolejność wyrzucania przy przepełnieniu: najpierw skończone, potem najstarsze."""
    return sorted(
        jobs,
        key=lambda j: (j.state == RUNNING, j.finished_at or j.touched_at),
    )
