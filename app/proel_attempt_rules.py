"""Rejestr prób ProEla: czysta logika, bez bazy.

Wydzielone z `app/proel_attempts.py`, bo ten moduł ciągnie `app.db`, a ten przy
imporcie łączy się z bazą - testy tych reguł nie mogą jej wymagać.

Zawiera: słownik etykiet kodów (po polsku, jedno miejsce), walidację i
czyszczenie wpisu z klienta, scalanie epizodu (upsert), podsumowanie oraz
decyzje o pushu.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

MAX_EVENTS = 50
MAX_STEPS = 24
LOGIN_RETENTION_DAYS = 365
DISPUTE_PUSH_WINDOW_SECONDS = 600

KINDS = ("start", "login", "lead")
OUTCOMES = ("ok", "blocked", "bypassed", "abandoned")
BLOCKERS = ("server", "zprp", "network", "app", "other_device", "user")
START_PATHS = ("token", "wczytaj", "rozegraj", "dzisiejszy", "wznowienie", "konfiguracja", "podglad")
LOGIN_PATHS = ("identity_gate", "proel_account", "match_token")
STEP_RESULTS = ("ok", "fail", "skip")

#: Jedyne miejsce z etykietami kodów powodów (kontrakt 25.11.2026).
REASON_LABELS: Dict[str, str] = {
    # start
    "NO_MATCH_NUMBER": "Mecz nie ma numeru",
    "NO_ZPRP_ID": "Mecz nie ma identyfikatora ZPRP",
    "PROEL_ENABLE_FAILED": "Nie udało się włączyć ProEla dla meczu",
    "NO_ZPRP_ACCOUNT": "Brak konta ZPRP przypisanego do sędziego",
    "ZPRP_NOT_CONFIRMED": "ZPRP nie potwierdziło dostępu do meczu",
    "ZPRP_LINK_FAILED": "Nie udało się połączyć meczu z ZPRP",
    "RATE_LIMIT": "Zbyt wiele prób w krótkim czasie",
    "BAD_TOKEN": "Nieprawidłowy token meczu",
    "LIVE_ELSEWHERE": "Mecz trwa już na innym urządzeniu",
    "GATE_UNKNOWN": "Bramka meczu nie rozpoznała tożsamości",
    "VERSION_CONFLICT": "Na serwerze jest nowsza wersja protokołu",
    "MATCH_APPROVED": "Mecz jest już zatwierdzony",
    "MATCH_ID_MISMATCH": "Numer meczu należy do innego meczu",
    "ACCESS_DENIED": "Brak uprawnień do prowadzenia meczu",
    "REJECTED": "Serwer odrzucił próbę",
    "CONFIG_OPEN_FAILED": "Nie udało się otworzyć konfiguracji meczu",
    "NOT_FOUND": "Nie znaleziono meczu",
    "PROEL_COMM_ERROR": "Błąd komunikacji z ProElem",
    "OFFLINE": "Brak połączenia z internetem",
    "TIMEOUT": "Przekroczono czas oczekiwania",
    "SERVER_BREAK": "Awaria po stronie serwera",
    "USER_CANCEL": "Sędzia zrezygnował",
    "LEAD_CONFIRM_DECLINED": "Sędzia nie potwierdził przejęcia prowadzenia",
    # login
    "BAD_CREDENTIALS": "Nieprawidłowy login lub hasło",
    "UNKNOWN_USER": "Nie ma takiego użytkownika",
    "ACCOUNT_DISABLED": "Konto zostało dezaktywowane",
    "PASSWORD_CHANGE_REQUIRED": "Wymagana zmiana hasła",
    "NETWORK": "Błąd sieci przy logowaniu",
    "ZPRP_UNAVAILABLE": "ZPRP jest niedostępne",
    "UNEXPECTED": "Nieoczekiwany błąd logowania",
    # lead
    "LEASE_HELD": "Mecz prowadzi inna osoba",
    "LEASE_LOST": "Prowadzenie meczu przejął ktoś inny",
    "LEASE_SHARED": "Dwie osoby prowadzą ten sam mecz",
    "TAKEOVER_REFUSED": "Odmowa przejęcia prowadzenia",
    "RECLAIM_REFUSED": "Odmowa odzyskania prowadzenia",
    "TAKEN_OVER": "Przejęcie prowadzenia meczu",
    "RECLAIMED": "Odzyskanie prowadzenia meczu",
}

#: Powody, od których zaczyna się spór o prowadzenie (push do adminów).
DISPUTE_REASONS = frozenset({"LEASE_HELD", "LEASE_LOST", "LEASE_SHARED", "TAKEN_OVER"})

_MATCH_CHARS = re.compile(r"[^\w\-./ ]", re.UNICODE)


def reason_label(code: Any) -> str:
    c = str(code or "").strip()
    return REASON_LABELS.get(c, c)


def _text(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] if s else None


def _choice(v: Any, allowed: Iterable[str]) -> Optional[str]:
    s = str(v or "").strip()
    return s if s in tuple(allowed) else None


def _parse_dt(v: Any) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def clean_steps(raw: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for s in raw[:MAX_STEPS]:
        if not isinstance(s, dict):
            continue
        step = _text(s.get("step"), 40)
        result = _choice(s.get("result"), STEP_RESULTS)
        if not step or not result:
            continue
        item: Dict[str, Any] = {"step": step, "result": result}
        ms = s.get("ms")
        if isinstance(ms, (int, float)) and not isinstance(ms, bool) and 0 <= ms < 86_400_000:
            item["ms"] = int(ms)
        reason = _text(s.get("reason"), 40)
        if reason:
            item["reason"] = reason
        out.append(item)
    return out


def clean_device(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    out = {
        "platform": _text(raw.get("platform"), 16),
        "model": _text(raw.get("model"), 60),
        "form": _choice(raw.get("form"), ("phone", "tablet")),
        "os_version": _text(raw.get("os_version"), 24),
    }
    out = {k: v for k, v in out.items() if v}
    return out or None


def clean_event(raw: Any) -> Optional[Dict[str, Any]]:
    """Wpis z klienta -> kolumny albo `None`, gdy nie da się go przyjąć.

    Żadne hasło nie ma tu wejścia: pola są z góry wymienione, reszta ginie.
    """
    if not isinstance(raw, dict):
        return None
    key = _text(raw.get("event_key"), 80)
    kind = _choice(raw.get("kind"), KINDS)
    outcome = _choice(raw.get("outcome"), OUTCOMES)
    if not key or not kind or not outcome:
        return None
    path_ok = START_PATHS if kind == "start" else LOGIN_PATHS if kind == "login" else ()
    official = raw.get("official")
    count = raw.get("count")
    dur = raw.get("duration_ms")
    row: Dict[str, Any] = {
        "event_key": key,
        "kind": kind,
        "outcome": outcome,
        "reason": _text(raw.get("reason"), 40) if outcome != "ok" else None,
        "reason_text": _text(raw.get("reason_text"), 400),
        "blocker": _choice(raw.get("blocker"), BLOCKERS),
        "path": _choice(raw.get("path"), path_ok) if path_ok else None,
        "match_number": _text(_MATCH_CHARS.sub("", str(raw.get("match_number") or "")), 64),
        "zprp_match_id": _text(raw.get("zprp_match_id"), 40),
        "official": official if isinstance(official, bool) else None,
        "actor_judge_id": _text(raw.get("actor_judge_id"), 40),
        "actor_name": _text(raw.get("actor_name"), 120),
        "actor_login": _text(raw.get("actor_login"), 120),
        "actor_install": _text(raw.get("actor_install"), 80),
        "actor_verified": bool(raw.get("actor_verified")),
        "holder_name": _text(raw.get("holder_name"), 120),
        "holder_install": _text(raw.get("holder_install"), 80),
        "steps": clean_steps(raw.get("steps")) or None,
        "duration_ms": int(dur) if isinstance(dur, (int, float)) and not isinstance(dur, bool) and 0 <= dur < 86_400_000 else None,
        "count": max(1, min(int(count), 10_000)) if isinstance(count, (int, float)) and not isinstance(count, bool) else 1,
        "client_at": _parse_dt(raw.get("client_at")),
        "queued": bool(raw.get("queued")),
        "net": _choice(raw.get("net"), ("online", "offline", "unknown")),
        "device": clean_device(raw.get("device")),
        "app_version": _text(raw.get("app_version"), 32),
        "first_at": _parse_dt(raw.get("first_at")),
        "last_at": _parse_dt(raw.get("last_at")),
    }
    return row


def merge_update(existing: Dict[str, Any], incoming: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """Wartości do `UPDATE` przy powtórnym wysłaniu tego samego klucza.

    Aktualizuje wynik, powód, etapy, licznik i `last_at`. Tożsamość (kind, mecz,
    aktor, `created_at`, `escalated_at`) zostaje z pierwszego zapisu, żeby
    późniejsze wysłanie nie mogło jej podmienić.
    """
    out: Dict[str, Any] = {
        "outcome": incoming["outcome"],
        "reason": incoming.get("reason"),
        "reason_text": incoming.get("reason_text") or existing.get("reason_text"),
        "blocker": incoming.get("blocker") or existing.get("blocker"),
        "steps": incoming.get("steps") or existing.get("steps"),
        "duration_ms": incoming.get("duration_ms") if incoming.get("duration_ms") is not None else existing.get("duration_ms"),
        "count": max(int(existing.get("count") or 1), int(incoming.get("count") or 1)),
        "last_at": incoming.get("last_at") or now,
    }
    return out


def bump_episode(existing: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """Kolejna odmowa tego samego epizodu: licznik +1 i `last_at`."""
    return {"count": int(existing.get("count") or 1) + 1, "last_at": now}


def lease_episode_key(code: str, match_number: str, install: str, epoch: int) -> str:
    return f"srv:{code}:{match_number}:{install or '-'}:{int(epoch)}"[:80]


def dispute_push_due(last: Dict[str, float], match_number: str, now_ts: float,
                     window: int = DISPUTE_PUSH_WINDOW_SECONDS) -> bool:
    """Najwyżej jeden push o sporze na mecz na `window` sekund. Zapamiętuje."""
    key = str(match_number or "")
    prev = last.get(key)
    if prev is not None and now_ts - prev < window:
        return False
    if len(last) > 500:
        for old in sorted(last, key=last.get)[:250]:
            last.pop(old, None)
    last[key] = now_ts
    return True


def is_hard_start_block(row: Dict[str, Any]) -> bool:
    """Czy wpis kwalifikuje się do eskalacji (push): blokada startu oficjalnego."""
    return (
        row.get("kind") == "start"
        and row.get("outcome") == "blocked"
        and row.get("official") is True
        and not row.get("escalated_at")
    )


def start_block_push(row: Dict[str, Any]) -> Dict[str, str]:
    who = row.get("actor_name") or "Sędzia"
    nr = row.get("match_number") or "?"
    why = row.get("reason_text") or reason_label(row.get("reason"))
    return {
        "title": "Blokada startu meczu",
        "body": f"{who} od 2 min nie może rozpocząć meczu {nr}. {why}".strip()[:240],
    }


def dispute_push(row: Dict[str, Any]) -> Dict[str, str]:
    nr = row.get("match_number") or "?"
    who = row.get("actor_name") or "Ktoś"
    holder = row.get("holder_name") or "inna osoba"
    code = row.get("reason")
    if code == "TAKEN_OVER":
        body = f"{who} przejął prowadzenie meczu {nr} od: {holder}."
    elif code == "LEASE_LOST":
        body = f"Mecz {nr}: {holder} stracił prowadzenie na rzecz innej osoby."
    else:
        body = f"Mecz {nr}: {who} nie może prowadzić, bo prowadzi {holder}."
    return {"title": "Spór o prowadzenie meczu", "body": body[:240]}


def _median(vals: List[int]) -> Optional[int]:
    if not vals:
        return None
    s = sorted(vals)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else int((s[mid - 1] + s[mid]) / 2)


def summarize(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Podsumowanie z kontraktu. Licznik `count` liczy się jako tyle prób."""
    totals = {k: {o: 0 for o in OUTCOMES} for k in KINDS}
    reasons: Dict[tuple, int] = {}
    people: Dict[str, Dict[str, Any]] = {}
    matches: Dict[str, Dict[str, Any]] = {}
    start_ms: List[int] = []
    for r in rows:
        kind, outcome = r.get("kind"), r.get("outcome")
        n = max(1, int(r.get("count") or 1))
        if kind not in totals or outcome not in totals[kind]:
            continue
        totals[kind][outcome] += n
        if outcome != "ok" and r.get("reason"):
            k = (r["reason"], kind)
            reasons[k] = reasons.get(k, 0) + n
        jid = r.get("actor_judge_id")
        if jid:
            p = people.setdefault(jid, {"judge_id": jid, "name": r.get("actor_name") or "", "blocked": 0, "total": 0})
            p["total"] += n
            if outcome == "blocked":
                p["blocked"] += n
            if r.get("actor_name"):
                p["name"] = r["actor_name"]
        nr = r.get("match_number")
        if nr:
            m = matches.setdefault(nr, {"match_number": nr, "blocked": 0, "lead_conflicts": 0})
            if kind == "lead":
                m["lead_conflicts"] += n
            elif outcome == "blocked":
                m["blocked"] += n
        if kind == "start" and outcome == "ok" and isinstance(r.get("duration_ms"), int):
            start_ms.append(r["duration_ms"])
    top_reasons = [
        {"reason": c, "label": reason_label(c), "kind": k, "count": n}
        for (c, k), n in sorted(reasons.items(), key=lambda kv: -kv[1])[:15]
    ]
    top_people = sorted(people.values(), key=lambda p: (-p["blocked"], -p["total"]))[:15]
    top_matches = sorted(
        (m for m in matches.values() if m["blocked"] or m["lead_conflicts"]),
        key=lambda m: -(m["blocked"] + m["lead_conflicts"]),
    )[:15]
    return {
        "totals": totals,
        "top_reasons": top_reasons,
        "top_people": top_people,
        "matches": top_matches,
        "median_start_ms": _median(start_ms),
    }


def login_cutoff(now: datetime) -> datetime:
    return now - timedelta(days=LOGIN_RETENTION_DAYS)


def login_failure_reason(status_code: int, detail: Any) -> str:
    """Kod powodu nieudanego logowania konta ProEl z odpowiedzi 401/403."""
    text = str(detail or "").lower()
    if status_code == 403:
        return "ACCOUNT_DISABLED"
    if "nie ma takiego" in text:
        return "UNKNOWN_USER"
    return "BAD_CREDENTIALS"
