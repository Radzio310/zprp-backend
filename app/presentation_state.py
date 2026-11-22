"""Tryb prezentacji - stan, dopasowanie kont, dziennik i nakładka.

Zasady (`docs/presentation-mode.md`):

* Stan czytamy z bazy najwyżej raz na `REFRESH_S` sekund (pamięć procesu), więc
  przy wyłączonym trybie middleware kosztuje jedno porównanie i nic więcej.
* Tryb wygasa sam (`expires_at`); przy wygaśnięciu albo wyłączeniu nakładka znika.
* Konto prezentacji to `{"kind": "judge", "value": "5124"}` (numer sędziego) albo
  `{"kind": "login", "value": "ks_slzpr"}` (login ZPRP). Konto podane numerem
  rozpoznajemy też po loginie, gdy raz przyszło z tokenem (`learned`) albo gdy
  `baza_vips` wiąże login z numerem.
* Nakładka (`presentation_overlay`) to jedyne miejsce, w które tryb cokolwiek
  pisze poza własnym stanem i dziennikiem. Czytają ją tylko konta objęte trybem.

Moduł nie importuje `app.db` na poziomie modułu - testy podstawiają atrapę.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

log = logging.getLogger("presentation")

AREAS: Tuple[str, ...] = ("market", "obsada", "settlements", "offtimes", "announcements", "events", "ratings")
#: Polskie nazwy obszarów (Ustawienia panelu).
AREA_LABELS: Dict[str, str] = {
    "market": "Giełda",
    "obsada": "Obsada",
    "settlements": "Rozliczenia",
    "offtimes": "Niedyspozycje",
    "announcements": "Ogłoszenia",
    "events": "Wydarzenia i formularze",
    "ratings": "Oceny młodych",
}
DEFAULT_MINUTES = 180
MIN_MINUTES = 15
MAX_MINUTES = 480
#: Co ile sekund najwyżej pytamy bazę o stan (każdy proces osobno).
REFRESH_S = 3.0
#: Identyfikatory udawanych ofert i zgłoszeń: daleko od prawdziwych numerów.
SYNTH_BASE = 900_000_000
#: Pola, które nigdy nie trafiają do dziennika.
SECRET_KEYS = frozenset({"password", "haslo", "pass", "username", "login_password", "token", "seal"})
MAX_PAYLOAD_CHARS = 8000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _loads(raw: Any, default: Any) -> Any:
    if raw is None or raw == "":
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _utc(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def _iso(value: Any) -> Optional[str]:
    stamp = _utc(value)
    return stamp.isoformat() if stamp else None


def clean_accounts(raw: Any) -> List[Dict[str, str]]:
    """Lista kont bez duplikatów; nieznany rodzaj = numer sędziego."""
    out: List[Dict[str, str]] = []
    seen = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        kind = "login" if _s(item.get("kind")) == "login" else "judge"
        value = _s(item.get("value"))
        if kind == "login":
            value = value.lower()
        if not value or len(value) > 80 or (kind, value) in seen:
            continue
        seen.add((kind, value))
        out.append({"kind": kind, "value": value, "label": _s(item.get("label"))[:120] or value})
    return out[:50]


#: Obszary, które znał zapis stanu sprzed dodania „ratings" (zapis jako zwykła lista).
LEGACY_AREAS: Tuple[str, ...] = ("market", "obsada", "settlements", "offtimes", "announcements", "events")


def clean_areas(raw: Any) -> List[str]:
    if raw is None:
        return list(AREAS)
    wanted = {_s(a) for a in raw} if isinstance(raw, list) else set()
    return [a for a in AREAS if a in wanted]


def unknown_areas(raw: Any) -> List[str]:
    """Nazwy spoza `AREAS` - PUT /presentation/state odpowiada na nie 400."""
    return [_s(a) for a in raw or [] if _s(a) not in AREAS] if isinstance(raw, list) else ["?"]


def stored_areas(raw: Any) -> List[str]:
    """Obszary z zapisu stanu. Obszar dodany PO zapisie jest domyślnie włączony.

    Zapis to `{"on": [...], "known": [...]}`; starszy zapis (sama lista) znał
    `LEGACY_AREAS`. Czego zapis nie znał, tego nikt nie wyłączył.
    """
    data = _loads(raw, None)
    if data is None:
        return list(AREAS)
    if isinstance(data, dict):
        on, known = data.get("on") or [], data.get("known") or list(LEGACY_AREAS)
    else:
        on, known = data, list(LEGACY_AREAS)
    wanted = {_s(a) for a in on} | {a for a in AREAS if a not in {_s(k) for k in known}}
    return [a for a in AREAS if a in wanted]


def areas_record(areas: List[str]) -> Dict[str, Any]:
    return {"on": [a for a in AREAS if a in set(areas)], "known": list(AREAS)}


def clamp_minutes(raw: Any) -> int:
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MINUTES
    return max(MIN_MINUTES, min(MAX_MINUTES, minutes))


@dataclass
class State:
    enabled: bool = False
    accounts: List[Dict[str, str]] = field(default_factory=list)
    areas: FrozenSet[str] = frozenset(AREAS)
    expires_at: Optional[datetime] = None
    enabled_by: Optional[str] = None
    updated_at: Optional[datetime] = None
    #: login (małe litery) -> numer sędziego, dla kont podanych numerem.
    learned: Dict[str, str] = field(default_factory=dict)
    #: to samo z `baza_vips` (nie zapisujemy, czytamy przy odświeżeniu).
    vip_logins: Dict[str, str] = field(default_factory=dict)

    def active(self, now: Optional[datetime] = None) -> bool:
        if not self.enabled:
            return False
        return self.expires_at is None or self.expires_at > (now or _now())

    @property
    def judge_values(self) -> FrozenSet[str]:
        return frozenset(a["value"] for a in self.accounts if a["kind"] == "judge")

    @property
    def login_values(self) -> FrozenSet[str]:
        return frozenset(a["value"] for a in self.accounts if a["kind"] == "login")

    def account_for(self, *, judge_id: Any = "", login: Any = "") -> Optional[str]:
        """Klucz konta prezentacji (`judge:5124` / `login:ks_slzpr`) albo None."""
        jid = _s(judge_id)
        lg = _s(login).lower()
        judges = self.judge_values
        if jid and jid in judges:
            return f"judge:{jid}"
        if lg and lg in self.login_values:
            return f"login:{lg}"
        if lg:
            mapped = self.learned.get(lg) or self.vip_logins.get(lg)
            if mapped and mapped in judges:
                return f"judge:{mapped}"
        return None


#: Przebieg „na sucho": handler liczy naprawdę, ale nie zapisuje swojego śladu
#: (dziś: Automat obsady nie dopisuje przebiegu do historii). Ustawia go
#: wyłącznie symulator trybu prezentacji na czas wewnętrznego wywołania.
DRY_RUN: "contextvars.ContextVar[bool]" = contextvars.ContextVar("presentation_dry_run", default=False)


def dry_run() -> bool:
    return DRY_RUN.get()


_state = State()
_loaded_at = float("-inf")
_lock: Optional[asyncio.Lock] = None
_pending_learn: Dict[str, str] = {}


def cached_state() -> State:
    return _state


def reset_cache() -> None:
    """Testy i zapis stanu: następne `current()` czyta bazę."""
    global _loaded_at
    _loaded_at = float("-inf")


def _db():
    from app import db as module

    return module


async def _read_row() -> Optional[Dict[str, Any]]:
    db = _db()
    row = await db.database.fetch_one(db.presentation_state.select().where(db.presentation_state.c.id == 1))
    return dict(row._mapping) if hasattr(row, "_mapping") else (dict(row) if row else None)


def _state_from_row(row: Optional[Dict[str, Any]]) -> State:
    if not row:
        return State()
    return State(
        enabled=bool(row.get("enabled")),
        accounts=clean_accounts(_loads(row.get("accounts_json"), [])),
        areas=frozenset(stored_areas(row.get("areas_json"))),
        expires_at=_utc(row.get("expires_at")),
        enabled_by=_s(row.get("enabled_by")) or None,
        updated_at=_utc(row.get("updated_at")),
        learned={_s(k).lower(): _s(v) for k, v in (_loads(row.get("learned_logins_json"), {}) or {}).items()},
    )


async def _vip_logins(judges: FrozenSet[str]) -> Dict[str, str]:
    if not judges:
        return {}
    try:
        db = _db()
        table = db.baza_vips
        rows = await db.database.fetch_all(
            table.select().with_only_columns(table.c.username, table.c.judge_id).where(table.c.judge_id.in_(sorted(judges)))
        )
        return {_s(r["username"]).lower(): _s(r["judge_id"]) for r in rows if _s(r["username"])}
    except Exception:  # noqa: BLE001 - brak tabeli albo atrapa w testach
        return {}


async def current(force: bool = False) -> State:
    """Stan z pamięci, odświeżany z bazy najwyżej co `REFRESH_S` sekund."""
    global _state, _loaded_at, _lock
    if not force and time.monotonic() - _loaded_at < REFRESH_S:
        return _state
    if _lock is None:
        _lock = asyncio.Lock()
    async with _lock:
        if not force and time.monotonic() - _loaded_at < REFRESH_S:
            return _state
        try:
            fresh = _state_from_row(await _read_row())
        except Exception:  # noqa: BLE001
            # Baza chwilowo nie odpowiada: zostaje ostatni znany stan (także
            # włączony - bezpieczniej udawać dalej niż nagle zapisać naprawdę).
            log.warning("tryb prezentacji: odczyt stanu nieudany", exc_info=True)
            _loaded_at = time.monotonic()
            return _state
        if fresh.enabled and not fresh.active():
            await _auto_disable()
            fresh.enabled = False
        if fresh.active():
            fresh.vip_logins = await _vip_logins(fresh.judge_values)
            fresh.learned.update(_pending_learn)
        _state = fresh
        _loaded_at = time.monotonic()
        return _state


async def _auto_disable() -> None:
    try:
        db = _db()
        await db.database.execute(
            db.presentation_state.update()
            .where(db.presentation_state.c.id == 1)
            .values(enabled=False, updated_at=_now())
        )
        cleared = await overlay_clear()
        log.info("tryb prezentacji: wygasł, nakładka wyczyszczona (%s)", cleared)
    except Exception:  # noqa: BLE001
        log.warning("tryb prezentacji: automatyczne wyłączenie nieudane", exc_info=True)


async def save_state(
    *,
    enabled: bool,
    accounts: List[Dict[str, str]],
    areas: List[str],
    minutes: Optional[int],
    enabled_by: str,
) -> State:
    """Zapis stanu. `minutes=None` przy włączonym trybie = zostaje dotychczasowy termin."""
    db = _db()
    previous = _state_from_row(await _read_row())
    now = _now()
    if not enabled:
        expires = None
    elif minutes is None and previous.active(now):
        expires = previous.expires_at
    else:
        expires = now + timedelta(minutes=clamp_minutes(minutes if minutes is not None else DEFAULT_MINUTES))
    values = {
        "enabled": bool(enabled),
        "accounts_json": _dumps(accounts),
        "areas_json": _dumps(areas_record(areas)),
        "expires_at": expires,
        "enabled_by": enabled_by if enabled and not previous.active(now) else (previous.enabled_by or enabled_by),
        "updated_at": now,
        "learned_logins_json": _dumps(previous.learned),
    }
    exists = await db.database.fetch_val(
        db.presentation_state.select().with_only_columns(db.presentation_state.c.id).where(db.presentation_state.c.id == 1)
    )
    if exists:
        await db.database.execute(db.presentation_state.update().where(db.presentation_state.c.id == 1).values(**values))
    else:
        await db.database.execute(db.presentation_state.insert().values(id=1, **values))
    if not enabled:
        await overlay_clear()
    reset_cache()
    return await current(force=True)


def learn(login: Any, judge_id: Any, *, schedule: bool = True) -> bool:
    """Konto podane numerem przyszło z tokenem - zapamiętaj jego login ZPRP.

    Zwraca True, gdy login jest nowy. `schedule=False`: zapis woła sam wołający
    (`await persist_learned()`), bez zadania w tle.
    """
    lg, jid = _s(login).lower(), _s(judge_id)
    if not lg or not jid or jid not in _state.judge_values or _state.learned.get(lg) == jid:
        return False
    _state.learned[lg] = jid
    _pending_learn[lg] = jid
    if schedule:
        try:
            asyncio.get_running_loop().create_task(persist_learned())
        except RuntimeError:
            pass
    return True


async def persist_learned() -> None:
    try:
        db = _db()
        row = await _read_row()
        merged = {**(_loads((row or {}).get("learned_logins_json"), {}) or {}), **_pending_learn}
        await db.database.execute(
            db.presentation_state.update()
            .where(db.presentation_state.c.id == 1)
            .values(learned_logins_json=_dumps(merged))
        )
    except Exception:  # noqa: BLE001
        log.warning("tryb prezentacji: zapis poznanego loginu nieudany", exc_info=True)


# ───────────────────────────── dziennik ─────────────────────────────


def sanitize(value: Any, depth: int = 0) -> Any:
    """Kopia ładunku bez haseł i loginów (szyfrogramów też nie trzymamy)."""
    if depth > 6:
        return "…"
    if isinstance(value, dict):
        return {
            k: ("***" if _s(k).lower() in SECRET_KEYS else sanitize(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize(v, depth + 1) for v in value[:100]]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…"
    return value


async def record_op(
    *, account: str, area: str, method: str, path: str, summary: str, payload: Any = None, extra: Any = None
) -> Optional[int]:
    db = _db()
    body = _dumps(sanitize(payload)) if payload is not None else None
    if body and len(body) > MAX_PAYLOAD_CHARS:
        body = body[:MAX_PAYLOAD_CHARS]
    try:
        return await db.database.execute(
            db.presentation_ops.insert().values(
                at=_now(),
                account=account[:160],
                area=area[:40],
                method=method[:10],
                path=path[:400],
                summary_json=_dumps({"text": summary, **({"extra": sanitize(extra)} if extra else {})}),
                payload_json=body,
            )
        )
    except Exception:  # noqa: BLE001 - dziennik nie ma prawa zepsuć udawanej odpowiedzi
        log.warning("tryb prezentacji: zapis dziennika nieudany", exc_info=True)
        return None


async def ops_count() -> int:
    db = _db()
    try:
        from sqlalchemy import func, select

        return int(await db.database.fetch_val(select(func.count()).select_from(db.presentation_ops)) or 0)
    except Exception:  # noqa: BLE001
        return 0


async def list_ops(limit: int = 100) -> List[Dict[str, Any]]:
    db = _db()
    t = db.presentation_ops
    rows = await db.database.fetch_all(t.select().order_by(t.c.id.desc()).limit(max(1, min(500, int(limit)))))
    out = []
    for r in rows:
        summary = _loads(r["summary_json"], {}) or {}
        out.append(
            {
                "id": r["id"],
                "at": _iso(r["at"]),
                "account": r["account"],
                "area": r["area"],
                "method": r["method"],
                "path": r["path"],
                "summary": _s(summary.get("text")) if isinstance(summary, dict) else _s(summary),
            }
        )
    return out


async def clear_ops() -> int:
    db = _db()
    count = await ops_count()
    await db.database.execute(db.presentation_ops.delete())
    await overlay_clear()
    return count


# ───────────────────────────── nakładka ─────────────────────────────


async def overlay_add(kind: str, key: Any, data: Dict[str, Any]) -> int:
    db = _db()
    return int(
        await db.database.execute(
            db.presentation_overlay.insert().values(kind=kind, key=_s(key), data_json=_dumps(data), created_at=_now())
        )
    )


async def overlay_list(kind: str, key: Any = None) -> List[Tuple[int, Dict[str, Any]]]:
    db = _db()
    t = db.presentation_overlay
    query = t.select().where(t.c.kind == kind)
    if key is not None:
        query = query.where(t.c.key == _s(key))
    rows = await db.database.fetch_all(query.order_by(t.c.id))
    return [(int(r["id"]), _loads(r["data_json"], {}) or {}) for r in rows]


async def overlay_get(kind: str, key: Any) -> Optional[Tuple[int, Dict[str, Any]]]:
    rows = await overlay_list(kind, key)
    return rows[-1] if rows else None


async def overlay_put(row_id: int, data: Dict[str, Any]) -> None:
    db = _db()
    t = db.presentation_overlay
    await db.database.execute(t.update().where(t.c.id == row_id).values(data_json=_dumps(data)))


async def overlay_upsert(kind: str, key: Any, data: Dict[str, Any]) -> int:
    found = await overlay_get(kind, key)
    if found:
        await overlay_put(found[0], data)
        return found[0]
    return await overlay_add(kind, key, data)


async def overlay_clear() -> int:
    db = _db()
    t = db.presentation_overlay
    try:
        from sqlalchemy import func, select

        count = int(await db.database.fetch_val(select(func.count()).select_from(t)) or 0)
        await db.database.execute(t.delete())
        return count
    except Exception:  # noqa: BLE001
        log.warning("tryb prezentacji: czyszczenie nakładki nieudane", exc_info=True)
        return 0


async def next_synthetic_id() -> int:
    """Numer udawanej oferty/zgłoszenia - z licznika w nakładce (unikat w trybie)."""
    found = await overlay_get("counter", "ids")
    n = int((found[1] if found else {}).get("n") or 0) + 1
    if found:
        await overlay_put(found[0], {"n": n})
    else:
        await overlay_add("counter", "ids", {"n": n})
    return SYNTH_BASE + n


def is_synthetic(value: Any) -> bool:
    try:
        return int(value) >= SYNTH_BASE
    except (TypeError, ValueError):
        return False
