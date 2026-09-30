# app/training_events_rules.py
#
# Reguły okresów szkoleniowych - bez bazy danych, więc z testem, który
# uruchomi się wszędzie (patrz `tests/test_training_events_rules.py`).
#
# Okres szkoleniowy to jedno wydarzenie: tytuł, okno widoczności, flaga
# włączenia i własna lista pełnych meczów. Administrator zakłada ich wiele,
# a stare zostają - ich przebiegi w `training_run` są przypięte identyfikatorem
# okresu (`event_id`), więc zmiana identyfikatora albo użycie go drugi raz
# pomieszałoby wyniki dwóch różnych szkoleń.
#
# Okresy sprzed tej zmiany nie mają własnego wiersza (tabela trzymała jeden,
# nadpisywany w miejscu). Odtwarzamy je z samych przebiegów: identyfikator,
# mecze i daty wynikają z tego, co sędziowie faktycznie poprowadzili.

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

_YMD = re.compile(r"^\d{4}-\d{2}-\d{2}$")
#: Identyfikator okresu idzie w adres i w każdy przebieg - bez spacji i znaków,
#: które trzeba by kodować.
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")

STATUS_ACTIVE = "active"
STATUS_SCHEDULED = "scheduled"
STATUS_ENDED = "ended"
STATUS_DISABLED = "disabled"
STATUS_ARCHIVED = "archived"
STATUS_RECOVERED = "recovered"


class PeriodError(ValueError):
    """Odmowa zapisu okresu - komunikat idzie wprost do administratora."""


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def clean_date(value: Any, field: str) -> str:
    text = _s(value)
    if not text:
        return ""
    if not _YMD.match(text):
        raise PeriodError(f"Pole {field} ma mieć postać RRRR-MM-DD albo zostać puste.")
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise PeriodError(f"Pole {field} zawiera datę, której nie ma w kalendarzu ({text}).") from exc
    return text


def valid_key(key: Any) -> bool:
    return bool(_KEY.match(_s(key)))


def normalize_period(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Payload okresu po walidacji. Rzuca `PeriodError` z wyjaśnieniem."""
    raw = raw or {}
    key = _s(raw.get("id"))
    title = _s(raw.get("title"))
    if not key or not title:
        raise PeriodError("Okres musi mieć identyfikator i tytuł.")
    if not valid_key(key):
        raise PeriodError(
            "Identyfikator okresu może zawierać tylko litery bez ogonków, cyfry, "
            "kropkę, dywiz i podkreślnik (do 80 znaków)."
        )

    visible_from = clean_date(raw.get("visibleFrom"), "visibleFrom")
    visible_to = clean_date(raw.get("visibleTo"), "visibleTo")
    if visible_from and visible_to and visible_from > visible_to:
        raise PeriodError("Początek okna widoczności jest późniejszy niż koniec.")

    matches: List[Dict[str, Any]] = []
    seen: set = set()
    for m in raw.get("matches") or []:
        m = m or {}
        zprp_id = _s(m.get("zprpMatchId"))
        number = _s(m.get("matchNumber"))
        if not zprp_id or not number:
            continue
        if not zprp_id.isdigit():
            raise PeriodError(
                f"IdZawody {zprp_id} nie jest liczbą - w bazie ZPRP to zawsze liczba."
            )
        if number in seen:
            # Wyniki są przypięte do pary (okres, numer meczu), więc dwa mecze
            # o tym samym numerze w jednym okresie zlałyby się w analizie.
            raise PeriodError(
                f"Mecz {number} jest na liście dwa razy - w jednym okresie numer meczu musi być unikalny."
            )
        seen.add(number)
        matches.append(
            {
                "zprpMatchId": zprp_id,
                "matchNumber": number,
                "label": _s(m.get("label")) or None,
            }
        )

    return {
        "id": key,
        "enabled": raw.get("enabled") is not False,
        "title": title,
        "subtitle": _s(raw.get("subtitle")) or None,
        "visibleFrom": visible_from,
        "visibleTo": visible_to,
        "matches": matches,
    }


def _today(today: Optional[date]) -> str:
    return (today or date.today()).isoformat()


def is_visible(payload: Dict[str, Any], archived: bool = False, today: Optional[date] = None) -> bool:
    """Ta sama reguła, co `isTrainingEventVisible` w aplikacji."""
    if archived or not payload or payload.get("enabled") is False:
        return False
    if not payload.get("matches"):
        return False
    t = _today(today)
    vf = _s(payload.get("visibleFrom"))
    vt = _s(payload.get("visibleTo"))
    if vf and t < vf:
        return False
    if vt and t > vt:
        return False
    return True


def period_status(
    payload: Dict[str, Any],
    archived: bool = False,
    recovered: bool = False,
    today: Optional[date] = None,
) -> str:
    if recovered:
        return STATUS_RECOVERED
    if archived:
        return STATUS_ARCHIVED
    t = _today(today)
    vt = _s(payload.get("visibleTo"))
    if vt and t > vt:
        return STATUS_ENDED
    if payload.get("enabled") is False:
        return STATUS_DISABLED
    vf = _s(payload.get("visibleFrom"))
    if vf and t < vf:
        return STATUS_SCHEDULED
    return STATUS_ACTIVE


_STATUS_RANK = {
    STATUS_ACTIVE: 0,
    STATUS_SCHEDULED: 1,
    STATUS_DISABLED: 2,
    STATUS_ENDED: 2,
    STATUS_ARCHIVED: 3,
    STATUS_RECOVERED: 4,
}


def _sort_date(p: Dict[str, Any]) -> str:
    return _s(p.get("visibleTo")) or _s(p.get("visibleFrom")) or _s(p.get("updatedAt"))[:10]


def sort_periods(periods: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Trwające na górze, potem zaplanowane, potem przeszłe od najnowszego.

    Wymaga pola `status` (patrz `period_status`). Zaplanowane rosnąco po
    początku - najbliższy pierwszy; wszystkie pozostałe malejąco po dacie.
    """
    buckets: Dict[int, List[Dict[str, Any]]] = {}
    for p in periods:
        buckets.setdefault(_STATUS_RANK.get(_s(p.get("status")), 5), []).append(p)
    out: List[Dict[str, Any]] = []
    for rank in sorted(buckets):
        items = buckets[rank]
        if rank == 1:
            # Najbliższy start pierwszy.
            items = sorted(items, key=lambda p: (_s(p.get("visibleFrom")) or "9999", _s(p.get("id"))))
        else:
            items = sorted(items, key=lambda p: (_sort_date(p), _s(p.get("id"))), reverse=True)
        out.extend(items)
    return out


def _ymd(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    text = _s(value)
    return text[:10] if _YMD.match(text[:10]) else ""


def _match_sort_key(m: Dict[str, Any]):
    return (_s(m.get("_first")) or "9999", _s(m.get("matchNumber")))


def recover_periods(
    run_rows: Iterable[Dict[str, Any]],
    known_keys: Iterable[str] = (),
) -> List[Dict[str, Any]]:
    """Okresy odtworzone z przebiegów, których nie ma w `training_event`.

    Każdy wiersz wejścia to agregat jednej pary (okres, mecz):
    `event_id`, `match_number`, `zprp_match_id`, `first_at`, `last_at`,
    `runs` oraz opcjonalnie `title` (z `data_json -> matchConfig -> training`).
    Okno dat bierzemy z pierwszego i ostatniego przebiegu - to nie jest okno
    widoczności, które kiedyś ustawiono, tylko czas, w którym faktycznie
    ćwiczono. Nic lepszego się nie zachowało.
    """
    known = {_s(k) for k in known_keys if _s(k)}
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in run_rows:
        row = dict(row or {})
        key = _s(row.get("event_id"))
        number = _s(row.get("match_number"))
        if not key or not number or key in known:
            continue
        first = _ymd(row.get("first_at"))
        last = _ymd(row.get("last_at"))
        runs = int(row.get("runs") or 0)
        title = _s(row.get("title"))
        p = grouped.setdefault(
            key,
            {
                "id": key,
                "enabled": False,
                "title": "",
                "subtitle": None,
                "visibleFrom": "",
                "visibleTo": "",
                "matches": [],
                "runsCount": 0,
            },
        )
        if title and not p["title"]:
            p["title"] = title
        if first and (not p["visibleFrom"] or first < p["visibleFrom"]):
            p["visibleFrom"] = first
        if last and (not p["visibleTo"] or last > p["visibleTo"]):
            p["visibleTo"] = last
        p["runsCount"] += runs
        existing = next((m for m in p["matches"] if m["matchNumber"] == number), None)
        zprp_id = _s(row.get("zprp_match_id"))
        if existing is None:
            p["matches"].append(
                {"zprpMatchId": zprp_id, "matchNumber": number, "label": None, "_first": first}
            )
        else:
            if not existing["zprpMatchId"] and zprp_id:
                existing["zprpMatchId"] = zprp_id
            if first and (not existing["_first"] or first < existing["_first"]):
                existing["_first"] = first

    out: List[Dict[str, Any]] = []
    for p in grouped.values():
        p["matches"] = [
            {k: v for k, v in m.items() if k != "_first"}
            for m in sorted(p["matches"], key=_match_sort_key)
        ]
        if not p["title"]:
            p["title"] = f"Okres {p['id']}"
        p["recovered"] = True
        p["archived"] = True
        p["status"] = STATUS_RECOVERED
        out.append(p)
    return out


def first_visible(
    rows: Sequence[Dict[str, Any]], today: Optional[date] = None
) -> Optional[Dict[str, Any]]:
    """Payload dla starych aplikacji, które znają tylko jeden okres.

    `rows` - wiersze od najnowszego, każdy z `payload` i `archived`. Wygrywa
    pierwszy widoczny dzisiaj; gdy żaden, najnowszy niezarchiwizowany (stara
    aplikacja sama sprawdzi daty i kafelka nie pokaże).
    """
    fallback: Optional[Dict[str, Any]] = None
    for r in rows:
        payload = r.get("payload") or {}
        archived = bool(r.get("archived"))
        if not payload:
            continue
        if is_visible(payload, archived, today):
            return payload
        if fallback is None and not archived:
            fallback = payload
    return fallback
