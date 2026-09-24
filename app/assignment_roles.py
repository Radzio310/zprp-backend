"""
Role sędziów z listy „Sędziowie i Delegaci" baza.zprp.pl - do zapisu i odczytu.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

Synchronizacja niedyspozycji (`province_offtime_sync._scrape_officials`, co 2 h)
przechodzi całą listę oficjeli, a przy każdym stoi kolumna ról: „Sędzia",
„Delegat", „Stolikowy" (parser: `app/zprp/officials._parse_roles_and_partner`).
Do 25.09.2026 te role nigdzie nie trafiały i Automat obsady stawiał na boisku
sędziów, którzy robią już tylko stolik. Teraz zapisujemy je w
`province_judge_zprp_roles` (klucz: okręg kanoniczny + numer sędziego),
a reguła, co z nich wynika, siedzi w `assignment_people.role_refusal`.

  - oficjel jest dopasowany po NUMERZE, a gdy numeru nie ma wśród sędziów
    okręgu - po imieniu i nazwisku (jednoznacznie, jak pary w
    `assignment_pairs`); niejednoznaczny przepada,
  - pusta kolumna ról = „nie wiemy" - wpis i tak zapisujemy (z pustą listą),
    żeby było widać, że synchronizacja go widziała, ale pusta lista niczego
    Automatowi nie zabrania.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from app.assignment_people import normalize_roles
from app.official_roster import person_key


def _s(value: Any) -> str:
    return str(value or "").strip()


#: Kolejność ról w zapisie - stała, żeby porównanie „czy coś się zmieniło"
#: nie zależało od kolejności z listy ZPRP.
ROLE_ORDER = ("sedzia", "delegat", "stolikowy")


def ordered_roles(roles: Iterable[Any]) -> list[str]:
    known = normalize_roles(roles)
    return [role for role in ROLE_ORDER if role in known]


def zprp_roles_by_judge(
    officials: Mapping[str, Mapping[str, Any]],
    judges: Iterable[tuple[Any, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Role z listy oficjeli po numerze sędziego OKRĘGU:
    numer -> {"roles": [...], "roles_text": "...", "name": "..."}.

    `officials` to wynik `_scrape_officials` (numer -> {"name", "roles",
    "roles_text", …}), `judges` - sędziowie okręgu jako (numer, imię i nazwisko).
    """
    known: set[str] = set()
    by_key: dict[str, set[str]] = {}
    for judge_id, name in judges:
        jid = _s(judge_id)
        if not jid:
            continue
        known.add(jid)
        key = person_key(name)
        if key:
            by_key.setdefault(key, set()).add(jid)

    out: dict[str, dict[str, Any]] = {}
    for official_id, item in (officials or {}).items():
        item = item or {}
        own_id = _s(official_id)
        if own_id not in known:
            found = by_key.get(person_key(item.get("name"))) or set()
            own_id = next(iter(found)) if len(found) == 1 else ""
        if not own_id:
            continue
        out[own_id] = {
            "roles": ordered_roles(item.get("roles") or ()),
            "roles_text": _s(item.get("roles_text")),
            "name": _s(item.get("name")),
        }
    return out


def dump_roles(roles: Iterable[Any]) -> str:
    """Role jako napis JSON do kolumny Text."""
    return json.dumps(ordered_roles(roles), ensure_ascii=False)


def load_roles(value: Any) -> list[str]:
    """Kolumna ról do listy - także gdy wróciła napisem albo bajtami."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return []
    if isinstance(value, str):
        if not value.strip():
            return []
        try:
            value = json.loads(value)
        except ValueError:
            return []
    if isinstance(value, (list, tuple)):
        return ordered_roles(value)
    return []


def _stamp(value: Any) -> datetime:
    if not isinstance(value, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def pick_role_rows(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, list[str]]:
    """
    Jeden wpis ról na sędziego spod WSZYSTKICH pisowni okręgu (ŚLĄSKIE /
    SLASKIE): wygrywa najświeższy `updated_at`, przy remisie wiersz pod
    kluczem kanonicznym.
    """
    best: dict[str, tuple[tuple[datetime, bool], list[str]]] = {}
    for row in rows:
        judge_id = _s(row.get("judge_id"))
        if not judge_id:
            continue
        rank = (_stamp(row.get("updated_at")), _s(row.get("province")) == key)
        current = best.get(judge_id)
        if current is None or rank > current[0]:
            best[judge_id] = (rank, load_roles(row.get("roles")))
    return {judge_id: roles for judge_id, (_rank, roles) in best.items()}


def roles_diff(
    existing: Mapping[str, Iterable[Any]],
    wanted: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Numery sędziów, których wpis trzeba zapisać (nowy albo inne role)."""
    out = []
    for judge_id, item in wanted.items():
        before: Optional[Iterable[Any]] = existing.get(judge_id)
        if before is None or ordered_roles(before) != ordered_roles(item.get("roles") or ()):
            out.append(judge_id)
    return sorted(out)
