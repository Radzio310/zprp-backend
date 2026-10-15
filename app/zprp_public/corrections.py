"""Warstwa korekt admina nakładana przy odczycie publicznych danych hurtowni.

Dane źródłowe (``rozgrywki.zprp.pl``) nigdy nie są nadpisywane - synchronizacja
działa jak dotąd. Korekta to osobny wiersz ``zprp_public_corrections``, który
przy odczycie podmienia wartość jednego pola z białej listy. Usunięcie korekty
(``revoked_at``) przywraca dane źródłowe; wiersze zostają jako audyt.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select, update

# Wyłącznie bezpieczne pola prezentacyjne. Nigdy identyfikatory, wyniki,
# daty, statystyki ani dane osobowe poza imieniem/nazwiskiem/zdjęciem.
WHITELIST: dict[str, dict[str, str]] = {
    "club": {"name": "str", "city": "str", "logo_url": "url", "website": "url"},
    "team": {"name": "str", "city": "str"},
    "player": {"first_name": "str", "last_name": "str", "photo_url": "url"},
    "match": {
        "venue_name": "str", "venue_city": "str", "venue_street": "str",
        "venue_number": "str", "venue_capacity": "int",
    },
    "competition": {"name": "str"},
}
ID_COLUMN = {"club": "club_id", "team": "team_id", "player": "player_id", "match": "match_id", "competition": "competition_id"}
_TTL = 30.0
_cache: dict[str, Any] = {"at": 0.0, "data": {}}


def invalidate() -> None:
    _cache["at"] = 0.0


def validate(entity_type: str, field: str, value: Any) -> Any:
    """Zwraca wartość po normalizacji albo ``ValueError`` z komunikatem."""
    fields = WHITELIST.get(entity_type)
    if fields is None:
        raise ValueError("Nieznany entity_type")
    kind = fields.get(field)
    if kind is None:
        raise ValueError(f"Pole {field} nie może być korygowane dla {entity_type}")
    if value is None or (isinstance(value, str) and not value.strip()):
        if field in {"name", "first_name", "last_name"}:
            raise ValueError("Nazwa nie może być pusta")
        return None
    text = str(value).strip()
    if len(text) > 500:
        raise ValueError("Wartość jest za długa")
    if kind == "url":
        if not text.lower().startswith(("https://", "http://")):
            raise ValueError("Adres musi zaczynać się od http(s)://")
        return text
    if kind == "int":
        try:
            number = int(text)
        except ValueError as exc:
            raise ValueError("Wartość musi być liczbą całkowitą") from exc
        if number < 0 or number > 200000:
            raise ValueError("Wartość poza zakresem")
        return str(number)
    return text


def _coerce(entity_type: str, field: str, value: Any) -> Any:
    if value is not None and WHITELIST.get(entity_type, {}).get(field) == "int":
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return value


async def active_overrides() -> dict[str, dict[str, dict[str, Any]]]:
    """{entity_type: {entity_id: {field: value}}} z krótkim cache w pamięci."""
    now = time.monotonic()
    if now - _cache["at"] < _TTL:
        return _cache["data"]
    try:
        from app.db import database, zprp_public_corrections as C

        rows = await database.fetch_all(
            select(C.c.entity_type, C.c.entity_id, C.c.field, C.c.value)
            .where(C.c.revoked_at.is_(None)).order_by(C.c.correction_id)
        )
    except Exception:  # noqa: BLE001 - korekty nigdy nie psują odczytu publicznego
        return _cache["data"] or {}
    data: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        data.setdefault(row["entity_type"], {}).setdefault(row["entity_id"], {})[row["field"]] = _coerce(
            row["entity_type"], row["field"], row["value"]
        )
    _cache.update(at=now, data=data)
    return data


async def apply(entity_type: str, rows: Iterable[Any], id_key: str | None = None) -> None:
    """Nakłada korekty na listę słowników (modyfikuje w miejscu)."""
    items = [r for r in rows if isinstance(r, dict)]
    if not items:
        return
    by_id = (await active_overrides()).get(entity_type)
    if not by_id:
        return
    key = id_key or ID_COLUMN[entity_type]
    for item in items:
        patch = by_id.get(str(item.get(key)))
        if patch:
            item.update(patch)
            item["corrected_fields"] = sorted(set(item.get("corrected_fields") or []) | set(patch))


async def apply_one(entity_type: str, row: dict[str, Any] | None, id_key: str | None = None) -> dict[str, Any] | None:
    if row:
        await apply(entity_type, [row], id_key)
    return row


async def create(entity_type: str, entity_id: str, field: str, value: Any, note: str | None, actor: str) -> dict[str, Any]:
    from app.db import database, zprp_public_corrections as C

    clean = validate(entity_type, field, value)
    now = datetime.now(timezone.utc)
    # Jedna aktywna korekta na pole - poprzednia zostaje w audycie jako wycofana.
    await database.execute(
        update(C).where((C.c.entity_type == entity_type) & (C.c.entity_id == entity_id) & (C.c.field == field) & C.c.revoked_at.is_(None))
        .values(revoked_at=now, revoked_by=f"{actor} (zastąpiona)")
    )
    new_id = await database.fetch_val(
        C.insert().returning(C.c.correction_id).values(entity_type=entity_type, entity_id=entity_id, field=field, value=clean, note=note, actor=actor, created_at=now)
    )
    invalidate()
    return {"correction_id": new_id, "entity_type": entity_type, "entity_id": entity_id, "field": field, "value": clean, "note": note, "actor": actor, "created_at": now}


async def revoke(correction_id: int, actor: str) -> bool:
    from app.db import database, zprp_public_corrections as C

    row = await database.fetch_one(select(C.c.correction_id).where((C.c.correction_id == correction_id) & C.c.revoked_at.is_(None)))
    if not row:
        return False
    await database.execute(update(C).where(C.c.correction_id == correction_id).values(revoked_at=datetime.now(timezone.utc), revoked_by=actor))
    invalidate()
    return True


async def entity_exists(entity_type: str, entity_id: str) -> bool:
    import app.db as db

    name = "zprp_public_competitions" if entity_type == "competition" else f"zprp_public_{entity_type}s"
    table = getattr(db, name)
    column = table.c[ID_COLUMN[entity_type]]
    return bool(await db.database.fetch_val(select(column).where(column == entity_id).limit(1)))
