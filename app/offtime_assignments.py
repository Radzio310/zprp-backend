"""
Niedyspozycje wpisywane sędziom przez obsadowego / Calendar Mastera / admina (12.11.2026).

Trasy `/silesia/offtimes/assigned` (kontrakt wspólny z panelem web):

  GET    ?province=P[&judge_id=J]  -> {items}
  POST   {province, judge_ids[], from, to?, info?, category_*}  -> {items}  (wiersz na sędziego)
  PATCH  /{id}  {from?, to?, info?, category_*}                 -> {item}
  DELETE /{id}                                                  -> {ok: true}

Tożsamość i rola WYŁĄCZNIE z tokenu + baz (admin / Calendar Master okręgu /
odznaka Obsadowy w WŁASNYM okręgu z `province_judges`). Okręg zmiany i usunięcia
bierzemy z wiersza w bazie, nie z żądania. Sędzia dostaje push przy dodaniu,
zmianie i usunięciu - deep-link `kind: offtime_assigned` (jeden dispatcher w apce).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import select, update

from app.db import database, province_judges, silesia_offtime_assignments as T
from app.deps import get_jwt_payload
from app.offtime_assignments_rules import (
    assigner_role,
    build_item,
    clean_judge_ids,
    normalize_fields,
    push_data,
    push_text,
)
from app.province_access import normalize_province
from app.province_guard import _read_access_lists, actor_judge_id
from app.settlement_province import spellings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/silesia/offtimes/assigned", tags=["Silesia - Offtimes assigned"])


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _forbidden(province: Any) -> HTTPException:
    prov = normalize_province(province)
    where = f" w okręgu {prov}" if prov else ""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"Wpisywanie niedyspozycji innym sędziom{where} wymaga odznaki Obsadowy, "
            "uprawnień Calendar Mastera albo administratora."
        ),
    )


async def _actor(payload: Optional[dict], province: Any) -> Dict[str, Any]:
    """Kim jest piszący w tym okręgu: {id, name, role}. 403, gdy nikim uprawnionym."""
    judge_id = actor_judge_id(payload)
    if not judge_id or str((payload or {}).get("account_type") or "").lower() == "org":
        raise _forbidden(province)
    masters, admins = await _read_access_lists("calendar", province)
    row = await database.fetch_one(
        select(province_judges).where(province_judges.c.judge_id == judge_id)
    )
    role = assigner_role(
        judge_id=judge_id,
        province=province,
        admin_ids=admins,
        calendar_master_ids=masters,
        judge_province=row["province"] if row else None,
        badges_raw=row["badges"] if row else None,
    )
    if role is None:
        raise _forbidden(province)
    name = (row["full_name"] if row else "") or str(
        (payload or {}).get("full_name") or (payload or {}).get("name") or ""
    )
    return {"id": judge_id, "name": str(name or ""), "role": role}


async def _load(item_id: str):
    row = await database.fetch_one(select(T).where(T.c.id == item_id))
    if row is None or row["deleted_at"] is not None:
        raise HTTPException(status_code=404, detail="Nie znaleziono tej niedyspozycji.")
    return row


async def _notify(action: str, row: Any, actor: Dict[str, Any]) -> None:
    """Push do sędziego. Nigdy nie wywraca zapisu, przy którym powstał."""
    if str(row["judge_id"]) == actor["id"]:
        return
    try:
        from app.push.push import send_push_to_judges

        title, body = push_text(
            action,
            role=actor["role"],
            start=row["from"],
            end=row["to"],
            category=row["category_name"],
            author_name=actor["name"],
        )
        await send_push_to_judges(
            [str(row["judge_id"])],
            title,
            body,
            push_data(
                item_id=str(row["id"]),
                province=str(row["province"]),
                start=row["from"],
                action=action,
            ),
            app_variant="baza",
        )
    except Exception:  # noqa: BLE001
        logger.warning("niedyspo od obsadowego: push nieudany", exc_info=True)


@router.get("", summary="Niedyspozycje wpisane sędziom (okręg, opcjonalnie sędzia)")
async def list_assigned(
    province: str = Query(...),
    judge_id: Optional[str] = Query(None),
    token_payload: dict = Depends(get_jwt_payload),
):
    me = actor_judge_id(token_payload)
    if not (judge_id and str(judge_id).strip() == me):
        await _actor(token_payload, province)
    rows = await database.fetch_all(
        select(T).where(T.c.province.in_(spellings(province)), T.c.deleted_at.is_(None))
    )
    items = [
        build_item(r)
        for r in rows
        if not judge_id or str(r["judge_id"]) == str(judge_id).strip()
    ]
    items.sort(key=lambda i: (str(i["from"]), i["id"]))
    return {"items": items}


@router.post("", summary="Wpisz niedyspozycję jednemu lub kilku sędziom")
async def create_assigned(
    body: Dict[str, Any] = Body(...),
    token_payload: dict = Depends(get_jwt_payload),
):
    province = str(body.get("province") or "").strip()
    if not province:
        raise HTTPException(status_code=422, detail="Podaj okręg.")
    actor = await _actor(token_payload, province)
    targets = clean_judge_ids(body.get("judge_ids"))
    if not targets:
        raise HTTPException(status_code=422, detail="Wybierz sędziego.")
    try:
        fields = normalize_fields(body)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))

    known = await database.fetch_all(
        select(province_judges.c.judge_id).where(
            province_judges.c.province.in_(spellings(province)),
            province_judges.c.judge_id.in_(targets),
        )
    )
    known_ids = {str(r["judge_id"]) for r in known}
    missing = [j for j in targets if j not in known_ids]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Sędzia {', '.join(missing)} nie jest na liście okręgu {normalize_province(province)}.",
        )

    now = _now()
    rows = []
    for target in targets:
        values = {
            "id": str(uuid.uuid4()),
            "province": province,
            "judge_id": target,
            **fields,
            "created_by": actor["id"],
            "created_by_name": actor["name"],
            "created_by_role": actor["role"],
            "created_at": now,
            "updated_at": now,
        }
        await database.execute(T.insert().values(**values))
        rows.append(values)
    for values in rows:
        await _notify("created", values, actor)
    return {"items": [build_item(v) for v in rows]}


@router.patch("/{item_id}", summary="Zmień wpisaną niedyspozycję")
async def update_assigned(
    item_id: str,
    body: Dict[str, Any] = Body(...),
    token_payload: dict = Depends(get_jwt_payload),
):
    row = await _load(item_id)
    actor = await _actor(token_payload, row["province"])
    merged = {
        "from": body.get("from", row["from"]),
        "to": body["to"] if "to" in body else row["to"],
        "info": body["info"] if "info" in body else row["info"],
        "category_id": body["category_id"] if "category_id" in body else row["category_id"],
        "category_name": body["category_name"] if "category_name" in body else row["category_name"],
        "category_color": body["category_color"] if "category_color" in body else row["category_color"],
    }
    try:
        fields = normalize_fields(merged)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    now = _now()
    await database.execute(
        update(T).where(T.c.id == item_id).values(**fields, updated_at=now, updated_by=actor["id"])
    )
    fresh = dict(row._mapping)
    fresh.update(fields, updated_at=now)
    await _notify("updated", fresh, actor)
    return {"item": build_item(fresh)}


@router.delete("/{item_id}", summary="Usuń wpisaną niedyspozycję")
async def delete_assigned(
    item_id: str,
    token_payload: dict = Depends(get_jwt_payload),
):
    row = await _load(item_id)
    actor = await _actor(token_payload, row["province"])
    await database.execute(
        update(T)
        .where(T.c.id == item_id)
        .values(deleted_at=_now(), updated_at=_now(), updated_by=actor["id"])
    )
    await _notify("deleted", dict(row._mapping), actor)
    return {"ok": True}


async def assigned_rows(*, province: Optional[str] = None, judge_id: Optional[str] = None):
    """Żywe wiersze do dołożenia przy odczycie `/offtimes/self` i `/offtimes/all`."""
    query = select(T).where(T.c.deleted_at.is_(None))
    if judge_id is not None:
        query = query.where(T.c.judge_id == str(judge_id))
    if province:
        query = query.where(T.c.province.in_(spellings(province)))
    return await database.fetch_all(query)


async def assigned_ids(*, judge_id: str, province: Any) -> List[str]:
    """Id WSZYSTKICH wpisów sędziego w okręgu, także usuniętych - do wycinania z bloba."""
    rows = await database.fetch_all(
        select(T.c.id).where(
            T.c.judge_id == str(judge_id), T.c.province.in_(spellings(province))
        )
    )
    return [str(r["id"]) for r in rows]
