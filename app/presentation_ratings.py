"""Tryb prezentacji - OCENY MŁODYCH SĘDZIÓW (obszar `ratings`, „Oceny młodych").

Zapisy (`app/young_referees.py`, ekran `YoungRefereeRatingModal` w BAZIE):

* `POST /young_referees/ratings` (201, `YoungRefereeRatingItem`) - nowa ocena
  albo „pominięcie meczu" (`rating.kind = "skip"`),
* `PUT /young_referees/ratings/{id}` - zmiana oceny,
* `DELETE /young_referees/ratings/{id}` - usunięcie.

Konto trybu nie zapisuje nic: ocena trafia do nakładki (`young_rating`, numer
udawany) albo jako łatka prawdziwej oceny (`young_rating_patch`). Te same
sprawdzenia co handler, tylko odczyty: młody sędzia nie ocenia (403), młody
sędzia z oceny musi istnieć (400).

Odczyty z nakładką (tylko konta trybu): `GET /young_referees/ratings` z tymi
samymi filtrami co handler (province, young_referee_id - 1. albo 2. sędzia,
mentor_name, date_from, date_to) i tą samą kolejnością, oraz
`GET /young_referees/ratings/{id}`. Średnie i statystyki młodego aplikacja
liczy SAMA z tej listy (`avg_score` w `rating`), więc doklejona ocena wchodzi
do nich bez osobnej trasy.

Moduł nie importuje `app.db` ani `presentation_sim` na poziomie modułu.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app import presentation_state as PS

log = logging.getLogger("presentation")

KIND = "young_rating"
PATCH = "young_rating_patch"
FIELDS = (
    "rating_date", "province", "mentor_name", "young_referee_name", "young_referee_id",
    "young_referee2_name", "young_referee2_id", "rating",
)


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _province(value: Any) -> str:
    return _s(value).upper()


def _date(value: Any) -> Optional[datetime]:
    return PS._utc(value)


async def _young(referee_id: Any) -> Optional[Dict[str, Any]]:
    """Wiersz młodego sędziego (odczyt). Brak tabeli / błąd = nie wiemy (None)."""
    rid = _int(referee_id)
    if rid is None:
        return None
    try:
        from sqlalchemy import select

        from app.db import database, young_referees

        row = await database.fetch_one(select(young_referees).where(young_referees.c.id == rid))
        return dict(row._mapping) if hasattr(row, "_mapping") else (dict(row) if row else None)
    except Exception:  # noqa: BLE001
        log.info("tryb prezentacji: młody sędzia %s nieczytelny", referee_id, exc_info=True)
        return {"id": rid, "full_name": ""}


async def _rater_check(ctx, mentor_name: Any):
    """403 jak w handlerze: młody sędzia nie wystawia ocen. Tylko odczyt."""
    from app import presentation_sim as sim

    try:
        from fastapi import HTTPException

        from app.young_referees import _ensure_rater_is_not_young

        await _ensure_rater_is_not_young(ctx.jwt, mentor_name)
    except HTTPException as exc:  # type: ignore[misc]
        return sim.Result(exc.status_code, {"detail": exc.detail})
    except Exception:  # noqa: BLE001 - brak bazy w teście / chwilowy błąd: nie blokujemy pokazu
        log.info("tryb prezentacji: sprawdzenie oceniającego pominięte", exc_info=True)
    return None


def item_view(item: Dict[str, Any]) -> Dict[str, Any]:
    """Kształt `YoungRefereeRatingItem` (bez pól wewnętrznych nakładki)."""
    out = {k: item.get(k) for k in ("id",) + FIELDS}
    out["rating_date"] = PS._iso(item.get("rating_date")) or item.get("rating_date")
    return out


async def rating_create(ctx, route):
    from app import presentation_sim as sim

    denied = await _rater_check(ctx, ctx.b("mentor_name"))
    if denied:
        return denied
    first = await _young(ctx.b("young_referee_id"))
    if first is None:
        return sim.Result(400, {"detail": "Nie znaleziono młodego sędziego o podanym ID"})
    province = _province(ctx.b("province"))
    if not province:
        return sim.Result(400, {"detail": "Pole 'province' jest wymagane"})
    second_id = _int(ctx.b("young_referee2_id"))
    second_name = ctx.b("young_referee2_name")
    if second_id is not None:
        if second_id == _int(ctx.b("young_referee_id")):
            return sim.Result(400, {"detail": "Drugi młody sędzia nie może być taki sam jak pierwszy"})
        second = await _young(second_id)
        if second is None:
            return sim.Result(400, {"detail": "Nie znaleziono drugiego młodego sędziego o podanym ID"})
        second_name = second_name or second.get("full_name")
    rating_id = await PS.next_synthetic_id()
    item = {
        "id": rating_id,
        "rating_date": PS._iso(ctx.b("rating_date")) or datetime.now(timezone.utc).isoformat(),
        "province": province,
        "mentor_name": _s(ctx.b("mentor_name")),
        "young_referee_name": _s(ctx.b("young_referee_name")) or _s(first.get("full_name")),
        "young_referee_id": _int(ctx.b("young_referee_id")),
        "young_referee2_name": second_name or None,
        "young_referee2_id": second_id,
        "rating": ctx.b("rating"),
        "account": ctx.account,
    }
    await PS.overlay_add(KIND, rating_id, item)
    rating = item["rating"] if isinstance(item["rating"], dict) else {}
    what = "Pominięcie meczu" if rating.get("skipped") or rating.get("kind") == "skip" else "Ocena"
    return sim.Result(
        201, item_view(item),
        f"{what} młodego sędziego {item['young_referee_name']} (mecz {_s(rating.get('matchNumber')) or '?'}) - bez zapisu",
    )


async def _find(rating_id: int):
    """(rodzaj, wiersz nakładki, ocena po łatkach) albo (None, None, None)."""
    if PS.is_synthetic(rating_id):
        found = await PS.overlay_get(KIND, rating_id)
        if not found or found[1].get("deleted"):
            return None, None, None
        return KIND, found, dict(found[1])
    real = await _real(rating_id)
    if real is None:
        return None, None, None
    found = await PS.overlay_get(PATCH, rating_id)
    patch = found[1] if found else {}
    if patch.get("deleted"):
        return None, None, None
    return PATCH, found, {**real, **{k: v for k, v in patch.items() if k in FIELDS}}


async def _real(rating_id: int) -> Optional[Dict[str, Any]]:
    try:
        from sqlalchemy import select

        from app.db import database, young_referee_ratings as T

        row = await database.fetch_one(select(T).where(T.c.id == rating_id))
    except Exception:  # noqa: BLE001
        return None
    if row is None:
        return None
    data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
    data["rating"] = data.pop("rating_json", None)
    return data


async def rating_update(ctx, route):
    from app import presentation_sim as sim

    denied = await _rater_check(ctx, ctx.b("mentor_name"))
    if denied:
        return denied
    rating_id = ctx.pid()
    kind, found, item = await _find(rating_id)
    if item is None:
        return sim.Result(404, {"detail": "Ocena nie znaleziona"})
    body = ctx.body if isinstance(ctx.body, dict) else {}
    changes: Dict[str, Any] = {}
    for key in FIELDS:
        if key in body and (body[key] is not None or key in ("young_referee2_id", "young_referee2_name")):
            changes[key] = body[key]
    if "province" in changes:
        changes["province"] = _province(changes["province"])
    if changes.get("young_referee_id") is not None and await _young(changes["young_referee_id"]) is None:
        return sim.Result(400, {"detail": "Nie znaleziono młodego sędziego o podanym ID"})
    if "young_referee2_id" in changes and changes["young_referee2_id"] is None:
        changes["young_referee2_name"] = None
    item.update(changes)
    if kind == KIND:
        await PS.overlay_put(found[0], item)
    else:
        patch = {**(found[1] if found else {}), **changes}
        await PS.overlay_upsert(PATCH, rating_id, patch)
    return sim.Result(200, item_view({**item, "id": rating_id}), f"Zmiana oceny młodego sędziego {rating_id} - bez zapisu")


async def rating_delete(ctx, route):
    from app import presentation_sim as sim

    rating_id = ctx.pid()
    kind, found, item = await _find(rating_id)
    if item is None:
        return sim.Result(404, {"detail": "Ocena nie znaleziona"})
    if kind == KIND:
        await PS.overlay_put(found[0], {**found[1], "deleted": True})
    else:
        await PS.overlay_upsert(PATCH, rating_id, {**(found[1] if found else {}), "deleted": True})
    return sim.Result(200, {"success": True}, f"Usunięcie oceny młodego sędziego {rating_id} - bez zapisu")


def _wanted(item: Dict[str, Any], query: Dict[str, str]) -> bool:
    """Te same filtry co `list_young_referee_ratings`."""
    if query.get("province") and _province(item.get("province")) != _province(query["province"]):
        return False
    if query.get("young_referee_id"):
        rid = _int(query["young_referee_id"])
        if rid not in (_int(item.get("young_referee_id")), _int(item.get("young_referee2_id"))):
            return False
    if query.get("mentor_name") and _s(item.get("mentor_name")) != query["mentor_name"]:
        return False
    when = _date(item.get("rating_date"))
    lo, hi = _date(query.get("date_from")), _date(query.get("date_to"))
    if lo and (when is None or when < lo):
        return False
    if hi and (when is None or when > hi):
        return False
    return True


def _order(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """rating_date malejąco, potem województwo rosnąco - jak handler."""
    floor = datetime.min.replace(tzinfo=timezone.utc)
    by_province = sorted(items, key=lambda i: _s(i.get("province")))
    return sorted(by_province, key=lambda i: _date(i.get("rating_date")) or floor, reverse=True)


async def merge_ratings_list(ctx, data: Any) -> Any:
    if data is None or not isinstance(data, dict):
        return None
    db = PS._db()
    t = db.presentation_overlay
    rows = await db.database.fetch_all(t.select().where(t.c.kind.in_((KIND, PATCH))).order_by(t.c.id))
    patches: Dict[str, Dict[str, Any]] = {}
    synthetic: List[Dict[str, Any]] = []
    for r in rows:
        item = PS._loads(r["data_json"], {}) or {}
        if r["kind"] == PATCH:
            patches[_s(r["key"])] = item
        elif not item.get("deleted"):
            synthetic.append(item)
    records = []
    for rec in data.get("records") or []:
        patch = patches.get(_s(rec.get("id")))
        if patch:
            if patch.get("deleted"):
                continue
            rec = {**rec, **{k: v for k, v in patch.items() if k in FIELDS}}
            if not _wanted(rec, ctx.query):
                continue
        records.append(rec)
    records += [item_view(i) for i in synthetic if _wanted(i, ctx.query)]
    data["records"] = _order(records)
    return data


async def merge_rating_detail(ctx, data: Any) -> Any:
    from app import presentation_sim as sim

    rating_id = ctx.pid()
    if data is None:
        if not PS.is_synthetic(rating_id):
            found = await PS.overlay_get(PATCH, rating_id)
            if found and found[1].get("deleted"):
                return sim.Result(404, {"detail": "Ocena nie znaleziona"})
            return None
        _kind, _found, item = await _find(rating_id)
        if item is None:
            return sim.Result(404, {"detail": "Ocena nie znaleziona"})
        return sim.Result(200, item_view(item))
    found = await PS.overlay_get(PATCH, rating_id)
    if not found:
        return data
    if found[1].get("deleted"):
        return sim.Result(404, {"detail": "Ocena nie znaleziona"})
    return {**data, **{k: v for k, v in found[1].items() if k in FIELDS}}


SIMS = {"rating_create": rating_create, "rating_update": rating_update, "rating_delete": rating_delete}
MERGES = {"merge_ratings_list": merge_ratings_list, "merge_rating_detail": merge_rating_detail}
