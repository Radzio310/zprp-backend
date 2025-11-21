# app/young_referees.py

from datetime import datetime, timezone
from typing import Optional, Any, Dict
import json

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select, insert, update, delete, or_

from app.db import (
    database,
    young_referees,
    young_referee_ratings,
)
from app.schemas import (
    CreateYoungRefereeRequest,
    UpdateYoungRefereeRequest,
    YoungRefereeItem,
    ListYoungRefereesResponse,
    CreateYoungRefereeRatingRequest,
    UpdateYoungRefereeRatingRequest,
    YoungRefereeRatingItem,
    ListYoungRefereeRatingsResponse,
)

router = APIRouter(
    prefix="/young_referees",
    tags=["Młodzi sędziowie"],
)

# ----------------- Helpers -----------------


def _normalize_province(province: Optional[str]) -> Optional[str]:
    if province is None:
        return None
    return province.strip().upper()


def _json_from_row(raw: Any) -> Any:
    """Bezpieczny parser JSON – przy Postgresie zwykle dostaniemy dict/list,
    przy SQLite może być string."""
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return raw


# ----------------- CRUD: młodzi sędziowie -----------------


@router.post(
    "/",
    response_model=YoungRefereeItem,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj młodego sędziego",
)
async def create_young_referee(req: CreateYoungRefereeRequest):
    province = _normalize_province(req.province)
    if not province:
        raise HTTPException(status_code=400, detail="Pole 'province' jest wymagane")

    values = {
        "full_name": req.full_name,
        "base_judge_id": req.base_judge_id,
        "province": province,
        "is_active": req.is_active,
    }

    insert_stmt = insert(young_referees).values(**values)
    new_id = await database.execute(insert_stmt)

    row = await database.fetch_one(
        select(young_referees).where(young_referees.c.id == new_id)
    )
    if row is None:
        raise HTTPException(
            status_code=500, detail="Nie udało się odczytać nowego rekordu"
        )

    return YoungRefereeItem(
        id=row["id"],
        full_name=row["full_name"],
        base_judge_id=row["base_judge_id"],
        province=row["province"],
        is_active=bool(row["is_active"]),
    )


@router.get(
    "/",
    response_model=ListYoungRefereesResponse,
    summary="Lista młodych sędziów",
)
async def list_young_referees(
    province: Optional[str] = None,
    active: Optional[bool] = None,
    base_judge_id: Optional[str] = None,
):
    q = select(young_referees)

    if province:
        q = q.where(young_referees.c.province == _normalize_province(province))
    if active is not None:
        q = q.where(young_referees.c.is_active == active)
    if base_judge_id:
        q = q.where(young_referees.c.base_judge_id == base_judge_id)

    q = q.order_by(young_referees.c.province.asc(), young_referees.c.full_name.asc())

    rows = await database.fetch_all(q)
    records = [
        YoungRefereeItem(
            id=r["id"],
            full_name=r["full_name"],
            base_judge_id=r["base_judge_id"],
            province=r["province"],
            is_active=bool(r["is_active"]),
        )
        for r in rows
    ]
    return ListYoungRefereesResponse(records=records)


@router.get(
    "/id/{referee_id}",
    response_model=YoungRefereeItem,
    summary="Pobierz młodego sędziego po ID",
)
async def get_young_referee(referee_id: int):
    row = await database.fetch_one(
        select(young_referees).where(young_referees.c.id == referee_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Młody sędzia nie znaleziony")

    return YoungRefereeItem(
        id=row["id"],
        full_name=row["full_name"],
        base_judge_id=row["base_judge_id"],
        province=row["province"],
        is_active=bool(row["is_active"]),
    )


@router.put(
    "/id/{referee_id}",
    response_model=YoungRefereeItem,
    summary="Zaktualizuj młodego sędziego",
)
async def update_young_referee(referee_id: int, req: UpdateYoungRefereeRequest):
    # sprawdź czy istnieje
    row = await database.fetch_one(
        select(young_referees).where(young_referees.c.id == referee_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Młody sędzia nie znaleziony")

    values: Dict[str, Any] = {}
    if req.full_name is not None:
        values["full_name"] = req.full_name
    if req.base_judge_id is not None:
        values["base_judge_id"] = req.base_judge_id
    if req.province is not None:
        values["province"] = _normalize_province(req.province)
    if req.is_active is not None:
        values["is_active"] = req.is_active

    if values:
        upd = (
            update(young_referees)
            .where(young_referees.c.id == referee_id)
            .values(**values)
        )
        await database.execute(upd)

    # odczyt po update
    row = await database.fetch_one(
        select(young_referees).where(young_referees.c.id == referee_id)
    )
    return YoungRefereeItem(
        id=row["id"],
        full_name=row["full_name"],
        base_judge_id=row["base_judge_id"],
        province=row["province"],
        is_active=bool(row["is_active"]),
    )


@router.delete(
    "/id/{referee_id}",
    response_model=Dict[str, bool],
    summary="Usuń młodego sędziego",
)
async def delete_young_referee(referee_id: int):
    stmt = delete(young_referees).where(young_referees.c.id == referee_id)
    result = await database.execute(stmt)
    if not result:
        raise HTTPException(status_code=404, detail="Młody sędzia nie znaleziony")
    return {"success": True}


# ----------------- CRUD: oceny młodych sędziów -----------------


@router.post(
    "/ratings",
    response_model=YoungRefereeRatingItem,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj ocenę młodego sędziego",
)
async def create_young_referee_rating(req: CreateYoungRefereeRatingRequest):
    # upewnij się, że pierwszy młody sędzia istnieje
    ref_row = await database.fetch_one(
        select(young_referees.c.id, young_referees.c.full_name).where(
            young_referees.c.id == req.young_referee_id
        )
    )
    if ref_row is None:
        raise HTTPException(
            status_code=400,
            detail="Nie znaleziono młodego sędziego o podanym ID",
        )

    province = _normalize_province(req.province)
    if not province:
        raise HTTPException(status_code=400, detail="Pole 'province' jest wymagane")

    rating_date = req.rating_date or datetime.now(timezone.utc)

    # --- obsługa drugiego sędziego ---
    second_id = req.young_referee2_id
    second_name = req.young_referee2_name

    if second_id is not None:
        if second_id == req.young_referee_id:
            raise HTTPException(
                status_code=400,
                detail="Drugi młody sędzia nie może być taki sam jak pierwszy",
            )

        ref_row_2 = await database.fetch_one(
            select(young_referees.c.id, young_referees.c.full_name).where(
                young_referees.c.id == second_id
            )
        )
        if ref_row_2 is None:
            raise HTTPException(
                status_code=400,
                detail="Nie znaleziono drugiego młodego sędziego o podanym ID",
            )

        # jeśli imię/nazwisko nie przyszło z frontu – uzupełnij z tabeli
        if not second_name:
            second_name = ref_row_2["full_name"]

    values = {
        "rating_date": rating_date,
        "province": province,
        "mentor_name": req.mentor_name,
        "young_referee_name": req.young_referee_name or ref_row["full_name"],
        "young_referee_id": req.young_referee_id,
        "rating_json": req.rating,
        # NOWE
        "young_referee2_name": second_name,
        "young_referee2_id": second_id,
    }

    insert_stmt = insert(young_referee_ratings).values(**values)
    new_id = await database.execute(insert_stmt)

    row = await database.fetch_one(
        select(young_referee_ratings).where(young_referee_ratings.c.id == new_id)
    )
    if row is None:
        raise HTTPException(
            status_code=500, detail="Nie udało się odczytać nowej oceny"
        )

    return YoungRefereeRatingItem(
        id=row["id"],
        rating_date=row["rating_date"],
        province=row["province"],
        mentor_name=row["mentor_name"],
        young_referee_name=row["young_referee_name"],
        young_referee_id=row["young_referee_id"],
        rating=_json_from_row(row["rating_json"]),
        young_referee2_name=row["young_referee2_name"],
        young_referee2_id=row["young_referee2_id"],
    )


@router.get(
    "/ratings",
    response_model=ListYoungRefereeRatingsResponse,
    summary="Lista ocen młodych sędziów",
)
async def list_young_referee_ratings(
    province: Optional[str] = None,
    young_referee_id: Optional[int] = None,
    mentor_name: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
):
    q = select(young_referee_ratings)

    if province:
        q = q.where(young_referee_ratings.c.province == _normalize_province(province))
    if young_referee_id is not None:
        # filtruj po 1. lub 2. sędzim
        q = q.where(
            or_(
                young_referee_ratings.c.young_referee_id == young_referee_id,
                young_referee_ratings.c.young_referee2_id == young_referee_id,
            )
        )
    if mentor_name:
        # proste dopasowanie case-sensitive; jak chcesz, możesz dodać ilike na Postgresie
        q = q.where(young_referee_ratings.c.mentor_name == mentor_name)
    if date_from is not None:
        q = q.where(young_referee_ratings.c.rating_date >= date_from)
    if date_to is not None:
        q = q.where(young_referee_ratings.c.rating_date <= date_to)

    q = q.order_by(
        young_referee_ratings.c.rating_date.desc(),
        young_referee_ratings.c.province.asc(),
    )

    rows = await database.fetch_all(q)
    records = [
        YoungRefereeRatingItem(
            id=r["id"],
            rating_date=r["rating_date"],
            province=r["province"],
            mentor_name=r["mentor_name"],
            young_referee_name=r["young_referee_name"],
            young_referee_id=r["young_referee_id"],
            rating=_json_from_row(r["rating_json"]),
            young_referee2_name=r["young_referee2_name"],
            young_referee2_id=r["young_referee2_id"],
        )
        for r in rows
    ]
    return ListYoungRefereeRatingsResponse(records=records)


@router.get(
    "/ratings/{rating_id}",
    response_model=YoungRefereeRatingItem,
    summary="Pobierz ocenę młodego sędziego po ID",
)
async def get_young_referee_rating(rating_id: int):
    row = await database.fetch_one(
        select(young_referee_ratings).where(young_referee_ratings.c.id == rating_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Ocena nie znaleziona")

    return YoungRefereeRatingItem(
        id=row["id"],
        rating_date=row["rating_date"],
        province=row["province"],
        mentor_name=row["mentor_name"],
        young_referee_name=row["young_referee_name"],
        young_referee_id=row["young_referee_id"],
        rating=_json_from_row(row["rating_json"]),
        young_referee2_name=row["young_referee2_name"],
        young_referee2_id=row["young_referee2_id"],
    )


@router.put(
    "/ratings/{rating_id}",
    response_model=YoungRefereeRatingItem,
    summary="Zaktualizuj ocenę młodego sędziego",
)
async def update_young_referee_rating(
    rating_id: int, req: UpdateYoungRefereeRatingRequest
):
    row = await database.fetch_one(
        select(young_referee_ratings).where(young_referee_ratings.c.id == rating_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Ocena nie znaleziona")

    values: Dict[str, Any] = {}

    if req.rating_date is not None:
        values["rating_date"] = req.rating_date
    if req.province is not None:
        values["province"] = _normalize_province(req.province)
    if req.mentor_name is not None:
        values["mentor_name"] = req.mentor_name
    if req.young_referee_name is not None:
        values["young_referee_name"] = req.young_referee_name

    # aktualizacja 1. sędziego (tak jak wcześniej)
    if req.young_referee_id is not None:
        ref_row = await database.fetch_one(
            select(young_referees.c.id).where(
                young_referees.c.id == req.young_referee_id
            )
        )
        if ref_row is None:
            raise HTTPException(
                status_code=400,
                detail="Nie znaleziono młodego sędziego o podanym ID",
            )
        values["young_referee_id"] = req.young_referee_id

    # rating_json
    if req.rating is not None:
        values["rating_json"] = req.rating

    # --- NOWE: aktualizacja drugiego sędziego ---
    # używamy __fields_set__, żeby rozróżnić:
    # - pole nieprzysłane wcale (nie zmieniamy)
    # - pole przysłane z wartością (w tym None => wyczyść)
    if "young_referee2_id" in req.__fields_set__:
        if req.young_referee2_id is not None:
            # walidacja – nie może być ten sam co 1.
            if (
                req.young_referee_id is not None
                and req.young_referee_id == req.young_referee2_id
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Drugi młody sędzia nie może być taki sam jak pierwszy",
                )

            ref_row2 = await database.fetch_one(
                select(young_referees.c.id, young_referees.c.full_name).where(
                    young_referees.c.id == req.young_referee2_id
                )
            )
            if ref_row2 is None:
                raise HTTPException(
                    status_code=400,
                    detail="Nie znaleziono drugiego młodego sędziego o podanym ID",
                )

            values["young_referee2_id"] = req.young_referee2_id

            # jeśli nie przysłano imienia/nazwiska 2. sędziego,
            # a chcemy go ustawić – uzupełnijmy z tabeli
            if "young_referee2_name" not in req.__fields_set__:
                values["young_referee2_name"] = ref_row2["full_name"]
        else:
            # explicite przysłane null => wyczyść w bazie
            values["young_referee2_id"] = None
            values["young_referee2_name"] = None

    if "young_referee2_name" in req.__fields_set__:
        # jeśli przysłano nazwę, to nadpisujemy (nawet jak None – ale w tym
        # przypadku i tak zwykle ustawiamy już None powyżej przy id)
        values["young_referee2_name"] = req.young_referee2_name

    if values:
        upd = (
            update(young_referee_ratings)
            .where(young_referee_ratings.c.id == rating_id)
            .values(**values)
        )
        await database.execute(upd)

    row = await database.fetch_one(
        select(young_referee_ratings).where(young_referee_ratings.c.id == rating_id)
    )
    return YoungRefereeRatingItem(
        id=row["id"],
        rating_date=row["rating_date"],
        province=row["province"],
        mentor_name=row["mentor_name"],
        young_referee_name=row["young_referee_name"],
        young_referee_id=row["young_referee_id"],
        rating=_json_from_row(row["rating_json"]),
        young_referee2_name=row["young_referee2_name"],
        young_referee2_id=row["young_referee2_id"],
    )


@router.delete(
    "/ratings/{rating_id}",
    response_model=Dict[str, bool],
    summary="Usuń ocenę młodego sędziego",
)
async def delete_young_referee_rating(rating_id: int):
    stmt = delete(young_referee_ratings).where(young_referee_ratings.c.id == rating_id)
    result = await database.execute(stmt)
    if not result:
        raise HTTPException(status_code=404, detail="Ocena nie znaleziona")
    return {"success": True}
