from typing import Dict
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import select
import bcrypt
from app.db import database, admin_pins, admin_settings
from app.schemas import ValidatePinRequest, ValidatePinResponse, UpdatePinRequest, UpdateAdminsRequest, ListAdminsResponse
from sqlalchemy.dialects.postgresql import insert as pg_insert

router = APIRouter(
    prefix="/admin",
    tags=["Admin"]
)

@router.post(
    "/validate_pin",
    response_model=ValidatePinResponse,
    summary="Walidacja PIN-u admina"
)
async def validate_pin(req: ValidatePinRequest):
    row = await database.fetch_one(select(admin_pins).limit(1))
    if not row:
        return ValidatePinResponse(valid=False)
    pin_hash = row["pin_hash"].encode()
    valid = bcrypt.checkpw(req.pin.encode(), pin_hash)
    return ValidatePinResponse(valid=valid)

@router.put(
    "/update_pin",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub zaktualizuj PIN admina"
)
async def update_pin(req: UpdatePinRequest):
    # tu możesz dodać uwierzytelnianie JWT jeśli potrzebne
    new_hash = bcrypt.hashpw(req.new_pin.encode(), bcrypt.gensalt()).decode()
    # upsert
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    stmt = pg_insert(admin_pins).values(
        id=1,
        pin_hash=new_hash
    ).on_conflict_do_update(
        index_elements=[admin_pins.c.id],
        set_={"pin_hash": new_hash}
    )
    await database.execute(stmt)
    return {"success": True}

@router.get(
    "/admins",
    response_model=ListAdminsResponse,
    summary="Pobierz listę ID adminów"
)
async def get_admins():
    row = await database.fetch_one(select(admin_settings).limit(1))
    return ListAdminsResponse(
        allowed_admins=row["allowed_admins"] or []
    )

@router.put(
    "/admins",
    response_model=Dict[str,bool],
    summary="Zaktualizuj listę ID adminów"
)
async def update_admins(req: UpdateAdminsRequest):
    stmt = pg_insert(admin_settings).values(
        id=1, allowed_admins=req.allowed_admins
    ).on_conflict_do_update(
        index_elements=[admin_settings.c.id],
        set_={"allowed_admins": req.allowed_admins}
    )
    await database.execute(stmt)
    return {"success": True}