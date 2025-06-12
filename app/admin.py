from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import select
import bcrypt
from app.db import database, admin_pins
from app.schemas import ValidatePinRequest, ValidatePinResponse, UpdatePinRequest

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