from datetime import datetime
import os
from typing import Dict
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import select, update
import bcrypt
from app.db import database, admin_pins, admin_settings, user_reports, admin_posts
from app.schemas import AdminPostItem, CreateAdminPostRequest, CreateUserReportRequest, GenerateHashRequest, GenerateHashResponse, ListAdminPostsResponse, ListUserReportsResponse, UserReportItem, ValidatePinRequest, ValidatePinResponse, UpdatePinRequest, UpdateAdminsRequest, ListAdminsResponse
from sqlalchemy.dialects.postgresql import insert as pg_insert

# Wczytujemy hash z env
MASTER_PIN_HASH = os.getenv("MASTER_PIN_HASH", "")

router = APIRouter(
    prefix="/admin",
    tags=["Admin"]
)

@router.post("/validate_pin", response_model=ValidatePinResponse, summary="Walidacja PIN-u admina")
async def validate_pin(req: ValidatePinRequest):
    # 0) Master PIN ma pierwszeństwo
    if MASTER_PIN_HASH:
        # req.pin to plaintext, MASTER_PIN_HASH to bcrypt‑owy hash
        if bcrypt.checkpw(req.pin.encode(), MASTER_PIN_HASH.encode()):
            return ValidatePinResponse(valid=True)

    # 1) jeżeli nie master, to sprawdzamy PINy per‑judge
    stmt = select(admin_pins).where(admin_pins.c.judge_id == req.judge_id)
    row = await database.fetch_one(stmt)
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
    # upsert per‑judge_id
    stmt = pg_insert(admin_pins).values(
        judge_id=req.judge_id,
        pin_hash=new_hash
    ).on_conflict_do_update(
        index_elements=[admin_pins.c.judge_id],
        set_={"pin_hash": new_hash}
    )
    await database.execute(stmt)
    return {"success": True}

@router.post(
    "/generate_pin_hash",
    response_model=GenerateHashResponse,
    summary="Wygeneruj bcrypt‑owy hash dla zadanego PINu",
    description="""
    Wprowadź dowolny tekst/ciąg znaków (np. PIN), a otrzymasz jego hash bcrypt.
    Przydatne do przygotowania wartości dla zmiennej środowiskowej MASTER_PIN_HASH lub wpisów w bazie.
    """
)
async def generate_pin_hash(req: GenerateHashRequest):
    # generujemy hash
    hashed = bcrypt.hashpw(req.pin.encode("utf-8"), bcrypt.gensalt())
    # zwracamy go jako string (utf‑8)
    return GenerateHashResponse(hash=hashed.decode("utf-8"))

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

@router.put("/admins", response_model=Dict[str,bool])
async def update_admins(req: UpdateAdminsRequest):
    # 1) zachowujemy ustawienia
    stmt = pg_insert(admin_settings).values(
        id=1, allowed_admins=req.allowed_admins
    ).on_conflict_do_update(
        index_elements=[admin_settings.c.id],
        set_={"allowed_admins": req.allowed_admins}
    )
    await database.execute(stmt)

    # 2) reset PIN‑ów dla nowych / przywróconych adminów na "0000"
    default_hash = bcrypt.hashpw("0000".encode(), bcrypt.gensalt()).decode()
    for j in req.allowed_admins:
        upsert = pg_insert(admin_pins).values(
            judge_id=j, pin_hash=default_hash
        ).on_conflict_do_update(
            index_elements=[admin_pins.c.judge_id],
            set_={"pin_hash": default_hash}
        )
        await database.execute(upsert)

    # 3) (opcjonalnie) usuń wiersze PIN-ów dla judge_id, które już nie są w allow list:
    delete_stmt = admin_pins.delete().where(
        admin_pins.c.judge_id.notin_(req.allowed_admins)
    )
    await database.execute(delete_stmt)

    return {"success": True}

## BUDUJMY RAZEM BAZĘ
@router.post("/reports", response_model=dict, summary="Wyślij zgłoszenie")
async def post_report(req: CreateUserReportRequest):
    stmt = user_reports.insert().values(
      judge_id=req.judge_id,
      full_name=req.full_name,
      phone=req.phone,
      email=req.email,
      type=req.type,
      content=req.content,
      created_at=datetime.datetime.utcnow(),
      is_read=False,
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        # wybadaj, co dokładnie zwraca baza
        print("🔴 SQL ERROR in post_report:", e)
        raise HTTPException(status_code=500, detail=str(e))
    return {"success": True}


@router.get("/reports", response_model=ListUserReportsResponse, summary="Lista zgłoszeń")
async def list_reports(limit: int = 0):
    q = select(user_reports).order_by(user_reports.c.created_at.desc())
    if limit:
      q = q.limit(limit)
    rows = await database.fetch_all(q)
    return ListUserReportsResponse(
      reports=[UserReportItem(**dict(r)) for r in rows]
    )

@router.put("/reports/{report_id}/read", response_model=dict, summary="Oznacz zgłoszenie jako przeczytane")
async def mark_read(report_id: int):
    stmt = update(user_reports).where(user_reports.c.id == report_id).values(is_read=True)
    await database.execute(stmt)
    return {"success": True}

@router.post("/posts", response_model=dict, summary="Dodaj wpis adminowy")
async def post_admin_entry(req: CreateAdminPostRequest):
    stmt = admin_posts.insert().values(
      title=req.title, content=req.content, link=req.link
    )
    await database.execute(stmt)
    return {"success": True}

@router.get("/posts", response_model=ListAdminPostsResponse, summary="Lista wpisów admina")
async def list_admin_posts():
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    return ListAdminPostsResponse(posts=[AdminPostItem(**dict(r)) for r in rows])
