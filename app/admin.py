from datetime import datetime
import os
from typing import Dict
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import delete, insert, select, update
import bcrypt
from app.db import database, admin_pins, admin_settings, user_reports, admin_posts, forced_logout, news_masters, calendar_masters, match_masters, json_files
from app.schemas import AdminPostItem, CreateAdminPostRequest, CreateUserReportRequest, ForcedLogoutResponse, GenerateHashRequest, GenerateHashResponse, GetJsonFileResponse, JsonFileItem, ListAdminPostsResponse, ListJsonFilesResponse, ListMastersResponse, ListUserReportsResponse, SetForcedLogoutRequest, UpdateMastersRequest, UpsertJsonFileRequest, UserReportItem, ValidatePinRequest, ValidatePinResponse, UpdatePinRequest, UpdateAdminsRequest, ListAdminsResponse
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
    # 1) Zapisz listę w admin_settings
    stmt = pg_insert(admin_settings).values(
        id=1, allowed_admins=req.allowed_admins
    ).on_conflict_do_update(
        index_elements=[admin_settings.c.id],
        set_={"allowed_admins": req.allowed_admins}
    )
    await database.execute(stmt)

    # 2) Pobierz obecną listę z bazy
    row = await database.fetch_one(select(admin_settings).limit(1))
    old_list = set(row["allowed_admins"] or [])

    # 3) Znajdź nowych i tylko dla nich upsert PIN=0000
    new_admins = set(req.allowed_admins) - old_list
    default_hash = bcrypt.hashpw("0000".encode(), bcrypt.gensalt()).decode()
    for j in new_admins:
        await database.execute(
            pg_insert(admin_pins)
            .values(judge_id=j, pin_hash=default_hash)
            .on_conflict_do_nothing()  # tylko wstaw, nie nadpisuj
        )

    # 4) (opcjonalnie) usuń PINy dla tych, których wykreślono – też możesz
    #    wyciągnąć removed = old_list - set(req.allowed_admins) i usunąć tylko te.

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
      created_at=datetime.utcnow(),
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

@router.put(
    "/reports/{report_id}/unread",
    response_model=dict,
    summary="Oznacz zgłoszenie jako nieprzeczytane"
)
async def mark_unread(report_id: int):
    """Przełącz flagę is_read na False."""
    # 1) aktualizacja
    stmt = update(user_reports).where(user_reports.c.id == report_id).values(is_read=False)
    result = await database.execute(stmt)
    # 2) sprawdź czy coś zostało zmienione
    #    (database.execute zwraca zazwyczaj ilość zmienionych wierszy)
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}


@router.delete(
    "/reports/{report_id}",
    response_model=dict,
    summary="Usuń zgłoszenie użytkownika"
)
async def delete_report(report_id: int):
    """Usuń zgłoszenie o danym ID z bazy."""
    # 1) wykonaj delete
    delete_stmt = user_reports.delete().where(user_reports.c.id == report_id)
    result = await database.execute(delete_stmt)
    # 2) jeżeli nic nie usunięte → 404
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
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

## UŻYTKOWNICY
@router.get("/forced_logout", response_model=ForcedLogoutResponse, summary="Pobierz termin wymuszonego wylogowania")
async def get_forced_logout():
    row = await database.fetch_one(select(forced_logout).limit(1))
    return ForcedLogoutResponse(logout_at=(row["logout_at"] if row else None))

@router.put("/forced_logout", response_model=dict, summary="Ustaw lub zaktualizuj termin wymuszonego wylogowania")
async def upsert_forced_logout(req: SetForcedLogoutRequest):
    stmt = pg_insert(forced_logout).values(
        id=1,
        logout_at=req.logout_at
    ).on_conflict_do_update(
        index_elements=[forced_logout.c.id],
        set_={"logout_at": req.logout_at}
    )
    await database.execute(stmt)
    return {"success": True}

@router.delete("/forced_logout", response_model=dict, summary="Usuń termin wymuszonego wylogowania")
async def delete_forced_logout():
    # usunięcie wiersza → później GET zwróci logout_at=None
    result = await database.execute(delete(forced_logout).where(forced_logout.c.id == 1))
    if not result:
        raise HTTPException(status_code=404, detail="Brak ustawionego terminu")
    return {"success": True}

# MODUŁ ŚLĄSKI
@router.get(
    "/slask/masters",
    response_model=ListMastersResponse,
    summary="Pobierz listy News/Calendar/Match Master"
)
async def get_slask_masters():
    news = [r["judge_id"] for r in await database.fetch_all(select(news_masters))]
    calendar = [r["judge_id"] for r in await database.fetch_all(select(calendar_masters))]
    match = [r["judge_id"] for r in await database.fetch_all(select(match_masters))]
    return ListMastersResponse(news=news, calendar=calendar, match=match)

@router.put(
    "/slask/masters",
    response_model=dict,
    summary="Zapisz wszystkie trzy listy naraz"
)
async def upsert_slask_masters(req: UpdateMastersRequest):
    # Wyczyść i zapisz każdą tabelę
    for table, arr in [
        (news_masters, req.news),
        (calendar_masters, req.calendar),
        (match_masters, req.match),
    ]:
        # usuń stare
        await database.execute(table.delete())
        # wstaw nowe
        for jid in arr:
            await database.execute(
                pg_insert(table).values(judge_id=jid)
                .on_conflict_do_nothing()
            )
    return {"success": True}

# (opcjonalnie) pojedyncze add/remove:
@router.post("/slask/masters/{kind}/{judge_id}", summary="Dodaj do jednej listy")
async def add_master(kind: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters}[kind]
    await database.execute(
        pg_insert(table).values(judge_id=judge_id).on_conflict_do_nothing()
    )
    return {"success": True}

@router.delete("/slask/masters/{kind}/{judge_id}", summary="Usuń z jednej listy")
async def remove_master(kind: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters}[kind]
    result = await database.execute(table.delete().where(table.c.judge_id == judge_id))
    if not result:
        raise HTTPException(404, "Nie znaleziono")
    return {"success": True}

# Pliki źródłowe
@router.get(
    "/json_files",
    response_model=ListJsonFilesResponse,
    summary="Lista wszystkich plików JSON"
)
async def list_json_files():
    rows = await database.fetch_all(select(json_files))
    files = [JsonFileItem(**dict(r)) for r in rows]
    return ListJsonFilesResponse(files=files)

@router.get(
    "/json_files/{key}",
    response_model=GetJsonFileResponse,
    summary="Pobierz konkretny plik JSON"
)
async def get_json_file(key: str):
    row = await database.fetch_one(select(json_files).where(json_files.c.key==key))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku")
    return GetJsonFileResponse(file=JsonFileItem(**dict(row)))

@router.put(
    "/json_files/{key}",
    response_model=GetJsonFileResponse,
    summary="Utwórz lub nadpisz plik JSON"
)
async def upsert_json_file(key: str, req: UpsertJsonFileRequest):
    if req.key != key:
        raise HTTPException(400, "Key mismatch")
    stmt = insert(json_files).values(
      key=key, content=req.content, enabled=req.enabled
    ).on_conflict_do_update(
      index_elements=[json_files.c.key],
      set_={"content": req.content, "enabled": req.enabled}
    )
    await database.execute(stmt)
    row = await database.fetch_one(select(json_files).where(json_files.c.key==key))
    return GetJsonFileResponse(file=JsonFileItem(**dict(row)))