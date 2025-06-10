# app/silesia.py
import datetime
from json import JSONDecodeError, loads
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy import select, insert, update, delete, func
from app.db import database, announcements, silesia_offtimes
from app.schemas import (
    CreateAnnouncementRequest,
    ListOfftimesRequest,
    ListOfftimesResponse,
    OfftimeRecord,
    SetOfftimesRequest,
    UpdateAnnouncementRequest,
    DeleteAnnouncementRequest,
    ListAnnouncementsResponse,
    AnnouncementResponse,
    LastUpdateResponse,
)
from app.deps import get_rsa_keys
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.dialects.postgresql import insert as pg_insert

router = APIRouter(
    prefix="/silesia/announcements",
    tags=["Silesia"]
)

def _decrypt_field(enc_b64: str, private_key) -> str:
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")

@router.get(
    "/last_update",
    response_model=LastUpdateResponse,
    summary="Pobierz datę ostatniej aktualizacji ogłoszeń sędziego"
)
async def get_last_update(
    auth: CreateAnnouncementRequest = Depends(),  # wykorzystujemy ten sam schemat uwierzytelniający
    keys=Depends(get_rsa_keys),
):
    """
    Zwraca timestamp ostatniej zmiany (lub None, jeśli brak wpisów).
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(auth.judge_id, private_key)

    query = select(func.max(announcements.c.updated_at)).where(
        announcements.c.judge_id == judge_plain
    )
    row = await database.fetch_one(query)
    return LastUpdateResponse(last_update=row[0])

@router.get(
    "/",
    response_model=ListAnnouncementsResponse,
    summary="Pobierz wszystkie ogłoszenia sędziego"
)
async def list_announcements(
    auth: CreateAnnouncementRequest = Depends(),
    keys=Depends(get_rsa_keys),
):
    """
    Zwraca listę ogłoszeń pogrupowaną według priorytetu (rosnąco).
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(auth.judge_id, private_key)

    query = select(announcements).where(
        announcements.c.judge_id == judge_plain
    ).order_by(announcements.c.priority)
    rows = await database.fetch_all(query)

    result = [
        AnnouncementResponse(
            id=r["id"],
            title=r["title"],
            content=r["content"],
            image_url=r["image_url"],
            priority=r["priority"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListAnnouncementsResponse(announcements=result)

@router.post(
    "/create",
    status_code=status.HTTP_201_CREATED,
    response_model=AnnouncementResponse,
    summary="Dodaj nowe ogłoszenie"
)
async def create_announcement(
    req: CreateAnnouncementRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Body:
    - title, content, image_url (opcjonalnie), priority
    - wszystkie pola zaszyfrowane Base64-RSA
    Zwraca utworzone ogłoszenie wraz z `id` i `updated_at`.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)
    title = _decrypt_field(req.title, private_key)
    content = _decrypt_field(req.content, private_key)
    image_url = _decrypt_field(req.image_url, private_key) if req.image_url else None

    stmt = (
        insert(announcements)
        .values(
            judge_id=judge_plain,
            title=title,
            content=content,
            image_url=image_url,
            priority=req.priority,
        )
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)
    return AnnouncementResponse(
        id=record["id"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        updated_at=record["updated_at"],
    )

@router.put(
    "/{ann_id}",
    response_model=AnnouncementResponse,
    summary="Edytuj ogłoszenie"
)
async def update_announcement(
    ann_id: int,
    req: UpdateAnnouncementRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Parametr URL: id ogłoszenia
    Body: dowolne pola do nadpisania (title, content, image_url, priority), wszystkie zaszyfrowane.
    Możliwe tylko jeśli ogłoszenie należy do sędziego.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)

    # sprawdź własność:
    exists = await database.fetch_one(
        select(announcements.c.id).where(
            (announcements.c.id == ann_id) &
            (announcements.c.judge_id == judge_plain)
        )
    )
    if not exists:
        raise HTTPException(status_code=404, detail="Nie znaleziono ogłoszenia")

    values = {}
    if req.title is not None:
        values["title"] = _decrypt_field(req.title, private_key)
    if req.content is not None:
        values["content"] = _decrypt_field(req.content, private_key)
    if req.image_url is not None:
        values["image_url"] = _decrypt_field(req.image_url, private_key)
    if req.priority is not None:
        values["priority"] = req.priority
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    stmt = (
        update(announcements)
        .where(
            (announcements.c.id == ann_id) &
            (announcements.c.judge_id == judge_plain)
        )
        .values(**values)
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)
    return AnnouncementResponse(
        id=record["id"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        updated_at=record["updated_at"],
    )

@router.delete(
    "/{ann_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń ogłoszenie"
)
async def delete_announcement(
    ann_id: int,
    req: DeleteAnnouncementRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Parametr URL: id ogłoszenia
    Body: tylko AuthPayload (username, password, judge_id)
    Usuwa, jeśli ogłoszenie należy do zadanego sędziego.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)

    # sprawdź własność:
    exists = await database.fetch_one(
        select(announcements.c.id).where(
            (announcements.c.id == ann_id) &
            (announcements.c.judge_id == judge_plain)
        )
    )
    if not exists:
        raise HTTPException(status_code=404, detail="Nie znaleziono ogłoszenia")

    await database.execute(
        delete(announcements).where(
            (announcements.c.id == ann_id) &
            (announcements.c.judge_id == judge_plain)
        )
    )
    # brak treści w odpowiedzi → 204 No Content
    return

router_off = APIRouter(
    prefix="/silesia/offtimes",
    tags=["Silesia"]
)

@router_off.post(
    "/set",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub nadpisz niedyspozycje sędziego"
)
async def set_offtimes(
    req: SetOfftimesRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Upsert (INSERT albo UPDATE) całej listy niedyspozycji danego sędziego.
    Body:
      - username, password, judge_id, full_name, data_json (wszystkie Base64‑RSA)
      - data_json: string JSON array np. '[{"from":"...","to":"...",...}, ...]'
    Zwraca success=true.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)
    full_name = _decrypt_field(req.full_name, private_key)
    data_json = _decrypt_field(req.data_json, private_key)

    # walidacja JSON
    try:
        loads(data_json)
    except JSONDecodeError:
        raise HTTPException(status_code=400, detail="Niepoprawny JSON w data_json")

    stmt = pg_insert(silesia_offtimes).values(
        judge_id=judge_plain,
        full_name=full_name,
        data_json=data_json
    ).on_conflict_do_update(
        index_elements=[silesia_offtimes.c.judge_id],
        set_={
            "full_name": full_name,
            "data_json": data_json,
            "updated_at": func.now()
        }
    )
    await database.execute(stmt)
    return {"success": True}

@router_off.get(
    "/self",
    response_model=OfftimeRecord,
    summary="Pobierz swoje niedyspozycje"
)
async def get_my_offtimes(
    req: SetOfftimesRequest = Depends(),
    keys=Depends(get_rsa_keys),
):
    """
    Zwraca wpis niedyspozycji dla zalogowanego sędziego.
    Body: username, password, judge_id (Base64‑RSA).
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)

    row = await database.fetch_one(
        select(silesia_offtimes).where(silesia_offtimes.c.judge_id == judge_plain)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Brak zapisanych niedyspozycji")
    return OfftimeRecord(
        judge_id=row["judge_id"],
        full_name=row["full_name"],
        data_json=row["data_json"],
        updated_at=row["updated_at"],
    )

@router_off.post(
    "/list",
    response_model=ListOfftimesResponse,
    summary="Pobierz niedyspozycje wielu sędziów"
)
async def list_offtimes(
    req: ListOfftimesRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Body:
      - username, password (Base64‑RSA, do uwierzytelnienia)
      - judge_ids: lista Base64‑RSA identyfikatorów
    Zwraca listę rekordów tylko dla tych judge_id.
    """
    private_key, _ = keys
    # odszyfruj listę ID
    plain_ids = []
    for enc in req.judge_ids:
        try:
            plain_ids.append(_decrypt_field(enc, private_key))
        except:
            raise HTTPException(status_code=400, detail="Błędny judge_id w liście")

    rows = await database.fetch_all(
        select(silesia_offtimes).where(silesia_offtimes.c.judge_id.in_(plain_ids))
    )
    records = [
        OfftimeRecord(
            judge_id=r["judge_id"],
            full_name=r["full_name"],
            data_json=r["data_json"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListOfftimesResponse(records=records)

@router_off.delete(
    "/{judge_id_enc}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń wpis niedyspozycji sędziego"
)
async def delete_offtimes(
    judge_id_enc: str,
    req: SetOfftimesRequest = Depends(),  # dla uwierzytelnienia
    keys=Depends(get_rsa_keys),
):
    """
    Path param: judge_id (Base64‑RSA).
    Body: username, password, judge_id (do weryfikacji).
    Usuwa wpis z bazy.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(judge_id_enc, private_key)

    deleted = await database.execute(
        delete(silesia_offtimes).where(silesia_offtimes.c.judge_id == judge_plain)
    )
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Nie znaleziono niedyspozycji")
    return