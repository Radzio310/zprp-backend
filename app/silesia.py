# app/silesia.py
from datetime import datetime
from json import JSONDecodeError
import base64
import json
import os
import shutil
import uuid
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy import select, insert, update, delete, func

from app.db import database, announcements, silesia_offtimes
from app.schemas import (
    # Announcements
    AnnouncementResponse,
    LastUpdateResponse,
    ListAnnouncementsResponse,
    # Offtimes
    OfftimeRecord,
    ListAllOfftimesResponse,
    SetOfftimesRequest,
)
from app.deps import get_rsa_keys

from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.dialects.postgresql import insert as pg_insert


# -------------------------
# Helpers
# -------------------------

def _decrypt_field(enc_b64: str, private_key) -> str:
    """
    Odszyfrowuje Base64-RSA (PKCS1v15) na str (utf-8).
    """
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")


# -------------------------
# Routers
# -------------------------

# Ogłoszenia (per-województwo)
router_ann = APIRouter(prefix="/silesia/announcements", tags=["Silesia - Announcements"])

# Niedyspozycje (per-województwo)
router_off = APIRouter(prefix="/silesia/offtimes", tags=["Silesia - Offtimes"])


# ============================================================
# ================  ANNOUNCEMENTS (OKRĘGOWE)  ================
# ============================================================

@router_ann.get(
    "/last_update",
    response_model=LastUpdateResponse,
    summary="Pobierz datę ostatniej aktualizacji ogłoszeń (opcjonalnie filtrowane po województwie)",
)
async def get_last_update(province: Optional[str] = Query(None)):
    """
    Zwraca timestamp ostatniej zmiany spośród ogłoszeń.
    Jeśli podasz ?province=..., filtruje po województwie.
    """
    q = select(func.max(announcements.c.updated_at))
    if province:
        q = q.where(announcements.c.province == province)
    row = await database.fetch_one(q)
    return LastUpdateResponse(last_update=row[0])


@router_ann.get(
    "/",
    response_model=ListAnnouncementsResponse,
    summary="Pobierz ogłoszenia (opcjonalnie filtrowane po województwie)",
)
async def list_announcements(province: Optional[str] = Query(None)):
    """
    Zwraca ogłoszenia posortowane wg priority rosnąco.
    Jeśli podasz ?province=..., zwróci tylko z danego województwa.
    """
    q = select(announcements)
    if province:
        q = q.where(announcements.c.province == province)
    q = q.order_by(announcements.c.priority)

    rows = await database.fetch_all(q)
    result = [
        AnnouncementResponse(
            id=r["id"],
            title=r["title"],
            content=r["content"],
            image_url=r["image_url"],
            priority=r["priority"],
            link=r["link"],
            updated_at=r["updated_at"],
            judge_name=r["judge_name"],
            province=r["province"],  # ⬅ per-województwo
        )
        for r in rows
    ]
    return ListAnnouncementsResponse(announcements=result)


@router_ann.post(
    "/create",
    status_code=status.HTTP_201_CREATED,
    response_model=AnnouncementResponse,
    response_model_exclude_none=True,
    summary="Dodaj nowe ogłoszenie (per-województwo)",
)
async def create_announcement(
    # Pola uwierzytelniające (RSA Base64)
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    # Treść (jak wcześniej – title RSA, content plaintext)
    title: str = Form(...),
    content: str = Form(...),
    priority: int = Form(...),
    link: Optional[str] = Form(None),
    province: str = Form(...),  # ⬅ NOWE – plaintext województwo
    image: Optional[UploadFile] = File(None),
    keys=Depends(get_rsa_keys),
):
    """
    Tworzy ogłoszenie przypisane do konkretnego `province`.
    """
    private_key, _ = keys
    judge_plain     = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)
    title_plain     = _decrypt_field(title, private_key)
    content_plain   = content
    link_plain      = link
    province_plain  = province

    image_url = None
    if image:
        ext = (image.filename or "img").split(".")[-1]
        filename = f"{uuid.uuid4()}.{ext}"
        dest = f"static/{filename}"
        with open(dest, "wb") as out:
            shutil.copyfileobj(image.file, out)
        image_url = f"/static/{filename}"

    stmt = (
        insert(announcements)
        .values(
            judge_id=judge_plain,
            judge_name=full_name_plain,
            title=title_plain,
            content=content_plain,
            image_url=image_url,
            priority=priority,
            link=link_plain,
            province=province_plain,  # ⬅ zapis województwa
        )
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)
    return AnnouncementResponse(
        id=record["id"],
        judge_name=record["judge_name"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        link=record["link"],
        updated_at=record["updated_at"],
        province=record["province"],
    )


@router_ann.put(
    "/{ann_id}",
    response_model=AnnouncementResponse,
    response_model_exclude_none=True,
    summary="Edytuj ogłoszenie (możesz zmienić province)",
)
async def update_announcement(
    ann_id: int,
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    title: Optional[str] = Form(None),
    content: Optional[str] = Form(None),
    priority: Optional[int] = Form(None),
    link: Optional[str] = Form(None),
    province: Optional[str] = Form(None),  # ⬅ NOWE – opcjonalna zmiana województwa
    image: Optional[UploadFile] = File(None),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    judge_plain     = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)
    title_plain     = _decrypt_field(title, private_key) if title else None
    content_plain   = content
    link_plain      = link

    image_url = None
    if image:
        # Usuń poprzedni plik (jeśli był)
        old = await database.fetch_one(
            select(announcements.c.image_url).where(announcements.c.id == ann_id)
        )
        old_url = old["image_url"] if old else None
        if old_url:
            old_path = old_url.lstrip("/")
            if os.path.isfile(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        ext = (image.filename or "img").split(".")[-1]
        filename = f"{uuid.uuid4()}.{ext}"
        dest = f"static/{filename}"
        with open(dest, "wb") as out:
            shutil.copyfileobj(image.file, out)
        image_url = f"/static/{filename}"

    update_values = {
        "judge_id": judge_plain,
        "judge_name": full_name_plain,
    }
    if title_plain is not None:
        update_values["title"] = title_plain
    if content_plain is not None:
        update_values["content"] = content_plain
    if priority is not None:
        update_values["priority"] = priority
    if link_plain is not None:
        update_values["link"] = link_plain
    if province is not None:
        update_values["province"] = province  # ⬅ zmiana województwa
    if image_url is not None:
        update_values["image_url"] = image_url

    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(**update_values)
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)
    if not record:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    return AnnouncementResponse(
        id=record["id"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        link=record["link"],
        judge_name=record["judge_name"],
        updated_at=record["updated_at"],
        province=record["province"],
    )


@router_ann.delete(
    "/{ann_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń ogłoszenie (wraz z plikiem, jeśli istnieje)",
)
async def delete_announcement(ann_id: int):
    row = await database.fetch_one(
        select(announcements.c.image_url).where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    image_url = row["image_url"]
    if image_url:
        path = image_url.lstrip("/")
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass

    await database.execute(delete(announcements).where(announcements.c.id == ann_id))
    return


# ============================================================
# ==================  OFFTIMES (OKRĘGOWE)  ===================
# ============================================================

@router_off.post(
    "/set",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub nadpisz niedyspozycje sędziego w okręgu",
)
async def set_offtimes(req: SetOfftimesRequest):
    """
    Upsert po (judge_id, province).
    `data_json` może być już obiektem/listą albo stringiem JSON.
    """
    judge_plain = req.judge_id
    full_name   = req.full_name
    city_plain  = req.city
    province    = req.province

    raw = req.data_json
    if isinstance(raw, str):
        try:
            data_json_obj = json.loads(raw)
        except JSONDecodeError:
            raise HTTPException(status_code=400, detail="Niepoprawny JSON w data_json")
    else:
        data_json_obj = raw

    # Postgres: ON CONFLICT (judge_id, province)
    # SQLite: w razie czego zadziała jako zwykły INSERT, ale rekomendowana migracja na composite PK
    stmt = pg_insert(silesia_offtimes).values(
        judge_id=judge_plain,
        province=province,
        full_name=full_name,
        city=city_plain,
        data_json=data_json_obj,
    ).on_conflict_do_update(
        index_elements=[silesia_offtimes.c.judge_id, silesia_offtimes.c.province],
        set_={
            "full_name": full_name,
            "city": city_plain,
            "data_json": data_json_obj,
            "updated_at": func.now(),
        },
    )
    await database.execute(stmt)
    return {"success": True}


@router_off.get(
    "/self/{judge_id}",
    response_model=OfftimeRecord,
    summary="Pobierz swoje niedyspozycje (wymaga parametru province)",
)
async def get_my_offtimes(
    judge_id: str,
    province: str = Query(..., description="Województwo, np. 'ŚLĄSKIE'"),
):
    row = await database.fetch_one(
        select(silesia_offtimes).where(
            (silesia_offtimes.c.judge_id == judge_id)
            & (silesia_offtimes.c.province == province)
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Brak zapisanych niedyspozycji")

    return OfftimeRecord(
        judge_id=row["judge_id"],
        province=row["province"],
        full_name=row["full_name"],
        city=row["city"],
        data_json=row["data_json"],
        updated_at=row["updated_at"],
    )


@router_off.delete(
    "/{judge_id_enc}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń niedyspozycje sędziego w konkretnym okręgu",
)
async def delete_offtimes(
    judge_id_enc: str,
    province: str = Query(..., description="Województwo, np. 'ŚLĄSKIE'"),
    # Body z autoryzacją (zostawiam jak u Ciebie – nieużywane pola, ale pilnują schematu):
    req: SetOfftimesRequest = Depends(),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    judge_plain = _decrypt_field(judge_id_enc, private_key)

    deleted = await database.execute(
        delete(silesia_offtimes).where(
            (silesia_offtimes.c.judge_id == judge_plain)
            & (silesia_offtimes.c.province == province)
        )
    )
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Nie znaleziono niedyspozycji")
    return


@router_off.get(
    "/all",
    response_model=ListAllOfftimesResponse,
    summary="Lista wszystkich niedyspozycji (opcjonalnie filtrowana po province)",
)
async def list_all_offtimes(province: Optional[str] = Query(None)):
    q = select(silesia_offtimes)
    if province:
        q = q.where(silesia_offtimes.c.province == province)
    rows = await database.fetch_all(q)

    return ListAllOfftimesResponse(
        records=[
            OfftimeRecord(
                judge_id=r["judge_id"],
                province=r["province"],
                full_name=r["full_name"],
                city=r["city"],
                data_json=r["data_json"],
                updated_at=r["updated_at"],
            )
            for r in rows
        ]
    )


# -------------------------
# Główny router eksportowany
# -------------------------
router = APIRouter()
router.include_router(router_ann)
router.include_router(router_off)
