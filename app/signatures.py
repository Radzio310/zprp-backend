# app/signatures.py
from __future__ import annotations

import os
import shutil
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, File, HTTPException, UploadFile, status, Query
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete, func

from app.db import database, signatures  # <- Table `signatures` musi istnieć


# -------------------------
# Static files (Railway Volume)
# -------------------------
RAILWAY_VOLUME_MOUNT_PATH = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")  # np. "/data"
STATIC_DIR = (
    os.path.join(RAILWAY_VOLUME_MOUNT_PATH, "static")
    if RAILWAY_VOLUME_MOUNT_PATH
    else "static"
)

os.makedirs(STATIC_DIR, exist_ok=True)


def _static_path_for_url(image_url: str) -> str:
    """
    Zamienia '/static/<filename>' -> '<STATIC_DIR>/<filename>'
    """
    filename = (image_url or "").split("/")[-1]
    return os.path.join(STATIC_DIR, filename)


def _guess_ext(upload: UploadFile) -> str:
    # preferuj rozszerzenie z filename
    fn = (upload.filename or "").strip()
    if "." in fn:
        ext = fn.split(".")[-1].strip().lower()
        if ext:
            return ext

    # fallback po content-type
    ctype = (upload.content_type or "").lower().strip()
    if ctype == "image/png":
        return "png"
    if ctype in ("image/jpeg", "image/jpg"):
        return "jpg"
    if ctype == "image/svg+xml":
        return "svg"
    if ctype == "image/webp":
        return "webp"

    # ostatecznie
    return "png"


def _save_upload_to_static(upload: UploadFile) -> str:
    """
    Zapisuje UploadFile do STATIC_DIR pod losową nazwą i zwraca image_url (/static/...).
    Brak walidacji usera – jedynie zapis pliku.
    """
    ext = _guess_ext(upload)
    filename = f"{uuid.uuid4()}.{ext}"
    dest = os.path.join(STATIC_DIR, filename)

    with open(dest, "wb") as out:
        shutil.copyfileobj(upload.file, out)

    return f"/static/{filename}"


def _delete_static_if_exists(image_url: Optional[str]) -> None:
    if not image_url:
        return
    path = _static_path_for_url(image_url)
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass


# -------------------------
# Schemas
# -------------------------
class SignatureResponse(BaseModel):
    id: int
    image_url: str
    kind: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ListSignaturesResponse(BaseModel):
    signatures: List[SignatureResponse]


# -------------------------
# Router
# -------------------------
router = APIRouter(prefix="/signatures", tags=["Signatures"])


def _row_to_response(row) -> SignatureResponse:
    return SignatureResponse(
        id=row["id"],
        image_url=row["image_url"],
        kind=row.get("kind"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


@router.get(
    "/{sig_id}",
    response_model=SignatureResponse,
    summary="Pobierz metadane podpisu + image_url (/static/...) po ID",
)
async def get_signature(sig_id: int):
    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")
    return _row_to_response(row)


@router.get(
    "/{sig_id}/url",
    response_model=str,
    summary="Zwróć sam link do grafiki podpisu (/static/...)",
)
async def get_signature_url(sig_id: int):
    row = await database.fetch_one(
        select(signatures.c.image_url).where(signatures.c.id == sig_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")
    return row["image_url"]


@router.get(
    "/",
    response_model=ListSignaturesResponse,
    summary="Lista podpisów (opcjonalnie filtrowana po kind)",
)
async def list_signatures(kind: Optional[str] = Query(None)):
    q = select(signatures).order_by(
        signatures.c.updated_at.desc().nullslast(),
        signatures.c.id.desc(),
    )
    if kind:
        q = q.where(signatures.c.kind == kind)

    rows = await database.fetch_all(q)
    return ListSignaturesResponse(signatures=[_row_to_response(r) for r in rows])


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    response_model=SignatureResponse,
    response_model_exclude_none=True,
    summary="Dodaj podpis (obraz) jako nowy rekord",
)
async def upload_signature(
    image: UploadFile = File(...),
    kind: Optional[str] = Query(None, description="np. hostTeam / guestTeam / medic"),
):
    image_url = _save_upload_to_static(image)

    stmt = (
        insert(signatures)
        .values(
            image_url=image_url,
            kind=kind,
            # created_at/updated_at zakładam że masz default w DB,
            # ale jeśli nie masz, możesz wymusić:
            # created_at=func.now(),
            # updated_at=func.now(),
        )
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    return _row_to_response(record)


@router.put(
    "/{sig_id}",
    response_model=SignatureResponse,
    response_model_exclude_none=True,
    summary="Podmień obraz podpisu (usuwa poprzedni plik)",
)
async def update_signature(
    sig_id: int,
    image: UploadFile = File(...),
    kind: Optional[str] = Query(None),
):
    old = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not old:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    _delete_static_if_exists(old["image_url"])
    new_image_url = _save_upload_to_static(image)

    update_values = {
        "image_url": new_image_url,
        "updated_at": func.now(),
    }
    if kind is not None:
        update_values["kind"] = kind

    stmt = (
        update(signatures)
        .where(signatures.c.id == sig_id)
        .values(**update_values)
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    return _row_to_response(record)


@router.delete(
    "/{sig_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń podpis (wraz z plikiem)",
)
async def delete_signature(sig_id: int):
    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    _delete_static_if_exists(row["image_url"])
    await database.execute(delete(signatures).where(signatures.c.id == sig_id))
    return