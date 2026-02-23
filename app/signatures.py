# app/signatures.py
from __future__ import annotations

import os
import shutil
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete, func

from app.db import database, signatures  # <- Twoja Table z db.py


RAILWAY_VOLUME_MOUNT_PATH = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
STATIC_DIR = (
    os.path.join(RAILWAY_VOLUME_MOUNT_PATH, "static")
    if RAILWAY_VOLUME_MOUNT_PATH
    else "static"
)
os.makedirs(STATIC_DIR, exist_ok=True)


def _static_path_for_url(image_url: str) -> str:
    filename = (image_url or "").split("/")[-1]
    return os.path.join(STATIC_DIR, filename)


def _guess_ext(upload: UploadFile) -> str:
    fn = (upload.filename or "").strip()
    if "." in fn:
        ext = fn.split(".")[-1].strip().lower()
        if ext:
            return ext

    ctype = (upload.content_type or "").lower().strip()
    if ctype == "image/png":
        return "png"
    if ctype in ("image/jpeg", "image/jpg"):
        return "jpg"
    if ctype == "image/svg+xml":
        return "svg"
    if ctype == "image/webp":
        return "webp"
    return "png"


def _save_upload_to_static(upload: UploadFile) -> str:
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


class SignatureResponse(BaseModel):
    id: int
    image_url: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ListSignaturesResponse(BaseModel):
    signatures: List[SignatureResponse]


router = APIRouter(prefix="/signatures", tags=["Signatures"])


def _row_to_response(row) -> SignatureResponse:
    return SignatureResponse(
        id=row["id"],
        image_url=row["image_url"],
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


@router.get("/{sig_id}", response_model=SignatureResponse)
async def get_signature(sig_id: int):
    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")
    return _row_to_response(row)


@router.get("/{sig_id}/url", response_model=str)
async def get_signature_url(sig_id: int):
    row = await database.fetch_one(
        select(signatures.c.image_url).where(signatures.c.id == sig_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")
    return row["image_url"]


@router.get("/", response_model=ListSignaturesResponse)
async def list_signatures():
    q = select(signatures).order_by(
        signatures.c.updated_at.desc().nullslast(),
        signatures.c.id.desc(),
    )
    rows = await database.fetch_all(q)
    return ListSignaturesResponse(signatures=[_row_to_response(r) for r in rows])


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    response_model=SignatureResponse,
    response_model_exclude_none=True,
)
async def upload_signature(image: UploadFile = File(...)):
    image_url = _save_upload_to_static(image)

    # Twoja tabela ma judge_id NOT NULL -> musimy coś wstawić.
    # Jeśli chcesz "bez walidacji", to daj stałą wartość albo poluzuj DB (nullable=True).
    # Najprościej: stały owner.
    stmt = (
        insert(signatures)
        .values(
            judge_id="system",
            judge_name=None,
            image_url=image_url,
            # created_at / updated_at ogarnia server_default
        )
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    return _row_to_response(record)


@router.put(
    "/{sig_id}",
    response_model=SignatureResponse,
    response_model_exclude_none=True,
)
async def update_signature(sig_id: int, image: UploadFile = File(...)):
    old = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not old:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    _delete_static_if_exists(old["image_url"])
    new_image_url = _save_upload_to_static(image)

    stmt = (
        update(signatures)
        .where(signatures.c.id == sig_id)
        .values(
            image_url=new_image_url,
            updated_at=func.now(),
        )
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    return _row_to_response(record)


@router.delete(
    "/{sig_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_signature(sig_id: int):
    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    _delete_static_if_exists(row["image_url"])
    await database.execute(delete(signatures).where(signatures.c.id == sig_id))
    return