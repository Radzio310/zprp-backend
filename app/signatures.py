# app/signatures.py
"""
Endpointy do obsługi grafik podpisów (signature images).

Założenia:
- Pliki są zapisywane na dysku w STATIC_DIR (Railway Volume / lokalnie).
- W DB przechowujemy jedynie ścieżkę `image_url` w formacie: "/static/<uuid>.<ext>"
- Serwowanie /static/* powinno być skonfigurowane w głównej aplikacji (np. FastAPI StaticFiles).

Wymagane w app.db:
- `database` (databases.Database)
- tabela `signatures` (SQLAlchemy Table) o polach co najmniej:
    id (PK, int),
    judge_id (str),
    judge_name (str, opcjonalnie),
    image_url (str),
    created_at (timestamp, default now),
    updated_at (timestamp, default now)
"""

from __future__ import annotations

import base64
import os
import shutil
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete, func

from cryptography.hazmat.primitives.asymmetric import padding

from app.db import database, signatures  # <- musisz mieć Table `signatures` w app/db.py
from app.deps import get_rsa_keys


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


def _decrypt_field(enc_b64: str, private_key) -> str:
    """
    Odszyfrowuje Base64-RSA (PKCS1v15) na str (utf-8).
    """
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")


def _save_upload_to_static(upload: UploadFile) -> str:
    """
    Zapisuje UploadFile do STATIC_DIR pod losową nazwą i zwraca image_url (/static/...).
    """
    # Minimalna walidacja typu (opcjonalna, ale przydatna)
    ctype = (upload.content_type or "").lower().strip()
    if ctype and not ctype.startswith("image/"):
        raise HTTPException(status_code=400, detail="Plik nie jest obrazem (content-type).")

    ext = (upload.filename or "img").split(".")[-1].strip().lower()
    if not ext or ext == (upload.filename or ""):
        ext = "png"

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
# Schemas (lokalne, żeby plik był samowystarczalny)
# -------------------------
class SignatureResponse(BaseModel):
    id: int
    judge_id: str
    judge_name: Optional[str] = None
    image_url: str
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
        judge_id=row["judge_id"],
        judge_name=row.get("judge_name"),
        image_url=row["image_url"],
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


@router.get(
    "/{sig_id}",
    response_model=SignatureResponse,
    summary="Pobierz metadane podpisu + link (/static/...) po ID",
)
async def get_signature(sig_id: int):
    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")
    return _row_to_response(row)


@router.get(
    "/by-judge/{judge_id}",
    response_model=SignatureResponse,
    summary="Pobierz najnowszy podpis po judge_id (jeśli masz jeden rekord na judge_id, zwróci go)",
)
async def get_signature_by_judge(judge_id: str):
    # Jeśli w DB masz unikalność judge_id -> możesz uprościć bez order_by
    q = (
        select(signatures)
        .where(signatures.c.judge_id == judge_id)
        .order_by(signatures.c.updated_at.desc().nullslast(), signatures.c.id.desc())
        .limit(1)
    )
    row = await database.fetch_one(q)
    if not row:
        raise HTTPException(status_code=404, detail="Brak podpisu dla tego sędziego")
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


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    response_model=SignatureResponse,
    response_model_exclude_none=True,
    summary="Dodaj podpis (obraz) jako nowy rekord",
)
async def upload_signature(
    # (opcjonalnie) pola jak w reszcie backendu – RSA base64
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    image: UploadFile = File(...),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    judge_plain = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)

    image_url = _save_upload_to_static(image)

    stmt = (
        insert(signatures)
        .values(
            judge_id=judge_plain,
            judge_name=full_name_plain,
            image_url=image_url,
        )
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    return _row_to_response(record)


@router.post(
    "/upload_or_replace",
    status_code=status.HTTP_200_OK,
    response_model=SignatureResponse,
    response_model_exclude_none=True,
    summary="Dodaj lub podmień podpis dla judge_id (upsert po judge_id)",
)
async def upload_or_replace_signature(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    image: UploadFile = File(...),
    keys=Depends(get_rsa_keys),
):
    """
    Jeżeli istnieje rekord dla judge_id:
      - usuwa stary plik
      - zapisuje nowy plik
      - aktualizuje image_url + updated_at
    W przeciwnym razie tworzy nowy rekord.
    """
    private_key, _ = keys

    judge_plain = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)

    existing = await database.fetch_one(
        select(signatures).where(signatures.c.judge_id == judge_plain)
    )

    new_image_url = _save_upload_to_static(image)

    if existing:
        _delete_static_if_exists(existing["image_url"])

        stmt = (
            update(signatures)
            .where(signatures.c.id == existing["id"])
            .values(
                judge_name=full_name_plain,
                image_url=new_image_url,
                updated_at=func.now(),
            )
            .returning(signatures)
        )
        updated = await database.fetch_one(stmt)
        return _row_to_response(updated)

    stmt = (
        insert(signatures)
        .values(
            judge_id=judge_plain,
            judge_name=full_name_plain,
            image_url=new_image_url,
        )
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    return _row_to_response(record)


@router.put(
    "/{sig_id}",
    response_model=SignatureResponse,
    response_model_exclude_none=True,
    summary="Edytuj podpis: podmień obraz (usuwa poprzedni plik)",
)
async def update_signature(
    sig_id: int,
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    image: UploadFile = File(...),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    judge_plain = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)

    old = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not old:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    # (opcjonalnie) prosty check właściciela:
    # jeśli chcesz wymusić, że tylko właściciel może edytować:
    if str(old["judge_id"]) != str(judge_plain):
        raise HTTPException(status_code=403, detail="Brak uprawnień do edycji tego podpisu")

    _delete_static_if_exists(old["image_url"])

    new_image_url = _save_upload_to_static(image)

    stmt = (
        update(signatures)
        .where(signatures.c.id == sig_id)
        .values(
            judge_name=full_name_plain,
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
    summary="Usuń podpis (wraz z plikiem)",
)
async def delete_signature(
    sig_id: int,
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    judge_plain = _decrypt_field(judge_id, private_key)

    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    # (opcjonalnie) check właściciela
    if str(row["judge_id"]) != str(judge_plain):
        raise HTTPException(status_code=403, detail="Brak uprawnień do usunięcia tego podpisu")

    _delete_static_if_exists(row["image_url"])

    await database.execute(delete(signatures).where(signatures.c.id == sig_id))
    return