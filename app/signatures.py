# app/signatures.py
from __future__ import annotations

import os
import uuid
from datetime import datetime
from io import BytesIO
from typing import Optional, List

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete, func

from app.db import database, signatures

try:
    import cairosvg  # type: ignore
except Exception:  # pragma: no cover
    cairosvg = None  # type: ignore

from PIL import Image  # type: ignore

RAILWAY_VOLUME_MOUNT_PATH = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
STATIC_DIR = (
    os.path.join(RAILWAY_VOLUME_MOUNT_PATH, "static")
    if RAILWAY_VOLUME_MOUNT_PATH
    else "static"
)
os.makedirs(STATIC_DIR, exist_ok=True)

OUT_W = 600
OUT_H = 400


def _static_path_for_url(image_url: str) -> str:
    filename = (image_url or "").split("/")[-1]
    return os.path.join(STATIC_DIR, filename)


def _delete_static_if_exists(image_url: Optional[str]) -> None:
    if not image_url:
        return
    path = _static_path_for_url(image_url)
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _sniff_is_svg(upload: UploadFile, first_bytes: bytes) -> bool:
    ctype = (upload.content_type or "").lower().strip()
    if "svg" in ctype:
        return True

    head = first_bytes.lstrip()[:600].lower()
    # typowe przypadki: <?xml ...?><svg ...> albo bez xml: <svg ...>
    if head.startswith(b"<svg") or head.startswith(b"<?xml"):
        return b"<svg" in head
    return b"<svg" in head


def _render_svg_to_png_bytes(svg_bytes: bytes) -> bytes:
    if cairosvg is None:
        raise HTTPException(
            status_code=500,
            detail=(
                "Backend nie ma cairosvg. "
                "Wysyłaj PNG/JPG z aplikacji albo doinstaluj cairosvg + zależności systemowe."
            ),
        )

    out = cairosvg.svg2png(
        bytestring=svg_bytes,
        output_width=OUT_W,
        output_height=OUT_H,
        background_color="white",
    )
    if not out:
        raise HTTPException(status_code=400, detail="Nie udało się wyrenderować SVG do PNG.")
    return out


def _fit_raster_to_canvas_png_bytes(raster_bytes: bytes) -> bytes:
    # Wczytaj raster (png/jpg), spłaszcz do białego tła i wpasuj w 600x400 (contain).
    try:
        img = Image.open(BytesIO(raster_bytes))
    except Exception:
        raise HTTPException(status_code=400, detail="Nieprawidłowy obraz wejściowy.")

    img = img.convert("RGBA")

    bg = Image.new("RGBA", (OUT_W, OUT_H), (255, 255, 255, 255))

    # contain (zachowaj proporcje)
    img.thumbnail((OUT_W, OUT_H), Image.LANCZOS)

    x = (OUT_W - img.size[0]) // 2
    y = (OUT_H - img.size[1]) // 2
    bg.paste(img, (x, y), img)

    out = BytesIO()
    bg.convert("RGB").save(out, format="PNG", optimize=True)
    return out.getvalue()


async def _read_upload_bytes(upload: UploadFile, max_bytes: int = 2_500_000) -> bytes:
    data = await upload.read()
    if not data:
        raise HTTPException(status_code=400, detail="Pusty plik.")
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="Plik za duży.")
    return data


def _save_png_bytes_to_static(png_bytes: bytes) -> str:
    filename = f"{uuid.uuid4()}.png"
    dest = os.path.join(STATIC_DIR, filename)
    with open(dest, "wb") as f:
        f.write(png_bytes)
    return f"/static/{filename}"


class SignatureResponse(BaseModel):
    id: int
    image_url: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ListSignaturesResponse(BaseModel):
    signatures: List[SignatureResponse]


router = APIRouter(prefix="/signatures", tags=["Signatures"])


def _row_to_response(row) -> SignatureResponse:
    m = row._mapping  # databases.Record
    return SignatureResponse(
        id=m["id"],
        image_url=m["image_url"],
        created_at=m.get("created_at"),
        updated_at=m.get("updated_at"),
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
    return row._mapping["image_url"]


@router.get("/", response_model=ListSignaturesResponse)
async def list_signatures():
    q = select(signatures).order_by(
        signatures.c.updated_at.desc().nullslast(),
        signatures.c.id.desc(),
    )
    rows = await database.fetch_all(q)
    return ListSignaturesResponse(signatures=[_row_to_response(r) for r in rows])


async def _upload_to_png_url(image: UploadFile) -> str:
    raw = await _read_upload_bytes(image)
    is_svg = _sniff_is_svg(image, raw[:800])

    if is_svg:
        png_bytes = _render_svg_to_png_bytes(raw)
    else:
        png_bytes = _fit_raster_to_canvas_png_bytes(raw)

    return _save_png_bytes_to_static(png_bytes)


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    response_model=SignatureResponse,
    response_model_exclude_none=True,
)
async def upload_signature(image: UploadFile = File(...)):
    image_url = await _upload_to_png_url(image)

    stmt = (
        insert(signatures)
        .values(
            judge_id="system",  # masz NOT NULL
            judge_name=None,
            image_url=image_url,
        )
        .returning(signatures)
    )
    record = await database.fetch_one(stmt)
    if not record:
        raise HTTPException(status_code=500, detail="Insert failed")
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

    _delete_static_if_exists(old._mapping["image_url"])

    new_image_url = await _upload_to_png_url(image)

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
    if not record:
        raise HTTPException(status_code=500, detail="Update failed")
    return _row_to_response(record)


@router.delete(
    "/{sig_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_signature(sig_id: int):
    row = await database.fetch_one(select(signatures).where(signatures.c.id == sig_id))
    if not row:
        raise HTTPException(status_code=404, detail="Podpis nie istnieje")

    _delete_static_if_exists(row._mapping["image_url"])
    await database.execute(delete(signatures).where(signatures.c.id == sig_id))
    return