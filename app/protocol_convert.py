# app/protocol_convert.py

import io
import logging
import math
from typing import List, Tuple

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from PIL import Image, ImageOps
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Protocol"])


def _read_image_normalized(file_bytes: bytes) -> Image.Image:
    """
    - Otwiera obraz z bajtów
    - Naprawia EXIF orientation
    - Konwertuje do RGB (dla PDF)
    """
    try:
        im = Image.open(io.BytesIO(file_bytes))
        im = ImageOps.exif_transpose(im)
        if im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        elif im.mode == "L":
            im = im.convert("RGB")
        return im
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nieprawidłowy obraz: {e}",
        )


def _draw_image_as_a4_page(
    c: canvas.Canvas,
    pil_img: Image.Image,
    page_size: Tuple[float, float],
    margin_pt: float = 24.0,  # ~8.5mm
    jpeg_quality: int = 92,
) -> None:
    """
    Skaluje obraz do A4 z zachowaniem proporcji (contain), centrowanie.
    """
    page_w, page_h = page_size
    max_w = page_w - 2 * margin_pt
    max_h = page_h - 2 * margin_pt

    iw, ih = pil_img.size
    if iw <= 0 or ih <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Obraz ma nieprawidłowy rozmiar (0).",
        )

    # contain scale
    scale = min(max_w / iw, max_h / ih)
    draw_w = iw * scale
    draw_h = ih * scale

    x = (page_w - draw_w) / 2.0
    y = (page_h - draw_h) / 2.0

    # ReportLab najpewniej rysuje obrazy z pliku/bytes jako JPEG/PNG,
    # więc zapisujemy PIL -> JPEG do pamięci.
    img_buf = io.BytesIO()
    pil_img.save(img_buf, format="JPEG", quality=jpeg_quality, optimize=True)
    img_buf.seek(0)

    c.drawImage(img_buf, x, y, width=draw_w, height=draw_h, preserveAspectRatio=True, mask="auto")


@router.post(
    "/judge/protocol/convert/images_to_pdf",
    summary="Konwertuj wiele obrazów (JPG/PNG) do jednego PDF (A4), każda grafika jako osobna strona",
)
async def convert_images_to_pdf(
    images: List[UploadFile] = File(..., description="Lista obrazów w kolejności stron PDF"),
):
    """
    Zwraca PDF jako odpowiedź (bez zapisu na serwerze).
    Kolejność stron = kolejność plików w multipart/form-data.
    """
    if not images or len(images) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Brak plików obrazów do konwersji.",
        )

    # Prosta walidacja mime (nie blokujemy na 100%, bo niektóre platformy wysyłają 'application/octet-stream')
    allowed = {"image/jpeg", "image/jpg", "image/png", "image/heic", "image/heif"}
    for f in images:
        if f.content_type and f.content_type not in allowed and not f.content_type.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Nieobsługiwany typ pliku: {f.content_type}",
            )

    out = io.BytesIO()
    c = canvas.Canvas(out, pagesize=A4)

    try:
        for idx, f in enumerate(images):
            data = await f.read()
            if not data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Plik {idx+1} jest pusty.",
                )

            pil_img = _read_image_normalized(data)
            _draw_image_as_a4_page(c, pil_img, A4)

            c.showPage()

        c.save()
        out.seek(0)

        filename = "protocol_images.pdf"
        headers = {
            "Content-Disposition": f'inline; filename="{filename}"'
        }

        return StreamingResponse(
            out,
            media_type="application/pdf",
            headers=headers,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("convert_images_to_pdf: błąd: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Nie udało się wygenerować PDF: {e}",
        )
