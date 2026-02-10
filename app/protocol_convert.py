# app/protocol_convert.py

import io
import logging
import os
from typing import List, Tuple, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from PIL import Image, ImageOps
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Protocol"])


# =========================
# Tuning (bez zmian API)
# =========================
# Sensowne “jak konwertery”: ~150–200 DPI
PDF_TARGET_DPI = int(os.getenv("PDF_TARGET_DPI", "170"))

# JPEG quality: 65–85 zwykle świetny kompromis dla fotek dokumentów
PDF_JPEG_QUALITY = int(os.getenv("PDF_JPEG_QUALITY", "75"))

# Margines w punktach (1 pt = 1/72 cala)
PDF_MARGIN_PT = float(os.getenv("PDF_MARGIN_PT", "24"))

# Włącza progressive + optimize (zwykle mniejszy rozmiar)
PDF_JPEG_PROGRESSIVE = os.getenv("PDF_JPEG_PROGRESSIVE", "1") != "0"
PDF_JPEG_OPTIMIZE = os.getenv("PDF_JPEG_OPTIMIZE", "1") != "0"


def _read_image_normalized(file_bytes: bytes) -> Image.Image:
    """
    - Otwiera obraz z bajtów
    - Naprawia EXIF orientation
    - Konwertuje do RGB (pod PDF/JPEG)
    """
    try:
        im = Image.open(io.BytesIO(file_bytes))
        im = ImageOps.exif_transpose(im)

        # Ujednolicamy do RGB (PDF i tak najlepiej działa z RGB)
        # PNG z alphą -> kompozycja na białym tle
        if im.mode in ("RGBA", "LA"):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            alpha = im.getchannel("A") if "A" in im.getbands() else None
            if alpha is not None:
                bg.paste(im, mask=alpha)
            else:
                bg.paste(im)
            im = bg
        elif im.mode != "RGB":
            im = im.convert("RGB")

        return im
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nieprawidłowy obraz lub brak wsparcia formatu (np. HEIC bez pluginu): {e}",
        )


def _fit_into_a4_pixels(
    img_w_px: int,
    img_h_px: int,
    page_size_pt: Tuple[float, float],
    margin_pt: float,
    target_dpi: int,
) -> Tuple[int, int]:
    """
    Liczy docelowy max rozmiar obrazu w px, tak aby:
    - mieścił się w obszarze A4 minus margines
    - odpowiadał target DPI (downsampling)
    """
    page_w_pt, page_h_pt = page_size_pt
    max_w_pt = page_w_pt - 2 * margin_pt
    max_h_pt = page_h_pt - 2 * margin_pt

    # pt -> inches -> px
    max_w_px = int(max_w_pt / 72.0 * target_dpi)
    max_h_px = int(max_h_pt / 72.0 * target_dpi)

    if max_w_px <= 0 or max_h_px <= 0:
        # skrajnie nie powinno się zdarzyć
        max_w_px = 1
        max_h_px = 1

    # Dopasuj zachowując proporcje
    scale = min(max_w_px / img_w_px, max_h_px / img_h_px)
    # Nie upscale’uj (to tylko powiększa PDF bez sensu)
    scale = min(scale, 1.0)

    out_w = max(1, int(img_w_px * scale))
    out_h = max(1, int(img_h_px * scale))
    return out_w, out_h


def _prepare_image_for_pdf(
    pil_img: Image.Image,
    page_size_pt: Tuple[float, float],
    margin_pt: float,
    target_dpi: int,
    jpeg_quality: int,
) -> Tuple[io.BytesIO, int, int]:
    """
    - Downsample do rozmiaru odpowiadającego A4@targetDPI (z marginesami)
    - Re-encode do JPEG (optimize/progressive) żeby PDF nie puchł
    Zwraca:
      - buffer JPEG (BytesIO)
      - width_px, height_px (po resize)
    """
    iw, ih = pil_img.size
    if iw <= 0 or ih <= 0:
        raise HTTPException(status_code=400, detail="Obraz ma nieprawidłowy rozmiar (0).")

    out_w, out_h = _fit_into_a4_pixels(iw, ih, page_size_pt, margin_pt, target_dpi)

    if out_w != iw or out_h != ih:
        pil_img = pil_img.resize((out_w, out_h), resample=Image.LANCZOS)

    # JPEG encode (mocno redukuje wagę dla zdjęć protokołu)
    buf = io.BytesIO()
    save_kwargs = {
        "format": "JPEG",
        "quality": max(1, min(95, int(jpeg_quality))),
        "optimize": PDF_JPEG_OPTIMIZE,
        "progressive": PDF_JPEG_PROGRESSIVE,
    }
    pil_img.save(buf, **save_kwargs)
    buf.seek(0)
    return buf, out_w, out_h


def _draw_prepared_jpeg_as_a4_page(
    c: canvas.Canvas,
    jpeg_buf: io.BytesIO,
    page_size_pt: Tuple[float, float],
    margin_pt: float,
) -> None:
    """
    Rysuje przygotowany (już skompresowany) JPEG na stronie A4,
    zachowując proporcje i centrowanie w obszarze z marginesami.
    """
    page_w, page_h = page_size_pt
    max_w = page_w - 2 * margin_pt
    max_h = page_h - 2 * margin_pt

    # ImageReader potrafi czytać file-like
    img_reader = ImageReader(jpeg_buf)
    iw, ih = img_reader.getSize()
    if iw <= 0 or ih <= 0:
        raise HTTPException(status_code=400, detail="Nie udało się odczytać rozmiaru obrazu po konwersji.")

    scale = min(max_w / iw, max_h / ih)
    draw_w = iw * scale
    draw_h = ih * scale

    x = (page_w - draw_w) / 2.0
    y = (page_h - draw_h) / 2.0

    c.drawImage(img_reader, x, y, width=draw_w, height=draw_h, mask=None)


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

    Optymalizacja:
    - downsampling do A4@PDF_TARGET_DPI
    - JPEG re-encode z PDF_JPEG_QUALITY
    """
    if not images:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Brak plików obrazów do konwersji.",
        )

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

            # przygotuj “jak konwerter”: resize + jpeg
            jpeg_buf, _, _ = _prepare_image_for_pdf(
                pil_img=pil_img,
                page_size_pt=A4,
                margin_pt=PDF_MARGIN_PT,
                target_dpi=PDF_TARGET_DPI,
                jpeg_quality=PDF_JPEG_QUALITY,
            )

            _draw_prepared_jpeg_as_a4_page(
                c=c,
                jpeg_buf=jpeg_buf,
                page_size_pt=A4,
                margin_pt=PDF_MARGIN_PT,
            )
            c.showPage()

            # domknięcie zasobów
            try:
                pil_img.close()
            except Exception:
                pass
            try:
                jpeg_buf.close()
            except Exception:
                pass

        c.save()
        out.seek(0)

        filename = "protocol_images.pdf"
        headers = {"Content-Disposition": f'inline; filename="{filename}"'}

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
