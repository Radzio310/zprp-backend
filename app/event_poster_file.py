"""Plakat i grafika z kodem obecności - plik do pobrania na telefon.

Decyzja z 17.09.2026: „samo Pobierz na telefon, pobierające jak protokół PDF,
bezpośrednio zapisujące samo co trzeba i gdzie trzeba". Telefon robi zrzut
(PNG w pikselach druku, `EventPoster.tsx`), serwer oddaje go pod adresem
z `Content-Disposition: attachment`, więc systemowe pobieranie zapisuje plik
w Pobranych bez pytania o folder - dokładnie jak protokół.

Co wraca:
  - plakat A4 / A5 - PDF w dokładnym rozmiarze kartki; obraz wchodzi
    BEZSTRATNIE (FlateDecode, 300 dpi), bo kod QR z wydruku ma czytać aparat
    z kilku metrów i artefakty JPEG by mu w tym przeszkadzały,
  - grafika 1:1 / 9:16 - ten sam PNG, tylko sprawdzony.

Liść: Pillow i zlib, bez bazy danych (pamięć `app-db-laczy-sie-przy-imporcie`).
"""

from __future__ import annotations

import io
import re
import zlib
from typing import Tuple

from PIL import Image

#: Piksele zrzutu - lustro `POSTER_PX` z `utils/eventPosterExport.ts`.
POSTER_PX = {
    "a4": (2480, 3508),
    "a5": (1748, 2480),
    "square": (2048, 2048),
    "story": (1440, 2560),
}
#: Kartka w milimetrach - tylko plakaty do druku.
PAGE_MM = {"a4": (210, 297), "a5": (148, 210)}

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
#: Tolerancja proporcji zrzutu (część telefonów zaokrąga bok o piksel).
ASPECT_TOLERANCE = 0.015

_DIACRITICS = str.maketrans("ąćęłńóśźż", "acelnoszz")


class PosterFileError(ValueError):
    """Plik, którego nie da się oddać - komunikat idzie wprost na ekran."""


def check_variant(value: object) -> str:
    variant = str(value or "").strip().lower()
    if variant not in POSTER_PX:
        raise PosterFileError("Nieznany format plakatu")
    return variant


def is_print(variant: str) -> bool:
    return variant in PAGE_MM


def read_poster(data: bytes, variant: str) -> Image.Image:
    """PNG z telefonu po sprawdzeniu: podpis, waga, wymiary pasujące do formatu."""
    if not data:
        raise PosterFileError("Pusty plik")
    if len(data) > MAX_UPLOAD_BYTES:
        raise PosterFileError("Plik jest za duży")
    if not data.startswith(PNG_SIGNATURE):
        raise PosterFileError("To nie jest obraz PNG")
    try:
        image = Image.open(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 - każdy błąd dekodera to zły plik
        raise PosterFileError("Nie da się odczytać obrazu") from exc
    width, height = image.size
    want_w, want_h = POSTER_PX[variant]
    # Wymiary sprawdzane PRZED dekodowaniem pikseli - bomba dekompresyjna
    # nie ma prawa dojść do `convert`.
    if width > want_w + 4 or height > want_h + 4 or width < want_w // 3:
        raise PosterFileError("Obraz ma inny rozmiar niż wybrany format")
    if abs(width / height - want_w / want_h) > ASPECT_TOLERANCE * (want_w / want_h):
        raise PosterFileError("Obraz ma inne proporcje niż wybrany format")
    return image


def _flatten(image: Image.Image) -> Image.Image:
    """RGB na białym papierze - przezroczystość w PDF-ie drukowałaby się czarno."""
    if image.mode == "RGB":
        return image
    rgba = image.convert("RGBA")
    paper = Image.new("RGB", rgba.size, (255, 255, 255))
    paper.paste(rgba, mask=rgba.getchannel("A"))
    return paper


def _points(mm: float) -> str:
    return f"{mm / 25.4 * 72:.2f}"


def pdf_from_image(image: Image.Image, variant: str) -> bytes:
    """Jednostronicowy PDF: obraz na całą kartkę A4/A5, bez marginesów."""
    rgb = _flatten(image)
    width, height = rgb.size
    page_w, page_h = (_points(mm) for mm in PAGE_MM[variant])
    pixels = zlib.compress(rgb.tobytes(), 6)
    content = f"q {page_w} 0 0 {page_h} 0 0 cm /Im0 Do Q".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w} {page_h}] "
            "/Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>"
        ).encode("ascii"),
        (
            f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {len(pixels)} >>\nstream\n"
        ).encode("ascii")
        + pixels
        + b"\nendstream",
        f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{number} 0 obj\n".encode("ascii"))
        out.write(body)
        out.write(b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets:
        out.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return out.getvalue()


def build_download(data: bytes, variant: str) -> Tuple[bytes, str]:
    """(treść, rozszerzenie) - PDF dla plakatów, sprawdzony PNG dla grafik."""
    image = read_poster(data, variant)
    try:
        if not is_print(variant):
            # Grafika idzie dalej bez przepisywania - wystarczą całe fragmenty PNG.
            Image.open(io.BytesIO(data)).verify()
            return data, "png"
        return pdf_from_image(image, variant), "pdf"
    except PosterFileError:
        raise
    except Exception as exc:  # noqa: BLE001 - uszkodzone piksele wychodzą dopiero tu
        raise PosterFileError("Nie da się odczytać obrazu") from exc


def download_name(raw: object, ext: str) -> str:
    """Nazwa w Pobranych: same małe litery ASCII, cyfry i dywizy + rozszerzenie."""
    stem = str(raw or "").strip().lower()
    stem = re.sub(r"\.(png|pdf)$", "", stem).translate(_DIACRITICS)
    stem = re.sub(r"[^a-z0-9]+", "-", stem).strip("-")[:90].rstrip("-")
    return f"{stem or 'baza-obecnosc'}.{ext}"
