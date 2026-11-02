"""Zrzuty klatek Mentora - obraz (Pillow): przygotowanie wgranej klatki i PNG z wypalonymi zaznaczeniami.

Współrzędne zaznaczeń są względem kadru (0..1), więc ten sam rysunek wygląda tak samo na każdym rozmiarze obrazu.
Grubość linii to ułamek SZEROKOŚCI obrazu (z dolnym progiem w pikselach), tekst to ułamek WYSOKOŚCI.
Każda linia ma ciemną obwódkę, żeby było ją widać i na jasnej murawie, i na ciemnej hali. Kontrakt: `docs/mentor-panel.md` 13.
"""

from __future__ import annotations

import io
import math
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app import mentor_shot_rules as SR
from app.mentor_panel_rules import RuleError

FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
FONT_TEXT = os.path.join(FONT_DIR, "NotoSans-Regular.ttf")
FONT_BANNER = os.path.join(FONT_DIR, "BarlowCondensed-Bold.ttf")
SUPERSAMPLE_MAX_PIXELS = 2_600_000
MIN_STROKE_PX = 2.0
HALO = (0, 0, 0, 150)


def _font(path: str, size: int):
    from PIL import ImageFont

    try:
        return ImageFont.truetype(path, max(8, int(size)))
    except OSError:
        try:
            return ImageFont.load_default(max(8, int(size)))
        except TypeError:  # stara Pillow bez rozmiaru domyślnej czcionki
            return ImageFont.load_default()


def _rgb(color: str) -> Tuple[int, int, int]:
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


# ─── Wgrany obraz ───────────────────────────────────────────────────────────


def prepare_stored(data: bytes) -> Dict[str, Any]:
    """Wgrany albo wycięty obraz -> JPEG do magazynu + miniatura. Kontrola wymiarów i pełne zdekodowanie (uszkodzony plik = 422).

    Wynik: `{jpeg, thumb, width, height}`. Metadane (EXIF) znikają, orientacja jest uwzględniona."""
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = SR.MAX_IMAGE_SIDE * SR.MAX_IMAGE_SIDE * 2
    try:
        with Image.open(io.BytesIO(data)) as probe:
            width, height = probe.size
        if min(width, height) < SR.MIN_IMAGE_SIDE:
            raise RuleError(422, "SHOT_IMAGE_SMALL", f"Obraz jest za mały (najmniejszy bok {SR.MIN_IMAGE_SIDE} px).")
        if max(width, height) > SR.MAX_IMAGE_SIDE:
            raise RuleError(422, "SHOT_IMAGE_DIMENSIONS", f"Obraz jest za duży (największy bok {SR.MAX_IMAGE_SIDE} px).")
        image = Image.open(io.BytesIO(data))
        image.load()
    except RuleError:
        raise
    except Exception as exc:  # noqa: BLE001 - uszkodzony albo podszyty plik
        raise RuleError(422, "SHOT_IMAGE_CORRUPT", "Nie udało się odczytać obrazu. Plik jest uszkodzony.") from exc
    image = ImageOps.exif_transpose(image).convert("RGB")
    if max(image.size) > SR.STORED_MAX_SIDE:
        image.thumbnail((SR.STORED_MAX_SIDE, SR.STORED_MAX_SIDE), Image.LANCZOS)
    out = io.BytesIO()
    image.save(out, "JPEG", quality=90, optimize=True)
    thumb = image.copy()
    thumb.thumbnail((SR.THUMB_SIDE, SR.THUMB_SIDE), Image.LANCZOS)
    thumb_out = io.BytesIO()
    thumb.save(thumb_out, "JPEG", quality=80, optimize=True)
    return {"jpeg": out.getvalue(), "thumb": thumb_out.getvalue(), "width": image.size[0], "height": image.size[1]}


# ─── Rysowanie ──────────────────────────────────────────────────────────────


def _stroke(shape: Dict[str, Any], width: int, scale: float) -> float:
    return max(MIN_STROKE_PX * scale, float(shape.get("width") or SR.DEFAULT_WIDTH) * width * scale)


def _arrow_polygon(x1: float, y1: float, x2: float, y2: float, stroke: float, head: float) -> List[Tuple[float, float]]:
    angle = math.atan2(y2 - y1, x2 - x1)
    spread = math.radians(26)
    left = (x2 - head * math.cos(angle - spread), y2 - head * math.sin(angle - spread))
    right = (x2 - head * math.cos(angle + spread), y2 - head * math.sin(angle + spread))
    return [(x2, y2), left, right]


def _line_with_halo(draw, points: Sequence[Tuple[float, float]], color, stroke: float, halo_extra: float) -> None:
    flat = [(float(x), float(y)) for x, y in points]
    draw.line(flat, fill=HALO, width=int(round(stroke + halo_extra)), joint="curve")
    draw.line(flat, fill=color, width=max(1, int(round(stroke))), joint="curve")
    r_halo, r = (stroke + halo_extra) / 2, stroke / 2
    for x, y in (flat[0], flat[-1]):
        draw.ellipse((x - r_halo, y - r_halo, x + r_halo, y + r_halo), fill=HALO)
        draw.ellipse((x - r, y - r, x + r, y + r), fill=color)


def _draw_overlay(size: Tuple[int, int], shapes: Sequence[Dict[str, Any]], scale: float):
    """Warstwa RGBA ze wszystkimi liniami (bez reflektora i lupy), w skali `scale` względem obrazu."""
    from PIL import Image, ImageDraw

    width, height = size
    layer = Image.new("RGBA", (int(width * scale), int(height * scale)), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    W, H = width * scale, height * scale
    for shape in shapes:
        kind = shape["type"]
        color = _rgb(shape["color"]) + (255,)
        stroke = _stroke(shape, width, scale)
        halo = max(2.0 * scale, stroke * 0.7)
        if kind == "ellipse":
            box = ((shape["cx"] - shape["rx"]) * W, (shape["cy"] - shape["ry"]) * H, (shape["cx"] + shape["rx"]) * W, (shape["cy"] + shape["ry"]) * H)
            draw.ellipse(box, outline=HALO, width=int(round(stroke + halo)))
            draw.ellipse(box, outline=color, width=max(1, int(round(stroke))))
        elif kind == "free":
            _line_with_halo(draw, [(x * W, y * H) for x, y in shape["points"]], color, stroke, halo)
        elif kind == "arrow":
            x1, y1, x2, y2 = shape["x1"] * W, shape["y1"] * H, shape["x2"] * W, shape["y2"] * H
            head = max(stroke * 4.2, 0.035 * W)
            length = math.hypot(x2 - x1, y2 - y1)
            back = min(head * 0.8, length * 0.9)
            angle = math.atan2(y2 - y1, x2 - x1)
            bx, by = x2 - back * math.cos(angle), y2 - back * math.sin(angle)
            _line_with_halo(draw, [(x1, y1), (bx, by)], color, stroke, halo)
            tri = _arrow_polygon(x1, y1, x2, y2, stroke, min(head, length))
            draw.polygon(tri, fill=color, outline=HALO, width=max(1, int(halo / 2)))
            draw.polygon(tri, fill=color)
        elif kind == "text":
            text = " ".join(str(shape["text"]).split())
            px = max(14.0 * scale, shape["size"] * H)
            font = _font(FONT_TEXT, px)
            outline = max(1, int(round(px / 11)))
            left, top, right, bottom = draw.textbbox((0, 0), text, font=font, stroke_width=outline)
            x = min(max(shape["x"] * W, 4 * scale), max(4 * scale, W - (right - left) - 4 * scale))
            y = min(max(shape["y"] * H, 4 * scale), max(4 * scale, H - (bottom - top) - 4 * scale))
            draw.text((x - left, y - top), text, font=font, fill=color, stroke_width=outline, stroke_fill=(0, 0, 0, 235))
    return layer


def _apply_spotlight(image, shape: Dict[str, Any]):
    from PIL import Image, ImageDraw, ImageFilter

    W, H = image.size
    ss = 2
    mask = Image.new("L", (W * ss, H * ss), int(255 * shape["dim"]))
    box = ((shape["cx"] - shape["rx"]) * W * ss, (shape["cy"] - shape["ry"]) * H * ss, (shape["cx"] + shape["rx"]) * W * ss, (shape["cy"] + shape["ry"]) * H * ss)
    ImageDraw.Draw(mask).ellipse(box, fill=0)
    mask = mask.resize((W, H), Image.LANCZOS).filter(ImageFilter.GaussianBlur(max(0.6, W / 900)))
    dark = Image.new("RGB", (W, H), (0, 0, 0))
    return Image.composite(dark, image, mask)


def _apply_loupe(image, shape: Dict[str, Any], source):
    from PIL import Image, ImageDraw

    W, H = image.size
    radius = max(12.0, shape["r"] * W)
    zoom = shape["zoom"]
    half = max(4.0, radius / zoom)
    cx, cy = shape["cx"] * W, shape["cy"] * H
    left = min(max(cx - half, 0), max(0, W - 2 * half))
    top = min(max(cy - half, 0), max(0, H - 2 * half))
    crop = source.crop((int(left), int(top), int(min(W, left + 2 * half)), int(min(H, top + 2 * half))))
    diameter = int(round(radius * 2))
    big = crop.resize((diameter, diameter), Image.LANCZOS)
    ss = 4
    mask = Image.new("L", (diameter * ss, diameter * ss), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, diameter * ss - 1, diameter * ss - 1), fill=255)
    mask = mask.resize((diameter, diameter), Image.LANCZOS)
    image.paste(big, (int(round(cx - radius)), int(round(cy - radius))), mask)
    # Obwódka lupy rysujemy razem z resztą linii (kolor i grubość kształtu) w `render_png`.


def _banner(image, lines: Sequence[str]):
    from PIL import Image, ImageDraw

    W, H = image.size
    bar = max(40, int(round(H * 0.06)))
    canvas = Image.new("RGB", (W, H + bar), (17, 20, 24))
    canvas.paste(image, (0, 0))
    text = "   |   ".join(lines)
    size = int(bar * 0.62)
    font = _font(FONT_BANNER, size)
    draw = ImageDraw.Draw(canvas)
    while size > 10 and draw.textlength(text, font=font) > W - 24:
        size -= 2
        font = _font(FONT_BANNER, size)
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    draw.text((12 - left, H + (bar - (bottom - top)) / 2 - top), text, font=font, fill=(245, 247, 250))
    return canvas


def render_png(image_bytes: bytes, shapes: Sequence[Dict[str, Any]], banner: Optional[Sequence[str]] = None) -> bytes:
    """Obraz zrzutu + kształty -> PNG. `banner` (lista fragmentów) dokleja pasek pod obrazem (nie zakrywa kadru)."""
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = SR.MAX_IMAGE_SIDE * SR.MAX_IMAGE_SIDE * 2
    image = Image.open(io.BytesIO(image_bytes))
    image.load()
    image = image.convert("RGB")
    original = image.copy()
    spotlight = next((s for s in shapes if s["type"] == "spotlight"), None)
    if spotlight:
        image = _apply_spotlight(image, spotlight)
    loupes = [s for s in shapes if s["type"] == "loupe"]
    for loupe in loupes:
        _apply_loupe(image, loupe, original)
    lines = [s for s in shapes if s["type"] != "spotlight" and s["type"] != "loupe"]
    rims = [{"type": "ellipse", "color": s["color"], "width": s["width"], "cx": s["cx"], "cy": s["cy"],
             "rx": s["r"], "ry": s["r"] * image.size[0] / image.size[1]} for s in loupes]
    # Obwódka lupy i obwódka reflektora (ten sam kolor i grubość co kształt).
    if spotlight:
        rims.append({"type": "ellipse", "color": spotlight["color"], "width": spotlight["width"], "cx": spotlight["cx"], "cy": spotlight["cy"],
                     "rx": spotlight["rx"], "ry": spotlight["ry"]})
    drawable = [*rims, *lines]
    if drawable:
        W, H = image.size
        scale = 2.0 if W * H <= SUPERSAMPLE_MAX_PIXELS else 1.0
        layer = _draw_overlay((W, H), drawable, scale)
        if scale != 1.0:
            layer = layer.resize((W, H), Image.LANCZOS)
        image = Image.alpha_composite(image.convert("RGBA"), layer).convert("RGB")
    if banner:
        image = _banner(image, banner)
    out = io.BytesIO()
    image.save(out, "PNG")
    return out.getvalue()
