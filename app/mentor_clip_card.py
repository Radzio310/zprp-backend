"""Plansza klipu „Pojedynek herbów” (decyzje właściciela 30-31.10.2026): Pillow + ruch w filtrach ffmpeg.

Plansza to także miniatura pliku w folderze, na Dysku i w Teczce, a nie wiemy, którą klatkę wezmą systemy. Dlatego:
  - kolejność czytania: nazwa klipu, kategoria, minuta, herby i numer; czytelne już przy szerokości 200 px,
  - klatka 0 jest kompletna: cały tekst leży na tle, rusza się tylko krótki dojazd herbów (widocznych od początku),
  - herb powiększamy najwyżej `MAX_CREST_ENLARGE` razy ponad jego prawdziwe piksele, nazwy drużyn stoją na stałej linii.
Pillow rysuje raz, ffmpeg dekoduje każdy PNG raz (filtr `loop`). Czyste: bez bazy i sieci.
"""

from __future__ import annotations

import colorsys
import io
import math
import os
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.mentor_clip_download_rules import CARD_FADE_S, CARD_SECONDS

FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
FONT_CLOCK = os.path.join(FONT_DIR, "BarlowCondensed-Bold.ttf")
FONT_LABEL = os.path.join(FONT_DIR, "BarlowCondensed-SemiBold.ttf")

FPS = 30
RGB = Tuple[int, int, int]
#: Koral Mentora: barwa drużyny bez herbu albo bez wyraźnego koloru w herbie.
MENTOR_CORAL: RGB = (255, 122, 89)
#: Paleta kategorii Mentora (nazwy z `mentor_panel_rules.PALETTE`), jasne wersje pod ciemne tło; jak `tokens.ts` w BAZA_web.
CATEGORY_INK: Dict[str, RGB] = {
    "emerald": (108, 199, 154), "rose": (236, 129, 131), "amber": (240, 182, 64), "sky": (127, 192, 228),
    "pink": (238, 92, 152), "violet": (180, 163, 232), "indigo": (147, 168, 238), "teal": (111, 208, 200),
    "lime": (181, 219, 110), "orange": (244, 162, 107), "cyan": (115, 205, 230), "slate": (179, 167, 146),
}
#: Bez tych słów inicjały mówią o klubie, a nie o jego formie prawnej.
_GENERIC_TOKENS = {"KS", "MKS", "UKS", "SPR", "KU", "MUKS", "LKS", "MTS", "HC", "KPR", "GKS", "TS", "SKS", "SMS", "ZKS", "KSS", "UKKS", "MLKS", "ULKS", "KKS", "RKS", "SSR"}
_MAX_CREST_PIXELS = 16_000_000
#: Herb ponad naturalny rozmiar najwyżej tyle razy: herby ZPRP to JPEG 50x50, a dwukrotność z LANCZOS jeszcze się nie rozmazuje.
MAX_CREST_ENLARGE = 2.0

# Dojazd herbów: krótki, z małego przesunięcia, herb jest widoczny od klatki 0. Goście ruszają chwilę później.
SLIDE_S = 0.5
AWAY_DELAY_S = 0.04
SLIDE_SHIFT = 0.035  # ułamek szerokości kadru


# ─── Barwy ──────────────────────────────────────────────────────────────────


def parse_color(value: Any) -> Optional[RGB]:
    """„#a1b2c3” albo krotka -> (r, g, b). Cokolwiek innego = brak barwy, nie wyjątek."""
    if isinstance(value, (tuple, list)) and len(value) == 3:
        return tuple(int(max(0, min(255, c))) for c in value)  # type: ignore[return-value]
    match = re.fullmatch(r"#?([0-9a-fA-F]{6})", str(value or "").strip())
    if not match:
        return None
    raw = match.group(1)
    return int(raw[:2], 16), int(raw[2:4], 16), int(raw[4:], 16)


def luminance(rgb: Sequence[float]) -> float:
    def channel(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2])


def contrast(a: Sequence[float], b: Sequence[float]) -> float:
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def _mix(a: Sequence[float], b: Sequence[float], t: float) -> RGB:
    return tuple(int(round(x + (y - x) * t)) for x, y in zip(a, b))  # type: ignore[return-value]


def team_tone(color: Optional[RGB], max_lum: float = 0.058) -> RGB:
    """Barwa pod tekstem: ten sam odcień, tak przyciemniony, by biel zawsze miała kontrast > 9:1.
    Żółć ciągniemy ku bursztynowi, bo przyciemniona czysta żółć wychodzi oliwkowa."""
    r, g, b = color or MENTOR_CORAL
    h, s, v = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
    if 0.10 < h < 0.19:
        h = 0.10 + (h - 0.10) * 0.25
    s = max(s, 0.74)
    v = max(v, 0.24)
    while True:
        rgb = tuple(c * 255.0 for c in colorsys.hsv_to_rgb(h, s, v))
        if luminance(rgb) <= max_lum or v <= 0.05:
            return tuple(int(round(c)) for c in rgb)  # type: ignore[return-value]
        v *= 0.97


def team_light(color: Optional[RGB]) -> RGB:
    """Jasna wersja barwy: światło za herbem, zastępcza tarcza, listwa."""
    r, g, b = color or MENTOR_CORAL
    h, s, _ = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
    rgb = colorsys.hsv_to_rgb(h, min(max(s, 0.5), 0.85), 0.95)
    return tuple(int(round(c * 255)) for c in rgb)  # type: ignore[return-value]


def category_ink(color: Any) -> RGB:
    """Kolor kategorii czytelny na ciemnym tle: nazwa z palety albo hex, zawsze co najmniej 4,5:1 do ciemnej planszy."""
    rgb = CATEGORY_INK.get(str(color or "").strip().lower()) or parse_color(color) or MENTOR_CORAL
    backdrop = (24, 26, 32)
    step = 0.0
    while contrast(_mix(rgb, (255, 255, 255), step), backdrop) < 4.5 and step < 1.0:
        step += 0.08
    return _mix(rgb, (255, 255, 255), min(step, 1.0))


# ─── Tekst ──────────────────────────────────────────────────────────────────


def initials(name: Any) -> str:
    """Inicjały klubu do zastępczej tarczy: bez form prawnych, numerów drużyn i lat („MTS II Żory” -> „Ż”, „AZS AWF Kraków” -> „AA”)."""
    tokens = [t for t in re.split(r"[\s\-./]+", str(name or "").strip()) if t]
    words = [t for t in tokens if re.search(r"[^\W\d_]", t) and not re.fullmatch(r"[IVX]+", t.upper())]
    core = [t for t in words if t.upper() not in _GENERIC_TOKENS]
    if core:
        return "".join(t[0] for t in core[:2]).upper()
    return words[0][:3].upper() if words else ""


def _ellipsize(draw: Any, text: str, font: Any, width: float) -> str:
    """Skraca do szerokości; gdy się da, na granicy słowa, bez urwanego „bra…”."""
    if draw.textlength(text, font=font) <= width:
        return text
    cut = text.rstrip(" .,")
    while cut and draw.textlength(cut.rstrip(" .,-") + "…", font=font) > width:
        cut = cut[:-1]
    whole = cut.rsplit(" ", 1)[0] if " " in cut else cut
    if whole != cut and draw.textlength(whole, font=font) >= width * 0.66:
        cut = whole
    return (cut.rstrip(" .,-") + "…") if cut else "…"


def wrap_lines(draw: Any, text: str, font: Any, width: float, max_lines: int) -> List[str]:
    """Zawija po słowach; zbyt długie słowo jest skracane. Dwa wiersze wyrównuje, żeby tytuł nie miał sieroty."""
    words, lines, line = str(text or "").split(), [], ""
    for word in words:
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=font) <= width:
            line = trial
            continue
        if line:
            lines.append(line)
        line = word if draw.textlength(word, font=font) <= width else _ellipsize(draw, word, font, width)
    if line:
        lines.append(line)
    if len(lines) > max_lines:
        rest = " ".join(lines[max_lines - 1:])
        lines = lines[:max_lines - 1] + [_ellipsize(draw, rest, font, width)]
    elif len(lines) == 2 and max_lines >= 2:
        all_words = " ".join(lines).split()
        best, score = lines, max(draw.textlength(x, font=font) for x in lines)
        for cut in range(1, len(all_words)):
            a, b = " ".join(all_words[:cut]), " ".join(all_words[cut:])
            top = max(draw.textlength(a, font=font), draw.textlength(b, font=font))
            if top < score:
                best, score = [a, b], top
        lines = best
    return lines


def _tracked_width(draw: Any, text: str, font: Any, tracking: float) -> float:
    return draw.textlength(text, font=font) + tracking * max(0, len(text) - 1)


def _ellipsize_tracked(draw: Any, text: str, font: Any, tracking: float, width: float) -> str:
    if _tracked_width(draw, text, font, tracking) <= width:
        return text
    cut = text
    while cut and _tracked_width(draw, cut.rstrip(" .,-") + "…", font, tracking) > width:
        cut = cut[:-1]
    whole = cut.rsplit(" ", 1)[0] if " " in cut else cut
    if whole != cut and _tracked_width(draw, whole, font, tracking) >= width * 0.66:
        cut = whole
    return cut.rstrip(" .,-") + "…"


def _draw_tracked(draw: Any, x: float, baseline: float, text: str, font: Any, fill: Any, tracking: float) -> None:
    for i, ch in enumerate(text):
        draw.text((x + draw.textlength(text[:i], font=font) + tracking * i, baseline), ch, font=font, fill=fill, anchor="ls")


def _fit_font(draw: Any, path: str, text: str, start: int, smallest: int, width: float) -> Any:
    from PIL import ImageFont

    size = start
    while size > smallest:
        font = ImageFont.truetype(path, size)
        if draw.textlength(text, font=font) <= width:
            return font
        size -= max(1, size // 24)
    return ImageFont.truetype(path, smallest)


# ─── Herb ───────────────────────────────────────────────────────────────────


def normalize_crest(data: bytes, limit: int = 512) -> Optional[bytes]:
    """Dekoduje herb raz (SVG, uszkodzony plik albo bomba pikseli = None), mniejszy niż `limit`, jako PNG do pamięci podręcznej."""
    from PIL import Image

    try:
        image = Image.open(io.BytesIO(data))
        if image.width * image.height > _MAX_CREST_PIXELS or image.width < 8 or image.height < 8:
            return None
        image = image.convert("RGBA")
        image.thumbnail((limit, limit))
        out = io.BytesIO()
        image.save(out, "PNG", compress_level=1)
        return out.getvalue()
    except Exception:  # noqa: BLE001 - zły herb to zastępcza tarcza, nie błąd planszy
        return None


def dominant_color(data: bytes) -> Optional[str]:
    """Dominująca barwa herbu jako „#rrggbb” albo None. Piksele grupowane po odcieniu; biel, czerń, szarości i pastelowe piksele
    krawędzi (zmieszane z białym tłem JPEG-a) odpadają, a z grupy bierzemy medianę środkowej połowy nasycenia."""
    from PIL import Image

    try:
        image = Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception:  # noqa: BLE001
        return None
    image.thumbnail((64, 64))
    groups: Dict[int, List[Tuple[float, RGB]]] = {}
    for r, g, b, a in image.getdata():
        if a < 200:
            continue
        h, s, v = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
        if s < 0.35 or v < 0.16:
            continue
        groups.setdefault(int(h * 24) % 24, []).append((s, (r, g, b)))
    if not groups:
        return None
    best = sorted(max(groups.values(), key=len), key=lambda item: item[0])
    r, g, b = best[len(best) // 2][1]
    return f"#{r:02x}{g:02x}{b:02x}"


def _resized(image: Any, factor: float) -> Any:
    """LANCZOS na alfie premultiplikowanej: przezroczyste piksele nie brudzą krawędzi."""
    from PIL import Image

    size = (max(1, int(round(image.width * factor))), max(1, int(round(image.height * factor))))
    return image if size == image.size else image.convert("RGBa").resize(size, Image.LANCZOS).convert("RGBA")


def _white_matte(image: Any) -> Any:
    """Herb bez przezroczystości (JPEG na białym): alfa z bieli połączonej z brzegiem. Białe wnętrze herbu zostaje.
    Zwraca maskę L albo None, gdy tło nie jest białe lub wycięcie zjadłoby prawie cały znak."""
    from PIL import ImageChops, ImageDraw

    rgb = image.convert("RGB")
    w, h = rgb.size
    darkest = ImageChops.darker(ImageChops.darker(rgb.getchannel("R"), rgb.getchannel("G")), rgb.getchannel("B"))
    near_white = darkest.point(lambda v: 255 if v >= 222 else 0)
    seeds = [(x, y) for x in range(0, w, max(1, w // 12)) for y in (0, h - 1)] + [(x, y) for y in range(0, h, max(1, h // 12)) for x in (0, w - 1)]
    white_edge = sum(1 for p in seeds if near_white.getpixel(p) == 255)
    if white_edge < len(seeds) * 0.55:
        return None
    flood = near_white.copy()
    for seed in seeds:
        if flood.getpixel(seed) == 255:
            ImageDraw.floodfill(flood, seed, 128, thresh=0)
    mask = flood.point(lambda v: 0 if v == 128 else 255)
    kept = sum(mask.histogram()[128:]) / float(w * h)
    return mask if kept >= 0.08 else None


def prepare_crest(data: bytes, box: int) -> Optional[Any]:
    """RGBA herbu w kwadracie `box`: wycięte tło, przycięte puste brzegi, gładko powiększony."""
    from PIL import Image, ImageDraw, ImageFilter

    try:
        image = Image.open(io.BytesIO(data))
        if image.width * image.height > _MAX_CREST_PIXELS:
            return None
        image = image.convert("RGBA")
    except Exception:  # noqa: BLE001
        return None
    opaque = image.getchannel("A").getextrema()[0] > 240
    image.thumbnail((640, 640))
    # Rozmiar wynika z pikseli źródła: duży, ostry herb wypełnia skrzynkę, mały zostaje mały i ostry.
    factor = min(MAX_CREST_ENLARGE, box / float(max(image.size)))
    mask = None
    if opaque:
        # Maska liczona na obrazie powiększonym: krawędź wychodzi z gładkiego przejścia, nie ze schodków 50 px.
        side = max(image.size)
        grow = max(1.0, 240.0 / side)
        working = image.resize((int(image.width * grow), int(image.height * grow)), Image.BICUBIC) if grow > 1 else image
        if max(working.size) > 320:
            working = working.resize((320, max(1, 320 * working.height // working.width)))
        mask = _white_matte(working)
    big = _resized(image, factor)
    if mask is not None:
        # Rozmycie + stroma krzywa = gładki obrys; maska ściągnięta o włos, bez białej obwódki na ciemnym tle.
        soft = mask.resize(big.size, Image.BICUBIC).filter(ImageFilter.GaussianBlur(max(0.7, big.width / 110.0)))
        big.putalpha(soft.point(lambda v: max(0, min(255, int((v - 148) * 6.0)))))
    elif opaque:
        # Kolorowe tło herbu: zaokrąglony kafel zamiast ostrego prostokąta.
        rounded = Image.new("L", (big.width * 3, big.height * 3), 0)
        ImageDraw.Draw(rounded).rounded_rectangle([0, 0, rounded.width - 1, rounded.height - 1], radius=rounded.width // 7, fill=255)
        big.putalpha(rounded.resize(big.size, Image.LANCZOS))
    bbox = big.getchannel("A").point(lambda v: 255 if v > 16 else 0).getbbox()
    return big.crop(bbox) if bbox else None


def _shield_points(w: float, h: float, inset: float = 0.0) -> List[Tuple[float, float]]:
    """Obrys tarczy: płaska góra z lekkim łukiem, boki zbiegają do szpica."""
    left, right, top, bottom = inset, w - inset, inset, h - inset
    mid = w / 2.0
    pts: List[Tuple[float, float]] = []
    for i in range(25):  # górny łuk
        t = i / 24.0
        pts.append((left + (right - left) * t, top + (h * 0.035) * abs(2 * t - 1) ** 2))
    for i in range(1, 41):  # prawy bok: Bézier kwadratowy z punktem kontrolnym nisko przy boku
        t = i / 40.0
        cx, cy = right, top + (bottom - top) * 0.78
        x = (1 - t) ** 2 * right + 2 * (1 - t) * t * cx + t ** 2 * mid
        y = (1 - t) ** 2 * (top + h * 0.035) + 2 * (1 - t) * t * cy + t ** 2 * bottom
        pts.append((x, y))
    for x, y in reversed(pts[25:-1]):  # lewy bok jako lustro
        pts.append((w - x, y))
    return pts


def _paint_ball(draw: Any, cx: float, cy: float, radius: float) -> None:
    """Znak bez nazwy drużyny: piłka (obwód, środkowy pięciokąt, szwy do obwodu)."""
    ink = (255, 255, 255, 235)
    stroke = max(2, int(radius * 0.10))
    draw.ellipse([cx - radius, cy - radius, cx + radius, cy + radius], outline=ink, width=stroke)
    inner, points = radius * 0.40, []
    for i in range(5):
        angle = math.radians(-90 + 72 * i)
        corner = (cx + inner * math.cos(angle), cy + inner * math.sin(angle))
        points.append(corner)
        draw.line([corner, (cx + radius * math.cos(angle), cy + radius * math.sin(angle))], fill=ink, width=stroke)
    draw.polygon(points, fill=ink)


def shield_crest(name: Any, color: Optional[RGB], box: int) -> Any:
    """Zastępczy znak: tarcza w barwie drużyny z inicjałami. Bez nazwy: sama tarcza z pasem."""
    from PIL import Image, ImageDraw, ImageFont

    k = 3
    w, h = int(box * 0.86) * k, box * k
    light, deep = team_light(color), team_tone(color, 0.03)
    shield = Image.new("L", (w, h), 0)
    ImageDraw.Draw(shield).polygon(_shield_points(w, h), fill=255)
    inner = Image.new("L", (w, h), 0)
    ImageDraw.Draw(inner).polygon(_shield_points(w, h, inset=h * 0.038), fill=255)
    fill = Image.new("RGB", (w, h))
    rows = ImageDraw.Draw(fill)
    upper = _mix(deep, light, 0.42)
    for y in range(h):
        rows.line([(0, y), (w, y)], fill=_mix(upper, deep, min(1.0, y / (h * 0.9))))
    rim = _mix(light, (255, 255, 255), 0.45)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(Image.new("RGB", (w, h), rim), (0, 0), shield)
    out.paste(fill, (0, 0), inner)
    draw = ImageDraw.Draw(out)
    letters = initials(name)
    if letters:
        size = int(h * (0.46 if len(letters) <= 2 else 0.34))
        font = ImageFont.truetype(FONT_CLOCK, size)
        while draw.textlength(letters, font=font) > w * 0.70 and size > 12:
            size -= 4
            font = ImageFont.truetype(FONT_CLOCK, size)
        draw.text((w / 2, h * 0.46), letters, font=font, fill=(255, 255, 255, 245), anchor="mm")
    else:
        _paint_ball(draw, w / 2.0, h * 0.45, h * 0.20)
    return out.resize((w // k, h // k), Image.LANCZOS)


# ─── Tło ────────────────────────────────────────────────────────────────────


def render_background(width: int, height: int, home: Optional[RGB], away: Optional[RGB], lights: Sequence[Tuple[float, float, float]]) -> Any:
    """Gradient z barw obu drużyn (lewa gospodarz, prawa gość), przyciemniony środek pod minutę, miękkie światło za herbami
    (gradient, nie plama), winieta i drobny szum jednobarwny: bez niego H.264 tnie ciemny gradient na pasma."""
    import numpy as np
    from PIL import Image

    # Gradient jest gładki: liczymy go w 1/4 rozdzielczości na liczbach zmiennoprzecinkowych, pełny rozmiar dostaje tylko szum.
    small_w, small_h = max(16, width // 4), max(16, height // 4)
    y, x = np.mgrid[0:small_h, 0:small_w].astype("float32")
    x /= small_w - 1
    y /= small_h - 1
    tone_a = np.array(team_tone(home), dtype="float32")
    tone_b = np.array(team_tone(away), dtype="float32")
    t = np.clip((x + 0.07 * (y - 0.5) - 0.20) / 0.60, 0.0, 1.0)
    t = t * t * (3.0 - 2.0 * t)
    image = tone_a[None, None, :] * (1.0 - t[..., None]) + tone_b[None, None, :] * t[..., None]
    image += 7.0  # podłoga: czarne piksele nie dają w YUV ani szumu, ani przejścia
    image *= (1.0 - 0.58 * np.exp(-(((x - 0.5) / 0.21) ** 2)))[..., None]
    side = float(min(width, height))
    colors = (team_light(home), team_light(away))
    for (cx, cy, radius), glow in zip(lights, colors):
        dist = ((x * (width - 1) - cx) ** 2 + (y * (height - 1) - cy) ** 2) / (2.0 * (radius * side) ** 2)
        image += np.exp(-dist)[..., None] * np.array(glow, dtype="float32")[None, None, :] * 0.115
    falloff = 1.0 - 0.34 * np.clip((y - 0.52) / 0.48, 0.0, 1.0) ** 1.4
    radial = np.clip(np.sqrt(((x - 0.5) / 0.74) ** 2 + ((y - 0.5) / 0.74) ** 2), 0.0, 1.0)
    image *= (falloff * (1.0 - 0.52 * radial ** 2.6))[..., None]
    # Wspólny szum to jasność; osobny na kanał rozbija też pasma barwy, które przy ciemnych tonach robi 4:2:0.
    rng = np.random.default_rng(20261030)
    grain = 1.25 * rng.standard_normal((height, width), dtype="float32")
    channels = []
    for c in range(3):
        full = np.asarray(Image.fromarray(image[..., c], "F").resize((width, height), Image.BICUBIC))
        tint = 0.9 * rng.standard_normal((height, width), dtype="float32")
        channels.append(np.clip(full + grain + tint + 0.5, 0, 255).astype("uint8"))
    del image, grain, tint
    return Image.fromarray(np.dstack(channels), "RGB")


# ─── Układ i warstwy ────────────────────────────────────────────────────────


def card_data(lines: Sequence[Any], details: Optional[Mapping[str, Any]] = None, crests: Optional[Mapping[str, Any]] = None,
              crest_colors: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Komplet treści planszy z `card_lines` (mecz, minuta, tytuł, kategoria), pól dodatkowych, herbów i ich barw."""
    match, clock, title, category = (list(lines) + ["", "", "", ""])[:4]
    info = dict(details or {})
    return {"match": str(match or ""), "clock": str(clock or "").replace("m", ":"), "title": str(title or ""), "category": str(category or ""),
            "half": str(info.get("half") or ""), "competition": str(info.get("competition") or ""), "date": str(info.get("date") or ""),
            "code": str(info.get("code") or ""), "code_color": info.get("code_color"), "home": str(info.get("home") or ""), "away": str(info.get("away") or ""),
            "category_color": info.get("category_color"), "crests": dict(crests or {}), "crest_colors": dict(crest_colors or {})}


def _font(path: str, size: float) -> Any:
    from PIL import ImageFont

    return ImageFont.truetype(path, max(9, int(size)))


def _shadow(layer: Any, radius: float, offset: int, strength: float) -> Any:
    from PIL import Image, ImageFilter

    alpha = layer.getchannel("A").filter(ImageFilter.GaussianBlur(radius)).point(lambda v: int(v * strength))
    shade = Image.new("RGBA", layer.size, (0, 0, 0, 0))
    shade.putalpha(alpha)
    out = Image.new("RGBA", layer.size, (0, 0, 0, 0))
    out.alpha_composite(shade, (0, min(offset, layer.height - 1)))
    out.alpha_composite(layer)
    return out


def _crest_with_light(crest: Any, u: float) -> Tuple[Any, int]:
    """Herb z cieniem i delikatną poświatą krawędzi: ciemny herb nie ginie na ciemnym tle. Zwraca (warstwa, margines)."""
    from PIL import Image, ImageChops, ImageFilter

    pad = int(max(6, 16 * u))
    canvas = Image.new("RGBA", (crest.width + 2 * pad, crest.height + 2 * pad), (0, 0, 0, 0))
    canvas.alpha_composite(crest, (pad, pad))
    alpha = canvas.getchannel("A")
    visible = crest.convert("RGB").resize((24, 24))
    weights = crest.getchannel("A").resize((24, 24))
    dark, total = 0, 0
    for px, a in zip(visible.getdata(), weights.getdata()):
        if a > 100:
            total += 1
            dark += 1 if luminance(px) < 0.06 else 0
    rim_strength = 0.46 if total and dark / total > 0.45 else 0.18
    rim = alpha.filter(ImageFilter.GaussianBlur(max(1.5, 4 * u))).point(lambda v: int(v * rim_strength))
    glow = Image.new("RGBA", canvas.size, (255, 255, 255, 0))
    glow.putalpha(rim)
    shade_alpha = alpha.filter(ImageFilter.GaussianBlur(max(2.0, 7 * u))).point(lambda v: int(v * 0.5))
    shade = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    shade.putalpha(ImageChops.offset(shade_alpha, 0, int(4 * u)))
    out = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    out.alpha_composite(shade)
    out.alpha_composite(glow)
    out.alpha_composite(canvas)
    return out, pad


def _title_fit(draw: Any, title: str, width: float, height: float, sizes: Sequence[Tuple[float, int]]) -> Tuple[Any, List[str]]:
    """Największy krój, w którym nazwa klipu mieści się bez skracania; ostatni zestaw skraca, jeśli musi."""
    font, rows = None, []
    for size, max_lines in sizes:
        font = _font(FONT_CLOCK, size)
        rows = wrap_lines(draw, title, font, width, max_lines)
        fits = font.size * 1.06 * len(rows) <= height
        if fits and not any(r.endswith("…") for r in rows):
            return font, rows
    return font, rows


def _tag(data_text: str, font: Any, fill: RGB, radius: int, pad_x: int, pad_y: int, cap: int, tracking: float, u: float) -> Any:
    """Kafelek: pełna barwa, napis o lepszym z dwóch kontrastów, miękka poświata w barwie kafelka (jak `MatchNumber.tsx`)."""
    from PIL import Image, ImageDraw, ImageFilter

    probe = ImageDraw.Draw(Image.new("L", (4, 4)))
    w = int(_tracked_width(probe, data_text, font, tracking)) + 2 * pad_x
    h = cap + 2 * pad_y
    glow = int(max(3, 9 * u))
    layer = Image.new("RGBA", (w + 2 * glow, h + 2 * glow), (0, 0, 0, 0))
    k = 3
    plate = Image.new("L", (w * k, h * k), 0)
    ImageDraw.Draw(plate).rounded_rectangle([0, 0, w * k - 1, h * k - 1], radius=radius * k, fill=255)
    plate = plate.resize((w, h), Image.LANCZOS)
    halo = Image.new("L", layer.size, 0)
    halo.paste(plate, (glow, glow))
    halo = halo.filter(ImageFilter.GaussianBlur(glow / 2)).point(lambda v: int(v * 0.42))
    layer.paste(Image.new("RGBA", layer.size, (*fill, 255)), (0, 0), halo)
    layer.paste(Image.new("RGBA", (w, h), (*fill, 255)), (glow, glow), plate)
    _draw_tracked(ImageDraw.Draw(layer), glow + pad_x, glow + pad_y + cap, data_text, font, (*on_color(fill), 255), tracking)
    return layer, glow


def on_color(fill: RGB) -> RGB:
    """Kolor napisu na barwnym kafelku: ciemny albo kremowy, ten o większym kontraście."""
    dark, light = (27, 18, 6), (255, 247, 238)
    return dark if contrast(fill, dark) >= contrast(fill, light) else light


def compose(data: Mapping[str, Any], width: int, height: int) -> Dict[str, Any]:
    """Układ: u góry drobno rozgrywki i data, potem nazwa klipu i kafelki, na dole pas pojedynku (herb, minuta, herb).
    Zwraca tło, warstwę tekstu (nieruchomą, od klatki 0) i dwie warstwy herbów."""
    from PIL import Image, ImageDraw

    landscape = width / max(1, height) >= 1.2
    u = min(width / 1280.0, height / 720.0) if landscape else width / 760.0
    colors = {side: parse_color((data.get("crest_colors") or {}).get(side)) for side in ("home", "away")}
    text = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(text)

    # Wysokości pasów: górna linia, pas pojedynku (skrzynka herbu i dwa wiersze nazwy), reszta dla nazwy klipu z kafelkami.
    box = int(132 * u)
    name_font = _font(FONT_LABEL, 29 * u)
    name_line = int(name_font.size * 1.08)
    band_h = box + int(10 * u) + 2 * name_line
    top_h = int(42 * u)
    tag_font = _font(FONT_CLOCK, 50 * u)
    tag_cap = int(tag_font.size * 0.70)
    tag_h = tag_cap + 2 * int(15 * u)
    sizes = ((116, 2), (102, 2), (88, 3), (76, 3), (66, 3)) if landscape else ((104, 3), (92, 4), (80, 4), (68, 5), (60, 5))
    zone = height - top_h - band_h - tag_h - int(92 * u)
    title_font, rows = _title_fit(draw, str(data.get("title") or ""), width * 0.92, zone, [(s * u, n) for s, n in sizes])
    title_line = title_font.size * 1.06
    title_h = title_line * len(rows)
    block_h = title_h + int(20 * u) + tag_h
    # Wysoki kadr: nadmiar idzie w odstępy, ale pasy nie odjeżdżają na krawędzie.
    extra = height - (top_h + block_h + band_h)
    gap = max(int(14 * u), min(extra / 4.0, 70 * u))
    margin = max(int(16 * u), (height - (top_h + block_h + band_h + 2 * gap)) / 2.0)

    # Rozgrywki i data: drobno.
    top_text = "   ·   ".join(p for p in (str(data.get("competition") or "").upper(), str(data.get("date") or "")) if p)
    if top_text:
        font = _font(FONT_LABEL, 25 * u)
        tracking = font.size * 0.12
        line = _ellipsize_tracked(draw, top_text, font, tracking, width * 0.90)
        _draw_tracked(draw, (width - _tracked_width(draw, line, font, tracking)) / 2, margin + font.size * 0.8, line, font, (255, 255, 255, 205), tracking)

    # Nazwa klipu: bohater, widoczny także na miniaturze.
    y = margin + top_h + gap
    ascent = title_font.size * 0.80
    for i, row in enumerate(rows):
        draw.text((width / 2, y + ascent + i * title_line), row, font=title_font, fill=(255, 255, 255, 255), anchor="ms")
    y += title_h + int(20 * u)

    # Kategoria (pigułka w swoim kolorze) i numer meczu (kafelek w kolorze ligi). Numeru nie zmieniamy: JmK to nie JMK.
    tracking = tag_font.size * 0.04
    pad_x, pad_y = int(24 * u), int(15 * u)
    category = str(data.get("category") or "").upper()
    code = str(data.get("code") or "")
    code_layer = _tag(code, tag_font, parse_color(data.get("code_color")) or (136, 136, 136), int(12 * u), int(18 * u), pad_y, tag_cap, 0.0, u) if code else None
    spacing = int(16 * u)
    room = width * 0.94 - (code_layer[0].width + spacing if code_layer else 0)
    cat_layer = None
    if category:
        label = _ellipsize_tracked(draw, category, tag_font, tracking, max(room - 2 * pad_x - 20 * u, tag_font.size * 2))
        cat_layer = _tag(label, tag_font, category_ink(data.get("category_color")), tag_h // 2, pad_x, pad_y, tag_cap, tracking, u)
    parts = [p for p in (cat_layer, code_layer) if p]
    total = sum(p[0].width - 2 * p[1] for p in parts) + spacing * (len(parts) - 1)
    x = (width - total) / 2.0
    for layer, glow in parts:
        text.alpha_composite(layer, (max(0, int(x) - glow), max(0, int(y) - glow)))
        x += layer.width - 2 * glow + spacing
    y += tag_h + gap

    # Pas pojedynku: osie herbów, nazwy na stałej linii, między nimi minuta.
    offset = min(width * 0.335, height * 0.70) if landscape else width * 0.33
    centers = (width / 2 - offset, width / 2 + offset)
    box_bottom = y + box
    name_y = box_bottom + int(10 * u) + name_font.getmetrics()[0]
    name_width = min(2 * (centers[0] - width * 0.025), offset * 0.90)  # nazwa nigdy nie dotyka krawędzi kadru
    layers: List[Dict[str, Any]] = []
    for side, cx in zip(("home", "away"), centers):
        raw = (data.get("crests") or {}).get(side)
        crest = prepare_crest(raw, box) if raw else None
        if crest is None:
            crest = shield_crest(data.get(side), colors.get(side), box)
        image, pad = _crest_with_light(crest, u)
        # Niski herb stoi na podstawie skrzynki: odstęp do nazwy jest zawsze ten sam.
        layers.append({"image": image, "x": int(cx - image.width / 2), "y": int(box_bottom - crest.height - pad), "motion": side})
        for i, row in enumerate(wrap_lines(draw, str(data.get(side) or "").upper(), name_font, name_width, 2)):
            draw.text((cx, name_y + i * name_line), row, font=name_font, fill=(255, 255, 255, 240), anchor="ms")

    clock = str(data.get("clock") or "")
    half = str(data.get("half") or "").upper()
    between = centers[1] - centers[0] - box - 24 * u
    clock_font = _fit_font(draw, FONT_CLOCK, clock or "0", int(112 * u), 14, between)
    clock_base = y + box * 0.66
    draw.text((width / 2, clock_base), clock, font=clock_font, fill=(255, 255, 255, 255), anchor="ms")
    if half:
        font = _font(FONT_LABEL, 27 * u)
        tracking = font.size * 0.16
        line = _ellipsize_tracked(draw, half, font, tracking, between)
        _draw_tracked(draw, (width - _tracked_width(draw, line, font, tracking)) / 2, clock_base + font.size * 1.25, line, font, (255, 255, 255, 225), tracking)

    text = _shadow(text, max(1.5, 5 * u), max(1, int(2 * u)), 0.5)
    lights = [(cx, y + box / 2.0, 0.27) for cx in centers]
    background = render_background(width, height, colors["home"], colors["away"], lights)
    return {"background": background, "text": text, "layers": layers, "unit": u}


def flatten(composition: Mapping[str, Any]) -> Any:
    """Stan po ustaniu ruchu jako jeden obraz."""
    frame = composition["background"].convert("RGBA")
    frame.alpha_composite(composition["text"])
    for layer in composition["layers"]:
        frame.alpha_composite(layer["image"].convert("RGBA"), (max(0, int(layer["x"])), max(0, int(layer["y"]))))
    return frame.convert("RGB")


def write_layers(data: Mapping[str, Any], width: int, height: int, folder: str) -> Dict[str, Any]:
    """Zapisuje PNG tła (razem z tekstem: jest nieruchomy od klatki 0) i herbów; zwraca plan ruchu dla `ffmpeg_args`."""
    composition = compose(data, width, height)
    base = composition["background"].convert("RGBA")
    base.alpha_composite(composition["text"])
    background = os.path.join(folder, "card-bg.png")
    base.convert("RGB").save(background, "PNG", compress_level=1)
    layers = []
    for i, layer in enumerate(composition["layers"]):
        path = os.path.join(folder, f"card-layer-{i}.png")
        layer["image"].save(path, "PNG", compress_level=1)
        layers.append({"path": path, "x": int(layer["x"]), "y": int(layer["y"]), "motion": layer["motion"]})
    return {"background": background, "layers": layers}


# ─── ffmpeg ─────────────────────────────────────────────────────────────────


def _slide_expr(target: int, start: int, delay: float, duration: float) -> str:
    """Dojazd z wyhamowaniem (ease-out quart), bez odbicia: kończy dokładnie w pozycji docelowej."""
    return f"{target}+({start - target})*pow(1-clip((t-{delay:.3f})/{duration:.3f},0,1),4)"


def ffmpeg_args(plan: Mapping[str, Any], source: str, target: str, width: int, height: int, has_audio: bool) -> List[str]:
    """Plansza + przenikanie w klip (`xfade`). Klip zaczyna się na CARD_SECONDS - CARD_FADE_S, więc dźwięk jest opóźniony
    o dokładnie tyle samo (cisza pod planszą) i obraz zostaje zsynchronizowany z dźwiękiem."""
    frames = int(round(CARD_SECONDS * FPS))
    clip_at = CARD_SECONDS - CARD_FADE_S
    hold = f"loop=loop={frames - 1}:size=1:start=0,setpts=N/{FPS}/TB"
    rgb_in = "scale=out_color_matrix=bt709:out_range=tv"
    layers = list(plan["layers"])
    shift = int(width * SLIDE_SHIFT)
    args = ["ffmpeg", "-hide_banner", "-nostdin", "-y", "-i", plan["background"]]
    graph = [f"[0:v]{rgb_in},format=yuv444p,{hold}[s0]"]
    for i, layer in enumerate(layers, start=1):
        args += ["-i", layer["path"]]
        home = layer["motion"] == "home"
        x = _slide_expr(layer["x"], layer["x"] + (-shift if home else shift), 0.0 if home else AWAY_DELAY_S, SLIDE_S)
        graph.append(f"[{i}:v]{rgb_in},format=yuva444p,{hold}[l{i}]")
        graph.append(f"[s{i - 1}][l{i}]overlay=x='{x}':y={layer['y']}:format=yuv444:eval=frame[s{i}]")
    src = len(layers) + 1
    args += ["-i", source]
    fit = f"scale={width}:{height}:force_original_aspect_ratio=decrease,pad={width}:{height}:(ow-iw)/2:(oh-ih)/2,setsar=1"
    # start_time=0: gdy obraz źródła startuje chwilę po dźwięku, pierwsza klatka wypełnia lukę i synchronizacja zostaje.
    graph.append(f"[s{len(layers)}]fps={FPS},setsar=1,format=yuv420p[card]")
    graph.append(f"[{src}:v]{fit},fps={FPS}:start_time=0,format=yuv420p[clip]")
    graph.append(f"[card][clip]xfade=transition=fade:duration={CARD_FADE_S:.3f}:offset={clip_at:.3f}[v]")
    maps = ["-map", "[v]"]
    if has_audio:
        delay_ms = int(round(clip_at * 1000))
        graph.append(f"[{src}:a]aformat=sample_rates=48000:channel_layouts=stereo,aresample=async=1:first_pts=0,"
                     f"adelay={delay_ms}:all=1,afade=t=in:st={clip_at:.3f}:d={CARD_FADE_S:.3f}[a]")
        maps += ["-map", "[a]", "-c:a", "aac", "-b:a", "128k"]
    else:
        maps += ["-an"]
    # Dwa wątki filtrów: domyślnie po jednym na rdzeń, a 12 rdzeni kręciło filtry 2x drożej przy tym samym wyniku (pomiar 31.10).
    return [*args, "-filter_complex_threads", "2", "-filter_complex", ";".join(graph), *maps, "-c:v", "libx264", "-preset", "veryfast", "-crf", "21",
            "-pix_fmt", "yuv420p", "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
            "-movflags", "+faststart", target]
