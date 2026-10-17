"""
Egzamin na żywo - oprawa marki: barwy okręgu, markowy kod QR, karta linku, obraz 9:16, plakat A4.

Moduł-liść (17.10.2026): nie zna bazy ani FastAPI. Trasy w `exam_live_routes.py` podają mu adres
i sesję, a on oddaje SVG, PNG (Pillow) albo HTML plakatu (weasyprint składa z niego PDF).

KOD QR. Korekcja błędów H (do 30% modułów może zniknąć), bo środek zajmuje herb. Moduły to
kropki w gradiencie barw herbu okręgu (egzamin krajowy albo bez okręgu: barwy ZPRP), oczka
w kształcie biletu - wklęsłe narożniki. Wklęsłe są TYLKO narożniki: wycięcie na środku boku
przecinałoby linię skanowania przez środek oczka (proporcja 1:1:3:1:1) i czytniki gubiłyby kod.
Środek wycinamy w samej macierzy (`excavate`), więc aplikacja i serwer rysują dokładnie to samo.

Barwy są SUROWE z herbów (lustro `BAZA/components/admin/provinceColors.ts`) i dla kodu
przyciemniane do kontrastu >= 4,5 z bielą: żółć dolnośląskiego na białym nie dałaby się zeskanować.
"""

from __future__ import annotations

import base64
import io
import math
import re
import unicodedata
from functools import lru_cache
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

IMG_DIR = Path(__file__).resolve().parent / "exam_live_img"
FONT_DIR = Path(__file__).resolve().parent / "fonts"

#: Barwy z herbów, para na województwo (primary, secondary) - te same liczby co w aplikacji.
PROVINCE_COLORS: Dict[str, Tuple[str, str]] = {
    "DOLNOSLASKIE": ("#F3C707", "#F3C707"),
    "KUJAWSKO_POMORSKIE": ("#D82519", "#D82519"),
    "LODZKIE": ("#FECC00", "#E31E24"),
    "LUBELSKIE": ("#8A0505", "#CAB16E"),
    "LUBUSKIE": ("#056839", "#BF1E2D"),
    "MALOPOLSKIE": ("#0575BB", "#0575BB"),
    "MAZOWIECKIE": ("#FAB001", "#E20612"),
    "OPOLSKIE": ("#0552A5", "#FFD90A"),
    "PODKARPACKIE": ("#D73212", "#078FDA"),
    "PODLASKIE": ("#00AEFC", "#FF0000"),
    "POMORSKIE": ("#B72531", "#BEA164"),
    "SLASKIE": ("#EEB90A", "#005CA3"),
    "SWIETOKRZYSKIE": ("#C1011F", "#C1011F"),
    "WARMINSKO_MAZURSKIE": ("#61A9CD", "#D95F3D"),
    "WIELKOPOLSKIE": ("#251169", "#088ED5"),
    "ZACHODNIOPOMORSKIE": ("#D77201", "#142C62"),
}
#: Związek: czerwień i granat pieczęci (egzamin krajowy albo sesja bez okręgu).
ZPRP_COLORS: Tuple[str, str] = ("#C8102E", "#1B2A5C")

#: Oczko-bilet. Sprawdzone dekoderem OpenCV na skalach 5-21 px/moduł (test): ZEWNĘTRZNY obrys oczka
#: musi zostać kwadratem - każde zaokrąglenie albo wcięcie narożnika (już od 0,5 modułu) gubi kod
#: w części skal. Bilet jest więc w środku: okienko o wklęsłych narożnikach i źrenica-bilecik.
HOLE_R = 0.9
PUPIL_R = 0.8
QUIET = 2  # margines w modułach w SVG (biel biletu dokłada resztę ciszy wokół kodu)


# ---------------------------------------------------------------------------
# Barwy
# ---------------------------------------------------------------------------


def province_slug(value: Any) -> str:
    """„Śląskie" / „WARMIŃSKO-MAZURSKIE" / „slaskie" -> „SLASKIE" / „WARMINSKO_MAZURSKIE"."""
    base = str(value or "").replace("Ł", "L").replace("ł", "l")
    base = unicodedata.normalize("NFKD", base).encode("ascii", "ignore").decode("ascii").upper()
    return re.sub(r"[^A-Z0-9]+", "_", base).strip("_")


def _rgb(hex_: str) -> Tuple[int, int, int]:
    h = hex_.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(rgb: Sequence[float]) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c))):02X}" for c in rgb)


def _lum(rgb: Sequence[float]) -> float:
    def ch(c: float) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (ch(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = _lum(_rgb(a)), _lum(_rgb(b))
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _mix(a: str, b: str, t: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return _hex([ra[i] + (rb[i] - ra[i]) * t for i in range(3)])


def ink_on_white(hex_: str, minimum: float = 4.5) -> str:
    """Barwa przyciemniona ku czerni tylko tyle, ile trzeba do kontrastu `minimum` z bielą."""
    if contrast(hex_, "#FFFFFF") >= minimum:
        return hex_.upper()
    for step in range(1, 21):
        cand = _mix(hex_, "#000000", step * 0.05)
        if contrast(cand, "#FFFFFF") >= minimum:
            return cand
    return "#000000"


def palette_for(scope: Any, province: Any) -> Dict[str, Any]:
    """Barwy sesji. `primary/secondary` surowe (światło na ciemnym tle), `from/to` do druku kodu."""
    slug = province_slug(province)
    kind = "province" if scope != "national" and slug in PROVINCE_COLORS else "zprp"
    primary, secondary = PROVINCE_COLORS[slug] if kind == "province" else ZPRP_COLORS
    start = ink_on_white(primary)
    end = ink_on_white(secondary)
    if start == end:
        # Herb jednobarwny: gradient i tak ma być widać - druga strona głębiej w tę samą barwę.
        end = _mix(start, "#000000", 0.38)
    return {"kind": kind, "slug": slug if kind == "province" else "ZPRP", "primary": primary.upper(),
            "secondary": secondary.upper(), "from": start, "to": end, "background": "#FFFFFF"}


def crest_name(palette: Mapping[str, Any]) -> str:
    """Plik w `app/exam_live_img`: `okregi/slaskie.png` albo `zprp.png`."""
    if palette.get("kind") == "province":
        return f"okregi/{str(palette['slug']).lower()}.png"
    return "zprp.png"


def crest_path(palette: Mapping[str, Any]) -> Optional[Path]:
    path = IMG_DIR / crest_name(palette)
    return path if path.exists() else None


@lru_cache(maxsize=32)
def _crest_bytes(name: str) -> bytes:
    path = IMG_DIR / name
    return path.read_bytes() if path.exists() else b""


def crest_data_uri(palette: Mapping[str, Any]) -> str:
    data = _crest_bytes(crest_name(palette))
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii") if data else ""


# ---------------------------------------------------------------------------
# Macierz kodu
# ---------------------------------------------------------------------------


def qr_layout(url: str) -> Dict[str, Any]:
    """Macierz modułów (korekcja H) z wyciętym środkiem pod herb i położeniem oczek."""
    import qrcode
    from qrcode.constants import ERROR_CORRECT_H

    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_H, border=0, box_size=1)
    qr.add_data(url)
    qr.make(fit=True)
    raw = [list(row) for row in qr.get_matrix()]
    n = len(raw)
    # Pole herbu: ~22% boku (≈5% powierzchni, daleko poniżej zapasu korekcji H), zawsze nieparzyste.
    logo = max(5, int(round(n * 0.22)))
    if logo % 2 == 0:
        logo += 1
    lx = (n - logo) // 2
    eyes = [(0, 0), (n - 7, 0), (0, n - 7)]

    def in_eye(x: int, y: int) -> bool:
        return any(ex <= x < ex + 7 and ey <= y < ey + 7 for ex, ey in eyes)

    modules: List[List[bool]] = []
    for y in range(n):
        row = []
        for x in range(n):
            dark = bool(raw[y][x])
            if in_eye(x, y) or (lx <= x < lx + logo and lx <= y < lx + logo):
                dark = False  # oczka rysujemy osobno (bilet), środek zostaje pod herb
            row.append(dark)
        modules.append(row)
    return {"url": url, "version": qr.version, "size": n, "ecc": "H", "modules": modules, "raw": [[bool(c) for c in r] for r in raw],
            "eyes": [{"x": ex, "y": ey, "size": 7} for ex, ey in eyes],
            "logo": {"x": lx, "y": lx, "size": logo}}


def qr_json(url: str, palette: Mapping[str, Any], crest_url: str, extra: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Kontrakt dla aplikacji (rysuje animowany kod sama). `modules` = wiersze z „0”/„1”."""
    lay = qr_layout(url)
    out = {
        "v": 1, "url": url, "ecc": "H", "version": lay["version"], "size": lay["size"], "quiet": QUIET,
        # `matrix`: pełna macierz (z oczkami i środkiem) - aplikacja sama wycina oczka i okno herbu.
        # `modules`: to samo po wycięciu (oczka i środek puste) - tak rysuje serwer i strona rzutnika.
        "matrix": ["".join("1" if c else "0" for c in row) for row in lay["raw"]],
        "modules": ["".join("1" if c else "0" for c in row) for row in lay["modules"]],
        "eyes": lay["eyes"], "logo": lay["logo"],
        "style": {"dot_radius": 0.42, "eye_outer": "square", "eye_hole_concave_radius": HOLE_R, "pupil_concave_radius": PUPIL_R,
                  "gradient": "diagonal", "logo_plate_radius": 0.9},
        "palette": dict(palette), "crest_url": crest_url,
    }
    if extra:
        out.update(extra)
    return out


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------


def _ticket_path(x: float, y: float, w: float, r: float) -> str:
    """Kwadrat o boku `w` z wklęsłymi narożnikami promienia `r` (kształt biletu)."""
    return (f"M{x + r:.3f} {y:.3f}H{x + w - r:.3f}A{r} {r} 0 0 0 {x + w:.3f} {y + r:.3f}"
            f"V{y + w - r:.3f}A{r} {r} 0 0 0 {x + w - r:.3f} {y + w:.3f}H{x + r:.3f}"
            f"A{r} {r} 0 0 0 {x:.3f} {y + w - r:.3f}V{y + r:.3f}A{r} {r} 0 0 0 {x + r:.3f} {y:.3f}Z")


def eye_paths(ex: float, ey: float) -> Tuple[str, str]:
    """(pierścień z dziurą - fill-rule evenodd, źrenica) jednego oczka 7x7."""
    ring = f"M{ex} {ey}h7v7h-7Z" + _ticket_path(ex + 1, ey + 1, 5, HOLE_R)
    pupil = _ticket_path(ex + 2, ey + 2, 3, PUPIL_R)
    return ring, pupil


def brand_svg(url: str, palette: Mapping[str, Any], *, crest: str = "", plain: bool = False) -> str:
    """Markowy kod QR jako samodzielny SVG (herb w data URI, więc działa też w <img>)."""
    lay = qr_layout(url)
    n, q = lay["size"], QUIET
    total = n + 2 * q
    a, b = (palette["from"], palette["to"]) if not plain else ("#000000", "#000000")
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="geometricPrecision" role="img" aria-label="Kod QR">',
             f'<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient></defs>',
             f'<rect width="{total}" height="{total}" fill="#FFFFFF"/>', f'<g transform="translate({q} {q})" fill="url(#g)">']
    dots = []
    for y, row in enumerate(lay["modules"]):
        for x, dark in enumerate(row):
            if dark:
                dots.append(f'<circle cx="{x + 0.5}" cy="{y + 0.5}" r="0.42"/>')
    parts.append("".join(dots))
    for e in lay["eyes"]:
        ring, pupil = eye_paths(e["x"], e["y"])
        parts.append(f'<path fill-rule="evenodd" d="{ring}"/><path d="{pupil}"/>')
    lg = lay["logo"]
    if crest:
        pad = 0.55
        parts.append(f'<rect x="{lg["x"] + 0.15}" y="{lg["y"] + 0.15}" width="{lg["size"] - 0.3}" height="{lg["size"] - 0.3}" rx="0.9" fill="#FFFFFF" stroke="url(#g)" stroke-width="0.22"/>')
        parts.append(f'<image href="{escape(crest)}" x="{lg["x"] + pad}" y="{lg["y"] + pad}" width="{lg["size"] - 2 * pad}" height="{lg["size"] - 2 * pad}" preserveAspectRatio="xMidYMid meet"/>')
    parts.append("</g></svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# PNG (Pillow): kod, karta linku 1200x630, obraz 9:16 1080x1920
# ---------------------------------------------------------------------------

_FONTS = {
    ("serif", True): ["/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf", "C:/Windows/Fonts/georgiab.ttf"],
    ("serif", False): ["/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf", "C:/Windows/Fonts/georgia.ttf"],
    ("sans", True): ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/arialbd.ttf"],
    ("sans", False): ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/arial.ttf"],
}


@lru_cache(maxsize=64)
def _font(kind: str, bold: bool, size: int):
    from PIL import ImageFont

    for path in _FONTS[(kind, bold)] + [str(FONT_DIR / "NotoSans-Regular.ttf")]:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size)
    except TypeError:  # Pillow < 10.1
        return ImageFont.load_default()


def _crest_image(palette: Mapping[str, Any]):
    from PIL import Image

    data = _crest_bytes(crest_name(palette))
    if not data:
        return None
    return Image.open(io.BytesIO(data)).convert("RGBA")


def qr_png(url: str, palette: Mapping[str, Any], px: int, *, with_crest: bool = True, plain: bool = False):
    """Kod jako obraz RGBA `px` x `px` (biel + moduły), rysowany z 4-krotnym nadpróbkowaniem."""
    from PIL import Image, ImageDraw

    lay = qr_layout(url)
    n, q = lay["size"], QUIET
    total = n + 2 * q
    ss = 4
    big = px * ss
    m = big / total  # piksele na moduł
    mask = Image.new("L", (big, big), 0)
    d = ImageDraw.Draw(mask)

    def box(x: float, y: float, w: float, h: float) -> List[float]:
        return [(x + q) * m, (y + q) * m, (x + q + w) * m - 1, (y + q + h) * m - 1]

    r = 0.42
    for y, row in enumerate(lay["modules"]):
        for x, dark in enumerate(row):
            if dark:
                cx, cy = (x + q + 0.5) * m, (y + q + 0.5) * m
                d.ellipse([cx - r * m, cy - r * m, cx + r * m, cy + r * m], fill=255)
    for e in lay["eyes"]:
        ex, ey = e["x"], e["y"]
        d.rectangle(box(ex, ey, 7, 7), fill=255)
        d.rectangle(box(ex + 1, ey + 1, 5, 5), fill=0)
        for cx, cy, rr in ((ex + 1, ey + 1, HOLE_R), (ex + 6, ey + 1, HOLE_R), (ex + 1, ey + 6, HOLE_R), (ex + 6, ey + 6, HOLE_R)):
            d.ellipse([(cx + q - rr) * m, (cy + q - rr) * m, (cx + q + rr) * m, (cy + q + rr) * m], fill=255)
        d.rectangle(box(ex + 2, ey + 2, 3, 3), fill=255)
        for cx, cy, rr in ((ex + 2, ey + 2, PUPIL_R), (ex + 5, ey + 2, PUPIL_R), (ex + 2, ey + 5, PUPIL_R), (ex + 5, ey + 5, PUPIL_R)):
            d.ellipse([(cx + q - rr) * m, (cy + q - rr) * m, (cx + q + rr) * m, (cy + q + rr) * m], fill=0)
    lg = lay["logo"]
    if with_crest and not plain:
        d.rounded_rectangle(box(lg["x"] + 0.15, lg["y"] + 0.15, lg["size"] - 0.3, lg["size"] - 0.3), radius=0.9 * m,
                            outline=255, width=max(1, int(0.22 * m)))
    a, b = (palette["from"], palette["to"]) if not plain else ("#000000", "#000000")
    grad = _diagonal(big, a, b)
    out = Image.new("RGBA", (big, big), (255, 255, 255, 255))
    out.paste(grad, (0, 0), mask)
    out = out.resize((px, px), Image.LANCZOS)
    crest = _crest_image(palette) if with_crest and not plain else None
    if crest is not None:
        pm = px / total
        size = int((lg["size"] - 1.1) * pm)
        crest.thumbnail((size, size), Image.LANCZOS)
        ox = int((lg["x"] + q) * pm + ((lg["size"]) * pm - crest.width) / 2)
        oy = int((lg["y"] + q) * pm + ((lg["size"]) * pm - crest.height) / 2)
        out.alpha_composite(crest, (ox, oy))
    return out


def _diagonal(size: int, a: str, b: str):
    from PIL import Image

    small = Image.new("RGB", (64, 64))
    ra, rb = _rgb(a), _rgb(b)
    px = small.load()
    for y in range(64):
        for x in range(64):
            t = (x + y) / 126
            px[x, y] = tuple(round(ra[i] + (rb[i] - ra[i]) * t) for i in range(3))
    return small.resize((size, size), Image.BILINEAR)


def _night(w: int, h: int, palette: Mapping[str, Any]):
    """Ciemna hala z dwoma światłami w barwach herbu (jak tło rzutnika)."""
    from PIL import Image, ImageDraw, ImageFilter

    scale = 8
    sw, sh = max(8, w // scale), max(8, h // scale)
    base = Image.new("RGB", (sw, sh), (7, 8, 12))
    glow = Image.new("RGB", (sw, sh), (0, 0, 0))
    d = ImageDraw.Draw(glow)
    for (cx, cy, rad, col, alpha) in ((0.12, 0.05, 0.62, palette["primary"], 0.55),
                                      (0.95, 0.98, 0.7, palette["secondary"], 0.45)):
        c = _rgb(col)
        rr = rad * max(sw, sh)
        d.ellipse([cx * sw - rr, cy * sh - rr, cx * sw + rr, cy * sh + rr], fill=tuple(int(v * alpha) for v in c))
    glow = glow.filter(ImageFilter.GaussianBlur(max(sw, sh) * 0.16))
    from PIL import ImageChops

    img = ImageChops.add(base, glow)
    return img.resize((w, h), Image.BICUBIC).convert("RGBA")


def _text_w(draw, text: str, font) -> float:
    return draw.textlength(text, font=font)


def _fit_font(draw, text: str, kind: str, bold: bool, max_w: float, start: int, minimum: int = 14):
    size = start
    while size > minimum and _text_w(draw, text, _font(kind, bold, size)) > max_w:
        size -= 2
    return _font(kind, bold, size)


def _wrap(draw, text: str, font, max_w: float, max_lines: int) -> List[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        cand = (cur + " " + w).strip()
        if _text_w(draw, cand, font) <= max_w or not cur:
            cur = cand
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and _text_w(draw, last + "…", font) > max_w:
            last = last[:-1]
        lines[-1] = last.rstrip() + "…"
    return lines


def _spaced(draw, xy, text: str, font, fill, spacing: float) -> float:
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        x += _text_w(draw, ch, font) + spacing
    return x


def _pin_tickets(img, draw, pin: str, x: float, y: float, cell: int, gap: int, ink: str) -> None:
    """Sześć cyfr PIN-u na papierowych bilecikach (wklęsłe narożniki jak w kodzie)."""
    from PIL import Image, ImageDraw

    font = _font("serif", True, int(cell * 0.78))
    for i, ch in enumerate(pin):
        cx = int(x + i * (cell + gap) + (gap if i >= 3 else 0))
        tile = Image.new("L", (cell, int(cell * 1.22)), 0)
        td = ImageDraw.Draw(tile)
        td.rectangle([0, 0, tile.width, tile.height], fill=255)
        rr = cell * 0.14
        for (px_, py_) in ((0, 0), (tile.width, 0), (0, tile.height), (tile.width, tile.height)):
            td.ellipse([px_ - rr, py_ - rr, px_ + rr, py_ + rr], fill=0)
        paper = Image.new("RGBA", tile.size, (246, 241, 231, 255))
        img.paste(paper, (cx, int(y)), tile)
        tw = _text_w(draw, ch, font)
        draw.text((cx + (cell - tw) / 2, y + tile.height * 0.11), ch, font=font, fill=ink)


def _png_bytes(img) -> bytes:
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "PNG", optimize=True)
    return buf.getvalue()


def og_card_png(*, title: str, pin: Optional[str], character: str, palette: Mapping[str, Any], url: Optional[str],
                province_label: str = "") -> bytes:
    """Karta podglądu linku 1200x630: herb, nazwa, PIN, mały bilet z kodem."""
    from PIL import ImageDraw

    W, H = 1200, 630
    img = _night(W, H, palette)
    d = ImageDraw.Draw(img)
    crest = _crest_image(palette)
    left = 72
    if crest is not None:
        c = crest.copy()
        c.thumbnail((132, 132))
        img.alpha_composite(c, (left, 64))
    head_x = left + (156 if crest is not None else 0)
    _spaced(d, (head_x, 84), "BAZA · EGZAMIN NA ŻYWO", _font("sans", True, 22), (244, 239, 230, 210), 3.2)
    sub = ("Egzamin na sali" if character == "exam" else "Quiz szkoleniowy") + (f" · {province_label}" if province_label else "")
    d.text((head_x, 120), sub, font=_font("sans", False, 26), fill=(244, 239, 230, 170))
    text_w = 640 if url else 1040
    tfont = _font("serif", True, 58)
    lines = _wrap(d, title or "Egzamin z przepisów", tfont, text_w, 3)
    ty = 232
    for line in lines:
        d.text((left, ty), line, font=tfont, fill=(250, 246, 238))
        ty += 70
    if pin:
        _spaced(d, (left, 470), "KOD PIN", _font("sans", True, 20), _hex(_rgb(palette["primary"])), 4)
        _pin_tickets(img, d, pin, left, 500, 66, 10, "#17140F")
    else:
        d.text((left, 500), "Dołącz kodem PIN z ekranu prowadzącego", font=_font("sans", False, 28), fill=(244, 239, 230, 200))
    if url:
        ticket = _ticket_image(url, palette, 380)
        img.alpha_composite(ticket, (W - 380 - 70, (H - ticket.height) // 2))
    return _png_bytes(img)


def _ticket_image(url: str, palette: Mapping[str, Any], width: int):
    """Biały bilet z kodem: wklęsłe narożniki, linia perforacji, napis „ZESKANUJ”."""
    from PIL import Image, ImageDraw

    pad = int(width * 0.08)
    qr_px = width - 2 * pad
    stub = int(width * 0.16)
    h = pad + qr_px + stub
    mask = Image.new("L", (width, h), 255)
    md = ImageDraw.Draw(mask)
    r = width * 0.07
    for (px_, py_) in ((0, 0), (width, 0), (0, h), (width, h)):
        md.ellipse([px_ - r, py_ - r, px_ + r, py_ + r], fill=0)
    perf_y = pad + qr_px + int(pad * 0.35)
    nr = width * 0.045
    md.ellipse([-nr, perf_y - nr, nr, perf_y + nr], fill=0)
    md.ellipse([width - nr, perf_y - nr, width + nr, perf_y + nr], fill=0)
    card = Image.new("RGBA", (width, h), (0, 0, 0, 0))
    card.paste(Image.new("RGBA", (width, h), (255, 255, 255, 255)), (0, 0), mask)
    card.alpha_composite(qr_png(url, palette, qr_px), (pad, pad))
    d = ImageDraw.Draw(card)
    dash = max(4, width // 60)
    for x in range(int(nr * 1.6), int(width - nr * 1.6), dash * 2):
        d.line([(x, perf_y), (x + dash, perf_y)], fill=(200, 192, 180), width=2)
    font = _font("sans", True, max(12, int(width * 0.055)))
    label = "ZESKANUJ I DOŁĄCZ"
    spacing = width * 0.012
    tw = sum(_text_w(d, ch, font) + spacing for ch in label) - spacing
    _spaced(d, ((width - tw) / 2, perf_y + (h - perf_y) * 0.32), label, font, palette["from"], spacing)
    return card


def story_png(*, title: str, pin: str, character: str, palette: Mapping[str, Any], url: str, join_hint: str,
              province_label: str = "") -> bytes:
    """Obraz 9:16 (1080x1920) do relacji i komunikatorów."""
    from PIL import ImageDraw

    W, H = 1080, 1920
    img = _night(W, H, palette)
    d = ImageDraw.Draw(img)
    crest = _crest_image(palette)
    y = 150
    if crest is not None:
        c = crest.copy()
        c.thumbnail((190, 190))
        img.alpha_composite(c, ((W - c.width) // 2, y))
        y += c.height + 50
    eyebrow = "BAZA · EGZAMIN NA ŻYWO"
    ef = _font("sans", True, 30)
    tw = sum(_text_w(d, ch, ef) + 5 for ch in eyebrow) - 5
    _spaced(d, ((W - tw) / 2, y), eyebrow, ef, (244, 239, 230, 210), 5)
    y += 64
    tfont = _font("serif", True, 78)
    for line in _wrap(d, title or "Egzamin z przepisów", tfont, W - 160, 3):
        lw = _text_w(d, line, tfont)
        d.text(((W - lw) / 2, y), line, font=tfont, fill=(250, 246, 238))
        y += 94
    sub = ("Egzamin na sali" if character == "exam" else "Quiz szkoleniowy") + (f" · {province_label}" if province_label else "")
    sf = _font("sans", False, 34)
    d.text(((W - _text_w(d, sub, sf)) / 2, y + 6), sub, font=sf, fill=(244, 239, 230, 175))
    ticket = _ticket_image(url, palette, 640)
    ty = max(y + 90, 820)
    img.alpha_composite(ticket, ((W - ticket.width) // 2, ty))
    py = ty + ticket.height + 70
    lab = "KOD PIN"
    lf = _font("sans", True, 28)
    lw = sum(_text_w(d, ch, lf) + 6 for ch in lab) - 6
    _spaced(d, ((W - lw) / 2, py), lab, lf, palette["primary"], 6)
    cell, gap = 118, 14
    total_w = 6 * cell + 5 * gap + gap
    _pin_tickets(img, d, pin, (W - total_w) / 2, py + 52, cell, gap, "#17140F")
    hf = _fit_font(d, join_hint, "sans", False, W - 140, 34, 18)
    d.text(((W - _text_w(d, join_hint, hf)) / 2, H - 150), join_hint, font=hf, fill=(244, 239, 230, 185))
    return _png_bytes(img)


# ---------------------------------------------------------------------------
# Plakat A4 (HTML dla weasyprint)
# ---------------------------------------------------------------------------


def poster_html(*, title: str, pin: str, character: str, palette: Mapping[str, Any], url: str, join_page: str,
                province_label: str, seal: str) -> str:
    """Plakat do powieszenia w sali: herb, nazwa, PIN, duży kod, instrukcja w trzech krokach, pieczęć.
    Wszystko inline (zero zasobów z sieci) - weasyprint składa z tego jedną stronę A4."""
    qr = brand_svg(url, palette, crest=crest_data_uri(palette))
    crest = crest_data_uri(palette)
    kind = "Egzamin na sali" if character == "exam" else "Quiz szkoleniowy"
    digits = "".join(f'<span class="d">{escape(ch)}</span>' + ('<span class="gap"></span>' if i == 2 else "") for i, ch in enumerate(pin))
    a, b = palette["from"], palette["to"]
    link = escape(join_page.replace("https://", "").replace("http://", ""))
    return f"""<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>{escape(title)}</title><style>
@page {{ size: A4; margin: 0; }}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; }}
body {{ width: 210mm; height: 297mm; font-family: "DejaVu Sans", sans-serif; color: #17140F; background: #FBF8F2; position: relative; overflow: hidden; }}
.band {{ position: absolute; left: 0; right: 0; top: 0; height: 9mm; background: linear-gradient(90deg, {a}, {b}); }}
.band.b {{ top: auto; bottom: 0; height: 5mm; }}
.wrap {{ position: absolute; left: 16mm; right: 16mm; top: 18mm; bottom: 14mm; }}
.head {{ display: flex; align-items: center; gap: 6mm; }}
.head img {{ width: 26mm; height: 26mm; object-fit: contain; }}
.eyebrow {{ font-size: 9.5pt; letter-spacing: 2.6pt; font-weight: 700; color: {a}; text-transform: uppercase; }}
.kind {{ font-size: 11pt; color: #5A5249; margin-top: 1.2mm; }}
h1 {{ font-family: "DejaVu Serif", serif; font-size: 30pt; line-height: 1.12; margin: 9mm 0 0; font-weight: 700; }}
.ticket {{ margin: 9mm auto 0; width: 128mm; background: #FFFFFF; border: 0.5mm solid #E5DED2; border-radius: 6mm; padding: 9mm 9mm 6mm; position: relative; }}
.ticket svg {{ width: 110mm; height: 110mm; display: block; }}
.perf {{ border-top: 0.5mm dashed #CFC6B8; margin: 6mm -9mm 0; }}
.stub {{ text-align: center; padding-top: 4mm; font-size: 10pt; letter-spacing: 3pt; font-weight: 700; color: {a}; }}
.pinlab {{ text-align: center; font-size: 10pt; letter-spacing: 3pt; font-weight: 700; color: #5A5249; margin-top: 8mm; }}
.pin {{ text-align: center; margin-top: 2.5mm; }}
.d {{ display: inline-block; width: 15mm; height: 19mm; line-height: 19mm; margin: 0 1mm; border-radius: 2.5mm; background: #17140F; color: #FBF8F2;
     font-family: "DejaVu Serif", serif; font-weight: 700; font-size: 30pt; text-align: center; }}
.gap {{ display: inline-block; width: 4mm; }}
.steps {{ display: flex; gap: 5mm; margin-top: 9mm; }}
.step {{ flex: 1; border-top: 0.6mm solid {a}; padding-top: 3mm; font-size: 10.5pt; line-height: 1.38; }}
.step b {{ display: block; font-family: "DejaVu Serif", serif; font-size: 18pt; color: {a}; margin-bottom: 1mm; }}
.step code {{ font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt; word-break: break-all; }}
.seal {{ position: absolute; right: 2mm; bottom: 4mm; transform: rotate(-11deg); opacity: .9; }}
.foot {{ position: absolute; left: 0; bottom: 0; font-size: 8.5pt; color: #7A7064; }}
</style></head><body><div class="band"></div><div class="wrap">
<div class="head">{f'<img src="{crest}" alt="">' if crest else ''}<div><div class="eyebrow">BAZA · Egzamin z przepisów · na żywo</div>
<div class="kind">{escape(kind)}{(' · ' + escape(province_label)) if province_label else ''}</div></div></div>
<h1>{escape(title)}</h1>
<div class="ticket">{qr}<div class="perf"></div><div class="stub">ZESKANUJ TELEFONEM I DOŁĄCZ</div></div>
<div class="pinlab">ALBO WPISZ KOD PIN</div><div class="pin">{digits}</div>
<div class="steps">
<div class="step"><b>1</b>Zeskanuj kod aparatem telefonu albo otwórz aplikację BAZA: Egzamin na żywo.</div>
<div class="step"><b>2</b>Bez aplikacji: wejdź na <code>{link}</code> i wpisz PIN. Zaloguj się kontem BAZY, a wynik trafi do Twojej historii.</div>
<div class="step"><b>3</b>Patrz na rzutnik i odpowiadaj na telefonie. Liczy się poprawność{'' if character == 'exam' else ' i szybkość'}.</div>
</div>
<div class="seal">{seal}</div>
<div class="foot">Kod PIN działa, dopóki sesja trwa. Kod QR prowadzi prosto do tej sesji.</div>
</div><div class="band b"></div></body></html>"""


def province_label(scope: Any, province: Any) -> str:
    if scope == "national" or not province:
        return "ZPRP"
    text = str(province).strip()
    return text[:1].upper() + text[1:].lower() if text.isupper() else text
