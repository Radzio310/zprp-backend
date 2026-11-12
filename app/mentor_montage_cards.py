"""Plansze montażu (12.11.2026): okładka-plakat, rozdział meczu, belka klipu, licznik z etykietą, napis z notatką, spis klipów.

Wspólny język z planszą klipu („Pojedynek herbów”, `mentor_clip_card`): tło z barw drużyn, herby z poświatą, kafelek numeru
meczu w barwie ligi. Kroje jak w aplikacji: Fontastique PL to GŁOS (nazwa zestawienia, duże liczby, minuta), Geist to TREŚĆ
(drużyny, daty, tytuły i notatki klipów). Bez nadtytułów nad tytułami (decyzja 05.11.2026).
Wszystko projektowane w jednostkach kadru 1920x1080 (`u`), więc 720p to ten sam układ w skali. Czyste: Pillow, bez bazy i sieci.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app import mentor_clip_card as K
from app import mentor_montage_rules as MR

FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
VOICE = os.path.join(FONT_DIR, "FontastiquePL.ttf")
BOLD = os.path.join(FONT_DIR, "Geist-Bold.ttf")
MEDIUM = os.path.join(FONT_DIR, "Geist-Medium.ttf")
REGULAR = os.path.join(FONT_DIR, "Geist-Regular.ttf")

CORAL = K.MENTOR_CORAL
INK = (255, 255, 255)
GLASS = (12, 10, 8)
#: Przesunięcie wjazdu herbów i wierszy (ułamek szerokości kadru) i czasy ruchu, jak w planszy klipu.
SLIDE_SHIFT = 0.045
SLIDE_S = 0.55
STAGGER_S = 0.07
#: Ile wierszy spisu mieści się bez przewijania (przy 1080 i 720 ten sam układ).
CREDITS_VISIBLE = 10


def unit(width: int, height: int) -> float:
    return min(width / 1920.0, height / 1080.0)


def _font(path: str, size: float) -> Any:
    from PIL import ImageFont

    return ImageFont.truetype(path, max(9, int(round(size))))


def _rgba(rgb: Sequence[int], alpha: int) -> Tuple[int, int, int, int]:
    return int(rgb[0]), int(rgb[1]), int(rgb[2]), int(alpha)


def _text_w(draw: Any, text: str, font: Any) -> float:
    return draw.textlength(text, font=font)


def _fit(draw: Any, path: str, text: str, start: float, smallest: float, width: float) -> Any:
    size = start
    while size > smallest:
        font = _font(path, size)
        if _text_w(draw, text, font) <= width:
            return font
        size -= max(1.0, size / 24.0)
    return _font(path, smallest)


def _wrap_fit(draw: Any, path: str, text: str, sizes: Sequence[Tuple[float, int]], width: float) -> Tuple[Any, List[str]]:
    """Największy krój, w którym tekst mieści się w `max_lines` wierszach bez skracania; ostatni zestaw skraca."""
    font, rows = None, []
    for size, lines in sizes:
        font = _font(path, size)
        rows = K.wrap_lines(draw, text, font, width, lines)
        if not any(r.endswith("…") for r in rows):
            return font, rows
    return font, rows


def _pill(size: Tuple[int, int], fill: Tuple[int, int, int, int], radius: Optional[int] = None) -> Any:
    """Zaokrąglony prostokąt RGBA z wygładzoną krawędzią (rysowany 3x większy)."""
    from PIL import Image, ImageDraw

    w, h = max(2, int(size[0])), max(2, int(size[1]))
    k = 3
    r = h // 2 if radius is None else int(radius)
    mask = Image.new("L", (w * k, h * k), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w * k - 1, h * k - 1], radius=r * k, fill=255)
    mask = mask.resize((w, h), Image.LANCZOS)
    out = Image.new("RGBA", (w, h), fill[:3] + (0,))
    solid = Image.new("RGBA", (w, h), fill)
    out.paste(solid, (0, 0), mask.point(lambda v: int(v * fill[3] / 255)))
    return out


def code_tile(code: str, color: Any, u: float, size: float = 44) -> Optional[Any]:
    """Kafelek numeru meczu w barwie ligi (jak `MatchNumber.tsx`), z poświatą; None bez numeru."""
    if not code:
        return None
    font = _font(K.FONT_CLOCK, size * u)
    cap = int(font.size * 0.70)
    layer, _glow = K._tag(code, font, K.parse_color(color) or (136, 136, 136), int(10 * u), int(16 * u), int(11 * u), cap, 0.0, u)
    return layer


def _crest(raw: Optional[bytes], name: str, color: Any, box: int, u: float) -> Tuple[Any, int]:
    crest = K.prepare_crest(raw, box) if raw else None
    if crest is None:
        crest = K.shield_crest(name, K.parse_color(color), box)
    return K._crest_with_light(crest, u)


def medallion(raw: Optional[bytes], name: str, color: Any, diameter: int, u: float) -> Any:
    """Herb w medalionie: koło w ciemnej barwie drużyny z jasną obwódką i poświatą, herb (albo tarcza z inicjałami) w środku.
    Herby ZPRP to często JPEG 50x50 - w medalionie mały herb wygląda na zamierzony, a nie zgubiony na planszy."""
    from PIL import Image, ImageDraw, ImageFilter

    rgb = K.parse_color(color)
    d = int(diameter)
    pad = int(max(8, 22 * u))
    size = d + 2 * pad
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    k = 3
    disc = Image.new("L", (d * k, d * k), 0)
    ImageDraw.Draw(disc).ellipse([0, 0, d * k - 1, d * k - 1], fill=255)
    disc = disc.resize((d, d), Image.LANCZOS)
    glow = Image.new("L", (size, size), 0)
    glow.paste(disc, (pad, pad))
    glow = glow.filter(ImageFilter.GaussianBlur(pad / 2.2)).point(lambda v: int(v * 0.55))
    out.paste(Image.new("RGBA", (size, size), _rgba(K.team_light(rgb), 255)), (0, 0), glow)
    deep, light = K.team_tone(rgb, 0.035), K.team_light(rgb)
    fill = Image.new("RGBA", (d, d))
    rows = ImageDraw.Draw(fill)
    for y in range(d):
        rows.line([(0, y), (d, y)], fill=_rgba(K._mix(K._mix(deep, light, 0.30), deep, y / float(d)), 255))
    ring_w = max(2, int(d * 0.035))
    ring = Image.new("RGBA", (d, d), _rgba(K._mix(light, INK, 0.35), 255))
    plate = Image.new("RGBA", (d, d), (0, 0, 0, 0))
    plate.paste(ring, (0, 0), disc)
    inner = disc.resize((d - 2 * ring_w, d - 2 * ring_w), Image.LANCZOS)
    plate.paste(fill.resize(inner.size), (ring_w, ring_w), inner)
    out.alpha_composite(plate, (pad, pad))
    box = int(d * 0.64)
    crest = K.prepare_crest(raw, box) if raw else None
    if crest is None:
        crest = K.shield_crest(name, rgb, box)
    elif max(crest.size) < box * 0.6:
        # Mały herb na jasnym krążku: czytelny na każdej barwie drużyny.
        back = int(max(crest.size) * 1.42)
        dot = Image.new("L", (back * k, back * k), 0)
        ImageDraw.Draw(dot).ellipse([0, 0, back * k - 1, back * k - 1], fill=255)
        dot = dot.resize((back, back), Image.LANCZOS)
        out.paste(Image.new("RGBA", (back, back), (250, 247, 240, 255)), (int(size / 2 - back / 2), int(size / 2 - back / 2)), dot)
    lit, lit_pad = K._crest_with_light(crest, u)
    out.alpha_composite(lit, (int(size / 2 - lit.width / 2), int(size / 2 - lit.height / 2)))
    return out


def _shadowed(layer: Any, u: float, strength: float = 0.55) -> Any:
    return K._shadow(layer, max(1.5, 6 * u), max(1, int(2 * u)), strength)


def _bg(width: int, height: int, left: Optional[Sequence[int]], right: Optional[Sequence[int]], lights: Sequence[Tuple[float, float, float]]) -> Any:
    return K.render_background(width, height, tuple(left) if left else None, tuple(right) if right else None, lights)


# ─── Okładka-plakat ─────────────────────────────────────────────────────────


def cover_data(name: str, description: str, matches: Sequence[Mapping[str, Any]], clips: int, film_s: float) -> Dict[str, Any]:
    """`matches`: [{home, away, code, code_color, date, crests:{home,away}, colors:{home,away}}] w kolejności filmu."""
    return {"name": MR.clean_text(name, MR.MAX_NAME) or "Zestawienie", "description": MR.clean_text(description, MR.MAX_DESCRIPTION),
            "matches": list(matches), "clips": int(clips), "film_s": float(film_s)}


def _stat(draw: Any, x: float, base: float, number: str, word: str, u: float) -> float:
    """Liczba (głos) z podpisem pod spodem; zwraca szerokość bloku."""
    big = _font(VOICE, 104 * u)
    small = _font(MEDIUM, 27 * u)
    tracking = small.size * 0.14
    draw.text((x, base), number, font=big, fill=_rgba(INK, 255), anchor="ls")
    K._draw_tracked(draw, x + 2 * u, base + 46 * u, word.upper(), small, _rgba(INK, 190), tracking)
    return max(_text_w(draw, number, big), K._tracked_width(draw, word.upper(), small, tracking))


def compose_cover(data: Mapping[str, Any], width: int, height: int) -> Dict[str, Any]:
    """Lewa kolumna: nazwa, kreska, opis, trzy liczby (klipy, mecze, czas). Prawa: wiersze meczów (herb - numer - herb),
    które wjeżdżają po kolei. Klatka 0 jest kompletna (to też miniatura pliku)."""
    from PIL import Image, ImageDraw

    u = unit(width, height)
    matches = list(data.get("matches") or [])
    first = matches[0] if matches else {}
    accent = K.parse_color((first.get("colors") or {}).get("home")) or K.parse_color((first.get("colors") or {}).get("away"))
    lights = [(width * 0.16, height * 0.30, 0.42), (width * 0.78, height * 0.50, 0.40)]
    background = _bg(width, height, CORAL, accent or (61, 117, 133), lights)
    text = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(text)

    left = 132 * u
    col_w = (980 if matches else 1600) * u
    name = str(data.get("name") or "Zestawienie")
    title_font, rows = _wrap_fit(draw, VOICE, name, ((150 * u, 2), (124 * u, 2), (104 * u, 3), (88 * u, 3)), col_w)
    line = title_font.size * 1.02
    desc = str(data.get("description") or "")
    desc_font = _font(REGULAR, 38 * u)
    desc_rows = K.wrap_lines(draw, desc, desc_font, col_w * 0.94, 3) if desc else []
    block = line * len(rows) + 46 * u + (len(desc_rows) * desc_font.size * 1.32 + 10 * u if desc_rows else 0)
    top = max(120 * u, (height * 0.60 - block) / 2.0)
    y = top
    for row in rows:
        draw.text((left, y + title_font.size * 0.86), row, font=title_font, fill=_rgba(INK, 255), anchor="ls")
        y += line
    y += 18 * u
    text.alpha_composite(_pill((int(112 * u), int(10 * u)), _rgba(CORAL, 255)), (int(left), int(y)))
    y += 46 * u
    for row in desc_rows:
        draw.text((left, y + desc_font.size * 0.9), row, font=desc_font, fill=_rgba(INK, 214), anchor="ls")
        y += desc_font.size * 1.32

    clips = int(data.get("clips") or 0)
    stats = [(str(clips), MR.plural(clips, "klip", "klipy", "klipów"))]
    if matches:
        stats.append((str(len(matches)), MR.plural(len(matches), "mecz", "mecze", "meczów")))
    stats.append((MR.duration_label(float(data.get("film_s") or 0)), "czas filmu"))
    x, base = left, height - 190 * u
    for number, word in stats:
        x += _stat(draw, x, base, number, word, u) + 84 * u
    brand = _font(MEDIUM, 26 * u)
    K._draw_tracked(draw, left, height - 64 * u, "BAZA · MENTOR", brand, _rgba(INK, 130), brand.size * 0.16)
    text = _shadowed(text, u, 0.5)

    layers: List[Dict[str, Any]] = []
    if matches:
        shown = matches if len(matches) <= 4 else matches[:3]
        row_h = 176 * u
        total_h = row_h * (len(shown) + (1 if len(matches) > len(shown) else 0))
        cx = width - 400 * u
        y0 = (height - total_h) / 2.0 + 10 * u
        for i, m in enumerate(shown):
            layers.append({"image": _match_row(m, u, row_h), "x": int(cx - 330 * u), "y": int(y0 + i * row_h), "delay": 0.12 + i * STAGGER_S})
        if len(matches) > len(shown):
            more = len(matches) - len(shown)
            layers.append({"image": _more_row(more, u, row_h), "x": int(cx - 330 * u), "y": int(y0 + len(shown) * row_h),
                           "delay": 0.12 + len(shown) * STAGGER_S})
    return {"background": background, "text": text, "layers": layers, "unit": u}


def _match_row(match: Mapping[str, Any], u: float, row_h: float) -> Any:
    """Wiersz okładki: herb gospodarza, kafelek numeru z datą pod spodem, herb gościa (szerokość 660u)."""
    from PIL import Image, ImageDraw

    w, h = int(660 * u), int(row_h)
    box = int(124 * u)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    crests = match.get("crests") or {}
    colors = match.get("colors") or {}
    for side, cx in (("home", 92 * u), ("away", w - 92 * u)):
        img = medallion(crests.get(side), str(match.get(side) or ""), colors.get(side), box, u)
        out.alpha_composite(img, (int(cx - img.width / 2), int(h / 2 - img.height / 2)))
    tile = code_tile(str(match.get("code") or ""), match.get("code_color"), u, 40)
    draw = ImageDraw.Draw(out)
    mid = w / 2.0
    if tile is not None:
        out.alpha_composite(tile, (int(mid - tile.width / 2), int(h / 2 - tile.height + 4 * u)))
    date = str(match.get("date") or "")
    if date:
        font = _font(MEDIUM, 26 * u)
        draw.text((mid, h / 2 + 40 * u), date, font=font, fill=_rgba(INK, 205), anchor="ms")
    elif tile is None:
        font = _font(BOLD, 34 * u)
        draw.text((mid, h / 2 + 12 * u), "-", font=font, fill=_rgba(INK, 200), anchor="ms")
    return out


def _more_row(more: int, u: float, row_h: float) -> Any:
    from PIL import Image, ImageDraw

    w, h = int(660 * u), int(row_h)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(out)
    font = _font(MEDIUM, 34 * u)
    draw.text((w / 2, h / 2 + 12 * u), f"i jeszcze {more} {MR.plural(more, 'mecz', 'mecze', 'meczów')}", font=font,
              fill=_rgba(INK, 210), anchor="ms")
    return out


# ─── Rozdział meczu ─────────────────────────────────────────────────────────


def compose_chapter(data: Mapping[str, Any], width: int, height: int) -> Dict[str, Any]:
    """Plansza nowego meczu: numer meczu w kafelku, rozgrywki i data, duże herby z nazwami, liczba klipów z tego meczu,
    kropki rozdziałów (który mecz z ilu). Herby dojeżdżają z boków jak w planszy klipu."""
    from PIL import Image, ImageDraw

    u = unit(width, height)
    colors = {side: K.parse_color((data.get("colors") or {}).get(side)) for side in ("home", "away")}
    offset = 560 * u
    centers = (width / 2 - offset, width / 2 + offset)
    crest_y = height * 0.47
    background = _bg(width, height, colors["home"], colors["away"], [(cx, crest_y, 0.30) for cx in centers])
    text = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(text)

    tile = code_tile(str(data.get("code") or ""), data.get("code_color"), u, 54)
    y = height * 0.17
    if tile is not None:
        text.alpha_composite(tile, (int(width / 2 - tile.width / 2), int(y - tile.height / 2)))
    info = "   ·   ".join(p for p in (str(data.get("competition") or ""), str(data.get("date") or "")) if p)
    if info:
        font = _font(MEDIUM, 34 * u)
        line = K._ellipsize(draw, info, font, width * 0.7)
        draw.text((width / 2, y + 78 * u), line, font=font, fill=_rgba(INK, 225), anchor="ms")

    box = int(300 * u)
    layers: List[Dict[str, Any]] = []
    name_font = _font(BOLD, 44 * u)
    for side, cx in zip(("home", "away"), centers):
        img = medallion((data.get("crests") or {}).get(side), str(data.get(side) or ""), (data.get("colors") or {}).get(side), box, u)
        layers.append({"image": img, "x": int(cx - img.width / 2), "y": int(crest_y - img.height / 2),
                       "motion": side, "delay": 0.0 if side == "home" else 0.05})
        rows = K.wrap_lines(draw, str(data.get(side) or ""), name_font, 520 * u, 2)
        for i, row in enumerate(rows):
            draw.text((cx, crest_y + box / 2 + 74 * u + i * name_font.size * 1.12), row, font=name_font, fill=_rgba(INK, 245), anchor="ms")

    count = int(data.get("clips") or 0)
    if count:
        big = _font(VOICE, 168 * u)
        draw.text((width / 2, crest_y + 52 * u), str(count), font=big, fill=_rgba(INK, 255), anchor="ms")
        small = _font(MEDIUM, 30 * u)
        word = (MR.plural(count, "klip", "klipy", "klipów") + " z meczu").upper()
        K._draw_tracked(draw, width / 2 - K._tracked_width(draw, word, small, small.size * 0.14) / 2, crest_y + 108 * u, word, small,
                        _rgba(INK, 200), small.size * 0.14)

    total = int(data.get("total") or 0)
    number = int(data.get("number") or 0)
    if total > 1:
        dot, gap = 16 * u, 34 * u
        span = (total - 1) * gap
        for i in range(total):
            cx = width / 2 - span / 2 + i * gap
            fill = _rgba(CORAL, 255) if i + 1 == number else _rgba(INK, 90 if i + 1 > number else 170)
            d = dot * (1.25 if i + 1 == number else 1.0)
            text.alpha_composite(_pill((int(d), int(d)), fill), (int(cx - d / 2), int(height * 0.90 - d / 2)))
    text = _shadowed(text, u)
    return {"background": background, "text": text, "layers": layers, "unit": u}


# ─── Belka klipu ────────────────────────────────────────────────────────────


def compose_bar(frame: Optional[Any], data: Mapping[str, Any], width: int, height: int) -> Dict[str, Any]:
    """Belka przed klipem: pierwsza klatka klipu rozmyta i przyciemniona (przenikanie w ruchomy klip „wyostrza” obraz),
    na niej minuta, połowa, etykieta i kategoria, tytuł, mecz; w rogu numer klipu. Tekst dojeżdża lekko od dołu."""
    from PIL import Image, ImageDraw, ImageFilter

    u = unit(width, height)
    if frame is not None:
        base = frame.convert("RGB").resize((width, height), Image.BILINEAR)
        small = base.resize((max(16, width // 6), max(16, height // 6)), Image.BILINEAR).filter(ImageFilter.GaussianBlur(4))
        base = small.resize((width, height), Image.BICUBIC).filter(ImageFilter.GaussianBlur(max(2, 6 * u)))
    else:
        base = _bg(width, height, CORAL, (40, 60, 70), [(width * 0.2, height * 0.5, 0.4)])
    background = _darken(base, u)
    text = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(text)
    left = 140 * u

    minute = str(data.get("minute") or "")
    half = str(data.get("half") or "").upper()
    title = str(data.get("title") or "Klip")
    title_font, title_rows = _wrap_fit(draw, BOLD, title, ((76 * u, 2), (64 * u, 2), (54 * u, 3)), 1320 * u)
    minute_font = _font(VOICE, 168 * u)
    chips = _chips(data, u)
    chip_h = max((c.height for c in chips), default=0)
    title_h = title_font.size * 1.12 * len(title_rows)
    block = (minute_font.size * 0.80 if minute else 0) + (36 * u if minute else 0) + (chip_h + 30 * u if chips else 0) + title_h + 100 * u
    y = (height - block) / 2.0
    if minute:
        base_y = y + minute_font.size * 0.80
        draw.text((left - 6 * u, base_y), minute, font=minute_font, fill=_rgba(INK, 255), anchor="ls")
        if half:
            font = _font(MEDIUM, 30 * u)
            K._draw_tracked(draw, left + _text_w(draw, minute, minute_font) + 26 * u, base_y - 8 * u, half, font, _rgba(INK, 215), font.size * 0.16)
        y = base_y + 36 * u
    x = left
    for chip in chips:
        text.alpha_composite(chip, (int(x), int(y)))
        x += chip.width + 14 * u
    if chips:
        y += chip_h + 30 * u
    for row in title_rows:
        draw.text((left, y + title_font.size * 0.92), row, font=title_font, fill=_rgba(INK, 255), anchor="ls")
        y += title_font.size * 1.12
    y += 26 * u
    tile = code_tile(str(data.get("code") or ""), data.get("code_color"), u, 32)
    x = left
    if tile is not None:
        text.alpha_composite(tile, (int(x - 8 * u), int(y - 8 * u)))
        x += tile.width + 6 * u
    teams = " - ".join(p for p in (str(data.get("home") or ""), str(data.get("away") or "")) if p)
    if teams:
        font = _font(MEDIUM, 32 * u)
        draw.text((x, y + font.size * 0.98), K._ellipsize(draw, teams, font, 1100 * u), font=font, fill=_rgba(INK, 205), anchor="ls")

    position, total = int(data.get("position") or 0), int(data.get("total") or 0)
    if position and total:
        font = _font(VOICE, 96 * u)
        label = f"{position}/{total}"
        draw.text((width - 120 * u, height - 110 * u), label, font=font, fill=_rgba(INK, 120), anchor="rs")
    text = _shadowed(text, u, 0.6)
    return {"background": background, "text": text, "unit": u}


def _darken(image: Any, u: float) -> Any:
    """Przyciemnienie pod tekst: całość do ~40%, lewa strona (tekst) mocniej, lekka winieta. Szum przeciw pasmom H.264."""
    import numpy as np
    from PIL import Image

    arr = np.asarray(image.convert("RGB"), dtype="float32")
    h, w = arr.shape[:2]
    x = np.linspace(0.0, 1.0, w, dtype="float32")[None, :]
    y = np.linspace(0.0, 1.0, h, dtype="float32")[:, None]
    side = 0.30 + 0.22 * np.clip((x - 0.10) / 0.75, 0.0, 1.0)
    vignette = 1.0 - 0.30 * np.clip(np.sqrt(((x - 0.5) / 0.75) ** 2 + ((y - 0.5) / 0.75) ** 2), 0.0, 1.0) ** 2
    arr = arr * (side * vignette)[..., None] + 5.0
    rng = np.random.default_rng(20261112)
    arr += 1.1 * rng.standard_normal((h, w, 1), dtype="float32")
    return Image.fromarray(np.clip(arr, 0, 255).astype("uint8"), "RGB")


def _chips(data: Mapping[str, Any], u: float) -> List[Any]:
    """Etykieta zestawienia (pełna barwa tonu) i kategoria klipu (obrys w barwie kategorii)."""
    from PIL import Image, ImageDraw

    out = []
    font = _font(BOLD, 30 * u)
    tracking = font.size * 0.08
    pad_x, h = 22 * u, int(54 * u)
    probe = ImageDraw.Draw(Image.new("L", (4, 4)))
    label = str(data.get("label") or "").upper()
    if label:
        fill = K.parse_color(data.get("label_color")) or CORAL
        w = int(K._tracked_width(probe, label, font, tracking) + 2 * pad_x)
        chip = _pill((w, h), _rgba(fill, 255))
        K._draw_tracked(ImageDraw.Draw(chip), pad_x, h / 2 + font.size * 0.36, label, font, _rgba(K.on_color(fill), 255), tracking)
        out.append(chip)
    category = str(data.get("category") or "").upper()
    if category and category != label:
        ink = K.category_ink(data.get("category_color"))
        w = int(K._tracked_width(probe, category, font, tracking) + 2 * pad_x)
        chip = _pill((w, h), _rgba(GLASS, 150))
        ring = _pill((w, h), _rgba(ink, 255))
        inner = _pill((w - int(5 * u), h - int(5 * u)), (0, 0, 0, 255))
        cut = Image.new("L", (w, h), 0)
        cut.paste(inner.getchannel("A"), (int(2.5 * u), int(2.5 * u)))
        from PIL import ImageChops

        ring.putalpha(ImageChops.subtract(ring.getchannel("A"), cut))
        chip.alpha_composite(ring)
        K._draw_tracked(ImageDraw.Draw(chip), pad_x, h / 2 + font.size * 0.36, category, font, _rgba(ink, 255), tracking)
        out.append(chip)
    return out


# ─── Na klipie: licznik z etykietą i napis z notatką ────────────────────────


def compose_badge(position: int, total: int, label: str, label_color: Any, width: int, height: int) -> Any:
    """Szklana pigułka w prawym górnym rogu: „3 / 12” i (gdy jest) kropka z etykietą. Pełny kadr RGBA."""
    from PIL import Image, ImageDraw

    u = unit(width, height)
    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    probe = ImageDraw.Draw(out)
    num_font = _font(BOLD, 31 * u)
    lab_font = _font(MEDIUM, 28 * u)
    counter = f"{position} / {total}"
    label = MR.clean_text(label, MR.MAX_LABEL)
    pad, h = 24 * u, int(60 * u)
    w = _text_w(probe, counter, num_font) + 2 * pad
    if label:
        label = K._ellipsize(probe, label, lab_font, 520 * u)
        w += 18 * u + 16 * u + 12 * u + _text_w(probe, label, lab_font)
    pill = _pill((int(w), h), _rgba(GLASS, 150))
    draw = ImageDraw.Draw(pill)
    draw.text((pad, h / 2 + num_font.size * 0.36), counter, font=num_font, fill=_rgba(INK, 250), anchor="ls")
    if label:
        x = pad + _text_w(draw, counter, num_font) + 18 * u
        dot = int(16 * u)
        pill.alpha_composite(_pill((dot, dot), _rgba(K.parse_color(label_color) or CORAL, 255)), (int(x), int(h / 2 - dot / 2)))
        draw.text((x + dot + 12 * u, h / 2 + lab_font.size * 0.36), label, font=lab_font, fill=_rgba(INK, 235), anchor="ls")
    out.alpha_composite(pill, (int(width - 48 * u - pill.width), int(44 * u)))
    return out


def compose_note(note: str, width: int, height: int) -> Optional[Any]:
    """Napis na dole kadru (do trzech wierszy), na ciemnym szkle. None bez notatki."""
    from PIL import Image, ImageDraw

    text = MR.clean_text(note, MR.MAX_NOTE)
    if not text:
        return None
    u = unit(width, height)
    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    probe = ImageDraw.Draw(out)
    font, rows = _wrap_fit(probe, MEDIUM, text, ((40 * u, 2), (36 * u, 3), (32 * u, 3)), 1440 * u)
    line = font.size * 1.3
    box_w = max(_text_w(probe, r, font) for r in rows) + 64 * u
    box_h = line * len(rows) + 40 * u
    plate = _pill((int(box_w), int(box_h)), _rgba(GLASS, 168), radius=int(20 * u))
    draw = ImageDraw.Draw(plate)
    for i, row in enumerate(rows):
        draw.text((box_w / 2, 20 * u + line * i + font.size * 0.98), row, font=font, fill=_rgba(INK, 250), anchor="ms")
    out.alpha_composite(plate, (int(width / 2 - box_w / 2), int(height - 64 * u - box_h)))
    return out


# ─── Spis klipów (koniec) ───────────────────────────────────────────────────


def compose_credits(data: Mapping[str, Any], width: int, height: int) -> Dict[str, Any]:
    """Koniec filmu: z lewej nazwa i liczby, z prawej spis klipów (numer, kafelek meczu, minuta, etykieta, tytuł).
    Dłuższy spis przewija się jak napisy końcowe; `viewport` i `list_h` mówią ffmpeg, ile przewinąć."""
    from PIL import Image, ImageDraw

    u = unit(width, height)
    rows = list(data.get("rows") or [])
    background = _bg(width, height, CORAL, (40, 52, 66), [(width * 0.18, height * 0.4, 0.40), (width * 0.75, height * 0.6, 0.35)])
    text = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(text)
    left = 132 * u
    title_font, title_rows = _wrap_fit(draw, VOICE, str(data.get("name") or "Zestawienie"), ((100 * u, 2), (84 * u, 3), (70 * u, 4)), 640 * u)
    y = height * 0.30
    for row in title_rows:
        draw.text((left, y), row, font=title_font, fill=_rgba(INK, 255), anchor="ls")
        y += title_font.size * 1.02
    text.alpha_composite(_pill((int(96 * u), int(9 * u)), _rgba(CORAL, 255)), (int(left), int(y - 12 * u)))
    y += 50 * u
    info_font = _font(MEDIUM, 32 * u)
    for line in data.get("info") or []:
        draw.text((left, y), str(line), font=info_font, fill=_rgba(INK, 214), anchor="ls")
        y += info_font.size * 1.45
    brand = _font(MEDIUM, 26 * u)
    K._draw_tracked(draw, left, height - 64 * u, "BAZA · MENTOR", brand, _rgba(INK, 130), brand.size * 0.16)
    text = _shadowed(text, u, 0.5)

    row_h = 78 * u
    list_x = int(880 * u)
    list_w = int(width - list_x - 110 * u)
    top, bottom = int(120 * u), int(height - 110 * u)
    list_h = max(int(row_h * len(rows)), 1)
    image = Image.new("RGBA", (list_w, list_h), (0, 0, 0, 0))
    ldraw = ImageDraw.Draw(image)
    num_font = _font(VOICE, 44 * u)
    min_font = _font(BOLD, 31 * u)
    title_font2 = _font(MEDIUM, 31 * u)
    lab_font = _font(BOLD, 24 * u)
    for i, row in enumerate(rows):
        base = i * row_h + row_h * 0.62
        ldraw.text((0, base), f"{i + 1:02d}", font=num_font, fill=_rgba(CORAL, 255), anchor="ls")
        x = 92 * u
        tile = code_tile(str(row.get("code") or ""), row.get("code_color"), u, 26)
        if tile is not None:
            image.alpha_composite(tile, (int(x - 6 * u), int(base - tile.height * 0.80)))
            x += tile.width + 4 * u
        minute = str(row.get("minute") or "")
        if minute:
            ldraw.text((x, base), minute, font=min_font, fill=_rgba(INK, 250), anchor="ls")
            x += _text_w(ldraw, minute, min_font) + 22 * u
        label = str(row.get("label") or "").upper()
        if label:
            color = K.parse_color(row.get("label_color")) or CORAL
            label = K._ellipsize(ldraw, label, lab_font, 260 * u)
            ldraw.text((x, base - 2 * u), label, font=lab_font, fill=_rgba(color, 255), anchor="ls")
            x += _text_w(ldraw, label, lab_font) + 22 * u
        room = list_w - x
        title = K._ellipsize(ldraw, str(row.get("title") or "Klip"), title_font2, max(60 * u, room))
        ldraw.text((x, base), title, font=title_font2, fill=_rgba(INK, 222), anchor="ls")
        if i + 1 < len(rows):
            ldraw.line([(0, (i + 1) * row_h), (list_w, (i + 1) * row_h)], fill=_rgba(INK, 26), width=max(1, int(1.5 * u)))
    viewport = bottom - top
    start_y = top if list_h > viewport else int(top + (viewport - list_h) / 2)
    return {"background": background, "text": text, "list": image, "list_x": list_x, "list_y": start_y,
            "viewport": (top, bottom), "list_h": list_h, "unit": u, "fade_h": int(70 * u)}


def credit_masks(background: Any, viewport: Tuple[int, int], list_x: int, fade_h: int) -> Tuple[Any, Any]:
    """Pasy tła nad i pod oknem spisu z miękkim przejściem: wiersze wjeżdżają i znikają łagodnie, a nie ucięte."""
    from PIL import Image

    top, bottom = viewport
    w = background.width - list_x
    upper = background.crop((list_x, 0, background.width, top + fade_h)).convert("RGBA")
    lower = background.crop((list_x, bottom - fade_h, background.width, background.height)).convert("RGBA")
    ramp_up = Image.new("L", (1, upper.height))
    for y in range(upper.height):
        ramp_up.putpixel((0, y), 255 if y < top else int(255 * (1 - (y - top) / max(1, fade_h))))
    upper.putalpha(ramp_up.resize((w, upper.height)))
    ramp_down = Image.new("L", (1, lower.height))
    for y in range(lower.height):
        ramp_down.putpixel((0, y), 255 if y >= fade_h else int(255 * (y / max(1, fade_h))))
    lower.putalpha(ramp_down.resize((w, lower.height)))
    return upper, lower


# ─── Pomocnicze ─────────────────────────────────────────────────────────────


def flatten(composition: Mapping[str, Any]) -> Any:
    """Stan po ustaniu ruchu jako jeden obraz RGB (okładka-miniatura, ogon okładki, podgląd)."""
    frame = composition["background"].convert("RGBA")
    frame.alpha_composite(composition["text"])
    for layer in composition.get("layers") or []:
        frame.alpha_composite(layer["image"].convert("RGBA"), (max(0, int(layer["x"])), max(0, int(layer["y"]))))
    if composition.get("list") is not None:
        frame.alpha_composite(composition["list"], (int(composition["list_x"]), int(composition["list_y"])))
    return frame.convert("RGB")
