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
from app.team_flags import is_flag

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
    return K._crest_with_light(K.crest_or_flag(raw, name, K.parse_color(color), box), u)


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
    flag = K.flag_tile(raw, inner.width, inner.height, inner.width / 2, gloss=0.16, shade=0.12) if raw and is_flag(raw) else None
    if flag is not None:
        # Reprezentacja: flaga na całą tarczę medalionu (jak w aplikacji), bez znaku w środku.
        plate.alpha_composite(flag, (ring_w, ring_w))
        out.alpha_composite(plate, (pad, pad))
        return out
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
#
# Plakat 13.11.2026 (zamiast koła-poświaty i liczb z kapitalikowymi podpisami): po lewej nazwa i jedno zdanie z liczbami
# wpisanymi w tekst, po prawej skośny panel w kropki z pasem barw meczów na krawędzi, a w nim mecze w układzie zależnym od ich
# liczby (1: pojedynek dwóch kamyków z herbami, 2-4: pas pojedynków, 5+: siatka par), na dole taśma filmowa z kadrami klipów,
# każdy kadr podkreślony barwą swojego meczu (ta sama paleta co przebieg filmu w aplikacji).
# Geometria w jednostkach kadru 1920x1080 jest lustrem `POSTER` w BAZA/components/mentorPanel/montage/MontageStudio.tsx.

#: Barwy meczów w kolejności pierwszego pojawienia się - lustro `MATCH_HUES` (BAZA components/mentorPanel/theme.ts).
MATCH_HUES = ("#FF7A59", "#8FBCC8", "#E9C46A", "#6CC79A", "#B4A3E8", "#EE8CB0", "#7FC0E4", "#F4A26B")
PANEL_TOP_X, PANEL_BOTTOM_X, PANEL_BOTTOM = 1090, 990, 780
STAGE_X, STAGE_Y, STAGE_W, STAGE_H = 1110, 110, 740, 620
TITLE_X, TITLE_W = 110, 840
STRIP_TOP, STRIP_H = 822, 218
FRAME_X, FRAME_W, FRAME_H, FRAME_GAP = 110, 235, 132, 16
FRAME_SLOTS = 7
GRID_MAX = 12
#: Tło: ciepły koral z lewej, granat z prawej, niezależnie od drużyn (podgląd w aplikacji ma to samo, `POSTER_GRADIENT`).
BG_WARM, BG_NAVY = CORAL, (43, 76, 155)
#: Do tylu klipów nie ma taśmy: kadry stają się tłem całej okładki (pionowe pasy), panel i tytuł zajmują pełną wysokość.
BACKDROP_MAX = 3
PANEL_FULL_BOTTOM_X = 952
STONE_LIGHT = ((255, 251, 248), (226, 214, 207))
STONE_DARK = ((43, 35, 32), (20, 16, 16))


def match_hue(index: int) -> Tuple[int, int, int]:
    return K.parse_color(MATCH_HUES[index % len(MATCH_HUES)]) or CORAL


def frame_count(clips: int) -> int:
    """Ile kadrów pokazuje taśma: wszystkie, gdy się mieszczą, inaczej o jeden mniej, a ostatnie okienko to „+N”."""
    return clips if clips <= FRAME_SLOTS else FRAME_SLOTS - 1


STRIP_SPAN = FRAME_SLOTS * FRAME_W + (FRAME_SLOTS - 1) * FRAME_GAP


def frame_box(index: int, slots: int) -> Tuple[float, float]:
    """(x, szerokość) okienka taśmy: okienka wypełniają taśmę, ile by ich nie było (bez pustych miejsc); przy 7 = 235 jednostek."""
    w = (STRIP_SPAN - (slots - 1) * FRAME_GAP) / float(max(1, slots))
    return FRAME_X + index * (w + FRAME_GAP), w


def backdrop(clips: int) -> bool:
    return clips <= BACKDROP_MAX


def cover_layout(matches: int) -> str:
    return "duel" if matches <= 1 else "rows" if matches <= 4 else "grid"


def grid_shape(matches: int) -> Tuple[int, int, int]:
    """(kolumny, wiersze, ile meczów rysujemy); przy więcej niż 12 ostatnia komórka to „+N”."""
    cols = 3 if matches <= 6 else 4
    cells = min(matches, GRID_MAX)
    shown = matches if matches <= GRID_MAX else GRID_MAX - 1
    return cols, -(-cells // cols), shown


def cover_sentence(clips: int, matches: int, film_s: float) -> List[List[Tuple[str, str]]]:
    """Liczby wpisane w zdanie: grupy przebiegów (tekst, „n” = liczba głosem / „w” = słowo treścią)."""
    first = [(str(clips), "n"), (" " + MR.plural(clips, "klip", "klipy", "klipów"), "w")]
    if matches > 1:
        first += [(" z ", "w"), (str(matches), "n"), (" meczów", "w")]
    seconds = max(0, int(round(film_s)))
    second = [(str(seconds), "n"), (" s filmu", "w")] if seconds < 60 else [(MR.duration_label(seconds), "n"), (" min filmu", "w")]
    return [first, second]


def cover_data(name: str, description: str, matches: Sequence[Mapping[str, Any]], clips: int, film_s: float,
               clip_matches: Optional[Sequence[int]] = None, frames: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
    """`matches`: [{home, away, code, code_color, date, competition, crests:{home,away}, colors:{home,away}}] w kolejności filmu;
    `clip_matches`: numer meczu (0..) każdego klipu w kolejności filmu; `frames`: kadry (PIL albo None) pierwszych klipów."""
    return {"name": MR.clean_text(name, MR.MAX_NAME) or "Zestawienie", "description": MR.clean_text(description, MR.MAX_DESCRIPTION),
            "matches": list(matches), "clips": int(clips), "film_s": float(film_s), "clip_matches": list(clip_matches or []),
            "frames": list(frames or [])}


def _rounded_mask(w: int, h: int, radius: float) -> Any:
    from PIL import Image, ImageDraw

    k = 3
    mask = Image.new("L", (w * k, h * k), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w * k - 1, h * k - 1], radius=int(radius * k), fill=255)
    return mask.resize((w, h), Image.LANCZOS)


def _vertical(w: int, h: int, top: Sequence[int], bottom: Sequence[int]) -> Any:
    from PIL import Image, ImageDraw

    out = Image.new("RGBA", (w, h))
    rows = ImageDraw.Draw(out)
    for y in range(h):
        rows.line([(0, y), (w, y)], fill=_rgba(K._mix(top, bottom, y / float(max(1, h - 1))), 255))
    return out


def stone(raw: Optional[bytes], name: str, color: Any, size: float, u: float) -> Any:
    """Herb na kamyku jak `Pebble` w aplikacji: jasny ciepły kamień pod logo (herby projektuje się na biel), bez logo ciemny
    kamyk z tarczą z inicjałami, reprezentacja to sama flaga. Cień pod spodem, żadnej poświaty. Mały herb zostaje mały - nie rozciągamy źródeł 50x50."""
    from PIL import Image

    s = max(12, int(size))
    flag = K.flag_tile(raw, s, s, s * 0.30, gloss=0.10, shade=0.30) if raw and is_flag(raw) else None
    crest = K.prepare_crest(raw, int(s * 0.74)) if raw and flag is None else None
    top, bottom = STONE_LIGHT if crest is not None else STONE_DARK
    plate = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    if flag is not None:
        # Reprezentacja: kamyk to sama flaga z połyskiem u góry i cieniem u dołu (`Pebble` + `CountryFlag` w aplikacji).
        plate.alpha_composite(flag)
    else:
        plate.paste(_vertical(s, s, top, bottom), (0, 0), _rounded_mask(s, s, s * 0.30))
        if crest is None:
            crest = K.shield_crest(name, K.parse_color(color), int(s * 0.64))
        plate.alpha_composite(crest, (int(s / 2 - crest.width / 2), int(s / 2 - crest.height / 2)))
    pad = int(max(6, s * 0.16))
    out = Image.new("RGBA", (s + 2 * pad, s + 2 * pad), (0, 0, 0, 0))
    out.alpha_composite(plate, (pad, pad))
    return K._shadow(out, max(2.0, s * 0.06), max(1, int(s * 0.05)), 0.55)


def _place(canvas: Any, layer: Any, cx: float, cy: float) -> None:
    canvas.alpha_composite(layer, (int(cx - layer.width / 2), int(cy - layer.height / 2)))


def _hue_bar(w: float, h: float, hue: Sequence[int]) -> Any:
    return _pill((int(w), int(max(2, h))), _rgba(hue, 255))


def _team_stone(match: Mapping[str, Any], side: str, size: float, u: float) -> Any:
    return stone((match.get("crests") or {}).get(side), str(match.get(side) or ""), (match.get("colors") or {}).get(side), size, u)


def _duel_parts(match: Mapping[str, Any], hue: Sequence[int], u: float) -> Tuple[Any, Any, Any]:
    """Jeden mecz: kamyki gospodarza i gościa (osobne warstwy, dojeżdżają z boków) i nieruchomy środek (numer, nazwy, data)."""
    from PIL import Image, ImageDraw

    w, h = int(STAGE_W * u), int(STAGE_H * u)
    size = 240 * u
    home = _team_stone(match, "home", size, u)
    away = _team_stone(match, "away", size, u)
    mid = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(mid)
    tile = code_tile(str(match.get("code") or ""), match.get("code_color"), u, 44)
    if tile is not None:
        _place(mid, tile, w / 2, 70 * u)
    _place(mid, _hue_bar(84 * u, 12 * u, hue), w / 2, 290 * u)
    name_font = _font(BOLD, 34 * u)
    for side, cx in (("home", 170 * u), ("away", 570 * u)):
        rows = K.wrap_lines(draw, str(match.get(side) or ""), name_font, 330 * u, 2)
        for i, row in enumerate(rows):
            draw.text((cx, 470 * u + i * name_font.size * 1.16), row, font=name_font, fill=_rgba(INK, 240), anchor="ms")
    info = "  ·  ".join(p for p in (str(match.get("competition") or ""), str(match.get("date") or "")) if p)
    if info:
        font = _font(MEDIUM, 28 * u)
        draw.text((w / 2, 600 * u), K._ellipsize(draw, info, font, 700 * u), font=font, fill=_rgba(INK, 190), anchor="ms")
    return home, away, mid


def _duel_row(match: Mapping[str, Any], hue: Sequence[int], u: float, row_h: float) -> Any:
    """Pas pojedynków: barwa meczu z lewej, kamyk - numer z datą - kamyk."""
    from PIL import Image, ImageDraw

    w, h = int(STAGE_W * u), int(row_h)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.alpha_composite(_hue_bar(10 * u, h * 0.6, hue), (0, int(h * 0.2)))
    size = h * 0.64
    home_cx, away_cx = 60 * u + size / 2, w - size / 2 - 6 * u
    _place(out, _team_stone(match, "home", size, u), home_cx, h / 2)
    _place(out, _team_stone(match, "away", size, u), away_cx, h / 2)
    mid = (home_cx + away_cx) / 2
    tile = code_tile(str(match.get("code") or ""), match.get("code_color"), u, 36)
    date = str(match.get("date") or "")
    draw = ImageDraw.Draw(out)
    if tile is not None:
        _place(out, tile, mid, h / 2 - (16 * u if date else 0))
    if date:
        font = _font(MEDIUM, 25 * u)
        draw.text((mid, h / 2 + (44 if tile is not None else 10) * u), date, font=font, fill=_rgba(INK, 200), anchor="ms")
    return out


def _grid_cell(match: Optional[Mapping[str, Any]], hue: Sequence[int], u: float, cw: float, ch: float, more: int = 0) -> Any:
    """Komórka siatki: para kamyków na zakładkę, pod nią barwa meczu i numer; albo „+N meczów”."""
    from PIL import Image, ImageDraw

    w, h = int(cw), int(ch)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(out)
    if match is None:
        big = _font(VOICE, 84 * u)
        small = _font(MEDIUM, 26 * u)
        draw.text((w / 2, h / 2 + 8 * u), f"+{more}", font=big, fill=_rgba(INK, 235), anchor="ms")
        draw.text((w / 2, h / 2 + 48 * u), MR.plural(more, "mecz", "mecze", "meczów"), font=small, fill=_rgba(INK, 190), anchor="ms")
        return out
    size = min(cw * 0.40, ch * 0.46)
    cy = size / 2 + h * 0.08
    _place(out, _team_stone(match, "home", size, u), w / 2 - size * 0.36, cy)
    _place(out, _team_stone(match, "away", size, u), w / 2 + size * 0.36, cy + size * 0.06)
    bar_y = cy + size * 0.62
    out.alpha_composite(_hue_bar(size * 1.3, 8 * u, hue), (int(w / 2 - size * 0.65), int(bar_y)))
    tile = code_tile(str(match.get("code") or ""), match.get("code_color"), u, 26)
    if tile is not None and bar_y + 20 * u + tile.height <= h + 6 * u:
        _place(out, tile, w / 2, bar_y + 20 * u + tile.height / 2)
    return out


def _placeholder(w: int, h: int, hue: Sequence[int], u: float) -> Any:
    """Kadr, którego nie udało się wyjąć: barwa meczu w ukośnych pasach i znak odtwarzania (nie czarna dziura)."""
    from PIL import Image, ImageDraw

    art = _vertical(w, h, K._mix(hue, (12, 10, 8), 0.45), K._mix(hue, (12, 10, 8), 0.82))
    lines = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(lines)
    step = max(6, int(22 * u))
    for x in range(-h, w, step):
        draw.line([(x, h), (x + h, 0)], fill=(255, 255, 255, 18), width=max(1, int(3 * u)))
    art.alpha_composite(lines)
    r = min(w, h) * 0.16
    cx, cy = w / 2, h / 2
    ImageDraw.Draw(art).polygon([(cx - r * 0.6, cy - r), (cx - r * 0.6, cy + r), (cx + r, cy)], fill=(255, 255, 255, 150))
    return art


def _frame_cell(frame: Optional[Any], number: int, hue: Sequence[int], u: float, box_w: float = FRAME_W) -> Any:
    """Okienko taśmy: kadr klipu przycięty do 16:9, barwa meczu na dole, numer klipu w rogu. Bez kadru: ciemne okienko z numerem."""
    from PIL import Image, ImageDraw, ImageOps

    w, h = int(box_w * u), int(FRAME_H * u)
    if frame is not None:
        art = ImageOps.fit(frame.convert("RGB"), (w, h), Image.LANCZOS).convert("RGBA")
    else:
        art = _placeholder(w, h, hue, u)
    art.alpha_composite(Image.new("RGBA", (w, int(9 * u) or 1), _rgba(hue, 255)), (0, h - (int(9 * u) or 1)))
    font = _font(BOLD, 22 * u)
    probe = ImageDraw.Draw(art)
    label = str(number)
    pill = _pill((int(max(34 * u, _text_w(probe, label, font) + 18 * u)), int(34 * u)), (12, 10, 8, 200), int(9 * u))
    ImageDraw.Draw(pill).text((pill.width / 2, pill.height / 2), label, font=font, fill=_rgba(INK, 255), anchor="mm")
    art.alpha_composite(pill, (int(8 * u), int(8 * u)))
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(art, (0, 0), _rounded_mask(w, h, 10 * u))
    return out


def _more_frames(more: int, u: float) -> Any:
    from PIL import Image, ImageDraw

    w, h = int(FRAME_W * u), int(FRAME_H * u)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(Image.new("RGBA", (w, h), _rgba(CORAL, 52)), (0, 0), _rounded_mask(w, h, 10 * u))
    draw = ImageDraw.Draw(out)
    draw.text((w / 2, h / 2 + 4 * u), f"+{more}", font=_font(VOICE, 70 * u), fill=_rgba(INK, 240), anchor="ms")
    draw.text((w / 2, h / 2 + 40 * u), MR.plural(more, "klip", "klipy", "klipów"), font=_font(MEDIUM, 24 * u), fill=_rgba(INK, 200), anchor="ms")
    return out


def _cover_art(width: int, height: int, hues: Sequence[Sequence[int]], frames_used: int, u: float, full: bool = False) -> Any:
    """Nieruchoma grafika: skośny panel w kropki z pasem barw meczów na krawędzi i taśma filmowa z perforacją."""
    from PIL import Image, ImageChops, ImageDraw

    k = 2
    bottom, bottom_x = (1080, PANEL_FULL_BOTTOM_X) if full else (PANEL_BOTTOM, PANEL_BOTTOM_X)
    art = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    panel = [(PANEL_TOP_X * u * k, 0), (width * k, 0), (width * k, bottom * u * k), (bottom_x * u * k, bottom * u * k)]
    mask = Image.new("L", (width * k, height * k), 0)
    ImageDraw.Draw(mask).polygon(panel, fill=255)
    mask = mask.resize((width, height), Image.LANCZOS)
    shade = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    shade.paste(Image.new("RGBA", (width, height), (0, 0, 0, 74)), (0, 0), mask)
    dots = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(dots)
    step, r = 34 * u, max(1.0, 2.6 * u)
    y = step / 2
    while y < bottom * u:
        x = bottom_x * u
        while x < width:
            draw.ellipse([x - r, y - r, x + r, y + r], fill=(255, 255, 255, 30))
            x += step
        y += step
    dots.putalpha(ImageChops.multiply(dots.getchannel("A"), mask))
    shade.alpha_composite(dots)
    art.alpha_composite(shade)
    layer = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    for i, hue in enumerate(list(hues)[:len(MATCH_HUES)] or [CORAL]):
        right, left = PANEL_TOP_X - 14 * i - 4, PANEL_TOP_X - 14 * (i + 1)
        shift = bottom_x - PANEL_TOP_X
        one = Image.new("L", (width * k, height * k), 0)
        ImageDraw.Draw(one).polygon([(left * u * k, 0), (right * u * k, 0), ((right + shift) * u * k, bottom * u * k),
                                     ((left + shift) * u * k, bottom * u * k)], fill=255)
        one = one.resize((width, height), Image.LANCZOS)
        layer.paste(Image.new("RGBA", (width, height), _rgba(hue, 255)), (0, 0), one)
    art.alpha_composite(layer)
    if full:
        return art
    band = ImageDraw.Draw(art)
    band.rectangle([0, STRIP_TOP * u, width, (STRIP_TOP + STRIP_H) * u], fill=(8, 6, 5, 150))
    hole_w, hole_h, pitch = 20 * u, 12 * u, 40 * u
    x = 24 * u
    hole = _pill((int(hole_w), int(hole_h)), (255, 255, 255, 40), int(3 * u))
    while x < width:
        for hy in (STRIP_TOP + 14, STRIP_TOP + STRIP_H - 26):
            art.alpha_composite(hole, (int(x), int(hy * u)))
        x += pitch
    return art


def _backdrop(background: Any, frames: Sequence[Any], hues: Sequence[Sequence[int]], u: float) -> Any:
    """Kilka klipów: kadry jako tło całej okładki (pionowe pasy w kolejności filmu), przykryte gradientem tła tak, żeby tytuł
    i panel były czytelne; pod każdym pasem barwa jego meczu, a przy 2-3 klipach numer klipu."""
    from PIL import Image, ImageDraw, ImageOps

    width, height = background.size
    n = max(1, len(frames))
    photo = Image.new("RGB", (width, height))
    for i, frame in enumerate(frames):
        x0, x1 = int(width * i / n), int(width * (i + 1) / n)
        part = ImageOps.fit(frame.convert("RGB"), (x1 - x0, height), Image.LANCZOS) if frame is not None else             _placeholder(x1 - x0, height, hues[i], u).convert("RGB")
        photo.paste(part, (x0, 0))
    out = Image.blend(photo, background.convert("RGB"), 0.74).convert("RGBA")
    draw = ImageDraw.Draw(out)
    font = _font(BOLD, 24 * u)
    for i, hue in enumerate(hues):
        x0, x1 = int(width * i / n), int(width * (i + 1) / n)
        draw.rectangle([x0, height - int(12 * u), x1 - (int(4 * u) if i < n - 1 else 0), height], fill=_rgba(hue, 255))
        if n > 1:
            label = str(i + 1)
            pill = _pill((int(max(38 * u, _text_w(draw, label, font) + 20 * u)), int(38 * u)), (12, 10, 8, 190), int(10 * u))
            ImageDraw.Draw(pill).text((pill.width / 2, pill.height / 2), label, font=font, fill=_rgba(INK, 255), anchor="mm")
            out.alpha_composite(pill, (x0 + int(24 * u), height - int(70 * u)))
    return out.convert("RGB")


def compose_cover(data: Mapping[str, Any], width: int, height: int) -> Dict[str, Any]:
    """Okładka: nazwa i zdanie z liczbami po lewej, mecze w skośnym panelu po prawej (układ od liczby meczów), taśma kadrów
    na dole. Kamyki, komórki i kadry dojeżdżają po kolei; klatka 0 i stan po ruchu są kompletne (to też miniatura pliku)."""
    from PIL import Image, ImageDraw

    u = unit(width, height)
    matches = list(data.get("matches") or [])
    hues = [match_hue(i) for i in range(len(matches))]
    background = _bg(width, height, BG_WARM, BG_NAVY, [])
    clips = int(data.get("clips") or 0)
    full = clips > 0 and backdrop(clips)
    shown_frames = frame_count(clips)
    frames = list(data.get("frames") or [])
    owners = list(data.get("clip_matches") or [])

    def hue_of(i: int) -> Tuple[int, int, int]:
        return hues[owners[i]] if i < len(owners) and 0 <= owners[i] < len(hues) else CORAL

    if full:
        background = _backdrop(background, [frames[i] if i < len(frames) else None for i in range(clips)], [hue_of(i) for i in range(clips)], u)
    art = _cover_art(width, height, hues, shown_frames + (1 if clips > shown_frames else 0), u, full)
    column_h = 1080 if full else PANEL_BOTTOM

    text = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(text)
    left, col_w = TITLE_X * u, TITLE_W * u
    name = str(data.get("name") or "Zestawienie")
    title_font, rows = _wrap_fit(draw, VOICE, name, ((132 * u, 2), (112 * u, 2), (96 * u, 3), (84 * u, 3)), col_w)
    line = title_font.size * 1.04
    num_font, word_font = _font(VOICE, 92 * u), _font(MEDIUM, 40 * u)
    sentence_lines: List[List[Tuple[str, str]]] = []
    for group in cover_sentence(clips, len(matches), float(data.get("film_s") or 0)):
        width_of = sum(_text_w(draw, t, num_font if kind == "n" else word_font) for t, kind in group)
        if sentence_lines and sum(_text_w(draw, t, num_font if kd == "n" else word_font) for t, kd in sentence_lines[-1]) + 70 * u + width_of <= col_w:
            sentence_lines[-1] = sentence_lines[-1] + [("  ·  ", "w")] + group
        else:
            sentence_lines.append(list(group))
    sentence_line = num_font.size * 1.12
    desc = str(data.get("description") or "")
    desc_font = _font(REGULAR, 34 * u)
    desc_rows = K.wrap_lines(draw, desc, desc_font, col_w, 2) if desc else []
    block = line * len(rows) + 40 * u + sentence_line * len(sentence_lines) + (24 * u + len(desc_rows) * desc_font.size * 1.3 if desc_rows else 0)
    y = max(96 * u, (column_h * u - block) / 2.0)
    for row in rows:
        draw.text((left, y + title_font.size * 0.86), row, font=title_font, fill=_rgba(INK, 255), anchor="ls")
        y += line
    y += 40 * u
    for runs in sentence_lines:
        x, base = left, y + num_font.size * 0.86
        for t, kind in runs:
            font = num_font if kind == "n" else word_font
            draw.text((x, base), t, font=font, fill=_rgba(INK, 255 if kind == "n" else 205), anchor="ls")
            x += _text_w(draw, t, font)
        y += sentence_line
    if desc_rows:
        y += 24 * u
        for row in desc_rows:
            draw.text((left, y + desc_font.size * 0.9), row, font=desc_font, fill=_rgba(INK, 200), anchor="ls")
            y += desc_font.size * 1.3
    brand = _font(MEDIUM, 24 * u)
    draw.text(((STAGE_X + STAGE_W) * u, 70 * u), "BAZA Mentor", font=brand, fill=_rgba(INK, 120), anchor="rs")

    layers: List[Dict[str, Any]] = []
    sx, sy = STAGE_X * u, (STAGE_Y + (1080 - PANEL_BOTTOM) / 2 if full else STAGE_Y) * u
    kind = cover_layout(len(matches))
    if matches and kind == "duel":
        home, away, mid = _duel_parts(matches[0], hues[0], u)
        text.alpha_composite(mid, (int(sx), int(sy)))
        for side, img, cx in (("home", home, 170), ("away", away, 570)):
            layers.append({"image": img, "x": int(sx + cx * u - img.width / 2), "y": int(sy + 290 * u - img.height / 2), "motion": side,
                           "delay": 0.10 if side == "home" else 0.16})
    elif kind == "rows":
        row_h = min(190.0, STAGE_H / len(matches)) * u
        y0 = sy + (STAGE_H * u - row_h * len(matches)) / 2
        for i, m in enumerate(matches):
            layers.append({"image": _duel_row(m, hues[i], u, row_h), "x": int(sx), "y": int(y0 + i * row_h), "delay": 0.10 + i * STAGGER_S})
    elif kind == "grid":
        cols, grid_rows, shown = grid_shape(len(matches))
        cw = STAGE_W * u / cols
        ch = min(STAGE_H / grid_rows, 240.0) * u
        y0 = sy + (STAGE_H * u - ch * grid_rows) / 2
        cells = [(m, hues[i]) for i, m in enumerate(matches[:shown])]
        for i in range(min(len(matches), GRID_MAX)):
            r, c = divmod(i, cols)
            m, hue = cells[i] if i < len(cells) else (None, CORAL)
            img = _grid_cell(m, hue, u, cw, ch, len(matches) - shown)
            layers.append({"image": img, "x": int(sx + c * cw), "y": int(y0 + r * ch), "delay": min(0.6, 0.08 + i * 0.045)})

    fy = (STRIP_TOP + (STRIP_H - FRAME_H) / 2) * u
    slots = shown_frames + (1 if clips > shown_frames else 0)
    for i in range(0 if full else shown_frames):
        x, box_w = frame_box(i, slots)
        img = _frame_cell(frames[i] if i < len(frames) else None, i + 1, hue_of(i), u, box_w)
        layers.append({"image": img, "x": int(x * u), "y": int(fy), "motion": "rise",
                       "delay": 0.30 + i * 0.06})
    if not full and clips > shown_frames:
        layers.append({"image": _more_frames(clips - shown_frames, u), "x": int(frame_box(shown_frames, slots)[0] * u),
                       "y": int(fy), "motion": "rise", "delay": 0.30 + shown_frames * 0.06})

    art.alpha_composite(_shadowed(text, u, 0.5))
    return {"background": background, "text": art, "layers": layers, "unit": u}


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
