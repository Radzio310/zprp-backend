"""
Karta podglądu linku formularza okręgowego - `og:image` dla Messengera, WhatsAppa, iMessage,
Telegrama, Signala (docs/formularze-okregowe.md §19).

Link `https://www.bazapodreka.app/f/<kod>` wklejony w komunikatorze ma się rozwinąć w dużą
kartę 1200 × 630 (proporcja 1.91:1 - szeroki podgląd w każdym komunikatorze): grafika
spiętego wydarzenia albo barwa okładki formularza, tytuł głosem aplikacji (Fontastique PL),
pod nim rodzaj i województwo (Geist), termin i zachęta w pigułkach, znak BAZA pod RĘKĄ.
Wzór: karta linku Communio (`Communio_serwer/app/link_card.py`).

Trzy układy:
  · okładka - grafika tytułowa wydarzenia na całą kartę, ciemny welon od lewej i od dołu,
    tekst w lewym dolnym rogu, znak BAZA u góry. Grafika, której nie da się pobrać albo
    odczytać, NIE psuje karty: wraca układ barwy, a taka karta zostaje w pamięci tylko
    na minutę (seria pytań jednego komunikatora), potem serwer spróbuje grafiki jeszcze raz,
  · barwa - gradient nocy w tonie okładki (`cover_json.tone`), światła hali, duży kafel
    z emoji okładki (Noto Color Emoji, gdy jest na serwerze) albo znakiem rodzaju
    rysowanym wektorowo - nigdy pustej ramki zamiast znaku,
  · marka - nieznany kod (literówka w linku): sam znak BAZA pod RĘKĄ, karta i tak się rozwija.

Bez nadtytułów nad tytułem (decyzja właściciela): rodzaj i województwo stoją POD tytułem.

Rysujemy w 2× i zmniejszamy (gładkie krawędzie), wynik trzymamy w małej pamięci procesu
(LRU, klucz = skrót treści karty) - komunikator pyta o obrazek kilka razy w sekundzie.
Kroje: Geist (OFL, informacja o licencji w tabeli `name` plików) i Fontastique PL - krój
aplikacji właściciela, tu tylko do rysowania jego własnych kart.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import os
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont, ImageOps

logger = logging.getLogger("district_form_card")

W, H = 1200, 630
_S = 2  # rysujemy w 2x i zmniejszamy
JPEG_QUALITY = 86
CACHE_MAX = 64
#: Grafika wydarzenia: najwyżej tyle bajtów i pikseli (ochrona przed bombą dekompresji).
PHOTO_MAX_BYTES = 12 * 1024 * 1024
PHOTO_MAX_PIXELS = 40_000_000
PHOTO_TIMEOUT_S = 4.0

_HERE = Path(__file__).parent
_FONTS = _HERE / "fonts"
_LOCKUP = _HERE / "data" / "baza-pod-reka-jasny.png"
_EMOJI_FONTS = (
    Path("/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf"),
    Path("/usr/share/fonts/noto/NotoColorEmoji.ttf"),
)

RGB = Tuple[int, int, int]

#: Paleta „Noc i złoto" (BAZA_web components/pod-reka/ds/tokens.ts, motyw ciemny).
NIGHT: RGB = (15, 14, 12)
CREAM: RGB = (255, 248, 234)
TEXT: RGB = (243, 235, 221)
MUTED: RGB = (179, 167, 146)
#: Ton okładki na nocnym hero - jak `toneColor(palettes.dark, tone)` w components/districtForm/css.ts.
TONES = {
    "gold": (217, 180, 90),
    "red": (229, 115, 95),
    "blue": (143, 188, 200),
    "green": (108, 199, 154),
    "violet": (180, 163, 232),
    "slate": (179, 167, 146),
}

_CACHE: "OrderedDict[str, bytes]" = OrderedDict()
#: Karta zastępcza (grafika nie przyszła) żyje krótko: seria pytań jednego komunikatora nie pobiera
#: grafiki dziesięć razy, a następne udostępnienie po minucie spróbuje pełnej karty jeszcze raz.
_STANDIN: "OrderedDict[str, Tuple[float, bytes]]" = OrderedDict()
STANDIN_TTL_S = 60.0
#: FreeType nie lubi jednej czcionki w dwóch wątkach naraz - rysujemy po jednej karcie.
_LOCK = threading.Lock()


@dataclass(frozen=True)
class CardData:
    """Wszystko, co widać na karcie (skrót z tych pól to wersja `?v=`)."""

    title: str
    kind: str = "list"              # "list" | "form" - znak na kaflu bez emoji
    meta: str = ""                  # „Lista deklaracji · Śląskie" (pod tytułem)
    status: str = ""                # „Zapisy do wt. 9 grudnia, 23:59" | „Zamknięte" | ""
    closed: bool = False
    cta: str = ""                   # „Odpowiedz w aplikacji BAZA" (pusta = bez pigułki)
    tone: str = "gold"
    emoji: Optional[str] = None
    photo: Optional[str] = None     # tożsamość grafiki (adres + mtime) - tylko do skrótu
    brand: bool = False             # nieznany kod: karta samej marki


def version(card: CardData) -> str:
    """Wersja karty do `?v=` - zmienia się, gdy zmienia się cokolwiek, co na niej widać."""
    raw = json.dumps({**asdict(card), "_": "v1"}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Kroje i tekst
# ---------------------------------------------------------------------------


@lru_cache(maxsize=64)
def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(_FONTS / name), size * _S)


def _geist(weight: str, size: int) -> ImageFont.FreeTypeFont:
    return _font(f"Geist-{weight}.ttf", size)


@lru_cache(maxsize=1)
def _display_notdef() -> Tuple[Tuple[int, int], bytes]:
    return _glyph_bits(_font("FontastiquePL.ttf", 40), "\ue000")  # prywatny znak = zawsze .notdef


def _glyph_bits(font: ImageFont.FreeTypeFont, char: str) -> Tuple[Tuple[int, int], bytes]:
    mask = font.getmask(char)
    img = Image.new("L", mask.size)
    img.im = mask
    return mask.size, img.tobytes()


@lru_cache(maxsize=4096)
def _display_has(char: str) -> bool:
    """Czy Fontastique ma glif (brak = pusty `.notdef`, czyli dziura w tytule)."""
    return _glyph_bits(_font("FontastiquePL.ttf", 40), char) != _display_notdef()


def display_covers(text: str) -> bool:
    """Tytuł krojem Fontastique tylko wtedy, gdy krój ma każdy znak - inaczej cały Geist Bold."""
    return all(c.isspace() or _display_has(c) for c in text or "")


def _title_font(text: str, size: int) -> ImageFont.FreeTypeFont:
    if display_covers(text):
        return _font("FontastiquePL.ttf", size)
    return _geist("Bold", round(size * 0.92))


def _words(text: str) -> List[str]:
    """Słowa z polską składnią: jednoliterowy spójnik („w", „i", „z") jedzie z następnym słowem."""
    out: List[str] = []
    for word in text.split():
        if out and len(out[-1]) == 1 and out[-1].isalpha():
            out[-1] = f"{out[-1]} {word}"
        else:
            out.append(word)
    return out


def ellipsize(text: str, font: ImageFont.FreeTypeFont, width: float) -> str:
    if font.getlength(text) <= width:
        return text
    while text and font.getlength(text.rstrip() + "…") > width:
        text = text[:-1]
    return text.rstrip(" ,.;:-–") + "…"


def wrap(text: str, font: ImageFont.FreeTypeFont, width: float, max_lines: int) -> Tuple[List[str], bool]:
    """(linie, zmieściło się). Za długie słowo łamiemy po znakach; nadmiar linii kończy wielokropek."""
    lines: List[str] = []
    current = ""
    fits = True
    for word in _words(text):
        probe = f"{current} {word}".strip()
        if font.getlength(probe) <= width:
            current = probe
            continue
        if current:
            lines.append(current)
            current = ""
        while font.getlength(word) > width:
            fits = False
            cut = len(word)
            while cut > 1 and font.getlength(word[:cut] + "-") > width:
                cut -= 1
            lines.append(word[:cut] + "-")
            word = word[cut:]
        current = word
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        fits = False
        lines = lines[:max_lines - 1] + [_last_line(" ".join(lines[max_lines - 1:]), font, width)]
    return lines or [""], fits


def _last_line(rest: str, font: ImageFont.FreeTypeFont, width: float) -> str:
    """Ostatnia linia z wielokropkiem po CAŁYM słowie (bez wiszącego „w…" ani ucięcia w pół słowa)."""
    words = rest.split()
    line = ""
    for word in words:
        probe = f"{line} {word}".strip()
        if font.getlength(probe + "…") > width:
            break
        line = probe
    if not line:
        return ellipsize(rest, font, width)
    parts = line.split()
    while len(parts) > 1 and len(parts[-1]) == 1 and parts[-1].isalpha():
        parts.pop()
    return " ".join(parts).rstrip(" ,.;:-–") + "…"


def fit_title(text: str, sizes: Sequence[int], width: int, max_lines: int) -> Tuple[ImageFont.FreeTypeFont, List[str], int]:
    """Największy rozmiar, przy którym tytuł mieści się w `max_lines`; inaczej najmniejszy z wielokropkiem."""
    for size in sizes:
        font = _title_font(text, size)
        lines, fits = wrap(text, font, width * _S, max_lines)
        if fits:
            return font, lines, size
    size = sizes[-1]
    font = _title_font(text, size)
    return font, wrap(text, font, width * _S, max_lines)[0], size


# ---------------------------------------------------------------------------
# Barwy i tła
# ---------------------------------------------------------------------------


def _mix(a: RGB, b: RGB, t: float) -> RGB:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))  # type: ignore[return-value]


def _luma(c: RGB) -> float:
    return (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255


def tone_rgb(tone: Optional[str]) -> RGB:
    return TONES.get(str(tone or ""), TONES["gold"])


def _field(fn, size: Tuple[int, int] = (160, 84)) -> Image.Image:
    """Gładkie pole barwy: `fn(x, y)` w [0,1]^2 -> RGBA, liczone w małej siatce i powiększone."""
    small = Image.new("RGBA", size)
    w, h = size
    small.putdata([fn(x / (w - 1), y / (h - 1)) for y in range(h) for x in range(w)])
    return small.resize((W * _S, H * _S), Image.Resampling.BICUBIC)


def _soft(layer: Image.Image, radius: float, step: int = 4) -> Image.Image:
    """Rozmycie Gaussa liczone w 1/`step` rozmiaru - miękkie cienie i poświaty i tak nie mają ostrych szczegółów."""
    small = layer.resize((layer.width // step, layer.height // step), Image.Resampling.BILINEAR)
    return small.filter(ImageFilter.GaussianBlur(radius / step)).resize(layer.size, Image.Resampling.BICUBIC)


def _beams(color: RGB, strength: int = 26) -> Image.Image:
    """Światła hali: trzy miękkie snopy z góry (echo `HallLights` na webie)."""
    layer = Image.new("RGBA", (W * _S, H * _S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for top, spread, alpha in ((560, 150, strength), (820, 120, round(strength * 0.8)), (1060, 110, round(strength * 0.6))):
        x = top * _S
        d.polygon(
            [(x - 18 * _S, -10), (x + 18 * _S, -10), (x - 120 * _S + spread * _S, H * _S), (x - 120 * _S - spread * _S, H * _S)],
            fill=(*color, alpha),
        )
    return _soft(layer, 38 * _S)


def _tone_background(tone: RGB, glow_at: Tuple[float, float], *, glow: float = 0.62, reach: float = 0.78,
                     tint: float = 0.26, beams: int = 30) -> Image.Image:
    """Noc z barwą okładki: ukośny gradient (ton u góry z prawej), reflektor w tonie, światła hali."""
    deep = _mix(NIGHT, tone, 0.04)
    lit = _mix(NIGHT, tone, tint)
    spot = _mix(tone, CREAM, 0.06)
    gx, gy = glow_at

    def px(x: float, y: float):
        t = max(0.0, min(1.0, 0.7 * x + 0.3 * (1 - y))) ** 1.8
        c = _mix(deep, lit, t)
        d = math.hypot((x - gx) * 1.45, y - gy)
        c = _mix(c, spot, max(0.0, 1 - d / reach) ** 2.2 * glow)
        # Lewy dół ciemniej - tam stoi tekst.
        v = max(0.0, 1 - x / 0.62) * max(0.0, (y - 0.3) / 0.7)
        c = _mix(c, NIGHT, 0.6 * v)
        return (*c, 255)

    img = _field(px, (120, 63))
    if beams:
        img.alpha_composite(_beams(_mix(tone, CREAM, 0.6), beams))
    return img


# ---------------------------------------------------------------------------
# Znaki: marka, emoji, rodzaj
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _lockup_source() -> Image.Image:
    with Image.open(_LOCKUP) as src:
        return src.convert("RGBA")


def _lockup(height: int) -> Image.Image:
    src = _lockup_source()
    h = height * _S
    return src.resize((round(src.width * h / src.height), h), Image.Resampling.LANCZOS)


@lru_cache(maxsize=32)
def _emoji_image(emoji: str) -> Optional[Image.Image]:
    """Kolorowe emoji przycięte do treści - `None`, gdy na serwerze nie ma kroju z tym znakiem."""
    for path in _EMOJI_FONTS:
        if not path.is_file():
            continue
        for text in (emoji, emoji[:1]):
            try:
                font = ImageFont.truetype(str(path), 109)  # Noto Color Emoji ma wyłącznie 109 px
                canvas = Image.new("RGBA", (round(font.getlength(text)) + 40, 170), (0, 0, 0, 0))
                ImageDraw.Draw(canvas).text((20, 14), text, font=font, embedded_color=True)
            except Exception:  # noqa: BLE001 - krój albo układ tekstu: karta ma powstać i tak
                continue
            box = canvas.getbbox()
            if box is None:
                continue
            img = canvas.crop(box)
            # Bez układu raqm sekwencja ZWJ rozpada się na kilka znaków - wtedy sam pierwszy.
            if img.width <= img.height * 1.45:
                return img
        return None
    return None


def _kind_glyph(kind: str, size: int, ink: RGB) -> Image.Image:
    """Znak rodzaju rysowany wektorowo: lista = trzy wiersze z ptaszkami, formularz = karta z polami."""
    s = min(size * _S * 3, 1600)  # rysujemy większe i zmniejszamy (gładkie krawędzie)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    stroke = round(s * 0.055)
    col = (*ink, 255)
    if kind == "form":
        d.rounded_rectangle((s * 0.18, s * 0.08, s * 0.82, s * 0.92), round(s * 0.09), outline=col, width=stroke)
        d.rounded_rectangle((s * 0.36, s * 0.02, s * 0.64, s * 0.16), round(s * 0.05), fill=col)
        for i, y in enumerate((0.36, 0.56, 0.76)):
            cy = s * y
            r = s * 0.045
            d.ellipse((s * 0.31 - r, cy - r, s * 0.31 + r, cy + r), fill=col)
            d.rounded_rectangle((s * 0.42, cy - stroke / 2, s * (0.70 if i != 1 else 0.62), cy + stroke / 2), stroke // 2, fill=col)
    else:
        for i, y in enumerate((0.22, 0.5, 0.78)):
            cy = s * y
            box = s * 0.17
            x0 = s * 0.08
            if i < 2:
                d.rounded_rectangle((x0, cy - box / 2, x0 + box, cy + box / 2), round(box * 0.28), fill=col)
                cut = (*ink, 0)
                check = [(x0 + box * 0.24, cy + box * 0.02), (x0 + box * 0.44, cy + box * 0.22), (x0 + box * 0.78, cy - box * 0.2)]
                d.line(check, fill=cut, width=round(stroke * 0.8), joint="curve")
            else:
                d.rounded_rectangle((x0, cy - box / 2, x0 + box, cy + box / 2), round(box * 0.28), outline=col, width=round(stroke * 0.8))
            d.rounded_rectangle((s * 0.36, cy - stroke * 0.6, s * (0.92 if i != 1 else 0.80), cy + stroke * 0.6), stroke, fill=col)
    return img.resize((size * _S, size * _S), Image.Resampling.LANCZOS)


def _mark(card: CardData, size: int, ink: RGB) -> Image.Image:
    """Emoji okładki albo znak rodzaju, wpisany w kwadrat `size`."""
    art = _emoji_image(card.emoji) if card.emoji else None
    if art is None:
        return _kind_glyph(card.kind, size, ink)
    return ImageOps.contain(art, (size * _S, size * _S), Image.Resampling.LANCZOS)


def _tile(card: CardData, tone: RGB, side: int) -> Image.Image:
    """Kafel okładki: połysk w tonie, cienka jaśniejsza krawędź, emoji albo znak rodzaju."""
    s = side * _S
    radius = round(s * 0.26)
    top, bottom = _mix(tone, CREAM, 0.22), _mix(tone, NIGHT, 0.18)
    fill = Image.new("RGBA", (1, s))
    fill.putdata([(*_mix(top, bottom, y / (s - 1)), 255) for y in range(s)])
    fill = fill.resize((s, s))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, s - 1, s - 1), radius, fill=255)
    tile = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    tile.paste(fill, (0, 0), mask)
    # Połysk w górnej połowie.
    gloss = Image.new("L", (1, s))
    gloss.putdata([round(70 * max(0.0, 1 - y / (s * 0.55)) ** 2) for y in range(s)])
    gloss_layer = Image.new("RGBA", (s, s), (*CREAM, 0))
    gloss_layer.putalpha(ImageChops.multiply(gloss.resize((s, s)), mask))
    tile.alpha_composite(gloss_layer)
    ImageDraw.Draw(tile).rounded_rectangle((1, 1, s - 2, s - 2), radius, outline=(*_mix(tone, CREAM, 0.55), 150), width=2 * _S)
    ink = NIGHT if _luma(tone) > 0.45 else CREAM
    mark = _mark(card, round(side * (0.58 if card.emoji else 0.52)), ink)
    tile.alpha_composite(mark, ((s - mark.width) // 2, (s - mark.height) // 2))
    return tile


def _shadow(img: Image.Image, box: Tuple[int, int, int, int], radius: int, blur: int, alpha: int, dy: int) -> None:
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    x0, y0, x1, y1 = box
    ImageDraw.Draw(layer).rounded_rectangle((x0, y0 + dy, x1, y1 + dy), radius, fill=(0, 0, 0, alpha))
    img.alpha_composite(_soft(layer, blur))


def _halo_lockup(img: Image.Image, x: int, y: int, height: int, veil: RGB) -> None:
    """Znak BAZA u góry; pod nim miękka ciemna poświata, żeby jasne niebo go nie zjadło."""
    lock = _lockup(height)
    halo = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(halo).rounded_rectangle(
        (x * _S - 30 * _S, y * _S - 18 * _S, x * _S + lock.width + 30 * _S, y * _S + lock.height + 18 * _S),
        40 * _S, fill=(*veil, 150),
    )
    img.alpha_composite(_soft(halo, 24 * _S))
    img.alpha_composite(lock, (x * _S, y * _S))


# ---------------------------------------------------------------------------
# Pigułki pod tytułem
# ---------------------------------------------------------------------------


def _clock(d: ImageDraw.ImageDraw, cx: float, cy: float, r: float, color: RGB) -> None:
    w = max(2, round(r * 0.2))
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=(*color, 255), width=w)
    d.line([(cx, cy - r * 0.55), (cx, cy), (cx + r * 0.42, cy + r * 0.26)], fill=(*color, 255), width=w, joint="curve")


def _lock(d: ImageDraw.ImageDraw, cx: float, cy: float, r: float, color: RGB) -> None:
    w = max(2, round(r * 0.2))
    d.arc((cx - r * 0.55, cy - r * 1.05, cx + r * 0.55, cy + r * 0.1), 180, 360, fill=(*color, 255), width=w)
    d.line([(cx - r * 0.55, cy - r * 0.48), (cx - r * 0.55, cy - r * 0.1)], fill=(*color, 255), width=w)
    d.line([(cx + r * 0.55, cy - r * 0.48), (cx + r * 0.55, cy - r * 0.1)], fill=(*color, 255), width=w)
    d.rounded_rectangle((cx - r * 0.85, cy - r * 0.15, cx + r * 0.85, cy + r * 0.95), round(r * 0.22), fill=(*color, 255))


CHIP_H, CHIP_PAD, CHIP_GAP = 54, 24, 14
CHIP_ICON = 30
CHIP_ARROW = "  →"


def _chip_rows(card: CardData, max_width: int) -> List[List[Tuple[str, str, int]]]:
    """Pigułki w wierszach: termin, potem zachęta; gdy obie się nie mieszczą obok siebie - pod spodem."""
    font, font_cta = _geist("Medium", 25), _geist("Bold", 25)
    chips: List[Tuple[str, str, int]] = []
    if card.status:
        text = ellipsize(card.status, font, (max_width - CHIP_PAD * 2 - CHIP_ICON) * _S)
        chips.append(("status", text, CHIP_PAD + CHIP_ICON + round(font.getlength(text) / _S) + CHIP_PAD))
    if card.cta and not card.closed:
        text = ellipsize(card.cta, font_cta, (max_width - CHIP_PAD * 2) * _S - font_cta.getlength(CHIP_ARROW))
        chips.append(("cta", text, CHIP_PAD + round(font_cta.getlength(text + CHIP_ARROW) / _S) + CHIP_PAD))
    rows: List[List[Tuple[str, str, int]]] = []
    used = 0
    for chip in chips:
        if rows and used + CHIP_GAP + chip[2] <= max_width:
            rows[-1].append(chip)
            used += CHIP_GAP + chip[2]
        else:
            rows.append([chip])
            used = chip[2]
    return rows


def _chips_height(rows: Sequence[Sequence[object]]) -> int:
    return len(rows) * CHIP_H + max(0, len(rows) - 1) * 12


def _chips(img: Image.Image, card: CardData, tone: RGB, rows, x: int, y: int) -> None:
    """Termin (szkło z zegarem albo kłódką) i zachęta (pigułka w tonie ze strzałką)."""
    font, font_cta = _geist("Medium", 25), _geist("Bold", 25)
    for row in rows:
        cursor = x
        cy = (y + CHIP_H / 2) * _S
        for kind, text, w in row:
            box = (cursor * _S, y * _S, (cursor + w) * _S, (y + CHIP_H) * _S)
            if kind == "status":
                glass = Image.new("RGBA", img.size, (0, 0, 0, 0))
                ImageDraw.Draw(glass).rounded_rectangle(
                    box, CHIP_H * _S // 2,
                    fill=(*_mix(NIGHT, tone, 0.10), 200), outline=(*_mix(tone, CREAM, 0.4), 72), width=2 * _S,
                )
                img.alpha_composite(glass)
                d = ImageDraw.Draw(img)
                accent = MUTED if card.closed else _mix(tone, CREAM, 0.1)
                icon_x = (cursor + CHIP_PAD + 11) * _S
                if card.closed:
                    _lock(d, icon_x, cy + 2 * _S, 11 * _S, accent)
                else:
                    _clock(d, icon_x, cy, 11 * _S, accent)
                d.text(((cursor + CHIP_PAD + CHIP_ICON) * _S, cy), text, font=font, fill=(*TEXT, 255), anchor="lm")
            else:
                d = ImageDraw.Draw(img)
                ink = NIGHT if _luma(tone) > 0.45 else CREAM
                d.rounded_rectangle(box, CHIP_H * _S // 2, fill=(*tone, 255))
                d.text(((cursor + CHIP_PAD) * _S, cy), text + CHIP_ARROW, font=font_cta, fill=(*ink, 255), anchor="lm")
            cursor += w + CHIP_GAP
        y += CHIP_H + 12


# ---------------------------------------------------------------------------
# Blok tekstu (tytuł, rodzaj, pigułki) - wspólny dla okładki i barwy
# ---------------------------------------------------------------------------


def _text_block(img: Image.Image, card: CardData, tone: RGB, *, x: int, bottom: int, width: int,
                sizes: Sequence[int], shadow: bool) -> None:
    font, lines, size = fit_title(card.title, sizes, width, 3)
    line_h = round(size * 1.08)
    meta_font = _geist("Medium", 30)
    meta = ellipsize(card.meta, meta_font, width * _S) if card.meta else ""
    rows = _chip_rows(card, width)
    block = len(lines) * line_h + (20 + 36 if meta else 0) + (30 + _chips_height(rows) if rows else 0)
    y = bottom - block

    texts = []
    for line in lines:
        # Linia bazowa w stałym rytmie - Fontastique ma wysokie akcenty nad wersalikami.
        texts.append(((x * _S, (y + line_h * 0.86) * _S), line, font, TEXT, "ls"))
        y += line_h
    if meta:
        y += 20
        texts.append(((x * _S, (y + 18) * _S), meta, meta_font, _mix(MUTED, CREAM, 0.35), "lm"))
        y += 36
    if shadow:
        layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
        dl = ImageDraw.Draw(layer)
        for (tx, ty), text, f, _, anchor in texts:
            dl.text((tx, ty + 3 * _S), text, font=f, fill=(0, 0, 0, 190), anchor=anchor)
        img.alpha_composite(_soft(layer, 10 * _S, 2))
    d = ImageDraw.Draw(img)
    for xy, text, f, color, anchor in texts:
        d.text(xy, text, font=f, fill=(*color, 255), anchor=anchor)
    if rows:
        _chips(img, card, tone, rows, x, y + 30)


# ---------------------------------------------------------------------------
# Układy
# ---------------------------------------------------------------------------


MARGIN = 72


def _veil(tone: RGB) -> Image.Image:
    """Ciemny welon na grafice: mocny od lewej i od dołu, lekki u góry (znak marki)."""
    shade = _mix(NIGHT, tone, 0.10)

    def px(x: float, y: float):
        left = 228 * max(0.0, 1 - x / 0.85) ** 1.3
        low = 250 * max(0.0, (y - 0.18) / 0.82) ** 1.15
        top = 120 * max(0.0, 1 - y / 0.32) ** 2
        a = 1 - (1 - left / 255) * (1 - low / 255) * (1 - top / 255)
        return (*shade, round(255 * a))

    return _field(px, (96, 52))


def _on_photo(card: CardData, data: bytes) -> Image.Image:
    with Image.open(io.BytesIO(data)) as src:
        if src.width * src.height > PHOTO_MAX_PIXELS:
            raise ValueError("grafika za duża")
        src.draft("RGB", (W * _S, H * _S))
        photo = ImageOps.exif_transpose(src).convert("RGB")
    tone = tone_rgb(card.tone)
    img = ImageOps.fit(photo, (W * _S, H * _S), Image.Resampling.LANCZOS, centering=(0.5, 0.42)).convert("RGBA")
    img.alpha_composite(_veil(tone))
    _halo_lockup(img, MARGIN - 6, 50, 64, _mix(NIGHT, tone, 0.1))
    if card.emoji and _emoji_image(card.emoji) is not None:
        side = 92
        x0 = (W - MARGIN - side) * _S
        _shadow(img, (x0, 46 * _S, x0 + side * _S, (46 + side) * _S), round(side * _S * 0.26), 14 * _S, 130, 8 * _S)
        img.alpha_composite(_tile(card, tone, side), (x0, 46 * _S))
    _text_block(img, card, tone, x=MARGIN, bottom=H - 60, width=W - MARGIN * 2 - 60,
                sizes=(80, 72, 64, 58, 52, 48), shadow=True)
    return img


def _on_tone(card: CardData) -> Image.Image:
    tone = tone_rgb(card.tone)
    side = 300
    cx, cy = W - MARGIN - side // 2 - 10, H // 2 + 6
    img = _tone_background(tone, (cx / W, cy / H))

    # Wielki, blady znak za kaflem - echo grafiki w hero strony www (obrót, mgła). Sama sylwetka
    # w tonie: kolorowe emoji w tle kłóciłoby się z kaflem.
    mark = _mark(card, 500, CREAM)
    ghost = Image.new("RGBA", mark.size, (*_mix(tone, CREAM, 0.35), 0))
    ghost.putalpha(mark.getchannel("A").point(lambda a: a * 34 // 255))
    ghost = ghost.rotate(-12, resample=Image.Resampling.BICUBIC, expand=True)
    img.alpha_composite(ghost, ((cx + 70) * _S - ghost.width // 2, (cy + 120) * _S - ghost.height // 2))

    x0, y0 = (cx - side // 2) * _S, (cy - side // 2) * _S
    _shadow(img, (x0, y0, x0 + side * _S, y0 + side * _S), round(side * _S * 0.26), 30 * _S, 170, 22 * _S)
    img.alpha_composite(_tile(card, tone, side), (x0, y0))

    img.alpha_composite(_lockup(60), ((MARGIN - 6) * _S, 54 * _S))
    text_w = cx - side // 2 - MARGIN - 56
    _text_block(img, card, tone, x=MARGIN, bottom=H - 64, width=text_w, sizes=(72, 66, 60, 54, 48, 44), shadow=False)
    return img


def _on_brand(card: CardData) -> Image.Image:
    tone = TONES["gold"]
    img = _tone_background(tone, (0.5, 0.36), glow=0.34, reach=0.85, tint=0.12, beams=22)
    lock = _lockup(210)
    x, y = (W * _S - lock.width) // 2, 150 * _S
    glow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse((x - 40 * _S, y - 30 * _S, x + lock.width + 40 * _S, y + lock.height + 30 * _S),
                                 fill=(*NIGHT, 110))
    img.alpha_composite(_soft(glow, 50 * _S))
    img.alpha_composite(lock, (x, y))
    d = ImageDraw.Draw(img)
    font = _geist("Medium", 32)
    line = ellipsize(card.title, font, (W - 2 * MARGIN) * _S)
    d.text((W * _S // 2, (y // _S + 210 + 64) * _S), line, font=font, fill=(*_mix(MUTED, CREAM, 0.35), 255), anchor="mm")
    if card.meta:
        small = _geist("Regular", 24)
        d.text((W * _S // 2, (y // _S + 210 + 110) * _S), ellipsize(card.meta, small, (W - 2 * MARGIN) * _S),
               font=small, fill=(*MUTED, 255), anchor="mm")
    return img


def _jpeg(img: Image.Image) -> bytes:
    out = io.BytesIO()
    img.convert("RGB").resize((W, H), Image.Resampling.LANCZOS).save(
        out, "JPEG", quality=JPEG_QUALITY, optimize=True, progressive=True,
    )
    return out.getvalue()


def _render(card: CardData, photo: Optional[bytes]) -> Tuple[bytes, bool]:
    """`(jpeg, pełna)` - `pełna=False`, gdy zamówiono grafikę, a wyszła karta w barwie."""
    with _LOCK:
        if card.brand:
            return _jpeg(_on_brand(card)), True
        if card.photo and photo:
            try:
                return _jpeg(_on_photo(card, photo)), True
            except Exception:  # noqa: BLE001 - zepsuta grafika nie może zabrać karty
                logger.info("Grafika %s nie dała się narysować - karta w barwie", card.photo)
        return _jpeg(_on_tone(card)), not card.photo


def render(card: CardData, photo: Optional[bytes] = None) -> bytes:
    """Karta JPEG 1200 x 630 bez pamięci (testy, próbki)."""
    return _render(card, photo)[0]


def card_jpeg(card: CardData, photo: Optional[bytes] = None) -> bytes:
    """`render` z pamięcią procesu po skrócie treści; karta zastępcza (grafika nie przyszła) - bez pamięci."""
    key = version(card)
    hit = _CACHE.get(key)
    if hit is not None:
        _CACHE.move_to_end(key)
        return hit
    jpeg, full = _render(card, photo)
    if full:
        _CACHE[key] = jpeg
        while len(_CACHE) > CACHE_MAX:
            _CACHE.popitem(last=False)
    else:
        _STANDIN[key] = (time.monotonic() + STANDIN_TTL_S, jpeg)
        while len(_STANDIN) > CACHE_MAX:
            _STANDIN.popitem(last=False)
    return jpeg


def cached(card: CardData) -> Optional[bytes]:
    """Gotowa karta z pamięci - pełna albo świeża zastępcza (seria pytań komunikatora)."""
    key = version(card)
    hit = _CACHE.get(key)
    if hit is not None:
        return hit
    standin = _STANDIN.get(key)
    if standin is not None and standin[0] > time.monotonic():
        return standin[1]
    _STANDIN.pop(key, None)
    return None


# ---------------------------------------------------------------------------
# Grafika wydarzenia: dysk (/static/...) albo https z zaporą SSRF
# ---------------------------------------------------------------------------


def static_root() -> Path:
    """Ten sam katalog, co `main.py::STATIC_DIR` i `app/beach/tournaments.py::_static_root_dir`."""
    volume = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
    return Path(volume) / "static" if volume else _HERE.parent / "static"


def static_file(url: Optional[str]) -> Optional[Path]:
    """Plik pod `/static/...` - tylko wewnątrz katalogu statycznego (bez `..`)."""
    if not url or not url.startswith("/static/"):
        return None
    root = static_root().resolve()
    try:
        path = (root / url[len("/static/"):].split("?", 1)[0]).resolve()
    except (OSError, ValueError):
        return None
    if root not in path.parents or not path.is_file():
        return None
    return path


def photo_key(url: Optional[str]) -> Optional[str]:
    """Tożsamość grafiki do skrótu karty: plik z datą zmiany albo adres https; brak = None."""
    if not url:
        return None
    path = static_file(url)
    if path is not None:
        stat = path.stat()
        return f"{url}:{stat.st_mtime_ns}:{stat.st_size}"
    if url.startswith("https://"):
        return url
    return None


async def photo_bytes(url: Optional[str]) -> Optional[bytes]:
    """Bajty grafiki - `None` przy KAŻDYM kłopocie (karta i tak powstaje)."""
    from fastapi.concurrency import run_in_threadpool

    try:
        path = static_file(url)
        if path is not None:
            if path.stat().st_size > PHOTO_MAX_BYTES:
                return None
            return await run_in_threadpool(path.read_bytes)
        if url and url.startswith("https://"):
            return await _fetch(url)
    except Exception:  # noqa: BLE001 - dysk, sieć, DNS: karta ma powstać i tak
        logger.info("Grafika %s niedostępna dla karty podglądu", url)
    return None


async def _fetch(url: str) -> Optional[bytes]:
    """Pobranie z zaporami z `link_preview_rules` (publiczne IP, ręczne przekierowania, limit bajtów)."""
    import httpx
    from urllib.parse import urlparse

    from app.link_preview import _resolve
    from app.link_preview_rules import all_ips_allowed, check_url_shape, redirect_target

    current = check_url_shape(url)
    async with httpx.AsyncClient(timeout=httpx.Timeout(PHOTO_TIMEOUT_S), follow_redirects=False,
                                 headers={"User-Agent": "BAZA-LinkCard/1.0", "Accept": "image/*"}) as client:
        for _ in range(3):
            all_ips_allowed(await _resolve(urlparse(current).hostname or ""))
            async with client.stream("GET", current) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    current = redirect_target(current, response.headers.get("location"))
                    continue
                if response.status_code >= 400:
                    return None
                chunks: List[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > PHOTO_MAX_BYTES:
                        return None
                    chunks.append(chunk)
                return b"".join(chunks)
    return None


async def respond(card: CardData, photo_url: Optional[str]):
    """Odpowiedź `image/jpeg`: pamięć najpierw, potem grafika, rysowanie poza pętlą zdarzeń."""
    from fastapi.concurrency import run_in_threadpool
    from fastapi.responses import Response

    jpeg = cached(card)
    if jpeg is None:
        photo = await photo_bytes(photo_url) if card.photo else None
        jpeg = await run_in_threadpool(card_jpeg, card, photo)
    return Response(jpeg, media_type="image/jpeg", headers={"Cache-Control": "public, max-age=86400"})
