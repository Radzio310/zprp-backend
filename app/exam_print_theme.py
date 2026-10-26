"""
Egzamin - motywy PLIKU studia eksportu (26.10.2026): barwy okręgu, jasny elegancki, ciemny premium.

Moduł-liść: zero bazy, zero sieci. Lustro w aplikacji: `constants/examPalette.ts`
(`studioMotif`) - podgląd na telefonie i plik z serwera mają te same barwy.

  province   barwy okręgu z herbu - para primary/secondary z
             `components/admin/provinceColors.ts` (wyliczone raz z plików herbów);
             egzamin krajowy = czerwień ZPRP. Barwa herbu przechodzi przez
             `readable` (ta sama arytmetyka kontrastu co `readableCrestColor`):
             na jasnym papierze ciemniejemy, nigdy nie rozjaśniamy.
  elegant    kremowy papier, złoto, szeryfowy tytuł
  premium    grafit, neon wykresów (ciemny plik)

Logo BAZY = `templates/brand/nowe_logo.png` (kopia 1:1 z aplikacji) - nigdy stare logo.
"""

from __future__ import annotations

import base64
import io
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

BRAND_DIR = Path(__file__).resolve().parent / "templates" / "brand"

#: Para barw herbu (surowa). Lustro `components/admin/provinceColors.ts` - herb jednobarwny ma obie takie same.
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

ZPRP_RED = "#B8322A"

#: Wspólne klucze motywu (te same co `exam_report_html.THEMES`) + `band`, `band2`, `gold`, `serif`, `dark`.
ELEGANT: Dict[str, Any] = {
    "bg": "#FBF6EC", "card": "#FFFDF8", "ink": "#2B2118", "soft": "#7A6A58", "line": "#E6D8BF",
    "accent": "#A8823A", "seal": "#9E2B25", "pass": "#2E7D57", "fail": "#9A7B66", "warn": "#B9781A",
    "track": "#F1E7D4", "glow": False, "heat": ((181, 71, 58), (201, 154, 62), (60, 138, 95)),
    "cover": "#F3EAD8", "cover_ink": "#2B2118", "cover_soft": "#7A6A58",
    "band": "#A8823A", "band2": "#D9BE84", "gold": "#B8924A", "serif": True, "dark": False,
}

PREMIUM: Dict[str, Any] = {
    "bg": "#0E1014", "card": "#161A21", "ink": "#EEF1F6", "soft": "#9AA3B2", "line": "#262C36",
    "accent": "#7FB2E8", "seal": "#FF5A4F", "pass": "#69E6AA", "fail": "#B9A193", "warn": "#F2C14E",
    "track": "#1E232C", "glow": True, "heat": ((255, 90, 79), (242, 193, 78), (105, 230, 170)),
    "cover": "#0A0C10", "cover_ink": "#EEF1F6", "cover_soft": "#9AA3B2",
    "band": "#7FB2E8", "band2": "#69E6AA", "gold": "#E7C27A", "serif": False, "dark": True,
}

PAPER_WHITE = "#FFFFFF"


def province_slug(value: Any) -> str:
    """„Warmińsko-Mazurskie" / „WARMINSKO_MAZURSKIE" -> „WARMINSKO_MAZURSKIE" (jak `provinceColors`)."""
    base = str(value or "").replace("Ł", "L").replace("ł", "l")
    base = unicodedata.normalize("NFKD", base).encode("ascii", "ignore").decode("ascii").upper()
    return re.sub(r"[^A-Z0-9]+", "_", base).strip("_")


def _rgb(hex_: str) -> Tuple[int, int, int]:
    h = hex_.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(rgb: Tuple[float, float, float]) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c))):02X}" for c in rgb)


def luminance(hex_: str) -> float:
    def ch(c: int) -> float:
        v = c / 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

    r, g, b = _rgb(hex_)
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def mix(a: str, b: str, t: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return _hex(tuple(ra[i] + (rb[i] - ra[i]) * t for i in range(3)))  # type: ignore[arg-type]


def readable(hex_: str, surface: str, fallback: str, minimum: float = 3.2) -> str:
    """Barwa herbu czytelna NA TYM tle - kierunek wybiera jasność tła (jak `readableCrestColor`)."""
    if contrast(hex_, surface) >= minimum:
        return hex_
    target = "#000000" if luminance(surface) > 0.4 else "#FFFFFF"
    for t in (0.25, 0.4, 0.55, 0.7, 0.85):
        m = mix(hex_, target, t)
        if contrast(m, surface) >= minimum:
            return m
    return fallback


def province_theme(province: Optional[str]) -> Dict[str, Any]:
    """Motyw „Barwy okręgu": biały papier, akcent i pasy z herbu. Brak okręgu (krajowy) = czerwień ZPRP."""
    pair = PROVINCE_COLORS.get(province_slug(province)) if province else None
    primary, secondary = pair or (ZPRP_RED, ZPRP_RED)
    bg = PAPER_WHITE
    accent = readable(primary, bg, ZPRP_RED, 4.0)
    accent2 = readable(secondary, bg, accent, 3.0)
    cover_ink = "#1C1C1C" if luminance(primary) > 0.45 else "#FFFFFF"
    return {
        "bg": bg, "card": "#FFFFFF", "ink": "#1E1A17", "soft": "#6B625B", "line": mix(primary, "#FFFFFF", 0.82),
        "accent": accent, "seal": ZPRP_RED, "pass": "#22804F", "fail": "#8A7C72", "warn": "#B97714",
        "track": mix(primary, "#FFFFFF", 0.9), "glow": False,
        "heat": ((184, 50, 42), (214, 160, 70), (34, 128, 79)),
        "cover": primary, "cover_ink": cover_ink, "cover_soft": "rgba(255,255,255,0.84)" if cover_ink == "#FFFFFF" else "rgba(0,0,0,0.62)",
        "band": primary, "band2": secondary, "gold": accent2, "serif": False, "dark": False,
    }


def theme_for(name: str, province: Optional[str], legacy: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Motyw po nazwie. Stare motywy (`paper|night|ink|zprp`) dostają brakujące klucze studia."""
    if name == "province":
        return province_theme(province)
    if name == "elegant":
        return dict(ELEGANT)
    if name == "premium":
        return dict(PREMIUM)
    th = dict(legacy.get(name) or legacy["paper"])
    dark = name == "night"
    th.setdefault("cover_ink", "#FFFFFF" if name == "zprp" else th["ink"])
    th.setdefault("cover_soft", "rgba(255,255,255,0.82)" if name == "zprp" else th["soft"])
    th.setdefault("band", th["accent"])
    th.setdefault("band2", th["seal"])
    th.setdefault("gold", th["accent"])
    th.setdefault("serif", False)
    th.setdefault("dark", dark)
    return th


@lru_cache(maxsize=4)
def brand_logo_uri(px: int = 220) -> str:
    """Logo BAZY (`nowe_logo.png`) jako data URI, zmniejszone do `px` - plik 1:1 jest za ciężki do PDF."""
    path = BRAND_DIR / "nowe_logo.png"
    if not path.exists():
        return ""
    try:
        from PIL import Image

        image = Image.open(path)
        image.thumbnail((px, px))
        buf = io.BytesIO()
        image.save(buf, "PNG", optimize=True)
        data = buf.getvalue()
    except Exception:  # noqa: BLE001 - bez Pillow bierzemy plik jak jest
        try:
            data = path.read_bytes()
        except OSError:
            return ""
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")
