"""Zrzuty klatek Mentora - reguły czyste (bez bazy i sieci). Kontrakt: `docs/mentor-panel.md`, sekcja 13."""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.mentor_panel_rules import RuleError, aware, json_value, plain, safe_filename, s

# ─── Limity ─────────────────────────────────────────────────────────────────

MAX_TITLE = 80
MAX_NOTE = 1000
MAX_SHAPES = 40
MAX_FREE_POINTS = 300
MAX_TEXT = 120
MAX_SHAPES_BYTES = 48 * 1024
MAX_LOUPES = 3
MAX_SPOTLIGHTS = 1
MAX_AT_S = 6 * 3600
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MIN_IMAGE_SIDE = 64
MAX_IMAGE_SIDE = 4096
THUMB_SIDE = 480
STORED_MAX_SIDE = 3840
MAX_SHOTS_PER_MATCH = 300
PROCESSING_STALE_S = 300

SHAPE_TYPES = ("ellipse", "arrow", "text", "free", "spotlight", "loupe")
ATTACH_MODES = ("auto", "manual", "detached")
IMAGE_STATUSES = ("ready", "processing", "none", "failed")
DEFAULT_COLOR = "#ffd60a"
DEFAULT_WIDTH = 0.005
MIN_WIDTH, MAX_WIDTH = 0.0005, 0.05
DEFAULT_TEXT_SIZE = 0.05
MIN_TEXT_SIZE, MAX_TEXT_SIZE = 0.02, 0.2
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")

#: Powody braku obrazu (`image_reason`) z polskim tekstem dla klienta.
REASONS = {
    "YOUTUBE_NO_IMAGE": "Z YouTube nie da się pobrać obrazu klatki. Zrzut zostaje jako moment z rysunkiem na żywym filmie.",
    "LINK_NO_IMAGE": "Z tego linku nie da się pobrać obrazu klatki. Zrzut zostaje jako moment z rysunkiem na żywym filmie.",
    "BASTION_OFF": "Obraz z Bastionu jest wyłączony na tym serwerze.",
    "BASTION_NOT_CONNECTED": "Do pobrania klatki z Bastionu potrzebne jest połączenie z kontem Bastion.",
    "BASTION_AUTH_REQUIRED": "Sesja Bastionu wygasła. Połącz konto Bastion ponownie i spróbuj jeszcze raz.",
    "BASTION_UNAVAILABLE": "Bastion albo jego łącznik nie odpowiada. Spróbuj za chwilę.",
    "BASTION_FRAME_FAILED": "Nie udało się wyciąć klatki z Bastionu. Spróbuj ponownie.",
    "VIDEO_NOT_READY": "Nagranie jeszcze się przetwarza. Spróbuj za chwilę.",
    "FFMPEG_MISSING": "Serwer nie ma narzędzia do wycinania klatek (ffmpeg).",
    "FRAME_FAILED": "Nie udało się wyciąć klatki z nagrania. Spróbuj ponownie albo zrób zrzut w przeglądarce.",
    "FRAME_TIMEOUT": "Wycinanie klatki trwało za długo. Spróbuj ponownie.",
    "STORAGE_OFF": "Magazyn obrazów jest chwilowo niedostępny.",
    "VEO_PRIVATE": "To nagranie w Veo jest prywatne. Zmień jego ustawienia w Veo i spróbuj ponownie.",
    "VEO_GONE": "To nagranie zostało usunięte z Veo albo link jest nieprawidłowy.",
    "VEO_PROCESSING": "Veo jeszcze przetwarza to nagranie. Spróbuj za chwilę.",
    "VEO_UNAVAILABLE": "Veo nie odpowiada. Spróbuj za chwilę.",
}

NO_IMAGE_MESSAGE = "Ten zrzut nie ma obrazu, więc nie ma czego pobrać ani zapisać w Teczce."
PROCESSING_MESSAGE = "Obraz zrzutu jeszcze się przygotowuje. Spróbuj za chwilę."


def reason_text(code: Any) -> Optional[str]:
    return REASONS.get(s(code)) if s(code) else None


# ─── Liczby ─────────────────────────────────────────────────────────────────


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def validate_at(at_s: Any, duration_s: Any = None) -> float:
    """Sekunda zrzutu: skończona, 0..czas nagrania (albo 6 h), z ułamkiem do milisekundy."""
    value = _num(at_s)
    if value is None or value < 0:
        raise RuleError(422, "SHOT_AT", "Czas zrzutu musi być liczbą sekund od początku nagrania.")
    known = _num(duration_s)
    cap = known if known and known > 0 else MAX_AT_S
    if value > min(cap, MAX_AT_S) + 0.001:
        raise RuleError(422, "SHOT_AT_RANGE", "Ten czas wykracza poza nagranie.")
    return round(value, 3)


# ─── Kształty ───────────────────────────────────────────────────────────────


def _bad(index: int, why: str) -> RuleError:
    return RuleError(422, "SHOT_SHAPES_INVALID", f"Zaznaczenie nr {index + 1}: {why}")


def _unit(shape: Mapping[str, Any], key: str, index: int) -> float:
    value = _num(shape.get(key))
    if value is None or value < 0 or value > 1:
        raise _bad(index, f"pole {key} musi być liczbą od 0 do 1.")
    return round(value, 4)


def _range(shape: Mapping[str, Any], key: str, index: int, low: float, high: float, default: Optional[float]) -> float:
    if shape.get(key) is None:
        if default is None:
            raise _bad(index, f"brakuje pola {key}.")
        return default
    value = _num(shape.get(key))
    if value is None or value < low or value > high:
        raise _bad(index, f"pole {key} musi być liczbą od {low} do {high}.")
    return round(value, 4)


def clean_shape(raw: Any, index: int) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise _bad(index, "to nie jest obiekt.")
    kind = s(raw.get("type"))
    if kind not in SHAPE_TYPES:
        raise _bad(index, f"nieznany typ {kind[:20]} (dozwolone: {', '.join(SHAPE_TYPES)}).")
    color = s(raw.get("color")) or DEFAULT_COLOR
    if not _COLOR.match(color):
        raise _bad(index, "kolor musi mieć postać #rrggbb.")
    out: Dict[str, Any] = {"type": kind, "color": color.lower(),
                           "width": _range(raw, "width", index, MIN_WIDTH, MAX_WIDTH, DEFAULT_WIDTH)}
    if s(raw.get("id")):
        out["id"] = s(raw.get("id"))[:40]
    if kind in ("ellipse", "spotlight"):
        for key in ("cx", "cy", "rx", "ry"):
            out[key] = _unit(raw, key, index)
        if out["rx"] <= 0 or out["ry"] <= 0:
            raise _bad(index, "promienie muszą być większe od zera.")
        if kind == "spotlight":
            out["dim"] = _range(raw, "dim", index, 0.2, 0.9, 0.6)
    elif kind == "arrow":
        for key in ("x1", "y1", "x2", "y2"):
            out[key] = _unit(raw, key, index)
        if (out["x1"], out["y1"]) == (out["x2"], out["y2"]):
            raise _bad(index, "strzałka ma zerową długość.")
    elif kind == "text":
        text = plain(raw.get("text"), MAX_TEXT)
        if not text:
            raise _bad(index, "tekst nie może być pusty.")
        out.update(x=_unit(raw, "x", index), y=_unit(raw, "y", index), text=text,
                   size=_range(raw, "size", index, MIN_TEXT_SIZE, MAX_TEXT_SIZE, DEFAULT_TEXT_SIZE))
    elif kind == "free":
        points = raw.get("points")
        if not isinstance(points, list) or len(points) < 2:
            raise _bad(index, "rysunek odręczny potrzebuje co najmniej dwóch punktów.")
        if len(points) > MAX_FREE_POINTS:
            raise _bad(index, f"rysunek odręczny ma za dużo punktów (najwyżej {MAX_FREE_POINTS}).")
        clean = []
        for point in points:
            if not isinstance(point, (list, tuple)) or len(point) != 2:
                raise _bad(index, "punkt rysunku to para [x, y].")
            x, y = _num(point[0]), _num(point[1])
            if x is None or y is None or not (0 <= x <= 1 and 0 <= y <= 1):
                raise _bad(index, "współrzędne punktów muszą być od 0 do 1.")
            clean.append([round(x, 4), round(y, 4)])
        out["points"] = clean
    elif kind == "loupe":
        out.update(cx=_unit(raw, "cx", index), cy=_unit(raw, "cy", index), r=_range(raw, "r", index, 0.02, 0.5, 0.1),
                   zoom=_range(raw, "zoom", index, 1.5, 8.0, 2.5))
        if raw.get("px") is not None or raw.get("py") is not None:
            if raw.get("px") is None or raw.get("py") is None:
                raise _bad(index, "pola px i py podaje się razem albo wcale.")
            out.update(px=_unit(raw, "px", index), py=_unit(raw, "py", index))
    return out


MAX_VIEW_ZOOM = 6.0


def clean_view(raw: Any) -> Optional[Dict[str, float]]:
    """Kadr zrzutu: `{cx, cy, zoom}` (środek 0..1, zoom 1..6) albo None (cała klatka). zoom <= 1 daje None. Błąd = 422."""
    if raw in (None, ""):
        return None
    if not isinstance(raw, Mapping):
        raise RuleError(422, "SHOT_VIEW_INVALID", "Kadr musi być obiektem {cx, cy, zoom} albo null.")
    out: Dict[str, float] = {}
    for key, low, high in (("cx", 0.0, 1.0), ("cy", 0.0, 1.0), ("zoom", 1.0, MAX_VIEW_ZOOM)):
        value = _num(raw.get(key))
        if value is None or value < low or value > high:
            raise RuleError(422, "SHOT_VIEW_INVALID", f"Kadr: pole {key} musi być liczbą od {low:g} do {high:g}.")
        out[key] = round(value, 4)
    return None if out["zoom"] <= 1.0001 else out


def view_of(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Kadr zapisany w wierszu zrzutu (`view_json`) albo None."""
    value = json_value(row.get("view_json"), {})
    return value if value and "zoom" in value else None


def view_window(view: Optional[Mapping[str, Any]]) -> Tuple[float, float, float, float]:
    """Okno kadru w ułamkach klatki `(x0, y0, x1, y1)`: szerokość i wysokość 1/zoom, środek cx,cy, dosunięte do krawędzi."""
    if not view:
        return 0.0, 0.0, 1.0, 1.0
    size = 1.0 / max(1.0, float(view["zoom"]))
    x0 = min(max(float(view["cx"]) - size / 2, 0.0), 1.0 - size)
    y0 = min(max(float(view["cy"]) - size / 2, 0.0), 1.0 - size)
    return x0, y0, x0 + size, y0 + size


def clean_shapes(raw: Any) -> List[Dict[str, Any]]:
    """Walidacja kształtów zrzutu. Błąd = `RuleError` 422 z numerem zaznaczenia; nic nie jest po cichu poprawiane."""
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise RuleError(422, "SHOT_SHAPES_INVALID", "Zaznaczenia muszą być listą.")
    if len(raw) > MAX_SHAPES:
        raise RuleError(422, "SHOT_SHAPES_TOO_MANY", f"Na zrzucie może być najwyżej {MAX_SHAPES} zaznaczeń.")
    out = [clean_shape(item, i) for i, item in enumerate(raw)]
    if sum(1 for x in out if x["type"] == "loupe") > MAX_LOUPES:
        raise RuleError(422, "SHOT_SHAPES_TOO_MANY", f"Na zrzucie mogą być najwyżej {MAX_LOUPES} lupy.")
    if sum(1 for x in out if x["type"] == "spotlight") > MAX_SPOTLIGHTS:
        raise RuleError(422, "SHOT_SHAPES_TOO_MANY", "Na zrzucie może być tylko jeden reflektor.")
    if len(json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_SHAPES_BYTES:
        raise RuleError(422, "SHOT_SHAPES_TOO_LARGE", "Zaznaczenia zajmują za dużo miejsca. Uprość rysunek odręczny.")
    return out


# ─── Dołączanie do klipu ────────────────────────────────────────────────────


def _span(clip: Mapping[str, Any]) -> float:
    return float(clip.get("end_s") or 0) - float(clip.get("start_s") or 0)


def clip_covers(clip: Mapping[str, Any], video_id: Any, at_s: float) -> bool:
    return (clip.get("deleted_at") is None and s(clip.get("video_id")) == s(video_id)
            and float(clip.get("start_s") or 0) <= at_s <= float(clip.get("end_s") or 0))


def pick_clip(clips: Iterable[Mapping[str, Any]], video_id: Any, at_s: float) -> Optional[str]:
    """Klip, do którego zrzut dołącza się sam: w zakresie na TYM nagraniu, a przy kilku najkrótszy (potem najstarszy)."""
    found = [c for c in clips if clip_covers(c, video_id, at_s)]
    if not found:
        return None
    found.sort(key=lambda c: (_span(c), str(c.get("created_at") or ""), s(c.get("id"))))
    return s(found[0]["id"])


def reattach_after_clip_change(shots: Sequence[Mapping[str, Any]], clip: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Zmiany dla zrzutów po utworzeniu albo zmianie zakresu klipu.

    Zgarnia zrzuty `auto` bez klipu, które mieszczą się w zakresie. Zrzut `auto` już przy tym klipie, który wypadł z
    zakresu, wraca do stanu bez klipu (`clip_id = None`, wciąż `auto`, więc inny klip może go zgarnąć).
    `manual` i `detached` zostają nietknięte. Wynik: `[{id, clip_id}]` tylko tam, gdzie coś się zmienia."""
    changes: List[Dict[str, Any]] = []
    for shot in shots:
        mode = s(shot.get("attach_mode")) or "auto"
        if mode != "auto" or shot.get("deleted_at") is not None:
            continue
        inside = clip_covers(clip, shot.get("video_id"), float(shot.get("at_s") or 0))
        current = s(shot.get("clip_id")) or None
        if current is None and inside:
            changes.append({"id": shot["id"], "clip_id": clip["id"]})
        elif current == s(clip.get("id")) and not inside:
            changes.append({"id": shot["id"], "clip_id": None})
    return changes


# ─── Obraz ──────────────────────────────────────────────────────────────────


def sniff_image(data: bytes) -> Optional[str]:
    """`jpeg` | `webp` po magicznych bajtach (nagłówek Content-Type niczego nie dowodzi)."""
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def declared_type(content_type: Any) -> Optional[str]:
    value = s(content_type).split(";")[0].strip().lower()
    return {"image/jpeg": "jpeg", "image/jpg": "jpeg", "image/webp": "webp"}.get(value)


def check_upload(data: bytes, content_type: Any) -> str:
    if not data:
        raise RuleError(422, "SHOT_IMAGE_EMPTY", "Nie przesłano obrazu.")
    if len(data) > MAX_IMAGE_BYTES:
        raise RuleError(413, "SHOT_IMAGE_TOO_LARGE", f"Obraz jest za duży (najwyżej {MAX_IMAGE_BYTES // (1024 * 1024)} MB).")
    claimed, real = declared_type(content_type), sniff_image(data)
    if claimed is None or real is None or claimed != real:
        raise RuleError(415, "SHOT_IMAGE_TYPE", "Obsługiwane są tylko obrazy JPEG i WebP, zgodne z nagłówkiem Content-Type.")
    return real


def stale_processing(updated_at: Any, now: Any) -> bool:
    """Zadanie `processing` starsze niż 5 minut uznajemy za przerwane (restart serwera)."""
    when, current = aware(updated_at), aware(now)
    return bool(when and current and (current - when).total_seconds() > PROCESSING_STALE_S)


# ─── Nazwy plików i pasek ───────────────────────────────────────────────────


def clock(seconds: float) -> str:
    tenths = int(round(max(0.0, float(seconds)) * 10))
    whole, frac = divmod(tenths, 10)
    h, rest = divmod(whole, 3600)
    m, sec = divmod(rest, 60)
    base = f"{h}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"
    return f"{base}.{frac}" if frac else base


def png_filename(title: Any, match_code: Any, at_s: float) -> str:
    stamp = clock(at_s).replace(":", "-")
    base = " ".join(p for p in (s(match_code).replace("/", "-"), s(title)) if p) or "zrzut"
    return safe_filename(f"{base} {stamp}", "png", "zrzut")


def banner_lines(match_label: Any, at_s: float, category: Any, match_clock: Optional[str] = None) -> List[str]:
    """Pasek na dole PNG: mecz, minuta (zegar nagrania) i kategoria. Puste pozycje są pomijane."""
    parts = [s(match_label), match_clock or clock(at_s), s(category)]
    return [p for p in parts if p]
