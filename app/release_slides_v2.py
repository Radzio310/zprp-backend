"""Model slajdu premiery `schema: 2` (czysta logika, bez bazy i bez R2).

Slajd w JSONB trzyma klucze obiektów R2 (`media.key`, `media.poster_key`);
adresy (`url`, `poster_url`) są podpisywane dopiero przy odczycie.
Starsze slajdy (model 1: template/media_key/kicker...) są tłumaczone w locie,
bez przepisywania danych w bazie.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any, Optional

from fastapi import HTTPException

SCHEMA = 2
ALLOWED_TAGS = {"new", "improved", "fixed"}
ALLOWED_LAYOUTS = {"side", "rise", "zoom", "type", "duo"}
ALLOWED_SIDES = {"left", "right"}
ALLOWED_FLIGHTS = {"spin", "flip", "swirl", "card", "throw"}
ALLOWED_KINDS = {"image", "video"}
MAX_TITLE = 180
MAX_BODY = 600
MAX_PREVIEW_SHOTS = 12
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
ICON_NAME = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,39}$")
DEFAULT_ASPECT = 9 / 16

_LAYOUT_FROM_TEMPLATE = {"hero": "zoom", "statement": "type", "split": "side"}
_TEMPLATE_FROM_LAYOUT = {"zoom": "hero", "type": "statement", "side": "split"}


def is_v2(slide: Any) -> bool:
    return isinstance(slide, dict) and int(slide.get("schema") or 0) == SCHEMA


def _num(value: Any, fallback: Optional[float] = None) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def clean_focus(raw: Any) -> Optional[dict[str, float]]:
    if not isinstance(raw, dict):
        return None
    vals = [_num(raw.get(k)) for k in ("x", "y", "w", "h")]
    if any(v is None for v in vals):
        return None
    x, y, w, h = vals  # type: ignore[misc]
    if w <= 0 or h <= 0:
        return None
    x, y = clamp01(x), clamp01(y)
    w = min(w, 1.0 - x)
    h = min(h, 1.0 - y)
    if w <= 0.001 or h <= 0.001:
        return None
    return {"x": round(x, 4), "y": round(y, 4), "w": round(w, 4), "h": round(h, 4)}


def _key_from_url(url: str, asset_types: dict[str, str]) -> str:
    path = url.split("?", 1)[0]
    for key in asset_types:
        if path.endswith(key):
            return key
    return ""


def clean_media(raw: Any, *, where: str, asset_types: dict[str, str]) -> Optional[dict[str, Any]]:
    """Normalizuje media do postaci przechowywanej: kind, key, poster_key, aspect, duration_ms."""
    if raw in (None, {}):
        return None
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowe media.")
    kind = str(raw.get("kind") or "image")
    if kind not in ALLOWED_KINDS:
        raise HTTPException(status_code=422, detail=f"{where}: nieznany rodzaj materiału.")
    key = str(raw.get("key") or "").strip()
    poster_key = str(raw.get("poster_key") or "").strip()
    # Klient oddaje to, co dostał z GET - gdy zgubił klucz, odzyskujemy go z adresu.
    if not key and raw.get("url"):
        key = _key_from_url(str(raw["url"]), asset_types)
    if not poster_key and raw.get("poster_url"):
        poster_key = _key_from_url(str(raw["poster_url"]), asset_types)
    if not key:
        raise HTTPException(status_code=422, detail=f"{where}: materiał nie został wgrany.")
    if key not in asset_types:
        raise HTTPException(status_code=422, detail=f"{where}: nieznany materiał.")
    content_type = asset_types[key]
    if kind == "video" and content_type != "video/mp4":
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowy film.")
    if kind == "image" and not content_type.startswith("image/"):
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowa grafika.")
    if poster_key and (
        poster_key not in asset_types or not asset_types[poster_key].startswith("image/")
    ):
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowy poster.")
    aspect = _num(raw.get("aspect"), DEFAULT_ASPECT) or DEFAULT_ASPECT
    media: dict[str, Any] = {
        "kind": kind,
        "key": key,
        "poster_key": poster_key or None,
        "aspect": round(min(max(aspect, 0.2), 5.0), 4),
        "duration_ms": None,
    }
    if kind == "video":
        duration = _num(raw.get("duration_ms"))
        media["duration_ms"] = int(duration) if duration and duration > 0 else None
    return media


def clean_slide_v2(
    raw: Any,
    *,
    position: int,
    publishing: bool,
    asset_types: dict[str, str],
    seen_ids: set[str],
) -> dict[str, Any]:
    where = f"Slajd {position + 1}"
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowy format.")
    slide_id = str(raw.get("id") or "").strip()[:80] or f"s{position + 1}-{uuid.uuid4().hex[:6]}"
    if slide_id in seen_ids:
        raise HTTPException(status_code=422, detail=f"{where}: powtórzony identyfikator.")
    seen_ids.add(slide_id)

    title = str(raw.get("title") or "").strip()
    body = str(raw.get("body") or "").strip()
    if len(title) > MAX_TITLE or len(body) > MAX_BODY:
        raise HTTPException(status_code=422, detail=f"{where}: tytuł lub opis za długi.")
    tag = str(raw.get("tag") or "new")
    if tag not in ALLOWED_TAGS:
        raise HTTPException(status_code=422, detail=f"{where}: nieznana etykieta.")
    accent = raw.get("accent")
    if accent in (None, ""):
        accent = None
    elif not HEX_COLOR.fullmatch(str(accent)):
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowy kolor.")
    icon = raw.get("icon")
    if icon in (None, ""):
        icon = None
    elif not ICON_NAME.fullmatch(str(icon)):
        raise HTTPException(status_code=422, detail=f"{where}: nieprawidłowa ikona.")
    layout = raw.get("layout") or None
    if layout is not None and layout not in ALLOWED_LAYOUTS:
        raise HTTPException(status_code=422, detail=f"{where}: nieznany układ.")
    side = str(raw.get("side") or "left")
    if side not in ALLOWED_SIDES:
        raise HTTPException(status_code=422, detail=f"{where}: nieznana strona.")
    flight = raw.get("flight") or None
    if flight is not None and flight not in ALLOWED_FLIGHTS:
        raise HTTPException(status_code=422, detail=f"{where}: nieznany lot.")

    media = clean_media(raw.get("media"), where=where, asset_types=asset_types)
    media2 = clean_media(raw.get("media2"), where=f"{where} (drugi materiał)", asset_types=asset_types)
    if publishing:
        if not media and not title:
            raise HTTPException(
                status_code=422, detail=f"{where} wymaga materiału albo tytułu przed publikacją."
            )
        if layout == "duo" and not (media and media2):
            raise HTTPException(status_code=422, detail=f"{where}: układ duo wymaga dwóch materiałów.")
    return {
        "schema": SCHEMA,
        "id": slide_id,
        "title": title,
        "body": body,
        "tag": tag,
        "accent": accent,
        "icon": icon,
        "media": media,
        "media2": media2,
        "layout": layout,
        "side": side,
        "focus": clean_focus(raw.get("focus")),
        "flight": flight,
    }


def clean_slides_v2(
    raw_slides: list[Any], *, publishing: bool, asset_types: dict[str, str], max_slides: int = 12
) -> list[dict[str, Any]]:
    if len(raw_slides) > max_slides:
        raise HTTPException(status_code=422, detail=f"Najwyżej {max_slides} slajdów.")
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for position, raw in enumerate(raw_slides):
        if isinstance(raw, dict) and not is_v2(raw) and any(
            k in raw for k in ("template", "media_key", "kicker", "media_type")
        ):
            raw = migrate_slide_v1(raw, {})
        out.append(
            clean_slide_v2(
                raw, position=position, publishing=publishing,
                asset_types=asset_types, seen_ids=seen,
            )
        )
    if publishing and not out:
        raise HTTPException(status_code=422, detail="Dodaj przynajmniej jeden slajd przed publikacją.")
    return out


def clean_preview_shots(raw: Any, asset_types: dict[str, str]) -> list[dict[str, Any]]:
    shots = raw or []
    if not isinstance(shots, list) or len(shots) > MAX_PREVIEW_SHOTS:
        raise HTTPException(status_code=422, detail=f"Najwyżej {MAX_PREVIEW_SHOTS} zrzutów podglądu.")
    result = []
    for i, shot in enumerate(shots):
        media = clean_media(shot, where=f"Zrzut {i + 1}", asset_types=asset_types)
        if media:
            result.append(media)
    return result


def migrate_slide_v1(slide: dict[str, Any], asset_dims: dict[str, tuple[int, int]]) -> dict[str, Any]:
    """Model 1 -> 2. Nic nie ginie: klucze mediów zostają, treść idzie do title/body."""
    if is_v2(slide):
        return slide
    kind = "video" if slide.get("media_type") == "video" else "image"
    key = str(slide.get("media_key") or "").strip()
    media = None
    if key:
        dims = asset_dims.get(key)
        aspect = round(dims[0] / dims[1], 4) if dims and dims[1] else round(DEFAULT_ASPECT, 4)
        media = {
            "kind": kind,
            "key": key,
            "poster_key": str(slide.get("poster_key") or "").strip() or None,
            "aspect": aspect,
            "duration_ms": int(slide["video_duration_ms"]) if slide.get("video_duration_ms") else None,
        }
    title = str(slide.get("title") or "").strip() or str(slide.get("kicker") or "").strip()
    accent = slide.get("accent")
    fx, fy = _num(slide.get("focal_x"), 0.5), _num(slide.get("focal_y"), 0.5)
    focus = None
    if media and (abs(fx - 0.5) > 0.02 or abs(fy - 0.5) > 0.02):
        focus = clean_focus({"x": clamp01(fx - 0.25), "y": clamp01(fy - 0.25), "w": 0.5, "h": 0.5})
    return {
        "schema": SCHEMA,
        "id": str(slide.get("id") or uuid.uuid4().hex[:8]),
        "title": title[:MAX_TITLE],
        "body": str(slide.get("body") or "").strip()[:MAX_BODY],
        "tag": "new",
        "accent": accent if accent and HEX_COLOR.fullmatch(str(accent)) else None,
        "icon": None,
        "media": media,
        "media2": None,
        "layout": _LAYOUT_FROM_TEMPLATE.get(str(slide.get("template") or "")),
        "side": "right" if slide.get("text_align") == "right" else "left",
        "focus": focus,
        "flight": None,
    }


def project_to_v1(slide: dict[str, Any]) -> dict[str, Any]:
    """Slajd 2 -> kształt, który rozumieją stare wydania aplikacji (/app/releases/experience[s])."""
    if not is_v2(slide):
        return slide
    media = slide.get("media") or {}
    focus = slide.get("focus")
    fx = clamp01(focus["x"] + focus["w"] / 2) if focus else 0.5
    fy = clamp01(focus["y"] + focus["h"] / 2) if focus else 0.5
    dur = media.get("duration_ms")
    return {
        "id": slide.get("id"),
        "template": _TEMPLATE_FROM_LAYOUT.get(str(slide.get("layout") or ""), "feature"),
        "media_key": media.get("key"),
        "media_url": media.get("url"),
        "media_type": media.get("kind") or "image",
        "poster_key": media.get("poster_key"),
        "poster_url": media.get("poster_url"),
        "video_duration_ms": min(int(dur), 10000) if dur else None,
        "kicker": "",
        "title": slide.get("title") or "",
        "body": slide.get("body") or "",
        "accent": slide.get("accent") or "#F4B942",
        "text_color": "#FFFFFF",
        "overlay_opacity": 0.62,
        "text_position": "bottom",
        "text_align": "left",
        "focal_x": fx,
        "focal_y": fy,
        "animation": "cinematic_zoom",
        "transition": "crossfade",
        "duration_ms": min(max(int(dur), 2500), 12000) if dur else 5200,
        "cta_label": "",
        "cta_url": "",
        "accessibility_label": "",
    }


def slide_keys(slide: Any) -> set[str]:
    """Wszystkie klucze R2 użyte przez slajd (model 1 i 2)."""
    keys: set[str] = set()
    if not isinstance(slide, dict):
        return keys
    for field in ("media_key", "poster_key"):
        if slide.get(field):
            keys.add(str(slide[field]))
    for field in ("media", "media2"):
        m = slide.get(field)
        if isinstance(m, dict):
            for kf in ("key", "poster_key"):
                if m.get(kf):
                    keys.add(str(m[kf]))
    return keys


def media_keys(items: Any) -> set[str]:
    keys: set[str] = set()
    for m in items or []:
        if isinstance(m, dict):
            for kf in ("key", "poster_key"):
                if m.get(kf):
                    keys.add(str(m[kf]))
    return keys


# ----------------------------- kreator AI -----------------------------

_BULLET = re.compile(r"^\s*(?:[-*•–]|\d+[.)])\s*(.+?)\s*$")
_FIXED = re.compile(r"(napraw|błęd|błąd|\bfix)", re.I)
_IMPROVED = re.compile(r"(popraw|ulepsz|szybsz|przyspiesz|zmienion|usprawni)", re.I)

ALLOWED_ICONS = (
    "sparkles", "rocket", "flash", "star", "trophy", "whistle", "timer", "stopwatch", "people", "person",
    "calendar", "map", "navigate", "car", "wallet", "cash", "document-text", "clipboard", "create",
    "pencil", "camera", "videocam", "images", "notifications", "chatbubbles", "shield-checkmark",
    "lock-closed", "cloud-upload", "cloud-download", "sync", "speedometer", "bug", "build", "settings",
    "stats-chart", "podium", "football", "search", "filter", "share-social", "qr-code", "school", "heart",
)
AI_DEFAULT_MODEL = "claude-opus-5-5"
AI_TIMEOUT_S = 90.0
AI_MAX_TOKENS = 8000

DRAFT_SYSTEM_PROMPT = (
    "Jesteś redaktorem premier aplikacji mobilnej BAZA dla sędziów piłki ręcznej. "
    "Z opisu zmian wersji zrób pokaz slajdów po polsku, z polskimi znakami, bez emoji.\n"
    "Zasady:\n"
    "- Każdy slajd to jedna zmiana widoczna dla użytkownika. Pomiń zmiany czysto techniczne. "
    "Nie wymyślaj funkcji spoza opisu.\n"
    "- Tytuł: krótki, konkretny, jak plakat, najwyżej 6 słów, bez nadtytułów i bez kropki na końcu.\n"
    "- Opis: 1-2 zdania, z korzyścią dla sędziego (co zyskuje, co mu się upraszcza), najwyżej 160 znaków.\n"
    "- Nie używaj długich myślników (— ani –). Używaj przecinków, dwukropków lub krótkich zdań.\n"
    "- tag: new (nowa funkcja), improved (ulepszenie), fixed (poprawka błędu).\n"
    "- icon: motyw wyłącznie z dozwolonej listy w schemacie; \"none\" gdy nic nie pasuje.\n"
    "- layout, side, flight: dobieraj kompozycje tak, by sąsiednie slajdy wyraźnie się różniły "
    "(nie powtarzaj tego samego układu ani tej samej strony dwa razy z rzędu). "
    "flight \"none\" jest w porządku.\n"
    "- accent: kolor #RRGGBB pasujący do tematu slajdu albo pusty tekst.\n"
    "- Brak mediów: nie wspominaj o zrzutach ani filmach.\n"
    "- warnings: krótkie uwagi dla redaktora (np. pominięte pozycje), zwykle pusta lista.\n"
    "Zrób najwyżej %d slajdów."
)

DRAFT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "slides": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "tag": {"type": "string", "enum": ["new", "improved", "fixed"]},
                    "accent": {"type": "string"},
                    "icon": {"type": "string", "enum": [*ALLOWED_ICONS, "none"]},
                    "layout": {"type": "string", "enum": ["side", "rise", "zoom", "type"]},
                    "side": {"type": "string", "enum": ["left", "right"]},
                    "flight": {"type": "string", "enum": [*sorted(ALLOWED_FLIGHTS), "none"]},
                },
                "required": ["title", "body", "tag", "accent", "icon", "layout", "side", "flight"],
                "additionalProperties": False,
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["slides", "warnings"],
    "additionalProperties": False,
}


def parse_draft_json(text: str) -> list[dict[str, Any]]:
    cleaned = (text or "").strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("brak JSON-a w odpowiedzi modelu")
    data = json.loads(cleaned[start : end + 1])
    slides = data.get("slides")
    if not isinstance(slides, list):
        raise ValueError("brak listy slajdów")
    return [s for s in slides if isinstance(s, dict)]


def parse_ai_answer(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    data = json.loads((text or "").strip())
    slides = data.get("slides") if isinstance(data, dict) else None
    if not isinstance(slides, list):
        raise ValueError("brak listy slajdów")
    notes = [str(w).strip() for w in (data.get("warnings") or []) if str(w).strip()]
    return [x for x in slides if isinstance(x, dict)], notes


async def ai_draft(
    description: str, max_slides: int, *, client: Any = None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Szkic slajdów przez Claude (structured outputs). Rzuca wyjątek, gdy się nie uda."""
    import os

    if client is None:
        key = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
        if not key:
            raise RuntimeError("brak ANTHROPIC_API_KEY")
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=key, timeout=AI_TIMEOUT_S, max_retries=1)
    model = (os.getenv("RELEASE_AI_MODEL") or AI_DEFAULT_MODEL).strip()
    response = await client.beta.messages.create(
        model=model,
        max_tokens=AI_MAX_TOKENS,
        thinking={"type": "adaptive"},
        output_config={"effort": "high", "format": {"type": "json_schema", "schema": DRAFT_SCHEMA}},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        system=DRAFT_SYSTEM_PROMPT % max_slides,
        messages=[{"role": "user", "content": description}],
    )
    stop = getattr(response, "stop_reason", None)
    if stop == "refusal":
        raise RuntimeError("model odmówił odpowiedzi (refusal)")
    if stop == "max_tokens":
        raise RuntimeError("odpowiedź modelu ucięta (max_tokens)")
    texts = [b.text for b in response.content if getattr(b, "type", None) == "text"]
    if not texts:
        raise ValueError("brak tekstu w odpowiedzi modelu")
    return parse_ai_answer(texts[-1])


def heuristic_draft(description: str, max_slides: int) -> list[dict[str, Any]]:
    """Szkic bez AI: każda pozycja listy z opisu = slajd."""
    items = []
    for line in (description or "").splitlines():
        m = _BULLET.match(line)
        text = (m.group(1) if m else line).strip()
        if text:
            items.append(text)
    slides = []
    for text in items:
        tag = "fixed" if _FIXED.search(text) else "improved" if _IMPROVED.search(text) else "new"
        parts = re.split(r"\s[-–]\s|:\s|(?<=[.!?])\s+", text, maxsplit=1)
        title = parts[0][:60].strip(" .:")
        body = (parts[1] if len(parts) > 1 else "")[:160].strip()
        slides.append({"title": title, "body": body, "tag": tag, "layout": None})
    return slides


def finalize_draft(
    raw_slides: list[dict[str, Any]], max_slides: int
) -> tuple[list[dict[str, Any]], list[str]]:
    """Czyści szkic (bez mediów) do slajdów schema 2 i zbiera ostrzeżenia."""
    warnings: list[str] = []
    slides: list[dict[str, Any]] = []
    for raw in raw_slides[:max_slides]:
        title = str(raw.get("title") or "").strip()[:MAX_TITLE]
        if not title:
            continue
        tag = str(raw.get("tag") or "new")
        layout = raw.get("layout")
        accent = str(raw.get("accent") or "").strip()
        icon = str(raw.get("icon") or "").strip()
        flight = raw.get("flight")
        slides.append(
            {
                "schema": SCHEMA,
                "id": f"s{len(slides) + 1}-{uuid.uuid4().hex[:6]}",
                "title": title,
                "body": str(raw.get("body") or "").strip()[:MAX_BODY],
                "tag": tag if tag in ALLOWED_TAGS else "new",
                "accent": accent if HEX_COLOR.fullmatch(accent) else None,
                "icon": icon if icon in ALLOWED_ICONS else None,
                "media": None,
                "media2": None,
                "layout": layout if layout in ALLOWED_LAYOUTS and layout != "duo" else None,
                "side": raw.get("side") if raw.get("side") in ALLOWED_SIDES else "left",
                "focus": None,
                "flight": flight if flight in ALLOWED_FLIGHTS else None,
            }
        )
    if len(raw_slides) > max_slides:
        warnings.append(f"Pominięto {len(raw_slides) - max_slides} pozycji ponad limit {max_slides} slajdów.")
    if not slides:
        warnings.append("Nie udało się wyłonić żadnego slajdu z opisu zmian.")
    for i in range(len(slides)):
        warnings.append(f"Slajd {i + 1}: dodaj zrzut ekranu lub film.")
    return slides, warnings
