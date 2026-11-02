"""Reguły ogłoszeń okręgowych: miniatury i daty. Liść: bez bazy i bez sieci."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

THUMB_WIDTH = 480
THUMB_SUFFIX = "_thumb"


def thumb_filename(image_filename: str, ext: str = "webp") -> str:
    """`abc.png` -> `abc_thumb.webp` (nazwa unikalna jak oryginał, więc cache bezpieczny)."""
    stem = os.path.splitext(os.path.basename(image_filename or ""))[0]
    return f"{stem}{THUMB_SUFFIX}.{ext}"


def make_thumbnail(src_path: str, dest_dir: str, width: int = THUMB_WIDTH) -> Optional[str]:
    """Zapisuje miniaturę o szerokości `width` (WebP, awaryjnie JPEG) obok oryginału.

    Zwraca nazwę pliku miniatury albo None. NIGDY nie rzuca: brak miniatury
    nie może wywrócić publikacji. Grafika węższa niż `width` nie jest powiększana.
    """
    try:
        from PIL import Image, ImageOps

        with Image.open(src_path) as im:
            im = ImageOps.exif_transpose(im)
            if im.width > width:
                height = max(1, round(im.height * width / im.width))
                im = im.resize((width, height), Image.LANCZOS)
            else:
                im = im.copy()
            for ext, fmt, kwargs, mode in (
                ("webp", "WEBP", {"quality": 80, "method": 4}, None),
                ("jpg", "JPEG", {"quality": 82, "optimize": True}, "RGB"),
            ):
                name = thumb_filename(os.path.basename(src_path), ext)
                dest = os.path.join(dest_dir, name)
                try:
                    out = im.convert(mode) if mode and im.mode != mode else im
                    out.save(dest, fmt, **kwargs)
                    return name
                except Exception:
                    try:
                        if os.path.isfile(dest):
                            os.remove(dest)
                    except OSError:
                        pass
        return None
    except Exception:
        return None


def _as_utc(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:  # reakcje/komentarze zapisują datetime.utcnow()
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def activity_times(likes: Any, comments: Any) -> list[datetime]:
    """Czasy `created_at` wszystkich reakcji i komentarzy."""
    out: list[datetime] = []
    for group in (likes, comments):
        if not isinstance(group, list):
            continue
        for entry in group:
            if isinstance(entry, dict):
                dt = _as_utc(entry.get("created_at"))
                if dt:
                    out.append(dt)
    return out


def backfilled_updated_at(
    updated_at: Any, likes: Any, comments: Any
) -> Optional[datetime]:
    """Nowa data ogłoszenia zniekształconej przez reakcję/komentarz, albo None.

    Ogłoszenie powstało przed pierwszą reakcją. Gdy `updated_at` jest PÓŹNIEJSZY
    niż najwcześniejszy `created_at` z `likes` i `comments`, to czas podbiła
    aktywność (albo edycja po niej: tego z danych nie odróżnimy, więc skrypt
    pokazuje to w podglądzie). Gdy jest równy lub wcześniejszy, nic nie zmieniamy.
    """
    current = _as_utc(updated_at)
    times = activity_times(likes, comments)
    if not current or not times:
        return None
    earliest = min(times)
    if current > earliest:
        return earliest
    return None


def order_conflicts(rows: Iterable[dict]) -> list[tuple[int, int]]:
    """Pary (id_nowszy, id_starszy), gdzie nowsze id ma WCZEŚNIEJSZĄ datę.

    `rows`: słowniki z `id`, `province`, `updated_at`. Porównanie w obrębie okręgu.
    Edycja może to uzasadniać, dlatego to lista do przeglądu, nie błąd.
    """
    by_prov: dict[Any, list[dict]] = {}
    for r in rows:
        by_prov.setdefault(r.get("province"), []).append(r)
    out: list[tuple[int, int]] = []
    for items in by_prov.values():
        items = sorted(items, key=lambda r: r["id"])
        for i, older in enumerate(items):
            for newer in items[i + 1:]:
                a, b = _as_utc(older["updated_at"]), _as_utc(newer["updated_at"])
                if a and b and b < a:
                    out.append((newer["id"], older["id"]))
    return out
