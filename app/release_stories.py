from __future__ import annotations

import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import jwt
from fastapi import APIRouter, Depends, File, HTTPException, Query, Security, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field
from sqlalchemy import delete, insert, select, update
from starlette.concurrency import run_in_threadpool

from app.db import (
    admin_settings,
    app_versions,
    database,
    release_experiences,
    release_story_assets,
)
from app.deps import Settings, get_settings


router = APIRouter(tags=["BAZA: Release Stories"])
bearer = HTTPBearer(auto_error=True)

ALLOWED_TEMPLATES = {"hero", "feature", "statement", "split", "cta"}
ALLOWED_ANIMATIONS = {
    "cinematic_zoom",
    "parallax_layers",
    "light_sweep",
    "mask_reveal",
    "card_explosion",
    "glitch_cut",
    "particle_burst",
    "device_fly_in",
}
ALLOWED_TRANSITIONS = {"crossfade", "push", "zoom", "flash"}
ALLOWED_ALIGNMENTS = {"top", "center", "bottom"}
ALLOWED_MODES = {"changelog_only", "story_then_changelog", "story_only"}
ALLOWED_STATUSES = {"draft", "published"}
MAX_UPLOAD_BYTES = 12 * 1024 * 1024
MAX_SLIDES = 12
SIGNED_URL_TTL_SECONDS = 24 * 60 * 60
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


class ReleaseStorySlide(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    template: Literal["hero", "feature", "statement", "split", "cta"] = "feature"
    media_key: Optional[str] = None
    media_url: Optional[str] = None
    kicker: str = Field(default="", max_length=100)
    title: str = Field(default="", max_length=180)
    body: str = Field(default="", max_length=420)
    accent: str = "#F4B942"
    text_color: str = "#FFFFFF"
    overlay_opacity: float = Field(default=0.62, ge=0.0, le=0.95)
    text_position: Literal["top", "center", "bottom"] = "bottom"
    text_align: Literal["left", "center"] = "left"
    focal_x: float = Field(default=0.5, ge=0.0, le=1.0)
    focal_y: float = Field(default=0.5, ge=0.0, le=1.0)
    animation: str = "cinematic_zoom"
    transition: str = "crossfade"
    duration_ms: int = Field(default=5200, ge=2500, le=12000)
    cta_label: str = Field(default="", max_length=80)
    cta_url: str = Field(default="", max_length=1000)
    accessibility_label: str = Field(default="", max_length=240)


class ReleaseStoryUpsert(BaseModel):
    status: Literal["draft", "published"] = "draft"
    experience_mode: Literal[
        "changelog_only", "story_then_changelog", "story_only"
    ] = "story_then_changelog"
    display_generation: int = Field(default=1, ge=1, le=100000)
    headline: str = Field(
        default="BAZA przekracza kolejne granice", min_length=1, max_length=180
    )
    slides: list[ReleaseStorySlide] = Field(default_factory=list, max_length=MAX_SLIDES)
    bump_generation: bool = False


def _semver_key(value: str) -> tuple[int, int, int]:
    parts = str(value or "").strip().lstrip("vV").split(".")
    parsed: list[int] = []
    for part in parts[:3]:
        match = re.match(r"^(\d+)", part)
        parsed.append(int(match.group(1)) if match else 0)
    while len(parsed) < 3:
        parsed.append(0)
    return parsed[0], parsed[1], parsed[2]


async def require_release_admin(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    settings: Settings = Depends(get_settings),
) -> str:
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Sesja administratora wygasła.") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Nieprawidłowa sesja administratora.") from exc

    judge_id = str(payload.get("judge_id") or "").strip()
    if not judge_id:
        raise HTTPException(status_code=403, detail="Token nie zawiera identyfikatora sędziego.")
    row = await database.fetch_one(select(admin_settings.c.allowed_admins).limit(1))
    allowed = {str(value) for value in ((dict(row).get("allowed_admins") if row else []) or [])}
    if judge_id not in allowed:
        raise HTTPException(status_code=403, detail="Brak uprawnień administratora.")
    return judge_id


def _json_value(raw: Any, fallback: Any) -> Any:
    if raw is None:
        return fallback
    if isinstance(raw, (list, dict)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def _storage_config() -> dict[str, str]:
    # Osobne zmienne mediów są preferowane. Istniejąca konfiguracja backupów
    # jest bezpiecznym fallbackiem; obiekty trafiają do osobnego prefiksu.
    config = {
        "endpoint": os.getenv("RELEASE_MEDIA_S3_ENDPOINT")
        or os.getenv("BACKUP_S3_ENDPOINT", ""),
        "region": os.getenv("RELEASE_MEDIA_S3_REGION")
        or os.getenv("BACKUP_S3_REGION", "auto"),
        "bucket": os.getenv("RELEASE_MEDIA_S3_BUCKET")
        or os.getenv("BACKUP_S3_BUCKET", ""),
        "access_key": os.getenv("RELEASE_MEDIA_S3_ACCESS_KEY_ID")
        or os.getenv("BACKUP_S3_ACCESS_KEY_ID", ""),
        "secret_key": os.getenv("RELEASE_MEDIA_S3_SECRET_ACCESS_KEY")
        or os.getenv("BACKUP_S3_SECRET_ACCESS_KEY", ""),
        "prefix": (
            os.getenv("RELEASE_MEDIA_S3_PREFIX", "release-stories").strip("/")
            or "release-stories"
        ),
        "public_base": os.getenv("RELEASE_MEDIA_PUBLIC_BASE_URL", "").rstrip("/"),
    }
    required = ("endpoint", "bucket", "access_key", "secret_key")
    if any(not config[key] for key in required):
        raise HTTPException(
            status_code=503,
            detail="Magazyn Cloudflare R2 dla premier nie jest skonfigurowany.",
        )
    return config


def _s3_client(config: dict[str, str]):
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=config["endpoint"],
        region_name=config["region"],
        aws_access_key_id=config["access_key"],
        aws_secret_access_key=config["secret_key"],
    )


def _asset_url(object_key: str) -> str:
    config = _storage_config()
    if config["public_base"]:
        return f"{config['public_base']}/{object_key}"
    client = _s3_client(config)
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": config["bucket"], "Key": object_key},
        ExpiresIn=SIGNED_URL_TTL_SECONDS,
    )


def _put_object(object_key: str, payload: bytes) -> None:
    config = _storage_config()
    _s3_client(config).put_object(
        Bucket=config["bucket"],
        Key=object_key,
        Body=payload,
        ContentType="image/webp",
        CacheControl="public, max-age=31536000, immutable",
    )


def _delete_object(object_key: str) -> None:
    try:
        config = _storage_config()
        _s3_client(config).delete_object(Bucket=config["bucket"], Key=object_key)
    except Exception:
        # Usunięcie rekordu nie może zostać zablokowane chwilową awarią R2.
        # Osierocone obiekty można posprzątać po prefiksie.
        pass


def _prepare_image(raw: bytes) -> tuple[bytes, int, int]:
    try:
        with Image.open(io.BytesIO(raw)) as opened:
            image = ImageOps.exif_transpose(opened)
            image.load()
    except (UnidentifiedImageError, OSError) as exc:
        raise HTTPException(status_code=415, detail="Plik nie jest obsługiwanym obrazem.") from exc

    width, height = image.size
    if width <= 0 or height <= 0:
        raise HTTPException(status_code=422, detail="Nieprawidłowe wymiary obrazu.")
    ratio = width / height
    target_ratio = 9 / 16
    if abs(ratio - target_ratio) > 0.025:
        raise HTTPException(
            status_code=422,
            detail=f"Grafika musi mieć proporcje 9:16 (otrzymano {width}×{height}).",
        )

    # Wyrównujemy drobne różnice po cropie i ograniczamy koszt pamięci na telefonie.
    if width >= 1080 and height >= 1920:
        out_w, out_h = 1080, 1920
    else:
        out_w = max(360, width - (width % 9))
        out_h = int(out_w * 16 / 9)
    image = ImageOps.fit(image, (out_w, out_h), method=Image.Resampling.LANCZOS)
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGB")
    output = io.BytesIO()
    image.save(output, format="WEBP", quality=88, method=6)
    return output.getvalue(), out_w, out_h


async def _version_row(version_id: int):
    row = await database.fetch_one(select(app_versions).where(app_versions.c.id == version_id))
    if not row:
        raise HTTPException(status_code=404, detail="Wersja nie istnieje.")
    return row


async def _ensure_experience(version_id: int):
    await _version_row(version_id)
    row = await database.fetch_one(
        select(release_experiences).where(release_experiences.c.version_id == version_id)
    )
    if row:
        return row
    try:
        await database.execute(
            insert(release_experiences).values(
                version_id=version_id,
                status="draft",
                experience_mode="story_then_changelog",
                display_generation=1,
                headline="BAZA przekracza kolejne granice",
                slides=[],
            )
        )
    except Exception:
        # Równoległe pierwsze otwarcie mogło już utworzyć rekord.
        pass
    row = await database.fetch_one(
        select(release_experiences).where(release_experiences.c.version_id == version_id)
    )
    if not row:
        raise HTTPException(status_code=500, detail="Nie udało się utworzyć pokazu.")
    return row


async def _assets_for(experience_id: int) -> list[dict[str, Any]]:
    rows = await database.fetch_all(
        select(release_story_assets)
        .where(release_story_assets.c.experience_id == experience_id)
        .order_by(release_story_assets.c.id.asc())
    )
    return [dict(row) for row in rows]


async def _serialize_story(row: Any, *, include_assets: bool = True) -> dict[str, Any]:
    data = dict(row)
    slides = _json_value(data.get("slides"), [])
    assets = await _assets_for(int(data["id"]))
    asset_by_key = {str(asset["object_key"]): asset for asset in assets}

    signed_by_key: dict[str, str] = {}
    for slide in slides:
        if not isinstance(slide, dict):
            continue
        key = str(slide.get("media_key") or "")
        if key and key in asset_by_key:
            if key not in signed_by_key:
                signed_by_key[key] = await run_in_threadpool(_asset_url, key)
            slide["media_url"] = signed_by_key[key]

    data["slides"] = slides
    if include_assets:
        serialized_assets = []
        for asset in assets:
            key = str(asset["object_key"])
            url = signed_by_key.get(key)
            if not url:
                url = await run_in_threadpool(_asset_url, key)
            serialized_assets.append({**asset, "url": url})
        data["assets"] = serialized_assets
    return data


async def purge_release_story_media(version_id: int) -> None:
    """Usuwa obiekty R2 przed skasowaniem wersji lub samego pokazu."""
    row = await database.fetch_one(
        select(release_experiences.c.id).where(
            release_experiences.c.version_id == version_id
        )
    )
    if not row:
        return
    assets = await _assets_for(int(dict(row)["id"]))
    for asset in assets:
        await run_in_threadpool(_delete_object, str(asset["object_key"]))


def _clean_and_validate_slides(
    slides: list[ReleaseStorySlide],
    *,
    publishing: bool,
    allowed_asset_keys: set[str],
) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for position, model in enumerate(slides):
        slide = model.model_dump() if hasattr(model, "model_dump") else model.dict()
        slide_id = str(slide.get("id") or "").strip()
        if not slide_id or slide_id in seen_ids:
            raise HTTPException(status_code=422, detail="Każdy slajd musi mieć unikalny identyfikator.")
        seen_ids.add(slide_id)

        animation = str(slide.get("animation") or "")
        transition = str(slide.get("transition") or "")
        if animation not in ALLOWED_ANIMATIONS:
            raise HTTPException(status_code=422, detail=f"Nieznana animacja slajdu {position + 1}.")
        if transition not in ALLOWED_TRANSITIONS:
            raise HTTPException(status_code=422, detail=f"Nieznane przejście slajdu {position + 1}.")
        for field in ("accent", "text_color"):
            if not HEX_COLOR.fullmatch(str(slide.get(field) or "")):
                raise HTTPException(status_code=422, detail=f"Nieprawidłowy kolor w slajdzie {position + 1}.")

        media_key = str(slide.get("media_key") or "").strip()
        if media_key and media_key not in allowed_asset_keys:
            raise HTTPException(status_code=422, detail=f"Nieznana grafika w slajdzie {position + 1}.")
        if publishing and (not media_key or not str(slide.get("title") or "").strip()):
            raise HTTPException(
                status_code=422,
                detail=f"Slajd {position + 1} wymaga grafiki 9:16 i tytułu przed publikacją.",
            )
        slide["media_key"] = media_key or None
        slide.pop("media_url", None)
        cleaned.append(slide)

    if publishing and not cleaned:
        raise HTTPException(status_code=422, detail="Dodaj przynajmniej jeden slajd przed publikacją.")
    return cleaned


@router.get("/admin/release-stories", summary="Podsumowanie pokazów wszystkich wersji")
async def list_release_story_summaries(_admin: str = Depends(require_release_admin)):
    rows = await database.fetch_all(
        select(
            release_experiences.c.id,
            release_experiences.c.version_id,
            release_experiences.c.status,
            release_experiences.c.experience_mode,
            release_experiences.c.display_generation,
            release_experiences.c.slides,
            release_experiences.c.updated_at,
        ).order_by(release_experiences.c.updated_at.desc())
    )
    return {
        "stories": [
            {
                **{key: value for key, value in dict(row).items() if key != "slides"},
                "slide_count": len(_json_value(dict(row).get("slides"), [])),
            }
            for row in rows
        ]
    }


@router.get("/admin/versions/{version_id}/release-story", summary="Pobierz szkic pokazu wersji")
async def get_release_story(version_id: int, _admin: str = Depends(require_release_admin)):
    row = await _ensure_experience(version_id)
    return {"experience": await _serialize_story(row)}


@router.put("/admin/versions/{version_id}/release-story", summary="Zapisz lub opublikuj pokaz wersji")
async def save_release_story(
    version_id: int,
    req: ReleaseStoryUpsert,
    _admin: str = Depends(require_release_admin),
):
    row = await _ensure_experience(version_id)
    current = dict(row)
    assets = await _assets_for(int(current["id"]))
    allowed_keys = {str(asset["object_key"]) for asset in assets}
    publishing = req.status == "published"
    slides = _clean_and_validate_slides(
        req.slides,
        publishing=publishing,
        allowed_asset_keys=allowed_keys,
    )
    generation = int(req.display_generation)
    if req.bump_generation:
        generation = max(generation, int(current.get("display_generation") or 1) + 1)

    values: dict[str, Any] = {
        "status": req.status,
        "experience_mode": req.experience_mode,
        "display_generation": generation,
        "headline": req.headline.strip(),
        "slides": slides,
        "updated_at": datetime.now(timezone.utc),
    }
    if publishing and current.get("status") != "published":
        values["published_at"] = datetime.now(timezone.utc)
    elif not publishing:
        values["published_at"] = None

    await database.execute(
        update(release_experiences)
        .where(release_experiences.c.id == int(current["id"]))
        .values(**values)
    )

    # Zastąpienie lub usunięcie grafiki w edytorze sprząta poprzedni obiekt.
    # Klucze są niezmienne, więc żaden opublikowany slajd nie wskazuje na plik,
    # który zmienił zawartość pod tym samym adresem.
    referenced_keys = {
        str(slide.get("media_key"))
        for slide in slides
        if isinstance(slide, dict) and slide.get("media_key")
    }
    for asset in assets:
        object_key = str(asset["object_key"])
        if object_key in referenced_keys:
            continue
        await run_in_threadpool(_delete_object, object_key)
        await database.execute(
            delete(release_story_assets).where(
                release_story_assets.c.id == int(asset["id"])
            )
        )

    updated = await database.fetch_one(
        select(release_experiences).where(release_experiences.c.id == int(current["id"]))
    )
    return {"success": True, "experience": await _serialize_story(updated)}


@router.delete("/admin/versions/{version_id}/release-story", summary="Usuń pokaz wersji")
async def delete_release_story(version_id: int, _admin: str = Depends(require_release_admin)):
    row = await database.fetch_one(
        select(release_experiences).where(release_experiences.c.version_id == version_id)
    )
    if not row:
        return {"success": True}
    data = dict(row)
    await purge_release_story_media(version_id)
    await database.execute(
        delete(release_experiences).where(release_experiences.c.id == int(data["id"]))
    )
    return {"success": True}


@router.post(
    "/admin/versions/{version_id}/release-story/assets",
    status_code=status.HTTP_201_CREATED,
    summary="Wgraj grafikę 9:16 do Cloudflare R2",
)
async def upload_release_story_asset(
    version_id: int,
    image: UploadFile = File(...),
    _admin: str = Depends(require_release_admin),
):
    raw = await image.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Pusty plik.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Grafika może mieć maksymalnie 12 MB.")

    version = dict(await _version_row(version_id))
    experience = dict(await _ensure_experience(version_id))
    payload, width, height = await run_in_threadpool(_prepare_image, raw)
    config = _storage_config()
    object_key = (
        f"{config['prefix']}/v{str(version['version']).strip()}/"
        f"{uuid.uuid4().hex}.webp"
    )
    await run_in_threadpool(_put_object, object_key, payload)
    try:
        asset_id = await database.execute(
            insert(release_story_assets).values(
                experience_id=int(experience["id"]),
                object_key=object_key,
                original_name=(image.filename or "grafika")[:512],
                content_type="image/webp",
                width=width,
                height=height,
                byte_size=len(payload),
            )
        )
    except Exception:
        await run_in_threadpool(_delete_object, object_key)
        raise
    url = await run_in_threadpool(_asset_url, object_key)
    return {
        "asset": {
            "id": int(asset_id),
            "object_key": object_key,
            "url": url,
            "width": width,
            "height": height,
            "byte_size": len(payload),
            "content_type": "image/webp",
        }
    }


@router.delete(
    "/admin/versions/{version_id}/release-story/assets/{asset_id}",
    summary="Usuń grafikę pokazu",
)
async def delete_release_story_asset(
    version_id: int,
    asset_id: int,
    _admin: str = Depends(require_release_admin),
):
    experience = await database.fetch_one(
        select(release_experiences).where(release_experiences.c.version_id == version_id)
    )
    if not experience:
        raise HTTPException(status_code=404, detail="Pokaz nie istnieje.")
    asset = await database.fetch_one(
        select(release_story_assets).where(
            (release_story_assets.c.id == asset_id)
            & (release_story_assets.c.experience_id == int(dict(experience)["id"]))
        )
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Grafika nie istnieje.")
    object_key = str(dict(asset)["object_key"])
    slides = _json_value(dict(experience).get("slides"), [])
    if any(isinstance(slide, dict) and slide.get("media_key") == object_key for slide in slides):
        raise HTTPException(status_code=409, detail="Grafika jest nadal używana przez slajd.")
    await run_in_threadpool(_delete_object, object_key)
    await database.execute(
        delete(release_story_assets).where(release_story_assets.c.id == asset_id)
    )
    return {"success": True}


@router.get("/app/releases/experience", summary="Pokaz premierowy dla zainstalowanej wersji")
async def get_published_release_experience(
    version: str = Query(..., min_length=1, max_length=40),
    platform: Literal["ios", "android"] = Query(...),
):
    platform_column = (
        app_versions.c.available_ios
        if platform == "ios"
        else app_versions.c.available_android
    )
    available_rows = await database.fetch_all(
        select(app_versions.c.version).where(platform_column == True)  # noqa: E712
    )
    latest_version = max(
        (str(dict(item)["version"]) for item in available_rows),
        key=_semver_key,
        default="",
    )
    # Pokaz historycznej wersji nigdy nie może przykryć monitu o aktualizację.
    if version.strip() != latest_version:
        return {"experience": None}

    query = (
        select(release_experiences, app_versions.c.version)
        .select_from(
            release_experiences.join(
                app_versions, release_experiences.c.version_id == app_versions.c.id
            )
        )
        .where(app_versions.c.version == version.strip())
        .where(release_experiences.c.status == "published")
    )
    query = query.where(platform_column == True)  # noqa: E712
    row = await database.fetch_one(query)
    if not row or dict(row).get("experience_mode") == "changelog_only":
        return {"experience": None}
    return {"experience": await _serialize_story(row, include_assets=False)}
