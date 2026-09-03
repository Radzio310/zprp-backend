# app/silesia.py
import asyncio
import binascii
from datetime import datetime
from json import JSONDecodeError
import base64
import json
import os
import shutil
import uuid
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy import select, insert, update, delete, func

from app.db import (
    database,
    announcements,
    province_central_offtimes,
    province_offtime_sync_runs,
    silesia_offtimes,
)
from app.notify_utils import schedule_province_push
from app.schemas import (
    # Announcements
    AddCommentRequest,
    AnnouncementResponse,
    DeleteCommentRequest,
    LastUpdateResponse,
    ListAnnouncementsResponse,
    # Offtimes
    OfftimeRecord,
    ListAllOfftimesResponse,
    PinCommentRequest,
    SetOfftimesRequest,
    ToggleReactionRequest,
)
from app.deps import get_rsa_keys

from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.zprp_accounts import configured_provinces, normalize_province
from app.release_stories import require_release_admin

CENTRAL_OFFTIME_SOURCE = "ZPRP_CENTRAL_SYNC"

# -------------------------
# Static files (Railway Volume)
# -------------------------
RAILWAY_VOLUME_MOUNT_PATH = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")  # np. "/data"
STATIC_DIR = (
    os.path.join(RAILWAY_VOLUME_MOUNT_PATH, "static")
    if RAILWAY_VOLUME_MOUNT_PATH
    else "static"
)

os.makedirs(STATIC_DIR, exist_ok=True)

def _static_path_for_url(image_url: str) -> str:
    """
    Zamienia '/static/<filename>' -> '<STATIC_DIR>/<filename>'
    """
    filename = (image_url or "").split("/")[-1]
    return os.path.join(STATIC_DIR, filename)


# -------------------------
# Helpers
# -------------------------

def _decrypt_field(enc_b64: str, private_key) -> str:
    cipher = base64.b64decode(enc_b64)
    plain_b64 = private_key.decrypt(cipher, padding.PKCS1v15()).decode("ascii", errors="strict")

    try:
        raw = base64.b64decode(plain_b64, validate=True)
    except binascii.Error:
        # fallback: jeśli kiedyś przyjdzie "stary" format
        # (możesz też zamiast fallback zrobić HTTP 400)
        return plain_b64

    return raw.decode("utf-8", errors="strict")

def _announcement_row_to_response(row) -> AnnouncementResponse:
    """
    Konwersja rekordu z DB na AnnouncementResponse – w jednym miejscu,
    żeby nie duplikować logiki.
    """
    likes = row["likes"] or []
    comments = row["comments"] or []

    return AnnouncementResponse(
        id=row["id"],
        title=row["title"],
        content=row["content"],
        image_url=row["image_url"],
        priority=row["priority"],
        link=row["link"],
        updated_at=row["updated_at"],
        judge_name=row["judge_name"],
        province=row["province"],
        likes=likes,
        comments=comments,
    )


# -------------------------
# Push helpers
# -------------------------

async def _fire_ann_push(
    prefix: str,
    title: str,
    content: str,
    province: str,
    ann_id: int,
) -> None:
    """Fire-and-forget: planuje powiadomienie dla województwa. Błędy tylko loguje."""
    try:
        short_title = title[:60] + ("…" if len(title) > 60 else "")
        short_body = content[:140] + ("…" if len(content) > 140 else "")
        await schedule_province_push(
            province=province,
            title=f"{prefix}: {short_title}",
            body=short_body,
            data={
                "type": "announcement_new",
                "announcement_id": ann_id,
            },
            seconds_from_now=60,
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("[silesia] _fire_ann_push error: %s", e)

# -------------------------
# Routers
# -------------------------

# Ogłoszenia (per-województwo)
router_ann = APIRouter(prefix="/silesia/announcements", tags=["Silesia - Announcements"])

# Niedyspozycje (per-województwo)
router_off = APIRouter(prefix="/silesia/offtimes", tags=["Silesia - Offtimes"])


# ============================================================
# ================  ANNOUNCEMENTS (OKRĘGOWE)  ================
# ============================================================

@router_ann.get(
    "/last_update",
    response_model=LastUpdateResponse,
    summary="Pobierz datę ostatniej aktualizacji ogłoszeń (opcjonalnie filtrowane po województwie)",
)
async def get_last_update(province: Optional[str] = Query(None)):
    """
    Zwraca timestamp ostatniej zmiany spośród ogłoszeń.
    Jeśli podasz ?province=..., filtruje po województwie.
    """
    q = select(func.max(announcements.c.updated_at))
    if province:
        q = q.where(announcements.c.province == province)
    row = await database.fetch_one(q)
    return LastUpdateResponse(last_update=row[0])


@router_ann.get(
    "/",
    response_model=ListAnnouncementsResponse,
    summary="Pobierz ogłoszenia (opcjonalnie filtrowane po województwie)",
)
async def list_announcements(province: Optional[str] = Query(None)):
    """
    Zwraca ogłoszenia posortowane wg priority rosnąco.
    Jeśli podasz ?province=..., zwróci tylko z danego województwa.
    """
    q = select(announcements)
    if province:
        q = q.where(announcements.c.province == province)
    q = q.order_by(announcements.c.priority)

    rows = await database.fetch_all(q)
    result = [_announcement_row_to_response(r) for r in rows]
    return ListAnnouncementsResponse(announcements=result)



@router_ann.post(
    "/create",
    status_code=status.HTTP_201_CREATED,
    response_model=AnnouncementResponse,
    response_model_exclude_none=True,
    summary="Dodaj nowe ogłoszenie (per-województwo)",
)
async def create_announcement(
    # Pola uwierzytelniające (RSA Base64)
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    # Treść (jak wcześniej – title RSA, content plaintext)
    title: str = Form(...),
    content: str = Form(...),
    priority: int = Form(...),
    link: Optional[str] = Form(None),
    province: str = Form(...),  # ⬅ plaintext województwo
    image: Optional[UploadFile] = File(None),
    keys=Depends(get_rsa_keys),
):
    """
    Tworzy ogłoszenie przypisane do konkretnego `province`.
    """
    private_key, _ = keys

    judge_plain     = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)
    title_plain     = _decrypt_field(title, private_key)
    content_plain   = content
    link_plain      = link
    province_plain  = province

    # domyślnie brak obrazka
    image_url = None

    # jeśli obrazek jest, zapisujemy plik i ustawiamy image_url
    if image:
        ext = (image.filename or "img").split(".")[-1]
        filename = f"{uuid.uuid4()}.{ext}"
        dest = os.path.join(STATIC_DIR, filename)
        with open(dest, "wb") as out:
            shutil.copyfileobj(image.file, out)
        image_url = f"/static/{filename}"

    # 🔴 TO MUSI BYĆ POZA if image: 🔴
    stmt = (
        insert(announcements)
        .values(
            judge_id=judge_plain,
            judge_name=full_name_plain,
            title=title_plain,
            content=content_plain,
            image_url=image_url,   # None lub ścieżka
            priority=priority,
            link=link_plain,
            province=province_plain,
            # likes/comments biorą się z domyślnego "[]"
        )
        .returning(announcements)
    )

    record = await database.fetch_one(stmt)

    # ← DODAJ (fire-and-forget, nie blokuje odpowiedzi 201)
    asyncio.create_task(
        _fire_ann_push("Nowe ogłoszenie", title_plain, content_plain, province_plain, record["id"])
    )

    return _announcement_row_to_response(record)


@router_ann.put(
    "/{ann_id}",
    response_model=AnnouncementResponse,
    response_model_exclude_none=True,
    summary="Edytuj ogłoszenie (możesz zmienić province)",
)
async def update_announcement(
    ann_id: int,
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    title: Optional[str] = Form(None),
    content: Optional[str] = Form(None),
    priority: Optional[int] = Form(None),
    link: Optional[str] = Form(None),
    province: Optional[str] = Form(None),  # ⬅ NOWE – opcjonalna zmiana województwa
    image: Optional[UploadFile] = File(None),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    judge_plain     = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)
    title_plain     = _decrypt_field(title, private_key) if title else None
    content_plain   = content
    link_plain      = link

    image_url = None
    if image:
        # Usuń poprzedni plik (jeśli był)
        old = await database.fetch_one(
            select(announcements.c.image_url).where(announcements.c.id == ann_id)
        )
        old_url = old["image_url"] if old else None
        if old_url:
            old_path = _static_path_for_url(old_url)
            if os.path.isfile(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        ext = (image.filename or "img").split(".")[-1]
        filename = f"{uuid.uuid4()}.{ext}"
        dest = os.path.join(STATIC_DIR, filename)
        with open(dest, "wb") as out:
            shutil.copyfileobj(image.file, out)
        image_url = f"/static/{filename}"

    update_values = {
        "judge_id": judge_plain,
        "judge_name": full_name_plain,
    }
    if title_plain is not None:
        update_values["title"] = title_plain
    if content_plain is not None:
        update_values["content"] = content_plain
    if priority is not None:
        update_values["priority"] = priority
    if link_plain is not None:
        update_values["link"] = link_plain
    if province is not None:
        update_values["province"] = province  # ⬅ zmiana województwa
    if image_url is not None:
        update_values["image_url"] = image_url

    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(**update_values)
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)

    if not record:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    # ← DODAJ
    ann_province = province if province is not None else record["province"]
    ann_title    = title_plain if title_plain is not None else record["title"]
    ann_content  = content_plain if content_plain is not None else record["content"]
    asyncio.create_task(
        _fire_ann_push("Zaktualizowane ogłoszenie", ann_title, ann_content, ann_province, ann_id)
    )

    return _announcement_row_to_response(record)


@router_ann.post(
    "/{ann_id}/reaction",
    response_model=AnnouncementResponse,
    summary="Dodaj / zmień / usuń reakcję użytkownika na ogłoszenie",
)
async def toggle_reaction(ann_id: int, payload: ToggleReactionRequest):
    """
    Logika jak na Facebooku:
    - jeśli użytkownik nie miał reakcji → dodaj
    - jeśli miał inną → podmień na nową
    - jeśli miał taką samą → usuń (toggle off)
    """
    row = await database.fetch_one(
        select(announcements).where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    likes = row["likes"] or []
    if not isinstance(likes, list):
        likes = []

    judge_id = payload.judge_id
    full_name = payload.full_name
    reaction = payload.reaction
    now = datetime.utcnow().isoformat()

    # znajdź istniejącą reakcję tego sędziego
    idx = None
    for i, entry in enumerate(likes):
        if entry.get("judge_id") == judge_id:
            idx = i
            break

    if idx is None:
        # brak reakcji → dodaj
        likes.append(
            {
                "judge_id": judge_id,
                "full_name": full_name,
                "reaction": reaction,
                "created_at": now,
            }
        )
    else:
        existing = likes[idx]
        if existing.get("reaction") == reaction:
            # ta sama reakcja → usuń (toggle off)
            likes.pop(idx)
        else:
            # inna reakcja → podmień typ + odśwież czas
            existing["reaction"] = reaction
            existing["created_at"] = now
            likes[idx] = existing

    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(likes=likes)
        .returning(announcements)
    )
    updated = await database.fetch_one(stmt)
    return _announcement_row_to_response(updated)


@router_ann.post(
    "/{ann_id}/comment",
    response_model=AnnouncementResponse,
    summary="Dodaj komentarz do ogłoszenia",
)
async def add_comment(ann_id: int, payload: AddCommentRequest):
    """
    Dodaje nowy komentarz na końcu wątku.
    Edycja/usuwanie komentarzy można dodać osobnymi endpointami.
    """
    row = await database.fetch_one(
        select(announcements).where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    comments = row["comments"] or []
    if not isinstance(comments, list):
        comments = []

    comment_id = uuid.uuid4().hex
    now = datetime.utcnow().isoformat()

    comments.append(
        {
            "id": comment_id,
            "judge_id": payload.judge_id,
            "full_name": payload.full_name,
            "text": payload.text,
            "created_at": now,
            "is_pinned": False,  # nowy klucz – domyślnie nieprzypięty
        }
    )

    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(comments=comments)
        .returning(announcements)
    )
    updated = await database.fetch_one(stmt)
    return _announcement_row_to_response(updated)

@router_ann.post(
    "/{ann_id}/comment_pin",
    response_model=AnnouncementResponse,
    summary="Przypnij / odepnij komentarz w ogłoszeniu",
)
async def pin_comment(ann_id: int, payload: PinCommentRequest):
    """
    Ustawia flagę is_pinned dla konkretnego komentarza w JSON-ie ogłoszenia.
    Widoczne globalnie dla wszystkich użytkowników.
    """
    row = await database.fetch_one(
        select(announcements).where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    comments = row["comments"] or []
    if not isinstance(comments, list):
        comments = []

    found = False
    target_id = str(payload.comment_id)

    for c in comments:
        if str(c.get("id")) == target_id:
            c["is_pinned"] = bool(payload.pin)
            found = True
            break

    if not found:
        raise HTTPException(status_code=404, detail="Komentarz nie istnieje")

    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(comments=comments)
        .returning(announcements)
    )
    updated = await database.fetch_one(stmt)

    return _announcement_row_to_response(updated)

@router_ann.post(
    "/{ann_id}/comment_delete",
    response_model=AnnouncementResponse,
    summary="Usuń komentarz z ogłoszenia",
)
async def delete_comment(ann_id: int, payload: DeleteCommentRequest):
    """
    Usuwa wybrany komentarz z JSON-a comments ogłoszenia.
    Zmiana jest globalna dla wszystkich użytkowników.
    """
    row = await database.fetch_one(
        select(announcements).where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    comments = row["comments"] or []
    if not isinstance(comments, list):
        comments = []

    target_id = str(payload.comment_id)
    before = len(comments)
    comments = [c for c in comments if str(c.get("id")) != target_id]

    if len(comments) == before:
        raise HTTPException(status_code=404, detail="Komentarz nie istnieje")

    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(comments=comments)
        .returning(announcements)
    )
    updated = await database.fetch_one(stmt)
    return _announcement_row_to_response(updated)


@router_ann.delete(
    "/{ann_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń ogłoszenie (wraz z plikiem, jeśli istnieje)",
)
async def delete_announcement(ann_id: int):
    row = await database.fetch_one(
        select(announcements.c.image_url).where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    image_url = row["image_url"]
    if image_url:
        path = _static_path_for_url(image_url)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass


    await database.execute(delete(announcements).where(announcements.c.id == ann_id))
    return


# ============================================================
# ==================  OFFTIMES (OKRĘGOWE)  ===================
# ============================================================

def _json_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (JSONDecodeError, TypeError):
            return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _is_central_zprp_entry(item: dict[str, Any]) -> bool:
    """Rozpoznaj nowy wpis źródłowy i jego starszą kopię wysyłaną z telefonu."""
    source = str(item.get("source") or "").strip().upper()
    if source == CENTRAL_OFFTIME_SOURCE:
        return True
    category = str(
        item.get("category_name") or item.get("categoryName") or ""
    ).strip().upper()
    is_global = bool(item.get("is_global") or item.get("isGlobal"))
    is_match = bool(item.get("isMatch") or item.get("is_match"))
    return category == "BAZOWA" and is_global and not is_match


def _without_client_central(value: Any) -> list[dict[str, Any]]:
    # Centralna część ma jednego właściciela: crawler ZPRP. Dzięki temu nawet
    # starsza wersja aplikacji, która nadal ją odsyła, nie cofnie snapshotu.
    return [item for item in _json_list(value) if not _is_central_zprp_entry(item)]


def _same_province(left: Any, right: Any) -> bool:
    left_norm = normalize_province(left)
    right_norm = normalize_province(right)
    if left_norm and right_norm:
        return left_norm == right_norm
    return str(left or "").strip().upper() == str(right or "").strip().upper()


def _dedupe_offtime_entries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    positions: dict[str, int] = {}
    for item in items:
        item_id = str(item.get("id") or "").strip()
        key = item_id or "|".join(
            str(item.get(name) or "")
            for name in ("source", "from", "to", "info", "category_name")
        )
        if key in positions:
            # Późniejszy element wygrywa. Snapshot centralny dokładamy po danych
            # okręgowych, więc jest autorytatywny także podczas migracji.
            result[positions[key]] = item
        else:
            positions[key] = len(result)
            result.append(item)
    return result


def _newest_datetime(*values: Any) -> datetime:
    valid = [value for value in values if isinstance(value, datetime)]
    if not valid:
        return datetime.now().astimezone()
    return max(
        valid,
        key=lambda value: (
            value.replace(tzinfo=None) if value.tzinfo is not None else value
        ),
    )


async def _composed_offtime_records(
    *,
    province: Optional[str] = None,
    judge_id: Optional[str] = None,
) -> list[OfftimeRecord]:
    """Złóż okręgowy zapis użytkownika i centralny snapshot ZPRP przy odczycie."""
    district_query = select(silesia_offtimes)
    if judge_id is not None:
        district_query = district_query.where(silesia_offtimes.c.judge_id == judge_id)
    district_rows = await database.fetch_all(district_query)
    if province:
        district_rows = [
            row for row in district_rows if _same_province(row["province"], province)
        ]

    central_query = select(province_central_offtimes)
    if judge_id is not None:
        central_query = central_query.where(
            province_central_offtimes.c.judge_id == judge_id
        )
    province_key = normalize_province(province) if province else ""
    if province and province_key:
        central_query = central_query.where(
            province_central_offtimes.c.province == province_key
        )
    central_rows = await database.fetch_all(central_query)
    if province and not province_key:
        central_rows = [
            row for row in central_rows if _same_province(row["province"], province)
        ]

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in district_rows:
        row_province = normalize_province(row["province"]) or str(row["province"])
        key = (row_province, str(row["judge_id"]))
        group = groups.setdefault(
            key,
            {
                "judge_id": str(row["judge_id"]),
                "province": str(row["province"]),
                "full_name": str(row["full_name"] or ""),
                "city": row["city"],
                "district": [],
                "central": [],
                "updated_at": row["updated_at"],
                "central_synced_at": None,
            },
        )
        # Legacy BAZOWA zostaje chwilowo jako fallback. Usuniemy ją dopiero,
        # gdy dla tego sędziego istnieje już prawidłowy snapshot serwerowy.
        group["district"].extend(_json_list(row["data_json"]))
        group["updated_at"] = _newest_datetime(
            group["updated_at"], row["updated_at"]
        )

    for row in central_rows:
        row_province = normalize_province(row["province"]) or str(row["province"])
        key = (row_province, str(row["judge_id"]))
        # Nieaktywny snapshot oznacza „sędzia zniknął z listy okręgu”. Dla
        # /self nadal zwracamy pustą, autorytatywną część centralną, aby telefon
        # wyczyścił cache. W /all nie tworzymy natomiast osieroconego kafelka.
        if not row["active"] and key not in groups and judge_id is None:
            continue
        group = groups.setdefault(
            key,
            {
                "judge_id": str(row["judge_id"]),
                "province": str(province or row["province"]),
                "full_name": str(row["full_name"] or ""),
                "city": row["city"],
                "district": [],
                "central": [],
                "updated_at": row["synced_at"],
                "central_synced_at": row["synced_at"],
            },
        )
        if not group["full_name"]:
            group["full_name"] = str(row["full_name"] or "")
        if not group["city"]:
            group["city"] = row["city"]
        group["central"] = _json_list(row["data_json"]) if row["active"] else []
        group["central_synced_at"] = row["synced_at"]
        group["updated_at"] = _newest_datetime(
            group["updated_at"], row["synced_at"]
        )

    records = [
        OfftimeRecord(
            judge_id=group["judge_id"],
            province=group["province"],
            full_name=group["full_name"] or f"Sędzia {group['judge_id']}",
            city=group["city"],
            data_json=_dedupe_offtime_entries(
                [
                    *(
                        _without_client_central(group["district"])
                        if group["central_synced_at"]
                        else group["district"]
                    ),
                    *group["central"],
                ]
            ),
            updated_at=group["updated_at"],
            central_synced_at=group["central_synced_at"],
            central_source=(
                CENTRAL_OFFTIME_SOURCE if group["central_synced_at"] else None
            ),
        )
        for group in groups.values()
    ]
    records.sort(key=lambda item: (item.full_name.casefold(), item.judge_id))
    return records

@router_off.post(
    "/set",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub nadpisz niedyspozycje sędziego w okręgu",
)
async def set_offtimes(req: SetOfftimesRequest):
    """
    Upsert po (judge_id, province).
    `data_json` może być już obiektem/listą albo stringiem JSON.
    """
    judge_plain = req.judge_id
    full_name   = req.full_name
    city_plain  = req.city
    province    = req.province

    raw = req.data_json
    if isinstance(raw, str):
        try:
            data_json_obj = json.loads(raw)
        except JSONDecodeError:
            raise HTTPException(status_code=400, detail="Niepoprawny JSON w data_json")
    else:
        data_json_obj = raw

    # Starsze aplikacje odsyłają do tego endpointu także lokalną kopię wpisów
    # BAZOWA. Od teraz centralny snapshot pochodzi wyłącznie z ZPRP i nie wolno
    # go nadpisywać zawartością telefonu.
    data_json_obj = _without_client_central(data_json_obj)

    # Postgres: ON CONFLICT (judge_id, province)
    # SQLite: w razie czego zadziała jako zwykły INSERT, ale rekomendowana migracja na composite PK
    stmt = pg_insert(silesia_offtimes).values(
        judge_id=judge_plain,
        province=province,
        full_name=full_name,
        city=city_plain,
        data_json=data_json_obj,
    ).on_conflict_do_update(
        index_elements=[silesia_offtimes.c.judge_id, silesia_offtimes.c.province],
        set_={
            "full_name": full_name,
            "city": city_plain,
            "data_json": data_json_obj,
            "updated_at": func.now(),
        },
    )
    await database.execute(stmt)
    return {"success": True}


@router_off.get(
    "/self/{judge_id}",
    response_model=OfftimeRecord,
    summary="Pobierz swoje niedyspozycje (wymaga parametru province)",
)
async def get_my_offtimes(
    judge_id: str,
    province: str = Query(..., description="Województwo, np. 'ŚLĄSKIE'"),
):
    records = await _composed_offtime_records(
        province=province,
        judge_id=judge_id,
    )
    if not records:
        raise HTTPException(status_code=404, detail="Brak zapisanych niedyspozycji")
    return records[0]


@router_off.delete(
    "/{judge_id_enc}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń niedyspozycje sędziego w konkretnym okręgu",
)
async def delete_offtimes(
    judge_id_enc: str,
    province: str = Query(..., description="Województwo, np. 'ŚLĄSKIE'"),
    # Body z autoryzacją (zostawiam jak u Ciebie – nieużywane pola, ale pilnują schematu):
    req: SetOfftimesRequest = Depends(),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    judge_plain = _decrypt_field(judge_id_enc, private_key)

    deleted = await database.execute(
        delete(silesia_offtimes).where(
            (silesia_offtimes.c.judge_id == judge_plain)
            & (silesia_offtimes.c.province == province)
        )
    )
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Nie znaleziono niedyspozycji")
    return


@router_off.get(
    "/all",
    response_model=ListAllOfftimesResponse,
    summary="Lista wszystkich niedyspozycji (opcjonalnie filtrowana po province)",
)
async def list_all_offtimes(province: Optional[str] = Query(None)):
    return ListAllOfftimesResponse(
        records=await _composed_offtime_records(province=province)
    )


@router_off.get(
    "/central-sync/status",
    summary="Stan automatycznej synchronizacji centralnych niedyspozycji",
)
async def central_offtime_sync_status(
    province: Optional[str] = Query(None),
    _admin: str = Depends(require_release_admin),
):
    """Diagnostyka bez loginów i haseł — bezpieczna do pokazania w panelu."""
    province_key = normalize_province(province) if province else ""
    if province and not province_key:
        raise HTTPException(status_code=400, detail="Nieznane województwo")
    run_query = select(province_offtime_sync_runs).order_by(
        province_offtime_sync_runs.c.started_at.desc()
    )
    snapshot_query = select(province_central_offtimes)
    if province_key:
        run_query = run_query.where(
            province_offtime_sync_runs.c.province == province_key
        )
        snapshot_query = snapshot_query.where(
            province_central_offtimes.c.province == province_key
        )
    runs = await database.fetch_all(run_query.limit(20))
    snapshots = await database.fetch_all(snapshot_query)
    configured = set(configured_provinces().keys())
    return {
        "enabled": os.getenv("ZPRP_OFFTIME_SYNC_ENABLED", "true").strip().lower()
        in ("1", "true", "yes", "on"),
        "interval_seconds": max(
            3600, int(os.getenv("ZPRP_OFFTIME_SYNC_SECONDS", "7200"))
        ),
        "configured_provinces": sorted(
            ([province_key] if province_key in configured else [])
            if province_key
            else configured
        ),
        "snapshots": {
            "total": len(snapshots),
            "active": sum(1 for row in snapshots if row["active"]),
            "last_synced_at": max(
                (row["synced_at"] for row in snapshots), default=None
            ),
        },
        "recent_runs": [
            {
                "province": row["province"],
                "status": row["status"],
                "officials_seen": row["officials_seen"],
                "officials_with_link": row["officials_with_link"],
                "judges_synced": row["judges_synced"],
                "entries_active": row["entries_active"],
                "errors_count": row["errors_count"],
                "error": row["error"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
            }
            for row in runs
        ],
    }


# -------------------------
# Główny router eksportowany
# -------------------------
router = APIRouter()
router.include_router(router_ann)
router.include_router(router_off)
