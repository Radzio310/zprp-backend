# app/silesia.py
from datetime import datetime
from json import JSONDecodeError, loads
import json
import os
import shutil
from typing import Optional
import uuid
from fastapi import APIRouter, File, Form, HTTPException, Depends, Query, UploadFile, status
from sqlalchemy import select, insert, update, delete, func
from app.db import database, announcements, silesia_offtimes, matches_to_offer, matches_to_approve, matches_events
from app.schemas import (
    ApprovalActionRequest,
    GoogleSyncRequest,
    ListAllOfftimesResponse,
    ListApprovalsResponse,
    ListOffersResponse,
    MatchAssignmentRequest,
    MatchOfferRequest,
    OfftimeRecord,
    SetOfftimesRequest,
    ListAnnouncementsResponse,
    AnnouncementResponse,
    LastUpdateResponse,
)
from app.deps import get_rsa_keys
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.dialects.postgresql import insert as pg_insert

# Router for announcements
router_ann = APIRouter(
    prefix="/silesia/announcements",
    tags=["Silesia - Announcements"]
)
# Router for offtimes
router_off = APIRouter(
    prefix="/silesia/offtimes",
    tags=["Silesia - Offtimes"]
)
# Router for matches
router_matches = APIRouter(
    prefix="/silesia/matches",
    tags=["Silesia - Matches"]
)

def _decrypt_field(enc_b64: str, private_key) -> str:
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")

@router_ann.get(
    "/last_update",
    response_model=LastUpdateResponse,
    summary="Pobierz datę ostatniej aktualizacji wszystkich ogłoszeń"
)
async def get_last_update():
    """
    Zwraca timestamp ostatniej zmiany spośród wszystkich ogłoszeń
    (lub None, jeśli tabela jest pusta).
    """
    query = select(func.max(announcements.c.updated_at))
    row = await database.fetch_one(query)
    return LastUpdateResponse(last_update=row[0])

@router_ann.get(
    "/",
    response_model=ListAnnouncementsResponse,
    summary="Pobierz wszystkie ogłoszenia"
)
async def list_announcements(
    # uwierzytelnianie JWT trzymamy globalnie, nie potrzebujemy RSA-dependów
):
    """
    Zwraca **wszystkie** ogłoszenia (niezależnie od sędziego), posortowane według priority.
    """
    query = select(announcements).order_by(announcements.c.priority)
    rows = await database.fetch_all(query)

    result = [
        AnnouncementResponse(
            id=r["id"],
            title=r["title"],
            content=r["content"],
            image_url=r["image_url"],
            priority=r["priority"],
            link=r["link"],
            updated_at=r["updated_at"],
            judge_name=r["judge_name"],
        )
        for r in rows
    ]
    return ListAnnouncementsResponse(announcements=result)

@router_ann.post(
    "/create",
    status_code=status.HTTP_201_CREATED,
    response_model=AnnouncementResponse,
    summary="Dodaj nowe ogłoszenie",
    response_model_exclude_none=True,
)
async def create_announcement(
    # pozostałe pola jako formy + plik
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    full_name: str = Form(...),
    title: str = Form(...),
    content: str = Form(...),
    priority: int = Form(...),
    link: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    judge_plain     = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)
    title_plain     = _decrypt_field(title, private_key)
    content_plain   = content  # zakładamy, że content jest już plaintext
    link_plain      = link

    # obsługa uploadu
    image_url = None
    if image:
        # dajemy plikowi unikalną nazwę
        ext = image.filename.split(".")[-1]
        filename = f"{uuid.uuid4()}.{ext}"
        dest = f"static/{filename}"
        with open(dest, "wb") as out:
            shutil.copyfileobj(image.file, out)
        # adres pod którym plik jest potem serwowany
        image_url = f"/static/{filename}"

    stmt = (
        insert(announcements)
        .values(
            judge_id=judge_plain,
            judge_name=full_name_plain,
            title=title_plain,
            content=content_plain,
            image_url=image_url,
            priority=priority,
            link=link_plain,
        )
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)
    return AnnouncementResponse(
        id=record["id"],
        judge_name=record["judge_name"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        link=record["link"],
        updated_at=record["updated_at"],
    )


@router_ann.put(
    "/{ann_id}",
    response_model=AnnouncementResponse,
    summary="Edytuj ogłoszenie",
    response_model_exclude_none=True,
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
    image: Optional[UploadFile] = File(None),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    judge_plain     = _decrypt_field(judge_id, private_key)
    full_name_plain = _decrypt_field(full_name, private_key)
    title_plain     = _decrypt_field(title, private_key) if title else None
    content_plain   = content
    link_plain      = link

    # obsługa uploadu – nadpisanie, jeśli jest nowy plik
    image_url = None
    if image:
        # 0) Pobierz starą ścieżkę, jeśli istnieje
        old = await database.fetch_one(
            select(announcements.c.image_url)
            .where(announcements.c.id == ann_id)
        )
        old_url = old["image_url"] if old else None
        if old_url:
            old_path = old_url.lstrip("/")
            if os.path.isfile(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        # 1) Zapis nowego pliku
        ext = image.filename.split(".")[-1]
        filename = f"{uuid.uuid4()}.{ext}"
        dest = f"static/{filename}"
        with open(dest, "wb") as out:
            shutil.copyfileobj(image.file, out)
        image_url = f"/static/{filename}"


    # przygotuj słownik wartości do update
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

    return AnnouncementResponse(
        id=record["id"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        link=record["link"],
        judge_name=record["judge_name"],
        updated_at=record["updated_at"],
    )


@router_ann.delete(
    "/{ann_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń ogłoszenie"
)
async def delete_announcement(
    ann_id: int,
):
    # 1) Pobierz istniejący rekord i ścieżkę do pliku
    row = await database.fetch_one(
        select(announcements.c.image_url)
        .where(announcements.c.id == ann_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ogłoszenie nie istnieje")

    image_url = row["image_url"]
    # 2) Jeżeli jest plik, usuń go fizycznie
    if image_url:
        # usuń wiodący slash i buduj ścieżkę na dysku
        path = image_url.lstrip("/")
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                # Możesz zalogować wyjątek, ale nie przerywaj całej operacji
                pass

    # 3) Usuń rekord z bazy
    await database.execute(
        delete(announcements).where(announcements.c.id == ann_id)
    )
    return


@router_off.post(
    "/set",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub nadpisz niedyspozycje sędziego"
)
async def set_offtimes(
    req: SetOfftimesRequest,
):
    # 1) Wyciągamy pola prosto z requestu
    judge_plain = req.judge_id
    full_name   = req.full_name
    city_plain  = req.city

    # 2) Parsujemy data_json:
    #    - jeśli to string, próbujemy json.loads
    #    - jeśli już jest listą/dict, zostawiamy
    raw = req.data_json
    if isinstance(raw, str):
        try:
            data_json_obj = json.loads(raw)
        except JSONDecodeError:
            raise HTTPException(status_code=400, detail="Niepoprawny JSON w data_json")
    else:
        data_json_obj = raw

    # 3) Upsert do bazy, wykorzystując JSON-typ kolumny
    stmt = pg_insert(silesia_offtimes).values(
        judge_id=judge_plain,
        full_name=full_name,
        city=city_plain,
        data_json=data_json_obj
    ).on_conflict_do_update(
        index_elements=[silesia_offtimes.c.judge_id],
        set_={
            "full_name": full_name,
            "city": city_plain,
            "data_json": data_json_obj,
            "updated_at": func.now()
        }
    )
    await database.execute(stmt)
    return {"success": True}



@router_off.get(
    "/self/{judge_id}",
    response_model=OfftimeRecord,
    summary="Pobierz swoje niedyspozycje po judge_id"
)
async def get_my_offtimes(judge_id: str):
    """
    Zwraca OfftimeRecord dla podanego jawnego judge_id.
    """
    row = await database.fetch_one(
        select(silesia_offtimes)
        .where(silesia_offtimes.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Brak zapisanych niedyspozycji")

    return OfftimeRecord(
        judge_id=row["judge_id"],
        full_name=row["full_name"],
        city=row["city"],
        data_json=row["data_json"],
        updated_at=row["updated_at"],
    )



@router_off.delete(
    "/{judge_id_enc}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń wpis niedyspozycji sędziego"
)
async def delete_offtimes(
    judge_id_enc: str,
    req: SetOfftimesRequest = Depends(),  # dla uwierzytelnienia
    keys=Depends(get_rsa_keys),
):
    """
    Path param: judge_id (Base64‑RSA).
    Body: username, password, judge_id (do weryfikacji).
    Usuwa wpis z bazy.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(judge_id_enc, private_key)

    deleted = await database.execute(
        delete(silesia_offtimes).where(silesia_offtimes.c.judge_id == judge_plain)
    )
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Nie znaleziono niedyspozycji")
    return

@router_off.get(
    "/all",
    summary="Lista wszystkich niedyspozycji",
    response_model=ListAllOfftimesResponse,
)
async def list_all_offtimes(
    keys=Depends(get_rsa_keys),
):
    rows = await database.fetch_all(select(silesia_offtimes))
    return ListAllOfftimesResponse(records=[
        OfftimeRecord(
            judge_id=r["judge_id"],
            full_name=r["full_name"],
            city=r["city"],
            data_json=r["data_json"],
            updated_at=r["updated_at"],
        ) for r in rows
    ])



@router_off.post(
    "/google/sync",
    summary="Wczytaj wydarzenia z Google Calendar i zaproponuj filtrowanie",
)
async def google_sync(
    req: GoogleSyncRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Pobiera wydarzenia z Google Calendar (następne 90 dni),
    zapisuje je w tabeli calendar_events i zwraca listę do wyboru w kliencie.
    """
    # 1) odszyfruj req.judge_id
    # 2) pobierz tokeny z calendar_tokens
    # 3) użyj google API do pobrania events.next(90 dni)
    # 4) wrzuć w calendar_events (upsert)
    # 5) zwróć listę GoogleEvent[]

    
# --- Matches module ---
@router_matches.post(
    "/offer",
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj mecz do oferty"
)
async def offer_match(
    req: MatchOfferRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Dodaje do tabeli matches_to_offer nowy mecz.
    Pole 'match_data' w formacie JSON string zaszyfrowane Base64-RSA.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)
    match_json = _decrypt_field(req.match_data, private_key)
    try:
        loads(match_json)
    except JSONDecodeError:
        raise HTTPException(status_code=400, detail="Niepoprawny JSON w match_data")
    stmt = (
        insert(matches_to_offer)
        .values(
            judge_id=judge_plain,
            judge_name=_decrypt_field(req.full_name, private_key),
            match_data=match_json,
            created_at=func.now()
        )
        .returning(matches_to_offer)
    )
    record = await database.fetch_one(stmt)
    return {"id": record["id"], "match_data": record["match_data"]}

@router_matches.get(
    "/offers",
    response_model=ListOffersResponse,
    summary="Lista meczów do oddania"
)
async def list_offers(
    keys=Depends(get_rsa_keys),
):
    rows = await database.fetch_all(
        select(matches_to_offer).order_by(matches_to_offer.c.created_at)
    )
    items = [{"id": r["id"], "judge_id": r["judge_id"], "judge_name": r["judge_name"], "match_data": r["match_data"]} for r in rows]
    return {"offers": items}

@router_matches.post(
    "/assign/{offer_id}",
    status_code=status.HTTP_200_OK,
    summary="Przypisz się do meczu"
)
async def assign_to_match(
    offer_id: int,
    req: MatchAssignmentRequest,
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    assign_judge_plain = _decrypt_field(req.judge_id, private_key)
    assign_name = _decrypt_field(req.full_name, private_key)
    # sprawdź istnienie oferty
    offer = await database.fetch_one(
        select(matches_to_offer).where(matches_to_offer.c.id == offer_id)
    )
    if not offer:
        raise HTTPException(status_code=404, detail="Oferta meczu nie znaleziona")
    # przenieś do matches_to_approve
    stmt = (
        insert(matches_to_approve)
        .values(
            original_offer_id=offer_id,
            judge_id=offer["judge_id"],
            judge_name=offer["judge_name"],
            match_data=offer["match_data"],
            assign_judges=[assign_judge_plain],
            assign_names=[assign_name],
            requested_at=func.now()
        )
    )
    await database.execute(stmt)
    # log event
    await database.execute(
        insert(matches_events).values(
            event_type="assign",
            event_time=func.now(),
            match_id=offer_id,
            owner_judge_id=offer["judge_id"],
            acting_judge_id=assign_judge_plain
        )
    )
    # kasuj oryginalną ofertę
    await database.execute(
        delete(matches_to_offer).where(matches_to_offer.c.id == offer_id)
    )
    return {"success": True}

@router_matches.get(
    "/approvals",
    response_model=ListApprovalsResponse,
    summary="Lista meczów do zaakceptowania"
)
async def list_approvals(
    keys=Depends(get_rsa_keys),
):
    rows = await database.fetch_all(
        select(matches_to_approve).order_by(matches_to_approve.c.requested_at)
    )
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "original_offer_id": r["original_offer_id"],
            "judge_id": r["judge_id"],
            "judge_name": r["judge_name"],
            "match_data": r["match_data"],
            "assign_judges": r["assign_judges"],
            "assign_names": r["assign_names"],
            "requested_at": r["requested_at"],
        })
    return {"approvals": items}

@router_matches.post(
    "/approve/{approval_id}",
    summary="Akceptuj przypisanie do meczu"
)
async def approve_match(
    approval_id: int,
    req: ApprovalActionRequest,
    keys=Depends(get_rsa_keys),
):
    # na razie pusty
    pass

@router_matches.post(
    "/reject/{approval_id}",
    status_code=status.HTTP_200_OK,
    summary="Odrzuć przypisanie do meczu"
)
async def reject_match(
    approval_id: int,
    keys=Depends(get_rsa_keys),
):
    # pobierz zapis
    rec = await database.fetch_one(
        select(matches_to_approve).where(matches_to_approve.c.id == approval_id)
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Rekord nie istnieje")
    # przenieś z powrotem do offers, jeśli tam nie ma
    exists = await database.fetch_one(
        select(matches_to_offer).where(matches_to_offer.c.id == rec["original_offer_id"])
    )
    if not exists:
        await database.execute(
            insert(matches_to_offer).values(
                id=rec["original_offer_id"],
                judge_id=rec["judge_id"],
                judge_name=rec["judge_name"],
                match_data=rec["match_data"],
                created_at=rec["requested_at"]
            )
        )
    # log event
    await database.execute(
        insert(matches_events).values(
            event_type="reject",
            event_time=func.now(),
            match_id=rec["original_offer_id"],
            owner_judge_id=rec["judge_id"]
        )
    )
    # usuń z approve
    await database.execute(
        delete(matches_to_approve).where(matches_to_approve.c.id == approval_id)
    )
    return {"success": True}

@router_matches.delete(
    "/offer/{offer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Usuń ofertę meczu (tylko właściciel)"
)
async def delete_offer(
    offer_id: int,
    req: MatchOfferRequest,
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)
    rec = await database.fetch_one(
        select(matches_to_offer).where(matches_to_offer.c.id == offer_id)
    )
    if not rec or rec["judge_id"] != judge_plain:
        raise HTTPException(status_code=404, detail="Nie znaleziono lub brak dostępu")
    await database.execute(
        delete(matches_to_offer).where(matches_to_offer.c.id == offer_id)
    )
    return

# Include routers
router = APIRouter()
router.include_router(router_ann)
router.include_router(router_off)
router.include_router(router_matches)