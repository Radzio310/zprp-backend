# app/silesia.py
from datetime import datetime
from json import JSONDecodeError, loads
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy import select, insert, update, delete, func
from app.db import database, announcements, silesia_offtimes, matches_to_offer, matches_to_approve, matches_events
from app.schemas import (
    ApprovalActionRequest,
    CreateAnnouncementRequest,
    ListApprovalsResponse,
    ListOffersResponse,
    ListOfftimesRequest,
    ListOfftimesResponse,
    MatchAssignmentRequest,
    MatchOfferRequest,
    OfftimeRecord,
    SetOfftimesRequest,
    UpdateAnnouncementRequest,
    DeleteAnnouncementRequest,
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
    summary="Pobierz datę ostatniej aktualizacji ogłoszeń sędziego"
)
async def get_last_update(
    auth: CreateAnnouncementRequest = Depends(),  # wykorzystujemy ten sam schemat uwierzytelniający
    keys=Depends(get_rsa_keys),
):
    """
    Zwraca timestamp ostatniej zmiany (lub None, jeśli brak wpisów).
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(auth.judge_id, private_key)

    query = select(func.max(announcements.c.updated_at)).where(
        announcements.c.judge_id == judge_plain
    )
    row = await database.fetch_one(query)
    return LastUpdateResponse(last_update=row[0])

@router_ann.get(
    "/",
    response_model=ListAnnouncementsResponse,
    summary="Pobierz wszystkie ogłoszenia sędziego"
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
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListAnnouncementsResponse(announcements=result)

@router_ann.post(
    "/create",
    status_code=status.HTTP_201_CREATED,
    response_model=AnnouncementResponse,
    summary="Dodaj nowe ogłoszenie"
)
async def create_announcement(
    req: CreateAnnouncementRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Body:
    - title, content, image_url (opcjonalnie), priority
    - wszystkie pola zaszyfrowane Base64-RSA
    Zwraca utworzone ogłoszenie wraz z `id` i `updated_at`.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)
    title = _decrypt_field(req.title, private_key)
    content = req.content
    image_url = req.image_url if req.image_url else None

    stmt = (
        insert(announcements)
        .values(
            judge_id=judge_plain,
            title=title,
            content=content,
            image_url=image_url,
            priority=req.priority,
        )
        .returning(announcements)
    )
    record = await database.fetch_one(stmt)
    return AnnouncementResponse(
        id=record["id"],
        title=record["title"],
        content=record["content"],
        image_url=record["image_url"],
        priority=record["priority"],
        updated_at=record["updated_at"],
    )

@router_ann.put(
    "/{ann_id}",
    response_model=AnnouncementResponse,
    summary="Edytuj ogłoszenie"
)
async def update_announcement(
    ann_id: int,
    req: CreateAnnouncementRequest,      # używamy tego samego request co przy create
    keys=Depends(get_rsa_keys),
):
    """
    Parametr URL: id ogłoszenia
    Body: 
      - username, password, judge_id, title, content, priority
      - image_url (opcjonalnie)
      wszystkie pola zaszyfrowane Base64-RSA
    Zwraca zaktualizowane ogłoszenie wraz z `id` i `updated_at`.
    """
    private_key, _ = keys

    # odszyfrowujemy wszystkie pola
    username_plain = _decrypt_field(req.username, private_key)
    password_plain = _decrypt_field(req.password, private_key)
    judge_plain    = _decrypt_field(req.judge_id, private_key)
    title_plain    = _decrypt_field(req.title, private_key)
    content_plain  = req.content
    priority_plain = req.priority  # to jest liczba lub string, nie szyfrujemy tutaj po stronie serwera
    image_url      = req.image_url if req.image_url else None

    # teraz wykonujemy update
    stmt = (
        update(announcements)
        .where(announcements.c.id == ann_id)
        .values(
            judge_id=judge_plain,
            title=title_plain,
            content=content_plain,
            priority=priority_plain,
            image_url=image_url,
        )
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
    """
    Parametr URL: id ogłoszenia
    Body: tylko AuthPayload (username, password, judge_id)
    Usuwa ogłoszenie
    """
    await database.execute(
        delete(announcements).where(announcements.c.id == ann_id)
    )
    # brak treści w odpowiedzi → 204 No Content
    return

@router_off.post(
    "/set",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub nadpisz niedyspozycje sędziego"
)
async def set_offtimes(
    req: SetOfftimesRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Upsert (INSERT albo UPDATE) całej listy niedyspozycji danego sędziego.
    Body:
      - username, password, judge_id, full_name, data_json (wszystkie Base64‑RSA)
      - data_json: string JSON array np. '[{"from":"...","to":"...",...}, ...]'
    Zwraca success=true.
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)
    full_name = _decrypt_field(req.full_name, private_key)
    data_json = _decrypt_field(req.data_json, private_key)

    # walidacja JSON
    try:
        loads(data_json)
    except JSONDecodeError:
        raise HTTPException(status_code=400, detail="Niepoprawny JSON w data_json")

    stmt = pg_insert(silesia_offtimes).values(
        judge_id=judge_plain,
        full_name=full_name,
        data_json=data_json
    ).on_conflict_do_update(
        index_elements=[silesia_offtimes.c.judge_id],
        set_={
            "full_name": full_name,
            "data_json": data_json,
            "updated_at": func.now()
        }
    )
    await database.execute(stmt)
    return {"success": True}

@router_off.get(
    "/self",
    response_model=OfftimeRecord,
    summary="Pobierz swoje niedyspozycje"
)
async def get_my_offtimes(
    req: SetOfftimesRequest = Depends(),
    keys=Depends(get_rsa_keys),
):
    """
    Zwraca wpis niedyspozycji dla zalogowanego sędziego.
    Body: username, password, judge_id (Base64‑RSA).
    """
    private_key, _ = keys
    judge_plain = _decrypt_field(req.judge_id, private_key)

    row = await database.fetch_one(
        select(silesia_offtimes).where(silesia_offtimes.c.judge_id == judge_plain)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Brak zapisanych niedyspozycji")
    return OfftimeRecord(
        judge_id=row["judge_id"],
        full_name=row["full_name"],
        data_json=row["data_json"],
        updated_at=row["updated_at"],
    )

@router_off.post(
    "/list",
    response_model=ListOfftimesResponse,
    summary="Pobierz niedyspozycje wielu sędziów"
)
async def list_offtimes(
    req: ListOfftimesRequest,
    keys=Depends(get_rsa_keys),
):
    """
    Body:
      - username, password (Base64‑RSA, do uwierzytelnienia)
      - judge_ids: lista Base64‑RSA identyfikatorów
    Zwraca listę rekordów tylko dla tych judge_id.
    """
    private_key, _ = keys
    # odszyfruj listę ID
    plain_ids = []
    for enc in req.judge_ids:
        try:
            plain_ids.append(_decrypt_field(enc, private_key))
        except:
            raise HTTPException(status_code=400, detail="Błędny judge_id w liście")

    rows = await database.fetch_all(
        select(silesia_offtimes).where(silesia_offtimes.c.judge_id.in_(plain_ids))
    )
    records = [
        OfftimeRecord(
            judge_id=r["judge_id"],
            full_name=r["full_name"],
            data_json=r["data_json"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListOfftimesResponse(records=records)

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