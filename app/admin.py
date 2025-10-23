from datetime import datetime, timezone
import json
import os
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import delete, insert, select, update
import bcrypt
from app.db import database, admin_pins, admin_settings, user_reports, admin_posts, forced_logout, forced_logout_rules, news_masters, calendar_masters, match_masters, zprp_masters, active_provinces, settlement_clubs, json_files, okreg_rates, okreg_distances, hall_reports, rejected_halls, app_versions
from app.schemas import ActiveProvinceItem, AdminPostItem, CreateAdminPostRequest, CreateForcedLogoutRuleRequest, CreateHallReportRequest, CreateUserReportRequest, CreateVersionRequest, ForcedLogoutResponse, ForcedLogoutRuleItem, GenerateHashRequest, GenerateHashResponse, GetActiveProvinceResponse, GetJsonFileResponse, GetOkregDistanceResponse, GetOkregRateResponse, GetSettlementClubsResponse, HallReportItem, JsonFileItem, ListActiveProvincesResponse, ListAdminPostsResponse, ListForcedLogoutRulesResponse, ListHallReportsResponse, ListJsonFilesResponse, ListMastersResponse, ListOkregDistancesResponse, ListOkregRatesResponse, ListSettlementClubsResponse, ListUserReportsResponse, ListVersionsResponse, ListZprpMastersResponse, OkregDistanceItem, OkregRateItem, SetForcedLogoutRequest, SettlementClubsItem, UpdateMastersRequest, UpdateVersionRequest, UpdateZprpMastersRequest, UpsertActiveProvinceRequest, UpsertJsonFileRequest, UpsertOkregDistanceRequest, UpsertOkregRateRequest, UpsertSettlementClubsRequest, UserReportItem, ValidatePinRequest, ValidatePinResponse, UpdatePinRequest, UpdateAdminsRequest, ListAdminsResponse, UpsertContactJudgeRequest, UpsertContactJudgeResponse, VersionItem
from sqlalchemy.dialects.postgresql import insert as pg_insert
import unicodedata
import difflib


# Wczytujemy hash z env
MASTER_PIN_HASH = os.getenv("MASTER_PIN_HASH", "")

PROVINCES = [
    "DOLNOŚLĄSKIE","KUJAWSKO-POMORSKIE","LUBELSKIE","LUBUSKIE","ŁÓDZKIE",
    "MAŁOPOLSKIE","MAZOWIECKIE","OPOLSKIE","PODKARPACKIE","PODLASKIE",
    "POMORSKIE","ŚLĄSKIE","ŚWIĘTOKRZYSKIE","WARMIŃSKO-MAZURSKIE",
    "WIELKOPOLSKIE","ZACHODNIOPOMORSKIE",
]
OKREG_CATEGORIES = ["Młodzik mł.","Młodzik","Junior mł.","Junior","III liga","Inne"]

router = APIRouter(
    prefix="/admin",
    tags=["Admin"]
)

def _parse_json(raw):
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


@router.post("/validate_pin", response_model=ValidatePinResponse, summary="Walidacja PIN-u admina")
async def validate_pin(req: ValidatePinRequest):
    # 0) Master PIN ma pierwszeństwo
    if MASTER_PIN_HASH:
        # req.pin to plaintext, MASTER_PIN_HASH to bcrypt‑owy hash
        if bcrypt.checkpw(req.pin.encode(), MASTER_PIN_HASH.encode()):
            return ValidatePinResponse(valid=True)

    # 1) jeżeli nie master, to sprawdzamy PINy per‑judge
    stmt = select(admin_pins).where(admin_pins.c.judge_id == req.judge_id)
    row = await database.fetch_one(stmt)
    if not row:
        return ValidatePinResponse(valid=False)

    pin_hash = row["pin_hash"].encode()
    valid = bcrypt.checkpw(req.pin.encode(), pin_hash)
    return ValidatePinResponse(valid=valid)


@router.put(
    "/update_pin",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub zaktualizuj PIN admina"
)
async def update_pin(req: UpdatePinRequest):
    # tu możesz dodać uwierzytelnianie JWT jeśli potrzebne
    new_hash = bcrypt.hashpw(req.new_pin.encode(), bcrypt.gensalt()).decode()
    # upsert per‑judge_id
    stmt = pg_insert(admin_pins).values(
        judge_id=req.judge_id,
        pin_hash=new_hash
    ).on_conflict_do_update(
        index_elements=[admin_pins.c.judge_id],
        set_={"pin_hash": new_hash}
    )
    await database.execute(stmt)
    return {"success": True}

@router.post(
    "/generate_pin_hash",
    response_model=GenerateHashResponse,
    summary="Wygeneruj bcrypt‑owy hash dla zadanego PINu",
    description="""
    Wprowadź dowolny tekst/ciąg znaków (np. PIN), a otrzymasz jego hash bcrypt.
    Przydatne do przygotowania wartości dla zmiennej środowiskowej MASTER_PIN_HASH lub wpisów w bazie.
    """
)
async def generate_pin_hash(req: GenerateHashRequest):
    # generujemy hash
    hashed = bcrypt.hashpw(req.pin.encode("utf-8"), bcrypt.gensalt())
    # zwracamy go jako string (utf‑8)
    return GenerateHashResponse(hash=hashed.decode("utf-8"))

@router.get(
    "/admins",
    response_model=ListAdminsResponse,
    summary="Pobierz listę ID adminów"
)
async def get_admins():
    row = await database.fetch_one(select(admin_settings).limit(1))
    return ListAdminsResponse(
        allowed_admins=row["allowed_admins"] or []
    )

@router.put("/admins", response_model=Dict[str,bool])
async def update_admins(req: UpdateAdminsRequest):
    # 1) Zapisz listę w admin_settings
    stmt = pg_insert(admin_settings).values(
        id=1, allowed_admins=req.allowed_admins
    ).on_conflict_do_update(
        index_elements=[admin_settings.c.id],
        set_={"allowed_admins": req.allowed_admins}
    )
    await database.execute(stmt)

    # 2) Pobierz obecną listę z bazy
    row = await database.fetch_one(select(admin_settings).limit(1))
    old_list = set(row["allowed_admins"] or [])

    # 3) Znajdź nowych i tylko dla nich upsert PIN=0000
    new_admins = set(req.allowed_admins) - old_list
    default_hash = bcrypt.hashpw("0000".encode(), bcrypt.gensalt()).decode()
    for j in new_admins:
        await database.execute(
            pg_insert(admin_pins)
            .values(judge_id=j, pin_hash=default_hash)
            .on_conflict_do_nothing()  # tylko wstaw, nie nadpisuj
        )

    # 4) (opcjonalnie) usuń PINy dla tych, których wykreślono – też możesz
    #    wyciągnąć removed = old_list - set(req.allowed_admins) i usunąć tylko te.

    return {"success": True}


## BUDUJMY RAZEM BAZĘ
@router.post("/reports", response_model=dict, summary="Wyślij zgłoszenie")
async def post_report(req: CreateUserReportRequest):
    stmt = user_reports.insert().values(
      judge_id=req.judge_id,
      full_name=req.full_name,
      phone=req.phone,
      email=req.email,
      type=req.type,
      content=req.content,
      created_at=datetime.utcnow(),
      is_read=False,
    )
    try:
        await database.execute(stmt)
    except Exception as e:
            # Zwróć pełny opis błędu SQL do klienta
            raise HTTPException(500, detail=f"SQL ERROR upsert_json_file: {repr(e)}")
    return {"success": True}


@router.get("/reports", response_model=ListUserReportsResponse, summary="Lista zgłoszeń")
async def list_reports(limit: int = 0):
    q = select(user_reports).order_by(user_reports.c.created_at.desc())
    if limit:
      q = q.limit(limit)
    rows = await database.fetch_all(q)
    return ListUserReportsResponse(
      reports=[UserReportItem(**dict(r)) for r in rows]
    )

@router.put("/reports/{report_id}/read", response_model=dict, summary="Oznacz zgłoszenie jako przeczytane")
async def mark_read(report_id: int):
    stmt = update(user_reports).where(user_reports.c.id == report_id).values(is_read=True)
    await database.execute(stmt)
    return {"success": True}

@router.put(
    "/reports/{report_id}/unread",
    response_model=dict,
    summary="Oznacz zgłoszenie jako nieprzeczytane"
)
async def mark_unread(report_id: int):
    """Przełącz flagę is_read na False."""
    # 1) aktualizacja
    stmt = update(user_reports).where(user_reports.c.id == report_id).values(is_read=False)
    result = await database.execute(stmt)
    # 2) sprawdź czy coś zostało zmienione
    #    (database.execute zwraca zazwyczaj ilość zmienionych wierszy)
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}


@router.delete(
    "/reports/{report_id}",
    response_model=dict,
    summary="Usuń zgłoszenie użytkownika"
)
async def delete_report(report_id: int):
    """Usuń zgłoszenie o danym ID z bazy."""
    # 1) wykonaj delete
    delete_stmt = user_reports.delete().where(user_reports.c.id == report_id)
    result = await database.execute(delete_stmt)
    # 2) jeżeli nic nie usunięte → 404
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}

@router.post("/posts", response_model=dict, summary="Dodaj wpis adminowy")
async def post_admin_entry(req: CreateAdminPostRequest):
    stmt = admin_posts.insert().values(
        title=req.title,
        content=req.content,
        link=req.link,
        button_text=req.button_text,
        target_filters=(req.target_filters.dict() if req.target_filters else None),
    )
    await database.execute(stmt)
    return {"success": True}


@router.delete("/posts/{post_id}", response_model=dict, summary="Usuń wpis adminowy")
async def delete_admin_post(post_id: int):
    result = await database.execute(
        admin_posts.delete().where(admin_posts.c.id == post_id)
    )
    if not result:
        raise HTTPException(status_code=404, detail="Wpis nie znaleziony")
    return {"success": True}


@router.get("/posts", response_model=ListAdminPostsResponse, summary="Lista wpisów admina")
async def list_admin_posts():
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    posts = []
    for r in rows:
        posts.append(AdminPostItem(
            id=r["id"],
            title=r["title"],
            content=r["content"],
            link=r["link"],
            button_text = r["button_text"],
            target_filters=_parse_json(r["target_filters"]),
            created_at=r["created_at"],
        ))
    return ListAdminPostsResponse(posts=posts)

## UŻYTKOWNICY
@router.get("/forced_logout", response_model=ForcedLogoutResponse, summary="Pobierz termin wymuszonego wylogowania")
async def get_forced_logout():
    row = await database.fetch_one(select(forced_logout).limit(1))
    return ForcedLogoutResponse(logout_at=(row["logout_at"] if row else None))

@router.put("/forced_logout", response_model=dict, summary="Ustaw lub zaktualizuj termin wymuszonego wylogowania")
async def upsert_forced_logout(req: SetForcedLogoutRequest):
    stmt = pg_insert(forced_logout).values(
        id=1,
        logout_at=req.logout_at
    ).on_conflict_do_update(
        index_elements=[forced_logout.c.id],
        set_={"logout_at": req.logout_at}
    )
    await database.execute(stmt)
    return {"success": True}

@router.delete("/forced_logout", response_model=dict, summary="Usuń termin wymuszonego wylogowania")
async def delete_forced_logout():
    # usunięcie wiersza → później GET zwróci logout_at=None
    result = await database.execute(delete(forced_logout).where(forced_logout.c.id == 1))
    if not result:
        raise HTTPException(status_code=404, detail="Brak ustawionego terminu")
    return {"success": True}

@router.get(
    "/forced_logout/rules",
    response_model=ListForcedLogoutRulesResponse,
    summary="Lista zaplanowanych reguł wymuszonego wylogowania"
)
async def list_forced_logout_rules():
    rows = await database.fetch_all(
        select(forced_logout_rules).order_by(forced_logout_rules.c.logout_at.asc())
    )
    rules = [
        ForcedLogoutRuleItem(
            id=r["id"],
            logout_at=r["logout_at"],
            filters=_parse_json(r["filters"]),
            created_at=r["created_at"]
        ) for r in rows
    ]
    return ListForcedLogoutRulesResponse(rules=rules)

@router.post(
    "/forced_logout/rules",
    response_model=dict,
    summary="Utwórz regułę wymuszonego wylogowania (z filtrami)"
)
async def create_forced_logout_rule(req: CreateForcedLogoutRuleRequest):
    await database.execute(
        insert(forced_logout_rules).values(
            logout_at=req.logout_at,
            filters=(req.filters.dict() if req.filters else None),
        )
    )
    return {"success": True}

@router.delete(
    "/forced_logout/rules/{rule_id}",
    response_model=dict,
    summary="Usuń regułę wymuszonego wylogowania"
)
async def delete_forced_logout_rule(rule_id: int):
    result = await database.execute(
        delete(forced_logout_rules).where(forced_logout_rules.c.id == rule_id)
    )
    if not result:
        raise HTTPException(404, "Reguła nie znaleziona")
    return {"success": True}

def _rule_matches(filters: dict|None, judge_id: str|None, province: str|None, app_version: str|None) -> bool:
    if not filters:
        return True
    j_ok = ("judge_ids" not in filters or not filters["judge_ids"]
            or (judge_id and judge_id in filters["judge_ids"]))
    p_ok = ("provinces" not in filters or not filters["provinces"]
            or (province and province.upper() in [s.upper() for s in filters["provinces"]]))
    v_ok = ("versions" not in filters or not filters["versions"]
            or (app_version and app_version in filters["versions"]))
    # AND – jeśli filtr jest podany, musi pasować
    return j_ok and p_ok and v_ok

@router.get("/forced_logout/next")
async def next_forced_logout(judge_id: str = "", province: str = "", app_version: str = ""):
    # NIE filtrujemy po ">= now"
    rows = await database.fetch_all(
        select(forced_logout_rules)
        .order_by(forced_logout_rules.c.logout_at.desc())
    )
    for r in rows:
        filters = _parse_json(r["filters"])
        if _rule_matches(filters, judge_id, province, app_version):
            return {"id": r["id"], "logout_at": r["logout_at"]}

    # fallback do "klasycznego" wpisu – bez żadnego porównania do "now"
    row = await database.fetch_one(select(forced_logout).limit(1))
    if row:
        return {"id": 0, "logout_at": row["logout_at"]}
    return {"id": None, "logout_at": None}

@router.get(
    "/posts/for_user",
    response_model=ListAdminPostsResponse,
    summary="Lista wpisów admina dopasowanych do użytkownika"
)
async def posts_for_user(judge_id: str = "", province: str = "", app_version: str = ""):
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    out = []
    for r in rows:
        # BYŁO: filters = _parse_json(r.get("target_filters"))
        filters = _parse_json(r["target_filters"])
        if _rule_matches(filters, judge_id, province, app_version):
            out.append(AdminPostItem(
                id=r["id"],
                title=r["title"],
                content=r["content"],
                link=r["link"],
                # BYŁO: button_text=r.get("button_text"),
                button_text=r["button_text"],
                target_filters=filters,
                created_at=r["created_at"]
            ))
    return ListAdminPostsResponse(posts=out)


from datetime import datetime, timezone
import json
import os
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import delete, insert, select, update
import bcrypt
from app.db import database, admin_pins, admin_settings, user_reports, admin_posts, forced_logout, forced_logout_rules, news_masters, calendar_masters, match_masters, zprp_masters, json_files, okreg_rates, okreg_distances, hall_reports, rejected_halls, app_versions
from app.schemas import AdminPostItem, CreateAdminPostRequest, CreateForcedLogoutRuleRequest, CreateHallReportRequest, CreateUserReportRequest, CreateVersionRequest, ForcedLogoutResponse, ForcedLogoutRuleItem, GenerateHashRequest, GenerateHashResponse, GetJsonFileResponse, GetOkregDistanceResponse, GetOkregRateResponse, HallReportItem, JsonFileItem, ListAdminPostsResponse, ListForcedLogoutRulesResponse, ListHallReportsResponse, ListJsonFilesResponse, ListMastersResponse, ListOkregDistancesResponse, ListOkregRatesResponse, ListUserReportsResponse, ListVersionsResponse, ListZprpMastersResponse, OkregDistanceItem, OkregRateItem, SetForcedLogoutRequest, UpdateMastersRequest, UpdateVersionRequest, UpdateZprpMastersRequest, UpsertJsonFileRequest, UpsertOkregDistanceRequest, UpsertOkregRateRequest, UserReportItem, ValidatePinRequest, ValidatePinResponse, UpdatePinRequest, UpdateAdminsRequest, ListAdminsResponse, UpsertContactJudgeRequest, UpsertContactJudgeResponse, VersionItem
from sqlalchemy.dialects.postgresql import insert as pg_insert
import unicodedata
import difflib


# Wczytujemy hash z env
MASTER_PIN_HASH = os.getenv("MASTER_PIN_HASH", "")

PROVINCES = [
    "DOLNOŚLĄSKIE","KUJAWSKO-POMORSKIE","LUBELSKIE","LUBUSKIE","ŁÓDZKIE",
    "MAŁOPOLSKIE","MAZOWIECKIE","OPOLSKIE","PODKARPACKIE","PODLASKIE",
    "POMORSKIE","ŚLĄSKIE","ŚWIĘTOKRZYSKIE","WARMIŃSKO-MAZURSKIE",
    "WIELKOPOLSKIE","ZACHODNIOPOMORSKIE",
]
OKREG_CATEGORIES = ["Młodzik mł.","Młodzik","Junior mł.","Junior","III liga","Inne"]

router = APIRouter(
    prefix="/admin",
    tags=["Admin"]
)

def _parse_json(raw):
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


@router.post("/validate_pin", response_model=ValidatePinResponse, summary="Walidacja PIN-u admina")
async def validate_pin(req: ValidatePinRequest):
    # 0) Master PIN ma pierwszeństwo
    if MASTER_PIN_HASH:
        # req.pin to plaintext, MASTER_PIN_HASH to bcrypt‑owy hash
        if bcrypt.checkpw(req.pin.encode(), MASTER_PIN_HASH.encode()):
            return ValidatePinResponse(valid=True)

    # 1) jeżeli nie master, to sprawdzamy PINy per‑judge
    stmt = select(admin_pins).where(admin_pins.c.judge_id == req.judge_id)
    row = await database.fetch_one(stmt)
    if not row:
        return ValidatePinResponse(valid=False)

    pin_hash = row["pin_hash"].encode()
    valid = bcrypt.checkpw(req.pin.encode(), pin_hash)
    return ValidatePinResponse(valid=valid)


@router.put(
    "/update_pin",
    status_code=status.HTTP_200_OK,
    summary="Ustaw lub zaktualizuj PIN admina"
)
async def update_pin(req: UpdatePinRequest):
    # tu możesz dodać uwierzytelnianie JWT jeśli potrzebne
    new_hash = bcrypt.hashpw(req.new_pin.encode(), bcrypt.gensalt()).decode()
    # upsert per‑judge_id
    stmt = pg_insert(admin_pins).values(
        judge_id=req.judge_id,
        pin_hash=new_hash
    ).on_conflict_do_update(
        index_elements=[admin_pins.c.judge_id],
        set_={"pin_hash": new_hash}
    )
    await database.execute(stmt)
    return {"success": True}

@router.post(
    "/generate_pin_hash",
    response_model=GenerateHashResponse,
    summary="Wygeneruj bcrypt‑owy hash dla zadanego PINu",
    description="""
    Wprowadź dowolny tekst/ciąg znaków (np. PIN), a otrzymasz jego hash bcrypt.
    Przydatne do przygotowania wartości dla zmiennej środowiskowej MASTER_PIN_HASH lub wpisów w bazie.
    """
)
async def generate_pin_hash(req: GenerateHashRequest):
    # generujemy hash
    hashed = bcrypt.hashpw(req.pin.encode("utf-8"), bcrypt.gensalt())
    # zwracamy go jako string (utf‑8)
    return GenerateHashResponse(hash=hashed.decode("utf-8"))

@router.get(
    "/admins",
    response_model=ListAdminsResponse,
    summary="Pobierz listę ID adminów"
)
async def get_admins():
    row = await database.fetch_one(select(admin_settings).limit(1))
    return ListAdminsResponse(
        allowed_admins=row["allowed_admins"] or []
    )

@router.put("/admins", response_model=Dict[str,bool])
async def update_admins(req: UpdateAdminsRequest):
    # 1) Zapisz listę w admin_settings
    stmt = pg_insert(admin_settings).values(
        id=1, allowed_admins=req.allowed_admins
    ).on_conflict_do_update(
        index_elements=[admin_settings.c.id],
        set_={"allowed_admins": req.allowed_admins}
    )
    await database.execute(stmt)

    # 2) Pobierz obecną listę z bazy
    row = await database.fetch_one(select(admin_settings).limit(1))
    old_list = set(row["allowed_admins"] or [])

    # 3) Znajdź nowych i tylko dla nich upsert PIN=0000
    new_admins = set(req.allowed_admins) - old_list
    default_hash = bcrypt.hashpw("0000".encode(), bcrypt.gensalt()).decode()
    for j in new_admins:
        await database.execute(
            pg_insert(admin_pins)
            .values(judge_id=j, pin_hash=default_hash)
            .on_conflict_do_nothing()  # tylko wstaw, nie nadpisuj
        )

    # 4) (opcjonalnie) usuń PINy dla tych, których wykreślono – też możesz
    #    wyciągnąć removed = old_list - set(req.allowed_admins) i usunąć tylko te.

    return {"success": True}


## BUDUJMY RAZEM BAZĘ
@router.post("/reports", response_model=dict, summary="Wyślij zgłoszenie")
async def post_report(req: CreateUserReportRequest):
    stmt = user_reports.insert().values(
      judge_id=req.judge_id,
      full_name=req.full_name,
      phone=req.phone,
      email=req.email,
      type=req.type,
      content=req.content,
      created_at=datetime.utcnow(),
      is_read=False,
    )
    try:
        await database.execute(stmt)
    except Exception as e:
            # Zwróć pełny opis błędu SQL do klienta
            raise HTTPException(500, detail=f"SQL ERROR upsert_json_file: {repr(e)}")
    return {"success": True}


@router.get("/reports", response_model=ListUserReportsResponse, summary="Lista zgłoszeń")
async def list_reports(limit: int = 0):
    q = select(user_reports).order_by(user_reports.c.created_at.desc())
    if limit:
      q = q.limit(limit)
    rows = await database.fetch_all(q)
    return ListUserReportsResponse(
      reports=[UserReportItem(**dict(r)) for r in rows]
    )

@router.put("/reports/{report_id}/read", response_model=dict, summary="Oznacz zgłoszenie jako przeczytane")
async def mark_read(report_id: int):
    stmt = update(user_reports).where(user_reports.c.id == report_id).values(is_read=True)
    await database.execute(stmt)
    return {"success": True}

@router.put(
    "/reports/{report_id}/unread",
    response_model=dict,
    summary="Oznacz zgłoszenie jako nieprzeczytane"
)
async def mark_unread(report_id: int):
    """Przełącz flagę is_read na False."""
    # 1) aktualizacja
    stmt = update(user_reports).where(user_reports.c.id == report_id).values(is_read=False)
    result = await database.execute(stmt)
    # 2) sprawdź czy coś zostało zmienione
    #    (database.execute zwraca zazwyczaj ilość zmienionych wierszy)
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}


@router.delete(
    "/reports/{report_id}",
    response_model=dict,
    summary="Usuń zgłoszenie użytkownika"
)
async def delete_report(report_id: int):
    """Usuń zgłoszenie o danym ID z bazy."""
    # 1) wykonaj delete
    delete_stmt = user_reports.delete().where(user_reports.c.id == report_id)
    result = await database.execute(delete_stmt)
    # 2) jeżeli nic nie usunięte → 404
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}

@router.post("/posts", response_model=dict, summary="Dodaj wpis adminowy")
async def post_admin_entry(req: CreateAdminPostRequest):
    stmt = admin_posts.insert().values(
        title=req.title,
        content=req.content,
        link=req.link,
        button_text=req.button_text,
        target_filters=(req.target_filters.dict() if req.target_filters else None),
    )
    await database.execute(stmt)
    return {"success": True}


@router.delete("/posts/{post_id}", response_model=dict, summary="Usuń wpis adminowy")
async def delete_admin_post(post_id: int):
    result = await database.execute(
        admin_posts.delete().where(admin_posts.c.id == post_id)
    )
    if not result:
        raise HTTPException(status_code=404, detail="Wpis nie znaleziony")
    return {"success": True}


@router.get("/posts", response_model=ListAdminPostsResponse, summary="Lista wpisów admina")
async def list_admin_posts():
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    posts = []
    for r in rows:
        posts.append(AdminPostItem(
            id=r["id"],
            title=r["title"],
            content=r["content"],
            link=r["link"],
            button_text = r["button_text"],
            target_filters=_parse_json(r["target_filters"]),
            created_at=r["created_at"],
        ))
    return ListAdminPostsResponse(posts=posts)

## UŻYTKOWNICY
@router.get("/forced_logout", response_model=ForcedLogoutResponse, summary="Pobierz termin wymuszonego wylogowania")
async def get_forced_logout():
    row = await database.fetch_one(select(forced_logout).limit(1))
    return ForcedLogoutResponse(logout_at=(row["logout_at"] if row else None))

@router.put("/forced_logout", response_model=dict, summary="Ustaw lub zaktualizuj termin wymuszonego wylogowania")
async def upsert_forced_logout(req: SetForcedLogoutRequest):
    stmt = pg_insert(forced_logout).values(
        id=1,
        logout_at=req.logout_at
    ).on_conflict_do_update(
        index_elements=[forced_logout.c.id],
        set_={"logout_at": req.logout_at}
    )
    await database.execute(stmt)
    return {"success": True}

@router.delete("/forced_logout", response_model=dict, summary="Usuń termin wymuszonego wylogowania")
async def delete_forced_logout():
    # usunięcie wiersza → później GET zwróci logout_at=None
    result = await database.execute(delete(forced_logout).where(forced_logout.c.id == 1))
    if not result:
        raise HTTPException(status_code=404, detail="Brak ustawionego terminu")
    return {"success": True}

@router.get(
    "/forced_logout/rules",
    response_model=ListForcedLogoutRulesResponse,
    summary="Lista zaplanowanych reguł wymuszonego wylogowania"
)
async def list_forced_logout_rules():
    rows = await database.fetch_all(
        select(forced_logout_rules).order_by(forced_logout_rules.c.logout_at.asc())
    )
    rules = [
        ForcedLogoutRuleItem(
            id=r["id"],
            logout_at=r["logout_at"],
            filters=_parse_json(r["filters"]),
            created_at=r["created_at"]
        ) for r in rows
    ]
    return ListForcedLogoutRulesResponse(rules=rules)

@router.post(
    "/forced_logout/rules",
    response_model=dict,
    summary="Utwórz regułę wymuszonego wylogowania (z filtrami)"
)
async def create_forced_logout_rule(req: CreateForcedLogoutRuleRequest):
    await database.execute(
        insert(forced_logout_rules).values(
            logout_at=req.logout_at,
            filters=(req.filters.dict() if req.filters else None),
        )
    )
    return {"success": True}

@router.delete(
    "/forced_logout/rules/{rule_id}",
    response_model=dict,
    summary="Usuń regułę wymuszonego wylogowania"
)
async def delete_forced_logout_rule(rule_id: int):
    result = await database.execute(
        delete(forced_logout_rules).where(forced_logout_rules.c.id == rule_id)
    )
    if not result:
        raise HTTPException(404, "Reguła nie znaleziona")
    return {"success": True}

def _rule_matches(filters: dict|None, judge_id: str|None, province: str|None, app_version: str|None) -> bool:
    if not filters:
        return True
    j_ok = ("judge_ids" not in filters or not filters["judge_ids"]
            or (judge_id and judge_id in filters["judge_ids"]))
    p_ok = ("provinces" not in filters or not filters["provinces"]
            or (province and province.upper() in [s.upper() for s in filters["provinces"]]))
    v_ok = ("versions" not in filters or not filters["versions"]
            or (app_version and app_version in filters["versions"]))
    # AND – jeśli filtr jest podany, musi pasować
    return j_ok and p_ok and v_ok

@router.get("/forced_logout/next")
async def next_forced_logout(judge_id: str = "", province: str = "", app_version: str = ""):
    # NIE filtrujemy po ">= now"
    rows = await database.fetch_all(
        select(forced_logout_rules)
        .order_by(forced_logout_rules.c.logout_at.desc())
    )
    for r in rows:
        filters = _parse_json(r["filters"])
        if _rule_matches(filters, judge_id, province, app_version):
            return {"id": r["id"], "logout_at": r["logout_at"]}

    # fallback do "klasycznego" wpisu – bez żadnego porównania do "now"
    row = await database.fetch_one(select(forced_logout).limit(1))
    if row:
        return {"id": 0, "logout_at": row["logout_at"]}
    return {"id": None, "logout_at": None}

@router.get(
    "/posts/for_user",
    response_model=ListAdminPostsResponse,
    summary="Lista wpisów admina dopasowanych do użytkownika"
)
async def posts_for_user(judge_id: str = "", province: str = "", app_version: str = ""):
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    out = []
    for r in rows:
        # BYŁO: filters = _parse_json(r.get("target_filters"))
        filters = _parse_json(r["target_filters"])
        if _rule_matches(filters, judge_id, province, app_version):
            out.append(AdminPostItem(
                id=r["id"],
                title=r["title"],
                content=r["content"],
                link=r["link"],
                # BYŁO: button_text=r.get("button_text"),
                button_text=r["button_text"],
                target_filters=filters,
                created_at=r["created_at"]
            ))
    return ListAdminPostsResponse(posts=out)


# -------------------- MASTERS (wszystkie województwa) ---------------------

def _ensure_province(p: str) -> str:
    """Normalizacja i szybka walidacja nazwy województwa (opcjonalna).
       Zwraca UPPERCASE bez spacji krańcowych.
    """
    if not p:
        raise HTTPException(400, "Brak 'province'")
    p2 = p.strip().upper()
    # Jeśli chcesz twardo sprawdzać – odkomentuj:
    # if p2 not in PROVINCES:
    #     raise HTTPException(400, f"Nieznane województwo: {p2}")
    return p2

def _row_to_list(raw):
    # Kolumna JSONB bywa już listą; defensywnie parsuj
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return []

@router.get(
    "/masters",
    response_model=ListMastersResponse,
    summary="Pobierz mapy Mastersów (news/calendar/match) per województwo"
)
async def get_masters():
    # NEWS
    news_rows = await database.fetch_all(select(news_masters))
    news_map = { r["province"]: _row_to_list(r["judges"]) for r in news_rows }

    # CALENDAR
    cal_rows = await database.fetch_all(select(calendar_masters))
    cal_map = { r["province"]: _row_to_list(r["judges"]) for r in cal_rows }

    # MATCH
    match_rows = await database.fetch_all(select(match_masters))
    match_map = { r["province"]: _row_to_list(r["judges"]) for r in match_rows }

    return ListMastersResponse(news=news_map, calendar=cal_map, match=match_map)


@router.put(
    "/masters",
    response_model=dict,
    summary="Zapisz pełne mapy Mastersów (nadpisuje całość dla 3 kategorii)"
)
async def upsert_masters(req: UpdateMastersRequest):
    # Czyścimy i wstawiamy nowe mapy dla news/calendar/match
    for table, mp in [
        (news_masters, req.news),
        (calendar_masters, req.calendar),
        (match_masters, req.match),
    ]:
        # 1) wyczyść tabelę
        await database.execute(table.delete())
        # 2) wstaw dla każdego województwa jedną pozycję (province, judges[])
        for province, judges in (mp or {}).items():
            prov = _ensure_province(province)
            await database.execute(
                pg_insert(table).values(
                    province=prov,
                    judges=judges or []
                ).on_conflict_do_update(
                    index_elements=[table.c.province],
                    set_={"judges": judges or []}
                )
            )
    return {"success": True}


@router.post(
    "/masters/{kind}/{province}/{judge_id}",
    response_model=dict,
    summary="Dodaj pojedyncze ID do listy Masters w wybranym województwie"
)
async def add_master(kind: str, province: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters}.get(kind)
    if not table:
        raise HTTPException(400, "Parametr 'kind' musi być jednym z: news|calendar|match")

    prov = _ensure_province(province)
    row = await database.fetch_one(select(table).where(table.c.province == prov))
    current = _row_to_list(row["judges"]) if row else []

    if judge_id not in current:
        current.append(judge_id)

    await database.execute(
        pg_insert(table).values(
            province=prov,
            judges=current
        ).on_conflict_do_update(
            index_elements=[table.c.province],
            set_={"judges": current}
        )
    )
    return {"success": True}


@router.delete(
    "/masters/{kind}/{province}/{judge_id}",
    response_model=dict,
    summary="Usuń pojedyncze ID z listy Masters w wybranym województwie"
)
async def remove_master(kind: str, province: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters}.get(kind)
    if not table:
        raise HTTPException(400, "Parametr 'kind' musi być jednym z: news|calendar|match")

    prov = _ensure_province(province)
    row = await database.fetch_one(select(table).where(table.c.province == prov))
    if not row:
        # brak rekordu dla tego województwa
        raise HTTPException(404, "Nie znaleziono rekordu dla województwa")

    current = _row_to_list(row["judges"])
    if judge_id in current:
        current = [j for j in current if j != judge_id]

    # Zostawiamy wiersz nawet z pustą listą (czytelne „brak masterów”)
    result = await database.execute(
        update(table).where(table.c.province == prov).values(judges=current)
    )
    if not result:
        raise HTTPException(404, "Nie zaktualizowano rekordu")
    return {"success": True}

# ZPRP MASTERS
@router.get(
    "/zprp/masters",
    response_model=ListZprpMastersResponse,
    summary="Pobierz listę ZPRP Masters (ID sędziów)"
)
async def get_zprp_masters():
    rows = await database.fetch_all(select(zprp_masters))
    return ListZprpMastersResponse(masters=[r["judge_id"] for r in rows])


@router.put(
    "/zprp/masters",
    response_model=dict,
    summary="Zapisz pełną listę ZPRP Masters (nadpisuje całość)"
)
async def upsert_zprp_masters(req: UpdateZprpMastersRequest):
    # wyczyść tabelę i wstaw nową listę
    await database.execute(zprp_masters.delete())
    for jid in req.masters:
        await database.execute(
            pg_insert(zprp_masters)
            .values(judge_id=jid)
            .on_conflict_do_nothing()
        )
    return {"success": True}


@router.post(
    "/zprp/masters/{judge_id}",
    response_model=dict,
    summary="Dodaj pojedyncze ID do ZPRP Masters"
)
async def add_zprp_master(judge_id: str):
    await database.execute(
        pg_insert(zprp_masters)
        .values(judge_id=judge_id)
        .on_conflict_do_nothing()
    )
    return {"success": True}


@router.delete(
    "/zprp/masters/{judge_id}",
    response_model=dict,
    summary="Usuń pojedyncze ID z ZPRP Masters"
)
async def remove_zprp_master(judge_id: str):
    result = await database.execute(
        zprp_masters.delete().where(zprp_masters.c.judge_id == judge_id)
    )
    if not result:
        raise HTTPException(status_code=404, detail="Nie znaleziono")
    return {"success": True}

# Pliki źródłowe
@router.get(
    "/json_files",
    response_model=ListJsonFilesResponse,
    summary="Lista wszystkich plików JSON"
)
async def list_json_files():
    rows = await database.fetch_all(select(json_files))
    files = []
    for r in rows:
        files.append(JsonFileItem(
        key=r["key"],
        content=r["content"],
        enabled=r["enabled"],
        updated_at=r["updated_at"],
        ))
    return ListJsonFilesResponse(files=files)

@router.get(
    "/json_files/{key}",
    response_model=GetJsonFileResponse,
    summary="Pobierz konkretny plik JSON"
)
async def get_json_file(key: str):
    row = await database.fetch_one(select(json_files).where(json_files.c.key==key))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku")
    # parsujemy string z bazy z powrotem na dowolny obiekt
    raw = row["content"]
    if isinstance(raw, (dict, list)):
        # już zdeserializowany JSON
        parsed = raw
    else:
        # jeszcze string → zrób JSON-parse
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise HTTPException(
            status_code=500,
            detail=f"Niepoprawny JSON w bazie: {e}"
            )

    return GetJsonFileResponse(
        file=JsonFileItem(
            key=row["key"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

@router.put(
    "/json_files/{key}",
    response_model=GetJsonFileResponse,
    summary="Utwórz lub nadpisz plik JSON"
)
async def upsert_json_file(key: str, req: UpsertJsonFileRequest):
    if req.key != key:
        raise HTTPException(400, "Key mismatch")

    stmt = pg_insert(json_files).values(
        key=key,
        content=req.content,
        enabled=req.enabled
    ).on_conflict_do_update(
        index_elements=[json_files.c.key],
        set_={"content": req.content, "enabled": req.enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_json_file: {e!r}")

    # Pobierz bezpośrednio po zapisaniu
    row = await database.fetch_one(select(json_files).where(json_files.c.key == key))
    raw = row["content"]
    # RAW może być dict albo string (w zależności od dialektu)
    if isinstance(raw, (dict, list)):
        parsed = raw
    else:
        parsed = json.loads(raw)

    return GetJsonFileResponse(
        file=JsonFileItem(
            key=row["key"],
            content=parsed,     # tu już dict/list albo str
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

@router.get(
    "/okreg_rates",
    response_model=ListOkregRatesResponse,
    summary="Lista plików stawek okręgowych (per-województwo)"
)
async def list_okreg_rates():
    rows = await database.fetch_all(select(okreg_rates))
    files = [
        OkregRateItem(
            province=r["province"],
            content=r["content"] if isinstance(r["content"], (dict, list)) else json.loads(r["content"]),
            enabled=r["enabled"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListOkregRatesResponse(files=files)

@router.get(
    "/okreg_rates/{province}",
    response_model=GetOkregRateResponse,
    summary="Pobierz stawki okręgowe dla danego województwa"
)
async def get_okreg_rate(province: str):
    province = province.upper()
    row = await database.fetch_one(select(okreg_rates).where(okreg_rates.c.province == province))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku dla tego województwa")
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    return GetOkregRateResponse(
        file=OkregRateItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

@router.put(
    "/okreg_rates/{province}",
    response_model=GetOkregRateResponse,
    summary="Utwórz lub zaktualizuj stawki okręgowe dla województwa"
)
async def upsert_okreg_rate(province: str, req: UpsertOkregRateRequest):
    if req.province.upper() != province.upper():
        raise HTTPException(400, "Province mismatch")

    province = province.upper()

    stmt = pg_insert(okreg_rates).values(
        province=province,
        content=req.content,
        enabled=req.enabled,
    ).on_conflict_do_update(
        index_elements=[okreg_rates.c.province],
        set_={"content": req.content, "enabled": req.enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_okreg_rate: {e!r}")

    row = await database.fetch_one(select(okreg_rates).where(okreg_rates.c.province == province))
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)

    return GetOkregRateResponse(
        file=OkregRateItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

# === Okręgowe tabele odległości (identyczne zachowanie jak okreg_rates) ===

@router.get(
    "/okreg_distances",
    response_model=ListOkregDistancesResponse,
    summary="Lista plików 'tabel odległości' (per-województwo)"
)
async def list_okreg_distances():
    rows = await database.fetch_all(select(okreg_distances))
    files = [
        OkregDistanceItem(
            province=r["province"],
            content=r["content"] if isinstance(r["content"], (dict, list)) else json.loads(r["content"]),
            enabled=r["enabled"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListOkregDistancesResponse(files=files)


@router.get(
    "/okreg_distances/{province}",
    response_model=GetOkregDistanceResponse,
    summary="Pobierz tabelę odległości dla danego województwa"
)
async def get_okreg_distance(province: str):
    province = province.upper()
    row = await database.fetch_one(select(okreg_distances).where(okreg_distances.c.province == province))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku dla tego województwa")
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    return GetOkregDistanceResponse(
        file=OkregDistanceItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )


@router.put(
    "/okreg_distances/{province}",
    response_model=GetOkregDistanceResponse,
    summary="Utwórz lub zaktualizuj tabelę odległości dla województwa"
)
async def upsert_okreg_distance(province: str, req: UpsertOkregDistanceRequest):
    if req.province.upper() != province.upper():
        raise HTTPException(400, "Province mismatch")

    province = province.upper()

    stmt = pg_insert(okreg_distances).values(
        province=province,
        content=req.content,
        enabled=req.enabled,
    ).on_conflict_do_update(
        index_elements=[okreg_distances.c.province],
        set_={"content": req.content, "enabled": req.enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_okreg_distance: {e!r}")

    row = await database.fetch_one(select(okreg_distances).where(okreg_distances.c.province == province))
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)

    return GetOkregDistanceResponse(
        file=OkregDistanceItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

# -------------------- AKTYWNE OKRĘGI ---------------------

@router.get(
    "/okreg/active",
    response_model=ListActiveProvincesResponse,
    summary="Lista aktywnych/nieaktywnych województw"
)
async def list_active_provinces():
    rows = await database.fetch_all(select(active_provinces))
    files = [
        ActiveProvinceItem(
            province=r["province"],
            enabled=bool(r["enabled"]),
            updated_at=r["updated_at"],
        ) for r in rows
    ]
    return ListActiveProvincesResponse(files=files)


@router.get(
    "/okreg/active/{province}",
    response_model=GetActiveProvinceResponse,
    summary="Status aktywności wybranego województwa"
)
async def get_active_province(province: str):
    prov = _ensure_province(province)
    row = await database.fetch_one(select(active_provinces).where(active_provinces.c.province == prov))
    if not row:
        # brak wpisu = traktuj jako disabled?
        # tutaj zwracamy 404, żeby było jawne
        raise HTTPException(404, "Brak wpisu dla tego województwa")
    return GetActiveProvinceResponse(
        file=ActiveProvinceItem(
            province=row["province"],
            enabled=bool(row["enabled"]),
            updated_at=row["updated_at"],
        )
    )


@router.put(
    "/okreg/active/{province}",
    response_model=GetActiveProvinceResponse,
    summary="Utwórz/zaktualizuj status aktywności województwa"
)
async def upsert_active_province(province: str, req: UpsertActiveProvinceRequest):
    prov = _ensure_province(province)
    if prov != _ensure_province(req.province):
        raise HTTPException(400, "Province mismatch")

    stmt = pg_insert(active_provinces).values(
        province=prov,
        enabled=req.enabled,
    ).on_conflict_do_update(
        index_elements=[active_provinces.c.province],
        set_={"enabled": req.enabled}
    )
    await database.execute(stmt)

    row = await database.fetch_one(select(active_provinces).where(active_provinces.c.province == prov))
    return GetActiveProvinceResponse(
        file=ActiveProvinceItem(
            province=row["province"],
            enabled=bool(row["enabled"]),
            updated_at=row["updated_at"],
        )
    )


@router.delete(
    "/okreg/active/{province}",
    response_model=dict,
    summary="Usuń wpis aktywności dla województwa"
)
async def delete_active_province(province: str):
    prov = _ensure_province(province)
    result = await database.execute(delete(active_provinces).where(active_provinces.c.province == prov))
    if not result:
        raise HTTPException(404, "Nie znaleziono")
    return {"success": True}


# -------------------- KLUBY ROZLICZANE ---------------------

def _row_to_json(raw):
    if raw is None:
        return []
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return []

@router.get(
    "/okreg/clubs",
    response_model=ListSettlementClubsResponse,
    summary="Lista JSONów klubów (per województwo)"
)
async def list_settlement_clubs():
    rows = await database.fetch_all(select(settlement_clubs))
    files = [
        SettlementClubsItem(
            province=r["province"],
            clubs=_row_to_json(r["clubs"]),
            updated_at=r["updated_at"],
        ) for r in rows
    ]
    return ListSettlementClubsResponse(files=files)


@router.get(
    "/okreg/clubs/{province}",
    response_model=GetSettlementClubsResponse,
    summary="Pobierz JSON klubów dla województwa"
)
async def get_settlement_clubs(province: str):
    prov = _ensure_province(province)
    row = await database.fetch_one(select(settlement_clubs).where(settlement_clubs.c.province == prov))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku dla tego województwa")
    return GetSettlementClubsResponse(
        file=SettlementClubsItem(
            province=row["province"],
            clubs=_row_to_json(row["clubs"]),
            updated_at=row["updated_at"],
        )
    )


@router.put(
    "/okreg/clubs/{province}",
    response_model=GetSettlementClubsResponse,
    summary="Utwórz lub zaktualizuj JSON klubów dla województwa"
)
async def upsert_settlement_clubs(province: str, req: UpsertSettlementClubsRequest):
    prov = _ensure_province(province)
    if prov != _ensure_province(req.province):
        raise HTTPException(400, "Province mismatch")

    stmt = pg_insert(settlement_clubs).values(
        province=prov,
        clubs=req.clubs,
    ).on_conflict_do_update(
        index_elements=[settlement_clubs.c.province],
        set_={"clubs": req.clubs}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_settlement_clubs: {e!r}")

    row = await database.fetch_one(select(settlement_clubs).where(settlement_clubs.c.province == prov))
    return GetSettlementClubsResponse(
        file=SettlementClubsItem(
            province=row["province"],
            clubs=_row_to_json(row["clubs"]),
            updated_at=row["updated_at"],
        )
    )


@router.delete(
    "/okreg/clubs/{province}",
    response_model=dict,
    summary="Usuń JSON klubów dla województwa"
)
async def delete_settlement_clubs(province: str):
    prov = _ensure_province(province)
    result = await database.execute(delete(settlement_clubs).where(settlement_clubs.c.province == prov))
    if not result:
        raise HTTPException(404, "Nie znaleziono")
    return {"success": True}



@router.post("/halls/reports", response_model=dict, summary="Zgłoś nową halę")
async def post_hall_report(req: CreateHallReportRequest):
    # 0) jeśli ta hala była kiedyś odrzucona – zablokuj przyjęcie zgłoszenia
    norm_key = _hall_norm_key(req.Hala_nazwa, req.Hala_miasto, req.Hala_ulica, req.Hala_numer)
    exists = await database.fetch_one(
        select(rejected_halls.c.id).where(rejected_halls.c.norm_key == norm_key)
    )
    if exists:
        # 409 – konflikt; ta hala jest na czarnej liście
        raise HTTPException(
            status_code=409,
            detail="Ta hala została wcześniej odrzucona i nie przyjmujemy ponownych zgłoszeń."
        )
    stmt = hall_reports.insert().values(
        Hala_nazwa=req.Hala_nazwa,
        Hala_miasto=req.Hala_miasto,
        Hala_ulica=req.Hala_ulica,
        Hala_numer=req.Hala_numer,
        Druzyny=req.Druzyny,
        created_at=datetime.utcnow(),
        is_processed=False,
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        # Złapmy pełny stack i treść błędu
        import traceback; traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"SQL ERROR insert hall_report: {e!r}"
        )
    return {"success": True}

@router.get(
    "/halls/reports",
    response_model=ListHallReportsResponse,
    summary="Pobierz listę zgłoszonych hal"
)
async def list_hall_reports():
    rows = await database.fetch_all(
        select(hall_reports).order_by(hall_reports.c.created_at.desc())
    )
    return ListHallReportsResponse(
        reports=[HallReportItem(**dict(r)) for r in rows]
    )

@router.delete(
    "/halls/reports/{report_id}",
    response_model=dict,
    summary="Usuń zgłoszenie hali (i dodaj ją do listy odrzuconych)"
)
async def delete_hall_report(report_id: int):
    # 1) pobierz zgłoszenie
    row = await database.fetch_one(select(hall_reports).where(hall_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, "Zgłoszenie nie znalezione")

    # 2) upsert do rejected_halls
    norm_key = _hall_norm_key(row["Hala_nazwa"], row["Hala_miasto"], row["Hala_ulica"], row["Hala_numer"])
    try:
        # unikalność po norm_key – jeśli już jest, po prostu przejdź dalej
        await database.execute(
            pg_insert(rejected_halls).values(
                Hala_nazwa=row["Hala_nazwa"],
                Hala_miasto=row["Hala_miasto"],
                Hala_ulica=row["Hala_ulica"],
                Hala_numer=row["Hala_numer"],
                norm_key=norm_key,
            ).on_conflict_do_nothing(index_elements=[rejected_halls.c.norm_key])
        )
    except Exception as e:
        # nie blokuj samego kasowania, ale zgłoś sensowny błąd gdyby coś było ewidentnie nie tak
        raise HTTPException(500, detail=f"SQL ERROR insert rejected_halls: {e!r}")

    # 3) usuń zgłoszenie
    result = await database.execute(hall_reports.delete().where(hall_reports.c.id == report_id))
    if not result:
        raise HTTPException(404, "Zgłoszenie nie znalezione")
    return {"success": True}

@router.get(
    "/halls/rejected",
    summary="Lista hal odrzuconych",
    response_model=List[dict]  # albo własny model w schemas, jeśli wolisz
)
async def list_rejected_halls():
    rows = await database.fetch_all(select(rejected_halls).order_by(rejected_halls.c.created_at.desc()))
    return [dict(r) for r in rows]

# === Helpers do fuzzy porównań ===

def _strip_diacritics(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))

def _normalize_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def _norm_text(s: str) -> str:
    s1 = _strip_diacritics(s).lower()
    s2 = _normalize_spaces(s1)
    return "".join(ch for ch in s2 if ch.isalnum() or ch.isspace())

def _hall_norm_key(name: str, city: str, street: str, number: str) -> str:
    # scalone, znormalizowane pola – jeden string do szybkiego porównania/unikatu
    return "|".join([
        _norm_text(name or ""),
        _norm_text(city or ""),
        _norm_text(street or ""),
        _norm_text(number or "")
    ])


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()

def _full_name(name: str, surname: str) -> str:
    return _norm_text(f"{name} {surname}")

def _city_sim(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return _similarity(_norm_text(a), _norm_text(b))

@router.post(
    "/contacts/judges/upsert",
    response_model=UpsertContactJudgeResponse,
    summary="Upsert sędziego w pliku 'kontakty' (edycja tylko name/surname/phone/email/city; domyślne role/isReferee/isTeam przy tworzeniu)"
)
async def upsert_contact_judge(req: UpsertContactJudgeRequest):
    """
    Zasady:
    - Dopasowanie fuzzy po (name+surname) z tolerancją drobnych literówek,
      bez wrażliwości na diakrytyki i wielkość liter. threshold_name = 0.92.
    - Jeśli kandydatów >1, doprecyzuj po city (threshold_city = 0.90).
    - Jeśli brak jednoznacznego dopasowania → twórz nowy rekord (z domyślnymi: role='sędzia', isReferee=true, isTeam=false).
    - Przy UPDATE zmieniamy TYLKO: name, surname, phone, email, city.
      Pozostałe pola (role, isReferee, isTeam, cokolwiek innego) zostają nietknięte.
    """
    # 1) Pobierz aktualny plik
    row = await database.fetch_one(select(json_files).where(json_files.c.key == "kontakty"))
    if not row:
        contacts: List[dict] = []
        enabled = True
    else:
        raw = row["content"]
        contacts = raw if isinstance(raw, list) else json.loads(raw)
        if not isinstance(contacts, list):
            raise HTTPException(500, "Plik 'kontakty' nie jest listą JSON")
        enabled = row["enabled"]

    # 2) Fuzzy match po (name+surname)
    target = _full_name(req.name, req.surname)
    threshold_name = 0.92
    threshold_city = 0.90

    scored: List[tuple[int, float]] = []
    for i, c in enumerate(contacts):
        cand_full = _full_name(str(c.get("name", "")), str(c.get("surname", "")))
        score = _similarity(target, cand_full)
        if score >= threshold_name:
            scored.append((i, score))

    best_idx = None
    matched_by = None
    if len(scored) == 1:
        best_idx = scored[0][0]
        matched_by = "name"
    elif len(scored) > 1:
        # doprecyzuj po city
        ranked = []
        for i, _s in scored:
            c = contacts[i]
            cs = _city_sim(req.city or "", str(c.get("city", "")))
            ranked.append((i, cs))
        ranked.sort(key=lambda x: x[1], reverse=True)
        if ranked and ranked[0][1] >= threshold_city and (len(ranked) == 1 or ranked[0][1] > ranked[1][1]):
            best_idx = ranked[0][0]
            matched_by = "name+city"

    # 3) Update albo create (dotykamy wyłącznie 5 pól)
    def _set_if_provided(rec: dict, key: str, val: Any):
        if req.overwrite:
            if val is not None:
                rec[key] = val
        else:
            if val not in (None, ""):
                rec[key] = val

    if best_idx is not None:
        rec = dict(contacts[best_idx])  # kopia
        _set_if_provided(rec, "name", req.name)
        _set_if_provided(rec, "surname", req.surname)
        _set_if_provided(rec, "phone", req.phone)
        _set_if_provided(rec, "email", req.email)
        _set_if_provided(rec, "city", req.city)
        contacts[best_idx] = rec
        action = "updated"
    else:
        # nowy rekord – szanuj schemat i wartości domyślne
        new_rec = {
            "name": req.name,
            "surname": req.surname,
            "phone": req.phone or "",
            "email": req.email or "",
            "city": req.city or "",
            "role": "sędzia",
            "isReferee": True,
            "isTeam": False,
        }
        contacts.append(new_rec)
        best_idx = len(contacts) - 1
        matched_by = "none"
        action = "created"

    # 4) Zapis z powrotem do json_files (bez zmiany enabled)
    stmt = pg_insert(json_files).values(
        key="kontakty",
        content=contacts,
        enabled=enabled,
    ).on_conflict_do_update(
        index_elements=[json_files.c.key],
        set_={"content": contacts, "enabled": enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_contact_judge: {e!r}")

    return UpsertContactJudgeResponse(
        success=True,
        action=action,
        matched_index=best_idx,
        matched_by=matched_by,
    )

# ---------------------------- APP VERSIONS CRUD ----------------------------

@router.get("/versions", response_model=ListVersionsResponse, summary="Pobierz listę wersji")
async def list_versions():
    rows = await database.fetch_all(
        select(app_versions).order_by(app_versions.c.created_at.desc())
    )
    # backward compatibility – brak kolumny to_show → False
    versions = []
    for r in rows:
        data = dict(r)
        data.setdefault("to_show", False)
        versions.append(VersionItem(**data))
    return ListVersionsResponse(versions=versions)


@router.post("/versions", response_model=dict, summary="Dodaj nową wersję")
async def create_version(req: CreateVersionRequest):
    import re
    if not re.fullmatch(r"\d+\.\d+\.\d+", req.version):
        raise HTTPException(status_code=400, detail="Wersja musi być w formacie X.Y.Z (np. 1.23.14)")

    exists = await database.fetch_one(
        select(app_versions.c.id).where(app_versions.c.version == req.version)
    )
    if exists:
        raise HTTPException(status_code=409, detail="Taka wersja już istnieje")

    await database.execute(
        insert(app_versions).values(
            version=req.version,
            name=req.name,
            description=req.description or "",
            to_show=req.to_show if req.to_show is not None else False,
        )
    )
    return {"success": True}


@router.put("/versions/{version_id}", response_model=dict, summary="Zaktualizuj wersję")
async def update_version(version_id: int, req: UpdateVersionRequest):
    import re
    values: Dict[str, Any] = {}

    if req.version is not None:
        if not re.fullmatch(r"\d+\.\d+\.\d+", req.version):
            raise HTTPException(status_code=400, detail="Wersja musi być w formacie X.Y.Z")
        exists = await database.fetch_one(
            select(app_versions.c.id).where(
                (app_versions.c.version == req.version)
                & (app_versions.c.id != version_id)
            )
        )
        if exists:
            raise HTTPException(status_code=409, detail="Ta wersja już istnieje")
        values["version"] = req.version

    if req.name is not None:
        values["name"] = req.name
    if req.description is not None:
        values["description"] = req.description
    if req.to_show is not None:
        values["to_show"] = req.to_show

    if not values:
        return {"success": True}

    result = await database.execute(
        update(app_versions).where(app_versions.c.id == version_id).values(**values)
    )
    if not result:
        raise HTTPException(404, "Wersja nie znaleziona")
    return {"success": True}


@router.delete("/versions/{version_id}", response_model=dict, summary="Usuń wersję")
async def delete_version(version_id: int):
    result = await database.execute(
        delete(app_versions).where(app_versions.c.id == version_id)
    )
    if not result:
        raise HTTPException(404, "Wersja nie znaleziona")
    return {"success": True}

# ZPRP MASTERS
@router.get(
    "/zprp/masters",
    response_model=ListZprpMastersResponse,
    summary="Pobierz listę ZPRP Masters (ID sędziów)"
)
async def get_zprp_masters():
    rows = await database.fetch_all(select(zprp_masters))
    return ListZprpMastersResponse(masters=[r["judge_id"] for r in rows])


@router.put(
    "/zprp/masters",
    response_model=dict,
    summary="Zapisz pełną listę ZPRP Masters (nadpisuje całość)"
)
async def upsert_zprp_masters(req: UpdateZprpMastersRequest):
    # wyczyść tabelę i wstaw nową listę
    await database.execute(zprp_masters.delete())
    for jid in req.masters:
        await database.execute(
            pg_insert(zprp_masters)
            .values(judge_id=jid)
            .on_conflict_do_nothing()
        )
    return {"success": True}


@router.post(
    "/zprp/masters/{judge_id}",
    response_model=dict,
    summary="Dodaj pojedyncze ID do ZPRP Masters"
)
async def add_zprp_master(judge_id: str):
    await database.execute(
        pg_insert(zprp_masters)
        .values(judge_id=judge_id)
        .on_conflict_do_nothing()
    )
    return {"success": True}


@router.delete(
    "/zprp/masters/{judge_id}",
    response_model=dict,
    summary="Usuń pojedyncze ID z ZPRP Masters"
)
async def remove_zprp_master(judge_id: str):
    result = await database.execute(
        zprp_masters.delete().where(zprp_masters.c.judge_id == judge_id)
    )
    if not result:
        raise HTTPException(status_code=404, detail="Nie znaleziono")
    return {"success": True}

# Pliki źródłowe
@router.get(
    "/json_files",
    response_model=ListJsonFilesResponse,
    summary="Lista wszystkich plików JSON"
)
async def list_json_files():
    rows = await database.fetch_all(select(json_files))
    files = []
    for r in rows:
        files.append(JsonFileItem(
        key=r["key"],
        content=r["content"],
        enabled=r["enabled"],
        updated_at=r["updated_at"],
        ))
    return ListJsonFilesResponse(files=files)

@router.get(
    "/json_files/{key}",
    response_model=GetJsonFileResponse,
    summary="Pobierz konkretny plik JSON"
)
async def get_json_file(key: str):
    row = await database.fetch_one(select(json_files).where(json_files.c.key==key))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku")
    # parsujemy string z bazy z powrotem na dowolny obiekt
    raw = row["content"]
    if isinstance(raw, (dict, list)):
        # już zdeserializowany JSON
        parsed = raw
    else:
        # jeszcze string → zrób JSON-parse
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise HTTPException(
            status_code=500,
            detail=f"Niepoprawny JSON w bazie: {e}"
            )

    return GetJsonFileResponse(
        file=JsonFileItem(
            key=row["key"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

@router.put(
    "/json_files/{key}",
    response_model=GetJsonFileResponse,
    summary="Utwórz lub nadpisz plik JSON"
)
async def upsert_json_file(key: str, req: UpsertJsonFileRequest):
    if req.key != key:
        raise HTTPException(400, "Key mismatch")

    stmt = pg_insert(json_files).values(
        key=key,
        content=req.content,
        enabled=req.enabled
    ).on_conflict_do_update(
        index_elements=[json_files.c.key],
        set_={"content": req.content, "enabled": req.enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_json_file: {e!r}")

    # Pobierz bezpośrednio po zapisaniu
    row = await database.fetch_one(select(json_files).where(json_files.c.key == key))
    raw = row["content"]
    # RAW może być dict albo string (w zależności od dialektu)
    if isinstance(raw, (dict, list)):
        parsed = raw
    else:
        parsed = json.loads(raw)

    return GetJsonFileResponse(
        file=JsonFileItem(
            key=row["key"],
            content=parsed,     # tu już dict/list albo str
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

@router.get(
    "/okreg_rates",
    response_model=ListOkregRatesResponse,
    summary="Lista plików stawek okręgowych (per-województwo)"
)
async def list_okreg_rates():
    rows = await database.fetch_all(select(okreg_rates))
    files = [
        OkregRateItem(
            province=r["province"],
            content=r["content"] if isinstance(r["content"], (dict, list)) else json.loads(r["content"]),
            enabled=r["enabled"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListOkregRatesResponse(files=files)

@router.get(
    "/okreg_rates/{province}",
    response_model=GetOkregRateResponse,
    summary="Pobierz stawki okręgowe dla danego województwa"
)
async def get_okreg_rate(province: str):
    province = province.upper()
    row = await database.fetch_one(select(okreg_rates).where(okreg_rates.c.province == province))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku dla tego województwa")
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    return GetOkregRateResponse(
        file=OkregRateItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

@router.put(
    "/okreg_rates/{province}",
    response_model=GetOkregRateResponse,
    summary="Utwórz lub zaktualizuj stawki okręgowe dla województwa"
)
async def upsert_okreg_rate(province: str, req: UpsertOkregRateRequest):
    if req.province.upper() != province.upper():
        raise HTTPException(400, "Province mismatch")

    province = province.upper()

    stmt = pg_insert(okreg_rates).values(
        province=province,
        content=req.content,
        enabled=req.enabled,
    ).on_conflict_do_update(
        index_elements=[okreg_rates.c.province],
        set_={"content": req.content, "enabled": req.enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_okreg_rate: {e!r}")

    row = await database.fetch_one(select(okreg_rates).where(okreg_rates.c.province == province))
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)

    return GetOkregRateResponse(
        file=OkregRateItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )

# === Okręgowe tabele odległości (identyczne zachowanie jak okreg_rates) ===

@router.get(
    "/okreg_distances",
    response_model=ListOkregDistancesResponse,
    summary="Lista plików 'tabel odległości' (per-województwo)"
)
async def list_okreg_distances():
    rows = await database.fetch_all(select(okreg_distances))
    files = [
        OkregDistanceItem(
            province=r["province"],
            content=r["content"] if isinstance(r["content"], (dict, list)) else json.loads(r["content"]),
            enabled=r["enabled"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListOkregDistancesResponse(files=files)


@router.get(
    "/okreg_distances/{province}",
    response_model=GetOkregDistanceResponse,
    summary="Pobierz tabelę odległości dla danego województwa"
)
async def get_okreg_distance(province: str):
    province = province.upper()
    row = await database.fetch_one(select(okreg_distances).where(okreg_distances.c.province == province))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku dla tego województwa")
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    return GetOkregDistanceResponse(
        file=OkregDistanceItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )


@router.put(
    "/okreg_distances/{province}",
    response_model=GetOkregDistanceResponse,
    summary="Utwórz lub zaktualizuj tabelę odległości dla województwa"
)
async def upsert_okreg_distance(province: str, req: UpsertOkregDistanceRequest):
    if req.province.upper() != province.upper():
        raise HTTPException(400, "Province mismatch")

    province = province.upper()

    stmt = pg_insert(okreg_distances).values(
        province=province,
        content=req.content,
        enabled=req.enabled,
    ).on_conflict_do_update(
        index_elements=[okreg_distances.c.province],
        set_={"content": req.content, "enabled": req.enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_okreg_distance: {e!r}")

    row = await database.fetch_one(select(okreg_distances).where(okreg_distances.c.province == province))
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)

    return GetOkregDistanceResponse(
        file=OkregDistanceItem(
            province=row["province"],
            content=parsed,
            enabled=row["enabled"],
            updated_at=row["updated_at"],
        )
    )


@router.post("/halls/reports", response_model=dict, summary="Zgłoś nową halę")
async def post_hall_report(req: CreateHallReportRequest):
    # 0) jeśli ta hala była kiedyś odrzucona – zablokuj przyjęcie zgłoszenia
    norm_key = _hall_norm_key(req.Hala_nazwa, req.Hala_miasto, req.Hala_ulica, req.Hala_numer)
    exists = await database.fetch_one(
        select(rejected_halls.c.id).where(rejected_halls.c.norm_key == norm_key)
    )
    if exists:
        # 409 – konflikt; ta hala jest na czarnej liście
        raise HTTPException(
            status_code=409,
            detail="Ta hala została wcześniej odrzucona i nie przyjmujemy ponownych zgłoszeń."
        )
    stmt = hall_reports.insert().values(
        Hala_nazwa=req.Hala_nazwa,
        Hala_miasto=req.Hala_miasto,
        Hala_ulica=req.Hala_ulica,
        Hala_numer=req.Hala_numer,
        Druzyny=req.Druzyny,
        created_at=datetime.utcnow(),
        is_processed=False,
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        # Złapmy pełny stack i treść błędu
        import traceback; traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"SQL ERROR insert hall_report: {e!r}"
        )
    return {"success": True}

@router.get(
    "/halls/reports",
    response_model=ListHallReportsResponse,
    summary="Pobierz listę zgłoszonych hal"
)
async def list_hall_reports():
    rows = await database.fetch_all(
        select(hall_reports).order_by(hall_reports.c.created_at.desc())
    )
    return ListHallReportsResponse(
        reports=[HallReportItem(**dict(r)) for r in rows]
    )

@router.delete(
    "/halls/reports/{report_id}",
    response_model=dict,
    summary="Usuń zgłoszenie hali (i dodaj ją do listy odrzuconych)"
)
async def delete_hall_report(report_id: int):
    # 1) pobierz zgłoszenie
    row = await database.fetch_one(select(hall_reports).where(hall_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, "Zgłoszenie nie znalezione")

    # 2) upsert do rejected_halls
    norm_key = _hall_norm_key(row["Hala_nazwa"], row["Hala_miasto"], row["Hala_ulica"], row["Hala_numer"])
    try:
        # unikalność po norm_key – jeśli już jest, po prostu przejdź dalej
        await database.execute(
            pg_insert(rejected_halls).values(
                Hala_nazwa=row["Hala_nazwa"],
                Hala_miasto=row["Hala_miasto"],
                Hala_ulica=row["Hala_ulica"],
                Hala_numer=row["Hala_numer"],
                norm_key=norm_key,
            ).on_conflict_do_nothing(index_elements=[rejected_halls.c.norm_key])
        )
    except Exception as e:
        # nie blokuj samego kasowania, ale zgłoś sensowny błąd gdyby coś było ewidentnie nie tak
        raise HTTPException(500, detail=f"SQL ERROR insert rejected_halls: {e!r}")

    # 3) usuń zgłoszenie
    result = await database.execute(hall_reports.delete().where(hall_reports.c.id == report_id))
    if not result:
        raise HTTPException(404, "Zgłoszenie nie znalezione")
    return {"success": True}

@router.get(
    "/halls/rejected",
    summary="Lista hal odrzuconych",
    response_model=List[dict]  # albo własny model w schemas, jeśli wolisz
)
async def list_rejected_halls():
    rows = await database.fetch_all(select(rejected_halls).order_by(rejected_halls.c.created_at.desc()))
    return [dict(r) for r in rows]

# === Helpers do fuzzy porównań ===

def _strip_diacritics(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))

def _normalize_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def _norm_text(s: str) -> str:
    s1 = _strip_diacritics(s).lower()
    s2 = _normalize_spaces(s1)
    return "".join(ch for ch in s2 if ch.isalnum() or ch.isspace())

def _hall_norm_key(name: str, city: str, street: str, number: str) -> str:
    # scalone, znormalizowane pola – jeden string do szybkiego porównania/unikatu
    return "|".join([
        _norm_text(name or ""),
        _norm_text(city or ""),
        _norm_text(street or ""),
        _norm_text(number or "")
    ])


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()

def _full_name(name: str, surname: str) -> str:
    return _norm_text(f"{name} {surname}")

def _city_sim(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return _similarity(_norm_text(a), _norm_text(b))

@router.post(
    "/contacts/judges/upsert",
    response_model=UpsertContactJudgeResponse,
    summary="Upsert sędziego w pliku 'kontakty' (edycja tylko name/surname/phone/email/city; domyślne role/isReferee/isTeam przy tworzeniu)"
)
async def upsert_contact_judge(req: UpsertContactJudgeRequest):
    """
    Zasady:
    - Dopasowanie fuzzy po (name+surname) z tolerancją drobnych literówek,
      bez wrażliwości na diakrytyki i wielkość liter. threshold_name = 0.92.
    - Jeśli kandydatów >1, doprecyzuj po city (threshold_city = 0.90).
    - Jeśli brak jednoznacznego dopasowania → twórz nowy rekord (z domyślnymi: role='sędzia', isReferee=true, isTeam=false).
    - Przy UPDATE zmieniamy TYLKO: name, surname, phone, email, city.
      Pozostałe pola (role, isReferee, isTeam, cokolwiek innego) zostają nietknięte.
    """
    # 1) Pobierz aktualny plik
    row = await database.fetch_one(select(json_files).where(json_files.c.key == "kontakty"))
    if not row:
        contacts: List[dict] = []
        enabled = True
    else:
        raw = row["content"]
        contacts = raw if isinstance(raw, list) else json.loads(raw)
        if not isinstance(contacts, list):
            raise HTTPException(500, "Plik 'kontakty' nie jest listą JSON")
        enabled = row["enabled"]

    # 2) Fuzzy match po (name+surname)
    target = _full_name(req.name, req.surname)
    threshold_name = 0.92
    threshold_city = 0.90

    scored: List[tuple[int, float]] = []
    for i, c in enumerate(contacts):
        cand_full = _full_name(str(c.get("name", "")), str(c.get("surname", "")))
        score = _similarity(target, cand_full)
        if score >= threshold_name:
            scored.append((i, score))

    best_idx = None
    matched_by = None
    if len(scored) == 1:
        best_idx = scored[0][0]
        matched_by = "name"
    elif len(scored) > 1:
        # doprecyzuj po city
        ranked = []
        for i, _s in scored:
            c = contacts[i]
            cs = _city_sim(req.city or "", str(c.get("city", "")))
            ranked.append((i, cs))
        ranked.sort(key=lambda x: x[1], reverse=True)
        if ranked and ranked[0][1] >= threshold_city and (len(ranked) == 1 or ranked[0][1] > ranked[1][1]):
            best_idx = ranked[0][0]
            matched_by = "name+city"

    # 3) Update albo create (dotykamy wyłącznie 5 pól)
    def _set_if_provided(rec: dict, key: str, val: Any):
        if req.overwrite:
            if val is not None:
                rec[key] = val
        else:
            if val not in (None, ""):
                rec[key] = val

    if best_idx is not None:
        rec = dict(contacts[best_idx])  # kopia
        _set_if_provided(rec, "name", req.name)
        _set_if_provided(rec, "surname", req.surname)
        _set_if_provided(rec, "phone", req.phone)
        _set_if_provided(rec, "email", req.email)
        _set_if_provided(rec, "city", req.city)
        contacts[best_idx] = rec
        action = "updated"
    else:
        # nowy rekord – szanuj schemat i wartości domyślne
        new_rec = {
            "name": req.name,
            "surname": req.surname,
            "phone": req.phone or "",
            "email": req.email or "",
            "city": req.city or "",
            "role": "sędzia",
            "isReferee": True,
            "isTeam": False,
        }
        contacts.append(new_rec)
        best_idx = len(contacts) - 1
        matched_by = "none"
        action = "created"

    # 4) Zapis z powrotem do json_files (bez zmiany enabled)
    stmt = pg_insert(json_files).values(
        key="kontakty",
        content=contacts,
        enabled=enabled,
    ).on_conflict_do_update(
        index_elements=[json_files.c.key],
        set_={"content": contacts, "enabled": enabled}
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_contact_judge: {e!r}")

    return UpsertContactJudgeResponse(
        success=True,
        action=action,
        matched_index=best_idx,
        matched_by=matched_by,
    )

# ---------------------------- APP VERSIONS CRUD ----------------------------

@router.get("/versions", response_model=ListVersionsResponse, summary="Pobierz listę wersji")
async def list_versions():
    rows = await database.fetch_all(
        select(app_versions).order_by(app_versions.c.created_at.desc())
    )
    return ListVersionsResponse(
        versions=[VersionItem(**dict(r)) for r in rows]
    )

@router.post("/versions", response_model=dict, summary="Dodaj nową wersję")
async def create_version(req: CreateVersionRequest):
    # Prosta walidacja formatu X.Y.Z (opcjonalnie rozszerz)
    import re
    if not re.fullmatch(r"\d+\.\d+\.\d+", req.version):
        raise HTTPException(status_code=400, detail="Wersja musi być w formacie X.Y.Z (np. 1.23.14)")

    # Unikalność 'version' dba DB, ale zróbmy też wstępny check
    exists = await database.fetch_one(
        select(app_versions.c.id).where(app_versions.c.version == req.version)
    )
    if exists:
        raise HTTPException(status_code=409, detail="Taka wersja już istnieje")

    await database.execute(
        insert(app_versions).values(
            version=req.version,
            name=req.name,
            description=req.description or "",
        )
    )
    return {"success": True}

@router.put("/versions/{version_id}", response_model=dict, summary="Zaktualizuj wersję")
async def update_version(version_id: int, req: UpdateVersionRequest):
    # jeśli ktoś zmienia numer wersji – sprawdź unikalność & format
    values: Dict[str, Any] = {}
    if req.version is not None:
        import re
        if not re.fullmatch(r"\d+\.\d+\.\d+", req.version):
            raise HTTPException(status_code=400, detail="Wersja musi być w formacie X.Y.Z")
        # kolizja?
        exists = await database.fetch_one(
            select(app_versions.c.id).where(
                (app_versions.c.version == req.version) &
                (app_versions.c.id != version_id)
            )
        )
        if exists:
            raise HTTPException(status_code=409, detail="Ta wersja już istnieje")
        values["version"] = req.version

    if req.name is not None:
        values["name"] = req.name
    if req.description is not None:
        values["description"] = req.description

    if not values:
        return {"success": True}

    result = await database.execute(
        update(app_versions).where(app_versions.c.id == version_id).values(**values)
    )
    if not result:
        raise HTTPException(404, "Wersja nie znaleziona")
    return {"success": True}

@router.delete("/versions/{version_id}", response_model=dict, summary="Usuń wersję")
async def delete_version(version_id: int):
    result = await database.execute(
        delete(app_versions).where(app_versions.c.id == version_id)
    )
    if not result:
        raise HTTPException(404, "Wersja nie znaleziona")
    return {"success": True}