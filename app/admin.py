# admin.py
from __future__ import annotations

import os
import json
import re
import unicodedata
import difflib
from datetime import datetime, date, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, insert, update, delete, and_, or_
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    admin_pins,
    admin_settings,
    user_reports,
    admin_posts,
    forced_logout,
    forced_logout_rules,
    news_masters,
    calendar_masters,
    match_masters,
    teach_masters,
    zprp_masters,
    json_files,
    okreg_rates,
    okreg_distances,
    active_provinces,
    settlement_clubs,
    hall_reports,
    rejected_halls,
    app_versions,
)

from app.schemas import (
    # PIN / admins
    ValidatePinRequest,
    ValidatePinResponse,
    UpdatePinRequest,
    GenerateHashRequest,
    GenerateHashResponse,
    UpdateAdminsRequest,
    ListAdminsResponse,
    # reports
    CreateUserReportRequest,
    ListUserReportsResponse,
    UserReportItem,
    # admin posts
    CreateAdminPostRequest,
    AdminPostItem,
    ListAdminPostsResponse,
    # forced logout
    SetForcedLogoutRequest,
    ForcedLogoutResponse,
    CreateForcedLogoutRuleRequest,
    ForcedLogoutRuleItem,
    ListForcedLogoutRulesResponse,
    # masters
    UpdateMastersRequest,
    ListMastersResponse,
    UpdateZprpMastersRequest,
    ListZprpMastersResponse,
    # json_files
    UpsertJsonFileRequest,
    GetJsonFileResponse,
    ListJsonFilesResponse,
    JsonFileItem,
    # okreg rates/distances
    OkregRateItem,
    GetOkregRateResponse,
    ListOkregRatesResponse,
    CreateOkregRateVersionRequest,
    UpdateOkregRateVersionRequest,
    ListOkregRateVersionsResponse,
    UpsertOkregRateRequest,
    OkregDistanceItem,
    GetOkregDistanceResponse,
    ListOkregDistancesResponse,
    UpsertOkregDistanceRequest,
    # active provinces
    ActiveProvinceItem,
    UpsertActiveProvinceRequest,
    GetActiveProvinceResponse,
    ListActiveProvincesResponse,
    # settlement clubs
    SettlementClubsItem,
    UpsertSettlementClubsRequest,
    GetSettlementClubsResponse,
    ListSettlementClubsResponse,
    # halls
    CreateHallReportRequest,
    HallReportItem,
    ListHallReportsResponse,
    # contacts
    UpsertContactJudgeRequest,
    UpsertContactJudgeResponse,
    # versions
    CreateVersionRequest,
    UpdateVersionRequest,
    VersionItem,
    ListVersionsResponse,
)

# ---------------------------------------------------------------------
# Router & constants
# ---------------------------------------------------------------------

router = APIRouter(prefix="/admin", tags=["Admin"])

MASTER_PIN_HASH = os.getenv("MASTER_PIN_HASH", "")

PROVINCES = [
    "DOLNOŚLĄSKIE", "KUJAWSKO-POMORSKIE", "LUBELSKIE", "LUBUSKIE", "ŁÓDZKIE",
    "MAŁOPOLSKIE", "MAZOWIECKIE", "OPOLSKIE", "PODKARPACKIE", "PODLASKIE",
    "POMORSKIE", "ŚLĄSKIE", "ŚWIĘTOKRZYSKIE", "WARMIŃSKO-MAZURSKIE",
    "WIELKOPOLSKIE", "ZACHODNIOPOMORSKIE",
]

# ---------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------

def _parse_json(raw: Any) -> Any:
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None

def _row_to_list(raw: Any) -> List[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return []

def _row_to_json(raw: Any) -> Any:
    if raw is None:
        return []
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return []

def _ensure_province(p: str) -> str:
    if not p:
        raise HTTPException(400, "Brak 'province'")
    return p.strip().upper()

def _rule_matches(filters: Optional[dict], judge_id: Optional[str], province: Optional[str], app_version: Optional[str]) -> bool:
    if not filters:
        return True
    j_ok = ("judge_ids" not in filters or not filters["judge_ids"] or (judge_id and judge_id in filters["judge_ids"]))
    p_ok = ("provinces" not in filters or not filters["provinces"] or (province and province.upper() in [s.upper() for s in filters["provinces"]]))
    v_ok = ("versions" not in filters or not filters["versions"] or (app_version and app_version in filters["versions"]))
    return j_ok and p_ok and v_ok

# ---------------------------------------------------------------------
# PIN / Admins
# ---------------------------------------------------------------------

@router.post("/validate_pin", response_model=ValidatePinResponse, summary="Walidacja PIN-u admina")
async def validate_pin(req: ValidatePinRequest):
    # 0) Master PIN ma pierwszeństwo
    if MASTER_PIN_HASH:
        if bcrypt.checkpw(req.pin.encode(), MASTER_PIN_HASH.encode()):
            return ValidatePinResponse(valid=True)

    # 1) per-judge
    row = await database.fetch_one(select(admin_pins).where(admin_pins.c.judge_id == req.judge_id))
    if not row:
        return ValidatePinResponse(valid=False)

    pin_hash = row["pin_hash"].encode()
    valid = bcrypt.checkpw(req.pin.encode(), pin_hash)
    return ValidatePinResponse(valid=valid)

@router.put("/update_pin", status_code=status.HTTP_200_OK, summary="Ustaw lub zaktualizuj PIN admina")
async def update_pin(req: UpdatePinRequest):
    new_hash = bcrypt.hashpw(req.new_pin.encode(), bcrypt.gensalt()).decode()
    stmt = (
        pg_insert(admin_pins)
        .values(judge_id=req.judge_id, pin_hash=new_hash)
        .on_conflict_do_update(index_elements=[admin_pins.c.judge_id], set_={"pin_hash": new_hash})
    )
    await database.execute(stmt)
    return {"success": True}

@router.post("/generate_pin_hash", response_model=GenerateHashResponse, summary="Wygeneruj bcrypt-owy hash dla PINu")
async def generate_pin_hash(req: GenerateHashRequest):
    hashed = bcrypt.hashpw(req.pin.encode("utf-8"), bcrypt.gensalt())
    return GenerateHashResponse(hash=hashed.decode("utf-8"))

@router.get("/admins", response_model=ListAdminsResponse, summary="Pobierz listę ID adminów")
async def get_admins():
    row = await database.fetch_one(select(admin_settings).limit(1))
    return ListAdminsResponse(allowed_admins=(row["allowed_admins"] if row else []) or [])

@router.put("/admins", response_model=Dict[str, bool], summary="Zapisz listę ID adminów")
async def update_admins(req: UpdateAdminsRequest):
    # Zapisz nową listę
    await database.execute(
        pg_insert(admin_settings)
        .values(id=1, allowed_admins=req.allowed_admins)
        .on_conflict_do_update(index_elements=[admin_settings.c.id], set_={"allowed_admins": req.allowed_admins})
    )

    # Pobierz aktualny stan po zapisie (żeby wyliczyć różnicę)
    row = await database.fetch_one(select(admin_settings).limit(1))
    old_list = set((row["allowed_admins"] if row else []) or [])

    new_admins = set(req.allowed_admins) - old_list
    default_hash = bcrypt.hashpw("0000".encode(), bcrypt.gensalt()).decode()
    for j in new_admins:
        await database.execute(
            pg_insert(admin_pins)
            .values(judge_id=j, pin_hash=default_hash)
            .on_conflict_do_nothing()
        )

    return {"success": True}

# ---------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------

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
        raise HTTPException(500, detail=f"SQL ERROR insert user_report: {repr(e)}")
    return {"success": True}

@router.get("/reports", response_model=ListUserReportsResponse, summary="Lista zgłoszeń")
async def list_reports(limit: int = 0):
    q = select(user_reports).order_by(user_reports.c.created_at.desc())
    if limit:
        q = q.limit(limit)
    rows = await database.fetch_all(q)
    return ListUserReportsResponse(reports=[UserReportItem(**dict(r)) for r in rows])

@router.put("/reports/{report_id}/read", response_model=dict, summary="Oznacz zgłoszenie jako przeczytane")
async def mark_read(report_id: int):
    result = await database.execute(update(user_reports).where(user_reports.c.id == report_id).values(is_read=True))
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}

@router.put("/reports/{report_id}/unread", response_model=dict, summary="Oznacz zgłoszenie jako nieprzeczytane")
async def mark_unread(report_id: int):
    result = await database.execute(update(user_reports).where(user_reports.c.id == report_id).values(is_read=False))
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}

@router.delete("/reports/{report_id}", response_model=dict, summary="Usuń zgłoszenie użytkownika")
async def delete_report(report_id: int):
    result = await database.execute(user_reports.delete().where(user_reports.c.id == report_id))
    if not result:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie znalezione")
    return {"success": True}

# ---------------------------------------------------------------------
# Admin posts
# ---------------------------------------------------------------------

@router.post("/posts", response_model=dict, summary="Dodaj wpis adminowy")
async def post_admin_entry(req: CreateAdminPostRequest):
    await database.execute(
        admin_posts.insert().values(
            title=req.title,
            content=req.content,
            link=req.link,
            button_text=req.button_text,
            target_filters=(req.target_filters.dict() if req.target_filters else None),
        )
    )
    return {"success": True}

@router.delete("/posts/{post_id}", response_model=dict, summary="Usuń wpis adminowy")
async def delete_admin_post(post_id: int):
    result = await database.execute(admin_posts.delete().where(admin_posts.c.id == post_id))
    if not result:
        raise HTTPException(status_code=404, detail="Wpis nie znaleziony")
    return {"success": True}

@router.get("/posts", response_model=ListAdminPostsResponse, summary="Lista wpisów admina")
async def list_admin_posts():
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    posts: List[AdminPostItem] = []
    for r in rows:
        posts.append(
            AdminPostItem(
                id=r["id"],
                title=r["title"],
                content=r["content"],
                link=r["link"],
                button_text=r["button_text"],
                target_filters=_parse_json(r["target_filters"]),
                created_at=r["created_at"],
            )
        )
    return ListAdminPostsResponse(posts=posts)

@router.get("/posts/for_user", response_model=ListAdminPostsResponse, summary="Lista wpisów admina dopasowanych do użytkownika")
async def posts_for_user(judge_id: str = "", province: str = "", app_version: str = ""):
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    out: List[AdminPostItem] = []
    for r in rows:
        filters = _parse_json(r["target_filters"])
        if _rule_matches(filters, judge_id or None, province or None, app_version or None):
            out.append(
                AdminPostItem(
                    id=r["id"],
                    title=r["title"],
                    content=r["content"],
                    link=r["link"],
                    button_text=r["button_text"],
                    target_filters=filters,
                    created_at=r["created_at"],
                )
            )
    return ListAdminPostsResponse(posts=out)

# ---------------------------------------------------------------------
# Forced logout
# ---------------------------------------------------------------------

@router.get("/forced_logout", response_model=ForcedLogoutResponse, summary="Pobierz termin wymuszonego wylogowania")
async def get_forced_logout():
    row = await database.fetch_one(select(forced_logout).limit(1))
    return ForcedLogoutResponse(logout_at=(row["logout_at"] if row else None))

@router.put("/forced_logout", response_model=dict, summary="Ustaw lub zaktualizuj termin wymuszonego wylogowania")
async def upsert_forced_logout(req: SetForcedLogoutRequest):
    stmt = (
        pg_insert(forced_logout)
        .values(id=1, logout_at=req.logout_at)
        .on_conflict_do_update(index_elements=[forced_logout.c.id], set_={"logout_at": req.logout_at})
    )
    await database.execute(stmt)
    return {"success": True}

@router.delete("/forced_logout", response_model=dict, summary="Usuń termin wymuszonego wylogowania")
async def delete_forced_logout():
    result = await database.execute(delete(forced_logout).where(forced_logout.c.id == 1))
    if not result:
        raise HTTPException(status_code=404, detail="Brak ustawionego terminu")
    return {"success": True}

@router.get("/forced_logout/rules", response_model=ListForcedLogoutRulesResponse, summary="Lista zaplanowanych reguł wymuszonego wylogowania")
async def list_forced_logout_rules():
    rows = await database.fetch_all(select(forced_logout_rules).order_by(forced_logout_rules.c.logout_at.asc()))
    rules = [
        ForcedLogoutRuleItem(
            id=r["id"],
            logout_at=r["logout_at"],
            filters=_parse_json(r["filters"]),
            created_at=r["created_at"],
        )
        for r in rows
    ]
    return ListForcedLogoutRulesResponse(rules=rules)

@router.post("/forced_logout/rules", response_model=dict, summary="Utwórz regułę wymuszonego wylogowania (z filtrami)")
async def create_forced_logout_rule(req: CreateForcedLogoutRuleRequest):
    await database.execute(
        insert(forced_logout_rules).values(
            logout_at=req.logout_at,
            filters=(req.filters.dict() if req.filters else None),
        )
    )
    return {"success": True}

@router.delete("/forced_logout/rules/{rule_id}", response_model=dict, summary="Usuń regułę wymuszonego wylogowania")
async def delete_forced_logout_rule(rule_id: int):
    result = await database.execute(delete(forced_logout_rules).where(forced_logout_rules.c.id == rule_id))
    if not result:
        raise HTTPException(status_code=404, detail="Reguła nie znaleziona")
    return {"success": True}

@router.get("/forced_logout/next", summary="Pobierz najbliższą (wg kolejności) pasującą regułę forced logout (bez filtrowania >=now)")
async def next_forced_logout(judge_id: str = "", province: str = "", app_version: str = ""):
    rows = await database.fetch_all(select(forced_logout_rules).order_by(forced_logout_rules.c.logout_at.desc()))
    for r in rows:
        filters = _parse_json(r["filters"])
        if _rule_matches(filters, judge_id or None, province or None, app_version or None):
            return {"id": r["id"], "logout_at": r["logout_at"]}

    row = await database.fetch_one(select(forced_logout).limit(1))
    if row:
        return {"id": 0, "logout_at": row["logout_at"]}
    return {"id": None, "logout_at": None}

# ---------------------------------------------------------------------
# Masters (news/calendar/match/teach)
# ---------------------------------------------------------------------

@router.get("/masters", response_model=ListMastersResponse, summary="Pobierz mapy Mastersów per województwo")
async def get_masters():
    news_rows = await database.fetch_all(select(news_masters))
    news_map = {r["province"]: _row_to_list(r["judges"]) for r in news_rows}

    cal_rows = await database.fetch_all(select(calendar_masters))
    cal_map = {r["province"]: _row_to_list(r["judges"]) for r in cal_rows}

    match_rows = await database.fetch_all(select(match_masters))
    match_map = {r["province"]: _row_to_list(r["judges"]) for r in match_rows}

    teach_rows = await database.fetch_all(select(teach_masters))
    teach_map = {r["province"]: _row_to_list(r["judges"]) for r in teach_rows}

    return ListMastersResponse(news=news_map, calendar=cal_map, match=match_map, teach=teach_map)

@router.put("/masters", response_model=dict, summary="Zapisz pełne mapy Mastersów (nadpisuje całość dla 4 kategorii)")
async def upsert_masters(req: UpdateMastersRequest):
    for table, mp in [
        (news_masters, req.news),
        (calendar_masters, req.calendar),
        (match_masters, req.match),
        (teach_masters, req.teach),
    ]:
        await database.execute(table.delete())
        for province, judges in (mp or {}).items():
            prov = _ensure_province(province)
            await database.execute(
                pg_insert(table)
                .values(province=prov, judges=judges or [])
                .on_conflict_do_update(index_elements=[table.c.province], set_={"judges": judges or []})
            )
    return {"success": True}

@router.post("/masters/{kind}/{province}/{judge_id}", response_model=dict, summary="Dodaj pojedyncze ID do listy Masters w województwie")
async def add_master(kind: str, province: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters, "teach": teach_masters}.get(kind)
    if not table:
        raise HTTPException(400, "Parametr 'kind' musi być jednym z: news|calendar|match|teach")

    prov = _ensure_province(province)
    row = await database.fetch_one(select(table).where(table.c.province == prov))
    current = _row_to_list(row["judges"]) if row else []
    if judge_id not in current:
        current.append(judge_id)

    await database.execute(
        pg_insert(table)
        .values(province=prov, judges=current)
        .on_conflict_do_update(index_elements=[table.c.province], set_={"judges": current})
    )
    return {"success": True}

@router.delete("/masters/{kind}/{province}/{judge_id}", response_model=dict, summary="Usuń pojedyncze ID z listy Masters w województwie")
async def remove_master(kind: str, province: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters, "teach": teach_masters}.get(kind)
    if not table:
        raise HTTPException(400, "Parametr 'kind' musi być jednym z: news|calendar|match|teach")

    prov = _ensure_province(province)
    row = await database.fetch_one(select(table).where(table.c.province == prov))
    if not row:
        raise HTTPException(404, "Nie znaleziono rekordu dla województwa")

    current = _row_to_list(row["judges"])
    current = [j for j in current if j != judge_id]

    result = await database.execute(update(table).where(table.c.province == prov).values(judges=current))
    if not result:
        raise HTTPException(404, "Nie zaktualizowano rekordu")
    return {"success": True}

# ---------------------------------------------------------------------
# ZPRP Masters
# ---------------------------------------------------------------------

@router.get("/zprp/masters", response_model=ListZprpMastersResponse, summary="Pobierz listę ZPRP Masters (ID sędziów)")
async def get_zprp_masters():
    rows = await database.fetch_all(select(zprp_masters))
    return ListZprpMastersResponse(masters=[r["judge_id"] for r in rows])

@router.put("/zprp/masters", response_model=dict, summary="Zapisz pełną listę ZPRP Masters (nadpisuje całość)")
async def upsert_zprp_masters(req: UpdateZprpMastersRequest):
    await database.execute(zprp_masters.delete())
    for jid in req.masters:
        await database.execute(pg_insert(zprp_masters).values(judge_id=jid).on_conflict_do_nothing())
    return {"success": True}

@router.post("/zprp/masters/{judge_id}", response_model=dict, summary="Dodaj pojedyncze ID do ZPRP Masters")
async def add_zprp_master(judge_id: str):
    await database.execute(pg_insert(zprp_masters).values(judge_id=judge_id).on_conflict_do_nothing())
    return {"success": True}

@router.delete(
    "/zprp/masters/{judge_id}",
    summary="Usuń pojedyncze ID z ZPRP Masters",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_zprp_master(judge_id: str):
    query = zprp_masters.delete().where(zprp_masters.c.judge_id == judge_id).returning(zprp_masters.c.judge_id)
    await database.fetch_one(query)
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)

# ---------------------------------------------------------------------
# json_files
# ---------------------------------------------------------------------

@router.get("/json_files", response_model=ListJsonFilesResponse, summary="Lista wszystkich plików JSON")
async def list_json_files():
    rows = await database.fetch_all(select(json_files))
    files = [
        JsonFileItem(
            key=r["key"],
            content=r["content"] if isinstance(r["content"], (dict, list)) else json.loads(r["content"]),
            enabled=r["enabled"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]
    return ListJsonFilesResponse(files=files)

@router.get("/json_files/{key}", response_model=GetJsonFileResponse, summary="Pobierz konkretny plik JSON")
async def get_json_file(key: str):
    row = await database.fetch_one(select(json_files).where(json_files.c.key == key))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku")
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    return GetJsonFileResponse(file=JsonFileItem(key=row["key"], content=parsed, enabled=row["enabled"], updated_at=row["updated_at"]))

@router.put("/json_files/{key}", response_model=GetJsonFileResponse, summary="Utwórz lub nadpisz plik JSON")
async def upsert_json_file(key: str, req: UpsertJsonFileRequest):
    if req.key != key:
        raise HTTPException(400, "Key mismatch")

    stmt = (
        pg_insert(json_files)
        .values(key=key, content=req.content, enabled=req.enabled)
        .on_conflict_do_update(index_elements=[json_files.c.key], set_={"content": req.content, "enabled": req.enabled})
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_json_file: {e!r}")

    row = await database.fetch_one(select(json_files).where(json_files.c.key == key))
    raw = row["content"]
    parsed = raw if isinstance(raw, (dict, list)) else json.loads(raw)
    return GetJsonFileResponse(file=JsonFileItem(key=row["key"], content=parsed, enabled=row["enabled"], updated_at=row["updated_at"]))

# ---------------------------------------------------------------------
# OKREG RATES (wersjonowane + backward compatible)
# ---------------------------------------------------------------------

def _warsaw_today() -> date:
    try:
        return datetime.now(timezone.utc).astimezone(ZoneInfo("Europe/Warsaw")).date()
    except Exception:
        return date.today()

def _parse_content(raw: Any) -> Any:
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return raw

def _is_effective(row: dict, today_: date) -> bool:
    if not bool(row.get("enabled")):
        return False
    vf = row.get("valid_from")
    vt = row.get("valid_to")
    if vf is not None and vf > today_:
        return False
    if vt is not None and vt < today_:
        return False
    return True

def _pick_best(rows: List[dict]) -> Optional[dict]:
    """
    Prefer:
    - większy valid_from (NULL traktuj jak date.min => legacy przegrywa z datowaną)
    - potem większy updated_at
    """
    if not rows:
        return None

    def k(r: dict):
        vf = r.get("valid_from") or date.min
        ua = r.get("updated_at") or datetime.min
        return (vf, ua)

    return sorted(rows, key=k, reverse=True)[0]

def _row_to_rate_item(r: dict) -> OkregRateItem:
    return OkregRateItem(
        id=r.get("id"),
        province=r["province"],
        content=_parse_content(r["content"]),
        enabled=bool(r["enabled"]),
        valid_from=r.get("valid_from"),
        valid_to=r.get("valid_to"),
        updated_at=r["updated_at"],
    )

# UWAGA: ten endpoint MUSI być przed /okreg_rates/{province}
@router.get("/okreg_rates/all", response_model=ListOkregRateVersionsResponse, summary="Lista WSZYSTKICH wersji stawek (admin/debug)")
async def list_okreg_rates_all(province: str = ""):
    q = select(okreg_rates)
    if province:
        q = q.where(okreg_rates.c.province == province.strip().upper())
    q = q.order_by(okreg_rates.c.province.asc(), okreg_rates.c.updated_at.desc())
    rows = [dict(r) for r in await database.fetch_all(q)]
    return ListOkregRateVersionsResponse(files=[_row_to_rate_item(r) for r in rows])

@router.get("/okreg_rates", response_model=ListOkregRatesResponse, summary="Lista stawek okręgowych (aktualnie obowiązujące per województwo)")
async def list_okreg_rates():
    today_ = _warsaw_today()
    q = select(okreg_rates).where(
        okreg_rates.c.enabled == True,
        or_(okreg_rates.c.valid_from == None, okreg_rates.c.valid_from <= today_),
        or_(okreg_rates.c.valid_to == None, okreg_rates.c.valid_to >= today_),
    )
    rows = [dict(r) for r in await database.fetch_all(q)]

    by_prov: Dict[str, List[dict]] = {}
    for r in rows:
        by_prov.setdefault(r["province"], []).append(r)

    out: List[OkregRateItem] = []
    for prov, items in by_prov.items():
        best = _pick_best(items)
        if best:
            out.append(_row_to_rate_item(best))

    out.sort(key=lambda x: x.province)
    return ListOkregRatesResponse(files=out)

@router.get("/okreg_rates/{province}/versions", response_model=ListOkregRateVersionsResponse, summary="Lista wszystkich wersji stawek dla województwa")
async def list_okreg_rate_versions(province: str):
    prov = province.strip().upper()
    q = select(okreg_rates).where(okreg_rates.c.province == prov).order_by(okreg_rates.c.updated_at.desc())
    rows = [dict(r) for r in await database.fetch_all(q)]
    return ListOkregRateVersionsResponse(files=[_row_to_rate_item(r) for r in rows])

@router.post("/okreg_rates/{province}/versions", response_model=GetOkregRateResponse, summary="Utwórz nową wersję stawek dla województwa (wersjonowanie)")
async def create_okreg_rate_version(province: str, req: CreateOkregRateVersionRequest):
    prov = province.strip().upper()
    if req.province.strip().upper() != prov:
        raise HTTPException(400, "Province mismatch")

    today_ = _warsaw_today()
    vf = req.valid_from
    vt = req.valid_to

    if vf is None and vt is not None:
        vf = today_
    if vf is not None and vt is not None and vt < vf:
        raise HTTPException(400, "valid_to nie może być wcześniejsze niż valid_from")

    ins = (
        insert(okreg_rates)
        .values(province=prov, content=req.content, enabled=req.enabled, valid_from=vf, valid_to=vt)
        .returning(okreg_rates.c.id)
    )
    new_id = await database.fetch_val(ins)

    # auto-zamykanie poprzednich „otwartych”
    if vf is not None:
        close_to = vf - timedelta(days=1)
        await database.execute(
            update(okreg_rates)
            .where(
                okreg_rates.c.province == prov,
                okreg_rates.c.id != new_id,
                okreg_rates.c.enabled == True,
                or_(okreg_rates.c.valid_to == None, okreg_rates.c.valid_to >= vf),
                or_(okreg_rates.c.valid_from == None, okreg_rates.c.valid_from <= vf),
            )
            .values(valid_to=close_to)
        )

    return await get_okreg_rate(prov)

@router.put(
    "/okreg_rates/{province}/versions/{rate_id}",
    response_model=GetOkregRateResponse,
    summary="Update konkretnej wersji stawek (explicit)",
)
async def update_okreg_rate_version(province: str, rate_id: int, req: UpdateOkregRateVersionRequest):
    prov = province.strip().upper()
    row = await database.fetch_one(select(okreg_rates).where(and_(okreg_rates.c.id == rate_id, okreg_rates.c.province == prov)))
    if not row:
        raise HTTPException(404, "Nie znaleziono wersji")

    values: Dict[str, Any] = {}
    if req.content is not None:
        values["content"] = req.content
    if req.enabled is not None:
        values["enabled"] = req.enabled
    if req.valid_from is not None:
        values["valid_from"] = req.valid_from
    if req.valid_to is not None:
        values["valid_to"] = req.valid_to

    if not values:
        return await get_okreg_rate(prov)

    final_vf = values.get("valid_from", row["valid_from"])
    final_vt = values.get("valid_to", row["valid_to"])
    if final_vf is not None and final_vt is not None and final_vt < final_vf:
        raise HTTPException(400, "valid_to nie może być wcześniejsze niż valid_from")

    await database.execute(update(okreg_rates).where(okreg_rates.c.id == rate_id).values(**values))
    return await get_okreg_rate(prov)

@router.delete("/okreg_rates/{province}/versions/{rate_id}", response_model=dict, summary="Usuń wersję stawek")
async def delete_okreg_rate_version(province: str, rate_id: int):
    prov = province.strip().upper()
    result = await database.execute(delete(okreg_rates).where(and_(okreg_rates.c.id == rate_id, okreg_rates.c.province == prov)))
    if not result:
        raise HTTPException(404, "Nie znaleziono wersji")
    return {"success": True}

@router.get("/okreg_rates/{province}", response_model=GetOkregRateResponse, summary="Pobierz aktualnie obowiązujące stawki (backward compatible)")
async def get_okreg_rate(province: str):
    today_ = _warsaw_today()
    prov = province.strip().upper()

    rows = [dict(r) for r in await database.fetch_all(select(okreg_rates).where(okreg_rates.c.province == prov))]
    effective = [r for r in rows if _is_effective(r, today_)]
    best = _pick_best(effective)

    if not best:
        raise HTTPException(404, "Nie znaleziono aktywnych stawek dla tego województwa na dzisiaj")

    return GetOkregRateResponse(file=_row_to_rate_item(best))

@router.put(
    "/okreg_rates/{province}",
    response_model=GetOkregRateResponse,
    summary="Backward compatible upsert: bez id -> legacy; z id -> update wersji; z datami bez id -> tworzy nową wersję",
)
async def upsert_okreg_rate(province: str, req: UpsertOkregRateRequest):
    prov = province.strip().upper()
    if req.province.strip().upper() != prov:
        raise HTTPException(400, "Province mismatch")

    # 1) UPDATE konkretnej wersji po ID (UWAGA: id=0 traktujemy jak brak)
    if req.id is not None and req.id > 0:
        row = await database.fetch_one(select(okreg_rates).where(and_(okreg_rates.c.id == req.id, okreg_rates.c.province == prov)))
        if not row:
            raise HTTPException(404, "Nie znaleziono wersji o takim id dla tego województwa")

        values: Dict[str, Any] = {"content": req.content, "enabled": req.enabled}
        if req.valid_from is not None:
            values["valid_from"] = req.valid_from
        if req.valid_to is not None:
            values["valid_to"] = req.valid_to

        final_vf = values.get("valid_from", row["valid_from"])
        final_vt = values.get("valid_to", row["valid_to"])
        if final_vf is not None and final_vt is not None and final_vt < final_vf:
            raise HTTPException(400, "valid_to nie może być wcześniejsze niż valid_from")

        await database.execute(update(okreg_rates).where(okreg_rates.c.id == req.id).values(**values))
        return await get_okreg_rate(prov)

    # 2) Jeśli nie ma id, ale są daty -> tworzymy NOWĄ wersję
    if req.valid_from is not None or req.valid_to is not None:
        create_req = CreateOkregRateVersionRequest(
            province=req.province,
            content=req.content,
            enabled=req.enabled,
            valid_from=req.valid_from,
            valid_to=req.valid_to,
        )
        return await create_okreg_rate_version(prov, create_req)

    # 3) Legacy upsert (stare zachowanie): valid_from/to NULL
    legacy = await database.fetch_one(
        select(okreg_rates)
        .where(
            okreg_rates.c.province == prov,
            okreg_rates.c.valid_from == None,
            okreg_rates.c.valid_to == None,
        )
        .order_by(okreg_rates.c.updated_at.desc())
        .limit(1)
    )

    if legacy:
        await database.execute(update(okreg_rates).where(okreg_rates.c.id == legacy["id"]).values(content=req.content, enabled=req.enabled))
    else:
        await database.execute(insert(okreg_rates).values(province=prov, content=req.content, enabled=req.enabled, valid_from=None, valid_to=None))

    return await get_okreg_rate(prov)

# ---------------------------------------------------------------------
# OKREG DISTANCES (niewersjonowane – jak w Twoim kodzie)
# ---------------------------------------------------------------------

@router.get("/okreg_distances", response_model=ListOkregDistancesResponse, summary="Lista plików 'tabel odległości' (per-województwo)")
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

@router.get("/okreg_distances/{province}", response_model=GetOkregDistanceResponse, summary="Pobierz tabelę odległości dla województwa")
async def get_okreg_distance(province: str):
    prov = province.upper()
    row = await database.fetch_one(select(okreg_distances).where(okreg_distances.c.province == prov))
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

@router.put("/okreg_distances/{province}", response_model=GetOkregDistanceResponse, summary="Utwórz lub zaktualizuj tabelę odległości dla województwa")
async def upsert_okreg_distance(province: str, req: UpsertOkregDistanceRequest):
    if req.province.upper() != province.upper():
        raise HTTPException(400, "Province mismatch")

    prov = province.upper()
    stmt = (
        pg_insert(okreg_distances)
        .values(province=prov, content=req.content, enabled=req.enabled)
        .on_conflict_do_update(index_elements=[okreg_distances.c.province], set_={"content": req.content, "enabled": req.enabled})
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_okreg_distance: {e!r}")

    row = await database.fetch_one(select(okreg_distances).where(okreg_distances.c.province == prov))
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

# ---------------------------------------------------------------------
# Active provinces
# ---------------------------------------------------------------------

@router.get("/okreg/active", response_model=ListActiveProvincesResponse, summary="Lista aktywnych/nieaktywnych województw")
async def list_active_provinces():
    rows = await database.fetch_all(select(active_provinces))
    files = [
        ActiveProvinceItem(province=r["province"], enabled=bool(r["enabled"]), updated_at=r["updated_at"])
        for r in rows
    ]
    return ListActiveProvincesResponse(files=files)

@router.get("/okreg/active/{province}", response_model=GetActiveProvinceResponse, summary="Status aktywności wybranego województwa")
async def get_active_province(province: str):
    prov = _ensure_province(province)
    row = await database.fetch_one(select(active_provinces).where(active_provinces.c.province == prov))
    if not row:
        raise HTTPException(404, "Brak wpisu dla tego województwa")
    return GetActiveProvinceResponse(
        file=ActiveProvinceItem(province=row["province"], enabled=bool(row["enabled"]), updated_at=row["updated_at"])
    )

@router.put("/okreg/active/{province}", response_model=GetActiveProvinceResponse, summary="Utwórz/zaktualizuj status aktywności województwa")
async def upsert_active_province(province: str, req: UpsertActiveProvinceRequest):
    prov = _ensure_province(province)
    if prov != _ensure_province(req.province):
        raise HTTPException(400, "Province mismatch")

    await database.execute(
        pg_insert(active_provinces)
        .values(province=prov, enabled=req.enabled)
        .on_conflict_do_update(index_elements=[active_provinces.c.province], set_={"enabled": req.enabled})
    )
    row = await database.fetch_one(select(active_provinces).where(active_provinces.c.province == prov))
    return GetActiveProvinceResponse(
        file=ActiveProvinceItem(province=row["province"], enabled=bool(row["enabled"]), updated_at=row["updated_at"])
    )

@router.delete("/okreg/active/{province}", response_model=dict, summary="Usuń wpis aktywności dla województwa")
async def delete_active_province(province: str):
    prov = _ensure_province(province)
    result = await database.execute(delete(active_provinces).where(active_provinces.c.province == prov))
    if not result:
        raise HTTPException(404, "Nie znaleziono")
    return {"success": True}

# ---------------------------------------------------------------------
# Settlement clubs
# ---------------------------------------------------------------------

@router.get("/okreg/clubs", response_model=ListSettlementClubsResponse, summary="Lista JSONów klubów (per województwo)")
async def list_settlement_clubs():
    rows = await database.fetch_all(select(settlement_clubs))
    files = [
        SettlementClubsItem(province=r["province"], clubs=_row_to_json(r["clubs"]), updated_at=r["updated_at"])
        for r in rows
    ]
    return ListSettlementClubsResponse(files=files)

@router.get("/okreg/clubs/{province}", response_model=GetSettlementClubsResponse, summary="Pobierz JSON klubów dla województwa")
async def get_settlement_clubs(province: str):
    prov = _ensure_province(province)
    row = await database.fetch_one(select(settlement_clubs).where(settlement_clubs.c.province == prov))
    if not row:
        raise HTTPException(404, "Nie znaleziono pliku dla tego województwa")
    return GetSettlementClubsResponse(
        file=SettlementClubsItem(province=row["province"], clubs=_row_to_json(row["clubs"]), updated_at=row["updated_at"])
    )

@router.put("/okreg/clubs/{province}", response_model=GetSettlementClubsResponse, summary="Utwórz lub zaktualizuj JSON klubów dla województwa")
async def upsert_settlement_clubs(province: str, req: UpsertSettlementClubsRequest):
    prov = _ensure_province(province)
    if prov != _ensure_province(req.province):
        raise HTTPException(400, "Province mismatch")

    stmt = (
        pg_insert(settlement_clubs)
        .values(province=prov, clubs=req.clubs)
        .on_conflict_do_update(index_elements=[settlement_clubs.c.province], set_={"clubs": req.clubs})
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_settlement_clubs: {e!r}")

    row = await database.fetch_one(select(settlement_clubs).where(settlement_clubs.c.province == prov))
    return GetSettlementClubsResponse(
        file=SettlementClubsItem(province=row["province"], clubs=_row_to_json(row["clubs"]), updated_at=row["updated_at"])
    )

@router.delete("/okreg/clubs/{province}", response_model=dict, summary="Usuń JSON klubów dla województwa")
async def delete_settlement_clubs(province: str):
    prov = _ensure_province(province)
    result = await database.execute(delete(settlement_clubs).where(settlement_clubs.c.province == prov))
    if not result:
        raise HTTPException(404, "Nie znaleziono")
    return {"success": True}

# ---------------------------------------------------------------------
# Halls
# ---------------------------------------------------------------------

def _strip_diacritics(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))

def _normalize_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def _norm_text(s: str) -> str:
    s1 = _strip_diacritics(s or "").lower()
    s2 = _normalize_spaces(s1)
    return "".join(ch for ch in s2 if ch.isalnum() or ch.isspace())

def _hall_norm_key(name: str, city: str, street: str, number: str) -> str:
    return "|".join([_norm_text(name or ""), _norm_text(city or ""), _norm_text(street or ""), _norm_text(number or "")])

@router.post("/halls/reports", response_model=dict, summary="Zgłoś nową halę")
async def post_hall_report(req: CreateHallReportRequest):
    norm_key = _hall_norm_key(req.Hala_nazwa, req.Hala_miasto, req.Hala_ulica, req.Hala_numer)
    exists = await database.fetch_one(select(rejected_halls.c.id).where(rejected_halls.c.norm_key == norm_key))
    if exists:
        raise HTTPException(status_code=409, detail="Ta hala została wcześniej odrzucona i nie przyjmujemy ponownych zgłoszeń.")

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
        raise HTTPException(status_code=500, detail=f"SQL ERROR insert hall_report: {e!r}")
    return {"success": True}

@router.get("/halls/reports", response_model=ListHallReportsResponse, summary="Pobierz listę zgłoszonych hal")
async def list_hall_reports():
    rows = await database.fetch_all(select(hall_reports).order_by(hall_reports.c.created_at.desc()))
    return ListHallReportsResponse(reports=[HallReportItem(**dict(r)) for r in rows])

@router.delete("/halls/reports/{report_id}", response_model=dict, summary="Usuń zgłoszenie hali (i dodaj ją do listy odrzuconych)")
async def delete_hall_report(report_id: int):
    row = await database.fetch_one(select(hall_reports).where(hall_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, "Zgłoszenie nie znalezione")

    norm_key = _hall_norm_key(row["Hala_nazwa"], row["Hala_miasto"], row["Hala_ulica"], row["Hala_numer"])
    try:
        await database.execute(
            pg_insert(rejected_halls)
            .values(
                Hala_nazwa=row["Hala_nazwa"],
                Hala_miasto=row["Hala_miasto"],
                Hala_ulica=row["Hala_ulica"],
                Hala_numer=row["Hala_numer"],
                norm_key=norm_key,
            )
            .on_conflict_do_nothing(index_elements=[rejected_halls.c.norm_key])
        )
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR insert rejected_halls: {e!r}")

    result = await database.execute(hall_reports.delete().where(hall_reports.c.id == report_id))
    if not result:
        raise HTTPException(404, "Zgłoszenie nie znalezione")
    return {"success": True}

@router.get("/halls/rejected", response_model=List[dict], summary="Lista hal odrzuconych")
async def list_rejected_halls():
    rows = await database.fetch_all(select(rejected_halls).order_by(rejected_halls.c.created_at.desc()))
    return [dict(r) for r in rows]

# ---------------------------------------------------------------------
# Contacts (kontakty)
# ---------------------------------------------------------------------

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
    summary="Upsert sędziego w pliku 'kontakty' (edycja tylko name/surname/phone/email/city; domyślne role/isReferee/isTeam przy tworzeniu)",
)
async def upsert_contact_judge(req: UpsertContactJudgeRequest):
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

    target = _full_name(req.name, req.surname)
    threshold_name = 0.92
    threshold_city = 0.90

    scored: List[Tuple[int, float]] = []
    for i, c in enumerate(contacts):
        cand_full = _full_name(str(c.get("name", "")), str(c.get("surname", "")))
        score = _similarity(target, cand_full)
        if score >= threshold_name:
            scored.append((i, score))

    best_idx: Optional[int] = None
    matched_by: Optional[str] = None

    if len(scored) == 1:
        best_idx = scored[0][0]
        matched_by = "name"
    elif len(scored) > 1:
        ranked: List[Tuple[int, float]] = []
        for i, _s in scored:
            c = contacts[i]
            cs = _city_sim(req.city or "", str(c.get("city", "")))
            ranked.append((i, cs))
        ranked.sort(key=lambda x: x[1], reverse=True)
        if ranked and ranked[0][1] >= threshold_city and (len(ranked) == 1 or ranked[0][1] > ranked[1][1]):
            best_idx = ranked[0][0]
            matched_by = "name+city"

    def _set_if_provided(rec: dict, key: str, val: Any):
        if req.overwrite:
            if val is not None:
                rec[key] = val
        else:
            if val not in (None, ""):
                rec[key] = val

    if best_idx is not None:
        rec = dict(contacts[best_idx])
        _set_if_provided(rec, "name", req.name)
        _set_if_provided(rec, "surname", req.surname)
        _set_if_provided(rec, "phone", req.phone)
        _set_if_provided(rec, "email", req.email)
        _set_if_provided(rec, "city", req.city)
        contacts[best_idx] = rec
        action = "updated"
    else:
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

    stmt = (
        pg_insert(json_files)
        .values(key="kontakty", content=contacts, enabled=enabled)
        .on_conflict_do_update(index_elements=[json_files.c.key], set_={"content": contacts, "enabled": enabled})
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_contact_judge: {e!r}")

    return UpsertContactJudgeResponse(success=True, action=action, matched_index=best_idx, matched_by=matched_by)

@router.post(
    "/contacts/clubs/upsert",
    response_model=UpsertContactJudgeResponse,
    summary="Upsert kontaktu KLUB w pliku 'kontakty' (update: tylko 5 pól; create: role=KLUB, isReferee=False, isTeam=True)",
)
async def upsert_contact_club(req: UpsertContactJudgeRequest):
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

    target = _full_name(req.name, req.surname)
    threshold_name = 0.92
    threshold_city = 0.90

    scored: List[Tuple[int, float]] = []
    for i, c in enumerate(contacts):
        cand_full = _full_name(str(c.get("name", "")), str(c.get("surname", "")))
        score = _similarity(target, cand_full)
        if score >= threshold_name:
            scored.append((i, score))

    best_idx: Optional[int] = None
    matched_by: Optional[str] = None

    if len(scored) == 1:
        best_idx = scored[0][0]
        matched_by = "name"
    elif len(scored) > 1:
        ranked: List[Tuple[int, float]] = []
        for i, _s in scored:
            c = contacts[i]
            cs = _city_sim(req.city or "", str(c.get("city", "")))
            ranked.append((i, cs))
        ranked.sort(key=lambda x: x[1], reverse=True)
        if ranked and ranked[0][1] >= threshold_city and (len(ranked) == 1 or ranked[0][1] > ranked[1][1]):
            best_idx = ranked[0][0]
            matched_by = "name+city"

    def _set_if_provided(rec: dict, key: str, val: Any):
        if req.overwrite:
            if val is not None:
                rec[key] = val
        else:
            if val not in (None, ""):
                rec[key] = val

    if best_idx is not None:
        rec = dict(contacts[best_idx])
        _set_if_provided(rec, "name", req.name)
        _set_if_provided(rec, "surname", req.surname)
        _set_if_provided(rec, "phone", req.phone)
        _set_if_provided(rec, "email", req.email)
        _set_if_provided(rec, "city", req.city)
        contacts[best_idx] = rec
        action = "updated"
    else:
        new_rec = {
            "name": req.name,
            "surname": req.surname,
            "phone": req.phone or "",
            "email": req.email or "",
            "city": req.city or "",
            "role": "KLUB",
            "isReferee": False,
            "isTeam": True,
        }
        contacts.append(new_rec)
        best_idx = len(contacts) - 1
        matched_by = "none"
        action = "created"

    stmt = (
        pg_insert(json_files)
        .values(key="kontakty", content=contacts, enabled=enabled)
        .on_conflict_do_update(index_elements=[json_files.c.key], set_={"content": contacts, "enabled": enabled})
    )
    try:
        await database.execute(stmt)
    except Exception as e:
        raise HTTPException(500, detail=f"SQL ERROR upsert_contact_club: {e!r}")

    return UpsertContactJudgeResponse(success=True, action=action, matched_index=best_idx, matched_by=matched_by)

# ---------------------------------------------------------------------
# App versions
# ---------------------------------------------------------------------

@router.get("/versions", response_model=ListVersionsResponse, summary="Pobierz listę wersji")
async def list_versions():
    rows = await database.fetch_all(select(app_versions).order_by(app_versions.c.created_at.desc()))
    versions: List[VersionItem] = []
    for r in rows:
        data = dict(r)
        # backward compatibility: jeśli w DB/rekordzie brak to_show, domyślnie False
        data.setdefault("to_show", False)
        versions.append(VersionItem(**data))
    return ListVersionsResponse(versions=versions)

@router.post("/versions", response_model=dict, summary="Dodaj nową wersję")
async def create_version(req: CreateVersionRequest):
    if not re.fullmatch(r"\d+\.\d+\.\d+", req.version):
        raise HTTPException(status_code=400, detail="Wersja musi być w formacie X.Y.Z (np. 1.23.14)")

    exists = await database.fetch_one(select(app_versions.c.id).where(app_versions.c.version == req.version))
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
    values: Dict[str, Any] = {}

    if req.version is not None:
        if not re.fullmatch(r"\d+\.\d+\.\d+", req.version):
            raise HTTPException(status_code=400, detail="Wersja musi być w formacie X.Y.Z")
        exists = await database.fetch_one(
            select(app_versions.c.id).where((app_versions.c.version == req.version) & (app_versions.c.id != version_id))
        )
        if exists:
            raise HTTPException(status_code=409, detail="Ta wersja już istnieje")
        values["version"] = req.version

    if req.name is not None:
        values["name"] = req.name
    if req.description is not None:
        values["description"] = req.description
    if getattr(req, "to_show", None) is not None:
        values["to_show"] = req.to_show

    if not values:
        return {"success": True}

    query = update(app_versions).where(app_versions.c.id == version_id).values(**values).returning(app_versions.c.id)
    row = await database.fetch_one(query)
    if row is None:
        raise HTTPException(status_code=404, detail="Wersja nie znaleziona")
    return {"success": True}

@router.delete("/versions/{version_id}", response_model=dict, summary="Usuń wersję")
async def delete_version(version_id: int):
    query = delete(app_versions).where(app_versions.c.id == version_id).returning(app_versions.c.id)
    row = await database.fetch_one(query)
    if row is None:
        raise HTTPException(status_code=404, detail="Wersja nie znaleziona")
    return {"success": True}
