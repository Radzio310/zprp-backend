from datetime import datetime
import json
import os
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import delete, insert, select, update
import bcrypt
from app.db import database, admin_pins, admin_settings, user_reports, admin_posts, forced_logout, news_masters, calendar_masters, match_masters, json_files, okreg_rates, hall_reports
from app.schemas import AdminPostItem, CreateAdminPostRequest, CreateHallReportRequest, CreateUserReportRequest, ForcedLogoutResponse, GenerateHashRequest, GenerateHashResponse, GetJsonFileResponse, GetOkregRateResponse, HallReportItem, JsonFileItem, ListAdminPostsResponse, ListHallReportsResponse, ListJsonFilesResponse, ListMastersResponse, ListOkregRatesResponse, ListUserReportsResponse, OkregRateItem, SetForcedLogoutRequest, UpdateMastersRequest, UpsertJsonFileRequest, UpsertOkregRateRequest, UserReportItem, ValidatePinRequest, ValidatePinResponse, UpdatePinRequest, UpdateAdminsRequest, ListAdminsResponse, UpsertContactJudgeRequest, UpsertContactJudgeResponse
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
      title=req.title, content=req.content, link=req.link
    )
    await database.execute(stmt)
    return {"success": True}

@router.get("/posts", response_model=ListAdminPostsResponse, summary="Lista wpisów admina")
async def list_admin_posts():
    rows = await database.fetch_all(select(admin_posts).order_by(admin_posts.c.created_at.desc()))
    return ListAdminPostsResponse(posts=[AdminPostItem(**dict(r)) for r in rows])

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

# MODUŁ ŚLĄSKI
@router.get(
    "/slask/masters",
    response_model=ListMastersResponse,
    summary="Pobierz listy News/Calendar/Match Master"
)
async def get_slask_masters():
    news = [r["judge_id"] for r in await database.fetch_all(select(news_masters))]
    calendar = [r["judge_id"] for r in await database.fetch_all(select(calendar_masters))]
    match = [r["judge_id"] for r in await database.fetch_all(select(match_masters))]
    return ListMastersResponse(news=news, calendar=calendar, match=match)

@router.put(
    "/slask/masters",
    response_model=dict,
    summary="Zapisz wszystkie trzy listy naraz"
)
async def upsert_slask_masters(req: UpdateMastersRequest):
    # Wyczyść i zapisz każdą tabelę
    for table, arr in [
        (news_masters, req.news),
        (calendar_masters, req.calendar),
        (match_masters, req.match),
    ]:
        # usuń stare
        await database.execute(table.delete())
        # wstaw nowe
        for jid in arr:
            await database.execute(
                pg_insert(table).values(judge_id=jid)
                .on_conflict_do_nothing()
            )
    return {"success": True}

# (opcjonalnie) pojedyncze add/remove:
@router.post("/slask/masters/{kind}/{judge_id}", summary="Dodaj do jednej listy")
async def add_master(kind: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters}[kind]
    await database.execute(
        pg_insert(table).values(judge_id=judge_id).on_conflict_do_nothing()
    )
    return {"success": True}

@router.delete("/slask/masters/{kind}/{judge_id}", summary="Usuń z jednej listy")
async def remove_master(kind: str, judge_id: str):
    table = {"news": news_masters, "calendar": calendar_masters, "match": match_masters}[kind]
    result = await database.execute(table.delete().where(table.c.judge_id == judge_id))
    if not result:
        raise HTTPException(404, "Nie znaleziono")
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

@router.post("/halls/reports", response_model=dict, summary="Zgłoś nową halę")
async def post_hall_report(req: CreateHallReportRequest):
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
    summary="Usuń zgłoszenie hali"
)
async def delete_hall_report(report_id: int):
    result = await database.execute(
        hall_reports.delete().where(hall_reports.c.id == report_id)
    )
    if not result:
        raise HTTPException(404, "Zgłoszenie nie znalezione")
    return {"success": True}

# === Helpers do fuzzy porównań ===

def _strip_diacritics(s: str) -> str:
    # NFKD + ASCII bez znaków łączących (np. ą->a)
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))

def _normalize_spaces(s: str) -> str:
    return " ".join(s.strip().split())

def _norm_text(s: str) -> str:
    s0 = s or ""
    s1 = _strip_diacritics(s0).lower()
    s2 = _normalize_spaces(s1)
    # Usuwamy „,.-” itp. i podwójne spacje (już zrobione)
    return "".join(ch for ch in s2 if ch.isalnum() or ch.isspace())

def _name_variants(first: str, last: str) -> List[str]:
    a = _norm_text(f"{first} {last}")
    b = _norm_text(f"{last} {first}")
    # czasem ludzie mają 2 nazwiska/2 imiona → normalizacja typu "ala ma-kota" już jest w _norm_text
    return list({a, b})

def _similarity(a: str, b: str) -> float:
    # SequenceMatcher z stdlib (bez zależności)
    return difflib.SequenceMatcher(None, a, b).ratio()

def _close_enough_name(target_first: str, target_last: str, candidate_fullname: str, threshold: float = 0.92) -> float:
    # Zwraca najlepszy score (0..1) między wariantami imię+nazwisko a polem w rekordzie
    c = _norm_text(candidate_fullname)
    best = 0.0
    for v in _name_variants(target_first, target_last):
        best = max(best, _similarity(v, c))
    return best

def _close_enough_city(target_city: str, candidate_city: str, threshold: float = 0.90) -> float:
    if not target_city or not candidate_city:
        return 0.0
    return _similarity(_norm_text(target_city), _norm_text(candidate_city))

@router.post(
    "/contacts/judges/upsert",
    response_model=UpsertContactJudgeResponse,
    summary="Utwórz lub zaktualizuj rekord sędziego w pliku 'kontakty' (fuzzy match po imieniu+nazwisku, ewentualnie + mieście)."
)
async def upsert_contact_judge(req: UpsertContactJudgeRequest):
    """
    Zasada:
    1) Pobieramy JSON z `json_files` o key='kontakty'.
       Oczekujemy, że to LISTA słowników (dowolny kształt).
       Każdy element musi mieć jakiś identyfikowalny 'name' lub ('first_name'+'last_name').
       Miasto: 'city' lub 'miasto'.
    2) Szukamy najlepszego dopasowania:
       - identyczny judge_id (jeśli występuje w rekordzie) → update
       - w przeciwnym razie fuzzy po imię+nazwisko (case/diakrytyki bez znaczenia, literówki tolerowane),
         jeśli kilka kandydatów → dookreślamy po mieście (fuzzy).
    3) Jeśli brak jednoznacznego dopasowania (score < 0.92 lub konflikt nazw): tworzymy nowy rekord.
    4) Aktualizacja: domyślnie wypełniamy tylko puste; jeśli overwrite_nonempty=True, nadpisujemy pola.
    """
    # 1) Wczytaj aktualny plik
    row = await database.fetch_one(select(json_files).where(json_files.c.key == "kontakty"))
    if not row:
        # Plik nie istnieje → zacznijmy od pustej listy
        contacts: List[dict] = []
        enabled = True
    else:
        raw = row["content"]
        contacts = raw if isinstance(raw, list) else json.loads(raw)
        if not isinstance(contacts, list):
            raise HTTPException(500, "Plik 'kontakty' nie jest listą JSON")
        enabled = row["enabled"]

    # 2) Szukanie po judge_id (najpewniejsze)
    best_idx = None
    matched_by = None
    if req.judge_id:
        for i, c in enumerate(contacts):
            cid = str(c.get("judge_id") or c.get("sędzia_id") or "").strip()
            if cid and cid == str(req.judge_id):
                best_idx = i
                matched_by = "judge_id"
                break

    # 3) Fuzzy match po imię+nazwisko (+ miasto, jeśli potrzeba)
    if best_idx is None:
        # Zbierz kandydatów: name / (first_name+last_name)
        target_full = f"{req.first_name} {req.last_name}"
        scored: List[tuple[int, float]] = []  # (index, score)

        for i, c in enumerate(contacts):
            # nazwisko+imię albo jedno pole "name"
            name = (
                c.get("name")
                or " ".join(x for x in [c.get("first_name"), c.get("last_name")] if x)
                or " ".join(x for x in [c.get("imie"), c.get("nazwisko")] if x)
            )
            if not name:
                continue
            score = _close_enough_name(req.first_name, req.last_name, name, threshold=0.92)
            if score >= 0.92:
                scored.append((i, score))

        if len(scored) == 1:
            best_idx = scored[0][0]
            matched_by = "name"
        elif len(scored) > 1:
            # Dookreśl po mieście (fuzzy)
            city_scores: List[tuple[int, float]] = []
            for i, _sc in scored:
                c = contacts[i]
                city = c.get("city") or c.get("miasto") or ""
                cs = _close_enough_city(req.city or "", city, threshold=0.90)
                city_scores.append((i, cs))
            # wybierz najlepszy po mieście, jeśli się wyróżnia
            city_scores.sort(key=lambda x: x[1], reverse=True)
            if city_scores and city_scores[0][1] >= 0.90:
                # upewnij się, że nie jest ex aequo z drugim
                if len(city_scores) == 1 or city_scores[0][1] > city_scores[1][1]:
                    best_idx = city_scores[0][0]
                    matched_by = "name+city"
                else:
                    # wątpliwe – nie dopasowuj na siłę
                    best_idx = None
            else:
                # brak wyraźnego rozstrzygnięcia po mieście → nie dopasowujemy
                best_idx = None

    # 4) Zdecyduj: update / create
    now_iso = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    def _maybe_set(c: dict, key: str, new: Any):
        if new is None or new == "":
            return
        if req.overwrite_nonempty or not c.get(key):
            c[key] = new

    if best_idx is not None:
        # UPDATE
        rec = dict(contacts[best_idx])  # kopia
        # Spróbuj wykryć istniejące klucze (PL/EN)
        # nazwa: preferujemy pojedyncze "name" w danych (nie wymuszamy migracji schematu)
        existing_name = rec.get("name")
        if existing_name:
            # Trzymajmy single-field "name", ale uzupełnijmy phone/email/city/judge_id
            _maybe_set(rec, "city", req.city)
            _maybe_set(rec, "miasto", req.city)  # jeśli używane PL
        else:
            # Mamy dwa pola
            _maybe_set(rec, "first_name", req.first_name)
            _maybe_set(rec, "last_name", req.last_name)
            _maybe_set(rec, "imie", req.first_name)
            _maybe_set(rec, "nazwisko", req.last_name)
            _maybe_set(rec, "city", req.city)
            _maybe_set(rec, "miasto", req.city)

        # wspólne pola
        _maybe_set(rec, "phone", req.phone)
        _maybe_set(rec, "telefon", req.phone)
        _maybe_set(rec, "email", req.email)
        _maybe_set(rec, "judge_id", req.judge_id)

        rec["updated_at"] = now_iso
        contacts[best_idx] = rec
        action = "updated"
    else:
        # CREATE – nowy rekord (unikamy duplikatów trywialnych przez fuzzy już powyżej)
        # Przyjmijmy neutralny, nieinwazyjny kształt – nie psujemy istniejącego schematu.
        # Jeżeli w Twoim pliku standardem jest "name", trzymajmy się "name".
        new_rec = {
            "name": f"{req.first_name} {req.last_name}",
            "city": req.city or "",
            "phone": req.phone or "",
            "email": req.email or "",
            "judge_id": req.judge_id or "",
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        contacts.append(new_rec)
        best_idx = len(contacts) - 1
        matched_by = "none"
        action = "created"

    # 5) Zapisz z powrotem do json_files (tylko serwer modyfikuje treść)
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
        action=action,            # "updated" albo "created"
        matched_index=best_idx,   # dla wglądu / debug
        matched_by=matched_by,    # jak dopasowano
    )
