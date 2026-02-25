# main.py

import asyncio
from datetime import datetime, timedelta, timezone
import os
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from cryptography.hazmat.primitives import serialization
import logging
from fastapi import Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64
import httpx
import re
import unicodedata
from collections import Counter, defaultdict

from app.deps import get_rsa_keys
from app.auth import router as auth_router
from app.proxy import router as proxy_router
from app.edit_judge import router as edit_router
from app.edit_photo import router as edit_photo_router
from app.offtime import router as offtime_router
from app.delegate import router as delegate_router
from app.results import router as results_router
from app.calendar import router as calendar_router
from app.silesia import router as silesia_router
from app.admin import router as admin_router
from app.login_records import router as login_records_router
from app.proel import router as proel_router
from app.server_matches import router as matches_router
from app.partner_offtimes import router as partner_offtimes_router
from app.short_result_records import router as short_result_records_router
from app.young_referees import router as young_referees_router
from app.agent_docs import router as agent_docs_router
from app.agent_chat import router as agent_chat_router
from app.upload_protocol import router as upload_protocol_router
from app.protocol_convert import router as protocol_convert_router
from app.password_change import router as password_change_router
from app.baza_web import router as baza_web_router
from app.province_judges import router as province_judges_router
from app.badges import router as badges_router
from app.baza_vips import router as baza_vips_router
from app.province_events import router as province_events_router
from app.province_travel import router as province_travel_router
from app.mentor_grades import router as mentor_grades_router
from app.signatures import router as signatures_router

from app.zprp.schedule import router as schedule_router
from app.zprp.competitions import router as competitions_router
from app.zprp.officials import router as officials_router

# -------------------------
# BEACH routers
# -------------------------
from app.beach.badges import router as beach_badges_router
from app.beach.users import router as beach_users_router
from app.beach.admins import router as beach_admins_router
from app.beach.tournaments import router as beach_tournaments_router

# NEW: push router + scheduler
from app.push.push import router as push_router
from app.push.scheduler import run_push_scheduler

from app.db import database, saved_matches, short_result_records, login_records, province_judges, json_files, push_schedules

app = FastAPI(title="BAZA - API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8081",
        "http://127.0.0.1:8081",
        "https://baza-web-two.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )

# -------------------------
# Static files (Railway Volume)
# -------------------------
RAILWAY_VOLUME_MOUNT_PATH = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")  # np. "/data"
STATIC_DIR = (
    os.path.join(RAILWAY_VOLUME_MOUNT_PATH, "static")
    if RAILWAY_VOLUME_MOUNT_PATH
    else os.path.join(os.path.dirname(__file__), "static")
)

os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


app.include_router(auth_router)
app.include_router(proxy_router)
app.include_router(edit_router)
app.include_router(edit_photo_router)
app.include_router(offtime_router)
app.include_router(delegate_router)
app.include_router(results_router)
app.include_router(calendar_router)
app.include_router(silesia_router)
app.include_router(admin_router)
app.include_router(login_records_router)
app.include_router(proel_router)
app.include_router(matches_router)
app.include_router(partner_offtimes_router)
app.include_router(short_result_records_router)
app.include_router(young_referees_router)
app.include_router(agent_docs_router)
app.include_router(agent_chat_router)
app.include_router(upload_protocol_router)
app.include_router(protocol_convert_router)
app.include_router(password_change_router)
app.include_router(baza_web_router)
app.include_router(province_judges_router)
app.include_router(badges_router)
app.include_router(baza_vips_router)
app.include_router(province_events_router)
app.include_router(province_travel_router)
app.include_router(mentor_grades_router)
app.include_router(signatures_router)

app.include_router(schedule_router, tags=["zprp"])
app.include_router(competitions_router, tags=["zprp"])
app.include_router(officials_router, tags=["zprp"])

# -------------------------
# BEACH routers
# -------------------------
app.include_router(beach_badges_router)
app.include_router(beach_users_router)
app.include_router(beach_admins_router)
app.include_router(beach_tournaments_router)

# NEW: push router
app.include_router(push_router)

logger = logging.getLogger("uvicorn")

# =========================
# Contacts refactor (clubs)
# =========================

# Advisory lock key (stała liczba) — chroni przed równoległym refaktorem w wielu instancjach
_CONTACTS_CLUB_REFACTOR_LOCK_KEY = 987654321

_last_contacts_refactor_utc_day: str | None = None  # np. "2026-01-21"


def _norm_text_key(s: str) -> str:
    """Normalizacja tekstu: trim, upper, usuń diakrytyki, spacje wielokrotne."""
    s = (s or "").strip()
    if not s:
        return ""
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")  # usuń diakrytyki
    s = s.upper()
    s = re.sub(r"\s+", " ", s).strip()
    return s


_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def _extract_emails(raw: str) -> list[str]:
    if not raw:
        return []
    found = _EMAIL_RE.findall(raw)
    out = []
    for e in found:
        ee = e.strip().lower()
        if ee and ee not in out:
            out.append(ee)
    return out


def _normalize_phone_token(tok: str) -> tuple[str, str] | None:
    """
    Normalizuje pojedynczy token telefonu.
    Zwraca (dedupe_key_digits, display_value).
    - dedupe_key_digits: tylko cyfry (np. "48123456789")
    - display_value: "+48123456789" jeśli było +, inaczej "123456789"
    """
    if not tok:
        return None

    t = tok.strip()
    if not t:
        return None

    has_plus = "+" in t
    digits = re.sub(r"\D+", "", t)  # tylko cyfry
    # minimalny sensowny telefon — możesz podnieść do 7/8 jeśli chcesz
    if len(digits) < 6:
        return None

    display = f"+{digits}" if has_plus else digits
    return (digits, display)


def _extract_phones(raw: str) -> list[str]:
    """
    Wyciąga telefony z dowolnego stringa:
    - rozcina po ; , | \n
    - dodatkowo wyciąga sekwencje cyfr z "dziwnych" zapisów
    """
    if not raw:
        return []

    chunks = re.split(r"[;\n,\|]+", raw)
    candidates: list[str] = []

    for ch in chunks:
        c = (ch or "").strip()
        if not c:
            continue

        # jeśli chunk ma dużo "śmieci", spróbuj znaleźć sekwencje które wyglądają jak tel
        # bierzemy fragmenty zawierające co najmniej 6 cyfr łącznie
        # (np. "tel: 123 456 789" albo "123-456-789")
        if re.search(r"\d", c):
            candidates.append(c)

    # normalizacja + dedupe po samych cyfrach
    seen_digits: set[str] = set()
    out: list[str] = []

    for cand in candidates:
        norm = _normalize_phone_token(cand)
        if not norm:
            continue
        digits, display = norm
        if digits in seen_digits:
            continue
        seen_digits.add(digits)
        out.append(display)

    return out


def _pick_best_field(values: list[str]) -> str:
    """
    Wybiera najlepszą wartość pola (np. city) z listy:
    - preferuj najczęściej występującą niepustą,
    - przy remisie preferuj najdłuższą.
    """
    cleaned = [v.strip() for v in values if (v or "").strip()]
    if not cleaned:
        return ""
    cnt = Counter(cleaned)
    best = sorted(cnt.items(), key=lambda x: (-x[1], -len(x[0])))[0][0]
    return best


def _merge_club_group(items: list[dict]) -> dict:
    """
    Łączy rekordy klubu w jeden:
    - name: preferuj najczęściej występującą / najdłuższą niepustą
    - city: jw.
    - phone/email: zbierz, znormalizuj, dedupe, join ";"
    - zachowaj role/isReferee/isTeam jako KLUB/False/True
    - surname: zostaw (zwykle puste), ale jeśli coś jest, wybierz "best"
    """
    names = [str(x.get("name", "") or "").strip() for x in items]
    surnames = [str(x.get("surname", "") or "").strip() for x in items]
    cities = [str(x.get("city", "") or "").strip() for x in items]
    roles = [str(x.get("role", "") or "").strip() for x in items]

    # Telefony i maile zbieramy z całych pól, bo mogą być sklejone ";"
    phones_all: list[str] = []
    emails_all: list[str] = []
    for it in items:
        phones_all.extend(_extract_phones(str(it.get("phone", "") or "")))
        emails_all.extend(_extract_emails(str(it.get("email", "") or "")))

    # dedupe już robiliśmy w extractorach, ale tu defensywnie:
    phones_uniq = []
    seen_p = set()
    for p in phones_all:
        d = re.sub(r"\D+", "", p)
        if not d or d in seen_p:
            continue
        seen_p.add(d)
        phones_uniq.append(p)

    emails_uniq = []
    seen_e = set()
    for e in emails_all:
        ee = (e or "").strip().lower()
        if not ee or ee in seen_e:
            continue
        seen_e.add(ee)
        emails_uniq.append(ee)

    merged = {
        "name": _pick_best_field(names),
        "surname": _pick_best_field(surnames),  # zwykle ""
        "phone": ";".join(phones_uniq),
        "email": ";".join(emails_uniq),
        "city": _pick_best_field(cities),
        "role": "KLUB",        # twardo
        "isReferee": False,    # twardo
        "isTeam": True,        # twardo
    }

    # jeśli role w danych bywa "klub" lub inne — nie przenosimy, bo utrzymujemy "KLUB"
    return merged


async def refactor_club_contacts_once_per_utc_day():
    """
    Raz na dobę (UTC) scala duplikaty klubów o tej samej nazwie (po normalizacji).
    Nie dotyka rekordów sędziów (isTeam==False).
    """
    global _last_contacts_refactor_utc_day

    now_utc = datetime.now(timezone.utc)
    today_key = now_utc.strftime("%Y-%m-%d")

    if _last_contacts_refactor_utc_day == today_key:
        return  # już było dzisiaj w tej instancji

    # Postgres advisory lock (jeśli masz kilka instancji)
    got_lock = False
    try:
        got_lock = bool(
            await database.fetch_val(
                "SELECT pg_try_advisory_lock(:k)",
                {"k": _CONTACTS_CLUB_REFACTOR_LOCK_KEY},
            )
        )
    except Exception:
        logger.exception("[contacts.refactor] advisory lock check failed")
        got_lock = False

    if not got_lock:
        # ktoś inny już robi / zrobił — nie ryzykuj równoległej modyfikacji
        return

    try:
        row = await database.fetch_one(select(json_files).where(json_files.c.key == "kontakty"))
        if not row:
            _last_contacts_refactor_utc_day = today_key
            return

        enabled = bool(row["enabled"])
        raw = row["content"]

        # content może być listą (JSON) albo stringiem
        contacts = raw if isinstance(raw, list) else None
        if contacts is None:
            try:
                import json as _json
                contacts = _json.loads(raw) if isinstance(raw, str) else []
            except Exception:
                logger.warning("[contacts.refactor] contacts content is not valid JSON list")
                _last_contacts_refactor_utc_day = today_key
                return

        if not isinstance(contacts, list):
            logger.warning("[contacts.refactor] contacts content is not a list")
            _last_contacts_refactor_utc_day = today_key
            return

        # Rozdziel: sędziowie bez zmian vs kluby do refaktoru
        judges: list[dict] = []
        clubs: list[dict] = []

        for c in contacts:
            if not isinstance(c, dict):
                continue
            is_team = bool(c.get("isTeam", False))
            # klub: isTeam True; sędzia: isTeam False
            if is_team:
                clubs.append(c)
            else:
                judges.append(c)

        if not clubs:
            _last_contacts_refactor_utc_day = today_key
            return

        # Grupowanie po znormalizowanej nazwie klubu
        by_name: dict[str, list[dict]] = defaultdict(list)
        singles: list[dict] = []

        for c in clubs:
            name = str(c.get("name", "") or "").strip()
            nk = _norm_text_key(name)
            if not nk:
                # brak nazwy → zostaw bez zmian (nie da się sensownie scalać)
                singles.append(c)
                continue
            by_name[nk].append(c)

        merged_clubs: list[dict] = []
        removed_count = 0
        merged_groups = 0

        for nk, group in by_name.items():
            if len(group) <= 1:
                merged_clubs.append(group[0])
                continue

            # Jest duplikat po nazwie → scalać
            merged_groups += 1
            removed_count += (len(group) - 1)
            merged_clubs.append(_merge_club_group(group))

        # Dodaj rekordy bez nazwy (singles)
        merged_clubs.extend(singles)

        # Finalny contacts: sędziowie + nowe kluby
        new_contacts = judges + merged_clubs

        # Zapisz tylko jeśli faktycznie coś się zmieniło (duplikaty)
        if merged_groups > 0:
            stmt = (
                pg_insert(json_files)
                .values(key="kontakty", content=new_contacts, enabled=enabled)
                .on_conflict_do_update(
                    index_elements=[json_files.c.key],
                    set_={"content": new_contacts, "enabled": enabled},
                )
            )
            await database.execute(stmt)

            logger.info(
                f"🧩 Contacts refactor (clubs): merged_groups={merged_groups}, removed={removed_count}, "
                f"clubs_before={len(clubs)}, clubs_after={len(merged_clubs)}, total_after={len(new_contacts)}"
            )

        _last_contacts_refactor_utc_day = today_key

    except Exception:
        logger.exception("[contacts.refactor] failed")
        # nie ustawiamy _last... żeby spróbować kolejnym razem
    finally:
        try:
            await database.execute(
                "SELECT pg_advisory_unlock(:k)",
                {"k": _CONTACTS_CLUB_REFACTOR_LOCK_KEY},
            )
        except Exception:
            # jeśli unlock się nie uda, lock i tak zwolni się po zamknięciu połączenia
            pass

_cleanup_task: asyncio.Task | None = None
_push_task: asyncio.Task | None = None

async def _cleanup_loop():
    retention_days = int(os.getenv("PROEL_RETENTION_DAYS", "7"))
    interval_sec = int(os.getenv("PROEL_CLEANUP_INTERVAL_SECONDS", str(24*60*60)))
    short_result_retention_days = int(os.getenv("SHORT_RESULT_RETENTION_DAYS", "10"))

    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
            stmt = delete(saved_matches).where(saved_matches.c.updated_at < cutoff)
            removed = await database.execute(stmt)
            logger.info(
                f"🧹 ProEl cleanup: removed {int(removed or 0)} rows older than {cutoff.isoformat()} UTC"
            )

            cutoff_sr = datetime.now(timezone.utc) - timedelta(days=short_result_retention_days)
            stmt_sr = delete(short_result_records).where(short_result_records.c.created_at < cutoff_sr)
            removed_sr = await database.execute(stmt_sr)
            logger.info(
                f"🧹 ShortResult cleanup: removed {int(removed_sr or 0)} rows older than {cutoff_sr.isoformat()} UTC"
            )
                        # 🧹 Push cleanup: usuń sent/failed starsze niż 48h (liczone po send_at_utc)
            cutoff_push = datetime.now(timezone.utc) - timedelta(hours=48)

            stmt_push = (
                delete(push_schedules)
                .where(
                    push_schedules.c.status.in_(["sent", "failed"]),
                    push_schedules.c.send_at_utc < cutoff_push,
                )
                .returning(push_schedules.c.id)
            )

            deleted_push_rows = await database.fetch_all(stmt_push)
            deleted_push = len(deleted_push_rows)

            logger.info(
                f"🧹 PushSchedules cleanup: removed {deleted_push} rows (sent/failed) older than {cutoff_push.isoformat()} UTC"
            )

            lr_rows = await database.fetch_all(
                select(
                    login_records.c.judge_id,
                    login_records.c.full_name,
                    login_records.c.province,
                )
            )

            pj_rows = await database.fetch_all(select(province_judges.c.judge_id))
            existing_ids = {r["judge_id"] for r in pj_rows}

            to_insert = []
            for r in lr_rows:
                jid = (r["judge_id"] or "").strip()
                if not jid or jid in existing_ids:
                    continue

                prov = (r["province"] or "").strip().upper()
                if not prov:
                    continue

                full_name = (r["full_name"] or "").strip()
                if not full_name:
                    continue

                to_insert.append({
                    "judge_id": jid,
                    "full_name": full_name,
                    "province": prov,
                    "badges": {},
                    "updated_at": datetime.now(timezone.utc),
                })

            inserted = 0
            if to_insert:
                stmt_ins = pg_insert(province_judges).values(to_insert).on_conflict_do_nothing(
                    index_elements=[province_judges.c.judge_id]
                )
                await database.execute(stmt_ins)
                inserted = len(to_insert)

            logger.info(f"👥 ProvinceJudges sync: inserted {inserted} missing judges from login_records")
            # 🧩 Raz na dobę: scal duplikaty klubów w 'kontakty' (sędziów nie ruszamy)
            await refactor_club_contacts_once_per_utc_day()

        except Exception:
            logger.exception("Cleanup loop error")
        await asyncio.sleep(interval_sec)

@app.on_event("startup")
async def startup():
    await database.connect()
    logger.info("✅ Connected to the database")

    global _cleanup_task, _push_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())

    # NEW: background scheduler for push queue
    _push_task = asyncio.create_task(run_push_scheduler())
    logger.info("✅ Push scheduler started")

@app.on_event("shutdown")
async def shutdown():
    global _cleanup_task, _push_task

    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass

    if _push_task:
        _push_task.cancel()
        try:
            await _push_task
        except asyncio.CancelledError:
            pass

    await database.disconnect()
    logger.info("✅ Disconnected from the database")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get(
    "/public_key",
    response_class=PlainTextResponse,
    summary="Pobierz publiczny klucz RSA używany do szyfrowania",
)
async def public_key_endpoint(
    keys=Depends(get_rsa_keys),
):
    _, public_key = keys
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")

security = HTTPBearer()

class SpeechToTextRequest(BaseModel):
    audio_base64: str
    filename: str | None = None
    language: str | None = None

@app.get(
    "/groq_key",
    summary="Pobierz GROQ_API_KEY z Railway variables (Tylko dozwolonym użytkownikom!)",
)
async def groq_key_endpoint(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Brak autoryzacji")

    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        raise HTTPException(status_code=404, detail="Brak GROQ_API_KEY w środowisku")

    return {"GROQ_API_KEY": groq_key}

@app.post(
    "/speech_to_text",
    summary="Transkrypcja nagrania audio na tekst (Whisper przez Groq)",
)
async def speech_to_text_endpoint(payload: SpeechToTextRequest):
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        raise HTTPException(status_code=500, detail="Brak GROQ_API_KEY w środowisku")

    try:
        audio_bytes = base64.b64decode(payload.audio_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Nieprawidłowe pole audio_base64 (błąd dekodowania base64)")

    url = "https://api.groq.com/openai/v1/audio/transcriptions"
    filename = payload.filename or "audio.m4a"

    headers = {"Authorization": f"Bearer {groq_key}"}
    data = {"model": "whisper-large-v3-turbo", "response_format": "json"}
    if payload.language:
        data["language"] = payload.language

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                url,
                headers=headers,
                data=data,
                files={"file": (filename, audio_bytes, "audio/m4a")},
            )

        if resp.status_code >= 400:
            logger.error("Groq STT error %s: %s", resp.status_code, resp.text[:500])
            raise HTTPException(status_code=502, detail="Błąd podczas przetwarzania mowy (Groq STT)")

        result = resp.json()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Groq STT request failed")
        raise HTTPException(status_code=502, detail="Nie udało się połączyć z usługą STT")

    text = (result.get("text") or "").strip()
    return {"text": text}

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version="1.0.0",
        routes=app.routes,
    )
    schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in schema["paths"].values():
        for op in path.values():
            op.setdefault("security", []).append({"bearerAuth": []})
    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = custom_openapi
