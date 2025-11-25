# main.py

import asyncio
from datetime import datetime, timedelta, timezone
import os
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import delete
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

from app.db import database, saved_matches, short_result_records

app = FastAPI(title="BAZA - API")

# opcjonalny rate‑limiter
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

# ensure the static/ folder exists before mounting
os.makedirs(os.path.join(os.path.dirname(__file__), "static"), exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# rejestracja Twoich routerów
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

logger = logging.getLogger("uvicorn")

_cleanup_task: asyncio.Task | None = None

async def _cleanup_loop():
    """Kasuje mecze z ProEl starsze niż PROEL_RETENTION_DAYS (domyślnie 7) co 24h."""
    retention_days = int(os.getenv("PROEL_RETENTION_DAYS", "7"))
    interval_sec = int(os.getenv("PROEL_CLEANUP_INTERVAL_SECONDS", str(24*60*60)))

    # ⬇⬇⬇ DODANE: retencja short result (domyślnie 10 dni, można nadpisać env-em) ⬇⬇⬇
    short_result_retention_days = int(os.getenv("SHORT_RESULT_RETENTION_DAYS", "10"))

    while True:
        try:
            # ProEl
            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
            stmt = delete(saved_matches).where(saved_matches.c.updated_at < cutoff)
            removed = await database.execute(stmt)
            logger.info(
                f"🧹 ProEl cleanup: removed {int(removed or 0)} rows older than {cutoff.isoformat()} UTC"
            )

            # ⬇⬇⬇ DODANE: short_result_records ⬇⬇⬇
            cutoff_sr = datetime.now(timezone.utc) - timedelta(days=short_result_retention_days)
            stmt_sr = delete(short_result_records).where(short_result_records.c.created_at < cutoff_sr)
            removed_sr = await database.execute(stmt_sr)
            logger.info(
                f"🧹 ShortResult cleanup: removed {int(removed_sr or 0)} rows older than {cutoff_sr.isoformat()} UTC"
            )

        except Exception as e:
            logger.exception("Cleanup loop error")
        await asyncio.sleep(interval_sec)


@app.on_event("startup")
async def startup():
    await database.connect()
    logger.info("✅ Connected to the database")
    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())

@app.on_event("shutdown")
async def shutdown():
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
    await database.disconnect()
    logger.info("✅ Disconnected from the database")


# prosty healthcheck
@app.get("/health")
async def health():
    return {"status": "ok"}

# —————————— Nowy endpoint: pobranie publicznego klucza RSA ——————————
@app.get(
    "/public_key",
    response_class=PlainTextResponse,
    summary="Pobierz publiczny klucz RSA używany do szyfrowania",
)
async def public_key_endpoint(
    keys=Depends(get_rsa_keys),  # get_rsa_keys zwraca (private_key, public_key)
):
    _, public_key = keys
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # zwracamy czysty PEM jako tekst
    return pem_bytes.decode("utf-8")

# —————————— Nowy endpoint: pobranie GROQ_API_KEY z Railway variables ——————————
security = HTTPBearer()

class SpeechToTextRequest(BaseModel):
    audio_base64: str
    filename: str | None = None  # opcjonalnie, jakbyś chciał kiedyś podawać
    language: str | None = None  # np. "pl"

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
        raise HTTPException(
            status_code=500,
            detail="Brak GROQ_API_KEY w środowisku",
        )

    # dekodowanie base64 z payloadu z appki mobilnej
    try:
        audio_bytes = base64.b64decode(payload.audio_base64)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Nieprawidłowe pole audio_base64 (błąd dekodowania base64)",
        )

    url = "https://api.groq.com/openai/v1/audio/transcriptions"
    filename = payload.filename or "audio.m4a"

    headers = {
        "Authorization": f"Bearer {groq_key}",
    }
    data = {
        "model": "whisper-large-v3-turbo",
        "response_format": "json",
    }
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
            logger.error(
                "Groq STT error %s: %s",
                resp.status_code,
                resp.text[:500],
            )
            raise HTTPException(
                status_code=502,
                detail="Błąd podczas przetwarzania mowy (Groq STT)",
            )

        result = resp.json()
    except HTTPException:
        # przepuszczamy nasze własne HTTPException
        raise
    except Exception:
        logger.exception("Groq STT request failed")
        raise HTTPException(
            status_code=502,
            detail="Nie udało się połączyć z usługą STT",
        )

    text = (result.get("text") or "").strip()
    return {"text": text}

# —————————— Custom OpenAPI (HTTP Bearer only) ——————————
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version="1.0.0",
        routes=app.routes,
    )
    # Definicja Bearer JWT
    schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    # Dodajemy wymaganie bearerAuth do wszystkich operacji
    for path in schema["paths"].values():
        for op in path.values():
            op.setdefault("security", []).append({"bearerAuth": []})
    app.openapi_schema = schema
    return app.openapi_schema

# podmieniamy metodę generującą OpenAPI
app.openapi = custom_openapi
