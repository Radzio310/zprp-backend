# main.py

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from cryptography.hazmat.primitives import serialization
import logging

from app.deps import get_rsa_keys
from app.auth import router as auth_router
from app.proxy import router as proxy_router
from app.edit_judge import router as edit_router
from app.edit_photo import router as edit_photo_router
from app.offtime import router as offtime_router
from app.delegate import router as delegate_router
from app.results import router as results_router
from app.calendar import router as calendar_router
from app.silesia import router as silesia_router, router_off as silesia_offtimes_router

from app.db import database

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
app.include_router(silesia_offtimes_router)

logger = logging.getLogger("uvicorn")

@app.on_event("startup")
async def startup():
    await database.connect()
    logger.info("✅ Connected to the database")

@app.on_event("shutdown")
async def shutdown():
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
