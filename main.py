from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address


from app.auth import router as auth_router
from app.proxy import router as proxy_router
from app.edit_judge import router as edit_router

app = FastAPI(title="BAZA - API")

# rate‑limiter (opcjonalnie)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# rejestracja routerów
app.include_router(auth_router)
app.include_router(proxy_router)
app.include_router(edit_router)

# prosty healthcheck
@app.get("/health")
async def health():
    return {"status": "ok"}

# ———————————— Custom OpenAPI (HTTP Bearer only) ————————————
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version="1.0.0",
        routes=app.routes,
    )
    # Definicja schematu bezpieczeństwa jako Bearer JWT
    schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    # Dodajemy wymóg bearerAuth do wszystkich operacji
    for path in schema["paths"].values():
        for op in path.values():
            op.setdefault("security", []).append({"bearerAuth": []})
    app.openapi_schema = schema
    return app.openapi_schema

# Podmieniamy domyślną metodę OpenAPI
app.openapi = custom_openapi
# ————————————————————————————————————————————————————————————————
