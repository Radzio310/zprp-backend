# app/auth.py

import datetime
import jwt
import re
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import httpx

from app.deps import get_settings, Settings
from app.utils import fetch_with_correct_encoding

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # w sekundach


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    data: LoginRequest,
    settings: Settings = Depends(get_settings),
):
    # 1) Wyślij POST bez follow_redirects, aby wykryć 302
    async with httpx.AsyncClient(
        base_url=settings.ZPRP_BASE_URL, follow_redirects=False
    ) as client:
        resp = await client.post(
            "/login.php",
            data={"login": data.username, "haslo": data.password, "from": "/index.php?"},
        )

    # 2) Jeżeli serwer zwrócił redirect do /index.php → sukces
    if resp.status_code == 302 and "/index.php" in resp.headers.get("location", ""):
        cookies = resp.cookies.get_dict()
    else:
        # 3) W przeciwnym razie pobierz body i zidentyfikuj komunikaty o błędzie
        html = resp.text
        if "Nieznany" in html or "tkownik" in html:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawny użytkownik")
        if "ponownie" in html:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niepoprawne hasło")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Logowanie nie powiodło się")

    # 4) Dla poprawnego logowania pobierz stronę docelową, by wyciągnąć judge_id
    async with httpx.AsyncClient(
        base_url=settings.ZPRP_BASE_URL, cookies=cookies
    ) as client2:
        resp2, html2 = await fetch_with_correct_encoding(
            client2,
            resp.headers["location"],
            method="GET",
        )

    match = re.search(r"NrSedzia=(\d+)", html2)
    judge_id = match.group(1) if match else ""

    # 5) Wygeneruj JWT z ciasteczkami i judge_id
    expire = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": data.username,
        "exp": expire,
        "cookies": cookies,
        "judge_id": judge_id,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    return {
        "access_token": token,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


async def get_current_cookies(
    token: str = Depends(oauth2_scheme),
    settings: Settings = Depends(get_settings),
) -> dict:
    """
    Dependency do pobierania ciasteczek z zakodowanego tokena.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        cookies = payload.get("cookies")
        if not isinstance(cookies, dict):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Brak ciasteczek w tokenie")
        return cookies
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token wygasł")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Nieprawidłowy token")
