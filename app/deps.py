import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# ====================================
# SETTINGS
# ====================================

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Core auth settings
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    # ZPRP application settings
    ZPRP_BASE_URL: str

    # Google OAuth2 Calendar
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    BACKEND_URL: str
    FRONTEND_DEEP_LINK: str

    # PEM prywatnego klucza RSA (multi-line stored as literal '\n')
    RSA_PRIVATE_KEY: str

# Dependency: settings singleton

def get_settings() -> Settings:
    return Settings()

# ====================================
# RSA KEYS
# ====================================

def get_rsa_keys():
    settings = get_settings()
    pem_str = settings.RSA_PRIVATE_KEY.replace('\\n', '\n')
    private_key = serialization.load_pem_private_key(
        data=pem_str.encode('utf-8'),
        password=None,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ====================================
# AUTHENTICATION DEPENDENCY
# ====================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """
    Dekoduje JWT i zwraca login użytkownika (pole 'sub').
    Jeśli token jest nieważny lub brak pola 'sub' → 401.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_login: str = payload.get("sub")
        if user_login is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user_login
