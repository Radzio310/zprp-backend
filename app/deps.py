# app/deps.py

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Settings(BaseSettings):
    # Wczytujemy zmienne środowiskowe z pliku .env
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Twoje istniejące ustawienia
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    ZPRP_BASE_URL: str

    # NOWOŚĆ: PEM prywatnego klucza RSA; nazwa dokładnie taka jak w .env / Railway
    RSA_PRIVATE_KEY: str

def get_settings() -> Settings:
    """
    Dependency FastAPI do wstrzykiwania ustawień.
    """
    return Settings()

def get_rsa_keys():
    """
    Ładuje RSA_PRIVATE_KEY z Settings i zwraca krotkę
      (private_key_obj, public_key_obj)
    do szyfrowania/dekrypcji.
    """
    settings = get_settings()

    # Jeśli w Railway przechowujesz multiline PEM jako one‑liner z '\n',
    # odkomentuj poniższą linię, aby odtworzyć nowe linie:
    # pem_str = settings.RSA_PRIVATE_KEY.replace("\\n", "\n")
    # w przeciwnym wypadku używaj bezpośrednio:
    pem_str = settings.RSA_PRIVATE_KEY

    private_key = serialization.load_pem_private_key(
        data=pem_str.encode("utf-8"),
        password=None,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key
