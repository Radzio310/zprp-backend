# upload_protocol.py

import os
from typing import Optional

import requests
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi import status

router = APIRouter(prefix="/zprp", tags=["zprp"])

# === KONFIGURACJA ===
# Te wartości najlepiej trzymać w zmiennych środowiskowych.
# TODO: Uzupełnij poprawne adresy URL logowania i dodawania załącznika.
ZPRP_LOGIN_URL = os.getenv("ZPRP_LOGIN_URL", "https://PRZYKLAD.PL/logowanie.php")
ZPRP_ATTACHMENT_URL = os.getenv(
    "ZPRP_ATTACHMENT_URL",
    "https://PRZYKLAD.PL/zawody_dodaj_zalacznik.php",
)

# Warto dodać prosty timeout, żeby nie wieszać aplikacji w nieskończoność
DEFAULT_TIMEOUT = 20


class ZPRPLoginError(Exception):
    """Rzucane gdy logowanie do systemu ZPRP się nie powiedzie."""


def login_to_zprp(username: str, password: str) -> requests.Session:
    """
    Loguje do systemu ZPRP i zwraca uwierzytelnioną sesję.

    Zakłada standardowy formularz logowania typu:
        <form action="..." method="post">
            <input name="login" ...>
            <input name="haslo" ...>
        </form>

    TODO: Dostosuj nazwy pól jeśli w rzeczywistości są inne.
    """
    if not ZPRP_LOGIN_URL:
        raise RuntimeError("Brak skonfigurowanego ZPRP_LOGIN_URL")

    session = requests.Session()

    payload = {
        "login": username,  # TODO: dostosuj nazwy pól, jeśli są inne
        "haslo": password,
    }

    try:
        resp = session.post(
            ZPRP_LOGIN_URL,
            data=payload,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ZPRPLoginError(f"Błąd połączenia z ZPRP: {exc}") from exc

    # TODO: Dostosuj sposób weryfikacji poprawnego logowania.
    # Poniżej przykładowa kontrola - najlepiej sprawdzić po fragmencie treści,
    # który występuje tylko po udanym logowaniu albo po braku tekstu błędu.
    if resp.status_code != 200:
        raise ZPRPLoginError(
            f"Nieudane logowanie do ZPRP (status {resp.status_code})"
        )

    # Przykład: jeśli na stronie błędu pojawia się fraza "Błędny login lub hasło"
    if "Błędny login lub hasło" in resp.text:
        raise ZPRPLoginError("Błędny login lub hasło do ZPRP")

    return session


def send_protocol_attachment(
    session: requests.Session,
    match_id: int,
    username: str,
    upload_file: UploadFile,
) -> None:
    """
    Wysyła załącznik (PDF/JPG) do formularza 'zawody_dodaj_zalacznik.php'.

    Odwzorowuje dokładnie formularz:

        <form action="zawody_dodaj_zalacznik.php" method="post"
              enctype="multipart/form-data">
          <input type="hidden" name="IdZawody" value="...">
          <input type="hidden" name="user" value="...">
          <input type="file" name="zalacznik" accept="image/jpeg,application/pdf">
          <input type="submit" name="przycisk" value="ZAPISZ">
        </form>
    """
    if not ZPRP_ATTACHMENT_URL:
        raise RuntimeError("Brak skonfigurowanego ZPRP_ATTACHMENT_URL")

    # Sprawdzamy typ MIME (nie jest to 100% zabezpieczenie, ale ogranicza pomyłki)
    allowed_mime_types = {"application/pdf", "image/jpeg"}
    content_type: Optional[str] = upload_file.content_type

    if content_type not in allowed_mime_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nieobsługiwany typ pliku: {content_type}. "
                   f"Dozwolone: PDF lub JPG.",
        )

    try:
        file_bytes = upload_file.file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Nie udało się odczytać pliku: {exc}",
        )

    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Przesłany plik jest pusty.",
        )

    data = {
        "IdZawody": str(match_id),
        "user": username,
        "przycisk": "ZAPISZ",
    }

    files = {
        "zalacznik": (
            upload_file.filename or "zalacznik",
            file_bytes,
            content_type or "application/octet-stream",
        )
    }

    try:
        resp = session.post(
            ZPRP_ATTACHMENT_URL,
            data=data,
            files=files,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Błąd połączenia z serwerem ZPRP podczas wysyłki: {exc}",
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Serwer ZPRP zwrócił status {resp.status_code} przy dodawaniu załącznika.",
        )

    # TODO: Dostosuj warunek sukcesu do realnej odpowiedzi serwera.
    # Przykład: szukamy konkretnego tekstu potwierdzającego zapis.
    if "Załącznik zapisany" not in resp.text and "Załącznik dodany" not in resp.text:
        # W celach debugowania można logować resp.text, ale do klienta lepiej
        # nie zwracać całego HTML.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Nie udało się potwierdzić, że załącznik został zapisany w systemie ZPRP.",
        )


@router.post(
    "/upload_protocol",
    summary="Wyślij protokół meczu jako załącznik (PDF/JPG) do systemu ZPRP.",
)
async def upload_protocol_endpoint(
    login: str = Form(..., description="Login do systemu ZPRP"),
    password: str = Form(..., description="Hasło do systemu ZPRP"),
    match_id: int = Form(..., description="IdZawody z systemu ZPRP"),
    attachment: UploadFile = File(..., description="Plik PDF/JPG z protokołem"),
):
    """
    Endpoint wywoływany z aplikacji mobilnej.

    1. Loguje do systemu ZPRP używając podanego loginu i hasła.
    2. W tej samej sesji wysyła formularz `zawody_dodaj_zalacznik.php` z:
       - IdZawody = `match_id`
       - user = `login`
       - zalacznik = przesłany plik
       - przycisk = "ZAPISZ"

    Zwraca prosty JSON z informacją o powodzeniu operacji.
    """
    # 1. Logowanie do ZPRP
    try:
        session = login_to_zprp(login, password)
    except ZPRPLoginError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    # 2. Wysyłka załącznika
    send_protocol_attachment(
        session=session,
        match_id=match_id,
        username=login,
        upload_file=attachment,
    )

    return {
        "status": "ok",
        "message": "Załącznik (protokół) został wysłany do systemu ZPRP.",
    }
