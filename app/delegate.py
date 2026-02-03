# app/delegate.py

import os
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from app.deps import get_settings, get_rsa_keys, Settings
from app.offtime import _decrypt_field, _login_and_client
from app.utils import fetch_with_correct_encoding

router = APIRouter()

# katalog na tymczasowe pliki PDF
TMP_DIR = os.path.abspath("tmp_pdfs")
os.makedirs(TMP_DIR, exist_ok=True)

# stała nazwa pliku wewnątrz TMP_DIR
_TEMP_FILE = "delegate.pdf"
_TEMP_PATH = os.path.join(TMP_DIR, _TEMP_FILE)


class DelegateNoteRequest(BaseModel):
    username: str  # Base64-RSA zaszyfrowany login
    password: str  # Base64-RSA zaszyfrowane hasło
    judge_id: str  # Base64-RSA zaszyfrowane judge_id
    delegate_url: str  # względna ścieżka do PDF, np. "./statystyki_sedzia_oc_PDF.php?…"


class DelegateHtmlRequest(BaseModel):
    username: str  # Base64-RSA zaszyfrowany login
    password: str  # Base64-RSA zaszyfrowane hasło
    judge_id: str  # Base64-RSA zaszyfrowane judge_id
    evaluation_url: str  # względna ścieżka do HTML, np. "./ocena2_sedzia.php?..."


def _normalize_zprp_path(raw: str) -> str:
    """
    Akceptuje:
      - "./something.php?x=1"
      - "/something.php?x=1"
      - "https://baza.zprp.pl/something.php?x=1"
    Zwraca zawsze ścieżkę zaczynającą się od "/".
    """
    if not raw:
        raise HTTPException(400, "Brak evaluation_url")

    s = raw.strip()

    # Jeśli ktoś poda pełny URL, wyciągnij sam path+query
    if s.startswith("http://") or s.startswith("https://"):
        u = urlparse(s)
        path = u.path or "/"
        if u.query:
            path = f"{path}?{u.query}"
        s = path

    # "./x" => "/x"
    if s.startswith("./"):
        s = "/" + s[2:]
    elif not s.startswith("/"):
        s = "/" + s

    # Minimalna ochrona przed jakimiś dziwnymi próbami
    if ".." in s:
        raise HTTPException(400, "Niepoprawny evaluation_url (..)")
    return s


@router.post(
    "/judge/offtimes/delegateNote",
    summary="Pobierz ocenę sędziów jako PDF i wygeneruj link (z szyfrowaniem)",
)
async def delegate_note(
    req: DelegateNoteRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) odszyfruj login, hasło i judge_id
    try:
        user = _decrypt_field(req.username, private_key)
        pwd = _decrypt_field(req.password, private_key)
        judge = _decrypt_field(req.judge_id, private_key)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Niepoprawny payload: {e}")

    # 2) logowanie
    client = await _login_and_client(user, pwd, settings)
    try:
        # 3) pobierz PDF z ZPRP
        path = "/" + req.delegate_url.lstrip("./")
        resp = await client.get(path)
        if resp.status_code != 200:
            ct = resp.headers.get("content-type", "")
            raise HTTPException(
                502, f"ZPRP zwrócił {resp.status_code}, content-type={ct}"
            )
        data = await resp.aread()
    finally:
        await client.aclose()

    # 4) zapisz (nadpisując poprzedni) do TMP_DIR/delegate.pdf
    with open(_TEMP_PATH, "wb") as f:
        f.write(data)

    # 5) zwróć link do pobrania
    download_url = request.url_for("download_delegate_pdf")
    return {"download_url": str(download_url)}


@router.get(
    "/temp/delegate.pdf",
    name="download_delegate_pdf",
    summary="(tymczasowe) Pobierz PDF „Ocena Sędziów”",
)
async def download_delegate_pdf():
    if not os.path.exists(_TEMP_PATH):
        raise HTTPException(404, "Plik nie istnieje lub wygasł")
    return FileResponse(
        path=_TEMP_PATH,
        media_type="application/pdf",
        filename="OCENA SĘDZIÓW.pdf",  # sugerowana nazwa przy pobieraniu
    )


@router.post(
    "/judge/offtimes/delegateHtml",
    summary="Pobierz HTML oceny sędziów (proxy przez backend, wymaga sesji/cookie na ZPRP)",
)
async def delegate_html(
    req: DelegateHtmlRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Backend:
      - odszyfrowuje creds
      - loguje się do ZPRP
      - pobiera HTML z evaluation_url (np. ocena2_sedzia.php?...)
      - zwraca CZYSTY HTML do aplikacji (text/html; charset=utf-8)
    """
    private_key, _ = keys

    # 1) odszyfruj login, hasło i judge_id
    try:
        user = _decrypt_field(req.username, private_key)
        pwd = _decrypt_field(req.password, private_key)
        _judge = _decrypt_field(req.judge_id, private_key)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Niepoprawny payload: {e}")

    # 2) normalizacja ścieżki
    path = _normalize_zprp_path(req.evaluation_url)

    # 3) logowanie i pobranie HTML
    client = await _login_and_client(user, pwd, settings)
    try:
        resp = await client.get(path)
        if resp.status_code != 200:
            ct = resp.headers.get("content-type", "")
            # często przy braku sesji jest 302/HTML login — to też tu wpadnie
            raise HTTPException(
                502, f"ZPRP zwrócił {resp.status_code}, content-type={ct}"
            )

        # użyj helpera, żeby poprawnie ogarnąć iso-8859-2/charsety ZPRP
        html_text = await fetch_with_correct_encoding(resp)

    finally:
        await client.aclose()

    if not html_text or len(html_text.strip()) < 40:
        raise HTTPException(502, "ZPRP zwrócił pusty HTML")

    # 4) zwróć HTML do apki
    return Response(
        content=html_text,
        media_type="text/html; charset=utf-8",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )
