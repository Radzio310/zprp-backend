# app/judge_documents.py
#
# Dokumenty sędziego z baza.zprp.pl (zakładka „Dokumenty").
#
# PO CO TO ISTNIEJE
# Gdy sędzia ma choć jeden niezaakceptowany dokument, ZPRP przestaje wpuszczać
# go na zakładkę statystyk - każde wejście ląduje na liście dokumentów. Dla
# aplikacji wyglądało to jak strona bez sezonów i bez meczów, więc pobieranie
# kończyło się pustą listą z komunikatem o sukcesie. Sędzia musi najpierw
# pobrać plik, a potem nacisnąć „Potwierdź odczyt".
#
# CO ROBI BACKEND, A CO APLIKACJA
# Listę dokumentów i oba potwierdzenia (`pobranie`, `akceptacja`) robi sama
# aplikacja - ma własną sesję na ZPRP, tak jak przy meczach i niedyspozycjach.
# Backend jest potrzebny WYŁĄCZNIE do samego pliku: PDF leży za sesją, więc
# systemowy menedżer pobierania telefonu nie ma jak go wziąć. Robimy to tak
# samo jak przy ocenie delegata i protokole meczu - serwer pobiera plik i
# oddaje zwykły link, który telefon zapisuje sam.
#
# Nazwa pliku na dysku pochodzi z listy w aplikacji (nazwa dokumentu w ZPRP),
# a nie z numeru: „2.pdf" w folderze pobranych nikomu nic nie mówi.

from __future__ import annotations

import os
import re
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.deps import get_settings, get_rsa_keys, Settings
from app.offtime import _decrypt_field, _login_and_client

router = APIRouter()

TMP_DIR = os.path.abspath("tmp_pdfs")
os.makedirs(TMP_DIR, exist_ok=True)

#: Po tylu sekundach plik z katalogu tymczasowego idzie do kosza przy najbliższym
#: pobraniu. Link jest jednorazowy i ma żyć tyle, ile trwa pobieranie na telefon.
_TTL_S = 30 * 60


class DocumentDownloadRequest(BaseModel):
    username: str  # Base64-RSA
    password: str  # Base64-RSA
    judge_id: str  # Base64-RSA
    doc_id: int  # numer dokumentu w ZPRP (plik: sedzia_dokumenty/<id>.pdf)
    filename: Optional[str] = None  # nazwa proponowana przy zapisie na telefonie


def _safe_filename(raw: Optional[str], doc_id: int) -> str:
    """Nazwa pliku, którą można bezpiecznie oddać systemowi pobierania.

    Zostawiamy polskie znaki (Content-Disposition radzi sobie z UTF-8), ale
    wycinamy wszystko, co mogłoby wyjść poza nazwę: separatory ścieżek i znaki
    zabronione w nazwach plików na Windowsie oraz w Androidzie.
    """
    name = (raw or "").strip()
    if not name:
        return f"dokument_zprp_{doc_id}.pdf"
    name = re.sub(r"[\\/:*?\"<>|\r\n\t]+", "_", name)
    name = name.strip(". ")
    if not name:
        return f"dokument_zprp_{doc_id}.pdf"
    if not name.lower().endswith(".pdf"):
        name = f"{name}.pdf"
    # 120 znaków to sufit, w którym mieszczą się nazwy ZPRP razem z rozszerzeniem.
    return name[:120]


def _sweep_old_files() -> None:
    """Sprzątanie starych plików. Nigdy nie przerywa pobierania."""
    try:
        now = time.time()
        for entry in os.listdir(TMP_DIR):
            if not entry.startswith("doc_"):
                continue
            path = os.path.join(TMP_DIR, entry)
            try:
                if now - os.path.getmtime(path) > _TTL_S:
                    os.remove(path)
            except OSError:
                continue
    except OSError:
        return


@router.post(
    "/judge/documents/download",
    summary="Pobierz dokument sędziego z ZPRP i oddaj link do zapisania na telefonie",
)
async def document_download(
    req: DocumentDownloadRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    try:
        user = _decrypt_field(req.username, private_key)
        pwd = _decrypt_field(req.password, private_key)
        _judge = _decrypt_field(req.judge_id, private_key)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 - komunikat idzie do aplikacji
        raise HTTPException(400, f"Niepoprawny payload: {e}")

    if req.doc_id <= 0:
        raise HTTPException(400, "Niepoprawny numer dokumentu")

    client = await _login_and_client(user, pwd, settings)
    try:
        resp = await client.get(f"/sedzia_dokumenty/{int(req.doc_id)}.pdf")
        if resp.status_code != 200:
            raise HTTPException(
                502,
                f"ZPRP zwrócił {resp.status_code} przy dokumencie {req.doc_id}",
            )
        data = await resp.aread()
    finally:
        await client.aclose()

    # Strona logowania zamiast pliku waży kilka kilobajtów i zaczyna się od
    # „<!DOCTYPE" - bez tej kontroli sędzia zapisywałby HTML z rozszerzeniem PDF.
    if not data[:5] == b"%PDF-":
        raise HTTPException(502, "ZPRP nie oddał pliku PDF (sesja albo brak dokumentu)")

    _sweep_old_files()

    token = uuid.uuid4().hex
    path = os.path.join(TMP_DIR, f"doc_{token}.pdf")
    with open(path, "wb") as f:
        f.write(data)

    filename = _safe_filename(req.filename, req.doc_id)
    download_url = request.url_for("download_judge_document", token=token)
    return {"download_url": f"{download_url}?name={filename}", "filename": filename}


@router.get(
    "/temp/document/{token}.pdf",
    name="download_judge_document",
    summary="(tymczasowe) Pobierz dokument sędziego",
)
async def download_judge_document(token: str, name: Optional[str] = None):
    # Token pochodzi z uuid4 - wszystko poza szesnastkowym ciągiem to próba
    # sięgnięcia gdzie indziej, nie literówka.
    if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
        raise HTTPException(404, "Plik nie istnieje lub wygasł")

    path = os.path.join(TMP_DIR, f"doc_{token}.pdf")
    if not os.path.exists(path):
        raise HTTPException(404, "Plik nie istnieje lub wygasł")

    return FileResponse(
        path=path,
        media_type="application/pdf",
        filename=_safe_filename(name, 0),
    )
