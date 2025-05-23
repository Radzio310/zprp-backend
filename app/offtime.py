from typing import Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from httpx import AsyncClient
from urllib.parse import urlencode
from bs4 import BeautifulSoup
import base64
import logging

from app.utils import fetch_with_correct_encoding
from app.deps import get_settings, get_rsa_keys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)
router = APIRouter(tags=["OffTime"])

# ----------------- SCHEMAS -----------------

class CreateOffTimeRequest(BaseModel):
    username: str  # Base64-RSA
    password: str  # Base64-RSA
    judge_id: str  # Base64-RSA
    DataOd: str   # format DD.MM.YYYY
    DataDo: str
    Info: str

class UpdateOffTimeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    IdOffT: str
    DataOd: str
    DataDo: str
    Info: str

class DeleteOffTimeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    IdOffT: str

# ----------------- HELPERS -----------------

def _decrypt_field(enc_b64: str, private_key) -> str:
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(
            cipher,
            padding.PKCS1v15()
        )
        return plain.decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Błąd deszyfrowania: {e}")

async def _login_and_client(user: str, pwd: str, settings) -> AsyncClient:
    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    )
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user, "haslo": pwd, "from": "/index.php?"},
    )
    if "/index.php" not in resp_login.url.path:
        await client.aclose()
        logger.error("Logowanie nie powiodło się dla user %s", user)
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    client.cookies.update(resp_login.cookies)
    return client

async def _submit_offtime(
    client: AsyncClient,
    judge_id: str,
    user: str,
    action_str: str,   # "Nowy" | "Edycja" | "Usun"
    overrides: Dict[str, str],
) -> bool:
    try:
        # 1) Otwórz popup przez POST
        initial_data = {
            "NrSedzia": judge_id,
            "user": user,
            "akcja": action_str,
            "IdOffT": overrides.get("IdOffT", "")
        }
        _, html = await fetch_with_correct_encoding(
            client,
            "/sedzia_offtimeF.php",
            method="POST",
            data=initial_data,
        )

        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form", {"name": "OffTimeForm"})
        if not form:
            raise RuntimeError("Nie znaleziono formularza OffTimeForm; HTML fragment=" + html[:500])

        # 2) Serializacja wszystkich pól formularza
        form_fields: Dict[str, str] = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            if inp.name == "select":
                opt = inp.find("option", selected=True)
                form_fields[name] = opt.get("value", "") if opt else ""
            elif inp.name == "textarea":
                form_fields[name] = inp.text or ""
            else:
                form_fields[name] = inp.get("value", "") or ""

        # 3) Nadpisanie pól
        for key, val in overrides.items():
            form_fields[key] = val
        # 4) Wymuszenie odpowiedniego potwierdzenia
        form_fields["akcja2"] = "tak" if action_str == "Usun" else "zapisz"

        # 5) POST zatwierdzający zmiany
        body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"}
        resp = await client.request(
            "POST",
            "/sedzia_offtimeF.php",
            content=body.encode("ascii"),
            headers=headers
        )
        text = resp.content.decode("iso-8859-2", errors="replace")
        if resp.status_code != 200:
            raise RuntimeError(f"Błąd HTTP {resp.status_code}: {text[:200]}")
        if action_str != "Usun" and "Zapisano" not in text:
            raise RuntimeError(f"Nie znaleziono potwierdzenia w odpowiedzi: {text[:200]}")
        return True
    except Exception as e:
        logger.error("_submit_offtime error: %s", e, exc_info=True)
        raise

# ----------------- ENDPOINTS -----------------

@router.post("/judge/offtimes/create", summary="Dodaj nową niedyspozycyjność")
async def create_offtime(
    req: CreateOffTimeRequest,
    settings = Depends(get_settings),
    keys = Depends(get_rsa_keys),  # (private_key, public_key)
):
    private_key, _ = keys
    # odszyfrowanie danych
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)
    judge_plain = _decrypt_field(req.judge_id, private_key)
    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            await _submit_offtime(
                client,
                judge_plain,
                user_plain,
                action_str="Nowy",
                overrides={
                    "dataOd": req.DataOd,
                    "dataDo": req.DataDo,
                    "info": req.Info,
                    "IdOffT": ""
                }
            )
        finally:
            await client.aclose()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_offtime error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się dodać niedyspozycyjności: {e}")

@router.post("/judge/offtimes/update", summary="Edytuj istniejącą niedyspozycyjność")
async def update_offtime(
    req: UpdateOffTimeRequest,
    settings = Depends(get_settings),
    keys = Depends(get_rsa_keys),
):
    private_key, _ = keys
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)
    judge_plain = _decrypt_field(req.judge_id, private_key)
    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            await _submit_offtime(
                client,
                judge_plain,
                user_plain,
                action_str="Edycja",
                overrides={
                    "IdOffT": req.IdOffT,
                    "dataOd": req.DataOd,
                    "dataDo": req.DataDo,
                    "info": req.Info
                }
            )
        finally:
            await client.aclose()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_offtime error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się edytować niedyspozycyjności: {e}")

@router.post("/judge/offtimes/delete", summary="Usuń niedyspozycyjność")
async def delete_offtime(
    req: DeleteOffTimeRequest,
    settings = Depends(get_settings),
    keys = Depends(get_rsa_keys),
):
    private_key, _ = keys
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)
    judge_plain = _decrypt_field(req.judge_id, private_key)
    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            await _submit_offtime(
                client,
                judge_plain,
                user_plain,
                action_str="Usun",
                overrides={"IdOffT": req.IdOffT}
            )
        finally:
            await client.aclose()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_offtime error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się usunąć niedyspozycyjności: {e}")
