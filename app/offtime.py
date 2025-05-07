# app/offtime.py
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from httpx import AsyncClient
from urllib.parse import urlencode
from bs4 import BeautifulSoup

from app.utils import fetch_with_correct_encoding
from app.deps import get_settings

router = APIRouter(tags=["OffTime"])

# ----------------- SCHEMAS -----------------

class CreateOffTimeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
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
        raise HTTPException(401, "Logowanie nie powiodło się")
    # przepychamy cookies, żeby AsyncClient automatycznie je trzymał
    client.cookies.update(resp_login.cookies)
    return client

async def _submit_offtime(
    client: AsyncClient,
    judge_id: str,
    user: str,
    action_str: str,   # "Nowy" | "Edycja" | "Usun"
    overrides: dict,
) -> bool:
    # 1) GET popup
    qs = urlencode({
        "NrSedzia": judge_id,
        "user": user,
        "akcja": action_str,
        "IdOffT": overrides.get("IdOffT", "")
    })
    _, html = await fetch_with_correct_encoding(
        client,
        f"/sedzia_offtimeF.php?{qs}",
        method="GET"
    )

    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"name": "OffTimeForm"})
    if not form:
        raise RuntimeError("Nie znaleziono formularza OffTimeForm")

    # 2) serializacja wszystkich pól
    form_fields = {}
    for inp in form.find_all(["input","select","textarea"]):
        n = inp.get("name")
        if not n: continue
        if inp.name == "select":
            opt = inp.find("option", selected=True)
            form_fields[n] = opt.get("value","") if opt else ""
        elif inp.name == "textarea":
            form_fields[n] = inp.text
        else:
            form_fields[n] = inp.get("value","")

    # 3) nadpisanie pól
    for k, v in overrides.items():
        form_fields[k] = v
    # wymuszamy użycie przycisku Zapisz
    form_fields["akcja"] = "Zapisz"

    # 4) POST
    body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
    headers = {"Content-Type":"application/x-www-form-urlencoded; charset=ISO-8859-2"}
    resp = await client.request(
        "POST",
        "/sedzia_offtimeF.php",
        content=body.encode("ascii"),
        headers=headers
    )
    text = resp.content.decode("iso-8859-2", errors="replace")
    return (resp.status_code == 200) and ("Zapisano" in text)

# ----------------- ENDPOINTS -----------------

@router.post("/judge/offtimes/create", summary="Dodaj nową niedyspozycyjność")
async def create_offtime(
    req: CreateOffTimeRequest,
    settings = Depends(get_settings),
):
    client = await _login_and_client(req.username, req.password, settings)
    try:
        ok = await _submit_offtime(
            client,
            req.judge_id,
            req.username,
            action_str="Nowy",
            overrides={
                "DataOd": req.DataOd,
                "DataDo": req.DataDo,
                "Info": req.Info,
                "IdOffT": ""
            }
        )
    finally:
        await client.aclose()

    if not ok:
        raise HTTPException(500, "Nie udało się dodać niedyspozycyjności")
    return {"success": True}


@router.post("/judge/offtimes/update", summary="Edytuj istniejącą niedyspozycyjność")
async def update_offtime(
    req: UpdateOffTimeRequest,
    settings = Depends(get_settings),
):
    client = await _login_and_client(req.username, req.password, settings)
    try:
        ok = await _submit_offtime(
            client,
            req.judge_id,
            req.username,
            action_str="Edycja",
            overrides={
                "IdOffT": req.IdOffT,
                "DataOd": req.DataOd,
                "DataDo": req.DataDo,
                "Info": req.Info
            }
        )
    finally:
        await client.aclose()

    if not ok:
        raise HTTPException(500, "Nie udało się edytować niedyspozycyjności")
    return {"success": True}


@router.post("/judge/offtimes/delete", summary="Usuń niedyspozycyjność")
async def delete_offtime(
    req: DeleteOffTimeRequest,
    settings = Depends(get_settings),
):
    client = await _login_and_client(req.username, req.password, settings)
    try:
        ok = await _submit_offtime(
            client,
            req.judge_id,
            req.username,
            action_str="Usun",
            overrides={
                "IdOffT": req.IdOffT
                # nie musimy nadpisywać DataOd/DataDo/Info
            }
        )
    finally:
        await client.aclose()

    if not ok:
        raise HTTPException(500, "Nie udało się usunąć niedyspozycyjności")
    return {"success": True}
