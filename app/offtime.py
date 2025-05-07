# app/offtime.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from urllib.parse import urlencode
from bs4 import BeautifulSoup

from app.utils import fetch_with_correct_encoding
from app.schemas import OffTimeAction
from app.deps import get_settings

router = APIRouter()

class PlainBatchOffTimeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    actions: List[OffTimeAction]

@router.post("/judge/offtimes/batch")
async def batch_offtimes(
    req: PlainBatchOffTimeRequest,
    settings = Depends(get_settings),
):
    user = req.username
    pwd  = req.password
    judge = req.judge_id
    actions = req.actions

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        # 1) logowanie
        resp_login, _ = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={"login": user, "haslo": pwd, "from": "/index.php?"},
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        cookies = dict(resp_login.cookies)

        results = []
        for idx, act in enumerate(actions):
            try:
                # a) GET formularza (Nowy / Edycja / Usun)
                params = {
                  "NrSedzia": judge,
                  "user": user,
                  "akcja": (
                      "Nowy" if act.type=="create"
                      else "Edycja" if act.type=="update"
                      else "Usun"
                  ),
                  "IdOffT": act.IdOffT or ""
                }
                _, html = await fetch_with_correct_encoding(
                    client,
                    "/sedzia_offtimeF.php?" + urlencode(params),
                    method="GET",
                    cookies=cookies,
                )
                soup = BeautifulSoup(html, "html.parser")
                form = soup.find("form", {"name": "OffTimeForm"})
                if not form:
                    raise RuntimeError("Nie znaleziono formularza OffTimeForm")

                # b) serializacja wszystkich pól <input>, <select>, <textarea>
                form_fields = {}
                for inp in form.find_all(["input","textarea","select"]):
                    n = inp.get("name")
                    if not n:
                        continue
                    if inp.name == "select":
                        v = inp.find("option", selected=True).get("value","")
                    elif inp.name == "textarea":
                        v = inp.text
                    else:
                        v = inp.get("value","")
                    form_fields[n] = v

                # c) nadpisanie DataOd, DataDo, Info i wymuszenie zapisu
                form_fields["DataOd"] = act.DataOd
                form_fields["DataDo"] = act.DataDo
                form_fields["Info"]   = act.Info
                form_fields["akcja"]  = "Zapisz"

                # d) POST back
                body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"
                }
                resp = await client.request(
                    "POST",
                    "/sedzia_offtimeF.php",
                    content=body.encode("ascii"),
                    headers=headers,
                    cookies=cookies,
                )
                text = resp.content.decode("iso-8859-2", errors="replace")

                # e) sprawdzenie, czy pojawił się komunikat "Zapisano"
                ok = (resp.status_code == 200) and ("Zapisano" in text)
                results.append({
                    "index": idx,
                    "type": act.type,
                    "success": ok,
                })
            except Exception as e:
                results.append({
                    "index": idx,
                    "type": act.type,
                    "success": False,
                    "error": str(e),
                })

    return {
        "success": all(r["success"] for r in results),
        "results": results
    }
