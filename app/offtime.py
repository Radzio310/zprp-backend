# app/offtime.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from urllib.parse import urlencode
from bs4 import BeautifulSoup
from pydantic import BaseModel

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
    user    = req.username
    pwd     = req.password
    judge   = req.judge_id
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
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"}

        for idx, act in enumerate(actions):
            result = {"index": idx, "type": act.type}
            try:
                # a) GET formularza przez fetch_with_correct_encoding
                qs = urlencode({
                    "NrSedzia": judge,
                    "user": user,
                    "akcja": "Nowy"   if act.type=="create"
                             else "Edycja" if act.type=="update"
                             else "Usun",
                    "IdOffT": act.IdOffT or ""
                })
                form_res, form_html = await fetch_with_correct_encoding(
                    client,
                    f"/sedzia_offtimeF.php?{qs}",
                    method="GET",
                    cookies=cookies,
                )

                # b) parsuj w ISO‑8859‑2
                soup = BeautifulSoup(form_html, "html.parser")
                form = soup.find("form", {"name": "OffTimeForm"})
                if not form:
                    raise RuntimeError(
                        "Nie znaleziono formularza OffTimeForm; HTML fragment: "
                        + form_html[:200]
                    )

                # c) wypakuj wszystkie pola
                form_fields = {}
                for inp in form.find_all(["input","textarea","select"]):
                    n = inp.get("name")
                    if not n:
                        continue
                    if inp.name == "select":
                        opt = inp.find("option", selected=True)
                        v = opt.get("value","") if opt else ""
                    elif inp.name == "textarea":
                        v = inp.text
                    else:
                        v = inp.get("value","")
                    form_fields[n] = v

                # d) nadpisz
                form_fields["DataOd"] = act.DataOd
                form_fields["DataDo"] = act.DataDo
                form_fields["Info"]   = act.Info
                form_fields["akcja"]  = "Zapisz"

                # e) wyślij POST
                body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
                resp = await client.request(
                    "POST",
                    "/sedzia_offtimeF.php",
                    content=body.encode("ascii"),
                    headers=headers,
                    cookies=cookies,
                )
                text = resp.content.decode("iso-8859-2", errors="replace")

                # f) weryfikuj
                ok = resp.status_code == 200 and "Zapisano" in text
                result["success"] = ok
                result["status_code"] = resp.status_code
                if not ok:
                    result["error"] = (
                        "Spodziewano się 'Zapisano' w odpowiedzi; HTML fragment: "
                        + text[:200]
                    )
            except Exception as e:
                result["success"] = False
                result["error"] = str(e)

            results.append(result)

    return {
        "success": all(r["success"] for r in results),
        "results": results
    }
