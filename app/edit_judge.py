# app/edit_judge.py
from fastapi import APIRouter, HTTPException, Depends
from httpx import AsyncClient
from urllib.parse import urlencode
import chardet
from bs4 import BeautifulSoup

from app.schemas import EditJudgeRequest
from app.utils import fetch_with_correct_encoding
from app.deps import get_settings, Settings

router = APIRouter()

@router.post("/judge/edit")
async def edit_judge(
    data: EditJudgeRequest,
    settings: Settings = Depends(get_settings),
):
    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        # 1) Logowanie
        resp_login, html_login = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={
                "login": data.username,
                "haslo": data.password,
                "from": "/index.php?",
            },
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        cookies = dict(resp_login.cookies)

        # 2) Pobranie formularza edycji
        path = f"/index.php?a=sedzia&b=edycja&NrSedzia={data.judge_id}"
        _, html_get = await fetch_with_correct_encoding(
            client, path, method="GET", cookies=cookies
        )
        soup = BeautifulSoup(html_get, "html.parser")
        form = soup.find("form", {"name": "edycja"})
        if not form:
            raise HTTPException(500, "Nie znaleziono formularza edycji")

        # 3) Parsowanie wszystkich pól formularza (hidden, current values, itp.)
        form_fields: dict[str, str] = {}
        # inputy
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type", "text")
            if typ in ("hidden", "text", "password"):
                form_fields[name] = inp.get("value", "")
            elif typ == "radio" and inp.has_attr("checked"):
                form_fields[name] = inp.get("value", "")

        # selecty
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            opt = sel.find("option", selected=True)
            form_fields[name] = opt.get("value", "") if opt else ""

        # 4) Nadpisanie tylko tych pól, które chcesz
        overrides = {}
        if data.Imie is not None:     overrides["Imie"]     = data.Imie
        if data.Nazwisko is not None: overrides["Nazwisko"] = data.Nazwisko
        if data.Miasto is not None:   overrides["Miasto"]   = data.Miasto
        if data.Telefon is not None:  overrides["Telefon"]  = data.Telefon
        if data.Email is not None:    overrides["Email"]    = data.Email
        overrides["akcja"] = "ZAPISZ"
        form_fields.update(overrides)

        # 5) Przygotowanie body – percent‑escaping pod ISO‑8859‑2
        #    Python3 urlencode wspiera parametry encoding/errors
        body_str = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
        body_bytes = body_str.encode("ascii")  # wszystkie non-ASCII są już %-encoded
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"
        }
        resp_edit = await client.request(
            "POST",
            path,
            content=body_bytes,
            headers=headers,
            cookies=cookies,
        )

        # 6) Sprawdzenie, czy wartości w odpowiedzi zostały zaktualizowane
        detected = chardet.detect(resp_edit.content)
        html_edit = resp_edit.content.decode(
            detected.get("encoding") or "utf-8", errors="replace"
        )
        soup2 = BeautifulSoup(html_edit, "html.parser")
        form2 = soup2.find("form", {"name": "edycja"})
        if not form2:
            # formularz zniknął? to sukces:
            return {"success": True}

        # jeśli formularz nadal jest, to zczytujemy z niego wartości
        result_fields = {}
        # text/hidden inputs
        for inp in form2.find_all("input"):
            name = inp.get("name")
            if name in overrides:
                result_fields[name] = inp.get("value", "")
        # selecty (choć tu nie nadpisujesz)
        # teraz porównujemy:
        for k, v in overrides.items():
            if result_fields.get(k, "") != v:
                return {
                    "success": False,
                    "error": f"Pole `{k}` nie zostało zapisane (o: `{v}` vs `{result_fields.get(k)}`)"
                }

        return {"success": True}
