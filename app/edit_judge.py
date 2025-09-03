# app/edit_judge.py
from fastapi import APIRouter, HTTPException, Depends
from httpx import AsyncClient
from urllib.parse import urlencode
from bs4 import BeautifulSoup
import base64

from app.schemas import EditJudgeRequest
from app.utils import fetch_with_correct_encoding
from app.deps import get_settings, Settings, get_rsa_keys

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

router = APIRouter()

@router.post("/judge/edit")
async def edit_judge(
    data: EditJudgeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),  # (private_key, public_key)
):
    private_key, _ = keys

    # ─── funkcja odszyfrowująca pojedyncze pole ─────────────────────────
    def decrypt_field(enc_b64: str) -> str:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(
            cipher,
            padding.PKCS1v15()
        )
        return plain.decode("utf-8")

    # 0) Najpierw odszyfruj login/hasło/judge_id
    try:
        user_plain, pass_plain, judge_plain = (
            decrypt_field(data.username),
            decrypt_field(data.password),
            decrypt_field(data.judge_id),
        )
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        # 1) Logowanie z odszyfrowanymi danymi
        resp_login, html_login = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={
                "login": user_plain,
                "haslo": pass_plain,
                "from": "/index.php?",
            },
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        cookies = dict(resp_login.cookies)

        # 2) Pobranie formularza edycji
        path = f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_plain}"
        _, html_get = await fetch_with_correct_encoding(
            client, path, method="GET", cookies=cookies
        )
        soup = BeautifulSoup(html_get, "html.parser")
        form = soup.find("form", {"name": "edycja"})
        if not form:
            raise HTTPException(500, "Nie znaleziono formularza edycji")

        # 3) Parsowanie wszystkich pól formularza (hidden, current values, itp.)
        form_fields: dict[str, str] = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name: continue
            typ = inp.get("type", "text")
            if typ in ("hidden", "text", "password"):
                form_fields[name] = inp.get("value", "")
            elif typ == "radio" and inp.has_attr("checked"):
                form_fields[name] = inp.get("value", "")

        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name: continue
            opt = sel.find("option", selected=True)
            form_fields[name] = opt.get("value", "") if opt else ""

        # 4) Nadpisanie tylko tych pól, które chcesz — odszyfrowane
        overrides: dict[str, str] = {}
        if data.Imie is not None:
            overrides["Imie"] = decrypt_field(data.Imie)
        if data.Nazwisko is not None:
            overrides["Nazwisko"] = decrypt_field(data.Nazwisko)
        if data.Miasto is not None:
            overrides["Miasto"] = decrypt_field(data.Miasto)
        if data.KodPocztowy is not None:
            overrides["KodPocztowy"] = decrypt_field(data.KodPocztowy)
        if data.Telefon is not None:
            overrides["Telefon"] = decrypt_field(data.Telefon)
        if data.Email is not None:
            overrides["Email"] = decrypt_field(data.Email)
        overrides["akcja"] = "ZAPISZ"
        form_fields.update(overrides)

        # 5) Przygotowanie body – percent‑escaping pod ISO‑8859‑2
        body_str = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
        body_bytes = body_str.encode("ascii")
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
        html_edit = resp_edit.content.decode("iso-8859-2", errors="replace")
        soup2 = BeautifulSoup(html_edit, "html.parser")
        form2 = soup2.find("form", {"name": "edycja"})
        if not form2:
            # formularz zniknął? to sukces:
            return {"success": True}

        result_fields: dict[str, str] = {}
        for inp in form2.find_all("input"):
            name = inp.get("name")
            if name in overrides:
                result_fields[name] = inp.get("value", "")

        for k, v in overrides.items():
            if result_fields.get(k, "") != v:
                return {
                    "success": False,
                    "error": f"Pole `{k}` nie zostało zapisane (o: `{v}` vs `{result_fields.get(k)}`)"
                }

        return {"success": True}
