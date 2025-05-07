from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from urllib.parse import urlencode               
from app.utils import fetch_with_correct_encoding
from app.schemas import BatchOffTimeRequest, OffTimeAction
from app.deps import get_settings, get_rsa_keys
from bs4 import BeautifulSoup
import base64, json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

router = APIRouter()

@router.post("/judge/offtimes/batch")
async def batch_offtimes(
    req: BatchOffTimeRequest,
    settings = Depends(get_settings),
    keys = Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) funkcja do odszyfrowania RSA
    def decrypt(enc_b64: str) -> str:
        data = base64.b64decode(enc_b64)
        return private_key.decrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode("utf-8")

    # 2) odszyfruj credentials i akcje
    user = decrypt(req.username)
    pwd  = decrypt(req.password)
    judge = decrypt(req.judge_id)
    actions_json = decrypt(req.actions)
    try:
        actions: List[OffTimeAction] = json.loads(actions_json)
    except Exception:
        raise HTTPException(400, "Niepoprawne akcje")

    # 3) zaloguj się do BAZY
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        resp_login, _ = await fetch_with_correct_encoding(
            client, "/login.php", method="POST",
            data={"login": user, "haslo": pwd, "from": "/index.php?"}
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        cookies = dict(resp_login.cookies)

        results = []
        for idx, act in enumerate(actions):
            try:
                # a) GET formularza
                params = {
                  "NrSedzia": judge,
                  "user": user,
                  "akcja": "Nowy" if act.type=="create" else "Edycja" if act.type=="update" else "Usun",
                  "IdOffT": act.IdOffT or ""
                }
                _, html = await fetch_with_correct_encoding(
                    client, "/sedzia_offtimeF.php?" + urlencode(params),
                    method="GET", cookies=cookies
                )
                soup = BeautifulSoup(html, "html.parser")
                form = soup.find("form", {"name": "OffTimeForm"})

                # b) wypakuj wszystkie pola
                form_fields = {}
                for inp in form.find_all(["input","textarea","select"]):
                    n = inp.get("name")
                    if not n: continue
                    if inp.name=="select":
                        v = inp.find("option", selected=True).get("value","")
                    elif inp.name=="textarea":
                        v = inp.text
                    else:
                        v = inp.get("value","")
                    form_fields[n] = v

                # c) nadpisz DataOd, DataDo, Info + wymuś przycisk "akcja2"="zapisz"
                form_fields["DataOd"] = act.DataOd
                form_fields["DataDo"] = act.DataDo
                form_fields["Info"]   = act.Info
                form_fields["akcja"]  = "Zapisz"

                # d) wyślij POST
                body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
                headers = {"Content-Type":"application/x-www-form-urlencoded; charset=ISO-8859-2"}
                resp = await client.request("POST", "/sedzia_offtimeF.php",
                                           content=body.encode("ascii"),
                                           headers=headers,
                                           cookies=cookies)
                text = resp.content.decode("iso-8859-2",errors="replace")

                # e) sprawdź czy się zapisało (np. czy pojawił się w HTML komunikat "Zapisano")
                ok = resp.status_code==200 and "Zapisano" in text
                results.append({"index":idx, "type":act.type, "success":ok})
            except Exception as e:
                results.append({"index":idx, "type":act.type, "success":False, "error":str(e)})

    return {"success": all(r["success"] for r in results), "results": results}
