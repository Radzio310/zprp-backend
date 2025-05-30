import logging, base64, re
from fastapi import APIRouter, Form, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import get_settings, get_rsa_keys

logger = logging.getLogger("edit_photo")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

router = APIRouter(prefix="/judge", tags=["judge"])

def decrypt_field(private_key, enc_b64: str) -> str:
    try:
        data = base64.b64decode(enc_b64)
        plain = private_key.decrypt(data, padding=padding.PKCS1v15())
        return plain.decode()
    except Exception as e:
        logger.error("Decrypt error", exc_info=e)
        raise HTTPException(400, "Decryption error")

async def authenticate(client: AsyncClient, settings, user, pwd):
    resp, _ = await client.request("POST", "/login.php",
        data={"login": user, "haslo": pwd, "from": "/index.php?"},
        follow_redirects=True
    )
    if "/index.php" not in resp.url.path:
        raise HTTPException(401, "Logowanie nie powiodło się")
    client.cookies.update(resp.cookies)

@router.post("/photo", status_code=status.HTTP_200_OK)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),  # base64 z Croppie
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    priv, _ = keys
    user = decrypt_field(priv, username)
    pwd  = decrypt_field(priv, password)
    jid  = decrypt_field(priv, judge_id)

    # 1) zaloguj i trzymaj cookies
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        await authenticate(client, settings, user, pwd)

        # 2) Krok otwarcia modalnego Croppie (bez pliku)
        resp_modal = await client.post(
            "/sedzia_foto_dodaj3.php",
            data={"NrSedzia": jid, "user": user},
            headers={"Accept": "text/html"},
        )
        if resp_modal.status_code != 200:
            raise HTTPException(500, "Nie udało się wczytać modalu Croppie")

        # (opcjonalnie) możesz tu sparsować resp_modal.text,
        # ale skoro wiemy, że modal z Croppie zadziała, przejdź od razu do kroku 3.

        # 3) Krok „ZAPISZ” – wysyłasz base64, NrSedzia, user, button=ZAPISZ
        resp_save = await client.post(
            "/sedzia_foto_dodaj3.php",
            data={
                "NrSedzia": jid,
                "user":     user,
                "foto":     foto,
                "button":   "ZAPISZ",
            },
            headers={"Accept": "text/html"},
        )
        if resp_save.status_code != 200:
            raise HTTPException(500, f"Zapis zdjęcia nie powiódł się ({resp_save.status_code})")

        # 4) potwierdź na stronie edycji
        resp_edit = await client.get(f"/index.php?a=sedzia&b=edycja&NrSedzia={jid}")
        if resp_edit.status_code != 200:
            raise HTTPException(500, "Nie udało się pobrać strony edycji")

    # 5) scrapuj <img src="foto_sedzia/...">
    soup = BeautifulSoup(resp_edit.text, "html.parser")
    img = soup.find("img", src=re.compile(r"foto_sedzia/", re.IGNORECASE))
    if not img or not img["src"]:
        raise HTTPException(500, "Nie znaleziono nowego zdjęcia")

    src = img["src"]
    url = src.lower().startswith("http") and src or settings.ZPRP_BASE_URL.rstrip("/") + "/" + src.lstrip("/")
    return JSONResponse({"success": True, "photo_url": url})
