from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import aiohttp
from utils.auth import decrypt_payload  # Twoja funkcja do deszyfrowania RSA
from utils.zprp_login import get_zprp_session  # logowanie / cookie‐jar

router = APIRouter(prefix="/judge/offtimes")

@router.post("/delegateNote")
async def delegate_note(raw: dict):
    # 1) deszyfrujemy payload
    try:
        data = decrypt_payload(raw)  # { username, password, judge_id, delegate_url }
    except Exception as e:
        raise HTTPException(400, "Invalid payload")

    # 2) pobieramy cookie‐jar (logowanie / odświeżenie sesji)
    session = await get_zprp_session(
        data["username"], data["password"], data["judge_id"]
    )

    # 3) pobieramy plik PDF
    pdf_url = f"https://baza.zprp.pl/{data['delegate_url']}"
    async with session.get(pdf_url) as resp:
        if resp.status != 200 or resp.headers.get("content-type") != "application/pdf":
            raise HTTPException(502, "Failed to fetch PDF from ZPRP")
        # 4) zwracamy strumień
        return StreamingResponse(
            resp.content.iter_chunked(1024),
            media_type="application/pdf"
        )
