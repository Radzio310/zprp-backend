from typing import Optional
import httpx
from sqlalchemy import select
from app.db import database, saved_matches

BASE_URL = "https://rozgrywki.zprp.pl/"

async def get_match_html_from_db(match_number: str) -> Optional[str]:
    """
    Przykład: jeśli w saved_matches.data_json trzymasz surowy HTML pod kluczem 'raw_html'.
    Zwraca None jeśli nie ma HTML-a w bazie.
    """
    row = await database.fetch_one(
        select(saved_matches).where(saved_matches.c.match_number == match_number)
    )
    if not row:
        return None
    data = row["data_json"] or {}
    html = data.get("raw_html") or data.get("html")
    return html

async def fetch_match_html_httpx(season_id: int, league_id: int, match_number: str, timeout: float = 10.0) -> str:
    url = f"{BASE_URL}?Sezon={season_id}&Rozgrywki={league_id}&Mecz={match_number}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text
