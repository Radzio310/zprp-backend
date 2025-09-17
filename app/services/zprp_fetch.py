# app/services/zprp_fetch.py
from typing import Optional
import httpx
from sqlalchemy import select
from app.db import database, saved_matches

async def fetch_match_html_by_number(match_number: str) -> Optional[str]:
    """
    Zwraca HTML strony meczu bazując WYŁĄCZNIE na numerze meczu.

    Kolejność prób:
    1) saved_matches.data_json -> 'players_html' | 'raw_html' | 'html'
    2) saved_matches.data_json -> URL ('players_url' | 'zprp_players_url' | 'zprp_match_url' | 'match_url')
       (pobieramy tylko jeśli to wygląda na stronę HTML)
    3) nic nie znaleziono -> None
    """
    row = await database.fetch_one(
        select(saved_matches.c.data_json)
        .where(saved_matches.c.match_number == match_number)
    )
    if not row:
        return None

    data = row["data_json"] or {}

    # 1) bezpośrednio zapisany HTML (jeśli kiedykolwiek zapisujesz)
    for k in ("players_html", "raw_html", "html"):
        v = data.get(k)
        if isinstance(v, str) and "<html" in v.lower():
            return v

    # 2) znany URL do karty meczu / składu — tylko HTML (NIE: PDF-y typu protocol_link)
    url_keys = ("players_url", "zprp_players_url", "zprp_match_url", "match_url")
    candidates = [
        data.get(k) for k in url_keys
        if isinstance(data.get(k), str) and data.get(k, "").startswith(("http://", "https://"))
    ]

    for url in candidates:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
                r = await client.get(url)
            if r.status_code == 200:
                # sprawdź czy naprawdę HTML (nie PDF itp.)
                ctype = r.headers.get("content-type", "").lower()
                if "text/html" in ctype or "<html" in (r.text or "").lower():
                    return r.text
        except Exception:
            # pomijamy i próbujemy kolejny kandydat
            pass

    # 3) nic nie znaleziono
    return None
