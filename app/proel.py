import re
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select, insert, update, delete
from app.db import database, saved_matches
from app.schemas import (
    CreateSavedMatchRequest,
    UpcomingMatchItem,
    UpcomingMatchesResponse,
    UpdateSavedMatchRequest,
    MatchItem,
    ListSavedMatchesResponse,
)
from datetime import datetime
from zoneinfo import ZoneInfo
import httpx
from bs4 import BeautifulSoup

ZPRP_BASE_URL = "http://rozgrywki.zprp.pl/"
TZ_PL = ZoneInfo("Europe/Warsaw")

router = APIRouter(
    prefix="/proel",
    tags=["ProEl"],
    responses={404: {"description": "Not found"}},
)

@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowy mecz do ProEl'a"
)
async def create_proel_match(req: CreateSavedMatchRequest):
    existing = await database.fetch_one(
        select(saved_matches)
        .where(saved_matches.c.match_number == req.match_number)
    )
    if existing:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "MATCH_EXISTS", "message": "Mecz o takim numerze już istnieje"},
        )

    stmt = insert(saved_matches).values(
        match_number=req.match_number,
        data_json=req.data_json,
        is_finished=req.is_finished  # używamy tego, co przyszło (domyślnie False)
    )
    await database.execute(stmt)
    return {"success": True}


@router.put(
    "/{match_number:path}",
    response_model=dict,
    summary="Aktualizuj mecz w ProEl'u (jeśli nie zakończony)"
)
async def update_proel_match(
    match_number: str,
    req: UpdateSavedMatchRequest
):
    row = await database.fetch_one(
        select(saved_matches)
        .where(saved_matches.c.match_number == match_number)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")
    if row["is_finished"]:
        raise HTTPException(
            status.HTTP_423_LOCKED,
            detail={"code": "MATCH_FINISHED", "message": "Nie można edytować zakończonego meczu"},
        )

    # Budujemy słownik pól do aktualizacji
    to_update: dict = {"data_json": req.data_json}
    if req.is_finished is not None:
        to_update["is_finished"] = req.is_finished
    # zawsze przepisujemy updated_at na teraz
    to_update["updated_at"] = datetime.utcnow()

    stmt = (
        update(saved_matches)
        .where(saved_matches.c.match_number == match_number)
        .values(**to_update)
    )
    await database.execute(stmt)
    return {"success": True}


@router.delete(
    "/{match_number:path}",
    response_model=dict,
    summary="Usuń mecz ProEl"
)
async def delete_proel_match(match_number: str):
    result = await database.execute(
        delete(saved_matches)
        .where(saved_matches.c.match_number == match_number)
    )
    if result == 0:
        raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")
    return {"success": True}


@router.get(
    "/",
    response_model=ListSavedMatchesResponse,
    summary="Lista wszystkich meczów w ProEl'u"
)
async def list_proel_matches(
    finished: Optional[bool] = Query(
        None,
        description="Filtruj po zakończonych (true) lub niezakończonych (false); domyślnie wszystkie"
    )
):
    # budujemy bazowy SELECT
    stmt = select(saved_matches)

    # jeżeli użytkownik podał finished, dodajemy WHERE
    if finished is not None:
        stmt = stmt.where(saved_matches.c.is_finished == finished)

    # najnowsze (ostatnio edytowane) najpierw
    stmt = stmt.order_by(
        saved_matches.c.updated_at.desc(),
        saved_matches.c.match_number.desc()
    )

    rows = await database.fetch_all(stmt)
    return ListSavedMatchesResponse(
        matches=[MatchItem(**dict(r)) for r in rows]
    )

@router.get(
    "/upcoming",
    response_model=UpcomingMatchesResponse,
    summary="Najbliższe mecze (sekcja NajblizszeMecze z rozgrywki.zprp.pl)"
)
async def proel_upcoming_matches(
    season: Optional[int] = Query(None, description="Parametr ?Sezon=… przekazany do rozgrywki.zprp.pl"),
    limit: int = Query(50, ge=1, le=200, description="Maksymalna liczba rekordów do zwrócenia")
):
    """
    Czyta stronę rozgrywki.zprp.pl i zwraca wiersze z sekcji <div id="NajblizszeMecze">.
    Jeśli sekcja nie istnieje albo brak wierszy — zwraca pustą listę.
    """
    params = {"Sezon": season} if season is not None else None
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ProElBot/1.0; +https://example.invalid)",
        "Accept-Language": "pl-PL,pl;q=0.9",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(ZPRP_BASE_URL, params=params, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        # Nie robimy 500 – po prostu zwracamy pustą listę, żeby front był odporny
        return UpcomingMatchesResponse(data=[])

    soup = BeautifulSoup(resp.text, "html.parser")
    container = soup.find(id="NajblizszeMecze")
    if not container:
        return UpcomingMatchesResponse(data=[])

    rows = container.select('table tr[align="center"]')
    items: list[UpcomingMatchItem] = []

    for tr in rows:
        tds = tr.find_all("td")
        if len(tds) < 7:
            continue

        # --- Kolumna "Mecz" (kod + link z parametrami Mecz i Rozgrywki)
        a = tds[1].find("a")
        if not a or not a.get("href"):
            continue

        code_text = (a.get_text(strip=True) or None)
        full_href = urljoin(ZPRP_BASE_URL, a["href"])
        q = parse_qs(urlparse(full_href).query)

        try:
            mecz_id = int(q.get("Mecz", [None])[0])  # wymagane
        except (TypeError, ValueError):
            continue
        rozgrywki_id = None
        try:
            rozgrywki_id = int(q.get("Rozgrywki", [None])[0]) if q.get("Rozgrywki") else None
        except (TypeError, ValueError):
            pass

        # --- Kolumna "Data"
        dt = None
        b_date = tds[2].find("b")
        date_str = b_date.get_text(strip=True) if b_date else None  # np. "10.09.2025"
        # Szukamy "(HH:MM)" w <small>
        small_text = " ".join(s.get_text(" ", strip=True) for s in tds[2].find_all("small"))
        m_time = re.search(r"\((\d{2}:\d{2})\)", small_text or "")
        time_str = m_time.group(1) if m_time else None
        try:
            if date_str and time_str:
                dt = datetime.strptime(f"{date_str} {time_str}", "%d.%m.%Y %H:%M").replace(tzinfo=TZ_PL)
            elif date_str:
                dt = datetime.strptime(date_str, "%d.%m.%Y").replace(tzinfo=TZ_PL)
        except Exception:
            dt = None

        # --- Gospodarz, wynik, gość
        home = tds[4].get_text(" ", strip=True) or None
        result_raw = " ".join(tds[5].stripped_strings)
        m_score = re.search(r"\b(\d+\s*:\s*\d+)\b", result_raw or "")
        score = m_score.group(1) if m_score else None
        away = tds[6].get_text(" ", strip=True) or None

        league_title = tr.get("title") or None

        items.append(UpcomingMatchItem(
            Id=mecz_id,
            Id_rozgrywki=rozgrywki_id,
            data_fakt=dt,
            ID_zespoly_gosp_ZespolNazwa=home,
            ID_zespoly_gosc_ZespolNazwa=away,
            RozgrywkiCode=code_text,
            code=code_text,
            league=league_title,
            href=full_href,
            wynik=score
        ))

        if len(items) >= limit:
            break

    return UpcomingMatchesResponse(data=items)
