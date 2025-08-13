import json
from fastapi.responses import JSONResponse
import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, urlunparse
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import date
import pandas as pd

from app.zprp_client import ZprpApiClient, ZprpResponseError

BASE_URL = "https://rozgrywki.zprp.pl/"

router = APIRouter(prefix="/matches", tags=["matches"])


def _get_soup(params=None, url=None):
    if url:
        r = requests.get(url, timeout=10)
    else:
        r = requests.get(BASE_URL, params=params or {}, timeout=10)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")


def _strip_zespoly(href: str) -> str:
    p = urlparse(href)
    qs = parse_qs(p.query)
    qs.pop("Zespoly", None)
    new_query = urlencode(qs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def get_all_first_links(season_id: int):
    root = _get_soup(params={"Sezon": season_id})

    # 1) Znajdź w menu “Rozgrywki”
    main_menu = root.select_one("#main-nav .menu")
    rozgrywki_li = next(
        (li for li in main_menu.find_all("li", recursive=False)
         if li.a and li.a.get_text(strip=True) == "Rozgrywki"),
        None
    )
    if not rozgrywki_li:
        raise HTTPException(500, "Nie znaleziono sekcji Rozgrywki")

    data = {}
    wojewodztwa = rozgrywki_li.find("ul", class_="sub-menu").find_all("li", recursive=False)

    for woj_li in wojewodztwa:
        woj_name = woj_li.a.get_text(strip=True)
        data[woj_name] = {}

        # KOBIETY / MĘŻCZYŹNI
        for cat_li in woj_li.find("ul", class_="sub-menu").find_all("li", recursive=False):
            cat_label = cat_li.a.get_text(strip=True).upper()
            cat_key = "Kobiety" if "KOBIETY" in cat_label else "Mężczyźni"
            data[woj_name][cat_key] = {}

            # Rozgrywki
            for roz_li in cat_li.find("ul", class_="sub-menu").find_all("li", recursive=False):
                roz_name = roz_li.a.get_text(strip=True)
                href = roz_li.a["href"]
                roz_qs = parse_qs(urlparse(href).query)
                if "Rozgrywki" not in roz_qs:
                    continue

                # URL rozgrywek bez parametru Zespoly
                comp_url = _strip_zespoly(urljoin(BASE_URL, href))

                # 2) Zbierz gotowe linki do rund (sekcja TERMINARZ)
                comp_soup = _get_soup(url=comp_url)
                terminarz = comp_soup.select_one("#menu-item-5 ul.sub-menu")
                first_links = {}
                if terminarz:
                    for li in terminarz.find_all("li", recursive=False):
                        a = li.find("a", href=True)
                        qs = parse_qs(a["href"].lstrip("?"))
                        label = a.get_text(strip=True)
                        first_links[label] = urljoin(
                            BASE_URL,
                            f"?Sezon={qs['Sezon'][0]}"
                            f"&Rozgrywki={qs['Rozgrywki'][0]}"
                            f"&Runda={qs['Runda'][0]}"
                            f"&Kolejka={qs['Kolejka'][0]}"
                        )

                data[woj_name][cat_key][roz_name] = {"first_links": first_links}

    return data


@router.get(
    "/{season_id}/first-links",
    summary="Zwraca tylko first_links do rund dla każdej rozgrywki",
)
def first_links(season_id: int):
    try:
        tree = get_all_first_links(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania z zewnętrznego serwisu: {e}")
    return {"season": season_id, "first_links": tree}


@router.get(
    "/{season_id}/full-timetable",
    summary="Zwraca terminarz meczów dla danego sezonu z opcjonalnym filtrem dat i kolejki",
    response_model=dict
)
def full_timetable_by_id(
    season_id: int,
    wzpr_list: List[str] = Query(
        [], title="Filtr WZPR",
        description="Lista skrótów województw (NazwaWZPR) do uwzględnienia; pusty = wszystkie"
    ),
    central_level_only: bool = Query(
        False, title="Poziom centralny",
        description="Jeśli True, zwróci tylko rozgrywki centralne"
    ),
    start_date: Optional[date] = Query(
        None, title="Data początkowa",
        description="Pokaż tylko mecze z tej daty lub później (YYYY-MM-DD)"
    ),
    end_date: Optional[date] = Query(
        None, title="Data końcowa",
        description="Pokaż tylko mecze do tej daty włącznie (YYYY-MM-DD)"
    ),
    series_id: Optional[int] = Query(
        None, title="ID kolejki",
        description="Pokaż tylko mecze z tej kolejki (ID_kolejka)"
    ),
):
    """
    Pobiera kompletny terminarz meczów z API rozgrywki.zprp.pl dla sezonu o danym ID,
    a następnie, jeśli podano `series_id`, `start_date` i/lub `end_date`, filtruje wyniki.
    """
    client = ZprpApiClient(debug_logging=False)

    # 1) Pobierz i znajdź sezon po ID
    seasons = client._get_request_json(client.get_link_zprp('seasons_api', {}), 'seasons_api')
    season = next((s for s in seasons.values() if s.get("ID_sezon") == str(season_id)), None)
    if not season:
        raise HTTPException(404, f"Sezon o ID {season_id} nie znaleziony.")

    # 2) Wstrzyknij znaleziony sezon
    client._find_season = lambda _: season

    # 3) Pobierz cały terminarz
    try:
        df = client.fetch_full_timetable(
            desired_season=str(season_id),
            wzpr_list=wzpr_list,
            central_level_only=central_level_only
        )
    except ZprpResponseError as e:
        raise HTTPException(502, f"Błąd podczas komunikacji z API ZPRP: {e}")
    except Exception as e:
        client.utils.log_this(f"Unexpected error in full-timetable: {e}", 'error')
        raise HTTPException(500, f"Nieoczekiwany błąd: {e}")

    # BEZPIECZNY filtr po dacie (priorytet: data_fakt -> data_prop), granice włącznie
    if start_date or end_date:
        dt_fakt = pd.to_datetime(df['data_fakt'], errors='coerce') if 'data_fakt' in df.columns else pd.Series(pd.NaT, index=df.index)
        dt_prop = pd.to_datetime(df['data_prop'], errors='coerce') if 'data_prop' in df.columns else pd.Series(pd.NaT, index=df.index)
        df['_match_dt'] = dt_fakt.fillna(dt_prop)  # preferuj data_fakt, fallback na data_prop

        if start_date:
            df = df[df['_match_dt'].dt.date >= start_date]
        if end_date:
            df = df[df['_match_dt'].dt.date <= end_date]

        df = df.drop(columns=['_match_dt'])

    # jeśli po filtrach nic nie zostało – zwróć pustą odpowiedź
    if df.empty:
        payload = {"season_id": season_id, "total_rows": 0, "shown_rows": 0, "data": []}
        return JSONResponse(content=payload)

    # BEZPIECZNY filtr po kolejce
    if series_id is not None and 'ID_kolejka' in df.columns:
        df = df[pd.to_numeric(df['ID_kolejka'], errors='coerce') == series_id]

    # BEZPIECZNY filtr po dacie
    if 'data_prop' in df.columns:
        df['data_prop_dt'] = pd.to_datetime(df['data_prop'], errors='coerce').dt.date

    # po wszystkich filtrach — zwróć pełną listę
    if 'data_prop_dt' in df.columns:
        df = df.drop(columns=['data_prop_dt'])

    records = json.loads(df.to_json(orient='records', force_ascii=False))

    payload = {
        "season_id": int(season_id),
        "total_rows": int(len(df)),
        "shown_rows": len(records),
        "data": records,
    }


    # ominięcie pydantic response_model
    return JSONResponse(content=payload)

@router.get(
    "/{season_id}/by-number",
    summary="Zwraca jeden mecz po numerze (opcjonalnie tylko z danego dnia)",
)
def match_by_number(
    season_id: int,
    match_number: str = Query(..., description="Np. SPM/1 (slash będzie url-enkodowany)"),
    match_date: Optional[date] = Query(
        None, description="Filtr dnia w formacie YYYY-MM-DD; jeśli podany, szukamy tylko tego dnia"
    ),
    wzpr_list: List[str] = Query([], description="Opcjonalny filtr WZPR"),
    central_level_only: bool = Query(False, description="Tylko poziom centralny"),
):
    client = ZprpApiClient(debug_logging=False)

    # znajdź sezon po ID (jak w innych endpointach)
    seasons = client._get_request_json(client.get_link_zprp('seasons_api', {}), 'seasons_api')
    season = next((s for s in seasons.values() if s.get("ID_sezon") == str(season_id)), None)
    if not season:
        raise HTTPException(404, f"Sezon o ID {season_id} nie znaleziony.")
    client._find_season = lambda _: season

    row = client.find_game_by_number(
        desired_season=str(season_id),
        match_number=match_number,
        wzpr_list=wzpr_list,
        central_level_only=central_level_only,
        match_date=match_date,   # <-- przekazujemy filtr dnia
    )
    if not row:
        suffix = f" w dniu {match_date.isoformat()}" if match_date else ""
        raise HTTPException(404, f"Nie znaleziono meczu o numerze '{match_number}' w sezonie {season_id}{suffix}.")

    # zwracamy pojedynczy rekord (spłaszczony jak w innych miejscach)
    return JSONResponse(content=row)
