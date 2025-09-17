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
import re

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

def _build_match_url_from_row(season_id: int, row: dict) -> Optional[str]:
    """
    Próbuje wyciągnąć z rekordu pola ID rozgrywek i meczu, by zbudować URL strony meczu.
    Obsługuje kilka wariantów nazw kluczy.
    """
    rozgrywki_keys = ["Rozgrywki", "RozgrywkiId", "Rozgrywki", "ID_rozgrywek", "ID_rozgrywki_zprp"]
    mecz_keys = ["ID_mecz", "ID_Mecz", "Mecz", "ID_meczu"]

    rozgrywki_id = next((row.get(k) for k in rozgrywki_keys if row.get(k) not in (None, "")), None)
    mecz_id = next((row.get(k) for k in mecz_keys if row.get(k) not in (None, "")), None)

    if not (rozgrywki_id and mecz_id):
        return None

    return f"{BASE_URL}?Sezon={season_id}&Rozgrywki={rozgrywki_id}&Mecz={mecz_id}"


def _players_from_table(table) -> List[dict]:
    """
    Parsuje pojedynczą tabelę `#resultsData` do listy graczy:
    [{number:int, full_name:str, photo_url:str|None}, ...]
    - numer: z <div id="circle2"> (musi zawierać cyfrę),
    - imię i nazwisko: preferencyjnie z <img alt="NAZWISKO Imię">,
      fallback: tekst z komórki z nazwiskiem,
    - link do zdjęcia: z <img src="..."> (puste -> None).
    Wiersze niekompletne (bez numeru lub bez nazwy) są pomijane.
    """
    players = []
    if not table:
        return players

    # każdy zawodnik to <tr> w tej tabeli
    for tr in table.find_all("tr", recursive=False):
        # numer
        num_div = tr.find("div", id="circle2")
        number_txt = (num_div.get_text(strip=True) if num_div else "") or ""
        digits = "".join(ch for ch in number_txt if ch.isdigit())
        if not digits:
            # brak numeru -> pomijamy
            continue
        number = int(digits)

        # imię i nazwisko + foto z <img>
        img = tr.find("img")
        full_name = None
        photo_url = None
        if img:
            full_name = (img.get("alt") or "").strip() or None
            src = (img.get("src") or "").strip()
            photo_url = src if src else None

        if not full_name:
            # fallback: spróbuj wziąć tekst z komórki imienia/nazwiska
            # wybierz td z wyrównaniem tekstowym (zwykle to kolumna nazwiska)
            candidate = None
            for td in tr.find_all("td"):
                style = td.get("style", "")
                if "text-align" in style:
                    t = td.get_text(" ", strip=True)
                    if t and t != "-" and not t.isdigit():
                        candidate = t
                        break
            full_name = candidate or None

        if not full_name:
            # nadal brak sensownego nazwiska -> pomijamy
            continue

        # normalizacja spacji
        full_name = " ".join(full_name.split())

        players.append({
            "number": number,
            "full_name": full_name,
            "photo_url": photo_url
        })

    return players


def _parse_players_from_html_local(html: str) -> tuple[List[dict], List[dict]]:
    """
    Zwraca (home_players, away_players) wyciągnięte z dwóch tabel `table#resultsData`.
    Pierwsza tabela = gospodarze (lewa), druga = goście (prawa).
    """
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.select("table#resultsData")
    if len(tables) < 2:
        raise ValueError("Nie znaleziono dwóch tabel 'resultsData' w HTML meczu.")

    home_table, away_table = tables[0], tables[1]
    home_players = _players_from_table(home_table)
    away_players = _players_from_table(away_table)
    return home_players, away_players



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

@router.get(
    "/{season_id}/players-by-number",
    summary="Składy meczu po numerze: preferuj poziom centralny, w razie braku szukaj także w okręgach",
)
def players_by_number(
    season_id: int,
    match_number: str = Query(..., description="Np. S/JmK/4 (slash będzie url-enkodowany)"),
    side: str = Query(
        "both",
        description="Wybór: 'home' (gospodarze) | 'away' (goście) | 'both' (łącznie - domyślnie). Działają aliasy: 'gospodarze'/'goście'/'łącznie'."
    ),
    match_date: Optional[date] = Query(
        None, description="Opcjonalny filtr dnia (YYYY-MM-DD) używany w wyszukiwaniu meczu"
    ),
):
    """
    Szuka meczu po numerze w podanym sezonie:
      1) najpierw na poziomie centralnym (central_level_only=True),
      2) jeśli nie znajdzie — ponownie bez ograniczenia (central_level_only=False).

    Po znalezieniu pobiera stronę meczu, parsuje dwie tabele `table#resultsData`
    i zwraca listę graczy (home/away/both) w formacie:
      [{number:int, full_name:str, photo_url:str|None}, ...]
    """
    # 0) Normalizacja parametru "side"
    side_aliases = {
        "gospodarze": "home",
        "goscie": "away", "goście": "away",
        "lacznie": "both", "łącznie": "both",
    }
    side_norm = side_aliases.get(side.lower(), side.lower())
    if side_norm not in {"home", "away", "both"}:
        raise HTTPException(422, "Parametr 'side' musi być jednym z: home | away | both")

    client = ZprpApiClient(debug_logging=False)

    # 1) Znajdź sezon po ID (jak w innych endpointach)
    seasons = client._get_request_json(client.get_link_zprp('seasons_api', {}), 'seasons_api')
    season = next((s for s in seasons.values() if s.get("ID_sezon") == str(season_id)), None)
    if not season:
        raise HTTPException(404, f"Sezon o ID {season_id} nie znaleziony.")
    client._find_season = lambda _: season

    # 2) Spróbuj znaleźć mecz po numerze:
    #    a) najpierw centralny,
    #    b) jeśli brak — bez ograniczenia (okręg/central).
    def _try_find(central_only: bool):
        return client.find_game_by_number(
            desired_season=str(season_id),
            match_number=match_number,
            wzpr_list=[],                 # bez województw
            central_level_only=central_only,
            match_date=match_date,
        )

    try:
        row = _try_find(True) or _try_find(False)
    except ZprpResponseError as e:
        raise HTTPException(502, f"Błąd podczas komunikacji z API ZPRP: {e}")
    except Exception as e:
        client.utils.log_this(f"Unexpected error in players-by-number: {e}", 'error')
        raise HTTPException(500, f"Nieoczekiwany błąd: {e}")

    if not row:
        suffix = f" w dniu {match_date.isoformat()}" if match_date else ""
        raise HTTPException(404, f"Nie znaleziono meczu o numerze '{match_number}' w sezonie {season_id}{suffix}.")

    # 3) Zbuduj URL do strony meczu
    url = _build_match_url_from_row(season_id, row)
    if not url:
        raise HTTPException(502, "Nie udało się zbudować URL strony meczu z danych rekordu (brak ID rozgrywek/meczu).")

    # 4) Pobierz HTML strony meczu
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        html = r.text
    except requests.RequestException as e:
        raise HTTPException(502, f"Błąd pobierania strony meczu: {e}")

    # 5) Parsowanie dwóch tabel #resultsData
    try:
        home_players, away_players = _parse_players_from_html_local(html)
    except ValueError as e:
        raise HTTPException(502, f"Błąd parsowania HTML z rozgrywki.zprp.pl: {e}")
    except Exception as e:
        raise HTTPException(500, f"Nieoczekiwany błąd podczas parsowania: {e}")

    # 6) Wybór strony
    if side_norm == "home":
        data = home_players
    elif side_norm == "away":
        data = away_players
    else:
        data = [*home_players, *away_players]

    # 7) Odpowiedź
    payload = {
        "season_id": int(season_id),
        "match_number": match_number,
        "side": side_norm,          # 'home' | 'away' | 'both'
        "count": len(data),
        "data": data,               # [{number, full_name, photo_url}, ...]
        "source_url": url,
    }
    return JSONResponse(content=payload)

