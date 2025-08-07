# app/server_matches.py

import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

BASE_URL = "https://rozgrywki.zprp.pl/"

def _get_html(params):
    r = requests.get(BASE_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.text

def _parse_match_row(tr):
    tds = tr.find_all("td")

    # numer meczu i link do szczegółów
    header = tds[0].get_text(" ", strip=True)
    match_id = header.split()[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])

    # data meczu
    raw_date = " ".join(tds[0].stripped_strings)
    # spodziewany format "IIM4/1 29.09.2024 15:00", bierzemy drugi element dalej
    date = " ".join(raw_date.split()[1:3])

    # miejsce + link Google Maps
    place_small = tds[-1].find_all("small")
    place = place_small[0].get_text(strip=True) if place_small else ""
    hall_map = tds[-1].find("a", href=True)["href"] if tds[-1].find("a", href=True) else ""

    # drużyny
    home = {
        "name": tds[1].get_text(strip=True),
        "logo": tds[2].img["src"] if tds[2].img else ""
    }
    away = {
        "name": tds[5].get_text(strip=True),
        "logo": tds[4].img["src"] if tds[4].img else ""
    }

    # wynik końcowy i do przerwy
    score = tds[3].find("big").get_text(strip=True) if tds[3].find("big") else ""
    half_time = tds[3].find("small").get_text(strip=True).strip("()") if tds[3].find("small") else ""

    # widzowie
    viewers_txt = tds[-2].get_text(strip=True)
    try:
        viewers = int(viewers_txt)
    except ValueError:
        viewers = None

    # sędziowie (tabela poniżej)
    sedzia_tbl = tr.find_next("table", id="prevSedziaTable")
    referees = ""
    if sedzia_tbl:
        center_td = sedzia_tbl.find("td", style=lambda v: v and "text-align:center" in v)
        if center_td:
            referees = center_td.get_text(strip=True)

    return {
        "match_id": match_id,
        "detail_link": detail_link,
        "date": date,
        "place": place,
        "hall_map": hall_map,
        "home": home,
        "away": away,
        "score": score,
        "half_time": half_time,
        "viewers": viewers,
        "referees": referees,
    }

def get_all_matches(season_id: int):
    """
    Zwraca strukturę:
    {
      "<województwo>": {
        "<runda>": {
          "<kolejka>": [ { ...mecz... }, ... ]
        }
      }
    }
    """
    root_html = _get_html({"Sezon": season_id})
    soup = BeautifulSoup(root_html, "lxml")

    # menu KLUBY → lista województw
    kluby_menu = soup.select_one("#main-nav li#menu-item-6 > ul.sub-menu")
    if not kluby_menu:
        raise ValueError("Nie znaleziono menu KLUBY na stronie startowej")

    result = {}

    for woj_li in kluby_menu.find_all("li", recursive=False):
        woj = woj_li.a.get_text(strip=True)
        result[woj] = defaultdict(lambda: defaultdict(list))

        # wejście na stronę województwa
        woj_url = urljoin(BASE_URL, woj_li.a["href"])
        woj_page = requests.get(woj_url, timeout=10)
        woj_page.raise_for_status()
        woj_soup = BeautifulSoup(woj_page.text, "lxml")

        # iteruj po rundach
        r_opts = woj_soup.select("select[name=Runda] option")[1:]
        k_opts = woj_soup.select("select[name=Kolejka] option")[1:]
        for r_opt in r_opts:
            r_id = r_opt["value"]
            r_txt = r_opt.get_text(strip=True)

            for k_opt in k_opts:
                k_id = k_opt["value"]
                k_txt = k_opt.get_text(strip=True)

                # pobierz tabelę z meczami
                page = requests.get(f"{woj_url}&Runda={r_id}&Kolejka={k_id}", timeout=10)
                page.raise_for_status()
                tbl = BeautifulSoup(page.text, "lxml").find("table", id="prevMatchTable")
                if not tbl:
                    continue

                for tr in tbl.select("tr")[1:]:
                    if tr.find("td"):
                        try:
                            m = _parse_match_row(tr)
                        except Exception:
                            # można logować wyjątki pod `logging`
                            continue
                        result[woj][r_txt][k_txt].append(m)

    return result


# ———————— FastAPI router ————————
router = APIRouter(prefix="/api/seasons", tags=["matches"])

@router.get(
    "/{season_id}/matches",
    summary="Pobierz wszystkie mecze z danego sezonu (podział: województwa → rundy → kolejki)",
    response_class=JSONResponse,
)
async def get_matches_endpoint(season_id: int):
    try:
        data = get_all_matches(season_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except requests.HTTPError as he:
        raise HTTPException(status_code=502, detail=f"Błąd zewnętrznego serwera: {he}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Nieoczekiwany błąd: {e}")

    return {"season": season_id, "matches": data}
