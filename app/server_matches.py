# server_matches.py

import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin
from fastapi import APIRouter, HTTPException

BASE_URL = "https://rozgrywki.zprp.pl/"

router = APIRouter(prefix="/matches", tags=["matches"])


def _get_html(params):
    r = requests.get(BASE_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.text


def _parse_match_row(tr):
    tds = tr.find_all("td")
    # Numer meczu + link do szczegółów
    header = tds[0].get_text(" ", strip=True).split()
    match_id = header[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])

    # Data meczu
    date = tds[0].get_text(" ", strip=True).split()[-2] + " " + tds[0].get_text(" ", strip=True).split()[-1]

    # Adres hali
    place = tds[-1].find_all("small")[0].get_text(strip=True)
    hall_map = tds[-1].find("a", href=True)["href"]

    # Drużyny
    home = {
        "name": tds[1].get_text(strip=True),
        "logo": urljoin(BASE_URL, tds[2].img["src"])
    }
    away = {
        "name": tds[5].get_text(strip=True),
        "logo": urljoin(BASE_URL, tds[4].img["src"])
    }

    # Wyniki
    score = tds[3].find("big").get_text(strip=True)
    half_time = tds[3].find("small").get_text(strip=True).strip("()")

    # Widzowie
    viewers = int(tds[-2].get_text(strip=True) or 0)

    # Sędziowie
    sedzia_tbl = tr.find_next("table", id="prevSedziaTable")
    referees = sedzia_tbl.find("td", style=lambda v: v and "text-align:center" in v).get_text(strip=True)

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
        "referees": referees
    }


def get_all_matches(season_id: int):
    """
    Zwraca dict:
    {
      "WOJEWÓDZTWO": {
        "Runda I": {
          "Kolejka 1": [ {...match...}, ... ],
          ...
        },
        ...
      },
      ...
    }
    """
    root = BeautifulSoup(_get_html({"Sezon": season_id}), "html.parser")

    # Lista województw z sekcji KLUBY
    kluby_menu = root.select_one("#main-nav li#menu-item-6 > ul.sub-menu")
    if not kluby_menu:
        raise HTTPException(500, "Nie udało się odczytać listy województw")

    data = {}
    for woj_li in kluby_menu.find_all("li", recursive=False):
        woj_name = woj_li.a.get_text(strip=True)
        woj_url = urljoin(BASE_URL, woj_li.a["href"])
        data[woj_name] = defaultdict(lambda: defaultdict(list))

        # pobieramy stronę województwa ONLY raz, żeby mieć listę rund
        woj_soup = BeautifulSoup(requests.get(woj_url).text, "html.parser")
        runda_opts = woj_soup.select("select[name=Runda] option")[1:]

        for r_opt in runda_opts:
            r_id = r_opt["value"]
            r_txt = r_opt.get_text(strip=True)

            # teraz pobieramy stronę z parametrem Runda, by mieć opcje Kolejka
            page_r = requests.get(woj_url, params={"Runda": r_id}).text
            soup_r = BeautifulSoup(page_r, "html.parser")
            kolejka_opts = soup_r.select("select[name=Kolejka] option")[1:]

            for k_opt in kolejka_opts:
                k_id = k_opt["value"]
                k_txt = k_opt.get_text(strip=True)

                # i dopiero teraz pobieramy wykaz meczów dla tej rundy i kolejki
                page_k = requests.get(woj_url, params={"Runda": r_id, "Kolejka": k_id}).text
                tbl = BeautifulSoup(page_k, "html.parser").find("table", id="prevMatchTable")
                if not tbl:
                    continue

                for tr in tbl.find_all("tr")[1:]:
                    if tr.find("td"):
                        data[woj_name][r_txt][k_txt].append(_parse_match_row(tr))

    return data


@router.get(
    "/{season_id}",
    summary="Zwraca wszystkie mecze dla podanego sezonu, podziałem na województwa → rundy → kolejki",
)
def matches(season_id: int):
    try:
        tree = get_all_matches(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania danych z zewnętrznego serwisu: {e}")
    return {"season": season_id, "matches": tree}
