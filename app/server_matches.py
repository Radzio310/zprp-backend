# server_matches.py

import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin, parse_qs, urlparse
from fastapi import APIRouter, HTTPException

BASE_URL = "https://rozgrywki.zprp.pl/"

router = APIRouter(prefix="/matches", tags=["matches"])


def _get_soup(params=None, url=None):
    if url:
        r = requests.get(url, timeout=10)
    else:
        r = requests.get(BASE_URL, params=params or {}, timeout=10)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")


def _parse_match_row(tr):
    tds = tr.find_all("td")
    header = tds[0].get_text(" ", strip=True).split()
    match_id = header[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])

    parts = tds[0].get_text(" ", strip=True).split()
    date = " ".join(parts[-2:])

    place = tds[-1].find_all("small")[0].get_text(strip=True)
    hall_map = tds[-1].find("a", href=True)["href"]

    home = {
        "name": tds[1].get_text(strip=True),
        "logo": urljoin(BASE_URL, tds[2].img["src"])
    }
    away = {
        "name": tds[5].get_text(strip=True),
        "logo": urljoin(BASE_URL, tds[4].img["src"])
    }

    score = tds[3].find("big").get_text(strip=True)
    half_time = tds[3].find("small").get_text(strip=True).strip("()")

    viewers_txt = tds[-2].get_text(strip=True)
    viewers = int(viewers_txt) if viewers_txt.isdigit() else 0

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
    root = _get_soup(params={"Sezon": season_id})

    # 1) Find the top‐level “Rozgrywki” menu item
    main_menu = root.select_one("#main-nav .menu")
    rozgrywki_li = None
    for li in main_menu.find_all("li", recursive=False):
        if li.a and li.a.get_text(strip=True) == "Rozgrywki":
            rozgrywki_li = li
            break
    if not rozgrywki_li:
        raise HTTPException(500, "Nie znaleziono sekcji Rozgrywki")

    # 2) Within it, find all województwa (direct children of its .sub-menu)
    wojewodztwa_ul = rozgrywki_li.find("ul", class_="sub-menu")
    wojewodztwa = wojewodztwa_ul.find_all("li", recursive=False)

    data = {}
    for woj_li in wojewodztwa:
        woj_name = woj_li.a.get_text(strip=True)
        data[woj_name] = {}

        # 3) Under each woj, there are two sub‐menus: Kobiety and Mężczyźni
        cat_ul = woj_li.find("ul", class_="sub-menu")
        for cat_li in cat_ul.find_all("li", recursive=False):
            cat_label = cat_li.a.get_text(strip=True).upper()
            cat_key = "Kobiety" if "KOBIETY" in cat_label else "Mężczyźni"
            data[woj_name][cat_key] = {}

            # 4) Each “Rozgrywka” under that category
            roz_ul = cat_li.find("ul", class_="sub-menu")
            for roz_li in roz_ul.find_all("li", recursive=False):
                roz_name = roz_li.a.get_text(strip=True)
                href = roz_li.a["href"]
                roz_qs = parse_qs(urlparse(href).query)
                roz_id = roz_qs.get("Rozgrywki", [None])[0]
                if not roz_id:
                    continue

                data[woj_name][cat_key][roz_name] = defaultdict(lambda: defaultdict(list))

                # 5) Fetch competition page to list rounds
                comp_soup = _get_soup(url=urljoin(BASE_URL, href))
                ronda_opts = comp_soup.select("select[name=Runda] option")[1:]
                for r_opt in ronda_opts:
                    r_id = r_opt["value"]
                    r_txt = r_opt.get_text(strip=True)

                    # 6) Fetch page with that round to list matchdays
                    soup_r = _get_soup(
                        url=urljoin(BASE_URL, href),
                        params={"Runda": r_id}
                    )
                    kolejka_opts = soup_r.select("select[name=Kolejka] option")[1:]
                    for k_opt in kolejka_opts:
                        k_id = k_opt["value"]
                        k_txt = k_opt.get_text(strip=True)

                        # 7) Finally fetch the matches table
                        soup_k = _get_soup(
                            url=urljoin(BASE_URL, href),
                            params={"Runda": r_id, "Kolejka": k_id}
                        )
                        tbl = soup_k.find("table", id="prevMatchTable")
                        if not tbl:
                            continue

                        for tr in tbl.find_all("tr")[1:]:
                            if tr.find("td"):
                                m = _parse_match_row(tr)
                                data[woj_name][cat_key][roz_name][r_txt][k_txt].append(m)

    return data


@router.get(
    "/{season_id}",
    summary="Zwraca wszystkie mecze podzielone na województwa → kategorie → rozgrywki → rundy → kolejki",
)
def matches(season_id: int):
    try:
        tree = get_all_matches(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania danych z zewnętrznego serwisu: {e}")
    return {"season": season_id, "matches": tree}
