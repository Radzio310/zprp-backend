# server_matches.py

import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin, parse_qs, urlparse
from fastapi import APIRouter, HTTPException

BASE_URL = "https://rozgrywki.zprp.pl/"

router = APIRouter(prefix="/matches", tags=["matches"])


def _get_soup(params=None, url=None):
    """Fetch a page (by URL or BASE_URL+params) and return BeautifulSoup."""
    if url:
        r = requests.get(url, timeout=10)
    else:
        r = requests.get(BASE_URL, params=params or {}, timeout=10)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")


def _parse_match_row(tr):
    """Extract all match info from a single <tr>."""
    tds = tr.find_all("td")
    # id & detail link
    header = tds[0].get_text(" ", strip=True).split()
    match_id = header[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])
    # date
    parts = tds[0].get_text(" ", strip=True).split()
    date = " ".join(parts[-2:])
    # place & map
    place = tds[-1].find_all("small")[0].get_text(strip=True)
    hall_map = tds[-1].find("a", href=True)["href"]
    # teams
    home = {
        "name": tds[1].get_text(strip=True),
        "logo": urljoin(BASE_URL, tds[2].img["src"])
    }
    away = {
        "name": tds[5].get_text(strip=True),
        "logo": urljoin(BASE_URL, tds[4].img["src"])
    }
    # score
    score = tds[3].find("big").get_text(strip=True)
    half_time = tds[3].find("small").get_text(strip=True).strip("()")
    # viewers
    viewers_txt = tds[-2].get_text(strip=True)
    viewers = int(viewers_txt) if viewers_txt.isdigit() else 0
    # referees
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
    Returns a nested dict:
    {
      "WOJEWÓDZTWO": {
        "Kobiety" or "Mężczyźni": {
          "Nazwa Rozgrywki": {
            "Runda I": {
              "Kolejka 1": [ {...}, ... ],
              ...
            },
            ...
          },
          ...
        },
        ...
      },
      ...
    }
    """
    # 1) fetch root season page
    root = _get_soup(params={"Sezon": season_id})

    # 2) find the "Rozgrywki" menu → województwa
    rozgrywki_li = root.select_one("#main-nav > .container .menu-item:has(>a[href='#']:contains('Rozgrywki'))")
    if not rozgrywki_li:
        raise HTTPException(500, "Nie znaleziono sekcji Rozgrywki")
    wojewodztwa = rozgrywki_li.select("> ul.sub-menu > li")

    data = {}

    for woj_li in wojewodztwa:
        woj_name = woj_li.a.get_text(strip=True)
        data[woj_name] = {"Kobiety": {}, "Mężczyźni": {}}

        # 3) within each województwo, two submenus: Kobiety i Mężczyźni
        for cat_li in woj_li.select("> ul.sub-menu > li"):
            cat_name = cat_li.a.get_text(strip=True)  # "KOBIETY" or "MĘŻCZYŹNI"
            cat_key = "Kobiety" if "KOBIETY" in cat_name.upper() else "Mężczyźni"
            data[woj_name][cat_key] = {}

            # 4) each Rozgrywka under that category
            for roz_li in cat_li.select("> ul.sub-menu > li"):
                roz_a = roz_li.a
                roz_name = roz_a.get_text(strip=True)
                # extract Rozgrywki=... param
                href = roz_a["href"]
                roz_qs = parse_qs(urlparse(href).query)
                roz_id = roz_qs.get("Rozgrywki", [None])[0]
                if not roz_id:
                    continue

                data[woj_name][cat_key][roz_name] = defaultdict(lambda: defaultdict(list))

                # 5) load first page for this competition to get rounds
                comp_soup = _get_soup(url= urljoin(BASE_URL, href))
                r_opts = comp_soup.select("select[name=Runda] option")[1:]
                for r_opt in r_opts:
                    r_id = r_opt["value"]
                    r_txt = r_opt.get_text(strip=True)

                    # fetch page with Runda to get Kolejka options
                    soup_r = _get_soup(url= urljoin(BASE_URL, href), params={"Runda": r_id})
                    k_opts = soup_r.select("select[name=Kolejka] option")[1:]
                    for k_opt in k_opts:
                        k_id = k_opt["value"]
                        k_txt = k_opt.get_text(strip=True)

                        # finally fetch the matches table
                        page_k = _get_soup(
                            url= urljoin(BASE_URL, href),
                            params={"Runda": r_id, "Kolejka": k_id}
                        )
                        tbl = page_k.find("table", id="prevMatchTable")
                        if not tbl:
                            continue

                        # skip header row
                        for tr in tbl.find_all("tr")[1:]:
                            if tr.find("td"):
                                m = _parse_match_row(tr)
                                data[woj_name][cat_key][roz_name][r_txt][k_txt].append(m)

    return data


@router.get(
    "/{season_id}",
    summary="Zwraca wszystkie mecze dla podanego sezonu, podziałem na województwa → kategorie → rozgrywki → rundy → kolejki",
)
def matches(season_id: int):
    try:
        tree = get_all_matches(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania danych z zewnętrznego serwisu: {e}")
    return {"season": season_id, "matches": tree}
