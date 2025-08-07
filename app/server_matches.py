import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin, urlencode
from fastapi import APIRouter, HTTPException

BASE_URL = "https://rozgrywki.zprp.pl/"

router = APIRouter(prefix="/matches", tags=["matches"])


def _get_soup(params: dict) -> BeautifulSoup:
    """Pobiera stronę z podanymi parametrami i zwraca BeautifulSoup."""
    r = requests.get(BASE_URL, params=params, timeout=10)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")


def _parse_match_row(tr) -> dict:
    """Parsuje wiersz tabeli z meczu na słownik."""
    tds = tr.find_all("td")
    # ID meczu i link do szczegółów
    cols0 = tds[0].get_text(" ", strip=True).split()
    match_id = cols0[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])
    # Data
    date = " ".join(cols0[-2:])
    # Drużyny i loga
    home = {"name": tds[1].get_text(strip=True),
            "logo": urljoin(BASE_URL, tds[2].img["src"])}
    away = {"name": tds[5].get_text(strip=True),
            "logo": urljoin(BASE_URL, tds[4].img["src"])}
    # Wynik
    score_big = tds[3].find("big")
    score = score_big.get_text(strip=True) if score_big else ""
    ht_small = tds[3].find("small")
    half_time = ht_small.get_text(strip=True).strip("()") if ht_small else ""
    # Miejsce
    place = tds[-1].find_all("small")[0].get_text(strip=True)
    hall_map = tds[-1].find("a", href=True)["href"]
    # Widzowie
    viewers_txt = tds[-2].get_text(strip=True)
    viewers = int(viewers_txt) if viewers_txt.isdigit() else 0
    # Sędziowie
    sedzia_tbl = tr.find_next("table", id="prevSedziaTable")
    referees = sedzia_tbl.find("td", style=lambda v: v and "text-align:center" in v).get_text(strip=True)

    return {
        "match_id": match_id,
        "detail_link": detail_link,
        "date": date,
        "home": home,
        "away": away,
        "score": score,
        "half_time": half_time,
        "place": place,
        "hall_map": hall_map,
        "viewers": viewers,
        "referees": referees,
    }


def get_all_matches(season_id: int) -> dict:
    """
    Zwraca strukturę:
    {
      WOJEWÓDZTWO: {
        Kategoria (Kobiety/Mężczyźni): {
          NazwaRozgrywek: {
            Runda X: {
              Kolejka Y: [ {...match...}, ... ],
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
    # 1) Strona główna z listą województw
    root = _get_soup({"Sezon": season_id})
    kluby_menu = root.select_one("#main-nav li#menu-item-6 > ul.sub-menu")
    if not kluby_menu:
        raise HTTPException(500, "Nie udało się odczytać listy województw")

    data = {}

    # 2) Dla każdego województwa
    for woj_li in kluby_menu.find_all("li", recursive=False):
        woj_name = woj_li.a.get_text(strip=True)
        woj_url = urljoin(BASE_URL, woj_li.a["href"])
        data[woj_name] = {"Kobiety": {}, "Mężczyźni": {}}

        # 3) Pobieramy stronę województwa raz, żeby wyciągnąć listę kategorii i rozgrywek
        woj_soup = BeautifulSoup(requests.get(woj_url).text, "html.parser")
        for kat_li in woj_soup.select("ul.sub-menu > li.menu-item-has-children"):
            kat_name = kat_li.a.get_text(strip=True)
            # dla każdej rozgrywki w tej kategorii
            for roz_li in kat_li.select("ul.sub-menu > li"):
                roz_name = roz_li.a.get_text(strip=True)
                roz_href = roz_li.a["href"]
                # id rozgrywek
                roz_params = dict([part.split("=") for part in roz_href.split("?")[-1].split("&")])
                rozgrywki_id = int(roz_params["Rozgrywki"])

                # inicjalizacja struktury
                data[woj_name][kat_name][roz_name] = defaultdict(list)

                # 4) Strona z parametrem Rozgrywki – wyciągamy dostępne rundy
                soup_roz = _get_soup({"Sezon": season_id, "Rozgrywki": rozgrywki_id})
                r_opt = soup_roz.select("select[name=Runda] option")[1:]  # pomijamy pierwszy pusty
                for r in r_opt:
                    r_id = r["value"]
                    r_txt = r.get_text(strip=True)

                    # 5) Dla każdej rundy: pobieramy opcje Kolejka
                    soup_r = _get_soup({
                        "Sezon": season_id,
                        "Rozgrywki": rozgrywki_id,
                        "Runda": r_id
                    })
                    k_opt = soup_r.select("select[name=Kolejka] option")[1:]
                    for k in k_opt:
                        k_id = k["value"]
                        k_txt = k.get_text(strip=True)

                        # 6) Na końcu: pobieramy terminarz (bez &Zespoly=1)
                        soup_k = _get_soup({
                            "Sezon": season_id,
                            "Rozgrywki": rozgrywki_id,
                            "Runda": r_id,
                            "Kolejka": k_id
                        })
                        tbl = soup_k.find("table", id="prevMatchTable")
                        if not tbl:
                            continue

                        for tr in tbl.find_all("tr")[1:]:
                            if tr.find("td"):
                                data[woj_name][kat_name][roz_name][r_txt + " | " + k_txt].append(
                                    _parse_match_row(tr)
                                )

    return data


@router.get(
    "/{season_id}",
    summary="Zwraca wszystkie mecze dla podanego sezonu, podziałem na województwa → kategorie → rozgrywki → rundy i kolejki",
)
def matches(season_id: int):
    try:
        tree = get_all_matches(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania zewnętrznego serwisu: {e}")
    return {"season": season_id, "matches": tree}
