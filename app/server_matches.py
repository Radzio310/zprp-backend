# server_matches.py

import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, urlunparse
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


def _strip_zespoly(href: str) -> str:
    """
    Z danego href usuń parametr Zespoly, zostaw pozostałe.
    """
    p = urlparse(href)
    qs = parse_qs(p.query)
    qs.pop("Zespoly", None)
    new_query = urlencode(qs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _parse_match_row(tr):
    tds = tr.find_all("td")
    # ID i link do szczegółów
    header = tds[0].get_text(" ", strip=True).split()
    match_id = header[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])
    # Data i miejsce
    parts = header
    date = " ".join(parts[-2:])
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
    # Wynik
    score = tds[3].find("big").get_text(strip=True)
    half_time = tds[3].find("small").get_text(strip=True).strip("()")
    # Widzowie (czasem brak liczby)
    viewers_txt = tds[-2].get_text(strip=True)
    viewers = int(viewers_txt) if viewers_txt.isdigit() else 0
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
    # 1) Pobierz stronę główną z listą rozgrywek dla danego sezonu
    root = _get_soup(params={"Sezon": season_id})

    # 2) Znajdź sekcję "Rozgrywki"
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

        # 3) Kategorie Kobiety / Mężczyźni
        for cat_li in woj_li.find("ul", class_="sub-menu").find_all("li", recursive=False):
            cat_label = cat_li.a.get_text(strip=True).upper()
            cat_key = "Kobiety" if "KOBIETY" in cat_label else "Mężczyźni"
            data[woj_name][cat_key] = {}

            # 4) Lista poszczególnych rozgrywek
            for roz_li in cat_li.find("ul", class_="sub-menu").find_all("li", recursive=False):
                roz_name = roz_li.a.get_text(strip=True)
                href = roz_li.a["href"]
                qs = parse_qs(urlparse(href).query)
                roz_id = qs.get("Rozgrywki", [None])[0]
                if not roz_id:
                    continue

                # Przygotuj bazowy URL do danej rozgrywki (bez parametru Zespoly)
                comp_url = _strip_zespoly(urljoin(BASE_URL, href))

                # Inicjalizacja struktury
                info = {
                    "first_link": None,
                    "rounds": defaultdict(lambda: defaultdict(list))
                }
                data[woj_name][cat_key][roz_name] = info

                # 5) Pobierz stronę z wyborem rund
                comp_soup = _get_soup(url=comp_url)

                # --- debugowy pierwszy link: pierwsza runda + pierwsza kolejka ---
                r_opts = comp_soup.select("select[name=Runda] option")[1:]
                if r_opts:
                    first_r_id = r_opts[0]["value"]
                    soup_r = _get_soup(url=comp_url, params={"Runda": first_r_id})
                    k_opts = soup_r.select("select[name=Kolejka] option")[1:]
                    if k_opts:
                        first_k_id = k_opts[0]["value"]
                        sep = "&" if "?" in comp_url else "?"
                        info["first_link"] = f"{comp_url}{sep}Runda={first_r_id}&Kolejka={first_k_id}"

                # 6) Przejdź po wszystkich rundach
                for r_opt in comp_soup.select("select[name=Runda] option")[1:]:
                    r_id = r_opt["value"]
                    r_txt = r_opt.get_text(strip=True)

                    # Pobierz stronę danej rundy
                    soup_r = _get_soup(url=comp_url, params={"Runda": r_id})
                    # I wszystkie kolejki w tej rundzie
                    for k_opt in soup_r.select("select[name=Kolejka] option")[1:]:
                        k_id = k_opt["value"]
                        k_txt = k_opt.get_text(strip=True)

                        # Pobierz meczową tabelę dla danej kolejki
                        soup_k = _get_soup(url=comp_url, params={"Runda": r_id, "Kolejka": k_id})
                        tbl = soup_k.find("table", id="prevMatchTable")
                        if not tbl:
                            continue

                        # Parsuj każdy wiersz z meczem
                        for tr in tbl.find_all("tr")[1:]:
                            if tr.find("td"):
                                match = _parse_match_row(tr)
                                info["rounds"][r_txt][k_txt].append(match)

    return data


@router.get(
    "/{season_id}",
    summary="Zwraca wszystkie mecze podzielone na województwa → kategorie → rozgrywki → rundy → kolejki (plus debugowe first_link)",
)
def matches(season_id: int):
    try:
        tree = get_all_matches(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania danych z zewnętrznego serwisu: {e}")
    return {"season": season_id, "matches": tree}
