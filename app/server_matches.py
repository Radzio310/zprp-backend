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

                data[woj_name][cat_key][roz_name] = {
                    "first_links": first_links
                }

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
