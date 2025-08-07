import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib.parse import urljoin, parse_qs, urlparse
from fastapi import APIRouter, HTTPException

BASE_URL = "https://rozgrywki.zprp.pl/"

router = APIRouter(prefix="/matches", tags=["matches"])


def _get_soup(url, params=None):
    """Pobiera stronę i zwraca BeautifulSoup."""
    r = requests.get(url, params=params or {}, timeout=10)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")


def _parse_match_row(tr):
    """Parsuje pojedynczy wiersz meczu."""
    tds = tr.find_all("td")
    header = tds[0].get_text(" ", strip=True).split()
    match_id = header[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=True)["href"])
    date = " ".join(header[-2:])
    place = tds[-1].find("small").get_text(strip=True)
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
    referees = sedzia_tbl.find(
        "td", style=lambda v: v and "text-align:center" in v
    ).get_text(strip=True)
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
    # 1) Strona główna z menu "Rozgrywki"
    root = _get_soup(BASE_URL, params={"Sezon": season_id})
    rozgrywki_root = root.select_one("#main-nav .menu > li:has(> a[href='#']:contains('Rozgrywki'))")
    if not rozgrywki_root:
        raise HTTPException(500, "Nie znaleziono sekcji Rozgrywki")

    data = {}
    # 2) Województwa
    for woj_li in rozgrywki_root.select("ul.sub-menu > li"):
        woj_name = woj_li.a.get_text(strip=True)
        data[woj_name] = {}

        # 3) Kobiety/Mężczyźni
        for cat_li in woj_li.select("ul.sub-menu > li"):
            cat_label = cat_li.a.get_text(strip=True).upper()
            cat_key = "Kobiety" if "KOBIETY" in cat_label else "Mężczyźni"
            data[woj_name][cat_key] = {}

            # 4) Poszczególne rozgrywki
            for roz_li in cat_li.select("ul.sub-menu > li"):
                roz_name = roz_li.a.get_text(strip=True)
                href = roz_li.a["href"]
                qs = parse_qs(urlparse(href).query)
                roz_id = qs.get("Rozgrywki", [None])[0]
                if not roz_id:
                    continue

                comp_url = urljoin(BASE_URL, href.split("&Zespoly")[0])
                comp_entry = {
                    "first_links": {},      # tu będziemy trzymać pierwszy link dla każdej rundy
                    "rounds": defaultdict(dict)
                }
                data[woj_name][cat_key][roz_name] = comp_entry

                # 5) Pobieramy submenu "TERMINARZ" z gotowymi linkami do rund
                comp_soup = _get_soup(comp_url)
                term_li = comp_soup.select_one("li#menu-item-5 ul.sub-menu")
                if term_li:
                    for li in term_li.find_all("li", recursive=False):
                        a = li.find("a", href=True)
                        label = a.get_text(strip=True)  # np. "I runda", "II runda"
                        raw_qs = parse_qs(a["href"].lstrip("?"))
                        # składamy pełny URL do pierwszej kolejki tej rundy
                        first_link = urljoin(
                            BASE_URL,
                            f"?Sezon={raw_qs['Sezon'][0]}"
                            f"&Rozgrywki={raw_qs['Rozgrywki'][0]}"
                            f"&Runda={raw_qs['Runda'][0]}"
                            f"&Kolejka={raw_qs['Kolejka'][0]}"
                        )
                        comp_entry["first_links"][label] = first_link

                # 6) Dla każdej rundy: wchodzimy na jej first_link, pobieramy listę wszystkich kolejek i parsujemy je
                for round_label, first_link in comp_entry["first_links"].items():
                    rsoup = _get_soup(first_link)
                    # szukamy menu kolejek
                    menu2 = rsoup.select_one("#main-nav2 ul.sub-menu")
                    if not menu2:
                        continue
                    for q_li in menu2.find_all("li", recursive=False):
                        qa = q_li.find("a", href=True)
                        qlabel = qa.get_text(" ", strip=True).split()[0]  # "Kolejka 1", "Kolejka 2"...
                        q_qs = parse_qs(qa["href"].lstrip("?"))
                        queue_link = urljoin(
                            BASE_URL,
                            f"?Sezon={q_qs['Sezon'][0]}"
                            f"&Rozgrywki={q_qs['Rozgrywki'][0]}"
                            f"&Runda={q_qs['Runda'][0]}"
                            f"&Kolejka={q_qs['Kolejka'][0]}"
                        )
                        # parsujemy wszystkie mecze z tej kolejki
                        ksoup = _get_soup(queue_link)
                        table = ksoup.find("table", id="prevMatchTable")
                        matches = []
                        if table:
                            for tr in table.find_all("tr"):
                                tds = tr.find_all("td")
                                # tylko prawdziwe wiersze z linkiem do meczu
                                mecz_link = tr.find("a", href=lambda h: h and "Mecz=" in h)
                                if not tds or not mecz_link:
                                    continue
                                matches.append(_parse_match_row(tr))
                        comp_entry["rounds"].setdefault(round_label, {})[qlabel] = matches

    return data


@router.get(
    "/{season_id}",
    summary="Zwraca wszystkie mecze podzielone na województwa → kategorie → rozgrywki → rundy → kolejki (plus first_links dla rund)",
)
def matches(season_id: int):
    try:
        tree = get_all_matches(season_id)
    except requests.HTTPError as e:
        raise HTTPException(502, f"Błąd podczas pobierania danych z zewnętrznego serwisu: {e}")
    return {"season": season_id, "matches": tree}
