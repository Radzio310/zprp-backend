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

def _parse_match_row(tr):
    tds = tr.find_all("td")
    header = tds[0].get_text(" ", strip=True).split()
    match_id = header[0]
    detail_link = urljoin(BASE_URL, tr.find("a", href=lambda h: h and "Mecz=" in h)["href"])
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

        for cat_li in woj_li.find("ul", class_="sub-menu").find_all("li", recursive=False):
            cat_label = cat_li.a.get_text(strip=True).upper()
            cat_key = "Kobiety" if "KOBIETY" in cat_label else "Mężczyźni"
            data[woj_name][cat_key] = {}

            for roz_li in cat_li.find("ul", class_="sub-menu").find_all("li", recursive=False):
                roz_name = roz_li.a.get_text(strip=True)
                href = roz_li.a["href"]
                roz_qs = parse_qs(urlparse(href).query)
                roz_id = roz_qs.get("Rozgrywki", [None])[0]
                if not roz_id:
                    continue

                # URL rozgrywek bez parametru Zespoly
                comp_url = _strip_zespoly(urljoin(BASE_URL, href))

                # 2) Zbierz gotowe linki do rund (TERMINARZ)
                comp_soup = _get_soup(url=comp_url)
                terminarz = comp_soup.select_one("#menu-item-5 ul.sub-menu")
                first_links = {}
                if terminarz:
                    for li in terminarz.find_all("li", recursive=False):
                        a = li.find("a", href=True)
                        qs = parse_qs(a["href"].lstrip("?"))
                        first_links[a.get_text(strip=True)] = urljoin(
                            BASE_URL,
                            f"?Sezon={qs['Sezon'][0]}"
                            f"&Rozgrywki={qs['Rozgrywki'][0]}"
                            f"&Runda={qs['Runda'][0]}"
                            f"&Kolejka={qs['Kolejka'][0]}"
                        )

                # Inicjalizacja
                data[woj_name][cat_key][roz_name] = {
                    "first_links": first_links,
                    "rounds": defaultdict(dict)
                }

                # 3) Dla każdej rundy: wejdź w pierwszy link i zbierz wszystkie kolejki
                for round_label, first_link in first_links.items():
                    rsoup = _get_soup(url=first_link)
                    menu2 = rsoup.select_one("#main-nav2 ul.sub-menu")
                    if not menu2:
                        continue

                    for q_li in menu2.find_all("li", recursive=False):
                        qa = q_li.find("a", href=True)
                        qlabel = qa.get_text(" ", strip=True).split()[0]
                        q_qs = parse_qs(qa["href"].lstrip("?"))
                        queue_link = urljoin(
                            BASE_URL,
                            f"?Sezon={q_qs['Sezon'][0]}"
                            f"&Rozgrywki={q_qs['Rozgrywki'][0]}"
                            f"&Runda={q_qs['Runda'][0]}"
                            f"&Kolejka={q_qs['Kolejka'][0]}"
                        )

                        # 4) Parsuj tabelę meczów
                        ksoup = _get_soup(url=queue_link)
                        table = ksoup.find("table", id="prevMatchTable")
                        matches = []
                        if table:
                            for tr in table.find_all("tr"):
                                if not tr.find("a", href=lambda h: h and "Mecz=" in h):
                                    continue
                                tds = tr.find_all("td")
                                if len(tds) < 7:
                                    continue
                                try:
                                    matches.append(_parse_match_row(tr))
                                except Exception:
                                    continue

                        data[woj_name][cat_key][roz_name]["rounds"][round_label][qlabel] = matches

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
