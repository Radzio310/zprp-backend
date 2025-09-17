from typing import List, Tuple
from bs4 import BeautifulSoup

def _row_to_player(tr) -> dict | None:
    """
    Wyciąga {number, full_name, photo_url} z pojedynczego wiersza <tr>.
    Zwraca None, jeśli wiersz nie zawiera pełnych danych zawodnika.
    """
    if tr is None:
        return None

    # numer koszulki (w wierszu jest <div id="circle2">NN</div>)
    num_div = tr.select_one("div#circle2")
    if not num_div:
        return None
    num_txt = "".join(num_div.stripped_strings)
    if not num_txt.isdigit():
        return None

    # zdjęcie + pełne imię+nazwisko w alt
    img = tr.select_one("img")
    full_name = None
    photo_url = None
    if img:
        full_name = (img.get("alt") or "").strip() or None
        photo_url = (img.get("src") or "").strip() or None

    # alt jest najlepszym źródłem pełnego imienia i nazwiska
    if not full_name:
        return None

    return {
        "number": int(num_txt),
        "full_name": full_name,
        "photo_url": photo_url or None,
    }

def parse_players_from_html(html: str) -> Tuple[List[dict], List[dict]]:
    """
    Przyjmuje pełny HTML strony meczu ZPRP i zwraca (home_players, away_players),
    gdzie każdy element listy to dict {number, full_name, photo_url}.
    """
    soup = BeautifulSoup(html, "lxml")

    # Na stronie są dwie tabele składów, obie mają id="resultsData"
    tables = soup.select("table#resultsData")
    if len(tables) < 2:
        raise ValueError("Nie znaleziono dwóch tabel ze składami (table#resultsData).")

    home_table, away_table = tables[0], tables[1]

    home_players: List[dict] = []
    for tr in home_table.select("tr"):
        p = _row_to_player(tr)
        if p:
            home_players.append(p)

    away_players: List[dict] = []
    for tr in away_table.select("tr"):
        p = _row_to_player(tr)
        if p:
            away_players.append(p)

    return home_players, away_players
