"""
Rozbior stron „Rozgrywki" i „Druzyny" z baza.zprp.pl.

Panel klubow potrzebuje drzewa: SEZON -> ROZGRYWKI -> DRUZYNY -> KLUB. ZPRP nie
ma na to API, ale obie strony niosa komplet identyfikatorow:

  - lista rozgrywek: numer rozgrywek w `title` komorki Lp oraz w odsylaczu
    „Druzyny" (`IdRozgr`), do tego kod (`IIK4`, `S/JmM`), plec, kategoria, typ,
    stan i liczba zgloszonych druzyn,
  - lista druzyn: `Filtr_zespol` (druzyna), `NrKlubu` (klub) i wojewodztwo
    w nawiasie przy nazwie.

MODUL-LISC: sam rozbior HTML, bez sieci i bazy - dzieki temu caly parser chodzi
w tescie na prawdziwych stronach zapisanych w `tests/fixtures`.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

#: Nazwa druzyny konczy sie skrotem wojewodztwa w nawiasie: „... (SL)".
_PROVINCE_SUFFIX = re.compile(r"\(([A-ZĄĆĘŁŃÓŚŹŻ]{2,4})\)\s*$")


def _text(node: Any) -> str:
    return re.sub(r"\s+", " ", node.get_text(" ", strip=True)) if node else ""


def _param(href: str, name: str) -> str:
    """Wartosc parametru z odsylacza, takze gdy href zaczyna sie od „?"."""
    query = urlparse(str(href or "").replace("&amp;", "&")).query
    values = parse_qs(query).get(name) or []
    return str(values[0]).strip() if values else ""


def team_key(name: Any) -> str:
    """
    Klucz porownania nazw druzyn.

    Mecze w naszej bazie niosa tylko NAZWY druzyn, bez identyfikatorow, wiec
    obciazenie trafia do druzyny po nazwie. Ujednolicamy wielkosc liter, ogonki
    i odstepy, a skrot wojewodztwa w nawiasie schodzi - ale CYFRY I LICZEBNIKI
    ZOSTAJA, bo „Sosnica" i „Sosnica II" to dwie rozne druzyny.
    """
    text = str(name or "")
    text = _PROVINCE_SUFFIX.sub(" ", text)
    text = text.replace("Ł", "L").replace("ł", "l")
    text = "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )
    text = text.lower().replace(".", " ")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split()).strip()


@dataclass
class SeasonOption:
    """Pozycja z listy sezonow (`Filtr_sezon`)."""

    id: str
    label: str
    selected: bool = False


@dataclass
class Competition:
    """Jedne rozgrywki w sezonie."""

    id: str
    name: str
    gender: str = ""
    category: str = ""
    province: str = ""
    code: str = ""
    kind: str = ""
    season_label: str = ""
    state: str = ""
    teams_required: Optional[int] = None
    teams_registered: Optional[int] = None
    teams_path: str = ""


@dataclass
class Team:
    """Druzyna zgloszona do rozgrywek."""

    team_id: str
    name: str
    province: str = ""
    club_id: str = ""
    key: str = field(default="")

    def __post_init__(self) -> None:
        if not self.key:
            self.key = team_key(self.name)


def parse_seasons(html: str) -> list[SeasonOption]:
    """Lista sezonow z `select[name=Filtr_sezon]`, w kolejnosci ze strony."""
    soup = BeautifulSoup(html or "", "html.parser")
    select = soup.find("select", attrs={"name": "Filtr_sezon"})
    if not select:
        return []
    out: list[SeasonOption] = []
    for option in select.find_all("option"):
        value = str(option.get("value") or "").strip()
        if not value:
            continue
        out.append(
            SeasonOption(
                id=value,
                label=_text(option),
                selected=option.has_attr("selected"),
            )
        )
    return out


def parse_selected_province(html: str) -> str:
    """
    Numer wojewodztwa zaznaczony w filtrze - konto komisyjne ma tam swoj okreg.

    Bierzemy go ze strony, zamiast trzymac wlasna mape wojewodztw: numeracja
    ZPRP nie jest ciagla (19 = DOR, 20 = DRK) i nie mamy jej skad potwierdzic.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    for select in soup.find_all("select", attrs={"name": "Filtr_woj"}):
        option = select.find("option", selected=True)
        if option is not None and str(option.get("value") or "").strip():
            return str(option.get("value")).strip()
    return ""


def _int_or_none(value: str) -> Optional[int]:
    text = re.sub(r"[^\d-]", "", str(value or ""))
    try:
        return int(text)
    except ValueError:
        return None


def parse_competitions(html: str) -> list[Competition]:
    """
    Rozgrywki z zakladki „Rozgrywki".

    Wiersz rozpoznajemy po odsylaczu „Druzyny" (`b=zespoly` z `IdRozgr`) - to
    jedyna kolumna, ktora ma go zawsze, a przy okazji daje gotowa sciezke do
    listy druzyn.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    out: list[Competition] = []
    seen: set[str] = set()

    for row in soup.find_all("tr"):
        # ⚠ Strona jest zbudowana z tabel w tabelach, wiec `find_all("tr")`
        # zwraca tez wiersze UKLADU, ktore zawieraja w sobie cala tabele danych
        # (i wszystkie jej odsylacze). Bez tego odsiewu pierwszym „wierszem
        # rozgrywek" bywal wiersz strony: numer z pierwszego odsylacza, a nazwa
        # i kategoria puste.
        if row.find("table") is not None:
            continue
        link = None
        for candidate in row.find_all("a", href=True):
            href = str(candidate["href"]).replace("&amp;", "&")
            if "b=zespoly" in href and _param(href, "IdRozgr"):
                link = candidate
                break
        if link is None:
            continue

        href = str(link["href"]).replace("&amp;", "&")
        competition_id = _param(href, "IdRozgr")
        if not competition_id or competition_id in seen:
            continue

        cells = row.find_all("td", recursive=False) or row.find_all("td")
        values = [_text(cell) for cell in cells]

        def cell(index: int) -> str:
            return values[index] if index < len(values) else ""

        seen.add(competition_id)
        out.append(
            Competition(
                id=competition_id,
                name=cell(1),
                gender=cell(2),
                category=cell(3),
                province=cell(4),
                code=cell(5),
                kind=cell(6),
                season_label=cell(7),
                state=cell(8),
                teams_required=_int_or_none(cell(10)),
                teams_registered=_int_or_none(cell(11)),
                teams_path=href,
            )
        )
    return out


def parse_teams(html: str) -> list[Team]:
    """
    Druzyny UCZESTNICZACE w rozgrywkach (lewa tabela).

    ⚠ Po prawej stoi druga tabela - „druzyny spelniajace kryteria", czyli te,
    ktore MOGLYBY zagrac. Ma te same odsylacze do skladow, wiec bez rozroznienia
    wpadlyby do panelu kluby, ktore z okregiem nie graja. Rozroznia je odsylacz
    do PDF ze skladem (`zespoly_PDF.php`), ktory ma tylko lewa tabela.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    out: list[Team] = []
    seen: set[str] = set()

    for row in soup.find_all("tr"):
        # ⚠ Strona jest zbudowana z tabel w tabelach, wiec `find_all("tr")`
        # zwraca tez wiersze UKLADU, ktore zawieraja w sobie cala tabele danych
        # (i wszystkie jej odsylacze). Bez tego odsiewu pierwszym „wierszem
        # rozgrywek" bywal wiersz strony: numer z pierwszego odsylacza, a nazwa
        # i kategoria puste.
        if row.find("table") is not None:
            continue
        if not row.find("a", href=re.compile(r"zespoly_PDF\.php")):
            continue

        team_link = None
        club_id = ""
        for candidate in row.find_all("a", href=True):
            href = str(candidate["href"]).replace("&amp;", "&")
            if not team_link and _param(href, "Filtr_zespol"):
                team_link = candidate
            if not club_id:
                club_id = _param(href, "NrKlubu")
        if team_link is None:
            continue

        team_id = _param(str(team_link["href"]).replace("&amp;", "&"), "Filtr_zespol")
        if not team_id or team_id in seen:
            continue
        raw_name = _text(team_link)
        province_match = _PROVINCE_SUFFIX.search(raw_name)
        name = _PROVINCE_SUFFIX.sub("", raw_name).strip()
        seen.add(team_id)
        out.append(
            Team(
                team_id=team_id,
                name=name,
                province=province_match.group(1) if province_match else "",
                club_id=club_id,
            )
        )
    return out


def club_display_name(names: list[str]) -> str:
    """
    Nazwa klubu z nazw jego druzyn - do czasu, az ktos ja w panelu poprawi.

    Klub nie ma na tych stronach wlasnej nazwy, jest tylko numer. Bierzemy wiec
    najkrotsza nazwe druzyny (zwykle pierwszy zespol, bez „II" i „III"), a przy
    remisie pierwsza alfabetycznie - zeby wynik nie zalezal od kolejnosci
    pobierania.
    """
    cleaned = [re.sub(r"\s+", " ", str(name or "")).strip() for name in names]
    cleaned = [name for name in cleaned if name]
    if not cleaned:
        return ""
    return sorted(cleaned, key=lambda name: (len(name), name))[0]
