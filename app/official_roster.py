"""
Klucz osoby (imię i nazwisko bez ogonków, tokeny posortowane) oraz JEDNORAZOWY
stan początkowy statusu „nieaktywny w okręgu”.

Od 03.11.2026 lista aktywnych NIE steruje już niczym na żywo: status
nieaktywnego sędziego leży w bazie (`province_judge_inactive`, trasy
`/province-judges/status`, reguły w `app/province_judge_status_rules.py`).
`SLASKIE_2026_27` służy wyłącznie do jednorazowego wczytania stanu
początkowego dla Śląskiego (`province_judge_status.ensure_seed`).

MODUŁ-LIŚĆ: bez bazy i bez sieci.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Tuple

SLASKIE_2026_27: Tuple[str, ...] = (
    "Anders Magdalena",
    "Bejnar Szymon",
    "Bloch Wojciech",
    "Boczek Michał",
    "Brehmer Joanna",
    "Dera Oliwia",
    "Drab Krzysztof",
    "Dymitruk Adrian",
    "Fabryczny Michał",
    "Gajos Janusz",
    "Gembus Kamil",
    "Góralczyk Marek",
    "Jędrycha Artur",
    "Kasznia Wojciech",
    "Kopiec Michał",
    "Krawczyk Rafał",
    "Krochmal Adam",
    "Kurasz Julia",
    "Kwiatoń Amelia",
    "Leszczyniak Dawid",
    "Łuszczykiewicz Maksymilian",
    "Majka Marek",
    "Musialik Paweł",
    "Pazur Leszek",
    "Pazur Mirosław",
    "Pestka Natalia",
    "Polczak Joanna",
    "Poloczek Kamil",
    "Pytlik Aleksandra",
    "Pytlik Krzysztof",
    "Pytlik Marcin",
    "Rawicki Jakub",
    "Schiwon Grzegorz",
    "Skowronek Agnieszka",
    "Solecki Michał",
    "Swadek Marcin",
    "Szostok Marcin",
    "Szulc Nicole",
    "Tomecka Wiktoria",
    "Uryga Jacek",
    "Urzyński Patryk",
    "Wiąckiewicz Łukasz",
    "Więcław Wiktoria",
    "Winkler Marceli",
    "Witkowicz Krzysztof",
    "Witkowicz Radosław",
    "Wojtyczka Grzegorz",
    "Wojtyczka Karol",
    "Woźniakowska Natalia",
    "Ziemiański Łukasz",
    "Zubek Artur",
    "Zubek Marcin",
)


# Wykaz KS DZPR 2026/27 (sekcje SĘDZIOWIE i DELEGACI) z dawnego BAZA_web/utils/officialDirectory.ts.
DOLNOSLASKIE_2026_27: Tuple[str, ...] = (
    "Afanasyeva Yaroslava",
    "Augustyniak Natalia",
    "Berezewski Adrian",
    "Białogrecka Basia",
    "Burchała-Stachurski Mikołaj",
    "Celoch Dawid",
    "Chmielowski Kamil",
    "Cieślik Karolina",
    "Dąbrowski Piotr",
    "Dec Dawid",
    "Domański Paweł",
    "Fahner Filip",
    "Gabrysz Mikołaj",
    "Gdakowicz Krzysztof",
    "Glinka Paweł",
    "Głuszek Wojciech",
    "Gołąbek Tomasz",
    "Habierski Korneliusz",
    "Herbut Daria",
    "Jankowicz Joanna",
    "Jaworski Kacper",
    "Kiedrzyński Dawid",
    "Kosmala Mateusz",
    "Krzykawski Damian",
    "Kubicki Mateusz",
    "Kubis Łukasz",
    "Kubisiewicz Martyna",
    "Kuczyński Marcin",
    "Latko Kacper",
    "Lipka Artur",
    "Liśkiewicz Sonia",
    "Mikołajów Marcin",
    "Padula Julia",
    "Parkitny Adam",
    "Pikus Olga",
    "Pisarek Kacper",
    "Prokopieva Yelyzaveta",
    "Radjusz Wojciech",
    "Rożek Franciszek",
    "Skrobak Grzegorz",
    "Sobolewski Gracjan",
    "Sosnowski Jakub",
    "Sulisz Mikołaj",
    "Szczypka Emilia",
    "Szkwarek Amelia",
    "Walczak Marcin",
    "Zając Karol",
    "Zając Karol Jr",
    "Załęczny Adrian",
    "Ziablicki Tomasz",
    "Christ Grzegorz",
    "Christ Tomasz",
    "Jaworski Andrzej",
    "Mikołajczak Andrzej",
    "Pisarek Tomasz",
    "Stężowski Przemysław",
)

# Zapisy z baza.zprp.pl różniące się od wykazu (ta sama osoba).
DOLNOSLASKIE_2026_27_ALIASES: Tuple[str, ...] = (
    "Zając Karol R",
    "Białogrecka Barbara",
)


def fold(value: Any) -> str:
    """Jak `fold` w `officialDirectory.ts`: bez numeracji „1)", bez ogonków, wielkie litery."""
    text = re.sub(r"\d*\)\s*", "", str(value if value is not None else ""))
    text = text.replace("ł", "L").replace("Ł", "L")
    text = "".join(ch for ch in unicodedata.normalize("NFD", text) if not unicodedata.combining(ch))
    return re.sub(r"[^a-zA-Z0-9]+", " ", text).strip().upper()


def person_key(name: Any) -> str:
    return "|".join(sorted(part for part in fold(name).split() if part))
