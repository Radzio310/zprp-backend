"""
Aktywni sędziowie okręgu w sezonie - lista z baza.zprp.pl.

Bliźniak `BAZA_web/utils/officialDirectory.ts` (`isSeasonActive`): ta sama
lista i ten sam klucz osoby. W BAZA_web chowa nieaktywnych na liście sędziów
okręgowych, w obsadach i w rozliczeniach; tutaj (decyzja z 17.09.2026)
zdejmuje ich z adresatów wydarzeń okręgowych - z licznika „trafi do N
sędziów", z pushy i przypomnień. Przy zmianie listy trzeba poprawić OBA pliki.

Zasady:
  * lista obowiązuje w SWOIM sezonie (granica sierpniowa, `season_rules`).
    Wydarzenie z sezonu bez listy - albo z okręgu bez listy - idzie do
    wszystkich jak dawniej, więc minione sezony nie tracą zaproszonych,
    a frekwencja sprzed listy się nie zmienia,
  * osoba = imię i nazwisko bez znaków diakrytycznych, w dowolnej kolejności
    („WITKOWICZ Radosław" = „Witkowicz Radosław"),
  * ręczne dopisanie osoby w wydarzeniu wygrywa z listą - komisja może zaprosić
    kogoś spoza niej świadomie.

MODUŁ-LIŚĆ: bez bazy i bez sieci.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from app.season_rules import season_start_year

try:  # pragma: no cover - strefa jest na serwerze
    from zoneinfo import ZoneInfo

    _WARSAW = ZoneInfo("Europe/Warsaw")
except Exception:  # noqa: BLE001
    _WARSAW = None

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


def fold(value: Any) -> str:
    """Jak `fold` w `officialDirectory.ts`: bez numeracji „1)", bez ogonków, wielkie litery."""
    text = re.sub(r"\d*\)\s*", "", str(value if value is not None else ""))
    text = text.replace("ł", "L").replace("Ł", "L")
    text = "".join(ch for ch in unicodedata.normalize("NFD", text) if not unicodedata.combining(ch))
    return re.sub(r"[^a-zA-Z0-9]+", " ", text).strip().upper()


def person_key(name: Any) -> str:
    return "|".join(sorted(part for part in fold(name).split() if part))


#: (okręg bez znaków, rok startu sezonu) -> klucze osób.
ROSTERS: Dict[Tuple[str, int], frozenset] = {
    ("SLASKIE", 2026): frozenset(person_key(name) for name in SLASKIE_2026_27),
}


def season_of(when: Any) -> Optional[int]:
    """Sezon daty wydarzenia liczony w czasie polskim (31.07 23:30 UTC to już sierpień)."""
    if isinstance(when, datetime):
        if when.tzinfo is not None and _WARSAW is not None:
            when = when.astimezone(_WARSAW)
        return season_start_year(when)
    if isinstance(when, date):
        return season_start_year(when)
    return None


def roster_for(province: Any, when: Any) -> Optional[frozenset]:
    season = season_of(when)
    return ROSTERS.get((fold(province), season)) if season is not None else None


def is_active(province: Any, when: Any, name: Any) -> bool:
    """Bez listy dla okręgu i sezonu każdy jest aktywny."""
    roster = roster_for(province, when)
    return True if roster is None else person_key(name) in roster


def inactive_ids(province: Any, when: Any, judges: Iterable[Mapping[str, Any]]) -> Set[str]:
    """Numery sędziów spoza listy aktywnych okręgu w sezonie wydarzenia."""
    roster = roster_for(province, when)
    if roster is None:
        return set()
    out: Set[str] = set()
    for judge in judges:
        jid = str(judge.get("judge_id") or "").strip()
        if jid and person_key(judge.get("full_name")) not in roster:
            out.add(jid)
    return out


def inactive_seasons(province: Any, name: Any) -> List[int]:
    """Sezony z listą dla okręgu, w których tej osoby na liście nie ma (dla aplikacji)."""
    key, prov = person_key(name), fold(province)
    return sorted(season for (p, season), roster in ROSTERS.items() if p == prov and key not in roster)
