"""
Zakres listy obsadowego: sezon, II liga, termin i kolejka meczu.

JEDNA reguła dla listy meczów (`province_assignments`) i automatu
(`province_assignment_auto`). Gdyby każde z nich liczyło sezon po swojemu,
automat układałby mecze, których obsadowy na liście w ogóle nie widzi.

SEZON MECZU (decyzje użytkownika z 16.09.2026). Migawka okręgu trzyma nie tylko
bieżący sezon - wiersze bez terminu wiszą w niej latami (mecze 113xxx z sezonów
sprzed lat trafiały na listę „do obsadzenia"). Sezon rozstrzygamy w kolejności:

  1. `ID_sezon` z publicznego API meczu, przeliczony na rok PRZEZ KATALOG
     `pokaz_sezony.php`. ⚠ Numer NIE rośnie o jeden na rok: 185 to 2017/2018,
     a 195 to 2026/2027, bo 189 nie istnieje. Odejmowanie dałoby zły sezon.
  2. etykieta sezonu z terminarza albo listy sędziego („2026/2027"),
  3. kolumna `province_matches.season`,
  4. data meczu - reguła sierpniowa z `app/season_rules.py`.

Czego nie da się ustalić, zostaje `None`. Lista takiego meczu NIE pokazuje, ale
go liczy i mówi o tym wprost - nic nie znika po cichu.

BIEŻĄCY SEZON to późniejszy z dwóch: oznaczony przez związek (`Stan=1`) i
wynikający z dzisiejszej daty. Związek potrafi otworzyć nowy sezon w lipcu -
wtedy wygrywa on; gdyby zapomniał przestawić znacznik, wygrywa kalendarz.

II LIGA. Obsady II ligi ustala związek, więc okręgowi jej nie podsuwamy -
domyślnie znika z listy i z automatu. Zasady powierzenia grup okręgom
(`is_managed_by_province`) zostają bez zmian: to, CZY okręg może obsadzić
mecz, i to, czy chce go dziś widzieć, to dwie różne rzeczy.

MODUŁ-LIŚĆ: bez bazy i bez sieci, żeby reguła miała test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, Iterable, Optional

from app.match_market_rules import league_level
from app.season_rules import season_label_full, season_label_short, season_start_year
from app.settlement_seasons import normalize_season_label

#: Katalog `pokaz_sezony.php` z 16.09.2026. Zapas na chwilę, gdy API związku
#: nie odpowiada - numery sezonów się nie zmieniają, a bez tej tabeli każdy mecz
#: znany tylko po `ID_sezon` wypadałby wtedy do „sezonu nieznanego".
KNOWN_SEASON_IDS: Dict[str, int] = {
    "41": 2007,
    "42": 2008,
    "61": 2009,
    "81": 2010,
    "82": 2011,
    "102": 2012,
    "104": 2013,
    "147": 2014,
    "164": 2015,
    "184": 2016,
    "185": 2017,
    "186": 2018,
    "187": 2019,
    "188": 2020,
    "190": 2021,
    "191": 2022,
    "192": 2023,
    "193": 2024,
    "194": 2025,
    "195": 2026,
}

#: Tryby terminu: tylko z datą, wszystkie, tylko bez daty.
WHEN_DATED = "dated"
WHEN_ALL = "all"
WHEN_UNDATED = "undated"
WHEN_MODES = (WHEN_DATED, WHEN_ALL, WHEN_UNDATED)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _year(value: Any) -> Optional[int]:
    text = _s(value)
    if not re.fullmatch(r"\d{4}", text):
        return None
    year = int(text)
    # Rok 1900 albo 2400 to nie sezon, tylko przypadkowa liczba w polu.
    return year if 2000 <= year <= 2100 else None


@dataclass(frozen=True)
class Season:
    #: `ID_sezon` związku; pusty, gdy sezon znamy tylko z kalendarza.
    id: str
    #: Rok początku („2026" dla 2026/2027) - po nim porównujemy mecze.
    start: int
    #: Znacznik `Stan=1` z katalogu związku.
    flagged: bool = False

    @property
    def label(self) -> str:
        return season_label_full(self.start)

    @property
    def short(self) -> str:
        return season_label_short(self.start)


def season_catalog(rows: Any) -> Dict[str, Season]:
    """`ID_sezon` -> sezon: odpowiedź `pokaz_sezony.php` nałożona na zapas.

    API oddaje słownik wierszy albo listę - przyjmujemy oba kształty. Wiersz
    bez numeru albo roku odpada; rok bierzemy z `Rok_rozpoczecia`, a gdy go
    brak - z nazwy („2026/2027").
    """
    out: Dict[str, Season] = {
        sid: Season(id=sid, start=start) for sid, start in KNOWN_SEASON_IDS.items()
    }
    if isinstance(rows, dict):
        items: Iterable[Any] = rows.values()
    elif isinstance(rows, list):
        items = rows
    else:
        items = []
    for row in items:
        if isinstance(row, list):
            # Pojedynczy wiersz bywa owinięty w listę, jak w innych odpowiedziach API.
            row = row[0] if row and isinstance(row[0], dict) else None
        if not isinstance(row, dict):
            continue
        sid = _s(row.get("ID_sezon"))
        start = _year(row.get("Rok_rozpoczecia")) or label_start(row.get("Nazwa"))
        if not sid or start is None:
            continue
        out[sid] = Season(id=sid, start=start, flagged=_s(row.get("Stan")) == "1")
    return out


def label_start(value: Any) -> Optional[int]:
    """Rok początku z etykiety sezonu („2026/2027", „2026/27"). Inaczej `None`."""
    label = normalize_season_label(value)
    return int(label[:4]) if label else None


def current_start(catalog: Dict[str, Season], today: date) -> int:
    """Rok początku bieżącego sezonu - patrz nagłówek modułu."""
    by_date = season_start_year(today)
    flagged = [season.start for season in catalog.values() if season.flagged]
    candidates = [year for year in (max(flagged) if flagged else None, by_date) if year is not None]
    return max(candidates)


def season_for_start(catalog: Dict[str, Season], start: int) -> Season:
    """Sezon o danym roku początku; bez wpisu w katalogu - sam rok."""
    hits = [season for season in catalog.values() if season.start == start]
    if not hits:
        return Season(id="", start=start)
    # Dwa numery na jeden rok się nie zdarzyły, ale gdyby - wygrywa nowszy.
    return max(hits, key=lambda season: int(season.id) if season.id.isdigit() else -1)


def match_season_start(
    state: Dict[str, Any],
    *,
    catalog: Dict[str, Season],
    column: Any = None,
    match_at: Optional[datetime] = None,
) -> Optional[int]:
    """Rok początku sezonu meczu albo `None`, gdy nie da się go ustalić."""
    sid = _s(state.get("ID_sezon"))
    if sid and sid in catalog:
        return catalog[sid].start
    for label in (state.get("season"), column):
        start = label_start(label)
        if start is not None:
            return start
    return season_start_year(match_at)


def is_league(code: Any) -> bool:
    """Mecz ligi, którą obsadza związek (II liga, a gdyby okręgowi powierzono
    coś wyżej - także to). Rozgrywki okręgowe i puchar województwa to `False`."""
    return league_level(code) != "okreg"


def normalize_when(value: Any, legacy_undated: Optional[bool] = None) -> str:
    """Tryb terminu z parametru; starszy panel wysyłał samo `undated`."""
    text = _s(value).lower()
    if text in WHEN_MODES:
        return text
    if legacy_undated is False:
        return WHEN_DATED
    return WHEN_ALL


def when_allows(mode: str, has_date: bool) -> bool:
    if mode == WHEN_DATED:
        return has_date
    if mode == WHEN_UNDATED:
        return not has_date
    return True


_NUMBER_RE = re.compile(r"(\d+)")
_DATE_RANGE_RE = re.compile(r"\d{1,2}\.\d{1,2}\.\d{4}")


def round_info(state: Dict[str, Any]) -> Dict[str, Any]:
    """Runda i kolejka meczu z danych związku.

    Monitor zapisuje w migawce dwa źródła naraz i oba są potrzebne:
      - API meczu: `Runda` („Runda I") i `Kolejka` („Kolejka 3", „Seria 1",
        „1/2 finału"),
      - terminarz: `kolejka_no` (3) i `kolejka` - ⚠ tu to ZAKRES DAT kolejki
        („03 - 04.10.2026"), a nie jej nazwa.

    Numer kolejki powtarza się w kolejnych rundach, więc klucz grupy to
    runda + kolejka. Bez kolejki klucz jest pusty - mecz trafia do grupy
    „bez kolejki", zamiast udawać, że należy do którejś.
    """
    phase = _s(state.get("Runda") or state.get("runda"))
    series = _s(state.get("Kolejka"))
    raw_range = _s(state.get("kolejka"))
    span = raw_range if _DATE_RANGE_RE.search(raw_range) else ""
    if not series and raw_range and not span:
        # Starsze wiersze trzymają nazwę kolejki małą literą.
        series = raw_range

    number: Optional[int] = None
    try:
        number = int(state.get("kolejka_no")) if _s(state.get("kolejka_no")) else None
    except (TypeError, ValueError):
        number = None
    if number is None and series:
        # Tylko „Kolejka 3" / „Seria 3". „1/2 finału" numeru kolejki nie ma.
        found = re.fullmatch(r"(?:kolejka|seria)\s+(\d+)", series, re.I)
        number = int(found.group(1)) if found else None
    if not series and number is not None:
        series = f"Kolejka {number}"

    key = f"{phase}|{series}".lower() if series else ""
    return {
        "key": key,
        "phase": phase,
        "name": series,
        "no": number,
        "span": span,
    }
