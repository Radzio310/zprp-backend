"""
Analiza obsad - reguły, bez bazy i bez sieci.

Decyzje użytkownika z 16.09.2026 (patrz `app/assignment_insights.py`):
  - statystyka i reguły liczone nocą, bez uczenia maszynowego i bez AI,
  - każda liczba ma prowadzić do listy meczów, z których wyszła,
  - trudność meczu = cztery składniki z wagami do ustawienia suwakami,
  - wnioski tylko się podgląda; obsadowy wybiera, których Automat ma się
    nauczyć, i przy każdym decyduje: punkty albo twarda zasada.

TRUDNOŚĆ MECZU (każdy składnik 0..1, z powodem słowami):
  - `tier`     szczebel i kategoria - ta sama klasyfikacja co Rozliczenia
               (`settlement_rates.category_label`),
  - `stake`    stawka: etap pucharu/baraż, derby (miasto hal obu drużyn), tabela
               liczona z wyników DO DNIA MECZU,
  - `protocol` przebieg z protokołu: wynik na styk, dogrywka/karne, kary 2 min
               względem średniej tych rozgrywek, dyskwalifikacje,
  - `manual`   ręczne oznaczenie obsadowego, a bez niego „Poziom trudności"
               z arkusza delegata.
Brakujący składnik (mecz bez protokołu, bez oceny) nie liczy się jako zero -
wagi pozostałych dzielą się na nowo.

STAWKA I PRZEBIEG WAŻĄ TYLE, ILE POZWALA SZCZEBEL (`scaled_by_tier`). Wynik na
styk i czołówka tabeli u dzieci to nie to samo, co u seniorów - bez tego na
prawdziwych danych Śląska co jedenasty mecz dzieci wychodził „trudny".

„Trudny" to górne `HARD_SHARE` meczów okręgu w wybranym horyzoncie, a nie
sztywny próg - okręg z samymi dziećmi też ma swoje trudne mecze.
"""

from __future__ import annotations

import math
import re
import statistics
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app import settlement_rates as R

DEFAULT_WEIGHTS: Dict[str, int] = {"tier": 35, "stake": 25, "protocol": 25, "manual": 15}
COMPONENTS = ("tier", "stake", "protocol", "manual")
#: Jaka część meczów okręgu to „trudne".
HARD_SHARE = 0.2
#: Dolna granica progu - w bardzo wyrównanym okręgu percentyl potrafi spaść nisko.
HARD_FLOOR = 0.45
#: Waga sezonu: bieżący 1, poprzedni 0.75, dwa wstecz 0.56...
SEASON_DECAY = 0.75
HORIZONS = {"3": 3, "5": 5, "all": None}

ROLE_GROUP = {
    "first": "field",
    "second": "field",
    "secretary": "table",
    "timer": "table",
    "delegate": "delegate",
    "delegate2": "delegate",
}

#: Szczebel i kategoria -> składnik `tier`. Klucz to `category_of`.
TIER: Dict[str, float] = {
    "OSM": 1.0,
    "OSK": 1.0,
    "SM": 1.0,
    "SK": 1.0,
    "LC": 0.92,
    "I liga": 0.88,
    "II liga": 0.8,
    "Puchar Polski / MP": 0.76,
    "Puchar okręgu": 0.7,
    "III liga": 0.7,
    "Junior": 0.55,
    "Junior mł.": 0.45,
    "Młodzik": 0.35,
    "Młodzik mł.": 0.25,
    "Dzieci": 0.15,
}
TIER_OTHER = 0.4

GRADE_POINTS = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def fold(value: Any) -> str:
    text = unicodedata.normalize("NFKD", _s(value).replace("ł", "l").replace("Ł", "L")).lower()
    return "".join(ch for ch in text if not unicodedata.combining(ch))


def team_key(name: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", fold(name)).strip()


# ---------------------------------------------------------------------------
# Składniki trudności
# ---------------------------------------------------------------------------


def category_of(code: Any) -> str:
    """Kategoria do analizy - Rozliczenia plus rozróżnienie pucharów."""
    if R.is_provincial_cup(code):
        return "Puchar okręgu"
    if R.is_cup_competition(code):
        return "Puchar Polski / MP"
    return R.category_label(code)


def tier_component(code: Any) -> Tuple[float, str]:
    category = category_of(code)
    return TIER.get(category, TIER_OTHER), category


_STAGES: Tuple[Tuple[str, float, str], ...] = (
    (r"polfina|1/2", 0.85, "półfinał"),
    (r"cwiercfina|1/4", 0.65, "ćwierćfinał"),
    (r"1/8", 0.45, "1/8 finału"),
    (r"o\s*(3|iii)\.?\s*miejsc", 0.6, "mecz o 3. miejsce"),
    (r"baraz", 0.9, "baraż"),
    (r"play[\s-]*off", 0.7, "play-off"),
    (r"final", 1.0, "finał"),
)


def stage_component(*texts: Any) -> Tuple[float, str]:
    """Etap z nazwy rundy i kolejki („Finał", „1/2 finału", „Baraże")."""
    joined = " ".join(fold(text) for text in texts if _s(text))
    if not joined:
        return 0.0, ""
    for pattern, value, label in _STAGES:
        if re.search(pattern, joined):
            return value, label
    return 0.0, ""


def derby_component(home_city: str, away_city: str) -> Tuple[float, str]:
    a, b = fold(home_city), fold(away_city)
    if a and a == b:
        return 0.65, f"derby: {home_city}"
    return 0.0, ""


def table_component(pos_home: Optional[int], pos_away: Optional[int], teams: int, progress: float) -> Tuple[float, str]:
    """Stawka z tabeli liczonej do dnia meczu."""
    if pos_home is None or pos_away is None or teams < 4 or progress < 0.25:
        return 0.0, ""
    top = min(pos_home, pos_away)
    low = max(pos_home, pos_away)
    value, label = 0.0, ""
    if low <= 2:
        value, label = 0.9, f"mecz o prowadzenie ({pos_home}. z {pos_away}.)"
    elif low <= 3:
        value, label = 0.8, f"czołówka tabeli ({pos_home}. z {pos_away}.)"
    elif top >= teams - 1:
        value, label = 0.5, f"dół tabeli ({pos_home}. z {pos_away}.)"
    elif low - top <= 1 and low <= math.ceil(teams / 2):
        value, label = 0.55, f"sąsiedzi w górnej połowie ({pos_home}. z {pos_away}.)"
    if value and progress >= 0.75:
        value = min(1.0, value * 1.15)
        label += ", końcówka sezonu"
    return value, label


def closeness(margin: int) -> float:
    return {0: 1.0, 1: 0.9, 2: 0.75, 3: 0.55, 4: 0.4}.get(margin, 0.25 if margin <= 6 else 0.1)


def protocol_component(match: Mapping[str, Any], comp_avg_sus: Optional[float]) -> Tuple[Optional[float], List[str]]:
    """Przebieg z protokołu. `None` = mecz bez wyniku (nieodbyty, walkower)."""
    if match.get("walkover") or match.get("withdrawn"):
        return None, []
    gh, ga = match.get("gH"), match.get("gA")
    if gh is None or ga is None:
        return None, []
    why: List[str] = []
    parts: List[Tuple[float, float]] = []

    margin = abs(int(gh) - int(ga))
    close = closeness(margin)
    parts.append((0.4, close))
    if margin <= 2:
        why.append(f"wynik na styk ({gh}:{ga})")

    extra = any(match.get(key) is not None for key in ("otH", "otA", "psH", "psA"))
    parts.append((0.15, 1.0 if extra else 0.0))
    if extra:
        why.append("dogrywka albo rzuty karne")

    roster = match.get("roster") or None
    if roster:
        sus = int(roster.get("susH") or 0) + int(roster.get("susA") or 0)
        if comp_avg_sus:
            ratio = sus / comp_avg_sus
            parts.append((0.25, max(0.0, min(1.0, (ratio - 0.6) / 1.2))))
            if ratio >= 1.4:
                why.append(f"dużo kar 2 min ({sus})")
        red = sum(int(roster.get(key) or 0) for key in ("redH", "redA", "bluH", "bluA"))
        parts.append((0.2, 0.0 if red == 0 else (0.6 if red == 1 else 1.0)))
        if red:
            why.append("dyskwalifikacja" if red == 1 else f"dyskwalifikacje ({red})")

    total = sum(weight for weight, _ in parts)
    return (sum(weight * value for weight, value in parts) / total if total else None), why


_EVAL_DIFFICULTY: Tuple[Tuple[str, float], ...] = (
    ("bardzo trudn", 1.0),
    ("trudn", 0.85),
    ("sredni", 0.5),
    ("latw", 0.15),
)


#: Początek powodu wziętego z arkusza delegata - po nim poznaje go `hide_evaluations`.
DELEGATE_WHY_PREFIX = "delegat: "
#: Ten sam powód dla kogoś, kto ocen delegatów nie widzi: składnik zostaje
#: w trudności meczu, ale bez słów delegata.
DELEGATE_WHY_HIDDEN = "z arkusza delegata"


def evaluation_difficulty(evaluation: Mapping[str, Any]) -> Tuple[Optional[float], str]:
    """„Poziom trudności" z arkusza delegata (`character.difficulty.short`)."""
    character = evaluation.get("character") if isinstance(evaluation, Mapping) else None
    difficulty = (character or {}).get("difficulty") if isinstance(character, Mapping) else None
    short = _s((difficulty or {}).get("short") if isinstance(difficulty, Mapping) else "")
    text = fold(short)
    for key, value in _EVAL_DIFFICULTY:
        if key in text:
            return value, f"{DELEGATE_WHY_PREFIX}{short.lower()}"
    return None, ""


def manual_component(mark: Optional[str], evaluation: Optional[Tuple[Optional[float], str]]) -> Tuple[Optional[float], str]:
    if mark == "hard":
        return 1.0, "oznaczony przez obsadowego jako trudny"
    if mark == "easy":
        return 0.1, "oznaczony przez obsadowego jako łatwy"
    if evaluation and evaluation[0] is not None:
        return evaluation
    return None, ""


def pair_grade(evaluation: Mapping[str, Any]) -> Optional[float]:
    """Średnia punktów arkusza delegata (A=1 ... G=7) - dotyczy PARY."""
    points: List[int] = []
    for section in (evaluation or {}).get("sections") or []:
        grades = [section.get("mainGrade")] + [item.get("grade") for item in section.get("items") or []]
        for grade in grades:
            point = GRADE_POINTS.get(_s(grade).upper())
            if point is not None:
                points.append(point)
    return sum(points) / len(points) if points else None


def scaled_by_tier(value: Optional[float], tier: float) -> Optional[float]:
    """Stawka i przebieg meczu ważą od połowy (dzieci) do całości (najwyższa liga)."""
    if value is None:
        return None
    return value * (0.5 + 0.5 * max(0.0, min(1.0, tier)))


def weighted(components: Mapping[str, Optional[float]], weights: Mapping[str, float]) -> float:
    total = 0.0
    score = 0.0
    for key in COMPONENTS:
        value = components.get(key)
        weight = float(weights.get(key, 0) or 0)
        if value is None or weight <= 0:
            continue
        total += weight
        score += weight * value
    return score / total if total else 0.0


def normalize_weights(raw: Any) -> Dict[str, int]:
    out = dict(DEFAULT_WEIGHTS)
    if isinstance(raw, Mapping):
        for key in COMPONENTS:
            try:
                out[key] = max(0, min(100, int(round(float(raw.get(key, out[key]))))))
            except (TypeError, ValueError):
                continue
    if not any(out.values()):
        return dict(DEFAULT_WEIGHTS)
    return out


# ---------------------------------------------------------------------------
# Fakty o meczach
# ---------------------------------------------------------------------------


@dataclass
class Fact:
    id: str
    season: int
    ts: Optional[int]
    code: str
    comp: str
    category: str
    home: str
    away: str
    origin: str
    played: bool
    field: Tuple[str, ...]
    table: Tuple[str, ...]
    delegate: Tuple[str, ...]
    tier: float
    stake: float
    protocol: Optional[float]
    manual: Optional[float]
    why: Dict[str, List[str]] = field(default_factory=dict)
    #: Średnia ocen delegata dla pary boiskowej tego meczu (1..7).
    grade: Optional[float] = None

    def components(self) -> Dict[str, Optional[float]]:
        return {"tier": self.tier, "stake": self.stake, "protocol": self.protocol, "manual": self.manual}


def team_cities(matches: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    """Miasto drużyny = najczęstsze miasto hali jej meczów u siebie."""
    seen: Dict[str, Counter] = defaultdict(Counter)
    for match in matches:
        city = _s(match.get("city"))
        home = team_key(match.get("home"))
        if city and home:
            seen[home][city] += 1
    return {team: counter.most_common(1)[0][0] for team, counter in seen.items() if counter}


def standings_positions(matches: Sequence[Mapping[str, Any]]) -> Dict[str, Tuple[Optional[int], Optional[int], int, float]]:
    """Pozycje obu drużyn PRZED każdym meczem jednej tabeli (rozgrywki + runda).

    Punkty 2-1-0 - bezwzględna liczba nie ma tu znaczenia, liczy się kolejność.
    Oddaje `id -> (poz. gospodarza, poz. gościa, drużyn, postęp sezonu)`.
    """
    teams = {team_key(m.get("home")) for m in matches} | {team_key(m.get("away")) for m in matches}
    teams.discard("")
    total = sum(1 for m in matches if m.get("gH") is not None and m.get("gA") is not None) or 1
    table: Dict[str, List[int]] = {team: [0, 0, 0] for team in teams}  # punkty, różnica, zdobyte
    played = 0
    out: Dict[str, Tuple[Optional[int], Optional[int], int, float]] = {}
    ordered = sorted((m for m in matches if m.get("ts") is not None), key=lambda m: (m["ts"], _s(m.get("id"))))
    for match in ordered:
        ranking = sorted(table.items(), key=lambda item: (-item[1][0], -item[1][1], -item[1][2], item[0]))
        position = {team: index + 1 for index, (team, _) in enumerate(ranking)}
        home, away = team_key(match.get("home")), team_key(match.get("away"))
        out[_s(match.get("id"))] = (position.get(home), position.get(away), len(teams), played / total)
        gh, ga = match.get("gH"), match.get("gA")
        if gh is None or ga is None or home not in table or away not in table:
            continue
        gh, ga = int(gh), int(ga)
        played += 1
        for team, own, other in ((home, gh, ga), (away, ga, gh)):
            table[team][0] += 2 if own > other else (1 if own == other else 0)
            table[team][1] += own - other
            table[team][2] += own
    return out


def build_facts(
    seasons: Mapping[int, Sequence[Mapping[str, Any]]],
    *,
    marks: Mapping[str, str],
    evaluations: Mapping[str, Sequence[Mapping[str, Any]]],
) -> List[Fact]:
    """Mecze archiwum -> fakty z policzonymi składnikami trudności.

    `seasons`: rok początku -> mecze sezonu (kształt `SlimMatch`),
    `marks`: numer meczu -> „hard" | „easy",
    `evaluations`: numer meczu -> arkusze delegata (`referee_ids`, `evaluation_json`).
    """
    facts: List[Fact] = []
    for start, matches in seasons.items():
        cities = team_cities(m for m in matches if m.get("origin") == "district")

        by_table: Dict[Tuple[str, str], List[Mapping[str, Any]]] = defaultdict(list)
        sus_by_comp: Dict[str, List[int]] = defaultdict(list)
        for match in matches:
            by_table[(_s(match.get("comp")), _s(match.get("round")))].append(match)
            roster = match.get("roster")
            if roster and match.get("gH") is not None:
                sus_by_comp[_s(match.get("comp"))].append(int(roster.get("susH") or 0) + int(roster.get("susA") or 0))
        positions: Dict[str, Tuple[Optional[int], Optional[int], int, float]] = {}
        for rows in by_table.values():
            positions.update(standings_positions(rows))
        avg_sus = {comp: (sum(values) / len(values)) for comp, values in sus_by_comp.items() if values and sum(values)}

        for match in matches:
            match_id = _s(match.get("id"))
            refs = match.get("refs") or {}
            groups: Dict[str, List[str]] = {"field": [], "table": [], "delegate": []}
            for role, judge in refs.items():
                group = ROLE_GROUP.get(role)
                if group and _s(judge):
                    groups[group].append(_s(judge))
            if not any(groups.values()):
                continue
            code = _s(match.get("code"))
            tier, category = tier_component(code)

            why: Dict[str, List[str]] = {"tier": [category]}
            stage, stage_label = stage_component(match.get("round"), match.get("series"))
            derby, derby_label = derby_component(
                cities.get(team_key(match.get("home")), ""), cities.get(team_key(match.get("away")), "")
            )
            pos = positions.get(match_id)
            table, table_label = table_component(*pos) if pos else (0.0, "")
            stake = scaled_by_tier(max(stage, derby, table), tier)
            why["stake"] = [label for label in (stage_label, derby_label, table_label) if label]

            protocol, protocol_why = protocol_component(match, avg_sus.get(_s(match.get("comp"))))
            protocol = scaled_by_tier(protocol, tier)
            why["protocol"] = protocol_why

            sheets = evaluations.get(match_id) or ()
            evaluation = None
            grade = None
            for sheet in sheets:
                body = sheet.get("evaluation_json") or {}
                found = evaluation_difficulty(body)
                if found[0] is not None and evaluation is None:
                    evaluation = found
                points = pair_grade(body)
                if points is not None:
                    ids = {_s(item) for item in sheet.get("referee_ids") or []}
                    if not groups["field"] or ids & set(groups["field"]):
                        grade = points if grade is None else (grade + points) / 2
            manual, manual_label = manual_component(marks.get(match_id), evaluation)
            why["manual"] = [manual_label] if manual_label else []

            facts.append(
                Fact(
                    id=match_id,
                    season=int(start),
                    ts=match.get("ts"),
                    code=code,
                    comp=_s(match.get("comp")),
                    category=category,
                    home=_s(match.get("home")),
                    away=_s(match.get("away")),
                    origin=_s(match.get("origin")) or "district",
                    played=match.get("gH") is not None and match.get("gA") is not None,
                    field=tuple(groups["field"]),
                    table=tuple(groups["table"]),
                    delegate=tuple(groups["delegate"]),
                    tier=round(tier, 3),
                    stake=round(stake, 3),
                    protocol=None if protocol is None else round(protocol, 3),
                    manual=manual,
                    why=why,
                    grade=grade,
                )
            )
    return facts


# ---------------------------------------------------------------------------
# Analiza
# ---------------------------------------------------------------------------


@dataclass
class Person:
    """Sędzia z listy okręgu, jak go widzi analiza."""

    judge_id: str
    name: str
    young: bool = False
    league: bool = False
    letters: Tuple[str, ...] = ()


LEAGUE_FIELD_CATEGORIES = frozenset({"II liga", "I liga", "Liga Centralna", "Superliga"})
LEAGUE_WINDOW = 3
LEAGUE_MIN_MATCHES = 8
LEAGUE_MIN_SEASONS = 2


def is_district_fact(fact: Fact) -> bool:
    """Mecz, za ktorego obsade odpowiada okreg."""
    return fact.origin == "district"


def league_activity(rows: Sequence[Fact], *, current: int) -> dict:
    """Aktualny status ligowca z faktycznych meczow boiskowych od II ligi."""
    first = current - LEAGUE_WINDOW + 1
    league_rows = [
        fact for fact in rows
        if first <= fact.season <= current and fact.category in LEAGUE_FIELD_CATEGORIES
    ]
    by_season = Counter(fact.season for fact in league_rows)
    active = len(league_rows) >= LEAGUE_MIN_MATCHES and len(by_season) >= LEAGUE_MIN_SEASONS
    return {
        "active": active,
        "matches": len(league_rows),
        "seasons": len(by_season),
        "by_season": [
            {"season": season, "matches": by_season[season]}
            for season in sorted(by_season)
        ],
        "last_season": max(by_season) if by_season else None,
        "window": LEAGUE_WINDOW,
        "minimum_matches": LEAGUE_MIN_MATCHES,
        "minimum_seasons": LEAGUE_MIN_SEASONS,
    }


def percentile(values: Sequence[float], share: float) -> Optional[float]:
    ordered = sorted(values)
    if not ordered:
        return None
    index = min(len(ordered) - 1, max(0, int(math.ceil(share * len(ordered))) - 1))
    return ordered[index]


def horizon_seasons(horizon: str, current: int, available: Iterable[int]) -> List[int]:
    years = sorted({int(year) for year in available if int(year) <= current}, reverse=True)
    span = HORIZONS.get(horizon, 5)
    if span is None:
        return years
    return [year for year in years if year > current - span]


def _median(values: Sequence[float]) -> Optional[float]:
    return statistics.median(values) if values else None


def _gini(values: Sequence[float]) -> Optional[float]:
    ordered = sorted(value for value in values if value >= 0)
    n = len(ordered)
    total = sum(ordered)
    if n < 2 or total <= 0:
        return None
    cumulative = sum((index + 1) * value for index, value in enumerate(ordered))
    return (2 * cumulative) / (n * total) - (n + 1) / n


def analyze(
    facts: Sequence[Fact],
    *,
    people: Mapping[str, Person],
    names: Mapping[str, str],
    weights: Mapping[str, float],
    horizon: str,
    current: int,
) -> dict:
    """Profile sędziów i wnioski dla wybranego horyzontu i wag.

    Oddaje słownik gotowy do JSON-a: `meta`, `judges` (tylko obecna lista
    okręgu), `conclusions` (z dowodami w postaci numerów meczów) i rozkład
    trudności. Liczy szybko, bo fakty są już policzone - dlatego suwaki wag
    mogą przeliczać podgląd od razu.
    """
    seasons = horizon_seasons(horizon, current, (fact.season for fact in facts))
    in_scope = [fact for fact in facts if fact.season in seasons]
    # Trudność liczymy dla CAŁEJ historii - doświadczenie i ścieżka rozwoju
    # patrzą na początek kariery, który bywa sprzed horyzontu.
    difficulty = {fact.id: weighted(fact.components(), weights) for fact in facts}
    district_scope = [fact for fact in in_scope if is_district_fact(fact)]
    played = [difficulty[fact.id] for fact in district_scope if fact.played]
    threshold = max(HARD_FLOOR, percentile(played, 1 - HARD_SHARE) or HARD_FLOOR)
    # Próg dla meczu PRZED rozegraniem liczymy z tej samej historii, ale bez
    # protokołu - inaczej przewidywana trudność porównywałaby się z inną skalą.
    before = [
        weighted({**fact.components(), "protocol": None}, weights)
        for fact in district_scope if fact.played
    ]
    predict_threshold = max(HARD_FLOOR, percentile(before, 1 - HARD_SHARE) or HARD_FLOOR)
    hard = {fact.id for fact in district_scope if difficulty[fact.id] >= threshold}
    hard_all = {
        fact.id for fact in facts
        if is_district_fact(fact) and difficulty[fact.id] >= threshold
    }
    first_data_season = min((fact.season for fact in facts), default=current)
    season_weight = {year: SEASON_DECAY ** max(0, current - year) for year in seasons}

    def name_of(judge_id: str) -> str:
        person = people.get(judge_id)
        return (person.name if person else "") or names.get(judge_id, "") or judge_id

    # --- zebranie obsad sędziów (chronologicznie) ---
    ordered = sorted(in_scope, key=lambda fact: (fact.ts or 0, fact.id))
    field_history: Dict[str, List[Fact]] = defaultdict(list)
    table_history: Dict[str, List[Fact]] = defaultdict(list)
    delegate_history: Dict[str, List[Fact]] = defaultdict(list)
    for fact in ordered:
        for judge in fact.field:
            field_history[judge].append(fact)
        for judge in fact.table:
            table_history[judge].append(fact)
        for judge in fact.delegate:
            delegate_history[judge].append(fact)

    everyone = set(field_history) | set(table_history) | set(delegate_history)

    # --- 1. doświadczenie przed pierwszym trudnym meczem (boisko) ---
    # Na całej historii i TYLKO u sędziów, których początek widać w danych -
    # ktoś, kto sędziował przed najstarszym sezonem archiwum, dostawał „pierwszy"
    # trudny mecz od razu, a próg wychodził zero.
    all_field: Dict[str, List[Fact]] = defaultdict(list)
    for fact in sorted(facts, key=lambda item: (item.ts or 0, item.id)):
        for judge in fact.field:
            all_field[judge].append(fact)
    before_first_hard: Dict[str, int] = {}
    for judge, rows in all_field.items():
        for index, fact in enumerate(rows):
            if fact.id in hard_all:
                before_first_hard[judge] = index
                break
    measured = {
        judge: value
        for judge, value in before_first_hard.items()
        if all_field[judge] and all_field[judge][0].season > first_data_season
    }
    exp_values = list(measured.values())
    exp_threshold = max(3, int(percentile(exp_values, 0.2) or 0)) if len(exp_values) >= 5 else None

    # --- 2. specjalizacja ---
    def category_mix(rows: Sequence[Fact]) -> Counter:
        return Counter(fact.category for fact in rows)

    # --- 3a. pary boiskowe ---
    pairs: Dict[Tuple[str, str], dict] = {}
    for fact in in_scope:
        if len(fact.field) < 2:
            continue
        key = tuple(sorted(fact.field[:2]))
        entry = pairs.setdefault(key, {"matches": 0, "hard": 0, "grades": [], "ids": [], "last": 0})
        entry["matches"] += 1
        entry["hard"] += 1 if fact.id in hard else 0
        entry["last"] = max(entry["last"], fact.season)
        entry["ids"].append(fact.id)
        if fact.grade is not None:
            entry["grades"].append(fact.grade)

    # --- 3b. powtarzalność z drużyną ---
    repeats: Dict[Tuple[str, int, str], List[str]] = defaultdict(list)
    for judge, rows in field_history.items():
        for fact in rows:
            for team in (fact.home, fact.away):
                if team_key(team):
                    repeats[(judge, fact.season, team)].append(fact.id)
    repeats_by_judge: Dict[str, List[Tuple[int, str, List[str]]]] = defaultdict(list)
    for (judge, year, team), ids in repeats.items():
        repeats_by_judge[judge].append((year, team, ids))
    repeat_counts = [len(ids) for ids in repeats.values()]
    repeat_limit = max(3, int(percentile(repeat_counts, 0.95) or 3)) if repeat_counts else None

    # --- 4a. ścieżka rozwoju ---
    first_year = first_data_season
    paths: List[Tuple[int, Optional[int], Optional[int]]] = []  # (start, lat do juniora, lat do III ligi)
    max_tier_by: Dict[str, Dict[int, float]] = defaultdict(dict)
    for judge, rows in all_field.items():
        by_year: Dict[int, List[float]] = defaultdict(list)
        for fact in rows:
            by_year[fact.season].append(fact.tier)
        for year, tiers in by_year.items():
            max_tier_by[judge][year] = percentile(tiers, 0.8) or 0.0
        start = min(by_year)
        if start <= first_year:
            continue  # zaczął przed horyzontem - nie widać jego początku
        to_junior = next((year - start for year in sorted(by_year) if max_tier_by[judge][year] >= 0.55), None)
        to_senior = next((year - start for year in sorted(by_year) if max_tier_by[judge][year] >= 0.7), None)
        paths.append((start, to_junior, to_senior))
    median_to_junior = _median([value for _, value, _ in paths if value is not None])
    median_to_senior = _median([value for _, _, value in paths if value is not None])

    # --- 4b. równy podział trudnych ---
    last_season = max(seasons) if seasons else current

    def hard_share(judge: str, year: Optional[int] = None) -> Tuple[int, int]:
        rows = [
            fact for fact in field_history.get(judge, [])
            if is_district_fact(fact) and (year is None or fact.season == year)
        ]
        return sum(1 for fact in rows if fact.id in hard), len(rows)

    # --- 5. mentorzy młodych ---
    young_ids = {judge for judge, person in people.items() if person.young}
    mentor: Dict[str, dict] = defaultdict(lambda: {"matches": 0, "young": set(), "grades": [], "ids": []})
    for fact in in_scope:
        pair = fact.field[:2]
        if len(pair) < 2:
            continue
        a, b = pair
        for mentor_id, pupil in ((a, b), (b, a)):
            if pupil in young_ids and mentor_id not in young_ids:
                entry = mentor[mentor_id]
                entry["matches"] += 1
                entry["young"].add(pupil)
                entry["ids"].append(fact.id)
                if fact.grade is not None:
                    entry["grades"].append(fact.grade)

    # --- profile obecnych sędziów ---
    judges_out: List[dict] = []
    group_shares: Dict[str, List[float]] = defaultdict(list)
    for judge_id, person in people.items():
        field_rows = field_history.get(judge_id, [])
        district_rows = [fact for fact in field_rows if is_district_fact(fact)]
        if district_rows:
            h, n = hard_share(judge_id)
            if n >= 10:
                active = league_activity(all_field.get(judge_id, []), current=current)["active"]
                group_shares["league" if active else "district"].append(h / n)

    for judge_id, person in sorted(people.items(), key=lambda item: item[1].name):
        field_rows = field_history.get(judge_id, [])
        district_field_rows = [fact for fact in field_rows if is_district_fact(fact)]
        league_field_rows = [fact for fact in field_rows if fact.category in LEAGUE_FIELD_CATEGORIES]
        table_rows = table_history.get(judge_id, [])
        delegate_rows = delegate_history.get(judge_id, [])
        if not (field_rows or table_rows or delegate_rows) and not person.young:
            continue
        mix = category_mix(district_field_rows) if district_field_rows else category_mix(table_rows)
        total = sum(mix.values())
        dominant, dominant_n = (mix.most_common(1)[0] if mix else ("", 0))
        h, n = hard_share(judge_id)
        h_last, n_last = hard_share(judge_id, last_season)
        league_now = league_activity(all_field.get(judge_id, []), current=current)
        group = "league" if league_now["active"] else "district"
        peer_median = _median(group_shares.get(group, []))
        per_season = []
        for year in sorted(seasons):
            rows = [fact for fact in field_rows if fact.season == year]
            if not rows and not any(fact.season == year for fact in table_rows):
                continue
            diffs = [difficulty[fact.id] for fact in rows]
            per_season.append(
                {
                    "season": year,
                    "field": len(rows),
                    "table": sum(1 for fact in table_rows if fact.season == year),
                    "hard": sum(1 for fact in rows if fact.id in hard),
                    "avg": round(sum(diffs) / len(diffs), 3) if diffs else None,
                    "top_tier": round(max_tier_by.get(judge_id, {}).get(year, 0.0), 3) if rows else None,
                }
            )
        partners = Counter()
        for fact in field_rows:
            for other in fact.field[:2]:
                if other != judge_id:
                    partners[other] += 1
        teams = sorted(
            ((team, len(ids)) for year, team, ids in repeats_by_judge.get(judge_id, []) if year == last_season),
            key=lambda item: -item[1],
        )[:3]
        mentor_entry = mentor.get(judge_id)
        weighted_field = sum(season_weight.get(fact.season, 0) for fact in district_field_rows)
        top_tier_now = max((value for year, value in max_tier_by.get(judge_id, {}).items()), default=None)
        judges_out.append(
            {
                "judge_id": judge_id,
                "name": person.name or name_of(judge_id),
                "young": person.young,
                "league": person.league,
                "league_active": league_now["active"],
                "league_activity": league_now,
                "letters": list(person.letters),
                "field": len(field_rows),
                "field_district": len(district_field_rows),
                "field_league": len(league_field_rows),
                "table": len(table_rows),
                "delegate": len(delegate_rows),
                "weighted_field": round(weighted_field, 1),
                "hard": h,
                "hard_share": round(h / n, 3) if n else None,
                "hard_last_season": h_last,
                "field_last_season": n_last,
                "peer_share": round(peer_median, 3) if peer_median is not None else None,
                "avg_difficulty": round(sum(difficulty[f.id] for f in field_rows) / len(field_rows), 3) if field_rows else None,
                "categories": [{"category": cat, "matches": count} for cat, count in mix.most_common()],
                "dominant": {"category": dominant, "share": round(dominant_n / total, 3)} if total else None,
                "field_all": len(all_field.get(judge_id, [])),
                "first_hard_after": before_first_hard.get(judge_id),
                "ready_for_hard": (len(all_field.get(judge_id, [])) >= exp_threshold) if exp_threshold is not None else None,
                "top_tier": round(top_tier_now, 3) if top_tier_now is not None else None,
                "seasons": per_season,
                "partners": [
                    {"judge_id": other, "name": name_of(other), "matches": count, "young": other in young_ids}
                    for other, count in partners.most_common(4)
                ],
                "team_repeats": [{"team": team, "matches": count} for team, count in teams],
                "mentoring": {
                    "matches": mentor_entry["matches"],
                    "young": len(mentor_entry["young"]),
                    "grade": round(sum(mentor_entry["grades"]) / len(mentor_entry["grades"]), 2)
                    if mentor_entry["grades"]
                    else None,
                }
                if mentor_entry
                else None,
            }
        )

    by_id = {item["judge_id"]: item for item in judges_out}

    # --- wnioski ---
    conclusions: List[dict] = []

    if exp_threshold is not None:
        below = [item for item in judges_out if item["field_all"] and item["field_all"] < exp_threshold]
        above = [item for item in judges_out if item["field_all"] >= exp_threshold]
        conclusions.append(
            {
                "key": "experience_before_hard",
                "kind": "experience",
                "title": "Doświadczenie przed trudnymi meczami",
                "summary": (
                    f"Nowi sędziowie dostawali pierwszy trudny mecz po co najmniej {exp_threshold} meczach "
                    f"na boisku (mediana {int(_median(exp_values) or 0)}, zmierzone u {len(exp_values)} osób)."
                ),
                "evidence": {
                    "judges_measured": len(exp_values),
                    "median": _median(exp_values),
                    "threshold": exp_threshold,
                },
                "affected": {
                    "ready": [item["judge_id"] for item in above][:60],
                    "not_ready": [item["judge_id"] for item in below][:60],
                },
                "rule": {
                    "params": {"min_field_matches": exp_threshold},
                    "points": "Kara za trudny mecz dla sędziego poniżej progu doświadczenia",
                    "hard": f"Trudny mecz tylko dla sędziów z co najmniej {exp_threshold} meczami na boisku",
                },
            }
        )

    specialists = [
        item
        for item in judges_out
        if item["dominant"] and item["field"] >= 10 and item["dominant"]["share"] >= 0.55
    ]
    if specialists:
        by_category = Counter(item["dominant"]["category"] for item in specialists)
        conclusions.append(
            {
                "key": "category_specialization",
                "kind": "specialization",
                "title": "Specjalizacja w kategoriach",
                "summary": (
                    f"{len(specialists)} sędziów prowadzi ponad połowę meczów w jednej kategorii - "
                    + ", ".join(f"{cat}: {count}" for cat, count in by_category.most_common(4))
                    + "."
                ),
                "evidence": {"by_category": dict(by_category)},
                "affected": {
                    "specialists": [
                        {"judge_id": item["judge_id"], "category": item["dominant"]["category"], "share": item["dominant"]["share"]}
                        for item in specialists
                    ][:80]
                },
                "rule": {
                    "params": {"min_share": 0.55},
                    "points": "Premia dla sędziego w kategorii, w której najczęściej prowadzi mecze",
                    "hard": "Sędziowie wyspecjalizowani tylko w swojej kategorii albo niższej",
                },
            }
        )

    current_ids = set(people)
    stable = [
        (key, entry)
        for key, entry in pairs.items()
        if entry["matches"] >= 6 and key[0] in current_ids and key[1] in current_ids
    ]
    stable.sort(key=lambda item: (-item[1]["hard"], -item[1]["matches"]))
    if stable:
        conclusions.append(
            {
                "key": "stable_pairs",
                "kind": "pairs",
                "title": "Sprawdzone pary na trudne mecze",
                "summary": (
                    f"{len(stable)} par sędziowało razem co najmniej 6 razy; "
                    f"najczęściej na trudnych: {name_of(stable[0][0][0])} i {name_of(stable[0][0][1])} "
                    f"({stable[0][1]['hard']} z {stable[0][1]['matches']})."
                ),
                "evidence": {"pairs": len(stable)},
                "affected": {
                    "pairs": [
                        {
                            "a": key[0],
                            "b": key[1],
                            "names": [name_of(key[0]), name_of(key[1])],
                            "matches": entry["matches"],
                            "hard": entry["hard"],
                            "grade": round(sum(entry["grades"]) / len(entry["grades"]), 2) if entry["grades"] else None,
                            "ids": entry["ids"][-40:],
                        }
                        for key, entry in stable[:40]
                    ]
                },
                "rule": {
                    "params": {"min_matches": 6},
                    "points": "Premia dla sprawdzonej pary na trudnym meczu",
                    "hard": "Na trudny mecz najpierw sprawdzone pary",
                },
            }
        )

    if repeat_limit is not None:
        over = sorted(
            (
                {"judge_id": judge, "name": name_of(judge), "team": team, "season": year, "matches": len(ids), "ids": ids}
                for (judge, year, team), ids in repeats.items()
                if len(ids) > repeat_limit and judge in current_ids and year == last_season
            ),
            key=lambda item: -item["matches"],
        )
        conclusions.append(
            {
                "key": "team_repetition",
                "kind": "pairs",
                "title": "Powtarzalność z tą samą drużyną",
                "summary": (
                    f"19 na 20 razy sędzia prowadził tę samą drużynę najwyżej {repeat_limit} razy w sezonie."
                    + (f" W sezonie {last_season}/{last_season + 1} więcej miało {len(over)} przypadków." if over else "")
                ),
                "evidence": {"limit": repeat_limit},
                "affected": {"over": over[:40]},
                "rule": {
                    "params": {"max_per_team": repeat_limit},
                    "points": f"Kara za kolejny mecz tej samej drużyny ponad {repeat_limit} w sezonie",
                    "hard": f"Najwyżej {repeat_limit} mecze tej samej drużyny w sezonie u jednego sędziego",
                },
            }
        )

    if paths:
        growing = [
            item
            for item in judges_out
            if item["field"] and (item["young"] or (item["seasons"] and item["seasons"][0]["season"] >= current - 2))
        ]
        conclusions.append(
            {
                "key": "development_path",
                "kind": "development",
                "title": "Ścieżka rozwoju",
                "summary": (
                    "Nowi sędziowie dochodzili do meczów juniorów "
                    + (f"zwykle w {int(median_to_junior) + 1}. sezonie" if median_to_junior is not None else "różnie")
                    + ", a do III ligi i seniorów "
                    + (
                        f"w {int(median_to_senior) + 1}. sezonie."
                        if median_to_senior is not None
                        else "rzadko w danych, które mamy."
                    )
                ),
                "evidence": {
                    "judges_measured": len(paths),
                    "median_to_junior": median_to_junior,
                    "median_to_senior": median_to_senior,
                },
                "affected": {
                    "growing": [
                        {"judge_id": item["judge_id"], "top_tier": item["top_tier"], "seasons": len(item["seasons"])}
                        for item in growing
                    ][:60]
                },
                "rule": {
                    "params": {"max_step": 0.15},
                    "points": "Premia za mecz o jeden szczebel wyżej dla rozwijających się sędziów",
                    "hard": "Młody sędzia najwyżej o jeden szczebel ponad dotychczasowy",
                },
            }
        )

    shares = [value for values in group_shares.values() for value in values]
    gini = _gini(shares)
    if gini is not None:
        unfair = []
        for item in judges_out:
            if item["hard_share"] is None or item["peer_share"] is None or item["field"] < 10:
                continue
            # „Za mało trudnych" nie dotyczy kogoś, kto prowadzi tylko młodsze
            # kategorie - takich meczów trudnych prawie nie ma.
            eligible = item["top_tier"] is not None and item["top_tier"] >= 0.45
            if item["hard_share"] >= 1.5 * item["peer_share"] or (
                eligible and item["hard_share"] <= 0.5 * item["peer_share"]
            ):
                unfair.append(
                    {
                        "judge_id": item["judge_id"],
                        "share": item["hard_share"],
                        "peers": item["peer_share"],
                        "direction": "over" if item["hard_share"] > item["peer_share"] else "under",
                    }
                )
        conclusions.append(
            {
                "key": "fair_hard_share",
                "kind": "development",
                "title": "Równy podział trudnych meczów",
                "summary": (
                    f"Nierówność podziału trudnych meczów (Gini) {gini:.2f} - "
                    + ("rozkład jest równy." if gini < 0.25 else "część sędziów dostaje ich wyraźnie więcej.")
                    + (f" Odstaje {len(unfair)} sędziów." if unfair else "")
                ),
                "evidence": {"gini": round(gini, 3)},
                "affected": {"unfair": unfair[:60]},
                "rule": {
                    "params": {},
                    "points": "Wyrównywanie: kara dla tych, którzy mają więcej trudnych niż sędziowie o tych samych uprawnieniach",
                    "hard": "Trudny mecz nie dla sędziego z udziałem trudnych dwa razy większym niż mediana grupy",
                },
            }
        )

    mentors = sorted(
        (
            {
                "judge_id": judge,
                "name": name_of(judge),
                "matches": entry["matches"],
                "young": len(entry["young"]),
                "grade": round(sum(entry["grades"]) / len(entry["grades"]), 2) if entry["grades"] else None,
                "ids": entry["ids"][-40:],
            }
            for judge, entry in mentor.items()
            if judge in current_ids
        ),
        key=lambda item: (-item["young"], -item["matches"]),
    )
    candidates = [
        {"judge_id": item["judge_id"], "name": item["name"], "field": item["field"]}
        for item in sorted(judges_out, key=lambda item: -item["field"])
        if not item["young"]
        and item["judge_id"] not in mentor
        and exp_threshold is not None
        and item["field"] >= 2 * exp_threshold
        and (item["avg_difficulty"] or 0) >= threshold * 0.8
    ][:15]
    if mentors or young_ids:
        conclusions.append(
            {
                "key": "mentors",
                "kind": "mentors",
                "title": "Mentorzy młodych sędziów",
                "summary": (
                    (
                        f"Z młodymi najczęściej sędziowali: "
                        + ", ".join(f"{item['name']} ({item['young']} młodych, {item['matches']} meczów)" for item in mentors[:3])
                        + "."
                    )
                    if mentors
                    else "W tym horyzoncie nikt jeszcze nie sędziował w parze z obecnymi młodymi sędziami."
                )
                + (f" Na mentorów nadaje się też {len(candidates)} doświadczonych sędziów." if candidates else ""),
                "evidence": {"young": len(young_ids)},
                "affected": {"mentors": mentors[:30], "candidates": candidates},
                "rule": {
                    "params": {},
                    "points": "Premia za parę młody sędzia + mentor",
                    "hard": "Młody sędzia na boisku tylko z mentorem",
                },
            }
        )

    histogram = [0] * 10
    for fact in in_scope:
        histogram[min(9, int(difficulty[fact.id] * 10))] += 1
    by_category: Dict[str, List[float]] = defaultdict(list)
    for fact in in_scope:
        by_category[fact.category].append(difficulty[fact.id])

    return {
        "meta": {
            "horizon": horizon,
            "seasons": sorted(seasons),
            "current": current,
            "weights": dict(weights),
            "matches": len(in_scope),
            "hard_threshold": round(threshold, 3),
            "predict_threshold": round(predict_threshold, 3),
            "hard_matches": len(hard),
            "judges": len(judges_out),
        },
        "judges": judges_out,
        "conclusions": conclusions,
        "distribution": {
            "histogram": histogram,
            "categories": sorted(
                (
                    {
                        "category": cat,
                        "matches": len(values),
                        "avg": round(sum(values) / len(values), 3),
                        "hard": sum(1 for fact in in_scope if fact.category == cat and fact.id in hard),
                    }
                    for cat, values in by_category.items()
                ),
                key=lambda item: -item["avg"],
            ),
        },
    }


def judge_matches(
    facts: Sequence[Fact],
    judge_id: str,
    *,
    weights: Mapping[str, float],
    threshold: float,
    seasons: Iterable[int],
) -> List[dict]:
    """Mecze jednego sędziego z trudnością i powodami - pod kliknięcie w liczbę."""
    wanted = set(seasons)
    out = []
    for fact in facts:
        if fact.season not in wanted:
            continue
        role = (
            "field" if judge_id in fact.field else "table" if judge_id in fact.table else "delegate" if judge_id in fact.delegate else ""
        )
        if not role:
            continue
        value = weighted(fact.components(), weights)
        out.append(
            {
                "id": fact.id,
                "season": fact.season,
                "ts": fact.ts,
                "code": fact.code,
                "category": fact.category,
                "home": fact.home,
                "away": fact.away,
                "role": role,
                "difficulty": round(value, 3),
                "hard": value >= threshold,
                "components": fact.components(),
                "why": fact.why,
                "grade": fact.grade,
            }
        )
    out.sort(key=lambda item: -(item["ts"] or 0))
    return out


# ---------------------------------------------------------------------------
# Oceny delegatów tylko dla uprawnionych
# ---------------------------------------------------------------------------
#
# Decyzja użytkownika z 16.09.2026: w BAZA_web oceny delegatów widzą tylko admin
# i konta VIP z uprawnieniem „Oceny delegatów”. Analizę widzi każdy z dostępem
# do Obsady, więc arkusze nadal liczą się do trudności meczu, ale średnie ocen
# i słowa delegata wycinamy z odpowiedzi. Pamięć podręczna analizy zostaje
# nietknięta - funkcje oddają KOPIE tego, co zmieniają.


def _hide_why(why: Any) -> Any:
    if not isinstance(why, Mapping):
        return why
    out = dict(why)
    manual = out.get("manual")
    if isinstance(manual, list):
        out["manual"] = [
            DELEGATE_WHY_HIDDEN if isinstance(label, str) and label.startswith(DELEGATE_WHY_PREFIX) else label
            for label in manual
        ]
    return out


def hide_match_evaluations(items: Iterable[Mapping[str, Any]]) -> List[dict]:
    """Mecze z `judge_matches` albo trasy dowodów - bez oceny i słów delegata."""
    out = []
    for item in items:
        copy = dict(item)
        if "grade" in copy:
            copy["grade"] = None
        if "why" in copy:
            copy["why"] = _hide_why(copy["why"])
        out.append(copy)
    return out


def hide_judge_evaluations(profile: Optional[Mapping[str, Any]]) -> Optional[dict]:
    if profile is None:
        return None
    copy = dict(profile)
    if isinstance(copy.get("mentoring"), Mapping):
        copy["mentoring"] = {**copy["mentoring"], "grade": None}
    return copy


def hide_evaluations(analysis: Mapping[str, Any]) -> dict:
    """Wynik `analyze` bez średnich ocen par, mentorów i sędziów."""
    out = dict(analysis)
    out["judges"] = [hide_judge_evaluations(item) for item in analysis.get("judges") or []]
    conclusions = []
    for conclusion in analysis.get("conclusions") or []:
        copy = dict(conclusion)
        affected = copy.get("affected")
        if isinstance(affected, Mapping):
            copy["affected"] = {
                key: [{**row, "grade": None} if isinstance(row, Mapping) and "grade" in row else row for row in value]
                if isinstance(value, list)
                else value
                for key, value in affected.items()
            }
        conclusions.append(copy)
    out["conclusions"] = conclusions
    return out


# ---------------------------------------------------------------------------
# Przewidywana trudność meczu, który się dopiero odbędzie (dla Automatu)
# ---------------------------------------------------------------------------


def predicted_difficulty(
    *,
    code: Any,
    round_text: Any,
    series_text: Any,
    home: Any,
    away: Any,
    cities: Mapping[str, str],
    positions: Optional[Tuple[Optional[int], Optional[int], int, float]],
    mark: Optional[str],
    weights: Mapping[str, float],
) -> Tuple[float, List[str]]:
    """Trudność PRZED meczem: bez protokołu, reszta tak samo jak w analizie."""
    tier, category = tier_component(code)
    stage, stage_label = stage_component(round_text, series_text)
    derby, derby_label = derby_component(cities.get(team_key(home), ""), cities.get(team_key(away), ""))
    table, table_label = table_component(*positions) if positions else (0.0, "")
    manual, manual_label = manual_component(mark, None)
    value = weighted(
        {"tier": tier, "stake": scaled_by_tier(max(stage, derby, table), tier), "protocol": None, "manual": manual},
        weights,
    )
    why = [category] + [label for label in (stage_label, derby_label, table_label, manual_label) if label]
    return value, why
