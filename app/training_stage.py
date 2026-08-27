# app/training_stage.py
#
# Drabina etapów ćwiczenia i decyzja „czy ten takt niesie coś nowego".
#
# Wydzielone z `app/training_runs.py` z tego samego powodu, co
# `app/proel_match_key.py` z `app/proel.py`: tamten moduł do zaimportowania
# wymaga żywego Postgresa (`app.db` woła `metadata.create_all`), a ta logika
# decyduje o tym, co administrator zobaczy w analizie szkolenia - i musi dać
# się sprawdzić testem, który wszędzie się uruchomi.

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: Drabina etapów, od pierwszego do ostatniego.
#:
#: Trzymamy etap NAJDALSZY, do jakiego sędzia doszedł, a nie ostatni zgłoszony.
#: Zejście z podsumowania z powrotem na tor meczowy jest normalne (poprawka
#: kary, dopisanie bramki), a pytanie brzmi „dokąd doprowadził ćwiczenie", nie
#: „gdzie akurat stoi".
STAGE_ORDER: List[str] = [
    "first_half",
    "half_break",
    "second_half",
    "penalties",
    "ended",
    "summary",
    "finalized",
]

STAGE_RANK: Dict[str, int] = {name: i for i, name in enumerate(STAGE_ORDER)}

#: Od tego etapu w górę uznajemy ćwiczenie za doprowadzone do końca meczu.
COMPLETED_FROM = "ended"

#: Krótszy odstęp niż ten nie zakłada nowego punktu na osi czasu, o ile nic
#: się nie zmieniło. Seria szybkich akcji sędziego (bramka, kara, zmiana)
#: dopisywałaby inaczej pięć identycznych punktów w dwie sekundy.
MIN_TICK_GAP_S = 20


def normalize_stage(value: Any) -> str:
    """Nieznany etap schodzi do pierwszej połowy zamiast wywracać zapis."""
    v = str(value or "").strip()
    return v if v in STAGE_RANK else "first_half"


def furthest_stage(a: Any, b: Any) -> str:
    """Dalszy z dwóch etapów."""
    na, nb = normalize_stage(a), normalize_stage(b)
    return na if STAGE_RANK[na] >= STAGE_RANK[nb] else nb


def is_completed(stage: Any) -> bool:
    """Czy ten etap znaczy „mecz doprowadzony do końca"."""
    return STAGE_RANK[normalize_stage(stage)] >= STAGE_RANK[COMPLETED_FROM]


def tick_is_new(
    prev: Optional[Dict[str, Any]],
    cur: Dict[str, Any],
    gap_s: Optional[float],
) -> bool:
    """Czy dopisać punkt na osi czasu.

    Dopisujemy, gdy:
      * nie ma jeszcze żadnego punktu,
      * zmienił się etap, wynik albo liczba zdarzeń (to jest TA informacja,
        po którą oś czasu w ogóle istnieje),
      * albo minęło dość czasu, żeby cisza sama w sobie coś znaczyła - sędzia
        stojący dziesięć minut w miejscu ma zostawić po sobie płaski odcinek,
        a nie dziurę.
    """
    if not prev:
        return True

    def num(d: Dict[str, Any], key: str) -> int:
        try:
            return int(d.get(key) or 0)
        except (TypeError, ValueError):
            return 0

    if normalize_stage(prev.get("stage")) != normalize_stage(cur.get("stage")):
        return True
    for key in ("score_host", "score_guest", "events_count"):
        if num(prev, key) != num(cur, key):
            return True

    if gap_s is None:
        return True
    return float(gap_s) >= MIN_TICK_GAP_S
