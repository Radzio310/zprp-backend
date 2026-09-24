"""
Czy sędzia zdąży z meczu na mecz - JEDNA reguła dla Automatu obsady
i dla alertów okręgu o kolizjach (decyzja użytkownika z 24.09.2026).

Skąd zmiana: stara reguła liczyła każdy mecz jako 2 godziny plus dojazd
60 km/h plus 45 minut zapasu - także wtedy, gdy oba mecze grano w TEJ SAMEJ
hali. Turniej młodzików w jednej hali (S/MłKR/16, 17, 18 o 10:00, 11:50
i 13:40) dawał przez to 23 fałszywe „kolizje" w mailu testowym.

Teraz:
  - TA SAMA HALA (ten sam numer obiektu albo ta sama nazwa hali w tym samym
    mieście): bez dojazdu i bez zapasu - mecze nie mogą się tylko nakładać,
    a czas meczu zależy od kategorii,
  - INNA HALA: czas wcześniejszego meczu + dojazd (domyślnie 60 km/h)
    + zapas (domyślnie 30 min).

Czas meczu według kategorii (numer meczu, ta sama klasyfikacja co
w rozliczeniach - `settlement_rates.district_category`):
    Senior i Junior         1:45
    Junior młodszy          1:30
    Młodzik                 1:15
    Młodzik młodszy, Dzieci 1:00
Wszystko, czego numer nie rozpoznaje (ligi, puchary, „Inne"), liczy się jak
Senior - dłużej znaczy ostrożniej.

Wartości da się zmienić w ustawieniach powiadomień okręgu (sekcja `timing`);
Automat czyta te same ustawienia, a bez zapisu bierze wartości domyślne.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional

from app import settlement_rates as R

#: Klucze kategorii w ustawieniach - w tej kolejności pokazuje je panel.
SENIOR = "senior"
JUNIOR = "junior"
JUNIOR_YOUNGER = "junior_mlodszy"
YOUTH = "mlodzik"
YOUTH_YOUNGER = "mlodzik_mlodszy"
CHILDREN = "dzieci"
CATEGORY_KEYS: tuple[str, ...] = (SENIOR, JUNIOR, JUNIOR_YOUNGER, YOUTH, YOUTH_YOUNGER, CHILDREN)
CATEGORY_LABELS = {
    SENIOR: "Senior",
    JUNIOR: "Junior",
    JUNIOR_YOUNGER: "Junior młodszy",
    YOUTH: "Młodzik",
    YOUTH_YOUNGER: "Młodzik młodszy",
    CHILDREN: "Dzieci",
}

DEFAULT_DURATIONS: dict[str, int] = {
    SENIOR: 105,
    JUNIOR: 105,
    JUNIOR_YOUNGER: 90,
    YOUTH: 75,
    YOUTH_YOUNGER: 60,
    CHILDREN: 60,
}
DEFAULT_TRAVEL_KMH = 60
DEFAULT_MARGIN_MINUTES = 30
#: Dojazd, gdy odległości nie znamy - godzina, jak dotąd.
UNKNOWN_TRAVEL_MINUTES = 60.0

#: Granice pól w ustawieniach (walidacja zapisu).
TRAVEL_KMH_RANGE = (20, 130)
MARGIN_RANGE = (0, 180)
DURATION_RANGE = (30, 240)

#: Kategoria z `district_category` -> klucz czasu meczu.
_DISTRICT_TO_KEY = {
    "Junior": JUNIOR,
    "Junior mł.": JUNIOR_YOUNGER,
    "Młodzik": YOUTH,
    "Młodzik mł.": YOUTH_YOUNGER,
    R.CHILDREN_CATEGORY: CHILDREN,
}


class TimingError(ValueError):
    """Zła wartość w ustawieniach czasu - komunikat idzie wprost do człowieka."""


@dataclass
class CollisionRules:
    """Ustawienia reguły kolizji jednego okręgu."""

    travel_kmh: float = DEFAULT_TRAVEL_KMH
    margin_minutes: int = DEFAULT_MARGIN_MINUTES
    durations: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_DURATIONS))

    def duration(self, code: Any) -> int:
        key = duration_key(code)
        return int(self.durations.get(key, DEFAULT_DURATIONS[key]))

    def as_config(self) -> dict:
        return {
            "travel_kmh": int(self.travel_kmh),
            "margin_minutes": int(self.margin_minutes),
            "durations": {key: int(self.durations.get(key, DEFAULT_DURATIONS[key])) for key in CATEGORY_KEYS},
        }


DEFAULT_RULES = CollisionRules()


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def duration_key(code: Any) -> str:
    """Klucz kategorii meczu do czasu trwania. Nieznany numer = Senior."""
    if not _s(code):
        return SENIOR
    # Mistrzostwa niosą kategorię w numerze („MPJMM") - mecz juniorów młodszych
    # trwa tyle samo w lidze okręgowej i w turnieju MP.
    return _DISTRICT_TO_KEY.get(R.district_category(code), SENIOR)


def match_minutes(code: Any, rules: Optional[CollisionRules] = None) -> int:
    return (rules or DEFAULT_RULES).duration(code)


def travel_minutes(km: Optional[float], rules: Optional[CollisionRules] = None) -> float:
    """Ile jedzie się tyle kilometrów. Bez odległości zakładamy godzinę."""
    if km is None:
        return UNKNOWN_TRAVEL_MINUTES
    speed = float((rules or DEFAULT_RULES).travel_kmh) or DEFAULT_TRAVEL_KMH
    return (float(km) / speed) * 60.0


def _fold(value: Any) -> str:
    text = _s(value).lower().replace("ł", "l")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def hall_key(hall: Any, city: Any) -> str:
    """
    Klucz hali: nazwa i miasto bez ogonków, wielkości liter i interpunkcji.

    Bez nazwy hali klucza nie ma - samo miasto to jeszcze nie ta sama hala.
    """
    name = _fold(hall)
    if not name:
        return ""
    return f"{name}|{_fold(city)}"


#: Pola migawki meczu, w których terminarz bywa podaje numer obiektu hali.
VENUE_FIELDS = ("ID_hala", "ID_hale", "Hala_id", "Hala_ID", "IdHala", "venue_id")


def venue_of(state: Any) -> str:
    """Numer obiektu hali z migawki meczu - pusto, gdy terminarz go nie niesie."""
    if not isinstance(state, Mapping):
        return ""
    for key in VENUE_FIELDS:
        value = _s(state.get(key))
        if value and value != "0":
            return value
    return ""


def same_hall(
    a_hall: Any,
    a_city: Any,
    b_hall: Any,
    b_city: Any,
    *,
    a_venue: Any = "",
    b_venue: Any = "",
) -> bool:
    """
    Czy oba mecze są w tej samej hali.

    Numer obiektu (gdy oba go mają) rozstrzyga sam; inaczej nazwa hali
    i miasto po normalizacji. Brak nazwy którejkolwiek hali = „nie wiemy",
    czyli NIE ta sama hala - wtedy liczymy dojazd i zapas, jak ostrożniej.
    """
    left, right = _s(a_venue), _s(b_venue)
    if left and right and left not in ("0",) and right not in ("0",):
        return left == right
    first, second = hall_key(a_hall, a_city), hall_key(b_hall, b_city)
    return bool(first) and first == second


def needed_minutes(
    earlier_code: Any,
    km: Optional[float],
    *,
    same_venue: bool = False,
    rules: Optional[CollisionRules] = None,
) -> float:
    """Ile minut musi minąć między początkami meczów."""
    rules = rules or DEFAULT_RULES
    minutes = float(rules.duration(earlier_code))
    if same_venue:
        return minutes
    return minutes + travel_minutes(km, rules) + float(rules.margin_minutes)


def gap_minutes(first: datetime, second: datetime) -> float:
    return abs((second - first).total_seconds()) / 60.0


def can_make_both(
    first: Optional[datetime],
    second: Optional[datetime],
    km: Optional[float],
    *,
    first_code: Any = "",
    second_code: Any = "",
    same_venue: bool = False,
    rules: Optional[CollisionRules] = None,
) -> bool:
    """
    Czy da się zdążyć z jednego meczu na drugi.

    Liczy się czas WCZEŚNIEJSZEGO meczu. Bez terminu (któregokolwiek) nie
    wiemy nic - i wtedy NIE blokujemy, bo „nie wiem" nie może odbierać
    sędziemu meczu.
    """
    if first is None or second is None:
        return True
    earlier_code = first_code if first <= second else second_code
    return gap_minutes(first, second) >= needed_minutes(
        earlier_code, km, same_venue=same_venue, rules=rules
    )


def shortfall_minutes(
    first: datetime,
    second: datetime,
    km: Optional[float],
    *,
    first_code: Any = "",
    second_code: Any = "",
    same_venue: bool = False,
    rules: Optional[CollisionRules] = None,
) -> int:
    """Ilu minut brakuje, żeby zdążyć (0, gdy starcza)."""
    earlier_code = first_code if first <= second else second_code
    need = needed_minutes(earlier_code, km, same_venue=same_venue, rules=rules)
    return max(0, int(round(need - gap_minutes(first, second))))


# ---------------------------------------------------------------------------
# Ustawienia
# ---------------------------------------------------------------------------

def default_config() -> dict:
    return DEFAULT_RULES.as_config()


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return int(round(number))


def _within(value: Optional[int], bounds: tuple[int, int]) -> bool:
    return value is not None and bounds[0] <= value <= bounds[1]


def normalize_config(raw: Any) -> dict:
    """Ustawienia z bazy uzupełnione domyślnymi - łagodnie, bez wyjątków."""
    data = raw if isinstance(raw, Mapping) else {}
    out = default_config()
    speed = _int(data.get("travel_kmh"))
    if _within(speed, TRAVEL_KMH_RANGE):
        out["travel_kmh"] = speed
    margin = _int(data.get("margin_minutes"))
    if _within(margin, MARGIN_RANGE):
        out["margin_minutes"] = margin
    durations = data.get("durations") if isinstance(data.get("durations"), Mapping) else {}
    for key in CATEGORY_KEYS:
        value = _int(durations.get(key))
        if _within(value, DURATION_RANGE):
            out["durations"][key] = value
    return out


def validate_config(raw: Any) -> dict:
    """
    Ustawienia do zapisu - zła wartość zatrzymuje zapis z nazwą pola.

    Brakujące pole dostaje wartość domyślną; podane musi mieścić się w granicach.
    """
    data = raw if isinstance(raw, Mapping) else {}
    if "travel_kmh" in data and not _within(_int(data.get("travel_kmh")), TRAVEL_KMH_RANGE):
        low, high = TRAVEL_KMH_RANGE
        raise TimingError(f"Prędkość dojazdu musi mieścić się w granicach {low}-{high} km/h.")
    if "margin_minutes" in data and not _within(_int(data.get("margin_minutes")), MARGIN_RANGE):
        low, high = MARGIN_RANGE
        raise TimingError(f"Zapas między meczami w różnych halach musi mieścić się w granicach {low}-{high} min.")
    durations = data.get("durations")
    if durations is not None and not isinstance(durations, Mapping):
        raise TimingError("Czasy meczów muszą być podane dla kategorii.")
    for key, value in (durations or {}).items():
        if key not in CATEGORY_KEYS:
            continue
        if not _within(_int(value), DURATION_RANGE):
            low, high = DURATION_RANGE
            raise TimingError(
                f"Czas meczu „{CATEGORY_LABELS[key]}” musi mieścić się w granicach {low}-{high} min."
            )
    return normalize_config(data)


def rules_from_config(raw: Any) -> CollisionRules:
    """Reguła z sekcji `timing` ustawień okręgu (brak = wartości domyślne)."""
    clean = normalize_config(raw)
    return CollisionRules(
        travel_kmh=float(clean["travel_kmh"]),
        margin_minutes=int(clean["margin_minutes"]),
        durations=dict(clean["durations"]),
    )


def describe(rules: Optional[CollisionRules] = None) -> str:
    """Jedno zdanie o regule - do raportu i do maila."""
    rules = rules or DEFAULT_RULES
    return (
        f"ta sama hala: mecze nie mogą się nakładać; inna hala: czas meczu + dojazd "
        f"{int(rules.travel_kmh)} km/h + {int(rules.margin_minutes)} min zapasu"
    )
