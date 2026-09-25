"""
Automat obsady - kto ma stanąć przy którym meczu.

MODUŁ-LIŚĆ: bez bazy i sieci. Wszystko, co wie o świecie, dostaje w `Context`
jako dane i funkcje - dzięki temu cała reguła chodzi w teście, a nie na
produkcji.

KRYTERIA UŻYTKOWNIKA (11.09.2026), w kolejności ważności:

  TWARDE - automat ich nie złamie, nawet kosztem pustego gniazda:
    1. niedyspozycja sędziego,
    2. mecz tego samego dnia, na który fizycznie nie da się zdążyć (z zapasem),
    3. para wykluczona przez okręg,
    4. dwoje młodych sędziów w jednej parze,
    5. znacznik „wymaga doświadczonego partnera" (partner z licencją A),
    6. wymagania stolików ligowych (Superliga i LC: ligowiec albo delegat plus
       licencja A; I i II liga: licencja A),
    7. przerwa sędziego (pauza) i drugie gniazdo w tym samym meczu,
    8. rola w obsadzie (25.09.2026): ręczne ustawienie okręgu („tylko stolik",
       „tylko boisko", „boisko i stolik"), a bez niego role z listy ZPRP -
       znane i bez „Sędzia" = nie na boisko (`assignment_people.role_refusal`).

  MIĘKKIE - liczą się punktami, mniej znaczy lepiej:
    - RÓWNY PODZIAŁ w sezonie i w miesiącu, boisko i stolik osobno (niżej),
    - KILOMETRY - rozstrzygają między podobnie obciążonymi,
    - sędzia z miasta gospodarza (unikamy),
    - dzień spoza preferowanych przez sędziego,
    - mecz tego samego dnia, na który ZDĄŻY - ostateczność,
    - premia za ustaloną parę.

RÓWNY PODZIAŁ (decyzja użytkownika z 24.09.2026 - Automat proponował w kółko
tych samych): liczy się SEZON i MIESIĄC meczu, boisko i stolik osobno, razem
z meczami przydzielonymi w TYM przebiegu i w kolejce (`pending`).
    - OKRES (25.09.2026, „powiela ciągle tych samych"): mecze w układanym
      zakresie - już obsadzone (`Context.load`) plus wybory tego przebiegu,
      wszystkie role razem. Kara `period_points` przebija kilometry i premie
      za pary, więc każdy wolny i uprawniony dostaje mecz, zanim ktoś dostanie
      drugi; po zachłannym ułożeniu `_rebalance` przenosi propozycje
      najbardziej obciążonych na tych z co najmniej dwoma mniej,
    - kilometry decydują tylko między podobnie obciążonymi (różnica 1 meczu
      kosztuje `W_GAP_ONE`, czyli tyle, co kilkadziesiąt kilometrów),
    - różnica 2 i więcej meczów względem najmniej obciążonego kandydata kosztuje
      `W_GAP_STEP` za każdy mecz ponad jeden - więcej niż najdalszy przejazd
      i więcej niż premia za parę (para nie przebije różnicy 2 meczów),
    - ponad średnią aktywnych sędziów kara rośnie z kwadratem nadwyżki
      (`W_OVER_MEAN`).

STOLIK W ROZGRYWKACH OKRĘGOWYCH: najpierw sędziowie z odznaką „Stolikowi"
(„Stolikowy"), pozostali dopiero, gdy żadnego stolikowego nie da się wziąć -
ale tylko dopóki stolikowy nie ma w okresie więcej niż JEDEN mecz ponad
najmniej obciążonego kandydata (decyzja 25.09.2026) (`TABLE_BADGE_SLACK`, `badge_tier`). Bez tej granicy
czterech stolikowych brało po kilkanaście stolików w dwa tygodnie.
W II lidze, I lidze, Lidze Centralnej i Superlidze stolik bez tej preferencji -
wszyscy na równi (liczą się tylko wymagania licencji z `table_rule`).

KOLIZJE DNIA: `collision_rules` - ta sama hala = mecze nie mogą się nakładać
(czas meczu z kategorii), inna hala = czas meczu + dojazd + zapas. Wartości
z ustawień powiadomień okręgu (`Context.collision`).

PARY NA BOISKU (decyzja użytkownika z 24.09.2026, „mocno, równość jako druga"):
    - ustalona para razem to MOCNA premia (`B_FIELD_PAIR`), a już pierwszy
      boiskowy dostaje premię, gdy jego para też może przyjechać
      (`B_PAIR_READY`) - inaczej automat brałby połówkę pary, której druga
      połowa akurat nie może,
    - gdy druga połowa nie może: połówka pary z kimś z JEJ pary mentorskiej
      (`B_FIELD_MENTOR`), dopiero potem ktokolwiek,
    - para traci pierwszeństwo, gdy ma wyraźnie więcej meczów niż inni
      (`assignment_people.heavy_judges`: sezon boiska > mediana + 2),
    - przy stoliku ustalona para też razem (`B_PAIR`), ale bez mentorów.

DWA OBIEGI: pierwszy obsadza wyłącznie w dniach preferowanych przez sędziego,
drugi dobiera resztę. Sędzia bez wskazanych dni pasuje do każdego obiegu.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from app import collision_rules as CR
from app.assignment_people import (
    MENTOR,
    PAIR,
    Judge,
    is_local,
    pair_ok,
    pair_relation,
    role_refusal,
    table_pair_ok,
    table_rule,
)
from app.match_market_rules import league_level

#: Wagi punktowe. Kilometr to jeden punkt - reszta jest wyskalowana względem niego.
W_KM = 1.0

#: Od tylu kilometrów przejazd przestaje być zwykłym kosztem i staje się
#: problemem - każdy następny kilometr liczy się `FAR_FACTOR` razy drożej.
#:
#: Bez tego progu automat traktował 140 km jak 35 km cztery razy i przy
#: wyrównywaniu obciążenia potrafił wysłać kogoś przez pół województwa, mimo
#: że bliżej siedział ktoś z jednym meczem więcej. Na danych w skali śląskiego
#: (190 sędziów, 200 meczów) próg ścina najdłuższy przejazd ze 144 do 96 km
#: i zdejmuje 500 km z sumy - przy TAKIM SAMYM wypełnieniu gniazd i nawet
#: równiejszym podziale pracy.
FAR_KM = 45.0
FAR_FACTOR = 4.0
W_LOCAL = 400.0
#: Stara waga obciążenia (mecze w oknie x punkty) - już tylko dla
#: `Context.legacy_load`, czyli do porównania w testach.
W_LOAD = 35.0
#: Równy podział: jeden mecz więcej niż najmniej obciążony kandydat.
W_GAP_ONE = 40.0
#: Każdy następny mecz różnicy - więcej niż najdalszy przejazd razem z premią
#: za parę, więc różnica 2 meczów zawsze przeważa.
W_GAP_STEP = 1500.0
#: Kara za nadwyżkę ponad średnią aktywnych sędziów (rośnie z kwadratem).
W_OVER_MEAN = 12.0
#: OKRES (zgłoszenie z 25.09.2026: „powiela ciągle tych samych"): każdy mecz
#: w układanym okresie ponad najmniej obciążonego kandydata. Kara rośnie
#: trójkątnie (1, 3, 6 ... x `W_PERIOD`), więc już pierwszy mecz różnicy
#: przebija kilometry, premie za parę i miejscowego, a drugi - także różnicę
#: kilku meczów w sezonie. Dzięki temu każdy wolny i uprawniony dostaje coś,
#: zanim ktoś dostanie drugi mecz w tym samym okresie.
W_PERIOD = 2500.0
#: Pierwszeństwo „Stolikowych" przy stoliku okręgowym trzyma się, dopóki
#: stolikowy ma w okresie najwyżej o tyle meczów więcej niż najmniej obciążony
#: kandydat. Bez tego progu czterech stolikowych brało po kilkanaście stolików
#: w dwa tygodnie, a reszta nic (test `test_assignment_period_spread`).
TABLE_BADGE_SLACK = 1
W_OFF_DAY = 120.0
W_SAME_DAY = 600.0
W_UNKNOWN_KM = 90.0
B_PAIR = 250.0
#: Ustalona para na BOISKU - premia warta kilkaset kilometrów (patrz nagłówek).
B_FIELD_PAIR = 600.0
#: Połówka pary z kimś z jej pary mentorskiej, gdy druga połówka nie może.
B_FIELD_MENTOR = 300.0
#: Pierwszy boiskowy, którego para też może przyjechać na ten mecz.
B_PAIR_READY = 300.0

#: Ile kilometrów na godzinę zakłada automat bez ustawień okręgu
#: (reguła i reszta wartości: `collision_rules`).
TRAVEL_KMH = float(CR.DEFAULT_TRAVEL_KMH)

FIELD = "field"
TABLE = "table"

FIELD_SLOTS = ("pierwszy", "drugi")
TABLE_SLOTS = ("sekretarz", "czas")


@dataclass
class BusyMatch:
    """Mecz, który sędzia już ma - własny albo właśnie przydzielony."""

    moment: Optional[datetime]
    city: str
    match_id: str
    #: Numer meczu - z niego czas trwania (`collision_rules.duration_key`).
    code: str = ""
    #: Hala i numer obiektu - ta sama hala nie wymaga dojazdu ani zapasu.
    hall: str = ""
    venue: str = ""


@dataclass
class MatchNeed:
    """Jeden mecz z listy do obsadzenia."""

    match_id: str
    code: str
    moment: Optional[datetime]
    day: Optional[date]
    host_city: str
    #: Klub gospodarza prosi, żeby nie wysyłać tu sędziów z jego miasta.
    #: Bez tego miejscowy jest tylko karany punktami i przy braku chętnych
    #: i tak wchodzi - a to ustawienie ma znaczyć „nie", nie „niechętnie".
    avoid_local: bool = False
    #: Nazwy drużyn - do raportu i PDF, nie do decyzji.
    host: str = ""
    guest: str = ""
    hall: str = ""
    field_needed: list[str] = field(default_factory=list)
    table_needed: list[str] = field(default_factory=list)
    #: Kto już stoi w tym meczu - nie dostanie drugiego gniazda.
    crew_ids: set[str] = field(default_factory=set)
    #: Obsada obecna w gniazdach boiskowych i stolikowych (do reguł par).
    crew_field: list[Judge] = field(default_factory=list)
    crew_table: list[Judge] = field(default_factory=list)
    #: Przewidywana trudność meczu z analizy obsad (`insights_rules.predicted_difficulty`)
    #: - tylko gdy obsadowy wybrał wnioski dla Automatu. Bez nich zostaje None.
    difficulty: Optional[float] = None
    difficulty_why: list[str] = field(default_factory=list)
    tier: float = 0.0
    category: str = ""
    #: Numer obiektu hali, gdy terminarz go niesie.
    venue: str = ""

    @property
    def weekday(self) -> Optional[int]:
        return self.day.weekday() if self.day else None

    @property
    def month(self) -> str:
        """Miesiąc meczu „2026-09" (czas polski) - pusto bez terminu."""
        return month_key(self.day)


@dataclass
class Context:
    """Świat automatu podany z zewnątrz."""

    judges: Mapping[str, Judge]
    #: Czy sędzia jest wolny w tym terminie (niedyspozycje).
    available: Callable[[str, Optional[datetime]], bool]
    #: Czy sędzia ma przerwę w tym dniu.
    paused: Callable[[str, Optional[date]], bool]
    #: Miasto sędziego w danym dniu (z czasową zmianą miasta).
    city_of: Callable[[str, Optional[date]], str]
    #: Odległość miasto - miasto; None znaczy „nie wiemy".
    km: Callable[[str, str], Optional[float]]
    #: Mecze, które sędzia już ma (klucz: numer sędziego).
    busy: Mapping[str, list[BusyMatch]] = field(default_factory=dict)
    #: Ustalone pary: numer sędziego -> numer partnera.
    partner_of: Mapping[str, str] = field(default_factory=dict)
    #: Para mentorska PARY sędziego: numer sędziego -> numery mentorów.
    mentors_of: Mapping[str, tuple] = field(default_factory=dict)
    #: Sędziowie z wyraźnie większą liczbą meczów boiska w sezonie - ich para
    #: traci pierwszeństwo (`assignment_people.heavy_judges`).
    heavy: set[str] = field(default_factory=set)
    #: Pary, których nie wolno stawiać razem.
    blocked: set[tuple[str, str]] = field(default_factory=set)
    #: Ile meczów sędzia ma już w oknie - punkt wyjścia do równego podziału.
    load: dict[str, int] = field(default_factory=dict)
    #: Wnioski z analizy obsad wybrane przez obsadowego (`insights_policy.Policy`).
    #: `None` = Automat dokładnie taki jak przed analizą.
    policy: Optional[Any] = None
    #: Reguła „zdąży z meczu na mecz" okręgu (`collision_rules`).
    collision: CR.CollisionRules = field(default_factory=CR.CollisionRules)
    #: Mecze w SEZONIE: numer sędziego -> {"field": n, "table": n}.
    season_counts: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    #: Mecze w MIESIĄCU: numer sędziego -> „2026-09" -> {"field": n, "table": n}.
    month_counts: Mapping[str, Mapping[str, Mapping[str, int]]] = field(default_factory=dict)
    #: Stara reguła obciążenia (`W_LOAD` x mecze w oknie) zamiast równego
    #: podziału - wyłącznie do testów porównawczych.
    legacy_load: bool = False
    #: Liczniki w trakcie przebiegu (ustawia `build_plan`); bez nich - kopia
    #: `season_counts` i `month_counts`.
    loads: Optional["Loads"] = None


def month_key(day: Any) -> str:
    """„2026-09" z daty albo chwili (już w czasie polskim)."""
    if day is None:
        return ""
    return f"{day.year:04d}-{day.month:02d}"


class Loads:
    """
    Liczniki równego podziału w trakcie układania: sezon i miesiąc, boisko
    i stolik osobno. To kopia - przebieg dopisuje swoje przydziały, a liczniki
    podane z zewnątrz zostają nietknięte.
    """

    __slots__ = ("season", "month", "period", "run")

    def __init__(
        self,
        season: Optional[Mapping[str, Mapping[str, int]]] = None,
        month: Optional[Mapping[str, Mapping[str, Mapping[str, int]]]] = None,
        period: Optional[Mapping[str, int]] = None,
    ) -> None:
        self.season: dict[str, dict[str, int]] = {
            str(judge_id): {
                FIELD: int((item or {}).get(FIELD, 0) or 0),
                TABLE: int((item or {}).get(TABLE, 0) or 0),
            }
            for judge_id, item in (season or {}).items()
        }
        self.month: dict[str, dict[str, dict[str, int]]] = {}
        for judge_id, months in (month or {}).items():
            own = self.month.setdefault(str(judge_id), {})
            for label, item in (months or {}).items():
                own[str(label)] = {
                    FIELD: int((item or {}).get(FIELD, 0) or 0),
                    TABLE: int((item or {}).get(TABLE, 0) or 0),
                }
        #: Mecze w UKŁADANYM OKRESIE (boisko, stolik i delegatury razem):
        #: te, które sędzia już ma w zakresie (`Context.load`), plus przydziały
        #: z tego przebiegu.
        self.period: dict[str, int] = {
            str(judge_id): int(value or 0) for judge_id, value in (period or {}).items()
        }
        #: Przydziały z TEGO przebiegu: numer -> {"field": n, "table": n}.
        self.run: dict[str, dict[str, int]] = {}

    def copy(self) -> "Loads":
        out = Loads(self.season, self.month, self.period)
        out.run = {judge_id: dict(item) for judge_id, item in self.run.items()}
        return out

    def period_count(self, judge_id: str) -> int:
        return int(self.period.get(judge_id, 0))

    def run_count(self, judge_id: str, kind: Optional[str] = None) -> int:
        own = self.run.get(judge_id) or {}
        if kind is None:
            return int(sum(own.values()))
        return int(own.get(kind, 0))

    def count(self, judge_id: str, kind: str) -> int:
        return int((self.season.get(judge_id) or {}).get(kind, 0))

    def month_count(self, judge_id: str, month: str, kind: str) -> int:
        if not month:
            return 0
        return int(((self.month.get(judge_id) or {}).get(month) or {}).get(kind, 0))

    def add(self, judge_id: str, kind: str, month: str, delta: int = 1) -> None:
        if kind not in (FIELD, TABLE) or not judge_id:
            return
        own = self.season.setdefault(judge_id, {FIELD: 0, TABLE: 0})
        own[kind] = max(0, own.get(kind, 0) + delta)
        if month:
            slot = self.month.setdefault(judge_id, {}).setdefault(month, {FIELD: 0, TABLE: 0})
            slot[kind] = max(0, slot.get(kind, 0) + delta)
        self.period[judge_id] = max(0, self.period.get(judge_id, 0) + delta)
        mine = self.run.setdefault(judge_id, {FIELD: 0, TABLE: 0})
        mine[kind] = max(0, mine.get(kind, 0) + delta)


def loads_of(ctx: "Context") -> Loads:
    """Liczniki przebiegu (`Context.loads`) albo świeża kopia liczników z kontekstu."""
    if ctx.loads is not None:
        return ctx.loads
    return Loads(ctx.season_counts, ctx.month_counts, ctx.load)


def fair_points(count: int, floor: int, mean: float) -> float:
    """
    Kara za obciążenie w jednym wymiarze (sezon albo miesiąc).

    `floor` to najmniej obciążony kandydat do tego gniazda, `mean` - średnia
    aktywnych sędziów. Różnica 1 meczu kosztuje tyle, co kilkadziesiąt
    kilometrów; 2 i więcej - więcej niż jakikolwiek przejazd i premia za parę.
    """
    gap = int(count) - int(floor)
    points = 0.0
    if gap >= 1:
        points += W_GAP_ONE
    if gap >= 2:
        points += W_GAP_STEP * (gap - 1)
    over = float(count) - float(mean)
    if over > 0:
        points += W_OVER_MEAN * over * over
    return points


def period_points(count: int, floor: int) -> float:
    """
    Kara za mecze w układanym okresie ponad najmniej obciążonego kandydata:
    1 mecz różnicy = `W_PERIOD`, 2 = 3 x, 3 = 6 x (trójkątnie).
    """
    gap = int(count) - int(floor)
    if gap <= 0:
        return 0.0
    return W_PERIOD * gap * (gap + 1) / 2


def table_badge_first(code: Any) -> bool:
    """
    Czy przy stoliku tych rozgrywek najpierw idą sędziowie „Stolikowi".

    Tak w rozgrywkach OKRĘGOWYCH. W II lidze i wyżej (I liga, Liga Centralna,
    Superliga) stolik obsadzamy bez tej preferencji - wszyscy na równi.
    """
    return league_level(code) == "okreg" and not table_rule(code)


@dataclass
class Standing:
    """Punkt odniesienia równego podziału dla jednego gniazda."""

    floor_season: int = 0
    floor_month: int = 0
    mean_season: float = 0.0
    mean_month: float = 0.0
    #: Najmniej meczów w układanym okresie wśród WSZYSTKICH kandydatów do
    #: gniazda (bez podziału na „Stolikowych" i resztę).
    floor_period: int = 0


@dataclass
class Proposal:
    """Propozycja do jednego gniazda, razem z uzasadnieniem."""

    match_id: str
    code: str
    slot: str
    judge_id: str
    judge_name: str
    km: Optional[float]
    score: float
    reasons: list[str]
    round_no: int


@dataclass
class Gap:
    """Gniazdo, którego automat nie obsadził, i powód."""

    match_id: str
    code: str
    slot: str
    reason: str


@dataclass
class Plan:
    proposals: list[Proposal] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)

    def by_match(self) -> dict[str, list[Proposal]]:
        out: dict[str, list[Proposal]] = {}
        for item in self.proposals:
            out.setdefault(item.match_id, []).append(item)
        return out


def travel_minutes(km: Optional[float], rules: Optional[CR.CollisionRules] = None) -> float:
    """Ile jedzie się tyle kilometrów. Bez odległości zakładamy godzinę."""
    return CR.travel_minutes(km, rules)


def can_make_both(
    first: Optional[datetime],
    second: Optional[datetime],
    km: Optional[float],
    *,
    first_code: Any = "",
    second_code: Any = "",
    same_venue: bool = False,
    rules: Optional[CR.CollisionRules] = None,
) -> bool:
    """
    Czy da się zdążyć z jednego meczu na drugi - reguła w `collision_rules`
    (ta sama hala: bez nakładania; inna hala: czas meczu + dojazd + zapas).
    Bez terminu (któregokolwiek) NIE blokujemy.
    """
    return CR.can_make_both(
        first,
        second,
        km,
        first_code=first_code,
        second_code=second_code,
        same_venue=same_venue,
        rules=rules,
    )


def _same_day_state(
    ctx: Context, judge_id: str, need: MatchNeed
) -> tuple[bool, bool]:
    """(ma mecz tego dnia, da się zdążyć na oba)."""
    if need.day is None:
        return False, True
    same_day = [
        item
        for item in ctx.busy.get(judge_id, [])
        if item.moment is not None and item.moment.date() == need.day
    ]
    if not same_day:
        return False, True
    for item in same_day:
        venue = CR.same_hall(
            item.hall, item.city, need.hall, need.host_city, a_venue=item.venue, b_venue=need.venue
        )
        distance = 0.0 if venue else ctx.km(item.city, need.host_city)
        if not can_make_both(
            item.moment,
            need.moment,
            distance,
            first_code=item.code,
            second_code=need.code,
            same_venue=venue,
            rules=ctx.collision,
        ):
            return True, False
    return True, True


def _hard_reason(
    ctx: Context, judge: Judge, need: MatchNeed, *, round_no: int
) -> Optional[str]:
    """Powód, dla którego ten sędzia w ogóle nie wchodzi w rachubę."""
    if judge.judge_id in need.crew_ids:
        return "już stoi w tym meczu"
    if ctx.paused(judge.judge_id, need.day):
        return "przerwa sędziego"
    if not ctx.available(judge.judge_id, need.moment):
        return "niedyspozycja"
    _, can_make = _same_day_state(ctx, judge.judge_id, need)
    if not can_make:
        return "ma tego dnia mecz, na który nie zdąży"
    if need.avoid_local and is_local(judge, need.host_city):
        return "klub gospodarza nie chce sędziów z tego miasta"
    if round_no == 1 and judge.preferred_days and need.weekday is not None:
        if need.weekday not in judge.preferred_days:
            return "dzień spoza preferowanych"
    return None


def _fair_score(
    judge_id: str,
    need: MatchNeed,
    kind: str,
    standing: Optional[Standing],
    loads: Loads,
) -> tuple[float, list[str]]:
    """
    Punkty i uzasadnienie równego podziału: okres (wszystkie role razem),
    sezon i miesiąc (ta sama grupa). Liczby w opisie to stan W CHWILI wyboru,
    razem z wcześniejszymi wyborami tego przebiegu.
    """
    base = standing or Standing()
    group = "boisko" if kind == FIELD else "stolik"
    season = loads.count(judge_id, kind)
    month = loads.month_count(judge_id, need.month, kind)
    period = loads.period_count(judge_id)
    in_run = loads.run_count(judge_id, kind)
    points = fair_points(season, base.floor_season, base.mean_season)
    head = f"{group}: {season} w sezonie"
    if in_run:
        head += f" (+{in_run} w tym przebiegu)"
    reasons = [head]
    if need.month:
        points += fair_points(month, base.floor_month, base.mean_month)
        reasons[0] += f", {month} w miesiącu"
    period_gap = period - base.floor_period
    points += period_points(period, base.floor_period)
    if period:
        run_all = loads.run_count(judge_id)
        text = f"{period} w okresie"
        if run_all:
            text += f" (+{run_all} w tym przebiegu)"
        reasons.append(text)
    season_gap = season - base.floor_season
    month_gap = (month - base.floor_month) if need.month else 0
    if season_gap <= 0 and month_gap <= 0:
        reasons.append("najmniej meczów w sezonie i miesiącu" if need.month else "najmniej meczów w sezonie")
    elif month_gap <= 0 and need.month:
        reasons.append("najmniej meczów w miesiącu")
    elif season_gap <= 0:
        reasons.append("najmniej meczów w sezonie")
    if max(season_gap, month_gap) >= 2:
        reasons.append(f"o {max(season_gap, month_gap)} mecze więcej niż najmniej obciążeni")
    if period_gap >= 1:
        # Zero cichych decyzji: wybrany ma już więcej w okresie - nikt z mniejszą
        # liczbą nie mógł (twarde reguły) albo przegrał wyraźnie sezonem.
        reasons.append(f"o {period_gap} w okresie więcej niż najmniej obciążeni")
    return points, reasons


def _standing(
    ctx: Context,
    need: MatchNeed,
    kind: str,
    group: Iterable[Judge],
    loads: Loads,
    *,
    everyone: Optional[Iterable[Judge]] = None,
) -> Standing:
    """
    Najmniej obciążony w grupie kandydatów i średnia AKTYWNYCH sędziów.

    `everyone` - wszyscy kandydaci do gniazda (także spoza grupy „Stolikowych");
    z nich dno okresu. Bez tego - sama grupa.
    """
    people = list(group)
    pool = list(everyone) if everyone is not None else people
    active = list(ctx.judges)
    month = need.month
    seasons = [loads.count(judge.judge_id, kind) for judge in people]
    months = [loads.month_count(judge.judge_id, month, kind) for judge in people]
    periods = [loads.period_count(judge.judge_id) for judge in pool]
    all_seasons = [loads.count(judge_id, kind) for judge_id in active]
    all_months = [loads.month_count(judge_id, month, kind) for judge_id in active]
    return Standing(
        floor_season=min(seasons) if seasons else 0,
        floor_month=min(months) if months else 0,
        mean_season=(sum(all_seasons) / len(all_seasons)) if all_seasons else 0.0,
        mean_month=(sum(all_months) / len(all_months)) if all_months else 0.0,
        floor_period=min(periods) if periods else 0,
    )


def badge_tier(judge: Judge, *, badge_first: bool, loads: Loads, floor_period: int) -> int:
    """
    Grupa przy stoliku okręgowym: 0 = „Stolikowi" (pierwsi), 1 = reszta.

    Stolikowy traci pierwszeństwo, gdy ma w okresie więcej niż
    `TABLE_BADGE_SLACK` meczów ponad najmniej obciążonego kandydata - wtedy
    staje w kolejce na równi z innymi.
    """
    if not badge_first:
        return 0
    if not judge.table_specialist:
        return 1
    if loads.period_count(judge.judge_id) - floor_period > TABLE_BADGE_SLACK:
        return 1
    return 0


def _score(
    ctx: Context,
    judge: Judge,
    need: MatchNeed,
    *,
    kind: str,
    partner: Optional[Judge],
    round_no: int,
    load: Mapping[str, int],
    pair_ready: Optional[Judge] = None,
    standing: Optional[Standing] = None,
    loads: Optional[Loads] = None,
    tier: int = 0,
) -> tuple[float, list[str], Optional[float]]:
    """
    Punkty kandydata - mniej znaczy lepiej - razem z uzasadnieniem.

    `pair_ready` to para kandydata, która TEŻ może stanąć w tym meczu - podawana
    tylko przy pierwszym z kilku pustych gniazd boiska. `standing` to punkt
    odniesienia równego podziału (najmniej obciążony kandydat i średnia).
    """
    reasons: list[str] = []
    city = ctx.city_of(judge.judge_id, need.day)
    km = ctx.km(city, need.host_city) if city and need.host_city else None

    score = 0.0
    if km is None:
        score += W_UNKNOWN_KM
        reasons.append("nie znamy odległości")
    else:
        score += km * W_KM
        reasons.append(f"{round(km)} km")
        # Powyżej progu każdy kilometr boli mocniej - patrz nota przy `FAR_KM`.
        if km > FAR_KM:
            score += (km - FAR_KM) * (FAR_FACTOR - 1.0) * W_KM
            reasons.append("bardzo daleko")

    if is_local(judge, need.host_city):
        score += W_LOCAL
        reasons.append("miejscowy, brano w ostatniej kolejności")

    if ctx.legacy_load:
        taken = int(load.get(judge.judge_id, 0))
        score += taken * W_LOAD
        if taken:
            reasons.append(f"ma już {taken} w tym zakresie")
    else:
        points, why = _fair_score(judge.judge_id, need, kind, standing, loads or loads_of(ctx))
        score += points
        reasons.extend(why)

    if round_no > 1 and judge.preferred_days and need.weekday is not None:
        if need.weekday not in judge.preferred_days:
            score += W_OFF_DAY
            reasons.append("dzień spoza preferowanych")

    has_same_day, _ = _same_day_state(ctx, judge.judge_id, need)
    if has_same_day:
        score += W_SAME_DAY
        reasons.append("ma już mecz tego dnia")

    if partner is not None:
        relation = pair_relation(
            judge.judge_id,
            partner.judge_id,
            partner_of=ctx.partner_of,
            mentors_of=ctx.mentors_of,
            allow_mentor=kind == "field",
        )
        if relation and kind == "field" and (
            judge.judge_id in ctx.heavy or partner.judge_id in ctx.heavy
        ):
            # Zero cichych decyzji: widać, że para BYŁA, tylko ustąpiła równości.
            reasons.append(
                f"{'para' if relation == PAIR else 'para mentorska'} z {partner.name} "
                "bez pierwszeństwa - dużo meczów w sezonie"
            )
        elif relation == PAIR:
            score -= B_FIELD_PAIR if kind == "field" else B_PAIR
            reasons.append(f"para z {partner.name}")
        elif relation == MENTOR:
            score -= B_FIELD_MENTOR
            reasons.append(f"para mentorska z {partner.name}")
    elif pair_ready is not None:
        score -= B_PAIR_READY
        reasons.append(f"może stanąć ze swoją parą ({pair_ready.name})")

    if kind == TABLE and judge.table_specialist and table_badge_first(need.code):
        # Samo pierwszeństwo daje kolejność grup w `_candidates` - tu tylko ślad.
        if tier == 0:
            reasons.append("sędzia stolikowy - pierwszeństwo przy stoliku okręgowym")
        else:
            reasons.append("sędzia stolikowy bez pierwszeństwa - więcej meczów w okresie niż inni")

    if ctx.policy is not None:
        delta, why = ctx.policy.points(
            judge.judge_id,
            need,
            kind=kind,
            partner_id=partner.judge_id if partner is not None else None,
            round_no=round_no,
        )
        if delta or why:
            score += delta
            reasons.extend(f"analiza: {item}" for item in why)

    if judge.preferred_days and need.weekday in judge.preferred_days:
        reasons.append("dzień preferowany")

    return score, reasons, km


def _candidates(
    ctx: Context,
    need: MatchNeed,
    *,
    kind: str,
    partner: Optional[Judge],
    round_no: int,
    load: Mapping[str, int],
    taken_ids: set[str],
    open_count: int = 1,
) -> tuple[list[tuple[float, Judge, list[str], Optional[float]]], dict[str, int]]:
    """
    Kandydaci posortowani od najlepszego, plus licznik powodów odmowy.

    `open_count` - ile gniazd tej grupy jest jeszcze pustych. Przy pierwszym
    z dwóch gniazd boiska premiujemy tych, których para też przejdzie
    wszystkie twarde reguły dla tego meczu.
    """
    valid: list[Judge] = []
    refused: dict[str, int] = {}
    for judge in ctx.judges.values():
        if judge.judge_id in taken_ids:
            continue
        hard = _hard_reason(ctx, judge, need, round_no=round_no) or role_refusal(judge, kind)
        if hard:
            refused[hard] = refused.get(hard, 0) + 1
            continue
        if partner is not None:
            ok, why = pair_ok(judge, partner, blocked=ctx.blocked)
            if not ok:
                refused[why] = refused.get(why, 0) + 1
                continue
        if ctx.policy is not None:
            why = ctx.policy.refuse(
                judge.judge_id,
                need,
                kind=kind,
                partner_id=partner.judge_id if partner is not None else None,
                round_no=round_no,
            )
            if why:
                refused[why] = refused.get(why, 0) + 1
                continue
        valid.append(judge)

    ready_ids = {judge.judge_id for judge in valid}

    # Stolik okręgowy: najpierw „Stolikowi", reszta dopiero po nich. Równy
    # podział sezonu i miesiąca liczy się WEWNĄTRZ grupy - inaczej stolikowy
    # z trzema meczami przegrywałby punktami z kimś spoza grupy, kto ma zero.
    # Okres liczy się dla wszystkich razem, a stolikowy z wyraźnie większą
    # liczbą meczów w okresie traci pierwszeństwo (`badge_tier`).
    badge_first = kind == TABLE and table_badge_first(need.code)
    loads = loads_of(ctx)
    floor_period = min((loads.period_count(judge.judge_id) for judge in valid), default=0)
    tiers = {
        judge.judge_id: badge_tier(judge, badge_first=badge_first, loads=loads, floor_period=floor_period)
        for judge in valid
    }

    def tier_of(judge: Judge) -> int:
        return tiers.get(judge.judge_id, 0)

    standings: dict[int, Standing] = {}
    for tier in set(tiers.values()):
        standings[tier] = _standing(
            ctx,
            need,
            kind,
            [judge for judge in valid if tier_of(judge) == tier],
            loads,
            everyone=valid,
        )

    out: list[tuple[float, Judge, list[str], Optional[float]]] = []
    for judge in valid:
        ready: Optional[Judge] = None
        if kind == "field" and partner is None and open_count >= 2:
            mate_id = ctx.partner_of.get(judge.judge_id)
            mate = ctx.judges.get(mate_id) if mate_id else None
            if (
                mate is not None
                and mate.judge_id in ready_ids
                and judge.judge_id not in ctx.heavy
                and mate.judge_id not in ctx.heavy
                and pair_ok(judge, mate, blocked=ctx.blocked)[0]
            ):
                ready = mate
        score, reasons, km = _score(
            ctx,
            judge,
            need,
            kind=kind,
            partner=partner,
            round_no=round_no,
            load=load,
            pair_ready=ready,
            standing=standings.get(tier_of(judge)),
            loads=loads,
            tier=tier_of(judge),
        )
        out.append((score, judge, reasons, km))
    # Grupa przed punktami: przy stoliku okręgowym „Stolikowi" zawsze pierwsi.
    out.sort(key=lambda item: (tier_of(item[1]), item[0], item[1].name))
    return out, refused


def _explain(refused: Mapping[str, int]) -> str:
    """Najczęstszy powód, dla którego gniazdo zostało puste."""
    if not refused:
        return "brak sędziów na liście okręgu"
    top = sorted(refused.items(), key=lambda item: (-item[1], item[0]))[:2]
    return ", ".join(f"{reason} ({count})" for reason, count in top)


def build_plan(
    needs: Sequence[MatchNeed],
    ctx: Context,
    *,
    rounds: int = 2,
) -> Plan:
    """
    Ułożenie obsady dla pustych gniazd.

    Idziemy meczami po kolei (w kolejności daty), w dwóch obiegach: pierwszy
    trzyma się dni preferowanych przez sędziów, drugi dobiera resztę. Każde
    gniazdo ma własny ranking liczony na bieżąco - wybory z wcześniejszych
    gniazd przebiegu od razu podnoszą liczniki (sezon, miesiąc, okres). Na
    końcu `_rebalance` wyrównuje okres. Obsadzamy WYŁĄCZNIE puste gniazda -
    kto już stoi, zostaje (decyzja użytkownika).
    """
    plan = Plan()
    load = dict(ctx.load)
    busy: dict[str, list[BusyMatch]] = {key: list(value) for key, value in ctx.busy.items()}
    working = Context(
        judges=ctx.judges,
        available=ctx.available,
        paused=ctx.paused,
        city_of=ctx.city_of,
        km=ctx.km,
        busy=busy,
        partner_of=ctx.partner_of,
        mentors_of=ctx.mentors_of,
        heavy=ctx.heavy,
        blocked=ctx.blocked,
        load=load,
        policy=ctx.policy,
        collision=ctx.collision,
        season_counts=ctx.season_counts,
        month_counts=ctx.month_counts,
        legacy_load=ctx.legacy_load,
        # Kopia liczników: przydziały z TEGO przebiegu liczą się od razu.
        loads=ctx.loads.copy()
        if ctx.loads is not None
        else Loads(ctx.season_counts, ctx.month_counts, ctx.load),
    )

    # Stan gniazd w trakcie układania: mecz -> gniazdo -> sędzia.
    filled: dict[str, dict[str, Judge]] = {}
    open_slots: dict[str, dict[str, list[str]]] = {
        need.match_id: {"field": list(need.field_needed), "table": list(need.table_needed)}
        for need in needs
    }
    last_refusals: dict[tuple[str, str], dict[str, int]] = {}

    # ⚠ KOLEJNOŚĆ PĘTLI MA ZNACZENIE. Najpierw BOISKOWI we wszystkich meczach,
    # dopiero potem stoliki - a nie mecz po meczu do kompletu.
    #
    # Idąc meczami, automat wyczerpywał listę sędziów na pierwszych spotkaniach
    # i ostatnie zostawały puste, choć wszystkie potrzebowały tak samo. Przy
    # dzieciach wyglądało to najgorzej: mecz dostawał sam stolik, bo boiskowych
    # już nie było. A to sędzia na boisku jest tam nieodzowny - stolik idzie
    # w ostatniej kolejności (decyzja użytkownika z 12.09.2026).
    for round_no in range(1, max(1, rounds) + 1):
        for kind in ("field", "table"):
            for need in needs:
                slots = open_slots.get(need.match_id) or {}
                pending = list(slots.get(kind) or [])
                if not pending:
                    continue
                for slot in pending:
                    taken = set(need.crew_ids) | {
                        judge.judge_id for judge in filled.get(need.match_id, {}).values()
                    }
                    # Partner do reguły par: ten, kto już stoi w tej samej grupie.
                    group_people = list(
                        need.crew_field if kind == "field" else need.crew_table
                    ) + [
                        judge
                        for key, judge in (filled.get(need.match_id) or {}).items()
                        if key in (FIELD_SLOTS if kind == "field" else TABLE_SLOTS)
                    ]
                    partner = group_people[0] if group_people else None

                    ranked, refused = _candidates(
                        working,
                        need,
                        kind=kind,
                        partner=partner,
                        round_no=round_no,
                        load=load,
                        taken_ids=taken,
                        open_count=len(slots.get(kind) or []),
                    )

                    chosen: Optional[tuple[float, Judge, list[str], Optional[float]]] = None
                    for candidate in ranked:
                        judge = candidate[1]
                        if kind == "table" and table_rule(need.code):
                            crew = [person for person in group_people if person] + [judge]
                            # Wymagania stolika sprawdzamy dopiero, gdy stolik
                            # będzie pełny - inaczej pierwszy wybór blokowałby drugi.
                            remaining = len(slots.get("table") or []) - 1
                            if remaining <= 0:
                                ok, why = table_pair_ok(crew, need.code)
                                if not ok:
                                    refused[why] = refused.get(why, 0) + 1
                                    continue
                        chosen = candidate
                        break

                    if chosen is None:
                        last_refusals[(need.match_id, slot)] = refused
                        continue

                    score, judge, reasons, km = chosen
                    filled.setdefault(need.match_id, {})[slot] = judge
                    slots[kind] = [item for item in (slots.get(kind) or []) if item != slot]
                    load[judge.judge_id] = load.get(judge.judge_id, 0) + 1
                    working.loads.add(judge.judge_id, kind, need.month)
                    if working.policy is not None:
                        working.policy.note_assigned(judge.judge_id, need, kind=kind)
                    busy.setdefault(judge.judge_id, []).append(
                        BusyMatch(
                            moment=need.moment,
                            city=need.host_city,
                            match_id=need.match_id,
                            code=need.code,
                            hall=need.hall,
                            venue=need.venue,
                        )
                    )
                    plan.proposals.append(
                        Proposal(
                            match_id=need.match_id,
                            code=need.code,
                            slot=slot,
                            judge_id=judge.judge_id,
                            judge_name=judge.name,
                            km=km,
                            score=round(score, 2),
                            reasons=reasons,
                            round_no=round_no,
                        )
                    )

    if not working.legacy_load:
        _rebalance(plan, needs, working, filled, busy, load, round_no=max(1, rounds))

    for need in needs:
        slots = open_slots.get(need.match_id) or {}
        for kind in ("field", "table"):
            for slot in slots.get(kind) or []:
                plan.gaps.append(
                    Gap(
                        match_id=need.match_id,
                        code=need.code,
                        slot=slot,
                        reason=_explain(last_refusals.get((need.match_id, slot), {})),
                    )
                )

    plan.proposals.sort(key=lambda item: (item.code, item.slot))
    plan.gaps.sort(key=lambda item: (item.code, item.slot))
    return plan


def _group_people(need: MatchNeed, filled: Mapping[str, Mapping[str, Judge]], kind: str) -> list[Judge]:
    """Kto już stoi w tej grupie gniazd meczu: obecna obsada plus przebieg."""
    slots = FIELD_SLOTS if kind == FIELD else TABLE_SLOTS
    return list(need.crew_field if kind == FIELD else need.crew_table) + [
        judge for key, judge in (filled.get(need.match_id) or {}).items() if key in slots
    ]


def _rebalance(
    plan: Plan,
    needs: Sequence[MatchNeed],
    working: Context,
    filled: dict[str, dict[str, Judge]],
    busy: dict[str, list[BusyMatch]],
    load: dict[str, int],
    *,
    round_no: int,
) -> int:
    """
    Wyrównanie po zachłannym układaniu: propozycja sędziego z NAJWIĘKSZĄ
    liczbą meczów w okresie przechodzi na kogoś, kto ma co najmniej o dwa mniej
    i przechodzi WSZYSTKIE twarde reguły tego gniazda (niedyspozycja, kolizja
    dnia, pary, rola, wymagania stolika). Każda zamiana zmniejsza różnicę, więc
    pętla się kończy; zwraca liczbę zamian.

    Zachłanne układanie z karą okresu zwykle wystarcza - to siatka na
    przypadki, w których wcześniejszy wybór zamknął drogę lepszemu podziałowi
    (np. kolizje dnia albo pierwszy obieg dni preferowanych).
    """
    by_id = {need.match_id: need for need in needs}
    loads = working.loads
    if loads is None:
        return 0
    swaps = 0
    for _ in range(max(1, len(plan.proposals)) * 2):
        order = sorted(
            range(len(plan.proposals)),
            key=lambda index: -loads.period_count(plan.proposals[index].judge_id),
        )
        done = False
        for index in order:
            item = plan.proposals[index]
            need = by_id.get(item.match_id)
            if need is None:
                continue
            kind = FIELD if item.slot in FIELD_SLOTS else TABLE
            before = loads.period_count(item.judge_id)
            if before < 2:
                break
            old = filled.get(need.match_id, {}).get(item.slot)
            if old is None:
                continue
            # Zdejmujemy sędziego z gniazda na próbę.
            filled[need.match_id].pop(item.slot, None)
            loads.add(old.judge_id, kind, need.month, -1)
            kept = [entry for entry in busy.get(old.judge_id, []) if entry.match_id != need.match_id]
            removed = busy.get(old.judge_id, [])
            busy[old.judge_id] = kept
            group = _group_people(need, filled, kind)
            taken = set(need.crew_ids) | {judge.judge_id for judge in filled.get(need.match_id, {}).values()}
            taken.add(old.judge_id)
            ranked, _refused = _candidates(
                working,
                need,
                kind=kind,
                partner=group[0] if group else None,
                round_no=round_no,
                load=load,
                taken_ids=taken,
                open_count=1,
            )
            chosen = None
            for candidate in ranked:
                judge = candidate[1]
                if loads.period_count(judge.judge_id) > before - 2:
                    continue
                if kind == TABLE and table_rule(need.code):
                    ok, _why = table_pair_ok([person for person in group if person] + [judge], need.code)
                    if not ok:
                        continue
                chosen = candidate
                break
            if chosen is None:
                # Nikt lepszy - wracamy do stanu sprzed próby.
                filled[need.match_id][item.slot] = old
                loads.add(old.judge_id, kind, need.month, 1)
                busy[old.judge_id] = removed
                continue
            score, judge, reasons, km = chosen
            filled[need.match_id][item.slot] = judge
            loads.add(judge.judge_id, kind, need.month, 1)
            load[old.judge_id] = max(0, load.get(old.judge_id, 0) - 1)
            load[judge.judge_id] = load.get(judge.judge_id, 0) + 1
            if working.policy is not None:
                forget = getattr(working.policy, "note_unassigned", None)
                if callable(forget):
                    forget(old.judge_id, need, kind=kind)
                working.policy.note_assigned(judge.judge_id, need, kind=kind)
            busy.setdefault(judge.judge_id, []).append(
                BusyMatch(
                    moment=need.moment,
                    city=need.host_city,
                    match_id=need.match_id,
                    code=need.code,
                    hall=need.hall,
                    venue=need.venue,
                )
            )
            plan.proposals[index] = Proposal(
                match_id=item.match_id,
                code=item.code,
                slot=item.slot,
                judge_id=judge.judge_id,
                judge_name=judge.name,
                km=km,
                score=round(score, 2),
                reasons=[
                    *reasons,
                    f"wyrównanie okresu: zamiast {old.name} ({before} w okresie)",
                ],
                round_no=item.round_no,
            )
            swaps += 1
            done = True
            break
        if not done:
            break
    return swaps


# ───────────────────────── kandydaci na jeden mecz ─────────────────────────
#
# Kafelki drag&drop w Obsadzie 2.0 (`POST /province/assignment/candidates`):
# WSZYSCY aktywni sędziowie okręgu z tą samą oceną, co Automat, plus stan
# terminu - `off` (niedyspozycja, przerwa, kolizja - z godzinami), `tight`
# (ten sam dzień, zdąży) albo `free`. Zero cichych odmów: każdy `off` mówi
# dlaczego.

FREE = "free"
TIGHT = "tight"
OFF = "off"


def same_day_matches(ctx: Context, judge_id: str, need: MatchNeed) -> list[BusyMatch]:
    """Inne mecze sędziego tego samego dnia (bez tego meczu)."""
    if need.day is None:
        return []
    return sorted(
        (
            item
            for item in ctx.busy.get(judge_id, [])
            if item.moment is not None
            and item.moment.date() == need.day
            and item.match_id != need.match_id
        ),
        key=lambda item: item.moment,
    )


def blocking_match(ctx: Context, judge_id: str, need: MatchNeed) -> Optional[BusyMatch]:
    """Mecz tego dnia, na który sędzia nie zdąży (albo z którego nie zdąży tutaj)."""
    for item in same_day_matches(ctx, judge_id, need):
        venue = CR.same_hall(
            item.hall, item.city, need.hall, need.host_city, a_venue=item.venue, b_venue=need.venue
        )
        distance = 0.0 if venue else ctx.km(item.city, need.host_city)
        if not can_make_both(
            item.moment,
            need.moment,
            distance,
            first_code=item.code,
            second_code=need.code,
            same_venue=venue,
            rules=ctx.collision,
        ):
            return item
    return None


def _busy_text(item: BusyMatch) -> str:
    when = f"{item.moment:%H:%M}" if item.moment else "?"
    place = item.hall or item.city or "hala nieznana"
    code = f"{item.code} " if item.code else ""
    return f"{code}o {when} ({place})"


@dataclass
class CandidateView:
    judge_id: str
    name: str
    city: str
    km: Optional[float]
    status: str
    reason: str
    why: list[str]
    fits: list[str]
    rank: int = 0
    score: Optional[float] = None
    #: Ograniczenie roli w obsadzie („tylko stolik (ZPRP)", „tylko boisko
    #: (ustawienie okręgu)") - pusto, gdy sędzia może wszędzie.
    role_note: str = ""


def describe_candidates(
    ctx: Context,
    need: MatchNeed,
    *,
    off_reason: Optional[Callable[[str, Optional[datetime]], str]] = None,
    kind: Optional[str] = None,
) -> list[CandidateView]:
    """
    Wszyscy sędziowie kontekstu jako kandydaci do tego meczu, od najlepszego.

    Ocena ta sama co w Automacie (`_score` z równym podziałem, parami,
    kilometrami i pierwszeństwem „Stolikowych" przy stoliku okręgowym) dla
    grupy, której meczowi brakuje (najpierw boisko, potem stolik). `off_reason`
    opisuje niedyspozycję słowami z kalendarza („Praca, 12:00-18:00").
    `kind` wymusza ocenę dla boiska albo stolika - zakładki kandydatów
    „Boisko" i „Stolik" mają własną kolejkę (stolik okręgowy: najpierw
    „Stolikowi"), niezależnie od tego, czego meczowi brakuje najpierw.
    """
    if kind not in (FIELD, TABLE):
        kind = FIELD if (need.field_needed or not need.table_needed) else TABLE
    group_crew = {FIELD: list(need.crew_field), TABLE: list(need.crew_table)}
    loads = loads_of(ctx)
    badge_first = kind == TABLE and table_badge_first(need.code)
    tiers: dict[str, int] = {}

    def tier_of(judge: Judge) -> int:
        return tiers.get(judge.judge_id, 0 if not badge_first or judge.table_specialist else 1)

    views: dict[str, CandidateView] = {}
    ready: list[Judge] = []
    for judge in ctx.judges.values():
        city = ctx.city_of(judge.judge_id, need.day)
        km = ctx.km(city, need.host_city) if city and need.host_city else None
        hard = _hard_reason(ctx, judge, need, round_no=2)
        if hard:
            reason = hard
            if hard == "niedyspozycja" and off_reason is not None:
                text = off_reason(judge.judge_id, need.moment)
                reason = f"niedyspozycja: {text}" if text else hard
            elif hard.startswith("ma tego dnia mecz"):
                other = blocking_match(ctx, judge.judge_id, need)
                if other is not None:
                    reason = f"kolizja: mecz {_busy_text(other)}"
            elif hard == "już stoi w tym meczu":
                reason = "już w obsadzie tego meczu"
            views[judge.judge_id] = CandidateView(
                judge_id=judge.judge_id,
                name=judge.name,
                city=city or judge.city,
                km=km,
                status=OFF,
                reason=reason,
                why=[reason],
                fits=[],
                role_note="; ".join(
                    item for item in (role_refusal(judge, FIELD), role_refusal(judge, TABLE)) if item
                ),
            )
            continue
        fits: list[str] = []
        refusals: list[str] = []
        role_notes: list[str] = []
        for group in (FIELD, TABLE):
            role_why = role_refusal(judge, group)
            if role_why:
                # Rola w obsadzie to twarda reguła Automatu - kafelek mówi
                # wprost, czemu sędzia nie pasuje do tej grupy.
                role_notes.append(role_why)
                refusals.append(f"{'boisko' if group == FIELD else 'stolik'}: {role_why}")
                continue
            partner = next(
                (person for person in group_crew[group] if person.judge_id != judge.judge_id), None
            )
            ok, why = pair_ok(judge, partner, blocked=ctx.blocked)
            if ok:
                fits.append(group)
            elif why:
                refusals.append(f"{'boisko' if group == FIELD else 'stolik'}: {why}")
        others = same_day_matches(ctx, judge.judge_id, need)
        status = TIGHT if others else FREE
        reason = (
            "tego dnia także " + ", ".join(f"mecz {_busy_text(item)}" for item in others)
            if others
            else ""
        )
        if refusals:
            reason = "; ".join([part for part in (reason, *refusals) if part])
        views[judge.judge_id] = CandidateView(
            judge_id=judge.judge_id,
            name=judge.name,
            city=city or judge.city,
            km=km,
            status=status,
            reason=reason,
            why=[],
            fits=fits,
            role_note="; ".join(role_notes),
        )
        if kind in fits:
            ready.append(judge)

    floor_period = min((loads.period_count(judge.judge_id) for judge in ready), default=0)
    for judge in ready:
        tiers[judge.judge_id] = badge_tier(
            judge, badge_first=badge_first, loads=loads, floor_period=floor_period
        )
    standings = {
        tier: _standing(
            ctx, need, kind, [judge for judge in ready if tier_of(judge) == tier], loads, everyone=ready
        )
        for tier in {tier_of(judge) for judge in ready}
    }
    ready_ids = {judge.judge_id for judge in ready}
    partner = next(iter(group_crew[kind]), None)
    for judge in ready:
        pair_ready: Optional[Judge] = None
        if kind == FIELD and partner is None and len(need.field_needed) >= 2:
            mate = ctx.judges.get(ctx.partner_of.get(judge.judge_id, ""))
            if (
                mate is not None
                and mate.judge_id in ready_ids
                and judge.judge_id not in ctx.heavy
                and mate.judge_id not in ctx.heavy
            ):
                pair_ready = mate
        score, reasons, _km = _score(
            ctx,
            judge,
            need,
            kind=kind,
            partner=partner if partner is not None and partner.judge_id != judge.judge_id else None,
            round_no=2,
            load=ctx.load,
            pair_ready=pair_ready,
            standing=standings.get(tier_of(judge)),
            loads=loads,
            tier=tier_of(judge),
        )
        view = views[judge.judge_id]
        view.score = round(score, 2)
        view.why = reasons

    def order(view: CandidateView) -> tuple:
        judge = ctx.judges[view.judge_id]
        return (
            view.status == OFF,
            view.score is None,
            tier_of(judge),
            view.score if view.score is not None else 0.0,
            view.name,
        )

    out = sorted(views.values(), key=order)
    for index, view in enumerate(out, start=1):
        view.rank = index
    return out
