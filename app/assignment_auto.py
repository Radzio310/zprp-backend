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
    7. przerwa sędziego (pauza) i drugie gniazdo w tym samym meczu.

  MIĘKKIE - liczą się punktami, mniej znaczy lepiej:
    - KILOMETRY, bo to główne kryterium,
    - sędzia z miasta gospodarza (unikamy),
    - równy podział (kto ma już dużo, dostaje mniej chętnie),
    - dzień spoza preferowanych przez sędziego,
    - mecz tego samego dnia, na który ZDĄŻY - ostateczność,
    - premia za ustaloną parę i za odznakę „Stolikowi" na stoliku okręgowym.

DWA OBIEGI: pierwszy obsadza wyłącznie w dniach preferowanych przez sędziego,
drugi dobiera resztę. Sędzia bez wskazanych dni pasuje do każdego obiegu.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Callable, Iterable, Mapping, Optional, Sequence

from app.assignment_people import Judge, is_local, pair_ok, table_pair_ok, table_rule

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
W_LOAD = 35.0
W_OFF_DAY = 120.0
W_SAME_DAY = 600.0
W_UNKNOWN_KM = 90.0
B_PAIR = 250.0
B_TABLE_BADGE = 60.0

#: Ile kilometrów na godzinę zakłada automat, licząc czy sędzia zdąży z meczu na mecz.
TRAVEL_KMH = 60.0
#: Mecz trwa dwie godziny, a do tego zapas na protokół i dojazd.
MATCH_HOURS = 2.0
SAFETY_MINUTES = 45

FIELD_SLOTS = ("pierwszy", "drugi")
TABLE_SLOTS = ("sekretarz", "czas")


@dataclass
class BusyMatch:
    """Mecz, który sędzia już ma - własny albo właśnie przydzielony."""

    moment: Optional[datetime]
    city: str
    match_id: str


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

    @property
    def weekday(self) -> Optional[int]:
        return self.day.weekday() if self.day else None


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
    #: Pary, których nie wolno stawiać razem.
    blocked: set[tuple[str, str]] = field(default_factory=set)
    #: Ile meczów sędzia ma już w oknie - punkt wyjścia do równego podziału.
    load: dict[str, int] = field(default_factory=dict)


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


def travel_minutes(km: Optional[float]) -> float:
    """Ile jedzie się tyle kilometrów. Bez odległości zakładamy godzinę."""
    if km is None:
        return 60.0
    return (float(km) / TRAVEL_KMH) * 60.0


def can_make_both(
    first: Optional[datetime],
    second: Optional[datetime],
    km: Optional[float],
) -> bool:
    """
    Czy da się zdążyć z jednego meczu na drugi.

    Mecz trwa dwie godziny, do tego dojazd i zapas bezpieczeństwa. Bez terminu
    (któregokolwiek) nie wiemy nic - i wtedy NIE blokujemy, bo „nie wiem" nie
    może odbierać sędziemu meczu.
    """
    if first is None or second is None:
        return True
    gap = abs((second - first).total_seconds()) / 60.0
    return gap >= MATCH_HOURS * 60 + travel_minutes(km) + SAFETY_MINUTES


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
        distance = ctx.km(item.city, need.host_city)
        if not can_make_both(item.moment, need.moment, distance):
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


def _score(
    ctx: Context,
    judge: Judge,
    need: MatchNeed,
    *,
    kind: str,
    partner: Optional[Judge],
    round_no: int,
    load: Mapping[str, int],
) -> tuple[float, list[str], Optional[float]]:
    """Punkty kandydata - mniej znaczy lepiej - razem z uzasadnieniem."""
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

    taken = int(load.get(judge.judge_id, 0))
    score += taken * W_LOAD
    if taken:
        reasons.append(f"ma już {taken} w tym zakresie")

    if round_no > 1 and judge.preferred_days and need.weekday is not None:
        if need.weekday not in judge.preferred_days:
            score += W_OFF_DAY
            reasons.append("dzień spoza preferowanych")

    has_same_day, _ = _same_day_state(ctx, judge.judge_id, need)
    if has_same_day:
        score += W_SAME_DAY
        reasons.append("ma już mecz tego dnia")

    if partner is not None and ctx.partner_of.get(judge.judge_id) == partner.judge_id:
        score -= B_PAIR
        reasons.append(f"para z {partner.name}")

    if kind == "table" and judge.table_specialist and not table_rule(need.code):
        score -= B_TABLE_BADGE
        reasons.append("sędzia stolikowy")

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
) -> tuple[list[tuple[float, Judge, list[str], Optional[float]]], dict[str, int]]:
    """Kandydaci posortowani od najlepszego, plus licznik powodów odmowy."""
    out: list[tuple[float, Judge, list[str], Optional[float]]] = []
    refused: dict[str, int] = {}
    for judge in ctx.judges.values():
        if judge.judge_id in taken_ids:
            continue
        hard = _hard_reason(ctx, judge, need, round_no=round_no)
        if hard:
            refused[hard] = refused.get(hard, 0) + 1
            continue
        if partner is not None:
            ok, why = pair_ok(judge, partner, blocked=ctx.blocked)
            if not ok:
                refused[why] = refused.get(why, 0) + 1
                continue
        score, reasons, km = _score(
            ctx, judge, need, kind=kind, partner=partner, round_no=round_no, load=load
        )
        out.append((score, judge, reasons, km))
    out.sort(key=lambda item: (item[0], item[1].name))
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

    Idziemy meczami po kolei, w dwóch obiegach: pierwszy trzyma się dni
    preferowanych przez sędziów, drugi dobiera resztę. Obsadzamy WYŁĄCZNIE
    puste gniazda - kto już stoi, zostaje (decyzja użytkownika).
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
        blocked=ctx.blocked,
        load=load,
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
                    busy.setdefault(judge.judge_id, []).append(
                        BusyMatch(moment=need.moment, city=need.host_city, match_id=need.match_id)
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
