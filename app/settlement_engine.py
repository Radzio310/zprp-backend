"""
Rachunek rozliczenia: z wierszy obsady robi kwoty sedziego i kwoty okregu.

MODUL-LISC. Dostaje gotowe dane (obsady + tabele stawek) i oddaje liczby -
bez bazy, bez sieci, bez daty systemowej poza jawnie podanym `now`. Dzieki temu
caly rachunek, lacznie z regula wyjazdu zbiorczego i przelacznikiem przyszlych
meczow, chodzi w tescie.

Podzial obowiazkow:
  `settlement_rates` - ile sie nalezy za JEDEN mecz (tabele, progi, etapy),
  `settlement_engine` - jak z tych meczow powstaje miesiac sedziego.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Iterable, Optional

from app import settlement_rates as R

#: Przerwa, ponizej ktorej kolejny mecz to jeszcze ten sam wyjazd.
TRIP_GAP_SECONDS = 3 * 60 * 60


def _city_key(value: Any) -> str:
    """Miasto do porownania: bez ogonkow, bez interpunkcji, malymi literami."""
    text = str(value or "").split(",")[0]
    text = R.strip_dia(text).lower()
    for ch in "'\"’.":
        text = text.replace(ch, " ")
    for ch in "-–—/":
        text = text.replace(ch, " ")
    return " ".join(text.split()).strip()


@dataclass
class Assignment:
    """Jedna obsada: sedzia + mecz + rola. Odpowiednik wiersza w bazie."""

    match_key: str
    judge_id: str
    judge_name: str = ""
    match_at: Optional[datetime] = None
    match_code: str = ""
    role: str = R.ROLE_FIELD
    origin: str = "district"
    city: str = ""
    hall: str = ""
    home_city: str = ""
    teams: str = ""
    round_text: Optional[str] = None
    series_text: Optional[str] = None
    distance_km: Optional[float] = None
    distance_source: Optional[str] = None
    approved: Optional[bool] = None


@dataclass
class SettledMatch:
    """Jeden mecz po przeliczeniu."""

    match_key: str
    judge_id: str
    match_at: Optional[datetime]
    day: Optional[date]
    match_code: str
    category: str
    level: str
    role: str
    origin: str
    city: str
    home_city: str
    teams: str
    distance_km: Optional[float]
    distance_source: Optional[str]
    km_rate: float
    gross: int
    travel: int
    travel_shared: bool
    future: bool
    approved: Optional[bool]
    stage: Optional[str] = None
    stage_guessed: bool = False
    status: str = "computed"


@dataclass
class JudgeSettlement:
    """Miesiac jednego sedziego - jeden wiersz zestawienia zbiorczego."""

    judge_id: str
    judge_name: str
    matches: list[SettledMatch] = field(default_factory=list)

    gross: int = 0
    costs: int = 0
    taxable: int = 0
    tax: int = 0
    net: int = 0
    travel: int = 0
    total: int = 0

    match_count: int = 0
    future_count: int = 0
    missing_distance: int = 0
    missing_rate: int = 0
    guessed_stage: int = 0


def _is_future(when: Optional[datetime], now: datetime) -> bool:
    if when is None:
        # Mecz bez terminu nie jest „przyszly" - jest niekompletny. Traktujemy
        # go jak rozegrany, zeby nie znikal z rozliczenia przez brak daty.
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when > now


def _mark_shared_travel(matches: list[SettledMatch]) -> None:
    """
    Dojazd za WYJAZD, ale TYLKO w rozgrywkach dzieci (DzM/DzK).

    Dzien dzieci to w praktyce turniej: kilkanascie spotkan pod rzad w jednej
    hali, na ktore sedzia przyjechal raz. Kazda inna kategoria liczy dojazd przy
    KAZDYM meczu - decyzja uzytkownika z 09.09.2026.

    Placi mecz NAJWCZESNIEJSZY. Kotwica idzie za OSTATNIM meczem wyjazdu, bo
    turniej 9:00-11:00-13:00 to jeden wyjazd, mimo ze skrajne mecze dzieli
    wiecej niz prog. Mecze bez godziny maja ten sam znacznik dnia, wiec przerwa
    wynosi zero i skleja sie w „ten sam dzien, ta sama hala".

    Ta sama regula stoi w `BAZA/utils/tripTravel.ts` i w `mergeTripTravel`
    w BAZA_web - rozjazd oznaczalby, ze aplikacja i lista przejazdow placa za
    inna liczbe dojazdow.
    """
    groups: dict[tuple[str, str], list[SettledMatch]] = {}
    for item in matches:
        if not R.is_children_competition(item.match_code):
            continue
        if item.match_at is None:
            continue
        place = _city_key(item.city or item.hall)
        if not place:
            continue
        groups.setdefault((item.judge_id, place), []).append(item)

    for group in groups.values():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda m: (m.match_at, m.match_key))  # type: ignore[arg-type]
        anchor = ordered[0].match_at
        for item in ordered[1:]:
            gap = (item.match_at - anchor).total_seconds()  # type: ignore[operator]
            if gap < TRIP_GAP_SECONDS:
                item.travel_shared = True
                item.travel = 0
            anchor = item.match_at


def settle_match(
    assignment: Assignment,
    *,
    province: str,
    central_versions: Iterable[Any],
    province_versions: Iterable[Any],
    now: datetime,
) -> SettledMatch:
    """Jeden mecz: stawka, kilometrowka, status."""
    when_date = assignment.match_at.date() if assignment.match_at else None
    central = R.pick_version(central_versions, when_date)
    provincial = R.pick_version(province_versions, when_date)
    central_book = (central or {}).get("content") if isinstance(central, dict) else getattr(central, "content", None)
    province_content = (provincial or {}).get("content") if isinstance(provincial, dict) else getattr(provincial, "content", None)

    level = R.match_level(assignment.match_code)
    stage_hit = R.cup_stage(assignment.match_code, assignment.round_text, assignment.series_text)
    distance = assignment.distance_km

    when = when_date or now.date()
    gross = 0.0
    km_rate = 0.0
    status = "computed"

    if distance is None:
        status = "missing-distance"
    else:
        gross = R.calculate_gross(
            code=assignment.match_code,
            role=assignment.role,
            distance_km=distance,
            when=when,
            central_book=central_book,
            province_content=province_content,
            round_text=assignment.round_text,
            series_text=assignment.series_text,
        )
        km_rate = R.kilometer_rate(
            code=assignment.match_code,
            province=province,
            province_content=province_content,
            central_book=central_book,
            when=when_date,
        )
        if gross <= 0:
            status = "missing-rate"

    return SettledMatch(
        match_key=assignment.match_key,
        judge_id=assignment.judge_id,
        match_at=assignment.match_at,
        day=when_date,
        match_code=assignment.match_code,
        category=R.category_label(assignment.match_code),
        level=level,
        role=assignment.role,
        origin=assignment.origin,
        city=assignment.city or assignment.hall,
        home_city=assignment.home_city,
        teams=assignment.teams,
        distance_km=distance,
        distance_source=assignment.distance_source,
        km_rate=km_rate,
        gross=round(gross),
        travel=R.travel_pln(distance, km_rate) if distance else 0,
        travel_shared=False,
        future=_is_future(assignment.match_at, now),
        approved=assignment.approved,
        stage=stage_hit[0] if stage_hit else None,
        stage_guessed=bool(stage_hit and not stage_hit[1]),
        status=status,
    )


def settle_judges(
    assignments: Iterable[Assignment],
    *,
    province: str,
    central_versions: Iterable[Any],
    province_versions: Iterable[Any],
    now: datetime,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    include_future: bool = False,
    names: Optional[dict[str, str]] = None,
) -> list[JudgeSettlement]:
    """
    Miesiac wszystkich sedziow.

    `include_future` NIE jest drugim zestawem danych, tylko filtrem: wiersze
    lezą w bazie niezaleznie, a przelacznik decyduje, czy mecz jeszcze
    nierozegrany wchodzi do sumy. Dzieki temu odpowiedz „ile bedzie" i „ile
    jest" pochodzi z tego samego zrodla i nie ma jak sie rozjechac.
    """
    central_versions = list(central_versions or [])
    province_versions = list(province_versions or [])
    names = names or {}

    settled: list[SettledMatch] = []
    for assignment in assignments:
        when = assignment.match_at.date() if assignment.match_at else None
        if date_from and (when is None or when < date_from):
            continue
        if date_to and (when is None or when > date_to):
            continue
        item = settle_match(
            assignment,
            province=province,
            central_versions=central_versions,
            province_versions=province_versions,
            now=now,
        )
        if item.future and not include_future:
            continue
        settled.append(item)

    # Sklejanie wyjazdow MUSI isc po odsiewie, bo dojazd placi najwczesniejszy
    # mecz Z TYCH, ktore weszly do rozliczenia.
    _mark_shared_travel(settled)

    by_judge: dict[str, JudgeSettlement] = {}
    for item in settled:
        entry = by_judge.get(item.judge_id)
        if entry is None:
            entry = JudgeSettlement(
                judge_id=item.judge_id,
                judge_name=names.get(item.judge_id, ""),
            )
            by_judge[item.judge_id] = entry
        entry.matches.append(item)

    for entry in by_judge.values():
        entry.matches.sort(key=lambda m: (m.match_at or datetime.min.replace(tzinfo=timezone.utc), m.match_key))
        entry.match_count = len(entry.matches)
        entry.future_count = sum(1 for m in entry.matches if m.future)
        entry.missing_distance = sum(1 for m in entry.matches if m.status == "missing-distance")
        entry.missing_rate = sum(1 for m in entry.matches if m.status == "missing-rate")
        entry.guessed_stage = sum(1 for m in entry.matches if m.stage_guessed)

        total_gross = sum(m.gross for m in entry.matches)
        # ⚠ Koszty uzysku i podatek od SUMY miesiaca, nie mecz po meczu -
        # decyzja uzytkownika z 09.09.2026. Prog 200 zl wypada raz.
        parts = R.settle_period(total_gross)
        entry.gross = parts["gross"]
        entry.costs = parts["costs"]
        entry.taxable = parts["taxable"]
        entry.tax = parts["tax"]
        entry.net = parts["net"]
        entry.travel = sum(m.travel for m in entry.matches)
        entry.total = entry.net + entry.travel

    return sorted(by_judge.values(), key=lambda e: (_sort_name(e.judge_name), e.judge_id))


def _sort_name(value: str) -> str:
    """Sortowanie po nazwisku, po polsku, bez ogonkow psujacych kolejnosc."""
    return unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode().upper()


def totals_of(entries: Iterable[JudgeSettlement]) -> dict[str, int]:
    entries = list(entries)
    return {
        "judges": len(entries),
        "matches": sum(e.match_count for e in entries),
        "future": sum(e.future_count for e in entries),
        "gross": sum(e.gross for e in entries),
        "costs": sum(e.costs for e in entries),
        "taxable": sum(e.taxable for e in entries),
        "tax": sum(e.tax for e in entries),
        "net": sum(e.net for e in entries),
        "travel": sum(e.travel for e in entries),
        "total": sum(e.total for e in entries),
    }


# ---------------------------------------------------------------------------
# Lista kosztow przejazdow
# ---------------------------------------------------------------------------

@dataclass
class TravelRow:
    """Jeden wyjazd - jeden wiersz Listy kosztow przejazdow."""

    judge_id: str
    judge_name: str
    day: Optional[date]
    route: str
    one_way_km: float
    total_km: float
    rate: float
    amount: int


def travel_rows(entries: Iterable[JudgeSettlement]) -> list[TravelRow]:
    """
    Wyjazdy do wydruku.

    Wchodza tylko mecze, ktore FAKTYCZNIE placa dojazd: pominiete sa te ze
    sklejonego wyjazdu (`travel_shared`) i te bez kilometrowki - wiersz na 0 zl
    w liscie kosztow to szum, a nie informacja.

    Trasa w postaci „Bystra-Gliwice-Bystra", bo dojazd rozlicza sie w obie
    strony i tak wyglada dotychczasowy dokument okregu.
    """
    rows: list[TravelRow] = []
    for entry in entries:
        for match in entry.matches:
            if match.travel_shared or not match.travel:
                continue
            home = str(match.home_city or "").strip()
            away = str(match.city or "").strip()
            route = f"{home}-{away}-{home}" if home and away else (away or home or "-")
            rows.append(
                TravelRow(
                    judge_id=entry.judge_id,
                    judge_name=entry.judge_name,
                    day=match.day,
                    route=route,
                    one_way_km=float(match.distance_km or 0),
                    total_km=float(match.distance_km or 0) * R.ROUND_TRIP,
                    rate=match.km_rate,
                    amount=match.travel,
                )
            )
    rows.sort(key=lambda r: (_sort_name(r.judge_name), r.day or date.min, r.route))
    return rows
