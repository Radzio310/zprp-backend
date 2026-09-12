"""
Swiat automatu obsady zbudowany z bazy: sedziowie, niedyspozycje, pary, kilometry.

Tu i tylko tu spotykaja sie tabele z regulami. `assignment_auto` nie wie, ze
istnieje Postgres, a ten modul nie wie, co to punkty - dzieki temu regule da sie
sprawdzic testem, a zapytania zoptymalizowac bez dotykania regul.

Skad co bierzemy:
  - KTO           `province_judges` (okreg + odznaki panelu),
  - UPRAWNIENIA   `zprp_judge_grades` po kluczu nazwiska - litery (SL)(LC)(I)…
                  zbierane przy kazdym otwarciu formularza obsady,
  - MIASTO        `silesia_offtimes` / `province_central_offtimes` (kalendarz
                  niesie miasto sedziego), a czasowa zmiana miasta („TEMP_CITY")
                  przestawia je na wskazane dni,
  - NIEDYSPOZYCJE te same kalendarze, przez `offtime_rules` - ta sama regula,
                  co w telefonie,
  - USTAWIENIA    `province_judge_settings`, `_blocks`, `_pauses`, `_pairs`,
  - OBCIAZENIE    `province_matches` - mecze, ktore sedzia juz ma w zakresie.

⚠ `state_json` i kazda inna kolumna JSON potrafi wrocic z bazy SUROWYM NAPISEM
(asyncpg bez kodeka jsonb) - dlatego wszystko idzie przez `state_dict`.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta
from typing import Any, Iterable, Mapping, Optional, Sequence

from app import assignment_rules as A
from app import offtime_rules as O
from app.assignment_auto import BusyMatch, Context, MatchNeed
from app.assignment_distances import DistanceBook
from app.assignment_people import Judge, make_judge, name_key
from app.match_market_access import badge_names
from app.match_market_rules import state_dict
from app.settlement_province import spellings

# ⚠ `app.db` laczy sie z Postgresem JUZ PRZY IMPORCIE, wiec wchodzi do srodka
# funkcji, ktore go potrzebuja. Dzieki temu reguly z tego modulu - `Roster`,
# `need_from_state`, `build_context` - chodza w tescie bez bazy.

logger = logging.getLogger(__name__)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _json_list(value: Any) -> list:
    """Kolumna JSON do listy - takze wtedy, gdy wrocila napisem."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return []
    if isinstance(value, str):
        if not value.strip():
            return []
        try:
            value = json.loads(value)
        except ValueError:
            return []
    if isinstance(value, dict):
        return [key for key, ok in value.items() if ok]
    return list(value) if isinstance(value, (list, tuple)) else []


class Roster:
    """Sedziowie okregu razem z tym, czego automat o nich nie policzy sam."""

    __slots__ = ("judges", "offtimes", "cities", "pauses", "pairs", "blocks", "settings", "grades")

    def __init__(self) -> None:
        self.judges: dict[str, Judge] = {}
        self.offtimes: dict[str, list[O.Offtime]] = {}
        self.cities: dict[str, list[O.TempCity]] = {}
        self.pauses: dict[str, list[tuple[date, date]]] = {}
        self.pairs: dict[str, str] = {}
        self.blocks: set[tuple[str, str]] = set()
        self.settings: dict[str, dict] = {}
        self.grades: dict[str, list[str]] = {}

    def available(self, judge_id: str, moment: Optional[datetime]) -> bool:
        return O.is_available_at(self.offtimes.get(judge_id, ()), moment)

    def paused(self, judge_id: str, day: Optional[date]) -> bool:
        if day is None:
            return False
        return any(start <= day <= end for start, end in self.pauses.get(judge_id, ()))

    def city_of(self, judge_id: str, day: Optional[date]) -> str:
        judge = self.judges.get(judge_id)
        home = judge.city if judge else ""
        if day is None:
            return home
        moment = datetime.combine(day, datetime.min.time())
        return O.city_at(home, self.cities.get(judge_id, ()), moment)

    def busy_minutes(self, judge_id: str, day: date) -> int:
        return O.busy_minutes_on_day(self.offtimes.get(judge_id, ()), day)


async def load_roster(province: str) -> Roster:
    """Jedno pobranie na przebieg - potem juz tylko odczyt z pamieci."""
    from sqlalchemy import and_, select

    from app.db import (
        database,
        province_central_offtimes,
        province_judge_blocks,
        province_judge_pairs,
        province_judge_pauses,
        province_judge_settings,
        province_judges,
        silesia_offtimes,
        zprp_judge_grades,
    )

    roster = Roster()
    names = spellings(province)

    people = await database.fetch_all(
        select(province_judges).where(province_judges.c.province.in_(names))
    )
    grades = {
        _s(row["name_key"]): [str(x) for x in _json_list(row["letters"])]
        for row in await database.fetch_all(select(zprp_judge_grades))
    }
    roster.grades = grades

    settings_rows = await database.fetch_all(
        select(province_judge_settings).where(province_judge_settings.c.province.in_(names))
    )
    settings = {
        _s(row["judge_id"]): {
            "needs_experienced": bool(row["needs_experienced"]),
            "preferred_days": [
                int(day) for day in _json_list(row["preferred_days"]) if str(day).strip().isdigit()
            ],
            "note": _s(row["note"]),
        }
        for row in settings_rows
    }
    roster.settings = settings

    # Kalendarze: okregowy i centralny. Miasto bierzemy z tego, ktory je ma -
    # wpis centralny bywa swiezszy, a okregowy pelniejszy.
    cities: dict[str, str] = {}
    entries: dict[str, list] = {}
    for table in (silesia_offtimes, province_central_offtimes):
        where = [table.c.province.in_(names)]
        if table is province_central_offtimes:
            where.append(table.c.active.is_(True))
        for row in await database.fetch_all(select(table).where(and_(*where))):
            judge_id = _s(row["judge_id"])
            if not judge_id:
                continue
            city = _s(row["city"])
            if city:
                cities.setdefault(judge_id, city)
            entries.setdefault(judge_id, []).extend(_json_list(row["data_json"]))

    for row in people:
        judge_id = _s(row["judge_id"])
        if not judge_id:
            continue
        full_name = _s(row["full_name"])
        own = settings.get(judge_id, {})
        roster.judges[judge_id] = make_judge(
            judge_id,
            full_name,
            city=cities.get(judge_id, ""),
            letters=grades.get(name_key(full_name), ()),
            badges=badge_names(row["badges"]),
            needs_experienced=own.get("needs_experienced", False),
            preferred_days=own.get("preferred_days", ()),
        )
        offtimes, temp_cities = O.parse_entries(entries.get(judge_id, ()))
        roster.offtimes[judge_id] = offtimes
        roster.cities[judge_id] = temp_cities

    today = datetime.now().date()
    for row in await database.fetch_all(
        select(province_judge_pauses).where(province_judge_pauses.c.province.in_(names))
    ):
        # Przerwy starsze niz tydzien nie maja po co wisiec - patrz `prune_pauses`.
        if row["date_to"] and row["date_to"] < today - timedelta(days=7):
            continue
        roster.pauses.setdefault(_s(row["judge_id"]), []).append(
            (row["date_from"], row["date_to"])
        )

    for row in await database.fetch_all(
        select(province_judge_blocks).where(province_judge_blocks.c.province.in_(names))
    ):
        left, right = _s(row["judge_id"]), _s(row["other_judge_id"])
        if left and right:
            roster.blocks.add((left, right))
            roster.blocks.add((right, left))

    # Pary: wlasna lista okregu wygrywa, lista ZPRP uzupelnia braki (decyzja
    # uzytkownika z 11.09.2026). Para jest obustronna, wiec zapisujemy ja w obie.
    for source in ("zprp", "own"):
        for row in await database.fetch_all(
            select(province_judge_pairs).where(
                and_(
                    province_judge_pairs.c.province.in_(names),
                    province_judge_pairs.c.source == source,
                )
            )
        ):
            left, right = _s(row["judge_id"]), _s(row["partner_id"])
            if left and right and left != right:
                roster.pairs[left] = right
                roster.pairs[right] = left

    return roster


async def manual_match_ids(province: str) -> set[str]:
    """Mecze ukladane recznie - automat ich nie rusza."""
    from sqlalchemy import select

    from app.db import database, province_match_manual

    rows = await database.fetch_all(
        select(province_match_manual.c.match_id).where(
            province_match_manual.c.province.in_(spellings(province))
        )
    )
    return {_s(row["match_id"]) for row in rows if _s(row["match_id"])}


def need_from_state(
    match_id: str,
    state: Mapping[str, Any],
    code: str,
    moment: Optional[datetime],
    roster: Roster,
    *,
    slots: Optional[Iterable[str]] = None,
) -> MatchNeed:
    """
    Jeden mecz przelozony na „czego temu meczowi brakuje".

    Obsadzamy WYLACZNIE puste gniazda: kto juz stoi, zostaje. `slots` zawezaja
    to jeszcze bardziej - obsadowy moze poprosic o same stoliki albo o jedno
    gniazdo w jednym meczu.
    """
    wanted = {str(item).strip() for item in slots} if slots is not None else None
    needs = A.crew_needs(code)
    local = O.match_moment(moment) if moment else None

    crew_ids: set[str] = set()
    crew_field: list[Judge] = []
    crew_table: list[Judge] = []
    empty_field: list[str] = []
    empty_table: list[str] = []

    for group, slot_names, taken, empty in (
        ("field", A.FIELD_SLOTS[: needs["field"]], crew_field, empty_field),
        ("table", A.TABLE_SLOTS[: needs["table"]], crew_table, empty_table),
    ):
        for slot in slot_names:
            person = A.slot_person(state, slot)
            if person and person.get("number"):
                crew_ids.add(_s(person.get("number")))
                known = roster.judges.get(_s(person.get("number")))
                taken.append(known or make_judge(person.get("number"), person.get("name")))
                continue
            if person and _s(person.get("name")):
                # Ktos stoi, ale bez numeru - i tak nie ma tu wolnego miejsca.
                taken.append(make_judge("", person.get("name")))
                continue
            if wanted is None or slot in wanted:
                empty.append(slot)

    return MatchNeed(
        match_id=_s(match_id),
        code=code,
        moment=local,
        day=local.date() if local else None,
        host_city=_s(state.get("Hala_miasto")),
        host=_s(state.get("ID_zespoly_gosp_ZespolNazwa")),
        guest=_s(state.get("ID_zespoly_gosc_ZespolNazwa")),
        hall=_s(state.get("Hala_nazwa")),
        field_needed=empty_field,
        table_needed=empty_table,
        crew_ids=crew_ids,
        crew_field=crew_field,
        crew_table=crew_table,
    )


async def load_busy(
    province: str,
    roster: Roster,
    *,
    date_from: date,
    date_to: date,
) -> tuple[dict[str, list[BusyMatch]], dict[str, int]]:
    """
    Mecze, ktore sedziowie JUZ maja w zakresie: kolizje dnia i rowny podzial.

    Jedno zapytanie o caly zakres zamiast pytania na sedziego - okreg ma ich
    dwustu, a mecze i tak czytamy w calosci.
    """
    from sqlalchemy import and_, select

    from app.db import database, province_matches

    rows = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_at,
            province_matches.c.state_json,
        ).where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.active.is_(True),
                province_matches.c.match_at.is_not(None),
                province_matches.c.match_at >= datetime.combine(date_from, datetime.min.time()),
                province_matches.c.match_at
                < datetime.combine(date_to + timedelta(days=1), datetime.min.time()),
            )
        )
    )

    busy: dict[str, list[BusyMatch]] = {}
    load: dict[str, int] = {}
    for row in rows:
        state = state_dict(row["state_json"])
        moment = O.match_moment(row["match_at"])
        city = _s(state.get("Hala_miasto"))
        match_id = _s(row["match_id"])
        for slot in A.FIELD_SLOTS + A.TABLE_SLOTS + A.DELEGATE_SLOTS:
            person = A.slot_person(state, slot)
            judge_id = _s(person.get("number")) if person else ""
            if not judge_id:
                continue
            entries = busy.setdefault(judge_id, [])
            if any(item.match_id == match_id for item in entries):
                continue
            entries.append(BusyMatch(moment=moment, city=city, match_id=match_id))
            load[judge_id] = load.get(judge_id, 0) + 1
    return busy, load


def build_context(
    roster: Roster,
    book: DistanceBook,
    *,
    busy: Mapping[str, list[BusyMatch]] | None = None,
    load: Mapping[str, int] | None = None,
    only_judges: Optional[Iterable[str]] = None,
) -> Context:
    """Swiat gotowy do podania automatowi."""
    people = dict(roster.judges)
    if only_judges is not None:
        wanted = {str(item).strip() for item in only_judges if str(item).strip()}
        people = {key: value for key, value in people.items() if key in wanted}
    return Context(
        judges=people,
        available=roster.available,
        paused=roster.paused,
        city_of=roster.city_of,
        km=book.km,
        busy=dict(busy or {}),
        partner_of=dict(roster.pairs),
        blocked=set(roster.blocks),
        load=dict(load or {}),
    )


def distance_pairs(needs: Sequence[MatchNeed], roster: Roster) -> list[tuple[str, str]]:
    """Wszystkie kombinacje miasto sedziego - miasto hali z tego przebiegu."""
    halls = {need.host_city for need in needs if need.host_city}
    cities: set[str] = set()
    for judge in roster.judges.values():
        if judge.city:
            cities.add(judge.city)
    for temp_list in roster.cities.values():
        for temp in temp_list:
            if temp.city:
                cities.add(temp.city)
    return [(city, hall) for city in sorted(cities) for hall in sorted(halls)]
