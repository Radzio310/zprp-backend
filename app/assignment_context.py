"""
Świat automatu obsady zbudowany z bazy: sędziowie, niedyspozycje, pary, kilometry.

Tu i tylko tu spotykają się tabele z regułami. `assignment_auto` nie wie, że
istnieje Postgres, a ten moduł nie wie, co to punkty - dzięki temu regule da się
sprawdzić testem, a zapytania zoptymalizować bez dotykania reguł.

Skąd co bierzemy:
  - KTO           `province_judges` (okręg + odznaki panelu),
  - UPRAWNIENIA   `zprp_judge_grades` po kluczu nazwiska - litery (SL)(LC)(I)…
                  zbierane przy każdym otwarciu formularza obsady,
  - MIASTO        `silesia_offtimes` / `province_central_offtimes` (kalendarz
                  niesie miasto sędziego), a czasową zmianą miasta („TEMP_CITY")
                  przestawia je na wskazane dni,
  - NIEDYSPOZYCJE te same kalendarze, przez `offtime_rules` - ta sama reguła,
                  co w telefonie,
  - USTAWIENIA    `province_judge_settings`, `_blocks`, `_pauses`, `_pairs`,
  - OBCIĄŻENIE    `province_matches` - mecze, które sędzia już ma w zakresie.

⚠ `state_json` i każda inna kolumna JSON potrafi wrócić z bazy SUROWYM NAPISEM
(asyncpg bez kodeka jsonb) - dlatego wszystko idzie przez `state_dict`.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta
from typing import Any, Iterable, Mapping, Optional, Sequence

from app import assignment_rules as A
from app import collision_rules as CR
from app import offtime_rules as O
from app.assignment_auto import BusyMatch, Context, MatchNeed
from app.assignment_distances import DistanceBook
from app.assignment_people import Judge, heavy_judges, make_judge, name_key, pair_key
from app.match_market_access import badge_names
from app.match_market_rules import state_dict
from app.settlement_province import spellings

# ⚠ `app.db` łączy się z Postgresem JUŻ PRZY IMPORCIE, więc wchodzi do środka
# funkcji, które go potrzebują. Dzięki temu reguły z tego modułu - `Roster`,
# `need_from_state`, `build_context` - chodzą w teście bez bazy.

logger = logging.getLogger(__name__)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _json_list(value: Any) -> list:
    """Kolumna JSON do listy - także wtedy, gdy wróciła napisem."""
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
    """Sędziowie okręgu razem z tym, czego automat o nich nie policzy sam."""

    __slots__ = (
        "judges", "offtimes", "cities", "pauses", "pairs", "blocks", "settings",
        "grades", "clubs", "pair_source", "mentor_pairs",
    )

    def __init__(self) -> None:
        self.judges: dict[str, Judge] = {}
        self.offtimes: dict[str, list[O.Offtime]] = {}
        self.cities: dict[str, list[O.TempCity]] = {}
        self.pauses: dict[str, list[tuple[date, date]]] = {}
        self.pairs: dict[str, str] = {}
        self.blocks: set[tuple[str, str]] = set()
        self.settings: dict[str, dict] = {}
        self.grades: dict[str, list[str]] = {}
        #: Ustawienia klubu dla obsady, po kluczu nazwy drużyny gospodarza.
        self.clubs: dict[str, dict] = {}
        #: Skąd para sędziego: "own" (okręg) albo "zprp" (baza.zprp.pl).
        self.pair_source: dict[str, str] = {}
        #: Pary mentorskie: klucz pary sędziowskiej (`pair_key`) -> mentorzy.
        self.mentor_pairs: dict[str, list[str]] = {}

    def mentors_of(self, judge_id: str) -> list[str]:
        """Mentorzy przypisani PARZE tego sędziego - bez pary nie ma mentorów."""
        partner = self.pairs.get(_s(judge_id))
        if not partner:
            return []
        return list(self.mentor_pairs.get(pair_key(judge_id, partner), []))

    def mentor_map(self) -> dict[str, tuple]:
        """Numer sędziego -> mentorzy jego pary, dla `Context.mentors_of`."""
        out: dict[str, tuple] = {}
        for judge_id in self.pairs:
            mentors = self.mentors_of(judge_id)
            if mentors:
                out[judge_id] = tuple(mentors)
        return out

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

    def club_for(self, host: Any) -> dict:
        """
        Ustawienia klubu gospodarza - po NAZWIE drużyny.

        ⚠ Mecze nie niosą numeru klubu, tylko nazwę drużyny, więc dopasowanie
        idzie tą samą drogą, co obciążenia w panelu klubów (`team_key`).
        Nieznana nazwa to pusty słownik, nie wyjątek: brak ustawień znaczy
        „wszystko po staremu".
        """
        from app.province_clubs_scrape import team_key

        return self.clubs.get(team_key(host), {})

    def busy_minutes(self, judge_id: str, day: date) -> int:
        return O.busy_minutes_on_day(self.offtimes.get(judge_id, ()), day)


async def load_roster(province: str) -> Roster:
    """Jedno pobranie na przebieg - potem już tylko odczyt z pamięci."""
    from sqlalchemy import and_, select

    from app.db import (
        database,
        judge_calendar_feeds,
        judge_feed_offtimes,
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

    # Kalendarze: okręgowy i centralny. Miasto bierzemy z tego, który je ma -
    # wpis centralny bywa świeższy, a okręgowy pełniejszy.
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

    # Kalendarze sędziego (plan zajęć, grafik pracy). Wchodzą TYLKO te, przy
    # których sędzia zostawił „blokuje obsadę" - kalendarz urodzin nie ma
    # zajmować terminu, a plan zajęć ma.
    blocking = await database.fetch_all(
        select(judge_calendar_feeds).where(
            and_(
                judge_calendar_feeds.c.enabled.is_(True),
                judge_calendar_feeds.c.blocks_assignment.is_(True),
            )
        )
    )
    feed_ids = [str(row["id"]) for row in blocking]
    feed_entries: dict[str, list] = {}
    if feed_ids:
        from app.calendar_feed_rules import judge_key

        for row in await database.fetch_all(
            select(judge_feed_offtimes).where(
                judge_feed_offtimes.c.feed_id.in_(feed_ids)
            )
        ):
            key = judge_key(row["judge_id"])
            if key:
                feed_entries.setdefault(key, []).extend(_json_list(row["data_json"]))

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
        # Kalendarze dokładamy po ZNORMALIZOWANYM numerze - w rejestrze okręgu i
        # w tokenie ten sam sędzia bywa zapisany inaczej (zero wiodące).
        from app.calendar_feed_rules import judge_key as _judge_key

        own_entries = [
            *entries.get(judge_id, ()),
            *feed_entries.get(_judge_key(judge_id), ()),
        ]
        offtimes, temp_cities = O.parse_entries(own_entries)
        roster.offtimes[judge_id] = offtimes
        roster.cities[judge_id] = temp_cities

    roster.clubs = await _club_rules(province)

    today = datetime.now().date()
    for row in await database.fetch_all(
        select(province_judge_pauses).where(province_judge_pauses.c.province.in_(names))
    ):
        # Przerwy starsze niż tydzień nie mają po co wisieć - patrz `prune_pauses`.
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

    # Pary: własna lista okręgu wygrywa, lista ZPRP uzupełnia braki (decyzja
    # użytkownika z 11.09.2026). Para jest obustronna, więc zapisujemy ja w obie.
    rows = await database.fetch_all(
        select(province_judge_pairs).where(province_judge_pairs.c.province.in_(names))
    )
    roster.pairs, roster.pair_source = merge_pairs(
        [(_s(row["judge_id"]), _s(row["partner_id"]), _s(row["source"])) for row in rows]
    )

    from app.db import province_mentor_pairs

    for row in await database.fetch_all(
        select(province_mentor_pairs).where(province_mentor_pairs.c.province.in_(names))
    ):
        mentors = [_s(item) for item in _json_list(row["mentor_ids"]) if _s(item)]
        key = _s(row["pair_key"])
        # Dwie pisownie okręgu - wygrywa wpis z mentorami (pusty to usunięty).
        if key and mentors:
            roster.mentor_pairs[key] = mentors

    return roster


def merge_pairs(rows: Iterable[tuple[str, str, str]]) -> tuple[dict[str, str], dict[str, str]]:
    """
    Pary z obu źródeł sklejone w jedną mapę: (numer -> partner, numer -> źródło).

    Własna para okręgu („own") wygrywa z listą ZPRP. ⚠ Wygrywa CAŁA para: gdy
    okręg sparował A z C, a ZPRP mówi A-B, to B zostaje bez pary - inaczej B
    wskazywałby na A, a A na C, i każdy miałby inne zdanie o tym, z kim sędziuje.
    """
    pairs: dict[str, str] = {}
    source: dict[str, str] = {}
    own = [(a, b) for a, b, kind in rows if kind == "own" and a and b and a != b]
    zprp = [(a, b) for a, b, kind in rows if kind != "own" and a and b and a != b]
    for left, right in own:
        pairs[left], pairs[right] = right, left
        source[left] = source[right] = "own"
    for left, right in zprp:
        if left in pairs or right in pairs:
            continue
        pairs[left], pairs[right] = right, left
        source[left] = source[right] = "zprp"
    return pairs, source


async def _club_rules(province: str) -> dict[str, dict]:
    """
    Ustawienia obsadowe klubów, gotowe do szukania po nazwie drużyny gospodarza.

    Klucz to `team_key` nazwy drużyny, bo tylko nazwę niesie mecz. Jeden klub
    ma zwykle kilka drużyn (młodziczki, juniorzy, dzieci) i wszystkie dziedziczą
    to samo ustawienie - stolik stawia KLUB, nie rocznik.
    """
    from sqlalchemy import and_, select

    from app.db import database, province_club_assignment, province_club_teams
    from app.province_clubs_bulk import newest_rule_per_club
    from app.province_clubs_scrape import team_key
    from app.settlement_province import canonical
    from app.settlement_seasons import season_of

    out: dict[str, dict] = {}
    rows = await database.fetch_all(
        select(province_club_assignment).where(
            province_club_assignment.c.province.in_(spellings(province))
        )
    )
    if not rows:
        return out
    by_club = {
        _s(row["club_id"]): {
            "club_id": _s(row["club_id"]),
            "table_by_club": int(row["table_by_club"] or 0),
            # Deklaracja działa od tego dnia - mecz sprzed niej liczy się po
            # staremu (`assignment_rules.club_table_active`).
            "table_by_club_since": row["table_by_club_since"]
            if "table_by_club_since" in row.keys()
            else None,
            "avoid_local": bool(row["avoid_local"]),
            "note": _s(row["note"]),
        }
        # Jeden wiersz na klub, najświeższy - patrz `newest_rule_per_club`.
        for row in newest_rule_per_club(rows, canonical(province)).values()
    }

    season = season_of(datetime.now())
    teams = await database.fetch_all(
        select(
            province_club_teams.c.club_id,
            province_club_teams.c.team_name,
            province_club_teams.c.name_key,
        ).where(
            and_(
                province_club_teams.c.province.in_(spellings(province)),
                province_club_teams.c.season == season,
            )
        )
    )
    for row in teams:
        rules = by_club.get(_s(row["club_id"]))
        if not rules:
            continue
        key = _s(row["name_key"]) or team_key(row["team_name"])
        if key:
            out.setdefault(key, rules)
    return out


async def manual_match_ids(province: str) -> set[str]:
    """Mecze układane ręcznie - automat ich nie rusza."""
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
    Jeden mecz przełożony na „czego temu meczowi brakuje".

    Obsadzamy WYŁĄCZNIE puste gniazda: kto już stoi, zostaje. `slots` zawężają
    to jeszcze bardziej - obsadowy może poprosić o same stoliki albo o jedno
    gniazdo w jednym meczu.
    """
    wanted = {str(item).strip() for item in slots} if slots is not None else None
    local = O.match_moment(moment) if moment else None

    # Klub gospodarza bywa umówiony, że jednego stolikowego stawia z własnych
    # ludzi - wtedy okręg posyła o jednego mniej, ale ZAWSZE co najmniej jednego.
    # Boiskowych to nie dotyczy: tych zapewnia okręg. Reguła siedzi w
    # `assignment_rules.club_crew_needs`, bo tak samo liczy ją lista obsady.
    club = roster.club_for(state.get("ID_zespoly_gosp_ZespolNazwa"))
    needs = A.club_crew_needs(
        code,
        A.club_table_active(
            club.get("table_by_club", 0), club.get("table_by_club_since"), local
        ),
    )

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
                # Ktoś stoi, ale bez numeru - i tak nie ma tu wolnego miejsca.
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
        avoid_local=bool(club.get("avoid_local")),
        host=_s(state.get("ID_zespoly_gosp_ZespolNazwa")),
        guest=_s(state.get("ID_zespoly_gosc_ZespolNazwa")),
        hall=_s(state.get("Hala_nazwa")),
        venue=CR.venue_of(state),
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
    Mecze, które sędziowie JUŻ mają w zakresie: kolizje dnia i równy podział.

    Jedno zapytanie o cały zakres zamiast pytania na sędziego - okręg ma ich
    dwustu, a mecze i tak czytamy w całości.
    """
    from sqlalchemy import and_, select

    from app.db import database, province_matches

    rows = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_code,
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
            entries.append(
                BusyMatch(
                    moment=moment,
                    city=city,
                    match_id=match_id,
                    code=_s(state.get("RozgrywkiCode") or row["match_code"]),
                    hall=_s(state.get("Hala_nazwa")),
                    venue=CR.venue_of(state),
                )
            )
            load[judge_id] = load.get(judge_id, 0) + 1
    return busy, load


def build_context(
    roster: Roster,
    book: DistanceBook,
    *,
    busy: Mapping[str, list[BusyMatch]] | None = None,
    load: Mapping[str, int] | None = None,
    only_judges: Optional[Iterable[str]] = None,
    inactive: Iterable[str] = (),
    season_field: Optional[Mapping[str, int]] = None,
    season_counts: Optional[Mapping[str, Mapping[str, int]]] = None,
    month_counts: Optional[Mapping[str, Mapping[str, Mapping[str, int]]]] = None,
    collision: Optional[CR.CollisionRules] = None,
) -> Context:
    """Świat gotowy do podania automatowi.

    `inactive` - numery sędziów spoza listy AKTYWNYCH okręgu w sezonie
    (`inactive_judges`). Automat ich nie proponuje; ich obecne obsady dalej
    liczą się w zajętości (`busy`) i zostają w meczach.

    `season_field` - mecze boiska w sezonie po numerze sędziego. Z nich wynika,
    czyja para traci pierwszeństwo (`assignment_people.heavy_judges`); bez
    liczników pary mają pierwszeństwo zawsze.

    `season_counts` / `month_counts` - boisko i stolik w sezonie i w miesiącach
    (`assignment_load.SeasonBook.counts`), podstawa równego podziału.
    `collision` - reguła „zdąży z meczu na mecz" okręgu (`collision_rules`).
    """
    skip = {str(item).strip() for item in inactive}
    people = {key: value for key, value in roster.judges.items() if key not in skip}
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
        mentors_of=roster.mentor_map(),
        heavy=heavy_judges(season_field or {}, people.keys()),
        blocked=set(roster.blocks),
        load=dict(load or {}),
        collision=collision or CR.CollisionRules(),
        season_counts=dict(season_counts or {}),
        month_counts=dict(month_counts or {}),
    )


def inactive_judges(province: str, when: Any, roster: Roster) -> set[str]:
    """
    Sędziowie z rejestru okręgu, których nie ma na liście aktywnych
    z baza.zprp.pl w sezonie `when` (`app/official_roster.py`). Okręg albo
    sezon bez listy - pusty zbiór, czyli wszyscy jak dawniej.

    Decyzja użytkownika z 23.09.2026: automat obsad bierze pod uwagę TYLKO
    aktywnych sędziów województwa.
    """
    from app.official_roster import inactive_ids

    return inactive_ids(
        province,
        when,
        [{"judge_id": jid, "full_name": judge.name} for jid, judge in roster.judges.items()],
    )


def distance_pairs(needs: Sequence[MatchNeed], roster: Roster) -> list[tuple[str, str]]:
    """Wszystkie kombinacje miasto sędziego - miasto hali z tego przebiegu."""
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
