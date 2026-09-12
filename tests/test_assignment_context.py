from datetime import date, datetime, timezone

from app.assignment_context import Roster, build_context, distance_pairs, need_from_state
from app.assignment_distances import DistanceBook
from app.assignment_people import make_judge
from app.offtime_rules import parse_entries
from app.settlement_distances import DistanceIndex


def roster_with(*judges, **rest):
    roster = Roster()
    for judge in judges:
        roster.judges[judge.judge_id] = judge
        roster.offtimes[judge.judge_id] = []
        roster.cities[judge.judge_id] = []
    for key, value in rest.items():
        setattr(roster, key, value)
    return roster


STATE = {
    "RozgrywkiCode": "S/JmM/12",
    "Hala_miasto": "Gliwice",
    "Hala_nazwa": "Hala Sportowa",
    "ID_zespoly_gosp_ZespolNazwa": "SPR Gliwice",
    "ID_zespoly_gosc_ZespolNazwa": "MKS Zabrze",
}


def test_only_empty_slots_become_needs():
    state = {**STATE, "NrSedzia_pierwszy": "77", "NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan"}
    need = need_from_state("1", state, "S/JmM/12", datetime(2026, 10, 5, 18, 0), roster_with())
    assert need.field_needed == ["drugi"]
    assert need.table_needed == ["sekretarz", "czas"]
    assert need.crew_ids == {"77"}
    assert need.host == "SPR Gliwice" and need.guest == "MKS Zabrze"


def test_zero_means_an_empty_slot_not_a_judge():
    state = {**STATE, "NrSedzia_pierwszy": "0", "NrSedzia_pierwszy_nazwisko": ""}
    need = need_from_state("1", state, "S/JmM/12", None, roster_with())
    assert need.field_needed == ["pierwszy", "drugi"]
    assert not need.crew_ids


def test_a_name_without_a_number_still_takes_the_slot():
    state = {**STATE, "NrSedzia_drugi_nazwisko": "NOWAK Anna"}
    need = need_from_state("1", state, "S/JmM/12", None, roster_with())
    assert need.field_needed == ["pierwszy"]
    assert [judge.name for judge in need.crew_field] == ["NOWAK Anna"]


def test_the_standing_crew_comes_back_as_known_people():
    jan = make_judge("77", "KOWALSKI Jan", city="Gliwice", letters=["II"])
    state = {**STATE, "NrSedzia_pierwszy": "77", "NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan"}
    need = need_from_state("1", state, "S/JmM/12", None, roster_with(jan))
    assert need.crew_field[0].league          # zna uprawnienia, nie samo nazwisko


def test_small_categories_need_one_of_each():
    need = need_from_state("1", {**STATE}, "DZM/4", None, roster_with())
    assert need.field_needed == ["pierwszy"]
    assert need.table_needed == ["sekretarz"]


def test_asking_for_one_slot_narrows_the_need():
    need = need_from_state("1", STATE, "S/JmM/12", None, roster_with(), slots=["czas"])
    assert need.field_needed == []
    assert need.table_needed == ["czas"]


def test_match_time_keeps_the_polish_hour():
    stored = datetime(2026, 10, 5, 18, 0, tzinfo=timezone.utc)
    need = need_from_state("1", STATE, "S/JmM/12", stored, roster_with())
    assert need.moment == datetime(2026, 10, 5, 18, 0)
    assert need.day == date(2026, 10, 5)


def test_pause_covers_the_whole_range():
    roster = roster_with(pauses={"1": [(date(2026, 10, 1), date(2026, 10, 10))]})
    assert roster.paused("1", date(2026, 10, 5))
    assert not roster.paused("1", date(2026, 10, 11))
    assert not roster.paused("1", None)       # mecz bez terminu nie jest w przerwie


def test_temporary_city_wins_for_those_days():
    jan = make_judge("1", "KOWALSKI Jan", city="Gliwice")
    roster = roster_with(jan)
    _, cities = parse_entries(
        [
            {
                "entry_type": "TEMP_CITY",
                "temp_city_name": "Kraków",
                "from": "2026-10-03T00:00:00",
                "to": "2026-10-06T00:00:00",
            }
        ]
    )
    roster.cities["1"] = cities
    assert roster.city_of("1", date(2026, 10, 4)) == "Kraków"
    assert roster.city_of("1", date(2026, 10, 9)) == "Gliwice"
    assert roster.city_of("1", None) == "Gliwice"


def test_unavailability_reaches_the_context():
    jan = make_judge("1", "KOWALSKI Jan", city="Gliwice")
    roster = roster_with(jan)
    roster.offtimes["1"], _ = parse_entries([{"from": "2026-10-05T09:00:00"}])
    assert not roster.available("1", datetime(2026, 10, 5, 18, 0))
    assert roster.available("1", datetime(2026, 10, 6, 18, 0))


def test_context_can_be_narrowed_to_chosen_judges():
    jan = make_judge("1", "KOWALSKI Jan")
    anna = make_judge("2", "NOWAK Anna")
    roster = roster_with(jan, anna, pairs={"1": "2", "2": "1"}, blocks={("1", "2")})
    ctx = build_context(roster, DistanceBook(DistanceIndex()), only_judges=["2"])
    assert list(ctx.judges) == ["2"]
    assert ctx.partner_of == {"1": "2", "2": "1"}
    assert ctx.blocked == {("1", "2")}


def test_distance_pairs_cover_every_judge_city_and_every_hall():
    jan = make_judge("1", "KOWALSKI Jan", city="Gliwice")
    anna = make_judge("2", "NOWAK Anna", city="Zabrze")
    roster = roster_with(jan, anna)
    needs = [
        need_from_state("1", {**STATE, "Hala_miasto": "Katowice"}, "S/JmM/1", None, roster),
        need_from_state("2", {**STATE, "Hala_miasto": "Bytom"}, "S/JmM/2", None, roster),
    ]
    pairs = distance_pairs(needs, roster)
    assert len(pairs) == 4
    assert ("Gliwice", "Bytom") in pairs and ("Zabrze", "Katowice") in pairs
