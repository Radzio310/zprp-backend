from datetime import datetime

from app.assignment_auto import BusyMatch, Context, MatchNeed, build_plan, can_make_both
from app.assignment_people import fold, make_judge

# Maly świat: cztery miasta i znane odległości miedzy nimi.
KM = {
    ("gliwice", "zabrze"): 12,
    ("gliwice", "katowice"): 28,
    ("gliwice", "bielsko-biala"): 78,
    ("zabrze", "katowice"): 20,
    ("zabrze", "bielsko-biala"): 85,
    ("katowice", "bielsko-biala"): 60,
}


def km(a, b):
    left, right = fold(a), fold(b)
    if not left or not right:
        return None
    if left == right:
        return 0.0
    return KM.get((left, right)) or KM.get((right, left))


JAN = make_judge("1", "KOWALSKI Jan", city="Gliwice", letters=["MP", "II", "III", "Mł"])
ANNA = make_judge("2", "NOWAK Anna", city="Zabrze", letters=["MP", "II", "III"])
PAWEL = make_judge("3", "ZIELIŃSKI Paweł", city="Katowice", letters=["SL", "LC", "I", "II"])
EWA = make_judge("4", "JANKOWSKA Ewa", city="Bielsko-Biała", letters=["Mł"], badges=["Młodzi"])
MAREK = make_judge("5", "SZYMAŃSKI Marek", city="Katowice", letters=["III", "Mł"], badges=["Stolikowi"])


def world(judges, **rest):
    people = {judge.judge_id: judge for judge in judges}
    options = {
        "judges": people,
        "available": lambda judge_id, moment: True,
        "paused": lambda judge_id, day: False,
        "city_of": lambda judge_id, day: people[judge_id].city,
        "km": km,
    }
    options.update(rest)
    return Context(**options)


def match(code="S/JmM/1", city="Gliwice", when="2026-10-05T18:00", field=2, table=0, **rest):
    """Mecz do obsadzenia. 5 pazdziernika 2026 to poniedzialek."""
    moment = datetime.fromisoformat(when) if when else None
    return MatchNeed(
        match_id=rest.pop("match_id", "1001"),
        code=code,
        moment=moment,
        day=moment.date() if moment else None,
        host_city=city,
        field_needed=["pierwszy", "drugi"][:field],
        table_needed=["sekretarz", "czas"][:table],
        **rest,
    )


def names(plan, slot=None):
    return [p.judge_name for p in plan.proposals if slot is None or p.slot == slot]


def test_closest_available_wins():
    # Mecz w Zabrzu: Jan ma 12 km, Pawel 20, Ewa 85.
    plan = build_plan([match(city="Zabrze", field=1)], world([JAN, PAWEL, EWA]))
    assert names(plan) == ["KOWALSKI Jan"]
    assert "12 km" in plan.proposals[0].reasons


def test_local_referee_is_the_last_resort():
    # Gospodarz gra w Katowicach, więc Pawel jest miejscowy - wchodzi Anna z Zabrza.
    plan = build_plan([match(city="Katowice", field=1)], world([ANNA, PAWEL]))
    assert names(plan) == ["NOWAK Anna"]
    # Gdy nie ma nikogo innego, miejscowy jednak wchodzi i automat to pisze.
    plan = build_plan([match(city="Katowice", field=1)], world([PAWEL]))
    assert names(plan) == ["ZIELIŃSKI Paweł"]
    assert any("miejscowy" in reason for reason in plan.proposals[0].reasons)


def test_established_pair_goes_together():
    # Mecz w Katowicach: Anna 20 km, Jan 28 km, Pawel miejscowy.
    ctx = world([JAN, ANNA, PAWEL], partner_of={"1": "2", "2": "1"})
    plan = build_plan([match(city="Katowice", field=2)], ctx)
    # Anna wchodzi jako najblizsza, a do drugiego gniazda jej para, nie Pawel.
    assert set(names(plan)) == {"KOWALSKI Jan", "NOWAK Anna"}
    assert any("para z" in " ".join(p.reasons) for p in plan.proposals)


def test_two_young_referees_never_together():
    young_two = make_judge("6", "MŁODA Zofia", city="Zabrze", letters=["Mł"], badges=["Młodzi"])
    plan = build_plan([match(city="Gliwice", field=2)], world([EWA, young_two, ANNA]))
    assigned = set(names(plan))
    assert "NOWAK Anna" in assigned
    assert len(assigned & {"JANKOWSKA Ewa", "MŁODA Zofia"}) == 1


def test_judge_who_needs_an_experienced_partner_gets_one():
    fragile = make_judge("7", "POLCZAK Joanna", city="Gliwice", letters=["III"], needs_experienced=True)
    ctx = world([fragile, ANNA, PAWEL])
    plan = build_plan([match(city="Zabrze", field=2)], ctx)
    assigned = set(names(plan))
    assert len(assigned) == 2
    if "POLCZAK Joanna" in assigned:
        assert "ZIELIŃSKI Paweł" in assigned      # jedyny z licencja A


def test_preferred_days_win_in_the_first_round():
    picky = make_judge("8", "PIĄTKOWY Piotr", city="Katowice", letters=["II"], preferred_days=[4])
    # Mecz wypada w poniedzialek, więc Piotr wchodzi dopiero w drugim obiegu.
    plan = build_plan([match(city="Katowice", field=1)], world([picky, ANNA]))
    assert names(plan) == ["NOWAK Anna"]
    # Sam Piotr: pierwszy obieg go omija, drugi bierze i to zapisuje.
    plan = build_plan([match(city="Katowice", field=1)], world([picky]))
    assert names(plan) == ["PIĄTKOWY Piotr"]
    assert plan.proposals[0].round_no == 2
    assert any("spoza preferowanych" in reason for reason in plan.proposals[0].reasons)


def test_second_league_table_needs_licence_a():
    ctx = world([MAREK, JAN, PAWEL])
    plan = build_plan([match(code="IIK4/3", city="Gliwice", field=0, table=2)], ctx)
    assert len(plan.proposals) == 2
    assert "ZIELIŃSKI Paweł" in set(names(plan))     # jedyny z licencja A


def test_district_table_prefers_the_table_badge():
    # Mecz w Gliwicach: Marek ma 28 km, Anna 12 - odznaka „Stolikowi" przewaza.
    ctx = world([MAREK, ANNA])
    plan = build_plan([match(code="S/JmM/4", city="Gliwice", field=0, table=1)], ctx)
    assert names(plan) == ["SZYMAŃSKI Marek"]
    assert any("stolikowy" in reason for reason in plan.proposals[0].reasons)


def test_same_day_match_too_far_is_out():
    busy = {"3": [BusyMatch(moment=datetime(2026, 10, 5, 17, 0), city="Bielsko-Biała", match_id="x")]}
    ctx = world([PAWEL, ANNA], busy=busy)
    plan = build_plan([match(city="Katowice", when="2026-10-05T18:00", field=1)], ctx)
    assert names(plan) == ["NOWAK Anna"]


def test_same_day_match_with_time_to_spare_is_allowed_as_a_last_resort():
    busy = {"3": [BusyMatch(moment=datetime(2026, 10, 5, 10, 0), city="Katowice", match_id="x")]}
    ctx = world([PAWEL], busy=busy)
    plan = build_plan([match(city="Katowice", when="2026-10-05T18:00", field=1)], ctx)
    assert names(plan) == ["ZIELIŃSKI Paweł"]
    assert any("mecz tego dnia" in reason for reason in plan.proposals[0].reasons)


def test_work_is_shared_between_matches():
    # Dwa mecze w Gliwicach w różne dni: Anna jest blizej, ale nie bierze obu.
    first = match(match_id="1", code="S/JmM/1", city="Gliwice", when="2026-10-05T18:00", field=1)
    second = match(match_id="2", code="S/JmM/2", city="Gliwice", when="2026-10-12T18:00", field=1)
    plan = build_plan([first, second], world([PAWEL, ANNA]))
    assert set(names(plan)) == {"NOWAK Anna", "ZIELIŃSKI Paweł"}


def test_unavailable_judge_leaves_a_gap_with_a_reason():
    ctx = world([ANNA], available=lambda judge_id, moment: False)
    plan = build_plan([match(field=1)], ctx)
    assert not plan.proposals
    assert plan.gaps and "niedyspozycja" in plan.gaps[0].reason


def test_nobody_gets_two_slots_in_one_match():
    plan = build_plan([match(city="Katowice", field=2)], world([PAWEL]))
    assert len(plan.proposals) == 1
    assert plan.gaps and plan.gaps[0].slot == "drugi"


def test_travel_feasibility_between_two_matches():
    at_ten = datetime(2026, 10, 5, 10, 0)
    at_six = datetime(2026, 10, 5, 18, 0)
    assert can_make_both(at_ten, at_six, 60)
    assert not can_make_both(at_ten, datetime(2026, 10, 5, 12, 0), 60)
    # Bez terminu nie wiemy nic i nie blokujemy.
    assert can_make_both(None, at_six, 10)


def test_a_match_without_a_date_can_still_be_filled():
    """
    Mecz bez terminu obsadza się, ale bez sprawdzania czasu.

    Bez godziny nie ma jak spytać o niedyspozycję ani o kolizję z innym meczem
    tego dnia - i to jest ŚWIADOMA zgoda, nie przeoczenie. Automat bierze takie
    mecze wyłącznie na wyraźne życzenie (`include_undated`), żeby dało się
    zobaczyć, kto w ogóle wchodzi w rachubę.
    """
    busy = {"3": [BusyMatch(moment=datetime(2026, 10, 5, 17, 0), city="Bielsko-Biała", match_id="x")]}
    ctx = world([PAWEL, ANNA], busy=busy)
    plan = build_plan([match(city="Zabrze", when=None, field=2)], ctx)
    assert len(plan.proposals) == 2
    assert not plan.gaps
    # Termin nieznany, więc mecz tego samego dnia nikogo nie wyklucza.
    assert set(names(plan)) == {"NOWAK Anna", "ZIELIŃSKI Paweł"}


def test_preferred_days_do_not_block_a_match_without_a_date():
    picky = make_judge("8", "PIĄTKOWY Piotr", city="Katowice", letters=["II"], preferred_days=[4])
    plan = build_plan([match(city="Gliwice", when=None, field=1)], world([picky]))
    assert names(plan) == ["PIĄTKOWY Piotr"]
    # Skoro nie wiadomo, w jaki dzień gra, pierwszy obieg go nie omija.
    assert plan.proposals[0].round_no == 1
