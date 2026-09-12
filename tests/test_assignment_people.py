from app.assignment_people import (
    is_local,
    make_judge,
    pair_ok,
    prefers_day,
    table_pair_ok,
    table_rule,
)


def judge(name, letters=(), badges=(), **rest):
    return make_judge(name.lower().replace(" ", ""), name, letters=letters, badges=badges, **rest)


LIGOWY = judge("KOWALSKI Jan", letters=["MP", "II", "III", "Mł"])
CENTRALNY = judge("ZIELIŃSKI Paweł", letters=["SL", "LC", "PP", "MP", "I", "II"])
MLODY = judge("JANKOWSKA Ewa", letters=["Mł"], badges=["Młodzi"])
MLODY_2 = judge("NOWAK Anna", letters=["Mł"], badges=["Młodzi"])
STOLIKOWY = judge("MAZUR Łukasz", letters=["III", "Mł"], badges=["Stolikowi"])
DELEGAT = judge("SZYMAŃSKI Marek", letters=["III"], badges=["Delegaci"])


def test_league_is_second_division_and_up():
    assert LIGOWY.league
    assert CENTRALNY.league
    assert not MLODY.league


def test_badge_decides_when_zprp_is_out_of_date():
    # Odznaka „Ligowcy" robi ligowca nawet bez liter - baza związku bywa stara.
    assert judge("KTOŚ Nowy", letters=["Mł"], badges=["Ligowcy"]).league


def test_licence_a_is_a_central_field_referee():
    assert CENTRALNY.central
    assert not LIGOWY.central          # ma tylko (II) i (MP)
    assert not STOLIKOWY.central


def test_table_requirements_by_level():
    assert table_rule("SM/8") == {"league_or_delegate": 1, "central": 1}
    assert table_rule("LCK/3") == {"league_or_delegate": 1, "central": 1}
    assert table_rule("IIK4/1") == {"central": 1}
    assert table_rule("IM/12") == {"central": 1}
    assert table_rule("S/JmM/12") == {}


def test_superleague_table_needs_a_league_referee_and_licence_a():
    ok, why = table_pair_ok([CENTRALNY, LIGOWY], "SM/8")
    assert ok and not why
    ok, why = table_pair_ok([STOLIKOWY, MLODY], "SM/8")
    assert not ok and "ligowego" in why
    # Ligowy jest, ale nikt nie ma licencji A.
    ok, why = table_pair_ok([LIGOWY, STOLIKOWY], "SM/8")
    assert not ok and "licencją A" in why


def test_second_league_table_needs_one_licence_a():
    assert table_pair_ok([CENTRALNY, STOLIKOWY], "IIK4/1")[0]
    assert not table_pair_ok([LIGOWY, STOLIKOWY], "IIK4/1")[0]


def test_district_table_has_no_level_requirement():
    assert table_pair_ok([MLODY, STOLIKOWY], "S/JmM/12")[0]


def test_two_young_referees_never_together():
    ok, why = pair_ok(MLODY, MLODY_2)
    assert not ok and "młodych" in why
    assert pair_ok(MLODY, LIGOWY)[0]


def test_blocked_pair_never_together():
    blocked = [(MLODY.judge_id, LIGOWY.judge_id)]
    ok, why = pair_ok(LIGOWY, MLODY, blocked=blocked)
    assert not ok and "wykluczona" in why


def test_needs_experienced_partner_requires_licence_a():
    fragile = make_judge("polczak", "POLCZAK Joanna", letters=["III"], needs_experienced=True)
    ok, why = pair_ok(fragile, STOLIKOWY)
    assert not ok and "licencją A" in why
    assert pair_ok(fragile, CENTRALNY)[0]
    # Zasada działa w obie strony, niezależnie od kolejności gniazd.
    assert not pair_ok(STOLIKOWY, fragile)[0]


def test_same_person_is_not_a_pair():
    assert not pair_ok(LIGOWY, LIGOWY)[0]


def test_preferred_days_empty_means_any_day():
    assert prefers_day(LIGOWY, 2)
    picky = make_judge("x", "X", preferred_days=[0, 4])
    assert prefers_day(picky, 4)
    assert not prefers_day(picky, 5)
    assert prefers_day(picky, None)      # mecz bez terminu


def test_local_judge_is_recognised():
    home = make_judge("a", "A", city="Gliwice")
    assert is_local(home, "gliwice")
    assert not is_local(home, "Zabrze")
