from app.assignment_grades import options_grades
from app.assignment_people import name_key


def form(*slots):
    return {"slots": {f"slot{i}": {"options": list(options)} for i, options in enumerate(slots)}}


def option(name, badges=(), **rest):
    return {"name": name, "badges": list(badges), **rest}


def test_letters_are_read_from_the_option_badges():
    parsed = form([option("ZIELIŃSKI Paweł", ["SL", "LC", "I", "II"])])
    grades = options_grades(parsed)
    assert grades[name_key("ZIELIŃSKI Paweł")] == ("ZIELIŃSKI Paweł", ["I", "II", "LC", "SL"])


def test_letters_from_all_slots_are_summed():
    # Lista stolikowa bywa przycieta filtrem i pokazuje mniej niz boiskowa.
    parsed = form(
        [option("KOWALSKI Jan", ["II", "III"])],
        [option("KOWALSKI Jan", ["MP"])],
    )
    _, letters = options_grades(parsed)[name_key("KOWALSKI Jan")]
    assert letters == ["II", "III", "MP"]


def test_the_same_person_written_both_ways_is_one_entry():
    parsed = form(
        [option("NOWAK Anna", ["II"])],
        [option("Anna Nowak", ["III"])],
    )
    grades = options_grades(parsed)
    assert len(grades) == 1
    assert grades[name_key("NOWAK Anna")][1] == ["II", "III"]


def test_the_youth_letter_survives_the_polish_l():
    parsed = form([option("JANKOWSKA Ewa", ["Mł"])])
    assert options_grades(parsed)[name_key("JANKOWSKA Ewa")][1] == ["ML"]


def test_unknown_marks_are_ignored():
    parsed = form([option("KTOŚ Nowy", ["II", "XYZ", ""])])
    assert options_grades(parsed)[name_key("KTOŚ Nowy")][1] == ["II"]


def test_someone_without_any_letter_is_not_written_down():
    # Brak liter to „nie wiemy", a nie „nie ma uprawnień" - wpis skasowalby
    # to, co wiemy z wcześniejszego formularza.
    assert options_grades(form([option("BEZ Liter", [])])) == {}


def test_an_empty_form_is_not_an_error():
    assert options_grades({}) == {}
    assert options_grades({"slots": {}}) == {}
    assert options_grades({"slots": {"a": {"options": None}}}) == {}
