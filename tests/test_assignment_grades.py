import pytest

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
    # Lista stolikowa bywa przycieta filtrem i pokazuje mniej niż boiskowa.
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


# ── jednorazowe uzupełnienie ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_backfill_without_a_monitor_account_does_nothing_and_keeps_the_claim(monkeypatch):
    """Brak konta NIE zajmuje śladu - konto może dojść jutro."""
    import app.assignment_grades as G

    claimed: list[str] = []
    monkeypatch.setattr("app.zprp_accounts.credentials_for", lambda *a, **k: None)
    monkeypatch.setattr("app.one_time.claim_once", _remember(claimed))

    result = await G.backfill_grades("SLASKIE")
    assert result["ran"] is False
    assert "konta" in result["reason"]
    assert claimed == []          # ślad wolny - poprawka wydarzy się później


@pytest.mark.anyio
async def test_backfill_runs_only_once(monkeypatch):
    import app.assignment_grades as G

    monkeypatch.setattr("app.zprp_accounts.credentials_for", lambda *a, **k: ("u", "p"))
    monkeypatch.setattr("app.one_time.claim_once", _always(False))

    result = await G.backfill_grades("SLASKIE")
    assert result["ran"] is False
    assert result["reason"] == "już wykonane"


def _remember(sink):
    async def claim(name):
        sink.append(name)
        return True

    return claim


def _always(value):
    async def claim(_name):
        return value

    return claim
