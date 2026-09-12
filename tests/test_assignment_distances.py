import pytest

from app.assignment_distances import DistanceBook, fill_missing
from app.settlement_distances import DistanceIndex

TABLE = {
    "Gliwice": {"Zabrze": 12, "Katowice": 28},
    "Zabrze": {"Gliwice": 12},
}


def book(cache=None):
    return DistanceBook(DistanceIndex(TABLE), cache)


def test_same_city_costs_nothing_and_asks_nobody():
    page = book()
    assert page.km("Gliwice", "gliwice") == 0.0
    assert page.km("Katowice", "Katowice") == 0.0
    assert page.stats["table"] == 0          # tabeli nawet nie ruszylismy


def test_table_answers_first():
    page = book()
    assert page.km("Gliwice", "Zabrze") == 12
    assert page.km("Zabrze", "Gliwice") == 12      # w obie strony
    assert page.stats["table"] == 2
    assert page.stats["google"] == 0


def test_remembered_pair_is_used_when_the_table_is_silent():
    page = book({("bielsko biala", "gliwice"): 78.0})
    assert page.km("Gliwice", "Bielsko-Biała") == 78.0
    assert page.stats["memory"] == 1


def test_unknown_pair_is_none_not_zero():
    assert book().km("Gliwice", "Szczecin") is None


def test_missing_lists_only_what_nobody_knows():
    page = book({("bielsko biala", "gliwice"): 78.0})
    pairs = [
        ("Gliwice", "Zabrze"),        # tabela
        ("Gliwice", "Bielsko-Biała"), # pamięć
        ("Gliwice", "Gliwice"),       # to samo miasto
        ("Gliwice", "Szczecin"),      # nikt nie wie
        ("Szczecin", "Gliwice"),      # ta sama para odwrotnie
    ]
    assert page.missing(pairs) == [("gliwice", "szczecin")]


def test_a_pair_google_could_not_find_is_not_asked_again():
    page = book()
    key = page.key("Gliwice", "Szczecin")
    page.remember(key, None)
    assert page.missing([("Gliwice", "Szczecin")]) == []
    assert page.stats["unknown_pairs"] == 1


def test_what_google_found_answers_right_away():
    page = book()
    page.remember(page.key("Gliwice", "Szczecin"), 480.0)
    assert page.km("Szczecin", "Gliwice") == 480.0
    assert page.stats["google"] == 1


@pytest.mark.anyio
async def test_fill_missing_does_nothing_when_nothing_is_missing():
    page = book()
    result = await fill_missing(page, [("Gliwice", "Zabrze")])
    assert result == {"asked": 0, "saved": 0, "missing": 0}


def test_the_same_question_is_answered_from_memory():
    """
    Automat pyta o odległość ~130 tysięcy razy przy jednym przebiegu.

    Bez pamięci po surowej parze napisów `normalize_city` liczyło swoje wyrażenia
    regularne za każdym razem i same odległości zjadały sześć sekund z siedmiu.
    """
    page = book()
    assert page.km("Gliwice", "Zabrze") == 12
    assert page.km("Gliwice", "Zabrze") == 12
    # Tabela odpytana RAZ - drugie pytanie poszło już z pamięci.
    assert page.stats["table"] == 1


def test_what_google_found_invalidates_the_memory():
    """
    Para, o którą pytaliśmy PRZED Google'em, nie może zostać nieznana na zawsze.
    """
    page = book()
    assert page.km("Gliwice", "Szczecin") is None
    page.remember(page.key("Gliwice", "Szczecin"), 480.0)
    assert page.km("Gliwice", "Szczecin") == 480.0


def test_memory_does_not_mix_up_different_pairs():
    page = book({("bielsko biala", "gliwice"): 78.0})
    assert page.km("Gliwice", "Zabrze") == 12
    assert page.km("Gliwice", "Katowice") == 28
    assert page.km("Gliwice", "Bielsko-Biała") == 78.0
    assert page.km("Gliwice", "Gliwice") == 0.0
