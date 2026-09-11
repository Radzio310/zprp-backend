"""
Kolejnosc sedziow w zestawieniach: NAZWISKO, potem imiona, po polsku.

ZPRP podaje nazwiska jako „Imie NAZWISKO" - sortowanie calego napisu ukladalo
liste po imieniu, a zamiana na ASCII gubila „Ł".
"""

from app.settlement_engine import _sort_name, split_judge_name


def test_first_name_then_surname():
    assert split_judge_name("Aleksandra PYTLIK") == ("PYTLIK", "Aleksandra")


def test_two_part_surnames_and_two_given_names():
    assert split_judge_name("Anna KOWALSKA-NOWAK") == ("KOWALSKA-NOWAK", "Anna")
    assert split_judge_name("Anna KOWALSKA NOWAK") == ("KOWALSKA NOWAK", "Anna")
    assert split_judge_name("Anna Maria KOWALSKA") == ("KOWALSKA", "Anna Maria")


def test_already_reversed_and_plain_case():
    assert split_judge_name("KOWALSKI Jan") == ("KOWALSKI", "Jan")
    assert split_judge_name("Jan Kowalski") == ("Kowalski", "Jan")
    assert split_judge_name("KOWALSKI") == ("KOWALSKI", "")


def test_without_a_name():
    assert split_judge_name("465") is None
    assert split_judge_name("") is None
    assert split_judge_name(None) is None


def test_order_is_surname_then_given_name_in_polish_alphabet():
    names = [
        "Jacek URYGA",
        "465",
        "Aleksandra PYTLIK",
        "Piotr ŁUKASIK",
        "Grzegorz SCHIWON",
        "Marek LIS",
        "Artur JĘDRYCHA",
        "Jan Maria KOWALSKI",
        "Anna KOWALSKA-NOWAK",
        "",
    ]
    ordered = sorted(names, key=_sort_name)
    assert ordered[:8] == [
        "Artur JĘDRYCHA",
        "Anna KOWALSKA-NOWAK",
        "Jan Maria KOWALSKI",
        "Marek LIS",
        "Piotr ŁUKASIK",
        "Aleksandra PYTLIK",
        "Grzegorz SCHIWON",
        "Jacek URYGA",
    ]
    # Bez nazwiska na koniec - sama liczba nie jest nazwiskiem.
    assert set(ordered[8:]) == {"465", ""}


def test_same_surname_falls_back_to_given_names():
    ordered = sorted(["Zofia NOWAK", "Adam NOWAK", "Łucja NOWAK"], key=_sort_name)
    assert ordered == ["Adam NOWAK", "Łucja NOWAK", "Zofia NOWAK"]
