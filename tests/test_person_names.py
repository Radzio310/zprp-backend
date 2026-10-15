# Tożsamość po nazwisku: kolejność członów nie ma znaczenia, inicjał ma.
#
# Dolnośląskie: „Karol ZAJĄC" (ID 288) i jego syn „Karol R. ZAJĄC" (ID 5601,
# w formularzu ZPRP „ZAJĄC Karol R."). Każda miara nazwisk na serwerze ma ich
# rozdzielać - giełda, obsady, bomby, role w meczu.

import pytest

from app.assignment_people import name_key
from app.bomb_penalty_rules import subject_key
from app.match_bombs_rules import same_person as bombs_same_person
from app.match_market_rules import names_match as market_names_match
from app.person_names import names_match, person_name_key, split_name
from app.proel_auth import names_match as proel_names_match

FATHER = "Karol ZAJĄC"
SON = "Karol R. ZAJĄC"
SON_ZPRP = "ZAJĄC Karol R."
SON_ROSTER = "Zając Karol Jr"

MEASURES = [names_match, market_names_match, bombs_same_person, proel_names_match]


@pytest.mark.parametrize("same", MEASURES)
def test_father_is_not_son(same):
    assert not same(FATHER, SON)
    assert not same(FATHER, SON_ZPRP)
    assert not same("ZAJĄC Karol", SON_ZPRP)
    assert not same(FATHER, SON_ROSTER)


@pytest.mark.parametrize("same", MEASURES)
def test_each_matches_himself_in_any_order(same):
    assert same(FATHER, "ZAJĄC Karol")
    assert same(SON, SON_ZPRP)
    assert same("Karol R ZAJĄC", SON_ZPRP)
    assert same("Krzysztof WITKOWICZ", "WITKOWICZ Krzysztof")
    assert same("Łukasz Bartłomiej", "LUKASZ Bartlomiej")


@pytest.mark.parametrize("same", [names_match, market_names_match, bombs_same_person])
def test_single_surname_is_not_enough(same):
    assert not same("Nowak", "Jan NOWAK")


def test_split_name_marks():
    assert split_name(SON_ZPRP) == (["karol", "zajac"], frozenset({"r"}))
    assert split_name(SON_ROSTER) == (["karol", "zajac"], frozenset({"jr"}))
    assert split_name("Junior Senior") == ([], frozenset({"jr", "sr"}))


def test_keys_split_father_and_son():
    assert person_name_key(FATHER) == person_name_key("ZAJĄC Karol") == "karol zajac"
    assert person_name_key(SON) == person_name_key(SON_ZPRP) != person_name_key(FATHER)
    # Klucz bez inicjału jest taki jak dawniej - zapisane wiersze zostają ważne.
    assert name_key("NOWAK Jan") == "jan nowak"
    assert name_key(SON_ZPRP) != name_key(FATHER)
    assert subject_key({"subject_name": SON}) != subject_key({"subject_name": FATHER})
    assert subject_key({"subject_name": "Jan NOWAK"}) == subject_key({"subject_name": "NOWAK Jan"})
