from datetime import datetime, timezone

from app import settlement_rates as R
from app.settlement_origin import (
    DROP,
    KEEP,
    OUTSIDE,
    collected_after_season,
    history_fix,
    is_other_district,
    own_past_match,
    own_prefixes,
)

SCHEDULE = ["S/JmM/12", "S/MłK/3", "S/PPK/2", "IIM4/7", "JMM/3", "L/MłK/20"]
AFTER = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)     # pierwsze pelne pobranie
DURING = datetime(2025, 11, 30, 18, 0, tzinfo=timezone.utc)   # jeszcze w sezonie 2025/2026


def test_own_prefixes_come_from_our_schedule():
    # „S" stoi przy trzech meczach okregowych, zablakany „L/" raz - za malo.
    assert own_prefixes(SCHEDULE) == {"S"}
    assert own_prefixes(["L/MłK/20", "L/MłK/21"]) == {"L"}
    assert own_prefixes([]) == set()


def test_other_district_needs_a_foreign_prefix():
    assert is_other_district("L/MłK/20", {"S"})
    assert not is_other_district("S/MłK/167", {"S"})
    assert not is_other_district("JMM/3", {"S"})        # bez przedrostka - nie wiemy
    assert not is_other_district("MP/JM/12", {"S"})     # Mistrzostwa Polski to nie okreg
    assert not is_other_district("L/MłK/20", set())     # nie znamy swoich - nie zgadujemy


def test_past_match_of_another_district_is_not_ours():
    assert not own_past_match("L/MłK/20", {"S"})
    assert own_past_match("S/MłK/167", {"S"})
    assert own_past_match("MPJMM/19", {"S"})            # puchary jak dotad


def test_provincial_cup_is_our_match():
    # „S/PPK/2" placi stawkami II ligi, ale to mecz okregu - liczy sie w kazdej roli.
    assert own_past_match("S/PPK/2", {"S"})
    assert not own_past_match("L/PPK/3", {"S"})


def test_collected_after_season():
    assert collected_after_season(AFTER, "2025/2026")
    assert not collected_after_season(DURING, "2025/2026")
    assert not collected_after_season(None, "2025/2026")


def fix(**changes):
    base = dict(
        match_key="d:194144",
        match_code="L/MłK/20",
        role=R.ROLE_TABLE,
        season="2025/2026",
        first_seen=AFTER,
        current="2026/2027",
        own={"S"},
    )
    base.update(changes)
    return history_fix(**base)


def test_table_at_another_district_moves_outside():
    assert fix() == OUTSIDE


def test_field_referee_or_delegate_at_another_district_drops():
    assert fix(role=R.ROLE_FIELD) == DROP
    assert fix(role=R.ROLE_DELEGATE) == DROP


def test_everything_else_stays():
    assert fix(match_code="S/MłK/167") == KEEP          # nasz mecz
    assert fix(match_key="o:194144") == KEEP            # juz spoza okregu
    assert fix(season="2026/2027") == KEEP              # biezacy sezon: terminarz
    assert fix(first_seen=DURING) == KEEP               # zapisany w trakcie sezonu - terminarz
    assert fix(own=set()) == KEEP                       # nie znamy naszych przedrostkow
