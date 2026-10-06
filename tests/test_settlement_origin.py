from datetime import datetime, timezone

from app import settlement_rates as R
from app.settlement_origin import (
    DROP,
    KEEP,
    OUTSIDE,
    collected_after_season,
    foreign_district_match,
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


def test_judge_lists_do_not_make_a_foreign_prefix_ours():
    # Zgloszenie z 06.10.2026: terminarz Slaska ma setki „S/", a sedzia
    # z Czestochowy wniosl dwa mecze juniorek z Piotrkowa („E/JmK/1", „E/JmK/3").
    schedule = [f"S/JmM/{n}" for n in range(200)] + ["E/JmK/1", "E/JmK/3"]
    assert own_prefixes(schedule) == {"S"}
    # Dwa rowne terminarze (okreg prowadzacy dwie numeracje) zostaja oba.
    assert own_prefixes(["S/JmM/1"] * 10 + ["X/JmM/1"] * 8) == {"S", "X"}


def test_foreign_district_match():
    assert foreign_district_match("E/JmK/3", {"S"})
    assert not foreign_district_match("S/JmK/3", {"S"})
    assert not foreign_district_match("IIM4/1", {"S"})     # II liga - inna regula
    assert not foreign_district_match("E/JmK/3", set())    # nie znamy swoich


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


def test_current_season_foreign_match_is_fixed_too():
    # Biezacy sezon (06.10.2026): terminarz trzyma mecze z list sedziow, wiec
    # „d:" meczu innego okregu poprawiamy niezaleznie od tego, kiedy go zapisano.
    assert fix(season="2026/2027", first_seen=DURING) == OUTSIDE
    assert fix(season="2026/2027", match_code="E/JmK/3", role=R.ROLE_FIELD) == DROP


def test_everything_else_stays():
    assert fix(match_code="S/MłK/167") == KEEP          # nasz mecz
    assert fix(match_key="o:194144") == KEEP            # juz spoza okregu
    assert fix(first_seen=DURING) == KEEP               # miniony sezon z terminarza - zamkniety
    assert fix(own=set()) == KEEP                       # nie znamy naszych przedrostkow
    assert fix(season="2026/2027", match_code="S/MłK/1") == KEEP


def test_mlodzik_makroregionalny_z_cudzym_przedrostkiem_jest_nasz():
    # Zgłoszenie z 06.10.2026: turniej młodzika makroregionalnego „K/MłMR/12"
    # (numer nadał Kraków, sędziuje obsada Śląska) zdejmował sędziom boiskowym
    # mecze, a stolik przenosił na „o:". Makroregion liczy się jak nasz.
    assert not foreign_district_match("K/MłMR/12", {"S"})
    assert not foreign_district_match("K/MłKR/3", {"S"})
    assert own_past_match("K/MłMR/12", {"S"})
    assert fix(season="2026/2027", match_code="K/MłMR/12", role=R.ROLE_FIELD) == KEEP
    assert fix(season="2026/2027", match_code="K/MłMR/12") == KEEP
    # Reszta meczów innych okręgów - bez zmian (sprawa Wiktorii Więcław).
    assert foreign_district_match("E/JmK/3", {"S"})
    assert foreign_district_match("K/MłM/3", {"S"})
