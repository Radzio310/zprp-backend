from datetime import date, datetime, timezone

from app import official_roster as O
from app import province_event_rules as R

UTC = timezone.utc
OCTOBER = datetime(2026, 10, 1, 16, tzinfo=UTC)


def test_osoba_bez_ogonkow_i_w_dowolnej_kolejnosci():
    assert O.person_key("WITKOWICZ Radosław") == O.person_key("Witkowicz Radoslaw") == O.person_key("Radosław  Witkowicz")
    assert O.person_key("1) Łuszczykiewicz Maksymilian") == O.person_key("ŁUSZCZYKIEWICZ Maksymilian")
    assert O.is_active("ŚLĄSKIE", OCTOBER, "ANDERS Magdalena")
    assert not O.is_active("Śląskie", OCTOBER, "NOWAK Jan")


def test_lista_obowiazuje_tylko_w_swoim_sezonie_i_okregu():
    # Sezon 2025/26 i okręg bez listy - wszyscy aktywni, nic nie znika wstecz.
    assert O.is_active("ŚLĄSKIE", datetime(2026, 5, 10, tzinfo=UTC), "NOWAK Jan")
    assert O.is_active("OPOLSKIE", OCTOBER, "NOWAK Jan")
    assert O.is_active("ŚLĄSKIE", None, "NOWAK Jan")
    # Granica sierpniowa w czasie polskim: 31.07 23:30 UTC to już 1 sierpnia.
    assert O.season_of(datetime(2026, 7, 31, 22, 30, tzinfo=UTC)) == 2026
    assert O.season_of(date(2026, 7, 31)) == 2025
    assert O.inactive_seasons("ŚLĄSKIE", "NOWAK Jan") == [2026]
    assert O.inactive_seasons("ŚLĄSKIE", "Pazur Leszek") == []
    assert O.inactive_seasons("OPOLSKIE", "NOWAK Jan") == []


def test_zaproszeni_bez_nieaktywnych_ale_reczne_dopisanie_wygrywa():
    judges = [
        {"judge_id": "1", "full_name": "ANDERS Magdalena", "badges": {"Delegaci": True}},
        {"judge_id": "2", "full_name": "NOWAK Jan", "badges": {"Delegaci": True}},
        {"judge_id": "3", "full_name": "BLOCH Wojciech", "badges": {}},
    ]
    inactive = O.inactive_ids("ŚLĄSKIE", OCTOBER, judges)
    assert inactive == {"2"}
    everyone = {"target": {"include_all": True}}
    assert R.invited_ids(judges, everyone, inactive=inactive) == ["1", "3"]
    assert R.invited_ids(judges, {"target": {"include_badges": ["Delegaci"]}}, inactive=inactive) == ["1"]
    assert R.invited_ids(judges, {**everyone, "include_ids": ["2"]}, inactive=inactive) == ["1", "2", "3"]
    # Stare wydarzenie bez kryteriów też bez nieaktywnych; bez listy - jak dawniej.
    assert R.invited_ids(judges, {"target": {}}, inactive=inactive) == ["1", "3"]
    assert R.invited_ids(judges, everyone) == ["1", "2", "3"]
