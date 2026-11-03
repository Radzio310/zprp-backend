from app import official_roster as O
from app import province_event_rules as R


def test_osoba_bez_ogonkow_i_w_dowolnej_kolejnosci():
    assert O.person_key("WITKOWICZ Radosław") == O.person_key("Witkowicz Radoslaw") == O.person_key("Radosław  Witkowicz")
    assert O.person_key("1) Łuszczykiewicz Maksymilian") == O.person_key("ŁUSZCZYKIEWICZ Maksymilian")


def test_zaproszeni_bez_nieaktywnych_ale_reczne_dopisanie_wygrywa():
    judges = [
        {"judge_id": "1", "full_name": "ANDERS Magdalena", "badges": {"Delegaci": True}},
        {"judge_id": "2", "full_name": "NOWAK Jan", "badges": {"Delegaci": True}},
        {"judge_id": "3", "full_name": "BLOCH Wojciech", "badges": {}},
    ]
    inactive = {"2"}
    everyone = {"target": {"include_all": True}}
    assert R.invited_ids(judges, everyone, inactive=inactive) == ["1", "3"]
    assert R.invited_ids(judges, {"target": {"include_badges": ["Delegaci"]}}, inactive=inactive) == ["1"]
    manual = {"target": {"include_all": True}, "include_ids": ["2"]}
    assert "2" in R.invited_ids(judges, manual, inactive=inactive)
