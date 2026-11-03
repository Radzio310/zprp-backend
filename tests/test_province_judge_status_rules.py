import pytest

from app import province_judge_status_rules as R
from app.official_roster import SLASKIE_2026_27


def test_kto_moze_zmieniac_status():
    assert R.may_manage(is_admin=True, has_committee_badge=False, own_province="OPOLSKIE", province="ŚLĄSKIE")
    assert R.may_manage(is_admin=False, has_committee_badge=True, own_province="SLASKIE", province="Śląskie")
    assert not R.may_manage(is_admin=False, has_committee_badge=True, own_province="OPOLSKIE", province="ŚLĄSKIE")
    assert not R.may_manage(is_admin=False, has_committee_badge=False, own_province="ŚLĄSKIE", province="ŚLĄSKIE")
    assert not R.may_manage(is_admin=False, has_committee_badge=True, own_province="", province="")


def test_okregi_odporne_na_ogonki():
    assert R.province_key("DOLNOŚLĄSKIE") == R.province_key("Dolnoslaskie")
    assert R.province_key("ŁÓDZKIE") == R.province_key("lodzkie")


def test_ids_czyszczone_i_ograniczone():
    assert R.clean_ids([" 1 ", "1", 2, None, ""]) == ["1", "2"]
    for bad in ("1", [], [None], [str(i) for i in range(R.MAX_IDS + 1)]):
        with pytest.raises(R.Invalid):
            R.clean_ids(bad)
    assert R.clean_note("  ") is None and R.clean_note(" a ") == "a"


def test_stan_poczatkowy_dopasowuje_nazwiska_regula_klucza():
    judges = [
        {"judge_id": "1", "full_name": "ANDERS Magdalena"},
        {"judge_id": "2", "full_name": "NOWAK Jan"},
        {"judge_id": "3", "full_name": "Łuszczykiewicz Maksymilian"},
        {"judge_id": "4", "full_name": "Radoslaw Witkowicz"},
    ]
    inactive, unmatched = R.plan_seed(judges, SLASKIE_2026_27)
    assert [p["judge_id"] for p in inactive] == ["2"]
    assert len(unmatched) == len(SLASKIE_2026_27) - 3
    assert "Pazur Leszek" in unmatched and "Anders Magdalena" not in unmatched


def test_wiersz_dla_klienta():
    row = {"judge_id": 5, "name": "A B", "since": None, "by_name": "", "note": " "}
    assert R.item(row) == {"judge_id": "5", "name": "A B", "since": "", "by": None, "note": None}


def test_stan_poczatkowy_dolnoslaskie_z_aliasami():
    names = R.SEED_ACTIVE["DOLNOSLASKIE"]
    judges = [
        {"judge_id": "1", "full_name": "Karol R. ZAJĄC"},
        {"judge_id": "2", "full_name": "Barbara BIAŁOGRECKA"},
        {"judge_id": "3", "full_name": "Zając Karol"},
        {"judge_id": "4", "full_name": "NOWAK Jan"},
    ]
    inactive, _ = R.plan_seed(judges, names)
    assert [p["judge_id"] for p in inactive] == ["4"]
    assert set(R.SEED_ACTIVE) == {"SLASKIE", "DOLNOSLASKIE"}
