from datetime import datetime, timezone

from app import national_lookup_rules as NL


def test_kolejnosc_zrodel_wedlug_szczebla():
    assert NL.distance_order(False) == ["same-city", "table", "zprp-table", "google"]
    assert NL.distance_order(True) == ["same-city", "zprp-table", "google"]


def test_warianty_klucza_tolerują_pisownię():
    keys = NL.lookup_keys("41-940 Piekary Śl., ul. Szkolna 2")
    assert "piekary sl" in keys
    assert "piekary slaskie" in keys
    assert "piekarysl" in keys


def test_national_km_po_wariantach_i_w_obie_strony():
    pairs = NL.expand_pairs({("gliwice", "piekary slaskie"): 31})
    assert NL.national_km(pairs, "Piekary Śl.", "Gliwice") == 31
    assert NL.national_km(pairs, "Gliwice", "Piekary Śląskie") == 31
    assert NL.national_km(pairs, "Gliwice", "Opole") is None
    assert NL.national_km(pairs, "Gliwice", "gliwice") is None
    assert NL.national_km({}, "Gliwice", "Opole") is None


def test_skrot_w_kluczu_tabeli_rozwija_sie_przy_budowie_mapy():
    pairs = NL.expand_pairs({("bytom", "piekary sl"): 12})
    assert NL.national_km(pairs, "Bytom", "Piekary Śląskie") == 12


def test_mapa_bez_rozwinięcia_też_działa_dla_dosłownych_kluczy():
    assert NL.national_km({("myslowice", "opole"): 122}, "Opole", "Mysłowice") == 122


def test_mecz_okregowy_tabela_okregu_wygrywa_z_tabela_zprp():
    national = NL.expand_pairs({("gliwice", "zabrze"): 20})
    assert NL.pick_distance(
        False, home="Gliwice", city="Zabrze", table_km=18, national=national
    ) == (18.0, "table")
    assert NL.pick_distance(
        False, home="Gliwice", city="Zabrze", table_km=None, national=national
    ) == (20.0, "zprp-table")
    assert NL.pick_distance(False, home="Gliwice", city="Opole", national=national) is None


def test_mecz_centralny_pomija_tabele_okregu():
    national = NL.expand_pairs({("gliwice", "zabrze"): 20})
    assert NL.pick_distance(
        True, home="Gliwice", city="Zabrze", table_km=18, national=national
    ) == (20.0, "zprp-table")
    assert NL.pick_distance(True, home="Gliwice", city="Kielce", table_km=150, national=national) is None


def test_to_samo_miasto_zawsze_zero():
    assert NL.pick_distance(True, home="Gliwice", city="GLIWICE") == (0.0, "same-city")
    assert NL.pick_distance(False, home="Piekary Śl.", city="Piekary Śląskie") == (0.0, "same-city")
    assert NL.pick_distance(False, home="", city="Gliwice") is None


def test_zero_z_tabeli_okregu_to_same_city():
    assert NL.pick_distance(False, home="Bystra", city="Bystra Śl", table_km=0) == (0.0, "same-city")


def test_wersja_i_etag():
    stamp = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    version = NL.pairs_version(12, stamp)
    assert version == f"12-{int(stamp.timestamp())}"
    assert NL.pairs_version(0, None) == "0-0"
    assert NL.etag_matches(f'"{version}"', version)
    assert NL.etag_matches(f'W/"{version}", "x"', version)
    assert NL.etag_matches("*", version)
    assert not NL.etag_matches('"inna"', version)
    assert not NL.etag_matches(None, version)


def test_pairs_rows_w_stalym_ukladzie():
    rows = [
        {"city_a_key": "zabrze", "city_b_key": "gliwice", "distance_km": 20, "observations": 2},
        {"city_a_key": "", "city_b_key": "x", "distance_km": 1, "observations": 1},
        {"city_a_key": "bytom", "city_b_key": "opole", "distance_km": 90, "observations": None},
    ]
    assert NL.pairs_rows(rows) == [["bytom", "opole", 90, 0], ["gliwice", "zabrze", 20, 2]]


def test_status_sedziego():
    at = datetime(2026, 9, 30, tzinfo=timezone.utc)
    assert NL.judge_status({"first_full_at": at, "last_full_at": at}) == {
        "built": True, "at": at.isoformat(), "reason": "judge",
    }
    assert NL.judge_status(None, at, True) == {"built": True, "at": at.isoformat(), "reason": "sources"}
    assert NL.judge_status(None, None, False) == {"built": False, "at": None, "reason": None}


def test_czyszczenie_numerow_meczow():
    assert NL.clean_match_ids(["12", " 12", "ab", None, "7"]) == ["12", "7"]
    assert len(NL.clean_match_ids(str(i) for i in range(5000))) == NL.MAX_STATUS_MATCH_IDS
