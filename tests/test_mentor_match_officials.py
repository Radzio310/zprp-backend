"""Karta meczu z całą obsadą i halą (17.11.2026): szukanie meczów pary po osobach i hali między sezonami."""

from app import mentor_panel_rules as R


def test_hurtownia_daje_obsade_i_hale():
    card = R.card_from_public({"match_id": "1", "referee_1_name": "KOWALSKI Jan", "referee_2_name": "NOWAK Adam",
                               "delegate_1_name": "SŁOWIŃSKI Bartosz", "delegate_2_name": "--- ---", "secretary_name": "LIS Ewa",
                               "timekeeper_name": "", "venue_name": "Hala Legionów", "venue_city": "Kielce"})
    assert card["venue_name"] == "Hala Legionów"
    assert card["officials"] == [{"role": "referee", "name": "KOWALSKI Jan"}, {"role": "referee", "name": "NOWAK Adam"},
                                 {"role": "delegate", "name": "SŁOWIŃSKI Bartosz"}, {"role": "secretary", "name": "LIS Ewa"}]


def test_monitor_i_archiwum_dokladaja_obsade_gdy_hurtownia_jej_nie_ma():
    state = {"NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan", "NrSedzia_sekretarz_nazwisko": "LIS Ewa", "NrSedzia_czas_nazwisko": "WRÓBEL Ola",
             "Hala_nazwa": "Hala MOSiR", "Hala_miasto": "Puławy"}
    province = R.card_from_state("2", state)
    assert {o["role"] for o in province["officials"]} == {"referee", "secretary", "timekeeper"}
    archive = R.card_from_archive({"match_id": "2", "slim_json": {"refNames": {"first": "KOWALSKI Jan", "timer": "WRÓBEL Ola"}, "hall": "Hala MOSiR"}})
    assert archive["venue_name"] == "Hala MOSiR"
    bare = R.base_card("2")
    merged = R.merge_matches([bare], [province])
    assert merged[0]["officials"] == province["officials"] and merged[0]["venue_name"] == "Hala MOSiR"
