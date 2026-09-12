from app.assignment_rules import (
    COMPLETE,
    is_bye,
    teams_known,
    GAP,
    SOFT,
    competition_key,
    crew,
    crew_needs,
    crew_status,
    match_category,
    slot_person,
)


def state(**people):
    """Migawka meczu: `pierwszy="5124 KOWALSKI Jan"` albo `pierwszy=""`."""
    out = {}
    for slot, value in people.items():
        number, _, name = str(value).partition(" ")
        out[f"NrSedzia_{slot}"] = number
        out[f"NrSedzia_{slot}_nazwisko"] = name
    return out


FULL = state(
    pierwszy="5124 KOWALSKI Jan",
    drugi="5131 NOWAK Anna",
    sekretarz="5188 MAZUR Łukasz",
    czas="5190 WÓJCIK Ewa",
)


def test_two_referees_from_mlodzik_up_one_below():
    assert crew_needs("S/MłK/12") == {"field": 2, "table": 2}
    assert crew_needs("S/JmM/3") == {"field": 2, "table": 2}
    assert crew_needs("IIK4/1") == {"field": 2, "table": 2}
    # Młodzik młodszy i dzieci moga miec jednego.
    assert crew_needs("S/MłM1213/3") == {"field": 1, "table": 1}
    assert crew_needs("S/DzK/1") == {"field": 1, "table": 1}


def test_zero_is_an_empty_slot_not_a_judge():
    assert slot_person({"NrSedzia_drugi": "0", "NrSedzia_drugi_nazwisko": ""}, "drugi") is None
    assert slot_person({"NrSedzia_drugi": "5131"}, "drugi") == {"number": "5131", "name": ""}
    # Terminarz podaje same nazwiska - to tez jest czlowiek w gniezdzie.
    assert slot_person({"NrSedzia_drugi_nazwisko": "NOWAK Anna"}, "drugi") == {
        "number": "",
        "name": "NOWAK Anna",
    }


def test_full_crew_is_complete():
    status = crew_status(FULL, "S/MłK/12")
    assert status["gaps"] == 0 and status["soft"] == 0
    assert status["state"] == COMPLETE
    assert crew(FULL)["pierwszy"] == {"number": "5124", "name": "KOWALSKI Jan"}


def test_missing_field_referee_is_a_gap():
    status = crew_status(state(pierwszy="5124 KOWALSKI Jan", sekretarz="1 A", czas="2 B"), "S/MłK/12")
    assert status["field"] == {"have": 1, "need": 2, "missing": 1}
    assert status["gaps"] == 1
    assert status["state"] == GAP


def test_one_table_official_is_only_a_light_difference():
    # Klub czesto daje jednego stolikowego - to nie jest dziura do zalatania.
    status = crew_status(
        state(pierwszy="5124 A", drugi="5131 B", sekretarz="5188 C"), "S/MłK/12"
    )
    assert status["gaps"] == 0
    assert status["soft"] == 1
    assert status["state"] == SOFT


def test_empty_table_is_a_gap():
    status = crew_status(state(pierwszy="5124 A", drugi="5131 B"), "S/MłK/12")
    assert status["table"] == {"have": 0, "need": 2, "missing": 2, "soft": 0}
    assert status["gaps"] == 2
    assert status["state"] == GAP


def test_delegate_is_never_a_gap():
    status = crew_status(FULL, "IIK4/1")
    assert status["delegate"] == {"have": 0}
    assert status["state"] == COMPLETE
    with_delegate = crew_status({**FULL, "NrSedzia_delegat_nazwisko": "DELEGAT Jan"}, "IIK4/1")
    assert with_delegate["delegate"]["have"] == 1
    assert with_delegate["state"] == COMPLETE


def test_small_categories_are_complete_with_one_of_each():
    status = crew_status(state(pierwszy="5124 A", sekretarz="5188 C"), "S/DzK/1")
    assert status["gaps"] == 0 and status["soft"] == 0
    assert status["state"] == COMPLETE


def test_competition_key_drops_the_match_number():
    assert competition_key("IIK4/1") == "IIK4"
    assert competition_key("S/JmM/12") == "S/JmM"
    assert competition_key("S/PPK/2") == "S/PPK"
    assert competition_key("") == ""


def test_category_comes_from_the_code():
    assert match_category("S/JmM/12")
    assert match_category("IIK4/1")


# ── mecze, których nie będzie ────────────────────────────────────────────────


def test_a_paused_team_is_not_a_match_to_fill():
    """
    Przy nieparzystej liczbie drużyn jedna pauzuje, a terminarz zapisuje to jak
    zwykły mecz - z numerem, halą i pustymi gniazdami. Automat wysyłał tam
    ludzi na spotkanie, którego nie będzie.
    """
    assert is_bye(
        {
            "ID_zespoly_gosp_ZespolNazwa": "Zespół nr 2",
            "ID_zespoly_gosc_ZespolNazwa": "SPR Sośnica Gliwice pauzuje",
        }
    )
    assert is_bye({"ID_zespoly_gosp_ZespolNazwa": "KS Bystra - PAUZA"})
    assert is_bye({"ID_zespoly_gosc_ZespolNazwa": "wolny los"})


def test_a_normal_match_is_not_a_bye():
    assert not is_bye(
        {
            "ID_zespoly_gosp_ZespolNazwa": "GKS Katowice",
            "ID_zespoly_gosc_ZespolNazwa": "SPR Sośnica Gliwice",
        }
    )
    assert not is_bye({})


def test_a_match_without_both_teams_is_flagged_but_not_refused():
    # Mecz z drabinki: hala i termin bywają znane, pary jeszcze nie.
    assert not teams_known({"ID_zespoly_gosc_ZespolNazwa": "KS Bystra"})
    assert not teams_known({})
    assert teams_known(
        {
            "ID_zespoly_gosp_ZespolNazwa": "GKS Katowice",
            "ID_zespoly_gosc_ZespolNazwa": "KS Bystra",
        }
    )
