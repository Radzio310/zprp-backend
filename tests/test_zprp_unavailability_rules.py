"""Opis meczu w powiadomieniu o kolizji - także meczu bez daty (termin kolejki)."""

from app.zprp_unavailability_rules import conflict_when, is_tentative, subject_prefix, window_label

SURE = {"code": "IIM4/10", "startAt": "2026-10-17T16:00:00"}
MAYBE = {"code": "IIM4/11", "startAt": "2026-10-03T00:00:00", "tentative": True, "windowStart": "2026-10-03", "windowEnd": "2026-10-05"}


def test_window_label_variants():
    assert window_label("2026-10-03", "2026-10-05") == "03-05.10.2026"
    assert window_label("2026-09-30", "2026-10-02") == "30.09-02.10.2026"
    assert window_label("2026-12-30", "2027-01-02") == "30.12.2026-02.01.2027"
    assert window_label("2026-10-03", "2026-10-03") == "03.10.2026"


def test_conflict_when_uses_round_window_for_undated_match():
    assert conflict_when(SURE) == "17.10.2026 · 16:00"
    assert conflict_when(MAYBE) == "możliwy termin: kolejka 03-05.10.2026, dokładny dzień nieznany"
    assert not is_tentative({**MAYBE, "windowStart": ""})


def test_subject_softens_only_when_all_are_tentative():
    assert subject_prefix([MAYBE]).startswith("Niedyspozycyjność może")
    assert subject_prefix([SURE, MAYBE]) == "Niedyspozycyjność nachodzi na obsadę ZPRP"
