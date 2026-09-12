"""Cofanie przebiegu i porównanie układów - reguły bez bazy."""

from app.assignment_undo import DONE, GONE, KEPT, RESTORE, compare, verdict


def change(**rest):
    base = {
        "id": 1,
        "slot": "pierwszy",
        "judge_id": "77",
        "judge_name": "KOWALSKI Jan",
        "before_id": "",
        "before_name": "",
        "undone_at": None,
    }
    base.update(rest)
    return base


def state(**rest):
    base = {"NrSedzia_pierwszy": "77", "NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan"}
    base.update(rest)
    return base


def test_slot_untouched_since_the_run_is_restored():
    call, why = verdict(change(before_name="NOWAK Anna", before_id="12"), state())
    assert call == RESTORE
    assert "NOWAK Anna" in why


def test_empty_slot_before_the_run_is_freed_not_filled():
    call, why = verdict(change(), state())
    assert call == RESTORE
    assert "zwalniamy" in why


def test_a_hand_made_change_after_the_run_is_left_alone():
    """Decyzja człowieka jest ważniejsza - i cofanie ma o niej powiedzieć."""
    now = state(NrSedzia_pierwszy="99", NrSedzia_pierwszy_nazwisko="ZIELIŃSKI Paweł")
    call, why = verdict(change(), now)
    assert call == KEPT
    assert "ZIELIŃSKI Paweł" in why


def test_the_same_person_written_the_other_way_round_still_counts_as_ours():
    # ZPRP podpisuje „NOWAK Jan", lista okręgu bywa „Jan Nowak".
    now = state(NrSedzia_pierwszy="", NrSedzia_pierwszy_nazwisko="Jan Kowalski")
    call, _ = verdict(change(judge_id=""), now)
    assert call == RESTORE


def test_zero_in_the_slot_means_empty_not_a_judge():
    now = state(NrSedzia_pierwszy="0", NrSedzia_pierwszy_nazwisko="")
    call, _ = verdict(change(judge_id="", judge_name=""), now)
    assert call == RESTORE


def test_a_match_gone_from_the_snapshot_is_reported_not_forced():
    call, why = verdict(change(), {})
    assert call == GONE
    assert "terminarz" in why


def test_a_change_undone_earlier_is_not_undone_twice():
    call, _ = verdict(change(undone_at="2026-09-12T10:00:00"), state())
    assert call == DONE


# ── porównanie układów ──────────────────────────────────────────────────────


def slot(match_id, name, km, judge_id="1", slot_name="pierwszy"):
    return {
        "match_id": match_id,
        "slot": slot_name,
        "code": "S/JmM/1",
        "judge_id": judge_id,
        "name": name,
        "km": km,
    }


def test_shorter_travel_is_worth_it():
    before = [slot("1", "KOWALSKI Jan", 80, "1")]
    after = [slot("1", "NOWAK Anna", 20, "2")]
    result = compare(before, after)
    assert result["km_saved"] == 60.0
    assert result["worth_it"]
    [move] = result["moves"]
    assert move["from_name"] == "KOWALSKI Jan" and move["to_name"] == "NOWAK Anna"
    assert move["gain"] == 60.0


def test_the_same_crew_is_not_a_move():
    rows = [slot("1", "KOWALSKI Jan", 30, "1")]
    result = compare(rows, rows)
    assert result["moves"] == []
    assert not result["worth_it"]


def test_a_draw_is_not_a_reason_to_shuffle_people():
    """Przestawianie bez zysku to tylko zamieszanie i kolejne powiadomienia."""
    before = [slot("1", "KOWALSKI Jan", 30, "1")]
    after = [slot("1", "NOWAK Anna", 30, "2")]
    result = compare(before, after)
    assert result["km_saved"] == 0.0
    assert not result["worth_it"]
    assert result["moves"]          # ruch widać, ale nie jest polecany


def test_filling_an_empty_slot_is_worth_it_even_without_kilometres():
    before = [slot("1", "", None, "")]
    after = [slot("1", "NOWAK Anna", None, "2")]
    result = compare(before, after)
    assert result["filled_before"] == 0 and result["filled_after"] == 1
    assert result["worth_it"]
    assert result["unknown_km"] == 1


# ── kilka wpisów na to samo gniazdo (automat, potem optymalizacja) ──────────


def merge(rows):
    """Powtórka scalania z `undo_plan` - reguła, nie zapytanie do bazy."""
    merged, order = {}, []
    for row in rows:
        key = (row["match_id"], row["slot"])
        if key not in merged:
            merged[key] = dict(row)
            order.append(key)
            continue
        first = merged[key]
        first["id"] = row["id"]
        first["judge_id"] = row["judge_id"]
        first["judge_name"] = row["judge_name"]
        first.setdefault("extra_ids", []).append(row["id"])
    return [merged[key] for key in order]


def test_undo_goes_back_to_the_state_before_the_whole_run():
    """
    Po optymalizacji to samo gniazdo ma dwa wpisy.

    Cofnięcie musi wrócić do stanu sprzed CAŁEGO przebiegu, a nie do kogoś,
    kogo i tak wpisał automat w pierwszym kroku.
    """
    rows = [
        # automat: gniazdo było puste, stanął Kowalski
        {"id": 1, "match_id": "1", "slot": "pierwszy", "judge_id": "77",
         "judge_name": "KOWALSKI Jan", "before_id": "", "before_name": "", "undone_at": None},
        # optymalizacja: Kowalskiego zastąpił Wójcik
        {"id": 2, "match_id": "1", "slot": "pierwszy", "judge_id": "88",
         "judge_name": "WÓJCIK Tomasz", "before_id": "77", "before_name": "KOWALSKI Jan",
         "undone_at": None},
    ]
    [row] = merge(rows)

    # Sprawdzamy obecność po OSTATNIM wpisie...
    now = {"NrSedzia_pierwszy": "88", "NrSedzia_pierwszy_nazwisko": "WÓJCIK Tomasz"}
    call, why = verdict(row, now)
    assert call == RESTORE
    # ...ale wracamy do PIERWSZEGO stanu: gniazdo było puste.
    assert row["before_id"] == "" and row["before_name"] == ""
    assert "zwalniamy" in why
    # Stempel cofnięcia obejmuje oba wpisy.
    assert row["extra_ids"] == [2]


def test_a_hand_change_after_the_optimisation_is_still_respected():
    rows = [
        {"id": 1, "match_id": "1", "slot": "pierwszy", "judge_id": "77",
         "judge_name": "KOWALSKI Jan", "before_id": "", "before_name": "", "undone_at": None},
        {"id": 2, "match_id": "1", "slot": "pierwszy", "judge_id": "88",
         "judge_name": "WÓJCIK Tomasz", "before_id": "77", "before_name": "KOWALSKI Jan",
         "undone_at": None},
    ]
    [row] = merge(rows)
    now = {"NrSedzia_pierwszy": "99", "NrSedzia_pierwszy_nazwisko": "ZIELIŃSKI Paweł"}
    call, why = verdict(row, now)
    assert call == KEPT
    assert "ZIELIŃSKI Paweł" in why
