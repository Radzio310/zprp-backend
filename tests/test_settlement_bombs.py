"""
Bomby z Rejestru nieobecności w rozliczeniu (decyzja użytkownika z 06.10.2026).
"""

from datetime import datetime, timezone

from app import settlement_engine as E
from app.settlement_bombs import (
    MANUAL_MATCH_PREFIX,
    BombRef,
    apply_penalties,
    apply_penalty,
    bomb_from_row,
    match_bombs,
    penalty_due,
    split_bombed,
)


def assignment(key, judge, *, hour=16, day=4, code="S/JMM/7"):
    return E.Assignment(
        match_key=key,
        judge_id=judge,
        match_at=datetime(2026, 10, day, hour, 0, tzinfo=timezone.utc),
        match_code=code,
        role="Sędzia boiskowy",
    )


def bomb(match_id, judge, *, bomb_id=1, penalty=0.0, hour=16, day=4, code="", name=""):
    return BombRef(
        bomb_id=bomb_id,
        match_id=match_id,
        judge_id=judge,
        subject_name=name,
        match_at=datetime(2026, 10, day, hour, 0, tzinfo=timezone.utc),
        match_code=code,
        penalty=penalty,
        note="",
        source="manual" if match_id.startswith(MANUAL_MATCH_PREFIX) else "crew",
        label="",
    )


DRAB = "465"
OTHER = "777"
CREW = [
    assignment("d:100", DRAB),
    assignment("d:100", OTHER),
    assignment("d:101", DRAB, day=5),
]


def test_bomb_with_match_number_hits_only_that_judge():
    hits = match_bombs([bomb("100", DRAB)], CREW)
    assert set(hits) == {("d:100", DRAB)}


def test_outside_key_matches_too():
    hits = match_bombs([bomb("200", DRAB)], [assignment("o:200", DRAB)])
    assert set(hits) == {("o:200", DRAB)}


def test_manual_bomb_by_judge_and_polish_day():
    hits = match_bombs([bomb(MANUAL_MATCH_PREFIX + "x", DRAB, day=5)], CREW)
    assert set(hits) == {("d:101", DRAB)}


def test_manual_bomb_ambiguous_day_needs_code_or_time():
    crew = [assignment("d:1", DRAB, hour=9), assignment("d:2", DRAB, hour=15, code="S/MłM/2")]
    # Dwa mecze tego dnia, godzina 12:00 nie wskazuje żadnego w granicy 90 min.
    assert match_bombs([bomb(MANUAL_MATCH_PREFIX + "x", DRAB, hour=12)], crew) == {}
    # Godzina blisko jednego z nich.
    assert set(match_bombs([bomb(MANUAL_MATCH_PREFIX + "x", DRAB, hour=14)], crew)) == {("d:2", DRAB)}
    # Numer meczu z wpisu rozstrzyga niezależnie od godziny.
    hit = match_bombs([bomb(MANUAL_MATCH_PREFIX + "x", DRAB, hour=12, code="s/młm/2")], crew)
    assert set(hit) == {("d:2", DRAB)}


def test_bomb_without_judge_number_matches_by_name():
    hits = match_bombs(
        [bomb("100", "", name="Jan DRAB")], CREW, names={DRAB: "DRAB Jan", OTHER: "NOWAK Anna"}
    )
    assert set(hits) == {("d:100", DRAB)}


def test_split_and_penalty_once_per_bomb():
    one = bomb("100", DRAB, penalty=50)
    # Sędzia w dwóch rolach przy jednym meczu - jedna bomba, jedna kara.
    crew = [assignment("d:100", DRAB), E.Assignment(match_key="d:100", judge_id=DRAB, role="Sędzia stolikowy")]
    hits = {("d:100", DRAB): one}
    payable, bombed = split_bombed(crew, hits)
    assert payable == []
    assert len(bombed) == 2
    assert penalty_due(bombed) == {DRAB: 50.0}


def test_penalty_comes_off_net_and_never_below_zero():
    assert apply_penalty(300, 50) == (50.0, 0.0)
    assert apply_penalty(30, 50) == (30.0, 20.0)
    assert apply_penalty(0, 50) == (0.0, 50.0)


def test_bomb_from_row():
    ref = bomb_from_row(
        {
            "id": 7,
            "match_id": "194144",
            "subject_judge_id": "465",
            "subject_name": "Jan DRAB",
            "match_at": datetime(2026, 10, 4, 16, 0),
            "penalty": "25.50",
            "host_team": "A",
            "guest_team": "B",
        }
    )
    assert ref.bomb_id == 7 and ref.penalty == 25.5 and ref.label == "A - B"
    assert ref.match_at.tzinfo is not None
    assert ref.source == "crew"


def test_apply_penalties_on_entries():
    rich = E.JudgeSettlement(judge_id=DRAB, judge_name="DRAB Jan", net=200, travel=30, total=230)
    poor = E.JudgeSettlement(judge_id=OTHER, judge_name="NOWAK Anna", net=20, travel=10, total=30)
    rows = [
        {"bomb_id": 1, "judge_id": DRAB, "penalty": 50},
        {"bomb_id": 1, "judge_id": DRAB, "penalty": 50},   # ta sama bomba, druga rola
        {"bomb_id": 2, "judge_id": OTHER, "penalty": 50},
        {"bomb_id": 3, "judge_id": "999", "penalty": 15},  # sedzia bez wyplaty w okresie
        {"bomb_id": 4, "judge_id": DRAB, "penalty": 0},
    ]
    out = apply_penalties([rich, poor], rows)
    assert (rich.penalty, rich.penalty_left, rich.total) == (50.0, 0.0, 180.0)
    # Przejazd zostaje - kara schodzi tylko z netto.
    assert (poor.penalty, poor.penalty_left, poor.total) == (20.0, 30.0, 10.0)
    assert out["999"] == {"due": 15.0, "applied": 0.0, "left": 15.0}


def test_bomba_bez_obsady_wchodzi_do_okresu_z_kara():
    # 07.10.2026: trzy bomby Krzysztofa Draba na 03.10 - tego dnia bez meczu
    # w rozliczeniu. Nie mogą zostać tylko w rejestrze.
    from datetime import datetime, timezone

    from app.settlement_bombs import BombRef, match_bombs, unlinked

    loose = BombRef(
        bomb_id=7, match_id="manual:abc", judge_id="900", subject_name="DRAB Krzysztof",
        match_at=datetime(2026, 10, 3, 10, 0, tzinfo=timezone.utc), match_code="", penalty=50.0,
        note="", source="manual", label="turniej",
    )
    other = BombRef(
        bomb_id=8, match_id="manual:def", judge_id="111", subject_name="Obcy",
        match_at=datetime(2026, 10, 3, 10, 0, tzinfo=timezone.utc), match_code="", penalty=0.0,
        note="", source="manual", label="",
    )
    hits = match_bombs([loose, other], [])
    assert hits == {}
    assert unlinked([loose, other], hits, {"900"}) == [loose]
