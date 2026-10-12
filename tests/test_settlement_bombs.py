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


def _entry(judge, name, gross, travel):
    from app import settlement_rates as R

    parts = R.settle_period(gross)
    return E.JudgeSettlement(
        judge_id=judge, judge_name=name, gross=parts["gross"], costs=parts["costs"],
        taxable=parts["taxable"], tax=parts["tax"], net=parts["net"], travel=travel,
        total=round(parts["net"] + travel, 2),
    )


def test_apply_penalties_on_entries():
    # 12.10.2026: kara POMNIEJSZA BRUTTO - netto spada dokładnie o karę.
    rich = _entry(DRAB, "DRAB Jan", 445, 30)
    poor = _entry(OTHER, "NOWAK Anna", 20, 10)
    rows = [
        {"bomb_id": 1, "judge_id": DRAB, "penalty": 270},
        {"bomb_id": 1, "judge_id": DRAB, "penalty": 270},  # ta sama bomba, druga rola
        {"bomb_id": 2, "judge_id": OTHER, "penalty": 50},
        {"bomb_id": 3, "judge_id": "999", "penalty": 15},  # sedzia bez wyplaty w okresie
        {"bomb_id": 4, "judge_id": DRAB, "penalty": 0},
    ]
    out = apply_penalties([rich, poor], rows)
    # Przykład księgowej: Drab 132 zł do wypłaty -> brutto 150, nie 445.
    assert (rich.gross, rich.tax, rich.net) == (150.0, 18, 132.0)
    assert (rich.gross_due, rich.penalty, rich.penalty_gross, rich.penalty_left) == (445.0, 270.0, 295.0, 0.0)
    assert rich.total == 162.0  # przejazd zostaje
    # Kara większa niż ekwiwalent: brutto do zera, przejazd nietknięty, reszta do potrącenia.
    assert (poor.gross, poor.net, poor.penalty, poor.penalty_left, poor.total) == (0.0, 0.0, 18.0, 32.0, 10.0)
    assert out["999"]["left"] == 15.0


def test_kara_netto_brutto_i_prog_200():
    from app import settlement_bombs as B
    from app import settlement_rates as R

    base = R.settle_period(445)
    r = B.penalize(base, 60)
    assert r["applied"] == 60.0 and r["left"] == 0.0
    assert r["parts"]["net"] == base["net"] - 60
    # Netto 179 nie wychodzi z żadnego brutto (próg 200 zł) - najbliższe wyższe,
    # różnica zostaje do potrącenia.
    r = B.penalize(R.settle_period(300), 92)
    assert r["parts"]["gross"] == 200.01 and r["parts"]["net"] == 181.01
    assert r["left"] == 2.01
    # Brutto z groszami zostaje z groszami.
    r = B.penalize(R.settle_period(150.5), 30)
    assert r["parts"]["net"] == 102.5


def test_kara_na_listach_najpierw_lista_kar():
    from app import settlement_bombs as B
    from app import settlement_rates as R

    a, b = R.settle_period(300), R.settle_period(145)
    entry = E.JudgeSettlement(
        judge_id=DRAB, judge_name="DRAB Jan",
        gross=445, costs=a["costs"] + b["costs"], taxable=a["taxable"] + b["taxable"],
        tax=a["tax"] + b["tax"], net=a["net"] + b["net"], travel=0, total=a["net"] + b["net"],
        split={"current": True, "parts": [
            {"letter": "A", **a, "travel": 0, "total": a["net"]},
            {"letter": "B", **b, "travel": 0, "total": b["net"]},
        ]},
    )
    B.apply_penalties([entry], [{"bomb_id": 1, "judge_id": DRAB, "penalty": 50}], first="B")
    part_a, part_b = entry.split["parts"]
    assert part_a.get("penalty") is None  # lista A nietknięta
    assert part_b["penalty"] == 50.0 and part_b["net"] == b["net"] - 50
    assert entry.net == a["net"] + b["net"] - 50
    assert entry.gross == 445 - part_b["penalty_gross"]


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
