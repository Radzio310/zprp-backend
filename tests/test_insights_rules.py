"""Analiza obsad (`app/insights_rules.py`) - trudność meczu, profile i wnioski."""
from __future__ import annotations

from app import insights_rules as I


def match(
    mid,
    *,
    code="S/JmM/1",
    ts=1_700_000_000_000,
    home="A",
    away="B",
    city="Katowice",
    gH=30,
    gA=20,
    refs=None,
    round_name="Runda I",
    series="Kolejka 1",
    roster=None,
    origin="district",
    **extra,
):
    return {
        "id": str(mid),
        "code": code,
        "comp": code.rsplit("/", 1)[0],
        "ts": ts,
        "home": home,
        "away": away,
        "city": city,
        "gH": gH,
        "gA": gA,
        "refs": refs or {"first": "1", "second": "2"},
        "round": round_name,
        "series": series,
        "roster": roster,
        "origin": origin,
        **extra,
    }


def test_szczebel_z_klasyfikacji_rozliczen():
    assert I.tier_component("S/DzK/12") == (0.15, "Dzieci")
    assert I.tier_component("S/JmM/3")[1] == "Junior mł."
    assert I.tier_component("IIM4/1") == (0.8, "II liga")
    assert I.tier_component("S/PPK/2")[1] == "Puchar okręgu"
    assert I.tier_component("PPM/23")[1] == "Puchar Polski / MP"
    assert I.tier_component("SM/5")[0] == 1.0


def test_etap_z_nazwy_rundy():
    assert I.stage_component("Finał") == (1.0, "finał")
    assert I.stage_component("Runda II", "1/2 finału")[1] == "półfinał"
    assert I.stage_component("Ćwierćfinał")[1] == "ćwierćfinał"
    assert I.stage_component("Baraże")[1] == "baraż"
    assert I.stage_component("Runda zasadnicza", "Kolejka 3") == (0.0, "")


def test_tabela_i_derby():
    assert I.table_component(1, 2, 10, 0.5)[0] == 0.9
    assert I.table_component(1, 2, 10, 0.1)[0] == 0.0  # za wcześnie na tabelę
    assert I.table_component(3, 1, 10, 0.8)[0] == min(1.0, 0.8 * 1.15)
    assert I.table_component(9, 10, 10, 0.5)[0] == 0.5
    assert I.table_component(5, 7, 10, 0.5)[0] == 0.0
    assert I.derby_component("Ruda Śląska", "ruda slaska")[0] == 0.65
    assert I.derby_component("", "")[0] == 0.0


def test_protokol_na_styk_i_kary():
    close = I.protocol_component(match(1, gH=25, gA=24, roster={"susH": 8, "susA": 7, "redH": 1}), 8.0)
    loose = I.protocol_component(match(2, gH=35, gA=20, roster={"susH": 2, "susA": 2}), 8.0)
    assert close[0] > 0.7 and loose[0] < 0.2
    assert any("na styk" in why for why in close[1])
    assert any("kar 2 min" in why for why in close[1])
    assert "dyskwalifikacja" in close[1]
    assert I.protocol_component(match(3, gH=None, gA=None), 8.0) == (None, [])
    assert I.protocol_component(match(4, walkover=True), 8.0) == (None, [])


def test_ocena_delegata_i_oznaczenie_obsadowego():
    sheet = {"character": {"difficulty": {"short": "Trudny"}}, "sections": [{"mainGrade": "D", "items": [{"grade": "F"}]}]}
    assert I.evaluation_difficulty(sheet) == (0.85, "delegat: trudny")
    assert I.pair_grade(sheet) == 5.0
    assert I.manual_component("hard", (0.15, "delegat: łatwy"))[0] == 1.0  # obsadowy wygrywa
    assert I.manual_component(None, (0.15, "delegat: łatwy"))[0] == 0.15
    assert I.manual_component(None, None) == (None, "")


def test_stawka_i_przebieg_skalowane_szczeblem():
    assert I.scaled_by_tier(1.0, 0.15) == 0.575
    assert I.scaled_by_tier(1.0, 1.0) == 1.0
    assert I.scaled_by_tier(None, 0.5) is None


def test_brakujacy_skladnik_nie_jest_zerem():
    weights = {"tier": 50, "stake": 0, "protocol": 50, "manual": 0}
    assert I.weighted({"tier": 0.8, "stake": 0.0, "protocol": None, "manual": None}, weights) == 0.8
    assert I.weighted({"tier": 0.8, "stake": 0.0, "protocol": 0.4, "manual": None}, weights) == 0.6


def test_wagi_z_panelu():
    assert I.normalize_weights({"tier": "70", "stake": 500, "protocol": -3}) == {
        "tier": 70,
        "stake": 100,
        "protocol": 0,
        "manual": 15,
    }
    assert I.normalize_weights({"tier": 0, "stake": 0, "protocol": 0, "manual": 0}) == I.DEFAULT_WEIGHTS


def test_tabela_do_dnia_meczu():
    day = 86_400_000
    rows = [
        match(1, home="A", away="B", gH=30, gA=20, ts=1 * day),
        match(2, home="C", away="D", gH=20, gA=25, ts=2 * day),
        match(3, home="A", away="D", gH=None, gA=None, ts=3 * day),
    ]
    positions = I.standings_positions(rows)
    home, away, teams, progress = positions["3"]
    assert (home, away, teams) == (2, 1, 4) or (home, away, teams) == (1, 2, 4)
    assert progress == 1.0
    assert positions["1"][3] == 0.0


def test_fakty_i_powody():
    seasons = {
        2025: [
            match(1, code="S/JK/1", home="MKS Ruda", away="Grunwald Ruda", gH=25, gA=25, series="Finał"),
            match(2, code="S/DzK/1", home="X", away="Y", city="Gliwice", gH=10, gA=30),
        ]
    }
    facts = I.build_facts(
        seasons,
        marks={"2": "hard"},
        evaluations={"1": [{"referee_ids": ["1", "2"], "evaluation_json": {"sections": [{"mainGrade": "G"}]}}]},
    )
    by_id = {fact.id: fact for fact in facts}
    assert abs(by_id["1"].stake - 0.775) < 1e-9 and "finał" in by_id["1"].why["stake"]
    assert by_id["1"].grade == 7.0
    assert by_id["2"].manual == 1.0
    assert by_id["2"].field == ("1", "2")


def _season(start, count, pair=("1", "2"), code="S/JK/1", **extra):
    base = (start - 2020) * 10_000_000_000
    return [
        match(f"{start}-{code}-{index}", code=code, ts=base + index * 86_400_000, refs={"first": pair[0], "second": pair[1]}, **extra)
        for index in range(count)
    ]


def test_analiza_profile_i_wnioski():
    seasons = {
        2024: _season(2024, 12, ("1", "2"), gH=30, gA=29, series="Finał")
        + _season(2024, 12, ("3", "4"), code="S/DzK/1", home="C", away="D", gH=30, gA=10),
        2025: _season(2025, 12, ("1", "5"), gH=28, gA=27) + _season(2025, 12, ("3", "4"), code="S/DzK/1", gH=40, gA=10),
    }
    facts = I.build_facts(seasons, marks={}, evaluations={})
    people = {
        "1": I.Person("1", "Anna Starsza", league=True),
        "2": I.Person("2", "Bartek Drugi"),
        "3": I.Person("3", "Celina Trzecia"),
        "4": I.Person("4", "Dawid Czwarty"),
        "5": I.Person("5", "Ela Młoda", young=True),
    }
    result = I.analyze(facts, people=people, names={}, weights=I.DEFAULT_WEIGHTS, horizon="5", current=2025)

    assert result["meta"]["seasons"] == [2024, 2025]
    assert result["meta"]["matches"] == 48
    judges = {item["judge_id"]: item for item in result["judges"]}
    assert judges["1"]["field"] == 24 and judges["1"]["hard"] > 0
    assert judges["3"]["hard"] == 0
    assert judges["1"]["dominant"]["category"] == "Junior"
    assert judges["1"]["mentoring"]["young"] == 1

    keys = {item["key"] for item in result["conclusions"]}
    assert {"category_specialization", "stable_pairs", "mentors"} <= keys
    pairs = next(item for item in result["conclusions"] if item["key"] == "stable_pairs")
    top = pairs["affected"]["pairs"][0]
    assert {top["a"], top["b"]} in ({"1", "2"}, {"1", "5"})

    matches = I.judge_matches(
        facts, "1", weights=I.DEFAULT_WEIGHTS, threshold=result["meta"]["hard_threshold"], seasons=[2024, 2025]
    )
    assert len(matches) == 24 and all(item["role"] == "field" for item in matches)
    assert matches[0]["ts"] >= matches[-1]["ts"]


def test_horyzont():
    assert I.horizon_seasons("3", 2026, [2020, 2023, 2024, 2025, 2026, 2027]) == [2026, 2025, 2024]
    assert I.horizon_seasons("all", 2026, [2020, 2026]) == [2026, 2020]


def test_aktywny_ligowiec_wynika_z_meczow_boiskowych_od_drugiej_ligi():
    rows = (
        [I.Fact(str(i), 2024, i, "IIM/1", "", "II liga", "A", "B", "league", True,
                ("1",), (), (), .8, 0, None, None) for i in range(4)]
        + [I.Fact(str(i), 2025, i, "IM/1", "", "I liga", "A", "B", "league", True,
                  ("1",), (), (), .88, 0, None, None) for i in range(4, 8)]
    )
    activity = I.league_activity(rows, current=2026)
    assert activity["active"] is True
    assert activity["matches"] == 8
    assert activity["seasons"] == 2


def test_puchar_i_stolik_nie_nadaja_statusu_ligowca():
    rows = [
        I.Fact(str(i), 2026, i, "PPM/1", "", "Puchar Polski / MP", "A", "B", "league", True,
               (), ("1",), (), .76, 0, None, None)
        for i in range(12)
    ]
    assert I.league_activity(rows, current=2026)["active"] is False


def test_przewidywana_trudnosc_bez_protokolu():
    value, why = I.predicted_difficulty(
        code="S/JK/3",
        round_text="Runda II",
        series_text="Finał",
        home="MKS Ruda",
        away="Grunwald",
        cities={"mks ruda": "Ruda Śląska", "grunwald": "Ruda Śląska"},
        positions=None,
        mark=None,
        weights=I.DEFAULT_WEIGHTS,
    )
    assert "Junior" in why and "finał" in why
    # Stawka waży tyle, ile szczebel pozwala: junior 0.55 -> 1.0 * 0.775.
    assert abs(value - (35 * 0.55 + 25 * 0.775) / 60) < 1e-9


def _grades(value):
    """Wszystkie wartości pod kluczem „grade”, na dowolnej głębokości."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "grade":
                yield item
            yield from _grades(item)
    elif isinstance(value, list):
        for item in value:
            yield from _grades(item)


def test_oceny_delegatow_tylko_dla_uprawnionych():
    sheet = {"character": {"difficulty": {"short": "Trudny"}}, "sections": [{"mainGrade": "G"}]}
    seasons = {
        2024: _season(2024, 12, ("1", "2"), gH=30, gA=29, series="Finał"),
        2025: _season(2025, 12, ("1", "5"), gH=28, gA=27),
    }
    evaluations = {
        f"2025-S/JK/1-{index}": [{"referee_ids": ["1", "5"], "evaluation_json": sheet}] for index in range(12)
    }
    facts = I.build_facts(seasons, marks={}, evaluations=evaluations)
    people = {
        "1": I.Person("1", "Anna Starsza", league=True),
        "2": I.Person("2", "Bartek Drugi"),
        "5": I.Person("5", "Ela Młoda", young=True),
    }
    result = I.analyze(facts, people=people, names={}, weights=I.DEFAULT_WEIGHTS, horizon="5", current=2025)
    assert 7.0 in set(_grades(result))

    hidden = I.hide_evaluations(result)
    assert set(_grades(hidden)) == {None}
    assert hidden["meta"] == result["meta"]
    # Pamięć podręczna analizy zostaje nietknięta.
    assert 7.0 in set(_grades(result))

    matches = I.judge_matches(
        facts, "5", weights=I.DEFAULT_WEIGHTS, threshold=result["meta"]["hard_threshold"], seasons=[2024, 2025]
    )
    assert matches and all(item["why"]["manual"] == ["delegat: trudny"] for item in matches)
    shown = I.hide_match_evaluations(matches)
    assert all(item["grade"] is None for item in shown)
    assert all(item["why"]["manual"] == ["z arkusza delegata"] for item in shown)
    # Arkusz dalej liczy się do trudności - znika tylko to, co napisał delegat.
    assert [item["difficulty"] for item in shown] == [item["difficulty"] for item in matches]
    assert all(fact.why["manual"] == ["delegat: trudny"] for fact in facts if fact.season == 2025)
