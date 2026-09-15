from app.delegate_evaluation_utils import (
    GRADE_POINTS,
    absorb_evaluation,
    allowed_season,
    canonical_hash,
    finalize_bucket,
    grade_values,
    new_bucket,
    pair_names,
    safe_source_fingerprint,
)


def test_only_supported_seasons_are_collected():
    assert allowed_season("2025/2026")
    assert allowed_season("2026_2027")
    assert not allowed_season("2024/2025")
    assert not allowed_season("")


def test_hash_is_canonical_and_source_url_is_not_exposed():
    assert canonical_hash({"b": 2, "a": 1}) == canonical_hash({"a": 1, "b": 2})
    url = "https://example.test/form?secret=abc"
    fingerprint = safe_source_fingerprint(url)
    assert url not in fingerprint
    assert "secret" not in fingerprint
    assert len(fingerprint) == 64


def test_grade_values_include_main_and_parameter_grades():
    result = grade_values({"sections": [
        {"key": "I", "mainGrade": "A", "items": [{"grade": "B"}, {"grade": "x"}]},
        {"title": "Komunikacja", "mainGrade": "C", "items": []},
    ]})
    assert result == {"I": [1, 2], "Komunikacja": [3]}


def test_wieksza_liczba_punktow_znaczy_lepsza_ocena():
    """A to „niedopuszczalnie", G to „wybitnie" - patrz legenda arkusza.

    Do 15.09.2026 mapa punktów była odwrócona i para z samymi „A" wychodziła
    na średnią 7,00, czyli wybitną. Ten test istnieje po to, żeby nikt nie
    odwrócił jej z powrotem „dla porządku alfabetycznego".
    """
    assert GRADE_POINTS["A"] < GRADE_POINTS["D"] < GRADE_POINTS["G"]
    assert GRADE_POINTS["G"] == max(GRADE_POINTS.values())


def test_najlepsza_i_najgorsza_ocena_nie_sa_zamienione():
    bucket = new_bucket(key="para")
    absorb_evaluation(
        bucket,
        {"sections": [{"key": "I", "mainGrade": "G", "items": [{"title": "Krok", "grade": "A"}]}]},
        grade_values({"sections": [{"key": "I", "mainGrade": "G", "items": [{"grade": "A"}]}]}),
    )
    done = finalize_bucket(bucket)
    assert done["best"] == GRADE_POINTS["G"]
    assert done["worst"] == GRADE_POINTS["A"]


def test_para_dostaje_rozpisanie_na_kryteria_tak_jak_osoba():
    """Delegat ocenia PARĘ - ekran pary nie może sięgać po dane jednego sędziego."""
    evaluation = {"sections": [
        {"key": "I", "title": "Zarządzanie", "mainGrade": "E",
         "items": [{"title": "Kontakt", "grade": "F"}, {"title": "Kontakt", "grade": "D"}]},
    ]}
    bucket = new_bucket(key="1|2", judge_ids=["1", "2"], names=["Kowalski", "Nowak"])
    absorb_evaluation(bucket, evaluation, grade_values(evaluation))
    done = finalize_bucket(bucket)
    assert done["evaluations"] == 1
    assert done["sections"]["I"]["samples"] == 3
    parametry = done["section_details"]["I"]["parameters"]
    assert [p["title"] for p in parametry] == ["Kontakt"]
    assert parametry[0]["samples"] == 2
    assert parametry[0]["best"] == GRADE_POINTS["F"]


def test_dwa_arkusze_tej_samej_pary_sumuja_sie():
    evaluation = {"sections": [{"key": "I", "mainGrade": "D", "items": []}]}
    bucket = new_bucket(key="1|2")
    for _ in range(2):
        absorb_evaluation(bucket, evaluation, grade_values(evaluation))
    done = finalize_bucket(bucket)
    assert done["evaluations"] == 2
    assert done["sections"]["I"]["samples"] == 2
    assert done["average"] == GRADE_POINTS["D"]


def test_nazwiska_pary_stoja_rownorzednie():
    """Kolejność z arkusza stawiałaby jednego sędziego zawsze pierwszego."""
    assert pair_names(["7", "3"], ["Zalewski", "Adamczyk"]) == ["Adamczyk", "Zalewski"]
    assert pair_names(["7", "3"], ["Adamczyk", "Zalewski"]) == ["Adamczyk", "Zalewski"]


def test_brak_nazwiska_zastepuje_numer_a_nie_pustka():
    assert pair_names(["7", "3"], ["Adamczyk"]) == ["3", "Adamczyk"]
