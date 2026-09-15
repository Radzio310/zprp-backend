from app.delegate_evaluation_utils import allowed_season, canonical_hash, grade_values, safe_source_fingerprint


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
    assert result == {"I": [7, 6], "Komunikacja": [5]}
