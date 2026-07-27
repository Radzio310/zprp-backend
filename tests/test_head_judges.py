import pytest

from app.beach.head_judges import (
    apply_default_head_judge_to_schedule,
    head_judge_ids,
    is_head_judge,
    sync_legacy_head_judge_fields,
    validate_schedule_head_judges,
)


def _data():
    return {
        "judges": [
            {"id": 11, "full_name": "NOWAK Anna"},
            {"id": 22, "full_name": "KOWAL Jan"},
        ],
        "head_judge_ids": [11, 22],
        "default_head_judge_id": 11,
        "head_judge_id": 11,
        "schedule": {
            "matches": [
                {
                    "id": "m1",
                    "status": "scheduled",
                    "referees": {},
                },
                {
                    "id": "m2",
                    "status": "scheduled",
                    "referees": {
                        "headJudge": {"id": 22, "name": "KOWAL Jan"},
                        "headJudgeSource": "manual",
                    },
                },
                {
                    "id": "m3",
                    "status": "finished",
                    "referees": {},
                },
            ]
        },
    }


def test_legacy_single_head_judge_is_normalized():
    data = {"head_judge_id": 7}
    assert head_judge_ids(data) == [7]
    assert is_head_judge(data, 7)
    ids, default = sync_legacy_head_judge_fields(data)
    assert ids == [7]
    assert default == 7
    assert data["head_judge_ids"] == [7]


def test_default_only_fills_unassigned_scheduled_matches():
    data = _data()
    result = apply_default_head_judge_to_schedule(data)
    matches = data["schedule"]["matches"]
    assert result["assigned"] == 1
    assert matches[0]["referees"]["headJudge"]["id"] == 11
    assert matches[0]["referees"]["headJudgeSource"] == "default"
    assert matches[1]["referees"]["headJudge"]["id"] == 22
    assert "headJudge" not in matches[2]["referees"]


def test_default_skips_a_judge_already_assigned_to_another_role():
    data = _data()
    data["schedule"]["matches"][0]["referees"] = {
        "fieldA": {"id": 11, "name": "NOWAK Anna"}
    }
    result = apply_default_head_judge_to_schedule(data)
    assert result["skipped"] == 1
    assert "headJudge" not in data["schedule"]["matches"][0]["referees"]


def test_changing_default_updates_only_automatic_assignments():
    data = _data()
    apply_default_head_judge_to_schedule(data)
    data["default_head_judge_id"] = 22
    data["head_judge_id"] = 22

    result = apply_default_head_judge_to_schedule(data)
    matches = data["schedule"]["matches"]

    assert result["updated"] == 1
    assert matches[0]["referees"]["headJudge"]["id"] == 22
    assert matches[0]["referees"]["headJudgeSource"] == "default"
    assert matches[1]["referees"]["headJudge"]["id"] == 22
    assert matches[1]["referees"]["headJudgeSource"] == "manual"


def test_default_never_changes_a_match_already_created_in_proel():
    data = _data()
    data["schedule"]["matches"][0]["referees"] = {
        "headJudge": {"id": 22, "name": "KOWAL Jan"},
        "headJudgeSource": "default",
    }

    result = apply_default_head_judge_to_schedule(
        data,
        protected_match_keys={"m1"},
    )

    assert result["updated"] == 0
    assert data["schedule"]["matches"][0]["referees"]["headJudge"]["id"] == 22


def test_default_skips_a_scheduled_match_whose_start_time_has_passed():
    data = _data()
    data["schedule"]["config"] = {"days": [{"date": "2000-01-01"}]}
    data["schedule"]["matches"][0].update(
        {"dayIndex": 0, "startTime": "10:00"}
    )

    result = apply_default_head_judge_to_schedule(data)

    assert result["assigned"] == 0
    assert "headJudge" not in data["schedule"]["matches"][0]["referees"]


def test_duplicate_role_in_same_match_is_rejected():
    data = _data()
    data["schedule"]["matches"][0]["referees"] = {
        "fieldA": {"id": 11, "name": "NOWAK Anna"},
        "headJudge": {"id": 11, "name": "NOWAK Anna"},
        "headJudgeSource": "manual",
    }
    with pytest.raises(ValueError, match="dwóch ról"):
        validate_schedule_head_judges(data, data["schedule"])
