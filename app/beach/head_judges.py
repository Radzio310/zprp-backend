from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


MAX_HEAD_JUDGES = 5
MATCH_REFEREE_SLOTS = (
    "fieldA",
    "fieldB",
    "tableSecretary",
    "tableTimer",
    "headJudge",
)


def _as_positive_int(value: Any) -> Optional[int]:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def normalize_head_judge_ids(values: Iterable[Any]) -> List[int]:
    result: List[int] = []
    seen: set[int] = set()
    for value in values:
        parsed = _as_positive_int(value)
        if parsed is None or parsed in seen:
            continue
        seen.add(parsed)
        result.append(parsed)
        if len(result) >= MAX_HEAD_JUDGES:
            break
    return result


def head_judge_ids(data: Dict[str, Any]) -> List[int]:
    raw = data.get("head_judge_ids")
    values = raw if isinstance(raw, list) else []
    result = normalize_head_judge_ids(values)
    legacy = _as_positive_int(data.get("head_judge_id"))
    if legacy is not None and legacy not in result:
        result.insert(0, legacy)
    return result[:MAX_HEAD_JUDGES]


def default_head_judge_id(data: Dict[str, Any]) -> Optional[int]:
    ids = head_judge_ids(data)
    preferred = _as_positive_int(data.get("default_head_judge_id"))
    if preferred in ids:
        return preferred
    legacy = _as_positive_int(data.get("head_judge_id"))
    if legacy in ids:
        return legacy
    return ids[0] if ids else None


def is_head_judge(data: Dict[str, Any], user_id: Any) -> bool:
    parsed = _as_positive_int(user_id)
    return parsed is not None and parsed in head_judge_ids(data)


def sync_legacy_head_judge_fields(
    data: Dict[str, Any],
    *,
    ids: Optional[Iterable[Any]] = None,
    default_id: Any = None,
    default_was_provided: bool = False,
) -> tuple[List[int], Optional[int]]:
    normalized = (
        normalize_head_judge_ids(ids)
        if ids is not None
        else head_judge_ids(data)
    )
    if default_was_provided:
        preferred = _as_positive_int(default_id)
    else:
        preferred = default_head_judge_id(data)
    if preferred not in normalized:
        preferred = normalized[0] if normalized else None

    data["head_judge_ids"] = normalized
    data["default_head_judge_id"] = preferred
    # Compatibility for older clients and old backend paths. The legacy field
    # always mirrors the default (or first) head judge.
    data["head_judge_id"] = preferred
    return normalized, preferred


def _judge_name(data: Dict[str, Any], user_id: int) -> str:
    for judge in data.get("judges") or []:
        if not isinstance(judge, dict):
            continue
        judge_id = _as_positive_int(judge.get("id") or judge.get("user_id"))
        if judge_id == user_id:
            return str(
                judge.get("full_name")
                or judge.get("name")
                or f"Sędzia #{user_id}"
            )
    return f"Sędzia #{user_id}"


def referee_conflict_slots(
    referees: Any,
    *,
    candidate_id: Any,
    except_slot: Optional[str] = None,
) -> List[str]:
    parsed = _as_positive_int(candidate_id)
    if parsed is None or not isinstance(referees, dict):
        return []
    conflicts: List[str] = []
    for slot in MATCH_REFEREE_SLOTS:
        if slot == except_slot:
            continue
        ref = referees.get(slot)
        if isinstance(ref, dict) and _as_positive_int(ref.get("id")) == parsed:
            conflicts.append(slot)
    return conflicts


def validate_schedule_head_judges(
    data: Dict[str, Any],
    schedule: Any,
    *,
    protected_match_keys: Optional[set[str]] = None,
) -> None:
    if not isinstance(schedule, dict):
        return
    allowed = set(head_judge_ids(data))
    for match in schedule.get("matches") or []:
        if not isinstance(match, dict):
            continue
        is_protected = bool(
            protected_match_keys
            and (
                str(match.get("id") or "") in protected_match_keys
                or str(match.get("matchNumber") or "") in protected_match_keys
            )
        )
        refs = match.get("referees")
        if not isinstance(refs, dict):
            continue
        seen: Dict[int, str] = {}
        for slot in MATCH_REFEREE_SLOTS:
            ref = refs.get(slot)
            if not isinstance(ref, dict):
                continue
            ref_id = _as_positive_int(ref.get("id"))
            if ref_id is None:
                continue
            if ref_id in seen:
                raise ValueError(
                    f"{ref.get('name') or 'Sędzia'} nie może pełnić dwóch ról "
                    f"w tym samym meczu ({seen[ref_id]} i {slot})."
                )
            seen[ref_id] = slot
            if (
                slot == "headJudge"
                and ref_id not in allowed
                and match.get("status") == "scheduled"
                and not is_protected
            ):
                raise ValueError(
                    "Sędzią głównym meczu może być wyłącznie jeden z sędziów "
                    "głównych tego turnieju."
                )


def apply_default_head_judge_to_schedule(
    data: Dict[str, Any],
    *,
    update_existing_auto: bool = True,
    protected_match_keys: Optional[set[str]] = None,
) -> Dict[str, int]:
    schedule = data.get("schedule")
    if not isinstance(schedule, dict):
        return {"assigned": 0, "updated": 0, "cleared": 0, "skipped": 0}

    default_id = default_head_judge_id(data)
    default_ref = (
        {"id": default_id, "name": _judge_name(data, default_id)}
        if default_id is not None
        else None
    )
    stats = {"assigned": 0, "updated": 0, "cleared": 0, "skipped": 0}
    allowed = set(head_judge_ids(data))

    for match in schedule.get("matches") or []:
        if not isinstance(match, dict) or match.get("status") != "scheduled":
            continue
        if protected_match_keys and (
            str(match.get("id") or "") in protected_match_keys
            or str(match.get("matchNumber") or "") in protected_match_keys
        ):
            continue
        refs = match.get("referees")
        refs = dict(refs) if isinstance(refs, dict) else {}
        current = refs.get("headJudge")
        source = refs.get("headJudgeSource")
        current_id = (
            _as_positive_int(current.get("id"))
            if isinstance(current, dict)
            else None
        )
        if current_id is not None and current_id not in allowed:
            refs.pop("headJudge", None)
            refs.pop("headJudgeSource", None)
            current = None
            source = None
            stats["cleared"] += 1

        # A manually selected person or a consciously empty slot is immutable
        # under changes of the tournament default.
        if source == "manual":
            continue
        if current and source != "default":
            continue
        if current and not update_existing_auto:
            continue

        if default_ref is None:
            if current and source == "default":
                refs.pop("headJudge", None)
                refs.pop("headJudgeSource", None)
                match["referees"] = refs
                stats["cleared"] += 1
            continue

        if referee_conflict_slots(
            refs,
            candidate_id=default_id,
            except_slot="headJudge",
        ):
            if current and source == "default":
                refs.pop("headJudge", None)
                refs.pop("headJudgeSource", None)
                match["referees"] = refs
                stats["cleared"] += 1
            stats["skipped"] += 1
            continue

        if isinstance(current, dict) and _as_positive_int(current.get("id")) == default_id:
            refs["headJudgeSource"] = "default"
            match["referees"] = refs
            continue
        refs["headJudge"] = dict(default_ref)
        refs["headJudgeSource"] = "default"
        match["referees"] = refs
        if current:
            stats["updated"] += 1
        else:
            stats["assigned"] += 1

    validate_schedule_head_judges(
        data,
        schedule,
        protected_match_keys=protected_match_keys,
    )
    return stats
