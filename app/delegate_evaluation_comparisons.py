"""Per-form comparison metrics for delegate and mentor evaluation sheets.

The module is deliberately database-free.  API code supplies the rows visible in
each scope; this module only normalises parameter labels and calculates deltas.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from typing import Any, Dict, Iterable, List

from app.delegate_evaluation_utils import GRADE_POINTS

MIN_REFERENCE_SHEETS = 3


def parameter_key(value: Any) -> str:
    text = str(value or "").strip().casefold().translate(str.maketrans({"ł": "l", "đ": "d"}))
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def _evaluation(row: Dict[str, Any]) -> Dict[str, Any]:
    value = row.get("evaluation_json") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            value = {}
    return value if isinstance(value, dict) else {}


def _point(value: Any) -> float | None:
    point = GRADE_POINTS.get(str(value or "").strip().upper())
    return float(point) if point is not None else None


def metrics(row: Dict[str, Any]) -> Dict[str, Any]:
    overall: List[float] = []
    sections: Dict[str, List[float]] = defaultdict(list)
    parameters: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for section in _evaluation(row).get("sections") or []:
        section_key = str(section.get("key") or section.get("title") or "Inne").strip()
        main = _point(section.get("mainGrade"))
        if main is not None:
            overall.append(main)
            sections[section_key].append(main)
        for item in section.get("items") or []:
            point = _point(item.get("grade"))
            key = parameter_key(item.get("title"))
            if point is None or not key:
                continue
            overall.append(point)
            sections[section_key].append(point)
            parameters[section_key][key].append(point)
    return {
        "overall": overall,
        "sections": dict(sections),
        "parameters": {key: dict(value) for key, value in parameters.items()},
    }


def _mean(values: Iterable[float]) -> float | None:
    values = list(values)
    return round(sum(values) / len(values), 2) if values else None


def _stat(current: List[float], reference: List[List[float]]) -> Dict[str, Any]:
    sheets = [values for values in reference if values]
    current_average = _mean(current)
    reference_average = _mean(value for values in sheets for value in values)
    available = len(sheets) >= MIN_REFERENCE_SHEETS and current_average is not None and reference_average is not None
    return {
        "average": reference_average if available else None,
        "delta": round(current_average - reference_average, 2) if available else None,
        "samples": len(sheets),
        "available": available,
    }


def _row_id(row: Dict[str, Any]) -> str:
    return str(row.get("id") or "")


def _pair(row: Dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted(str(value).strip() for value in row.get("referee_ids") or [] if str(value).strip()))


def _kind(row: Dict[str, Any]) -> str:
    return "mentor" if row.get("kind") == "mentor" or row.get("source_kind") == "mentor" else "delegate"


def _cached_metrics(row: Dict[str, Any], cache: Dict[str, Dict[str, Any]] | None) -> Dict[str, Any]:
    if cache is None:
        return metrics(row)
    key = f"{_kind(row)}:{_row_id(row) or id(row)}"
    if key not in cache:
        cache[key] = metrics(row)
    return cache[key]


def _scope_metrics(
    target: Dict[str, Any],
    candidates: Iterable[Dict[str, Any]],
    cache: Dict[str, Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    current = _cached_metrics(target, cache)
    refs = [_cached_metrics(row, cache) for row in candidates if _row_id(row) != _row_id(target)]
    section_keys = set(current["sections"])
    parameter_keys = {
        (section, key)
        for section, values in current["parameters"].items()
        for key in values
    }
    return {
        "overall": _stat(current["overall"], [item["overall"] for item in refs]),
        "sections": {
            key: _stat(current["sections"].get(key, []), [item["sections"].get(key, []) for item in refs])
            for key in section_keys
        },
        "parameters": {
            section: {
                key: _stat(
                    current["parameters"].get(section, {}).get(key, []),
                    [item["parameters"].get(section, {}).get(key, []) for item in refs],
                )
                for sec, key in parameter_keys
                if sec == section
            }
            for section in {sec for sec, _ in parameter_keys}
        },
    }


def comparisons_for_form(
    target: Dict[str, Any],
    *,
    pair_rows: Iterable[Dict[str, Any]],
    district_rows: Iterable[Dict[str, Any]] | None = None,
    national_rows: Iterable[Dict[str, Any]] | None = None,
    include_combined: bool = False,
    metric_cache: Dict[str, Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Return like-for-like and optionally combined comparisons for one form."""
    pair = _pair(target)
    kind = _kind(target)
    scopes = {
        "pair": [row for row in pair_rows if _pair(row) == pair],
    }
    if district_rows is not None:
        scopes["district"] = list(district_rows)
    if national_rows is not None:
        scopes["national"] = list(national_rows)

    def build(same_kind: bool) -> Dict[str, Any]:
        return {
            scope: _scope_metrics(
                target,
                [row for row in rows if not same_kind or _kind(row) == kind],
                metric_cache,
            )
            for scope, rows in scopes.items()
        }

    result = {"same_kind": build(True), "minimum_samples": MIN_REFERENCE_SHEETS}
    if include_combined:
        result["combined"] = build(False)
    return result
