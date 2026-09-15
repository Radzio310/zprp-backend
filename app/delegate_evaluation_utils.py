import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional

MIN_SEASON_START = 2025
GRADE_POINTS = {"A": 7, "B": 6, "C": 5, "D": 4, "E": 3, "F": 2, "G": 1}

def season_start(value: Any) -> Optional[int]:
    match = re.search(r"(20\d{2})\s*[/_-]", str(value or ""))
    return int(match.group(1)) if match else None

def allowed_season(value: Any) -> bool:
    start = season_start(value)
    return start is not None and start >= MIN_SEASON_START

def canonical_hash(value: Any) -> str:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()

def safe_source_fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()

def grade_values(evaluation: Dict[str, Any]) -> Dict[str, List[int]]:
    values: Dict[str, List[int]] = defaultdict(list)
    for section in evaluation.get("sections") or []:
        key = str(section.get("key") or section.get("title") or "Inne").strip()
        grades = [section.get("mainGrade")]
        grades.extend(item.get("grade") for item in section.get("items") or [])
        for grade in grades:
            point = GRADE_POINTS.get(str(grade or "").strip().upper())
            if point is not None:
                values[key].append(point)
    return dict(values)
