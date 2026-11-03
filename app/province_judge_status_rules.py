"""
Status „sędzia nieaktywny w okręgu” - reguły bez bazy i bez sieci.

Decyzje właściciela z 03.11.2026: status jest trwały do odwołania, jeden na
serwerze dla BAZA, BAZA_web i backendu; oznacza admin (wszędzie) albo posiadacz
odznaki „Komisja sędziowska” dla SWOJEGO województwa. Okręgi porównujemy
odpornie na ogonki (`settlement_province.canonical`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from app.official_roster import DOLNOSLASKIE_2026_27, DOLNOSLASKIE_2026_27_ALIASES, SLASKIE_2026_27, person_key
from app.settlement_province import canonical

MAX_IDS = 500
NOTE_MAX = 500
SEED_SOURCE = "seed"
SEED_NOTE = "Stan początkowy: lista aktywnych okręgu 2026/27 (baza.zprp.pl)"
#: Okręg -> lista aktywnych, z której powstaje stan początkowy.
SEED_ACTIVE: Dict[str, Tuple[str, ...]] = {
    "SLASKIE": SLASKIE_2026_27,
    "DOLNOSLASKIE": DOLNOSLASKIE_2026_27 + DOLNOSLASKIE_2026_27_ALIASES,
}


class Invalid(ValueError):
    pass


def province_key(value: Any) -> str:
    return canonical(value)


def may_manage(*, is_admin: bool, has_committee_badge: bool, own_province: Any, province: Any) -> bool:
    """Admin wszędzie, komisja sędziowska tylko we własnym okręgu."""
    if is_admin:
        return True
    own, target = province_key(own_province), province_key(province)
    return bool(has_committee_badge and own and own == target)


def clean_ids(raw: Any) -> List[str]:
    if not isinstance(raw, (list, tuple)):
        raise Invalid("judge_ids musi być listą numerów sędziów")
    out: List[str] = []
    for item in raw:
        text = str(item if item is not None else "").strip()
        if text and text not in out:
            out.append(text)
    if not out:
        raise Invalid("Zaznacz przynajmniej jednego sędziego")
    if len(out) > MAX_IDS:
        raise Invalid(f"Za dużo osób naraz (najwyżej {MAX_IDS})")
    return out


def clean_note(raw: Any) -> Optional[str]:
    text = str(raw if raw is not None else "").strip()
    return text[:NOTE_MAX] or None


def plan_seed(
    judges: Iterable[Mapping[str, Any]], active_names: Iterable[str]
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Kogo oznaczyć jako nieaktywnych i które nazwiska z listy nie trafiły na nikogo.

    `judges`: sędziowie okręgu z rejestru (`judge_id`, `full_name`).
    """
    active = {person_key(name): name for name in active_names}
    seen: set = set()
    inactive: List[Dict[str, str]] = []
    for judge in judges:
        jid = str(judge.get("judge_id") or "").strip()
        name = str(judge.get("full_name") or "").strip()
        if not jid:
            continue
        key = person_key(name)
        if key in active:
            seen.add(key)
        else:
            inactive.append({"judge_id": jid, "name": name})
    unmatched = sorted(name for key, name in active.items() if key not in seen)
    return inactive, unmatched


def _iso(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value or "")


def item(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "judge_id": str(row.get("judge_id") or ""),
        "name": str(row.get("name") or ""),
        "since": _iso(row.get("since")),
        "by": (str(row.get("by_name") or "").strip() or None),
        "note": (str(row.get("note") or "").strip() or None),
    }
