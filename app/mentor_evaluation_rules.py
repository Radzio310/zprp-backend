"""
Reguły ocen mentora - LIŚĆ bez bazy (testowalny bez połączenia).

KTO OCENIA (decyzje użytkownika z 29.09.2026):
  1. mentor z programu Mentoring - każdy mecz swojej pary, także z podglądu
     (nie musi być w obsadzie),
  2. mentor z pary mentorskiej okręgu (Obsada w BAZA_web) - tylko mecz, w
     którym sam jest w obsadzie (stolik),
  3. NIGDY delegat tego meczu - jego ocena to arkusz ZPRP, druga byłaby
     dublem; i nigdy nikt z ocenianej pary.

KTO WIDZI OPUBLIKOWANĄ: oceniana para, autorzy i współmentorzy pary, komisja
i admin (przez dostęp do ocen okręgu). Szkic widzą wyłącznie autorzy.

Skala jak u delegata: A = 1 … G = 7, ND nie liczy się do średniej, a ocena
ogólna to średnia liter DZIESIĘCIU sekcji.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

GRADES = ("A", "B", "C", "D", "E", "F", "G")
GRADE_OPTIONS = set(GRADES) | {"ND"}
SECTION_KEYS = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X")
YES_NO = {"Tak", "Nie", "ND"}
DIFFICULTIES = {"Bardzo trudny", "Trudny", "Średni", "Normalny", "Łatwy", "Negatywny wpływ sędziów"}
SITUATION_CATEGORIES = {"dobra", "bledna", "analiza", "protest", "wynik"}
MAX_SITUATIONS = 5
MAX_PRIORITIES = 3
MAX_TEXT = 4000
MAX_LABEL = 300
MAX_ITEMS = 12
MAX_CRITERIA = 12

#: Pola obsady w stanie meczu ZPRP.
REFEREE_FIELDS = ("NrSedzia_pierwszy", "NrSedzia_drugi")
TABLE_FIELDS = ("NrSedzia_sekretarz", "NrSedzia_czas")
DELEGATE_FIELDS = ("NrSedzia_delegat", "NrSedzia_delegat2")

NOT_A_PAIR = "Mecz nie ma jeszcze obsadzonej pary sędziów - nie ma kogo ocenić."
OWN_PAIR = "To Twoja para - własnego meczu nie oceniasz."
DELEGATE = "Jesteś delegatem tego meczu - Twoja ocena to arkusz delegata w ZPRP."
OBSADA_NOT_IN_CREW = "Para mentorska okręgu ocenia mecze swojej pary, w których jest w obsadzie."
NOT_A_MENTOR = "Nie jesteś mentorem tej pary."


def _s(value: Any) -> str:
    return str(value or "").strip()


def json_list(value: Any) -> List[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return []
    return [_s(v) for v in value if _s(v)] if isinstance(value, list) else []


def pair_of(state: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Para sędziów głównych po numerach - bez nazwisk (nieznana tożsamość nie daje dostępu)."""
    ids = [_s(state.get(field)) for field in REFEREE_FIELDS]
    if not all(ids) or ids[0] == ids[1]:
        return None
    a, b = sorted(ids)
    return a, b


def pair_key(pair: Iterable[str]) -> str:
    return "|".join(sorted(_s(v) for v in pair))


def crew_roles(state: Dict[str, Any], judge_id: str) -> Set[str]:
    judge_id = _s(judge_id)
    if not judge_id:
        return set()
    roles = set()
    for field in REFEREE_FIELDS:
        if _s(state.get(field)) == judge_id:
            roles.add("referee")
    for field in TABLE_FIELDS:
        if _s(state.get(field)) == judge_id:
            roles.add("table")
    for field in DELEGATE_FIELDS:
        if _s(state.get(field)) == judge_id:
            roles.add("delegate")
    return roles


def eligibility(
    *,
    actor_id: str,
    state: Dict[str, Any],
    mentoring_mentor: bool,
    obsada_mentor: bool,
) -> Dict[str, Any]:
    """Czy ten sędzia może wypełnić ocenę mentora tego meczu - z powodem odmowy."""
    pair = pair_of(state)
    if not pair:
        return {"can_rate": False, "source": None, "reason": NOT_A_PAIR}
    roles = crew_roles(state, actor_id)
    if "referee" in roles or _s(actor_id) in pair:
        return {"can_rate": False, "source": None, "reason": OWN_PAIR}
    if "delegate" in roles:
        return {"can_rate": False, "source": None, "reason": DELEGATE}
    if mentoring_mentor:
        return {"can_rate": True, "source": "mentoring", "reason": ""}
    if obsada_mentor:
        if "table" in roles:
            return {"can_rate": True, "source": "obsada", "reason": ""}
        return {"can_rate": False, "source": None, "reason": OBSADA_NOT_IN_CREW}
    return {"can_rate": False, "source": None, "reason": NOT_A_MENTOR}


def can_view_published(
    *,
    actor_id: str,
    pair: Iterable[str],
    authors: Iterable[str],
    is_pair_mentor: bool,
    province_access: bool,
) -> bool:
    actor_id = _s(actor_id)
    return (
        actor_id in {_s(v) for v in pair}
        or actor_id in {_s(v) for v in authors}
        or is_pair_mentor
        or province_access
    )


# ─── Arkusz ─────────────────────────────────────────────────────────────────


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return str(value or "")[:limit]


def _grade(value: Any) -> Optional[str]:
    g = _s(value).upper()
    return g if g in GRADE_OPTIONS else None


def clean_sheet(raw: Any) -> Dict[str, Any]:
    """Arkusz z telefonu przycięty do wzoru: nieznane litery i nadmiar pól odpadają."""
    raw = raw if isinstance(raw, dict) else {}
    sections_in = raw.get("sections") if isinstance(raw.get("sections"), dict) else {}
    sections: Dict[str, Any] = {}
    for key in SECTION_KEYS:
        sec = sections_in.get(key) if isinstance(sections_in.get(key), dict) else {}
        items_in = sec.get("items") if isinstance(sec.get("items"), dict) else {}
        items = {}
        for label, grade in list(items_in.items())[:MAX_ITEMS]:
            items[_text(label, MAX_LABEL)] = _grade(grade)
        sections[key] = {"main": _grade(sec.get("main")), "items": items, "comment": _text(sec.get("comment"))}
    character_in = raw.get("character") if isinstance(raw.get("character"), dict) else {}
    character = {}
    for label, value in list(character_in.items())[:MAX_CRITERIA]:
        v = _s(value)
        character[_text(label, MAX_LABEL)] = v if v in YES_NO else None
    situations = []
    for sit in (raw.get("situations") if isinstance(raw.get("situations"), list) else [])[:MAX_SITUATIONS]:
        if not isinstance(sit, dict):
            continue
        category = _s(sit.get("category"))
        situations.append(
            {
                "id": _text(sit.get("id"), 40),
                "time": _text(sit.get("time"), 8),
                "category": category if category in SITUATION_CATEGORIES else None,
                "description": _text(sit.get("description")),
            }
        )
    priorities_in = raw.get("priorities") if isinstance(raw.get("priorities"), list) else []
    priorities = [_text(p) for p in priorities_in[:MAX_PRIORITIES]]
    priorities += [""] * (MAX_PRIORITIES - len(priorities))
    difficulty = _s(raw.get("difficulty"))
    return {
        "difficulty": difficulty if difficulty in DIFFICULTIES else None,
        "character": character,
        "sections": sections,
        "situations": situations,
        "priorities": priorities,
    }


def sheet_points(sheet: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Średnia liter sekcji (A = 1 … G = 7) i najbliższa jej litera."""
    values = []
    for key in SECTION_KEYS:
        main = (sheet.get("sections") or {}).get(key, {}).get("main")
        if main in GRADES:
            values.append(GRADES.index(main) + 1)
    if not values:
        return None, None
    points = round(sum(values) / len(values), 4)
    # Połówka w górę, jak `Math.round` w aplikacji - `round()` Pythona robi
    # z 4,5 czwórkę (zaokrąglenie bankierskie) i litera rozjechałaby się z ekranem.
    letter = GRADES[max(1, min(7, int(points + 0.5))) - 1]
    return points, letter
