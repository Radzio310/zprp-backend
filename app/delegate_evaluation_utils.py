import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

MIN_SEASON_START = 2025

#: Punkty za literę oceny - WIĘCEJ ZNACZY LEPIEJ.
#:
#: Skalę arkusza delegata opisuje legenda w `components/RefereeEvaluationModal.tsx`:
#: „A - niedopuszczalnie", „D - prawidłowo", „G - wybitnie". Do 15.09.2026 ta mapa
#: przyznawała literze A siedem punktów, czyli NAJWIĘCEJ ocenie NAJGORSZEJ. Średnie
#: wychodziły przez to odwrócone: para z samymi „A" miała 7,00 i wyświetlała się
#: jako wybitna, a `best` wskazywał najsłabszą ocenę w zestawieniu.
GRADE_POINTS = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7}

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


def new_bucket(**identity: Any) -> Dict[str, Any]:
    """Pusty worek na oceny - taki sam dla pojedynczego sędziego i dla pary."""
    return {
        **identity,
        "evaluations": 0,
        "sections": defaultdict(list),
        "section_details": {},
    }


def absorb_evaluation(bucket: Dict[str, Any], evaluation: Dict[str, Any], scores: Dict[str, List[int]]) -> None:
    """Dokłada jeden arkusz do worka.

    PARA I OSOBA LICZĄ SIĘ TAK SAMO. Wcześniej rozpisanie na kryteria
    (`section_details`) powstawało wyłącznie dla osoby, więc ekran pary musiał
    i tak sięgać po dane jednego sędziego - a delegat ocenia PARĘ i ta sama
    litera dotyczy obojga.
    """
    bucket["evaluations"] += 1
    for key, values in scores.items():
        bucket["sections"][key].extend(values)
    for section in evaluation.get("sections") or []:
        key = str(section.get("key") or section.get("title") or "Inne").strip()
        detail = bucket["section_details"].setdefault(
            key, {"title": section.get("title") or key, "grades": [], "parameters": {}}
        )
        main = GRADE_POINTS.get(str(section.get("mainGrade") or "").strip().upper())
        if main is not None:
            detail["grades"].append(main)
        for item in section.get("items") or []:
            item_title = str(item.get("title") or "Parametr").strip()
            point = GRADE_POINTS.get(str(item.get("grade") or "").strip().upper())
            if point is not None:
                detail["parameters"].setdefault(item_title, []).append(point)


def summary_of(values: List[int]) -> Dict[str, Any]:
    return {
        "average": round(sum(values) / len(values), 2),
        "best": max(values),
        "worst": min(values),
        "samples": len(values),
    }


def finalize_bucket(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """Worek zamieniony w gotowe liczby."""
    sections = {
        key: summary_of(values)
        for key, values in bucket["sections"].items()
        if values
    }
    details = {}
    for key, detail in bucket["section_details"].items():
        parameters = [
            {"title": title, **summary_of(values)}
            for title, values in detail["parameters"].items()
            if values
        ]
        parameters.sort(key=lambda item: item["title"])
        details[key] = {"title": detail["title"], "parameters": parameters}
    all_values = [value for values in bucket["sections"].values() for value in values]
    return {
        **bucket,
        "sections": sections,
        "section_details": details,
        "average": round(sum(all_values) / len(all_values), 2) if all_values else None,
        "best": max(all_values) if all_values else None,
        "worst": min(all_values) if all_values else None,
        "grades": grade_distribution(all_values),
    }


def grade_distribution(points: List[int]) -> Dict[str, int]:
    """Ile razy padła każda litera - w tym te, które nie padły ani razu.

    Liczymy DOKŁADNIE te punkty, z których powstała średnia (ocena sekcji plus
    każde kryterium), żeby rozkład i średnia nie mówiły o dwóch różnych
    zbiorach. Litery bez ani jednego trafienia zostają z zerem: pusta kolumna
    w skali też jest informacją, a brak klucza kazałby ekranowi zgadywać.
    """
    counts = Counter(points)
    return {letter: counts.get(point, 0) for letter, point in GRADE_POINTS.items()}


def pair_names(ids: List[str], names: List[Any]) -> List[str]:
    """Nazwiska pary W KOLEJNOŚCI ALFABETYCZNEJ.

    Kolejność z arkusza stawiałaby jednego sędziego zawsze pierwszego, a para
    jest równorzędna - nie ma w niej sędziego głównego i pomocniczego.
    """
    paired = []
    for index, judge_id in enumerate(ids):
        label = str(names[index]).strip() if index < len(names) else ""
        paired.append(label or str(judge_id))
    return sorted(paired, key=lambda value: value.casefold())


# ---------------------------------------------------------------------------
# Dostęp
# ---------------------------------------------------------------------------

#: Uprawnienie konta VIP (panel admina BAZY -> `baza_vips.permissions_json`).
VIP_PERMISSION = "delegate_evaluations"

#: Wołający z BAZA_web. Tam logują się też konta VIP okręgów, więc oceny okręgu
#: widzą WYŁĄCZNIE admin i VIP z uprawnieniem - decyzja użytkownika z 16.09.2026.
#: Dostęp nadany sędziemu w panelu admina działa dalej, ale tylko w aplikacji BAZA.
WEB_SURFACE = "web"

NO_ACCESS_VIP_PROVINCE = "Konto VIP ma ustawione inne województwo niż to okręgu"
NO_ACCESS_VIP_PERMISSION = "Konto VIP nie ma uprawnienia „Oceny delegatów”"
NO_ACCESS_WEB_JUDGE = "W BAZA_web oceny okręgu widzą tylko admin i konta VIP z uprawnieniem „Oceny delegatów”"
NO_ACCESS_GRANT = "Administrator nie nadał dostępu do ocen tego okręgu"


def vip_permissions(raw: Any) -> Dict[str, Any]:
    """`permissions_json` jako słownik - kolumna JSONB potrafi wrócić napisem."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return dict(raw) if isinstance(raw, dict) else {}


def vip_sees_evaluations(permissions: Any) -> bool:
    """VIP z „admin" ma wszystko, pozostali tylko z osobnym uprawnieniem."""
    perms = vip_permissions(permissions)
    return bool(perms.get("admin") or perms.get(VIP_PERMISSION))


def resolve_access(
    *,
    surface: str = "",
    is_org: bool,
    is_admin: bool = False,
    same_province: bool = False,
    permissions: Any = None,
    grant: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Kto widzi statystyki (`stats`) i pełne arkusze (`full`) jednego okręgu.

    Konto VIP: własne województwo ORAZ uprawnienie - samo województwo nie
    wystarcza (do 16.09.2026 wystarczało i oceny widział np. VIP od samych
    niedyspozycji). Sędzia: admin wszędzie; nadany dostęp tylko poza BAZA_web.
    Każda odmowa mówi, czego brakuje (`reason`).
    """
    if is_org:
        allowed = same_province and vip_sees_evaluations(permissions)
        reason = "" if allowed else (NO_ACCESS_VIP_PROVINCE if not same_province else NO_ACCESS_VIP_PERMISSION)
        return {"stats": allowed, "full": allowed, "admin": False, "commission": allowed, "reason": reason}
    if is_admin:
        return {"stats": True, "full": True, "admin": True, "reason": ""}
    if surface == WEB_SURFACE:
        return {"stats": False, "full": False, "admin": False, "reason": NO_ACCESS_WEB_JUDGE}
    stats = bool(grant and grant.get("can_view_stats"))
    full = bool(grant and grant.get("can_view_full"))
    return {"stats": stats, "full": full, "admin": False, "reason": "" if stats else NO_ACCESS_GRANT}
