"""
Egzamin z przepisów - reguły bez bazy i bez sieci (etap 1, 16.10.2026).

Plan i decyzje właściciela: BAZA/docs/egzamin-z-przepisow-plan.md.

Wszystko, co rozstrzyga o wyniku, leży tutaj i da się przetestować bez Postgresa:
  - uprawnienia (krajowy = admin, okręgowy = admin / komisja / Teach Master),
  - czyszczenie konfiguracji egzaminu i szablony,
  - pula pytań, zestaw wspólny albo losowany, mieszanie odpowiedzi,
  - maszyna sesji: pytanie po pytaniu, cofanie, czas liczony przez serwer,
    bufor odpowiedzi ze stemplem klienta (z tolerancją i flagami),
  - ocena (wszystko albo nic / częściowa), unieważnienie pytania,
  - polityka wyniku i przeglądu,
  - wskaźnik rzetelności 0-100 z rozpisaniem (nic nie dyskwalifikuje),
  - podobieństwo par, statystyki pytań, przypomnienia push.

Zasada: ZERO CICHYCH BLOKAD. Każda odmowa to `ExamError` z kodem i zdaniem
po polsku, które mówi, co się stało i co z tym zrobić.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.board_rules import has_committee_badge
from app.province_event_rules import local_label, same_province


class ExamError(Exception):
    """Błąd z kodem dla aplikacji i polskim zdaniem dla człowieka."""

    def __init__(self, code: str, message: str, status: int = 400, extra: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.extra = extra or {}


# ---------------------------------------------------------------------------
# Stałe
# ---------------------------------------------------------------------------

#: Zapas na opóźnienie sieci przy odpowiedzi na pytanie z limitem czasu.
GRACE_S = 3.0
#: Dopuszczalna rozbieżność zegara telefonu względem serwera.
CLOCK_TOL_S = 5.0
#: Odpowiedź z bufora, która leżała w telefonie dłużej, dostaje flagę.
BUFFER_SUSPICIOUS_S = 60.0
#: Stempel starszy od odbioru o więcej niż tyle sekund to odpowiedź „z bufora": bez
#: deklaracji `buffered` serwer liczy czas odpowiedzi od odbioru, nie od stempla.
BUFFER_CLAIM_S = 5.0
#: Ile po terminie podejścia (i po końcu okna egzaminu) serwer jeszcze przyjmuje paczkę
#: z bufora, jeśli telefon był poza zasięgiem albo aplikację zabito.
BUFFER_ACCEPT_WINDOW_S = 6 * 3600.0
#: Tyle słów na sekundę ktoś jeszcze potrafi przeczytać (poniżej = flaga).
FAST_READ_WPS = 8.0
FAST_READ_MIN_S = 1.0
#: Kod sali zmienia się co tyle sekund; przyjmujemy bieżący i poprzedni.
ROOM_CODE_STEP_S = 30

NAME_MAX = 200
DESCRIPTION_MAX = 4000
MAX_QUESTIONS = 100
MAX_ATTEMPTS = 10
MAX_TOTAL_MIN = 480
MAX_PER_QUESTION_S = 600
MAX_REMINDERS = 6

SCOPES = ("national", "province")
SET_MODES = ("shared", "drawn")
MULTI_SCORING = ("all_or_nothing", "partial")
RESULT_RELEASE = ("immediate", "after_close")
RETAKE = ("any", "only_failed")
LEAVE_POLICIES = ("log", "warn", "void_question", "end")
DIFFICULTY = ("any", "hard", "easy")
QUESTION_KINDS = ("wiedza", "scenariusz")
VOID_MODES = ("drop", "credit")

#: Zdarzenia, które może zgłosić telefon. Resztę (czas, urządzenie) zapisuje serwer.
CLIENT_EVENT_KINDS = ("app_background", "screenshot", "resume")
EVENT_KINDS = CLIENT_EVENT_KINDS + ("time_flag", "device_change", "similarity", "room_code")

#: Pole konfiguracji, którego nie wolno zmieniać, gdy ktoś już zaczął egzamin.
LOCKED_AFTER_START = (
    "scope", "question_count", "set_mode", "shuffle_answers", "shuffle_questions", "allow_back",
    "time_per_question_s", "time_total_min", "multi_scoring", "pass_percent", "max_attempts", "retake",
    "result_release", "anti", "single_hint_all", "single_hint_ids",
)

CURIOSITIES: Dict[str, str] = {
    "6.24": (
        "Ciekawostka: według Wytycznych do 8:8i (przypadek b) zawodnik z pola, który łapie piłkę "
        "w powietrzu i ląduje z nią w polu bramkowym, powinien dostać rzut karny dla przeciwnika "
        "i bezpośrednie 2-minutowe wykluczenie - por. pytanie 14.24. Klucz z katalogu ZPRP "
        "(kara progresywna) zostaje bez zmian, bo pytania są 1:1 z wydaniem Kolegium Sędziów."
    ),
}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def parse_time(value: Any, label: str = "data") -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return _aware(value)
    try:
        return _aware(datetime.fromisoformat(_s(value).replace("Z", "+00:00")))
    except ValueError as error:
        raise ExamError("BAD_DATE", f"Niepoprawna {label}: {value!r}") from error


def number_key(number: Any) -> Tuple[int, int]:
    """„6.24" -> (6, 24); do sortowania numerów pytań po ludzku."""
    match = re.match(r"^\s*(\d+)\.(\d+)", _s(number))
    return (int(match.group(1)), int(match.group(2))) if match else (9999, 9999)


# ---------------------------------------------------------------------------
# Uprawnienia
# ---------------------------------------------------------------------------


def manage_refusal(
    *,
    scope: str,
    province: Any,
    is_admin: bool,
    own_province: Any,
    badges: Any,
    is_teach_master: bool,
) -> Optional[str]:
    """None = wolno. Inaczej zdanie dla człowieka (nigdy cicha odmowa).

    Krajowy: tylko admin. Okręgowy: admin, komisja TEGO okręgu (`can_manage`)
    albo Teach Master tego okręgu - jedna funkcja łączy wszystkie trzy drogi.
    """
    if is_admin:
        return None
    if scope == "national":
        return "Egzaminy ogólnopolskie tworzy i zmienia tylko administrator aplikacji."
    if has_committee_badge(badges) and same_province(own_province, province):
        return None
    if is_teach_master:
        return None
    where = f" okręgu {province}" if _s(province) else " okręgu"
    return (
        f"Egzaminami{where} zarządza komisja sędziowska tego okręgu, Teach Master okręgu albo administrator. "
        "O nadanie uprawnień poproś administratora aplikacji."
    )


def require_manage(**kwargs: Any) -> None:
    reason = manage_refusal(**kwargs)
    if reason:
        raise ExamError("EXAM_FORBIDDEN", reason, 403)


# ---------------------------------------------------------------------------
# Konfiguracja i szablony
# ---------------------------------------------------------------------------

#: Progi rzetelności (ustala komisja; zmiana przelicza wskaźnik także po starcie egzaminu).
#: Klucz = rodzaj zdarzenia albo flaga czasu. `penalties` = kara za jedno zdarzenie,
#: `max_events` = ile zdarzeń liczy się do kary (górny limit grupy = kara x max_events).
DEFAULT_INTEGRITY: Dict[str, Any] = {
    "penalties": {
        "app_background": 4, "screenshot": 10, "too_fast": 3, "buffered_late": 4, "buffered_over_limit": 6,
        "stamp_ignored": 3, "future_stamp": 4, "before_shown": 4, "device_change": 25, "similarity": 15,
    },
    "max_events": {
        "app_background": 7, "screenshot": 3, "too_fast": 7, "buffered_late": 3, "buffered_over_limit": 3,
        "stamp_ignored": 3, "future_stamp": 3, "before_shown": 3, "device_change": 1, "similarity": 2,
    },
    "long_absence_s": 30,
    "long_absence_extra": 4,
    "ok_min": 80,
    "warning_min": 50,
    "similarity_min_common": 3,
    "similarity_close_s": 30,
    "similarity_close_min": 2,
}

DEFAULT_ANTI: Dict[str, Any] = {
    "leave_app": "log",
    "screenshots": False,
    "speed_flags": False,
    "similarity": False,
    "single_device": False,
    "room_code": False,
    "integrity": copy.deepcopy(DEFAULT_INTEGRITY),
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "scope": {"rules": [], "topics": [], "kinds": [], "manual_ids": [], "difficulty": "any"},
    "question_count": 20,
    "set_mode": "shared",
    "shuffle_answers": True,
    "shuffle_questions": False,
    "allow_back": False,
    "time_per_question_s": None,
    "time_total_min": None,
    "window_start": None,
    "window_end": None,
    "max_attempts": 1,
    "retake": "any",
    "pass_percent": 75.0,
    "multi_scoring": "all_or_nothing",
    #: Podpowiedź „jedna odpowiedź jest poprawna" (decyzja 24.10.2026: domyślnie WYŁĄCZONA).
    #: Bez niej każde pytanie pozwala zaznaczyć kilka odpowiedzi - zdający nie wie, ile jest poprawnych.
    "single_hint_all": False,
    "single_hint_ids": [],
    "result_release": "after_close",
    "mandatory": False,
    "target": {"include_all": False, "include_badges": [], "exclude_badges": []},
    "include_ids": [],
    "exclude_ids": [],
    "reminders_hours": [24],
    "results_push": True,
    "anti": copy.deepcopy(DEFAULT_ANTI),
}

#: Odznaki okręgu wyłączane z „Egzaminu 25" i „Egzaminu 15". Nazwy 1:1 jak w
#: automacie obsad (`app/assignment_people.BADGE_LEAGUE` / `BADGE_DELEGATE`) -
#: `invited_ids` porównuje odznaki dokładnie, bez zwijania wielkości liter.
#: Stała wpisana tutaj, a nie importowana: moduł reguł egzaminu zostaje liściem.
TEMPLATE_EXCLUDED_BADGES = ["Ligowcy", "Delegaci"]

_TEMPLATE_BASE: Dict[str, Any] = {
    # Pełna pula pytań (pusty zakres = wszystkie 432), jeden zestaw, 100 s na pytanie.
    "scope": {"rules": [], "topics": [], "kinds": [], "manual_ids": [], "difficulty": "any"},
    "set_mode": "shared", "shuffle_answers": True, "shuffle_questions": False, "allow_back": False,
    "time_per_question_s": 100, "time_total_min": None, "max_attempts": 1, "retake": "any",
    "pass_percent": 75, "result_release": "after_close", "mandatory": True,
    "include_ids": [], "exclude_ids": [], "reminders_hours": [72, 24, 2], "results_push": True,
    "anti": {"leave_app": "warn", "screenshots": True, "speed_flags": True, "similarity": True,
             "single_device": True, "room_code": False},
}


def _template(count: int, exclude_badges: List[str]) -> Dict[str, Any]:
    config = copy.deepcopy(_TEMPLATE_BASE)
    config["question_count"] = count
    config["target"] = {"include_all": True, "include_badges": [], "exclude_badges": list(exclude_badges)}
    return config


# Decyzja właściciela 17.10.2026: trzy druki, okno 7 dni, próg 75%, wynik po
# zamknięciu okna. „Egzamin 30" obowiązkowy dla wszystkich; 25 i 15 dla
# wszystkich oprócz odznak „Ligowcy" i „Delegaci".
TEMPLATES: Dict[str, Dict[str, Any]] = {
    "exam25": {"label": "Egzamin 25", "window_days": 7, "config": _template(25, TEMPLATE_EXCLUDED_BADGES)},
    "exam30": {"label": "Egzamin 30", "window_days": 7, "config": _template(30, [])},
    "exam15": {"label": "Egzamin 15", "window_days": 7, "config": _template(15, TEMPLATE_EXCLUDED_BADGES)},
}


def templates_view() -> List[Dict[str, Any]]:
    out = []
    for key, tpl in TEMPLATES.items():
        out.append({"key": key, "label": tpl["label"], "window_days": tpl["window_days"], "config": template_config(key)})
    return out


def template_config(key: Any) -> Dict[str, Any]:
    """Pełna konfiguracja szablonu (wartości domyślne + nadpisania szablonu)."""
    base = copy.deepcopy(DEFAULT_CONFIG)
    name = _s(key)
    if not name:
        return base
    if name not in TEMPLATES:
        raise ExamError("BAD_TEMPLATE", f"Nie znam szablonu „{name}”. Dostępne: {', '.join(TEMPLATES)}.")
    return _merge(base, TEMPLATES[name]["config"])


def _merge(base: Dict[str, Any], over: Mapping[str, Any]) -> Dict[str, Any]:
    for key, value in over.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), dict):
            base[key] = _merge(dict(base[key]), value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _int(value: Any, label: str, low: int, high: int, *, none_ok: bool = False) -> Optional[int]:
    if value is None or value == "":
        if none_ok:
            return None
        raise ExamError("BAD_CONFIG", f"Podaj pole: {label}.")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ExamError("BAD_CONFIG", f"{label}: to ma być liczba całkowita.") from error
    if number < low or number > high:
        raise ExamError("BAD_CONFIG", f"{label}: dozwolony zakres to {low}-{high}.")
    return number


def _choice(value: Any, allowed: Sequence[str], label: str) -> str:
    text = _s(value)
    if text not in allowed:
        raise ExamError("BAD_CONFIG", f"{label}: dozwolone wartości to {', '.join(allowed)}.")
    return text


def _strings(values: Any) -> List[str]:
    out: List[str] = []
    for value in values or []:
        text = _s(value)
        if text and text not in out:
            out.append(text)
    return out


def clean_integrity(raw: Any) -> Dict[str, Any]:
    """Progi rzetelności: braki z wartości domyślnych, zakresy sprawdzone, polskie komunikaty."""
    raw = raw if isinstance(raw, Mapping) else {}
    out: Dict[str, Any] = copy.deepcopy(DEFAULT_INTEGRITY)
    for group, label, low, high in (("penalties", "kara za zdarzenie", 0, 50), ("max_events", "limit zdarzeń w grupie", 1, 50)):
        given = raw.get(group) if isinstance(raw.get(group), Mapping) else {}
        for key in given:
            if key not in out[group]:
                raise ExamError("BAD_CONFIG", f"Progi rzetelności: nieznany rodzaj sygnału „{_s(key)}”.")
        for key in out[group]:
            if key in given:
                out[group][key] = _int(given[key], f"Progi rzetelności, {label} ({INTEGRITY_LABELS[key]})", low, high)
    for key, label, low, high in (
        ("long_absence_s", "długa nieobecność (sekundy)", 5, 600),
        ("long_absence_extra", "dopłata za długą nieobecność", 0, 20),
        ("ok_min", "dolna granica poziomu „w porządku”", 1, 100),
        ("warning_min", "dolna granica poziomu „uwaga”", 0, 99),
        ("similarity_min_common", "minimum wspólnych błędów", 2, 20),
        ("similarity_close_s", "okno bliskości odpowiedzi (sekundy)", 1, 600),
        ("similarity_close_min", "minimum bliskich w czasie błędów", 1, 20),
    ):
        if key in raw:
            out[key] = _int(raw[key], f"Progi rzetelności, {label}", low, high)
    if out["warning_min"] >= out["ok_min"]:
        raise ExamError("BAD_CONFIG", "Progi rzetelności: granica „uwaga” musi być niższa niż granica „w porządku”.")
    if out["similarity_close_min"] > out["similarity_min_common"]:
        raise ExamError("BAD_CONFIG", "Progi rzetelności: bliskich w czasie błędów nie może być więcej niż wspólnych.")
    return out


def clean_config(raw: Mapping[str, Any], *, template: Any = None) -> Dict[str, Any]:
    """Pełna, sprawdzona konfiguracja. Rzuca `ExamError` z polskim zdaniem."""
    merged = _merge(template_config(template), raw or {})
    scope_raw = merged.get("scope") if isinstance(merged.get("scope"), Mapping) else {}
    rules = []
    for item in scope_raw.get("rules") or []:
        rules.append(_int(item, "numer przepisu", 1, 99))
    kinds = _strings(scope_raw.get("kinds"))
    for kind in kinds:
        _choice(kind, QUESTION_KINDS, "rodzaj pytań")
    scope = {
        "rules": sorted(set(rules)),
        "topics": _strings(scope_raw.get("topics")),
        "kinds": kinds,
        "manual_ids": _strings(scope_raw.get("manual_ids")),
        "difficulty": _choice(scope_raw.get("difficulty") or "any", DIFFICULTY, "trudność"),
    }

    count = _int(merged.get("question_count"), "liczba pytań", 1, MAX_QUESTIONS)
    per_q = _int(merged.get("time_per_question_s"), "czas na pytanie (s)", 5, MAX_PER_QUESTION_S, none_ok=True)
    total = _int(merged.get("time_total_min"), "czas na całość (min)", 1, MAX_TOTAL_MIN, none_ok=True)
    allow_back = bool(merged.get("allow_back"))
    if allow_back and per_q:
        raise ExamError(
            "BAD_CONFIG",
            "Cofanie do poprzednich pytań nie łączy się z czasem na pytanie - wybierz jedno z dwóch.",
        )
    start = parse_time(merged.get("window_start"), "data otwarcia okna")
    end = parse_time(merged.get("window_end"), "data zamknięcia okna")
    if start is None or end is None:
        raise ExamError(
            "BAD_CONFIG",
            "Podaj okno egzaminu (od - do). Przegląd odpowiedzi otwiera się dopiero po zamknięciu okna.",
        )
    if end <= start:
        raise ExamError("BAD_CONFIG", "Okno egzaminu musi kończyć się po jego otwarciu.")

    max_attempts = _int(merged.get("max_attempts"), "liczba podejść", 1, MAX_ATTEMPTS)
    retake = _choice(merged.get("retake") or "any", RETAKE, "ponowne podejście")
    release = _choice(merged.get("result_release"), RESULT_RELEASE, "kiedy wynik")
    if retake == "only_failed" and release != "immediate":
        raise ExamError(
            "BAD_CONFIG",
            "Druga szansa tylko dla niezdanych wymaga wyniku od razu - inaczej zdający nie wie, czy mu przysługuje.",
        )
    try:
        pass_percent = float(merged.get("pass_percent"))
    except (TypeError, ValueError) as error:
        raise ExamError("BAD_CONFIG", "Próg zdania: podaj procent.") from error
    if not 0 <= pass_percent <= 100:
        raise ExamError("BAD_CONFIG", "Próg zdania: dozwolony zakres to 0-100%.")

    reminders = sorted({_int(h, "przypomnienie (godziny przed końcem)", 1, 24 * 60) for h in merged.get("reminders_hours") or []}, reverse=True)
    if len(reminders) > MAX_REMINDERS:
        raise ExamError("BAD_CONFIG", f"Najwyżej {MAX_REMINDERS} przypomnień na egzamin.")

    anti_raw = merged.get("anti") if isinstance(merged.get("anti"), Mapping) else {}
    anti = {
        "leave_app": _choice(anti_raw.get("leave_app") or "log", LEAVE_POLICIES, "wyjście z aplikacji"),
        "screenshots": bool(anti_raw.get("screenshots")),
        "speed_flags": bool(anti_raw.get("speed_flags")),
        "similarity": bool(anti_raw.get("similarity")),
        "single_device": bool(anti_raw.get("single_device")),
        "room_code": bool(anti_raw.get("room_code")),
        "integrity": clean_integrity(anti_raw.get("integrity")),
    }
    target_raw = merged.get("target") if isinstance(merged.get("target"), Mapping) else {}
    target = {
        "include_all": bool(target_raw.get("include_all")),
        "include_badges": _strings(target_raw.get("include_badges")),
        "exclude_badges": _strings(target_raw.get("exclude_badges")),
    }
    set_mode = _choice(merged.get("set_mode"), SET_MODES, "zestaw pytań")
    return {
        "scope": scope,
        "question_count": count,
        "set_mode": set_mode,
        "shuffle_answers": bool(merged.get("shuffle_answers")),
        "shuffle_questions": bool(merged.get("shuffle_questions")),
        "allow_back": allow_back,
        "time_per_question_s": per_q,
        "time_total_min": total,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "max_attempts": max_attempts,
        "retake": retake,
        "pass_percent": round(pass_percent, 2),
        "multi_scoring": _choice(merged.get("multi_scoring"), MULTI_SCORING, "punktacja wielokrotnego wyboru"),
        "single_hint_all": bool(merged.get("single_hint_all")),
        "single_hint_ids": _strings(merged.get("single_hint_ids")),
        "result_release": release,
        "mandatory": bool(merged.get("mandatory")),
        "target": target,
        "include_ids": _strings(merged.get("include_ids")),
        "exclude_ids": _strings(merged.get("exclude_ids")),
        "reminders_hours": reminders,
        "results_push": bool(merged.get("results_push")),
        "anti": anti,
    }


def clean_text(name: Any, description: Any) -> Tuple[str, Optional[str]]:
    title = " ".join(_s(name).split())
    if not title:
        raise ExamError("BAD_CONFIG", "Podaj nazwę egzaminu.")
    if len(title) > NAME_MAX:
        raise ExamError("BAD_CONFIG", f"Nazwa egzaminu może mieć najwyżej {NAME_MAX} znaków.")
    desc = _s(description)
    if len(desc) > DESCRIPTION_MAX:
        raise ExamError("BAD_CONFIG", f"Opis egzaminu może mieć najwyżej {DESCRIPTION_MAX} znaków.")
    return title, desc or None


#: Nazwy pól do komunikatu o blokadzie (czytelne dla człowieka).
LOCKED_LABELS: Dict[str, str] = {
    "result_release": "moment ujawniania wyników (result_release)",
    "anti": "zabezpieczenia antyoszustwa (anti)",
}


def locked_changes(old: Mapping[str, Any], new: Mapping[str, Any]) -> List[str]:
    """Pola, które ktoś chce zmienić po tym, jak zdający zaczęli egzamin."""
    def comparable(cfg: Mapping[str, Any], key: str) -> Any:
        value = cfg.get(key)
        if key in HINT_DEFAULTS and value is None:
            # Egzamin sprzed podpowiedzi (24.10.2026) nie ma tych pól - brak = domyślnie wyłączona.
            return HINT_DEFAULTS[key]
        if key == "single_hint_ids":
            return sorted(value or [])
        if key == "anti" and isinstance(value, Mapping):
            # Progi rzetelności to ocena komisji, nie zasada dla zdającego - nie są zablokowane.
            return {k: v for k, v in value.items() if k != "integrity"}
        return value

    return [key for key in LOCKED_AFTER_START if comparable(old, key) != comparable(new, key)]


# ---------------------------------------------------------------------------
# Pytania: pula, zestaw, kolejność
# ---------------------------------------------------------------------------


HINT_DEFAULTS: Dict[str, Any] = {"single_hint_all": False, "single_hint_ids": []}


def single_hint(config: Mapping[str, Any], question: Mapping[str, Any]) -> bool:
    """Czy karta mówi zdającemu „jedna odpowiedź jest poprawna".

    Tylko pytanie z JEDNĄ poprawną i tylko z włączoną podpowiedzią (dla całego
    egzaminu albo dla tego pytania). Stare egzaminy pól nie mają = bez podpowiedzi."""
    if len(correct_keys(question)) != 1:
        return False
    if config.get("single_hint_all"):
        return True
    return question.get("qid") in set(config.get("single_hint_ids") or [])


def exam_question(config: Mapping[str, Any], question: Mapping[str, Any],
                  keys_order: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Pytanie na arkuszu egzaminu. `multi` znaczy tu „wolno zaznaczyć kilka" -
    bez podpowiedzi zawsze prawda, więc karta nie zdradza liczby poprawnych.
    `single_hint` = karta mówi wprost, że poprawna jest jedna."""
    hint = single_hint(config, question)
    return {**public_question(question, keys_order), "multi": not hint, "single_hint": hint}


def public_question(question: Mapping[str, Any], keys_order: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Pytanie dla telefonu: BEZ kluczy poprawności i bez ciekawostki."""
    answers = {a["key"]: a for a in question.get("answers") or []}
    order = [k for k in (keys_order or [a["key"] for a in question.get("answers") or []]) if k in answers]
    return {
        "qid": question["qid"],
        "number": question.get("number"),
        "rule": question.get("rule"),
        "kind": question.get("kind"),
        "multi": bool(question.get("multi")),
        "text": question.get("text"),
        "answers": [{"key": k, "text": answers[k].get("text")} for k in order],
    }


def resolve_pool(
    scope: Mapping[str, Any],
    questions: Iterable[Mapping[str, Any]],
    history: Optional[Mapping[str, Tuple[int, float]]] = None,
) -> List[str]:
    """Identyfikatory pytań spełniających zakres, w kolejności numerów.

    `history`: qid -> (liczba odpowiedzi, odsetek poprawnych) z wcześniejszych
    egzaminów. „Trudne" = poniżej 60% przy co najmniej 5 odpowiedziach.
    """
    manual = set(scope.get("manual_ids") or [])
    rules = set(scope.get("rules") or [])
    topics = set(scope.get("topics") or [])
    kinds = set(scope.get("kinds") or [])
    difficulty = scope.get("difficulty") or "any"
    out = []
    for q in questions:
        if manual and q["qid"] not in manual:
            continue
        if not manual:
            if rules and q.get("rule") not in rules:
                continue
            if topics and not (topics & set(q.get("topics") or [])):
                continue
            if kinds and q.get("kind") not in kinds:
                continue
        if difficulty != "any":
            n, rate = (history or {}).get(q["qid"], (0, 0.0))
            if n < 5:
                continue
            if difficulty == "hard" and rate >= 0.6:
                continue
            if difficulty == "easy" and rate < 0.85:
                continue
        out.append(q)
    out.sort(key=lambda q: number_key(q.get("number")))
    if manual:
        missing = manual - {q["qid"] for q in out}
        if missing:
            raise ExamError("BAD_SCOPE", f"Ręcznie wybrane pytania nie istnieją w banku: {', '.join(sorted(missing)[:5])}.")
    return [q["qid"] for q in out]


def pick_set(pool: Sequence[str], count: int, set_mode: str, seed: str) -> List[str]:
    """Pula egzaminu: wspólny zestaw (wylosowany raz) albo cała pula do losowania per osoba."""
    if len(pool) < count:
        raise ExamError(
            "POOL_TOO_SMALL",
            f"Zakres obejmuje tylko {len(pool)} pytań, a egzamin ma ich mieć {count}. Poszerz zakres albo zmniejsz liczbę pytań.",
        )
    if set_mode == "drawn":
        return list(pool)
    if len(pool) == count:
        return list(pool)
    chosen = random.Random(seed).sample(list(pool), count)
    return sorted(chosen, key=lambda qid: number_key(qid.replace("q", "").replace("-", ".")))


def build_paper(
    config: Mapping[str, Any],
    pool: Sequence[str],
    bank: Mapping[str, Mapping[str, Any]],
    *,
    exam_id: str,
    judge_id: str,
    attempt_no: int,
) -> List[Dict[str, Any]]:
    """Arkusz jednego podejścia: kolejność pytań i kolejność kluczy odpowiedzi."""
    rng = random.Random(f"{exam_id}:{judge_id}:{attempt_no}")
    count = int(config["question_count"])
    if config.get("set_mode") == "drawn":
        ids = rng.sample(list(pool), count)
        ids.sort(key=lambda qid: number_key((bank.get(qid) or {}).get("number")))
    else:
        ids = list(pool)[:count]
    if config.get("shuffle_questions"):
        rng.shuffle(ids)
    paper = []
    for qid in ids:
        keys = [a["key"] for a in bank[qid]["answers"]]
        if config.get("shuffle_answers"):
            rng.shuffle(keys)
        paper.append({"qid": qid, "keys": keys})
    return paper


# ---------------------------------------------------------------------------
# Ocena
# ---------------------------------------------------------------------------


def correct_keys(question: Mapping[str, Any]) -> Set[str]:
    return {a["key"] for a in question.get("answers") or [] if a.get("correct")}


def score_question(question: Mapping[str, Any], selected: Iterable[str], mode: str) -> float:
    """Punkty 0-1. Wszystko albo nic: zbiór musi być identyczny. Częściowa:
    (trafione - błędne) / liczba poprawnych, nie mniej niż 0."""
    chosen = {_s(k) for k in selected or [] if _s(k)}
    right = correct_keys(question)
    if not chosen or not right:
        return 0.0
    if mode == "partial" and len(right) > 1:
        hit = len(chosen & right)
        wrong = len(chosen - right)
        return max(0.0, (hit - wrong) / len(right))
    return 1.0 if chosen == right else 0.0


def score_attempt(
    config: Mapping[str, Any],
    paper: Sequence[Mapping[str, Any]],
    answers: Mapping[str, Mapping[str, Any]],
    bank: Mapping[str, Mapping[str, Any]],
    voided: Mapping[str, str],
) -> Dict[str, Any]:
    """Wynik podejścia. `voided`: qid -> tryb ("drop" wyłącza pytanie z puli punktów,
    "credit" zalicza je wszystkim). Liczone WYŁĄCZNIE na serwerze."""
    mode = config.get("multi_scoring") or "all_or_nothing"
    rows = []
    points = 0.0
    maximum = 0.0
    for item in paper:
        qid = item["qid"]
        q = bank[qid]
        ans = answers.get(qid) or {}
        void = voided.get(qid)
        if void == "drop":
            rows.append({"qid": qid, "points": 0.0, "max": 0.0, "voided": "drop", "correct": None})
            continue
        maximum += 1.0
        if void == "credit":
            got = 1.0
        else:
            got = score_question(q, ans.get("selected") or [], mode)
        points += got
        rows.append({"qid": qid, "points": round(got, 4), "max": 1.0, "voided": void,
                     "correct": (got >= 1.0) if not void else None})
    percent = round(points / maximum * 100, 2) if maximum else 0.0
    threshold = float(config.get("pass_percent") or 0)
    return {
        "points": round(points, 4),
        "max": maximum,
        "percent": percent,
        "passed": bool(maximum) and percent + 1e-9 >= threshold,
        "pass_percent": threshold,
        "questions": rows,
    }


# ---------------------------------------------------------------------------
# Polityka wyniku i przeglądu
# ---------------------------------------------------------------------------


def window_closed(config: Mapping[str, Any], now: datetime) -> bool:
    end = parse_time(config.get("window_end"))
    return bool(end and now >= end)


def result_visible(config: Mapping[str, Any], attempt_status: str, now: datetime) -> bool:
    if attempt_status == "in_progress":
        return False
    return config.get("result_release") == "immediate" or window_closed(config, now)


def result_view(config: Mapping[str, Any], attempt: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """To, co zdający wolno zobaczyć o wyniku. Przed czasem: jawny powód, nie pustka."""
    if attempt.get("status") == "in_progress":
        return {"visible": False, "reason": "Egzamin jeszcze trwa - wynik pojawi się po jego zakończeniu."}
    if not result_visible(config, attempt.get("status"), now):
        return {
            "visible": False,
            "available_at": config.get("window_end"),
            "reason": "Autor egzaminu ustawił wynik dopiero po zamknięciu okna. Dostaniesz powiadomienie, gdy będzie gotowy.",
        }
    score = attempt.get("score") or {}
    return {
        "visible": True,
        "points": score.get("points"),
        "max": score.get("max"),
        "percent": score.get("percent"),
        "passed": score.get("passed"),
        "pass_percent": score.get("pass_percent"),
    }


def review_refusal(config: Mapping[str, Any], attempt_status: str, now: datetime) -> Optional[str]:
    if attempt_status == "in_progress":
        return "Przegląd odpowiedzi jest dostępny dopiero po zakończeniu podejścia."
    if not window_closed(config, now):
        return "Przegląd odpowiedzi z kluczem otwiera się dla wszystkich dopiero po zamknięciu okna egzaminu."
    return None


def review_view(
    config: Mapping[str, Any],
    paper: Sequence[Mapping[str, Any]],
    answers: Mapping[str, Mapping[str, Any]],
    bank: Mapping[str, Mapping[str, Any]],
    score: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    per = {row["qid"]: row for row in score.get("questions") or []}
    out = []
    for item in paper:
        q = bank[item["qid"]]
        ans = answers.get(item["qid"]) or {}
        row = per.get(item["qid"]) or {}
        out.append({
            **exam_question(config, q, item.get("keys")),
            "correct_keys": sorted(correct_keys(q)),
            "selected": list(ans.get("selected") or []),
            "points": row.get("points"),
            "max": row.get("max"),
            "voided": row.get("voided"),
            "timed_out": bool(ans.get("timed_out")),
            "refs": q.get("refs") or [],
            "curiosity": q.get("curiosity"),
        })
    return out


# ---------------------------------------------------------------------------
# Maszyna sesji
# ---------------------------------------------------------------------------
#
# Stan podejścia (słownik): status, started_at, deadline_at, current_index,
# finished_at, finish_reason, paper. Odpowiedzi: qid -> słownik z polami
# position, shown_at, answered_at, selected, timed_out, changes, flags.
# Funkcje zmieniają te słowniki w miejscu, a warstwa tras zapisuje różnicę.


def new_answer_row(qid: str, position: int) -> Dict[str, Any]:
    return {"qid": qid, "position": position, "shown_at": None, "answered_at": None,
            "selected": None, "timed_out": False, "changes": 0, "flags": [], "dirty": True}


def attempt_deadline(config: Mapping[str, Any], started: datetime) -> datetime:
    end = parse_time(config.get("window_end"))
    total = config.get("time_total_min")
    by_time = started + timedelta(minutes=int(total)) if total else None
    candidates = [d for d in (by_time, end) if d is not None]
    return min(candidates)


def start_refusal(
    config: Mapping[str, Any],
    now: datetime,
    attempts: Sequence[Mapping[str, Any]],
) -> Optional[ExamError]:
    """Czy wolno zacząć NOWE podejście. Zwraca błąd do rzucenia albo None."""
    start = parse_time(config.get("window_start"))
    end = parse_time(config.get("window_end"))
    if start and now < start:
        return ExamError("EXAM_NOT_OPEN", f"Egzamin otwiera się {local_label(start)}. Wróć wtedy.", 409,
                         {"opens_at": start.isoformat()})
    if end and now >= end:
        return ExamError("EXAM_CLOSED", "Okno egzaminu jest już zamknięte, nie można zacząć podejścia.", 409,
                         {"closed_at": end.isoformat()})
    done = [a for a in attempts if a.get("status") != "in_progress"]
    if len(attempts) >= int(config.get("max_attempts") or 1):
        return ExamError("EXAM_NO_ATTEMPTS", f"Wykorzystano wszystkie podejścia ({config.get('max_attempts')}).", 409)
    if done and config.get("retake") == "only_failed":
        last = sorted(done, key=lambda a: a.get("attempt_no") or 0)[-1]
        if (last.get("score") or {}).get("passed"):
            return ExamError("EXAM_ALREADY_PASSED", "Egzamin już zdany - ponowne podejście przysługuje tylko po niezaliczeniu.", 409)
    return None


def finish_attempt(attempt: Dict[str, Any], at: datetime, reason: str) -> None:
    if attempt.get("status") != "in_progress":
        return
    attempt["status"] = "expired" if reason in ("time_up", "window_closed") else "submitted"
    attempt["finish_reason"] = reason
    attempt["finished_at"] = at
    attempt["dirty"] = True


def settle(
    config: Mapping[str, Any],
    attempt: Dict[str, Any],
    answers: Dict[str, Dict[str, Any]],
    at: datetime,
) -> None:
    """Domyka to, co upłynęło do chwili `at`: koniec czasu całości i pytania, które przepadły."""
    if attempt.get("status") != "in_progress":
        return
    deadline = attempt["deadline_at"]
    if at >= deadline + timedelta(seconds=GRACE_S):
        _expire_open_question(config, attempt, answers, deadline)
        finish_attempt(attempt, deadline, "window_closed" if _is_window_end(config, deadline) else "time_up")
        return
    limit = config.get("time_per_question_s")
    if not limit:
        return
    paper = attempt["paper"]
    while attempt["current_index"] < len(paper):
        qid = paper[attempt["current_index"]]["qid"]
        row = answers.get(qid)
        if not row or row.get("shown_at") is None or row.get("answered_at") is not None:
            break
        due = row["shown_at"] + timedelta(seconds=float(limit) + GRACE_S)
        if at <= due:
            break
        row.update(answered_at=row["shown_at"] + timedelta(seconds=float(limit)), selected=[], timed_out=True, dirty=True)
        attempt["current_index"] += 1
        attempt["dirty"] = True
    if attempt["current_index"] >= len(paper):
        finish_attempt(attempt, at, "completed")


def _is_window_end(config: Mapping[str, Any], moment: datetime) -> bool:
    end = parse_time(config.get("window_end"))
    return bool(end and abs((end - moment).total_seconds()) < 1)


def _expire_open_question(config: Mapping[str, Any], attempt: Dict[str, Any], answers: Dict[str, Dict[str, Any]], at: datetime) -> None:
    paper = attempt["paper"]
    if attempt["current_index"] < len(paper):
        row = answers.get(paper[attempt["current_index"]]["qid"])
        if row and row.get("shown_at") is not None and row.get("answered_at") is None:
            row.update(answered_at=at, selected=[], timed_out=True, dirty=True)


def serve_question(
    config: Mapping[str, Any],
    attempt: Dict[str, Any],
    answers: Dict[str, Dict[str, Any]],
    now: datetime,
    index: Optional[int] = None,
) -> Optional[int]:
    """Które pytanie pokazać. Zaczyna jego zegar, jeśli to pierwsze pokazanie.
    Zwraca indeks albo None, gdy podejście jest zakończone."""
    settle(config, attempt, answers, now)
    if attempt["status"] != "in_progress":
        return None
    current = attempt["current_index"]
    wanted = current if index is None else int(index)
    if wanted < 0 or wanted >= len(attempt["paper"]):
        raise ExamError("EXAM_BAD_INDEX", "Nie ma pytania o tym numerze w twoim arkuszu.", 404)
    if wanted < current and not config.get("allow_back"):
        raise ExamError("EXAM_NO_BACK", "Ten egzamin nie pozwala wracać do poprzednich pytań.", 409)
    if wanted > current:
        raise ExamError("EXAM_ORDER", "Następne pytanie odblokuje się po odpowiedzi na bieżące.", 409,
                        {"current_index": current})
    qid = attempt["paper"][wanted]["qid"]
    row = answers.get(qid)
    if row is None:
        row = answers[qid] = new_answer_row(qid, wanted)
    if row["shown_at"] is None:
        row["shown_at"] = now
        row["dirty"] = True
    return wanted


def question_seconds_left(config: Mapping[str, Any], row: Optional[Mapping[str, Any]], now: datetime) -> Optional[float]:
    limit = config.get("time_per_question_s")
    if not limit or not row or row.get("shown_at") is None or row.get("answered_at") is not None:
        return None
    return max(0.0, float(limit) - (now - row["shown_at"]).total_seconds())


def _min_read_seconds(question: Mapping[str, Any]) -> float:
    words = len(_s(question.get("text")).split()) + sum(len(_s(a.get("text")).split()) for a in question.get("answers") or [])
    return max(FAST_READ_MIN_S, words / FAST_READ_WPS)


def estimate_answer_time(
    item: Mapping[str, Any], client_now_ms: Optional[float], now: datetime
) -> Tuple[datetime, List[str]]:
    """Kiedy NAPRAWDĘ padła odpowiedź: stempel klienta + przesunięcie zegara
    (czas serwera - czas klienta w chwili wysyłki). Bez stempla = teraz."""
    flags: List[str] = []
    stamp = item.get("client_ts_ms")
    if stamp is None or client_now_ms is None:
        return now, flags
    try:
        stamp = float(stamp)
        client_now = float(client_now_ms)
    except (TypeError, ValueError):
        flags.append("bad_stamp")
        return now, flags
    if stamp > client_now + CLOCK_TOL_S * 1000:
        flags.append("future_stamp")
        return now, flags
    offset_ms = now.timestamp() * 1000 - client_now
    estimate = datetime.fromtimestamp((stamp + offset_ms) / 1000, tz=timezone.utc)
    if estimate > now:
        estimate = now
    if (now - estimate).total_seconds() > BUFFER_SUSPICIOUS_S:
        flags.append("buffered_late")
    return estimate, flags


def buffer_reopen_ok(config: Mapping[str, Any], attempt: Mapping[str, Any], now: datetime) -> bool:
    """Czy zamknięte przez czas podejście wciąż przyjmie paczkę z bufora (stemple nadal sprawdzane)."""
    if attempt.get("status") == "in_progress":
        return False
    if attempt.get("finish_reason") not in ("time_up", "window_closed", "completed"):
        return False
    end = parse_time(config.get("window_end"))
    limit = max([d for d in (end, attempt.get("deadline_at")) if d is not None] or [now])
    return now <= limit + timedelta(seconds=BUFFER_ACCEPT_WINDOW_S)


def apply_answers(
    config: Mapping[str, Any],
    attempt: Dict[str, Any],
    answers: Dict[str, Dict[str, Any]],
    items: Sequence[Mapping[str, Any]],
    bank: Mapping[str, Mapping[str, Any]],
    now: datetime,
    client_now_ms: Optional[float] = None,
    buffered: bool = False,
) -> List[Dict[str, Any]]:
    """Przyjmuje paczkę odpowiedzi (także z bufora). Każda pozycja dostaje własny wynik
    (`accepted` / `duplicate` / `rejected` + kod + zdanie), nigdy ciche pominięcie.

    `buffered` = telefon deklaruje, że odpowiedzi leżały w kolejce offline. Tylko wtedy stempel
    wcześniejszy od odbioru o więcej niż BUFFER_CLAIM_S jest brany za chwilę odpowiedzi; bez
    deklaracji czas liczy się od odbioru. Zamknięte przez czas podejście przyjmuje wyłącznie
    taką paczkę i tylko w oknie BUFFER_ACCEPT_WINDOW_S."""
    reopened = bool(buffered) and buffer_reopen_ok(config, attempt, now)
    stamped = []
    for pos, item in enumerate(items):
        est, flags = estimate_answer_time(item, client_now_ms, now)
        item_buffered = bool(buffered or item.get("buffered"))
        lag = (now - est).total_seconds()
        if lag > BUFFER_CLAIM_S:
            if item_buffered:
                flags = flags + ["buffered"]
                if "buffered_late" not in flags and lag > BUFFER_SUSPICIOUS_S:
                    flags.append("buffered_late")
            else:
                est = now
                flags = flags + ["stamp_ignored"]
        stamped.append((est, pos, item, flags, item_buffered))
    stamped.sort(key=lambda t: (t[0], t[1]))
    results: List[Dict[str, Any]] = []
    for est, _pos, item, flags, item_buffered in stamped:
        results.append(_apply_one(config, attempt, answers, item, bank, now, est, flags,
                                  buffered=item_buffered, reopened=reopened))
    settle(config, attempt, answers, now)
    return results


def _reject(qid: Any, code: str, message: str, flags: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"qid": qid, "status": "rejected", "code": code, "message": message, "flags": flags or []}


def _apply_one(
    config: Mapping[str, Any],
    attempt: Dict[str, Any],
    answers: Dict[str, Dict[str, Any]],
    item: Mapping[str, Any],
    bank: Mapping[str, Mapping[str, Any]],
    now: datetime,
    est: datetime,
    flags: List[str],
    buffered: bool = False,
    reopened: bool = False,
) -> Dict[str, Any]:
    qid = _s(item.get("qid"))
    paper = attempt["paper"]
    index = next((i for i, p in enumerate(paper) if p["qid"] == qid), None)
    if index is None:
        return _reject(qid, "EXAM_UNKNOWN_QUESTION", "Tego pytania nie ma w twoim arkuszu.")
    closed = attempt["status"] != "in_progress"
    if closed and not (reopened and buffered):
        return _reject(qid, "EXAM_FINISHED", "To podejście jest już zakończone.", flags)
    if closed:
        # Podejście zamknął upływ czasu, zanim telefon oddał kolejkę. Liczy się chwila odpowiedzi.
        if est > attempt["deadline_at"] + timedelta(seconds=GRACE_S):
            return _reject(qid, "EXAM_TIME_UP", "Czas egzaminu minął, zanim ta odpowiedź została oddana.", flags)
        if "buffered_late" not in flags:
            flags = flags + ["buffered_late"]
    else:
        settle(config, attempt, answers, min(est, now))
        if attempt["status"] != "in_progress":
            return _reject(qid, "EXAM_TIME_UP", "Czas egzaminu minął, zanim ta odpowiedź została oddana.", flags)
    question = bank[qid]
    selected = [k for k in dict.fromkeys(_s(k) for k in item.get("selected") or []) if k]
    valid = {a["key"] for a in question["answers"]}
    if not selected:
        return _reject(qid, "EXAM_EMPTY_ANSWER", "Zaznacz co najmniej jedną odpowiedź.", flags)
    if any(k not in valid for k in selected):
        return _reject(qid, "EXAM_BAD_KEY", "Zaznaczono odpowiedź, której to pytanie nie ma.", flags)
    if len(selected) > 1 and single_hint(config, question):
        # Tylko pytanie z podpowiedzią „jedna poprawna" przyjmuje jedną odpowiedź. Bez niej
        # zdający może zaznaczyć kilka - ocena i tak liczy zbiór (wszystko albo nic / częściowa).
        return _reject(qid, "EXAM_SINGLE_ONLY", "W tym pytaniu poprawna jest jedna odpowiedź - zaznacz tylko jedną.", flags)
    current = attempt["current_index"]
    limit = config.get("time_per_question_s")
    row = answers.get(qid)
    revived = False
    if (buffered and row and row.get("timed_out") and row.get("shown_at") is not None
            and (not limit or (est - row["shown_at"]).total_seconds() <= float(limit) + GRACE_S)
            and est <= attempt["deadline_at"] + timedelta(seconds=GRACE_S)):
        # Serwer zamknął pytanie po swoim zegarze, zanim telefon oddał odpowiedź udzieloną w czasie.
        row.update(answered_at=None, selected=None, timed_out=False, dirty=True)
        flags = flags + ["buffered_revived"]
        revived = True
    if row and row.get("timed_out"):
        return _reject(qid, "EXAM_QUESTION_TIME_UP", "Czas na to pytanie minął - pytanie przepadło, bez punktów.", flags)
    if index > current and not closed:
        return _reject(qid, "EXAM_ORDER", "Najpierw odpowiedz na bieżące pytanie - następne odblokuje się po nim.", flags)
    if index < current and not config.get("allow_back") and not revived:
        if row and row.get("answered_at") is not None and set(row.get("selected") or []) == set(selected):
            return {"qid": qid, "status": "duplicate", "code": "EXAM_DUPLICATE", "message": "Ta odpowiedź już jest zapisana.", "flags": flags}
        return _reject(qid, "EXAM_ALREADY_ANSWERED", "Na to pytanie już odpowiedziano, a egzamin nie pozwala wracać.", flags)
    if row is None or row.get("shown_at") is None:
        return _reject(qid, "EXAM_NOT_SERVED", "Najpierw pobierz to pytanie z serwera - zegar pytania liczy się od pokazania.", flags)
    shown = row["shown_at"]
    if est < shown - timedelta(seconds=CLOCK_TOL_S):
        flags = flags + ["before_shown"]
        est = shown
    # Bez deklaracji bufora est == now (patrz apply_answers), więc czas liczy się od odbioru.
    elapsed = max(0.0, (est - shown).total_seconds())
    if limit and buffered and (now - est).total_seconds() > float(limit):
        flags = flags + ["buffered_over_limit"]
    if limit and row.get("answered_at") is None and elapsed > float(limit) + GRACE_S:
        row.update(answered_at=shown + timedelta(seconds=float(limit)), selected=[], timed_out=True, dirty=True)
        if index == current and not closed:
            attempt["current_index"] += 1
            attempt["dirty"] = True
        return _reject(qid, "EXAM_QUESTION_TIME_UP",
                       f"Czas na to pytanie ({int(limit)} s) minął - pytanie przepadło, bez punktów.", flags)
    if row.get("answered_at") is not None and set(row.get("selected") or []) == set(selected) and not row.get("timed_out"):
        return {"qid": qid, "status": "duplicate", "code": "EXAM_DUPLICATE", "message": "Ta odpowiedź już jest zapisana.", "flags": flags}
    if (config.get("anti") or {}).get("speed_flags") and elapsed < _min_read_seconds(question):
        flags = flags + ["too_fast"]
    if row.get("answered_at") is not None:
        row["changes"] = int(row.get("changes") or 0) + 1
    row.update(selected=selected, answered_at=est, dirty=True)
    row["flags"] = list(dict.fromkeys(list(row.get("flags") or []) + flags))
    row["elapsed_ms"] = int(elapsed * 1000)
    if index == current and not closed:
        attempt["current_index"] += 1
        attempt["dirty"] = True
        if attempt["current_index"] >= len(paper) and not config.get("allow_back"):
            finish_attempt(attempt, est, "completed")
    return {"qid": qid, "status": "accepted", "code": None, "message": None, "flags": flags,
            "elapsed_ms": int(elapsed * 1000)}


def finish_refusal(config: Mapping[str, Any], attempt: Mapping[str, Any]) -> Optional[ExamError]:
    left = len(attempt["paper"]) - attempt["current_index"]
    if left > 0:
        return ExamError("EXAM_INCOMPLETE", f"Zostało {left} pytań bez odpowiedzi. Odpowiedz na wszystkie, zanim oddasz arkusz.", 409,
                         {"remaining": left})
    return None


def apply_leave_policy(
    config: Mapping[str, Any],
    attempt: Dict[str, Any],
    answers: Dict[str, Dict[str, Any]],
    now: datetime,
) -> Dict[str, Any]:
    """Wyjście z aplikacji wg polityki egzaminu. Zwraca opis dla telefonu."""
    policy = (config.get("anti") or {}).get("leave_app") or "log"
    result = {"policy": policy, "action": "logged", "message": None}
    if attempt.get("status") != "in_progress":
        return result
    if policy == "warn":
        result.update(action="warned", message="Wyjście z aplikacji w trakcie egzaminu zostało zapisane i zobaczy je komisja.")
    elif policy == "void_question":
        paper = attempt["paper"]
        if attempt["current_index"] < len(paper):
            qid = paper[attempt["current_index"]]["qid"]
            row = answers.get(qid) or new_answer_row(qid, attempt["current_index"])
            answers[qid] = row
            row.update(answered_at=now, selected=[], timed_out=True, dirty=True,
                       flags=list(dict.fromkeys(list(row.get("flags") or []) + ["lost_on_leave"])))
            if row.get("shown_at") is None:
                row["shown_at"] = now
            attempt["current_index"] += 1
            attempt["dirty"] = True
            if attempt["current_index"] >= len(paper):
                finish_attempt(attempt, now, "completed")
        result.update(action="question_lost",
                      message="Wyszedłeś z aplikacji - bieżące pytanie przepadło i dostaje 0 punktów.")
    elif policy == "end":
        finish_attempt(attempt, now, "left_app")
        result.update(action="ended", message="Wyszedłeś z aplikacji - egzamin został zakończony zgodnie z jego zasadami.")
    return result


# ---------------------------------------------------------------------------
# Kod sali (tryb sali: zmienny co 30 s)
# ---------------------------------------------------------------------------


def _room_code_for(secret: str, exam_id: str, slot: int) -> str:
    digest = hmac.new(secret.encode(), f"{exam_id}:{slot}".encode(), hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def room_code(secret: str, exam_id: str, now: datetime) -> Dict[str, Any]:
    slot = int(now.timestamp()) // ROOM_CODE_STEP_S
    return {"code": _room_code_for(secret, exam_id, slot), "valid_until": datetime.fromtimestamp((slot + 1) * ROOM_CODE_STEP_S, tz=timezone.utc).isoformat(),
            "step_s": ROOM_CODE_STEP_S}


def room_code_ok(secret: str, exam_id: str, code: Any, now: datetime) -> bool:
    slot = int(now.timestamp()) // ROOM_CODE_STEP_S
    text = _s(code)
    return any(hmac.compare_digest(text, _room_code_for(secret, exam_id, s)) for s in (slot, slot - 1))


# ---------------------------------------------------------------------------
# Rzetelność
# ---------------------------------------------------------------------------

#: (rodzaj, flaga) -> (etykieta, kara za jedno, górny limit kary) - WARTOŚCI DOMYŚLNE.
#: Faktyczne progi egzaminu: `config.anti.integrity` (DEFAULT_INTEGRITY).
_INTEGRITY_ROWS: Tuple[Tuple[str, str, str, str], ...] = (
    ("app_background", "app_background", "", "Wyjścia z aplikacji"),
    ("screenshot", "screenshot", "", "Zrzuty ekranu"),
    ("too_fast", "time_flag", "too_fast", "Odpowiedzi szybsze niż czas czytania"),
    ("buffered_late", "time_flag", "buffered_late", "Odpowiedzi długo leżące w telefonie"),
    ("buffered_over_limit", "time_flag", "buffered_over_limit", "Odpowiedź z bufora starsza niż limit pytania"),
    ("stamp_ignored", "time_flag", "stamp_ignored", "Stempel czasu odrzucony (brak deklaracji bufora)"),
    ("future_stamp", "time_flag", "future_stamp", "Stempel czasu z przyszłości"),
    ("before_shown", "time_flag", "before_shown", "Odpowiedź przed pokazaniem pytania"),
    ("device_change", "device_change", "", "Wznowienie na innym urządzeniu"),
    ("similarity", "similarity", "", "Podobieństwo odpowiedzi do innego zdającego"),
)
INTEGRITY_LABELS: Dict[str, str] = {key: label for key, _k, _f, label in _INTEGRITY_ROWS}
_INTEGRITY_KEY_OF: Dict[Tuple[str, str], str] = {(kind, flag): key for key, kind, flag, _l in _INTEGRITY_ROWS}
INTEGRITY_RULES: Dict[Tuple[str, str], Tuple[str, int, int]] = {
    (kind, flag): (label, DEFAULT_INTEGRITY["penalties"][key],
                   DEFAULT_INTEGRITY["penalties"][key] * DEFAULT_INTEGRITY["max_events"][key])
    for key, kind, flag, label in _INTEGRITY_ROWS
}
LONG_ABSENCE_S = DEFAULT_INTEGRITY["long_absence_s"]
LONG_ABSENCE_EXTRA = DEFAULT_INTEGRITY["long_absence_extra"]


def integrity_report(events: Iterable[Mapping[str, Any]], thresholds: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Wskaźnik 0-100 z rozpisaniem kar. To sygnał dla komisji, nie wyrok.

    `thresholds` = `config.anti.integrity` egzaminu (brak = wartości domyślne).
    Odpowiedź niesie `thresholds` (z jakich progów powstał wskaźnik) i `custom`."""
    th = clean_integrity(thresholds)
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for event in events:
        kind = _s(event.get("kind"))
        detail = event.get("detail") if isinstance(event.get("detail"), Mapping) else {}
        flag = _s(detail.get("flag")) if kind == "time_flag" else ""
        key = (kind, flag)
        name = _INTEGRITY_KEY_OF.get(key)
        if name is None:
            continue
        per = th["penalties"][name]
        cap = per * th["max_events"][name]
        group = groups.setdefault(key, {"kind": kind, "flag": flag or None, "label": INTEGRITY_LABELS[name],
                                        "count": 0, "raw": 0, "cap": cap})
        group["count"] += 1
        group["raw"] += per
        if kind == "app_background" and float(detail.get("seconds") or 0) >= th["long_absence_s"]:
            group["raw"] += th["long_absence_extra"]
    breakdown = []
    total = 0
    for group in groups.values():
        penalty = min(group["raw"], group["cap"])
        total += penalty
        breakdown.append({"kind": group["kind"], "flag": group["flag"], "label": group["label"],
                          "count": group["count"], "penalty": penalty})
    score = max(0, 100 - total)
    level = "ok" if score >= th["ok_min"] else "warning" if score >= th["warning_min"] else "suspicious"
    return {"score": score, "level": level, "breakdown": breakdown, "thresholds": th,
            "custom": th != DEFAULT_INTEGRITY,
            "note": "Wskaźnik jest sygnałem dla komisji. Nic nie dyskwalifikuje automatycznie."}


def similarity_pairs(attempts: Sequence[Mapping[str, Any]], *, min_common: Optional[int] = None,
                     close_s: Optional[float] = None, close_min: Optional[int] = None,
                     thresholds: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
    """Pary z tymi samymi BŁĘDNYMI odpowiedziami (domyślnie min. 3) i co najmniej dwiema
    z nich oddanymi w odstępie do 30 s. Progi: `thresholds` (= `anti.integrity`) lub jawne argumenty.

    attempt: {"attempt_id", "judge_id", "answers": {qid: {"selected", "correct", "answered_at"}}}
    """
    th = clean_integrity(thresholds)
    min_common = th["similarity_min_common"] if min_common is None else min_common
    close_s = th["similarity_close_s"] if close_s is None else close_s
    close_min = th["similarity_close_min"] if close_min is None else close_min
    out = []
    items = list(attempts)
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            common, close = [], []
            for qid, ra in (a.get("answers") or {}).items():
                rb = (b.get("answers") or {}).get(qid)
                if not rb or ra.get("correct") or rb.get("correct"):
                    continue
                sa, sb = set(ra.get("selected") or []), set(rb.get("selected") or [])
                if not sa or sa != sb:
                    continue
                common.append(qid)
                ta, tb = ra.get("answered_at"), rb.get("answered_at")
                if ta and tb and abs((ta - tb).total_seconds()) <= close_s:
                    close.append(qid)
            if len(common) >= min_common and len(close) >= close_min:
                out.append({"attempt_ids": [a["attempt_id"], b["attempt_id"]], "judge_ids": [a["judge_id"], b["judge_id"]],
                            "common_wrong": sorted(common), "close_in_time": sorted(close)})
    return out


# ---------------------------------------------------------------------------
# Statystyki pytań (surowe, pod etap 4)
# ---------------------------------------------------------------------------


def question_stats(
    rows: Iterable[Mapping[str, Any]],
    bank: Mapping[str, Mapping[str, Any]],
    voided: Mapping[str, str],
    mode: str,
) -> List[Dict[str, Any]]:
    """rows: {qid, selected, timed_out, elapsed_ms} z zakończonych podejść."""
    agg: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        qid = row["qid"]
        q = bank.get(qid)
        if not q:
            continue
        st = agg.setdefault(qid, {"qid": qid, "number": q.get("number"), "rule": q.get("rule"), "answered": 0,
                                  "skipped": 0, "timed_out": 0, "points": 0.0, "time_ms": 0, "time_n": 0,
                                  "distribution": {a["key"]: 0 for a in q["answers"]}})
        selected = row.get("selected") or []
        if row.get("timed_out"):
            st["timed_out"] += 1
        if not selected:
            st["skipped"] += 1
        else:
            st["answered"] += 1
            for key in selected:
                if key in st["distribution"]:
                    st["distribution"][key] += 1
        st["points"] += score_question(q, selected, mode)
        if row.get("elapsed_ms") is not None:
            st["time_ms"] += int(row["elapsed_ms"])
            st["time_n"] += 1
    out = []
    for qid, st in agg.items():
        total = st["answered"] + st["skipped"]
        out.append({
            "qid": qid, "number": st["number"], "rule": st["rule"], "total": total,
            "answered": st["answered"], "skipped": st["skipped"], "timed_out": st["timed_out"],
            "correct_rate": round(st["points"] / total, 4) if total else None,
            "avg_time_s": round(st["time_ms"] / st["time_n"] / 1000, 1) if st["time_n"] else None,
            "distribution": st["distribution"],
            "correct_keys": sorted(correct_keys(bank[qid])),
            "voided": voided.get(qid),
        })
    out.sort(key=lambda r: number_key(r["number"]))
    return out


# ---------------------------------------------------------------------------
# Przypomnienia push
# ---------------------------------------------------------------------------


def reminder_kind(hours: int) -> str:
    return f"before_{int(hours)}h"


def due_exam_reminders(
    *,
    now: datetime,
    window_start: datetime,
    window_end: datetime,
    created_at: Optional[datetime],
    thresholds_hours: Sequence[int],
    pending: Sequence[str],
    sent: Set[Tuple[str, str]],
) -> List[Tuple[str, List[str]]]:
    """Przypomnienie „X przed końcem okna" do tych, którzy nie przystąpili.

    Po przestoju serwera wysyłamy tylko NAJBLIŻSZY przekroczony próg, nie serię.
    Próg, który minął, zanim egzamin się otworzył (albo powstał), nie liczy się -
    świeżo dodany egzamin dostał już push „nowe wydarzenie".
    """
    if now < window_start or now >= window_end or not pending:
        return []
    opened = max(window_start, _aware(created_at) or window_start)
    crossed = [h for h in sorted({int(h) for h in thresholds_hours})
               if window_end - timedelta(hours=h) <= now and window_end - timedelta(hours=h) >= opened]
    if not crossed:
        return []
    hours = crossed[0]
    kind = reminder_kind(hours)
    people = [jid for jid in pending if (jid, kind) not in sent]
    return [(kind, people)] if people else []


def exam_event_fields(name: str, description: Optional[str], config: Mapping[str, Any], exam_id: str) -> Dict[str, Any]:
    """Pola wydarzenia okręgowego publikowanego przez egzamin (typ „exam")."""
    return {
        "name": name,
        "description": description,
        "event_type": "exam",
        "event_date": parse_time(config["window_start"]),
        "end_date": parse_time(config["window_end"]),
        "data_json": {
            "exam_id": exam_id,
            "target": dict(config.get("target") or {}),
            "include_ids": list(config.get("include_ids") or []),
            "exclude_ids": list(config.get("exclude_ids") or []),
            "obligatory": bool(config.get("mandatory")),
            "place": {"name": None, "address": None},
            "online_url": None,
            "rsvp_deadline": None,
        },
    }
