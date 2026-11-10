"""
Formularze okręgowe - schemat listy (§4) i formularza (§5), bez bazy i bez sieci.

Kontrakt: `docs/formularze-okregowe.md`.

Lista deklaracji (`kind = "list"`): kolumny ustawia twórca, wiersze to sędziowie.
Formularz (`kind = "form"`): port 1:1 z Communio (`Communio_serwer/app/form_schemas.py`,
`app/forms.py`, `app/form_stats.py`):

  - sekcje i pytania, logika „przejdź do sekcji" WYŁĄCZNIE do przodu (pętla
    zrobiłaby z formularza coś, co można przechodzić w nieskończoność),
  - przy zapisie serwer liczy trasę przez sekcje i WYCINA odpowiedzi z pominiętych
    sekcji; obowiązkowość dotyczy tylko pytań na trasie,
  - kształt odpowiedzi:

        tekst, e-mail, telefon, PESEL, kod   "napis"
        jednokrotny, lista                   {"option": "o1"} | {"other": "napis"}
        wielokrotny                          {"options": ["o1", …], "other": "napis" | null}
        skala, ocena                         liczba całkowita
        liczba                               liczba
        data / godzina / data i godzina      "RRRR-MM-DD" / "GG:MM" / "RRRR-MM-DDTGG:MM"
        plik                                 ["token", …]
        siatka                               {"wiersz": "kolumna"} | {"wiersz": ["kolumna", …]}

Różnica względem Communio: własny wzorzec przy krótkiej odpowiedzi przyjmujemy
TYLKO prosty (bez zagnieżdżonych powtórzeń i odwołań wstecznych). Communio puszcza
złożone przez osobny proces z limitem czasu; tutaj wolimy odmówić od razu przy
zapisie formularza, niż trzymać pulę procesów dla jednego pola.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Dict, Iterable, List, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.district_forms_rules import FormError

# ===========================================================================
# Lista deklaracji (§4)
# ===========================================================================

COLUMN_TYPES = ("status", "check", "confirm", "choice", "number", "text")
EDITORS = ("self", "managers", "self_confirm")
VISIBILITIES = ("all", "self", "managers")
TONES = ("positive", "negative", "neutral", "warning")
MAX_COLUMNS = 20
COLUMN_TITLE_MAX = 60
HINT_MAX = 200
OPTION_LABEL_MAX = 60
TEXT_MAX = 500
STATUS_OPTIONS = (2, 5)
CHOICE_OPTIONS = (2, 20)
AMOUNT_MAX = 1_000_000

COLUMN_ID = re.compile(r"^[a-z0-9_-]{1,24}$")
OPTION_ID = re.compile(r"^[A-Za-z0-9_-]{1,24}$")

DEFAULT_STATUS_OPTIONS = (
    {"id": "yes", "label": "Będę", "tone": "positive"},
    {"id": "no", "label": "Nie będę", "tone": "negative"},
)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _bad(message: str, code: str = "bad_schema") -> FormError:
    return FormError(code, message, 400)


def _number(value: Any, what: str) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise _bad(f"{what}: to musi być liczba.")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise _bad(f"{what}: to musi być liczba.") from error
    if number != number or number in (float("inf"), float("-inf")):
        raise _bad(f"{what}: to musi być liczba.")
    return int(number) if int(number) == number else number


def _options(raw: Any, column_title: str, limits: Tuple[int, int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in raw or []:
        if not isinstance(item, Mapping):
            raise _bad(f"Kolumna „{column_title}”: opcja ma zły kształt.")
        oid, label = _s(item.get("id")), _s(item.get("label"))
        if not OPTION_ID.match(oid):
            raise _bad(f"Kolumna „{column_title}”: identyfikator opcji ma 1-24 znaki (litery, cyfry, _ i -).")
        if not label:
            raise _bad(f"Kolumna „{column_title}”: każda opcja potrzebuje nazwy.")
        if len(label) > OPTION_LABEL_MAX:
            raise _bad(f"Kolumna „{column_title}”: nazwa opcji ma najwyżej {OPTION_LABEL_MAX} znaków.")
        option: Dict[str, Any] = {"id": oid, "label": label}
        tone = _s(item.get("tone"))
        if tone:
            if tone not in TONES:
                raise _bad(f"Kolumna „{column_title}”: nieznany kolor opcji.")
            option["tone"] = tone
        out.append(option)
    ids = [o["id"] for o in out]
    if len(set(ids)) != len(ids):
        raise _bad(f"Kolumna „{column_title}”: dwie opcje mają ten sam identyfikator.")
    low, high = limits
    if not low <= len(out) <= high:
        raise _bad(f"Kolumna „{column_title}” ma od {low} do {high} opcji.")
    return out


def clean_column(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise _bad("Kolumna ma zły kształt.")
    cid = _s(raw.get("id"))
    if not COLUMN_ID.match(cid):
        raise _bad("Identyfikator kolumny ma 1-24 znaki: małe litery, cyfry, _ i -.")
    ctype = _s(raw.get("type"))
    if ctype not in COLUMN_TYPES:
        raise _bad("Nieznany rodzaj kolumny.")
    title = _s(raw.get("title"))
    if not title:
        raise _bad("Każda kolumna potrzebuje nazwy.")
    if len(title) > COLUMN_TITLE_MAX:
        raise _bad(f"Nazwa kolumny ma najwyżej {COLUMN_TITLE_MAX} znaków.")
    hint = _s(raw.get("hint"))
    if len(hint) > HINT_MAX:
        raise _bad(f"Podpowiedź pod kolumną ma najwyżej {HINT_MAX} znaków.")
    editor = _s(raw.get("editor")) or ("self_confirm" if ctype == "confirm" else "self")
    if editor not in EDITORS:
        raise _bad(f"Kolumna „{title}”: nieznane ustawienie „kto wpisuje”.")
    if editor == "self_confirm" and ctype != "confirm":
        raise _bad(f"Kolumna „{title}”: „sędzia zgłasza, komisja potwierdza” jest tylko przy kolumnie potwierdzenia.")
    visibility = _s(raw.get("visibility")) or "all"
    if visibility not in VISIBILITIES:
        raise _bad(f"Kolumna „{title}”: nieznane ustawienie widoczności.")
    lock = raw.get("lock_after_deadline")
    column: Dict[str, Any] = {
        "id": cid,
        "type": ctype,
        "title": title,
        "editor": editor,
        "visibility": visibility,
        "required": bool(raw.get("required")),
        # Po terminie sędzia nie zmienia już deklaracji; wpłatę zgłasza dalej (domyślnie).
        "lock_after_deadline": (ctype != "confirm") if lock is None else bool(lock),
    }
    if hint:
        column["hint"] = hint
    if ctype == "status":
        options = raw.get("options") or [dict(o) for o in DEFAULT_STATUS_OPTIONS]
        column["options"] = _options(options, title, STATUS_OPTIONS)
    elif ctype == "choice":
        column["options"] = _options(raw.get("options"), title, CHOICE_OPTIONS)
        column["multi"] = bool(raw.get("multi"))
    elif ctype == "confirm":
        amount = _number(raw.get("amount"), f"Kolumna „{title}”, kwota")
        if amount is not None and not 0 <= amount <= AMOUNT_MAX:
            raise _bad(f"Kolumna „{title}”: kwota od 0 do {AMOUNT_MAX} zł.")
        column["amount"] = amount
    elif ctype == "number":
        low = _number(raw.get("min"), f"Kolumna „{title}”, najmniej")
        high = _number(raw.get("max"), f"Kolumna „{title}”, najwięcej")
        if low is not None and high is not None and low > high:
            raise _bad(f"Kolumna „{title}”: najmniejsza wartość jest większa od największej.")
        column["min"], column["max"] = low, high
        column["integer"] = bool(raw.get("integer"))
    elif ctype == "text":
        limit = raw.get("max_length")
        if limit in (None, ""):
            limit = TEXT_MAX
        try:
            limit = int(limit)
        except (TypeError, ValueError) as error:
            raise _bad(f"Kolumna „{title}”: długość tekstu to liczba.") from error
        if not 1 <= limit <= TEXT_MAX:
            raise _bad(f"Kolumna „{title}”: tekst ma od 1 do {TEXT_MAX} znaków.")
        column["max_length"] = limit
    return column


def clean_list_schema(raw: Any) -> Dict[str, Any]:
    """Schemat listy deklaracji. Zła wartość = 400 ze zdaniem, nie ciche przycięcie."""
    columns_raw = raw.get("columns") if isinstance(raw, Mapping) else None
    if not isinstance(columns_raw, list) or not columns_raw:
        raise _bad("Lista potrzebuje co najmniej jednej kolumny.")
    if len(columns_raw) > MAX_COLUMNS:
        raise _bad(f"Lista może mieć najwyżej {MAX_COLUMNS} kolumn.")
    columns = [clean_column(c) for c in columns_raw]
    ids = [c["id"] for c in columns]
    if len(set(ids)) != len(ids):
        raise _bad("Dwie kolumny mają ten sam identyfikator.")
    if sum(1 for c in columns if c["type"] == "status") > 1:
        raise _bad("Lista może mieć najwyżej jedną kolumnę statusu (Będę / Nie będę).")
    return {"columns": columns}


# ===========================================================================
# Formularz (§5) - modele jak w Communio
# ===========================================================================

QuestionType = Literal[
    "short_text", "long_text",
    "single", "multi", "dropdown",
    "scale", "rating",
    "date", "time", "datetime",
    "number",
    "email", "phone", "pesel", "postal",
    "file", "grid",
]

_ID = r"^[A-Za-z0-9_-]{1,24}$"
_FILE_TOKEN = r"^[a-f0-9]{16}$"

END = "end"
TEXTUAL = frozenset({"short_text", "long_text", "email", "phone", "pesel", "postal"})
SINGLE_CHOICE = frozenset({"single", "dropdown"})
CHOICE = frozenset({"single", "dropdown", "multi"})
MAX_QUESTIONS = 200
MAX_SECTIONS = 30
SHORT_MAX = 500
LONG_MAX = 5000
PATTERN_MAX = 200

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
_POSTAL = re.compile(r"^\d{2}-?\d{3}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T([01]\d|2[0-3]):[0-5]\d$")
_TOKEN = re.compile(_FILE_TOKEN)


class _Loose(BaseModel):
    """Pola spoza kontraktu są pomijane - starsza aplikacja z nowym polem dalej zapisze formularz."""

    model_config = ConfigDict(extra="ignore")


class FormOption(_Loose):
    id: str = Field(..., pattern=_ID)
    label: str = Field(..., max_length=200)


class FormGridLine(_Loose):
    id: str = Field(..., pattern=_ID)
    label: str = Field(..., max_length=120)


class FormQuestion(_Loose):
    id: str = Field(..., pattern=_ID)
    type: QuestionType
    title: str = Field("", max_length=300)
    description: Optional[str] = Field(None, max_length=2000)
    required: bool = False
    image: Optional[str] = Field(None, pattern=_FILE_TOKEN)
    #: Adres obrazu do wyświetlenia (BAZA). Serwer i tak wylicza go z `image` w odpowiedziach (`with_image_urls`).
    image_url: Optional[str] = Field(None, max_length=500, pattern=r"^(https://|/district-forms/|/static/)\S*$")
    options: List[FormOption] = Field(default_factory=list, max_length=50)
    other: bool = False
    min_choices: Optional[int] = Field(None, ge=0, le=50)
    max_choices: Optional[int] = Field(None, ge=1, le=50)
    logic: Dict[str, str] = Field(default_factory=dict)
    scale_min: int = Field(1, ge=0, le=1)
    scale_max: int = Field(5, ge=2, le=10)
    min_label: Optional[str] = Field(None, max_length=60)
    max_label: Optional[str] = Field(None, max_length=60)
    stars: int = Field(5, ge=3, le=10)
    number_min: Optional[float] = None
    number_max: Optional[float] = None
    integer: bool = False
    min_length: Optional[int] = Field(None, ge=0, le=5000)
    max_length: Optional[int] = Field(None, ge=1, le=5000)
    pattern: Optional[str] = Field(None, max_length=PATTERN_MAX)
    pattern_message: Optional[str] = Field(None, max_length=200)
    rows: List[FormGridLine] = Field(default_factory=list, max_length=30)
    columns: List[FormGridLine] = Field(default_factory=list, max_length=12)
    grid_multi: bool = False
    max_files: int = Field(1, ge=1, le=10)
    accept: Literal["image", "any"] = "any"


class FormSection(_Loose):
    id: str = Field(..., pattern=_ID)
    title: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    questions: List[FormQuestion] = Field(default_factory=list, max_length=100)
    next: Optional[str] = None


def sections_of(schema: Any) -> List[FormSection]:
    """Sekcje z zapisanego schematu (już sprawdzonego) - bez ponownej walidacji całości."""
    raw = schema.get("sections") if isinstance(schema, Mapping) else None
    out: List[FormSection] = []
    for item in raw or []:
        try:
            out.append(FormSection.model_validate(item))
        except ValidationError:
            continue
    return out


def questions(sections: Iterable[FormSection]) -> List[FormQuestion]:
    return [q for s in sections for q in s.questions]


def images(sections: Iterable[FormSection]) -> set:
    return {q.image for q in questions(sections) if q.image}


def _label(q: FormQuestion) -> str:
    return f"„{q.title.strip()}”" if q.title.strip() else "pytanie bez treści"


# --- Wzorzec własny (tylko prosty) ----------------------------------------

try:  # pragma: no cover - ścieżka zależy od wersji Pythona
    from re import _constants as _sre_const  # type: ignore[attr-defined]
    from re import _parser as _sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    import sre_constants as _sre_const  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

_REPEATS = {_sre_const.MAX_REPEAT, _sre_const.MIN_REPEAT}
_INFINITE = _sre_const.MAXREPEAT
_BACKREFS = {_sre_const.GROUPREF, getattr(_sre_const, "GROUPREF_EXISTS", None)}


def _has_repeat_or_branch(items) -> bool:
    for op, av in items:
        if op in _REPEATS or op == _sre_const.BRANCH:
            return True
        if op == _sre_const.SUBPATTERN and _has_repeat_or_branch(av[-1]):
            return True
    return False


def _simple(items, counter: List[int]) -> bool:
    for op, av in items:
        if op in _BACKREFS:
            return False
        if op in _REPEATS:
            _low, high, inner = av
            if high == _INFINITE or high > 50:
                counter[0] += 1
            if _has_repeat_or_branch(inner) or not _simple(inner, counter):
                return False
        elif op == _sre_const.SUBPATTERN:
            if not _simple(av[-1], counter):
                return False
        elif op == _sre_const.BRANCH:
            if not all(_simple(branch, counter) for branch in av[1]):
                return False
        elif op in (_sre_const.ASSERT, _sre_const.ASSERT_NOT):
            if not _simple(av[1], counter):
                return False
    return counter[0] <= 2


def _has_backref(items) -> bool:
    for op, av in items:
        if op in _BACKREFS:
            return True
        if op in _REPEATS and _has_backref(av[2]):
            return True
        if op == _sre_const.SUBPATTERN and _has_backref(av[-1]):
            return True
        if op == _sre_const.BRANCH and any(_has_backref(b) for b in av[1]):
            return True
        if op in (_sre_const.ASSERT, _sre_const.ASSERT_NOT) and _has_backref(av[1]):
            return True
    return False


def pattern_simple(pattern: str) -> bool:
    """Czy wzorzec wolno dopasować w miejscu (co najwyżej kwadratowo względem 500 znaków)."""
    try:
        tree = _sre_parse.parse(pattern)
    except Exception:  # noqa: BLE001 - każdy błąd analizy = „nie ufamy"
        return False
    return _simple(tree, [0])


def check_pattern(pattern: str) -> None:
    """Przy zapisie formularza: składnia, odwołania wsteczne, złożoność."""
    if len(pattern) > PATTERN_MAX:
        raise _bad(f"Wzorzec może mieć najwyżej {PATTERN_MAX} znaków.")
    try:
        tree = _sre_parse.parse(pattern)
        re.compile(pattern)
    except Exception as error:  # noqa: BLE001
        raise _bad("Ten wzorzec ma błąd składni - sprawdź nawiasy i znaki specjalne.") from error
    if _has_backref(tree):
        raise _bad("Wzorzec nie może odwoływać się do wcześniejszych grup (\\1, (?P=…)).")
    if not _simple(tree, [0]):
        raise _bad(
            "Ten wzorzec jest zbyt złożony - sprawdzanie odpowiedzi trwałoby za długo. "
            "Uprość powtarzane grupy, np. zamiast (a+)+ wpisz a+."
        )


def pattern_matches(pattern: str, text: str) -> Optional[bool]:
    """True/False albo None, gdy wzorca nie da się bezpiecznie sprawdzić."""
    if len(text) > SHORT_MAX:
        return False
    if not pattern_simple(pattern):
        return None
    try:
        return re.fullmatch(pattern, text) is not None
    except re.error:
        return None


# --- Dokument ---------------------------------------------------------------


def _check_question(q: FormQuestion) -> None:
    if not q.title.strip():
        raise _bad("Każde pytanie potrzebuje treści.")
    if q.type in CHOICE:
        if not q.options and not q.other:
            raise _bad(f"Pytanie {_label(q)} potrzebuje co najmniej jednej odpowiedzi do wyboru.")
        ids = [o.id for o in q.options]
        if len(set(ids)) != len(ids):
            raise _bad(f"Pytanie {_label(q)}: dwie odpowiedzi mają ten sam identyfikator.")
        if any(not o.label.strip() for o in q.options):
            raise _bad(f"Pytanie {_label(q)}: każda odpowiedź do wyboru potrzebuje treści.")
        if q.type == "dropdown" and q.other:
            raise _bad(f"Pytanie {_label(q)}: lista rozwijana nie ma pozycji „Inne”.")
    if q.type == "multi":
        count = len(q.options) + (1 if q.other else 0)
        if q.max_choices is not None and q.max_choices > count:
            raise _bad(f"Pytanie {_label(q)}: limit wyborów jest większy niż liczba odpowiedzi.")
        if q.min_choices is not None and q.max_choices is not None and q.min_choices > q.max_choices:
            raise _bad(f"Pytanie {_label(q)}: najmniej wyborów jest więcej niż najwięcej.")
    if q.type == "scale" and q.scale_min >= q.scale_max:
        raise _bad(f"Pytanie {_label(q)}: skala musi rosnąć.")
    if q.type == "number" and q.number_min is not None and q.number_max is not None and q.number_min > q.number_max:
        raise _bad(f"Pytanie {_label(q)}: najmniejsza wartość jest większa od największej.")
    if q.min_length is not None and q.max_length is not None and q.min_length > q.max_length:
        raise _bad(f"Pytanie {_label(q)}: najkrótsza odpowiedź jest dłuższa od najdłuższej.")
    if q.type == "grid":
        if not q.rows or len(q.columns) < 2:
            raise _bad(f"Pytanie {_label(q)}: siatka potrzebuje wierszy i co najmniej dwóch kolumn.")
        for lines in (q.rows, q.columns):
            ids = [x.id for x in lines]
            if len(set(ids)) != len(ids) or any(not x.label.strip() for x in lines):
                raise _bad(f"Pytanie {_label(q)}: wiersze i kolumny siatki potrzebują treści.")
    if q.pattern:
        if q.type != "short_text":
            raise _bad(f"Pytanie {_label(q)}: własny wzorzec ma tylko krótka odpowiedź.")
        try:
            check_pattern(q.pattern)
        except FormError as error:
            raise _bad(f"Pytanie {_label(q)}: {error.message}") from error


def check_document(sections: List[FormSection]) -> None:
    """Reguły, które wymagają spojrzenia na całość - rzuca FormError (400)."""
    if not sections:
        raise _bad("Formularz potrzebuje co najmniej jednej sekcji.")
    if len(sections) > MAX_SECTIONS:
        raise _bad(f"Formularz może mieć najwyżej {MAX_SECTIONS} sekcji.")
    every = questions(sections)
    if not every:
        raise _bad("Formularz potrzebuje co najmniej jednego pytania.")
    if len(every) > MAX_QUESTIONS:
        raise _bad(f"Formularz może mieć najwyżej {MAX_QUESTIONS} pytań.")
    section_ids = [s.id for s in sections]
    if len(set(section_ids)) != len(section_ids):
        raise _bad("Dwie sekcje mają ten sam identyfikator.")
    question_ids = [q.id for q in every]
    if len(set(question_ids)) != len(question_ids):
        raise _bad("Dwa pytania mają ten sam identyfikator.")
    if set(section_ids) & set(question_ids) or END in section_ids:
        raise _bad("Identyfikator sekcji pokrywa się z innym w formularzu.")
    position = {sid: i for i, sid in enumerate(section_ids)}

    def target(goal: Optional[str], index: int, where: str) -> None:
        if goal is None or goal == END:
            return
        if goal not in position:
            raise _bad(f"{where}: wskazana sekcja nie istnieje.")
        if position[goal] <= index:
            raise _bad(f"{where}: przejść można tylko do sekcji dalej w formularzu - skok wstecz zrobiłby z niego pętlę.")

    for index, section in enumerate(sections):
        target(section.next, index, f"Sekcja {index + 1}")
        for q in section.questions:
            _check_question(q)
            if q.logic:
                if q.type not in SINGLE_CHOICE:
                    raise _bad(
                        f"Pytanie {_label(q)}: przejście do sekcji wybiera się tylko przy jednokrotnym wyborze albo liście."
                    )
                options = {o.id for o in q.options}
                for option, goal in q.logic.items():
                    if option not in options:
                        raise _bad(f"Pytanie {_label(q)}: logika wskazuje odpowiedź, której nie ma.")
                    target(goal, index, f"Pytanie {_label(q)}")


def _first_validation_message(error: ValidationError) -> str:
    try:
        first = error.errors()[0]
    except (IndexError, TypeError):
        return "Formularz ma zły kształt."
    where = ".".join(str(x) for x in first.get("loc") or ())
    return f"Formularz ma zły kształt ({where})." if where else "Formularz ma zły kształt."


def clean_form_schema(raw: Any) -> Dict[str, Any]:
    """Schemat formularza `{sections:[...]}` - kształt (pydantic) i całość (`check_document`)."""
    sections_raw = raw.get("sections") if isinstance(raw, Mapping) else None
    if not isinstance(sections_raw, list) or not sections_raw:
        raise _bad("Formularz potrzebuje co najmniej jednej sekcji.")
    try:
        sections = [FormSection.model_validate(s) for s in sections_raw]
    except ValidationError as error:
        raise _bad(_first_validation_message(error)) from error
    check_document(sections)
    return {"sections": [s.model_dump() for s in sections]}


def image_path(form_id: str, token: str) -> str:
    return f"/district-forms/{form_id}/files/{token}"


def with_image_urls(schema: Any, form_id: str, *, public_code: Optional[str] = None) -> Any:
    """Schemat do odpowiedzi: pytanie z tokenem `image` dostaje `image_url` (po przeładowaniu obraz dalej widać)."""
    if not isinstance(schema, Mapping) or not isinstance(schema.get("sections"), list):
        return schema
    sections = []
    for section in schema["sections"]:
        if not isinstance(section, Mapping):
            continue
        items = []
        for q in section.get("questions") or []:
            q = dict(q) if isinstance(q, Mapping) else q
            if isinstance(q, dict) and q.get("image") and _TOKEN.match(str(q["image"])):
                q["image_url"] = (
                    f"/public/forms/{public_code}/files/{q['image']}" if public_code else image_path(form_id, q["image"])
                )
            items.append(q)
        sections.append({**section, "questions": items})
    return {**schema, "sections": sections}


def clean_schema(kind: str, raw: Any) -> Dict[str, Any]:
    return clean_list_schema(raw) if kind == "list" else clean_form_schema(raw)


# --- Trasa ------------------------------------------------------------------


def route(sections: List[FormSection], answers: Mapping[str, Any]) -> List[str]:
    """Sekcje odwiedzone przez ten zestaw odpowiedzi - w kolejności.

    Po sekcji decyduje PIERWSZE pytanie z logiką, na które padła odpowiedź mająca
    regułę; bez takiej - `next` sekcji; bez niego - następna sekcja.
    """
    position = {s.id: i for i, s in enumerate(sections)}
    visited: List[str] = []
    index = 0
    while 0 <= index < len(sections) and sections[index].id not in visited:
        section = sections[index]
        visited.append(section.id)
        goal: Optional[str] = None
        for q in section.questions:
            if q.type not in SINGLE_CHOICE or not q.logic:
                continue
            answer = answers.get(q.id)
            option = answer.get("option") if isinstance(answer, dict) else None
            if isinstance(option, str) and option in q.logic:
                goal = q.logic[option]
                break
        if goal is None:
            goal = section.next
        if goal == END:
            break
        if goal is None or goal not in position or position[goal] <= index:
            index += 1
        else:
            index = position[goal]
    return visited


# --- Odpowiedzi ---------------------------------------------------------------


def pesel_valid(number: str) -> bool:
    """11 cyfr, suma kontrolna i data urodzenia, która istnieje."""
    if not re.fullmatch(r"\d{11}", number):
        return False
    digits = [int(c) for c in number]
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    control = (10 - sum(c * w for c, w in zip(digits, weights)) % 10) % 10
    if control != digits[10]:
        return False
    year, month, day = int(number[0:2]), int(number[2:4]), int(number[4:6])
    for shift, century in ((80, 1800), (0, 1900), (20, 2000), (40, 2100), (60, 2200)):
        if shift < month <= shift + 12:
            try:
                date(century + year, month - shift, day)
                return True
            except ValueError:
                return False
    return False


def phone_valid(number: str) -> bool:
    clean = re.sub(r"[\s\-()]", "", number)
    return re.fullmatch(r"\+?\d{9,15}", clean) is not None


def empty_answer(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, list):
        return len(value) == 0
    if isinstance(value, dict):
        if "options" in value or "option" in value or "other" in value:
            return not value.get("options") and not value.get("option") and not str(value.get("other") or "").strip()
        return all(v in (None, "", []) for v in value.values())
    return False


@dataclass
class Files:
    """token -> czy obraz, dla plików WGRANYCH PRZEZ TĘ OSOBĘ do tego formularza."""

    mine: Dict[str, bool] = field(default_factory=dict)


class AnswerError(ValueError):
    pass


def _num_label(x: float) -> str:
    return str(int(x)) if int(x) == x else str(x).replace(".", ",")


def _answer(q: FormQuestion, value: Any, files: Files) -> Any:
    t = q.type
    if t in TEXTUAL:
        if not isinstance(value, str):
            raise AnswerError("Tu wpisuje się tekst.")
        text = value.strip()
        ceiling = LONG_MAX if t == "long_text" else SHORT_MAX
        if len(text) > ceiling:
            raise AnswerError(f"Odpowiedź może mieć najwyżej {ceiling} znaków.")
        if q.min_length is not None and len(text) < q.min_length:
            raise AnswerError(f"Odpowiedź musi mieć co najmniej {q.min_length} znaków.")
        if q.max_length is not None and len(text) > q.max_length:
            raise AnswerError(f"Odpowiedź może mieć najwyżej {q.max_length} znaków.")
        if t == "email" and not _EMAIL.match(text):
            raise AnswerError("To nie wygląda na adres e-mail.")
        if t == "phone" and not phone_valid(text):
            raise AnswerError("To nie wygląda na numer telefonu.")
        if t == "pesel" and not pesel_valid(text):
            raise AnswerError("Ten PESEL jest niepoprawny - sprawdź cyfry.")
        if t == "postal":
            if not _POSTAL.match(text):
                raise AnswerError("Kod pocztowy ma postać 00-000.")
            text = f"{text[:2]}-{text[-3:]}"
        if t == "short_text" and q.pattern:
            result = pattern_matches(q.pattern, text)
            if result is None:
                raise AnswerError("Nie udało się sprawdzić tej odpowiedzi - wzorzec jest zbyt złożony.")
            if not result:
                raise AnswerError(q.pattern_message or "Odpowiedź nie pasuje do wymaganego formatu.")
        return text

    if t in SINGLE_CHOICE:
        if not isinstance(value, dict):
            raise AnswerError("Wybierz jedną odpowiedź.")
        option = value.get("option")
        if isinstance(option, str):
            if option not in {o.id for o in q.options}:
                raise AnswerError("Takiej odpowiedzi nie ma.")
            return {"option": option}
        other = str(value.get("other") or "").strip()
        if q.other and other:
            if len(other) > SHORT_MAX:
                raise AnswerError(f"Odpowiedź może mieć najwyżej {SHORT_MAX} znaków.")
            return {"other": other}
        raise AnswerError("Wybierz jedną odpowiedź.")

    if t == "multi":
        if not isinstance(value, dict) or not isinstance(value.get("options", []), list):
            raise AnswerError("Zaznacz odpowiedzi.")
        chosen = list(dict.fromkeys(str(x) for x in value.get("options") or []))
        known = {o.id for o in q.options}
        if any(x not in known for x in chosen):
            raise AnswerError("Takiej odpowiedzi nie ma.")
        other = str(value.get("other") or "").strip() if q.other else ""
        if len(other) > SHORT_MAX:
            raise AnswerError(f"Odpowiedź może mieć najwyżej {SHORT_MAX} znaków.")
        count = len(chosen) + (1 if other else 0)
        if q.min_choices is not None and count < q.min_choices:
            raise AnswerError(f"Zaznacz co najmniej {q.min_choices}.")
        if q.max_choices is not None and count > q.max_choices:
            raise AnswerError(f"Zaznacz najwyżej {q.max_choices}.")
        order = {o.id: i for i, o in enumerate(q.options)}
        return {"options": sorted(chosen, key=lambda x: order[x]), "other": other or None}

    if t in ("scale", "rating"):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
            raise AnswerError("Wybierz wartość.")
        low, high = (q.scale_min, q.scale_max) if t == "scale" else (1, q.stars)
        if not low <= int(value) <= high:
            raise AnswerError(f"Wartość musi być od {low} do {high}.")
        return int(value)

    if t == "number":
        if isinstance(value, str):
            try:
                value = float(value.replace(",", ".").strip())
            except ValueError as error:
                raise AnswerError("Tu wpisuje się liczbę.") from error
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value in (float("inf"), float("-inf")):
            raise AnswerError("Tu wpisuje się liczbę.")
        if q.integer and int(value) != value:
            raise AnswerError("Tu wpisuje się liczbę całkowitą.")
        if q.number_min is not None and value < q.number_min:
            raise AnswerError(f"Najmniej: {_num_label(q.number_min)}.")
        if q.number_max is not None and value > q.number_max:
            raise AnswerError(f"Najwięcej: {_num_label(q.number_max)}.")
        return int(value) if int(value) == value else float(value)

    if t == "date":
        if not isinstance(value, str) or not _DATE.match(value):
            raise AnswerError("Wybierz datę.")
        try:
            date.fromisoformat(value)
        except ValueError as error:
            raise AnswerError("Takiej daty nie ma.") from error
        return value
    if t == "time":
        if not isinstance(value, str) or not _TIME.match(value):
            raise AnswerError("Wybierz godzinę.")
        return value
    if t == "datetime":
        if not isinstance(value, str) or not _DATETIME.match(value):
            raise AnswerError("Wybierz datę i godzinę.")
        try:
            datetime.fromisoformat(value)
        except ValueError as error:
            raise AnswerError("Takiej daty nie ma.") from error
        return value

    if t == "file":
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise AnswerError("Dołącz plik.")
        tokens = list(dict.fromkeys(value))
        if len(tokens) > q.max_files:
            raise AnswerError(f"Najwyżej {q.max_files} plików.")
        for token in tokens:
            if not _TOKEN.match(token) or token not in files.mine:
                raise AnswerError("Tego pliku nie ma - dołącz go jeszcze raz.")
            if q.accept == "image" and not files.mine[token]:
                raise AnswerError("Tu można dołączyć tylko zdjęcie.")
        return tokens

    if t == "grid":
        if not isinstance(value, dict):
            raise AnswerError("Zaznacz odpowiedź w każdym wierszu.")
        rows = {r.id for r in q.rows}
        cols = {c.id for c in q.columns}
        clean: Dict[str, Any] = {}
        for row, picked in value.items():
            if row not in rows:
                raise AnswerError("Takiego wiersza nie ma.")
            if q.grid_multi:
                listed = picked if isinstance(picked, list) else []
                if any(k not in cols for k in listed):
                    raise AnswerError("Takiej kolumny nie ma.")
                if listed:
                    clean[row] = list(dict.fromkeys(listed))
            else:
                if picked is None:
                    continue
                if picked not in cols:
                    raise AnswerError("Takiej kolumny nie ma.")
                clean[row] = picked
        if q.required and set(clean) != rows:
            raise AnswerError("Zaznacz odpowiedź w każdym wierszu.")
        return clean

    raise AnswerError("Nieznany rodzaj pytania.")  # pragma: no cover


def check_answers(
    sections: List[FormSection],
    answers: Mapping[str, Any],
    *,
    files: Optional[Files] = None,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """(oczyszczone odpowiedzi, błędy pytanie -> zdanie). Pusty słownik błędów = w porządku."""
    files = files or Files()
    on_route = set(route(sections, answers))
    clean: Dict[str, Any] = {}
    errors: Dict[str, str] = {}
    for section in sections:
        if section.id not in on_route:
            continue
        for q in section.questions:
            value = answers.get(q.id)
            if empty_answer(value):
                if q.required:
                    errors[q.id] = "To pytanie jest obowiązkowe."
                continue
            try:
                clean[q.id] = _answer(q, value, files)
            except AnswerError as error:
                errors[q.id] = str(error)
    return clean, errors


def answer_text(q: FormQuestion, value: Any, file_name: Optional[Callable[[str], str]] = None) -> str:
    """Odpowiedź jako napis do komórki arkusza. Pusta -> pusty napis."""
    if value is None:
        return ""
    labels = {o.id: o.label for o in q.options}
    if q.type in SINGLE_CHOICE:
        if isinstance(value, dict):
            if value.get("option") in labels:
                return labels[value["option"]]
            if value.get("other"):
                return f"Inne: {value['other']}"
        return ""
    if q.type == "multi" and isinstance(value, dict):
        parts = [labels.get(x, "") for x in value.get("options") or []]
        if value.get("other"):
            parts.append(f"Inne: {value['other']}")
        return "; ".join(p for p in parts if p)
    if q.type == "file" and isinstance(value, list):
        return "; ".join(file_name(x) if file_name else x for x in value)
    if q.type == "grid" and isinstance(value, dict):
        cols = {c.id: c.label for c in q.columns}
        rows = {r.id: r.label for r in q.rows}
        parts = []
        for r in q.rows:
            v = value.get(r.id)
            if v is None:
                continue
            shown = ", ".join(cols.get(x, "") for x in v) if isinstance(v, list) else cols.get(v, "")
            parts.append(f"{rows[r.id]}: {shown}")
        return "; ".join(parts)
    if isinstance(value, float):
        return _num_label(value)
    return str(value)


# --- Wyniki zbiorczo (port `form_stats.py`) -----------------------------------

#: Rodzaje pytań, które z natury niosą dane osobowe - poza widokiem zbiorczym całkowicie.
PERSONAL = frozenset({"email", "phone", "pesel", "postal", "file", "date", "datetime"})


def _blank(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def median(numbers: List[float]) -> Optional[float]:
    if not numbers:
        return None
    ordered = sorted(numbers)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def _choice_stat(q: FormQuestion, present: List[Any]) -> Dict[str, Any]:
    counter = {o.id: 0 for o in q.options}
    answered = other = 0
    for value in present:
        if not isinstance(value, dict):
            continue
        chosen = value.get("options") if isinstance(value.get("options"), list) else (
            [value["option"]] if isinstance(value.get("option"), str) else []
        )
        text = str(value.get("other") or "").strip()
        if not chosen and not text:
            continue
        answered += 1
        for x in chosen:
            if x in counter:
                counter[x] += 1
        if text:
            other += 1
    return {
        "kind": "choice",
        "answered": answered,
        "multi": q.type == "multi",
        "options": [
            {"id": o.id, "label": o.label, "count": counter[o.id], "share": counter[o.id] / answered if answered else 0.0}
            for o in q.options
        ],
        "other_count": other,
    }


def _scale_stat(q: FormQuestion, present: List[Any]) -> Dict[str, Any]:
    low, high = (q.scale_min, q.scale_max) if q.type == "scale" else (1, q.stars)
    values = [int(v) for v in present if isinstance(v, (int, float)) and not isinstance(v, bool) and low <= v <= high]
    counts = Counter(values)
    return {
        "kind": "scale",
        "answered": len(values),
        "buckets": [{"value": v, "count": counts.get(v, 0)} for v in range(low, high + 1)],
        "average": sum(values) / len(values) if values else None,
        "max": high,
        "stars": q.type == "rating",
    }


def _number_stat(present: List[Any]) -> Dict[str, Any]:
    numbers = [float(v) for v in present if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return {
        "kind": "number",
        "answered": len(numbers),
        "average": sum(numbers) / len(numbers) if numbers else None,
        "median": median(numbers),
        "min": min(numbers) if numbers else None,
        "max": max(numbers) if numbers else None,
    }


def _grid_stat(q: FormQuestion, present: List[Any]) -> Dict[str, Any]:
    cells = {r.id: {c.id: 0 for c in q.columns} for r in q.rows}
    answered = 0
    for value in present:
        if not isinstance(value, dict):
            continue
        anything = False
        for r in q.rows:
            v = value.get(r.id)
            chosen = v if isinstance(v, list) else [v] if isinstance(v, str) else []
            for k in chosen:
                if k in cells[r.id]:
                    cells[r.id][k] += 1
                    anything = True
        answered += 1 if anything else 0
    return {
        "kind": "grid",
        "answered": answered,
        "rows": [
            {"id": r.id, "label": r.label, "cells": [{"id": c.id, "label": c.label, "count": cells[r.id][c.id]} for c in q.columns]}
            for r in q.rows
        ],
    }


def question_stat(q: FormQuestion, answers: List[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Zbiorczy wynik jednego pytania albo None - pytanie z danymi osobowymi."""
    if q.type in PERSONAL:
        return None
    present = [a.get(q.id) for a in answers if not _blank(a.get(q.id))]
    if q.type in CHOICE:
        result = _choice_stat(q, present)
    elif q.type in ("scale", "rating"):
        result = _scale_stat(q, present)
    elif q.type == "number":
        result = _number_stat(present)
    elif q.type == "grid":
        result = _grid_stat(q, present)
    elif q.type == "time":
        counts = Counter(v for v in present if isinstance(v, str))
        result = {
            "kind": "values",
            "answered": sum(counts.values()),
            "values": [{"value": v, "count": n} for v, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))],
        }
    else:  # short_text, long_text - sama liczba (w wolnym polu ludzie wpisują dane osobowe)
        result = {"kind": "text", "answered": sum(1 for v in present if isinstance(v, str) and v.strip())}
    return {"question_id": q.id, **result}


def aggregate(sections: List[FormSection], answers: List[Mapping[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """(wyniki pytań, numery pytań ukrytych jako dane osobowe)."""
    results: List[Dict[str, Any]] = []
    hidden: List[str] = []
    for q in questions(sections):
        stat = question_stat(q, answers)
        if stat is None:
            hidden.append(q.id)
        else:
            results.append(stat)
    return results, hidden
