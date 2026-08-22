"""Rejestr pól współdzielonych meczu ProEl.

Overlay (`proel_match_state.fields_json`) jest źródłem prawdy dla ścieżek
zdefiniowanych tutaj. `proel_matches.data_json` jest widokiem POCHODNYM:
przy każdym zapisie serwer nakłada overlay z powrotem na blob w tej samej
transakcji, także wtedy, gdy blob przyszedł ze starej wersji aplikacji, która
o overlayu nic nie wie.

To jest jedyny powód, dla którego potwierdzenie badań zrobione przez sędziego
na jednym telefonie nie znika, gdy telefon prowadzącego mecz wysyła swój pełny
snapshot co 60 sekund (`MatchScreen.services.ts`).

Odpowiednik po stronie aplikacji: `BAZA/utils/proelFields.ts`.
Ranking badań MUSI się zgadzać z `BAZA/utils/playerExam.ts` i z kolorami
protokołu w `app/results.py`.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─────────────────────────── fazy ───────────────────────────

PHASE_PRE = "pre"
PHASE_LIVE = "live"
PHASE_POST = "post"
PHASE_LOCKED = "locked"

ALL_PHASES = (PHASE_PRE, PHASE_LIVE, PHASE_POST)

# ─────────────────────────── role ───────────────────────────

ROLE_REFEREE1 = "referee1"
ROLE_REFEREE2 = "referee2"
ROLE_SECRETARY = "secretary"
ROLE_TIMEKEEPER = "timekeeper"
ROLE_DELEGATE = "delegate"

ALL_ROLES = frozenset(
    {ROLE_REFEREE1, ROLE_REFEREE2, ROLE_SECRETARY, ROLE_TIMEKEEPER, ROLE_DELEGATE}
)
FIELD_REFS = frozenset({ROLE_REFEREE1, ROLE_REFEREE2, ROLE_DELEGATE})

# ───────────────────── badania: krata wartości ─────────────────────
# none < manual < wzpr < zprp. Kolejność jest istotna: status z API ZPRP
# zawsze wygrywa z potwierdzeniem ręcznym (patrz `applyManualExam`).
EXAM_RANK: Dict[str, int] = {"none": 0, "manual": 1, "wzpr": 2, "zprp": 3}
EXAM_FROM_API = ("zprp", "wzpr")


def exam_rank(mark: Any) -> int:
    return EXAM_RANK.get(str(mark or "none"), 0)


# ─────────────────────── normalizacja nazwisk ───────────────────────
# Port `normalizeName` z BAZA/utils/matchRole.ts — musi dawać ten sam wynik,
# bo po tym kluczu dopasowujemy zawodnika przy projekcji.


def normalize_name(s: Any) -> str:
    txt = unicodedata.normalize("NFKD", str(s or ""))
    txt = "".join(ch for ch in txt if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", txt).strip().lower()


# ─────────────────────────── wyjątki ───────────────────────────


class PathRejected(Exception):
    """Odrzucenie POJEDYNCZEJ operacji — reszta patcha idzie dalej."""

    def __init__(self, code: str, message: str, current: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.current = current


class UnknownPath(Exception):
    def __init__(self, path: str):
        super().__init__(f"Nieznana ścieżka: {path}")
        self.path = path


# ─────────────────────────── specyfikacja pola ───────────────────────────

MergeFn = Callable[[Optional[dict], Any, bool], Any]
ProjectFn = Callable[[dict, Dict[str, str], Any], None]


@dataclass(frozen=True)
class FieldSpec:
    name: str
    pattern: re.Pattern
    phases: Tuple[str, ...]
    roles: frozenset
    merge: MergeFn
    project: ProjectFn
    #: gdy True, zapis o wartości identycznej z seedem nie tworzy wpisu
    skip_if_equals_seed: bool = False


# ─────────────────────────── reguły scalania ───────────────────────────


def merge_exam(existing: Optional[dict], incoming: Any, force: bool) -> Any:
    """Krata: wygrywa wyższy stopień. Obniżenie wymaga `force`.

    Dzięki temu dwa telefony potwierdzające tego samego zawodnika dają ten sam
    wynik niezależnie od kolejności, a ponowienie z outboxa jest nieszkodliwe.
    Cofnięcie potwierdzenia jest świadomym gestem, więc niesie `force`.
    """
    mark = str((incoming or {}).get("mark") or "none")
    if mark not in EXAM_RANK:
        raise PathRejected("BAD_VALUE", f"Nieznany status badań: {mark}")
    if existing is None:
        return incoming
    prev = str((existing.get("v") or {}).get("mark") or "none")
    if exam_rank(mark) >= exam_rank(prev) or force:
        return incoming
    raise PathRejected(
        "STALE_VALUE",
        "Nowsze potwierdzenie jest wyższego stopnia — pomijam obniżenie.",
        existing.get("v"),
    )


def merge_lww(existing: Optional[dict], incoming: Any, force: bool) -> Any:
    return incoming


def merge_write_once(existing: Optional[dict], incoming: Any, force: bool) -> Any:
    """Podpisu nie nadpisujemy po cichu — to dokument, nie pole formularza."""
    if existing is None or force:
        return incoming
    prev = existing.get("v")
    if prev in (None, "", incoming):
        return incoming
    raise PathRejected(
        "SIGNATURE_EXISTS",
        "Podpis jest już złożony. Aby go zmienić, usuń poprzedni.",
        prev,
    )


# ─────────────────────────── projekcja overlay → blob ───────────────────────────


def _cfg(blob: dict) -> dict:
    mc = blob.get("matchConfig")
    if not isinstance(mc, dict):
        mc = {}
        blob["matchConfig"] = mc
    return mc


def _extras(blob: dict) -> dict:
    cfg = _cfg(blob)
    ex = cfg.get("extras")
    if not isinstance(ex, dict):
        ex = {}
        cfg["extras"] = ex
    return ex


def _cards(blob: dict, team: str) -> Optional[list]:
    cfg = _cfg(blob)
    cards = cfg.get(f"{team}PlayerCards")
    return cards if isinstance(cards, list) else None


def project_exam(blob: dict, params: Dict[str, str], value: Any) -> None:
    """Wstaw status badań do właściwej karty zawodnika.

    Dopasowanie NAJPIERW po znormalizowanym nazwisku, potem po numerze —
    zmiana numeru koszulki między zgłoszeniem a meczem nie może gubić
    potwierdzenia (a numery bywają zmieniane tuż przed gwizdkiem).

    Karty NIE tworzymy: jeśli zawodnika nie ma w blobie, nie ma czego oznaczać.
    Wpis w overlayu zostaje i zaprojektuje się, gdy skład dojdzie.
    """
    team = params["team"]
    cards = _cards(blob, team)
    if not cards:
        return

    mark = str((value or {}).get("mark") or "none")
    want_name = normalize_name((value or {}).get("name"))
    want_num = params.get("num")

    target = None
    if want_name:
        for c in cards:
            if isinstance(c, dict) and normalize_name(c.get("fullName")) == want_name:
                target = c
                break
    if target is None and want_num is not None:
        for c in cards:
            if isinstance(c, dict) and str(c.get("number")) == str(want_num):
                target = c
                break
    if target is None:
        return

    # Status z API ZPRP/WZPR zawsze wygrywa — ręcznie da się tylko uzupełnić
    # brak. To jest dokładnie `applyManualExam` z BAZA/utils/playerExam.ts.
    current = str(target.get("exam") or "none")
    if current in EXAM_FROM_API:
        return
    if mark == "none":
        target.pop("exam", None)  # "none" nie jest zapisywane na karcie
    else:
        target["exam"] = mark


def project_team_signature(blob: dict, params: Dict[str, str], value: Any) -> None:
    _extras(blob)[f"{params['team']}TeamSignature"] = value


def project_official(blob: dict, params: Dict[str, str], value: Any) -> None:
    ex = _extras(blob)
    officials = ex.get("officials")
    if not isinstance(officials, dict):
        officials = {}
        ex["officials"] = officials
    person = officials.get(params["role"])
    if not isinstance(person, dict):
        person = {}
        officials[params["role"]] = person
    person[params["leaf"]] = value


def project_companion(blob: dict, params: Dict[str, str], value: Any) -> None:
    """Wstaw pole osoby towarzyszącej do `matchConfig.{team}Companions`.

    Lista jest kluczowana literą A–E, a nie pozycją w tablicy: kolejność
    wpisów w blobie bywa różna między klientami, a litera jest tym, co widzi
    sędzia w protokole. Brakujący wpis DOTWORZYMY — inaczej dopisanie osoby
    towarzyszącej w trakcie meczu przepadałoby do czasu, aż prowadzący wyśle
    pełny snapshot (a to jest dokładnie sytuacja, dla której ta ścieżka
    powstała).
    """
    cfg = _cfg(blob)
    key = f"{params['team']}Companions"
    arr = cfg.get(key)
    if not isinstance(arr, list):
        arr = []
        cfg[key] = arr

    cid = params["id"]
    target = None
    for c in arr:
        if isinstance(c, dict) and str(c.get("id")) == cid:
            target = c
            break
    if target is None:
        target = {"id": cid}
        arr.append(target)

    target[params["leaf"]] = value


def project_extras_field(key: str) -> ProjectFn:
    def _p(blob: dict, params: Dict[str, str], value: Any) -> None:
        _extras(blob)[key] = value

    return _p


def project_cfg_field(key: str) -> ProjectFn:
    def _p(blob: dict, params: Dict[str, str], value: Any) -> None:
        _cfg(blob)[key] = value

    return _p


# ─────────────────────────── rejestr ───────────────────────────
#
# ŚWIADOMIE POMINIĘTE na tym etapie: `roster.*`. Wspólna edycja składu wymaga
# OR-setu i reguły supersede po gwizdku (dochodzą dodania i usunięcia numerów);
# zanim to wejdzie, skład zostaje tam, gdzie jest dzisiaj (blob prowadzącego).
# Nieznana ścieżka jest odrzucana z 422, więc dołożenie go później nic nie psuje.
#
# `companion.*` NIE wymaga OR-setu i dlatego wchodzi wcześniej: to pięć STAŁYCH
# rubryk A–E, a nie zbiór o zmiennej liczności. Każda litera jest osobnym
# kluczem, więc dwóch sędziów wypełniających różne rubryki nigdy nie koliduje,
# a konflikt na tej samej rubryce rozstrzyga LWW — dokładnie jak przy
# `official.*`, które ma identyczny kształt (rola → liść).

_POST_EXTRAS = {
    "spectatorsCount": "spectatorsCount",
    "venueCapacity": "venueCapacity",
    "eventRegistration": "eventRegistration",
    "detailedRefereeNotes": "detailedRefereeNotes",
    "extraReport": "extraReport",
    "notesText": "detailedRefereeNotesText",
    # Znacznik „pełne dane meczu poszły do bazy związku".
    #
    # Wartość jest nieistotna (True) - całą treść niesie sam wpis overlaya:
    # `by` mówi KTO, `at` mówi KIEDY. To jest dokładnie ta informacja, której
    # brakowało sędziemu wracającemu do meczu na drugim telefonie: bez niej
    # ekran pokazywał zadanie jako niezrobione i namawiał do wysłania składu
    # drugi raz.
    "fullDataSent": "fullDataSent",
    # Znacznik „protokół PDF leży w załącznikach meczu".
    #
    # Ta sama konstrukcja i ten sam powód co wyżej. ZPRP nie oddaje listy
    # załączników żadnym endpointem GET, więc bez tego wpisu drugi telefon (i
    # ten sam telefon po powrocie z autozapisu) nie ma skąd wiedzieć, że
    # protokół już tam jest - a wysłany drugi raz zostaje przy meczu jako
    # drugi plik.
    "protocolSent": "protocolSent",
}

_CFG_FIELDS = {
    "referee1": "referee1",
    "referee2": "referee2",
    "delegate": "delegate",
    "timekeeper": "timekeeper",
    "secretary": "secretary",
    "venueAddress": "venueAddress",
}


def _build_registry() -> List[FieldSpec]:
    specs: List[FieldSpec] = [
        FieldSpec(
            name="exam",
            pattern=re.compile(r"^exam\.(?P<team>host|guest)\.#(?P<num>\d{1,3})$"),
            phases=ALL_PHASES,  # także w LIVE: spóźniony zawodnik w przerwie
            roles=ALL_ROLES,  # stolikowy robi to dziś w ekranie konfiguracji
            merge=merge_exam,
            project=project_exam,
        ),
        FieldSpec(
            name="team_signature",
            pattern=re.compile(r"^sig\.team\.(?P<team>host|guest)$"),
            phases=(PHASE_PRE, PHASE_POST),
            roles=ALL_ROLES,
            merge=merge_write_once,
            project=project_team_signature,
        ),
        FieldSpec(
            name="official",
            pattern=re.compile(
                r"^official\.(?P<role>referee1|referee2|secretary|timekeeper|delegate)"
                r"\.(?P<leaf>fullName|city|signature)$"
            ),
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            merge=merge_write_once,
            project=project_official,
        ),
        FieldSpec(
            name="companion",
            pattern=re.compile(
                r"^companion\.(?P<team>host|guest)\.(?P<id>[A-E])"
                r"\.(?P<leaf>fullName|function|license)$"
            ),
            # Także w LIVE: osoby towarzyszące dopisuje się i poprawia w trakcie
            # meczu (spóźniony trener, korekta licencji) — to był główny powód,
            # dla którego ta ścieżka powstała.
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            merge=merge_lww,
            project=project_companion,
        ),
    ]

    for key, extras_key in _POST_EXTRAS.items():
        specs.append(
            FieldSpec(
                name=f"post.{key}",
                pattern=re.compile(rf"^post\.{re.escape(key)}$"),
                phases=(PHASE_PRE, PHASE_POST)
                if key in ("venueCapacity", "notesText")
                else (PHASE_POST,),
                roles=ALL_ROLES,
                merge=merge_lww,
                project=project_extras_field(extras_key),
            )
        )

    for key, cfg_key in _CFG_FIELDS.items():
        specs.append(
            FieldSpec(
                name=f"cfg.{key}",
                pattern=re.compile(rf"^cfg\.{re.escape(key)}$"),
                phases=(PHASE_PRE, PHASE_POST),
                roles=FIELD_REFS,
                merge=merge_lww,
                project=project_cfg_field(cfg_key),
                skip_if_equals_seed=True,
            )
        )

    # extras.matchDate / matchTime siedzą w `extras`, nie w `matchConfig`.
    for key, extras_key in (("matchDate", "matchDate"), ("matchTime", "matchTime")):
        specs.append(
            FieldSpec(
                name=f"cfg.{key}",
                pattern=re.compile(rf"^cfg\.{re.escape(key)}$"),
                phases=(PHASE_PRE, PHASE_POST),
                roles=FIELD_REFS,
                merge=merge_lww,
                project=project_extras_field(extras_key),
                skip_if_equals_seed=True,
            )
        )

    return specs


FIELD_REGISTRY: List[FieldSpec] = _build_registry()


def parse_path(path: str) -> Tuple[FieldSpec, Dict[str, str]]:
    """Ścieżka → (specyfikacja, parametry). Nieznana ścieżka to błąd, nie zapis.

    Zamknięty rejestr jest tu świadomy: gdyby przyjmować dowolny JSON-pointer,
    ten endpoint pozwalałby nadpisać dowolne pole dowolnego meczu.
    """
    p = str(path or "").strip()
    for spec in FIELD_REGISTRY:
        m = spec.pattern.match(p)
        if m:
            return spec, m.groupdict()
    raise UnknownPath(p)


def project(overlay: Dict[str, Any], blob: dict) -> dict:
    """Nałóż CAŁY overlay na blob. Idempotentne — wołane przy każdym zapisie."""
    if not isinstance(blob, dict) or not overlay:
        return blob
    for path, entry in overlay.items():
        if not isinstance(entry, dict) or entry.get("superseded_at"):
            continue
        try:
            spec, params = parse_path(path)
        except UnknownPath:
            continue  # wpis z nowszej wersji serwera — zostawiamy nietknięty
        try:
            spec.project(blob, params, entry.get("v"))
        except Exception:  # noqa: BLE001 — projekcja nie może wywrócić zapisu
            continue
    return blob


# ─────────────────────────── wykrywanie fazy LIVE ───────────────────────────


def live_signal(blob: Any) -> bool:
    """Czy ten blob dowodzi, że mecz się już zaczął?

    Potrzebne, bo stara wersja aplikacji nie zna leasingu i nigdy nie zawoła
    `/lease`. Bez tego mecz prowadzony ze starego telefonu zostałby na zawsze
    w fazie „pre", a przedmeczowe pola dalej dałoby się nadpisywać.
    """
    if not isinstance(blob, dict):
        return False
    if blob.get("isGameRunning") is True:
        return True
    if blob.get("isFirstHalf") is False:
        return True
    if blob.get("penaltyShootoutActive") is True:
        return True
    try:
        if float(blob.get("mainTime") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    for key in ("scoreHost", "scoreGuest"):
        try:
            if int(blob.get(key) or 0) > 0:
                return True
        except (TypeError, ValueError):
            pass
    for key in ("protocol", "goalHistory"):
        v = blob.get(key)
        if isinstance(v, list) and len(v) > 0:
            return True
    return False
