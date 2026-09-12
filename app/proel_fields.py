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

#: Próg badań w rozgrywce: „any" - wystarcza każde potwierdzenie, „zprp" -
#: WZPR nie uprawnia do gry. Który mecz ma który próg, mówi
#: `app/protocol_category.exam_requirement_for_code`; bliźniak reguły stoi
#: w `BAZA/utils/playerExam.ts` (`examMeetsRequirement`).
EXAM_REQUIREMENT_ANY = "any"
EXAM_REQUIREMENT_ZPRP = "zprp"


def exam_mark_meets(mark: Any, requirement: str = EXAM_REQUIREMENT_ANY) -> bool:
    """Czy badania tego stopnia wystarczają w rozgrywce o takim progu.

    Krata `EXAM_RANK` zostaje bez zmian: `wzpr` jest w niej WYŻEJ niż
    `manual`, bo to prawda o tym, kto potwierdził badania. Próg jest osobnym
    pytaniem - o prawo gry - i dlatego nie mieszamy go do rangi.
    """
    m = str(mark or "none").strip().lower()
    if m in ("zprp", "manual"):
        return True
    return m == "wzpr" and requirement != EXAM_REQUIREMENT_ZPRP
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


def phase_of(state: Optional[Dict[str, Any]], status_value: Any) -> str:
    """Faza meczu - jedna reguła dla całego systemu.

    Mieszkała w `app/proel.py`, ale pyta o nią też awans badań (który wolno
    robić wyłącznie PRZED pierwszym gwizdkiem), a stamtąd nie ma jak jej
    zaimportować bez cyklu.
    """
    if status_value == "approved":
        return PHASE_LOCKED
    if status_value == "finished":
        return PHASE_POST
    if state and state.get("live_started_at") is not None:
        return PHASE_LIVE
    return PHASE_PRE


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
    """Podpisu nie nadpisujemy po cichu — to dokument, nie pole formularza.

    Reguła dotyczy WYŁĄCZNIE podpisów. Objęte nią były przez pomyłkę także
    nazwisko i miejscowość obsady, bo wszystkie trzy liście siedziały w jednej
    specyfikacji ścieżki. Skutek: dopisany raz delegat nie dawał się już ani
    poprawić, ani skasować, a sędzia dostawał przy tym komunikat o podpisie -
    o którym nie było mowy, bo poprawiał nazwisko.
    """
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


def project_medic(blob: dict, params: Dict[str, str], value: Any) -> None:
    """Wstaw pole medyka do `matchConfig.extras.medic`.

    Kształt jest taki sam jak u oficjeli (jedna osoba, kilka liści), tylko
    bez roli w kluczu - medyk jest jeden.
    """
    ex = _extras(blob)
    medic = ex.get("medic")
    if not isinstance(medic, dict):
        medic = {}
        ex["medic"] = medic
    medic[params["leaf"]] = value


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
    # Znacznik „wynik skrócony jest w bazie związku".
    #
    # Ten sam kłopot co niżej, tylko starszy: ślad po wysyłce leżał wyłącznie w
    # pliku na telefonie, więc drugi telefon - i to samo konto ProEl po
    # przelogowaniu - pokazywał przystanek „Wyślij wynik skrócony" jako
    # nietknięty. API związku nie oddaje informacji „czy już zapisano", a
    # ponowna wysyłka jest wprawdzie bezpieczna, tylko zupełnie zbędna.
    "shortResultSent": "shortResultSent",
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
    # Znacznik „zgłoszenie wyniku SMS-em zostało otwarte".
    #
    # Ostatni z czterech przystanków pomeczowych, który tego znacznika nie miał:
    # ślad leżał wyłącznie w pliku na telefonie, więc sędzia boiskowy wchodzący
    # na SWOIM urządzeniu widział „Wyślij wynik SMS-em" jako nietknięte, choć
    # stolikowy wysłał wiadomość godzinę wcześniej - i wysyłał drugi raz.
    #
    # Ponowna wysyłka nikomu nie szkodzi (to wiadomość, nie zapis w bazie), więc
    # ten wpis niczego nie blokuje. Ma tylko przestać namawiać do zbędnej roboty
    # i pokazać, KTO oraz KIEDY to zrobił.
    "smsSent": "smsSent",
}

_CFG_FIELDS = {
    "referee1": "referee1",
    "referee2": "referee2",
    "delegate": "delegate",
    "delegate2": "delegate2",
    "timekeeper": "timekeeper",
    "secretary": "secretary",
    "venueAddress": "venueAddress",
}

#: Pola konfiguracji, które wypełnia KTOKOLWIEK z obsady — nie tylko sędziowie.
#:
#: Kolory koszulek ustala się przy stoliku, razem z resztą ustawień meczu, i robi
#: to zwykle sekretarz albo mierzący czas. `FIELD_REFS` — właściwe dla nagłówka
#: protokołu obok — odbiłby im ten zapis, a odmowa byłaby CICHA: kolor i tak
#: wszedłby do bloba, tylko poza rejestrem, czyli dokładnie w stan, w którym
#: ginie przy pełnym zapisie z drugiego urządzenia. Tak działo się do tej pory.
#:
#: `ALL_PHASES`, bo źle wybrany kolor poprawia się wtedy, kiedy się to zauważy —
#: a zauważa się po pierwszym gwizdku, gdy obie drużyny wybiegną na boisko.
_CFG_OPEN_FIELDS = {
    "hostJerseyColor": "hostJerseyColor",
    "guestJerseyColor": "guestJerseyColor",
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
            # ALL_PHASES, tak samo jak `official_signature` obok. Wcześniejsze
            # (PRE, POST) było przeoczeniem, nie regułą: podpis osoby
            # odpowiedzialnej bywa zbierany w przerwie (spóźniony kierownik,
            # zmiana osoby na ławce), a odmowa w fazie LIVE nie chroniła
            # niczego - podpis i tak lądował w blobie telefonu. Zostawał tylko
            # POZA rejestrem, czyli dokładnie w tym stanie, w którym kasował go
            # pełny zapis z drugiego urządzenia.
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            merge=merge_write_once,
            project=project_team_signature,
        ),
        FieldSpec(
            name="official_signature",
            pattern=re.compile(
                r"^official\.(?P<role>referee1|referee2|secretary|timekeeper|delegate|delegate2)"
                r"\.(?P<leaf>signature)$"
            ),
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            merge=merge_write_once,
            project=project_official,
        ),
        FieldSpec(
            name="official",
            pattern=re.compile(
                r"^official\.(?P<role>referee1|referee2|secretary|timekeeper|delegate|delegate2)"
                r"\.(?P<leaf>fullName|city)$"
            ),
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            # Nazwisko i miejscowość to pola formularza: wpisuje się je, poprawia
            # i kasuje. Zapis jednokrotny (ten od podpisów) zamykał je po
            # pierwszym wpisaniu - delegata dopisanego w hali nie dało się już
            # usunąć, a mecz zostawał „meczem z delegatem" na zawsze.
            merge=merge_lww,
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
        # ── medyk ──────────────────────────────────────────────────────────
        #
        # Do tej pory medyk jechał WYŁĄCZNIE w blobie prowadzącego. Skutek był
        # taki sam jak przy każdym polu spoza rejestru: drugie urządzenie
        # wysyłało swój pełny snapshot, w którym medyka nie było, reprojekcja
        # nie miała czego nałożyć z powrotem i dane po prostu znikały z ProEla
        # - mimo że na telefonie, który je wpisał, leżały nietknięte.
        #
        # Podpis ma osobną specyfikację, bo rządzi się inną regułą: zapis
        # jednokrotny, tak jak wszystkie pozostałe podpisy. Nazwisko, numer
        # licencji i rola to zwykłe pola formularza - poprawia się je i kasuje,
        # więc idą przez LWW (patrz `official`, gdzie ten sam podział powstał
        # po tym, jak write-once zabetonował dopisanego delegata).
        FieldSpec(
            name="medic_signature",
            pattern=re.compile(r"^medic\.(?P<leaf>signature)$"),
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            merge=merge_write_once,
            project=project_medic,
        ),
        FieldSpec(
            name="medic",
            pattern=re.compile(r"^medic\.(?P<leaf>fullName|number|role)$"),
            phases=ALL_PHASES,
            roles=ALL_ROLES,
            merge=merge_lww,
            project=project_medic,
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

    # Nagłówek protokołu - obsada, hala, data i godzina - jest edytowalny we
    # WSZYSTKICH fazach, także w LIVE.
    #
    # Stało tu wcześniej `(PRE, POST)` i wyglądało to na ostrożność, a było
    # dziurą: te same nazwiska mają DRUGĄ ścieżkę - `official.*` z
    # `ALL_PHASES` - więc w trakcie meczu dawało się je poprawić z ekranu
    # finalizacji, a nie dawało z ekranu konfiguracji. Blokada niczego nie
    # chroniła; zamykała wyłącznie ten ekran, na którym ludzie to robią.
    #
    # A robi się to właśnie w trakcie: sędzia nie dojechał i ktoś wchodzi za
    # niego, delegat dopisuje się w przerwie, adres hali przyszedł z ZPRP
    # błędny i widać to dopiero na miejscu. Kto ma prawo zmieniać, pilnuje
    # nadal `roles=FIELD_REFS`, a zbieg dwóch poprawek rozstrzyga `merge_lww`.
    for key, cfg_key in _CFG_FIELDS.items():
        specs.append(
            FieldSpec(
                name=f"cfg.{key}",
                pattern=re.compile(rf"^cfg\.{re.escape(key)}$"),
                phases=ALL_PHASES,
                roles=FIELD_REFS,
                merge=merge_lww,
                project=project_cfg_field(cfg_key),
                skip_if_equals_seed=True,
            )
        )

    for key, cfg_key in _CFG_OPEN_FIELDS.items():
        specs.append(
            FieldSpec(
                name=f"cfg.{key}",
                pattern=re.compile(rf"^cfg\.{re.escape(key)}$"),
                phases=ALL_PHASES,
                roles=ALL_ROLES,
                merge=merge_lww,
                project=project_cfg_field(cfg_key),
            )
        )

    # extras.matchDate / matchTime siedzą w `extras`, nie w `matchConfig`.
    # Ta sama reguła i ten sam powód co wyżej: faktyczna godzina pierwszego
    # gwizdka bywa poprawiana dopiero wtedy, gdy mecz już trwa.
    for key, extras_key in (("matchDate", "matchDate"), ("matchTime", "matchTime")):
        specs.append(
            FieldSpec(
                name=f"cfg.{key}",
                pattern=re.compile(rf"^cfg\.{re.escape(key)}$"),
                phases=ALL_PHASES,
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


# ─────────────────────────── odmowa po ludzku ───────────────────────────


_PHASE_WORDS = {
    PHASE_PRE: "przed meczem",
    PHASE_LIVE: "w trakcie meczu",
    PHASE_POST: "po zakończeniu meczu",
}


def phase_refusal(spec: FieldSpec) -> str:
    """Zdanie dla sędziego: KIEDY wolno zmienić to pole.

    Odmowa brzmiała dotąd „(faza: live)" - słowem z kodu, nie z hali. Reguła,
    która kogoś zatrzymuje, ma się wytłumaczyć jego językiem.
    """
    words = [_PHASE_WORDS[p] for p in ALL_PHASES if p in spec.phases]
    if not words:
        return "Tego pola nie da się już zmienić."
    if len(words) == 1:
        return f"To pole wypełnia się {words[0]}."
    return "To pole zmienia się " + " albo ".join(words) + "."


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


# ─────────── badania: co mówi baza związku i co przysłał blob ───────────
#
# Trzy pytania, wszystkie bez bazy i bez sieci (spięcie jest w `proel_exams`):
#
#  * jaki status badań daje rekord zawodnika z `pokaz_mecze_szczegoly.php`
#    (bliźniak `parseExamMarkFromRoster` z BAZA/utils/playerExam.ts),
#  * które ręczne potwierdzenia przyszły W BLOBIE, a overlay o nich nie wie -
#    ekran konfiguracji zapisuje badania wyłącznie w kartach zawodników, więc
#    takie potwierdzenie nie zostawiało śladu ani w overlayu, ani w dzienniku
#    (SK/5, GAKIDOVA nr 77: ręczny ptaszek bez wpisu „kto i kiedy"),
#  * które ręczne potwierdzenia baza związku ma już jako „OK" - to jest awans
#    `manual -> zprp/wzpr`, który krata dopuszcza od zawsze, a nikt go nie robił.

#: Wartości `badania_ZPRP` / `badania_WZPR` znaczące „OK". Szersze niż to, co
#: API wysyła dziś, z tego samego powodu, co po stronie aplikacji.
EXAM_OK_TOKENS = frozenset({"OK", "TAK", "1", "T", "Y", "YES"})

#: Skąd wziął się wpis badań w overlayu (`src`). `patch` stawia trasa
#: `/proel/patch`; te dwa są nowe i rozróżnialne, bo cofnięcie z bloba wolno
#: przyjąć tylko wpisowi, który z bloba przyszedł.
EXAM_SRC_BLOB = "blob"
EXAM_SRC_ZPRP = "zprp"

#: Strona w blobie -> klucz rosteru w odpowiedzi API. Zawsze nominalnie:
#: `mapApiDetailsToBasics` buduje karty gospodarzy z `gosp` bez względu na
#: znacznik zamiany gospodarza (`zamiana`), więc i tu nie ma czego obracać.
ROSTER_KEY_BY_TEAM: Dict[str, str] = {"host": "gosp", "guest": "gosc"}


def exam_mark_from_roster(raw: Any) -> str:
    """Rekord zawodnika z API -> `zprp` / `wzpr` / `none`. ZPRP wygrywa z WZPR."""
    if not isinstance(raw, dict):
        return "none"

    def ok(value: Any) -> bool:
        return str(value or "").strip().upper() in EXAM_OK_TOKENS

    if ok(raw.get("badania_ZPRP")):
        return "zprp"
    if ok(raw.get("badania_WZPR")):
        return "wzpr"
    return "none"


def exam_path(team: str, number: Any) -> str:
    """Ścieżka overlaya badań - ta sama, którą buduje `examPath` w aplikacji."""
    return f"exam.{team}.#{str(number).strip()}"


def card_number(card: Any) -> Optional[int]:
    """Numer koszulki z karty albo rekordu API; poza 1-999 to „bez numeru"."""
    raw = card.get("number", card.get("NrKoszulki")) if isinstance(card, dict) else None
    try:
        num = int(str(raw or "").strip())
    except (TypeError, ValueError):
        return None
    return num if 1 <= num <= 999 else None


def _player_name(card: Any) -> str:
    if not isinstance(card, dict):
        return ""
    full = str(card.get("fullName") or "").strip()
    if full:
        return full
    # Rekord API: nazwisko i imię osobno, w tej kolejności - jak w kartach.
    return " ".join(
        part
        for part in (
            str(card.get("nazwisko") or "").strip(),
            str(card.get("imie") or "").strip(),
        )
        if part
    )


def blob_exam_cards(blob: Any) -> List[Dict[str, Any]]:
    """Karty zawodników z numerem: `{path, team, number, name, mark}`.

    Karta bez numeru nie ma ścieżki w overlayu, więc zostaje poza tym
    mechanizmem - dokładnie tak, jak w arkuszu, który bez numeru zapisuje
    badanie wyłącznie u siebie.
    """
    if not isinstance(blob, dict):
        return []
    out: List[Dict[str, Any]] = []
    # Odczyt BEZ `_cards`: tamto przez `_cfg` dopisuje pusty `matchConfig` do
    # bloba, a tu dostajemy prosto obiekt zadania - nic w nim nie zmieniamy.
    config = blob.get("matchConfig")
    if not isinstance(config, dict):
        return []
    for team in ROSTER_KEY_BY_TEAM:
        cards = config.get(f"{team}PlayerCards")
        for card in cards if isinstance(cards, list) else []:
            number = card_number(card)
            if number is None:
                continue
            mark = str((card or {}).get("exam") or "none").strip().lower()
            out.append(
                {
                    "path": exam_path(team, number),
                    "team": team,
                    "number": number,
                    "name": _player_name(card),
                    "mark": mark if mark in EXAM_RANK else "none",
                }
            )
    return out


def exam_recheck_from_blob(blob: Any) -> Optional[Dict[str, Any]]:
    """`matchConfig.examCheck` z bloba, znormalizowane albo `None`.

    Telefon zapisuje tu OSTATNIE pytanie do bazy związku zadane przed
    pierwszym gwizdkiem i listę zawodników, którzy nadal nie mieli badań.
    To jedyny dowód na to, że ręczny ptaszek postawiono z powodu, a nie
    zamiast sprawdzenia - dlatego jedzie w blobie, a nie w pamięci ekranu.

    Pusta lista zwraca `None`: „sprawdzone, komplet" nie jest zdarzeniem,
    o którym warto zawracać głowę dziennikowi.
    """
    core = blob.get("matchConfig") if isinstance(blob, dict) else None
    raw = core.get("examCheck") if isinstance(core, dict) else None
    if not isinstance(raw, dict):
        return None
    at = str(raw.get("at") or "").strip()
    if not at:
        return None
    # Godzina z zegarka sędziego - telefon podaje ją gotową, bo mecz gra
    # się w hali, a nie w UTC. Starszy zapis bez niej po prostu jej nie ma.
    clock = str(raw.get("clock") or "").strip()[:5]
    players: List[Dict[str, Any]] = []
    for item in raw.get("missing") or []:
        if not isinstance(item, dict):
            continue
        team = str(item.get("team") or "").strip()
        if team not in ("host", "guest"):
            continue
        mark = str(item.get("mark") or "none").strip().lower()
        players.append(
            {
                "team": team,
                "number": item.get("number"),
                "name": str(item.get("name") or "").strip(),
                "mark": mark if mark in EXAM_RANK else "none",
            }
        )
    if not players:
        return None
    return {"at": at, "clock": clock, "players": players}


def has_manual_exams(blob: Any) -> bool:
    return any(card["mark"] == "manual" for card in blob_exam_cards(blob))


def live_exam_entries(overlay: Any) -> Dict[str, Dict[str, Any]]:
    """Żywe wpisy badań z overlaya: ścieżka -> `{team, number, name, mark, entry}`."""
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(overlay, dict):
        return out
    for path, entry in overlay.items():
        if not isinstance(entry, dict) or entry.get("superseded_at"):
            continue
        try:
            spec, params = parse_path(str(path))
        except UnknownPath:
            continue
        if spec.name != "exam":
            continue
        value = entry.get("v") if isinstance(entry.get("v"), dict) else {}
        mark = str(value.get("mark") or "none").strip().lower()
        out[str(path)] = {
            "team": params["team"],
            "number": int(params["num"]),
            "name": str(value.get("name") or "").strip(),
            "mark": mark if mark in EXAM_RANK else "none",
            "entry": entry,
        }
    return out


def manual_exam_candidates(overlay: Any, blob: Any) -> List[Dict[str, Any]]:
    """Ręczne potwierdzenia, o które warto zapytać związek.

    Z overlaya i z kart bloba razem: potwierdzenie z ekranu konfiguracji bywa
    tylko w kartach (starsza aplikacja, blob sprzed wchłonięcia), a to ono
    najczęściej czeka na awans.
    """
    out: List[Dict[str, Any]] = []
    seen: set = set()
    live = live_exam_entries(overlay)
    for path, item in live.items():
        if item["mark"] != "manual":
            continue
        seen.add(path)
        out.append(
            {"path": path, "team": item["team"], "number": item["number"], "name": item["name"]}
        )
    for card in blob_exam_cards(blob):
        if card["mark"] != "manual" or card["path"] in seen:
            continue
        current = live.get(card["path"])
        if current is not None and exam_rank(current["mark"]) > exam_rank("manual"):
            continue  # overlay już wie lepiej
        seen.add(card["path"])
        out.append(
            {"path": card["path"], "team": card["team"], "number": card["number"], "name": card["name"]}
        )
    return out


def roster_marks(payload: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Statusy badań z odpowiedzi API, po stronach bloba: `host` / `guest`."""
    out: Dict[str, List[Dict[str, Any]]] = {team: [] for team in ROSTER_KEY_BY_TEAM}
    if not isinstance(payload, dict):
        return out
    for team, key in ROSTER_KEY_BY_TEAM.items():
        roster = payload.get(key)
        if isinstance(roster, dict):
            players = list(roster.values())
        elif isinstance(roster, list):
            players = roster
        else:
            players = []
        for raw in players:
            if not isinstance(raw, dict):
                continue
            out[team].append(
                {
                    "number": card_number(raw),
                    "name": _player_name(raw),
                    "mark": exam_mark_from_roster(raw),
                }
            )
    return out


def _same_person(a: Any, b: Any) -> bool:
    """To samo nazwisko mimo innej kolejnosci czlonow (NAZWISKO Imie / Imie NAZWISKO)."""
    left, right = normalize_name(a), normalize_name(b)
    if not left or not right:
        return False
    if left == right:
        return True
    return set(left.split()) == set(right.split())


def promotions_for(
    candidates: List[Dict[str, Any]],
    marks_by_team: Dict[str, List[Dict[str, Any]]],
    requirement: str = EXAM_REQUIREMENT_ANY,
) -> List[Dict[str, Any]]:
    """Które ręczne znaczniki związek już zastąpił własnym statusem.

    `requirement` broni progu rozgrywki: w Superlidze awans „ręczne -> WZPR"
    byłby ODEBRANIEM prawa gry zawodniczce, którą sędzia potwierdził, mimo
    że w kracie jest awansem. Ręczny ptaszek zostaje wtedy na miejscu.

    Dopasowanie NAJPIERW po numerze, potem po znormalizowanym nazwisku - ta
    sama para kluczy, co w `project_exam`. Numer w rosterze API jest
    wiarygodny, a nazwisko ratuje zawodnika, któremu numer zmieniono tuż
    przed gwizdkiem.
    """
    out: List[Dict[str, Any]] = []
    for cand in candidates:
        players = marks_by_team.get(str(cand.get("team") or ""), []) or []
        hit = None
        number = cand.get("number")
        want = str(cand.get("name") or "")
        if number is not None:
            by_number = next((p for p in players if p.get("number") == number), None)
            # Numer to TA SAMA OSOBA tylko wtedy, gdy nazwisko sie zgadza (albo
            # ktoras strona nazwiska nie ma). Sprawdzone na SK/5: karta z
            # wymyslonym nazwiskiem i numerem 5 dostawalaby "OK" prawdziwej
            # zawodniczki z numerem 5 - awans na cudzych badaniach.
            if by_number is not None and (
                not normalize_name(want)
                or not normalize_name(by_number.get("name"))
                or _same_person(want, by_number.get("name"))
            ):
                hit = by_number
        if hit is None and normalize_name(want):
            hit = next((p for p in players if _same_person(want, p.get("name"))), None)
        if hit is None or str(hit.get("mark") or "none") not in EXAM_FROM_API:
            continue
        if not exam_mark_meets(hit.get("mark"), requirement):
            continue
        out.append(
            {
                "path": cand["path"],
                "team": cand["team"],
                "number": number,
                "name": str(cand.get("name") or hit.get("name") or "").strip(),
                "mark": str(hit["mark"]),
            }
        )
    return out


def exam_entry(
    mark: str,
    name: str,
    *,
    rev: int,
    at: str,
    by: Dict[str, Any],
    src: str,
) -> Dict[str, Any]:
    """Wpis overlaya w kształcie, jaki zapisuje `/proel/patch`."""
    return {
        "v": {"mark": str(mark), "name": str(name or "").strip()},
        "rev": int(rev),
        "at": str(at),
        "by": dict(by or {}),
        "src": str(src),
        "superseded_at": None,
    }


def adopt_blob_exams(
    overlay: Any,
    blob: Any,
    *,
    rev: int,
    at: str,
    by: Dict[str, Any],
    install: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Wciągnij do overlaya ręczne potwierdzenia z kart bloba. KOPIA, nie zmiana.

    Reguły, obie ostre:

    * ręczny ptaszek na karcie wchodzi tylko tam, gdzie overlay nie ma nic
      albo ma mniej (`none`); wyższy stopień z API zostaje,
    * karta BEZ badania cofa wyłącznie wpis, który przyszedł z bloba
      (`src == "blob"`) i to z TEGO SAMEGO urządzenia. Snapshot z drugiego
      telefonu, który o potwierdzeniu nie wie, nie ma prawa go skasować -
      to jest dokładnie ta sytuacja, dla której powstała reprojekcja.

    Zwraca (overlay po zmianie, potwierdzone, cofnięte); listy niosą
    `{team, number, name}` do dziennika.
    """
    out = dict(overlay) if isinstance(overlay, dict) else {}
    confirmed: List[Dict[str, Any]] = []
    withdrawn: List[Dict[str, Any]] = []
    live = live_exam_entries(out)
    own = str(install or "").strip()
    for card in blob_exam_cards(blob):
        current = live.get(card["path"])
        player = {"team": card["team"], "number": card["number"], "name": card["name"]}
        if card["mark"] == "manual":
            if current is not None and exam_rank(current["mark"]) >= exam_rank("manual"):
                continue
            out[card["path"]] = exam_entry(
                "manual", card["name"], rev=rev, at=at, by=by, src=EXAM_SRC_BLOB
            )
            confirmed.append(player)
        elif card["mark"] == "none":
            if current is None or current["mark"] != "manual":
                continue
            entry = current["entry"]
            if str(entry.get("src") or "") != EXAM_SRC_BLOB:
                continue
            author = str(((entry.get("by") or {}).get("install")) or "").strip()
            if not own or author != own:
                continue
            out[card["path"]] = exam_entry(
                "none", card["name"], rev=rev, at=at, by=by, src=EXAM_SRC_BLOB
            )
            withdrawn.append(player)
    return out, confirmed, withdrawn
