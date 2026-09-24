"""
Powiadomienia okręgu z Obsady - same reguły.

Dwa alerty (decyzje użytkownika z 24.09.2026):

1. MECZ BEZ OBSADY. Mecz, który obsadza okręg (zakres listy obsadowego:
   `assignment_scope`, bez II ligi), ma PUSTE WYMAGANE GNIAZDO, a do jego
   początku zostało nie więcej niż X godzin (24/48/72/96/120/168, domyślnie 72).
   Wymagane gniazda liczy model potrzeb `assignment_rules.club_crew_needs`
   ({field, table, club_table}): stolikowy „od klubu", delegaci i stolik
   w kategoriach bez stolika okręgowego (DZM, DZK, MLM1213, MLK1213) brakiem
   nie są. Drugi stolikowy od okręgu jest brakiem, ale da się to wyłączyć
   (`count_soft_table`), bo lista obsadowego pokazuje go jako „lekką różnicę".
     - push do obsadowych RAZ, gdy mecz przekroczy próg, i drugi raz 24 h przed
       meczem, jeśli dalej jest pusty (`remind_24h`),
     - mail: JEDNO zestawienie na sprawdzenie ze wszystkimi meczami, które
       właśnie przekroczyły próg,
     - mecz obsadzony w komplecie gasi swoje znaczniki - gdy ktoś potem zejdzie
       z obsady, alert wraca.

2. KOLIZJA PO ZMIANIE TERMINU. Mecz zmienił termin i któryś sędzia z jego
   obsady ma teraz problem:
     - `overlap` - inny mecz, na który nie zdąży (ta sama reguła dojazdu, co
       w Automacie: 2 h meczu + dojazd 60 km/h + 45 min zapasu),
     - `offtime` - nowy termin wpada w niedyspozycję (kalendarz okręgowy,
       centralny i kalendarze iCal z „blokuje obsadę"),
     - `city`    - miękka: tego samego dnia mecz w innym mieście, na który
       zdąży, ale trzeba dojechać.
   Odbiorcy: sędzia z kolizją, obsadowi i lista adresów.

CISZA NOCNA (domyślnie 22-7): pushe czekają do rana, WYJĄTEK - mecz za mniej
niż 12 h idzie od razu. Maile idą zawsze od razu.

CZAS: `province_matches.match_at` to prawdziwy UTC. Wszystko, co widzi
człowiek, jest w czasie polskim (`offtime_rules.as_local`).

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguły chodziły w teście.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from app import assignment_rules as AR
from app import offtime_rules as O
from app.assignment_auto import can_make_both
from app.assignment_board_rules import display_name
from app.assignment_people import fold
from app.province_alert_rules import AlertRuleError, normalize_emails, plural

try:
    from zoneinfo import ZoneInfo

    WARSAW = ZoneInfo("Europe/Warsaw")
except Exception:  # pragma: no cover
    WARSAW = timezone.utc  # type: ignore[assignment]

UNASSIGNED = "unassigned"
COLLISION = "collision"
ALERTS = (UNASSIGNED, COLLISION)

#: Progi „do meczu zostało mniej niż" w godzinach.
THRESHOLDS: tuple[int, ...] = (24, 48, 72, 96, 120, 168)
DEFAULT_THRESHOLD = 72
#: Drugie przypomnienie o pustym meczu.
FINAL_HOURS = 24
#: Mecz bliżej niż tyle godzin przebija ciszę nocną.
URGENT_HOURS = 12

STAGE_THRESHOLD = "threshold"
STAGE_FINAL = "final"

KIND_OVERLAP = "overlap"
KIND_OFFTIME = "offtime"
KIND_CITY = "city"
KINDS: tuple[str, ...] = (KIND_OVERLAP, KIND_OFFTIME, KIND_CITY)
KIND_LABELS = {
    KIND_OVERLAP: "Dwa mecze naraz",
    KIND_OFFTIME: "Niedyspozycja",
    KIND_CITY: "Ten sam dzień, inne miasto",
}

DEFAULT_QUIET_START = 22
DEFAULT_QUIET_END = 7

#: Od tylu meczów w jednym sprawdzeniu obsadowi dostają JEDEN zbiorczy push.
SUMMARY_FROM = 4
#: Ile meczów ze zmienionym terminem sprawdzamy do przodu.
COLLISION_HORIZON_DAYS = 60
#: Tylu kandydatów Automatu pokazuje mail przy każdym meczu.
SUGGESTIONS = 3

WEEKDAYS = ("pon.", "wt.", "śr.", "czw.", "pt.", "sob.", "niedz.")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "tak", "yes", "on")
    return bool(value)


def _strings(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    for item in values:
        text = _s(item)
        if text and text not in out:
            out.append(text)
    return out


# ---------------------------------------------------------------------------
# Konfiguracja
# ---------------------------------------------------------------------------

def default_config() -> dict:
    """Domyślnie wszystko wyłączone - decyzja użytkownika."""
    return {
        UNASSIGNED: {
            "enabled": False,
            "threshold_hours": DEFAULT_THRESHOLD,
            "remind_24h": True,
            "count_soft_table": True,
            "email": True,
            "emails": [],
            "email_managers": True,
            "push": True,
            "competitions": [],
            "categories": [],
        },
        COLLISION: {
            "enabled": False,
            "kinds": list(KINDS),
            "email": True,
            "emails": [],
            "email_managers": True,
            "email_judge": True,
            "push_judge": True,
            "push_managers": True,
            "competitions": [],
            "categories": [],
        },
        "quiet": {"enabled": True, "start": DEFAULT_QUIET_START, "end": DEFAULT_QUIET_END},
    }


def _hour(value: Any, default: int) -> int:
    try:
        hour = int(value)
    except (TypeError, ValueError):
        return default
    return hour if 0 <= hour <= 23 else default


def normalize_config(raw: Any) -> dict:
    """
    Konfiguracja z bazy uzupełniona domyślnymi - łagodnie, bez wyjątków.

    Stary albo niepełny zapis nie może wywrócić pętli: brakujące pole dostaje
    wartość domyślną, a nieznane odpada.
    """
    base = default_config()
    data = raw if isinstance(raw, Mapping) else {}
    un_raw = data.get(UNASSIGNED) if isinstance(data.get(UNASSIGNED), Mapping) else {}
    co_raw = data.get(COLLISION) if isinstance(data.get(COLLISION), Mapping) else {}
    qu_raw = data.get("quiet") if isinstance(data.get("quiet"), Mapping) else {}

    un = base[UNASSIGNED]
    for key in ("enabled", "remind_24h", "count_soft_table", "email", "email_managers", "push"):
        un[key] = _bool(un_raw.get(key), un[key])
    try:
        threshold = int(un_raw.get("threshold_hours", DEFAULT_THRESHOLD))
    except (TypeError, ValueError):
        threshold = DEFAULT_THRESHOLD
    un["threshold_hours"] = threshold if threshold in THRESHOLDS else DEFAULT_THRESHOLD
    un["emails"] = _strings(un_raw.get("emails"))
    un["competitions"] = _strings(un_raw.get("competitions"))
    un["categories"] = _strings(un_raw.get("categories"))

    co = base[COLLISION]
    for key in ("enabled", "email", "email_managers", "email_judge", "push_judge", "push_managers"):
        co[key] = _bool(co_raw.get(key), co[key])
    kinds = co_raw.get("kinds")
    if isinstance(kinds, (list, tuple)):
        co["kinds"] = [kind for kind in KINDS if kind in {_s(item) for item in kinds}]
    co["emails"] = _strings(co_raw.get("emails"))
    co["competitions"] = _strings(co_raw.get("competitions"))
    co["categories"] = _strings(co_raw.get("categories"))

    qu = base["quiet"]
    qu["enabled"] = _bool(qu_raw.get("enabled"), True)
    qu["start"] = _hour(qu_raw.get("start"), DEFAULT_QUIET_START)
    qu["end"] = _hour(qu_raw.get("end"), DEFAULT_QUIET_END)
    return base


def validate_config(raw: Any) -> dict:
    """
    Konfiguracja do zapisu - ze sprawdzeniem, które mówi, co jest nie tak.

    Włączony alert musi mieć dokąd iść: mail z adresem (albo do obsadowych)
    albo push. Zły adres zatrzymuje zapis z nazwą tego adresu.
    """
    data = raw if isinstance(raw, Mapping) else {}
    clean = normalize_config(data)
    un_raw = data.get(UNASSIGNED) if isinstance(data.get(UNASSIGNED), Mapping) else {}
    if "threshold_hours" in un_raw:
        try:
            wanted = int(un_raw.get("threshold_hours"))
        except (TypeError, ValueError):
            wanted = -1
        if wanted not in THRESHOLDS:
            allowed = ", ".join(f"{item} h" for item in THRESHOLDS)
            raise AlertRuleError(f"Próg „mecz bez obsady” może wynosić tylko: {allowed}.")
    for alert, label in ((UNASSIGNED, "Mecz bez obsady"), (COLLISION, "Kolizja po zmianie terminu")):
        section = clean[alert]
        section_raw = data.get(alert) if isinstance(data.get(alert), Mapping) else {}
        section["emails"] = normalize_emails(section_raw.get("emails") or [])
        if not section["enabled"]:
            continue
        mail_ok = section["email"] and (section["emails"] or section["email_managers"] or section.get("email_judge"))
        push_ok = section.get("push") or section.get("push_judge") or section.get("push_managers")
        if not mail_ok and not push_ok:
            raise AlertRuleError(
                f"„{label}” jest włączony, ale nie ma dokąd iść - włącz mail z adresem albo powiadomienia push."
            )
        if section["email"] and not section["emails"] and not section["email_managers"] and not section.get("email_judge"):
            raise AlertRuleError(
                f"„{label}”: mail jest włączony, ale bez adresów - dopisz adres albo zaznacz obsadowych."
            )
    if clean[COLLISION]["enabled"] and not clean[COLLISION]["kinds"]:
        raise AlertRuleError("„Kolizja po zmianie terminu” jest włączona, ale bez żadnego rodzaju kolizji.")
    return clean


def any_enabled(config: Mapping[str, Any]) -> bool:
    return any(bool((config.get(alert) or {}).get("enabled")) for alert in ALERTS)


def scope_allows(section: Mapping[str, Any], competition: Any, category: Any) -> bool:
    """Filtr rozgrywek i kategorii z ustawień. Pusty filtr = wszystko."""
    comps = {c.upper() for c in _strings(section.get("competitions"))}
    cats = set(_strings(section.get("categories")))
    if comps and _s(competition).upper() not in comps:
        return False
    if cats and _s(category) not in cats:
        return False
    return True


# ---------------------------------------------------------------------------
# Czas i cisza nocna
# ---------------------------------------------------------------------------

def local(value: Any) -> Optional[datetime]:
    """Czas polski (naiwny) z dowolnego zapisu - patrz `offtime_rules.as_local`."""
    return O.as_local(value)


def to_utc(local_moment: datetime) -> datetime:
    """Naiwna ściana zegara w Polsce -> prawdziwy UTC."""
    return local_moment.replace(tzinfo=WARSAW).astimezone(timezone.utc)


def in_quiet(moment_local: datetime, start: int, end: int) -> bool:
    """Czy godzina wpada w ciszę [start, end). Start == koniec - ciszy nie ma."""
    if start == end:
        return False
    hour = moment_local.hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def quiet_release(moment_local: datetime, start: int, end: int) -> datetime:
    """Pierwsza chwila po ciszy nocnej (czas polski)."""
    release = datetime.combine(moment_local.date(), time(end, 0))
    if release <= moment_local:
        release += timedelta(days=1)
    return release


def push_due_at(now: datetime, match_at: Optional[datetime], quiet: Mapping[str, Any]) -> datetime:
    """
    Kiedy wolno wysłać push (UTC).

    Poza ciszą albo przy meczu za mniej niż `URGENT_HOURS` - od razu. W ciszy
    - o godzinie końca ciszy (czas polski).
    """
    if not quiet or not quiet.get("enabled", True):
        return now
    start = _hour(quiet.get("start"), DEFAULT_QUIET_START)
    end = _hour(quiet.get("end"), DEFAULT_QUIET_END)
    now_local = local(now)
    if now_local is None or not in_quiet(now_local, start, end):
        return now
    if match_at is not None and match_at - now < timedelta(hours=URGENT_HOURS):
        return now
    return to_utc(quiet_release(now_local, start, end))


# ---------------------------------------------------------------------------
# Napisy
# ---------------------------------------------------------------------------

def when_text(value: Any, *, weekday: bool = True) -> str:
    """„sob. 27.09, 14:00" - zawsze czas polski."""
    moment = local(value)
    if moment is None:
        return "termin nieznany"
    prefix = f"{WEEKDAYS[moment.weekday()]} " if weekday else ""
    return f"{prefix}{moment:%d.%m}, {moment:%H:%M}"


def when_long(value: Any) -> str:
    """„sobota 27.09.2026, 14:00"."""
    names = ("poniedziałek", "wtorek", "środa", "czwartek", "piątek", "sobota", "niedziela")
    moment = local(value)
    if moment is None:
        return "termin nieznany"
    return f"{names[moment.weekday()]} {moment:%d.%m.%Y}, {moment:%H:%M}"


def hour_text(value: Any) -> str:
    moment = local(value)
    return f"{moment:%H:%M}" if moment else "?"


def teams_text(host: Any, guest: Any) -> str:
    host, guest = _s(host), _s(guest)
    if host and guest:
        return f"{host} - {guest}"
    return host or guest or "drużyny nieznane"


def km_text(km: Optional[float]) -> str:
    if km is None:
        return "odległość nieznana"
    return f"{int(round(km))} km"


def hours_left_text(hours: float) -> str:
    """„za 2 dni 5 h", „za 9 h", „za 40 min"."""
    minutes = max(0, int(round(hours * 60)))
    if minutes < 60:
        return f"za {minutes} min"
    whole = minutes // 60
    days, rest = divmod(whole, 24)
    if days and rest:
        return f"za {days} {plural(days, 'dzień', 'dni', 'dni')} {rest} h"
    if days:
        return f"za {days} {plural(days, 'dzień', 'dni', 'dni')}"
    return f"za {whole} h"


def missing_text(missing: Mapping[str, int]) -> str:
    """„2 sędziów boiskowych i 1 stolikowego"."""
    field_n = int(missing.get("field") or 0)
    table_n = int(missing.get("table") or 0)
    parts = []
    if field_n:
        parts.append(f"{field_n} {plural(field_n, 'sędziego boiskowego', 'sędziów boiskowych', 'sędziów boiskowych')}")
    if table_n:
        parts.append(f"{table_n} {plural(table_n, 'stolikowego', 'stolikowych', 'stolikowych')}")
    return " i ".join(parts) or "nikogo"


def judge_label(name: Any) -> str:
    """Sędzia zawsze jako „NAZWISKO Imię"."""
    return display_name(name) or "sędzia bez nazwiska"


# ---------------------------------------------------------------------------
# Mecz bez obsady
# ---------------------------------------------------------------------------

def missing_slots(
    crew: Mapping[str, Any],
    needs: Mapping[str, Any],
    *,
    count_soft_table: bool = True,
) -> dict[str, int]:
    """
    Ile WYMAGANYCH gniazd stoi pustych: {field, table}.

    `needs` to `club_crew_needs` - `table` to już stolikowi OD OKRĘGU (gniazdo
    „od klubu" jest odjęte), a w kategoriach bez stolika okręgowego 0.
    Delegatów nie liczymy nigdy. Bez `count_soft_table` jeden stolikowy
    zamiast dwóch nie jest brakiem - tak jak „lekka różnica" na liście.
    """
    field_have = sum(1 for slot in AR.FIELD_SLOTS if (crew or {}).get(slot))
    table_have = sum(1 for slot in AR.TABLE_SLOTS if (crew or {}).get(slot))
    field_need = int((needs or {}).get("field") or 0)
    table_need = int((needs or {}).get("table") or 0)
    field_missing = max(0, field_need - field_have)
    table_missing = max(0, table_need - table_have)
    if not count_soft_table and table_have:
        table_missing = 0
    return {"field": field_missing, "table": table_missing}


def due_stages(hours_left: float, threshold: int, remind_24h: bool = True) -> list[str]:
    """Etapy, które mecz już przekroczył (próg i ewentualnie 24 h)."""
    if hours_left <= 0:
        return []
    stages = []
    if hours_left <= threshold:
        stages.append(STAGE_THRESHOLD)
    if remind_24h and threshold > FINAL_HOURS and hours_left <= FINAL_HOURS:
        stages.append(STAGE_FINAL)
    return stages


def unassigned_key(match_id: Any, stage: str) -> str:
    return f"{UNASSIGNED}|{_s(match_id)}|{stage}"


@dataclass
class UnassignedHit:
    """Mecz, o którym właśnie trzeba napisać."""

    match_id: str
    code: str
    match_at: datetime
    hours_left: float
    missing: dict[str, int]
    #: Etapy do oznaczenia jako ogłoszone.
    stages: list[str]
    #: Mecz przekroczył próg w tym sprawdzeniu - trafia do maila.
    email: bool
    #: Etap, którym podpisujemy push („threshold" albo „final").
    push_stage: str
    item: dict = field(default_factory=dict)


@dataclass
class UnassignedPlan:
    hits: list[UnassignedHit] = field(default_factory=list)
    #: Mecze obsadzone w komplecie - ich znaczniki gasną.
    rearm: list[str] = field(default_factory=list)
    #: Ile meczów w oknie ma braki (także te już ogłoszone).
    open_in_window: int = 0


def is_candidate_item(item: Mapping[str, Any]) -> bool:
    """Mecz z listy obsadowego, o którym alert w ogóle może mówić."""
    if item.get("league"):
        return False
    if item.get("season_unknown"):
        return False
    if item.get("approved") or item.get("score"):
        return False
    state = {
        "ID_zespoly_gosp_ZespolNazwa": item.get("host"),
        "ID_zespoly_gosc_ZespolNazwa": item.get("guest"),
    }
    return not AR.is_bye(state)


def plan_unassigned(
    items: Iterable[Mapping[str, Any]],
    done: Iterable[str],
    section: Mapping[str, Any],
    now: datetime,
) -> UnassignedPlan:
    """
    Kto dostaje alert w tym sprawdzeniu, a czyje znaczniki gasną.

    `items` to mecze z listy obsadowego (`province_assignments._item`) z polem
    `match_at_dt` (UTC), `done` - klucze już ogłoszonych etapów.
    """
    threshold = int(section.get("threshold_hours") or DEFAULT_THRESHOLD)
    remind = bool(section.get("remind_24h", True))
    soft = bool(section.get("count_soft_table", True))
    seen = set(done)
    plan = UnassignedPlan()
    for item in items:
        match_at = item.get("match_at_dt")
        if not isinstance(match_at, datetime) or not is_candidate_item(item):
            continue
        if not scope_allows(section, item.get("competition"), item.get("category")):
            continue
        match_id = _s(item.get("match_id"))
        missing = missing_slots(item.get("crew") or {}, item.get("needs") or {}, count_soft_table=soft)
        hours_left = (match_at - now).total_seconds() / 3600.0
        if not (missing["field"] or missing["table"]):
            if any(unassigned_key(match_id, stage) in seen for stage in (STAGE_THRESHOLD, STAGE_FINAL)):
                plan.rearm.append(match_id)
            continue
        stages = due_stages(hours_left, threshold, remind)
        if not stages:
            continue
        plan.open_in_window += 1
        fresh = [stage for stage in stages if unassigned_key(match_id, stage) not in seen]
        if not fresh:
            continue
        plan.hits.append(
            UnassignedHit(
                match_id=match_id,
                code=_s(item.get("code")),
                match_at=match_at,
                hours_left=hours_left,
                missing=missing,
                stages=fresh,
                email=STAGE_THRESHOLD in fresh,
                push_stage=STAGE_FINAL if STAGE_FINAL in stages else STAGE_THRESHOLD,
                item=dict(item),
            )
        )
    plan.hits.sort(key=lambda hit: hit.match_at)
    return plan


def unassigned_push(hit: UnassignedHit) -> tuple[str, str]:
    """(tytuł, treść) pusha do obsadowych o jednym meczu."""
    item = hit.item
    left = hours_left_text(hit.hours_left)
    title = f"Brak obsady · {hit.code} · {left}"
    place = _s(item.get("city")) or "hala nieznana"
    body = (
        f"{teams_text(item.get('host'), item.get('guest'))}, {when_text(hit.match_at)}, {place}. "
        f"Brakuje: {missing_text(hit.missing)}."
    )
    return title, body


def unassigned_summary_push(hits: Sequence[UnassignedHit], threshold: int) -> tuple[str, str]:
    """Jeden push o wielu meczach naraz (pierwsze włączenie, weekend turniejowy)."""
    count = len(hits)
    title = f"{count} {plural(count, 'mecz', 'mecze', 'meczów')} bez obsady w ciągu {threshold} h"
    first = hits[:2]
    lines = [f"{hit.code} {when_text(hit.match_at)} - brakuje {missing_text(hit.missing)}" for hit in first]
    rest = count - len(first)
    tail = f" i {rest} {plural(rest, 'kolejny', 'kolejne', 'kolejnych')}" if rest > 0 else ""
    return title, "; ".join(lines) + tail + ". Szczegóły w Obsadzie."


# ---------------------------------------------------------------------------
# Kolizje
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MatchInfo:
    """Mecz w regułach kolizji - czas polski (naiwny)."""

    match_id: str
    code: str
    moment: Optional[datetime]
    city: str = ""
    hall: str = ""
    host: str = ""
    guest: str = ""

    @property
    def teams(self) -> str:
        return teams_text(self.host, self.guest)


@dataclass
class Collision:
    kind: str
    judge_id: str
    judge_name: str
    moved: MatchInfo
    #: Poprzedni termin przeniesionego meczu (czas polski) - do treści.
    previous: Optional[datetime] = None
    other: Optional[MatchInfo] = None
    km: Optional[float] = None
    #: Ile minut między początkami meczów.
    gap_minutes: Optional[int] = None
    #: Ile minut brakuje, żeby zdążyć (dla `overlap`).
    short_minutes: Optional[int] = None
    offtime: Optional[O.Offtime] = None

    @property
    def key(self) -> str:
        return collision_key(self)


def _iso(moment: Optional[datetime]) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M") if moment else "-"


def collision_key(item: Collision) -> str:
    """
    Klucz deduplikacji: sędzia + mecz + rodzaj + NOWY termin.

    Kolizja dwóch meczów jest symetryczna - para meczów (z terminami) idzie
    posortowana, żeby przeniesienie obu naraz nie dawało dwóch alertów.
    """
    if item.kind == KIND_OFFTIME:
        off = item.offtime
        tail = f"{_iso(off.start) if off else '-'}|{_iso(off.end) if off else '-'}"
        return f"{COLLISION}|{KIND_OFFTIME}|{item.judge_id}|{item.moved.match_id}|{_iso(item.moved.moment)}|{tail}"
    pair = sorted(
        [
            f"{item.moved.match_id}@{_iso(item.moved.moment)}",
            f"{item.other.match_id if item.other else '-'}@{_iso(item.other.moment if item.other else None)}",
        ]
    )
    return f"{COLLISION}|{item.kind}|{item.judge_id}|{'|'.join(pair)}"


def short_key(key: str) -> str:
    """Klucz do kolumny o rozsądnej długości (skrót, gdy za długi)."""
    if len(key) <= 180:
        return key
    return key[:120] + "#" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]


def find_collisions(
    judge_id: str,
    judge_name: str,
    moved: MatchInfo,
    others: Iterable[MatchInfo],
    offtimes: Iterable[O.Offtime],
    km: Callable[[str, str], Optional[float]],
    kinds: Iterable[str] = KINDS,
    previous: Optional[datetime] = None,
) -> list[Collision]:
    """
    Kolizje jednego sędziego z przeniesionym meczem.

    `others` - pozostałe mecze sędziego (czas polski). Mecz bez terminu nie
    koliduje z niczym: „nie wiem" nie może alarmować.
    """
    wanted = set(kinds)
    out: list[Collision] = []
    if moved.moment is None:
        return out
    for other in others:
        if other.match_id == moved.match_id or other.moment is None:
            continue
        distance = km(moved.city, other.city) if moved.city and other.city else None
        gap = int(abs((other.moment - moved.moment).total_seconds()) // 60)
        if not can_make_both(moved.moment, other.moment, distance):
            if KIND_OVERLAP in wanted:
                from app.assignment_auto import MATCH_HOURS, SAFETY_MINUTES, travel_minutes

                need = MATCH_HOURS * 60 + travel_minutes(distance) + SAFETY_MINUTES
                out.append(
                    Collision(
                        kind=KIND_OVERLAP,
                        judge_id=judge_id,
                        judge_name=judge_name,
                        moved=moved,
                        previous=previous,
                        other=other,
                        km=distance,
                        gap_minutes=gap,
                        short_minutes=max(0, int(round(need - gap))),
                    )
                )
            continue
        if (
            KIND_CITY in wanted
            and other.moment.date() == moved.moment.date()
            and moved.city
            and other.city
            and fold(moved.city) != fold(other.city)
        ):
            out.append(
                Collision(
                    kind=KIND_CITY,
                    judge_id=judge_id,
                    judge_name=judge_name,
                    moved=moved,
                    previous=previous,
                    other=other,
                    km=distance,
                    gap_minutes=gap,
                )
            )
    if KIND_OFFTIME in wanted:
        # Wpisy „MATCH" to mecze z kalendarza sędziego - te liczymy wyżej, po
        # prawdziwym terminarzu, a stary wpis przeniesionego meczu udawałby
        # kolizję z samym sobą.
        own = [off for off in offtimes if off.kind != "MATCH"]
        off = O.blocking_offtime(own, moved.moment)
        if off is not None:
            out.append(
                Collision(
                    kind=KIND_OFFTIME,
                    judge_id=judge_id,
                    judge_name=judge_name,
                    moved=moved,
                    previous=previous,
                    offtime=off,
                )
            )
    return out


def offtime_text(off: O.Offtime) -> str:
    """„Praca, 12:00-18:00" albo „Urlop, cały dzień"."""
    label = _s(off.label) or "niedyspozycja"
    if off.all_day or off.kind == "BAZOWE":
        if off.start.date() == off.end.date():
            return f"{label}, cały dzień"
        return f"{label}, {off.start:%d.%m}-{off.end:%d.%m}"
    if off.start.date() == off.end.date():
        return f"{label}, {off.start:%H:%M}-{off.end:%H:%M}"
    return f"{label}, {off.start:%d.%m %H:%M}-{off.end:%d.%m %H:%M}"


def _other_when(moved: MatchInfo, other: MatchInfo) -> str:
    """„o 15:00" tego samego dnia, inaczej „w niedz. 28.09 o 11:00"."""
    if moved.moment and other.moment and moved.moment.date() == other.moment.date():
        return f"o {hour_text(other.moment)}"
    return f"w {WEEKDAYS[other.moment.weekday()]} {other.moment:%d.%m} o {hour_text(other.moment)}" if other.moment else ""


def _other_place(other: MatchInfo, km: Optional[float]) -> str:
    city = _s(other.city) or "miejsce nieznane"
    return f"({city}, {km_text(km)})" if km is not None else f"({city})"


def collision_sentence(item: Collision, *, you: bool) -> str:
    """Zdanie o kolizji - w drugiej osobie dla sędziego, w trzeciej dla obsadowych."""
    moved = item.moved
    head = f"{moved.teams} przeniesiony na {when_text(moved.moment)}"
    has = "masz" if you else "ma"
    if item.kind == KIND_OFFTIME and item.offtime is not None:
        return f"{head} - w tym czasie {has} niedyspozycję ({offtime_text(item.offtime)})."
    other = item.other
    if other is None:
        return head + "."
    if item.kind == KIND_OVERLAP:
        return f"{head}, a {_other_when(moved, other)} {has} mecz {_other_place(other, item.km)}."
    return (
        f"{head}, a {_other_when(moved, other)} {has} też mecz {_other_place(other, item.km)} - "
        + ("zdążysz, ale sprawdź dojazd." if you else "zdąży, ale ma dojazd.")
    )


def judge_push(item: Collision) -> tuple[str, str]:
    title = {
        KIND_OVERLAP: "Kolizja w Twoim terminarzu",
        KIND_OFFTIME: "Mecz w czasie Twojej niedyspozycji",
        KIND_CITY: "Dwa mecze jednego dnia",
    }.get(item.kind, "Kolizja w Twoim terminarzu")
    return title, f"{'Kolizja: ' if item.kind == KIND_OVERLAP else ''}{collision_sentence(item, you=True)}"


def manager_push(items: Sequence[Collision]) -> tuple[str, str]:
    """Jeden push do obsadowych o jednym przeniesionym meczu (wszyscy sędziowie)."""
    first = items[0]
    moved = first.moved
    hard = any(item.kind != KIND_CITY for item in items)
    title = f"{'Kolizja' if hard else 'Uwaga'} po zmianie terminu · {moved.code}"
    parts = []
    for item in items[:2]:
        text = collision_sentence(item, you=False)
        # Nazwa meczu jest w tytule - w treści zostaje to, co dotyczy sędziego.
        tail = text.split(", a ", 1)[1] if ", a " in text else text.split(" - ", 1)[-1]
        parts.append(f"{judge_label(item.judge_name)}: {tail.rstrip('.')}")
    rest = len(items) - len(parts)
    more = f" (+{rest} {plural(rest, 'kolejna', 'kolejne', 'kolejnych')})" if rest > 0 else ""
    body = f"{moved.teams}, teraz {when_text(moved.moment)}. " + "; ".join(parts) + more + "."
    return title, body


# ---------------------------------------------------------------------------
# Ładunek pusha
# ---------------------------------------------------------------------------

def push_data(
    *,
    alert: str,
    audience: str,
    province: str,
    match_id: str,
    code: str,
    title: str,
    body: str,
    extra: Optional[Mapping[str, Any]] = None,
) -> dict[str, str]:
    """
    Ładunek pusha - same napisy (FCM i tak wszystko zamienia na napisy).

    `matchId` + `matchNumber` to ten sam kształt, co w powiadomieniach monitora
    (`province_match_change`) - dispatcher aplikacji otwiera po nich mecz.
    Własny `kind` pozwala nowej aplikacji pokazać obsadowemu kartę alertu,
    a stara wersja rozpozna mecz po numerze.
    """
    data = {
        "kind": "district_alert",
        "alert": alert,
        "audience": audience,
        "province": _s(province),
        "matchId": _s(match_id),
        "match_id": _s(match_id),
        "matchNumber": _s(code),
        "title": title[:180],
        "body": body[:600],
    }
    for key, value in (extra or {}).items():
        text = _s(value)
        if text:
            data[str(key)] = text[:300]
    return data


def config_copy(config: Mapping[str, Any]) -> dict:
    return copy.deepcopy(dict(config))
