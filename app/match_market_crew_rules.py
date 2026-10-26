"""
Oferty obsadowego na giełdzie (25.10.2026) - reguły. MODUŁ-LIŚĆ: bez bazy,
sieci i FastAPI, żeby każda decyzja chodziła w teście.

Obsadowy wystawia mecz z wybranymi gniazdami (np. DRK = tylko stolik), sędziowie
się zgłaszają na ROLĘ ("table" albo "field", bez podziału na sędziego 1/2),
a obsadowy przydziela gniazda. Gniazda mówią językiem MODUŁU OBSADY:
pierwszy / drugi / sekretarz / czas (delegaci poza giełdą).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping, Optional

from app.assignment_board_rules import normalize_slot
from app.assignment_people import fold
from app.collision_rules import CollisionRules, gap_grade, same_hall
from app.match_market_access import badge_names
from app.match_market_notify import slot_for, teams_of, when_of

FIELD_SLOTS = ("pierwszy", "drugi")
TABLE_SLOTS = ("sekretarz", "czas")
CREW_SLOTS = FIELD_SLOTS + TABLE_SLOTS
ROLE_FIELD = "field"
ROLE_TABLE = "table"
ROLES = (ROLE_TABLE, ROLE_FIELD)
ROLE_LABELS = {ROLE_TABLE: "stolikowy", ROLE_FIELD: "boiskowy"}
SLOT_LABELS = {"pierwszy": "sędzia 1", "drugi": "sędzia 2", "sekretarz": "sekretarz", "czas": "mierzący czas"}
DEFAULT_DEADLINE_HOURS = 24

OPEN, FILLED, EXPIRED, WITHDRAWN = "open", "filled", "expired", "withdrawn"
PENDING, ASSIGNED, DECLINED, CLAIM_WITHDRAWN = "pending", "assigned", "declined", "withdrawn"
ACTIVE_CLAIMS = frozenset({PENDING, ASSIGNED})

MODE_NONE, MODE_INCLUDE, MODE_EXCLUDE = "none", "include", "exclude"

#: Źródła kilometrów w kolejności próby.
KM_SOURCES = ("same_city", "district_table", "national_table", "google", "unknown")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _utc(moment: Optional[datetime]) -> Optional[datetime]:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


# ───────────────────────────── gniazda i role ─────────────────────────────


def role_of_slot(slot: Any) -> str:
    return ROLE_FIELD if _s(slot) in FIELD_SLOTS else ROLE_TABLE if _s(slot) in TABLE_SLOTS else ""


def normalize_slots(raw: Any) -> list[str]:
    """Gniazda oferty w słowniku modułu, bez duplikatów i bez delegatów."""
    out: list[str] = []
    for item in raw if isinstance(raw, (list, tuple)) else []:
        slot = normalize_slot(item)
        if slot in CREW_SLOTS and slot not in out:
            out.append(slot)
    return [slot for slot in CREW_SLOTS if slot in out]


def roles_of(slots: Iterable[Any]) -> list[str]:
    """Rodzaje ról, jakich oferta szuka: ["table"], ["field"] albo oba."""
    have = {role_of_slot(slot) for slot in slots}
    return [role for role in ROLES if role in have]


def suggest_slots(
    crew: Mapping[str, Any],
    editable: Iterable[str],
    needs: Mapping[str, int],
) -> dict[str, Any]:
    """
    Domyślne gniazda oferty: WOLNE gniazda, które okręg obsadza w tym meczu.

    `crew` to `assignment_rules.crew(state)`, `editable` - gniazda z prawa
    ręcznej obsady, `needs` - `club_crew_needs` (np. DRK: field 0, table 2).
    Zwraca także powód każdego pominięcia, żeby panel mógł je pokazać.
    """
    allowed = set(editable)
    picked: list[str] = []
    skipped: list[dict[str, str]] = []
    for group, order in (("field", FIELD_SLOTS), ("table", TABLE_SLOTS)):
        usable = [slot for slot in order if slot in allowed]
        have = sum(1 for slot in usable if crew.get(slot))
        missing = max(0, int(needs.get(group, 0) or 0) - have)
        for slot in order:
            if slot not in allowed:
                skipped.append({"slot": slot, "reason": "Okręg nie ma tu prawa do tego gniazda."})
            elif crew.get(slot):
                skipped.append({"slot": slot, "reason": "Gniazdo jest już obsadzone."})
            elif missing > 0:
                picked.append(slot)
                missing -= 1
            else:
                skipped.append({"slot": slot, "reason": "Okręg nie obsadza tego gniazda w tym meczu."})
    return {"slots": [s for s in CREW_SLOTS if s in picked], "skipped": skipped}


def slots_refusal(
    slots: list[str],
    crew: Mapping[str, Any],
    editable: Iterable[str],
) -> Optional[str]:
    if not slots:
        return "Wybierz co najmniej jedno wolne gniazdo do wystawienia."
    allowed = set(editable)
    for slot in slots:
        label = SLOT_LABELS.get(slot, slot)
        if slot not in allowed:
            return f"Okręg nie obsadza gniazda „{label}” w tym meczu, więc nie da się go wystawić."
        if crew.get(slot):
            return f"Gniazdo „{label}” jest już obsadzone. Zdejmij sędziego w Obsadzie albo odznacz to gniazdo."
    return None


# ───────────────────────────── filtr odznak ─────────────────────────────


def parse_filter(raw: Any) -> dict[str, Any]:
    """Filtr odznak {mode, badges}; zły kształt to ValueError z wyjaśnieniem."""
    if raw in (None, "", {}):
        return {"mode": MODE_NONE, "badges": []}
    if not isinstance(raw, Mapping):
        raise ValueError("Filtr odznak ma mieć postać {mode, badges}.")
    mode = _s(raw.get("mode")).lower() or MODE_NONE
    if mode not in (MODE_NONE, MODE_INCLUDE, MODE_EXCLUDE):
        raise ValueError("Filtr odznak: tryb to none, include (tylko ci z odznaką) albo exclude (bez tej odznaki).")
    badges: list[str] = []
    for item in raw.get("badges") or []:
        name = _s(item)
        if name and name not in badges:
            badges.append(name)
    if mode == MODE_NONE:
        return {"mode": MODE_NONE, "badges": []}
    if not badges:
        raise ValueError("Filtr odznak wymaga co najmniej jednej odznaki albo trybu none.")
    return {"mode": mode, "badges": badges}


def passes_filter(badges_raw: Any, flt: Mapping[str, Any]) -> bool:
    mode = _s(flt.get("mode")) or MODE_NONE
    if mode == MODE_NONE:
        return True
    wanted = {fold(b) for b in flt.get("badges") or []}
    has = {fold(b) for b in badge_names(badges_raw)}
    hit = bool(wanted & has)
    return hit if mode == MODE_INCLUDE else not hit


def filter_sentence(flt: Mapping[str, Any]) -> str:
    mode = _s(flt.get("mode"))
    names = ", ".join(flt.get("badges") or [])
    if mode == MODE_INCLUDE:
        return f"Oferta jest dla sędziów z odznaką: {names}."
    if mode == MODE_EXCLUDE:
        return f"Oferta nie jest dla sędziów z odznaką: {names}."
    return ""


# ───────────────────────────── termin i stan ─────────────────────────────


def default_deadline(match_at: Optional[datetime]) -> Optional[datetime]:
    match_at = _utc(match_at)
    return match_at - timedelta(hours=DEFAULT_DEADLINE_HOURS) if match_at else None


def deadline_refusal(
    deadline: Optional[datetime], match_at: Optional[datetime], now: datetime
) -> Optional[str]:
    deadline, match_at = _utc(deadline), _utc(match_at)
    if match_at is not None and match_at <= now:
        return "Ten mecz już się rozpoczął, nie ma czego wystawiać."
    if deadline is None:
        return None
    if deadline <= now:
        return "Termin zgłoszeń jest w przeszłości. Ustaw późniejszy albo zostaw domyślny (24 h przed meczem)."
    if match_at is not None and deadline > match_at:
        return "Termin zgłoszeń nie może być po rozpoczęciu meczu."
    return None


def accepting_claims(status: Any, deadline: Optional[datetime], now: datetime) -> bool:
    deadline = _utc(deadline)
    return _s(status) == OPEN and (deadline is None or now < deadline)


def effective_status(
    status: Any,
    deadline: Optional[datetime],
    match_at: Optional[datetime],
    active_claims: int,
    now: datetime,
) -> str:
    """
    Stan oferty z uwzględnieniem czasu (sprawdzenie leniwe, bez zadania w tle).

    Po terminie oferta bez zgłoszeń wygasa od razu. Ze zgłoszeniami zostaje
    otwarta do decyzji obsadowego (nie przyjmuje już nowych), a gasi ją
    dopiero początek meczu.
    """
    if _s(status) != OPEN:
        return _s(status)
    match_at, deadline = _utc(match_at), _utc(deadline)
    if match_at is not None and now >= match_at:
        return EXPIRED
    if deadline is not None and now >= deadline and active_claims <= 0:
        return EXPIRED
    return OPEN


def offer_filled(slots: Iterable[str], assigned: Mapping[str, Any]) -> bool:
    wanted = list(slots)
    return bool(wanted) and all(slot in assigned for slot in wanted)


# ───────────────────────────── zgłoszenia ─────────────────────────────


def resolve_role(offer_roles: list[str], requested: Any) -> tuple[str, Optional[str]]:
    """(rola, odmowa). Wybór roli jest wymagany tylko, gdy oferta ma oba rodzaje."""
    want = _s(requested).lower()
    if want and want not in ROLES:
        return "", "Rola to „table” (stolik) albo „field” (boisko)."
    if len(offer_roles) == 1:
        only = offer_roles[0]
        if want and want != only:
            return "", f"Ta oferta szuka tylko: {ROLE_LABELS[only]}. Zgłoś się na tę rolę."
        return only, None
    if not want:
        return "", "Ta oferta szuka i boiskowych, i stolikowych. Wybierz, na którą rolę się zgłaszasz."
    if want not in offer_roles:
        return "", "Ta oferta nie szuka takiej roli."
    return want, None


def claim_refusal(
    *,
    status: Any,
    deadline: Optional[datetime],
    match_at: Optional[datetime],
    now: datetime,
    flt: Mapping[str, Any],
    badges_raw: Any,
    holds_slot_in_match: bool,
    role_blocked: Optional[str] = None,
    manager: bool = False,
) -> Optional[str]:
    """Powód odmowy zgłoszenia albo None. Zawsze zdanie, nigdy cisza.

    `manager` - obsadowy okręgu albo administrator. Sam wystawia ofertę, więc
    filtr odznak (skierowany do zwykłych sędziów) go nie dotyczy; termin,
    zamknięcie, miejsce w obsadzie i reguły ról - tak jak każdego.
    """
    if _s(status) != OPEN:
        return "Ta oferta jest już zamknięta."
    if match_at is not None and now >= _utc(match_at):
        return "Ten mecz już się rozpoczął."
    if deadline is not None and now >= _utc(deadline):
        return "Minął termin zgłoszeń do tego meczu."
    if not manager and not passes_filter(badges_raw, flt):
        return "Ta oferta jest ograniczona odznakami, a Ty nie spełniasz warunku. " + filter_sentence(flt)
    if holds_slot_in_match:
        return "Jesteś już w obsadzie tego meczu."
    if role_blocked:
        return role_blocked
    return None


def crew_metrics_pending(quick: bool, metrics: Mapping[str, Mapping[str, Any]]) -> bool:
    """
    Szybki odczyt (bez Google): czy ktoś ma nieznane km, które Google może
    jeszcze dać (znane miasto skąd i dokąd). Pełny odczyt nigdy nie każe
    pobierać drugi raz.
    """
    if not quick:
        return False
    for m in metrics.values():
        km = m.get("km") or {}
        if isinstance(km, Mapping) and km.get("source") == "unknown" and _s(km.get("from")) and _s(km.get("to")):
            return True
    return False


def claim_province_refusal(
    *,
    known: bool,
    judge_province: Any,
    offer_province: Any,
    manager: bool,
) -> Optional[str]:
    """Czy ten numer sędziego może zgłosić się na ofertę z tego okręgu.

    Zwykły sędzia - tylko we własnym okręgu (z listy sędziów okręgu). Obsadowy
    i administrator, który może zarządzać ofertą, zgłasza się swoim numerem
    sędziego także wtedy, gdy na liście okręgu go nie ma (admin z innego okręgu).
    """
    if manager:
        return None
    if not known:
        return "Nie ma Cię na liście sędziów okręgu, więc nie możesz zgłosić się na tę ofertę. Zgłoś to administratorowi okręgu."
    if _s(judge_province) != _s(offer_province):
        return "Ta oferta jest z innego okręgu niż Twój."
    return None


def partner_refusal(
    *,
    role: str,
    partner_id: str,
    self_id: str,
    offer_field_slots: int,
    partner_known: bool,
    partner_passes: bool,
    partner_role_blocked: Optional[str] = None,
) -> Optional[str]:
    if not partner_id:
        return None
    if role != ROLE_FIELD:
        return "Parę można zgłosić tylko na boisko."
    if partner_id == self_id:
        return "Nie możesz być własnym partnerem."
    if offer_field_slots < 2:
        return "W tej ofercie jest jedno miejsce boiskowe, więc nie ma dla kogo szukać pary."
    if not partner_known:
        return "Nie ma takiego sędziego w Twoim okręgu."
    if not partner_passes:
        return "Wskazany partner nie spełnia filtra odznak tej oferty."
    if partner_role_blocked:
        return f"Wskazany partner nie może stanąć na boisku: {partner_role_blocked}."
    return None


def packages(claims: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Pakiety boiskowe: dwoje zgłoszonych, którzy wskazali siebie nawzajem."""
    live = {
        _s(c.get("judge_id")): c
        for c in claims
        if _s(c.get("status")) in ACTIVE_CLAIMS and _s(c.get("role")) == ROLE_FIELD
    }
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for judge_id, claim in live.items():
        partner = _s(claim.get("partner_id"))
        other = live.get(partner)
        if not partner or other is None or _s(other.get("partner_id")) != judge_id:
            continue
        key = "|".join(sorted((judge_id, partner)))
        if key in seen:
            continue
        seen.add(key)
        out.append({"judge_ids": sorted((judge_id, partner)), "claim_ids": sorted((claim["id"], other["id"]))})
    return out


def pick_slot(
    offer_slots: list[str],
    assigned: Mapping[str, Any],
    role: str,
    requested: Any = "",
) -> tuple[str, Optional[str]]:
    """Gniazdo dla przydzielanego zgłoszenia (puste -> pierwsze wolne tej roli)."""
    free = [s for s in offer_slots if s not in assigned and role_of_slot(s) == role]
    want = normalize_slot(requested) if _s(requested) else ""
    if _s(requested) and not want:
        return "", f"Nieznane gniazdo „{_s(requested)}”."
    if want:
        if want not in offer_slots:
            return "", "To gniazdo nie jest częścią oferty."
        if want in assigned:
            return "", f"Gniazdo „{SLOT_LABELS[want]}” jest już przydzielone. Cofnij przydział, żeby je zmienić."
        if role_of_slot(want) != role:
            return "", f"To zgłoszenie jest na rolę: {ROLE_LABELS[role]}, a gniazdo „{SLOT_LABELS[want]}” jest innej roli."
        return want, None
    if not free:
        return "", f"Wszystkie gniazda roli „{ROLE_LABELS[role]}” są już przydzielone."
    return free[0], None


# ───────────────────────────── kilometry ─────────────────────────────


def km_chain(
    origin: Any,
    destination: Any,
    *,
    district: Callable[[Any, Any], Optional[float]],
    national: Callable[[Any, Any], Optional[float]],
    remembered: Callable[[Any, Any], Optional[float]],
    same_city: Callable[[Any, Any], bool],
) -> dict[str, Any]:
    """
    Kilometry z JAWNYM źródłem: to samo miasto -> tabela okręgu (wg daty meczu)
    -> tabela ogólnopolska ZPRP -> pamięć Google. Brak = unknown (nie zero).
    """
    if not _s(origin) or not _s(destination):
        return {"km": None, "source": "unknown"}
    if same_city(origin, destination):
        return {"km": 0.0, "source": "same_city"}
    for source, lookup in (
        ("district_table", district),
        ("national_table", national),
        ("google", remembered),
    ):
        value = lookup(origin, destination)
        if value is not None:
            return {"km": round(float(value), 1), "source": source}
    return {"km": None, "source": "unknown"}


# ───────────────────────────── obciążenie i odstępy ─────────────────────────────


def week_bounds(day: date) -> tuple[date, date]:
    monday = day - timedelta(days=day.weekday())
    return monday, monday + timedelta(days=6)


def judge_load_view(
    entries: Iterable[Mapping[str, Any]],
    match: Mapping[str, Any],
    km_between: Callable[[Any, Any], Optional[float]],
    rules: Optional[CollisionRules] = None,
) -> dict[str, Any]:
    """
    Co sędzia już ma wokół tego meczu.

    `entries` - jego inne mecze: {match_id, moment, code, hall, venue, city};
    `match` - {match_id, moment, code, hall, venue, city}. Zwraca liczbę meczów
    w tygodniu meczu, najbliższy mecz i stopień ostrzeżenia o odstępie
    (yellow / orange / red wg `gap_grade`, jak przy ręcznej obsadzie).
    Ostrzeżenie NIE blokuje: decyzja należy do obsadowego.
    """
    moment = match.get("moment")
    others = [e for e in entries if _s(e.get("match_id")) != _s(match.get("match_id"))]
    week = 0
    if moment is not None:
        start, end = week_bounds(moment.date())
        week = sum(1 for e in others if e.get("moment") and start <= e["moment"].date() <= end)
    dated = [e for e in others if e.get("moment") and moment is not None]
    dated.sort(key=lambda e: abs((e["moment"] - moment).total_seconds()))
    nearest = None
    collisions: list[dict[str, Any]] = []
    worst = None
    order = {"yellow": 1, "orange": 2, "red": 3}
    for entry in dated:
        hours = abs((entry["moment"] - moment).total_seconds()) / 3600.0
        if nearest is None:
            nearest = {
                "match_id": _s(entry.get("match_id")),
                "code": _s(entry.get("code")),
                "at": entry["moment"].isoformat(),
                "gap_minutes": int(round(hours * 60)),
                "city": _s(entry.get("city")),
            }
        if hours > 36:
            continue
        same_venue = same_hall(
            entry.get("hall"), entry.get("city"), match.get("hall"), match.get("city"),
            a_venue=entry.get("venue"), b_venue=match.get("venue"),
        )
        km = 0.0 if same_venue else km_between(entry.get("city"), match.get("city"))
        grade = gap_grade(
            entry["moment"], moment, km,
            first_code=entry.get("code"), second_code=match.get("code"),
            same_venue=same_venue, rules=rules,
        )
        if grade is None:
            continue
        item = {
            "match_id": _s(entry.get("match_id")),
            "code": _s(entry.get("code")),
            "at": entry["moment"].isoformat(),
            "level": grade.level,
            "shortfall_minutes": grade.shortfall,
            "overlap": grade.overlap,
        }
        collisions.append(item)
        if worst is None or order[grade.level] > order[worst["level"]]:
            worst = item
    return {
        "week_matches": week,
        "nearest": nearest,
        "gap": (
            {"level": worst["level"], "shortfall_minutes": worst["shortfall_minutes"], "overlap": worst["overlap"]}
            if worst else None
        ),
        "collisions": collisions,
    }


# ───────────────────────────── powiadomienia ─────────────────────────────


def _match_line(offer: Mapping[str, Any]) -> str:
    code = _s(offer.get("match_code"))
    teams = teams_of(offer.get("match_snapshot"))
    return " ".join(p for p in (code, teams) if p)


def _join(*parts: str) -> str:
    out = []
    for part in parts:
        text = _s(part)
        if text:
            out.append(text if text.endswith((".", "!", "?")) else text + ".")
    return " ".join(out)


def roles_phrase(slots: Iterable[str]) -> str:
    return ", ".join(slot_for(s) for s in slots)


def text_new_offer(offer: Mapping[str, Any], slots: list[str]) -> tuple[str, str]:
    return (
        "Nowy mecz do wzięcia",
        _join(_match_line(offer), when_of(offer), "Szukamy: " + roles_phrase(slots), "Zgłoś się w aplikacji"),
    )


def text_assigned(offer: Mapping[str, Any], slot: str) -> tuple[str, str]:
    return (
        "Przydzielono Cię",
        _join(f"Obsadowy przydzielił Cię do meczu {_match_line(offer)} jako {SLOT_LABELS.get(slot, slot)}", when_of(offer)),
    )


def text_unassigned(offer: Mapping[str, Any]) -> tuple[str, str]:
    return ("Cofnięto przydział", _join(f"Obsadowy cofnął Twój przydział do meczu {_match_line(offer)}", when_of(offer)))


def text_filled(offer: Mapping[str, Any]) -> tuple[str, str]:
    return ("Mecz obsadzony", _join(f"Mecz {_match_line(offer)} został już obsadzony. Dziękujemy za zgłoszenie", when_of(offer)))


def text_withdrawn(offer: Mapping[str, Any]) -> tuple[str, str]:
    return ("Oferta wycofana", _join(f"Obsadowy wycofał ofertę na mecz {_match_line(offer)}", when_of(offer)))
