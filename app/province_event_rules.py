"""
Wydarzenia okręgowe - reguły bez bazy i bez sieci.

Decyzje użytkownika z 17.09.2026 (przebudowa wydarzeń w panelu okręgowym):
  - sędzia odpowiada „Będę" albo „Nie będę" (powód opcjonalny) do terminu
    odpowiedzi albo do startu; „Będę" widzą wszyscy zaproszeni, odmowy i ich
    powody tylko komisja,
  - wydarzenie ma typ, koniec, miejsce albo link online, znacznik
    obowiązkowości, termin odpowiedzi, limit miejsc i program,
  - ZAPROSZENI liczą się przy każdym odczycie z aktualnych odznak. Dawniej
    lista zamarzała przy tworzeniu i sędzia z odznaką nadaną później nie
    widział wydarzenia, dopóki ktoś go nie edytował,
  - obecność: obecny / usprawiedliwiony / brak wpisu = nieobecny; komisja
    zaznacza ręcznie, sędzia może też wbić się kodem (QR albo 4 znaki),
  - odwołanie zostaje widoczne z powodem; usunięte leży 30 dni w koszu,
  - wydarzenia cykliczne rozpisują się na osobne wiersze jednej serii,
  - push: nowe, zmiana, odwołanie od razu; przypomnienia dobę i godzinę
    przed oraz ponaglenie o brak odpowiedzi dobę przed terminem - z przejścia
    w tle, bo restart Railway zjadłby zadanie odroczone w pamięci.
"""

from __future__ import annotations

import calendar
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.board_rules import Invalid, clean_url, has_committee_badge
from app.match_market_access import badge_names
from app.settlement_province import canonical

try:  # pragma: no cover - strefa jest na serwerze; bez niej liczymy w UTC
    from zoneinfo import ZoneInfo

    WARSAW = ZoneInfo("Europe/Warsaw")
except Exception:  # noqa: BLE001
    WARSAW = timezone.utc

# ---------------------------------------------------------------------------
# Słowniki
# ---------------------------------------------------------------------------

EVENT_TYPES: Dict[str, str] = {
    "training": "Szkolenie",
    "exam": "Egzamin",
    "fitness_test": "Egzamin kondycyjny",
    "meeting": "Zebranie",
    "conference": "Konferencja",
    "course": "Kurs",
    "integration": "Integracja",
    "other": "Inne",
}
DEFAULT_TYPE = "other"

RSVP_STATUSES = ("yes", "no")
ATTENDANCE_STATUSES = ("present", "excused")
ATTENDANCE_SOURCES = ("manual", "qr", "code", "legacy")
RECURRENCE_RULES = ("weekly", "biweekly", "monthly")

TRASH_DAYS = 30
NAME_MAX = 200
DESCRIPTION_MAX = 4000
REASON_MAX = 300
PLACE_MAX = 200
PROGRAM_MAX = 30
PROGRAM_TITLE_MAX = 140
CAPACITY_MAX = 5000
MAX_OCCURRENCES = 26
MAX_DURATION = timedelta(days=14)

#: Kod do wpisania: bez O/0 i I/1, żeby nie mylić znaków na rzutniku.
CHECKIN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CHECKIN_CODE_LEN = 4
CHECKIN_OPEN_BEFORE = timedelta(hours=2)
CHECKIN_CLOSE_AFTER = timedelta(hours=2)
#: Wydarzenie bez końca trwa na potrzeby kodu tyle.
ASSUMED_DURATION = timedelta(hours=3)
QR_PREFIX = "BAZA-EVENT"

REMINDER_DAY = timedelta(hours=24)
REMINDER_HOUR = timedelta(hours=1)
RSVP_NUDGE = timedelta(hours=24)

NOTIFY_KINDS = ("new", "changed", "cancelled", "day", "hour", "rsvp")

_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _ids(values: Any) -> List[str]:
    out: List[str] = []
    for value in values or []:
        text = _s(value)
        if text and text not in out:
            out.append(text)
    return out


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def parse_iso(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return _aware(value)
    text = _s(value)
    if not text:
        return None
    try:
        return _aware(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError as error:
        raise Invalid("Niepoprawna data") from error


# ---------------------------------------------------------------------------
# Dostęp
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Viewer:
    judge_id: str
    province: str
    is_admin: bool
    is_commission: bool


def viewer(*, judge_id: Any, province: Any, is_admin: bool, badges: Any) -> Viewer:
    return Viewer(
        judge_id=_s(judge_id),
        province=_s(province).upper(),
        is_admin=bool(is_admin),
        is_commission=has_committee_badge(badges),
    )


def same_province(a: Any, b: Any) -> bool:
    """„ŚLĄSKIE", „Śląskie" i „SLASKIE" to ten sam okręg - lista sędziów trzyma klucz bez znaków."""
    left, right = canonical(a), canonical(b)
    return bool(left) and left == right


def can_manage(who: Viewer, event_province: str) -> bool:
    """Admin wszędzie, komisja sędziowska tylko we własnym okręgu."""
    if who.is_admin:
        return True
    return who.is_commission and same_province(who.province, event_province)


def can_view_province(who: Viewer, province: str) -> bool:
    return who.is_admin or same_province(who.province, province)


# ---------------------------------------------------------------------------
# Zaproszeni
# ---------------------------------------------------------------------------


def invited_ids(judges: Iterable[Mapping[str, Any]], data: Mapping[str, Any]) -> List[str]:
    """Zaproszeni z aktualnych odznak okręgu.

    Kolejność pierwszeństwa: ręczne wyłączenie osoby, ręczne dopisanie osoby,
    wykluczona odznaka, potem „do wszystkich" albo odznaki uwzględnione.
    Wydarzenie bez żadnego kryterium (stare rekordy) idzie do wszystkich -
    tak liczył je dawny serwer i nie wolno ich teraz nikomu schować.
    """
    target = data.get("target") if isinstance(data.get("target"), Mapping) else {}
    include_all = bool(target.get("include_all"))
    include_badges = set(_ids(target.get("include_badges")))
    exclude_badges = set(_ids(target.get("exclude_badges")))
    include_people = set(_ids(data.get("include_ids")))
    exclude_people = set(_ids(data.get("exclude_ids")))
    no_criteria = not include_all and not include_badges and not include_people

    out: List[str] = []
    for judge in judges:
        jid = _s(judge.get("judge_id"))
        if not jid or jid in exclude_people:
            continue
        if jid in include_people:
            out.append(jid)
            continue
        names = set(badge_names(judge.get("badges")))
        if names & exclude_badges:
            continue
        if include_all or no_criteria or (names & include_badges):
            out.append(jid)
    return sorted(set(out))


# ---------------------------------------------------------------------------
# Walidacja
# ---------------------------------------------------------------------------


def clean_name(value: Any) -> str:
    text = _s(value)
    if not text:
        raise Invalid("Podaj nazwę wydarzenia")
    if len(text) > NAME_MAX:
        raise Invalid(f"Nazwa ma najwyżej {NAME_MAX} znaków")
    return text


def clean_description(value: Any) -> Optional[str]:
    text = str(value if value is not None else "").strip()
    if len(text) > DESCRIPTION_MAX:
        raise Invalid(f"Opis ma najwyżej {DESCRIPTION_MAX} znaków")
    return text or None


def clean_type(value: Any) -> str:
    text = _s(value)
    if not text:
        return DEFAULT_TYPE
    if text not in EVENT_TYPES:
        raise Invalid("Nieznany typ wydarzenia")
    return text


def clean_period(start: Any, end: Any) -> Tuple[datetime, Optional[datetime]]:
    begin = parse_iso(start)
    if begin is None:
        raise Invalid("Podaj datę i godzinę rozpoczęcia")
    finish = parse_iso(end)
    if finish is not None:
        if finish <= begin:
            raise Invalid("Koniec musi być później niż początek")
        if finish - begin > MAX_DURATION:
            raise Invalid("Wydarzenie może trwać najwyżej 14 dni")
    return begin, finish


def clean_reason(value: Any) -> Optional[str]:
    text = _s(value)
    if len(text) > REASON_MAX:
        raise Invalid(f"Powód ma najwyżej {REASON_MAX} znaków")
    return text or None


def clean_place(value: Any) -> Dict[str, Optional[str]]:
    raw = value if isinstance(value, Mapping) else {}
    name, address = _s(raw.get("name")), _s(raw.get("address"))
    if len(name) > PLACE_MAX or len(address) > PLACE_MAX:
        raise Invalid(f"Miejsce ma najwyżej {PLACE_MAX} znaków")
    return {"name": name or None, "address": address or None}


def clean_program(items: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for index, item in enumerate(items or []):
        if not isinstance(item, Mapping):
            continue
        title = _s(item.get("title"))
        if not title:
            continue
        if len(title) > PROGRAM_TITLE_MAX:
            raise Invalid(f"Punkt programu ma najwyżej {PROGRAM_TITLE_MAX} znaków")
        time = _s(item.get("time"))
        if time and not _TIME.match(time):
            raise Invalid("Godzina w programie ma format GG:MM")
        out.append({"id": _s(item.get("id")) or f"p{index + 1}", "time": time or None, "title": title})
    if len(out) > PROGRAM_MAX:
        raise Invalid(f"Program ma najwyżej {PROGRAM_MAX} punktów")
    return out


def clean_capacity(value: Any) -> Optional[int]:
    if value in (None, "", 0, "0"):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise Invalid("Limit miejsc to liczba") from error
    if number < 1 or number > CAPACITY_MAX:
        raise Invalid(f"Limit miejsc od 1 do {CAPACITY_MAX}")
    return number


def clean_deadline(value: Any, start: datetime) -> Optional[datetime]:
    deadline = parse_iso(value)
    if deadline is None:
        return None
    if deadline > start:
        raise Invalid("Termin odpowiedzi musi być przed rozpoczęciem")
    return deadline


def clean_target(value: Any) -> Dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    return {
        "include_all": bool(raw.get("include_all")),
        "include_badges": _ids(raw.get("include_badges")),
        "exclude_badges": _ids(raw.get("exclude_badges")),
    }


def clean_details(raw: Mapping[str, Any], start: datetime) -> Dict[str, Any]:
    """Pola trzymane w `data_json` - wszystko poza nazwą, opisem i datami."""
    deadline = clean_deadline(raw.get("rsvp_deadline"), start)
    return {
        "target": clean_target(raw.get("target")),
        "include_ids": _ids(raw.get("include_ids")),
        "exclude_ids": _ids(raw.get("exclude_ids")),
        "place": clean_place(raw.get("place")),
        "online_url": clean_url(raw.get("online_url")),
        "obligatory": bool(raw.get("obligatory")),
        "rsvp_deadline": deadline.isoformat() if deadline else None,
        "capacity": clean_capacity(raw.get("capacity")),
        "program": clean_program(raw.get("program")),
    }


# ---------------------------------------------------------------------------
# Odpowiedzi
# ---------------------------------------------------------------------------


def rsvp_refusal(
    *,
    now: datetime,
    start: datetime,
    deadline: Optional[datetime],
    cancelled: bool,
    invited: bool,
    status: str,
    current: Optional[str],
    yes_count: int,
    capacity: Optional[int],
) -> Optional[str]:
    """Powód odmowy po polsku albo None, gdy odpowiedź można zapisać."""
    if status not in RSVP_STATUSES:
        return "Odpowiedź to „Będę” albo „Nie będę”"
    if not invited:
        return "To wydarzenie nie jest skierowane do Ciebie"
    if cancelled:
        return "Wydarzenie zostało odwołane"
    if now >= start:
        return "Wydarzenie już się zaczęło - odpowiedzi są zamknięte"
    if deadline is not None and now > deadline:
        local = deadline.astimezone(WARSAW)
        return f"Termin odpowiedzi minął {local:%d.%m o %H:%M}"
    if status == "yes" and capacity and current != "yes" and yes_count >= capacity:
        return f"Brak wolnych miejsc - limit to {capacity}"
    return None


# ---------------------------------------------------------------------------
# Obecność i kody
# ---------------------------------------------------------------------------


def new_checkin_code() -> str:
    return "".join(secrets.choice(CHECKIN_ALPHABET) for _ in range(CHECKIN_CODE_LEN))


def new_checkin_token() -> str:
    return secrets.token_urlsafe(12)


def qr_payload(event_id: int, token: str) -> str:
    return f"{QR_PREFIX}|{int(event_id)}|{token}"


def parse_qr(value: Any) -> Optional[Tuple[int, str]]:
    parts = _s(value).split("|")
    if len(parts) != 3 or parts[0] != QR_PREFIX:
        return None
    try:
        return int(parts[1]), parts[2]
    except ValueError:
        return None


def normalize_code(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", _s(value).upper())


def checkin_window(start: datetime, end: Optional[datetime]) -> Tuple[datetime, datetime]:
    finish = end or (start + ASSUMED_DURATION)
    return start - CHECKIN_OPEN_BEFORE, finish + CHECKIN_CLOSE_AFTER


def checkin_refusal(
    *,
    now: datetime,
    start: datetime,
    end: Optional[datetime],
    cancelled: bool,
    invited: bool,
    code_matches: bool,
) -> Optional[str]:
    if cancelled:
        return "Wydarzenie zostało odwołane"
    if not invited:
        return "To wydarzenie nie jest skierowane do Ciebie"
    opens, closes = checkin_window(start, end)
    if now < opens:
        local = opens.astimezone(WARSAW)
        return f"Kod zadziała od {local:%d.%m %H:%M}"
    if now > closes:
        return "Czas na potwierdzenie obecności kodem minął - poproś komisję o wpis"
    if not code_matches:
        return "Ten kod nie pasuje do wydarzenia"
    return None


def attendance_state(
    judge_id: str,
    rows: Mapping[str, Mapping[str, Any]],
    legacy_present: Iterable[str],
) -> str:
    """present / excused / absent. Stara lista `present_ids` liczy się jako obecność."""
    row = rows.get(judge_id)
    if row:
        return _s(row.get("status")) or "present"
    return "present" if judge_id in set(_ids(legacy_present)) else "absent"


# ---------------------------------------------------------------------------
# Serie
# ---------------------------------------------------------------------------


def _add_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def expand_recurrence(
    start: datetime,
    end: Optional[datetime],
    rule: Any,
    until: Any,
) -> List[Tuple[datetime, Optional[datetime]]]:
    """Kolejne terminy serii w czasie POLSKIM - zmiana czasu nie przesuwa godziny."""
    kind = _s(rule)
    if not kind:
        return [(start, end)]
    if kind not in RECURRENCE_RULES:
        raise Invalid("Nieznana reguła powtarzania")
    last = parse_iso(until)
    if last is None:
        raise Invalid("Podaj datę końca serii")
    if last < start:
        raise Invalid("Koniec serii musi być po pierwszym terminie")
    local_start = start.astimezone(WARSAW)
    duration = (end - start) if end else None
    last_local_day = last.astimezone(WARSAW).date()
    out: List[Tuple[datetime, Optional[datetime]]] = []
    step = 0
    while True:
        if kind == "monthly":
            candidate = _add_months(local_start.replace(tzinfo=None), step)
        else:
            days = 7 if kind == "weekly" else 14
            candidate = local_start.replace(tzinfo=None) + timedelta(days=days * step)
        if candidate.date() > last_local_day:
            break
        begin = candidate.replace(tzinfo=WARSAW).astimezone(timezone.utc)
        out.append((begin, begin + duration if duration else None))
        step += 1
        if len(out) > MAX_OCCURRENCES:
            raise Invalid(f"Seria może mieć najwyżej {MAX_OCCURRENCES} terminów")
    return out


# ---------------------------------------------------------------------------
# Kosz
# ---------------------------------------------------------------------------


def restorable(deleted_at: Optional[datetime], now: datetime) -> bool:
    return deleted_at is not None and _aware(deleted_at) >= now - timedelta(days=TRASH_DAYS)


def days_left(deleted_at: datetime, now: datetime) -> int:
    left = (_aware(deleted_at) + timedelta(days=TRASH_DAYS)) - now
    return max(0, left.days + (1 if left.seconds else 0))


# ---------------------------------------------------------------------------
# Powiadomienia
# ---------------------------------------------------------------------------


def due_reminders(
    *,
    now: datetime,
    start: datetime,
    created_at: Optional[datetime],
    deadline: Optional[datetime],
    invited: Sequence[str],
    responses: Mapping[str, str],
    sent: Set[Tuple[str, str]],
) -> List[Tuple[str, List[str]]]:
    """Które przypomnienia wysłać teraz i komu. `sent` = pary (numer, rodzaj).

    - „day": dobę przed, jeśli wydarzenie powstało wcześniej niż dobę przed
      startem (świeże dostało już push „nowe"),
    - „hour": godzinę przed,
    - „rsvp": dobę przed terminem odpowiedzi do tych, którzy milczą.
    Kto odpowiedział „Nie będę", przypomnień o starcie nie dostaje.
    """
    out: List[Tuple[str, List[str]]] = []
    if now >= start:
        return out
    created = _aware(created_at)
    going = [jid for jid in invited if responses.get(jid) != "no"]

    def pending(kind: str, people: Iterable[str]) -> List[str]:
        return [jid for jid in people if (jid, kind) not in sent]

    if start - REMINDER_HOUR <= now:
        people = pending("hour", going)
        if people:
            out.append(("hour", people))
    elif start - REMINDER_DAY <= now and (created is None or created <= start - REMINDER_DAY):
        people = pending("day", going)
        if people:
            out.append(("day", people))

    if deadline is not None and deadline - RSVP_NUDGE <= now < deadline:
        silent = [jid for jid in invited if jid not in responses]
        people = pending("rsvp", silent)
        if people:
            out.append(("rsvp", people))
    return out


def meaningful_change(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    """Zmiana, o której warto powiadomić: termin albo miejsce, nie literówka w opisie."""
    keys = ("event_date", "end_date", "place", "online_url")
    return any(before.get(key) != after.get(key) for key in keys)


def local_label(value: datetime) -> str:
    local = value.astimezone(WARSAW)
    return f"{local:%d.%m} o {local:%H:%M}"


# ---------------------------------------------------------------------------
# Grafika tytułowa
# ---------------------------------------------------------------------------

TITLE_IMAGE_REGENERATIONS = 2

_IMAGE_SCENES = {
    "training": "an indoor handball hall prepared for a referee training session, whistle and cards on a bench in the foreground",
    "exam": "a quiet lecture room with exam sheets, a referee whistle and yellow and red cards resting on a desk",
    "fitness_test": "an athletics track at dawn with a referee stopwatch and running shoes, subtle handball hall in the distance",
    "meeting": "a modern meeting room with a long table, notebooks and a handball resting on a chair",
    "conference": "a conference auditorium with stage lights and a projector glow, handball court lines subtly reflected",
    "course": "a sports classroom with a tactics board showing a handball court diagram without any text",
    "integration": "a warm evening outdoor gathering near a sports hall with string lights and a handball on the grass",
    "other": "an empty indoor handball court with polished floor, goal and dramatic light beams",
}


def title_image_prompt(*, name: str, event_type: str, place: str, date_label: str, extra: str = "") -> str:
    scene = _IMAGE_SCENES.get(event_type, _IMAGE_SCENES["other"])
    return (
        "Landscape realistic editorial photograph used as a title image for a Polish handball referees "
        "district event in a mobile app. Not a cartoon, not CGI, no plastic-looking people. "
        f"Scene: {scene}. "
        "If people appear, show them naturally from behind or far away, no posed group photos, no visible faces. "
        "Warm cinematic light with deep shadows, premium minimalist composition, rich but calm colors. "
        "No text, no letters, no numbers, no logos, no badges, no watermarks. "
        "Leave darker open space in the lower-left area for app overlay text. "
        f"Event name inspiration: {name}. "
        f"Event type: {EVENT_TYPES.get(event_type, 'event')}. "
        f"Date context: {date_label or 'this season'}. "
        f"Location inspiration: {place or 'a Polish city'}; only a very subtle local reference."
        + (f" Additional context from organizer: {extra}" if extra else "")
    )
