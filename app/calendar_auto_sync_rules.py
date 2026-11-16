"""Kalendarz Google w tle (16.11.2026, BAZA 2.1.8): reguły czyste, bez bazy i bez Google.

Serwer sam dodaje, poprawia i usuwa mecze w kalendarzu sędziego - także wtedy,
gdy nikt nie otwiera aplikacji. Źródłem prawdy jest monitor okręgu
(``province_matches`` + ``province_match_judges``), więc działa to dla meczów,
które monitor zna (okręgi ze skonfigurowanym kontem ZPRP).

Tytuł, miejsce, godzina i przypomnienia MUSZĄ wyglądać tak samo jak z telefonu
(``BAZA/utils/calendarHelpers.ts::buildCalendarPayload`` i
``utils/calendarReminderRules.ts``) - inaczej wpis z serwera i wpis z telefonu
nadpisywałyby się nawzajem przy każdym otwarciu aplikacji. Zmiana tam = zmiana tu.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")

BALL = "⚽️"  # ⚽️ - mecz boiskowy
STOPWATCH = "⏱️"  # ⏱️ - mecz stolikowy
MATCH_DURATION = timedelta(hours=2)

#: Role stolikowe (ikona stopera i kolor stolikowy) - jak ``isUserTableOfficial`` w aplikacji.
TABLE_ROLE_FIELDS = ("NrSedzia_sekretarz", "NrSedzia_czas")
CREW_ROLE_FIELDS = (
    "NrSedzia_pierwszy",
    "NrSedzia_drugi",
    "NrSedzia_sekretarz",
    "NrSedzia_czas",
    "NrSedzia_delegat",
    "NrSedzia_delegat2",
)

MAX_REMINDER_RULES = 5
GOOGLE_MAX_MINUTES = 40320
DEFAULT_REMINDER_RULES: List[Dict[str, Any]] = [
    {"kind": "before", "minutes": 24 * 60, "method": "popup"},
    {"kind": "before", "minutes": 3 * 60, "method": "popup"},
    {"kind": "at", "hour": 7, "minute": 0, "method": "popup"},
]

_DATE_RE = re.compile(r"^\s*(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?")


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


# ── Przypomnienia (port utils/calendarReminderRules.ts) ─────────────────────


def _clean_rule(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    method = "email" if raw.get("method") == "email" else "popup"
    try:
        if raw.get("kind") == "before":
            minutes = round(float(raw.get("minutes")))
            if minutes <= 0 or minutes > GOOGLE_MAX_MINUTES:
                return None
            return {"kind": "before", "minutes": minutes, "method": method}
        if raw.get("kind") == "at":
            hour = round(float(raw.get("hour")))
            minute = round(float(raw.get("minute") or 0))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                return None
            return {"kind": "at", "hour": hour, "minute": minute, "method": method}
    except (TypeError, ValueError):
        return None
    return None


def normalize_reminder_rules(raw: Any) -> Optional[List[Dict[str, Any]]]:
    """``None`` = sędzia nie wybierał (domyślne), ``[]`` = świadomie bez przypomnień."""
    if not isinstance(raw, list):
        return None
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for item in raw:
        rule = _clean_rule(item)
        if not rule:
            continue
        when = f"b{rule['minutes']}" if rule["kind"] == "before" else f"a{rule['hour']}:{rule['minute']}"
        key = f"{when}|{rule['method']}"
        if key in seen:
            continue
        seen.add(key)
        out.append(rule)
        if len(out) == MAX_REMINDER_RULES:
            break
    return out


def reminders_for_start(start: datetime, raw_rules: Any) -> List[Dict[str, Any]]:
    rules = normalize_reminder_rules(raw_rules)
    if rules is None:
        rules = [dict(r) for r in DEFAULT_REMINDER_RULES]
    local = start.astimezone(WARSAW)
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for rule in rules:
        if rule["kind"] == "before":
            minutes = int(rule["minutes"])
        else:
            at = datetime(local.year, local.month, local.day, rule["hour"], rule["minute"], tzinfo=WARSAW)
            minutes = round((start - at).total_seconds() / 60)
            if minutes <= 0:
                continue
        key = f"{rule['method']}|{minutes}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"method": rule["method"], "minutes": minutes})
    return out


# ── Mecz -> wpis ────────────────────────────────────────────────────────────


def match_start(state: Mapping[str, Any]) -> Optional[datetime]:
    """Godzina meczu (czas polski -> UTC). Bez godziny (sama data) wpisu nie robimy."""
    if state.get("data_fakt_time_known") is False:
        return None
    m = _DATE_RE.match(_s(state.get("data_fakt") or state.get("dateTime")))
    if not m or m.group(4) is None:
        return None
    y, mo, d, h, mi = (int(m.group(i)) for i in range(1, 6))
    try:
        return datetime(y, mo, d, h, mi, tzinfo=WARSAW).astimezone(timezone.utc)
    except ValueError:
        return None


def judge_role(state: Mapping[str, Any], judge_id: str) -> Optional[str]:
    """``"table"`` / ``"field"`` - albo ``None``, gdy sędziego nie ma w obsadzie."""
    jid = _s(judge_id)
    if not jid:
        return None
    for field in TABLE_ROLE_FIELDS:
        if _s(state.get(field)) == jid:
            return "table"
    for field in CREW_ROLE_FIELDS:
        if _s(state.get(field)) == jid:
            return "field"
    return None


def _sides(state: Mapping[str, Any]) -> tuple[str, str]:
    host = _s(state.get("ID_zespoly_gosp_ZespolNazwa"))
    guest = _s(state.get("ID_zespoly_gosc_ZespolNazwa"))
    swapped = state.get("host_swapped") is True or _s(state.get("zamiana")) == "1"
    # Przy zamianie pierwszy jest gospodarz hali (nominalny gość) - jak na kafelku w aplikacji.
    return (guest, host) if swapped else (host, guest)


def location_of(state: Mapping[str, Any]) -> str:
    raw = f"{_s(state.get('Hala_miasto'))} ul. {_s(state.get('Hala_ulica'))} {_s(state.get('Hala_numer'))}"
    return re.sub(r"\s+", " ", raw).strip()


@dataclass(frozen=True)
class Profile:
    """Ustawienia kalendarza sędziego (z aplikacji): kolory ról i reguły przypomnień."""

    user_login: str
    judge_id: str
    match_color: str = "11"
    table_color: str = "10"
    reminder_rules: Any = None


def desired_event(state: Mapping[str, Any], match_id: str, profile: Profile) -> Optional[Dict[str, Any]]:
    """Wpis, jaki dałaby aplikacja (`EventCreate` z ``app/calendar.py``) - albo ``None`` (brak godziny / roli)."""
    role = judge_role(state, profile.judge_id)
    start = match_start(state)
    if role is None or start is None:
        return None
    host, guest = _sides(state)
    prefix = STOPWATCH if role == "table" else BALL
    return {
        "matchId": match_id,
        "summary": f"{prefix} {_s(state.get('RozgrywkiCode'))} - {host} vs {guest}",
        "start": start,
        "end": start + MATCH_DURATION,
        "location": location_of(state),
        "colorId": profile.table_color if role == "table" else profile.match_color,
        "reminders": reminders_for_start(start, profile.reminder_rules),
    }


def event_fingerprint(summary: str, start: datetime, location: str, reminders: Any = None) -> str:
    """Odcisk pól, których zmiana wymaga poprawienia wpisu (tytuł, godzina, miejsce, przypomnienia)."""
    start_utc = start.astimezone(timezone.utc).replace(microsecond=0).isoformat() if start.tzinfo else start.replace(microsecond=0).isoformat()
    payload = json.dumps([_s(summary), start_utc, _s(location), reminders or []], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def fingerprint_of(event: Mapping[str, Any]) -> str:
    return event_fingerprint(event["summary"], event["start"], event["location"], event.get("reminders"))


# ── Plan uzgodnienia ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Known:
    """Wpis, który już jest w kalendarzu (mapowanie) i jego ostatni znany odcisk (``None`` = nie wiemy)."""

    match_id: str
    fingerprint: Optional[str]


@dataclass
class Plan:
    create: List[Dict[str, Any]]
    update: List[Dict[str, Any]]
    delete: List[str]
    #: Wpisy z telefonu bez odcisku: zapamiętujemy odcisk bez zapisu do Google (nie ruszamy kalendarza na ślepo).
    seed: List[Dict[str, Any]]


def plan_sync(
    *,
    desired: Mapping[str, Optional[Dict[str, Any]]],
    known: Iterable[Known],
    monitored_future: set[str],
) -> Plan:
    """Co zrobić z kalendarzem jednego sędziego.

    ``desired``          - mecze sędziego z monitora (przyszłe): match_id -> wpis albo None (brak godziny).
    ``known``            - mapowania wpisów, które już są w jego kalendarzu.
    ``monitored_future`` - przyszłe mecze, które monitor ZNA (także te, w których sędziego już nie ma).
                           Usuwamy wyłącznie wpisy z tej puli: mecz spoza monitora (inny okręg, liga
                           centralna) albo z przeszłości zostaje nietknięty.
    """
    known_by_id = {k.match_id: k for k in known}
    plan = Plan(create=[], update=[], delete=[], seed=[])
    for match_id, event in desired.items():
        if event is None:
            continue
        k = known_by_id.get(match_id)
        fp = fingerprint_of(event)
        if k is None:
            plan.create.append(event)
        elif k.fingerprint is None:
            plan.seed.append(event)
        elif k.fingerprint != fp:
            plan.update.append(event)
    for match_id in known_by_id:
        if match_id in desired:
            continue
        if match_id in monitored_future:
            plan.delete.append(match_id)
    return plan


def clean_color(value: Any, default: str) -> str:
    v = _s(value)
    if re.fullmatch(r"\d{1,2}", v) or re.fullmatch(r"[0-9a-fA-F-]{8,64}", v):
        return v
    return default
