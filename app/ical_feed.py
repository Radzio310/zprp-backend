"""Kalendarz w formacie iCal (ICS) zamieniony na wpisy niedyspozycji.

PO CO. Sędzia ma swój plan poza BAZĄ: zajęcia na uczelni, grafik w pracy, inny
kalendarz. Uczelnia (USOS) czy dowolny kalendarz udostępnia go linkiem w
formacie iCal, więc zamiast przepisywać zajęcia ręcznie wystarczy podać ten
link raz, a serwer będzie go czytał cyklicznie.

CZYSTY LIŚĆ. Ten moduł NIE chodzi do sieci i NIE zna bazy - dostaje tekst ICS,
oddaje gotowe wpisy. Dzięki temu da się go w całości przetestować, a reguły
czytania obcego formatu (a tam czai się cała trudność) nie są wymieszane z
pobieraniem i zapisem.

CZEGO NIE UDAJEMY. Nie jest to pełna implementacja RFC 5545: rozwijamy serie
dzienne, tygodniowe, miesięczne i roczne z ``INTERVAL``, ``COUNT``, ``UNTIL``,
``BYDAY`` i ``EXDATE`` - czyli to, z czego składają się plany zajęć i zwykłe
kalendarze. Reguła, której nie rozumiemy, daje samo pierwsze wystąpienie
zamiast wywracać cały import: lepiej pokazać mniej niż zgubić kalendarz.

⚠ CZAS. Wpisy niedyspozycji w BAZIE mają czas UTC (tak zapisuje je też
synchronizacja centralna), ale znaczą godziny polskie. Wydarzenie bez strefy
(„floating") i wydarzenie ze strefą, której nie znamy, czytamy jako czas
polski - to jedyna interpretacja, która ma sens dla sędziego w Polsce.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")

#: Znacznik źródła w danych niedyspozycji. Odróżnia wpisy z kalendarza od
#: ręcznych i od centralnych (``ZPRP_CENTRAL_SYNC``) - po nim poznajemy wpisy,
#: których właścicielem jest serwer i których telefon nie może nadpisać.
SOURCE = "CALENDAR_FEED"

#: Bezpieczniki. Semestr zajęć to ~15 powtórzeń na przedmiot, ale „codziennie
#: bez końca" rozwinęłoby się w nieskończoność, a cudzy plik może mieć i
#: dziesięć tysięcy wydarzeń.
MAX_OCCURRENCES_PER_EVENT = 500
MAX_EVENTS = 3000

WEEKDAYS = {"MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6}

_DURATION_RE = re.compile(
    r"^[+-]?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$",
    re.IGNORECASE,
)


@dataclass
class IcsEvent:
    """Jedno wydarzenie z pliku - jeszcze przed rozwinięciem serii."""

    uid: str
    summary: str
    location: str
    start: Any  # datetime (z strefą) albo date dla całodniowych
    end: Any
    all_day: bool
    rrule: Dict[str, str] = field(default_factory=dict)
    exdates: Set[str] = field(default_factory=set)


def unfold_lines(text: str) -> List[str]:
    """Skleja linie zawinięte przez format (kolejna zaczyna się spacją)."""
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: List[str] = []
    for line in raw:
        if line[:1] in (" ", "\t") and out:
            out[-1] += line[1:]
        else:
            out.append(line)
    return out


def split_property(line: str) -> Tuple[str, Dict[str, str], str]:
    """`DTSTART;TZID=Europe/Warsaw:20260302T093000` -> (nazwa, parametry, wartość)."""
    in_quotes = False
    cut = -1
    for i, ch in enumerate(line):
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == ":" and not in_quotes:
            cut = i
            break
    if cut < 0:
        return "", {}, ""
    head, value = line[:cut], line[cut + 1 :]
    parts = head.split(";")
    name = parts[0].strip().upper()
    params: Dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            continue
        key, raw_value = part.split("=", 1)
        params[key.strip().upper()] = raw_value.strip().strip('"')
    return name, params, value


def unescape(value: str) -> str:
    """Tekst z pliku: `\\,` `\\;` `\\n` `\\\\` znaczą przecinek, średnik, nową linię, ukośnik."""
    out: List[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append(
                "\n" if nxt in ("n", "N") else nxt if nxt in (",", ";", "\\") else nxt
            )
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out).strip()


def _zone(tzid: Optional[str]) -> ZoneInfo:
    if not tzid:
        return WARSAW
    try:
        return ZoneInfo(tzid)
    except Exception:  # noqa: BLE001 - nieznana strefa to nie powód do awarii
        return WARSAW


def parse_datetime(value: str, params: Dict[str, str]) -> Tuple[Any, bool]:
    """(data albo czas ze strefą, czy całodniowe). `(None, False)` dla śmieci."""
    raw = (value or "").strip()
    if not raw:
        return None, False
    if params.get("VALUE", "").upper() == "DATE" or re.fullmatch(r"\d{8}", raw):
        try:
            return datetime.strptime(raw[:8], "%Y%m%d").date(), True
        except ValueError:
            return None, False
    match = re.fullmatch(r"(\d{8})T(\d{6})(Z?)", raw)
    if not match:
        return None, False
    try:
        naive = datetime.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M%S")
    except ValueError:
        return None, False
    if match.group(3):
        return naive.replace(tzinfo=timezone.utc), False
    # Bez strefy i bez „Z" - czas lokalny czytającego, czyli u nas polski.
    return naive.replace(tzinfo=_zone(params.get("TZID"))), False


def parse_duration(value: str) -> Optional[timedelta]:
    match = _DURATION_RE.fullmatch((value or "").strip())
    if not match:
        return None
    weeks, days, hours, minutes, seconds = (int(x or 0) for x in match.groups())
    return timedelta(
        weeks=weeks, days=days, hours=hours, minutes=minutes, seconds=seconds
    )


def _rrule_dict(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (value or "").split(";"):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        out[key.strip().upper()] = raw.strip().upper()
    return out


def _exdate_keys(value: str, params: Dict[str, str]) -> Set[str]:
    keys: Set[str] = set()
    for piece in (value or "").split(","):
        moment, all_day = parse_datetime(piece, params)
        if moment is None:
            continue
        keys.add(_occurrence_key(moment, all_day))
    return keys


def _occurrence_key(moment: Any, all_day: bool) -> str:
    """Klucz do porównania z `EXDATE` - zawsze czas lokalny (albo data)."""
    if all_day or isinstance(moment, date) and not isinstance(moment, datetime):
        return moment.strftime("%Y%m%d")
    return moment.astimezone(WARSAW).strftime("%Y%m%dT%H%M%S")


def parse_events(text: str) -> List[IcsEvent]:
    """Wydarzenia z pliku ICS. Uszkodzony wpis pomijamy, reszta wchodzi."""
    events: List[IcsEvent] = []
    current: Optional[Dict[str, Any]] = None

    for line in unfold_lines(text or ""):
        stripped = line.strip()
        if stripped.upper() == "BEGIN:VEVENT":
            current = {"exdates": set(), "rrule": {}}
            continue
        if stripped.upper() == "END:VEVENT":
            if current is not None:
                event = _build_event(current)
                if event is not None:
                    events.append(event)
                    if len(events) >= MAX_EVENTS:
                        break
            current = None
            continue
        if current is None:
            continue

        name, params, value = split_property(line)
        if not name:
            continue
        if name == "DTSTART":
            current["start"], current["start_all_day"] = parse_datetime(value, params)
        elif name == "DTEND":
            current["end"], _ = parse_datetime(value, params)
        elif name == "DURATION":
            current["duration"] = parse_duration(value)
        elif name == "SUMMARY":
            current["summary"] = unescape(value)
        elif name == "LOCATION":
            current["location"] = unescape(value)
        elif name == "UID":
            current["uid"] = unescape(value)
        elif name == "RRULE":
            current["rrule"] = _rrule_dict(value)
        elif name == "EXDATE":
            current["exdates"] |= _exdate_keys(value, params)
        elif name == "STATUS":
            current["status"] = value.strip().upper()

    return events


def _build_event(props: Dict[str, Any]) -> Optional[IcsEvent]:
    start = props.get("start")
    if start is None:
        return None
    # Odwołane zajęcia nie są niedyspozycją.
    if props.get("status") == "CANCELLED":
        return None

    all_day = bool(props.get("start_all_day"))
    end = props.get("end")
    if end is None:
        duration = props.get("duration")
        if duration is not None:
            end = start + duration
        elif all_day:
            end = start + timedelta(days=1)  # koniec całodniowego jest WYŁĄCZNY
        else:
            end = start + timedelta(hours=1)

    return IcsEvent(
        uid=str(props.get("uid") or ""),
        summary=str(props.get("summary") or ""),
        location=str(props.get("location") or ""),
        start=start,
        end=end,
        all_day=all_day,
        rrule=props.get("rrule") or {},
        exdates=props.get("exdates") or set(),
    )


def _add_months(moment: datetime, months: int) -> Optional[datetime]:
    month_index = moment.month - 1 + months
    year = moment.year + month_index // 12
    month = month_index % 12 + 1
    try:
        return moment.replace(year=year, month=month)
    except ValueError:
        # 31. dzień w krótszym miesiącu - RFC każe takie wystąpienie pominąć.
        return None


def _starts(event: IcsEvent, window_end: date) -> List[Any]:
    """Początki wystąpień serii, jeszcze bez okna i bez `EXDATE`."""
    rule = event.rrule
    first = event.start
    if not rule or "FREQ" not in rule:
        return [first]

    freq = rule.get("FREQ", "")
    try:
        interval = max(1, int(rule.get("INTERVAL", "1")))
    except ValueError:
        interval = 1
    try:
        count = int(rule["COUNT"]) if "COUNT" in rule else None
    except ValueError:
        count = None

    until: Optional[Any] = None
    if "UNTIL" in rule:
        until, _ = parse_datetime(rule["UNTIL"], {})

    def past_end(moment: Any) -> bool:
        day = moment.date() if isinstance(moment, datetime) else moment
        if day > window_end:
            return True
        if until is None:
            return False
        if isinstance(until, datetime) and isinstance(moment, datetime):
            return moment > until
        until_day = until.date() if isinstance(until, datetime) else until
        return day > until_day

    out: List[Any] = []
    if freq == "WEEKLY" and rule.get("BYDAY"):
        wanted = [
            WEEKDAYS[token[-2:]]
            for token in rule["BYDAY"].split(",")
            if token[-2:] in WEEKDAYS
        ]
        if not wanted:
            wanted = [first.weekday()]
        # Poniedziałek tygodnia, w którym zaczyna się seria.
        week_start = first - timedelta(days=first.weekday())
        week = 0
        while len(out) < MAX_OCCURRENCES_PER_EVENT:
            base = week_start + timedelta(weeks=week * interval)
            stop = True
            for weekday in sorted(wanted):
                moment = base + timedelta(days=weekday)
                if moment < first:
                    stop = False
                    continue
                if past_end(moment):
                    continue
                stop = False
                out.append(moment)
                if count is not None and len(out) >= count:
                    return out[:count]
                if len(out) >= MAX_OCCURRENCES_PER_EVENT:
                    break
            base_day = base.date() if isinstance(base, datetime) else base
            if stop or base_day > window_end:
                break
            week += 1
        return out

    step: Optional[timedelta] = None
    if freq == "DAILY":
        step = timedelta(days=interval)
    elif freq == "WEEKLY":
        step = timedelta(weeks=interval)

    moment: Optional[Any] = first
    while moment is not None and len(out) < MAX_OCCURRENCES_PER_EVENT:
        if past_end(moment):
            break
        out.append(moment)
        if count is not None and len(out) >= count:
            break
        if step is not None:
            moment = moment + step
        elif freq == "MONTHLY":
            moment = _shift_months(moment, interval)
        elif freq == "YEARLY":
            moment = _shift_months(moment, 12 * interval)
        else:
            # Reguły, której nie rozumiemy, nie zgadujemy - zostaje pierwsze
            # wystąpienie, a kalendarz nie znika.
            break
    return out


def _shift_months(moment: Any, months: int) -> Optional[Any]:
    if isinstance(moment, datetime):
        return _add_months(moment, months)
    month_index = moment.month - 1 + months
    year = moment.year + month_index // 12
    month = month_index % 12 + 1
    try:
        return moment.replace(year=year, month=month)
    except ValueError:
        return None


def occurrences(
    event: IcsEvent, window_start: date, window_end: date
) -> List[Tuple[datetime, datetime]]:
    """Wystąpienia w oknie, jako pary czasów ZE STREFĄ (polską dla całodniowych)."""
    length: Optional[timedelta] = None
    if isinstance(event.start, datetime) and isinstance(event.end, datetime):
        length = event.end - event.start
        if length <= timedelta(0):
            length = timedelta(hours=1)
    elif not isinstance(event.start, datetime) and not isinstance(event.end, datetime):
        length = (event.end - event.start) or timedelta(days=1)

    out: List[Tuple[datetime, datetime]] = []
    for start in _starts(event, window_end):
        if start is None:
            continue
        if _occurrence_key(start, event.all_day) in event.exdates:
            continue

        if event.all_day:
            days = max(1, (length or timedelta(days=1)).days)
            first_day = start if isinstance(start, date) else start.date()
            last_day = first_day + timedelta(days=days - 1)
            begin = datetime.combine(first_day, time.min, tzinfo=WARSAW)
            finish = datetime.combine(last_day, time.max, tzinfo=WARSAW)
        else:
            begin = start
            finish = start + (length or timedelta(hours=1))

        if finish.astimezone(WARSAW).date() < window_start:
            continue
        if begin.astimezone(WARSAW).date() > window_end:
            continue
        out.append((begin, finish))

    out.sort(key=lambda pair: pair[0])
    return out


def _entry_id(feed_id: str, event: IcsEvent, begin: datetime) -> str:
    """Stały identyfikator wpisu - ten sam przy każdej synchronizacji."""
    tag = event.uid or hashlib.sha1(
        f"{event.summary}|{event.location}".encode("utf-8")
    ).hexdigest()[:12]
    stamp = begin.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"feed:{feed_id}:{tag}:{stamp}"


def feed_entries(
    ics_text: str,
    *,
    feed_id: str,
    feed_name: str,
    color: Optional[str],
    window_start: date,
    window_end: date,
    synced_at: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Wpisy niedyspozycji z pliku ICS - w formacie wspólnym z kalendarzem okręgu.

    Kształt jest ten sam, co w synchronizacji centralnej (`from`/`to` w UTC),
    więc aplikacja i automat obsady czytają je bez żadnej nowej obsługi. Nazwa
    źródła wchodzi jako nazwa kategorii, żeby na kalendarzu było widać, skąd
    wziął się wpis („Plan studiów"), a nie tylko że termin jest zajęty.
    """
    stamp = (synced_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    entries: List[Dict[str, Any]] = []
    for event in parse_events(ics_text):
        for begin, finish in occurrences(event, window_start, window_end):
            entries.append(
                {
                    "entry_type": "UNAVAIL",
                    "id": _entry_id(feed_id, event, begin),
                    "source": SOURCE,
                    "source_feed": feed_id,
                    "source_feed_name": feed_name,
                    "source_synced_at": stamp.isoformat(),
                    "from": begin.astimezone(timezone.utc).isoformat(),
                    "to": finish.astimezone(timezone.utc).isoformat(),
                    "info": event.summary or feed_name,
                    "location": event.location or "",
                    "category_id": f"feed:{feed_id}",
                    "category_name": feed_name,
                    "category_color": color,
                    "color": color,
                    "is_manual": False,
                    "is_global": False,
                    "isMatch": False,
                }
            )
    # Ten sam termin dwa razy (plik bywa sklejony z kilku) liczy się raz.
    unique: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        unique[entry["id"]] = entry
    return sorted(unique.values(), key=lambda item: (item["from"], item["to"], item["id"]))


def is_feed_entry(item: Any) -> bool:
    """Czy wpis pochodzi z kalendarza sędziego (właścicielem jest serwer)."""
    if not isinstance(item, dict):
        return False
    return str(item.get("source") or "").strip().upper() == SOURCE
