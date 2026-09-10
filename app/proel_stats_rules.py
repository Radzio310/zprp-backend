"""Statystyki ProEla - cała logika, bez bazy.

Panel „Statystyki ProEla" odpowiada na pytania, których żaden ekran dotąd nie
zadawał: kto prowadzi protokoły i ile, kiedy się gra, na którym etapie mecze
utykają, gdzie wysyłki do ZPRP się sypią, jak wygląda sezon w każdej lidze.

DLACZEGO LIŚĆ. Schemat bazy używa typów wyłącznie postgresowych, więc testy z
bazą są w tym projekcie pomijane bez Postgresa. Wszystko, co tu decyduje o
liczbach - klasyfikacja meczu, przypisanie województwa, reguła „kto prowadził",
mediany, lejek - musi dać się sprawdzić bez niej. Router (`app/proel_stats.py`)
tylko zbiera wiersze i woła `build_stats`.

DWA WYMIARY WOJEWÓDZTWA - decyzja z 10.09.2026:
  • MECZU - z przedrostka numeru („S/PPK/2" -> okręg prowadzący „S"). Mapy
    przedrostków NIE wpisujemy ręcznie: liczy ją `learn_prefix_provinces`
    z terminarzy okręgowych (`province_matches`), głosowaniem większościowym.
    Zgadywana mapa pomyliłaby się przy pierwszym okręgu, który zmieni oznaczenie.
    Mecze centralne (Superliga, I i II liga, runda centralna Pucharu Polski)
    przedrostka nie mają i trafiają do osobnej grupy „Rozgrywki centralne".
  • OSOBY prowadzącej - z jej profilu (lista okręgowa, rejestr logowań,
    konto ProEl).

DWIE OSIE LUDZI - decyzja z 10.09.2026:
  • PROWADZĄCY - kto prowadził stolik: aktor pierwszego `match.live_started`,
    a gdy go nie ma - aktor założenia meczu.
  • WYKONAWCY - kto zrobił czynności pomeczowe: wynik skrócony, pełne dane,
    PDF, załącznik, SMS, zatwierdzenie. Z dziennika, a więc z podpisem sesji
    podniesionej, gdy czynność wykonał ktoś na cudzym telefonie.

Mecze szkoleniowe i testowe są w liczbach głównych WYŁĄCZONE (chyba że filtr
mówi inaczej) i mają osobną zakładkę - sto ćwiczeń z kursokonferencji jednego
dnia zamieniłoby każdy wykres w wykres szkolenia.
"""
from __future__ import annotations

import json
import statistics
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.match_bombs_rules import season_label, season_of
from app.proel_training_key import is_training_key, match_number_from_key
from app.protocol_category import (
    COMPETITION_LABELS,
    _token_of_segment,
    classify_match_code,
)
from app.settlement_rates import match_level

try:  # strefa hali, nie serwera - mapa ciepła ma pokazywać polską godzinę
    from zoneinfo import ZoneInfo

    _LOCAL_TZ = ZoneInfo("Europe/Warsaw")
except Exception:  # noqa: BLE001 - brak tzdata nie może wywrócić panelu
    _LOCAL_TZ = timezone(timedelta(hours=1))


#: Grupa meczów bez okręgu w numerze.
CENTRAL = "CENTRALNE"
#: Grupa „nie umiemy powiedzieć".
UNKNOWN = "NIEZNANE"

#: Nazwy województw do pokazania. Klucz jest KANONICZNY (`canon_province`),
#: bo terminarze okręgowe piszą „ŚLĄSKIE", a rejestr logowań bywa „slaskie" -
#: bez jednej reguły to samo województwo wyszłoby na wykresie dwa razy.
PROVINCE_LABELS: Dict[str, str] = {
    "DOLNOSLASKIE": "Dolnośląskie",
    "KUJAWSKO-POMORSKIE": "Kujawsko-pomorskie",
    "LUBELSKIE": "Lubelskie",
    "LUBUSKIE": "Lubuskie",
    "LODZKIE": "Łódzkie",
    "MALOPOLSKIE": "Małopolskie",
    "MAZOWIECKIE": "Mazowieckie",
    "OPOLSKIE": "Opolskie",
    "PODKARPACKIE": "Podkarpackie",
    "PODLASKIE": "Podlaskie",
    "POMORSKIE": "Pomorskie",
    "SLASKIE": "Śląskie",
    "SWIETOKRZYSKIE": "Świętokrzyskie",
    "WARMINSKO-MAZURSKIE": "Warmińsko-mazurskie",
    "WIELKOPOLSKIE": "Wielkopolskie",
    "ZACHODNIOPOMORSKIE": "Zachodniopomorskie",
    CENTRAL: "Rozgrywki centralne",
    UNKNOWN: "Nieznane",
}


def canon_province(value: Any) -> str:
    """Województwo do porównań: wielkie litery, bez ogonków, bez spacji.

    Ta sama reguła co `normalize_province` w `app/province_access.py`, tylko
    tutaj, żeby liść nie ciągnął modułu uprawnień. „Ł" nie ma rozkładu NFD,
    więc zamieniamy je ręcznie - inaczej „ŁÓDZKIE" nie spotkałoby „LODZKIE".
    """
    text = str(value or "").strip().upper().replace("Ł", "L")
    if not text:
        return ""
    stripped = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in stripped if unicodedata.category(ch) != "Mn").replace(" ", "")


def province_label(key: Any) -> str:
    k = str(key or "")
    return PROVINCE_LABELS.get(k) or (k.capitalize() if k else "Nieznane")

#: Runda centralna Pucharu Polski („L/PM/1") ma przedrostek, ale nie jest
#: meczem okręgu - patrz nota przy `COMPETITION_TOKENS`.
_CENTRAL_TOKENS = frozenset({"PM", "PK"})

#: Zdarzenia, które robią z osoby WYKONAWCĘ czynności pomeczowej.
FINISH_EVENTS: Tuple[str, ...] = (
    "zprp.summary_sent",
    "zprp.full_data_sent",
    "zprp.attachment_sent",
    "match.sms_sent",
    "protocol.pdf_generated",
    "match.approved",
)

#: Etapy obiegu dokumentów - w kolejności, w jakiej mecz przez nie przechodzi.
FLOW_STAGES: Tuple[Tuple[str, str], ...] = (
    ("created", "Założony"),
    ("live", "Prowadzony na żywo"),
    ("finished", "Zakończony"),
    ("summary", "Wynik skrócony w ZPRP"),
    ("full", "Pełne dane w ZPRP"),
    ("pdf", "Protokół PDF"),
    ("attachment", "PDF w załącznikach ZPRP"),
    ("approved", "Zatwierdzony"),
)

#: Zdarzenia liczone w zakładce jakości - klucz to nazwa z dziennika.
QUALITY_EVENTS: Tuple[Tuple[str, str], ...] = (
    ("zprp.send_failed", "Nieudane próby wysyłki do ZPRP"),
    ("zprp.send_queued", "Wysyłki odłożone do dosyłki"),
    ("table.taken_over", "Przejęcia stolika"),
    ("match.id_conflict", "Odrzucone zapisy (inny mecz pod numerem)"),
    ("match.unapproved", "Cofnięte zatwierdzenia"),
    ("match.deleted", "Usunięte zapisy"),
    ("match.restored", "Przywrócone zapisy"),
    ("exam.confirmed", "Badania potwierdzone ręcznie"),
    ("exam.promoted", "Badania potwierdzone przez ZPRP"),
    ("exam.withdrawn", "Cofnięte potwierdzenia badań"),
)

_WEEKDAYS = ("Pn", "Wt", "Śr", "Cz", "Pt", "Sb", "Nd")

#: Po tylu godzinach zakończony, a niezatwierdzony mecz uznajemy za utknięty.
STUCK_AFTER_H = 24


# ─────────────────────────── drobne narzędzia ───────────────────────────


def as_dict(value: Any) -> Dict[str, Any]:
    """Kolumna JSON potrafi wrócić z bazy jako SUROWY NAPIS.

    asyncpg pod `databases` bez kodeka nie dekoduje JSON-a - ta sama pułapka,
    która w giełdzie meczów zabrała obsadowym uprawnienia. Każdy blob przechodzi
    więc tędy.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes)):
        try:
            out = json.loads(value)
        except ValueError:
            return {}
        return out if isinstance(out, dict) else {}
    return {}


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_at(value: Any) -> Optional[datetime]:
    """Znacznik czasu z każdego kształtu, w jakim leży w blobie i w bazie."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        out = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def median(values: Sequence[float]) -> Optional[float]:
    clean = [v for v in values if isinstance(v, (int, float))]
    return float(statistics.median(clean)) if clean else None


def competition_label(key: str) -> str:
    return COMPETITION_LABELS.get(key, "Inne rozgrywki") if key else "Nierozpoznane"


LEVEL_LABELS: Dict[str, str] = {
    "central": "Centralne",
    "district": "Okręgowe",
    "cup": "Puchary",
    "unknown": "Nierozpoznane",
}


# ─────────────────────────── województwo meczu ───────────────────────────


def prefix_of(code: Any) -> str:
    """Przedrostek okręgu z numeru meczu, albo pusty napis.

    Przedrostek jest wtedy, gdy PIERWSZY człon numeru nie jest kodem rozgrywek:
    „S/PPK/2" -> „S", ale „SM/8" -> nic (to Superliga), a „MP/JM/12" -> nic
    („MP" to Mistrzostwa Polski, nie okręg). Najdłuższe dopasowanie kodu robi
    `_token_of_segment` - ta sama reguła, co kratka ZAWODY w protokole.
    """
    parts = [p.strip() for p in str(code or "").split("/") if p.strip()]
    if len(parts) < 2:
        return ""
    head = parts[0]
    if _token_of_segment(head):
        return ""
    return head.upper() if head.isalpha() else ""


def learn_prefix_provinces(
    rows: Iterable[Tuple[Any, Any]],
    *,
    min_share: float = 0.6,
) -> Dict[str, str]:
    """Mapa przedrostek -> województwo, wyuczona z terminarzy okręgowych.

    Głosowanie większościowe z progiem: przedrostek, który w terminarzach
    występuje u kilku okręgów bez wyraźnej przewagi, NIE dostaje województwa.
    Lepiej powiedzieć „nieznane" niż przypisać mecz cudzemu okręgowi.
    """
    votes: Dict[str, Counter] = defaultdict(Counter)
    for province, code in rows:
        prov = canon_province(province)
        if not prov:
            continue
        kind = classify_match_code(code)
        if kind.token in _CENTRAL_TOKENS:
            continue
        prefix = prefix_of(code)
        if prefix:
            votes[prefix][prov] += 1

    out: Dict[str, str] = {}
    for prefix, counter in votes.items():
        total = sum(counter.values())
        (best, count), *rest = counter.most_common()
        if rest and rest[0][1] == count:
            continue  # remis - nie rozstrzygamy
        if total and count / total >= min_share:
            out[prefix] = best
    return out


def match_province(code: Any, level: str, learned: Mapping[str, str]) -> str:
    """Województwo MECZU: okręg z przedrostka, grupa centralna albo nieznane."""
    kind = classify_match_code(code)
    prefix = prefix_of(code)
    if prefix and kind.token not in _CENTRAL_TOKENS:
        return learned.get(prefix) or UNKNOWN
    if level == "central" or kind.token in _CENTRAL_TOKENS:
        return CENTRAL
    return UNKNOWN


# ─────────────────────────── podsumowanie meczu ───────────────────────────


def _match_moment(blob: Mapping[str, Any]) -> Optional[datetime]:
    """Kiedy grano. Najpierw data meczu z bloba, potem z konfiguracji."""
    cfg = as_dict(blob.get("matchConfig"))
    for candidate in (blob.get("date"), cfg.get("date")):
        at = parse_at(candidate)
        if at:
            return at
    return None


def _player_rows(blob: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    out: List[Mapping[str, Any]] = []
    for key in ("hostPlayerStats", "guestPlayerStats"):
        for row in blob.get(key) or []:
            if isinstance(row, Mapping):
                out.append(row)
    return out


def _filled(value: Any) -> bool:
    return str(value or "").strip() != ""


def match_summary(match_key: Any, status: Any, blob_raw: Any) -> Dict[str, Any]:
    """Jeden mecz spłaszczony do tego, czego potrzebują statystyki.

    Liczone RAZ na wersję meczu i trzymane w `proel_match_stats` - blob
    potrafi ważyć setki kilobajtów, a panel pokazuje wszystkie mecze naraz.
    Wiersz nie niesie danych osobowych zawodników: tylko liczby.
    """
    blob = as_dict(blob_raw)
    cfg = as_dict(blob.get("matchConfig"))
    key = str(match_key or "").strip()
    training = is_training_key(key) or cfg.get("training") is not None
    number = match_number_from_key(key) if is_training_key(key) else key
    kind = classify_match_code(number)
    level = match_level(number) if kind.competition else "unknown"
    at = _match_moment(blob)

    host = _int(blob.get("scoreHost"))
    guest = _int(blob.get("scoreGuest"))
    penalty_score = str(blob.get("penaltyScore") or "").strip()

    players = _player_rows(blob)
    suspensions = sum(
        1 for p in players for f in ("penalty1", "penalty2", "penalty3") if _filled(p.get(f))
    )
    extra = sum(1 for p in players if _filled(p.get("penaltyExtra")))
    warnings = sum(1 for p in players if _filled(p.get("warning")))
    blue = sum(1 for p in players if _filled(p.get("disqualificationDesc")))
    red = sum(
        1
        for p in players
        if _filled(p.get("disqualification")) and not _filled(p.get("disqualificationDesc"))
    )
    entered = sum(1 for p in players if p.get("entered") or _int(p.get("goals")) > 0)

    pk_scored = pk_missed = timeouts = 0
    for ev in blob.get("protocol") or []:
        if not isinstance(ev, Mapping) or ev.get("shootout"):
            continue
        kind_ev = str(ev.get("type") or "")
        if kind_ev == "penaltyKickScored":
            pk_scored += 1
        elif kind_ev == "penaltyKickMissed":
            pk_missed += 1
        elif kind_ev == "teamTime":
            timeouts += 1

    return {
        "key": key,
        "number": number,
        "status": str(status or "in_progress"),
        "training": bool(training),
        "test": bool(cfg.get("isTest")),
        "origin": str(cfg.get("origin") or ""),
        "competition": kind.competition,
        "gender": kind.gender,
        "token": kind.token,
        "level": level,
        "prefix": prefix_of(number),
        "at": _iso(at),
        "season": season_of(at),
        "city": str(cfg.get("venueCity") or "").strip(),
        "host": str(cfg.get("hostTeamName") or "").strip(),
        "guest": str(cfg.get("guestTeamName") or "").strip(),
        "score": [host, guest],
        "goals": host + guest,
        "shootout": bool(penalty_score and penalty_score not in ("0 - 0", "0-0")),
        "suspensions": suspensions,
        "extra_suspensions": extra,
        "warnings": warnings,
        "red": red,
        "blue": blue,
        "pk_scored": pk_scored,
        "pk_missed": pk_missed,
        "timeouts": timeouts,
        "players_entered": entered,
    }


# ─────────────────────────── ludzie ───────────────────────────


def person_kind(actor_id: Any) -> str:
    """„judge" (numer sędziego), „account" (konto ProEl) albo „device" (token)."""
    text = str(actor_id or "").strip()
    if text.startswith("proel:"):
        return "account"
    if text.startswith("inst:") or not text:
        return "device"
    return "judge"


PERSON_KIND_LABELS: Dict[str, str] = {
    "judge": "Sędzia BAZY",
    "account": "Konto ProEl",
    "device": "Wejście tokenem",
}


def person_province(
    actor_id: Any,
    *,
    judges: Mapping[str, str],
    logins: Mapping[str, str],
    accounts: Mapping[str, str],
) -> str:
    """Województwo OSOBY: lista okręgowa, potem rejestr logowań, potem konto."""
    text = str(actor_id or "").strip()
    if not text:
        return UNKNOWN
    if text.startswith("proel:"):
        return canon_province(accounts.get(text[len("proel:"):], "")) or UNKNOWN
    return canon_province(judges.get(text) or logins.get(text)) or UNKNOWN


# ─────────────────────────── składanie całości ───────────────────────────


def _local(at: datetime) -> datetime:
    return at.astimezone(_LOCAL_TZ)


def _hours_between(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
    if not a or not b or b < a:
        return None
    return (b - a).total_seconds() / 3600.0


def _week_start(at: datetime) -> str:
    local = _local(at)
    monday = local - timedelta(days=local.weekday())
    return monday.date().isoformat()


def _counts(values: Iterable[str]) -> List[Dict[str, Any]]:
    counter = Counter(v for v in values if v)
    return [{"key": k, "count": c} for k, c in counter.most_common()]


def build_stats(
    *,
    summaries: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    learned_prefixes: Mapping[str, str],
    judge_provinces: Mapping[str, str],
    login_provinces: Mapping[str, str],
    account_provinces: Mapping[str, str],
    live_now: Iterable[str] = (),
    training_pdfs: int = 0,
    filters: Optional[Mapping[str, Any]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Cały panel jednym przebiegiem - z gotowych wierszy, bez bazy.

    `events` to dziennik bez „Zmian pól" (te nie mówią nic o obiegu meczu, a są
    ich tysiące). Każdy wiersz: match_number, event, actor_judge_id, actor_name,
    app_version, details, created_at.
    """
    f = dict(filters or {})
    now = now or datetime.now(timezone.utc)
    live_set = {str(x) for x in live_now}

    province_of = lambda actor: person_province(  # noqa: E731
        actor,
        judges=judge_provinces,
        logins=login_provinces,
        accounts=account_provinces,
    )

    # ── dziennik pogrupowany po meczu ──
    by_match: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for ev in events:
        by_match[str(ev.get("match_number") or "")].append(ev)
    for rows in by_match.values():
        rows.sort(key=lambda e: parse_at(e.get("created_at")) or now)

    def first(rows: Sequence[Mapping[str, Any]], name: str) -> Optional[Mapping[str, Any]]:
        return next((e for e in rows if e.get("event") == name), None)

    # ── mecze wzbogacone o dziennik ──
    enriched: List[Dict[str, Any]] = []
    for s in summaries:
        m = dict(s)
        rows = by_match.get(m["key"], [])
        live_ev = first(rows, "match.live_started")
        created_ev = first(rows, "match.created")
        runner_ev = live_ev or created_ev
        runner_id = str((runner_ev or {}).get("actor_judge_id") or "")
        m["runner_id"] = runner_id
        m["runner_name"] = str((runner_ev or {}).get("actor_name") or "").strip()
        m["runner_kind"] = person_kind(runner_id) if runner_ev else ""
        m["runner_province"] = province_of(runner_id) if runner_ev else UNKNOWN
        m["runner_version"] = str((runner_ev or {}).get("app_version") or "")
        m["match_province"] = match_province(m["number"], m["level"], learned_prefixes)

        started = parse_at((live_ev or {}).get("created_at"))
        finished = parse_at((first(rows, "match.finished") or {}).get("created_at"))
        summary_at = parse_at((first(rows, "zprp.summary_sent") or {}).get("created_at"))
        approved_at = parse_at((first(rows, "match.approved") or {}).get("created_at"))
        m["started_at"] = started
        m["finished_at"] = finished
        m["h_to_summary"] = _hours_between(finished, summary_at)
        m["h_to_approved"] = _hours_between(finished, approved_at)

        names = {str(e.get("event") or "") for e in rows}
        status = m["status"]
        m["flow"] = {
            "created": True,
            "live": bool(live_ev) or status in ("finished", "approved"),
            "finished": status in ("finished", "approved") or bool(finished),
            "summary": "zprp.summary_sent" in names,
            "full": "zprp.full_data_sent" in names,
            "pdf": "protocol.pdf_generated" in names or "zprp.attachment_sent" in names,
            "attachment": "zprp.attachment_sent" in names,
            "approved": status == "approved",
        }
        m["events"] = rows
        m["live_now"] = m["key"] in live_set
        enriched.append(m)

    # ── zbiór filtrów, zanim cokolwiek odsiejemy ──
    facets = {
        "seasons": sorted(
            {m["season"] for m in enriched if isinstance(m.get("season"), int)},
            reverse=True,
        ),
        "competitions": sorted({m["competition"] for m in enriched if m["competition"]}),
        "levels": sorted({m["level"] for m in enriched if m["level"]}),
        "match_provinces": sorted({m["match_province"] for m in enriched}),
        "person_provinces": sorted({m["runner_province"] for m in enriched}),
    }

    # ── filtry ──
    include_training = bool(f.get("training"))

    def keep(m: Mapping[str, Any]) -> bool:
        if not include_training and (m["training"] or m["test"]):
            return False
        if f.get("season") not in (None, "") and m.get("season") != _int(f["season"]):
            return False
        if f.get("competition") and m["competition"] != f["competition"]:
            return False
        if f.get("level") and m["level"] != f["level"]:
            return False
        if f.get("match_province") and m["match_province"] != f["match_province"]:
            return False
        if f.get("person_province") and m["runner_province"] != f["person_province"]:
            return False
        return True

    matches = [m for m in enriched if keep(m)]
    keys = {m["key"] for m in matches}
    scoped_events = [e for m in matches for e in m["events"]]

    # ── PULS ──
    finished = [m for m in matches if m["flow"]["finished"]]
    full_cycle = [
        m
        for m in finished
        if m["flow"]["summary"] and m["flow"]["full"] and m["flow"]["pdf"] and m["flow"]["approved"]
    ]
    stuck = [
        m
        for m in matches
        if m["status"] == "finished"
        and m.get("finished_at")
        and (now - m["finished_at"]) > timedelta(hours=STUCK_AFTER_H)
    ]

    def active_people(days: int) -> int:
        border = now - timedelta(days=days)
        return len(
            {
                str(e.get("actor_judge_id") or "")
                for e in scoped_events
                if (parse_at(e.get("created_at")) or now) >= border and e.get("actor_judge_id")
            }
        )

    current_season = season_of(now)
    pulse = {
        "matches": len(matches),
        "this_season": sum(1 for m in matches if m.get("season") == current_season),
        "approved": sum(1 for m in matches if m["status"] == "approved"),
        "in_progress": sum(1 for m in matches if m["status"] == "in_progress"),
        "live_now": sum(1 for m in matches if m["live_now"]),
        "stuck": len(stuck),
        "people_7d": active_people(7),
        "people_30d": active_people(30),
        "full_cycle_share": (len(full_cycle) / len(finished)) if finished else None,
        "season_label": season_label(current_season) if current_season else "",
    }

    # ── LUDZIE ──
    people: Dict[str, Dict[str, Any]] = {}

    def person(actor: str, name: str) -> Dict[str, Any]:
        entry = people.get(actor)
        if entry is None:
            entry = people[actor] = {
                "id": actor,
                "name": name or actor or "Nieznany",
                "kind": person_kind(actor),
                "province": province_of(actor),
                "ran": 0,
                "finished": 0,
                "actions": Counter(),
                "competitions": Counter(),
                "approve_hours": [],
                "takeovers": 0,
                "last_at": None,
            }
        if name and (entry["name"] in ("", actor, "Nieznany")):
            entry["name"] = name
        return entry

    for m in matches:
        if m["runner_id"] or m["runner_name"]:
            p = person(m["runner_id"], m["runner_name"])
            p["ran"] += 1
            p["competitions"][m["competition"] or ""] += 1
            if m.get("h_to_approved") is not None:
                p["approve_hours"].append(m["h_to_approved"])
        finishers_here = set()
        for e in m["events"]:
            actor = str(e.get("actor_judge_id") or "")
            name = str(e.get("actor_name") or "").strip()
            at = parse_at(e.get("created_at"))
            event = str(e.get("event") or "")
            if not (actor or name):
                continue
            p = person(actor, name)
            if at and (p["last_at"] is None or at > p["last_at"]):
                p["last_at"] = at
            if event in FINISH_EVENTS:
                p["actions"][event] += 1
                finishers_here.add(actor or name)
            if event == "table.taken_over":
                p["takeovers"] += 1
        for who in finishers_here:
            if who in people:
                people[who]["finished"] += 1

    people_out = []
    for p in people.values():
        people_out.append(
            {
                "id": p["id"],
                "name": p["name"],
                "kind": p["kind"],
                "province": p["province"],
                "province_label": province_label(p["province"]),
                "ran": p["ran"],
                "finished": p["finished"],
                "takeovers": p["takeovers"],
                "actions": dict(p["actions"]),
                "competitions": [
                    {"key": k, "label": competition_label(k), "count": c}
                    for k, c in p["competitions"].most_common()
                ],
                "median_approve_h": median(p["approve_hours"]),
                "last_at": _iso(p["last_at"]),
            }
        )
    people_out.sort(key=lambda p: (-p["ran"], -p["finished"], p["name"]))

    # Nowi ludzie w czasie: tydzień pierwszego wpisu każdej osoby.
    first_seen: Dict[str, datetime] = {}
    for e in scoped_events:
        actor = str(e.get("actor_judge_id") or "")
        at = parse_at(e.get("created_at"))
        if actor and at and (actor not in first_seen or at < first_seen[actor]):
            first_seen[actor] = at
    newcomers = Counter(_week_start(at) for at in first_seen.values())

    # ── CZAS ──
    heat = [[0] * 24 for _ in range(7)]
    per_week: Counter = Counter()
    per_day: Counter = Counter()
    for m in matches:
        moment = m.get("started_at") or parse_at(m.get("at"))
        if not moment:
            continue
        local = _local(moment)
        heat[local.weekday()][local.hour] += 1
        per_week[_week_start(moment)] += 1
        per_day[local.date().isoformat()] += 1

    by_comp_summary: Dict[str, List[float]] = defaultdict(list)
    by_comp_approve: Dict[str, List[float]] = defaultdict(list)
    for m in matches:
        if m.get("h_to_summary") is not None:
            by_comp_summary[m["competition"]].append(m["h_to_summary"])
        if m.get("h_to_approved") is not None:
            by_comp_approve[m["competition"]].append(m["h_to_approved"])

    durations = {
        "to_summary_h": median([m["h_to_summary"] for m in matches if m.get("h_to_summary") is not None]),
        "to_approved_h": median([m["h_to_approved"] for m in matches if m.get("h_to_approved") is not None]),
        "by_competition": [
            {
                "key": comp,
                "label": competition_label(comp),
                "to_summary_h": median(by_comp_summary.get(comp, [])),
                "to_approved_h": median(by_comp_approve.get(comp, [])),
                "count": len(by_comp_approve.get(comp, [])) or len(by_comp_summary.get(comp, [])),
            }
            for comp in sorted(set(by_comp_summary) | set(by_comp_approve))
        ],
    }

    time_out = {
        "heatmap": heat,
        "weekdays": list(_WEEKDAYS),
        "weeks": [{"week": w, "count": c} for w, c in sorted(per_week.items())][-26:],
        "days": [{"day": d, "count": c} for d, c in sorted(per_day.items())],
        "durations": durations,
        "newcomers": [{"week": w, "count": c} for w, c in sorted(newcomers.items())][-26:],
    }

    # ── OBIEG ──
    flow = [
        {"key": key, "label": label, "count": sum(1 for m in matches if m["flow"][key])}
        for key, label in FLOW_STAGES
    ]
    stuck_list = sorted(stuck, key=lambda m: m["finished_at"])[:20]
    flow_out = {
        "stages": flow,
        "stuck": [
            {
                "number": m["number"],
                "host": m["host"],
                "guest": m["guest"],
                "runner": m["runner_name"],
                "finished_at": _iso(m["finished_at"]),
                "hours": round((now - m["finished_at"]).total_seconds() / 3600.0, 1),
                "missing": [label for key, label in FLOW_STAGES if not m["flow"][key]],
            }
            for m in stuck_list
        ],
    }

    # ── LIGI I SZCZEBLE ──
    competitions = [
        {
            "key": c["key"],
            "label": competition_label(c["key"]),
            "count": c["count"],
            "women": sum(1 for m in matches if m["competition"] == c["key"] and m["gender"] == "K"),
            "men": sum(1 for m in matches if m["competition"] == c["key"] and m["gender"] == "M"),
        }
        for c in _counts(m["competition"] or "" for m in matches)
    ]
    unrecognised = sum(1 for m in matches if not m["competition"])
    if unrecognised:
        competitions.append(
            {"key": "", "label": "Nierozpoznane", "count": unrecognised, "women": 0, "men": 0}
        )
    leagues_out = {
        "competitions": competitions,
        "levels": [
            {"key": c["key"], "label": LEVEL_LABELS.get(c["key"], c["key"]), "count": c["count"]}
            for c in _counts(m["level"] for m in matches)
        ],
        "gender": {
            "K": sum(1 for m in matches if m["gender"] == "K"),
            "M": sum(1 for m in matches if m["gender"] == "M"),
            "": sum(1 for m in matches if not m["gender"]),
        },
    }

    # ── WOJEWÓDZTWA ──
    def labelled(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{**r, "label": province_label(r["key"])} for r in rows]

    provinces_out = {
        "matches": labelled(_counts(m["match_province"] for m in matches)),
        "people": labelled(
            _counts(p["province"] for p in people_out if p["ran"] or p["finished"])
        ),
        "runners": labelled(
            _counts(m["runner_province"] for m in matches if m["runner_id"])
        ),
        "learned_prefixes": [
            {"prefix": k, "province": v, "label": province_label(v)}
            for k, v in sorted(learned_prefixes.items())
        ],
    }

    # ── JAKOŚĆ ──
    event_counter = Counter(str(e.get("event") or "") for e in scoped_events)
    legacy = sum(
        1
        for e in scoped_events
        if e.get("event") in FINISH_EVENTS
        and str(as_dict(e.get("details")).get("via") or "") in ("legacy", "mixed")
    )
    admin_actions = sum(1 for e in scoped_events if as_dict(e.get("details")).get("admin") is True)
    failed_matches = {m["key"] for m in matches if "zprp.send_failed" in {e.get("event") for e in m["events"]}}
    recovered = sum(
        1 for m in matches if m["key"] in failed_matches and m["flow"]["full"]
    )
    quality_out = {
        "events": [
            {"key": key, "label": label, "count": event_counter.get(key, 0)}
            for key, label in QUALITY_EVENTS
        ],
        "legacy_route": legacy,
        "admin_actions": admin_actions,
        "failed_matches": len(failed_matches),
        "recovered_matches": recovered,
        "app_versions": _counts(m["runner_version"] for m in matches if m["runner_version"]),
        "runner_kinds": [
            {"key": c["key"], "label": PERSON_KIND_LABELS.get(c["key"], c["key"]), "count": c["count"]}
            for c in _counts(m["runner_kind"] for m in matches if m["runner_kind"])
        ],
    }

    # ── SPORT ──
    played = [m for m in matches if m["flow"]["finished"]]

    def per_match(rows: Sequence[Mapping[str, Any]], field: str) -> Optional[float]:
        return (sum(_int(r.get(field)) for r in rows) / len(rows)) if rows else None

    def sport_block(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        pk_total = sum(_int(r["pk_scored"]) + _int(r["pk_missed"]) for r in rows)
        decided = [r for r in rows if r["score"][0] != r["score"][1]]
        return {
            "matches": len(rows),
            "goals": per_match(rows, "goals"),
            "suspensions": per_match(rows, "suspensions"),
            "warnings": per_match(rows, "warnings"),
            "red": sum(_int(r["red"]) for r in rows),
            "blue": sum(_int(r["blue"]) for r in rows),
            "pk_share": (sum(_int(r["pk_scored"]) for r in rows) / pk_total) if pk_total else None,
            "shootouts": sum(1 for r in rows if r["shootout"]),
            "home_wins": (sum(1 for r in decided if r["score"][0] > r["score"][1]) / len(rows)) if rows else None,
            "draws": (sum(1 for r in rows if r["score"][0] == r["score"][1]) / len(rows)) if rows else None,
            "timeouts": per_match(rows, "timeouts"),
        }

    by_comp_rows: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for m in played:
        by_comp_rows[m["competition"]].append(m)

    def record(field: str) -> List[Dict[str, Any]]:
        top = sorted(played, key=lambda m: -_int(m.get(field)))[:5]
        return [
            {
                "number": m["number"],
                "host": m["host"],
                "guest": m["guest"],
                "score": m["score"],
                "value": _int(m.get(field)),
            }
            for m in top
            if _int(m.get(field)) > 0
        ]

    sport_out = {
        "overall": sport_block(played),
        "by_competition": sorted(
            (
                {"key": comp, "label": competition_label(comp), **sport_block(rows)}
                for comp, rows in by_comp_rows.items()
            ),
            key=lambda row: -row["matches"],
        ),
        "records": {
            "goals": record("goals"),
            "suspensions": record("suspensions"),
        },
    }

    # ── SZKOLENIA ── (liczone z CAŁOŚCI, nie z odfiltrowanych)
    training_rows = [m for m in enriched if m["training"] or m["test"]]
    training_out = {
        "matches": sum(1 for m in training_rows if m["training"]),
        "test_matches": sum(1 for m in training_rows if m["test"] and not m["training"]),
        "pdfs": int(training_pdfs or 0),
        "origins": _counts(m["origin"] or "nieznane" for m in enriched),
        "people": len({m["runner_id"] for m in training_rows if m["runner_id"]}),
    }

    return {
        "generated_at": now.isoformat(),
        "filters": f,
        "facets": {
            **facets,
            "season_labels": {str(s): season_label(s) for s in facets["seasons"]},
            "competition_labels": {c: competition_label(c) for c in facets["competitions"]},
            "level_labels": {lvl: LEVEL_LABELS.get(lvl, lvl) for lvl in facets["levels"]},
            "province_labels": {
                p: province_label(p)
                for p in set(facets["match_provinces"]) | set(facets["person_provinces"])
            },
        },
        "pulse": pulse,
        "people": {"list": people_out[:200], "total": len(people_out)},
        "time": time_out,
        "flow": flow_out,
        "leagues": leagues_out,
        "provinces": provinces_out,
        "quality": quality_out,
        "sport": sport_out,
        "training": training_out,
        "scope": {"matches": len(keys)},
    }
