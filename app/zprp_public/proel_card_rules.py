"""Protokół elektroniczny (ProEl) jako zapas dla karty meczu - czyste reguły, bez bazy.

Superliga i inne rozgrywki centralne mają w publicznym API ZPRP termin
„RRRR-MM-DD 00:00:00" (godzina do ustalenia), a wynik pojawia się tam
z opóźnieniem. Mecz prowadzony w ProElu zna oba: godzinę z konfiguracji
(`matchConfig.extras.matchTime`, albo chwilę pierwszego gwizdka) i wynik
z zakończonego/zatwierdzonego protokołu.

Zasady:
* ZPRP zawsze wygrywa - ProEl wypełnia tylko to, czego ZPRP nie podał,
* wynik tylko z protokołu `finished`/`approved` (nigdy z meczu w toku),
  oznaczony `score_source = "proel"` („wynik z protokołu elektronicznego"),
  aż ZPRP poda własny,
* godzina tylko, gdy dzień z ProEla zgadza się z dniem z ZPRP,
* ćwiczenia, testy i szkolenia nigdy (`is_public_blob`).
"""

from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.time_pl import has_kickoff_time, to_warsaw_naive
from app.zprp_public.proel_live_rules import host_is_home, is_public_blob

FINISHED = ("finished", "approved")
#: Po tylu godzinach od godziny meczu bez wyniku karta mówi „czeka na wynik".
RESULT_GRACE = timedelta(hours=2)
#: Jak daleko wstecz szukamy w ProElu wyniku, którego ZPRP jeszcze nie ma.
SCORE_LOOKBACK = timedelta(days=30)

_HHMM = re.compile(r"^\s*(\d{1,2})[:.](\d{2})(?::(\d{2}))?\s*$")
_DAY = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})")
_DAY_PL = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})")
_PAIR = re.compile(r"^\s*(\d{1,2})\s*[-:]\s*(\d{1,2})\s*$")


def parse_clock(value: Any) -> Optional[time]:
    """„18:00", „18.00", „18:00:00" -> time; 00:00 i śmieci -> None (godzina do ustalenia)."""
    hit = _HHMM.match(str(value or ""))
    if not hit:
        return None
    hour, minute = int(hit.group(1)), int(hit.group(2))
    if hour > 23 or minute > 59 or (hour == 0 and minute == 0):
        return None
    return time(hour, minute)


def with_clock(day: Any, clock: Any) -> Optional[datetime]:
    """Dzień (date/datetime) + godzina z napisu -> naiwny czas warszawski albo None."""
    hhmm = parse_clock(clock)
    if hhmm is None:
        return None
    if isinstance(day, datetime):
        day = day.date()
    if not isinstance(day, date):
        return None
    return datetime.combine(day, hhmm)


def _blob_day(value: Any) -> Optional[date]:
    raw = str(value or "")
    try:
        hit = _DAY.match(raw)
        if hit:
            return date(int(hit.group(1)), int(hit.group(2)), int(hit.group(3)))
        hit = _DAY_PL.match(raw)
        if hit:
            return date(int(hit.group(3)), int(hit.group(2)), int(hit.group(1)))
    except ValueError:
        return None
    return None


def _cfg(blob: Any) -> Dict[str, Any]:
    cfg = blob.get("matchConfig") if isinstance(blob, dict) else None
    return cfg if isinstance(cfg, dict) else {}


def _extras(blob: Any) -> Dict[str, Any]:
    extras = _cfg(blob).get("extras")
    return extras if isinstance(extras, dict) else {}


def blob_day(blob: Any) -> Optional[date]:
    """Dzień meczu zapisany w protokole (`extras.matchDate`, „RRRR-MM-DD")."""
    return _blob_day(_extras(blob).get("matchDate"))


def proel_kickoff(blob: Any, day: Optional[date], started_at: Any = None) -> Optional[datetime]:
    """Godzina meczu z ProEla na dzień `day` (ZPRP): planowana z konfiguracji, potem pierwszy gwizdek.

    `started_at` = `proel_match_state.live_started_at` (timestamptz; naiwny = UTC, jak w live.py).
    Pierwszy gwizdek przycinamy do pełnej minuty. Inny dzień niż w ZPRP = brak godziny
    (protokół mógł zostać założony pod stary termin).
    """
    if day is None or not is_public_blob(blob):
        return None
    planned_day = blob_day(blob)
    if planned_day is None or planned_day == day:
        planned = with_clock(day, _extras(blob).get("matchTime"))
        if planned is not None:
            return planned
    if isinstance(started_at, datetime):
        local = to_warsaw_naive(started_at if started_at.tzinfo else started_at.replace(tzinfo=timezone.utc))
        if local is not None and local.date() == day and has_kickoff_time(local):
            return local.replace(second=0, microsecond=0)
    return None


def _int(value: Any) -> Optional[int]:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def proel_result(blob: Any, status: Any, home_name: Any, away_name: Any) -> Optional[Dict[str, Optional[int]]]:
    """Wynik z zakończonego protokołu w orientacji ZPRP (home/away) albo None.

    Karne z `penaltyScore` („3 - 2", gospodarz - gość), połowa z `halfScore`.
    """
    if str(status or "") not in FINISHED or not is_public_blob(blob):
        return None
    host, guest = _int(blob.get("scoreHost")), _int(blob.get("scoreGuest"))
    if host is None or guest is None or host < 0 or guest < 0:
        return None
    home_is_host = host_is_home(_cfg(blob), home_name, away_name)

    def oriented(a: Optional[int], b: Optional[int]) -> tuple:
        return (a, b) if home_is_host else (b, a)

    out: Dict[str, Optional[int]] = {}
    out["score_home"], out["score_away"] = oriented(host, guest)
    pen = _PAIR.match(str(blob.get("penaltyScore") or ""))
    sh = sa = None
    if pen and host == guest:
        sh, sa = oriented(int(pen.group(1)), int(pen.group(2)))
        if sh == sa:
            sh = sa = None
    out["shootout_home"], out["shootout_away"] = sh, sa
    half = blob.get("halfScore") if isinstance(blob.get("halfScore"), dict) else {}
    hh, ha = _int(half.get("host")), _int(half.get("guest"))
    out["halftime_home"], out["halftime_away"] = oriented(hh, ha) if hh is not None and ha is not None else (None, None)
    return out


def _kick_day(card: dict) -> Optional[date]:
    at = card.get("scheduled_at")
    if isinstance(at, datetime):
        return to_warsaw_naive(at).date()
    if isinstance(at, date):
        return at
    return None


def needs(card: dict, now_local: datetime) -> tuple:
    """(potrzebny wynik, potrzebna godzina) - kiedy w ogóle pytać ProEl o ten mecz."""
    day = _kick_day(card)
    if day is None or card.get("withdrawn"):
        return False, False
    today = now_local.date()
    no_score = card.get("score_home") is None or card.get("score_away") is None
    need_score = no_score and today - SCORE_LOOKBACK <= day <= today
    need_kick = not has_kickoff_time(card.get("scheduled_at")) and today - timedelta(days=1) <= day <= today + timedelta(days=3)
    return need_score, need_kick


def pick_row(rows: List[dict], card: dict) -> Optional[dict]:
    """Protokół tego meczu: po identyfikatorze ZPRP, a bez niego po numerze i dniu.

    Kluczem ProEla jest NUMER meczu, unikalny tylko w sezonie - wiersz bez
    `zprp_match_id` bierzemy wyłącznie, gdy dzień w protokole zgadza się z ZPRP.
    Zakończony/zatwierdzony przed meczem w toku.
    """
    match_id = str(card.get("match_id") or "")
    code = str(card.get("match_code") or "").strip()
    day = _kick_day(card)
    good = []
    for row in rows:
        zid = str(row.get("zprp_match_id") or "").strip()
        if zid:
            if zid != match_id:
                continue
        elif not code or str(row.get("match_number") or "").strip() != code or blob_day(row.get("blob")) != day:
            continue
        if not is_public_blob(row.get("blob")):
            continue
        good.append(row)
    good.sort(key=lambda r: (bool(str(r.get("zprp_match_id") or "").strip()), str(r.get("status") or "") in FINISHED,
                             str(r.get("status") or "") == "approved"), reverse=True)
    return good[0] if good else None


def extract(row: Optional[dict], card: dict) -> Dict[str, Any]:
    """Z wiersza protokołu to, co karta może przejąć: {"result": .., "kickoff": ..} (małe, do pamięci)."""
    if not row:
        return {}
    blob = row.get("blob")
    out: Dict[str, Any] = {}
    result = proel_result(blob, row.get("status"), card.get("home_team_name"), card.get("away_team_name"))
    if result:
        out["result"] = result
    kick = proel_kickoff(blob, _kick_day(card), row.get("live_started_at"))
    if kick is not None:
        out["kickoff"] = kick
    return out


def apply(card: dict, found: Dict[str, Any]) -> dict:
    """Nakłada zapas z ProEla na kartę (mutuje): tylko puste pola ZPRP. Ustawia `*_source`."""
    result = found.get("result")
    if result and (card.get("score_home") is None or card.get("score_away") is None) and not card.get("withdrawn"):
        for key, value in result.items():
            if card.get(key) is None:
                card[key] = value
        card["score_source"] = "proel"
        if card.get("status") in (None, "scheduled"):
            card["status"] = "finished"
    kick = found.get("kickoff")
    if kick is not None and not has_kickoff_time(card.get("scheduled_at")) and _kick_day(card) == kick.date():
        card["scheduled_at"] = kick
        card["kickoff_source"] = "proel"
    return card


def result_pending(card: dict, now_local: datetime) -> bool:
    """Mecz powinien być już po, a wyniku nie ma ani w ZPRP, ani w ProElu.

    Z godziną: 2 h po godzinie meczu. Bez godziny: dopiero następnego dnia
    (nie wiemy, kiedy grali).
    """
    if card.get("withdrawn") or (card.get("score_home") is not None and card.get("score_away") is not None):
        return False
    at = card.get("scheduled_at")
    if not isinstance(at, datetime):
        return False
    at = to_warsaw_naive(at)
    if has_kickoff_time(at):
        return at + RESULT_GRACE <= now_local
    return at.date() < now_local.date()


def mark_sources(card: dict, now_local: datetime) -> dict:
    """Domyślne `score_source`/`kickoff_source` (ZPRP) i `result_pending` (mutuje)."""
    if card.get("score_home") is not None and card.get("score_away") is not None:
        card.setdefault("score_source", "zprp")
    else:
        card.setdefault("score_source", None)
    if "scheduled_at" in card:
        card.setdefault("kickoff_source", "zprp" if has_kickoff_time(card.get("scheduled_at")) else None)
        card["result_pending"] = result_pending(card, now_local)
    return card
