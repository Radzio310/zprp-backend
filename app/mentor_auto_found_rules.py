"""Automat nagrań w dniu meczu - reguły czyste (bez bazy i sieci). Kontrakt: `docs/mentor-panel.md`, § "Automat nagrań".

Próby: start meczu z obsady ZPRP, start + 30 min i start + 2 h; każda ma okno spóźnienia 15 min (pętla chodzi co ~5 min).
Po pewnym trafieniu kolejnych prób nie ma. Pewne = jeden kandydat (kod meczu albo drużyny + dzień + godzina), reszta to sugestie.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")

#: Minuty od startu meczu, o których szukamy nagrania.
SLOT_MINUTES: Tuple[int, ...] = (0, 30, 120)
#: Ile po godzinie próby próba jeszcze się liczy (pętla chodzi co ~5 min; restart serwera nie gubi próby).
LATE_MIN = 15
#: Push dopiero po ostatniej próbie (start + 2 h): nigdy w trakcie gry.
PUSH_AFTER_MIN = SLOT_MINUTES[-1]
#: Zawężenie "ta sama godzina" dla kandydata bez kodu meczu.
TIME_CLOSE_MIN = 90
#: Sugestie: ile najwyżej i od jakiej pewności.
SUGGEST_MAX = 5
SUGGEST_MIN = 45


# --- Czas -------------------------------------------------------------------


def aware(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def start_of(card: Mapping[str, Any]) -> Optional[datetime]:
    """Start meczu (UTC) z karty albo None, gdy godziny nie znamy (00:00 czasu polskiego = tylko dzień)."""
    when = aware(card.get("scheduled_at"))
    if when is None:
        return None
    local = when.astimezone(WARSAW)
    if local.hour == 0 and local.minute == 0:
        return None
    return when.astimezone(timezone.utc)


def slot_times(start: datetime) -> List[datetime]:
    return [start + timedelta(minutes=m) for m in SLOT_MINUTES]


def plan(start: datetime, now: datetime, done: Iterable[int]) -> Dict[str, Any]:
    """Co teraz zrobić z próbami meczu. `run` = numer próby do wykonania teraz (najwcześniejsza z otwartym oknem), `missed` = próby,
    których okno minęło bez wykonania, `finished` = nie ma już żadnej przyszłej ani bieżącej próby."""
    done_set = set(done)
    run: Optional[int] = None
    missed: List[int] = []
    for k, at in enumerate(slot_times(start)):
        if k in done_set:
            continue
        if now > at + timedelta(minutes=LATE_MIN):
            missed.append(k)
        elif now >= at and run is None:
            run = k
    last_end = slot_times(start)[-1] + timedelta(minutes=LATE_MIN)
    finished = now > last_end
    return {"run": run, "missed": missed, "finished": finished}


def window_end(start: datetime, slot: int) -> datetime:
    return slot_times(start)[slot] + timedelta(minutes=LATE_MIN)


def next_attempt(start: datetime, now: datetime, done: Iterable[int]) -> Optional[datetime]:
    """Najbliższa próba do pokazania w liście (bieżąca = teraz); None, gdy już po wszystkim."""
    done_set = set(done)
    for k, at in enumerate(slot_times(start)):
        if k in done_set:
            continue
        if now <= at + timedelta(minutes=LATE_MIN):
            return at if now < at else now
    return None


def push_due(start: datetime, now: datetime) -> bool:
    return now >= start + timedelta(minutes=PUSH_AFTER_MIN)


# --- Pewność ----------------------------------------------------------------

_LOCAL = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$")


def entry_moment(value: Any) -> Optional[datetime]:
    """Czas wpisu (ISO ze strefą albo czas polski bez strefy) jako UTC; None, gdy godziny brak (00:00:00)."""
    text = str(value or "").strip()
    if not text:
        return None
    m = _LOCAL.match(text)
    if m:
        if m.group(2) == "00" and m.group(3) == "00":
            return None
        naive = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}:{m.group(3)}:00")
        return naive.replace(tzinfo=WARSAW).astimezone(timezone.utc)
    when = aware(text)
    if when is None:
        return None
    local = when.astimezone(WARSAW)
    if local.hour == 0 and local.minute == 0:
        return None
    return when.astimezone(timezone.utc)


def time_close(value: Any, start: datetime, minutes: int = TIME_CLOSE_MIN) -> bool:
    moment = entry_moment(value)
    return moment is not None and abs((moment - start).total_seconds()) <= minutes * 60


def auto_sure(entry: Mapping[str, Any], start: datetime) -> bool:
    """Kandydat, którego wolno dodać bez pytania: `sure` z rankingu (kod co do litery + drużyny + dzień u kaset; kod albo obie drużyny
    + dzień u filmów), albo obie drużyny + ten sam dzień + godzina w granicach 90 min od startu, gdy kod meczu nie jest sprzeczny
    i kategoria nie jest inna."""
    sig = entry.get("signals") or {}
    if sig.get("code") is False or sig.get("category") == "diff":
        return False
    if entry.get("sure"):
        return True
    return sig.get("teams") == "both" and sig.get("date") == "same" and time_close(entry.get("date"), start)


def idempotency(match_id: Any, key: Any) -> str:
    """Klucz idempotencji dodania (8-80 znaków [A-Za-z0-9._:-])."""
    return "auto-" + hashlib.sha1(f"{match_id}|{key}".encode("utf-8")).hexdigest()[:24]


# --- Decyzja ----------------------------------------------------------------


def source_keys(group: Mapping[str, Any]) -> List[Any]:
    return [s.get("key") for s in group.get("sources") or [{"key": group.get("key")}]]


def decide(merged: List[Dict[str, Any]], members: Mapping[str, Mapping[str, Any]], start: datetime) -> Dict[str, Any]:
    """`merged` = wpisy po `merge_ranked` (jeden na mecz, posortowane), `members` = wpisy źródłowe po `key` (przed scaleniem).
    Zwraca `{action: add|suggest|none, pick, groups}`: `add` tylko gdy dokładnie JEDEN wpis jest pewny (inaczej wszyscy kandydaci
    idą do sugestii). `pick` to źródło do dodania (kaseta z nagraniem przed filmem z YouTube)."""
    for group in merged:
        group["auto_sure"] = any(auto_sure(members[k], start) for k in source_keys(group) if k in members)
    sure_groups = [g for g in merged if g["auto_sure"]]
    if len(sure_groups) == 1:
        return {"action": "add", "pick": representative(sure_groups[0], members, start), "group": sure_groups[0],
                "groups": [g for g in merged if g is not sure_groups[0] and int(g.get("confidence") or 0) >= SUGGEST_MIN][:SUGGEST_MAX]}
    cands = [g for g in merged if g["auto_sure"] or int(g.get("confidence") or 0) >= SUGGEST_MIN]
    return {"action": "suggest" if cands else "none", "pick": None, "group": None, "groups": cands[:SUGGEST_MAX]}


def representative(group: Mapping[str, Any], members: Mapping[str, Mapping[str, Any]], start: datetime) -> Dict[str, Any]:
    """Źródło, które dodajemy: pewne przed niepewnym, kaseta Bastionu przed YouTube, wyższa pewność przed niższą."""
    found = [members[k] for k in source_keys(group) if k in members] or [group]
    found.sort(key=lambda e: (0 if auto_sure(e, start) else 1, 0 if e.get("source") == "bastion" else 1, -int(e.get("confidence") or 0)))
    return dict(found[0])


def add_url(entry: Mapping[str, Any]) -> Optional[str]:
    """Adres do `POST .../videos`: kaseta = kanoniczny adres portalu, film = jego adres."""
    ref = entry.get("ref") or {}
    if entry.get("source") == "bastion":
        item = ref.get("bunny_item_id")
        if item:
            from app import mentor_bastion_rules as BR

            return BR.canonical_game_url(int(item))
        return entry.get("url") or None
    return ref.get("url") or entry.get("url") or None


def candidate(entry: Mapping[str, Any], group: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Kształt kandydata w odpowiedzi (jak wpis `ranked` z Trybuny): title, source(s), thumbnail_url, confidence, date, home/away,
    crests, bunny_item_id | url | video_id."""
    ref = entry.get("ref") or {}
    top = group if group is not None else entry
    srcs = [s.get("source") for s in top.get("sources") or [] if s.get("source")] or [entry.get("source")]
    return {
        "key": entry.get("key"), "source": entry.get("source"), "sources": sorted(set(srcs)),
        "title": entry.get("title"), "thumbnail_url": entry.get("thumbnail_url"),
        "confidence": int(top.get("confidence") or entry.get("confidence") or 0),
        "sure": bool(top.get("auto_sure") or entry.get("sure")),
        "date": entry.get("date"), "code": entry.get("code"), "home": entry.get("home"), "away": entry.get("away"),
        "home_crest": entry.get("home_crest"), "away_crest": entry.get("away_crest"),
        "url": add_url(entry), "bunny_item_id": ref.get("bunny_item_id"), "video_id": ref.get("video_id"),
    }


def merge_candidates(old: List[Dict[str, Any]], new: List[Dict[str, Any]], dismissed: Set[str]) -> Tuple[List[Dict[str, Any]], bool]:
    """Stare i nowe sugestie bez powtórek (po kluczu) i bez odrzuconych; nowsze dane nadpisują, wynik wg pewności. Zwraca
    (lista do 5, czy pojawił się klucz, którego wcześniej nie było)."""
    by_key: Dict[str, Dict[str, Any]] = {}
    for c in old:
        if c.get("key") and c["key"] not in dismissed:
            by_key[c["key"]] = c
    fresh = False
    for c in new:
        key = c.get("key")
        if not key or key in dismissed:
            continue
        if key not in by_key:
            fresh = True
        by_key[key] = c
    out = sorted(by_key.values(), key=lambda c: (0 if c.get("sure") else 1, -int(c.get("confidence") or 0)))
    return out[:SUGGEST_MAX], fresh


# --- Push -------------------------------------------------------------------


def push_text(state: str, card: Mapping[str, Any]) -> Tuple[str, str]:
    """Tytuł i treść pusha: "Nagranie IMB/49 czeka" (added) / "Mamy propozycje nagrania IMB/49" (suggested)."""
    code = str(card.get("match_code") or "").strip()
    teams = " - ".join(x for x in ((card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")) if x)
    label = code or teams or "meczu"
    title = f"Nagranie {label} czeka" if state == "added" else f"Mamy propozycje nagrania {label}"
    if code and teams:
        body = teams
    else:
        body = "Dodane automatycznie - sprawdź i w razie czego cofnij." if state == "added" else "Wybierz właściwe nagranie."
    return title, body


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=lambda v: v.isoformat() if hasattr(v, "isoformat") else str(v))


def loads(value: Any, default: Any) -> Any:
    if isinstance(value, (list, dict)):
        return value
    try:
        out = json.loads(value) if isinstance(value, str) and value else default
    except ValueError:
        return default
    return out if isinstance(out, type(default)) else default
