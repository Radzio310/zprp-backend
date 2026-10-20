"""Przebieg meczu z protokołu ProEl dla publicznego portalu - czysta logika, bez bazy.

ProEl (protokół stolikowy w aplikacji BAZA) zapisuje każde zdarzenie z minutą:
bramki, 7 m, kary, kartki, czasy drużyn. ZPRP podaje tylko liczniki, więc
przebieg meczu, wykresy i LIVE na portalu biorą się wyłącznie stąd.

Prywatność: z bloba wychodzą WYŁĄCZNIE dane sportowe - strona, numer koszulki
(albo litera osoby towarzyszącej), rodzaj zdarzenia i czas. Żadnych nazwisk
z kart zawodników, licencji, badań, podpisów ani obsady stolika - nazwiska
portal dobiera sam z publicznych składów ZPRP.

Strony: ProEl mówi host/guest, portal home/away. Zwykle host = home, ale
konfigurator meczu potrafi zamienić gospodarza (`matchConfig.hostSwapped`),
a ZPRP bywa pomylony. Rozstrzyga porównanie nazw drużyn, potem flaga.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_HALF_MIN = 30
LETTERS = {"A", "B", "C", "D", "E"}

#: Rodzaj zdarzenia ProEl -> identyfikator portalu.
KIND = {
    "goal": "goal",
    "penaltyKickScored": "seven_goal",
    "penaltyKickMissed": "seven_miss",
    "warning": "warning",
    "penalty1": "two_min",
    "penalty2": "two_min",
    "penalty3": "two_min",
    "penaltyExtra": "extra",
    "disqualification": "red",
    "disqualificationBlue": "blue",
    "teamTime": "timeout",
}
TWO_MIN_LADDER = {"penalty1": 1, "penalty2": 2, "penalty3": 3}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _num(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _extra(ev: Dict[str, Any]) -> Dict[str, Any]:
    raw = ev.get("extra")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {}
        except ValueError:
            return {}
    return {}


def mmss(ms: Any) -> str:
    total = max(0, _int(ms)) // 1000
    return "%02d:%02d" % (total // 60, total % 60)


def fold(text: Any) -> str:
    base = unicodedata.normalize("NFKD", str(text or "").lower().replace("ł", "l"))
    return re.sub(r"[^a-z0-9 ]", " ", "".join(c for c in base if not unicodedata.combining(c)))


_STOP = {"ks", "mks", "uks", "sms", "kps", "spr", "mks", "klub", "sportowy", "ii", "i", "ssr", "kpr", "azs", "sp", "zo", "o", "sa", "s", "a"}


def _tokens(name: Any) -> set:
    return {w for w in fold(name).split() if len(w) > 2 and w not in _STOP}


def name_score(a: Any, b: Any) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / float(min(len(ta), len(tb)))


def host_is_home(config: Dict[str, Any], home_name: Any, away_name: Any) -> bool:
    """Czy ProElowy gospodarz to gospodarz w ZPRP."""
    host, guest = config.get("hostTeamName"), config.get("guestTeamName")
    direct = name_score(host, home_name) + name_score(guest, away_name)
    crossed = name_score(host, away_name) + name_score(guest, home_name)
    if abs(direct - crossed) >= 0.5:
        return direct > crossed
    return not bool(config.get("hostSwapped"))


def half_ms(blob: Dict[str, Any]) -> int:
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
    minutes = _int(cfg.get("halfTime"), DEFAULT_HALF_MIN)
    return (minutes if 5 <= minutes <= 45 else DEFAULT_HALF_MIN) * 60_000


def is_public_blob(blob: Any) -> bool:
    """Ćwiczenia, testy i szkolenia nigdy nie wychodzą na portal."""
    if not isinstance(blob, dict):
        return False
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
    if cfg.get("isTest") or cfg.get("training") is not None:
        return False
    return True


def _drop_removed(protocol: List[Any]) -> List[Dict[str, Any]]:
    """Cofnięta bramka zabiera swoje zdarzenie (ta sama reguła co protokół PDF w `results.py`)."""
    kept: List[Dict[str, Any]] = []
    for ev in protocol:
        if not isinstance(ev, dict):
            continue
        if ev.get("type") != "goalRemoved":
            kept.append(ev)
            continue
        extra = _extra(ev)
        wanted = "penaltyKickScored" if extra.get("penalty") else "goal"
        orig = extra.get("origTime", ev.get("time"))
        for i in range(len(kept) - 1, -1, -1):
            prev = kept[i]
            if (prev.get("type") == wanted and prev.get("team") == ev.get("team")
                    and str(prev.get("player")) == str(ev.get("player")) and prev.get("time") == orig):
                kept.pop(i)
                break
    return kept


def _half_of(ev: Dict[str, Any], hms: int) -> int:
    h = _int(ev.get("half"), 0)
    if h in (1, 2):
        return h
    return 2 if _int(ev.get("time")) > hms else 1


def timeline(blob: Any, host_home: bool = True) -> Dict[str, Any]:
    """-> {"half_ms", "events": [...], "shootout": {...}}. Zdarzenia chronologicznie z wynikiem po każdym."""
    if not isinstance(blob, dict):
        return {"half_ms": DEFAULT_HALF_MIN * 60_000, "events": [], "shootout": None}
    hms = half_ms(blob)
    side = {"host": "home", "guest": "away"} if host_home else {"host": "away", "guest": "home"}
    raw = [ev for ev in _drop_removed(blob.get("protocol") or []) if ev.get("team") in side and ev.get("type") in KIND]
    regular = [ev for ev in raw if not ev.get("shootout")]
    regular.sort(key=lambda ev: (_half_of(ev, hms), _int(ev.get("time"))))
    score = {"home": 0, "away": 0}
    events: List[Dict[str, Any]] = []
    for ev in regular:
        kind = KIND[ev["type"]]
        who = ev.get("player")
        staff = who.strip().upper() if isinstance(who, str) and who.strip().upper() in LETTERS else None
        number = None if staff else _num(who)
        s = side[ev["team"]]
        if kind in ("goal", "seven_goal"):
            score[s] += 1
        item: Dict[str, Any] = {
            "t": max(0, _int(ev.get("time"))),
            "half": _half_of(ev, hms),
            "side": s,
            "kind": kind,
            "number": number,
            "staff": staff,
            "score": dict(score),
        }
        if ev["type"] in TWO_MIN_LADDER:
            item["step"] = TWO_MIN_LADDER[ev["type"]]
        events.append(item)
    return {"half_ms": hms, "events": events, "shootout": _shootout(blob, side)}


def _shootout(blob: Dict[str, Any], side: Dict[str, str]) -> Optional[Dict[str, Any]]:
    shots = blob.get("penaltyShots")
    if not isinstance(shots, dict):
        return None
    out: Dict[str, Any] = {"home": [], "away": []}
    for team, s in side.items():
        for shot in shots.get(team) or []:
            if isinstance(shot, dict) and shot.get("result") in (0, 1):
                out[s].append({"number": _num(shot.get("player")), "scored": shot.get("result") == 1})
    if not out["home"] and not out["away"]:
        return None
    starter = blob.get("penaltyStarterTeam")
    out["starter"] = side.get(starter) if starter in side else None
    return out


def clock(blob: Any) -> Dict[str, Any]:
    """Stan zegara do ekstrapolacji po stronie klienta (jak `utils/liveMatchView.ts` w BAZA)."""
    if not isinstance(blob, dict):
        return {}
    return {
        "main_ms": max(0, _int(blob.get("mainTime"))),
        "first_half": blob.get("isFirstHalf") is not False,
        "running": blob.get("isGameRunning") is True,
        "half_break": blob.get("isHalfBreak") is True,
        "half_break_paused": blob.get("isHalfBreakPaused") is True,
        "timeout": blob.get("isBreakRunning") is True,
        "timeout_side": None,
        "break_remaining_ms": _int(blob.get("breakRemainingMs"), 0) or None,
        "half_break_remaining_ms": _int(blob.get("halfBreakRemainingMs"), 0) or None,
        "saved_at_ms": _int(blob.get("savedAtMs"), 0) or None,
        "half_ms": half_ms(blob),
        "shootout": blob.get("penaltyShootoutActive") is True,
    }


def active_penalties(blob: Any, host_home: bool = True) -> List[Dict[str, Any]]:
    """Kafelki kar z tablicy: kto siedzi, od kiedy (czas gry) i na ile. Odlicza klient."""
    if not isinstance(blob, dict):
        return []
    side = {"host": "home", "guest": "away"} if host_home else {"host": "away", "guest": "home"}
    out = []
    for tile in blob.get("penaltyTiles") or []:
        if not isinstance(tile, dict) or tile.get("team") not in side:
            continue
        duration = _int(tile.get("duration"))
        if duration <= 0:
            continue
        who = tile.get("playerNumber")
        out.append({
            "side": side[tile["team"]],
            "number": _num(who),
            "staff": who.strip().upper() if isinstance(who, str) and who.strip().upper() in LETTERS else None,
            "type": str(tile.get("type") or ""),
            "from_ms": _int(tile.get("assignedAt")),
            "duration_ms": duration,
        })
    return out


def board(blob: Any, host_home: bool = True) -> Dict[str, Any]:
    """Tablica wyniku: wynik, połowa, zegar, aktywne kary, czasy i 7 m na stronę portalu."""
    if not isinstance(blob, dict):
        return {}
    side = {"host": "home", "guest": "away"} if host_home else {"host": "away", "guest": "home"}
    half = blob.get("halfScore") if isinstance(blob.get("halfScore"), dict) else None
    stats = blob.get("penaltyStats") if isinstance(blob.get("penaltyStats"), dict) else {}
    tos = blob.get("teamTimeouts") if isinstance(blob.get("teamTimeouts"), dict) else {}
    c = clock(blob)
    active = blob.get("activeTimeoutTeam")
    c["timeout_side"] = side.get(active) if c.get("timeout") and active in side else None
    out: Dict[str, Any] = {
        "score": {side["host"]: _int(blob.get("scoreHost")), side["guest"]: _int(blob.get("scoreGuest"))},
        "half_score": None,
        "clock": c,
        "penalties": active_penalties(blob, host_home),
        "timeouts": {s: 0 for s in side.values()},
        "sevens": {s: {"total": 0, "goals": 0} for s in side.values()},
        "shootout_label": blob.get("penaltyShootoutScoreLabel") or None,
    }
    if half and (half.get("host") is not None or half.get("guest") is not None):
        if not c["first_half"] or c["half_break"]:
            out["half_score"] = {side["host"]: _int(half.get("host")), side["guest"]: _int(half.get("guest"))}
    for team, s in side.items():
        slots = tos.get(team) if isinstance(tos.get(team), dict) else {}
        out["timeouts"][s] = sum(1 for k in ("first", "second", "third") if slots.get(k) is not None)
        st = stats.get(team) if isinstance(stats.get(team), dict) else {}
        out["sevens"][s] = {"total": _int(st.get("total")), "goals": _int(st.get("goals"))}
    return out


def last_events(events: List[Dict[str, Any]], n: int = 3) -> List[Dict[str, Any]]:
    return events[-n:][::-1]


def doc_token(rows: List[Tuple[Any, ...]]) -> str:
    """Odcisk zestawu (numer, rev, czas zapisu) - zmienia się przy każdym zapisie z telefonu."""
    import hashlib

    h = hashlib.sha1()
    for row in sorted(str(r) for r in rows):
        h.update(row.encode("utf-8"))
    return h.hexdigest()[:16]
