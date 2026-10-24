"""Skład z protokołu elektronicznego (ProEl), gdy ZPRP jeszcze go nie opublikował - czysta logika.

Po meczu prowadzonym w ProElu sekretarz wysyła do ZPRP wynik i statystyki
zawodników pojedynczo (`/proel/zprp/summary`, `/player-stats`, pakiet
`/full-batch`). Zanim to dojdzie, a portal to pobierze, publiczny skład ZPRP
bywa pusty albo częściowy (np. zgłoszenie wpisane do połowy, bez bramek).
Protokół w BAZIE ma już komplet: numery, bramki, 7 m, kary z minutami.

Prywatność (jak `proel_live_rules`): z bloba wychodzą WYŁĄCZNIE dane sportowe -
strona, numer koszulki albo litera osoby towarzyszącej, liczniki i czasy kar.
Nazwiska z kart ProEl (`fullName`) nigdy nie trafiają do odpowiedzi: służą
tylko do SPRAWDZENIA, czy publiczna tożsamość z ZPRP pasuje do numeru.
Nazwisko, zdjęcie i profil pochodzą wyłącznie z publicznych tabel ZPRP:
* `zprpId` karty (identyfikator zawodnika z bazy związku) - gdy jest w publicznej hurtowni,
* numer, w którym zawodnik ostatnio grał dla tej drużyny w sezonie (publiczne składy),
* numer z publicznej kadry drużyny,
a gdy nic nie pasuje - wiersz bez nazwiska („Zawodnik nr N").
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.zprp_public import proel_live_rules as L

SIDES = ("home", "away")
_LETTERS = ("A", "B", "C", "D", "E")
_CARD_KINDS = {"warning", "penalty1", "penalty2", "penalty3", "penaltyExtra", "disqualification", "disqualificationBlue"}

#: Pola zawodnika, które wolno zwrócić (publiczne ZPRP + sport z protokołu).
PUBLIC_PLAYER_KEYS = ("player_id", "first_name", "last_name", "gender", "birth_year", "photo_url", "updated_at")


def _fold(text: Any) -> str:
    base = unicodedata.normalize("NFKD", str(text or "").lower().replace("ł", "l"))
    return re.sub(r"[^a-z ]", " ", "".join(c for c in base if not unicodedata.combining(c)))


def _words(text: Any) -> List[str]:
    return [w for w in _fold(text).split() if w]


def _num(value: Any) -> Optional[int]:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _letter(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip().upper() in _LETTERS:
        return value.strip().upper()
    return None


def side_map(host_home: bool) -> Dict[str, str]:
    return {"host": "home", "guest": "away"} if host_home else {"host": "away", "guest": "home"}


# ---------------------------------------------------------------------------
# Statystyki z protokołu
# ---------------------------------------------------------------------------


def _empty_stats() -> Dict[str, Any]:
    return {
        "goals": 0, "warnings": 0, "two_minutes": 0, "disqualifications": 0, "direct_red_cards": 0,
        "penalty_attempts": 0, "penalty_goals": 0, "shootout_attempts": 0, "shootout_goals": 0,
        "warning_time": None, "two_minutes_times": [], "disqualification_time": None,
        "disqualification_blue": False, "extra_penalty": False, "extra_penalty_time": None,
    }


def protocol_stats(blob: Any, host_home: bool = True) -> Dict[str, Dict[str, Dict[Any, Dict[str, Any]]]]:
    """-> {"home": {"players": {nr: staty}, "staff": {litera: staty}}, "away": ...}.

    Cofnięte bramki zdejmuje ta sama reguła co LIVE (`_drop_removed`). Seria
    rzutów karnych liczy się osobno (`shootout_*`), nie do bramek z gry.
    """
    out: Dict[str, Dict[str, Dict[Any, Dict[str, Any]]]] = {s: {"players": {}, "staff": {}} for s in SIDES}
    if not isinstance(blob, dict):
        return out
    side = side_map(host_home)
    hms = L.half_ms(blob)
    events = [ev for ev in L._drop_removed(blob.get("protocol") or []) if ev.get("team") in side]
    events.sort(key=lambda ev: (L._half_of(ev, hms), L._int(ev.get("time"))))
    for ev in events:
        if ev.get("shootout"):
            continue
        kind = ev.get("type")
        who = ev.get("player")
        letter = _letter(who)
        bucket, key = ("staff", letter) if letter else ("players", _num(who))
        if key is None:
            continue
        s = side[ev["team"]]
        if kind not in ("goal", "penaltyKickScored", "penaltyKickMissed") and kind not in _CARD_KINDS:
            continue
        if bucket == "staff" and kind not in _CARD_KINDS:
            continue
        rec = out[s][bucket].setdefault(key, _empty_stats())
        t = L.mmss(ev.get("time"))
        if kind == "goal":
            rec["goals"] += 1
        elif kind == "penaltyKickScored":
            rec["goals"] += 1
            rec["penalty_attempts"] += 1
            rec["penalty_goals"] += 1
        elif kind == "penaltyKickMissed":
            rec["penalty_attempts"] += 1
        elif kind == "warning":
            rec["warnings"] += 1
            rec["warning_time"] = rec["warning_time"] or t
        elif kind in ("penalty1", "penalty2", "penalty3"):
            rec["two_minutes"] += 1
            if len(rec["two_minutes_times"]) < 3:
                rec["two_minutes_times"].append(t)
        elif kind == "penaltyExtra":
            rec["direct_red_cards"] += 1
            rec["extra_penalty"] = True
            rec["extra_penalty_time"] = rec["extra_penalty_time"] or t
        else:  # disqualification / disqualificationBlue
            rec["disqualifications"] += 1
            rec["disqualification_time"] = rec["disqualification_time"] or t
            if kind == "disqualificationBlue":
                rec["disqualification_blue"] = True
    shots = blob.get("penaltyShots")
    if isinstance(shots, dict):
        for team, s in side.items():
            for shot in shots.get(team) or []:
                if not isinstance(shot, dict) or shot.get("result") not in (0, 1):
                    continue
                nr = _num(shot.get("player"))
                if nr is None:
                    continue
                rec = out[s]["players"].setdefault(nr, _empty_stats())
                rec["shootout_attempts"] += 1
                rec["shootout_goals"] += 1 if shot.get("result") == 1 else 0
    return out


# ---------------------------------------------------------------------------
# Skład z konfiguracji meczu (numery; nazwiska tylko do weryfikacji)
# ---------------------------------------------------------------------------


def proel_roster(blob: Any, host_home: bool = True) -> Dict[str, Dict[str, Any]]:
    """-> {"home": {"players": [{number, zprp_id, check}], "staff": [{letter, check}]}, ...}.

    `check` to nazwisko z karty - WYŁĄCZNIE do porównania z publicznym ZPRP,
    nigdy do odpowiedzi. Wykreśleni (`struck`) wypadają, chyba że mają zdarzenie.
    """
    out: Dict[str, Dict[str, Any]] = {s: {"players": [], "staff": []} for s in SIDES}
    if not isinstance(blob, dict):
        return out
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
    for team, s in side_map(host_home).items():
        seen: Dict[int, Dict[str, Any]] = {}
        struck: Dict[int, Dict[str, Any]] = {}
        for card in cfg.get(f"{team}PlayerCards") or []:
            if not isinstance(card, dict):
                continue
            nr = _num(card.get("number"))
            if nr is None:
                continue
            zid = str(card.get("zprpId") or "").strip() or None
            item = {"number": nr, "zprp_id": zid, "check": str(card.get("fullName") or "").strip() or None}
            if card.get("struck"):
                struck.setdefault(nr, item)
            else:
                seen.setdefault(nr, item)
        for raw in cfg.get(f"{team}Players") or []:
            nr = _num(raw)
            if nr is not None and nr not in seen:
                seen[nr] = struck.pop(nr, None) or {"number": nr, "zprp_id": None, "check": None}
        out[s]["players"] = [seen[k] for k in sorted(seen)]
        out[s]["struck"] = struck
        staff: Dict[str, Dict[str, Any]] = {}
        for comp in cfg.get(f"{team}Companions") or []:
            if not isinstance(comp, dict):
                continue
            letter = _letter(comp.get("id"))
            name = str(comp.get("fullName") or "").strip()
            if letter and name:
                staff[letter] = {"letter": letter, "check": name}
        out[s]["staff"] = [staff[k] for k in sorted(staff)]
    return out


# ---------------------------------------------------------------------------
# Nazwiska z publicznego ZPRP
# ---------------------------------------------------------------------------


def number_index(appearances: Iterable[Dict[str, Any]], roster: Iterable[Dict[str, Any]] = ()) -> Dict[int, str]:
    """Numer -> player_id z publicznych danych drużyny w sezonie.

    `appearances`: {player_id, shirt_number, at} z publicznych składów meczów.
    Zawodnik liczy się pod numerem, w którym grał OSTATNIO (numer po zmianie
    nie wskazuje dawnego właściciela). Przy dwóch chętnych na numer wygrywa
    świeższy występ. Kadra (`roster`: {player_id, shirt_number}) uzupełnia
    numery, których składy nie znają.
    """
    latest: Dict[str, Tuple[Any, int]] = {}
    for row in appearances:
        pid = str(row.get("player_id") or "").strip()
        nr = _num(row.get("shirt_number"))
        if not pid or nr is None:
            continue
        at = row.get("at")
        key = (at is not None, at)
        old = latest.get(pid)
        if old is None or _later(key, old[0]):
            latest[pid] = (key, nr)
    by_number: Dict[int, Tuple[Any, str]] = {}
    for pid, (key, nr) in latest.items():
        old = by_number.get(nr)
        if old is None or _later(key, old[0]):
            by_number[nr] = (key, pid)
    out = {nr: pid for nr, (_, pid) in by_number.items()}
    taken = set(out.values())
    counts: Dict[int, List[str]] = {}
    for row in roster:
        pid = str(row.get("player_id") or "").strip()
        nr = _num(row.get("shirt_number"))
        if pid and nr is not None and pid not in taken:
            counts.setdefault(nr, []).append(pid)
    for nr, pids in counts.items():
        if nr not in out and len(set(pids)) == 1:
            out[nr] = pids[0]
    return out


def _later(a: Tuple[bool, Any], b: Tuple[bool, Any]) -> bool:
    if a[0] != b[0]:
        return a[0]
    if not a[0]:
        return False
    try:
        return a[1] > b[1]
    except TypeError:
        return str(a[1]) > str(b[1])


def name_matches(public: Dict[str, Any], check: Optional[str]) -> bool:
    """Publiczne nazwisko (i imię, gdy jest) zgodne z nazwiskiem z karty. Brak karty = nie blokuje."""
    if not check:
        return True
    have = set(_words(check))
    last = _words(public.get("last_name"))
    if not last or not all(w in have for w in last):
        return False
    first = _words(public.get("first_name"))
    return not first or first[0] in have


def _find_by_name(check: Optional[str], pool: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not check:
        return None
    hits = {str(p["player_id"]): p for p in pool if p.get("player_id") and _words(p.get("first_name")) and name_matches(p, check)}
    return next(iter(hits.values())) if len(hits) == 1 else None


def resolve_player(
    entry: Dict[str, Any],
    public: Dict[str, Dict[str, Any]],
    by_number: Dict[int, str],
    team_pool: List[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """-> (publiczny zawodnik albo None, skąd: zprp_id | zprp_number | zprp_name | None)."""
    zid = entry.get("zprp_id")
    if zid and zid in public:
        return public[zid], "zprp_id"
    guess = by_number.get(entry["number"])
    if guess and guess in public and name_matches(public[guess], entry.get("check")):
        return public[guess], "zprp_number"
    found = _find_by_name(entry.get("check"), team_pool)
    if found:
        return found, "zprp_name"
    return None, None


def _public_view(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    row = row or {}
    return {k: row.get(k) for k in PUBLIC_PLAYER_KEYS}


def build_players(
    roster: List[Dict[str, Any]],
    stats: Dict[Any, Dict[str, Any]],
    side: str,
    team_id: Optional[str],
    public: Dict[str, Dict[str, Any]],
    by_number: Dict[int, str],
    team_pool: List[Dict[str, Any]],
    positions: Optional[Dict[str, str]] = None,
    struck: Optional[Dict[int, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Wiersze tabeli protokołu jednej strony - kształt jak wiersz ZPRP z `match_overview`."""
    entries = {e["number"]: e for e in roster}
    for nr in stats:
        if isinstance(nr, int) and nr not in entries:
            entries[nr] = (struck or {}).get(nr) or {"number": nr, "zprp_id": None, "check": None}
    out: List[Dict[str, Any]] = []
    used: set = set()
    for nr in sorted(entries):
        entry = entries[nr]
        person, how = resolve_player(entry, public, by_number, team_pool)
        if person and str(person.get("player_id")) in used:
            person, how = None, None  # jeden człowiek - jeden wiersz
        if person:
            used.add(str(person.get("player_id")))
        rec = stats.get(nr) or _empty_stats()
        row = {
            **_public_view(person),
            "team_id": team_id,
            "side": side,
            "shirt_number": str(nr),
            "position": (positions or {}).get(str(person.get("player_id"))) if person else None,
            **{k: (list(v) if isinstance(v, list) else v) for k, v in rec.items()},
            "source": "proel",
            "name_source": how,
        }
        out.append(row)
    return out


def staff_index(rows: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Litera -> publiczne osoby towarzyszące drużyny (najświeższe pierwsze), z `staff_view`."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        letter = row.get("letter")
        if letter in _LETTERS and (row.get("last_name") or row.get("first_name")):
            out.setdefault(letter, []).append(row)
    return out


def build_staff(
    roster: List[Dict[str, Any]],
    stats: Dict[Any, Dict[str, Any]],
    side: str,
    team_id: Optional[str],
    public_staff: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Osoby A-E z protokołu. Nazwisko tylko z publicznego ZPRP i tylko zgodne z kartą (inaczej bez nazwiska)."""
    letters = {e["letter"]: e for e in roster}
    for letter in stats:
        if isinstance(letter, str) and letter not in letters:
            letters[letter] = {"letter": letter, "check": None}
    out: List[Dict[str, Any]] = []
    for letter in sorted(letters):
        check = letters[letter].get("check")
        person = None
        if check:
            for cand in public_staff.get(letter) or []:
                if name_matches(cand, check):
                    person = cand
                    break
        rec = stats.get(letter) or _empty_stats()
        out.append({
            "team_id": team_id,
            "side": side,
            "letter": letter,
            "person_id": person.get("person_id") if person else None,
            "first_name": person.get("first_name") if person else None,
            "last_name": person.get("last_name") if person else None,
            "role": person.get("role") if person else None,
            "function": person.get("function") if person else None,
            "license": None,
            **{k: (list(v) if isinstance(v, list) else v) for k, v in rec.items() if k not in ("goals", "shootout_attempts", "shootout_goals")},
            "penalty_attempts": 0,
            "penalty_goals": 0,
            "source": "proel",
        })
    return out


# ---------------------------------------------------------------------------
# Wybór źródła i wynik
# ---------------------------------------------------------------------------


def side_complete(count: int, goals: int, score: Optional[int]) -> bool:
    """Strona ZPRP kompletna: ma zawodników, a bramki (gdy są) zgadzają się z wynikiem."""
    if count <= 0:
        return False
    if score is None:
        return False
    return goals == 0 or goals == score


def zprp_complete(counts: Dict[str, int], goals: Dict[str, int], score_home: Optional[int], score_away: Optional[int]) -> bool:
    """Protokół ZPRP kompletny: obie strony mają zawodników, wynik jest, bramki (gdy podane) zgadzają się z wynikiem."""
    return (side_complete(int(counts.get("home") or 0), int(goals.get("home") or 0), score_home)
            and side_complete(int(counts.get("away") or 0), int(goals.get("away") or 0), score_away))


def choose_sources(
    zprp: Dict[str, List[Dict[str, Any]]],
    fallback: Optional[Dict[str, List[Dict[str, Any]]]],
    complete: bool,
) -> Dict[str, Optional[str]]:
    """Źródło składu dla każdej strony osobno: "zprp" | "proel" | None.

    ZPRP wygrywa, gdy cały protokół jest kompletny albo gdy jego strona nie jest
    widocznie uboższa od protokołu elektronicznego (tylu zawodników i tyle bramek).
    """
    out: Dict[str, Optional[str]] = {}
    for s in SIDES:
        z = zprp.get(s) or []
        f = (fallback or {}).get(s) or []
        if complete and z:
            out[s] = "zprp"
        elif not f:
            out[s] = "zprp" if z else None
        elif not z:
            out[s] = "proel"
        else:
            zg = sum(int(p.get("goals") or 0) for p in z)
            fg = sum(int(p.get("goals") or 0) for p in f)
            out[s] = "zprp" if len(z) >= len(f) and zg >= fg else "proel"
    return out


def final_score(blob: Any, host_home: bool, status: Optional[str]) -> Optional[Dict[str, int]]:
    """Wynik końcowy z protokołu - tylko po zakończeniu/zatwierdzeniu meczu w ProElu."""
    if status not in ("finished", "approved") or not isinstance(blob, dict):
        return None
    if blob.get("scoreHost") is None and blob.get("scoreGuest") is None:
        return None
    side = side_map(host_home)
    return {side["host"]: L._int(blob.get("scoreHost")), side["guest"]: L._int(blob.get("scoreGuest"))}
