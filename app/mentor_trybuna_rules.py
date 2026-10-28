"""Trybuna Mentora - czyste reguły (bez bazy i sieci), kontrakt: `docs/mentor-panel.md` 8.11.

Tu jest wszystko, co da się sprawdzić bez serwera: identyfikatory, normalizacja sędziów, bilet spinający
(wybór kandydata z pewnością i luką), widok ze startu „kto jest w obsadzie", reguły półek, oznaczeń i głosów.
"""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app import mentor_panel_rules as R
from app.mentor_bastion_search import _plain, parse_day, score_game, team_tokens
from app.mentor_trybuna_tables import WATCHED_PREFIX

#: Pewność, od której wybór ZPRP/ProElu wpisuje się sam, i luka do drugiego kandydata.
AUTO_MIN = 75
AUTO_GAP = 15
#: Poniżej tej pewności kandydat nie trafia nawet na listę do poprawy.
CANDIDATE_MIN = 35
MAX_CANDIDATES = 5

VOTES = ("agree", "differ", "unsure")
VOTE_LABELS = {"agree": "Zgadzam się", "differ": "Inaczej", "unsure": "Nie wiem"}
ROLES = ("A", "B", "?")
LINK_KINDS = ("zprp", "proel", "video")
ORIGINS = ("bastion", "youtube", "link")
MAX_QUEUE = 200
MAX_SHELVES = 40
MAX_FOLLOWS = 60
MAX_REFEREE_TAGS = 4


def new_match_id() -> str:
    return WATCHED_PREFIX + uuid.uuid4().hex[:20]


def is_watched(match_id: Any) -> bool:
    return R.s(match_id).startswith(WATCHED_PREFIX)


def name_key(name: Any) -> str:
    """Klucz nazwiska niezależny od kolejności, wielkości liter i polskich znaków ("Kowalski Jan" == "jan kowalski")."""
    words = [w for w in re.split(r"[^0-9a-z]+", _plain(name)) if w]
    return " ".join(sorted(words))


def referee_key(name: Any, judge_id: Any = None) -> str:
    jid = R.s(judge_id)
    return f"id:{jid}" if jid else f"name:{name_key(name)}"


def same_referee(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    ia, ib = R.s(a.get("judge_id")), R.s(b.get("judge_id"))
    if ia and ib:
        return ia == ib
    ka, kb = name_key(a.get("name")), name_key(b.get("name"))
    return bool(ka) and ka == kb


def clean_referees(raw: Any, limit: int = 6) -> List[Dict[str, Any]]:
    """Sędziowie z dowolnego wejścia: lista napisów albo obiektów {name, judge_id, position}; bez powtórzeń."""
    out: List[Dict[str, Any]] = []
    for item in raw if isinstance(raw, (list, tuple)) else []:
        if isinstance(item, str):
            item = {"name": item}
        if not isinstance(item, Mapping):
            continue
        name = R.plain(item.get("name") or item.get("full_name"), 80)
        if not name:
            continue
        entry = {"name": name, "judge_id": R.s(item.get("judge_id") or item.get("id")) or None, "position": R.plain(item.get("position"), 20) or None,
                 "role": R.s(item.get("role")) if R.s(item.get("role")) in ("delegate", "table") else "referee"}
        if any(same_referee(entry, e) and e["role"] == entry["role"] for e in out):
            continue
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def pick_link(candidates: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Wybór kandydata: `auto` tylko gdy pewne (sure) albo wysoki wynik z wyraźną luką do następnego.

    Zwraca {state: auto|candidates|none, chosen, confidence, sure}. Kandydaci posortowani od najpewniejszego."""
    ranked = sorted((c for c in candidates if int(c.get("confidence") or 0) >= CANDIDATE_MIN),
                    key=lambda c: -int(c.get("confidence") or 0))[:MAX_CANDIDATES]
    if not ranked:
        return {"state": "none", "chosen": None, "confidence": 0, "sure": False, "candidates": []}
    top = ranked[0]
    second = int(ranked[1].get("confidence") or 0) if len(ranked) > 1 else 0
    conf = int(top.get("confidence") or 0)
    auto = bool(top.get("sure")) or (conf >= AUTO_MIN and conf - second >= AUTO_GAP)
    # Dwóch pewnych kandydatów naraz to niejednoznaczność (np. dwa mecze o tym samym kodzie i dniu) - decyduje człowiek.
    if top.get("sure") and len(ranked) > 1 and ranked[1].get("sure"):
        auto = False
    return {"state": "auto" if auto else "candidates", "chosen": top if auto else None, "confidence": conf,
            "sure": bool(top.get("sure")), "candidates": ranked}


def pseudo_game(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Migawka karty meczu z Trybuny w kształcie wiersza Meczoteki - do `score_game` względem meczu ZPRP."""
    return {"home": (snapshot.get("home") or {}).get("name"), "away": (snapshot.get("away") or {}).get("name"),
            "date": snapshot.get("scheduled_at"), "code": snapshot.get("match_code"),
            "competition": snapshot.get("competition_name") or snapshot.get("category")}


def score_zprp(snapshot: Mapping[str, Any], card: Mapping[str, Any]) -> Dict[str, Any]:
    """Pewność, że migawka z Trybuny to mecz `card` z hurtowni ZPRP (kod, drużyny, dzień, kategoria)."""
    game = pseudo_game(snapshot)
    if isinstance(game.get("date"), datetime):
        game["date"] = game["date"].isoformat()
    return score_game(game, card)


def card_snapshot(card: Mapping[str, Any]) -> Dict[str, Any]:
    """Karta meczu -> migawka do zapisu (JSON-owalna)."""
    when = card.get("scheduled_at")
    return {
        "season": card.get("season") or "", "scheduled_at": when.isoformat() if isinstance(when, datetime) else (when or None),
        "competition_name": card.get("competition_name"), "category": card.get("category"), "round_name": card.get("round_name"),
        "home": {"name": (card.get("home") or {}).get("name"), "logo_url": (card.get("home") or {}).get("logo_url"),
                 "score": (card.get("home") or {}).get("score")},
        "away": {"name": (card.get("away") or {}).get("name"), "logo_url": (card.get("away") or {}).get("logo_url"),
                 "score": (card.get("away") or {}).get("score")},
        "halftime": card.get("halftime"), "venue_city": card.get("venue_city"), "match_code": card.get("match_code"),
    }


def card_from_snapshot(match_id: str, snap: Mapping[str, Any], *, title: Optional[str] = None) -> Dict[str, Any]:
    """Karta meczu z Trybuny w kształcie `MatchCard` (pola pary: delegat, arkusze - puste)."""
    card = R.base_card(match_id)
    when = snap.get("scheduled_at")
    if isinstance(when, str) and when:
        try:
            when = datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            when = None
    if isinstance(when, datetime) and when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    home, away = dict(snap.get("home") or {}), dict(snap.get("away") or {})
    if not home.get("name") and not away.get("name") and title:
        home["name"] = R.plain(title, 120)
    card.update({
        "scheduled_at": when if isinstance(when, datetime) else None,
        "season": snap.get("season") or (R.season_key(when) if isinstance(when, datetime) else ""),
        "competition_name": snap.get("competition_name"), "category": snap.get("category"), "round_name": snap.get("round_name"),
        "home": {"name": home.get("name"), "logo_url": home.get("logo_url"), "score": home.get("score")},
        "away": {"name": away.get("name"), "logo_url": away.get("logo_url"), "score": away.get("score")},
        "halftime": snap.get("halftime"), "venue_city": snap.get("venue_city"), "match_code": snap.get("match_code"),
        "source": "watched",
    })
    return card


def snapshot_from_game(game: Mapping[str, Any]) -> Dict[str, Any]:
    """Wiersz Meczoteki (kaseta) -> migawka. Wynik "37:32" rozbity na bramki."""
    day = parse_day(game.get("date"))
    when = None
    raw = str(game.get("date") or "")
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})", raw)
    if m and (game.get("unscheduled") or (m.group(4), m.group(5)) == ("00", "00")):
        m = None  # godzina 00:00 przy mecz bez terminu = brak godziny: tylko dzień (południe jako znacznik)
    if m:
        # Bastion podaje czas polski bez strefy; zapisujemy jako czas lokalny -> UTC.
        from app.mentor_panel_rules import _local_naive_to_utc

        try:
            when = _local_naive_to_utc(datetime(*(int(x) for x in m.groups())))
        except (ValueError, TypeError):
            when = None
    elif day:
        when = datetime(day.year, day.month, day.day, 12, 0, tzinfo=timezone.utc)
    score = R.s(game.get("score"))
    hs = as_ = None
    sm = re.match(r"^(\d+)\s*:\s*(\d+)$", score)
    if sm:
        hs, as_ = int(sm.group(1)), int(sm.group(2))
    comp = R.plain(game.get("competition"), 120) or None
    snap = {
        "season": R.season_key(when) if when else "", "scheduled_at": when.isoformat() if when else None,
        "competition_name": comp, "category": None, "round_name": None,
        "home": {"name": R.plain(game.get("home"), 120) or None, "logo_url": None, "score": hs},
        "away": {"name": R.plain(game.get("away"), 120) or None, "logo_url": None, "score": as_},
        "halftime": None, "venue_city": None, "match_code": R.plain(game.get("code"), 40) or None,
    }
    return snap


_VS = re.compile(r"\s+(?:-|vs\.?|v)\s+", re.IGNORECASE)
_DATE = re.compile(r"(\d{1,2})[./](\d{1,2})[./](\d{4})")


def snapshot_from_title(title: Any) -> Dict[str, Any]:
    """Z tytułu filmu z YouTube ("KS Alfa - MKS Beta, 12.10.2026") wyciąga drużyny i datę; czego nie zna, zostawia puste."""
    text = R.plain(title, 200)
    day = None
    m = _DATE.search(text)
    if m:
        try:
            day = date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            day = None
    core = _DATE.sub("", text)
    core = re.split(r"[|,(\[]", core)[0].strip(" -:")
    parts = _VS.split(core, maxsplit=1)
    home = parts[0].strip() if len(parts) == 2 else None
    away = parts[1].strip() if len(parts) == 2 else None
    when = datetime(day.year, day.month, day.day, 12, 0, tzinfo=timezone.utc) if day else None
    return {
        "season": R.season_key(when) if when else "", "scheduled_at": when.isoformat() if when else None,
        "competition_name": None, "category": None, "round_name": None,
        "home": {"name": home[:120] if home else None, "logo_url": None, "score": None},
        "away": {"name": away[:120] if away else None, "logo_url": None, "score": None},
        "halftime": None, "venue_city": None, "match_code": None,
    }


def merge_snapshot(base: Mapping[str, Any], over: Mapping[str, Any]) -> Dict[str, Any]:
    """Pola `over` wygrywają, ale tylko niepuste (ręczna korekta nie kasuje tego, co znamy)."""
    out = {**base, "home": dict(base.get("home") or {}), "away": dict(base.get("away") or {})}
    for key, value in over.items():
        if key in ("home", "away") and isinstance(value, Mapping):
            for k, v in value.items():
                if v not in (None, ""):
                    out[key][k] = v
        elif value not in (None, "", {}):
            out[key] = value
    return out


# ─── Obsada ZPRP i obserwowani ──────────────────────────────────────────────


def referees_of_zprp_row(row: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Obsada meczu z hurtowni: sędziowie (`role: referee`, pozycje A, B) i delegaci (`role: delegate`, D1, D2)."""
    out = []
    for slot in (1, 2):
        name = R.s(row.get(f"referee_{slot}_name"))
        jid = R.s(row.get(f"referee_{slot}_id"))
        if name or jid:
            out.append({"name": name or f"Sędzia {jid}", "judge_id": jid or None, "position": "AB"[slot - 1], "role": "referee"})
    for slot in (1, 2):
        name = R.s(row.get(f"delegate_{slot}_name"))
        jid = R.s(row.get(f"delegate_{slot}_id"))
        if name or jid:
            out.append({"name": name or f"Delegat {jid}", "judge_id": jid or None, "position": f"D{slot}", "role": "delegate"})
    for pos, field in (("S1", "secretary"), ("S2", "timekeeper")):  # stolikowi: sekretarz i czasowy
        name, jid = R.s(row.get(f"{field}_name")), R.s(row.get(f"{field}_id"))
        if name or jid:
            out.append({"name": name or f"Stolikowy {jid}", "judge_id": jid or None, "position": pos, "role": "table"})
    return out


def follow_matches(follow: Mapping[str, Any], referees: Iterable[Mapping[str, Any]]) -> bool:
    """Czy obsada meczu zawiera obserwowanego sędziego (albo oboje sędziów obserwowanej pary)."""
    role = "delegate" if follow.get("kind") == "delegate" else "referee"
    refs = [r for r in referees if (r.get("role") or "referee") == role]
    if follow.get("kind") == "pair":
        parts = [{"name": n, "judge_id": j} for n, j in zip(follow.get("names") or [], list(follow.get("judge_ids") or []) + [None, None])]
        return len(parts) == 2 and all(any(same_referee(p, r) for r in refs) for p in parts)
    target = {"name": follow.get("name"), "judge_id": (follow.get("judge_ids") or [None])[0]}
    return any(same_referee(target, r) for r in refs)


def follow_key(kind: str, judge_ids: Sequence[Any], names: Sequence[Any]) -> str:
    keys = sorted(referee_key(n, j) for n, j in zip(names, list(judge_ids) + [None] * len(names)))
    return "|".join(keys)


def follow_shape(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {"id": row["id"], "kind": row.get("kind"), "name": row.get("name"),
            "judge_ids": [R.s(x) for x in R.json_value(row.get("judge_ids"), []) if R.s(x)],
            "names": [R.s(x) for x in R.json_value(row.get("names"), [])], "created_at": row.get("created_at")}


# ─── Rozmowa o klipie: głosy, półki, oznaczenia ─────────────────────────────


def tally_votes(rows: Iterable[Mapping[str, Any]], me: str) -> Dict[str, Any]:
    counts = {v: 0 for v in VOTES}
    mine = None
    for r in rows:
        vote = R.s(r.get("vote"))
        if vote in counts:
            counts[vote] += 1
            if R.s(r.get("judge_id")) == R.s(me):
                mine = vote
    return {"counts": counts, "total": sum(counts.values()), "mine": mine, "labels": dict(VOTE_LABELS)}


def clean_tags(raw: Any) -> List[Dict[str, Any]]:
    """Oznaczenia sędziów na klipie: nazwisko, rola A/B/?, pozycja (opis ≤ 40)."""
    out: List[Dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, Mapping):
            continue
        name = R.plain(item.get("name"), 80)
        if not name:
            continue
        role = R.s(item.get("role")).upper() or "?"
        if role not in ROLES:
            raise R.RuleError(422, "TAG_ROLE", "Rola sędziego to A, B albo ?.")
        entry = {"name": name, "judge_id": R.s(item.get("judge_id")) or None, "role": role,
                 "position": R.plain(item.get("position"), 40) or None}
        if any(same_referee(entry, e) for e in out):
            continue
        out.append(entry)
    if len(out) > MAX_REFEREE_TAGS:
        raise R.RuleError(422, "TAG_LIMIT", f"Na klipie można oznaczyć najwyżej {MAX_REFEREE_TAGS} sędziów.")
    return out


def feed_state(video_state: Any) -> str:
    """„video" gdy nagranie gotowe, inaczej „waiting" (czeka na nagranie)."""
    return "video" if R.s(video_state).upper() == "READY" else "waiting"


def feed_window(days: int, now: Optional[datetime] = None) -> Tuple[date, date]:
    today = (now or datetime.now(timezone.utc)).date()
    days = max(1, min(int(days or 14), 60))
    return today - timedelta(days=days), today
