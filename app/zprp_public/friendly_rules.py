"""Mecze TOWARZYSKIE z ProEla dla publicznego portalu BAZA pod Ręką - czysta logika, bez bazy.

Decyzja właściciela 06.11.2026: mecz prowadzony na żywo w ProElu, którego ZPRP nie zna
(klucz `M-...` bez IdZawody albo inny zapis bez numerycznego `matchId`; NIE szkoleniowy `T-`),
jest publiczny jako mecz towarzyski. Nie ma go w tabelach ZPRP, więc dostaje własny,
odwracalny identyfikator `tow-<klucz w base64url>` - bez tabeli pośredniej.

Mecze towarzyskie NIE wchodzą do tabel ligowych, rankingów ani statystyk rozgrywek
(`proel_match_key.public_rows_clause` zostaje bez zmian i dalej je odcina).

Prywatność: przebieg i liczniki jak w `proel_live_rules`. Dodatkowo, bo ZPRP nie zna tych
osób, nazwiska zawodników i osób towarzyszących idą z kart protokołu, a obsada
(sędziowie, delegat, sekretarz, mierzący czas) z konfiguracji meczu. Żadnych licencji,
badań, zdjęć ani podpisów.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from app.zprp_public import proel_lineup_rules as PL
from app.zprp_public import proel_live_rules as L

ID_PREFIX = "tow-"
FINISHED = ("finished", "approved")
WARSAW = ZoneInfo("Europe/Warsaw")
COMPETITION_NAME = "Mecz towarzyski"

_ID_RE = re.compile(r"^tow-[A-Za-z0-9_-]{2,400}$")


def friendly_id(key: Any) -> str:
    """Identyfikator portalu dla klucza meczu ProEla (`M-ABC123/EHF/1`, `EHF/1`...)."""
    raw = str(key or "").strip().encode("utf-8")
    return ID_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def key_of_id(match_id: Any) -> str:
    """Klucz ProEla z identyfikatora portalu; pusty napis, gdy to nie jest mecz towarzyski."""
    text = str(match_id or "").strip()
    if not _ID_RE.match(text):
        return ""
    body = text[len(ID_PREFIX):]
    try:
        key = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""
    return key.strip() if friendly_id(key) == text else ""


def is_friendly_id(match_id: Any) -> bool:
    return bool(key_of_id(match_id))


def _cfg(blob: Any) -> Dict[str, Any]:
    if isinstance(blob, dict) and isinstance(blob.get("matchConfig"), dict):
        return blob["matchConfig"]
    return {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def is_friendly_blob(blob: Any) -> bool:
    """Publiczny (nie test, nie szkolenie), bez numerycznego IdZawody, z obiema drużynami."""
    from app.proel_match_key import zprp_id_of

    if not L.is_public_blob(blob):
        return False
    cfg = _cfg(blob)
    if not cfg or zprp_id_of(blob):
        return False
    return bool(_text(cfg.get("hostTeamName")) and _text(cfg.get("guestTeamName")))


def started(status: Any, live_started_at: Any) -> bool:
    """Mecz wystartował w ProElu (albo jest zakończony) - przedmeczowy szkic nie jest publiczny."""
    return status in FINISHED or live_started_at is not None


def played_at(blob: Any, doc_at: Any) -> Optional[datetime]:
    """Początek meczu jako czas lokalny (naiwny, jak `scheduled_at` w ZPRP)."""
    cfg = _cfg(blob)
    extras = cfg.get("extras") if isinstance(cfg.get("extras"), dict) else {}
    day = _text(extras.get("matchDate") or cfg.get("matchDate"))[:10]
    clock = _text(extras.get("matchTime") or cfg.get("matchTime"))[:5]
    if re.match(r"^\d{4}-\d{2}-\d{2}$", day):
        try:
            hh, mm = (int(x) for x in clock.split(":")) if re.match(r"^\d{1,2}:\d{2}$", clock) else (0, 0)
            return datetime.fromisoformat(day).replace(hour=hh, minute=mm)
        except ValueError:
            pass
    if isinstance(doc_at, datetime):
        aware = doc_at if doc_at.tzinfo else doc_at.replace(tzinfo=WARSAW)
        return aware.astimezone(WARSAW).replace(tzinfo=None)
    return None


def _split_name(full: str) -> Dict[str, Optional[str]]:
    """Karta ProEl trzyma „Nazwisko Imię": pierwsze słowo to nazwisko."""
    parts = full.split()
    if not parts:
        return {"first_name": None, "last_name": None}
    return {"last_name": parts[0], "first_name": " ".join(parts[1:]) or None}


def officials(blob: Any) -> List[Dict[str, Any]]:
    """Obsada z konfiguracji meczu, w stałej kolejności ról; puste pola znikają."""
    from app.zprp_public.referee_placeholder import clean_official

    cfg = _cfg(blob)
    out: List[Dict[str, Any]] = []
    for field, label in (("referee1", "Sędzia"), ("referee2", "Sędzia"), ("delegate", "Delegat"),
                         ("delegate2", "Delegat"), ("secretary", "Sekretarz"), ("timekeeper", "Czas")):
        _rid, name = clean_official(None, _text(cfg.get(field)))
        if name:
            out.append({"role": label, "id": None, "name": name})
    return out


def card(key: str, status: Any, doc_at: Any, blob: Any, live_started_at: Any = None) -> Dict[str, Any]:
    """Karta meczu w kształcie karty ZPRP (`CARD_COLUMNS`) plus znaczniki towarzyskiego."""
    from app.proel_training_key import match_number_from_key

    cfg = _cfg(blob)
    code = match_number_from_key(key)
    done = status in FINISHED
    host, guest = _int(blob.get("scoreHost")), _int(blob.get("scoreGuest"))
    half = blob.get("halfScore") if isinstance(blob.get("halfScore"), dict) else None
    at = played_at(blob, doc_at)
    winner = None
    if done:
        winner = "home" if host > guest else "away" if guest > host else "draw"
    return {
        "match_id": friendly_id(key),
        "season_id": None,
        "competition_id": None,
        "competition_name": COMPETITION_NAME,
        "round_name": None,
        "matchday_name": None,
        "home_team_id": None,
        "away_team_id": None,
        "home_club_id": None,
        "away_club_id": None,
        "home_team_name": _text(cfg.get("hostTeamName")),
        "away_team_name": _text(cfg.get("guestTeamName")),
        "scheduled_at": at,
        "played_at": at if done else None,
        "score_home": host if (done or blob.get("scoreHost") is not None) else None,
        "score_away": guest if (done or blob.get("scoreGuest") is not None) else None,
        "halftime_home": _int(half.get("host")) if half and half.get("host") is not None else None,
        "halftime_away": _int(half.get("guest")) if half and half.get("guest") is not None else None,
        "winner": winner,
        "withdrawn": False,
        "protocol_approved": status == "approved",
        "venue_name": _text(cfg.get("venueAddress")) or None,
        "venue_city": _text(cfg.get("venueCity")) or None,
        "match_code": code,
        "shootout_home": None,
        "shootout_away": None,
        "walkover_team_id": None,
        "home_logo_url": None,
        "away_logo_url": None,
        "status": "finished" if done else "scheduled",
        "friendly": True,
        "match_kind": "friendly",
    }


def _int(value: Any) -> int:
    return L._int(value)


def lineups(blob: Any) -> Dict[str, Any]:
    """Składy i osoby towarzyszące obu stron z protokołu (home = gospodarz protokołu)."""
    stats = PL.protocol_stats(blob, True)
    roster = PL.proel_roster(blob, True)
    people: Dict[str, List[Dict[str, Any]]] = {"home": [], "away": []}
    staff: List[Dict[str, Any]] = []
    for side in PL.SIDES:
        rows = PL.build_players(roster[side]["players"], stats[side]["players"], side, None, {}, {}, [], None,
                                roster[side].get("struck"))
        names = {e["number"]: e.get("check") for e in roster[side]["players"]}
        for nr, e in (roster[side].get("struck") or {}).items():
            names.setdefault(nr, e.get("check"))
        for row in rows:
            full = names.get(_int(row.get("shirt_number")))
            if full:
                row.update(_split_name(full))
                row["name_source"] = "protocol"
            people[side].append(row)
        rows_staff = PL.build_staff(roster[side]["staff"], stats[side]["staff"], side, None, {})
        checks = {e["letter"]: e.get("check") for e in roster[side]["staff"]}
        for row in rows_staff:
            full = checks.get(row.get("letter"))
            if full:
                row.update(_split_name(full))
            staff.append(row)
    sums = {s: sum(_int(p.get("goals")) for p in people[s]) for s in PL.SIDES}
    return {"lineups": people, "staff": staff, "sums": sums}
