"""Czyste reguły „runda 3" portalu Pod Ręką (bez bazy i sieci).

Rzuty karne meczu, zwycięzca, numer meczu, tabela liczona z wyników, serie,
rekordy, agregacja strzelców, plik .ics i walidacja adresów załączników.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from app.time_pl import has_kickoff_time, to_warsaw_naive, warsaw_to_utc
from app.zprp_public.round_rules import card_matchday_label

WARSAW = ZoneInfo("Europe/Warsaw")

# ---------------------------------------------------------------------------
# Rzuty karne i zwycięzca
# ---------------------------------------------------------------------------

SHOOTOUT_HOME_KEY = "dogrywka_karne_gosp"
SHOOTOUT_AWAY_KEY = "dogrywka_karne_gosc"


def _int(value: Any) -> Optional[int]:
    try:
        text = str(value).strip()
        if not text or text.lower() == "none":
            return None
        return int(float(text.replace(",", ".")))
    except (TypeError, ValueError):
        return None


def _header(source: Any) -> dict:
    """Nagłówek meczu z surowego payloadu (lista, `{"0": [..]}`, `{"0": {..}}`)."""
    current = source
    for _ in range(4):
        if isinstance(current, dict):
            if SHOOTOUT_HOME_KEY in current or "Id" in current or "wynik_gosp_full" in current:
                return current
            for key in ("0", "value", "data", "matches"):
                if key in current:
                    current = current[key]
                    break
            else:
                return {}
        elif isinstance(current, list) and current:
            current = current[0]
        else:
            return {}
    return current if isinstance(current, dict) else {}


def parse_shootout(source: Any) -> tuple[Optional[int], Optional[int]]:
    """Wynik rzutów karnych z surowego payloadu ZPRP; (None, None) gdy go nie było.

    Para 0:0 oznacza „nie rozgrywano" (źródło wypełnia pola zerami), więc
    traktujemy ją jak brak serii.
    """
    header = _header(source)
    home, away = _int(header.get(SHOOTOUT_HOME_KEY)), _int(header.get(SHOOTOUT_AWAY_KEY))
    if home is None or away is None or (home == 0 and away == 0):
        return None, None
    return home, away


def outcome(match: dict) -> tuple[Optional[str], str]:
    """(winner_side, decided_by) z pól meczu.

    decided_by: ``walkover`` (walkower/wycofanie), ``shootout`` (rzuty karne
    po remisie w czasie gry), inaczej ``regular``. winner_side: ``home``/``away``
    albo ``None`` (remis, mecz nierozegrany).
    """
    sh, sa = match.get("shootout_home"), match.get("shootout_away")
    home, away = match.get("score_home"), match.get("score_away")
    upstream = str(match.get("winner") or "").strip()
    if match.get("walkover_team_id"):
        side = {"1": "home", "2": "away"}.get(upstream)
        if side is None and home is not None and away is not None and home != away:
            side = "home" if home > away else "away"
        return side, "walkover"
    if sh is not None and sa is not None and sh != sa and (home is None or away is None or home == away):
        return ("home" if sh > sa else "away"), "shootout"
    if home is not None and away is not None:
        if home > away:
            return "home", "regular"
        if away > home:
            return "away", "regular"
        return None, "regular"
    return None, "regular"


def full_match_code(match_code: Any, competition_code: Any = None) -> Optional[str]:
    """Pełny numer meczu, np. ``S/DzK/1``. Kod bez ukośnika dopełniamy kodem rozgrywek."""
    code = str(match_code or "").strip()
    comp = str(competition_code or "").strip()
    if not code:
        return None
    if "/" in code or not comp or code.startswith(comp):
        return code
    return f"{comp}/{code}"


def current_season_id(seasons: Iterable[dict]) -> Optional[str]:
    """Ta sama reguła co `_resolve_season`: aktywny, potem najnowszy."""
    ordered = sorted(
        seasons, key=lambda s: (bool(s.get("active")), s.get("start_year") or 0), reverse=True
    )
    return ordered[0]["season_id"] if ordered else None


def apply_match_extras(
    item: dict,
    seasons: dict[str, dict],
    current_id: Optional[str],
    competition_codes: dict[str, str],
) -> dict:
    """Dokłada do karty meczu pola kontraktu rundy 3 (idempotentnie)."""
    side, decided = outcome(item)
    season = seasons.get(item.get("season_id") or "") or {}
    item["winner_side"] = side
    item["decided_by"] = decided
    item["match_code_full"] = full_match_code(
        item.get("match_code"), competition_codes.get(item.get("competition_id") or "")
    )
    item["season_name"] = season.get("name")
    item["is_current_season"] = bool(current_id and item.get("season_id") == current_id)
    item.setdefault("shootout_home", None)
    item.setdefault("shootout_away", None)
    if "scheduled_at" in item:
        # 00:00 / sam dzień ze ZPRP = godzina do ustalenia (klient: nie "00:00", nie start o północy).
        item["kickoff_time_known"] = has_kickoff_time(item.get("scheduled_at"))
    if "matchday_name" in item:
        # „Seria 8" (Superliga) i „8. kolejka" -> „Kolejka 8"; surowe matchday_name zostaje.
        item["matchday_label"] = card_matchday_label(item.get("matchday_name"))
    return item


# ---------------------------------------------------------------------------
# Obsada sztabu: litery A-E i kartki
# ---------------------------------------------------------------------------

_STAFF_LETTER = re.compile(r"(?:^|[\s(\-])([A-E])(?:$|[\s).:\-])", re.I)


def penalty_fields(warnings: Any, two_minutes: Any, disqualifications: Any, direct_red: Any) -> dict:
    """Pola kar z czasami. Upstream (pokaz_mecze_szczegoly.php) podaje tylko LICZNIKI,
    bez minut, więc czasy są zawsze null; liczniki zostają w polach *_count istniejących
    kolumn. `extra_penalty` = kara dodatkowa (pole upstream `kd`)."""
    return {
        "warning_time": None,
        "two_minutes_times": [],
        "disqualification_time": None,
        "extra_penalty": (_int(direct_red) or 0) > 0,
        "extra_penalty_time": None,
    }


def staff_view(row: dict) -> dict:
    """Osoba towarzysząca z kartkami (klucze jak u zawodników w payloadzie)."""
    src = row.get("source_json") if isinstance(row.get("source_json"), dict) else {}
    letter = None
    for candidate in (row.get("role"), row.get("function"), src.get("rola"), src.get("funkcja")):
        text = str(candidate or "").strip()
        if len(text) == 1 and text.upper() in "ABCDE":
            letter = text.upper()
            break
        found = _STAFF_LETTER.search(text)
        if found:
            letter = found.group(1).upper()
            break
    out = {k: v for k, v in row.items() if k != "source_json"}
    out["letter"] = letter
    out["warnings"] = _int(src.get("upomnienie")) or 0
    out["two_minutes"] = _int(src.get("2minuty")) or 0
    out["disqualifications"] = _int(src.get("dyskwalifikacja")) or 0
    out["direct_red_cards"] = _int(src.get("kd")) or 0
    out["penalty_attempts"] = 0
    out["penalty_goals"] = 0
    out.update(penalty_fields(out["warnings"], out["two_minutes"], out["disqualifications"], out["direct_red_cards"]))
    return out


# ---------------------------------------------------------------------------
# Tabela liczona z wyników, serie
# ---------------------------------------------------------------------------


def points_for(side_won: Optional[bool], decided_by: str) -> int:
    """Punkty Superligi 3/2/1/0: wygrana w regulaminowym czasie (i walkower) 3,
    wygrana w karnych 2, porażka w karnych 1, porażka 0; remis bez karnych 1."""
    if side_won is None:
        return 1
    if decided_by == "shootout":
        return 2 if side_won else 1
    return 3 if side_won else 0


def simulate_table(matches: Iterable[dict]) -> list[dict]:
    """Tabela z rozegranych meczów: punkty, różnica bramek, bramki zdobyte."""
    rows: dict[str, dict] = {}

    def row(tid: str, name: Any, club: Any) -> dict:
        return rows.setdefault(
            tid, {"team_id": tid, "team_name": name, "club_id": club, "matches": 0, "points": 0, "goals_for": 0, "goals_against": 0}
        )

    for m in matches:
        h, a = m.get("score_home"), m.get("score_away")
        ht, at = m.get("home_team_id"), m.get("away_team_id")
        if h is None or a is None or not ht or not at or m.get("withdrawn") and not m.get("walkover_team_id"):
            continue
        side, decided = outcome(m)
        hr, ar = row(ht, m.get("home_team_name"), m.get("home_club_id")), row(at, m.get("away_team_name"), m.get("away_club_id"))
        hr["matches"] += 1
        ar["matches"] += 1
        hr["goals_for"] += h
        hr["goals_against"] += a
        ar["goals_for"] += a
        ar["goals_against"] += h
        hr["points"] += points_for(None if side is None else side == "home", decided)
        ar["points"] += points_for(None if side is None else side == "away", decided)
    ordered = sorted(
        rows.values(),
        key=lambda r: (-r["points"], -(r["goals_for"] - r["goals_against"]), -r["goals_for"], str(r["team_name"] or "")),
    )
    for pos, r in enumerate(ordered, start=1):
        r["position"] = pos
        r["goal_difference"] = r["goals_for"] - r["goals_against"]
    return ordered


def team_result(match: dict, team_id: str) -> Optional[str]:
    """``W``/``D``/``L`` z punktu widzenia drużyny albo None (nierozegrany)."""
    if match.get("score_home") is None or match.get("score_away") is None:
        return None
    mine = "home" if match.get("home_team_id") == team_id else "away"
    side, _ = outcome(match)
    if side is None:
        return "D"
    return "W" if side == mine else "L"


# ---------------------------------------------------------------------------
# Bilans w czterech stanach: piłka ręczna nie zna remisu
# ---------------------------------------------------------------------------

#: Kody wyniku z punktu widzenia drużyny: zwycięstwo, zwycięstwo po rzutach
#: karnych, porażka po rzutach karnych, porażka. Walkower liczy się jak W/L.
RESULT_CODES = ("W", "WK", "LK", "L")
#: Punkty za wynik (system 3/2/1/0).
RESULT_POINTS = {"W": 3, "WK": 2, "LK": 1, "L": 0}


def side_result(match: dict, side: str) -> Optional[str]:
    """``W``/``WK``/``LK``/``L`` dla strony ``home``/``away`` albo None.

    None: mecz bez wyniku albo równy wynik bez serii karnych w danych (źródło
    nie podało rozstrzygnięcia - nie zgadujemy i nie nazywamy tego remisem).
    """
    side_won, decided = outcome(match)
    if side_won is None:
        return None
    if decided != "walkover" and (match.get("score_home") is None or match.get("score_away") is None):
        return None
    won = side_won == side
    if decided == "shootout":
        return "WK" if won else "LK"
    return "W" if won else "L"


def team_result_detail(match: dict, team_id: str) -> Optional[str]:
    """Jak :func:`side_result`, ale strona z ``team_id`` (gospodarz/gość)."""
    if match.get("home_team_id") == team_id:
        return side_result(match, "home")
    if match.get("away_team_id") == team_id:
        return side_result(match, "away")
    return None


def empty_record() -> dict[str, int]:
    return {"w": 0, "wk": 0, "lk": 0, "l": 0}


def tally_results(results: Iterable[Optional[str]]) -> dict[str, int]:
    """``{"w", "wk", "lk", "l"}`` z ciągu kodów (None pomijane)."""
    rec = empty_record()
    for r in results:
        if r in RESULT_POINTS:
            rec[r.lower()] += 1
    return rec


def record_points(rec: dict) -> int:
    """Punkty 3/2/1/0 z bilansu ``{"w", "wk", "lk", "l"}``."""
    return 3 * int(rec.get("w") or 0) + 2 * int(rec.get("wk") or 0) + int(rec.get("lk") or 0)


def basic_result(code: Optional[str]) -> Optional[str]:
    """Stary kod W/L z nowego (karne to też zwycięstwo/porażka)."""
    return {"W": "W", "WK": "W", "LK": "L", "L": "L"}.get(code or "")


# --- Tabela ZPRP: rozbicie zwycięstw i porażek po karnych ------------------

def _fold_key(key: Any) -> str:
    base = unicodedata.normalize("NFKD", str(key or "").lower().replace("ł", "l"))
    return re.sub(r"[^a-z0-9]+", "", "".join(c for c in base if not unicodedata.combining(c)))


def explicit_shootout_columns(source: Any) -> Optional[tuple[int, int]]:
    """(zwycięstwa po karnych, porażki po karnych) z wiersza pokaz_tabela.php,
    jeśli źródło ma takie kolumny (np. ``ZwyciestwaKarne``/``PrzegraneKarne``).
    Bramki z karnych (``BramkiKarne``) się nie liczą."""
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except ValueError:
            return None
    if not isinstance(source, dict):
        return None
    wins = losses = None
    for key, value in source.items():
        k = _fold_key(key)
        if "bram" in k or "gol" in k or not any(x in k for x in ("karn", "shootout", "penalt")):
            continue
        n = _int(value)
        if n is None:
            continue
        if any(x in k for x in ("zw", "wyg", "win")):
            wins = n
        elif any(x in k for x in ("prz", "por", "los")):
            losses = n
    return (wins, losses) if wins is not None and losses is not None else None


def _split_standing(wins: int, draws: int, losses: int, matches: int, wk: int, lk: int) -> Optional[dict[str, int]]:
    """Dopasowuje (wk, lk) do kolumn W/D/L tabeli. Źródło trzyma mecze z karnymi
    albo w „Remisach" (D = wk + lk), albo wlicza je do zwycięstw/porażek."""
    if wk < 0 or lk < 0:
        return None
    if draws > 0:
        return {"w": wins, "wk": wk, "lk": lk, "l": losses} if wk + lk == draws else None
    if (wk or lk) and matches and wins + losses + wk + lk == matches:
        return {"w": wins, "wk": wk, "lk": lk, "l": losses}
    if wins >= wk and losses >= lk:
        return {"w": wins - wk, "wk": wk, "lk": lk, "l": losses - lk}
    return None


def standing_record(row: dict, counted: Optional[dict] = None) -> Optional[dict[str, Any]]:
    """Bilans Z/Zk/Pk/P wiersza tabeli ZPRP: ``{"w", "wk", "lk", "l", "source"}``.

    Kolejność źródeł: kolumny karnych w samym wierszu (``extra_json``) →
    mecze drużyny w tych rozgrywkach (``counted``: ``{"played", "w", "wk", "lk", "l"}``)
    → punkty 3/2/1/0 (gdy „Remisy" > 0, rozkład z punktów jest jednoznaczny).
    None: tabela ma „Remisy", a podziału nie da się ustalić.
    """
    wins, draws, losses = (int(row.get(k) or 0) for k in ("wins", "draws", "losses"))
    matches, points = int(row.get("matches") or 0), row.get("points")
    explicit = explicit_shootout_columns(row.get("extra_json"))
    if explicit:
        hit = _split_standing(wins, draws, losses, matches, *explicit)
        if hit:
            return {**hit, "source": "zprp"}
    if counted:
        hit = _split_standing(wins, draws, losses, matches, int(counted.get("wk") or 0), int(counted.get("lk") or 0))
        if hit:
            return {**hit, "source": "matches"}
        if matches and int(counted.get("played") or 0) == matches:
            return {**{k: int(counted.get(k) or 0) for k in ("w", "wk", "lk", "l")}, "source": "matches"}
    if draws > 0:
        if points is not None:
            wk = int(points) - 3 * wins - draws
            if 0 <= wk <= draws:
                return {"w": wins, "wk": wk, "lk": draws - wk, "l": losses, "source": "points"}
        return None
    return {"w": wins, "wk": 0, "lk": 0, "l": losses, "source": "zprp"}


def count_team_results(matches: Iterable[dict]) -> dict[str, dict]:
    """Bilans każdej drużyny z listy meczów: ``{team_id: {"played", "w", "wk", "lk", "l"}}``."""
    out: dict[str, dict] = {}
    for m in matches:
        if m.get("withdrawn") and not m.get("walkover_team_id"):
            continue  # jak w simulate_table: wycofanie bez walkowera nie wchodzi do tabeli
        for side in ("home", "away"):
            tid = m.get(f"{side}_team_id")
            code = side_result(m, side)
            if not tid or code is None:
                continue
            rec = out.setdefault(tid, {"played": 0, **empty_record()})
            rec["played"] += 1
            rec[code.lower()] += 1
    return out


def streaks(results: list[str]) -> dict[str, Any]:
    """Serie z ciągu wyników W/D/L (chronologicznie)."""
    best_win = best_unbeaten = best_loss = 0
    run_w = run_u = run_l = 0
    for r in results:
        run_w = run_w + 1 if r == "W" else 0
        run_u = run_u + 1 if r in ("W", "D") else 0
        run_l = run_l + 1 if r == "L" else 0
        best_win, best_unbeaten, best_loss = max(best_win, run_w), max(best_unbeaten, run_u), max(best_loss, run_l)
    current = {"type": None, "length": 0}
    if results:
        last = results[-1]
        length = 0
        for r in reversed(results):
            if r != last:
                break
            length += 1
        current = {"type": last, "length": length}
    return {
        "current": current,
        "longest_win": best_win,
        "longest_unbeaten": best_unbeaten,
        "longest_loss": best_loss,
    }


def margin_for(match: dict, team_id: str) -> Optional[int]:
    if match.get("score_home") is None or match.get("score_away") is None:
        return None
    diff = match["score_home"] - match["score_away"]
    return diff if match.get("home_team_id") == team_id else -diff


# ---------------------------------------------------------------------------
# Strzelcy
# ---------------------------------------------------------------------------

SCORER_SORTS = ("goals", "avg", "pen_acc", "penalties")
#: Progi, żeby jeden rzut karny nie dawał „100% skuteczności" na czele rankingu.
MIN_MATCHES_AVG = 3
MIN_PENALTIES_ACC = 3


def sort_player_competitions(rows: Iterable[dict], current_season_id: Optional[str] = None) -> list[dict]:
    """Rozgrywki zawodnika: bieżący sezon pierwszy, potem nowsze sezony, w sezonie wg goli."""
    items = [dict(r) for r in rows]

    def key(r: dict) -> tuple:
        sid = str(r.get("season_id") or "")
        cur = 0 if current_season_id and sid == str(current_season_id) else 1
        try:
            sn = -int(sid)
        except ValueError:
            sn = 0
        return (cur, sn, -int(r.get("goals") or 0), str(r.get("name") or ""))

    return sorted(items, key=key)


def aggregate_scorers(rows: Iterable[dict], sort: str = "goals", limit: int = 50) -> list[dict]:
    """Łączy wiersze strzelców (zawodnik x rozgrywki x drużyna) w ranking zawodników."""
    by_player: dict[str, dict] = {}
    for r in rows:
        pid = r.get("player_id")
        if not pid:
            continue
        agg = by_player.setdefault(pid, {
            "player_id": pid, "name": f"{r.get('first_name') or ''} {r.get('last_name') or ''}".strip(),
            "team": None, "club_id": r.get("club_id"), "club_logo_url": None,
            "photo_url": r.get("photo_url") or None,
            "matches": 0, "goals": 0, "pen_goals": 0, "pen_attempts": 0, "two_minutes": 0, "warnings": 0, "disq": 0,
            "_best": -1,
        })
        agg["matches"] += int(r.get("matches") or 0)
        agg["goals"] += int(r.get("goals") or 0)
        agg["pen_goals"] += int(r.get("penalty_goals") or 0)
        agg["pen_attempts"] += int(r.get("penalty_attempts") or 0)
        agg["two_minutes"] += int(r.get("two_minutes") or 0)
        agg["warnings"] += int(r.get("warnings") or 0)
        agg["disq"] += int(r.get("disqualifications") or 0)
        if int(r.get("goals") or 0) > agg["_best"]:
            agg["_best"] = int(r.get("goals") or 0)
            agg["team"] = r.get("team_name")
            agg["club_id"] = r.get("club_id")
    items = list(by_player.values())
    for it in items:
        it.pop("_best", None)
        it["avg"] = round(it["goals"] / it["matches"], 2) if it["matches"] else 0.0
        it["pen_acc"] = round(it["pen_goals"] / it["pen_attempts"], 3) if it["pen_attempts"] else None

    if sort == "avg":
        items = [i for i in items if i["matches"] >= MIN_MATCHES_AVG]
        key = lambda i: (-i["avg"], -i["goals"])
        value = lambda i: i["avg"]
    elif sort == "pen_acc":
        items = [i for i in items if i["pen_attempts"] >= MIN_PENALTIES_ACC]
        key = lambda i: (-(i["pen_acc"] or 0), -i["pen_attempts"], -i["goals"])
        value = lambda i: (i["pen_acc"], i["pen_attempts"])
    elif sort == "penalties":
        items = [i for i in items if i["pen_attempts"] > 0]
        key = lambda i: (-i["pen_goals"], -i["pen_attempts"], -i["goals"])
        value = lambda i: (i["pen_goals"], i["pen_attempts"])
    else:
        key = lambda i: (-i["goals"], i["matches"], i["name"])
        value = lambda i: (i["goals"], i["matches"])
    items.sort(key=key)
    rank, prev = 0, object()
    for position, it in enumerate(items, start=1):
        current = value(it)
        if current != prev:
            rank, prev = position, current
        it["rank"] = rank
    return items[:limit]


# ---------------------------------------------------------------------------
# Hale
# ---------------------------------------------------------------------------


def _fold(text: Any) -> str:
    base = unicodedata.normalize("NFKD", str(text or "").lower().replace("ł", "l"))
    return re.sub(r"[^a-z0-9]+", "-", "".join(c for c in base if not unicodedata.combining(c))).strip("-")


def venue_key(name: Any, city: Any) -> str:
    """Stabilny klucz hali z nazwy i miasta (bez kodu pocztowego)."""
    city_clean = re.sub(r"^\d{2}\s*-\s*\d{3}[\s,]*", "", str(city or "").strip())
    return f"{_fold(name)}--{_fold(city_clean)}".strip("-")


# ---------------------------------------------------------------------------
# Kalendarz .ics
# ---------------------------------------------------------------------------


def _ics_escape(text: Any) -> str:
    return (
        str(text or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\r", "").replace("\n", "\\n")
    )


def _fold_line(line: str) -> str:
    out, data = [], line.encode("utf-8")
    while len(data) > 74:
        cut = 74
        while cut > 0 and (data[cut] & 0xC0) == 0x80:
            cut -= 1
        out.append(data[:cut].decode("utf-8"))
        data = b" " + data[cut:]
    out.append(data.decode("utf-8"))
    return "\r\n".join(out)


def _utc(local: datetime) -> str:
    return warsaw_to_utc(local).strftime("%Y%m%dT%H%M%SZ")


def build_ics(name: str, matches: Iterable[dict], team_id: str, now: Optional[datetime] = None) -> str:
    """Kalendarz drużyny (subskrypcja): jeden VEVENT na mecz z datą."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//BAZA//Pod Reka//PL", "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
        f"X-WR-CALNAME:{_ics_escape(name)}", "X-WR-TIMEZONE:Europe/Warsaw",
        "REFRESH-INTERVAL;VALUE=DURATION:PT6H", "X-PUBLISHED-TTL:PT6H",
    ]
    for m in matches:
        start = m.get("scheduled_at")
        if not isinstance(start, datetime):
            continue
        home, away = m.get("home_team_name") or "?", m.get("away_team_name") or "?"
        title = f"{home} - {away}"
        if m.get("score_home") is not None and m.get("score_away") is not None:
            title += f" ({m['score_home']}:{m['score_away']})"
        desc = " | ".join(x for x in (m.get("competition_name"), m.get("match_code_full") or m.get("match_code")) if x)
        place = ", ".join(x for x in (m.get("venue_name"), m.get("venue_city")) if x)
        if has_kickoff_time(start):
            when = [f"DTSTART:{_utc(start)}", f"DTEND:{_utc(start + timedelta(hours=2))}"]
        else:
            # Godzina do ustalenia: wydarzenie całodniowe, nie mecz o północy.
            day = start.date()
            when = [f"DTSTART;VALUE=DATE:{day:%Y%m%d}", f"DTEND;VALUE=DATE:{day + timedelta(days=1):%Y%m%d}"]
        lines += [
            "BEGIN:VEVENT",
            f"UID:{m.get('match_id')}-{team_id}@podreka.baza",
            f"DTSTAMP:{stamp}",
            *when,
            f"SUMMARY:{_ics_escape(title)}",
        ]
        if desc:
            lines.append(f"DESCRIPTION:{_ics_escape(desc)}")
        if place:
            lines.append(f"LOCATION:{_ics_escape(place)}")
        lines += ["TRANSP:TRANSPARENT", "END:VEVENT"]
    lines.append("END:VCALENDAR")
    return "\r\n".join(_fold_line(line) for line in lines) + "\r\n"


# ---------------------------------------------------------------------------
# Załączniki: lista i dozwolone adresy proxy
# ---------------------------------------------------------------------------

ATTACHMENT_HOSTS = frozenset({"baza.zprp.pl", "rozgrywki.zprp.pl"})
ATTACHMENT_PATH_PREFIX = "/zawody_zalaczniki/"
ATTACHMENT_MAX_BYTES = 15 * 1024 * 1024
_IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "webp", "heic", "bmp"}


def attachment_kind(is_pdf: bool, filename: str) -> str:
    if is_pdf:
        return "pdf"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return "image" if ext in _IMAGE_EXT else "file"


def is_allowed_attachment_url(url: Any) -> bool:
    """Tylko https, host ZPRP i katalog załączników meczów - nic więcej nie przechodzi przez proxy."""
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in ATTACHMENT_HOSTS or parsed.port not in (None, 443):
        return False
    if parsed.username or parsed.password:
        return False
    path = parsed.path
    return path.startswith(ATTACHMENT_PATH_PREFIX) and ".." not in path and len(path) > len(ATTACHMENT_PATH_PREFIX)


THUMB_SIDE = 480


def make_thumbnail(body: bytes, side: int = THUMB_SIDE) -> bytes | None:
    """Miniatura JPEG (dłuższy bok `side`, q75). None, gdy to nie obraz do odczytu."""
    try:
        import io

        from PIL import Image, ImageOps

        with Image.open(io.BytesIO(body)) as im:
            im.draft("RGB", (side * 2, side * 2))  # JPEG: dekodowanie w zmniejszeniu, mało RAM
            im = ImageOps.exif_transpose(im)
            im.thumbnail((side, side))
            out = io.BytesIO()
            im.convert("RGB").save(out, "JPEG", quality=75, optimize=True)
            return out.getvalue()
    except Exception:  # noqa: BLE001 - uszkodzony/nieobsługiwany plik: front pokaże kartkę
        return None


def attachment_items(attachments: dict[str, dict], hidden_ids: Iterable[str], proxy_url) -> list[dict]:
    """`visible_attachments` + księga ukrytych -> lista kontraktu."""
    hidden = {str(h) for h in hidden_ids}
    out = []
    for att_id, info in attachments.items():
        if att_id in hidden or not is_allowed_attachment_url(info.get("file_url")):
            continue
        kind = attachment_kind(bool(info.get("is_pdf")), info.get("filename") or "")
        url = proxy_url(info["file_url"])
        out.append({
            "id": att_id,
            "name": info.get("label") or info.get("filename"),
            "type": kind,
            "url": url,
            "thumb_url": f"{url}&w={THUMB_SIDE}" if kind == "image" else None,
        })
    return out


def naive_local(value: datetime | None) -> datetime | None:
    """Kolumny czasu meczu są naiwne (czas polski); data z "Z"/offsetem dawała 500 w asyncpg."""
    return to_warsaw_naive(value)


def lineups_swapped(sum_home: int, sum_away: int, score_home: Optional[int], score_away: Optional[int]) -> bool:
    """True, gdy sumy bramek ze składów pasują do wyniku dopiero po zamianie stron.

    Źródło (pokaz_mecze_szczegoly.php) bywa błędne: klucze ``gosp``/``gosc`` ze składami
    są zamienione względem ``ID_zespoly_gosp``/``gosc`` (mecz 212530), a w samych
    zawodnikach nie ma identyfikatora drużyny. Zamieniamy tylko przy jednoznacznej
    zgodności odwrotnej (obie sumy dodatnie, różne, bezpośrednio niezgodne).
    """
    if score_home is None or score_away is None or score_home == score_away:
        return False
    if sum_home <= 0 or sum_away <= 0:
        return False
    return (sum_home, sum_away) == (score_away, score_home)


def goals_known(sum_home: int, sum_away: int, score_home: Optional[int], score_away: Optional[int]) -> bool:
    """False, gdy w składach nie ma bramek, choć wynik je zakłada (źródło ich nie podało)."""
    return (sum_home + sum_away) > 0 or not ((score_home or 0) + (score_away or 0))
