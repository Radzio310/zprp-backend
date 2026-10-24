"""Wstępne przeliczenie tabeli grupy po wyniku skróconym (czyste reguły, bez bazy i sieci).

Bierzemy OFICJALNE wiersze tabeli ZPRP, dokładamy do nich jeden wpisany wynik
i układamy kolejność od nowa. Kolejność: punkty, potem mecze bezpośrednie
remisujących (punkty, różnica, bramki), potem bilans ogólny i bramki zdobyte.
Gdy nic nie rozstrzyga - drużyny dzielą miejsce (ex aequo: 9, 9, 11), zgodnie
z regułą z `standings.py` / `scheduleUtils.resolveTiedBucket`.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Optional

#: Po tylu godzinach wstępny wynik wygasa nawet gdy ZPRP go nie przeliczyło.
OVERLAY_TTL = timedelta(hours=48)
#: Odświeżenie ligi na żądanie: jedno na tyle sekund, reszta dostaje świeży stan.
ON_DEMAND_INTERVAL = 120.0
#: Auto w dni meczowe: ta sama liga najwyżej raz na tyle sekund.
AUTO_INTERVAL = 900.0
#: Kolejne pobrania po wpisie wyniku (sekundy od wpisu): ok. 1, 5 i 15 minut.
FOLLOW_UP_DELAYS = (60.0, 300.0, 900.0)

_STAT_KEYS = ("matches", "points", "goals_for", "goals_against")


def _int_or_none(value: Any) -> Optional[int]:
    text = str(value if value is not None else "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _i(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def win_points(rows: list[dict]) -> int:
    """Punkty za wygraną w grupie: 3 (Superliga) albo 2 - wnioskujemy z samej tabeli."""
    fit3 = fit2 = 0
    for r in rows:
        w, d, p = _i(r.get("wins")), _i(r.get("draws")), _i(r.get("points"))
        if w <= 0:
            continue
        fit3 += p == 3 * w + d
        fit2 += p == 2 * w + d
    return 2 if fit2 > fit3 else 3


def _points(
    gf: int, ga: int, sh: Optional[int], sa: Optional[int], win_pts: int
) -> tuple[int, int, str, str]:
    """(punkty gospodarza, punkty gościa, kod gospodarza, kod gościa); kod W/D/L."""
    if gf > ga:
        return win_pts, 0, "W", "L"
    if ga > gf:
        return 0, win_pts, "L", "W"
    if win_pts == 3 and sh is not None and sa is not None and sh != sa:
        # Rzuty karne po remisie: 2 pkt zwycięzca, 1 pkt przegrany (jak `match_rules.points_for`).
        return (2, 1, "W", "L") if sh > sa else (1, 2, "L", "W")
    return 1, 1, "D", "D"


def _shift(row: dict, gf: int, ga: int, pts: int, code: str, sign: int) -> None:
    row["matches"] = max(0, _i(row.get("matches")) + sign)
    row["points"] = max(0, _i(row.get("points")) + sign * pts)
    row["goals_for"] = max(0, _i(row.get("goals_for")) + sign * gf)
    row["goals_against"] = max(0, _i(row.get("goals_against")) + sign * ga)
    key = {"W": "wins", "D": "draws", "L": "losses"}[code]
    row[key] = max(0, _i(row.get(key)) + sign)


def apply_result(
    rows: list[dict],
    home_id: str,
    away_id: str,
    home_goals: int,
    away_goals: int,
    *,
    shootout: tuple[Optional[int], Optional[int]] = (None, None),
    previous: Optional[tuple[int, int]] = None,
    previous_shootout: tuple[Optional[int], Optional[int]] = (None, None),
) -> list[dict]:
    """Kopie wierszy z dołożonym wynikiem (i cofniętym `previous`, jeśli był już liczony)."""
    out = [dict(r) for r in rows]
    by_team = {str(r.get("team_id")): r for r in out}
    home, away = by_team.get(str(home_id)), by_team.get(str(away_id))
    if home is None or away is None:
        return out
    wp = win_points(rows)
    if previous is not None:
        ph, pa, ch, ca = _points(previous[0], previous[1], *previous_shootout, wp)
        _shift(home, previous[0], previous[1], ph, ch, -1)
        _shift(away, previous[1], previous[0], pa, ca, -1)
    ph, pa, ch, ca = _points(home_goals, away_goals, *shootout, wp)
    _shift(home, home_goals, away_goals, ph, ch, +1)
    _shift(away, away_goals, home_goals, pa, ca, +1)
    for r in (home, away):
        r["goal_difference"] = _i(r.get("goals_for")) - _i(r.get("goals_against"))
        r["provisional"] = True
    return out


def _head_to_head(team_ids: list[str], matches: list[dict], win_pts: int) -> dict[str, tuple[int, int, int]]:
    """Mini-tabela remisujących z ich meczów bezpośrednich: (punkty, różnica, bramki zdobyte)."""
    ids = set(team_ids)
    table = {t: [0, 0, 0] for t in team_ids}
    for m in matches:
        h, a = str(m.get("home_team_id")), str(m.get("away_team_id"))
        if h not in ids or a not in ids or m.get("score_home") is None or m.get("score_away") is None:
            continue
        gh, ga = _i(m["score_home"]), _i(m["score_away"])
        ph, pa, _, _ = _points(gh, ga, m.get("shootout_home"), m.get("shootout_away"), win_pts)
        table[h][0] += ph
        table[a][0] += pa
        table[h][1] += gh - ga
        table[a][1] += ga - gh
        table[h][2] += gh
        table[a][2] += ga
    return {t: (v[0], v[1], v[2]) for t, v in table.items()}


def rank(rows: list[dict], matches: list[dict]) -> list[dict]:
    """Układa wiersze i nadaje `position` z remisami ex aequo (wspólne miejsce, następne przeskakuje)."""
    wp = win_points(rows)
    buckets: dict[int, list[dict]] = {}
    for r in rows:
        buckets.setdefault(_i(r.get("points")), []).append(r)
    ordered: list[dict] = []
    keys: dict[str, tuple] = {}
    for pts in sorted(buckets, reverse=True):
        group = buckets[pts]
        h2h = _head_to_head([str(r["team_id"]) for r in group], matches, wp) if len(group) > 1 else {}
        for r in group:
            tid = str(r["team_id"])
            gd = _i(r.get("goals_for")) - _i(r.get("goals_against"))
            keys[tid] = (pts, *(h2h.get(tid, (0, 0, 0))), gd, _i(r.get("goals_for")))
        group.sort(key=lambda r: (tuple(-x for x in keys[str(r["team_id"])]), str(r.get("team_name") or "")))
        ordered.extend(group)
    position = 0
    for index, r in enumerate(ordered, start=1):
        if index > 1 and keys[str(r["team_id"])] == keys[str(ordered[index - 2]["team_id"])]:
            r["position"] = position
        else:
            position = index
            r["position"] = position
    return ordered


def signature(rows_by_team: dict[str, dict], home_id: str, away_id: str) -> dict[str, list[int]]:
    """Podpis oficjalnych wierszy obu drużyn - zmiana oznacza, że ZPRP przeliczyło tabelę."""
    out: dict[str, list[int]] = {}
    for t in (str(home_id), str(away_id)):
        row = rows_by_team.get(t)
        out[t] = [_i(row.get(k)) for k in _STAT_KEYS] if row else []
    return out


def overlay_active(
    overlay: dict, rows_by_team: dict[str, dict], now: datetime, ttl: timedelta = OVERLAY_TTL
) -> bool:
    """Czy wstępny wynik nadal obowiązuje (oficjalna tabela go jeszcze nie uwzględniła)."""
    created = overlay.get("created_at")
    if isinstance(created, datetime):
        if created.tzinfo is None and now.tzinfo is not None:
            created = created.replace(tzinfo=now.tzinfo)
        elif created.tzinfo is not None and now.tzinfo is None:
            created = created.replace(tzinfo=None)
        if now - created > ttl:
            return False
    try:
        base = json.loads(overlay.get("base_json") or "{}")
    except ValueError:
        return False
    current = signature(rows_by_team, overlay["home_team_id"], overlay["away_team_id"])
    if not base or any(not v for v in current.values()):
        return False
    return base == current


def provisional_group(
    rows: list[dict], matches: list[dict], overlays: list[dict], now: datetime
) -> tuple[list[dict], bool]:
    """Tabela jednej grupy z aktywnymi nakładkami. Zwraca (wiersze, czy coś nałożono)."""
    by_team = {str(r["team_id"]): r for r in rows}
    current = [dict(r) for r in rows]
    applied = False
    work = [dict(m) for m in matches]
    for ov in overlays:
        if not overlay_active(ov, by_team, now):
            continue
        has_prev = ov.get("prev_home") is not None and ov.get("prev_away") is not None
        current = apply_result(
            current,
            ov["home_team_id"],
            ov["away_team_id"],
            _i(ov["score_home"]),
            _i(ov["score_away"]),
            shootout=(ov.get("shootout_home"), ov.get("shootout_away")),
            previous=(ov["prev_home"], ov["prev_away"]) if has_prev else None,
        )
        applied = True
        score = {
            "score_home": ov["score_home"],
            "score_away": ov["score_away"],
            "shootout_home": ov.get("shootout_home"),
            "shootout_away": ov.get("shootout_away"),
        }
        hit = [m for m in work if str(m.get("match_id")) == str(ov["match_id"])]
        for m in hit:
            m.update(score)
        if not hit:
            work.append(
                {"match_id": ov["match_id"], "home_team_id": ov["home_team_id"],
                 "away_team_id": ov["away_team_id"], **score}
            )
    if not applied:
        return rows, False
    return rank(current, work), True


# ---------------------------------------------------------------------------
# Bramka odświeżeń: jedno pobranie ligi na okno, reszta dostaje świeży stan
# ---------------------------------------------------------------------------


@dataclass
class GateResult:
    ran: bool
    throttled: bool
    error: bool = False


class RefreshGate:
    """Jedno odświeżenie na klucz (liga) w oknie `min_interval`.

    Równoległe wywołania czekają na to samo pobranie (nie robią własnego), a
    wywołania w oknie po udanym pobraniu wracają od razu jako `throttled`.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._done_at: dict[str, float] = {}
        self._inflight: dict[str, asyncio.Future] = {}

    def age(self, key: str) -> Optional[float]:
        t = self._done_at.get(key)
        return None if t is None else self._clock() - t

    async def run(self, key: str, fn: Callable[[], Awaitable[Any]], min_interval: float) -> GateResult:
        pending = self._inflight.get(key)
        if pending is not None:
            try:
                await asyncio.shield(pending)
            except Exception:
                return GateResult(ran=False, throttled=True, error=True)
            return GateResult(ran=False, throttled=True)
        last = self._done_at.get(key)
        if min_interval > 0 and last is not None and self._clock() - last < min_interval:
            return GateResult(ran=False, throttled=True)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._inflight[key] = fut
        try:
            await fn()
        except Exception as exc:
            # Nieudane pobranie nie otwiera okna (kolejna próba wolno), ale czekających uwalniamy.
            self._inflight.pop(key, None)
            fut.set_exception(exc)
            fut.exception()  # odebrany: bez ostrzeżeń asyncio o nieodczytanym wyjątku
            return GateResult(ran=True, throttled=False, error=True)
        except BaseException:
            self._inflight.pop(key, None)
            fut.cancel()
            raise
        self._done_at[key] = self._clock()
        self._inflight.pop(key, None)
        fut.set_result(True)
        if len(self._done_at) > 3000:
            cutoff = self._clock() - 3600
            for k in [k for k, v in self._done_at.items() if v < cutoff]:
                self._done_at.pop(k, None)
        return GateResult(ran=True, throttled=False)


def pick_auto_competitions(
    matches: list[dict],
    local_now: datetime,
    last_age: Callable[[str], Optional[float]],
    *,
    interval: float = AUTO_INTERVAL,
    limit: int = 12,
) -> list[str]:
    """Ligi z dzisiejszym meczem, który zapewne już się skończył (start + 90 min) do 8 h po starcie.

    `matches`: wiersze z `competition_id` i `scheduled_at` (naiwny czas polski).
    Dla każdej ligi odświeżenie co `interval` s (`last_age` = sekundy od ostatniego pobrania).
    """
    out: list[str] = []
    for m in matches:
        cid, when = m.get("competition_id"), m.get("scheduled_at")
        if not cid or not isinstance(when, datetime) or str(cid) in out:
            continue
        elapsed = local_now - when
        if not (timedelta(minutes=90) <= elapsed <= timedelta(hours=8)):
            continue
        age = last_age(str(cid))
        if age is not None and age < interval:
            continue
        out.append(str(cid))
        if len(out) >= limit:
            break
    return out


def parse_short_result(fields: dict[str, str]) -> Optional[dict[str, Optional[int]]]:
    """Wynik końcowy i karne z pól summary.php; None, gdy w żądaniu nie ma kompletu bramek."""
    home, away = _int_or_none(fields.get("wynik_gosp_full")), _int_or_none(fields.get("wynik_gosc_full"))
    if home is None or away is None:
        return None
    return {
        "home": home,
        "away": away,
        "shootout_home": _int_or_none(fields.get("dogrywka_karne_gosp")),
        "shootout_away": _int_or_none(fields.get("dogrywka_karne_gosc")),
    }
