"""Tabela ligi po wyniku skróconym: wstępne przeliczenie, odświeżanie w tle i na żądanie.

Rdzeń reguł jest w `standings_provisional.py` (czysty, testowany bez bazy).
Tu jest tylko klej: baza, pobieranie z ZPRP i harmonogram. Kontrakt:
docs/tabela-po-wyniku-skroconym.md.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import Table, and_, delete, func, or_, select, update

from app import standings_provisional as SP
from app.time_pl import warsaw_now

log = logging.getLogger(__name__)

GATE = SP.RefreshGate()
_tasks: set[asyncio.Task] = set()
_last_purge = 0.0
_FETCH_TIMEOUT = float(os.getenv("ZPRP_TABLE_REFRESH_TIMEOUT", "25"))


def _tables():
    """(database, matches, standings, provisional) z BIEŻĄCEGO `app.db`.

    Czytane przy każdym wywołaniu: testy hurtowni podmieniają `app.db` atrapą, a atrapa
    nie ma tabeli nakładek - wtedy `provisional` to None i nakładki po prostu nie ma.
    """
    import importlib

    mod = importlib.import_module("app.db")
    extra = getattr(mod, "zprp_public_provisional_results", None)
    return mod.database, mod.zprp_public_matches, mod.zprp_public_standings, extra if isinstance(extra, Table) else None


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _invalidate_caches() -> None:
    try:
        from app.zprp_public import enrich, portal

        portal.invalidate_caches()
        enrich.invalidate()
    except Exception:  # pragma: no cover - cache to tylko przyspieszenie
        log.exception("[standings] invalidate_caches")


# ---------------------------------------------------------------------------
# Odczyt: nakładka na tabelę
# ---------------------------------------------------------------------------


async def _overlays_for(competition_ids: list[str]) -> list[dict]:
    database, M, S, P = _tables()
    if not competition_ids or P is None:
        return []
    found = await database.fetch_all(select(P).where(P.c.competition_id.in_(competition_ids)).order_by(P.c.created_at))
    return [dict(r) for r in found]


def _group_key(row: dict) -> tuple[str, str, str]:
    return (str(row["competition_id"]), str(row.get("table_id") or ""), str(row.get("group_id") or ""))


async def apply_provisional(items: list[dict]) -> bool:
    """Nakłada wstępne wyniki na wiersze tabel (zmienia `items` w miejscu).

    Wiersze mogą być częścią tabeli (np. tylko własne drużyny z overview) - pełną
    grupę do ustalenia miejsc czytamy z bazy. Zwraca True, gdy coś nałożono.
    Każdy dotknięty wiersz dostaje `provisional: True`.
    """
    database, M, S, P = _tables()
    comps = sorted({str(i["competition_id"]) for i in items if i.get("competition_id")})
    overlays = await _overlays_for(comps)
    if not overlays:
        return False
    now = _utc()
    applied_any = False
    for cid in sorted({o["competition_id"] for o in overlays}):
        official = [dict(r) for r in await database.fetch_all(select(S).where(S.c.competition_id == cid))]
        groups: dict[tuple[str, str, str], list[dict]] = {}
        for r in official:
            groups.setdefault(_group_key(r), []).append(r)
        per_group: dict[tuple[str, str, str], list[dict]] = {}
        for ov in (o for o in overlays if o["competition_id"] == cid):
            for key, rows in groups.items():
                if any(str(r["team_id"]) == str(ov["home_team_id"]) for r in rows):
                    per_group.setdefault(key, []).append(ov)
                    break
        for key, ovs in per_group.items():
            rows = groups[key]
            ids = {str(r["team_id"]) for r in rows}
            found = await database.fetch_all(
                select(M.c.match_id, M.c.home_team_id, M.c.away_team_id, M.c.score_home, M.c.score_away,
                       M.c.shootout_home, M.c.shootout_away)
                .where(and_(M.c.competition_id == cid, M.c.home_team_id.in_(ids), M.c.away_team_id.in_(ids)))
            )
            ranked, applied = SP.provisional_group(rows, [dict(m) for m in found], ovs, now)
            if not applied:
                continue
            applied_any = True
            by_team = {str(r["team_id"]): r for r in ranked}
            for item in items:
                if _group_key(item) != key or str(item.get("team_id")) not in by_team:
                    continue
                src = by_team[str(item["team_id"])]
                for field in ("position", "matches", "wins", "draws", "losses", "goals_for",
                              "goals_against", "goal_difference", "points"):
                    if field in item or field == "position":
                        item[field] = src.get(field)
                item["provisional"] = True
    return applied_any


async def competition_state(competition_id: str) -> dict[str, Any]:
    """Świeżość tabeli ligi: kiedy pobrana z ZPRP i czy leży na niej wstępny wynik."""
    database, M, S, P = _tables()
    fetched = await database.fetch_val(select(func.max(S.c.fetched_at)).where(S.c.competition_id == competition_id))
    overlays = await _overlays_for([competition_id])
    provisional = False
    if overlays:
        rows = {str(r["team_id"]): dict(r) for r in await database.fetch_all(select(S).where(S.c.competition_id == competition_id))}
        provisional = any(SP.overlay_active(o, rows, _utc()) for o in overlays)
    return {"fetched_at": fetched.isoformat() if isinstance(fetched, datetime) else fetched, "provisional": provisional}


# ---------------------------------------------------------------------------
# Zapis: wynik skrócony -> nakładka + pobrania w tle
# ---------------------------------------------------------------------------


async def record_short_result(match_id: str, fields: dict[str, str]) -> dict[str, Any]:
    """Wstępna tabela z wpisanego wyniku + harmonogram pobrań oficjalnych. Nigdy nie rzuca."""
    try:
        return await _record_short_result(str(match_id), fields)
    except Exception as exc:
        log.exception("[standings] wynik skrócony %s", match_id)
        return {"provisional": False, "reason": "error", "message": str(exc)[:200]}


async def _record_short_result(match_id: str, fields: dict[str, str]) -> dict[str, Any]:
    database, M, S, P = _tables()
    result = SP.parse_short_result(fields)
    if result is None:
        return {"provisional": False, "reason": "no-score"}
    match = await database.fetch_one(select(M).where(M.c.match_id == match_id))
    if not match or not match["competition_id"] or not match["home_team_id"] or not match["away_team_id"]:
        # Mecz spoza naszej hurtowni: nie ma tabeli do przeliczenia.
        return {"provisional": False, "reason": "match-unknown"}
    cid = str(match["competition_id"])
    home_id, away_id = str(match["home_team_id"]), str(match["away_team_id"])

    official = {str(r["team_id"]): dict(r) for r in await database.fetch_all(select(S).where(S.c.competition_id == cid))}
    _spawn(_follow_up(match_id, cid))
    if home_id not in official or away_id not in official:
        return {"provisional": False, "reason": "not-in-table", "competition_id": cid, "refresh": True}

    prev: Optional[tuple[int, int]] = None
    if match["score_home"] is not None and match["score_away"] is not None:
        if (int(match["score_home"]), int(match["score_away"])) == (result["home"], result["away"]):
            return {"provisional": False, "reason": "unchanged", "competition_id": cid, "refresh": True}
        # Poprzedni wynik: liczony oficjalnie tylko wtedy, gdy tabela ma tyle meczów, ile znamy z wynikiem.
        scored = await database.fetch_all(
            select(M.c.home_team_id, M.c.away_team_id).where(
                and_(M.c.competition_id == cid, M.c.score_home.is_not(None), M.c.score_away.is_not(None),
                     or_(M.c.home_team_id.in_([home_id, away_id]), M.c.away_team_id.in_([home_id, away_id])))
            )
        )
        counted = all(
            int(official[t]["matches"] or 0) >= sum(1 for m in scored if t in (str(m["home_team_id"]), str(m["away_team_id"])))
            for t in (home_id, away_id)
        )
        if counted:
            prev = (int(match["score_home"]), int(match["score_away"]))

    now = _utc()
    values = {
        "competition_id": cid,
        "home_team_id": home_id,
        "away_team_id": away_id,
        "score_home": result["home"],
        "score_away": result["away"],
        "shootout_home": result["shootout_home"],
        "shootout_away": result["shootout_away"],
        "prev_home": prev[0] if prev else None,
        "prev_away": prev[1] if prev else None,
        "base_json": json.dumps(SP.signature(official, home_id, away_id)),
        "created_at": now,
        "updated_at": now,
    }
    await database.execute(delete(P).where(P.c.match_id == match_id))
    await database.execute(P.insert().values(match_id=match_id, **values))
    score_update: dict[str, Any] = {"score_home": result["home"], "score_away": result["away"]}
    if result["shootout_home"] is not None and result["shootout_away"] is not None:
        score_update.update(shootout_home=result["shootout_home"], shootout_away=result["shootout_away"])
    await database.execute(update(M).where(M.c.match_id == match_id).values(**score_update))
    _invalidate_caches()
    return {
        "provisional": True,
        "competition_id": cid,
        "refresh_after_seconds": list(SP.FOLLOW_UP_DELAYS),
    }


def _spawn(coro) -> None:
    task = asyncio.get_running_loop().create_task(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def _follow_up(match_id: str, competition_id: str) -> None:
    """Pobrania oficjalnej tabeli ok. 1, 5 i 15 min po wpisie; kończy, gdy ZPRP już przeliczyło."""
    database, M, S, P = _tables()
    waited = 0.0
    for delay in SP.FOLLOW_UP_DELAYS:
        await asyncio.sleep(delay - waited)
        waited = delay
        try:
            await refresh_competition(competition_id, min_interval=0)
            ov = await database.fetch_one(select(P).where(P.c.match_id == match_id))
            if ov is None:
                return
            rows = {str(r["team_id"]): dict(r) for r in await database.fetch_all(select(S).where(S.c.competition_id == competition_id))}
            if not SP.overlay_active(dict(ov), rows, _utc()):
                return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("[standings] pobranie po wyniku %s", match_id)


# ---------------------------------------------------------------------------
# Pobieranie oficjalnych danych
# ---------------------------------------------------------------------------


async def _fetch_official(competition_id: str) -> None:
    database, M, S, P = _tables()
    from app.zprp_public import ondemand
    from app.zprp_public.client import rows as payload_rows
    from app.zprp_public.sync import Counters, _store_match, _sync_competition_tables

    client = ondemand._get_client()
    counters = Counters()
    async with ondemand._slots:
        await _sync_competition_tables(client, competition_id, counters)
        # Mecze kolejek z okolic dzisiaj (i meczu z wpisanym wynikiem): jedno żądanie na kolejkę.
        local = warsaw_now()
        ctx_rows = await database.fetch_all(
            select(M.c.matchday_id, M.c.season_id, M.c.competition_name, M.c.round_id, M.c.round_name,
                   M.c.matchday_name)
            .where(and_(M.c.competition_id == competition_id, M.c.matchday_id.is_not(None),
                        M.c.scheduled_at >= local - timedelta(days=2), M.c.scheduled_at <= local + timedelta(days=1)))
            .distinct()
            .limit(3)
        )
        for ctx in ctx_rows:
            payload = await client.get(f"pokaz_mecze.php?Kolejka={ctx['matchday_id']}")
            for item in payload_rows(payload):
                await _store_match(
                    item, counters,
                    season_id=ctx["season_id"], competition_id=competition_id,
                    competition_name=ctx["competition_name"], round_id=ctx["round_id"],
                    round_name=ctx["round_name"], matchday_id=ctx["matchday_id"],
                    matchday_name=ctx["matchday_name"],
                )
    await _reapply_scores(competition_id)
    _invalidate_caches()


async def _reapply_scores(competition_id: str) -> None:
    """ZPRP bywa jeszcze bez wyniku: dopóki nakładka obowiązuje, mecz zachowuje wpisany wynik."""
    database, M, S, P = _tables()
    overlays = await _overlays_for([competition_id])
    if not overlays:
        return
    rows = {str(r["team_id"]): dict(r) for r in await database.fetch_all(select(S).where(S.c.competition_id == competition_id))}
    for ov in overlays:
        if not SP.overlay_active(ov, rows, _utc()):
            continue
        await database.execute(
            update(M)
            .where(and_(M.c.match_id == ov["match_id"], or_(M.c.score_home.is_(None), M.c.score_away.is_(None))))
            .values(score_home=ov["score_home"], score_away=ov["score_away"])
        )


async def refresh_competition(competition_id: str, min_interval: float = SP.ON_DEMAND_INTERVAL) -> dict[str, Any]:
    """Odświeża tabelę i mecze ligi, najwyżej raz na `min_interval` s; reszta dostaje stan z bazy.

    Nigdy nie rzuca. `refreshed`: pobraliśmy teraz z ZPRP; `throttled`: ktoś pobrał przed chwilą
    (albo właśnie pobiera) i dostajemy jego wynik; `error`: pobranie się nie udało (stan z bazy).
    """
    cid = str(competition_id)

    async def work() -> None:
        await asyncio.wait_for(_fetch_official(cid), timeout=_FETCH_TIMEOUT)

    try:
        gate = await GATE.run(cid, work, min_interval)
    except asyncio.CancelledError:
        raise
    except Exception:  # pragma: no cover - bramka sama łapie błędy pobrania
        log.exception("[standings] odświeżenie %s", cid)
        gate = SP.GateResult(ran=False, throttled=False, error=True)
    if gate.error:
        log.warning("[standings] odświeżenie ligi %s nieudane", cid)
    state = await competition_state(cid)
    return {
        "competition_id": cid,
        "refreshed": gate.ran and not gate.error,
        "throttled": gate.throttled,
        "error": gate.error,
        **state,
    }


async def run_auto_refresh() -> None:
    """Wywoływane co minutę z pętli synchronizacji: ligi dni meczowych co ok. 15 min."""
    database, M, S, P = _tables()
    global _last_purge
    loop_time = asyncio.get_running_loop().time()
    if P is not None and loop_time - _last_purge > 3600:
        _last_purge = loop_time
        await database.execute(delete(P).where(P.c.created_at < _utc() - SP.OVERLAY_TTL))
    local = warsaw_now()
    found = await database.fetch_all(
        select(M.c.competition_id, M.c.scheduled_at)
        .where(and_(M.c.competition_id.is_not(None), M.c.scheduled_at <= local - timedelta(minutes=90),
                    M.c.scheduled_at >= local - timedelta(hours=8)))
        .order_by(M.c.scheduled_at.desc())
    )
    for cid in SP.pick_auto_competitions([dict(r) for r in found], local, GATE.age):
        await refresh_competition(cid, min_interval=SP.AUTO_INTERVAL)
