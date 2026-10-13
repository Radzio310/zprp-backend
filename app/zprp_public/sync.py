"""Synchronizacja publicznych danych ZPRP do znormalizowanych tabel BAZY.

Najważniejsza zasada wydajnościowa: szybki cykl nie przechodzi całego drzewa
sezonu. Pobiera jeden zbiorczy terminarz, a szczegóły tylko dla meczów blisko
terminu. Pełny katalog idzie raz na dobę, kluby/składy i archiwalne szczegóły
małymi partiami.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.db import (
    DATABASE_URL,
    database,
    zprp_public_associations,
    zprp_public_club_licenses,
    zprp_public_clubs,
    zprp_public_competitions,
    zprp_public_match_players,
    zprp_public_match_staff,
    zprp_public_matchdays,
    zprp_public_matches,
    zprp_public_players,
    zprp_public_raw_snapshots,
    zprp_public_rounds,
    zprp_public_scorers,
    zprp_public_seasons,
    zprp_public_standings,
    zprp_public_sync_runs,
    zprp_public_team_rosters,
    zprp_public_teams,
)
from app.zprp_public.client import (
    PublicZprpClient,
    birth_year,
    bool_value,
    checksum,
    int_value,
    rows,
    sanitize,
    text_value,
)
from app.zprp_public.store import insert_ignore, now_utc, store_entity, upsert_values

log = logging.getLogger(__name__)
WARSAW = ZoneInfo("Europe/Warsaw")
_run_lock = asyncio.Lock()


def _insert(table, values: dict[str, Any]):
    return sqlite_insert(table).values(**values) if DATABASE_URL.startswith("sqlite") else pg_insert(table).values(**values)


def _dt(value: Any) -> datetime | None:
    raw = text_value(value)
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d.%m.%Y %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw[:19], fmt)
        except ValueError:
            continue
    return None


def _local_now() -> datetime:
    return datetime.now(WARSAW).replace(tzinfo=None)


def _truth(value: Any) -> bool:
    return bool_value(value)


def _first(payload: Any) -> dict[str, Any]:
    candidates = rows(payload)
    return candidates[0] if candidates else {}


async def _chunks(items: list[Any], size: int, worker: Callable[[Any], Awaitable[Any]]) -> list[Any]:
    results: list[Any] = []
    for start in range(0, len(items), size):
        results.extend(await asyncio.gather(*(worker(item) for item in items[start : start + size])))
    return results


class Counters(dict):
    def add(self, key: str, amount: int = 1) -> None:
        self[key] = int(self.get(key, 0)) + amount


async def _claim_run(kind: str, cycle_key: str, season_ids: list[str]) -> int | None:
    now = now_utc()
    stale_before = now - timedelta(minutes=45)
    existing = await database.fetch_one(
        select(
            zprp_public_sync_runs.c.id,
            zprp_public_sync_runs.c.status,
            zprp_public_sync_runs.c.heartbeat_at,
        ).where(zprp_public_sync_runs.c.cycle_key == cycle_key)
    )
    if existing:
        heartbeat = existing["heartbeat_at"]
        if heartbeat and heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        retryable = existing["status"] in {"failed", "cancelled"} or (
            existing["status"] == "running" and heartbeat and heartbeat < stale_before
        )
        if not retryable:
            return None
        await database.execute(
            update(zprp_public_sync_runs)
            .where(zprp_public_sync_runs.c.id == existing["id"])
            .values(
                kind=kind,
                status="running",
                season_ids=season_ids,
                counters={},
                errors=[],
                started_at=now,
                heartbeat_at=now,
                finished_at=None,
            )
        )
        return int(existing["id"])

    statement = _insert(
        zprp_public_sync_runs,
        {
            "kind": kind,
            "cycle_key": cycle_key,
            "status": "running",
            "season_ids": season_ids,
            "counters": {},
            "errors": [],
            "started_at": now,
            "heartbeat_at": now,
        },
    ).on_conflict_do_nothing(index_elements=[zprp_public_sync_runs.c.cycle_key])
    try:
        row = await database.fetch_one(statement.returning(zprp_public_sync_runs.c.id))
        return int(row["id"]) if row else None
    except Exception:
        # Starszy SQLite nie zawsze obsługuje RETURNING. Drugi SELECT zachowuje
        # idempotencję; produkcyjny PostgreSQL korzysta ze ścieżki wyżej.
        try:
            await database.execute(statement)
        except Exception:
            return None
        row = await database.fetch_one(
            select(zprp_public_sync_runs.c.id, zprp_public_sync_runs.c.status).where(
                zprp_public_sync_runs.c.cycle_key == cycle_key
            )
        )
        return int(row["id"]) if row and row["status"] == "running" else None


async def _finish_run(run_id: int, status: str, counters: Counters, errors: list[str]) -> None:
    await database.execute(
        update(zprp_public_sync_runs)
        .where(zprp_public_sync_runs.c.id == run_id)
        .values(
            status=status,
            counters=dict(counters),
            errors=errors[-50:],
            heartbeat_at=now_utc(),
            finished_at=now_utc(),
        )
    )


async def _heartbeat(run_id: int, counters: Counters) -> None:
    await database.execute(
        update(zprp_public_sync_runs)
        .where(zprp_public_sync_runs.c.id == run_id)
        .values(counters=dict(counters), heartbeat_at=now_utc())
    )


async def _store_seasons(client: PublicZprpClient, counters: Counters) -> list[dict[str, Any]]:
    payload = await client.get("pokaz_sezony.php")
    result = rows(payload)
    for item in result:
        sid = text_value(item.get("ID_sezon"))
        if not sid:
            continue
        await store_entity(
            zprp_public_seasons,
            {
                "season_id": sid,
                "start_year": int_value(item.get("Rok_rozpoczecia")),
                "name": text_value(item.get("Nazwa")),
                "active": _truth(item.get("Stan")),
                "competition_count": int_value(item.get("IleRozgrywek"), 0) or 0,
            },
            key_columns=("season_id",),
            resource_type="season",
            resource_key=sid,
            source=item,
        )
        counters.add("seasons")
    return result


async def _store_associations(client: PublicZprpClient, counters: Counters) -> list[dict[str, Any]]:
    payload = await client.get("pokaz_woj.php")
    result = rows(payload)
    for item in result:
        aid = text_value(item.get("NrWZPR"))
        if not aid:
            continue
        await store_entity(
            zprp_public_associations,
            {
                "association_id": aid,
                "name": text_value(item.get("woj")),
                "code": text_value(item.get("woj_skrot")),
                "full_name": text_value(item.get("Nazwa")),
            },
            key_columns=("association_id",),
            resource_type="association",
            resource_key=aid,
            source=item,
        )
        counters.add("associations")
    return result


async def _store_player(source: dict[str, Any], counters: Counters) -> str:
    player_id = text_value(source.get("NrZawodnika") or source.get("player_id"))
    if not player_id:
        return ""
    existing = await database.fetch_one(
        select(zprp_public_players).where(zprp_public_players.c.player_id == player_id)
    )
    identity = {
        "NrZawodnika": player_id,
        "Nazwisko": text_value(source.get("Nazwisko") or source.get("nazwisko")),
        "Imie": text_value(source.get("Imie") or source.get("imie")),
        "Plec": text_value(source.get("Plec")),
        "RokUr": birth_year(source.get("DataUr") or source.get("dataUr")),
        "Foto": text_value(source.get("Foto")),
    }
    values = {
        "player_id": player_id,
        "first_name": identity["Imie"] or (text_value(existing["first_name"]) if existing else ""),
        "last_name": identity["Nazwisko"] or (text_value(existing["last_name"]) if existing else ""),
        "gender": identity["Plec"] or (text_value(existing["gender"]) if existing else ""),
        "birth_year": identity["RokUr"] or (existing["birth_year"] if existing else None),
        "photo_url": identity["Foto"] or (text_value(existing["photo_url"]) if existing else ""),
    }
    await store_entity(
        zprp_public_players,
        values,
        key_columns=("player_id",),
        resource_type="player",
        resource_key=player_id,
        source=identity,
        keep_snapshot=False,
    )
    counters.add("players")
    return player_id


def _match_values(item: dict[str, Any], **context: Any) -> dict[str, Any]:
    match_id = text_value(item.get("Id") or item.get("IdZawody") or item.get("ID_zawody"))
    return {
        "match_id": match_id,
        "season_id": text_value(item.get("ID_sezon") or context.get("season_id")),
        "competition_id": text_value(item.get("Id_rozgrywki") or item.get("IdRozgrywki") or context.get("competition_id")),
        "round_id": text_value(context.get("round_id")),
        "matchday_id": text_value(context.get("matchday_id")),
        "match_code": text_value(item.get("RozgrywkiCode") or item.get("RozgrywkiTypCode")),
        "competition_name": text_value(item.get("Nazwa") if item.get("Id_rozgrywki") else item.get("RozgrywkiNazwa") or context.get("competition_name")),
        "round_name": text_value(item.get("Runda") or context.get("round_name")),
        "matchday_name": text_value(item.get("Kolejka") or item.get("Nazwa") or context.get("matchday_name")),
        "home_team_id": text_value(item.get("ID_zespoly_gosp")),
        "away_team_id": text_value(item.get("ID_zespoly_gosc")),
        "home_club_id": text_value(item.get("ID_zespoly_gosp_ZespolNrKlubu")),
        "away_club_id": text_value(item.get("ID_zespoly_gosc_ZespolNrKlubu")),
        "home_team_name": text_value(item.get("ID_zespoly_gosp_ZespolNazwa")),
        "away_team_name": text_value(item.get("ID_zespoly_gosc_ZespolNazwa")),
        "scheduled_at": _dt(item.get("data_prop")),
        "played_at": _dt(item.get("data_fakt")),
        "halftime_home": int_value(item.get("wynik_gosp_pol")),
        "halftime_away": int_value(item.get("wynik_gosc_pol")),
        "score_home": int_value(item.get("wynik_bramki_gosp") or item.get("wynik_gosp_full")),
        "score_away": int_value(item.get("wynik_bramki_gosc") or item.get("wynik_gosc_full")),
        "winner": text_value(item.get("zwyciezca")),
        "withdrawn": _truth(item.get("wycofany")),
        "walkover_team_id": text_value(item.get("walkower_ID_zespoly")),
        "protocol_approved": _truth(item.get("protokol_zatwierdz")),
        "spectators": int_value(item.get("widzowie")),
        "stream_url": text_value(item.get("transmisja")),
        "tickets_url": text_value(item.get("bilety_url")),
        "comment": text_value(item.get("komentarz")),
        "referee_1_id": text_value(item.get("NrSedzia_pierwszy")),
        "referee_1_name": text_value(item.get("NrSedzia_pierwszy_nazwisko")),
        "referee_2_id": text_value(item.get("NrSedzia_drugi")),
        "referee_2_name": text_value(item.get("NrSedzia_drugi_nazwisko")),
        "delegate_1_id": text_value(item.get("NrSedzia_delegat")),
        "delegate_1_name": text_value(item.get("NrSedzia_delegat_nazwisko")),
        "delegate_2_id": text_value(item.get("NrSedzia_delegat2")),
        "delegate_2_name": text_value(item.get("NrSedzia_delegat2_nazwisko")),
        "secretary_id": text_value(item.get("NrSedzia_sekretarz")),
        "secretary_name": text_value(item.get("NrSedzia_sekretarz_nazwisko")),
        "timekeeper_id": text_value(item.get("NrSedzia_czas")),
        "timekeeper_name": text_value(item.get("NrSedzia_czas_nazwisko")),
        "venue_name": text_value(item.get("Hala_nazwa")),
        "venue_city": text_value(item.get("Hala_miasto")),
        "venue_street": text_value(item.get("Hala_ulica")),
        "venue_number": text_value(item.get("Hala_numer")),
        "venue_capacity": int_value(item.get("Hala_pojemnosc")),
        "upstream_changed_at": text_value(item.get("DataOstatnieZmiany")),
    }


async def _store_match(item: dict[str, Any], counters: Counters, **context: Any) -> tuple[str, bool]:
    values = _match_values(item, **context)
    match_id = values["match_id"]
    if not match_id:
        return "", False
    changed = await store_entity(
        zprp_public_matches,
        values,
        key_columns=("match_id",),
        resource_type="match",
        resource_key=match_id,
        source=item,
    )
    counters.add("matches")
    if changed:
        counters.add("matches_changed")
    return match_id, changed


async def _sync_match_details(client: PublicZprpClient, match_id: str, counters: Counters) -> str:
    payload = await client.get(f"pokaz_mecze_szczegoly.php?Zawody={match_id}")
    header: dict[str, Any] = {}
    if isinstance(payload, dict):
        zero = payload.get("0")
        if isinstance(zero, list) and zero and isinstance(zero[0], dict):
            header = zero[0]
        elif isinstance(zero, dict):
            header = zero
    if not header:
        header = _first(payload)
    if not header:
        return ""
    existing_match = await database.fetch_one(
        select(zprp_public_matches).where(zprp_public_matches.c.match_id == match_id)
    )
    values = _match_values(
        header,
        season_id=existing_match["season_id"] if existing_match else "",
        competition_id=existing_match["competition_id"] if existing_match else "",
        competition_name=existing_match["competition_name"] if existing_match else "",
        round_id=existing_match["round_id"] if existing_match else "",
        round_name=existing_match["round_name"] if existing_match else "",
        matchday_id=existing_match["matchday_id"] if existing_match else "",
        matchday_name=existing_match["matchday_name"] if existing_match else "",
    )
    values["details_fetched_at"] = now_utc()
    competition_id = values.get("competition_id") or ""
    await store_entity(
        zprp_public_matches,
        values,
        key_columns=("match_id",),
        resource_type="match_details",
        resource_key=match_id,
        source=payload,
    )

    side_map = {"gosp": (values.get("home_team_id") or "", "home"), "gosc": (values.get("away_team_id") or "", "away")}
    for upstream_side, (team_id, side) in side_map.items():
        people = payload.get(upstream_side) if isinstance(payload, dict) else None
        if isinstance(people, dict):
            for pid, item in people.items():
                if not isinstance(item, dict):
                    continue
                source = {**item, "NrZawodnika": text_value(pid)}
                player_id = await _store_player(source, counters)
                if not player_id:
                    continue
                clean = sanitize(source)
                await upsert_values(
                    zprp_public_match_players,
                    {
                        "match_id": match_id,
                        "team_id": team_id,
                        "player_id": player_id,
                        "side": side,
                        "shirt_number": text_value(item.get("NrKoszulki")),
                        "position": text_value(item.get("Pozycja")),
                        "goals": int_value(item.get("bramki"), 0) or 0,
                        "warnings": int_value(item.get("upomnienie"), 0) or 0,
                        "two_minutes": int_value(item.get("2minuty"), 0) or 0,
                        "disqualifications": int_value(item.get("dyskwalifikacja"), 0) or 0,
                        "direct_red_cards": int_value(item.get("kd"), 0) or 0,
                        "penalty_attempts": int_value(item.get("karne_liczba"), 0) or 0,
                        "penalty_goals": int_value(item.get("karne_bramki"), 0) or 0,
                        "shootout_attempts": int_value(item.get("karne_liczba_seria"), 0) or 0,
                        "shootout_goals": int_value(item.get("karne_bramki_seria"), 0) or 0,
                        "source_hash": checksum(clean),
                        "source_json": clean,
                        "fetched_at": now_utc(),
                    },
                    key_columns=("match_id", "team_id", "player_id"),
                )
                counters.add("match_players")

        staff = payload.get(f"{upstream_side}_osoby") if isinstance(payload, dict) else None
        if isinstance(staff, dict):
            for person_id, item in staff.items():
                if not isinstance(item, dict):
                    continue
                clean = sanitize(item)
                await upsert_values(
                    zprp_public_match_staff,
                    {
                        "match_id": match_id,
                        "team_id": team_id,
                        "person_id": text_value(person_id),
                        "side": side,
                        "first_name": text_value(item.get("imie")),
                        "last_name": text_value(item.get("nazwisko")),
                        "role": text_value(item.get("rola")),
                        "function": text_value(item.get("funkcja")),
                        "license": text_value(item.get("licencja")),
                        "source_hash": checksum(clean),
                        "source_json": clean,
                        "fetched_at": now_utc(),
                    },
                    key_columns=("match_id", "team_id", "person_id"),
                )
                counters.add("match_staff")
    counters.add("match_details")
    return text_value(competition_id)


async def _sync_competition_stats(client: PublicZprpClient, competition_id: str, counters: Counters) -> None:
    scorers_payload, tables_payload = await asyncio.gather(
        client.get(f"pokaz_strzelcow.php?Rozgrywki={competition_id}"),
        client.get(f"pokaz_tabele_spis.php?Rozgrywki={competition_id}"),
    )

    scorer_rows = [item for item in rows(scorers_payload) if item.get("NrZawodnika")]
    if scorer_rows or scorers_payload in ({}, [], None):
        await database.execute(delete(zprp_public_scorers).where(zprp_public_scorers.c.competition_id == competition_id))
    for item in scorer_rows:
        player_id = await _store_player(item, counters)
        if not player_id:
            continue
        clean = sanitize(item)
        await upsert_values(
            zprp_public_scorers,
            {
                "competition_id": competition_id,
                "player_id": player_id,
                "team_id": text_value(item.get("ID_zespol")),
                "team_name": text_value(item.get("Nazwa")),
                "goals": int_value(item.get("Bramki"), 0) or 0,
                "matches": int_value(item.get("Mecze"), 0) or 0,
                "average": text_value(item.get("Srednia")),
                "warnings": int_value(item.get("upomnienie"), 0) or 0,
                "two_minutes": int_value(item.get("2minuty"), 0) or 0,
                "disqualifications": int_value(item.get("dyskwalifikacja"), 0) or 0,
                "direct_red_cards": int_value(item.get("kd"), 0) or 0,
                "penalty_attempts": int_value(item.get("karne_liczba"), 0) or 0,
                "penalty_goals": int_value(item.get("karne_bramki"), 0) or 0,
                "shootout_attempts": int_value(item.get("karne_liczba_seria"), 0) or 0,
                "shootout_goals": int_value(item.get("karne_bramki_seria"), 0) or 0,
                "source_hash": checksum(clean),
                "source_json": clean,
                "fetched_at": now_utc(),
            },
            key_columns=("competition_id", "player_id", "team_id"),
        )
        counters.add("scorers")

    for table_item in rows(tables_payload):
        table_id = text_value(table_item.get("tabela_id"))
        if not table_id:
            continue
        payload = await client.get(f"pokaz_tabela.php?Rozgrywki={competition_id}&Tabela={table_id}")
        table_rows = [item for item in rows(payload) if item.get("ID_zespoly")]
        await database.execute(
            delete(zprp_public_standings).where(
                and_(
                    zprp_public_standings.c.competition_id == competition_id,
                    zprp_public_standings.c.table_id == table_id,
                    zprp_public_standings.c.group_id == "",
                )
            )
        )
        for position, item in enumerate(table_rows, start=1):
            clean = sanitize(item)
            await upsert_values(
                zprp_public_standings,
                {
                    "competition_id": competition_id,
                    "table_id": table_id,
                    "group_id": "",
                    "team_id": text_value(item.get("ID_zespoly")),
                    "club_id": text_value(item.get("NrKlubu")),
                    "position": position,
                    "team_name": text_value(item.get("Nazwa")),
                    "matches": int_value(item.get("Mecze"), 0) or 0,
                    "wins": int_value(item.get("Zwyciestwa"), 0) or 0,
                    "draws": int_value(item.get("Remisy"), 0) or 0,
                    "losses": int_value(item.get("Przegrane"), 0) or 0,
                    "goals_for": int_value(item.get("BramkiZdobyte"), 0) or 0,
                    "goals_against": int_value(item.get("BramkiStracone"), 0) or 0,
                    "goal_difference": int_value(item.get("Zd_St"), 0) or 0,
                    "points": int_value(item.get("PunktyZdobyte"), 0) or 0,
                    "extra_json": clean,
                    "source_hash": checksum(clean),
                    "fetched_at": now_utc(),
                },
                key_columns=("competition_id", "table_id", "group_id", "team_id"),
            )
            counters.add("standings")


async def _sync_competition_tree(
    client: PublicZprpClient,
    competition: dict[str, Any],
    counters: Counters,
    *,
    include_stats: bool,
) -> None:
    competition_id = text_value(competition.get("Id_rozgrywki"))
    if not competition_id:
        return
    rounds_payload = await client.get(f"pokaz_rundy.php?Rozgrywki={competition_id}")
    for round_item in rows(rounds_payload):
        round_id = text_value(round_item.get("Id"))
        if not round_id:
            continue
        await store_entity(
            zprp_public_rounds,
            {"round_id": round_id, "competition_id": competition_id, "name": text_value(round_item.get("Nazwa"))},
            key_columns=("round_id",),
            resource_type="round",
            resource_key=round_id,
            source=round_item,
            keep_snapshot=False,
        )
        counters.add("rounds")
        matchdays_payload = await client.get(f"pokaz_kolejki.php?Runda={round_id}")
        for matchday in rows(matchdays_payload):
            matchday_id = text_value(matchday.get("ID_kolejka"))
            if not matchday_id:
                continue
            await store_entity(
                zprp_public_matchdays,
                {
                    "matchday_id": matchday_id,
                    "round_id": round_id,
                    "number": int_value(matchday.get("Nr")),
                    "sequence": int_value(matchday.get("Lp")),
                    "name": text_value(matchday.get("Nazwa")),
                    "starts_on": text_value(matchday.get("DataStart")),
                    "ends_on": text_value(matchday.get("DataKoniec")),
                },
                key_columns=("matchday_id",),
                resource_type="matchday",
                resource_key=matchday_id,
                source=matchday,
                keep_snapshot=False,
            )
            counters.add("matchdays")
            matches_payload = await client.get(f"pokaz_mecze.php?Kolejka={matchday_id}")
            for item in rows(matches_payload):
                await _store_match(
                    item,
                    counters,
                    season_id=competition.get("ID_sezon"),
                    competition_id=competition_id,
                    competition_name=competition.get("Nazwa"),
                    round_id=round_id,
                    round_name=round_item.get("Nazwa"),
                    matchday_id=matchday_id,
                    matchday_name=matchday.get("Nazwa"),
                )
    if include_stats:
        await _sync_competition_stats(client, competition_id, counters)


async def _sync_season(
    client: PublicZprpClient,
    season_id: str,
    counters: Counters,
    run_id: int,
    *,
    include_stats: bool,
) -> None:
    payload = await client.get(f"pokaz_rozgrywki.php?Sezon={season_id}")
    competitions = [item for item in rows(payload) if item.get("Id_rozgrywki")]
    for item in competitions:
        competition_id = text_value(item.get("Id_rozgrywki"))
        await store_entity(
            zprp_public_competitions,
            {
                "competition_id": competition_id,
                "season_id": text_value(item.get("ID_sezon") or season_id),
                "association_id": text_value(item.get("NrWZPR")),
                "association_name": text_value(item.get("NazwaWZPR")),
                "name": text_value(item.get("Nazwa")),
                "gender": text_value(item.get("Plec")),
                "category": text_value(item.get("Kategoria")),
                "code": text_value(item.get("code")),
                "export_code": text_value(item.get("code_export")),
                "team_count": int_value(item.get("IleZespolow"), 0) or 0,
                "started": _truth(item.get("Wystartowano")),
                "protocol_type": text_value(item.get("Protokol_typ")),
                "regulations_url": text_value(item.get("Regulamin")),
                "has_groups": _truth(item.get("Grupy")),
            },
            key_columns=("competition_id",),
            resource_type="competition",
            resource_key=competition_id,
            source=item,
        )
        counters.add("competitions")

    async def one(item: dict[str, Any]) -> None:
        try:
            await _sync_competition_tree(client, item, counters, include_stats=include_stats)
        except Exception as exc:  # jedna uszkodzona liga nie zatrzymuje całego kraju
            counters.add("competition_errors")
            log.warning("[zprp_public] rozgrywki %s: %s", item.get("Id_rozgrywki"), exc)

    for start in range(0, len(competitions), 10):
        await asyncio.gather(*(one(item) for item in competitions[start : start + 10]))
        await _heartbeat(run_id, counters)


async def _club_index(client: PublicZprpClient, associations: list[dict[str, Any]], counters: Counters) -> None:
    for association in associations:
        aid = text_value(association.get("NrWZPR"))
        if not aid:
            continue
        payload = await client.get(f"pokaz_kluby.php?NrWZPR={aid}")
        for item in rows(payload):
            club_id = text_value(item.get("NrKlubu"))
            if not club_id:
                continue
            clean = sanitize(item)
            values = {
                "club_id": club_id,
                "association_id": aid,
                "name": text_value(item.get("Nazwa")),
                "member": _truth(item.get("CzlonekZPRP")),
                "archived": False,
                "logo_url": text_value(item.get("Logo")),
                "source_hash": checksum(clean),
                "source_json": clean,
                "fetched_at": now_utc(),
                "updated_at": now_utc(),
            }
            await upsert_values(
                zprp_public_clubs,
                values,
                key_columns=("club_id",),
                update_columns=("association_id", "name", "member", "logo_url", "fetched_at"),
            )
            counters.add("club_index")


async def _sync_one_club(client: PublicZprpClient, club_id: str, season_ids: set[str], counters: Counters) -> None:
    detail_payload, license_payload, teams_payload = await asyncio.gather(
        client.get(f"pokaz_klub_szczeg.php?NrKlubu={club_id}"),
        client.get(f"pokaz_klub_licencje.php?NrKlubu={club_id}"),
        client.get(f"pokaz_klub_zespoly.php?NrKlubu={club_id}"),
    )
    item = _first(detail_payload)
    if item:
        existing = await database.fetch_one(
            select(zprp_public_clubs.c.association_id, zprp_public_clubs.c.member).where(
                zprp_public_clubs.c.club_id == club_id
            )
        )
        await store_entity(
            zprp_public_clubs,
            {
                "club_id": club_id,
                "association_id": text_value(item.get("NrWZPR") or (existing["association_id"] if existing else "")),
                "name": text_value(item.get("Nazwa")),
                "member": existing["member"] if existing else None,
                "city": text_value(item.get("Miasto")),
                "postal_code": text_value(item.get("KodPocztowy")),
                "street": text_value(item.get("Ulica")),
                "email": text_value(item.get("Email")),
                "website": text_value(item.get("Www")),
                "phone_1": text_value(item.get("Telefon1")),
                "phone_2": text_value(item.get("Telefon2")),
                "archived": _truth(item.get("Archiwalny")),
                "logo_url": text_value(item.get("Logo")),
                "source_updated_at": text_value(item.get("Data_akt")),
                "details_fetched_at": now_utc(),
            },
            key_columns=("club_id",),
            resource_type="club",
            resource_key=club_id,
            source=item,
        )
        counters.add("clubs")

    await database.execute(delete(zprp_public_club_licenses).where(zprp_public_club_licenses.c.club_id == club_id))
    for license_item in rows(license_payload):
        clean = sanitize(license_item)
        await insert_ignore(
            zprp_public_club_licenses,
            {
                "club_id": club_id,
                "season_name": text_value(license_item.get("Sezon")),
                "name": text_value(license_item.get("NazwaLicencji")),
                "status": text_value(license_item.get("Realizacja")),
                "gender": text_value(license_item.get("Plec")),
                "source_hash": checksum(clean),
                "source_json": clean,
                "fetched_at": now_utc(),
            },
            key_columns=("club_id", "season_name", "name", "gender"),
        )
        counters.add("licenses")

    for team in rows(teams_payload):
        season_id = text_value(team.get("ID_sezon"))
        team_id = text_value(team.get("ID_zespol"))
        if not team_id or season_id not in season_ids:
            continue
        await store_entity(
            zprp_public_teams,
            {
                "team_id": team_id,
                "season_id": season_id,
                "club_id": club_id,
                "source_row_id": text_value(team.get("Id")),
                "season_name": text_value(team.get("Sezon")),
                "name": text_value(team.get("Nazwa")),
                "gender": text_value(team.get("Plec")),
                "category": text_value(team.get("Kategoria")),
            },
            key_columns=("team_id", "season_id"),
            resource_type="team",
            resource_key=f"{season_id}:{team_id}",
            source=team,
            keep_snapshot=False,
        )
        counters.add("teams")


async def _sync_club_batch(client: PublicZprpClient, season_ids: list[str], counters: Counters) -> None:
    associations = await _store_associations(client, counters)
    await _club_index(client, associations, counters)
    cutoff = now_utc() - timedelta(days=7)
    limit = max(4, min(80, int(os.getenv("ZPRP_PUBLIC_CLUB_BATCH", "24"))))
    stale = await database.fetch_all(
        select(zprp_public_clubs.c.club_id)
        .where(
            or_(
                zprp_public_clubs.c.details_fetched_at.is_(None),
                zprp_public_clubs.c.details_fetched_at < cutoff,
            )
        )
        .order_by(zprp_public_clubs.c.details_fetched_at.asc())
        .limit(limit)
    )

    async def one(row: Any) -> None:
        try:
            await _sync_one_club(client, text_value(row["club_id"]), set(season_ids), counters)
        except Exception as exc:
            counters.add("club_errors")
            log.warning("[zprp_public] klub %s: %s", row["club_id"], exc)

    await _chunks(list(stale), 6, one)


async def _sync_roster(client: PublicZprpClient, team_id: str, season_id: str, counters: Counters) -> None:
    payload = await client.get(f"pokaz_sklad.php?Zespol={team_id}&Sezon={season_id}")
    items = rows(payload)
    meta = next((item for item in items if not item.get("NrZawodnika")), {})
    if meta:
        existing = await database.fetch_one(
            select(zprp_public_teams).where(
                and_(zprp_public_teams.c.team_id == team_id, zprp_public_teams.c.season_id == season_id)
            )
        )
        await store_entity(
            zprp_public_teams,
            {
                "team_id": team_id,
                "season_id": season_id,
                "club_id": text_value(meta.get("NrKlubu") or (existing["club_id"] if existing else "")),
                "source_row_id": text_value(existing["source_row_id"] if existing else ""),
                "season_name": text_value(meta.get("Sezon")),
                "name": text_value(meta.get("Nazwa")),
                "gender": text_value(meta.get("Plec")),
                "category": text_value(meta.get("Kategoria")),
                "city": text_value(meta.get("Miasto")),
                "postal_code": text_value(meta.get("KodPocztowy")),
                "street": text_value(meta.get("Ulica")),
                "email": text_value(meta.get("Email")),
                "website": text_value(meta.get("Www")),
                "roster_fetched_at": now_utc(),
            },
            key_columns=("team_id", "season_id"),
            resource_type="team_roster",
            resource_key=f"{season_id}:{team_id}",
            source=payload,
        )
    await database.execute(
        update(zprp_public_team_rosters)
        .where(and_(zprp_public_team_rosters.c.team_id == team_id, zprp_public_team_rosters.c.season_id == season_id))
        .values(active=False)
    )
    for item in items:
        if not item.get("NrZawodnika"):
            continue
        player_id = await _store_player(item, counters)
        clean = sanitize(item)
        await upsert_values(
            zprp_public_team_rosters,
            {
                "team_id": team_id,
                "season_id": season_id,
                "player_id": player_id,
                "shirt_number": text_value(item.get("NrKoszulki")),
                "position_id": text_value(item.get("IdPozycja")),
                "position": text_value(item.get("Pozycja")),
                "active": True,
                "source_hash": checksum(clean),
                "source_json": clean,
                "fetched_at": now_utc(),
            },
            key_columns=("team_id", "season_id", "player_id"),
        )
        counters.add("roster_players")
    counters.add("rosters")


async def _sync_roster_batch(client: PublicZprpClient, season_ids: list[str], counters: Counters) -> None:
    if not season_ids:
        return
    current_id = season_ids[0]
    cutoff = now_utc() - timedelta(hours=24)
    limit = max(8, min(120, int(os.getenv("ZPRP_PUBLIC_ROSTER_BATCH", "40"))))
    stale = await database.fetch_all(
        select(zprp_public_teams.c.team_id, zprp_public_teams.c.season_id)
        .where(
            and_(
                zprp_public_teams.c.season_id.in_(season_ids),
                or_(
                    zprp_public_teams.c.roster_fetched_at.is_(None),
                    and_(zprp_public_teams.c.season_id == current_id, zprp_public_teams.c.roster_fetched_at < cutoff),
                ),
            )
        )
        .order_by(zprp_public_teams.c.roster_fetched_at.asc())
        .limit(limit)
    )

    async def one(row: Any) -> None:
        try:
            await _sync_roster(client, text_value(row["team_id"]), text_value(row["season_id"]), counters)
        except Exception as exc:
            counters.add("roster_errors")
            log.warning("[zprp_public] skład %s/%s: %s", row["season_id"], row["team_id"], exc)

    await _chunks(list(stale), 8, one)


async def _active_season_ids(limit: int = 2) -> list[str]:
    rows_db = await database.fetch_all(
        select(zprp_public_seasons.c.season_id)
        .order_by(zprp_public_seasons.c.start_year.desc().nullslast())
        .limit(limit)
    )
    return [text_value(row["season_id"]) for row in rows_db if row["season_id"]]


async def _sync_live(client: PublicZprpClient, season_id: str, counters: Counters) -> None:
    query = urlencode({"Sezon": season_id, "Sort": "2", "DniMinus": "1", "DniPlus": "7", "Ostatnie": "1"})
    payload = await client.get(f"pokaz_terminarz.php?{query}")
    changed_competitions: set[str] = set()
    active_ids: list[str] = []
    now = _local_now()
    for item in rows(payload):
        match_id, changed = await _store_match(item, counters)
        competition_id = text_value(item.get("IdRozgrywki"))
        if changed and competition_id:
            changed_competitions.add(competition_id)
        when = _dt(item.get("data_fakt") or item.get("data_prop"))
        if match_id and when and now - timedelta(hours=12) <= when <= now + timedelta(hours=4):
            active_ids.append(match_id)

    for match_id in active_ids[:40]:
        try:
            competition_id = await _sync_match_details(client, match_id, counters)
            if competition_id:
                changed_competitions.add(competition_id)
        except Exception as exc:
            counters.add("detail_errors")
            log.warning("[zprp_public] szczegóły meczu %s: %s", match_id, exc)

    # Tabele i strzelcy tylko lig, w których coś się zmieniło. Limit zapobiega
    # gwałtownemu skokowi po awarii upstreamu; resztę domknie katalog dobowy.
    for competition_id in sorted(changed_competitions)[:12]:
        try:
            await _sync_competition_stats(client, competition_id, counters)
        except Exception as exc:
            counters.add("stats_errors")
            log.warning("[zprp_public] statystyki %s: %s", competition_id, exc)


async def _sync_detail_backfill(client: PublicZprpClient, season_ids: list[str], counters: Counters) -> None:
    limit = max(10, min(160, int(os.getenv("ZPRP_PUBLIC_DETAILS_BATCH", "60"))))
    stale = await database.fetch_all(
        select(zprp_public_matches.c.match_id)
        .where(
            and_(
                zprp_public_matches.c.season_id.in_(season_ids),
                zprp_public_matches.c.details_fetched_at.is_(None),
            )
        )
        .order_by(zprp_public_matches.c.scheduled_at.desc().nullslast())
        .limit(limit)
    )

    async def one(row: Any) -> None:
        try:
            await _sync_match_details(client, text_value(row["match_id"]), counters)
        except Exception as exc:
            counters.add("detail_errors")
            log.warning("[zprp_public] backfill meczu %s: %s", row["match_id"], exc)

    await _chunks(list(stale), 8, one)


def _selected_seasons(upstream: list[dict[str, Any]]) -> list[str]:
    valid = [item for item in upstream if item.get("ID_sezon")]
    valid.sort(key=lambda item: int_value(item.get("Rok_rozpoczecia"), 0) or 0, reverse=True)
    active = next((item for item in valid if _truth(item.get("Stan"))), valid[0] if valid else None)
    if not active:
        return []
    selected = [text_value(active.get("ID_sezon"))]
    selected.extend(
        text_value(item.get("ID_sezon"))
        for item in valid
        if text_value(item.get("ID_sezon")) != selected[0]
    )
    return selected[:2]


async def run_sync_job(kind: str, *, season_id: str | None = None, cycle_key: str | None = None) -> dict[str, Any]:
    """Uruchamia pojedynczy, rozproszony-idempotentny przebieg synchronizacji."""
    allowed = {"catalog", "live", "clubs", "details", "historical", "cleanup"}
    if kind not in allowed:
        raise ValueError(f"Nieznany rodzaj synchronizacji: {kind}")
    existing_seasons = await _active_season_ids()
    seasons_for_run = [season_id] if season_id else existing_seasons
    bucket = int(datetime.now(timezone.utc).timestamp() // 60)
    key = cycle_key or f"{kind}:{season_id or '-'}:{bucket}"
    run_id = await _claim_run(kind, key, seasons_for_run)
    if run_id is None:
        return {"started": False, "reason": "cycle-already-claimed", "cycle_key": key}

    counters = Counters()
    errors: list[str] = []
    client = PublicZprpClient()
    try:
        if kind == "catalog":
            upstream = await _store_seasons(client, counters)
            associations = await _store_associations(client, counters)
            del associations
            selected = _selected_seasons(upstream)
            seasons_for_run = selected
            completed_catalogs = await database.fetch_val(
                select(func.count())
                .select_from(zprp_public_sync_runs)
                .where(
                    zprp_public_sync_runs.c.kind == "catalog",
                    zprp_public_sync_runs.c.status == "success",
                    zprp_public_sync_runs.c.id != run_id,
                )
            )
            for index, sid in enumerate(selected):
                # Bieżący sezon codziennie. Poprzedni pobieramy automatycznie
                # do pierwszego kompletnego cyklu. Częściowy import po awarii
                # zostanie dzięki temu bezpiecznie dokończony przy ponowieniu.
                if index > 0 and int(completed_catalogs or 0) > 0:
                    counters.add("static_seasons_skipped")
                    continue
                await _sync_season(client, sid, counters, run_id, include_stats=True)
                counters.add("seasons_synced")
        elif kind == "historical":
            if not season_id:
                raise ValueError("Dla synchronizacji historycznej wymagany jest season_id")
            await _sync_season(client, season_id, counters, run_id, include_stats=True)
        elif kind == "live":
            if not seasons_for_run:
                upstream = await _store_seasons(client, counters)
                seasons_for_run = _selected_seasons(upstream)
            if seasons_for_run:
                await _sync_live(client, seasons_for_run[0], counters)
        elif kind == "clubs":
            if not seasons_for_run:
                upstream = await _store_seasons(client, counters)
                seasons_for_run = _selected_seasons(upstream)
            await _sync_club_batch(client, seasons_for_run, counters)
            await _sync_roster_batch(client, seasons_for_run, counters)
        elif kind == "details":
            await _sync_detail_backfill(client, seasons_for_run, counters)
        elif kind == "cleanup":
            cutoff = now_utc() - timedelta(days=max(30, int(os.getenv("ZPRP_PUBLIC_RAW_RETENTION_DAYS", "90"))))
            counters["snapshots_deleted"] = int(
                await database.execute(
                    delete(zprp_public_raw_snapshots).where(zprp_public_raw_snapshots.c.fetched_at < cutoff)
                )
                or 0
            )
        counters["requests"] = client.requests
        counters["request_errors"] = client.errors
        await _finish_run(run_id, "success", counters, errors)
        return {"started": True, "run_id": run_id, "status": "success", "counters": dict(counters)}
    except asyncio.CancelledError:
        errors.append("cancelled")
        await _finish_run(run_id, "cancelled", counters, errors)
        raise
    except Exception as exc:
        errors.append(str(exc))
        counters["requests"] = client.requests
        counters["request_errors"] = client.errors
        await _finish_run(run_id, "failed", counters, errors)
        log.exception("[zprp_public] przebieg %s nieudany", kind)
        return {"started": True, "run_id": run_id, "status": "failed", "errors": errors}
    finally:
        await client.close()


async def _last_success(kind: str) -> datetime | None:
    row = await database.fetch_one(
        select(zprp_public_sync_runs.c.finished_at)
        .where(and_(zprp_public_sync_runs.c.kind == kind, zprp_public_sync_runs.c.status == "success"))
        .order_by(zprp_public_sync_runs.c.finished_at.desc())
        .limit(1)
    )
    return row["finished_at"] if row else None


def _due(last: datetime | None, interval: timedelta) -> bool:
    if last is None:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return now_utc() - last >= interval


async def run_zprp_public_scheduler() -> None:
    """Jedna oszczędna pętla; unikalny ``cycle_key`` chroni wiele replik."""
    if os.getenv("ZPRP_PUBLIC_SYNC_ENABLED", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        log.info("[zprp_public] scheduler wyłączony przez ZPRP_PUBLIC_SYNC_ENABLED")
        return
    await asyncio.sleep(max(5, int(os.getenv("ZPRP_PUBLIC_START_DELAY_SECONDS", "30"))))
    while True:
        try:
            async with _run_lock:
                if _due(await _last_success("catalog"), timedelta(hours=24)):
                    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    await run_sync_job("catalog", cycle_key=f"catalog:{day}")
                if _due(await _last_success("live"), timedelta(minutes=2)):
                    bucket = int(datetime.now(timezone.utc).timestamp() // 120)
                    await run_sync_job("live", cycle_key=f"live:{bucket}")
                if _due(await _last_success("clubs"), timedelta(minutes=15)):
                    bucket = int(datetime.now(timezone.utc).timestamp() // 900)
                    await run_sync_job("clubs", cycle_key=f"clubs:{bucket}")
                if _due(await _last_success("details"), timedelta(minutes=15)):
                    bucket = int(datetime.now(timezone.utc).timestamp() // 900)
                    await run_sync_job("details", cycle_key=f"details:{bucket}")
                if _due(await _last_success("cleanup"), timedelta(hours=24)):
                    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    await run_sync_job("cleanup", cycle_key=f"cleanup:{day}")
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("[zprp_public] błąd pętli synchronizacji")
        await asyncio.sleep(60)

