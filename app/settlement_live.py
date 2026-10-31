"""Update just the changed match; keep the existing settlement engine/rules.

The synchronous path reads local data only. Missing road measurements are filled
in the background. Full scrapes share the commit lock and cannot undo this write.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import select, text, update

from app.db import (database, okreg_distances, province_judges, province_matches,
                    province_modules, province_settlement_judges, province_settlement_matches)
from app.settlement_province import canonical, spellings

logger = logging.getLogger(__name__)
_routes: dict[tuple, asyncio.Task] = {}


async def lock_province(province: str) -> None:
    # Transaction-scoped and shared by all workers; only the local commit is locked.
    key = int.from_bytes(hashlib.sha256(f"settlement:{canonical(province)}".encode()).digest()[:8],
                         "big", signed=True)
    await database.execute(text("SELECT pg_advisory_xact_lock(:key)").bindparams(key=key))


async def sync_match(province: str, match_id: str, *, previous_state=None, enrich=True) -> None:
    """Best effort after a successful write; never fail the ZPRP operation."""
    try:
        await _sync_match(province, str(match_id), previous_state=previous_state, enrich=enrich)
    except Exception:
        logger.exception("[settlement] live update failed for %s/%s", province, match_id)


async def _sync_match(province, match_id, *, previous_state=None, enrich=True):
    from app import province_settlement_sync as S
    from app import national_lookup_rules as NL, settlement_rates as R
    from app import route_atlas as RA, route_atlas_rules as AR
    from app.match_market_rules import crew_judge_ids
    from app.national_place_rules import province_label, province_slug

    province = canonical(province)
    if not province or not match_id.isdigit():
        return
    enabled = await database.fetch_val(select(province_modules.c.province).where(
        province_modules.c.province.in_(spellings(province)),
        province_modules.c.module.in_(["settlements", "stats"]),
        province_modules.c.enabled.is_(True)).limit(1))
    if not enabled:
        return
    pending = []
    async with database.transaction():
        await lock_province(province)
        row = await database.fetch_one(select(province_matches).where(
            province_matches.c.province.in_(spellings(province)),
            province_matches.c.match_id == match_id))
        if row is None or not row["active"]:
            return
        state = S._state(row["state_json"])
        judges = {}
        for person in await database.fetch_all(select(province_settlement_judges).where(
                province_settlement_judges.c.province.in_(spellings(province)))):
            judges[str(person["judge_id"])] = {"full_name": person["full_name"], "city": person["home_city"]}
        # A newly added judge may not yet appear in the nightly settlement roster.
        for person in await database.fetch_all(select(province_judges).where(
                province_judges.c.province.in_(spellings(province)))):
            judges.setdefault(str(person["judge_id"]), {"full_name": person["full_name"], "city": ""})
        existing = await database.fetch_all(select(province_settlement_matches).where(
            province_settlement_matches.c.province == province,
            province_settlement_matches.c.match_key.in_([f"d:{match_id}", f"o:{match_id}"])))
        for old in existing:
            if str(old["judge_id"]) in judges and not judges[str(old["judge_id"])].get("city"):
                judges[str(old["judge_id"])]["city"] = old["home_city"] or ""
        missing_cities = [j for j in crew_judge_ids(state) if j in judges and not judges[j].get("city")]
        for judge_id, city in (await S.judge_cities(missing_cities)).items():
            judges[judge_id]["city"] = city
        # Prefix discovery is only relevant to historical foreign competitions.
        season = S._s(row["season"] or state.get("season")) or S.season_of(row["match_at"])
        own = await S._own_prefixes(province) if season and season < S.season_of(S._now()) else set()
        rows = S._district_rows([row], judges, own=own)
        for item in rows:
            city = S._s(item.get("city"))
            if city:
                item["city"] = S.pretty_city(city) if S.looks_like_city(city) else ""
            else:
                # Partial snapshots must not erase a venue already resolved by
                # the full run. A genuinely changed hall gets a fresh distance.
                prior = next((p for p in existing if p["hall"] == item.get("hall") and p["city"]), None)
                if prior:
                    item["city"] = prior["city"]
        distance_row = await database.fetch_one(select(okreg_distances.c.content).where(
            okreg_distances.c.province.in_(spellings(province))))
        book = S.VersionedDistanceIndex(S._state(distance_row["content"]) if distance_row else None)
        national = await S.load_national_pairs()
        region = province_label(province_slug(province))
        # Only build the gazetteer when there is actually a route to resolve.
        locate = None
        route_rows = []
        for item in rows:
            home = S._s(judges[item["judge_id"]].get("city"))
            city = S._s(item.get("city"))
            item["home_city"] = home
            central = R.is_central_level_competition(item.get("match_code"))
            hit = NL.pick_distance(central, home=home, city=city,
                table_km=None if central else book.for_day(item.get("match_at")).lookup(home, city),
                national=national, province=province) if home and city else None
            item["distance_km"], item["distance_source"] = hit if hit is not None else (None, "none")
            prior = next((p for p in existing if str(p["judge_id"]) == item["judge_id"]
                and p["home_city"] == home and p["city"] == city and p["distance_source"] == "manual"), None)
            if prior is not None:
                item["distance_km"], item["distance_source"] = prior["distance_km"], "manual"
                continue
            if hit is None and home and city:
                locate = locate or S._route_locator(province)
                destination = S._google_destination(city, " ".join(filter(None,
                    [S._s(state.get("Hala_ulica")), S._s(state.get("Hala_numer"))])), item.get("teams"))
                start, end = locate(home, destination)
                pair = RA.Pair(AR.Endpoint(name=home, region=region, hint=start),
                    AR.Endpoint(name=destination, directional=True, hint=end,
                        key=S.normalize_city(destination)[0] if "," in destination else ""))
                route_rows.append((item, pair))
        if route_rows:
            # Direct cache read: even an in-flight Google request must not delay the save.
            cached = await RA.DbStore().get_many([AR.pair_key(p.origin, p.destination) for _, p in route_rows])
            for item, pair in route_rows:
                hit = cached.get(AR.pair_key(pair.origin, pair.destination))
                if hit and hit.get("km") is not None:
                    item["distance_km"], item["distance_source"] = hit["km"], "google"
                else:
                    pending.append(pair)
        now = datetime.now(timezone.utc)
        values = [{**item, "province": province, "active": True,
                   "last_seen_at": now, "updated_at": now} for item in rows]
        await S._upsert_matches(values)
        for item in rows:
            # Moving between historical outside/district sources must not leave
            # two payable rows for the same person and physical match.
            alternate = f"{'o' if item['match_key'].startswith('d:') else 'd'}:{match_id}"
            await database.execute(update(province_settlement_matches).where(
                province_settlement_matches.c.province == province,
                province_settlement_matches.c.match_key == alternate,
                province_settlement_matches.c.judge_id == item["judge_id"],
                province_settlement_matches.c.active.is_(True),
            ).values(active=False, updated_at=now))
        removed = set(crew_judge_ids(previous_state or {})) - set(crew_judge_ids(state))
        if previous_state is not None:
            roles = {"pierwszy": R.ROLE_FIELD, "drugi": R.ROLE_FIELD,
                     "sekretarz": R.ROLE_TABLE, "czas": R.ROLE_TABLE,
                     "delegat": R.ROLE_DELEGATE, "delegat2": R.ROLE_DELEGATE}
            changed_roles = {role for slot, role in roles.items()
                if previous_state.get(f"NrSedzia_{slot}") != state.get(f"NrSedzia_{slot}")}
            current_ids = set(crew_judge_ids(state))
            removed.update(str(p["judge_id"]) for p in existing
                if p["active"] and p["role"] in changed_roles and str(p["judge_id"]) not in current_ids)
        # Only explicitly replaced people are removed; a partial API response is
        # never evidence that an unmentioned judge lost the match.
        if removed:
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            old_row = {**dict(row), "state_json": previous_state}
            old_rows = S._district_rows([old_row], judges, own=own)
            tombstones = {item["judge_id"]: item for item in old_rows if item["judge_id"] in removed}
            for item in tombstones.values():
                await database.execute(pg_insert(province_settlement_matches).values(
                    **item, province=province, active=False,
                    home_city=S._s(judges[item["judge_id"]].get("city")),
                    last_seen_at=now, updated_at=now,
                ).on_conflict_do_nothing(index_elements=[
                    province_settlement_matches.c.province,
                    province_settlement_matches.c.judge_id,
                    province_settlement_matches.c.match_key,
                ]))
            await database.execute(update(province_settlement_matches).where(
                province_settlement_matches.c.province == province,
                province_settlement_matches.c.match_key.in_([f"d:{match_id}", f"o:{match_id}"]),
                province_settlement_matches.c.judge_id.in_(removed)
            ).values(active=False, updated_at=now))
    if pending and enrich:
        key = (province, match_id, tuple(sorted(AR.pair_key(p.origin, p.destination) for p in pending)))
        if key not in _routes:
            async def measure():
                try:
                    await RA.resolve(pending, max_new=6, need_shape=False)
                    await sync_match(province, match_id, enrich=False)
                except Exception:
                    logger.exception("[settlement] live routes failed for %s/%s", province, match_id)
                finally:
                    _routes.pop(key, None)
            _routes[key] = asyncio.create_task(measure())
