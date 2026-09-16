"""
Archiwum meczów okręgu - wspólne źródło sezonów dla Statystyk i analizy obsad.

Decyzje użytkownika z 16.09.2026:
  - serwer pobiera sezon RAZ (zamknięty) albo nocą (bieżący) i trzyma go
    gotowego; Statystyki dostają go jednym zapytaniem zamiast kilkuset zapytań
    kaskady i szczegółów przy każdym wejściu,
  - liczenie zostaje w przeglądarce - serwer oddaje `ProvinceDataset` w tym
    samym kształcie, który dotąd składał ekran (reguły: `app/archive_rules.py`,
    zgodność pilnowana testem na prawdziwych meczach),
  - mecze spoza okręgu są od razu w danych,
  - tylko okręgi z włączonym modułem Statystyk.

Skąd co:
  - kaskada rozgrywek i szczegóły meczów - publiczne API ZPRP (bez logowania),
  - mecze spoza okręgu - listy meczów sędziów (konto `sync` okręgu). Dla
    bieżącego sezonu oddaje je przebieg Rozliczeń (`spawn_after_settlement`),
    zamknięte sezony pobieramy tu, jednym przejściem po sędziach.

Szczegóły meczu pytamy tylko wtedy, gdy są potrzebne (`needs_details`):
zamknięty mecz ma je na zawsze, a przebudowa sezonu bez zmian to sama kaskada.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Response
from httpx import AsyncClient
from pydantic import BaseModel
from sqlalchemy import and_, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import archive_rules as AR
from app.assignment_scope import Season, current_start
from app.db import (
    database,
    zprp_archive_matches,
    zprp_archive_officials,
    zprp_archive_seasons,
)
from app.province_settlements import require_province
from app.settlement_province import display
from app.zprp_seasons import season_catalog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/archive", tags=["province_archive"])

API = "https://rozgrywki.zprp.pl/api/"

#: Równoległe zapytania do publicznego API. Przeglądarka brała 10-12; serwer
#: chodzi w tle i nie musi się spieszyć.
API_CONCURRENCY = 8
API_RETRIES = 2
API_TIMEOUT = 25.0

#: Bieżący sezon starszy niż to - przebudowa (w nocy albo przy wejściu).
CURRENT_MAX_AGE = timedelta(hours=20)
#: Po tylu godzinach bez znaku życia przebieg uznajemy za martwy.
STALE_RUN = timedelta(minutes=30)
#: Ile zamkniętych sezonów budujemy w jednym obiegu harmonogramu.
BACKLOG_BATCH = 3
#: Najstarszy sezon, o który w ogóle pytamy (Śląsk ma rozgrywki w API od 2013/14).
OLDEST_START = 2012

#: Budowy w toku: (okręg, sezon). Jedna instancja serwera - wystarczy pamięć.
_running: set[Tuple[str, str]] = set()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


# ---------------------------------------------------------------------------
# Publiczne API
# ---------------------------------------------------------------------------


class PublicApi:
    """Zapytania do `rozgrywki.zprp.pl/api` z liczeniem i ponowieniami."""

    def __init__(self, client: AsyncClient):
        self.client = client
        self.requests = 0
        self.errors = 0
        self.gate = asyncio.Semaphore(API_CONCURRENCY)

    async def get(self, path: str) -> Any:
        async with self.gate:
            for attempt in range(API_RETRIES + 1):
                self.requests += 1
                try:
                    response = await self.client.get(API + path, timeout=API_TIMEOUT)
                    if response.status_code in (408, 425, 429, 500, 502, 503, 504) and attempt < API_RETRIES:
                        await asyncio.sleep(0.4 * (2**attempt))
                        continue
                    if response.status_code >= 400:
                        self.errors += 1
                        return None
                    return AR.decode_api_bytes(response.content)
                except Exception:
                    if attempt >= API_RETRIES:
                        self.errors += 1
                        return None
                    await asyncio.sleep(0.4 * (2**attempt))
        return None


async def _cascade(api: PublicApi, season_id: str, province: str) -> Tuple[Optional[str], List[dict], List[dict], dict]:
    """Rozgrywki okręgu -> rundy -> kolejki -> mecze (`fetchMatchesForCompetitions`)."""
    all_comps = AR.as_rows(await api.get(f"pokaz_rozgrywki.php?Sezon={season_id}"))
    code = AR.resolve_wzpr_code(all_comps, display(province) or province)
    mine = AR.filter_province_competitions(all_comps, code) if code else []
    counters = {"competitions": len(mine), "rounds": 0, "series": 0, "matches": 0}
    if not mine:
        return code, [], [], counters

    round_lists = await asyncio.gather(
        *(api.get(f"pokaz_rundy.php?Rozgrywki={comp['Id_rozgrywki']}") for comp in mine)
    )
    rounds = [r for payload in round_lists for r in AR.as_rows(payload) if r.get("Id")]
    counters["rounds"] = len(rounds)

    series_lists = await asyncio.gather(*(api.get(f"pokaz_kolejki.php?Runda={r['Id']}") for r in rounds))
    series: List[dict] = []
    for rnd, payload in zip(rounds, series_lists):
        name = str(rnd.get("Nazwa")) if rnd.get("Nazwa") is not None else ""
        for item in AR.as_rows(payload):
            if item.get("ID_kolejka"):
                series.append({**item, "_rundaNazwa": name})
    counters["series"] = len(series)

    match_lists = await asyncio.gather(*(api.get(f"pokaz_mecze.php?Kolejka={s['ID_kolejka']}") for s in series))
    by_id: Dict[str, dict] = {}
    for item, payload in zip(series, match_lists):
        for row in AR.as_rows(payload):
            if row.get("Id"):
                by_id[str(row.get("Id"))] = {**row, "_runda": item["_rundaNazwa"], "_kolejka": AR.series_label(item)}
    rows = list(by_id.values())
    counters["matches"] = len(rows)
    return code, mine, rows, counters


# ---------------------------------------------------------------------------
# Sędziowie i ich listy meczów (baza.zprp.pl, konto sync)
# ---------------------------------------------------------------------------


def official_info(judge_id: str, item: dict) -> dict:
    """Wpis z listy „Sędziowie i Delegaci" -> `OfficialInfo` (jak `fetchOfficials`)."""
    name = _s(item.get("name"))
    return {
        "id": judge_id,
        "name": AR.pretty_person_name(name) or name,
        "city": _s(item.get("city")),
        "photo": _s(item.get("photo_href")),
        "roles": item.get("roles") if isinstance(item.get("roles"), list) else [],
        "partner": _s(item.get("partner")),
        "phone": _s(item.get("phone")),
    }


def officials_from_judges(judges: Dict[str, dict]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for judge_id, judge in judges.items():
        item = judge.get("official")
        if isinstance(item, dict):
            out[judge_id] = official_info(judge_id, item)
    return out


async def _store_officials(province: str, officials: Dict[str, dict]) -> None:
    if not officials:
        return
    _, etag = AR.pack(officials)
    statement = pg_insert(zprp_archive_officials).values(
        province=province, officials_json=officials, etag=etag, updated_at=_now()
    )
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[zprp_archive_officials.c.province],
            set_={"officials_json": officials, "etag": etag, "updated_at": _now()},
        )
    )


async def _load_officials(province: str) -> Dict[str, dict]:
    row = await database.fetch_one(
        select(zprp_archive_officials.c.officials_json).where(zprp_archive_officials.c.province == province)
    )
    value = row["officials_json"] if row else None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            value = None
    return value if isinstance(value, dict) else {}


async def _judge_lists(
    province: str,
    labels: List[str],
    collectors: Dict[str, AR.OutsideCollector],
    beat,
) -> Tuple[Dict[str, dict], Dict[str, Tuple[int, int]]]:
    """Jedno przejście po sędziach dla kilku sezonów naraz.

    Oddaje (sędziowie, `label -> (odczytane, nieudane)`). Wiersze trafiają od
    razu do zbieraczy - pełnych list nie trzymamy.
    """
    from app.deps import get_settings
    from app.province_settlement_sync import (
        JUDGE_REQUEST_DELAY,
        _build_judge_matches_path,
        _judge_season_pages,
        _load_judges,
        _login_zprp_and_get_cookies,
        _records_from_page,
    )
    from app.zprp_accounts import credentials_for
    from app.utils import fetch_with_correct_encoding
    from bs4 import BeautifulSoup

    stats = {label: (0, 0) for label in labels}
    credentials = credentials_for(province, "sync")
    if not credentials or not credentials[0] or not credentials[1]:
        return {}, stats

    settings = get_settings()
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, credentials[0], credentials[1])
        judges = await _load_judges(client, cookies, province)
        officials = officials_from_judges(judges)
        await _store_officials(province, officials)
        for collector in collectors.values():
            collector.officials = _naming(officials, judges)

        # Kolejność numerów rosnąco - tak przegląda je przeglądarka (klucze obiektu).
        for judge_id in sorted(judges, key=lambda value: (len(value), value)):
            try:
                entry_soup, options, selected = await _judge_season_pages(client, cookies, judge_id)
            except Exception as exc:
                logger.warning("[archive] %s: lista sędziego %s: %s", province, judge_id, exc)
                for label in labels:
                    ok, failed = stats[label]
                    stats[label] = (ok, failed + 1)
                continue
            for label in labels:
                value = options.get(label)
                ok, failed = stats[label]
                if not value:
                    # Sędzia nie ma tego sezonu na liście - nie sędziował w nim.
                    stats[label] = (ok + 1, failed)
                    continue
                try:
                    if label == selected:
                        soup = entry_soup
                    else:
                        _, html = await fetch_with_correct_encoding(
                            client, _build_judge_matches_path(judge_id, value), method="GET", cookies=cookies
                        )
                        soup = BeautifulSoup(html, "html.parser")
                        await asyncio.sleep(JUDGE_REQUEST_DELAY)
                except Exception as exc:
                    logger.warning("[archive] %s: sędzia %s, sezon %s: %s", province, judge_id, label, exc)
                    stats[label] = (ok, failed + 1)
                    continue
                records = _records_from_page(soup)
                if records is None:
                    stats[label] = (ok, failed + 1)
                    continue
                collectors[label].add(judge_id, records.values())
                stats[label] = (ok + 1, failed)
            await beat()
            await asyncio.sleep(JUDGE_REQUEST_DELAY)
    return judges, stats


def _naming(officials: Dict[str, dict], judges: Dict[str, dict]) -> Dict[str, dict]:
    """Nazwiska do dopasowania roli na liście: lista ZPRP, a bez niej lista okręgu."""
    out = {judge_id: {"name": info.get("name")} for judge_id, info in officials.items()}
    for judge_id, judge in (judges or {}).items():
        if judge_id not in out and _s(judge.get("full_name")):
            out[judge_id] = {"name": AR.pretty_person_name(judge.get("full_name")) or judge.get("full_name")}
    return out


# ---------------------------------------------------------------------------
# Budowa sezonu
# ---------------------------------------------------------------------------


async def _stored_matches(province: str, season_id: str) -> Dict[str, dict]:
    rows = await database.fetch_all(
        select(
            zprp_archive_matches.c.match_id,
            zprp_archive_matches.c.origin,
            zprp_archive_matches.c.slim_json,
            zprp_archive_matches.c.details_json,
        ).where(
            and_(zprp_archive_matches.c.province == province, zprp_archive_matches.c.season_id == season_id)
        )
    )

    def parse(value):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return None
        return value

    return {
        _s(row["match_id"]): {
            "origin": row["origin"],
            "slim": parse(row["slim_json"]),
            "details": parse(row["details_json"]),
        }
        for row in rows
    }


async def _fetch_details(api: PublicApi, ids: Iterable[str]) -> Dict[str, dict]:
    ids = [match_id for match_id in ids if _s(match_id).isdigit()]
    payloads = await asyncio.gather(*(api.get(f"pokaz_mecze_szczegoly.php?Zawody={match_id}") for match_id in ids))
    out: Dict[str, dict] = {}
    for match_id, payload in zip(ids, payloads):
        det = AR.details_from_payload(payload)
        if det:
            out[match_id] = det
    return out


def _ms_to_dt(ms: Optional[int]) -> Optional[datetime]:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc) if ms is not None else None


async def _mark(province: str, season: Season, **values: Any) -> None:
    statement = pg_insert(zprp_archive_seasons).values(
        province=province,
        season_id=season.id,
        season_label=season.label,
        season_start=season.start,
        **values,
    )
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[zprp_archive_seasons.c.province, zprp_archive_seasons.c.season_id],
            set_=values,
        )
    )


async def _write_matches(province: str, season_id: str, entries: List[dict]) -> None:
    keep = {entry["match_id"] for entry in entries}
    stored = await database.fetch_all(
        select(zprp_archive_matches.c.match_id).where(
            and_(zprp_archive_matches.c.province == province, zprp_archive_matches.c.season_id == season_id)
        )
    )
    gone = [_s(row["match_id"]) for row in stored if _s(row["match_id"]) not in keep]
    for start in range(0, len(gone), 500):
        await database.execute(
            delete(zprp_archive_matches).where(
                and_(
                    zprp_archive_matches.c.province == province,
                    zprp_archive_matches.c.season_id == season_id,
                    zprp_archive_matches.c.match_id.in_(gone[start : start + 500]),
                )
            )
        )
    # Wiersz po wierszu w jednej transakcji - tym samym wzorcem, co zapis
    # obsad Rozliczeń. Wielowierszowy upsert przez `databases` nie był w tym
    # kodzie nigdzie sprawdzony, a sezon to ~2000 wierszy raz na dobę.
    async with database.transaction():
        for entry in entries:
            values = {key: value for key, value in entry.items() if key != "match_id"}
            statement = pg_insert(zprp_archive_matches).values(
                province=province, season_id=season_id, match_id=entry["match_id"], **values
            )
            await database.execute(
                statement.on_conflict_do_update(
                    index_elements=[
                        zprp_archive_matches.c.province,
                        zprp_archive_matches.c.season_id,
                        zprp_archive_matches.c.match_id,
                    ],
                    set_={**values, "updated_at": _now()},
                )
            )


async def build_seasons(
    province: str,
    seasons: List[Season],
    *,
    current: int,
    lists: Optional[Dict[str, List[Tuple[str, List[dict]]]]] = None,
    lists_complete: Optional[Dict[str, bool]] = None,
    judges: Optional[Dict[str, dict]] = None,
) -> List[dict]:
    """Buduje kilka sezonów jednym przejściem po listach sędziów.

    `lists` podaje przebieg Rozliczeń (bieżący sezon) - wtedy po listy nie
    chodzimy. Bez nich pobieramy je tu, kontem `sync` okręgu.
    """
    keys = [(province, season.id) for season in seasons if (province, season.id) not in _running]
    todo = [season for season in seasons if (province, season.id) in keys]
    if not todo:
        return []
    _running.update(keys)
    started = _now()
    results: List[dict] = []

    async def beat() -> None:
        for season in todo:
            try:
                await database.execute(
                    update(zprp_archive_seasons)
                    .where(
                        and_(
                            zprp_archive_seasons.c.province == province,
                            zprp_archive_seasons.c.season_id == season.id,
                        )
                    )
                    .values(heartbeat_at=_now())
                )
            except Exception:
                pass

    try:
        for season in todo:
            await _mark(province, season, started_at=started, heartbeat_at=started, error=None)

        async with AsyncClient(follow_redirects=True) as http:
            api = PublicApi(http)

            # --- 1. kaskada i mecze okręgowe każdego sezonu ---
            prepared: Dict[str, dict] = {}
            now_ms = int(time.time() * 1000)
            for season in todo:
                code, comps, rows, counters = await _cascade(api, season.id, province)
                stored = await _stored_matches(province, season.id)
                closed = season.start < current

                fresh = [
                    AR.to_slim(row, origin="district", round_name=row["_runda"], series=row["_kolejka"])
                    for row in rows
                ]
                ask = [
                    slim["id"]
                    for slim in fresh
                    if AR.needs_details(
                        slim,
                        (stored.get(slim["id"]) or {}).get("slim"),
                        ((stored.get(slim["id"]) or {}).get("details") or {}).get("extract"),
                        now_ms,
                    )
                    # Zamknięty sezon: raz pobrane szczegóły zostają, nawet przy
                    # protokole, którego nikt już nie zatwierdzi.
                    and not (closed and ((stored.get(slim["id"]) or {}).get("details") or {}).get("extract"))
                ]
                details = await _fetch_details(api, ask)
                await beat()

                district: List[dict] = []
                ok = fail = 0
                for slim in fresh:
                    old = stored.get(slim["id"]) or {}
                    det = details.get(slim["id"])
                    extract = AR.extract_details(det, slim["ts"]) if det else ((old.get("details") or {}).get("extract"))
                    if det:
                        ok += 1
                    elif slim["id"] in ask:
                        fail += 1
                    else:
                        ok += 1
                    enriched = AR.apply_details(slim, extract) if extract else slim
                    district.append(
                        {
                            "slim": enriched,
                            "details": {"extract": extract} if extract else None,
                            "fetched": bool(det),
                        }
                    )

                prepared[season.id] = {
                    "season": season,
                    "code": code or "",
                    "comps": comps,
                    "counters": {**counters, "detailsOk": ok, "detailsFail": fail},
                    "district": district,
                    "stored": stored,
                    "collector": AR.OutsideCollector({item["slim"]["id"] for item in district}, {}),
                }

            # --- 2. listy sędziów (mecze spoza okręgu) ---
            outside_stats: Dict[str, Tuple[int, int]] = {}
            judge_total = 0
            if lists is not None:
                officials = officials_from_judges(judges or {}) or await _load_officials(province)
                if officials:
                    await _store_officials(province, officials)
                naming = _naming(officials, judges or {})
                for season_id, item in prepared.items():
                    label = item["season"].label
                    item["collector"].officials = naming
                    source = sorted(lists.get(label) or [], key=lambda pair: (len(pair[0]), pair[0]))
                    for judge_id, records in source:
                        item["collector"].add(judge_id, records)
                    complete = bool((lists_complete or {}).get(label))
                    outside_stats[label] = (len(source), 0 if complete else 1)
                judge_total = len(judges or {})
            else:
                # Sezon, w którym okręg nie miał rozgrywek, nie ma czego szukać
                # na listach sędziów - nie chodzimy po nie na darmo.
                wanted = [item for item in prepared.values() if item["district"]]
                labels = [item["season"].label for item in wanted]
                collectors = {item["season"].label: item["collector"] for item in wanted}
                found, outside_stats = await _judge_lists(province, labels, collectors, beat) if labels else ({}, {})
                judge_total = len(found)

            # --- 3. szczegóły meczów spoza okręgu, zapis, paczka ---
            for season_id, item in prepared.items():
                season: Season = item["season"]
                label = season.label
                closed = season.start < current
                candidates, skipped = item["collector"].result()
                stored = item["stored"]

                def stored_det(match_id: str) -> Optional[dict]:
                    old = stored.get(match_id) or {}
                    return old.get("details") if old.get("origin") == "outside" else None

                ask = []
                for candidate in candidates:
                    old = stored_det(candidate["id"])
                    if not old or not old.get("match"):
                        ask.append(candidate["id"])
                        continue
                    if closed:
                        continue
                    base = AR.row_to_slim(candidate)
                    if AR.needs_details(base, (stored.get(candidate["id"]) or {}).get("slim"), old.get("extract"), now_ms):
                        ask.append(candidate["id"])
                details = await _fetch_details(api, ask)
                await beat()

                outside: List[dict] = []
                for candidate in candidates:
                    det = details.get(candidate["id"])
                    old = stored_det(candidate["id"])
                    if det:
                        slim = AR.details_to_slim(candidate, det)
                        payload = {"match": det["match"], "extract": AR.extract_details(det, slim["ts"])}
                    elif old and old.get("match"):
                        base = AR.to_slim(old["match"], origin="outside")
                        enriched = AR.apply_details(base, old["extract"])
                        row_slim = AR.row_to_slim(candidate)
                        slim = {
                            **enriched,
                            "id": candidate["id"],
                            "hall": enriched.get("hall") or row_slim["hall"],
                            "city": enriched.get("city") or row_slim["city"],
                            "spect": enriched.get("spect") if enriched.get("spect") is not None else row_slim["spect"],
                            "refNames": {**row_slim["refNames"], **enriched.get("refNames", {})},
                            "refs": {**row_slim["refs"], **enriched.get("refs", {})},
                        }
                        payload = old
                    else:
                        slim = AR.row_to_slim(candidate)
                        payload = None
                    outside.append({"slim": slim, "details": payload, "fetched": bool(det)})

                ok, failed = outside_stats.get(label, (0, 0))
                has_outside = bool(ok or failed) and (lists is not None or judge_total)
                outside_stage = "none" if not has_outside else ("full" if not failed else "partial")

                entries = []
                for position, entry in enumerate(item["district"] + outside):
                    slim = entry["slim"]
                    entries.append(
                        {
                            "match_id": slim["id"],
                            "ord": position,
                            "origin": slim["origin"],
                            "code": slim.get("code"),
                            "match_at": _ms_to_dt(slim.get("ts")),
                            "slim_json": slim,
                            "details_json": entry["details"],
                            "details_at": _now() if entry["fetched"] else None,
                        }
                    )
                await _write_matches(province, season.id, entries)

                counters = {
                    **item["counters"],
                    "requests": api.requests,
                    "errors": api.errors,
                    "outsideOk": ok,
                    "outsideFail": failed,
                    "outsideMatches": len(outside),
                }
                payload = AR.dataset_payload(
                    province=display(province) or province,
                    wzpr_code=item["code"],
                    season_id=season.id,
                    season_name=label,
                    fetched_at_ms=int(time.time() * 1000),
                    competitions=[AR.competition_entry(comp) for comp in item["comps"]],
                    matches=[entry["slim_json"] for entry in entries],
                    counters=counters,
                    outside_stage=outside_stage,
                    outside_scanned=ok,
                    outside_total=judge_total,
                )
                packed, etag = AR.pack(payload)
                await _mark(
                    province,
                    season,
                    wzpr_code=item["code"],
                    schema=AR.ARCHIVE_SCHEMA,
                    closed=closed,
                    matches=len(entries),
                    outside_stage=outside_stage,
                    outside_scanned=ok,
                    outside_total=judge_total,
                    counters_json=counters,
                    payload_gz=packed,
                    etag=etag,
                    built_at=_now(),
                    heartbeat_at=_now(),
                    error=None,
                )
                results.append({"season": label, "matches": len(entries), "outside": len(outside), "stage": outside_stage})
                logger.info(
                    "[archive] %s %s: %d meczów (%d spoza okręgu, %s), %d zapytań",
                    province, label, len(entries), len(outside), outside_stage, api.requests,
                )

        # Analiza obsad liczy się z archiwum - po każdej budowie jest z czego.
        try:
            from app.assignment_insights import schedule_recompute

            schedule_recompute(province)
        except Exception:
            pass
        return results
    except Exception as exc:
        logger.exception("[archive] budowa %s nie powiodła się", province)
        for season in todo:
            try:
                await _mark(province, season, error=str(exc)[:500], heartbeat_at=_now())
            except Exception:
                pass
        return results
    finally:
        _running.difference_update(keys)


def spawn_after_settlement(
    province: str,
    *,
    season_label: str,
    lists: List[Tuple[str, List[dict]]],
    lists_complete: bool,
    judges: Dict[str, dict],
) -> None:
    """Bieżący sezon po przebiegu Rozliczeń - listy sędziów już są w pamięci."""

    async def job() -> None:
        try:
            from app.province_settlement_sync import module_enabled

            if not await module_enabled(province, "stats"):
                return
            catalog = await season_catalog()
            current = current_start(catalog, _now().date())
            season = next((item for item in catalog.values() if item.label == season_label), None)
            if season is None:
                return
            await build_seasons(
                province,
                [season],
                current=current,
                lists={season_label: lists},
                lists_complete={season_label: lists_complete},
                judges=judges,
            )
        except Exception:
            logger.exception("[archive] %s: budowa po Rozliczeniach", province)

    asyncio.create_task(job())


# ---------------------------------------------------------------------------
# Harmonogram
# ---------------------------------------------------------------------------


async def _season_rows(province: str) -> Dict[str, dict]:
    rows = await database.fetch_all(
        select(
            zprp_archive_seasons.c.season_id,
            zprp_archive_seasons.c.season_start,
            zprp_archive_seasons.c.schema,
            zprp_archive_seasons.c.closed,
            zprp_archive_seasons.c.matches,
            zprp_archive_seasons.c.built_at,
            zprp_archive_seasons.c.started_at,
            zprp_archive_seasons.c.heartbeat_at,
            zprp_archive_seasons.c.error,
            zprp_archive_seasons.c.outside_stage,
            zprp_archive_seasons.c.season_label,
        ).where(zprp_archive_seasons.c.province == province)
    )
    return {_s(row["season_id"]): dict(row) for row in rows}


def _is_running(row: Optional[dict], province: str, season_id: str) -> bool:
    if (province, season_id) in _running:
        return True
    if not row or not row.get("started_at"):
        return False
    beat = row.get("heartbeat_at") or row.get("started_at")
    built = row.get("built_at")
    return (built is None or built < row["started_at"]) and _now() - beat < STALE_RUN


async def run_archive_scheduler() -> None:
    """Pętla archiwum: co 20 minut sprawdza, czy jest co budować."""
    await asyncio.sleep(180)
    while True:
        try:
            from app.province_settlement_sync import enabled_provinces

            catalog = await season_catalog()
            current = current_start(catalog, _now().date())
            for province in await enabled_provinces("stats"):
                rows = await _season_rows(province)
                todo = [
                    season
                    for season in AR.plan_builds(
                        catalog,
                        rows,
                        current=current,
                        now=_now(),
                        max_age=CURRENT_MAX_AGE,
                        oldest=OLDEST_START,
                        batch=BACKLOG_BATCH,
                    )
                    if not _is_running(rows.get(season.id), province, season.id)
                ]
                if not todo:
                    continue
                # Bieżący sezon za dnia buduje przebieg Rozliczeń (z gotowymi
                # listami). Tu tylko wtedy, gdy tamten go nie odświeżył.
                await build_seasons(province, todo, current=current)
        except Exception:
            logger.exception("[archive] pętla harmonogramu")
        await asyncio.sleep(20 * 60)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


async def _require_stats(province: str) -> str:
    from app.province_settlement_sync import module_enabled

    key = require_province(province)
    if not await module_enabled(key, "stats"):
        raise HTTPException(403, "Moduł Statystyk nie jest włączony w tym okręgu")
    return key


@router.get("/season", summary="Sezon z archiwum - gotowy ProvinceDataset (gzip)")
async def archive_season(
    request: Request,
    background: BackgroundTasks,
    province: str = Query(...),
    season_id: str = Query(..., description="ID_sezon ZPRP"),
):
    key = await _require_stats(province)
    row = await database.fetch_one(
        select(
            zprp_archive_seasons.c.payload_gz,
            zprp_archive_seasons.c.etag,
            zprp_archive_seasons.c.built_at,
            zprp_archive_seasons.c.closed,
            zprp_archive_seasons.c.schema,
        ).where(
            and_(zprp_archive_seasons.c.province == key, zprp_archive_seasons.c.season_id == _s(season_id))
        )
    )
    catalog = await season_catalog()
    current = current_start(catalog, _now().date())
    season = catalog.get(_s(season_id))

    if not row or not row["payload_gz"]:
        # Pierwsze wejście w sezon, którego jeszcze nie ma - budujemy w tle,
        # a ekran idzie dotychczasową ścieżką.
        if season is not None and season.start <= current and not _is_running(None, key, season.id):
            background.add_task(build_seasons, key, [season], current=current)
        raise HTTPException(404, detail={"code": "NOT_BUILT", "message": "Sezonu nie ma jeszcze w archiwum"})

    stale = bool(
        season is not None
        and season.start >= current
        and (row["built_at"] is None or _now() - row["built_at"] > CURRENT_MAX_AGE)
    )
    if stale and not _is_running(None, key, season.id):
        # Nieświeży bieżący sezon: oddajemy to, co jest, i odświeżamy w tle.
        background.add_task(build_seasons, key, [season], current=current)

    headers = {
        "ETag": f'"{row["etag"]}"',
        "Cache-Control": "private, no-cache",
        "X-Archive-Built-At": row["built_at"].isoformat() if row["built_at"] else "",
        "X-Archive-Stale": "1" if stale else "0",
        "Access-Control-Expose-Headers": "ETag, X-Archive-Built-At, X-Archive-Stale",
    }
    wanted = _s(request.headers.get("if-none-match")).strip('"')
    if wanted and wanted == row["etag"]:
        return Response(status_code=304, headers=headers)

    accepts_gzip = "gzip" in _s(request.headers.get("accept-encoding")).lower()
    if accepts_gzip:
        return Response(
            content=bytes(row["payload_gz"]),
            media_type="application/json",
            headers={**headers, "Content-Encoding": "gzip", "Vary": "Accept-Encoding"},
        )
    return Response(content=gzip.decompress(bytes(row["payload_gz"])), media_type="application/json", headers=headers)


@router.get("/officials", summary="Lista „Sędziowie i Delegaci” okręgu (OfficialInfo)")
async def archive_officials(request: Request, province: str = Query(...)):
    key = await _require_stats(province)
    row = await database.fetch_one(
        select(zprp_archive_officials.c.officials_json, zprp_archive_officials.c.etag, zprp_archive_officials.c.updated_at).where(
            zprp_archive_officials.c.province == key
        )
    )
    if not row:
        raise HTTPException(404, detail={"code": "NOT_BUILT", "message": "Listy sędziów nie ma jeszcze w archiwum"})
    headers = {
        "ETag": f'"{row["etag"]}"',
        "Cache-Control": "private, no-cache",
        "Access-Control-Expose-Headers": "ETag",
    }
    if _s(request.headers.get("if-none-match")).strip('"') == row["etag"]:
        return Response(status_code=304, headers=headers)
    officials = row["officials_json"]
    if isinstance(officials, str):
        officials = json.loads(officials)
    body = {
        "officials": officials,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }
    return Response(
        content=json.dumps(body, ensure_ascii=False),
        media_type="application/json",
        headers=headers,
    )


@router.get("/status", summary="Które sezony są w archiwum i kiedy powstały")
async def archive_status(province: str = Query(...)):
    key = await _require_stats(province)
    rows = await _season_rows(key)
    catalog = await season_catalog()
    current = current_start(catalog, _now().date())
    return {
        "province": key,
        "current_season": current,
        "seasons": sorted(
            (
                {
                    "season_id": season_id,
                    "label": row.get("season_label"),
                    "start": row.get("season_start"),
                    "matches": row.get("matches"),
                    "closed": row.get("closed"),
                    "outside_stage": row.get("outside_stage"),
                    "built_at": row["built_at"].isoformat() if row.get("built_at") else None,
                    "running": _is_running(row, key, season_id),
                    "error": row.get("error"),
                }
                for season_id, row in rows.items()
            ),
            key=lambda item: -(item["start"] or 0),
        ),
    }


class RefreshRequest(BaseModel):
    province: str
    season_id: str


@router.post("/refresh", summary="Przebuduj sezon w archiwum (w tle)")
async def archive_refresh(payload: RefreshRequest):
    key = await _require_stats(payload.province)
    catalog = await season_catalog()
    current = current_start(catalog, _now().date())
    season = catalog.get(_s(payload.season_id))
    if season is None or season.start > current:
        raise HTTPException(404, detail={"code": "UNKNOWN_SEASON", "message": "Nie znam takiego sezonu"})
    rows = await _season_rows(key)
    if _is_running(rows.get(season.id), key, season.id):
        return {"started": False, "running": True, "reason": "Ten sezon już się buduje"}
    asyncio.create_task(build_seasons(key, [season], current=current))
    return {"started": True, "running": True}
