"""Automatyczna synchronizacja centralnych niedyspozycji sędziów.

Konto komisji widzi listę sędziów okręgu oraz link do niedyspozycji każdego z
nich. Co dwie godziny wykonujemy jeden login na okręg, pobieramy tę listę i
odświeżamy osobny, autorytatywny snapshot. Danych centralnych celowo nie
zapisujemy w ``silesia_offtimes``: tę tabelę nadpisuje telefon i starszy cache
nie może cofnąć stanu pobranego bezpośrednio z ZPRP.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from httpx import AsyncClient
from sqlalchemy import and_, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    login_records,
    province_central_offtimes,
    province_judges,
    province_match_sync_leases,
    province_offtime_sync_runs,
    silesia_offtimes,
)
from app.deps import get_settings
from app.utils import fetch_with_correct_encoding
from app.zprp.officials import (
    _ensure_index_php_prefix,
    _extract_menu_href_from_page,
    _login_zprp_and_get_cookies,
    _merge_officials,
    _parse_officials_page,
    _parse_offtime_rows,
)
from app.zprp_accounts import configured_provinces, normalize_province

logger = logging.getLogger("app.province_offtime_sync")
WARSAW = ZoneInfo("Europe/Warsaw")
SOURCE = "ZPRP_CENTRAL_SYNC"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _parse_source_date(value: Any) -> Optional[date]:
    raw = _clean(value)
    if not raw or raw == "0000-00-00":
        return None
    for fmt in ("%Y-%m-%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            pass
    return None


def _stable_source_key(judge_id: str, row: Dict[str, Any]) -> str:
    source_id = _clean(row.get("id"))
    if source_id:
        return source_id
    raw = "|".join(
        (
            judge_id,
            _clean(row.get("date_from")),
            _clean(row.get("date_to")),
            _clean(row.get("info")),
            _clean(row.get("created_by")),
        )
    )
    return "fp-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def central_entries_from_parsed(
    judge_id: str,
    parsed: Dict[str, Any],
    *,
    synced_at: Optional[datetime] = None,
) -> list[Dict[str, Any]]:
    """Zamień aktywne rekordy ZPRP na format wspólny z kalendarzem okręgowym."""
    stamp = synced_at or _now()
    entries: list[Dict[str, Any]] = []
    for row in parsed.get("offtimes") or []:
        if row.get("is_deleted"):
            continue
        start_day = _parse_source_date(row.get("date_from"))
        if start_day is None:
            continue
        end_day = _parse_source_date(row.get("date_to")) or start_day
        if end_day < start_day:
            end_day = start_day

        start_local = datetime.combine(start_day, time.min, tzinfo=WARSAW)
        end_local = datetime.combine(end_day, time.max, tzinfo=WARSAW)
        source_key = _stable_source_key(judge_id, row)
        entries.append(
            {
                "entry_type": "UNAVAIL",
                "id": f"zprp-central:{judge_id}:{source_key}",
                "source": SOURCE,
                "source_id": _clean(row.get("id")) or None,
                "source_lp": row.get("lp"),
                "source_synced_at": stamp.isoformat(),
                "from": start_local.astimezone(timezone.utc).isoformat(),
                "to": end_local.astimezone(timezone.utc).isoformat(),
                "info": _clean(row.get("info")),
                "location": "",
                "category_id": None,
                "category_name": "BAZOWA",
                "category_color": None,
                "color": None,
                "is_manual": False,
                "is_global": True,
                "isMatch": False,
            }
        )
    entries.sort(key=lambda item: (item["from"], item["to"], item["id"]))
    return entries


async def _scrape_officials(
    client: AsyncClient, cookies: Dict[str, str]
) -> Dict[str, Dict[str, Any]]:
    """Pełna, stronicowana lista oficjeli w ramach jednej sesji komisji."""
    _, home_html = await fetch_with_correct_encoding(
        client, "/index.php", method="GET", cookies=cookies
    )
    officials_href = _extract_menu_href_from_page(
        home_html,
        label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
        href_regex=r"\ba=sedzia\b",
    )
    _, first_html = await fetch_with_correct_encoding(
        client, officials_href, method="GET", cookies=cookies
    )
    first = _parse_officials_page(first_html, current_offset=0)
    officials: Dict[str, Dict[str, Any]] = {}
    _merge_officials(officials, first["officials"])

    paging = first.get("paging") or {}
    count = int(paging.get("count", 10))
    max_offset = int(paging.get("max_offset", 0))
    base_qs = dict(first.get("base_qs") or {})
    base_qs.update(
        {
            "a": "sedzia",
            "Filtr_archiwum": base_qs.get("Filtr_archiwum", "1") or "1",
            "count": str(count),
        }
    )
    for offset in range(1, max_offset + 1):
        qs = dict(base_qs)
        qs["offset"] = str(offset)
        _, html = await fetch_with_correct_encoding(
            client,
            "/index.php?" + urlencode(qs, doseq=True),
            method="GET",
            cookies=cookies,
        )
        page = _parse_officials_page(html, current_offset=offset)
        _merge_officials(officials, page["officials"])

    if not officials:
        raise RuntimeError("ZPRP returned a valid officials page without any officials")
    return officials


async def _fetch_offtimes(
    client: AsyncClient,
    cookies: Dict[str, str],
    href: str,
    *,
    retries: int,
) -> Dict[str, Any]:
    path = _ensure_index_php_prefix(href)
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            _, html = await fetch_with_correct_encoding(
                client, path, method="GET", cookies=cookies
            )
            return _parse_offtime_rows(html)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                await asyncio.sleep(0.6 * (2**attempt))
    raise RuntimeError(str(last_error or "unknown offtime fetch error"))


async def upsert_central_snapshot(
    *,
    province: str,
    judge_id: str,
    full_name: str,
    city: str,
    parsed: Dict[str, Any],
) -> int:
    province_key = normalize_province(province)
    if not province_key:
        raise ValueError(f"Unknown province: {province}")
    now = _now()
    entries = central_entries_from_parsed(judge_id, parsed, synced_at=now)
    summary = parsed.get("summary") or {}
    values = {
        "province": province_key,
        "judge_id": _clean(judge_id),
        "full_name": _clean(full_name) or _clean(parsed.get("official_name")) or f"Sędzia {judge_id}",
        "city": _clean(city) or None,
        "data_json": entries,
        "source_total": int(summary.get("total", len(parsed.get("offtimes") or [])) or 0),
        "source_deleted": int(summary.get("deleted", 0) or 0),
        "active": True,
        "missing_roster_runs": 0,
        "last_error": None,
        "last_attempt_at": now,
        "synced_at": now,
        "updated_at": now,
    }
    stmt = (
        pg_insert(province_central_offtimes)
        .values(**values)
        .on_conflict_do_update(
            index_elements=[
                province_central_offtimes.c.province,
                province_central_offtimes.c.judge_id,
            ],
            set_={key: value for key, value in values.items() if key not in ("province", "judge_id")},
        )
    )
    await database.execute(stmt)
    return len(entries)


async def _mark_snapshot_error(province: str, judge_id: str, error: Exception) -> None:
    await database.execute(
        update(province_central_offtimes)
        .where(
            and_(
                province_central_offtimes.c.province == province,
                province_central_offtimes.c.judge_id == judge_id,
            )
        )
        .values(last_error=str(error)[:1000], last_attempt_at=_now(), updated_at=_now())
    )


async def _reconcile_roster(province: str, seen_ids: Iterable[str]) -> None:
    """Wygaszaj snapshot dopiero po dwóch pełnych nieobecnościach na liście."""
    seen = {_clean(item) for item in seen_ids if _clean(item)}
    rows = await database.fetch_all(
        select(province_central_offtimes).where(
            province_central_offtimes.c.province == province
        )
    )
    for row in rows:
        judge_id = _clean(row["judge_id"])
        if judge_id in seen:
            await database.execute(
                update(province_central_offtimes)
                .where(
                    and_(
                        province_central_offtimes.c.province == province,
                        province_central_offtimes.c.judge_id == judge_id,
                    )
                )
                .values(active=True, missing_roster_runs=0, updated_at=_now())
            )
            continue
        missing = int(row["missing_roster_runs"] or 0) + 1
        await database.execute(
            update(province_central_offtimes)
            .where(
                and_(
                    province_central_offtimes.c.province == province,
                    province_central_offtimes.c.judge_id == judge_id,
                )
            )
            .values(
                missing_roster_runs=missing,
                active=missing < 2,
                updated_at=_now(),
            )
        )


async def _acquire_lease(province: str, holder: str, max_wait_seconds: int) -> bool:
    """Wspólna blokada z monitorem meczów, również między replikami Railway."""
    deadline = asyncio.get_running_loop().time() + max_wait_seconds
    while True:
        now = _now()
        stmt = (
            pg_insert(province_match_sync_leases)
            .values(
                province=province,
                holder=holder,
                locked_until=now + timedelta(minutes=3),
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=[province_match_sync_leases.c.province],
                set_={
                    "holder": holder,
                    "locked_until": now + timedelta(minutes=3),
                    "updated_at": now,
                },
                where=province_match_sync_leases.c.locked_until < now,
            )
            .returning(province_match_sync_leases.c.holder)
        )
        if await database.fetch_val(stmt) == holder:
            return True
        if asyncio.get_running_loop().time() >= deadline:
            return False
        await asyncio.sleep(5)


async def _heartbeat_lease(province: str, holder: str) -> None:
    while True:
        await asyncio.sleep(60)
        await database.execute(
            update(province_match_sync_leases)
            .where(province_match_sync_leases.c.province == province)
            .where(province_match_sync_leases.c.holder == holder)
            .values(locked_until=_now() + timedelta(minutes=3), updated_at=_now())
        )


async def _release_lease(province: str, holder: str) -> None:
    await database.execute(
        delete(province_match_sync_leases)
        .where(province_match_sync_leases.c.province == province)
        .where(province_match_sync_leases.c.holder == holder)
    )


async def _claim_run(province: str, interval: int) -> Optional[int]:
    slot = int(_now().timestamp()) // interval
    stmt = (
        pg_insert(province_offtime_sync_runs)
        .values(
            province=province,
            cycle_key=f"{province}:offtimes:{slot}",
            status="running",
        )
        .on_conflict_do_nothing(index_elements=[province_offtime_sync_runs.c.cycle_key])
        .returning(province_offtime_sync_runs.c.id)
    )
    run_id = await database.fetch_val(stmt)
    return int(run_id) if run_id else None


async def _sync_province(
    province: str,
    credentials: tuple[str, str],
    *,
    judge_concurrency: int,
    retries: int,
) -> Dict[str, int]:
    settings = get_settings()
    username, password = credentials
    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=60.0,
    ) as client:
        cookies = await _login_zprp_and_get_cookies(client, username, password)
        officials = await _scrape_officials(client, cookies)
        numeric_officials = {
            _clean(judge_id): item
            for judge_id, item in officials.items()
            if re.fullmatch(r"\d+", _clean(judge_id))
        }
        await _reconcile_roster(province, numeric_officials.keys())
        with_link = {
            judge_id: item
            for judge_id, item in numeric_officials.items()
            if _clean(item.get("offtime_href"))
        }
        semaphore = asyncio.Semaphore(judge_concurrency)
        synced = active_entries = errors = 0

        async def one(judge_id: str, official: Dict[str, Any]) -> tuple[bool, int]:
            async with semaphore:
                try:
                    parsed = await _fetch_offtimes(
                        client,
                        cookies,
                        _clean(official.get("offtime_href")),
                        retries=retries,
                    )
                    count = await upsert_central_snapshot(
                        province=province,
                        judge_id=judge_id,
                        full_name=_clean(official.get("name")),
                        city=_clean(official.get("city")),
                        parsed=parsed,
                    )
                    return True, count
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "Central offtimes %s/%s failed: %s", province, judge_id, exc
                    )
                    await _mark_snapshot_error(province, judge_id, exc)
                    return False, 0

        results = await asyncio.gather(
            *(one(judge_id, official) for judge_id, official in with_link.items())
        )
        for ok, count in results:
            if ok:
                synced += 1
                active_entries += count
            else:
                errors += 1
        return {
            "officials_seen": len(numeric_officials),
            "officials_with_link": len(with_link),
            "judges_synced": synced,
            "entries_active": active_entries,
            "errors_count": errors,
        }


async def _execute_province(
    province: str,
    credentials: tuple[str, str],
    *,
    interval: int,
    judge_concurrency: int,
    retries: int,
) -> None:
    holder = f"offtimes:{uuid.uuid4().hex}"
    if not await _acquire_lease(province, holder, max_wait_seconds=min(600, interval)):
        logger.warning("Central offtimes %s skipped: province lease busy", province)
        return
    run_id = await _claim_run(province, interval)
    if not run_id:
        await _release_lease(province, holder)
        return
    heartbeat = asyncio.create_task(_heartbeat_lease(province, holder))
    try:
        result = await _sync_province(
            province,
            credentials,
            judge_concurrency=judge_concurrency,
            retries=retries,
        )
        status = "partial" if result["errors_count"] else "success"
        await database.execute(
            update(province_offtime_sync_runs)
            .where(province_offtime_sync_runs.c.id == run_id)
            .values(status=status, finished_at=_now(), **result)
        )
        logger.info("Central offtimes %s finished: %s", province, result)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("Central offtimes %s failed", province)
        await database.execute(
            update(province_offtime_sync_runs)
            .where(province_offtime_sync_runs.c.id == run_id)
            .values(status="failed", error=str(exc)[:1800], finished_at=_now())
        )
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass
        await _release_lease(province, holder)


async def run_province_offtime_sync() -> None:
    """Scheduler Railway; domyślnie pełny przebieg co dwie godziny."""
    if os.getenv("ZPRP_OFFTIME_SYNC_ENABLED", "true").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        logger.info("Central offtime sync disabled")
        return
    interval = max(3600, int(os.getenv("ZPRP_OFFTIME_SYNC_SECONDS", "7200")))
    initial_delay = max(0, int(os.getenv("ZPRP_OFFTIME_SYNC_INITIAL_DELAY_SECONDS", "120")))
    province_concurrency = max(
        1, int(os.getenv("ZPRP_OFFTIME_SYNC_PROVINCE_CONCURRENCY", "2"))
    )
    judge_concurrency = max(
        1, int(os.getenv("ZPRP_OFFTIME_SYNC_JUDGE_CONCURRENCY", "4"))
    )
    retries = max(0, int(os.getenv("ZPRP_OFFTIME_SYNC_RETRIES", "2")))
    if initial_delay:
        await asyncio.sleep(initial_delay)

    semaphore = asyncio.Semaphore(province_concurrency)
    while True:
        started = asyncio.get_running_loop().time()
        accounts = configured_provinces()

        async def one(province: str, creds: tuple[str, str]) -> None:
            async with semaphore:
                await _execute_province(
                    province,
                    creds,
                    interval=interval,
                    judge_concurrency=judge_concurrency,
                    retries=retries,
                )

        try:
            await asyncio.gather(*(one(p, c) for p, c in accounts.items()))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Central offtime scheduler loop failed")
        elapsed = asyncio.get_running_loop().time() - started
        await asyncio.sleep(max(1.0, interval - elapsed))


async def refresh_central_snapshot_after_user_change(
    client: AsyncClient, judge_id: str
) -> int:
    """Natychmiast odśwież snapshot po create/update/delete z aplikacji.

    Zapis w ZPRP jest operacją główną. Ta funkcja jest best-effort i nie może
    zamienić poprawnego zapisu w błąd tylko dlatego, że serwerowy cache chwilowo
    nie jest dostępny.
    """
    judge_id = _clean(judge_id)
    if not judge_id:
        return 0
    _, html = await fetch_with_correct_encoding(
        client,
        f"/index.php?a=sedzia&b=off&NrSedzia={judge_id}",
        method="GET",
    )
    parsed = _parse_offtime_rows(html)

    candidates: Dict[str, Dict[str, str]] = {}
    central_rows = await database.fetch_all(
        select(province_central_offtimes).where(
            province_central_offtimes.c.judge_id == judge_id
        )
    )
    district_rows = await database.fetch_all(
        select(silesia_offtimes).where(silesia_offtimes.c.judge_id == judge_id)
    )
    judge_row = await database.fetch_one(
        select(province_judges).where(province_judges.c.judge_id == judge_id)
    )
    login_row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )

    for row in [*central_rows, *district_rows, judge_row, login_row]:
        if not row:
            continue
        values = dict(row)
        province = normalize_province(values.get("province"))
        if not province:
            continue
        current = candidates.setdefault(province, {"full_name": "", "city": ""})
        current["full_name"] = current["full_name"] or _clean(
            values.get("full_name")
        )
        current["city"] = current["city"] or _clean(values.get("city"))

    written = 0
    for province, meta in candidates.items():
        written += await upsert_central_snapshot(
            province=province,
            judge_id=judge_id,
            full_name=meta["full_name"] or _clean(parsed.get("official_name")),
            city=meta["city"],
            parsed=parsed,
        )
    return written
