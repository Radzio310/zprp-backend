"""Zapisane stany zakładek „Raporty i podsumowania ZPRP" (10.11.2026) - trasy, zapis, nocny przebieg.

  GET  /zprp/reports/snapshot?province=&kind=&key=   - ostatni stan okręgu (albo 404)
  GET  /zprp/reports/snapshots?province=              - spis zapisanych stanów (bez danych)
  POST /zprp/reports/snapshot                          - zapis po ręcznym odświeżeniu {province, kind, key, payload}

Dostęp: JWT. Administrator aplikacji - każdy okręg; konto VIP - okręg własny albo
z listy `provinces` w uprawnieniach. Konto sędziego - nie (zakładki są panelem okręgu).

Automat (`run_report_snapshot_scheduler`, start w `main.py`): dla okręgów z kontem
`sync` na serwerze raz na dobę w nocy (3-6 czasu polskiego; pierwszy raz od razu)
woła TE SAME trasy `/zprp/*` co zakładka, z danymi konta okręgu - kształt danych
jest identyczny. Lista sędziów nie czeka na noc: zapisuje ją synchronizacja
niedyspozycji co 2 h (`province_offtime_sync`, `save_snapshot`).

Reguły: `app/zprp_report_snapshot_rules.py`, kontrakt: `docs/raporty-zprp-zapisany-stan.md`.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import gzip
import json
import logging
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import and_, delete, func, select

from app import zprp_report_snapshot_rules as R
from app.deps import get_jwt_payload, get_rsa_keys, get_settings
from app.zprp_accounts import configured_provinces, credentials_for, normalize_province

logger = logging.getLogger("app.zprp_report_snapshots")

router = APIRouter(prefix="/zprp/reports", tags=["ZprpReportSnapshots"])

#: Ostatnia PRÓBA nocnego przebiegu na okręg (w pamięci) - gdy ZPRP nie odpowiada,
#: nie pukamy co 30 minut, tylko najwcześniej po `RETRY_AFTER`.
_attempted: Dict[str, _dt.datetime] = {}
RETRY_AFTER = _dt.timedelta(hours=6)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(value: Optional[_dt.datetime]) -> Optional[str]:
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Dostęp
# ---------------------------------------------------------------------------


async def _require_province(payload: dict, province: Any) -> str:
    """Okręg bez ogonków albo 401/403 z czytelnym powodem."""
    from app.province_panel_access import vip_covers_province
    from app.province_panel_guard import _lookup

    key = normalize_province(province)
    if not key:
        raise HTTPException(400, "Brak okręgu w żądaniu.")
    is_admin, vip = await _lookup(payload)
    if is_admin:
        return key
    if vip is None:
        raise HTTPException(403, "Zapisane stany raportów ZPRP widzą konta VIP okręgu i administrator aplikacji.")
    if not vip_covers_province(vip.province, vip.permissions, key):
        raise HTTPException(403, f"Konto VIP ma ustawione inne województwo niż {key}.")
    return key


# ---------------------------------------------------------------------------
# Magazyn
# ---------------------------------------------------------------------------


async def save_snapshot(
    province: Any,
    kind: str,
    key: str,
    payload: Any,
    *,
    source: str,
    fetched_by: str,
) -> int:
    """Zapisuje (nadpisuje) stan. Zwraca rozmiar po spakowaniu."""
    from app.db import database, zprp_report_snapshots as T

    prov = normalize_province(province)
    clean = R.clean_key(key)
    if not prov or not R.valid_kind(kind) or clean is None:
        raise ValueError(f"Zły zapis stanu: {province!r} {kind!r} {key!r}")
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > R.MAX_PAYLOAD_BYTES:
        raise ValueError("Stan jest za duży do zapisu.")
    packed = gzip.compress(raw, compresslevel=6)
    async with database.transaction():
        await database.execute(
            delete(T).where(and_(T.c.province == prov, T.c.kind == kind, T.c.key == clean))
        )
        await database.execute(
            T.insert().values(
                province=prov,
                kind=kind,
                key=clean,
                payload_gz=packed,
                size=len(packed),
                fetched_at=_now(),
                source=source,
                fetched_by=fetched_by,
            )
        )
    return len(packed)


async def _last_auto(province: str) -> Optional[_dt.datetime]:
    from app.db import database, zprp_report_snapshots as T

    return await database.fetch_val(
        select(func.max(T.c.fetched_at)).where(
            and_(T.c.province == province, T.c.source == R.SOURCE_AUTO, T.c.kind == "competitions_meta")
        )
    )


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------


@router.get("/snapshot")
async def read_snapshot(
    province: str = Query(...),
    kind: str = Query(...),
    key: str = Query(""),
    jwt: dict = Depends(get_jwt_payload),
):
    from app.db import database, zprp_report_snapshots as T

    prov = await _require_province(jwt, province)
    clean = R.clean_key(key)
    if not R.valid_kind(kind) or clean is None:
        raise HTTPException(400, "Nieznany rodzaj danych albo zły klucz.")
    row = await database.fetch_one(
        select(T).where(and_(T.c.province == prov, T.c.kind == kind, T.c.key == clean))
    )
    if not row:
        raise HTTPException(404, "Brak zapisanego stanu.")
    payload = json.loads(gzip.decompress(row["payload_gz"]).decode("utf-8"))
    return {
        "province": prov,
        "kind": kind,
        "key": clean,
        "fetched_at": _iso(row["fetched_at"]),
        "source": row["source"],
        "fetched_by": row["fetched_by"],
        "stale": R.is_stale(kind, row["fetched_at"], _now()),
        "auto_province": prov in configured_provinces(),
        "payload": payload,
    }


@router.get("/snapshots")
async def list_snapshots(province: str = Query(...), jwt: dict = Depends(get_jwt_payload)):
    from app.db import database, zprp_report_snapshots as T

    prov = await _require_province(jwt, province)
    rows = await database.fetch_all(
        select(T.c.kind, T.c.key, T.c.size, T.c.fetched_at, T.c.source, T.c.fetched_by)
        .where(T.c.province == prov)
        .order_by(T.c.kind, T.c.key)
    )
    return {
        "province": prov,
        "auto_province": prov in configured_provinces(),
        "items": [{**dict(r), "fetched_at": _iso(r["fetched_at"])} for r in rows],
    }


@router.post("/snapshot")
async def write_snapshot(body: Dict[str, Any] = Body(...), jwt: dict = Depends(get_jwt_payload)):
    prov = await _require_province(jwt, body.get("province"))
    kind = str(body.get("kind") or "")
    key = R.clean_key(body.get("key"))
    if not R.valid_kind(kind) or key is None:
        raise HTTPException(400, "Nieznany rodzaj danych albo zły klucz.")
    payload = body.get("payload")
    if not isinstance(payload, dict) or not payload:
        raise HTTPException(400, "Brak danych do zapisu.")
    try:
        size = await save_snapshot(
            prov, kind, key, payload, source=R.SOURCE_MANUAL, fetched_by=str(jwt.get("sub") or "")
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "size": size, "fetched_at": _iso(_now())}


# ---------------------------------------------------------------------------
# Automat
# ---------------------------------------------------------------------------


def _encrypt_for_self(text: str) -> str:
    """Trasy `/zprp/*` przyjmują dane logowania zaszyfrowane kluczem serwera - automat szyfruje sam sobie."""
    _, public_key = get_rsa_keys()
    return base64.b64encode(public_key.encrypt(text.encode("utf-8"), padding.PKCS1v15())).decode("ascii")


async def refresh_province(province: str) -> Dict[str, Any]:
    """Nocny przebieg dla okręgu: terminarz, rozgrywki i statystyki domyślnych rozgrywek."""
    from app.schemas import ZprpScheduleScrapeRequest, ZprpStatsScrapeRequest
    from app.zprp import competitions, schedule, stats

    creds = credentials_for(province, "sync")
    if not creds:
        return {"province": province, "skipped": "brak konta sync"}
    user, password = creds
    enc_user, enc_pass = _encrypt_for_self(user), _encrypt_for_self(password)
    settings, keys = get_settings(), get_rsa_keys()
    done: Dict[str, Any] = {}

    async def step(kind: str, key: str, call):
        try:
            result = await call()
            if hasattr(result, "body") and not isinstance(result, dict):  # JSONResponse
                result = json.loads(result.body)
            await save_snapshot(province, kind, key, result, source=R.SOURCE_AUTO, fetched_by="serwer")
            done[f"{kind}:{key}"] = "ok"
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # jeden błędny krok nie zatrzymuje pozostałych
            logger.warning("[reports] %s %s/%s: %s", province, kind, key, exc)
            done[f"{kind}:{key}"] = f"błąd: {str(exc)[:200]}"
            return None

    sched_req = lambda **kw: ZprpScheduleScrapeRequest(username=enc_user, password=enc_pass, **kw)  # noqa: E731
    stats_req = lambda **kw: ZprpStatsScrapeRequest(username=enc_user, password=enc_pass, **kw)  # noqa: E731

    meta = await step("schedule_meta", "", lambda: schedule.get_terminarz_meta(sched_req(), settings, keys))
    season = str((meta or {}).get("Filtr_sezon") or "").strip()
    if season:
        await save_snapshot(province, "schedule_meta", season, meta, source=R.SOURCE_AUTO, fetched_by="serwer")
        await step("schedule_full", season, lambda: schedule.scrape_terminarz_full(sched_req(season_id=season), settings, keys))

    # competitions_meta zapisywane jako znacznik nocnego przebiegu (`_last_auto`).
    cmeta = await step("competitions_meta", "", lambda: competitions.get_rozgrywki_meta(sched_req(), settings, keys))
    newest = R.newest_season(cmeta or {})
    if newest:
        await step("competitions_lite", newest, lambda: competitions.scrape_rozgrywki_lite(sched_req(season_id=newest), settings, keys))

    await step("stats_table", "", lambda: stats.get_league_table(stats_req(), settings, keys))
    await step("stats_teams", "", lambda: stats.get_team_stats(stats_req(), settings, keys))
    await step("stats_scorers", "", lambda: stats.get_top_scorers(stats_req(), settings, keys))
    return {"province": province, "steps": done}


async def run_report_snapshot_scheduler() -> None:
    """Co 30 min sprawdza okręgi z kontem `sync`; przebieg nocą raz na dobę (pierwszy od razu)."""
    import os

    if os.getenv("ZPRP_REPORT_SNAPSHOTS", "1").strip() in ("0", "false", "off"):
        logger.info("[reports] automat wyłączony (ZPRP_REPORT_SNAPSHOTS)")
        return
    await asyncio.sleep(10 * 60)  # niech ruszą synchronizacje ważniejsze dla powiadomień
    while True:
        try:
            for province in sorted(configured_provinces()):
                if not R.nightly_due(await _last_auto(province), _now()):
                    continue
                tried = _attempted.get(province)
                if tried and _now() - tried < RETRY_AFTER:
                    continue
                _attempted[province] = _now()
                logger.info("[reports] odświeżam zapisane stany %s", province)
                result = await refresh_province(province)
                logger.info("[reports] %s: %s", province, result.get("steps") or result)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("[reports] pętla dobowa")
        await asyncio.sleep(30 * 60)
