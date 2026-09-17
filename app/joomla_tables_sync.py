"""Dobowa publikacja śląskich stolików ligowych do Joomla Media Manager."""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, select

from app.db import database, joomla_table_publications, zprp_archive_officials, zprp_archive_seasons
from app.deps import get_jwt_payload
from app.province_stats_export import ExportColumn, ExportMeta, ExportSection, ReportExportRequest, _render_pdf, enrich_table_official_rows
from app.zprp_archive import current_start, season_catalog

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/province/tables-publication", tags=["tables_publication"])

PROVINCE = "SLASKIE"
MEDIA_PAGE = "https://slzpr.com.pl/administrator/index.php?option=com_media&path=local-images:/dokumenty"
MEDIA_API = "https://slzpr.com.pl/administrator/index.php"
PUBLIC_BASE = "https://slzpr.com.pl/images/dokumenty"
INTERVAL = 24 * 60 * 60
WARSAW = ZoneInfo("Europe/Warsaw")
_sync_lock = asyncio.Lock()


def _as_dict(value: Any) -> dict:
    if isinstance(value, str):
        return json.loads(value)
    return value or {}


def _tier(code: str) -> str:
    prefix = str(code or "").split("/", 1)[0].upper()
    if prefix.startswith(("MP", "PP", "SP")):
        return "cup"
    if prefix.startswith(("SK", "SM", "OSK", "OSM", "LCK", "LCM", "IK", "IM", "IIK", "IIM")):
        return "central"
    return "district"


def _accent(code: str) -> str:
    colors = {
        "IIIM": "#ffaa00", "IIIK": "#ffaa00", "IIM": "#ffd6a5", "IIK": "#ffd6a5",
        "IK": "#e56b6f", "IM": "#e56b6f", "LCM": "#8338ec", "LCK": "#8338ec",
        "OSM": "#3a86ff", "OSK": "#3a86ff", "MP": "#cb997e", "PP": "#ddbea9",
        "SPM": "#F72585", "SPK": "#F72585", "SM": "#bb9457", "SK": "#936639",
    }
    prefix = str(code or "").split("/", 1)[0].upper()
    return colors.get(prefix, "#888888")


def _person(match: dict, role: str, officials: dict) -> str:
    ref_id = str((match.get("refs") or {}).get(role) or "")
    info = officials.get(ref_id) or {}
    return str(info.get("name") or (match.get("refNames") or {}).get(role) or "—")


def _date_time(match: dict) -> tuple[str, str, int]:
    stamp = match.get("ts") if match.get("ts") is not None else match.get("tsProp")
    stamp = int(stamp or 0)
    if not stamp:
        return "—", "—", 0
    dt = datetime.fromtimestamp(stamp / 1000, tz=timezone.utc).astimezone(WARSAW)
    return dt.strftime("%d.%m.%Y"), dt.strftime("%H:%M"), stamp


async def _current_payload() -> tuple[str, str, list[dict], dict]:
    catalog = await season_catalog()
    start = current_start(catalog, datetime.now(timezone.utc).date())
    season = next((item for item in catalog.values() if item.start == start), None)
    if season is None:
        raise RuntimeError("Nie znaleziono bieżącego sezonu ZPRP")
    row = await database.fetch_one(select(zprp_archive_seasons.c.payload_gz).where(and_(
        zprp_archive_seasons.c.province == PROVINCE,
        zprp_archive_seasons.c.season_id == season.id,
    )))
    roster = await database.fetch_one(select(zprp_archive_officials.c.officials_json).where(
        zprp_archive_officials.c.province == PROVINCE
    ))
    if not row or not row["payload_gz"] or not roster:
        raise RuntimeError("Archiwum bieżącego sezonu lub lista sędziów nie są jeszcze gotowe")
    payload = json.loads(gzip.decompress(bytes(row["payload_gz"])))
    return season.id, season.label, list(payload.get("matches") or []), _as_dict(roster["officials_json"])


async def _report(season_id: str, season_label: str, matches: list[dict], officials: dict) -> tuple[ReportExportRequest, list[dict], str]:
    ids = {str(key) for key in officials}
    selected = []
    for match in matches:
        refs = match.get("refs") or {}
        if _tier(str(match.get("code") or "")) not in {"central", "cup"}:
            continue
        if not any(str(refs.get(role) or "") in ids for role in ("secretary", "timer")):
            continue
        date, time_label, stamp = _date_time(match)
        selected.append((stamp, match, date, time_label))
    selected.sort(key=lambda item: (item[0], str(item[1].get("code") or "")), reverse=True)
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    rows = [{
        "lp": index,
        "date": date,
        "time": time_label,
        "code": str(match.get("code") or "—"),
        "match_id": str(match.get("id") or ""),
        "match_url": f"https://rozgrywki.zprp.pl/index.php?a=zawody&b=protokol&IdZawody={match.get('id')}" if match.get("id") else "",
        "accent": _accent(str(match.get("code") or "")),
        "home": str(match.get("home") or "—"),
        "away": str(match.get("away") or "—"),
        # Ulica i numer zostaną dociągnięte z API szczegółów. Przy chwilowej
        # awarii zostaje samo miasto — nigdy nazwa obiektu udająca adres.
        "hall": str(match.get("city") or "—"),
        "secretary": _person(match, "secretary", officials),
        "timer": _person(match, "timer", officials),
        "past": bool(stamp and stamp < now_ms),
    } for index, (_, match, date, time_label) in enumerate(selected, 1)]
    short = season_label.replace("20", "").replace("/", "_")
    filename = f"stoliki_{short}.pdf"
    request = ReportExportRequest(
        meta=ExportMeta(province="ŚLĄSKIE", season=season_label, title="Stoliki ligowe na okręgu", filters=[]),
        sections=[ExportSection(
            title="Stoliki ligowe", subtitle="", tiles=[{"label": "Stolików", "value": str(len(rows))}],
            columns=[ExportColumn(key=key, label=label) for key, label in (
                ("lp", "Lp"), ("date", "Data"), ("time", "Godzina"), ("code", "Zawody"),
                ("home", "Gospodarz"), ("away", "Gość"), ("hall", "Hala"),
                ("secretary", "Sekretarz"), ("timer", "Mierzący czas"),
            )], rows=rows,
        )],
        filename=filename[:-4],
    )
    await enrich_table_official_rows(request)
    # Dzień jest częścią odcisku świadomie: nawet bez zmiany obsady codzienny
    # dokument odświeża stan wizualny meczów, które właśnie stały się minione.
    canonical = json.dumps({"season": season_id, "day": datetime.now(WARSAW).date().isoformat(), "rows": request.sections[0].rows}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return request, request.sections[0].rows, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _script_options(html: str) -> dict:
    for raw in re.findall(r'<script[^>]+class="[^"]*joomla-script-options[^"]*"[^>]*>(.*?)</script>', html, re.S):
        try:
            data = json.loads(raw)
            if data.get("com_media"):
                return data
        except Exception:
            pass
    raise RuntimeError("Joomla nie zwróciła konfiguracji menedżera mediów")


async def _upload_joomla(path: str, filename: str) -> None:
    username, password = os.getenv("JOOMLA_USERNAME"), os.getenv("JOOMLA_PASSWORD")
    if not username or not password:
        raise RuntimeError("Brak JOOMLA_USERNAME lub JOOMLA_PASSWORD")
    async with httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(60.0)) as client:
        login = await client.get(MEDIA_PAGE)
        login.raise_for_status()
        token_match = re.search(r'name="([a-f0-9]{32})"\s+value="1"', login.text)
        return_match = re.search(r'name="return"\s+value="([^"]+)"', login.text)
        if not token_match:
            raise RuntimeError("Nie znaleziono tokenu logowania Joomla")
        auth = await client.post("https://slzpr.com.pl/administrator/index.php", data={
            "username": username, "passwd": password, "option": "com_login", "task": "login",
            "return": return_match.group(1) if return_match else "", token_match.group(1): "1",
        })
        auth.raise_for_status()
        media = await client.get(MEDIA_PAGE)
        media.raise_for_status()
        options = _script_options(media.text)
        config, csrf = options["com_media"], options.get("csrf.token") or options["com_media"].get("csrfToken")
        if "form-login" in media.text or not csrf:
            raise RuntimeError("Logowanie do Joomla nie powiodło się")
        with open(path, "rb") as source:
            content = base64.b64encode(source.read()).decode("ascii")
        query = urlencode({"option": "com_media", "format": "json", "mediatypes": "0,1,2,3", "task": "api.files", "path": "local-images:/dokumenty"})
        uploaded = await client.post(f"{MEDIA_API}?{query}", json={csrf: "1", "name": filename, "content": content, "override": True})
        uploaded.raise_for_status()
        body = uploaded.json()
        if not body.get("success", True) and not body.get("data"):
            raise RuntimeError(str(body.get("message") or "Joomla odrzuciła plik"))
        # Nie zapisujemy sukcesu wyłącznie na podstawie odpowiedzi panelu. Publiczna
        # ścieżka ma już zwracać PDF — cachebuster zapobiega odczytaniu starej kopii.
        public = None
        cache_key = hashlib.sha256(content[:2048].encode()).hexdigest()[:12]
        for attempt in range(3):
            public = await client.get(f"{PUBLIC_BASE}/{filename}?v={cache_key}-{attempt}")
            if public.status_code == 200 and public.content.startswith(b"%PDF"):
                break
            await asyncio.sleep(1.5)
        if public is None or public.status_code != 200 or not public.content.startswith(b"%PDF"):
            code = public.status_code if public is not None else "brak odpowiedzi"
            raise RuntimeError(f"Joomla przyjęła plik, ale publiczny PDF nie jest dostępny (HTTP {code})")


async def sync_tables_to_joomla(trigger: str = "scheduled") -> dict:
    if _sync_lock.locked():
        return {"status": "running", "changed": False, "message": "Sprawdzenie już trwa"}
    async with _sync_lock:
        return await _sync_tables_to_joomla(trigger)


async def _sync_tables_to_joomla(trigger: str) -> dict:
    checked_at = datetime.now(timezone.utc)
    season_id = season_label = fingerprint = previous = None
    filename = "stoliki_26_27.pdf"
    matches_count = 0
    try:
        season_id, season_label, matches, officials = await _current_payload()
        request, rows, fingerprint = await _report(season_id, season_label, matches, officials)
        filename, matches_count = f"stoliki_{season_label[2:4]}_{season_label[-2:]}.pdf", len(rows)
        latest = await database.fetch_one(select(joomla_table_publications.c.fingerprint).where(
            joomla_table_publications.c.status == "published"
        ).order_by(joomla_table_publications.c.id.desc()).limit(1))
        previous = latest["fingerprint"] if latest else None
        if fingerprint == previous:
            status, changed, message = "unchanged", False, "Brak zmian w obsadach — bez publikacji"
        else:
            response = _render_pdf(request, "stoliki_ligowe", "okreg_stoliki.html")
            pdf_path = Path(str(response.path))
            try:
                await _upload_joomla(str(pdf_path), filename)
            finally:
                pdf_path.unlink(missing_ok=True)
            status, changed, message = "published", True, "PDF wygenerowany i nadpisany w Joomla"
    except Exception as exc:
        logger.exception("[joomla-tables] synchronizacja nie powiodła się")
        status, changed, message = "error", False, str(exc)[:1000]
    public_url = f"{PUBLIC_BASE}/{filename}"
    await database.execute(joomla_table_publications.insert().values(
        checked_at=checked_at, season_id=season_id, season_label=season_label, filename=filename,
        fingerprint=fingerprint, previous_fingerprint=previous, status=status, trigger=trigger, changed=changed,
        matches=matches_count, message=message, public_url=public_url,
    ))
    return {"status": status, "changed": changed, "matches": matches_count, "filename": filename, "message": message}


async def run_joomla_tables_scheduler() -> None:
    while True:
        await sync_tables_to_joomla()
        await asyncio.sleep(INTERVAL)


@router.get("/history")
async def publication_history(limit: int = Query(80, ge=1, le=365)):
    rows = await database.fetch_all(select(joomla_table_publications).order_by(
        joomla_table_publications.c.id.desc()
    ).limit(limit))
    return {"province": "ŚLĄSKIE", "items": [dict(row) for row in rows]}


@router.post("/check-now")
async def check_now(_payload: dict = Depends(get_jwt_payload)):
    """Ręczne sprawdzenie z panelu VIP; operacja jest deterministyczna i wymaga logowania."""
    return await sync_tables_to_joomla("manual")
