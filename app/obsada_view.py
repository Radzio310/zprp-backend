"""
Obsada na zywo (12.11.2026) - tylko-do-odczytu podglad obsady okregowej.

Dostep per okreg: off / app (zalogowani sedziowie okregu) / link (+ tajny link
`bazapodreka.app/obsada;<token>`). Wlacza komisja okregu swoj okreg, admin
kazdy. Dane to migawka `province_matches` (to, co w ZPRP) przez ten sam
`match_list_payload` co Obsada 2.0 - nigdy szkice. Reguly w
`app/obsada_view_rules.py`, tabele w `app/obsada_view_tables.py`.

Kto zarzadza ("komisja okregu"): admin aplikacji, Master `match` tego okregu
(sedzia z tokenem) albo konto VIP z panelem `assignments` (token org, ta sama
regula co bramka Obsady w BAZA_web).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from app import obsada_view_rules as R
from app.db import database, province_judges
from app.deps import _beach_auth_secret, get_jwt_payload
from app.obsada_view_tables import obsada_changes, obsada_view
from app.settlement_province import DISPLAY, canonical, spellings

log = logging.getLogger(__name__)

router = APIRouter(tags=["obsada_view"])

LINK_BASE = "https://bazapodreka.app/obsada;"
CACHE_TTL = 30.0
_cache: dict[str, tuple[float, dict]] = {}
_locks: dict[str, asyncio.Lock] = {}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _secret() -> str:
    return _beach_auth_secret() + ":obsada-ics"


# --- ustawienia okregu --------------------------------------------------------

async def _row(province: str, create: bool = True) -> Optional[dict]:
    row = await database.fetch_one(select(obsada_view).where(obsada_view.c.province == province))
    if row is not None:
        return dict(row)
    if not create:
        return None
    for _ in range(5):
        try:
            await database.execute(insert(obsada_view).values(
                province=province, mode=R.DEFAULT_MODE, token=R.new_token()))
            break
        except IntegrityError:
            row = await database.fetch_one(select(obsada_view).where(obsada_view.c.province == province))
            if row is not None:
                return dict(row)
    row = await database.fetch_one(select(obsada_view).where(obsada_view.c.province == province))
    return dict(row) if row else None


def _settings_view(row: dict, *, with_link: bool) -> dict:
    out = {"province": row["province"], "mode": row["mode"],
           "updated_by": row.get("updated_by"),
           "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None}
    if with_link:
        out["token"] = row["token"]
        out["link"] = LINK_BASE + row["token"] if row["mode"] == "link" else None
    return out


# --- kto pyta ----------------------------------------------------------------

async def _viewer(payload: dict, province: str) -> dict:
    """{admin, manage, view} dla tokenu wobec okregu (klucz kanoniczny)."""
    from app.admin_alerts import admin_judge_ids

    judge_id = _s(payload.get("judge_id"))
    if judge_id:
        admin = judge_id in {_s(x) for x in await admin_judge_ids()}
        manage = admin
        if not manage:
            from app.province_guard import _read_access_lists
            from app.province_access import may_write_province

            masters, admins = await _read_access_lists("match", province)
            manage = may_write_province(judge_id=judge_id, master_judge_ids=masters, admin_ids=admins)
        view = manage
        if not view:
            row = await database.fetch_one(
                select(province_judges.c.province).where(province_judges.c.judge_id == judge_id))
            view = bool(row) and canonical(row["province"]) == province
        return {"admin": admin, "manage": manage, "view": view, "who": judge_id}
    # Konto organizacji (VIP BAZA_web): panel Obsady swojego okregu.
    from app.province_panel_guard import ensure_panel_write

    try:
        await ensure_panel_write(payload, province=province, panel="assignments",
                                 action="Obsada na żywo")
        ok = True
    except HTTPException:
        ok = False
    return {"admin": False, "manage": ok, "view": ok, "who": "o" + _s(payload.get("sub"))}


async def _require(payload: dict, province: str, need: str) -> dict:
    who = await _viewer(payload, province)
    if not who[need]:
        raise HTTPException(403, "Ustawienia Obsady na żywo zmienia komisja okręgu albo administrator."
                            if need == "manage" else "Podgląd obsady jest dla sędziów tego okręgu.")
    return who


def _key(province: str) -> str:
    key = canonical(province)
    if not key:
        raise HTTPException(400, f"Nieznane województwo: {province}")
    return key


# --- dane ----------------------------------------------------------------------

def _changed_map(rows: list) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in rows:
        at = row["at"].isoformat()
        if at > out.get(row["match_id"], ""):
            out[row["match_id"]] = at
    return out


async def _season_payload(province: str) -> dict:
    """Caly biezacy sezon okregu; krotki cache, bo klienci pytaja co 60 s."""
    hit = _cache.get(province)
    if hit and time.monotonic() - hit[0] < CACHE_TTL:
        return hit[1]
    lock = _locks.setdefault(province, asyncio.Lock())
    async with lock:
        hit = _cache.get(province)
        if hit and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[1]
        from app.province_assignments import match_list_payload

        base = await match_list_payload(province, include_past=True, when="all",
                                        include_league=True, limit=None)
        changed = _changed_map(await database.fetch_all(
            select(obsada_changes.c.match_id, obsada_changes.c.at)
            .where(obsada_changes.c.province == province)
            .where(obsada_changes.c.at >= datetime.now(timezone.utc) - timedelta(days=30))))
        roster = R.Roster(await database.fetch_all(
            select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url)
            .where(province_judges.c.province.in_(spellings(province)))))
        matches, halls = [], {}
        stamp = ""
        for item in base["matches"]:
            crew = item["crew"]
            # Cudze mecze (np. Liga Juniorow z innego okregu) tylko z naszym sedzia w obsadzie.
            if not R.keep_match((item.get("access") or {}).get("organizer_kind"), crew, roster):
                continue
            row = {
                "match_id": item["match_id"], "code": item["code"],
                "competition": item["competition"],
                "competition_label": item["competition_label"],
                "category": item["category"], "level": item["level"],
                "match_at": item["match_at"],
                "round_label": item["round_name"] or item["round"] or None,
                "host": item["host"], "guest": item["guest"],
                "host_logo": None, "guest_logo": None,
                "score": item["score"], "status_live": None,
                "hall": item["hall"], "city": item["city"], "address": item["address"],
                "lat": None, "lng": None,
                "crew": R.crew_view(crew, roster), "needs": R.needs_view(crew, item["needs"]),
                "changed_at": changed.get(item["match_id"]),
            }
            matches.append(row)
            stamp = max(stamp, item["updated_at"] or "")
            if item["hall"]:
                halls.setdefault((item["hall"], item["city"]),
                                 {"hall": item["hall"], "city": item["city"], "lat": None, "lng": None})
        data = {"season": base["season"], "updated_at": stamp or None,
                "matches": matches, "halls": list(halls.values())}
        _cache[province] = (time.monotonic(), data)
        return data


def _day(value: Any) -> Optional[str]:
    text = _s(value)
    return text[:10] if text else None


async def view_payload(province: str, mode: str, date_from: Optional[str], date_to: Optional[str]) -> dict:
    data = await _season_payload(province)
    lo, hi = _day(date_from), _day(date_to)
    # Widok (filtr dat + rev) liczony raz na okno i wersje danych: klienci pytaja co 60 s,
    # a compute_rev to json.dumps calego sezonu. Cache zyje w `data`, wiec odswieza sie z nim.
    views = data.setdefault("_views", {})
    vkey = (mode, lo, hi)
    hit = views.get(vkey)
    if hit is not None:
        return hit
    matches = [m for m in data["matches"]
               if not (lo or hi) or (m["match_at"] and (not lo or m["match_at"][:10] >= lo)
                                     and (not hi or m["match_at"][:10] <= hi))]
    used = {(m["hall"], m["city"]) for m in matches}
    halls = [h for h in data["halls"] if (h["hall"], h["city"]) in used]
    out = {"province": province, "mode": mode, "season": data["season"],
           "updated_at": data["updated_at"],
           "rev": R.compute_rev(matches, f"{data['updated_at']}|{mode}"),
           "matches": matches, "halls": halls}
    if len(views) >= 16:
        views.clear()
    views[vkey] = out
    return out


def _reply(request: Request, payload: dict) -> Response:
    headers = {"ETag": f'"{payload["rev"]}"', "Cache-Control": "private, max-age=0, must-revalidate"}
    if R.etag_matches(request.headers.get("if-none-match"), payload["rev"]):
        return Response(status_code=304, headers=headers)
    return JSONResponse(payload, headers=headers)


async def _link_province(token: str) -> tuple[str, dict]:
    if not R.valid_token(token):
        raise HTTPException(404, "Nie ma takiego linku.")
    row = await database.fetch_one(select(obsada_view).where(obsada_view.c.token == token))
    if row is None or row["mode"] != "link":
        raise HTTPException(404, "Ten link nie działa (wyłączony albo zmieniony).")
    return row["province"], dict(row)


async def _app_province(payload: dict, province: str) -> tuple[str, dict, dict]:
    key = _key(province)
    who = await _require(payload, key, "view")
    row = await _row(key)
    if row["mode"] not in ("app", "link"):
        raise HTTPException(403, "Obsada na żywo jest w tym okręgu wyłączona.")
    return key, row, who


# --- zarzadzanie --------------------------------------------------------------

class ModeBody(BaseModel):
    mode: str


@router.get("/province/obsada-view/settings", summary="Ustawienia Obsady na żywo")
async def get_settings_route(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    key = _key(province)
    await _require(payload, key, "manage")
    return _settings_view(await _row(key), with_link=True)


@router.put("/province/obsada-view/settings", summary="Zmień tryb dostępu")
async def put_settings(body: ModeBody, province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    key = _key(province)
    mode = R.normalize_mode(body.mode)
    if mode is None:
        raise HTTPException(400, "Tryb to off, app albo link.")
    who = await _require(payload, key, "manage")
    await _row(key)
    await database.execute(update(obsada_view).where(obsada_view.c.province == key)
                           .values(mode=mode, updated_by=who["who"], updated_at=datetime.now(timezone.utc)))
    return _settings_view(await _row(key), with_link=True)


@router.post("/province/obsada-view/rotate", summary="Nowy link (stary przestaje działać)")
async def rotate(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    key = _key(province)
    who = await _require(payload, key, "manage")
    await _row(key)
    for _ in range(5):
        try:
            await database.execute(update(obsada_view).where(obsada_view.c.province == key)
                                   .values(token=R.new_token(), updated_by=who["who"],
                                           updated_at=datetime.now(timezone.utc)))
            break
        except IntegrityError:
            continue
    return _settings_view(await _row(key), with_link=True)


@router.get("/province/obsada-view/all", summary="Tryby wszystkich okręgów (admin)")
async def all_provinces(payload: dict = Depends(get_jwt_payload)):
    from app.admin_alerts import admin_judge_ids

    if _s(payload.get("judge_id")) not in {_s(x) for x in await admin_judge_ids()}:
        raise HTTPException(403, "Tylko administrator widzi wszystkie okręgi.")
    rows = {r["province"]: dict(r) for r in await database.fetch_all(select(obsada_view))}
    return {"provinces": [
        {"province": key, "display": name, "mode": (rows.get(key) or {}).get("mode", R.DEFAULT_MODE),
         "link": (LINK_BASE + rows[key]["token"]) if rows.get(key, {}).get("mode") == "link" else None}
        for key, name in DISPLAY.items()]}


# --- dane: link i aplikacja --------------------------------------------------

@router.get("/public/obsada/{token}", summary="Obsada na żywo przez tajny link")
async def public_data(token: str, request: Request, date_from: Optional[str] = Query(None, alias="from"),
                      date_to: Optional[str] = Query(None, alias="to")):
    province, row = await _link_province(token)
    return _reply(request, await view_payload(province, row["mode"], date_from, date_to))


@router.get("/province/obsada-view/data", summary="Obsada na żywo w aplikacji")
async def app_data(request: Request, province: str = Query(...), date_from: Optional[str] = Query(None, alias="from"),
                   date_to: Optional[str] = Query(None, alias="to"), payload: dict = Depends(get_jwt_payload)):
    key, row, _ = await _app_province(payload, province)
    return _reply(request, await view_payload(key, row["mode"], date_from, date_to))


# --- dziennik zmian ----------------------------------------------------------

async def _changes(province: str, since: Optional[str]) -> dict:
    try:
        start = datetime.fromisoformat(_s(since).replace("Z", "+00:00")) if since else None
    except ValueError:
        raise HTTPException(400, "Zły format `since` (ISO 8601).")
    if start is None:
        start = datetime.now(timezone.utc) - timedelta(days=14)
    elif start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    rows = await database.fetch_all(
        select(obsada_changes).where(obsada_changes.c.province == province)
        .where(obsada_changes.c.at > start).order_by(obsada_changes.c.at.desc()).limit(500))
    known = {m["match_id"]: m for m in (await _season_payload(province))["matches"]}
    out = []
    for row in rows:
        match = known.get(row["match_id"])
        if match is None:
            continue
        out.append({"match_id": row["match_id"], "code": match["code"], "host": match["host"],
                    "guest": match["guest"], "match_at": match["match_at"], "kind": row["kind"],
                    "before": json.loads(row["before"]) if row["before"] else None,
                    "after": json.loads(row["after"]) if row["after"] else None,
                    "at": row["at"].isoformat()})
    return {"province": province, "since": start.isoformat(), "changes": out[:200]}


@router.get("/public/obsada/{token}/changes", summary="Zmiany obsady (link)")
async def public_changes(token: str, since: Optional[str] = Query(None)):
    province, _ = await _link_province(token)
    return await _changes(province, since)


@router.get("/province/obsada-view/changes", summary="Zmiany obsady (aplikacja)")
async def app_changes(province: str = Query(...), since: Optional[str] = Query(None),
                      payload: dict = Depends(get_jwt_payload)):
    key, _, _ = await _app_province(payload, province)
    return await _changes(key, since)


async def record_changes(province: str, match_id: str, old_state: dict, new_state: dict,
                         old_at: Any, new_at: Any) -> int:
    """Zaczep monitora: zapisuje roznice obsady/terminu. Nigdy nie rzuca."""
    try:
        key = canonical(province) or _s(province)
        diffs = R.diff_changes(old_state or {}, new_state or {}, old_at, new_at)
        for diff in diffs:
            await database.execute(insert(obsada_changes).values(
                province=key, match_id=_s(match_id), kind=diff["kind"],
                before=json.dumps(diff["before"], ensure_ascii=False) if diff["before"] is not None else None,
                after=json.dumps(diff["after"], ensure_ascii=False) if diff["after"] is not None else None))
        return len(diffs)
    except Exception:  # noqa: BLE001 - monitor nie moze na tym paść
        log.debug("obsada changes hook skipped", exc_info=True)
        return 0


# --- .ics sedziego -------------------------------------------------------------

def _ics_response(payload: dict, key: str) -> Response:
    if not R.safe_key(key):
        raise HTTPException(404, "Nie ma takiego sędziego.")
    body = R.build_ics(payload["matches"], key, calendar_name=f"Obsada {payload['province']}")
    return Response(body, media_type="text/calendar; charset=utf-8",
                    headers={"Content-Disposition": 'inline; filename="obsada.ics"'})


@router.get("/public/obsada/{token}/sedzia/{key_ics}", summary="Kalendarz .ics sędziego (link)")
async def public_ics(token: str, key_ics: str):
    if not key_ics.endswith(".ics"):
        raise HTTPException(404, "Oczekiwano adresu .ics.")
    province, row = await _link_province(token)
    return _ics_response(await view_payload(province, row["mode"], None, None), key_ics[:-4])


@router.get("/province/obsada-view/ics-link", summary="Stały podpisany adres .ics sędziego")
async def ics_link(province: str = Query(...), judge_key: str = Query(...),
                   payload: dict = Depends(get_jwt_payload)):
    key, row, who = await _app_province(payload, province)
    if not R.safe_key(judge_key):
        raise HTTPException(400, "Zły klucz sędziego.")
    scope = "".join(ch for ch in who["who"] if ch.isalnum()) or "u"
    sig = R.sign_ics(_secret(), key, scope, judge_key, row["token"])
    path = f"/public/obsada/ics/{key}/{scope}/{judge_key}/{sig}.ics"
    return {"path": path, "judge_key": judge_key}


@router.get("/public/obsada/ics/{province}/{scope}/{judge_key}/{sig_ics}", summary="Kalendarz .ics (podpisany)")
async def signed_ics(province: str, scope: str, judge_key: str, sig_ics: str):
    if not sig_ics.endswith(".ics"):
        raise HTTPException(404, "Oczekiwano adresu .ics.")
    key = canonical(province)
    row = await _row(key, create=False) if key else None
    if row is None or row["mode"] == "off" or not R.verify_ics(
            _secret(), key, scope, judge_key, row["token"], sig_ics[:-4]):
        raise HTTPException(404, "Ten adres kalendarza nie działa.")
    return _ics_response(await view_payload(key, row["mode"], None, None), judge_key)
