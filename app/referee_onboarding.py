"""Kreator nowych sędziów na baza.zprp.pl - trasy (09.11.2026).

Panel okręgowy BAZA_web, Lista sędziów okręgowych -> „Dodaj nowego sędziego na
baza.zprp.pl". Każda trasa wymaga JWT i uprawnienia panelu `province_judges`
dla okręgu z żądania (`panel_read_gate`), a trasy rozmawiające z ZPRP dostają
dodatkowo zaszyfrowany login i hasło do baza.zprp.pl (jak `/zprp/sedziowie/*`).
Konto ZPRP musi mieć w „Sędziowie i Delegaci" opcję NOWY - sprawdza `/probe`.

  POST /province_referees/onboarding/probe    - czy konto może zakładać osoby
  POST /province_referees/onboarding/parse    - plik (xlsx/xls/csv) -> wiersze z ukryciem
  POST /province_referees/onboarding/check    - duplikaty w ZPRP dla listy osób
  POST /province_referees/onboarding/create   - załóż JEDNĄ osobę (kreator woła po kolei)
  GET  /province_referees/onboarding/history  - osoby założone w okręgu
  POST /province_referees/onboarding/history/mailed  - oznacz „mail do ZPRP wysłany"
  POST /province_referees/onboarding/history/remove  - usuń wpis z historii (nie z ZPRP)
  POST /province_referees/onboarding/badges          - nadaj badge (i Młodych) osobom z historii

Kontrakt: `docs/kreator-nowych-sedziow.md`. Reguły: `referee_onboarding_rules.py`.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from httpx import AsyncClient
from pydantic import BaseModel, Field
from sqlalchemy import delete, desc, select, update

from app import referee_onboarding_rules as R
from app.db import (
    database,
    province_judges,
    province_referee_onboarding,
    province_referee_onboarding_badges,
    province_settlement_judges,
    young_referees,
)
from app.deps import Settings, get_jwt_payload, get_rsa_keys, get_settings
from app.province_panel_access import PANEL_PROVINCE_JUDGES
from app.province_panel_guard import panel_read_gate
from app.referee_onboarding_excel import SheetError, read_table
from app.settlement_province import spellings
from app.utils import fetch_with_correct_encoding
from app.zprp.officials import (
    _decrypt_field,
    _form_urlencoded_bytes,
    _login_zprp_and_get_cookies,
)

logger = logging.getLogger("app.referee_onboarding")

ADD_PATH = "/index.php?a=sedzia&b=dodaj"
LIST_PATH = "/index.php?a=sedzia&Filtr_archiwum=1"
EDIT_PATH = "/index.php?a=sedzia&b=edycja&NrSedzia={nr}"

_gate = panel_read_gate(PANEL_PROVINCE_JUDGES, "Kreator nowych sędziów")

router = APIRouter(
    prefix="/province_referees/onboarding",
    tags=["RefereeOnboarding"],
    dependencies=[Depends(_gate)],
)


# ---------------------------------------------------------------------------
# Modele
# ---------------------------------------------------------------------------


class ZprpCreds(BaseModel):
    province: str
    username: str
    password: str
    judge_id: Optional[str] = None


class PersonIn(BaseModel):
    key: str = ""
    first_name: str = ""
    middle_name: str = ""
    last_name: str = ""
    maiden_name: str = ""
    gender: str = ""
    birth_date: str = ""
    street: str = ""
    postal_code: str = ""
    city: str = ""
    phone: str = ""
    email: str = ""
    roles: List[str] = Field(default_factory=lambda: ["sedzia"])


class CheckRequest(ZprpCreds):
    people: List[PersonIn] = Field(default_factory=list)


class CreateRequest(ZprpCreds):
    person: PersonIn
    force: bool = False
    source: str = "manual"
    batch_id: str = ""
    #: Badge do nadania zaraz po założeniu (10.11.2026); „young" = rejestr Młodych.
    badges: List[str] = Field(default_factory=list)
    young: bool = False


class BadgesRequest(BaseModel):
    province: str
    ids: List[int] = Field(default_factory=list)
    badges: List[str] = Field(default_factory=list)
    young: bool = False


class HistoryIdsRequest(BaseModel):
    province: str
    ids: List[int] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# ZPRP
# ---------------------------------------------------------------------------


def _creds(payload: ZprpCreds, keys) -> tuple[str, str]:
    private_key, _ = keys
    try:
        return _decrypt_field(private_key, payload.username), _decrypt_field(private_key, payload.password)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Nie udało się odczytać danych logowania: {exc}")


async def _get(client: AsyncClient, path: str, cookies) -> str:
    _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
    return html


async def _registry(province: str) -> List[Dict[str, Any]]:
    """Osoby okręgu znane BAZIE (rejestr sędziów + lista z rozliczeń)."""
    names = spellings(province)
    out: List[Dict[str, Any]] = []
    for table, source in ((province_judges, "BAZA"), (province_settlement_judges, "BAZA")):
        rows = await database.fetch_all(
            select(table.c.judge_id, table.c.full_name).where(table.c.province.in_(names))
        )
        for row in rows:
            out.append(
                {
                    "nr": R.s(row["judge_id"]),
                    "label": R.s(row["full_name"]),
                    "source": source,
                    **R.split_full_name(row["full_name"]),
                }
            )
    return out


async def _duplicates(
    client: AsyncClient,
    cookies,
    people: List[Dict[str, Any]],
    sources: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Dla każdej osoby kandydaci z ZPRP + data urodzenia z karty edycji (gdy dostępna)."""
    per_person = {p["key"]: R.match_candidates(p, sources) for p in people}
    wanted = sorted({m["nr"] for ms in per_person.values() for m in ms if m["relation"] == "same"})[:40]
    births: Dict[str, str] = {}
    sem = asyncio.Semaphore(3)

    async def load(nr: str) -> None:
        async with sem:
            try:
                html = await _get(client, EDIT_PATH.format(nr=nr), cookies)
                births[nr] = R.birth_date_from_edit_page(html)
            except Exception:  # noqa: BLE001 - brak dostępu do karty = data nieznana
                births[nr] = ""

    await asyncio.gather(*(load(nr) for nr in wanted))
    out: Dict[str, Dict[str, Any]] = {}
    for p in people:
        matches = per_person[p["key"]]
        for m in matches:
            if m["nr"] in births:
                m["birth_date"] = births[m["nr"]]
        status = R.classify_duplicate(p, matches)
        out[p["key"]] = {"status": status, "blocking": status in R.BLOCKING, "matches": matches}
    return out


def _sources(add_page: Dict[str, Any], registry: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    zprp = [{**o, "source": "ZPRP"} for o in add_page["options"]]
    return zprp + registry


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------


@router.post("/probe")
async def probe(
    payload: ZprpCreds,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    user, password = _creds(payload, keys)
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user, password)
        list_html = await _get(client, LIST_PATH, cookies)
        new_button = R.has_new_button(list_html)
        page = R.parse_add_page(await _get(client, ADD_PATH, cookies))
    can = bool(page["has_form"] and page["woj_code"])
    reason = ""
    if not can:
        reason = (
            "To konto na baza.zprp.pl nie ma w zakładce „Sędziowie i Delegaci” opcji NOWY. "
            "Zaloguj się kontem okręgu, które może dodawać osoby."
        )
    return {
        "can_create": can,
        "new_button": new_button,
        "reason": reason,
        "woj_code": page["woj_code"],
        "woj_name": page["woj_name"],
        "known_people": len(page["options"]),
    }


@router.post("/parse")
async def parse_file(
    province: str = Query(...),
    file: UploadFile = File(...),
):
    data = await file.read()
    try:
        return await asyncio.to_thread(read_table, data, file.filename or "")
    except SheetError as exc:
        raise HTTPException(400, str(exc))


@router.post("/check")
async def check(
    payload: CheckRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    if len(payload.people) > 300:
        raise HTTPException(400, "Za dużo osób naraz (limit 300).")
    people = [{**R.normalize_person(p.model_dump()), "key": p.key or str(i)} for i, p in enumerate(payload.people)]
    user, password = _creds(payload, keys)
    registry = await _registry(payload.province)
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user, password)
        page = R.parse_add_page(await _get(client, ADD_PATH, cookies))
        results = await _duplicates(client, cookies, people, _sources(page, registry))
    return {"checked_at": _now(), "results": results}


@router.post("/create")
async def create(
    payload: CreateRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
    jwt: dict = Depends(get_jwt_payload),
):
    person = {**R.normalize_person(payload.person.model_dump()), "key": payload.person.key or "0"}
    errors = R.validate_person(person)
    bad = R.encodable(person)
    if bad:
        errors.append("Znaki spoza polskiego alfabetu w polach: " + ", ".join(bad) + ".")
    if errors:
        return {"status": "invalid", "nr": "", "message": " ".join(errors), "errors": errors}

    user, password = _creds(payload, keys)
    registry = await _registry(payload.province)
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        cookies = await _login_zprp_and_get_cookies(client, user, password)
        page = R.parse_add_page(await _get(client, ADD_PATH, cookies))
        if not page["has_form"] or not page["woj_code"]:
            raise HTTPException(403, "To konto na baza.zprp.pl nie ma opcji NOWY w „Sędziowie i Delegaci”.")

        # Drugie sprawdzenie tuż przed zapisem: ponowione kliknięcie nie założy osoby drugi raz.
        dup = (await _duplicates(client, cookies, [person], _sources(page, registry)))[person["key"]]
        if dup["blocking"] and not payload.force:
            return {"status": "duplicate", "nr": "", "message": "Ta osoba prawdopodobnie już jest w ZPRP.", "duplicate": dup}

        form = R.build_form(person, page["woj_code"])
        logger.info(
            "Onboarding: create province=%s by=%s fields=%s roles=%s",
            payload.province,
            jwt.get("sub"),
            sorted(k for k, v in form.items() if v),
            person["roles"],
        )
        resp = await client.post(
            ADD_PATH,
            content=_form_urlencoded_bytes(form, charset="iso-8859-2"),
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-2"},
            cookies=cookies,
        )
        html_after = resp.content.decode("iso-8859-2", errors="replace")
        options_after = None
        try:
            options_after = R.parse_add_page(await _get(client, ADD_PATH, cookies))["options"]
        except Exception:  # noqa: BLE001
            options_after = None
        result = R.detect_result(person, html_after, page["options"], options_after)

    record = None
    if result["status"] in ("created", "unconfirmed"):
        birth = R.parse_date(person["birth_date"])
        record_id = await database.execute(
            province_referee_onboarding.insert().values(
                province=R.s(payload.province).upper(),
                nr_sedzia=result["nr"] or None,
                status=result["status"],
                first_name=person["first_name"],
                last_name=person["last_name"],
                gender=person["gender"],
                birth_year=birth.year if birth else None,
                city=person["city"],
                email=person["email"],
                roles=person["roles"],
                source="import" if payload.source == "import" else "manual",
                batch_id=R.s(payload.batch_id) or None,
                created_by=R.s(jwt.get("sub")),
                created_at=_dt.datetime.utcnow(),
            )
        )
        row = await database.fetch_one(
            select(province_referee_onboarding).where(province_referee_onboarding.c.id == record_id)
        )
        record = _row(row) if row else None
        if row and (R.clean_badges(payload.badges) or payload.young):
            outcome = await _order_badges(row, R.clean_badges(payload.badges), payload.young, jwt)
            record = {**(record or {}), **outcome}
    return {**result, "record": record}


@router.get("/history")
async def history(province: str = Query(...)):
    rows = await database.fetch_all(
        select(province_referee_onboarding)
        .where(province_referee_onboarding.c.province.in_(_province_keys(province)))
        .order_by(desc(province_referee_onboarding.c.created_at))
        .limit(1000)
    )
    items = [_row(r) for r in rows]
    if items:
        orders = await database.fetch_all(
            select(province_referee_onboarding_badges).where(
                province_referee_onboarding_badges.c.record_id.in_([i["id"] for i in items])
            )
        )
        by_id = {o["record_id"]: _badge_row(o) for o in orders}
        for item in items:
            item.update(by_id.get(item["id"], {}))
    return {"items": items}


@router.post("/history/mailed")
async def mark_mailed(payload: HistoryIdsRequest, jwt: dict = Depends(get_jwt_payload)):
    if payload.ids:
        await database.execute(
            update(province_referee_onboarding)
            .where(province_referee_onboarding.c.id.in_(payload.ids))
            .where(province_referee_onboarding.c.province.in_(_province_keys(payload.province)))
            .values(mailed_at=_dt.datetime.utcnow(), mailed_by=R.s(jwt.get("sub")))
        )
    return {"ok": True}


@router.post("/history/remove")
async def remove(payload: HistoryIdsRequest):
    if payload.ids:
        await database.execute(
            delete(province_referee_onboarding)
            .where(province_referee_onboarding.c.id.in_(payload.ids))
            .where(province_referee_onboarding.c.province.in_(_province_keys(payload.province)))
        )
    return {"ok": True}


@router.post("/badges")
async def give_badges(payload: BadgesRequest, jwt: dict = Depends(get_jwt_payload)):
    """Badge dla osób z historii okręgu. Osoba bez numeru dostaje je, gdy numer się znajdzie."""
    names = R.clean_badges(payload.badges)
    if not payload.ids or not (names or payload.young):
        raise HTTPException(400, "Wybierz osoby i co najmniej jeden badge.")
    rows = await database.fetch_all(
        select(province_referee_onboarding)
        .where(province_referee_onboarding.c.id.in_(payload.ids))
        .where(province_referee_onboarding.c.province.in_(_province_keys(payload.province)))
    )
    registry = None
    results = []
    for row in rows:
        if not R.s(row["nr_sedzia"]):
            # Numer mógł już przyjść z listy ZPRP (synchronizacja okręgu) - szukamy po imieniu i nazwisku.
            registry = registry if registry is not None else await _registry(payload.province)
            nr = R.resolve_nr(dict(row), registry)
            if nr:
                await database.execute(
                    update(province_referee_onboarding)
                    .where(province_referee_onboarding.c.id == row["id"])
                    .values(nr_sedzia=nr, status="created")
                )
                row = await database.fetch_one(
                    select(province_referee_onboarding).where(province_referee_onboarding.c.id == row["id"])
                )
        outcome = await _order_badges(row, names, payload.young, jwt)
        results.append({"id": row["id"], "nr_sedzia": row["nr_sedzia"], **outcome})
    return {"results": results}


async def _order_badges(row, names: List[str], young: bool, jwt: dict) -> Dict[str, Any]:
    """Zapisuje zamówienie badge i - gdy osoba ma numer - od razu je nadaje."""
    T = province_referee_onboarding_badges
    prev = await database.fetch_one(select(T).where(T.c.record_id == row["id"]))
    wanted = R.clean_badges(list((prev["badges"] if prev else None) or []) + names)
    want_young = bool(young or (prev and prev["young"]))
    applied_at, note = None, "czeka na numer NrSedzia"
    nr = R.s(row["nr_sedzia"])
    if nr:
        notes = []
        if wanted:
            await _upsert_judge_badges(nr, R.display_name(row["first_name"], row["last_name"]), row["province"], wanted)
            notes.append("badge nadane")
        if want_young:
            notes.append(await _add_young(nr, R.display_name(row["first_name"], row["last_name"]), row["province"], jwt))
        applied_at, note = _dt.datetime.utcnow(), " · ".join(notes)
    values = dict(
        badges=wanted,
        young=want_young,
        applied_at=applied_at,
        note=note,
        updated_by=R.s(jwt.get("sub")),
        updated_at=_dt.datetime.utcnow(),
    )
    async with database.transaction():
        await database.execute(delete(T).where(T.c.record_id == row["id"]))
        await database.execute(T.insert().values(record_id=row["id"], **values))
    return _badge_row({**values, "record_id": row["id"]})


async def _upsert_judge_badges(nr: str, full_name: str, province: str, names: List[str]) -> None:
    """Rejestr sędziów okręgu (`province_judges`): dopisuje badge, istniejących nie rusza."""
    existing = await database.fetch_one(select(province_judges).where(province_judges.c.judge_id == nr))
    now = _dt.datetime.now(_dt.timezone.utc)
    if existing:
        badges = existing["badges"]
        if isinstance(badges, str):
            import json

            try:
                badges = json.loads(badges)
            except ValueError:
                badges = {}
        await database.execute(
            update(province_judges)
            .where(province_judges.c.judge_id == nr)
            .values(badges=R.merge_badges(badges, names), updated_at=now)
        )
    else:
        await database.execute(
            province_judges.insert().values(
                judge_id=nr,
                full_name=full_name,
                province=R.s(province).upper(),
                badges=R.merge_badges({}, names),
                photo_url="",
                updated_at=now,
            )
        )
    from app.assignment_board_cache import bump_all

    bump_all()


async def _add_young(nr: str, full_name: str, province: str, jwt: dict) -> str:
    """Rejestr Młodych - z tymi samymi uprawnieniami co moduł Młodych (Teach Master okręgu / admin)."""
    from app.young_referees import _ensure_young_referee_write

    prov = R.s(province).upper()
    try:
        await _ensure_young_referee_write(jwt, province=prov, action="Dodanie młodego sędziego")
    except HTTPException as exc:
        return f"Młodzi: {exc.detail}"
    exists = await database.fetch_one(
        select(young_referees.c.id).where(
            (young_referees.c.base_judge_id == nr) & (young_referees.c.province == prov)
        )
    )
    if not exists:
        await database.execute(
            young_referees.insert().values(full_name=full_name, base_judge_id=nr, province=prov, is_active=True)
        )
    return "dodano do Młodych"


def _badge_row(row) -> Dict[str, Any]:
    d = dict(row)
    at = d.get("applied_at")
    return {
        "badges": R.clean_badges(d.get("badges") or []),
        "young": bool(d.get("young")),
        "badges_applied_at": at.replace(microsecond=0).isoformat() + "Z" if at else None,
        "badges_note": d.get("note"),
    }


def _province_keys(province: str) -> List[str]:
    return sorted({p.upper() for p in spellings(province)} | {R.s(province).upper()})


def _now() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _row(row) -> Dict[str, Any]:
    d = dict(row)
    for key in ("created_at", "mailed_at"):
        value = d.get(key)
        d[key] = value.replace(microsecond=0).isoformat() + "Z" if value else None
    d["roles"] = R.normalize_roles(d.get("roles")) or ["sedzia"]
    return d
