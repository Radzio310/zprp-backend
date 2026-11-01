"""Mecze ręczne wspólne (31.10.2026). Kontrakt: `docs/mecze-wspolne-api.md`.

Mecz ręczny leży na serwerze i jest wspólny dla obsady: dodany sędzia widzi go od razu (z pushem, bez akceptacji), każdy
członek edytuje dane, wpisuje wynik skrócony i prowadzi ProEla, a tylko twórca usuwa mecz wszystkim i usuwa innych z obsady.

Zasady, których ten moduł pilnuje:
  - dostęp WYŁĄCZNIE dla członków (twórca jest członkiem); obcy dostaje 404, jakby meczu nie było,
  - każdy zapis treści niesie `base_rev`; niezgodny = 409 `REV_CONFLICT` z aktualną wersją (nic nie nadpisuje się po cichu),
  - ukrycie meczu dotyczy tylko ukrywającego i niczego nie kasuje u innych,
  - wynik ręczny nigdy nie idzie do ZPRP (moduł nie ma żadnego wywołania ZPRP),
  - błędy w kopercie `HTTPException(detail={code, message, ...})` - `main.py` spłaszcza ją obok `error`.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, insert, or_, select, update

from app import mentor_panel_core as C
from app import shared_match_notify as N
from app import shared_match_rules as SR
from app.db import (
    database,
    login_records,
    partner_offtimes,
    province_judges,
    saved_matches,
    shared_match_blocks,
    shared_match_log,
    shared_match_members,
    shared_matches,
    zprp_public_matches,
)
from app.mentor_panel_auth import base_actor

logger = logging.getLogger("app.shared_match")
router = APIRouter(prefix="/shared-matches", tags=["Mecze wspólne"])
Actor = C.MentorActor

M = shared_matches
MM = shared_match_members
BL = shared_match_blocks
LG = shared_match_log
s = SR.s


# ─── Pomocnicze ─────────────────────────────────────────────────────────────


def _bad(message: str, code: str = "VALIDATION") -> HTTPException:
    return C.err(422, code, message)


def _guard(fn, *args, **kwargs):
    """Reguła rzuca `ValueError` z polskim zdaniem -> 422 (nie 500)."""
    try:
        return fn(*args, **kwargs)
    except ValueError as exc:
        raise _bad(str(exc)) from exc


async def _names(ids: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    """Imię i zdjęcie: konto aplikacji (`login_records`), w drugiej kolejności lista sędziów okręgu."""
    wanted = sorted({s(i) for i in ids if s(i)})
    out: Dict[str, Dict[str, Any]] = {}
    if not wanted:
        return out
    for row in await C.rows(select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url,
                                   province_judges.c.province).where(province_judges.c.judge_id.in_(wanted))):
        out[s(row["judge_id"])] = {"name": row.get("full_name"), "photo_url": row.get("photo_url"), "province": row.get("province")}
    for row in await C.rows(select(login_records.c.judge_id, login_records.c.full_name, login_records.c.photo_url,
                                   login_records.c.province).where(login_records.c.judge_id.in_(wanted))):
        prev = out.get(s(row["judge_id"]), {})
        out[s(row["judge_id"])] = {"name": row.get("full_name") or prev.get("name"),
                                   "photo_url": row.get("photo_url") or prev.get("photo_url"),
                                   "province": row.get("province") or prev.get("province")}
    return out


async def _app_users(ids: Iterable[Any]) -> set:
    wanted = sorted({s(i) for i in ids if s(i)})
    if not wanted:
        return set()
    rows = await C.rows(select(login_records.c.judge_id).where(login_records.c.judge_id.in_(wanted)))
    return {s(r["judge_id"]) for r in rows}


def _name_of(names: Dict[str, Dict[str, Any]], judge_id: Any, fallback: str = "") -> str:
    return s((names.get(s(judge_id)) or {}).get("name")) or fallback or (f"Sędzia {s(judge_id)}" if s(judge_id) else "")


def _extra(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("extra_json")
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def match_shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]], *, viewer: str = "") -> Dict[str, Any]:
    has_result = row.get("score_home") is not None and row.get("score_away") is not None
    return {
        "id": row["id"], "card_id": f"my:{row['id']}", "creator_id": row["creator_id"],
        "creator_name": _name_of(names, row["creator_id"]),
        "rev": int(row.get("rev") or 1),
        "code": row.get("code"), "competition": row.get("competition"),
        "home_name": row.get("home_name"), "away_name": row.get("away_name"),
        "match_at": row.get("match_at"), "date_key": row.get("date_key"),
        "hall": row.get("hall"), "city": row.get("city"),
        "zprp_match_id": row.get("zprp_match_id"), "proel_key": row.get("proel_key"),
        "result": {
            "score_home": row.get("score_home"), "score_away": row.get("score_away"),
            "half_home": row.get("half_home"), "half_away": row.get("half_away"),
            "by": row.get("result_by"), "by_name": _name_of(names, row.get("result_by")) if row.get("result_by") else None,
            "at": row.get("result_at"),
        } if has_result else None,
        "extra": _extra(row),
        "local_id": row.get("local_id") if s(viewer) == s(row["creator_id"]) else None,
        "created_at": row.get("created_at"), "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"), "updated_by_name": _name_of(names, row.get("updated_by")) if row.get("updated_by") else None,
    }


def member_shape(member: Dict[str, Any], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    judge_id = s(member.get("judge_id"))
    info = names.get(judge_id) or {}
    return {
        "id": member["id"], "judge_id": judge_id or None, "manual": not judge_id,
        "name": s(info.get("name")) or s(member.get("name")) or (f"Sędzia {judge_id}" if judge_id else ""),
        "photo_url": info.get("photo_url"), "role": member["role"], "role_label": SR.role_label(member["role"]),
        "added_by": member.get("added_by"), "added_at": member.get("added_at"),
    }


def my_shape(member: Optional[Dict[str, Any]], names: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not member:
        return None
    return {
        "member_id": member["id"], "role": member["role"], "hidden": member.get("hidden_at") is not None,
        "hidden_at": member.get("hidden_at"), "counts_in_stats": bool(member.get("counts_in_stats")),
        "added_by": member.get("added_by"), "added_by_name": _name_of(names, member.get("added_by")) if member.get("added_by") else None,
    }


async def _row(match_id: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(M).where(M.c.id == s(match_id)))


async def _members(match_id: str) -> List[Dict[str, Any]]:
    return await C.rows(select(MM).where(MM.c.match_id == s(match_id)).order_by(MM.c.added_at.asc(), MM.c.id.asc()))


async def _load(match_id: str, actor: Actor) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """Mecz + obsada + członkostwo pytającego. Obcy: 404. Usunięty: członkowie 410, obcy 404."""
    row = await _row(match_id)
    members = await _members(match_id) if row else []
    mine = next((m for m in members if s(m.get("judge_id")) == s(actor.judge_id)), None)
    if not row or not mine:
        raise C.err(404, "MATCH_NOT_FOUND", "Nie ma takiego meczu albo nie masz do niego dostępu.")
    if row.get("deleted_at") is not None:
        raise C.err(410, "MATCH_DELETED", "Twórca usunął ten mecz u wszystkich.")
    return row, members, mine


async def _log_rows(match_id: str, limit: int = 60) -> List[Dict[str, Any]]:
    return await C.rows(select(LG).where(LG.c.match_id == s(match_id)).order_by(LG.c.id.desc()).limit(limit))


async def _write_log(match_id: str, rev: int, actor_id: str, action: str, changes: List[Dict[str, Any]]) -> None:
    await database.execute(insert(LG).values(match_id=match_id, rev=rev, actor_id=s(actor_id), at=C.now(), action=action,
                                             changes_json=C.dumps(changes)))


async def detail_payload(row: Dict[str, Any], members: List[Dict[str, Any]], actor: Actor, *, with_log: bool = True) -> Dict[str, Any]:
    log = await _log_rows(row["id"]) if with_log else []
    ids = [row["creator_id"], row.get("updated_by"), row.get("result_by"), *[m.get("judge_id") for m in members],
           *[m.get("added_by") for m in members], *[entry.get("actor_id") for entry in log]]
    names = await _names(ids)
    mine = next((m for m in members if s(m.get("judge_id")) == s(actor.judge_id)), None)
    is_creator = s(actor.judge_id) == s(row["creator_id"])
    return {
        "match": match_shape(row, names, viewer=actor.judge_id),
        "crew": [member_shape(m, names) for m in members],
        "my": my_shape(mine, names),
        "can": {"edit": bool(mine), "delete": is_creator, "remove_members": is_creator, "hide": bool(mine)},
        "log": [{"id": e["id"], "rev": e["rev"], "actor_id": e["actor_id"], "actor_name": _name_of(names, e["actor_id"]),
                 "at": e["at"], "action": e["action"], "changes": R_json(e.get("changes_json"))} for e in log],
        "rev": int(row.get("rev") or 1),
    }


def R_json(value: Any) -> Any:
    try:
        return json.loads(value) if isinstance(value, str) else (value or [])
    except ValueError:
        return []


async def _conflict(match_id: str, actor: Actor, sent_rev: Any) -> HTTPException:
    """409 z aktualną wersją meczu - klient pokazuje różnicę i prosi o decyzję, nic nie nadpisujemy."""
    row = await _row(match_id)
    current: Any = None
    rev = None
    if row and row.get("deleted_at") is None:
        members = await _members(match_id)
        if any(s(m.get("judge_id")) == s(actor.judge_id) for m in members):
            current = await detail_payload(row, members, actor)
            rev = int(row.get("rev") or 1)
    if row and row.get("deleted_at") is not None:
        return C.err(410, "MATCH_DELETED", "Twórca usunął ten mecz u wszystkich.")
    message = "Ktoś zmienił ten mecz, zanim zapisałeś(aś). Sprawdź aktualną wersję i zdecyduj, co zachować."
    return HTTPException(409, detail={"code": "REV_CONFLICT", "message": message, "rev": rev, "base_rev": sent_rev, "current": current})


async def _bump(match_id: str, actor: Actor, sent_rev: Any, values: Dict[str, Any]) -> int:
    """Zapis warunkowy: rośnie tylko wtedy, gdy `rev` w bazie == `base_rev`. Zwraca nowy rev albo rzuca 409."""
    if sent_rev is not None and not isinstance(sent_rev, bool):
        try:
            expected = int(sent_rev)
        except (TypeError, ValueError):
            raise _bad("Pole base_rev musi być liczbą.") from None
    else:
        raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
    query = (update(M).where(M.c.id == match_id).where(M.c.rev == expected).where(M.c.deleted_at.is_(None))
             .values(**values, rev=M.c.rev + 1, updated_at=C.now(), updated_by=actor.judge_id).returning(M.c.rev))
    found = await database.fetch_one(query)
    if found is None:
        raise await _conflict(match_id, actor, sent_rev)
    return int(found["rev"])


async def _blocked(judge_id: str, via_judge_id: str) -> bool:
    found = await C.one(select(BL.c.judge_id).where(BL.c.judge_id == s(judge_id)).where(BL.c.via_judge_id == s(via_judge_id)))
    return found is not None


async def _after(row: Dict[str, Any], actor: Actor, extra_ids: Iterable[Any] = ()) -> None:
    """Po zmianie: odśwież panele par, w których ten mecz jest kartą (przed i po zmianie obsady)."""
    from app.shared_match_pair import refresh_pairs

    members = await _members(row["id"])
    ids = [m.get("judge_id") for m in members if m.get("role") in SR.REFEREE_ROLES] + list(extra_ids)
    await refresh_pairs(ids, actor.judge_id, row["id"])


# ─── Modele żądań ───────────────────────────────────────────────────────────


class CrewIn(BaseModel):
    #: Sędzia z aplikacji. Bez niego: wpis ręczny (sam podpis, bez dostępu) - wtedy `name` jest wymagane.
    judge_id: Optional[str] = Field(default=None, max_length=40)
    name: Optional[str] = Field(default=None, max_length=120)
    role: str = Field(max_length=20)


class ResultIn(BaseModel):
    score_home: Optional[int] = None
    score_away: Optional[int] = None
    half_home: Optional[int] = None
    half_away: Optional[int] = None


class CreateBody(BaseModel):
    local_id: Optional[str] = Field(default=None, max_length=80)
    code: Optional[str] = Field(default=None, max_length=60)
    competition: Optional[str] = Field(default=None, max_length=120)
    home_name: Optional[str] = Field(default=None, max_length=120)
    away_name: Optional[str] = Field(default=None, max_length=120)
    #: ISO 8601; bez strefy = czas polski.
    match_at: Optional[str] = Field(default=None, max_length=40)
    hall: Optional[str] = Field(default=None, max_length=160)
    city: Optional[str] = Field(default=None, max_length=120)
    zprp_match_id: Optional[str] = Field(default=None, max_length=20)
    proel_key: Optional[str] = Field(default=None, max_length=80)
    my_role: str = Field(default="sedzia1", max_length=20)
    crew: List[CrewIn] = Field(default_factory=list, max_length=SR.MAX_MEMBERS)
    counts_in_stats: bool = False
    extra: Optional[Dict[str, Any]] = None
    result: Optional[ResultIn] = None
    #: true = utwórz mimo wykrytego duplikatu.
    force: bool = False


class EditBody(BaseModel):
    base_rev: Optional[int] = None
    code: Optional[str] = Field(default=None, max_length=60)
    competition: Optional[str] = Field(default=None, max_length=120)
    home_name: Optional[str] = Field(default=None, max_length=120)
    away_name: Optional[str] = Field(default=None, max_length=120)
    match_at: Optional[str] = Field(default=None, max_length=40)
    hall: Optional[str] = Field(default=None, max_length=160)
    city: Optional[str] = Field(default=None, max_length=120)
    extra: Optional[Dict[str, Any]] = None


class ResultBody(BaseModel):
    base_rev: Optional[int] = None
    score_home: Optional[int] = None
    score_away: Optional[int] = None
    half_home: Optional[int] = None
    half_away: Optional[int] = None
    #: true = zdejmij wynik.
    clear: bool = False


class CrewAddBody(BaseModel):
    base_rev: Optional[int] = None
    add: List[CrewIn] = Field(min_length=1, max_length=SR.MAX_MEMBERS)


class CrewEditBody(BaseModel):
    base_rev: Optional[int] = None
    role: Optional[str] = Field(default=None, max_length=20)
    #: Tylko dla wpisu ręcznego.
    name: Optional[str] = Field(default=None, max_length=120)


class HideBody(BaseModel):
    #: true = „nie dodawaj mnie więcej przez tę osobę" (osoba, która mnie dodała do tego meczu).
    block_adder: bool = False


class StatsBody(BaseModel):
    counts_in_stats: bool


class ZprpBody(BaseModel):
    base_rev: Optional[int] = None
    #: Liczbowe IdZawody; null/"" zdejmuje powiązanie.
    zprp_match_id: Optional[str] = Field(default=None, max_length=20)


class ProelBody(BaseModel):
    base_rev: Optional[int] = None
    #: Klucz protokołu ProEla (numer meczu albo T-XXXXXXXX/NUMER); null/"" zdejmuje.
    proel_key: Optional[str] = Field(default=None, max_length=80)


class JoinBody(BaseModel):
    match_id: str = Field(max_length=60)
    #: Bez roli nie dołączamy (rola sędziowska nie jest przydzielana automatycznie).
    role: Optional[str] = Field(default=None, max_length=20)
    #: Dane meczu, które użytkownik wpisał - serwer sprawdza, czy to TEN SAM mecz (dołączyć można tylko do duplikatu).
    home_name: Optional[str] = Field(default=None, max_length=120)
    away_name: Optional[str] = Field(default=None, max_length=120)
    match_at: Optional[str] = Field(default=None, max_length=40)
    zprp_match_id: Optional[str] = Field(default=None, max_length=20)


class RepeatBody(BaseModel):
    #: Nowa data meczu (ISO 8601) - wymagana.
    match_at: str = Field(max_length=40)
    #: Własny kod zamiast kolejnego numeru serii.
    code: Optional[str] = Field(default=None, max_length=60)
    copy_crew: bool = True
    force: bool = False


# ─── Obsada: walidacja i wstawianie ─────────────────────────────────────────


async def _prepare_crew(items: List[CrewIn], *, actor_id: str, skip_ids: Iterable[str] = ()) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Zwraca (do dodania, pominięci). Rzuca 422 dla nieznanej roli i osoby bez konta w aplikacji."""
    skip = {s(x) for x in skip_ids}
    wanted: List[Dict[str, Any]] = []
    seen: set = set()
    for item in items:
        role = _guard(SR.clean_role, item.role)
        judge_id = s(item.judge_id)
        name = SR.clean_text(item.name, 120)
        if judge_id:
            if judge_id in seen:
                continue
            seen.add(judge_id)
        elif not name:
            raise _bad("Wpis ręczny wymaga imienia i nazwiska.", "MANUAL_NAME_REQUIRED")
        wanted.append({"judge_id": judge_id or None, "name": name, "role": role})
    known = await _app_users(w["judge_id"] for w in wanted if w["judge_id"])
    missing = [w["judge_id"] for w in wanted if w["judge_id"] and w["judge_id"] not in known]
    if missing:
        raise HTTPException(422, detail={"code": "NOT_APP_USER", "message": "Ta osoba nie ma konta w aplikacji - dodaj ją jako wpis ręczny (sam podpis).",
                                         "judge_ids": missing})
    ok: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for w in wanted:
        jid = w["judge_id"]
        if jid and jid in skip:
            skipped.append({"judge_id": jid, "reason": "ALREADY_MEMBER"})
        elif jid and await _blocked(jid, actor_id):
            skipped.append({"judge_id": jid, "reason": "BLOCKED"})
        else:
            ok.append(w)
    return ok, skipped


async def _insert_members(match_id: str, items: List[Dict[str, Any]], added_by: str) -> List[Dict[str, Any]]:
    out = []
    names = await _names(i["judge_id"] for i in items if i["judge_id"])
    for item in items:
        member_id = uuid.uuid4().hex
        values = {"id": member_id, "match_id": match_id, "judge_id": item["judge_id"],
                  "name": _name_of(names, item["judge_id"], s(item.get("name"))) if item["judge_id"] else s(item.get("name")),
                  "role": item["role"], "added_by": s(added_by) or None, "added_at": C.now(), "counts_in_stats": False}
        await database.execute(insert(MM).values(**values))
        out.append(values)
    return out


def _summary_label(items: List[Dict[str, Any]], names: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"judge_id": i.get("judge_id"), "name": _name_of(names, i.get("judge_id"), s(i.get("name"))), "role": i["role"]} for i in items]


# ─── Duplikat ───────────────────────────────────────────────────────────────


async def _duplicates(actor: Actor, *, key: Optional[Tuple[str, str]], exclude_id: str = "") -> List[Dict[str, Any]]:
    """Duplikaty po dacie i drużynach. Samo `zprp_match_id` NIE wystarcza (nie ujawnia meczu bez zgodności drużyn i daty).

    Nie-członek dostaje tylko minimum do decyzji (id, data, drużyny, imię twórcy); hala i obsada tylko dla członka.
    """
    if not key:
        return []
    query = (select(M).where(M.c.deleted_at.is_(None)).where(and_(M.c.date_key == key[0], M.c.teams_key == key[1]))
             .order_by(M.c.created_at.asc()).limit(5))
    if exclude_id:
        query = query.where(M.c.id != exclude_id)
    found = await C.rows(query)
    if not found:
        return []
    members: Dict[str, List[Dict[str, Any]]] = {}
    for m in await C.rows(select(MM).where(MM.c.match_id.in_([f["id"] for f in found]))):
        members.setdefault(s(m["match_id"]), []).append(m)
    names = await _names([f["creator_id"] for f in found] + [m.get("judge_id") for ms in members.values() for m in ms])
    out = []
    for row in found:
        crew = members.get(row["id"], [])
        mine = next((m for m in crew if s(m.get("judge_id")) == s(actor.judge_id)), None)
        item = {
            "id": row["id"], "home_name": row.get("home_name"), "away_name": row.get("away_name"),
            "match_at": row.get("match_at"), "creator_name": _name_of(names, row["creator_id"]),
            "already_member": mine is not None, "hidden": bool(mine and mine.get("hidden_at") is not None),
        }
        if mine is not None:
            item.update({"code": row.get("code"), "hall": row.get("hall"),
                         "crew": [{"name": member_shape(m, names)["name"], "role": m["role"], "role_label": SR.role_label(m["role"])} for m in crew]})
        out.append(item)
    return out


# ─── Utworzenie ─────────────────────────────────────────────────────────────


def _core_values(body: Any, *, for_edit: bool = False) -> Dict[str, Any]:
    """Pola treści z żądania -> wartości kolumn (z walidacją i kluczami duplikatu)."""
    values: Dict[str, Any] = {}
    sent = body.model_fields_set if hasattr(body, "model_fields_set") else set()
    for field in ("code", "competition", "home_name", "away_name", "hall", "city"):
        if not for_edit or field in sent:
            values[field] = SR.clean_text(getattr(body, field, None), 160)
    if not for_edit or "match_at" in sent:
        values["match_at"] = _guard(SR.parse_match_at, getattr(body, "match_at", None))
    return values


def _with_keys(values: Dict[str, Any], base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    merged = {**(base or {}), **values}
    out = dict(values)
    if any(k in values for k in ("home_name", "away_name", "match_at")):
        out["date_key"] = SR.date_key(merged.get("match_at"))
        out["teams_key"] = SR.teams_key(merged.get("home_name"), merged.get("away_name"))
    return out


async def _create(actor: Actor, params: Dict[str, Any], *, force: bool, crew_in: List[CrewIn], my_role: str, counts: bool,
                  local_id: Optional[str], result: Optional[ResultIn]) -> Dict[str, Any]:
    role = _guard(SR.clean_role, my_role)
    zprp_id = s(params.get("zprp_match_id"))
    if zprp_id and not SR.is_zprp_id(zprp_id):
        raise _bad("zprp_match_id musi być liczbą (IdZawody z ZPRP).")
    proel_key = _guard(SR.clean_proel_key, params.get("proel_key"))
    extra = _guard(SR.clean_extra, params.get("extra"))
    if local_id:
        existing = await C.one(select(M).where(M.c.creator_id == actor.judge_id).where(M.c.local_id == local_id))
        if existing:
            return await _existing_response(existing, actor)
    values = _with_keys({k: params.get(k) for k in ("code", "competition", "home_name", "away_name", "hall", "city", "match_at")})
    if not force:
        dupes = await _duplicates(actor, key=SR.duplicate_key(values.get("home_name"), values.get("away_name"), values.get("match_at")))
        if dupes:
            raise HTTPException(409, detail={"code": "DUPLICATE_MATCH", "can_join": True, "duplicates": dupes,
                                             "message": "Ten mecz już istnieje (te same drużyny i data). Możesz do niego dołączyć albo utworzyć drugi."})
    if len(crew_in) + 1 > SR.MAX_MEMBERS:
        raise _bad(f"Obsada może mieć najwyżej {SR.MAX_MEMBERS} osób.")
    crew, skipped = await _prepare_crew([c for c in crew_in if s(c.judge_id) != s(actor.judge_id)], actor_id=actor.judge_id)
    match_id = uuid.uuid4().hex
    scores: Dict[str, Any] = {}
    if result is not None and (result.score_home is not None or result.score_away is not None):
        home = _guard(SR.clean_score, result.score_home, "wynik gospodarzy")
        away = _guard(SR.clean_score, result.score_away, "wynik gości")
        if home is None or away is None:
            raise _bad("Wynik wymaga obu liczb.")
        scores = {"score_home": home, "score_away": away, "half_home": _guard(SR.clean_score, result.half_home, "wynik do przerwy"),
                  "half_away": _guard(SR.clean_score, result.half_away, "wynik do przerwy"), "result_by": actor.judge_id, "result_at": C.now()}
    try:
        async with database.transaction():
            await database.execute(insert(M).values(
                id=match_id, creator_id=actor.judge_id, local_id=local_id or None, rev=1, **values,
                zprp_match_id=zprp_id or None, proel_key=proel_key, extra_json=C.dumps(extra), created_at=C.now(), updated_at=C.now(),
                updated_by=actor.judge_id, **scores))
            await _insert_members(match_id, [{"judge_id": actor.judge_id, "name": actor.display_name, "role": role}], actor.judge_id)
            await database.execute(update(MM).where(MM.c.match_id == match_id).where(MM.c.judge_id == actor.judge_id)
                                   .values(counts_in_stats=bool(counts)))
            added = await _insert_members(match_id, crew, actor.judge_id)
            await _write_log(match_id, 1, actor.judge_id, "create", [{"field": "created", "from": None, "to": values.get("code") or True}])
    except Exception:
        if local_id:  # wyścig dwóch migracji tego samego lokalnego meczu: wygrywa pierwsza, druga dostaje ten sam mecz
            existing = await C.one(select(M).where(M.c.creator_id == actor.judge_id).where(M.c.local_id == local_id))
            if existing:
                return await _existing_response(existing, actor)
        raise
    row = await _row(match_id)
    members = await _members(match_id)
    await _notify_added(row, actor, added)
    await _after(row, actor)
    payload = await detail_payload(row, members, actor)
    return {"ok": True, "existing": False, "skipped": skipped, **payload}


async def _existing_response(existing: Dict[str, Any], actor: Actor) -> Dict[str, Any]:
    if existing.get("deleted_at") is not None:
        return {"ok": True, "existing": True, "deleted": True, "id": existing["id"], "skipped": []}
    members = await _members(existing["id"])
    return {"ok": True, "existing": True, "skipped": [], **await detail_payload(existing, members, actor)}


async def _notify_added(row: Dict[str, Any], actor: Actor, added: List[Dict[str, Any]]) -> None:
    for member in added:
        if member.get("judge_id") and s(member["judge_id"]) != s(actor.judge_id):
            title, body = N.added(row, actor.display_name, member["role"])
            await N.send([member["judge_id"]], actor.judge_id, title, body, row["id"], "added")


@router.post("")
async def create_match(body: CreateBody, actor: Actor = Depends(base_actor)):
    """Utwórz mecz wspólny (także migracja lokalnego meczu: `local_id` -> idempotentnie)."""
    params = {**_core_values(body), "zprp_match_id": body.zprp_match_id, "proel_key": body.proel_key, "extra": body.extra}
    return await _create(actor, params, force=body.force, crew_in=body.crew, my_role=body.my_role, counts=body.counts_in_stats,
                         local_id=s(body.local_id) or None, result=body.result)


# ─── Lista ──────────────────────────────────────────────────────────────────


@router.get("")
async def list_matches(include_hidden: bool = Query(False), limit: int = Query(300, ge=1, le=500), actor: Actor = Depends(base_actor)):
    """Moje mecze wspólne (domyślnie bez ukrytych; `include_hidden=true` dokłada je z `my.hidden=true`)."""
    mine = await C.rows(select(MM).where(MM.c.judge_id == actor.judge_id))
    hidden = len([1 for m in mine if m.get("hidden_at") is not None]) if not include_hidden else 0
    if not include_hidden:
        mine = [m for m in mine if m.get("hidden_at") is None]
    by_match = {s(m["match_id"]): m for m in mine}
    if not by_match:
        return {"matches": [], "count": 0, "hidden_count": hidden}
    rows = await C.rows(select(M).where(M.c.id.in_(list(by_match))).where(M.c.deleted_at.is_(None)))
    rows.sort(key=lambda r: (r.get("match_at") is None, -(r["match_at"].timestamp() if r.get("match_at") else 0)))
    rows = rows[:limit]
    crew: Dict[str, List[Dict[str, Any]]] = {}
    for m in await C.rows(select(MM).where(MM.c.match_id.in_([r["id"] for r in rows])).order_by(MM.c.added_at.asc())):
        crew.setdefault(s(m["match_id"]), []).append(m)
    names = await _names([r["creator_id"] for r in rows] + [m.get("judge_id") for ms in crew.values() for m in ms]
                         + [r.get("result_by") for r in rows] + [by_match[r["id"]].get("added_by") for r in rows])
    items = [{"match": match_shape(r, names, viewer=actor.judge_id), "crew": [member_shape(m, names) for m in crew.get(r["id"], [])],
              "my": my_shape(by_match[r["id"]], names)} for r in rows]
    return {"matches": items, "count": len(items), "hidden_count": hidden}


# ─── Blokady (stałe trasy przed /{match_id}) ────────────────────────────────


@router.get("/blocks")
async def list_blocks(actor: Actor = Depends(base_actor)):
    """Osoby, przez które nie chcę być dodawany(a)."""
    found = await C.rows(select(BL).where(BL.c.judge_id == actor.judge_id).order_by(BL.c.created_at.desc()))
    names = await _names(b["via_judge_id"] for b in found)
    return {"blocks": [{"via_judge_id": b["via_judge_id"], "via_name": _name_of(names, b["via_judge_id"]), "created_at": b["created_at"]} for b in found]}


@router.delete("/blocks/{via_judge_id}")
async def remove_block(via_judge_id: str, actor: Actor = Depends(base_actor)):
    await database.execute(delete(BL).where(BL.c.judge_id == actor.judge_id).where(BL.c.via_judge_id == s(via_judge_id)))
    return {"ok": True}


# ─── Użytkownicy aplikacji: wyszukiwarka i sugestie ─────────────────────────


SEARCH_LIMIT_PER_MIN = 60
_search_hits: Dict[str, List[float]] = {}


def _search_allowed(judge_id: Any, now: Optional[float] = None) -> bool:
    """Prosty limit w pamięci procesu: najwyżej `SEARCH_LIMIT_PER_MIN` zapytań na konto w ciągu minuty."""
    moment = time.monotonic() if now is None else now
    key = s(judge_id)
    hits = [h for h in _search_hits.get(key, []) if moment - h < 60.0]
    if len(hits) >= SEARCH_LIMIT_PER_MIN:
        _search_hits[key] = hits
        return False
    hits.append(moment)
    _search_hits[key] = hits
    if len(_search_hits) > 5000:  # nie rośnij bez końca: wyrzuć konta bez świeżych trafień
        for k in [k for k, v in _search_hits.items() if not v or moment - v[-1] >= 60.0]:
            _search_hits.pop(k, None)
    return True


@router.get("/users/search")
async def search_users(q: str = Query("", max_length=60), limit: int = Query(10, ge=1, le=25), actor: Actor = Depends(base_actor)):
    """Użytkownicy aplikacji (konta z `login_records`) po imieniu/nazwisku albo numerze sędziego. Limit: 60 zapytań/min na konto."""
    needle = s(q)
    if len(needle) < 2:
        return {"users": []}
    if not _search_allowed(actor.judge_id):
        raise C.err(429, "RATE_LIMITED", "Za dużo wyszukiwań. Odczekaj chwilę i spróbuj ponownie.")
    conds = [login_records.c.judge_id == needle]
    tokens = [t for t in needle.split() if t][:4]
    if tokens:
        conds.append(and_(*[login_records.c.full_name.ilike(SR.like_pattern(t), escape="\\") for t in tokens]))
    found = await C.rows(
        select(login_records.c.judge_id, login_records.c.full_name, login_records.c.photo_url, login_records.c.province)
        .where(or_(*conds)).where(login_records.c.judge_id != actor.judge_id).order_by(login_records.c.full_name.asc()).limit(limit))
    return {"users": [{"judge_id": r["judge_id"], "name": r["full_name"], "photo_url": r.get("photo_url") or None, "province": r.get("province")}
                      for r in found]}


@router.get("/users/suggestions")
async def suggest_users(limit: int = Query(8, ge=1, le=15), actor: Actor = Depends(base_actor)):
    """Sugestie obsady: partner z dyspozycji, najczęstszy wspólny partner (z moich meczów wspólnych i z meczów ZPRP), ostatnio dodani."""
    me = s(actor.judge_id)
    groups: List[Tuple[str, List[str]]] = []
    try:
        offtime = await C.one(select(partner_offtimes.c.partner_id).where(partner_offtimes.c.judge_id == me))
        if offtime and s(offtime.get("partner_id")):
            groups.append(("partner", [s(offtime["partner_id"])]))
    except Exception:  # noqa: BLE001 - brak dyspozycji nie psuje sugestii
        logger.warning("mecz wspólny: partner z dyspozycji nieczytelny", exc_info=True)
    counts: Dict[str, int] = {}
    mine_ids = [s(m["match_id"]) for m in await C.rows(select(MM.c.match_id).where(MM.c.judge_id == me))]
    if mine_ids:
        for m in await C.rows(select(MM.c.judge_id).where(MM.c.match_id.in_(mine_ids)).where(MM.c.judge_id.is_not(None))):
            counts[s(m["judge_id"])] = counts.get(s(m["judge_id"]), 0) + 1
    try:
        pub = await C.rows(select(zprp_public_matches.c.referee_1_id, zprp_public_matches.c.referee_2_id)
                           .where(or_(zprp_public_matches.c.referee_1_id == me, zprp_public_matches.c.referee_2_id == me))
                           .order_by(zprp_public_matches.c.scheduled_at.desc()).limit(400))
        for r in pub:
            other = s(r["referee_2_id"]) if s(r["referee_1_id"]) == me else s(r["referee_1_id"])
            if other:
                counts[other] = counts.get(other, 0) + 1
    except Exception:  # noqa: BLE001
        logger.warning("mecz wspólny: partnerzy z meczów ZPRP nieczytelni", exc_info=True)
    groups.append(("frequent", [j for j, _ in SR.rank_partners(counts, exclude=[me], limit=5)]))
    recent = await C.rows(select(MM.c.judge_id).where(MM.c.added_by == me).where(MM.c.judge_id.is_not(None))
                          .order_by(MM.c.added_at.desc()).limit(30))
    groups.append(("recent", [s(r["judge_id"]) for r in recent if s(r["judge_id"]) != me]))
    merged = [x for x in SR.merge_suggestions(groups, limit=limit * 2) if x["judge_id"] != me]
    known = await _app_users(x["judge_id"] for x in merged)
    merged = [x for x in merged if x["judge_id"] in known][:limit]
    names = await _names(x["judge_id"] for x in merged)
    return {"suggestions": [{**x, "name": _name_of(names, x["judge_id"]), "photo_url": (names.get(x["judge_id"]) or {}).get("photo_url"),
                             "shared_count": counts.get(x["judge_id"], 0)} for x in merged]}


# ─── Dołączenie do duplikatu ────────────────────────────────────────────────


@router.post("/join")
async def join_match(body: JoinBody, actor: Actor = Depends(base_actor)):
    """Dołącz do istniejącego meczu. Dozwolone TYLKO dla duplikatu: serwer porównuje drużyny+datę z meczem (samo `zprp_match_id` nie wystarcza)."""
    if not s(body.role):
        raise _bad("Wybierz rolę, w jakiej dołączasz do meczu.", "ROLE_REQUIRED")
    role = _guard(SR.clean_role, body.role)
    row = await _row(body.match_id)
    if not row or row.get("deleted_at") is not None:
        raise C.err(404, "MATCH_NOT_FOUND", "Nie ma takiego meczu albo nie masz do niego dostępu.")
    # Sam `zprp_match_id` nie wystarcza: ta sama reguła co w ostrzeżeniu o duplikacie (data + drużyny).
    key = SR.duplicate_key(body.home_name, body.away_name, _guard(SR.parse_match_at, body.match_at))
    if not (key and key == (row.get("date_key"), row.get("teams_key"))):
        raise C.err(403, "NOT_A_DUPLICATE", "Dołączyć można tylko do meczu, który ma te same drużyny i datę.")
    members = await _members(row["id"])
    mine = next((m for m in members if s(m.get("judge_id")) == s(actor.judge_id)), None)
    if mine is not None:
        if mine.get("hidden_at") is not None:
            await database.execute(update(MM).where(MM.c.id == mine["id"]).values(hidden_at=None))
        return {"ok": True, "joined": False, "already_member": True, **await detail_payload(row, await _members(row["id"]), actor)}
    if len(members) >= SR.MAX_MEMBERS:
        raise _bad(f"Obsada może mieć najwyżej {SR.MAX_MEMBERS} osób.")
    if role in SR.REFEREE_ROLES and any(m.get("role") == role for m in members):
        raise C.err(409, "ROLE_TAKEN", f"Rola {SR.role_label(role)} jest już zajęta w tym meczu. Wybierz inną rolę albo poproś twórcę o zmianę obsady.")
    async with database.transaction():
        found = await database.fetch_one(update(M).where(M.c.id == row["id"]).where(M.c.deleted_at.is_(None))
                                         .values(rev=M.c.rev + 1, updated_at=C.now(), updated_by=actor.judge_id).returning(M.c.rev))
        if found is None:
            raise C.err(410, "MATCH_DELETED", "Twórca usunął ten mecz u wszystkich.")
        await _insert_members(row["id"], [{"judge_id": actor.judge_id, "name": actor.display_name, "role": role}], actor.judge_id)
        await _write_log(row["id"], int(found["rev"]), actor.judge_id, "join", [{"field": "crew", "from": None, "to": f"{actor.display_name} ({role})"}])
    fresh = await _row(row["id"])
    title, text = N.joined(row, actor.display_name, role)
    await N.send([row["creator_id"]], actor.judge_id, title, text, row["id"], "joined")
    await _after(fresh, actor)
    return {"ok": True, "joined": True, "already_member": False, **await detail_payload(fresh, await _members(row["id"]), actor)}


# ─── Szczegół, edycja, usunięcie ────────────────────────────────────────────


@router.get("/{match_id}")
async def get_match(match_id: str, actor: Actor = Depends(base_actor)):
    row, members, _ = await _load(match_id, actor)
    return await detail_payload(row, members, actor)


@router.put("/{match_id}")
async def edit_match(match_id: str, body: EditBody, actor: Actor = Depends(base_actor)):
    """Edycja danych meczu (każdy członek). `base_rev` wymagany; niezgodny = 409 `REV_CONFLICT` z aktualną wersją."""
    row, members, _ = await _load(match_id, actor)
    values = _with_keys(_core_values(body, for_edit=True), row)
    if "extra" in body.model_fields_set:
        values["extra_json"] = C.dumps(_guard(SR.clean_extra, body.extra))
    changes = SR.diff_fields(row, {**row, **values}, [*SR.EDITABLE_FIELDS])
    if "extra_json" in values and values["extra_json"] != C.dumps(_extra(row)):
        changes.append({"field": "extra", "from": None, "to": "zmieniono"})
    if not changes:
        if body.base_rev is None:
            raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
        return {"ok": True, "unchanged": True, **await detail_payload(row, members, actor)}
    async with database.transaction():
        rev = await _bump(row["id"], actor, body.base_rev, values)
        await _write_log(row["id"], rev, actor.judge_id, "edit", changes)
    fresh = await _row(row["id"])
    await _after(fresh, actor)
    return {"ok": True, "unchanged": False, **await detail_payload(fresh, await _members(row["id"]), actor)}


@router.delete("/{match_id}")
async def delete_match(match_id: str, base_rev: Optional[int] = Query(None), actor: Actor = Depends(base_actor)):
    """Usuń mecz u WSZYSTKICH (tylko twórca). Wiersz zostaje oznaczony jako usunięty, członkowie dostają push i 410."""
    row, members, _ = await _load(match_id, actor)
    if s(row["creator_id"]) != s(actor.judge_id):
        raise C.err(403, "CREATOR_ONLY", "Mecz u wszystkich usuwa tylko jego twórca. Możesz go ukryć u siebie.")
    if base_rev is not None and SR.revision_conflict(base_rev, row.get("rev")):
        raise await _conflict(row["id"], actor, base_rev)
    async with database.transaction():
        found = await database.fetch_one(update(M).where(M.c.id == row["id"]).where(M.c.deleted_at.is_(None))
                                         .values(deleted_at=C.now(), deleted_by=actor.judge_id, rev=M.c.rev + 1, updated_at=C.now(),
                                                 updated_by=actor.judge_id).returning(M.c.rev))
        rev = int(found["rev"]) if found else int(row.get("rev") or 1) + 1
        await _write_log(row["id"], rev, actor.judge_id, "delete", [{"field": "deleted", "from": False, "to": True}])
    title, text = N.deleted(row, actor.display_name)
    await N.send([m.get("judge_id") for m in members], actor.judge_id, title, text, row["id"], "deleted")
    await _after(row, actor)
    return {"ok": True, "deleted": True}


# ─── Wynik skrócony ─────────────────────────────────────────────────────────


@router.put("/{match_id}/result")
async def put_result(match_id: str, body: ResultBody, actor: Actor = Depends(base_actor)):
    """Wynik skrócony (każdy członek). Zapamiętujemy autora i czas. Wynik ręczny NIGDY nie idzie do ZPRP."""
    row, members, _ = await _load(match_id, actor)
    if body.clear:
        values = {"score_home": None, "score_away": None, "half_home": None, "half_away": None, "result_by": None, "result_at": None}
    else:
        home = _guard(SR.clean_score, body.score_home, "wynik gospodarzy")
        away = _guard(SR.clean_score, body.score_away, "wynik gości")
        if home is None or away is None:
            raise _bad("Wynik wymaga obu liczb (gospodarze i goście).")
        values = {"score_home": home, "score_away": away, "half_home": _guard(SR.clean_score, body.half_home, "wynik do przerwy"),
                  "half_away": _guard(SR.clean_score, body.half_away, "wynik do przerwy"), "result_by": actor.judge_id, "result_at": C.now()}
    changes = SR.diff_fields(row, {**row, **values}, ("score_home", "score_away", "half_home", "half_away"))
    if not changes:
        if body.base_rev is None:
            raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
        return {"ok": True, "unchanged": True, **await detail_payload(row, members, actor)}
    async with database.transaction():
        rev = await _bump(row["id"], actor, body.base_rev, values)
        await _write_log(row["id"], rev, actor.judge_id, "result_clear" if body.clear else "result", changes)
    fresh = await _row(row["id"])
    await _after(fresh, actor)
    return {"ok": True, "unchanged": False, **await detail_payload(fresh, await _members(row["id"]), actor)}


# ─── Obsada ─────────────────────────────────────────────────────────────────


@router.post("/{match_id}/crew")
async def add_crew(match_id: str, body: CrewAddBody, actor: Actor = Depends(base_actor)):
    """Dodaj osoby do obsady (każdy członek). Osoba z blokadą „nie dodawaj mnie przez tę osobę" jest pominięta i wymieniona w `skipped`."""
    row, members, _ = await _load(match_id, actor)
    present = {s(m.get("judge_id")) for m in members if s(m.get("judge_id"))}
    ok, skipped = await _prepare_crew(body.add, actor_id=actor.judge_id, skip_ids=present)
    if len(members) + len(ok) > SR.MAX_MEMBERS:
        raise _bad(f"Obsada może mieć najwyżej {SR.MAX_MEMBERS} osób.")
    if not ok:
        if any(x["reason"] == "BLOCKED" for x in skipped):
            raise HTTPException(409, detail={"code": "ADD_BLOCKED", "skipped": skipped,
                                             "message": "Ta osoba nie chce być dodawana przez Ciebie do meczów wspólnych."})
        if body.base_rev is None:
            raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
        return {"ok": True, "unchanged": True, "skipped": skipped, **await detail_payload(row, members, actor)}
    async with database.transaction():
        rev = await _bump(row["id"], actor, body.base_rev, {})
        added = await _insert_members(row["id"], ok, actor.judge_id)
        names = await _names(a["judge_id"] for a in added if a["judge_id"])
        await _write_log(row["id"], rev, actor.judge_id, "crew_add",
                         [{"field": "crew", "from": None, "to": f"{x['name']} ({x['role']})"} for x in _summary_label(added, names)])
    fresh = await _row(row["id"])
    await _notify_added(fresh, actor, added)
    await _after(fresh, actor)
    return {"ok": True, "unchanged": False, "skipped": skipped, **await detail_payload(fresh, await _members(row["id"]), actor)}


@router.put("/{match_id}/crew/{member_id}")
async def edit_crew(match_id: str, member_id: str, body: CrewEditBody, actor: Actor = Depends(base_actor)):
    """Zmiana roli (twórca: każdemu, członek: sobie) albo nazwy wpisu ręcznego (twórca albo ten, kto go dodał)."""
    row, members, _ = await _load(match_id, actor)
    target = next((m for m in members if m["id"] == member_id), None)
    if not target:
        raise C.err(404, "MEMBER_NOT_FOUND", "Nie ma takiej osoby w obsadzie.")
    is_creator = s(actor.judge_id) == s(row["creator_id"])
    values: Dict[str, Any] = {}
    changes: List[Dict[str, Any]] = []
    if body.role is not None:
        role = _guard(SR.clean_role, body.role)
        manual_owner = not s(target.get("judge_id")) and s(target.get("added_by")) == s(actor.judge_id)
        if not (SR.may_change_role(actor_id=actor.judge_id, creator_id=row["creator_id"], member_judge_id=target.get("judge_id")) or manual_owner):
            raise C.err(403, "NOT_ALLOWED", "Rolę zmienia twórca meczu albo sama osoba.")
        if role != target["role"]:
            values["role"] = role
            changes.append({"field": "role", "from": target["role"], "to": role, "member": target.get("name")})
    if body.name is not None:
        if s(target.get("judge_id")):
            raise _bad("Nazwę można zmienić tylko we wpisie ręcznym (osoby z aplikacji mają własne konto).")
        if not (is_creator or s(target.get("added_by")) == s(actor.judge_id)):
            raise C.err(403, "NOT_ALLOWED", "Wpis ręczny edytuje twórca meczu albo ten, kto go dodał.")
        name = SR.clean_text(body.name, 120)
        if not name:
            raise _bad("Wpis ręczny wymaga imienia i nazwiska.", "MANUAL_NAME_REQUIRED")
        if name != target.get("name"):
            values["name"] = name
            changes.append({"field": "name", "from": target.get("name"), "to": name})
    if not changes:
        if body.base_rev is None:
            raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
        return {"ok": True, "unchanged": True, **await detail_payload(row, members, actor)}
    async with database.transaction():
        rev = await _bump(row["id"], actor, body.base_rev, {})
        await database.execute(update(MM).where(MM.c.id == member_id).values(**values))
        await _write_log(row["id"], rev, actor.judge_id, "crew_edit", changes)
    fresh = await _row(row["id"])
    await _after(fresh, actor)
    return {"ok": True, "unchanged": False, **await detail_payload(fresh, await _members(row["id"]), actor)}


@router.delete("/{match_id}/crew/{member_id}")
async def remove_crew(match_id: str, member_id: str, base_rev: Optional[int] = Query(None), actor: Actor = Depends(base_actor)):
    """Usuń osobę z obsady - TYLKO twórca. Twórcy nie da się usunąć (może ukryć albo usunąć mecz). Usunięta osoba dostaje push."""
    row, members, _ = await _load(match_id, actor)
    target = next((m for m in members if m["id"] == member_id), None)
    if not target:
        raise C.err(404, "MEMBER_NOT_FOUND", "Nie ma takiej osoby w obsadzie.")
    if not SR.may_remove_member(actor_id=actor.judge_id, creator_id=row["creator_id"], member_judge_id=target.get("judge_id")):
        if s(actor.judge_id) == s(row["creator_id"]):
            raise C.err(403, "CREATOR_STAYS", "Twórca nie może usunąć siebie z własnego meczu - może go ukryć u siebie albo usunąć wszystkim.")
        raise C.err(403, "CREATOR_ONLY", "Innych z obsady usuwa tylko twórca meczu. Możesz ukryć mecz u siebie.")
    async with database.transaction():
        rev = await _bump(row["id"], actor, base_rev, {})
        await database.execute(delete(MM).where(MM.c.id == member_id))
        await _write_log(row["id"], rev, actor.judge_id, "crew_remove", [{"field": "crew", "from": f"{target.get('name')} ({target['role']})", "to": None}])
    fresh = await _row(row["id"])
    if s(target.get("judge_id")):
        title, text = N.removed(fresh, actor.display_name)
        await N.send([target["judge_id"]], actor.judge_id, title, text, row["id"], "removed")
    await _after(fresh, actor, [target.get("judge_id")])
    return {"ok": True, **await detail_payload(fresh, await _members(row["id"]), actor)}


# ─── Ukrycie, statystyki ────────────────────────────────────────────────────


@router.post("/{match_id}/hide")
async def hide_match(match_id: str, body: Optional[HideBody] = None, actor: Actor = Depends(base_actor)):
    """Ukryj mecz u siebie (każdy członek). Nic nie znika u innych. `block_adder` = nie dodawaj mnie więcej przez osobę, która mnie dodała."""
    row, members, mine = await _load(match_id, actor)
    await database.execute(update(MM).where(MM.c.id == mine["id"]).values(hidden_at=C.now()))
    blocked_via = None
    adder = s(mine.get("added_by"))
    if body and body.block_adder and adder and adder != s(actor.judge_id):
        if not await _blocked(actor.judge_id, adder):
            await database.execute(insert(BL).values(judge_id=actor.judge_id, via_judge_id=adder, created_at=C.now()))
        blocked_via = adder
    return {"ok": True, "hidden": True, "blocked_via": blocked_via,
            "message": None if (not body or not body.block_adder or blocked_via) else "Tę osobę zostawiłeś(aś) bez blokady - to Ty założyłeś(aś) ten mecz."}


@router.post("/{match_id}/restore")
async def restore_match(match_id: str, actor: Actor = Depends(base_actor)):
    row, members, mine = await _load(match_id, actor)
    await database.execute(update(MM).where(MM.c.id == mine["id"]).values(hidden_at=None))
    return {"ok": True, "hidden": False}


@router.put("/{match_id}/stats")
async def put_stats(match_id: str, body: StatsBody, actor: Actor = Depends(base_actor)):
    """Czy ten mecz liczy się do MOICH statystyk (osobno u każdego członka, domyślnie nie). Nie zmienia `rev` meczu."""
    row, members, mine = await _load(match_id, actor)
    await database.execute(update(MM).where(MM.c.id == mine["id"]).values(counts_in_stats=bool(body.counts_in_stats)))
    return {"ok": True, "counts_in_stats": bool(body.counts_in_stats)}


# ─── Powiązania: ZPRP i ProEl ───────────────────────────────────────────────


@router.put("/{match_id}/zprp")
async def put_zprp(match_id: str, body: ZprpBody, actor: Actor = Depends(base_actor)):
    """Ustaw (albo zdejmij) powiązanie z meczem w bazie ZPRP u wszystkich. Reguły jak `utils/myMatchLink.ts`: tylko liczbowe
    IdZawody; lokalne `id` meczu nigdy się nie zmienia. Wynik ręczny NIE jest wysyłany do ZPRP."""
    row, members, _ = await _load(match_id, actor)
    zid = s(body.zprp_match_id)
    if zid and not SR.is_zprp_id(zid):
        raise _bad("zprp_match_id musi być liczbą (IdZawody z ZPRP).")
    values = {"zprp_match_id": zid or None}
    changes = SR.diff_fields(row, {**row, **values}, ("zprp_match_id",))
    if not changes:
        if body.base_rev is None:
            raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
        return {"ok": True, "unchanged": True, **await detail_payload(row, members, actor)}
    async with database.transaction():
        rev = await _bump(row["id"], actor, body.base_rev, values)
        await _write_log(row["id"], rev, actor.judge_id, "zprp_link", changes)
    fresh = await _row(row["id"])
    await _after(fresh, actor)
    return {"ok": True, "unchanged": False, **await detail_payload(fresh, await _members(row["id"]), actor)}


async def proel_key_allowed(key: str, judge_ids: Iterable[str]) -> bool:
    """Klucz oficjalny - zawsze. Szkoleniowy - tylko gdy zapis (jeśli już istnieje) pisał ktoś z `judge_ids`."""
    from app.proel_training_key import is_training_key

    if not is_training_key(key):
        return True
    row = await C.one(select(saved_matches.c.doc_writer_judge).where(saved_matches.c.match_number == key))
    if not row:
        return True  # mecz dopiero powstaje - klucz czeka na pierwszy zapis
    writer = s(row.get("doc_writer_judge"))
    from app.proel_fields import same_judge_number

    return bool(writer) and any(same_judge_number(writer, j) for j in judge_ids)


@router.put("/{match_id}/proel")
async def put_proel(match_id: str, body: ProelBody, actor: Actor = Depends(base_actor)):
    """Ustaw (albo zdejmij) klucz protokołu ProEla meczu - u wszystkich członków. Wołane też automatycznie, gdy ktoś
    prowadzi ProEla z tego meczu. To tylko wskaźnik: nie zapisuje niczego w `proel_matches` i nie daje praw zapisu."""
    row, members, _ = await _load(match_id, actor)
    key = _guard(SR.clean_proel_key, body.proel_key)
    if key and not await proel_key_allowed(key, [m.get("judge_id") for m in members if m.get("judge_id")]):
        raise C.err(403, "PROEL_SCOPE", "Mecz szkoleniowy może podpiąć tylko jego autor albo osoba z tej obsady.")
    values = {"proel_key": key}
    changes = SR.diff_fields(row, {**row, **values}, ("proel_key",))
    if not changes:
        if body.base_rev is None:
            raise _bad("Brak base_rev - podaj wersję meczu, którą widzisz.", "BASE_REV_REQUIRED")
        return {"ok": True, "unchanged": True, **await detail_payload(row, members, actor)}
    async with database.transaction():
        rev = await _bump(row["id"], actor, body.base_rev, values)
        await _write_log(row["id"], rev, actor.judge_id, "proel_link", changes)
    fresh = await _row(row["id"])
    await _after(fresh, actor)
    return {"ok": True, "unchanged": False, **await detail_payload(fresh, await _members(row["id"]), actor)}


# ─── Powtórz mecz (seria) ───────────────────────────────────────────────────


@router.post("/{match_id}/repeat")
async def repeat_match(match_id: str, body: RepeatBody, actor: Actor = Depends(base_actor)):
    """Kopia meczu z nową datą i kolejnym numerem serii (EHF/1 -> EHF/2). Kopiuje drużyny, miejsce, rozgrywki i (opcjonalnie)
    obsadę; NIE kopiuje wyniku, powiązań ZPRP/ProEl ani statystyk. Autorem kopii jest ten, kto ją tworzy."""
    row, members, mine = await _load(match_id, actor)
    when = _guard(SR.parse_match_at, body.match_at)
    if when is None:
        raise _bad("Podaj datę nowego meczu.")
    own_ids = [s(m["match_id"]) for m in await C.rows(select(MM.c.match_id).where(MM.c.judge_id == actor.judge_id))]
    codes = [s(r.get("code")) for r in await C.rows(select(M.c.code).where(M.c.id.in_(own_ids)).where(M.c.deleted_at.is_(None)))] if own_ids else []
    code = SR.clean_text(body.code, 60) or SR.next_series_code(row.get("code"), codes)
    params = {"code": code, "competition": row.get("competition"), "home_name": row.get("home_name"), "away_name": row.get("away_name"),
              "hall": row.get("hall"), "city": row.get("city"), "match_at": when, "extra": _extra(row)}
    crew = [CrewIn(judge_id=m.get("judge_id"), name=m.get("name"), role=m["role"]) for m in members
            if s(m.get("judge_id")) != s(actor.judge_id)] if body.copy_crew else []
    return await _create(actor, params, force=body.force, crew_in=crew, my_role=mine["role"], counts=False, local_id=None, result=None)
