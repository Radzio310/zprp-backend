"""
Panel „Mentor" - wspólne zaplecze tras: kto pyta, rola w parze, licznik zmian,
mecze pary z trzech źródeł i kształty odpowiedzi (`docs/mentor-panel.md`).

Reguły bez bazy: `app/mentor_panel_rules.py`. Trasy: `app/mentor_panel.py`
(+ `_library`, `_media`, `_reports`, `_auth`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import and_, func, or_, select, text, update

from app import mentor_panel_rules as R
from app.mentoring_rules import state_ref
from app.db import (
    database,
    delegate_evaluations,
    mentor_audit,
    mentor_categories,
    mentor_clips,
    mentor_comments,
    mentor_evaluations,
    mentor_match_flags,
    mentor_match_videos,
    mentor_panels,
    mentor_reads,
    mentor_sheet_seen,
    mentor_thread_prefs,
    mentor_thread_reads,
    mentor_threads,
    mentoring_assignments,
    mentoring_pairs,
    province_judges,
    province_match_judges,
    province_matches,
    saved_matches,
    zprp_archive_matches,
    zprp_public_clubs,
    zprp_public_competitions,
    zprp_public_matches,
)

logger = logging.getLogger("app.mentor_panel")

WEB_BASE = "https://www.bazapodreka.app/mentor"
APP_BASE = "refhandballapp://mentor"


def now() -> datetime:
    return datetime.now(timezone.utc)


def err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def rule_error(exc: R.RuleError) -> HTTPException:
    return err(exc.status, exc.code, exc.message)


def row_dict(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    mapping = getattr(row, "_mapping", None)
    return dict(mapping) if mapping is not None else dict(row)


async def rows(query) -> List[Dict[str, Any]]:
    return [row_dict(r) for r in await database.fetch_all(query)]


async def one(query) -> Optional[Dict[str, Any]]:
    found = await database.fetch_one(query)
    return row_dict(found) if found is not None else None


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


# ─── Kto pyta ───────────────────────────────────────────────────────────────


class MentorActor:
    """Sędzia z JWT aplikacji albo z sesji web (`via`)."""

    def __init__(self, judge_id: str, *, display_name: str = "", is_admin: bool = False, province: str = "",
                 badges: Iterable[str] = (), via: str = "jwt", session: Optional[Dict[str, Any]] = None,
                 photo_url: Optional[str] = None, acted_by: Optional[str] = None,
                 acted_by_name: Optional[str] = None):
        self.judge_id = R.s(judge_id)
        self.display_name = display_name or f"Sędzia {self.judge_id}"
        self.is_admin = bool(is_admin)
        self.province = province
        self.badges = list(badges or ())
        self.via = via
        self.session = session
        self.photo_url = photo_url
        # Tryb `act_as`: administrator (`acted_by`) działa okiem mentora `judge_id`.
        self.acted_by = acted_by or None
        self.acted_by_name = acted_by_name or None

    def as_rule_actor(self) -> Dict[str, Any]:
        return {"judge_id": self.judge_id, "is_admin": self.is_admin, "province": self.province, "badges": self.badges}

    def me(self) -> Dict[str, Any]:
        return {"judge_id": self.judge_id, "display_name": self.display_name, "is_admin": self.is_admin,
                "province": self.province, "photo_url": self.photo_url, "via": self.via,
                "acted_by": self.acted_by, "acted_by_name": self.acted_by_name}


def canonical_province(value: Any) -> str:
    """Ta sama kanonizacja co `mentoring.prov` (lekki import, bez giełdy)."""
    from app.mentoring_rules import CROSS_PROVINCE
    from app.settlement_province import display

    text_value = R.s(value).upper()
    if not text_value or text_value == CROSS_PROVINCE:
        return text_value
    return display(text_value)


async def load_actor(judge_id: str, *, via: str, session: Optional[Dict[str, Any]] = None,
                     display_name: str = "") -> MentorActor:
    from app.match_market_access import badge_names
    from app.proel_auth import is_admin

    row = await one(select(province_judges).where(province_judges.c.judge_id == str(judge_id)))
    row = row or {}
    return MentorActor(
        judge_id,
        display_name=R.s(row.get("full_name")) or display_name,
        is_admin=await is_admin(str(judge_id)),
        province=canonical_province(row.get("province")),
        badges=badge_names(row.get("badges")),
        via=via,
        session=session,
        photo_url=row.get("photo_url"),
    )


# ─── Osoby ──────────────────────────────────────────────────────────────────


async def people(ids: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    wanted = {R.s(i) for i in ids if R.s(i)}
    if not wanted:
        return {}
    found = await rows(select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url)
                       .where(province_judges.c.judge_id.in_(wanted)))
    by_id = {R.s(r["judge_id"]): r for r in found}
    return {
        i: {"judge_id": i, "full_name": R.s((by_id.get(i) or {}).get("full_name")) or f"Sędzia {i}",
            "photo_url": (by_id.get(i) or {}).get("photo_url")}
        for i in wanted
    }


def acted_fields(names: Dict[str, Dict[str, Any]], row: Dict[str, Any]) -> Dict[str, Any]:
    """`acted_by` (administrator działający okiem mentora) i jego nazwisko; null gdy brak."""
    key = R.s(row.get("acted_by"))
    if not key:
        return {"acted_by": None, "acted_by_name": None}
    return {"acted_by": key, "acted_by_name": (names.get(key) or {}).get("full_name") or f"Sędzia {key}"}


def person(names: Dict[str, Dict[str, Any]], judge_id: Any) -> Dict[str, Any]:
    key = R.s(judge_id)
    entry = names.get(key) or {"judge_id": key, "full_name": f"Sędzia {key}"}
    return {"judge_id": key, "name": entry["full_name"]}


# ─── Para i rola ────────────────────────────────────────────────────────────


async def pair_program(pair: Dict[str, Any]) -> str:
    from app.mentoring_rules import pair_program as program_rule
    from app.proel_auth import is_admin

    stored = R.s(pair.get("program"))
    if stored:
        return program_rule(stored)
    creator = R.s(pair.get("created_by"))
    return program_rule(None, bool(creator) and await is_admin(creator), canonical_province(pair.get("province")))


async def mentoring_config(province: str) -> Dict[str, Any]:
    from app.mentoring_rules import CROSS_PROVINCE, DEFAULT_CONFIG
    from app.settlement_province import spellings

    if province == CROSS_PROVINCE or not province:
        return {"province": province, "enabled": False, "manager_ids": []}
    from app.db import mentoring_config as config_table

    found = await one(
        select(config_table).where(config_table.c.province.in_(spellings(province) or [province]))
        .order_by((config_table.c.province == province).desc(), config_table.c.province)
    )
    if not found:
        return {"province": province, **DEFAULT_CONFIG}
    return {**found, "manager_ids": R.json_value(found.get("manager_ids"), [])}


async def ensure_panel(pair_id: str) -> Dict[str, Any]:
    found = await one(select(mentor_panels).where(mentor_panels.c.pair_id == pair_id))
    if found:
        return found
    try:
        await database.execute(mentor_panels.insert().values(pair_id=pair_id, enabled=False, rev=0,
                                                             settings_json="{}", updated_at=now()))
    except Exception:  # noqa: BLE001 - wyścig dwóch pierwszych wejść kończy się jednym wierszem
        pass
    return await one(select(mentor_panels).where(mentor_panels.c.pair_id == pair_id)) or {
        "pair_id": pair_id, "enabled": False, "rev": 0}


async def pair_context(pair_id: str, actor: MentorActor, *, action: str = "view") -> Dict[str, Any]:
    """Para + rola pytającego + stan panelu; odmowa jako `HTTPException` z kodem."""
    pair = await one(select(mentoring_pairs).where(mentoring_pairs.c.id == str(pair_id)))
    if not pair:
        raise err(404, "PAIR_NOT_FOUND", "Nie ma takiej pary.")
    pair["judge_ids"] = [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]
    pair["province"] = canonical_province(pair.get("province"))
    pair["program"] = await pair_program(pair)
    links = await rows(select(mentoring_assignments).where(mentoring_assignments.c.pair_id == pair["id"]))
    rule_actor = actor.as_rule_actor()
    role = R.role_in_pair(rule_actor, pair, links, None)
    config = None
    if role in (None, "admin") or action == "toggle":
        config = await mentoring_config(pair["province"])
        role = role or R.role_in_pair(rule_actor, pair, links, config)
    manages = actor.is_admin or (config is not None and R.committee_scope(rule_actor, pair, config))
    if actor.acted_by:
        if role != "mentor" or actor.judge_id not in {R.s(link["mentor_id"]) for link in links if link.get("ended_at") is None}:
            raise err(403, "ACT_AS_NOT_MENTOR",
                      f"Sędzia {actor.display_name} nie jest mentorem tej pary - nie można działać jego oczami.")
    if role is None:
        raise err(403, "NO_ACCESS", "Nie masz dostępu do panelu tej pary.")
    panel = await ensure_panel(pair["id"])
    enabled = bool(panel.get("enabled"))
    ctx = {
        "pair": pair,
        "pair_id": pair["id"],
        "pair_key": "|".join(sorted(pair["judge_ids"])),
        "judge_ids": pair["judge_ids"],
        "mentor_ids": [R.s(link["mentor_id"]) for link in links if link.get("ended_at") is None],
        "all_mentor_ids": sorted({R.s(link["mentor_id"]) for link in links}),
        "role": role,
        "enabled": enabled,
        "panel": panel,
        "rev": int(panel.get("rev") or 0),
        "manages": bool(manages),
        "actor": actor,
    }
    check(ctx, action)
    return ctx


def check(ctx: Dict[str, Any], action: str, *, owner: bool = False) -> None:
    try:
        R.require(action, ctx["role"], is_admin=ctx["actor"].is_admin, enabled=ctx["enabled"], owner=owner,
                  manages=ctx.get("manages", False))
    except R.RuleError as exc:
        raise rule_error(exc) from exc


def may(ctx: Dict[str, Any], action: str, *, owner: bool = False) -> bool:
    return R.can(action, ctx["role"], is_admin=ctx["actor"].is_admin, enabled=ctx["enabled"], owner=owner,
                 manages=ctx.get("manages", False))


def member_role(ctx: Dict[str, Any], judge_id: Any) -> str:
    judge_id = R.s(judge_id)
    if judge_id in ctx["judge_ids"]:
        return "pair"
    if judge_id in ctx["all_mentor_ids"]:
        return "mentor"
    return "admin"


def links_of(pair_id: str) -> Dict[str, str]:
    return {"web": f"{WEB_BASE}/{pair_id}", "app": f"{APP_BASE}/{pair_id}"}


# ─── Licznik zmian (long-poll) ──────────────────────────────────────────────

_waiters: Dict[str, asyncio.Event] = {}


def _event(pair_id: str) -> asyncio.Event:
    ev = _waiters.get(pair_id)
    if ev is None:
        ev = _waiters[pair_id] = asyncio.Event()
    return ev


def wake(pair_id: str) -> None:
    ev = _waiters.pop(pair_id, None)
    if ev is not None:
        ev.set()


async def touch(ctx_or_pair: Any, actor_id: str, action: str, scope: str, match_id: Optional[str] = None,
                data: Optional[Dict[str, Any]] = None) -> int:
    """Każdy zapis podbija `mentor_panels.rev` i zostawia ślad w `mentor_audit`."""
    pair_id = ctx_or_pair["pair_id"] if isinstance(ctx_or_pair, dict) else str(ctx_or_pair)
    acted_by = ctx_or_pair["actor"].acted_by if isinstance(ctx_or_pair, dict) and ctx_or_pair.get("actor") else None
    await ensure_panel(pair_id)
    await database.execute(
        update(mentor_panels).where(mentor_panels.c.pair_id == pair_id)
        .values(rev=mentor_panels.c.rev + 1, updated_at=now())
    )
    found = await one(select(mentor_panels.c.rev).where(mentor_panels.c.pair_id == pair_id))
    rev = int((found or {}).get("rev") or 0)
    try:
        await database.execute(mentor_audit.insert().values(
            id=R.new_id(), pair_id=pair_id, actor_id=str(actor_id or ""), action=action, data=dumps(data or {}),
            rev=rev, scope=scope, match_id=match_id, acted_by=acted_by, created_at=now(),
        ))
    except Exception:  # noqa: BLE001 - ślad nie może cofnąć zapisu
        logger.warning("mentor: zapis śladu nieudany", exc_info=True)
    _rev_cache.pop(pair_id, None)
    if isinstance(ctx_or_pair, dict):
        ctx_or_pair["rev"] = rev
    wake(pair_id)
    return rev


TICK_S = 1.5
MAX_WAIT_S = 25
_rev_cache: Dict[str, Tuple[float, int]] = {}


async def current_rev(pair_id: str) -> int:
    """Wspólny zegar: wiele osób na jednej parze pyta bazę najwyżej raz na `TICK_S`."""
    cached = _rev_cache.get(pair_id)
    if cached and time.monotonic() - cached[0] < TICK_S:
        return cached[1]
    found = await one(select(mentor_panels.c.rev).where(mentor_panels.c.pair_id == pair_id))
    rev = int((found or {}).get("rev") or 0)
    _rev_cache[pair_id] = (time.monotonic(), rev)
    if len(_rev_cache) > 2000:
        _rev_cache.clear()
    return rev


async def wait_for_change(pair_id: str, since: int, wait: float) -> int:
    rev = await current_rev(pair_id)
    deadline = time.monotonic() + max(0.0, min(float(wait or 0), MAX_WAIT_S))
    while rev <= since and time.monotonic() < deadline:
        ev = _event(pair_id)
        try:
            await asyncio.wait_for(ev.wait(), timeout=min(TICK_S, max(0.05, deadline - time.monotonic())))
        except asyncio.TimeoutError:
            pass
        rev = await current_rev(pair_id)
    return rev


async def changes_since(pair_id: str, since: int, limit: int = 500) -> Dict[str, Any]:
    found = await rows(
        select(mentor_audit.c.rev, mentor_audit.c.scope, mentor_audit.c.match_id)
        .where(mentor_audit.c.pair_id == pair_id).where(mentor_audit.c.rev > since)
        .order_by(mentor_audit.c.rev.desc()).limit(limit)
    )
    scopes = sorted({R.s(r["scope"]) for r in found if R.s(r["scope"])})
    match_ids = sorted({R.s(r["match_id"]) for r in found if R.s(r["match_id"])})
    return {"scopes": scopes, "match_ids": match_ids}


# ─── Obecność („Mentor ogląda teraz") ───────────────────────────────────────

_presence: Dict[str, Dict[str, Dict[str, Any]]] = {}


def set_presence(pair_id: str, actor: MentorActor, where: str) -> None:
    room = _presence.setdefault(pair_id, {})
    room[actor.judge_id] = {"judge_id": actor.judge_id, "name": actor.display_name, "where": where,
                            "at": time.monotonic()}


def viewers(pair_id: str, me: str = "") -> List[Dict[str, Any]]:
    room = _presence.get(pair_id) or {}
    limit = time.monotonic() - R.PRESENCE_TTL_S
    for judge_id in [j for j, v in room.items() if v["at"] < limit]:
        room.pop(judge_id, None)
    return [{k: v[k] for k in ("judge_id", "name", "where")} for j, v in sorted(room.items()) if j != me]


# ─── Mecze pary ─────────────────────────────────────────────────────────────

MATCH_CACHE_S = 60
_match_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}


def forget_matches(pair_key: str = "") -> None:
    if pair_key:
        _match_cache.pop(pair_key, None)
    else:
        _match_cache.clear()


async def _public_cards(a: str, b: str) -> List[Dict[str, Any]]:
    M = zprp_public_matches
    found = await rows(select(M).where(or_(and_(M.c.referee_1_id == a, M.c.referee_2_id == b),
                                           and_(M.c.referee_1_id == b, M.c.referee_2_id == a))))
    if not found:
        return []
    club_ids = {R.s(r.get(k)) for r in found for k in ("home_club_id", "away_club_id") if R.s(r.get(k))}
    logos: Dict[str, Any] = {}
    if club_ids:
        for club in await rows(select(zprp_public_clubs.c.club_id, zprp_public_clubs.c.logo_url)
                               .where(zprp_public_clubs.c.club_id.in_(club_ids))):
            logos[R.s(club["club_id"])] = club.get("logo_url")
    comp_ids = {R.s(r.get("competition_id")) for r in found if R.s(r.get("competition_id"))}
    categories: Dict[str, Any] = {}
    if comp_ids:
        for comp in await rows(select(zprp_public_competitions.c.competition_id, zprp_public_competitions.c.category)
                               .where(zprp_public_competitions.c.competition_id.in_(comp_ids))):
            categories[R.s(comp["competition_id"])] = comp.get("category")
    return [R.card_from_public(r, logos, categories.get(R.s(r.get("competition_id")))) for r in found]


async def _province_cards(a: str, b: str) -> List[Dict[str, Any]]:
    J = province_match_judges
    hits = await rows(
        select(J.c.province, J.c.match_id).where(J.c.judge_id.in_([a, b]))
        .group_by(J.c.province, J.c.match_id).having(func.count(func.distinct(J.c.judge_id)) == 2)
    )
    if not hits:
        return []
    ids = sorted({R.s(h["match_id"]) for h in hits})
    found = await rows(select(province_matches.c.match_id, province_matches.c.match_at, province_matches.c.state_json,
                              province_matches.c.active, province_matches.c.updated_at)
                       .where(province_matches.c.match_id.in_(ids)))
    found.sort(key=lambda r: (bool(r.get("active")), R.aware(r.get("updated_at")) or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    out, seen = [], set()
    for r in found:
        match_id = R.s(r["match_id"])
        if match_id in seen:
            continue
        state = R.json_value(r.get("state_json"), {})
        if not R.pair_refs_match((a, b), state_ref(state, "NrSedzia_pierwszy"), state_ref(state, "NrSedzia_drugi")):
            continue
        seen.add(match_id)
        out.append(R.card_from_state(match_id, state, r.get("match_at")))
    return out


async def _archive_cards(a: str, b: str) -> List[Dict[str, Any]]:
    A = zprp_archive_matches
    if is_postgres():
        # Dokładnie wyrażenie z indeksu (`mentor_panel_tables.MIGRATIONS`) - bez
        # parametrów w kluczach i bez rzutowań, inaczej planista nie użyje indeksu.
        first, second = "(zprp_archive_matches.slim_json->'refs'->>'first')", "(zprp_archive_matches.slim_json->'refs'->>'second')"
        condition = text(f"({first} = :ref_a AND {second} = :ref_b) OR ({first} = :ref_b AND {second} = :ref_a)").bindparams(ref_a=a, ref_b=b)
    else:
        first_col = A.c.slim_json["refs"]["first"].as_string()
        second_col = A.c.slim_json["refs"]["second"].as_string()
        condition = or_(and_(first_col == a, second_col == b), and_(first_col == b, second_col == a))
    found = await rows(select(A.c.match_id, A.c.code, A.c.match_at, A.c.slim_json).where(condition))
    return [R.card_from_archive(r) for r in found]


async def pair_match_cards(judge_ids: Iterable[str]) -> List[Dict[str, Any]]:
    """Wszystkie mecze pary (cała historia): hurtownia + monitor okręgu + archiwum."""
    ids = sorted({R.s(j) for j in judge_ids if R.s(j)})
    if len(ids) != 2:
        return []
    key = "|".join(ids)
    cached = _match_cache.get(key)
    if cached and time.monotonic() - cached[0] < MATCH_CACHE_S:
        return [dict(c, home=dict(c["home"]), away=dict(c["away"])) for c in cached[1]]
    a, b = ids
    async def load(loader):
        try:
            return await loader(a, b)
        except Exception:  # noqa: BLE001 - jedno źródło nie zabiera reszty
            logger.warning("mentor: źródło meczów %s nieudane", loader.__name__, exc_info=True)
            return []

    # Trzy niezależne źródła (hurtownia, monitor okręgu, archiwum) naraz.
    sources = list(await asyncio.gather(*(load(l) for l in (_public_cards, _province_cards, _archive_cards))))
    cards = R.merge_matches(*sources)
    _match_cache[key] = (time.monotonic(), cards)
    if len(_match_cache) > 500:
        _match_cache.clear()
    return [dict(c, home=dict(c["home"]), away=dict(c["away"])) for c in cards]


def is_postgres() -> bool:
    url = str(getattr(database, "url", "") or "")
    return url.startswith("postgres")


async def delegate_sheet_rows(judge_ids: List[str], match_ids: Iterable[str]) -> List[Dict[str, Any]]:
    """Arkusze delegatów meczów pary (nowa reguła dostępu: oboje sędziowie arkusza = para)."""
    D = delegate_evaluations
    ids = sorted({R.s(m) for m in match_ids if R.s(m)})
    if is_postgres():
        query = select(D).where(D.c.referee_ids.contains([judge_ids[0]])).where(D.c.referee_ids.contains([judge_ids[1]]))
    elif ids:
        query = select(D).where(D.c.match_id.in_(ids))
    else:
        return []
    found = await rows(query)
    return [r for r in found if R.pair_role_sees_delegate_sheet("pair", R.json_value(r.get("referee_ids"), []), judge_ids)]


async def mentor_sheet_rows(pair_key: str) -> List[Dict[str, Any]]:
    return await rows(select(mentor_evaluations).where(mentor_evaluations.c.pair_key == pair_key)
                      .where(mentor_evaluations.c.status == "published"))


async def unread_threads(pair_id: str, judge_id: str) -> Dict[str, Optional[str]]:
    """Wątki z odpowiedziami innych po moim ostatnim przeczytaniu: `{thread_id: match_id}`.

    Jedno zapytanie (GROUP BY po wątku + LEFT JOIN do moich odczytów) zamiast
    wczytywania wszystkich komentarzy pary do Pythona.
    """
    me = R.s(judge_id)
    last = (select(mentor_comments.c.thread_id.label("thread_id"), mentor_threads.c.match_id.label("match_id"),
                   func.max(mentor_comments.c.created_at).label("last_at"))
            .select_from(mentor_comments.join(mentor_threads, mentor_threads.c.id == mentor_comments.c.thread_id))
            .where(mentor_threads.c.pair_id == pair_id).where(mentor_comments.c.deleted_at.is_(None))
            .where(mentor_comments.c.author_id != me)
            .group_by(mentor_comments.c.thread_id, mentor_threads.c.match_id)).subquery()
    query = (select(last.c.thread_id, last.c.match_id)
             .select_from(last.outerjoin(mentor_thread_reads, and_(mentor_thread_reads.c.thread_id == last.c.thread_id,
                                                                   mentor_thread_reads.c.judge_id == me)))
             .where(or_(mentor_thread_reads.c.seen_at.is_(None), last.c.last_at > mentor_thread_reads.c.seen_at)))
    return {r["thread_id"]: r.get("match_id") for r in await rows(query)}


async def unseen_sheets(pair_key: str, judge_id: str) -> Dict[str, str]:
    """Wysłane oceny mentorów nieotwarte przeze mnie (poza moimi): `{evaluation_id: match_id}`."""
    me = R.s(judge_id)
    sheets = [r for r in await mentor_sheet_rows(pair_key)
              if r.get("author_id") != me and me not in R.json_value(r.get("co_author_ids"), [])]
    if not sheets:
        return {}
    seen = {r["evaluation_id"] for r in await rows(select(mentor_sheet_seen.c.evaluation_id).where(mentor_sheet_seen.c.judge_id == me)
                                                   .where(mentor_sheet_seen.c.evaluation_id.in_([r["id"] for r in sheets])))}
    return {r["id"]: R.s(r["match_id"]) for r in sheets if r["id"] not in seen}


async def mark_sheets_seen(pair_key: str, match_id: str, judge_id: str) -> int:
    stamp = now()
    done = 0
    for evaluation_id, mid in (await unseen_sheets(pair_key, judge_id)).items():
        if mid == R.s(match_id):
            await database.execute(mentor_sheet_seen.insert().values(evaluation_id=evaluation_id, judge_id=R.s(judge_id), seen_at=stamp))
            done += 1
    return done


async def enrich_cards(ctx: Dict[str, Any], cards: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flagi pary, wideo, klipy, wątki i punkty arkuszy na kartach meczów (zapytania zbiorcze)."""
    if not cards:
        return cards
    ids = [c["match_id"] for c in cards]
    pair_id, key = ctx["pair_id"], ctx["pair_key"]
    me = ctx["actor"].judge_id

    async def load_flags() -> Dict[str, Any]:
        return {r["match_id"]: r for r in await rows(select(mentor_match_flags).where(mentor_match_flags.c.pair_id == pair_id)
                                                     .where(mentor_match_flags.c.match_id.in_(ids)))}

    async def load_videos() -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for v in await rows(select(mentor_match_videos.c.match_id, mentor_match_videos.c.kind)
                            .where(mentor_match_videos.c.match_id.in_(ids)).where(mentor_match_videos.c.pair_key == key)):
            entry = out.setdefault(R.s(v["match_id"]), {"count": 0, "uploads": 0})
            entry["count"] += 1
            entry["uploads"] += 1 if v.get("kind") == "upload" else 0
        return out

    async def load_clips() -> Dict[str, int]:
        return {R.s(c["match_id"]): int(c["n"] or 0) for c in await rows(
            select(mentor_clips.c.match_id, func.count().label("n")).where(mentor_clips.c.pair_id == pair_id)
            .where(mentor_clips.c.deleted_at.is_(None)).where(mentor_clips.c.match_id.in_(ids))
            .group_by(mentor_clips.c.match_id))}

    async def load_threads() -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for t in await rows(select(mentor_threads.c.match_id, mentor_threads.c.status).where(mentor_threads.c.pair_id == pair_id)
                            .where(mentor_threads.c.match_id.in_(ids))):
            entry = out.setdefault(R.s(t["match_id"]), {"open": 0, "total": 0})
            entry["total"] += 1
            entry["open"] += 1 if t.get("status") == "open" else 0
        return out

    async def load_delegate() -> Dict[str, Optional[float]]:
        out: Dict[str, Optional[float]] = {}
        try:
            for d in await delegate_sheet_rows(ctx["judge_ids"], ids):
                out[R.s(d["match_id"])] = R.sheet_points(R.json_value(d.get("evaluation_json"), {}))
        except Exception:  # noqa: BLE001
            logger.warning("mentor: arkusze delegatów nieczytelne", exc_info=True)
        return out

    async def load_mentor() -> Dict[str, Optional[float]]:
        return {R.s(m["match_id"]): m.get("points") for m in await mentor_sheet_rows(key)}

    codes = sorted({R.s(c.get("match_code")) for c in cards if R.s(c.get("match_code"))})

    async def load_proel() -> Tuple[set, set]:
        proel_ids, proel_codes = set(), set()
        try:
            cond = [saved_matches.c.zprp_match_id.in_(ids)]
            if codes:
                cond.append(saved_matches.c.match_number.in_(codes))
            for p in await rows(select(saved_matches.c.match_number, saved_matches.c.zprp_match_id).where(or_(*cond))):
                if R.s(p.get("zprp_match_id")):
                    proel_ids.add(R.s(p["zprp_match_id"]))
                else:
                    proel_codes.add(R.s(p.get("match_number")))
        except Exception:  # noqa: BLE001
            logger.warning("mentor: odczyt protokołów ProEla nieudany", exc_info=True)
        return proel_ids, proel_codes

    async def load_sheet_unseen() -> set:
        return set((await unseen_sheets(key, me)).values()) if me in ctx["judge_ids"] else set()

    # Niezależne odczyty równolegle (każdy na własnym połączeniu z puli).
    (flags, videos, clips, threads, delegate_points, mentor_points, (proel_ids, proel_codes),
     unread, sheet_unseen) = await asyncio.gather(
        load_flags(), load_videos(), load_clips(), load_threads(), load_delegate(), load_mentor(), load_proel(),
        unread_threads(pair_id, me), load_sheet_unseen())
    unseen_by_match: Dict[str, int] = {}
    for mid in unread.values():
        unseen_by_match[R.s(mid)] = unseen_by_match.get(R.s(mid), 0) + 1
    for card in cards:
        match_id = card["match_id"]
        flag = flags.get(match_id) or {}
        card.update({
            "starred": bool(flag.get("starred")),
            "star_reason": flag.get("star_reason"),
            "submitted": bool(flag.get("submitted")),
            "review_status": flag.get("review_status"),
            "due_at": flag.get("due_at"),
            "has_proel": match_id in proel_ids or R.s(card.get("match_code")) in proel_codes,
            "videos": videos.get(match_id, {"count": 0, "uploads": 0}),
            "clips": {"count": clips.get(match_id, 0)},
            "threads": threads.get(match_id, {"open": 0, "total": 0}),
            "sheets": {"delegate": delegate_points.get(match_id), "mentor": mentor_points.get(match_id)},
            "unseen": {"threads": unseen_by_match.get(match_id, 0), "sheet": match_id in sheet_unseen},
        })
        card.pop("source", None)
    return cards


async def match_card(ctx: Dict[str, Any], match_id: str, *, required: bool = True) -> Optional[Dict[str, Any]]:
    cards = [c for c in await pair_match_cards(ctx["judge_ids"]) if c["match_id"] == R.s(match_id)]
    if not cards:
        if required:
            raise err(404, "MATCH_NOT_FOUND", "To nie jest mecz tej pary.")
        return None
    return (await enrich_cards(ctx, cards))[0]


# ─── Kategorie ──────────────────────────────────────────────────────────────


async def categories(ctx: Dict[str, Any], *, seed: bool = True) -> List[Dict[str, Any]]:
    C = mentor_categories
    found = await rows(select(C).where(or_(C.c.pair_id == ctx["pair_id"], C.c.pair_id.is_(None))))
    if seed and not any(r.get("pair_id") == ctx["pair_id"] for r in found):
        for row in R.default_category_rows(ctx["pair_id"], "", now()):
            await database.execute(C.insert().values(**row))
        found = await rows(select(C).where(or_(C.c.pair_id == ctx["pair_id"], C.c.pair_id.is_(None))))
    found.sort(key=lambda r: (r.get("pair_id") is None, bool(r.get("archived")), int(r.get("sort") or 0), R.s(r.get("name"))))
    return found


def category_shape(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"], "key": row.get("key"), "name": row.get("name"), "color": row.get("color"),
        "icon": row.get("icon"), "description": row.get("description"), "sort": int(row.get("sort") or 0),
        "archived": bool(row.get("archived")), "global": row.get("pair_id") is None, "created_by": row.get("created_by"),
    }


# ─── Kształty ───────────────────────────────────────────────────────────────


def clip_shape(ctx: Dict[str, Any], row: Dict[str, Any], names: Dict[str, Dict[str, Any]],
               thread: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    owner = R.s(row.get("author_id")) == ctx["actor"].judge_id
    return {
        "id": row["id"], "match_id": row.get("match_id"), "video_id": row.get("video_id"),
        "start_s": row.get("start_s"), "end_s": row.get("end_s"), "title": row.get("title"), "note": row.get("note"),
        "category_ids": R.json_value(row.get("category_ids"), []), "source": row.get("source"),
        "source_key": row.get("source_key"), "match_ms": row.get("match_ms"), "half": row.get("half"),
        "author": person(names, row.get("author_id")), **acted_fields(names, row), "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"), "can_edit": may(ctx, "edit", owner=owner),
        "mp4_status": row.get("mp4_status") or "none",
        "important": bool(row.get("important")), "to_discuss": bool(row.get("to_discuss")),
        "public_url": R.public_url("clip", row.get("public_token")),
        "thread": thread,
    }


async def clip_threads(pair_id: str, clip_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not clip_ids:
        return {}
    found = await rows(select(mentor_threads).where(mentor_threads.c.pair_id == pair_id)
                       .where(mentor_threads.c.target_kind == "clip").where(mentor_threads.c.target_id.in_(clip_ids))
                       .order_by(mentor_threads.c.created_at.asc()))
    counts: Dict[str, int] = {}
    if found:
        for c in await rows(select(mentor_comments.c.thread_id, func.count().label("n"))
                            .where(mentor_comments.c.thread_id.in_([t["id"] for t in found]))
                            .where(mentor_comments.c.deleted_at.is_(None)).group_by(mentor_comments.c.thread_id)):
            counts[c["thread_id"]] = int(c["n"] or 0)
    out: Dict[str, Dict[str, Any]] = {}
    for t in found:
        out.setdefault(R.s(t["target_id"]), {"id": t["id"], "open": t.get("status") == "open", "comments": counts.get(t["id"], 0)})
    return out


async def clips_payload(ctx: Dict[str, Any], clip_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    names = await people({r.get("author_id") for r in clip_rows} | {r.get("acted_by") for r in clip_rows})
    threads = await clip_threads(ctx["pair_id"], [r["id"] for r in clip_rows])
    return [clip_shape(ctx, r, names, threads.get(r["id"])) for r in clip_rows]


def comment_shape(ctx: Dict[str, Any], row: Dict[str, Any], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    author = person(names, row.get("author_id"))
    owner = author["judge_id"] == ctx["actor"].judge_id
    drawing = R.json_value(row.get("drawing_json"), [])
    return {
        "id": row["id"], "author": {**author, "role": member_role(ctx, author["judge_id"])}, **acted_fields(names, row),
        "body": row.get("body"),
        "video_id": row.get("video_id"), "video_s": row.get("video_s"), "drawing": drawing or None,
        "mentions": R.json_value(row.get("mentions"), []), "created_at": row.get("created_at"),
        "edited_at": row.get("edited_at"), "can_edit": may(ctx, "edit", owner=owner),
    }


async def threads_payload(ctx: Dict[str, Any], thread_rows: List[Dict[str, Any]], *, with_comments: bool = True) -> List[Dict[str, Any]]:
    ids = [t["id"] for t in thread_rows]
    comments: Dict[str, List[Dict[str, Any]]] = {}
    if ids:
        for c in await rows(select(mentor_comments).where(mentor_comments.c.thread_id.in_(ids))
                            .where(mentor_comments.c.deleted_at.is_(None)).order_by(mentor_comments.c.created_at.asc())):
            comments.setdefault(c["thread_id"], []).append(c)
    me = ctx["actor"].judge_id
    my_prefs = {r["thread_id"]: r["mode"] for r in await rows(select(mentor_thread_prefs).where(mentor_thread_prefs.c.judge_id == me)
                                                               .where(mentor_thread_prefs.c.thread_id.in_(ids)))} if ids else {}
    unread_ids = set(await unread_threads(ctx["pair_id"], me)) if ids else set()
    names = await people({t.get("created_by") for t in thread_rows} | {t.get("acted_by") for t in thread_rows}
                         | {c.get("author_id") for cs in comments.values() for c in cs}
                         | {c.get("acted_by") for cs in comments.values() for c in cs})
    out = []
    for t in thread_rows:
        items = comments.get(t["id"], [])
        shaped = {
            "id": t["id"], "target_kind": t.get("target_kind"), "target_id": t.get("target_id"), "match_id": t.get("match_id"),
            "title": t.get("title"), "kind": t.get("kind"), "status": t.get("status"),
            "created_by": person(names, t.get("created_by")), **acted_fields(names, t), "created_at": t.get("created_at"),
            "last_comment_at": t.get("last_comment_at"),
            "my_follow": my_prefs.get(t["id"]) or "auto", "unread": t["id"] in unread_ids,
            "can_edit": may(ctx, "edit", owner=R.s(t.get("created_by")) == ctx["actor"].judge_id),
        }
        if with_comments:
            shaped["comments"] = [comment_shape(ctx, c, names) for c in items]
        else:
            last = items[-1] if items else None
            shaped["comments_count"] = len(items)
            shaped["last_comment"] = {"author": person(names, last.get("author_id")), "body": R.s(last.get("body"))[:160],
                                      "created_at": last.get("created_at")} if last else None
        out.append(shaped)
    return out


def pair_people_shape(pair: Dict[str, Any], mentor_ids: List[str], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    def full(judge_id: str) -> Dict[str, Any]:
        entry = names.get(judge_id) or {"judge_id": judge_id, "full_name": f"Sędzia {judge_id}", "photo_url": None}
        return {"judge_id": judge_id, "full_name": entry["full_name"], "photo_url": entry.get("photo_url")}

    return {
        "id": pair["id"], "program": pair.get("program"), "province": pair.get("province"),
        "judges": [full(j) for j in pair["judge_ids"]], "mentors": [full(m) for m in mentor_ids],
        "created_at": pair.get("created_at"), "ended_at": pair.get("ended_at"),
    }


async def mark_read(ctx: Dict[str, Any]) -> None:
    me = ctx["actor"].judge_id
    stamp = now()
    found = await one(select(mentor_reads).where(mentor_reads.c.pair_id == ctx["pair_id"]).where(mentor_reads.c.judge_id == me))
    try:
        if found:
            await database.execute(update(mentor_reads).where(mentor_reads.c.pair_id == ctx["pair_id"])
                                   .where(mentor_reads.c.judge_id == me).values(seen_rev=ctx["rev"], seen_at=stamp))
        else:
            await database.execute(mentor_reads.insert().values(pair_id=ctx["pair_id"], judge_id=me, seen_rev=ctx["rev"], seen_at=stamp))
    except Exception:  # noqa: BLE001 - znacznik przeczytania nie psuje pulpitu
        logger.warning("mentor: zapis przeczytania nieudany", exc_info=True)
