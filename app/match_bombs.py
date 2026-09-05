# app/match_bombs.py
#
# Bomby - zgłoszenia, że sędziego nie było na meczu.
#
# Rejestr prowadzi komisja sędziowska okręgu; zgłasza obsada meczu, o kimś z tej
# samej obsady (także o sobie - „nie dojechałem" to też fakt, który warto mieć
# zapisany po swojej stronie).
#
# Wszystkie reguły - kto, komu, w jakim oknie czasu, kto widzi autora i co
# liczy się do rankingu - mieszkają w `app/match_bombs_rules.py`. Tutaj jest
# wyłącznie baza, uprawnienia i powiadomienia.
#
# ODMOWA JEST ZDANIEM, nie kodem. Każde 403 i 409 niesie tekst, który da się
# pokazać człowiekowi wprost - kafel ma napisać, czemu opcji nie ma, a nie
# zgasnąć bez słowa.

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, insert, or_, select, update

from app.db import database, match_bombs, province_judges, province_matches
from app.match_bombs_rules import (
    COMMISSION_BADGE,
    SUBJECT_NOTICE_DELAY_HOURS,
    author_is_visible,
    bomb_sentence,
    counts_to_stats,
    crew_from_payload,
    crew_from_state,
    find_in_crew,
    may_report,
    may_void,
    may_withdraw,
    month_key,
    month_label,
    rank_bombs,
    season_label,
    season_of,
    slot_label,
)
# Jeden aktor na aplikację, nie drugi taki sam. `market_actor` czyta token,
# dociąga wiersz z listy sędziów okręgu (numer, nazwisko, okręg, odznaki) i
# pyta, czy to administrator - dokładnie to, czego potrzebuje rejestr bomb.
# Kopia tej logiki znaczyłaby dwa miejsca, w których można się pomylić o to,
# kim jest zalogowany człowiek.
from app.match_market import Actor, market_actor
from app.match_market_access import badge_names
from app.match_market_rules import CREW_STATE_FIELDS, state_dict
from app.push.push import send_push_to_judges

logger = logging.getLogger("app.match_bombs")

router = APIRouter(prefix="/match-bombs", tags=["Bomby"])


def _s(value: Any) -> str:
    return str(value or "").strip()


def _row(row: Any) -> Dict[str, Any]:
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def _is_commission(actor: Actor) -> bool:
    """Komisja sędziowska albo administrator aplikacji.

    Administrator przechodzi zawsze i bez odznaki - tak samo, jak w każdym
    innym module okręgowym.
    """
    if actor.is_admin:
        return True
    return COMMISSION_BADGE in badge_names(actor.badges)


def _require_province(actor: Actor) -> str:
    if not actor.province:
        raise HTTPException(
            403,
            "Nie ma Cię na liście sędziów okręgu, więc nie wiem, do którego "
            "rejestru miałoby trafić to zgłoszenie. Zgłoś to administratorowi okręgu.",
        )
    return actor.province


async def _commission_of(province: str) -> List[str]:
    """Numery sędziów, którzy w tym okręgu prowadzą rejestr."""
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.badges).where(
            province_judges.c.province == province
        )
    )
    return [
        _s(_row(r)["judge_id"])
        for r in rows
        if COMMISSION_BADGE in badge_names(_row(r).get("badges"))
    ]


async def _notify(judge_ids: List[str], title: str, body: str, bomb: Dict[str, Any]) -> None:
    """Wysyłka, która nigdy nie wywraca czynności, przy której powstała."""
    targets = sorted({_s(j) for j in judge_ids if _s(j)})
    if not targets:
        return
    try:
        await send_push_to_judges(
            targets,
            title,
            body,
            {
                "kind": "match_bomb",
                "bombId": str(bomb.get("id") or ""),
                "matchId": _s(bomb.get("match_id")),
                "matchCode": _s(bomb.get("match_code")),
            },
        )
    except Exception:  # noqa: BLE001
        logger.warning("bomby: powiadomienie nieudane", exc_info=True)


async def _match_crew(province: str, match_id: str, fallback: Any) -> tuple[List[Dict[str, str]], str]:
    """Obsada meczu i to, skąd ją znamy.

    Terminarz okręgu jest źródłem pierwszym, bo jego nikt z telefonu nie
    napisze. Mecz spoza okręgu - centralny, turniejowy - w terminarzu nie
    istnieje, a zgłaszać przy nim wolno; wtedy zostaje obsada z aplikacji i
    rejestr zapisuje, że tak było.
    """
    row = await database.fetch_one(
        select(province_matches.c.state_json).where(
            and_(
                province_matches.c.province == province,
                province_matches.c.match_id == match_id,
            )
        )
    )
    if row:
        crew = crew_from_state(state_dict(_row(row).get("state_json")))
        if crew:
            return crew, "province"
    return crew_from_payload(fallback or ()), "app"


def _view(bomb: Dict[str, Any], viewer: str, is_commission: bool) -> Dict[str, Any]:
    """Zgłoszenie tak, jak wolno je zobaczyć TEMU widzowi."""
    show_author = author_is_visible(bomb, viewer, is_commission=is_commission)
    return {
        "id": int(bomb["id"]),
        "matchId": _s(bomb.get("match_id")),
        "matchCode": _s(bomb.get("match_code")),
        "matchAt": _iso(bomb.get("match_at")),
        "hostTeam": _s(bomb.get("host_team")),
        "guestTeam": _s(bomb.get("guest_team")),
        "season": bomb.get("season"),
        "seasonLabel": season_label(bomb.get("season")) if bomb.get("season") else "",
        "subjectJudgeId": _s(bomb.get("subject_judge_id")),
        "subjectName": _s(bomb.get("subject_name")),
        "subjectSlot": _s(bomb.get("subject_slot")),
        "subjectRole": slot_label(bomb.get("subject_slot")),
        "note": _s(bomb.get("note")) or None,
        "status": _s(bomb.get("status")),
        "createdAt": _iso(bomb.get("created_at")),
        # Nazwisko autora tylko dla tych, którzy mają prawo je znać; `mine`
        # dostaje każdy, bo bez tego nie wiedziałby, co wolno mu cofnąć.
        "authorName": _s(bomb.get("author_name")) if show_author else "",
        "authorJudgeId": _s(bomb.get("author_judge_id")) if show_author else "",
        "mine": _s(bomb.get("author_judge_id")) == _s(viewer),
        "aboutMe": _s(bomb.get("subject_judge_id")) == _s(viewer) and bool(viewer),
        "voidReason": _s(bomb.get("void_reason")) or None,
        "voidByName": _s(bomb.get("void_by_name")) or None,
        "voidedAt": _iso(bomb.get("voided_at")),
        "crewSource": _s(bomb.get("crew_source")),
    }


@router.get("/me", summary="Czy widzę rejestr i którego okręgu")
async def who_am_i(actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    """Jedno lekkie pytanie dla menu „Więcej".

    Kafel rejestru pojawia się tylko tym, którzy mają go po co otwierać -
    ekran, który wita odmową, jest gorszy od jego braku. Menu nie ma jak
    policzyć odznak samo, bo lista sędziów okręgu to osobne, cięższe pobranie.
    """
    return {
        "judgeId": actor.judge_id,
        "province": actor.province,
        "fullName": actor.full_name,
        "isAdmin": actor.is_admin,
        "isCommission": _is_commission(actor),
    }


# ─────────────────────────── ekran meczu ───────────────────────────


class CrewMember(BaseModel):
    slot: str
    name: str = ""
    judgeId: str = ""


class ReportRequest(BaseModel):
    match_id: str
    subject_slot: str
    subject_name: str = ""
    subject_judge_id: str = ""
    note: str = ""
    match_code: str = ""
    match_at: Optional[datetime] = None
    host_team: str = ""
    guest_team: str = ""
    hall: str = ""
    crew: List[CrewMember] = []


class VoidRequest(BaseModel):
    reason: str = ""


@router.get("/match/{match_id}", summary="Bomby przy tym meczu i co mi wolno")
async def bombs_for_match(
    match_id: str,
    match_at: Optional[datetime] = Query(
        None, description="Termin meczu z aplikacji - do policzenia okna zgłoszeń."
    ),
    actor: Actor = Depends(market_actor),
) -> Dict[str, Any]:
    """Jedno wywołanie dla ekranu meczu: co już zgłoszono i czy mogę zgłosić.

    Ekran pyta o to przy otwarciu, więc odpowiedź musi wystarczyć do
    pomalowania kafelków i do napisania, dlaczego opcji nie ma.
    """
    province = actor.province
    commission = _is_commission(actor)
    rows = await database.fetch_all(
        select(match_bombs)
        .where(match_bombs.c.match_id == _s(match_id))
        .where(match_bombs.c.status == "active")
        .order_by(match_bombs.c.created_at.asc())
    )
    bombs = [_row(r) for r in rows]
    refusal = may_report(match_at, _now(), is_commission=commission)
    return {
        "matchId": _s(match_id),
        "province": province,
        "isCommission": commission,
        "canReport": bool(province) and refusal is None,
        # Powód, dla którego zgłoszenie jest dziś niemożliwe - do napisania na
        # kaflu. Pusty znaczy „wolno".
        "refusal": refusal or ("" if province else "Nie ma Cię na liście sędziów okręgu."),
        "bombs": [_view(b, actor.judge_id, commission) for b in bombs],
    }


@router.post("", status_code=201, summary="Zgłoś nieobecność na meczu")
async def report_bomb(
    req: ReportRequest, actor: Actor = Depends(market_actor)
) -> Dict[str, Any]:
    province = _require_province(actor)
    commission = _is_commission(actor)

    slot = _s(req.subject_slot)
    if slot not in CREW_STATE_FIELDS and slot not in ("delegat", "delegat2"):
        raise HTTPException(400, "Nie znam takiej roli w obsadzie meczu.")

    refusal = may_report(req.match_at, _now(), is_commission=commission)
    if refusal:
        raise HTTPException(409, refusal)

    crew, crew_source = await _match_crew(province, _s(req.match_id), [c.dict() for c in req.crew])
    if not crew:
        raise HTTPException(
            409,
            "Nie znam obsady tego meczu, więc nie mam jak sprawdzić, kto przy nim "
            "był. Odśwież mecz i spróbuj ponownie.",
        )

    # Zgłasza WYŁĄCZNIE obsada tego meczu. Komisja dochodzi osobno - jako ta,
    # która rejestr prowadzi, nie jako świadek.
    author_place = find_in_crew(crew, judge_id=actor.judge_id, full_name=actor.full_name)
    if not author_place and not commission:
        raise HTTPException(
            403,
            "Zgłosić nieobecność może tylko ktoś z obsady tego meczu - kto tam był, "
            "ten wie, kogo nie było.",
        )

    subject = find_in_crew(
        crew, judge_id=_s(req.subject_judge_id), full_name=_s(req.subject_name), slot=slot
    )
    if not subject:
        raise HTTPException(
            409,
            "Tej osoby nie ma w obsadzie tego meczu, więc nie ma czego zgłaszać.",
        )

    existing = await database.fetch_one(
        select(match_bombs.c.id)
        .where(match_bombs.c.match_id == _s(req.match_id))
        .where(match_bombs.c.subject_slot == slot)
        .where(match_bombs.c.author_judge_id == actor.judge_id)
        .where(match_bombs.c.status == "active")
    )
    if existing:
        raise HTTPException(409, "Już zgłosiłeś nieobecność tej osoby przy tym meczu.")

    values = {
        "province": province,
        "season": season_of(req.match_at),
        "match_id": _s(req.match_id),
        "match_code": _s(req.match_code) or None,
        "match_at": req.match_at,
        "host_team": _s(req.host_team) or None,
        "guest_team": _s(req.guest_team) or None,
        "hall": _s(req.hall) or None,
        "crew_source": crew_source,
        "subject_judge_id": _s(subject.get("judgeId")) or _s(req.subject_judge_id) or None,
        "subject_name": _s(subject.get("name")) or _s(req.subject_name),
        "subject_slot": slot,
        "author_judge_id": actor.judge_id,
        "author_name": _s(actor.full_name) or actor.judge_id,
        "author_slot": _s((author_place or {}).get("slot")) or None,
        "note": _s(req.note) or None,
        "status": "active",
    }
    bomb_id = await database.fetch_val(
        insert(match_bombs).values(**values).returning(match_bombs.c.id)
    )
    bomb = {**values, "id": int(bomb_id)}

    # Komisja od razu; osoba zgłoszona dopiero po dobie - zamiata to
    # `run_bomb_notice_sweep`, żeby cofnięta pomyłka nie zdążyła narobić hałasu.
    await _notify(
        await _commission_of(province),
        "🚩 Zgłoszona nieobecność",
        bomb_sentence(bomb, with_author=True),
        bomb,
    )
    logger.info(
        "bomby: %s zgłosił nieobecność %s przy meczu %s",
        actor.judge_id, values["subject_name"], values["match_id"],
    )
    return {"id": int(bomb_id), "status": "active"}


@router.delete("/{bomb_id}", summary="Cofnij własne zgłoszenie")
async def withdraw_bomb(bomb_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    row = await database.fetch_one(select(match_bombs).where(match_bombs.c.id == bomb_id))
    if not row:
        raise HTTPException(404, "Nie ma takiego zgłoszenia.")
    bomb = _row(row)
    if not may_withdraw(bomb, actor.judge_id):
        raise HTTPException(
            403,
            "Cofnąć zgłoszenie może tylko ten, kto je złożył. Cudze unieważnia "
            "komisja sędziowska, podając powód.",
        )
    await database.execute(
        update(match_bombs)
        .where(match_bombs.c.id == bomb_id)
        .values(status="withdrawn", withdrawn_at=func.now(), updated_at=func.now())
    )
    return {"id": bomb_id, "status": "withdrawn"}


@router.post("/{bomb_id}/void", summary="Unieważnij zgłoszenie (komisja)")
async def void_bomb(
    bomb_id: int, req: VoidRequest, actor: Actor = Depends(market_actor)
) -> Dict[str, Any]:
    row = await database.fetch_one(select(match_bombs).where(match_bombs.c.id == bomb_id))
    if not row:
        raise HTTPException(404, "Nie ma takiego zgłoszenia.")
    bomb = _row(row)
    commission = _is_commission(actor)
    if not actor.is_admin and _s(bomb.get("province")) != actor.province:
        raise HTTPException(403, "To zgłoszenie należy do innego okręgu.")
    if not may_void(commission, bomb):
        raise HTTPException(
            403,
            "Unieważnić zgłoszenie może komisja sędziowska - i tylko takie, które "
            "jeszcze obowiązuje.",
        )
    reason = _s(req.reason)
    if not reason:
        raise HTTPException(
            400,
            "Podaj powód unieważnienia. Wpis zostaje w rejestrze, więc musi być "
            "przy nim napisane, dlaczego przestał się liczyć.",
        )
    await database.execute(
        update(match_bombs)
        .where(match_bombs.c.id == bomb_id)
        .values(
            status="voided",
            void_reason=reason,
            void_by=actor.judge_id,
            void_by_name=_s(actor.full_name) or actor.judge_id,
            voided_at=func.now(),
            updated_at=func.now(),
        )
    )
    await _notify(
        [_s(bomb.get("author_judge_id")), _s(bomb.get("subject_judge_id"))],
        "✅ Zgłoszenie unieważnione",
        f"{bomb_sentence(bomb)} Komisja unieważniła ten wpis. Powód: {reason}",
        bomb,
    )
    return {"id": bomb_id, "status": "voided"}


# ─────────────────────────── rejestr okręgu ───────────────────────────


@router.get("/registry/{province}", summary="Rejestr, statystyki i ranking okręgu")
async def registry(
    province: str,
    season: Optional[int] = Query(None, description="Rok początku sezonu; brak = wszystkie."),
    actor: Actor = Depends(market_actor),
) -> Dict[str, Any]:
    """Pełna historia zgłoszeń okręgu - dla komisji i administratora.

    Ranking i statystyki liczy SERWER, bo ta sama liczba ma stać w rankingu, w
    kaflu sędziego i w podsumowaniu miesiąca. Aplikacja grupuje i podpisuje, ale
    nie liczy drugi raz po swojemu.
    """
    wanted = _s(province).upper()
    commission = _is_commission(actor)
    if not commission:
        raise HTTPException(
            403,
            "Rejestr zgłoszeń prowadzi komisja sędziowska - ten ekran należy do niej.",
        )
    if not actor.is_admin and wanted != _s(actor.province).upper():
        raise HTTPException(403, "Komisja czyta rejestr własnego okręgu.")

    rows = [
        _row(r)
        for r in await database.fetch_all(
            select(match_bombs)
            .where(match_bombs.c.province == wanted)
            .order_by(match_bombs.c.created_at.desc())
        )
    ]

    # Sezony budujemy z tego, co NAPRAWDĘ jest - przełącznik, który otwiera
    # pusty rok, jest gorszy od braku przełącznika.
    seasons: Dict[Any, int] = {}
    for row in rows:
        seasons[row.get("season")] = seasons.get(row.get("season"), 0) + 1
    season_list = [
        {
            "year": year,
            "label": season_label(year) if year else "Bez daty",
            "count": count,
        }
        for year, count in sorted(
            seasons.items(), key=lambda kv: (kv[0] is None, -(kv[0] or 0))
        )
    ]

    chosen = [r for r in rows if season is None or r.get("season") == season]
    counted = [r for r in chosen if counts_to_stats(r.get("status"))]

    tally: Dict[str, Dict[str, Any]] = {}
    for row in counted:
        key = _s(row.get("subject_judge_id")) or _s(row.get("subject_name")).lower()
        entry = tally.setdefault(
            key,
            {"judgeId": _s(row.get("subject_judge_id")), "name": _s(row.get("subject_name")), "count": 0},
        )
        entry["count"] += 1

    months: Dict[str, int] = {}
    for row in counted:
        key = month_key(row.get("match_at"))
        if key:
            months[key] = months.get(key, 0) + 1

    return {
        "province": wanted,
        "season": season,
        "seasons": season_list,
        "isAdmin": actor.is_admin,
        "stats": {
            "total": len(chosen),
            "active": len(counted),
            "voided": len([r for r in chosen if _s(r.get("status")) == "voided"]),
            "withdrawn": len([r for r in chosen if _s(r.get("status")) == "withdrawn"]),
            "judges": len(tally),
            "byMonth": [
                {"key": key, "label": month_label(key), "count": months[key]}
                for key in sorted(months)
            ],
        },
        "ranking": rank_bombs(tally.values()),
        "bombs": [_view(r, actor.judge_id, True) for r in chosen],
    }


# ─────────────────────────── karencja powiadomienia ───────────────────────────


async def sweep_subject_notices(now: Optional[datetime] = None) -> int:
    """Powiadamia zgłoszonych o wpisach, które przetrwały dobę.

    Osobne przejście, a nie zadanie odroczone w pamięci procesu: restart
    Railway zjadłby każde zaplanowane w ten sposób powiadomienie, a rejestr ma
    działać także wtedy, gdy backend wstanie w międzyczasie trzy razy.
    """
    stamp = now or _now()
    cutoff = stamp - timedelta(hours=SUBJECT_NOTICE_DELAY_HOURS)
    rows = await database.fetch_all(
        select(match_bombs)
        .where(match_bombs.c.status == "active")
        .where(match_bombs.c.subject_notified_at.is_(None))
        .where(match_bombs.c.created_at <= cutoff)
        .limit(200)
    )
    sent = 0
    for raw in rows:
        bomb = _row(raw)
        target = _s(bomb.get("subject_judge_id"))
        if target:
            await _notify(
                [target],
                "🚩 Zgłoszono Twoją nieobecność",
                (
                    f"Ktoś z obsady zgłosił, że nie było Cię na meczu "
                    f"{_s(bomb.get('match_code')) or 'okręgowym'}. Szczegóły masz w "
                    "ekranie meczu; sprawę prowadzi komisja sędziowska."
                ),
                bomb,
            )
            sent += 1
        await database.execute(
            update(match_bombs)
            .where(match_bombs.c.id == int(bomb["id"]))
            .values(subject_notified_at=func.now())
        )
    return sent


async def run_bomb_notice_sweep() -> None:
    """Pętla tła - ta sama forma, co pozostałe zadania cykliczne w `main.py`."""
    interval = int(os.getenv("BOMB_NOTICE_SWEEP_SECONDS", str(15 * 60)))
    while True:
        try:
            await sweep_subject_notices()
        except Exception:  # noqa: BLE001
            logger.exception("bomby: przejście powiadomień nie powiodło się")
        await asyncio.sleep(interval)
