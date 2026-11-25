"""Rejestr prób ProEla: kto, kiedy i przez co nie mógł wejść do ProEla,
rozpocząć meczu albo stracił prowadzenie.

Kontrakt: odpowiedzi i pola są opisane w komentarzach przy trasach, reguły bez
bazy siedzą w `app/proel_attempt_rules.py`, tabele w `app/proel_attempt_tables.py`.

Dwie zasady twarde (jak w `proel_journal.log_match_event`):

1. Zapis rejestru NIGDY nie psuje i nie spowalnia właściwej odpowiedzi. Zapisy
   serwera idą w tle (`spawn`) i łykają każdy wyjątek.
2. Hasło nie ma tu wejścia: `clean_event` przepuszcza wyłącznie wymienione pola.

Trasy są dopięte do routera `proel_journal` (patrz koniec tamtego pliku), więc
nie trzeba ruszać `main.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import delete, func, or_, select, update

from app.pod_reka_login_rules import AttemptLimiter, client_key
from app.proel_admin_guard import proel_admin_guard
from app.proel_attempt_rules import (
    DISPUTE_REASONS,
    MAX_EVENTS,
    REASON_LABELS,
    bump_episode,
    clean_event,
    dispute_push,
    dispute_push_due,
    is_hard_start_block,
    lease_episode_key,
    login_cutoff,
    login_failure_reason,
    merge_update,
    reason_label,
    start_block_push,
    summarize,
)
from app.proel_attempt_stmt import build_list_stmt
from app.proel_attempt_tables import attempt_alert_prefs, attempt_log, ensure_tables
from app.proel_auth import Actor, proel_actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/attempts", tags=["ProEl: rejestr prób"])

MAX_BODY_BYTES = 256 * 1024
_limiter = AttemptLimiter(limit=60, window=timedelta(minutes=1), max_keys=20_000)

#: Mecz -> kiedy ostatnio poszedł push o sporze (pamięć procesu, jak `admin_alerts`).
_dispute_pushed: Dict[str, float] = {}
_tasks: set = set()
_last_login_cleanup = 0.0


def spawn(coro: Coroutine[Any, Any, Any]) -> None:
    """Uruchamia zapis w tle; odpowiedź właściwej trasy na nim nie czeka."""
    try:
        task = asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        coro.close()
        return
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _out(row: Any) -> Dict[str, Any]:
    d = dict(row)
    for k in ("first_at", "last_at", "client_at", "escalated_at", "created_at"):
        v = d.get(k)
        d[k] = v.isoformat() if v else None
    return d


# ─────────────────────────── zapis ───────────────────────────


async def _upsert_client(values: Dict[str, Any], ip: str) -> bool:
    """Wstawia albo scala po `event_key`. Zwraca `True`, gdy to NOWY wpis."""
    from app.db import database

    now = _now()
    T = attempt_log
    found = await database.fetch_one(select(T).where(T.c.event_key == values["event_key"]))
    if found is not None:
        await database.execute(
            update(T).where(T.c.id == found["id"]).values(**merge_update(dict(found), values, now))
        )
        return False
    ins = {k: v for k, v in values.items() if v is not None}
    ins["first_at"] = values.get("first_at") or now
    ins["last_at"] = values.get("last_at") or now
    ins["client_ip"] = ip or None
    ins["source"] = "client"
    try:
        await database.execute(T.insert().values(**ins))
        return True
    except Exception:
        # Wyścig dwóch wysyłek tego samego klucza: druga wchodzi jako scalenie.
        again = await database.fetch_one(select(T).where(T.c.event_key == values["event_key"]))
        if again is None:
            raise
        await database.execute(
            update(T).where(T.c.id == again["id"]).values(**merge_update(dict(again), values, now))
        )
        return False


async def _upsert_episode(values: Dict[str, Any]) -> bool:
    """Wpis serwera: nowy epizod albo +1 do licznika. `True` = nowy epizod."""
    from app.db import database

    T = attempt_log
    now = _now()
    found = await database.fetch_one(select(T).where(T.c.event_key == values["event_key"]))
    if found is not None:
        await database.execute(update(T).where(T.c.id == found["id"]).values(**bump_episode(dict(found), now)))
        return False
    ins = {k: v for k, v in values.items() if v is not None}
    ins.update(first_at=now, last_at=now, source="server", count=1)
    try:
        await database.execute(T.insert().values(**ins))
        return True
    except Exception:
        again = await database.fetch_one(select(T).where(T.c.event_key == values["event_key"]))
        if again is None:
            raise
        await database.execute(update(T).where(T.c.id == again["id"]).values(**bump_episode(dict(again), now)))
        return False


async def _cleanup_logins(force: bool = False) -> None:
    """Wpisy kind=login starsze niż 12 miesięcy; najwyżej raz na dobę na proces."""
    global _last_login_cleanup
    ts = time.time()
    if not force and ts - _last_login_cleanup < 86_400:
        return
    _last_login_cleanup = ts
    from app.db import database

    await database.execute(
        delete(attempt_log).where(attempt_log.c.kind == "login", attempt_log.c.created_at < login_cutoff(_now()))
    )


async def _alert_admins() -> List[str]:
    from app.admin_alerts import admin_judge_ids
    from app.db import database

    admins = await admin_judge_ids()
    if not admins:
        return []
    rows = await database.fetch_all(
        select(attempt_alert_prefs.c.judge_id).where(
            attempt_alert_prefs.c.judge_id.in_(admins), attempt_alert_prefs.c.enabled.is_(True)
        )
    )
    return sorted({str(r["judge_id"]) for r in rows})


async def _push(row: Dict[str, Any], texts: Dict[str, str], tag: str = "") -> int:
    """Push do adminów z włączonym alertem + wpis w skrzynce aplikacji. Nigdy nie rzuca."""
    try:
        targets = await _alert_admins()
        if not targets:
            return 0
        from app.push.push import send_push_to_judges

        rid = str(row.get("id") or "")
        data = {
            "type": "proel_attempt",
            "alertKind": "proel_attempt",
            "ref": rid,
            "id": rid,
            "kind": str(row.get("kind") or ""),
            "match_number": str(row.get("match_number") or ""),
        }
        # Skrzynka powiadomień: ten sam zapis co `admin_alerts.notify_admins`
        # (judge_id, kind, reference, event_key, title, body, data_json).
        try:
            from app.db import admin_alert_notifications, database

            for judge_id in targets:
                try:
                    await database.execute(admin_alert_notifications.insert().values(
                        judge_id=judge_id, kind="proel_attempt", reference=rid or None,
                        event_key=f"proel_attempt:{tag}:{rid}"[:120] if rid else None,
                        title=texts["title"], body=texts["body"], data_json=data,
                    ))
                except Exception:
                    logger.info("proel attempts: wpis skrzynki pominięty", exc_info=True)
        except Exception:
            logger.info("proel attempts: skrzynka niedostępna", exc_info=True)
        return await send_push_to_judges(targets, texts["title"], texts["body"], data)
    except Exception:
        logger.warning("proel attempts: push nieudany", exc_info=True)
        return 0


async def _maybe_dispute_push(row: Dict[str, Any]) -> None:
    if row.get("kind") != "lead" or row.get("reason") not in DISPUTE_REASONS:
        return
    if not dispute_push_due(_dispute_pushed, str(row.get("match_number") or ""), time.time()):
        return
    await _push(row, dispute_push(row), "dispute")


async def _record_server(values: Dict[str, Any]) -> None:
    try:
        await ensure_tables()
        is_new = await _upsert_episode(values)
        if values.get("kind") == "login":
            await _cleanup_logins()
        if is_new:
            from app.db import database

            row = await database.fetch_one(select(attempt_log).where(attempt_log.c.event_key == values["event_key"]))
            if row is not None:
                await _maybe_dispute_push(dict(row))
    except Exception:
        logger.debug("proel attempts: nie zapisano wpisu serwera", exc_info=True)


def record_lease_refusal(
    *, match_number: str, code: str, actor: Optional[Actor], holder_name: str = "",
    zprp_match_id: str = "", app_version: Optional[str] = None,
) -> None:
    """409 LEASE_HELD / 412 LEASE_LOST. Wołać po złapaniu wyjątku; nie czeka i nie rzuca."""
    try:
        spawn(_refusal_task(match_number, code, actor, holder_name, zprp_match_id, app_version))
    except Exception:
        pass


async def _refusal_task(match_number, code, actor, holder_name, zprp_match_id, app_version) -> None:
    try:
        number = str(match_number or "").strip()
        if not number or code not in REASON_LABELS:
            return
        epoch, holder_install, holder = 0, None, holder_name or None
        try:
            from app.db import database, proel_match_state

            st = await database.fetch_one(
                select(
                    proel_match_state.c.lease_epoch,
                    proel_match_state.c.lease_install,
                    proel_match_state.c.lease_name,
                ).where(proel_match_state.c.match_number == number)
            )
            if st is not None:
                epoch = int(st["lease_epoch"] or 0)
                holder_install = st["lease_install"]
                holder = holder or st["lease_name"]
        except Exception:
            pass
        install = (actor.installation_id if actor else "") or ""
        await _record_server({
            "event_key": lease_episode_key(code, number, install, epoch),
            "kind": "lead", "outcome": "blocked", "reason": code,
            "reason_text": reason_label(code),
            "blocker": "other_device", "match_number": number,
            "zprp_match_id": zprp_match_id or None,
            "actor_judge_id": (actor.judge_id or None) if actor else None,
            "actor_name": (actor.name or None) if actor else None,
            "actor_install": install or None,
            "actor_verified": bool(actor.verified) if actor else False,
            "holder_name": holder, "holder_install": holder_install,
            "app_version": app_version,
        })
    except Exception:
        logger.debug("proel attempts: odmowa leasingu nie zapisana", exc_info=True)


def record_lead_change(
    *, match_number: str, reclaimed: bool, actor: Optional[Actor], holder_name: str = "",
    holder_install: str = "", holder_judge_id: str = "", epoch: int = 0, forced: bool = False,
    zprp_match_id: str = "",
) -> None:
    """Udane przejęcie (TAKEN_OVER) albo odzyskanie (RECLAIMED) z danymi poprzednika."""
    try:
        code = "RECLAIMED" if reclaimed else "TAKEN_OVER"
        number = str(match_number or "").strip()
        if not number:
            return
        install = (actor.installation_id if actor else "") or ""
        text = reason_label(code) + (" (administrator)" if forced else "")
        spawn(_record_server({
            "event_key": f"srv:{code}:{number}:{int(epoch)}"[:80],
            "kind": "lead", "outcome": "ok", "reason": code, "reason_text": text,
            "blocker": None, "match_number": number, "zprp_match_id": zprp_match_id or None,
            "actor_judge_id": (actor.judge_id or None) if actor else None,
            "actor_name": (actor.name or None) if actor else None,
            "actor_install": install or None,
            "actor_verified": bool(actor.verified) if actor else False,
            "holder_name": holder_name or None, "holder_install": holder_install or None,
        }))
    except Exception:
        pass


def record_login_failure(
    *, login: str, status_code: int, detail: Any, ip: str = "", app_version: Optional[str] = None,
    install: str = "", platform: str = "",
) -> None:
    """Nieudane logowanie konta ProEl (401/403). Hasła nie przyjmuje."""
    try:
        code = login_failure_reason(status_code, detail)
        who = str(login or "").strip()[:120]
        bucket = _now().strftime("%Y%m%d%H")
        key = f"srv:login:{code}:{who.lower()}:{bucket}"[:80]
        spawn(_record_server({
            "event_key": key, "kind": "login", "outcome": "blocked", "reason": code,
            "reason_text": reason_label(code),
            "blocker": "server" if status_code == 403 else "user",
            "path": "proel_account", "actor_login": who or None,
            "actor_install": install or None, "client_ip": ip or None,
            "app_version": app_version,
            "device": {"platform": platform} if platform else None,
        }))
    except Exception:
        pass


# ─────────────────────────── trasy ───────────────────────────


async def _require_admin(actor: Actor) -> None:
    from app.proel_journal import _require_admin as _req

    await _req(actor)


@router.post("", summary="Wpisy rejestru z aplikacji (maks. 50, upsert po event_key)")
async def post_attempts(
    request: Request,
    x_judge_id: Optional[str] = Header(None),
    x_installation_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    x_elevation: Optional[str] = Header(None),
    x_forwarded_for: Optional[str] = Header(None),
):
    """Odpowiedź: `{ "accepted": n }`. Bez wymaganej tożsamości, z limitem 60/min na adres."""
    from app.proel_journal import client_ip, soft_actor

    ip = client_key(x_forwarded_for or "", client_ip(request))
    if _limiter.blocked(ip):
        raise HTTPException(429, detail={"code": "RATE_LIMIT", "message": "Zbyt wiele zgłoszeń."})
    _limiter.fail(ip)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, detail={"code": "TOO_LARGE", "message": "Zbyt duże zgłoszenie."})
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(413, detail={"code": "TOO_LARGE", "message": "Zbyt duże zgłoszenie."})
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise HTTPException(400, detail={"code": "BAD_JSON", "message": "Niepoprawny JSON."})
    events = body.get("events") if isinstance(body, dict) else None
    if not isinstance(events, list):
        raise HTTPException(400, detail={"code": "BAD_BODY", "message": "Brak listy events."})

    actor = await soft_actor(
        x_judge_id, x_installation_id, x_actor_name, authorization=authorization, x_elevation=x_elevation
    )
    accepted = 0
    try:
        await ensure_tables()
        for raw_ev in events[:MAX_EVENTS]:
            values = clean_event(raw_ev)
            if values is None:
                continue
            if actor is not None:
                values["actor_judge_id"] = actor.judge_id or values.get("actor_judge_id")
                values["actor_name"] = actor.name or values.get("actor_name")
                values["actor_install"] = actor.installation_id or values.get("actor_install")
                values["actor_verified"] = bool(actor.verified)
            try:
                is_new = await _upsert_client(values, ip)
            except Exception:
                logger.debug("proel attempts: wpis odrzucony", exc_info=True)
                continue
            accepted += 1
            if values["kind"] == "login":
                spawn(_cleanup_logins())
            elif is_new and values["kind"] == "lead" and values.get("reason") in DISPUTE_REASONS:
                spawn(_dispute_from_key(values["event_key"]))
    except Exception:
        # Rejestr nie ma prawa wywrócić aplikacji: telefon nie ponawia w nieskończoność.
        logger.warning("proel attempts: zapis nieudany", exc_info=True)
    return {"accepted": accepted}


async def _dispute_from_key(event_key: str) -> None:
    try:
        from app.db import database

        row = await database.fetch_one(select(attempt_log).where(attempt_log.c.event_key == event_key))
        if row is not None:
            await _maybe_dispute_push(dict(row))
    except Exception:
        logger.debug("proel attempts: spór nie zgłoszony", exc_info=True)


@router.post("/{event_key}/escalate", summary="Blokada startu trwa 2 min: push do adminów (raz na wpis)")
async def escalate_attempt(event_key: str, request: Request, x_forwarded_for: Optional[str] = Header(None)):
    """Odpowiedź: `{ "escalated": bool }` (false: brak wpisu, nie kwalifikuje się albo już zgłoszony)."""
    from app.db import database
    from app.proel_journal import client_ip

    ip = client_key(x_forwarded_for or "", client_ip(request))
    if _limiter.blocked(ip):
        raise HTTPException(429, detail={"code": "RATE_LIMIT", "message": "Zbyt wiele zgłoszeń."})
    _limiter.fail(ip)
    try:
        await ensure_tables()
        T = attempt_log
        row = await database.fetch_one(select(T).where(T.c.event_key == str(event_key)[:80]))
        if row is None or not is_hard_start_block(dict(row)):
            return {"escalated": False}
        claimed = await database.fetch_one(
            update(T)
            .where(T.c.id == row["id"], T.c.escalated_at.is_(None))
            .values(escalated_at=_now())
            .returning(T.c.id)
        )
        if claimed is None:
            return {"escalated": False}
        spawn(_push(dict(row), start_block_push(dict(row)), "start_block"))
        return {"escalated": True}
    except Exception:
        logger.warning("proel attempts: eskalacja nieudana", exc_info=True)
        return {"escalated": False}


def _parse_bound(v: Optional[str], name: str) -> Optional[datetime]:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, detail={"code": "BAD_DATE", "message": f"Niepoprawna data: {name}."})
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@router.get("", summary="Lista prób (admin), kursor before_id", dependencies=[Depends(proel_admin_guard)])
async def list_attempts(
    kind: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    reason: Optional[str] = Query(None),
    match: Optional[str] = Query(None),
    actor: Optional[str] = Query(None, description="Numer sędziego"),
    q: Optional[str] = Query(None, description="Szukaj: nazwisko, login, mecz, opis"),
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = Query(None),
    before_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    who: Actor = Depends(proel_actor),
):
    """Odpowiedź: `{ items: [wpis], next_cursor: id|null, labels: {kod: etykieta} }`."""
    await _require_admin(who)
    from app.db import database

    await ensure_tables()
    stmt = build_list_stmt(
        kind=kind, outcome=outcome, reason=reason, match=match, actor=actor, q=q,
        lo=_parse_bound(from_, "from"), hi=_parse_bound(to, "to"), before_id=before_id,
    )
    rows = await database.fetch_all(stmt.limit(limit))
    return {
        "items": [_out(r) for r in rows],
        "next_cursor": int(rows[-1]["id"]) if len(rows) == limit else None,
        "labels": REASON_LABELS,
    }


@router.get("/summary", summary="Podsumowanie rejestru (admin)", dependencies=[Depends(proel_admin_guard)])
async def attempts_summary(
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = Query(None),
    who: Actor = Depends(proel_actor),
):
    """Odpowiedź: `{ totals:{start|login|lead:{ok,blocked,bypassed,abandoned}}, top_reasons:[{reason,label,kind,count}],
    top_people:[{judge_id,name,blocked,total}], matches:[{match_number,blocked,lead_conflicts}], median_start_ms,
    by_blocker:[{blocker,count}] }`."""
    await _require_admin(who)
    from app.db import database

    await ensure_tables()
    T = attempt_log
    stmt = select(
        T.c.kind, T.c.outcome, T.c.reason, T.c.count, T.c.actor_judge_id, T.c.actor_name,
        T.c.match_number, T.c.duration_ms, T.c.blocker,
    ).order_by(T.c.id.desc()).limit(50_000)
    lo, hi = _parse_bound(from_, "from"), _parse_bound(to, "to")
    if lo:
        stmt = stmt.where(T.c.last_at >= lo)
    if hi:
        stmt = stmt.where(T.c.last_at <= hi)
    rows = await database.fetch_all(stmt)
    return summarize([dict(r) for r in rows])


@router.get("/alerts/me", summary="Czy ten admin ma włączony alert (admin)", dependencies=[Depends(proel_admin_guard)])
async def get_alert_pref(who: Actor = Depends(proel_actor)):
    """Odpowiedź: `{ "enabled": bool }` (domyślnie false)."""
    await _require_admin(who)
    from app.db import database

    await ensure_tables()
    row = await database.fetch_one(
        select(attempt_alert_prefs.c.enabled).where(attempt_alert_prefs.c.judge_id == who.judge_id)
    )
    return {"enabled": bool(row["enabled"]) if row else False}


@router.put("/alerts/me", summary="Włącz albo wyłącz alert (admin)", dependencies=[Depends(proel_admin_guard)])
async def put_alert_pref(payload: Dict[str, Any], who: Actor = Depends(proel_actor)):
    """Body `{ "enabled": bool }`. Odpowiedź: `{ "enabled": bool }`."""
    await _require_admin(who)
    from app.db import database
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    enabled = bool(payload.get("enabled")) if isinstance(payload, dict) else False
    await ensure_tables()
    T = attempt_alert_prefs
    stmt = pg_insert(T).values(judge_id=who.judge_id, enabled=enabled, updated_at=_now())
    await database.execute(stmt.on_conflict_do_update(
        index_elements=[T.c.judge_id], set_={"enabled": enabled, "updated_at": _now()}
    ))
    return {"enabled": enabled}
