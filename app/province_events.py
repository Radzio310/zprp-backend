# app/province_events.py
"""
Wydarzenia okręgowe - trasy.

Przebudowa z 17.09.2026 (reguły i decyzje w `app/province_event_rules.py`).

Najważniejsze zmiany względem wersji pierwotnej:
  - KAŻDA trasa wymaga podpisanego tokenu. Wcześniej serwer nie sprawdzał
    niczego: kto znał adres, mógł dodać, zmienić albo usunąć wydarzenie,
    a `/visible` wierzyło numerowi sędziego z adresu,
  - zaproszeni liczą się z aktualnych odznak przy każdym odczycie,
  - odpowiedzi „Będę / Nie będę" i obecność w osobnych tabelach,
  - odwołanie, kosz na 30 dni, serie, szablony, kod obecności, PDF listy,
    grafika tytułowa z OpenAI i powiadomienia push.

Stare trasy (`GET /`, `GET /visible`, `POST /`, `PATCH /{id}`,
`PATCH /{id}/attendance`, `DELETE /{id}`) zostają dla wydanej wersji
aplikacji - z tym samym kształtem odpowiedzi, ale już z tokenem.
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
import shutil
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import province_event_rules as R
from app.db import (
    database,
    province_event_attendance,
    province_event_notifications,
    province_event_responses,
    province_event_templates,
    province_events,
    province_judges,
)
from app.match_market import Actor, market_actor
from app.push.push import send_push_to_judges
from app.settlement_province import display, spellings
from app.schemas import (
    CreateProvinceEventRequest,
    ListProvinceEventsResponse,
    ProvinceEventItem,
    UpdateProvinceEventAttendanceRequest,
    UpdateProvinceEventRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province-events", tags=["Province Events"])

PDF_DIR = os.path.join(tempfile.gettempdir(), "province_event_pdf")
#: Nieudane próby kodu: najwyżej tyle w oknie, potem chwila przerwy.
CHECKIN_FAIL_LIMIT = 8
CHECKIN_FAIL_WINDOW_S = 600
_checkin_failures: Dict[str, List[float]] = {}


# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def _row(row: Any) -> Dict[str, Any]:
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})


def _data(raw: Any) -> Dict[str, Any]:
    import json

    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _bad(error: R.Invalid) -> HTTPException:
    return HTTPException(400, str(error))


def _province(value: Any) -> str:
    """Zapis okręgu w wydarzeniach: WIELKIE LITERY z polskimi znakami („ŚLĄSKIE")."""
    return display(value) or _s(value).upper()


def _names(value: Any) -> List[str]:
    """Wszystkie zapisy okręgu - stare wiersze i lista sędziów mają różne."""
    return sorted({*spellings(value), _province(value), _s(value).upper()} - {""})


def _viewer(actor: Actor) -> R.Viewer:
    return R.viewer(judge_id=actor.judge_id, province=actor.province, is_admin=actor.is_admin, badges=actor.badges)


def _require_judge(actor: Actor) -> R.Viewer:
    who = _viewer(actor)
    if not who.judge_id:
        raise HTTPException(403, "Ten token nie niesie numeru sędziego")
    return who


def _resolve_province(who: R.Viewer, requested: Any) -> str:
    raw = _s(requested) or who.province
    province = _province(raw) if raw else ""
    if not province:
        raise HTTPException(403, "Nie ma Cię na liście sędziów okręgu - zgłoś to administratorowi okręgu")
    if not R.can_view_province(who, province):
        raise HTTPException(403, "Wydarzenia innego okręgu widzi tylko administrator")
    return province


def _require_manager(who: R.Viewer, province: str) -> None:
    if not R.can_manage(who, province):
        raise HTTPException(403, "Wydarzeniami zarządza komisja sędziowska okręgu i administrator")


async def _event(event_id: int, *, deleted_ok: bool = False) -> Dict[str, Any]:
    row = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono wydarzenia")
    item = _row(row)
    if item.get("deleted_at") is not None and not deleted_ok:
        raise HTTPException(404, "Wydarzenie leży w koszu")
    item["data_json"] = _data(item.get("data_json"))
    return item


async def _judges(province: str) -> List[Dict[str, Any]]:
    rows = await database.fetch_all(
        select(
            province_judges.c.judge_id,
            province_judges.c.full_name,
            province_judges.c.photo_url,
            province_judges.c.badges,
        ).where(province_judges.c.province.in_(_names(province)))
    )
    return [_row(r) for r in rows]


async def _responses(event_ids: List[int]) -> Dict[int, Dict[str, Dict[str, Any]]]:
    out: Dict[int, Dict[str, Dict[str, Any]]] = {}
    if not event_ids:
        return out
    rows = await database.fetch_all(
        select(province_event_responses).where(province_event_responses.c.event_id.in_(event_ids))
    )
    for raw in rows:
        row = _row(raw)
        out.setdefault(int(row["event_id"]), {})[_s(row["judge_id"])] = row
    return out


async def _attendance(event_ids: List[int]) -> Dict[int, Dict[str, Dict[str, Any]]]:
    out: Dict[int, Dict[str, Dict[str, Any]]] = {}
    if not event_ids:
        return out
    rows = await database.fetch_all(
        select(province_event_attendance).where(province_event_attendance.c.event_id.in_(event_ids))
    )
    for raw in rows:
        row = _row(raw)
        out.setdefault(int(row["event_id"]), {})[_s(row["judge_id"])] = row
    return out


def _person(judge: Optional[Mapping[str, Any]], judge_id: str) -> Dict[str, Any]:
    return {
        "judge_id": judge_id,
        "name": _s((judge or {}).get("full_name")) or judge_id,
        "photo_url": _s((judge or {}).get("photo_url")) or None,
    }


def _details(data: Mapping[str, Any]) -> Dict[str, Any]:
    target = data.get("target") if isinstance(data.get("target"), Mapping) else {}
    image = data.get("title_image") if isinstance(data.get("title_image"), Mapping) else None
    return {
        "target": R.clean_target(target),
        "include_ids": [_s(x) for x in data.get("include_ids") or [] if _s(x)],
        "exclude_ids": [_s(x) for x in data.get("exclude_ids") or [] if _s(x)],
        "place": data.get("place") if isinstance(data.get("place"), Mapping) else {"name": None, "address": None},
        "online_url": data.get("online_url") or None,
        "obligatory": bool(data.get("obligatory")),
        "rsvp_deadline": data.get("rsvp_deadline") or None,
        "capacity": data.get("capacity") or None,
        "program": data.get("program") if isinstance(data.get("program"), list) else [],
        "title_image": dict(image) if image else None,
    }


def _view(
    event: Mapping[str, Any],
    *,
    judges_by_id: Mapping[str, Mapping[str, Any]],
    invited: List[str],
    responses: Mapping[str, Mapping[str, Any]],
    attendance: Mapping[str, Mapping[str, Any]],
    me: str,
    manager: bool,
) -> Dict[str, Any]:
    """Wydarzenie dla aplikacji. Odmowy i ich powody widzi tylko komisja."""
    data = _data(event.get("data_json"))
    legacy_present = data.get("present_ids") or []
    invited_set = set(invited)
    going = [jid for jid, row in responses.items() if row.get("status") == "yes" and jid in invited_set]
    declined = [jid for jid, row in responses.items() if row.get("status") == "no" and jid in invited_set]
    states = {jid: R.attendance_state(jid, attendance, legacy_present) for jid in invited}
    my_response = responses.get(me)
    view: Dict[str, Any] = {
        "id": int(event["id"]),
        "province": event["province"],
        "name": event["name"],
        "description": event.get("description"),
        "event_type": event.get("event_type") or R.DEFAULT_TYPE,
        "event_date": _iso(event.get("event_date")),
        "end_date": _iso(event.get("end_date")),
        "cancelled_at": _iso(event.get("cancelled_at")),
        "cancel_reason": event.get("cancel_reason"),
        "series_id": event.get("series_id"),
        "created_by_name": event.get("created_by_name"),
        "updated_at": _iso(event.get("updated_at")),
        "details": _details(data),
        "counts": {
            "invited": len(invited),
            "yes": len(going),
            "no": len(declined),
            "pending": max(0, len(invited) - len(going) - len(declined)),
            "present": sum(1 for s in states.values() if s == "present"),
            "excused": sum(1 for s in states.values() if s == "excused"),
        },
        "going": [_person(judges_by_id.get(jid), jid) for jid in sorted(going, key=lambda j: _s((judges_by_id.get(j) or {}).get("full_name")))],
        "me": {
            "invited": me in invited_set,
            "response": (my_response or {}).get("status"),
            "reason": (my_response or {}).get("reason"),
            "attendance": states.get(me, "absent") if me in invited_set else None,
            "attendance_source": _s((attendance.get(me) or {}).get("source")) or None,
        },
        "can_manage": manager,
    }
    if manager:
        view["invited_ids"] = invited
        view["responses"] = [
            {
                "judge_id": jid,
                "status": row.get("status"),
                "reason": row.get("reason"),
                "updated_at": _iso(row.get("updated_at")),
            }
            for jid, row in responses.items()
            if jid in invited_set
        ]
        view["attendance"] = [
            {
                "judge_id": jid,
                "status": state,
                "source": _s((attendance.get(jid) or {}).get("source")) or ("legacy" if state == "present" else None),
                "marked_at": _iso((attendance.get(jid) or {}).get("marked_at")),
            }
            for jid, state in states.items()
            if state != "absent"
        ]
        checkin = data.get("checkin") if isinstance(data.get("checkin"), Mapping) else None
        view["checkin_open"] = bool(checkin and checkin.get("code"))
    return view


def _judge_public(judge: Mapping[str, Any]) -> Dict[str, Any]:
    from app.match_market_access import badge_names

    return {
        "judge_id": _s(judge.get("judge_id")),
        "name": _s(judge.get("full_name")),
        "photo_url": _s(judge.get("photo_url")) or None,
        "badges": badge_names(judge.get("badges")),
    }


# ---------------------------------------------------------------------------
# Powiadomienia
# ---------------------------------------------------------------------------


def _place_label(data: Mapping[str, Any]) -> str:
    place = data.get("place") if isinstance(data.get("place"), Mapping) else {}
    if _s(place.get("name")):
        return _s(place.get("name"))
    return "online" if data.get("online_url") else ""


async def _push(judge_ids: List[str], title: str, body: str, event: Mapping[str, Any], kind: str) -> None:
    targets = sorted({_s(j) for j in judge_ids if _s(j)})
    if not targets:
        return
    try:
        await send_push_to_judges(
            targets,
            title,
            body,
            {
                "kind": "province_event",
                "type": "province_event",
                "eventId": str(event.get("id") or ""),
                "province": _s(event.get("province")),
                "notice": kind,
            },
        )
    except Exception:  # noqa: BLE001
        logger.warning("wydarzenia: powiadomienie nieudane", exc_info=True)


def _when(event: Mapping[str, Any]) -> str:
    start = event.get("event_date")
    return R.local_label(start) if isinstance(start, datetime) else ""


async def _notify_new(event: Mapping[str, Any], invited: List[str], occurrences: int, actor_id: str) -> None:
    data = _data(event.get("data_json"))
    place = _place_label(data)
    people = [jid for jid in invited if jid != actor_id]
    if occurrences > 1:
        title = "📅 Nowa seria wydarzeń"
        body = f"{event['name']}: {occurrences} terminów, pierwszy {_when(event)}."
    else:
        title = "📅 Nowe wydarzenie okręgowe"
        body = f"{event['name']} · {_when(event)}{f' · {place}' if place else ''}. Daj znać, czy będziesz."
    await _push(people, title, body, event, "new")


async def _notify_changed(event: Mapping[str, Any], invited: List[str], actor_id: str) -> None:
    data = _data(event.get("data_json"))
    place = _place_label(data)
    body = f"Nowy termin: {_when(event)}{f' · {place}' if place else ''}."
    await _push([j for j in invited if j != actor_id], f"🔁 Zmiana: {event['name']}", body, event, "changed")


async def _notify_cancelled(event: Mapping[str, Any], invited: List[str], actor_id: str) -> None:
    reason = _s(event.get("cancel_reason"))
    body = reason or f"Komisja odwołała wydarzenie zaplanowane na {_when(event)}."
    await _push([j for j in invited if j != actor_id], f"❌ Odwołane: {event['name']}", body, event, "cancelled")


async def sweep_event_reminders(now: Optional[datetime] = None) -> int:
    """Przypomnienia dobę i godzinę przed oraz ponaglenie o brak odpowiedzi."""
    stamp = now or _now()
    horizon = stamp + R.REMINDER_DAY + timedelta(hours=1)
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.deleted_at.is_(None))
        .where(province_events.c.cancelled_at.is_(None))
        .where(province_events.c.event_date > stamp)
        .where(province_events.c.event_date <= stamp + timedelta(days=R.MAX_OCCURRENCES * 31))
        .order_by(province_events.c.event_date.asc())
        .limit(500)
    )
    events = []
    for raw in rows:
        event = _row(raw)
        data = _data(event.get("data_json"))
        deadline = R.parse_iso(data.get("rsvp_deadline")) if data.get("rsvp_deadline") else None
        start = event["event_date"]
        if start <= horizon or (deadline is not None and deadline - R.RSVP_NUDGE <= stamp < deadline):
            event["data_json"] = data
            event["_deadline"] = deadline
            events.append(event)
    if not events:
        return 0

    ids = [int(e["id"]) for e in events]
    responses = await _responses(ids)
    sent_rows = await database.fetch_all(
        select(province_event_notifications).where(province_event_notifications.c.event_id.in_(ids))
    )
    sent: Dict[int, Set[Tuple[str, str]]] = {}
    for raw in sent_rows:
        row = _row(raw)
        sent.setdefault(int(row["event_id"]), set()).add((_s(row["judge_id"]), _s(row["kind"])))

    judges_cache: Dict[str, List[Dict[str, Any]]] = {}
    total = 0
    for event in events:
        province = _province(event["province"])
        if province not in judges_cache:
            judges_cache[province] = await _judges(province)
        invited = R.invited_ids(judges_cache[province], event["data_json"])
        answers = {jid: _s(row.get("status")) for jid, row in responses.get(int(event["id"]), {}).items()}
        due = R.due_reminders(
            now=stamp,
            start=event["event_date"],
            created_at=event.get("created_at"),
            deadline=event["_deadline"],
            invited=invited,
            responses=answers,
            sent=sent.get(int(event["id"]), set()),
        )
        for kind, people in due:
            place = _place_label(event["data_json"])
            local = event["event_date"].astimezone(R.WARSAW)
            if kind == "hour":
                title, body = f"⏰ Za godzinę: {event['name']}", f"Start {local:%H:%M}{f' · {place}' if place else ''}."
            elif kind == "day":
                tomorrow = (local.date() - stamp.astimezone(R.WARSAW).date()).days == 1
                title = f"⏰ {'Jutro' if tomorrow else 'Za dobę'}: {event['name']}"
                body = f"{local:%d.%m} o {local:%H:%M}{f' · {place}' if place else ''}."
            else:
                deadline = event["_deadline"].astimezone(R.WARSAW)
                title = f"✋ Będziesz na: {event['name']}?"
                body = f"Odpowiedz do {deadline:%d.%m} {deadline:%H:%M} - jednym dotknięciem w aplikacji."
            # Najpierw wpis, potem wysyłka: powtórzone przejście nie wyśle drugi raz.
            for jid in people:
                await database.execute(
                    pg_insert(province_event_notifications)
                    .values(event_id=int(event["id"]), judge_id=jid, kind=kind, sent_at=stamp)
                    .on_conflict_do_nothing()
                )
            await _push(people, title, body, event, kind)
            total += len(people)
    return total


async def run_event_reminder_sweep() -> None:
    interval = int(os.getenv("PROVINCE_EVENT_SWEEP_SECONDS", str(5 * 60)))
    while True:
        try:
            await sweep_event_reminders()
        except Exception:  # noqa: BLE001
            logger.exception("wydarzenia: przejście przypomnień nie powiodło się")
        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Odczyt
# ---------------------------------------------------------------------------


@router.get("/feed", summary="Wydarzenia okręgu dla aplikacji (zaproszeni liczeni na żywo)")
async def feed(province: str = Query(""), actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    prov = _resolve_province(who, province)
    manager = R.can_manage(who, prov)
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province.in_(_names(prov)))
        .where(province_events.c.deleted_at.is_(None))
        .order_by(province_events.c.event_date.asc(), province_events.c.id.asc())
    )
    judges = await _judges(prov)
    by_id = {_s(j["judge_id"]): j for j in judges}
    events = [_row(r) for r in rows]
    ids = [int(e["id"]) for e in events]
    responses, attendance = await _responses(ids), await _attendance(ids)

    out = []
    for event in events:
        data = _data(event.get("data_json"))
        invited = R.invited_ids(judges, data)
        if not manager and who.judge_id not in invited:
            continue
        out.append(
            _view(
                event,
                judges_by_id=by_id,
                invited=invited,
                responses=responses.get(int(event["id"]), {}),
                attendance=attendance.get(int(event["id"]), {}),
                me=who.judge_id,
                manager=manager,
            )
        )
    return {
        "province": prov,
        "access": {"can_manage": manager, "is_admin": who.is_admin, "judge_id": who.judge_id},
        "events": out,
        "judges": [_judge_public(j) for j in judges] if manager else [],
        "types": [{"key": key, "label": label} for key, label in R.EVENT_TYPES.items()],
        "server_time": _now().isoformat(),
    }


@router.get("/item/{event_id}", summary="Jedno wydarzenie (np. z powiadomienia)")
async def item(event_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    manager = R.can_manage(who, prov)
    judges = await _judges(prov)
    invited = R.invited_ids(judges, event["data_json"])
    if not manager and who.judge_id not in invited:
        raise HTTPException(403, "To wydarzenie nie jest skierowane do Ciebie")
    responses, attendance = await _responses([event_id]), await _attendance([event_id])
    return _view(
        event,
        judges_by_id={_s(j["judge_id"]): j for j in judges},
        invited=invited,
        responses=responses.get(event_id, {}),
        attendance=attendance.get(event_id, {}),
        me=who.judge_id,
        manager=manager,
    )


# ---------------------------------------------------------------------------
# Tworzenie i edycja
# ---------------------------------------------------------------------------


class RecurrenceBody(BaseModel):
    rule: str
    until: str


class EventBody(BaseModel):
    province: str
    name: str
    description: Optional[str] = None
    event_type: Optional[str] = None
    event_date: str
    end_date: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    title_image: Optional[Dict[str, Any]] = None
    recurrence: Optional[RecurrenceBody] = None


class EventPatch(EventBody):
    #: `one` - tylko ten termin; `future` - ten i kolejne z tej samej serii.
    scope: str = "one"


def _clean_body(body: EventBody) -> Dict[str, Any]:
    try:
        start, end = R.clean_period(body.event_date, body.end_date)
        values = {
            "name": R.clean_name(body.name),
            "description": R.clean_description(body.description),
            "event_type": R.clean_type(body.event_type),
            "event_date": start,
            "end_date": end,
        }
        details = R.clean_details(body.details or {}, start)
    except R.Invalid as error:
        raise _bad(error)
    if body.title_image and _s(body.title_image.get("url")):
        details["title_image"] = {
            "url": _s(body.title_image.get("url")),
            "regeneration_count": int(body.title_image.get("regeneration_count") or 0),
            "generated_at": _s(body.title_image.get("generated_at")) or None,
        }
    values["details"] = details
    return values


@router.post("/v2", summary="Utwórz wydarzenie (również serię)")
async def create_v2(body: EventBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    prov = _resolve_province(who, body.province)
    _require_manager(who, prov)
    values = _clean_body(body)
    try:
        dates = R.expand_recurrence(
            values["event_date"],
            values["end_date"],
            body.recurrence.rule if body.recurrence else "",
            body.recurrence.until if body.recurrence else None,
        )
    except R.Invalid as error:
        raise _bad(error)

    now = _now()
    series_id = uuid.uuid4().hex if len(dates) > 1 else None
    ids: List[int] = []
    for start, end in dates:
        data = dict(values["details"])
        if data.get("rsvp_deadline") and start != values["event_date"]:
            # Termin odpowiedzi przesuwa się razem z terminem serii.
            shift = start - values["event_date"]
            data["rsvp_deadline"] = (R.parse_iso(data["rsvp_deadline"]) + shift).isoformat()
        row = await database.fetch_one(
            insert(province_events)
            .values(
                province=prov,
                event_date=start,
                end_date=end,
                name=values["name"],
                description=values["description"],
                event_type=values["event_type"],
                data_json=data,
                series_id=series_id,
                created_by=who.judge_id,
                created_by_name=actor.full_name or None,
                created_at=now,
                updated_at=now,
            )
            .returning(province_events.c.id)
        )
        ids.append(int(row["id"]))

    first = await _event(ids[0])
    invited = R.invited_ids(await _judges(prov), first["data_json"])
    await _notify_new(first, invited, len(ids), who.judge_id)
    return {"ids": ids, "series_id": series_id, "invited": len(invited)}


@router.patch("/v2/{event_id}", summary="Zmień wydarzenie (ten termin albo dalszą część serii)")
async def patch_v2(event_id: int, body: EventPatch, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    existing = await _event(event_id)
    prov = _resolve_province(who, existing["province"])
    _require_manager(who, prov)
    values = _clean_body(body)

    targets = [existing]
    if body.scope == "future" and existing.get("series_id"):
        rows = await database.fetch_all(
            select(province_events)
            .where(province_events.c.series_id == existing["series_id"])
            .where(province_events.c.event_date >= existing["event_date"])
            .where(province_events.c.deleted_at.is_(None))
            .order_by(province_events.c.event_date.asc())
        )
        targets = [_row(r) for r in rows]

    shift = values["event_date"] - existing["event_date"]
    duration = (values["end_date"] - values["event_date"]) if values["end_date"] else None
    judges = await _judges(prov)
    changed = 0
    for target in targets:
        data = _data(target.get("data_json"))
        start = target["event_date"] + shift if target["id"] != event_id else values["event_date"]
        details = dict(values["details"])
        if details.get("rsvp_deadline") and target["id"] != event_id:
            details["rsvp_deadline"] = (R.parse_iso(details["rsvp_deadline"]) + (start - values["event_date"])).isoformat()
        # Kod obecności i stara lista obecnych nie przychodzą z formularza.
        for keep in ("checkin", "present_ids", "invited_cache"):
            if keep in data:
                details[keep] = data[keep]
        # Brak pola = grafika bez zmian; pusty słownik = usunięta w formularzu.
        if "title_image" not in details and body.title_image is None and data.get("title_image"):
            details["title_image"] = data["title_image"]
        new_values = {
            "name": values["name"],
            "description": values["description"],
            "event_type": values["event_type"],
            "event_date": start,
            "end_date": start + duration if duration else None,
            "data_json": details,
            "updated_at": _now(),
        }
        before = {
            "event_date": target["event_date"],
            "end_date": target.get("end_date"),
            "place": data.get("place"),
            "online_url": data.get("online_url"),
        }
        after = {
            "event_date": new_values["event_date"],
            "end_date": new_values["end_date"],
            "place": details.get("place"),
            "online_url": details.get("online_url"),
        }
        await database.execute(update(province_events).where(province_events.c.id == target["id"]).values(**new_values))
        if R.meaningful_change(before, after) and new_values["event_date"] > _now() and not target.get("cancelled_at"):
            # Przypomnienia liczą się od nowa, bo zmienił się termin.
            if before["event_date"] != after["event_date"]:
                await database.execute(
                    delete(province_event_notifications).where(province_event_notifications.c.event_id == target["id"])
                )
            if target["id"] == event_id:
                fresh = await _event(event_id)
                await _notify_changed(fresh, R.invited_ids(judges, fresh["data_json"]), who.judge_id)
        changed += 1
    return {"updated": changed}


class CancelBody(BaseModel):
    reason: Optional[str] = None


@router.post("/{event_id}/cancel", summary="Odwołaj wydarzenie (zostaje widoczne z powodem)")
async def cancel(event_id: int, body: CancelBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    try:
        reason = R.clean_reason(body.reason)
    except R.Invalid as error:
        raise _bad(error)
    if event.get("cancelled_at"):
        raise HTTPException(409, "Wydarzenie jest już odwołane")
    await database.execute(
        update(province_events)
        .where(province_events.c.id == event_id)
        .values(cancelled_at=_now(), cancel_reason=reason, updated_at=_now())
    )
    fresh = await _event(event_id)
    if fresh["event_date"] > _now():
        await _notify_cancelled(fresh, R.invited_ids(await _judges(prov), fresh["data_json"]), who.judge_id)
    return {"ok": True}


@router.post("/{event_id}/uncancel", summary="Przywróć odwołane wydarzenie")
async def uncancel(event_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    await database.execute(
        update(province_events)
        .where(province_events.c.id == event_id)
        .values(cancelled_at=None, cancel_reason=None, updated_at=_now())
    )
    fresh = await _event(event_id)
    if fresh["event_date"] > _now():
        await _notify_changed(fresh, R.invited_ids(await _judges(prov), fresh["data_json"]), who.judge_id)
    return {"ok": True}


@router.post("/{event_id}/trash", summary="Do kosza (30 dni na przywrócenie)")
async def trash(event_id: int, series: bool = Query(False), actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    condition = province_events.c.id == event_id
    if series and event.get("series_id"):
        condition = and_(
            province_events.c.series_id == event["series_id"],
            province_events.c.event_date >= event["event_date"],
            province_events.c.deleted_at.is_(None),
        )
    rows = await database.fetch_all(select(province_events.c.id).where(condition))
    await database.execute(update(province_events).where(condition).values(deleted_at=_now()))
    return {"ids": [int(r["id"]) for r in rows]}


class RestoreBody(BaseModel):
    ids: List[int]


@router.post("/restore", summary="Przywróć z kosza")
async def restore(body: RestoreBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    restored = []
    now = _now()
    for event_id in body.ids[:60]:
        event = await _event(event_id, deleted_ok=True)
        prov = _resolve_province(who, event["province"])
        _require_manager(who, prov)
        if event.get("deleted_at") is None:
            continue
        if not R.restorable(event["deleted_at"], now):
            raise HTTPException(410, "Minęło 30 dni - tego wydarzenia nie da się już przywrócić")
        await database.execute(update(province_events).where(province_events.c.id == event_id).values(deleted_at=None))
        restored.append(event_id)
    return {"restored": restored}


@router.get("/trash", summary="Kosz wydarzeń okręgu")
async def trash_list(province: str = Query(""), actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    prov = _resolve_province(who, province)
    _require_manager(who, prov)
    now = _now()
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province.in_(_names(prov)))
        .where(province_events.c.deleted_at.is_not(None))
        .where(province_events.c.deleted_at >= now - timedelta(days=R.TRASH_DAYS))
        .order_by(province_events.c.deleted_at.desc())
    )
    return {
        "items": [
            {
                "id": int(r["id"]),
                "name": r["name"],
                "event_type": r["event_type"] or R.DEFAULT_TYPE,
                "event_date": _iso(r["event_date"]),
                "deleted_at": _iso(r["deleted_at"]),
                "days_left": R.days_left(r["deleted_at"], now),
                "series_id": r["series_id"],
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------------------------
# Szablony
# ---------------------------------------------------------------------------


class TemplateBody(BaseModel):
    province: str
    name: str
    payload: Dict[str, Any] = Field(default_factory=dict)


@router.get("/templates", summary="Szablony wydarzeń okręgu")
async def templates(province: str = Query(""), actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    prov = _resolve_province(who, province)
    _require_manager(who, prov)
    rows = await database.fetch_all(
        select(province_event_templates)
        .where(province_event_templates.c.province.in_(_names(prov)))
        .order_by(province_event_templates.c.name.asc())
    )
    return {
        "items": [
            {"id": int(r["id"]), "name": r["name"], "payload": _data(r["payload"]), "created_at": _iso(r["created_at"])}
            for r in rows
        ]
    }


@router.post("/templates", summary="Zapisz szablon")
async def template_create(body: TemplateBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    prov = _resolve_province(who, body.province)
    _require_manager(who, prov)
    name = _s(body.name)
    if not name or len(name) > 80:
        raise HTTPException(400, "Nazwa szablonu ma od 1 do 80 znaków")
    allowed = ("name", "description", "event_type", "duration_minutes", "start_time", "details")
    payload = {key: body.payload.get(key) for key in allowed if key in body.payload}
    row = await database.fetch_one(
        insert(province_event_templates)
        .values(province=prov, name=name, payload=payload, created_by=who.judge_id, created_at=_now())
        .returning(province_event_templates.c.id)
    )
    return {"id": int(row["id"])}


@router.delete("/templates/{template_id}", summary="Usuń szablon")
async def template_delete(template_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    row = await database.fetch_one(select(province_event_templates).where(province_event_templates.c.id == template_id))
    if not row:
        raise HTTPException(404, "Nie ma takiego szablonu")
    _require_manager(who, _resolve_province(who, row["province"]))
    await database.execute(delete(province_event_templates).where(province_event_templates.c.id == template_id))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Odpowiedzi i obecność
# ---------------------------------------------------------------------------


class RsvpBody(BaseModel):
    status: str
    reason: Optional[str] = None


@router.post("/{event_id}/rsvp", summary="Będę / Nie będę")
async def rsvp(event_id: int, body: RsvpBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    data = event["data_json"]
    judges = await _judges(prov)
    invited = R.invited_ids(judges, data)
    responses = (await _responses([event_id])).get(event_id, {})
    current = _s((responses.get(who.judge_id) or {}).get("status")) or None
    yes_count = sum(1 for jid, row in responses.items() if row.get("status") == "yes" and jid in invited)
    try:
        reason = R.clean_reason(body.reason) if body.status == "no" else None
        deadline = R.parse_iso(data.get("rsvp_deadline")) if data.get("rsvp_deadline") else None
    except R.Invalid as error:
        raise _bad(error)
    refusal = R.rsvp_refusal(
        now=_now(),
        start=event["event_date"],
        deadline=deadline,
        cancelled=event.get("cancelled_at") is not None,
        invited=who.judge_id in invited,
        status=body.status,
        current=current,
        yes_count=yes_count,
        capacity=data.get("capacity"),
    )
    if refusal:
        raise HTTPException(409, refusal)
    await database.execute(
        pg_insert(province_event_responses)
        .values(event_id=event_id, judge_id=who.judge_id, status=body.status, reason=reason, updated_at=_now())
        .on_conflict_do_update(
            index_elements=["event_id", "judge_id"],
            set_={"status": body.status, "reason": reason, "updated_at": _now()},
        )
    )
    return await item(event_id, actor)


class AttendanceEntry(BaseModel):
    judge_id: str
    status: str  # present | excused | absent


class AttendanceBody(BaseModel):
    entries: List[AttendanceEntry]


async def _migrate_legacy_present(event: Mapping[str, Any]) -> None:
    """Stara lista `present_ids` przechodzi do tabeli przy pierwszym zapisie obecności."""
    data = _data(event.get("data_json"))
    legacy = [_s(x) for x in data.get("present_ids") or [] if _s(x)]
    if not legacy:
        return
    for jid in legacy:
        await database.execute(
            pg_insert(province_event_attendance)
            .values(event_id=int(event["id"]), judge_id=jid, status="present", source="legacy", marked_at=_now())
            .on_conflict_do_nothing()
        )
    data["present_ids"] = []
    await database.execute(update(province_events).where(province_events.c.id == int(event["id"])).values(data_json=data))


async def _set_attendance(event_id: int, entries: List[Tuple[str, str]], *, source: str, marked_by: str) -> None:
    for jid, status in entries:
        if status == "absent":
            await database.execute(
                delete(province_event_attendance).where(
                    and_(province_event_attendance.c.event_id == event_id, province_event_attendance.c.judge_id == jid)
                )
            )
            continue
        await database.execute(
            pg_insert(province_event_attendance)
            .values(event_id=event_id, judge_id=jid, status=status, source=source, marked_by=marked_by, marked_at=_now())
            .on_conflict_do_update(
                index_elements=["event_id", "judge_id"],
                set_={"status": status, "source": source, "marked_by": marked_by, "marked_at": _now()},
            )
        )


@router.put("/{event_id}/attendance/v2", summary="Zmiany obecności (tylko przesłane osoby)")
async def attendance_v2(event_id: int, body: AttendanceBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    """Zapisujemy RÓŻNICE, nie całą listę - wpis z kodu w trakcie sprawdzania nie znika."""
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    entries: List[Tuple[str, str]] = []
    for entry in body.entries[:2000]:
        status = _s(entry.status)
        if status not in (*R.ATTENDANCE_STATUSES, "absent"):
            raise HTTPException(400, "Obecność to: obecny, usprawiedliwiony albo nieobecny")
        if _s(entry.judge_id):
            entries.append((_s(entry.judge_id), status))
    await _migrate_legacy_present(event)
    await _set_attendance(event_id, entries, source="manual", marked_by=who.judge_id)
    return await item(event_id, actor)


# ---------------------------------------------------------------------------
# Kod obecności
# ---------------------------------------------------------------------------


def _qr_matrix(payload: str) -> List[str]:
    import qrcode

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, border=0)
    qr.add_data(payload)
    qr.make(fit=True)
    return ["".join("1" if cell else "0" for cell in row) for row in qr.get_matrix()]


async def _checkin_view(event: Mapping[str, Any], checkin: Mapping[str, Any]) -> Dict[str, Any]:
    opens, closes = R.checkin_window(event["event_date"], event.get("end_date"))
    payload = R.qr_payload(int(event["id"]), _s(checkin.get("token")))
    rows = await database.fetch_all(
        select(province_event_attendance)
        .where(province_event_attendance.c.event_id == int(event["id"]))
        .where(province_event_attendance.c.source.in_(("qr", "code")))
        .order_by(province_event_attendance.c.marked_at.desc())
    )
    judges = {_s(j["judge_id"]): j for j in await _judges(_province(event["province"]))}
    return {
        "event_id": int(event["id"]),
        "code": checkin.get("code"),
        "payload": payload,
        "matrix": _qr_matrix(payload),
        "opens_at": opens.isoformat(),
        "closes_at": closes.isoformat(),
        "checked_in": [
            {**_person(judges.get(_s(r["judge_id"])), _s(r["judge_id"])), "source": r["source"], "marked_at": _iso(r["marked_at"])}
            for r in rows
        ],
    }


@router.post("/{event_id}/checkin/open", summary="Kod obecności dla komisji (QR + 4 znaki)")
async def checkin_open(event_id: int, refresh: bool = Query(False), actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    data = event["data_json"]
    checkin = data.get("checkin") if isinstance(data.get("checkin"), Mapping) else None
    if refresh or not checkin or not checkin.get("code"):
        # Kod unikalny wśród wydarzeń, których okno obecności się zazębia.
        for _ in range(12):
            code = R.new_checkin_code()
            clash = await database.fetch_one(
                select(province_events.c.id)
                .where(province_events.c.id != event_id)
                .where(province_events.c.deleted_at.is_(None))
                .where(province_events.c.event_date >= event["event_date"] - timedelta(days=1))
                .where(province_events.c.event_date <= event["event_date"] + timedelta(days=1))
                .where(province_events.c.data_json["checkin"]["code"].astext == code)
            )
            if not clash:
                break
        checkin = {"code": code, "token": R.new_checkin_token(), "opened_at": _now().isoformat(), "opened_by": who.judge_id}
        data["checkin"] = checkin
        await database.execute(update(province_events).where(province_events.c.id == event_id).values(data_json=data))
    return await _checkin_view(event, checkin)


@router.get("/{event_id}/checkin", summary="Kod obecności i lista wbitych (komisja)")
async def checkin_state(event_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    _require_manager(who, _resolve_province(who, event["province"]))
    checkin = event["data_json"].get("checkin")
    if not isinstance(checkin, Mapping) or not checkin.get("code"):
        raise HTTPException(404, "Kod obecności nie jest jeszcze otwarty")
    return await _checkin_view(event, checkin)


class CheckinBody(BaseModel):
    qr: Optional[str] = None
    code: Optional[str] = None


def _too_many_failures(judge_id: str) -> bool:
    now = time.monotonic()
    recent = [t for t in _checkin_failures.get(judge_id, []) if now - t < CHECKIN_FAIL_WINDOW_S]
    _checkin_failures[judge_id] = recent
    return len(recent) >= CHECKIN_FAIL_LIMIT


def _fail(judge_id: str) -> None:
    _checkin_failures.setdefault(judge_id, []).append(time.monotonic())


@router.post("/checkin", summary="Sędzia potwierdza obecność kodem QR albo 4 znakami")
async def checkin(body: CheckinBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    if _too_many_failures(who.judge_id):
        raise HTTPException(429, "Za dużo nieudanych prób - spróbuj za kilka minut albo poproś komisję o wpis")
    now = _now()
    candidates: List[Dict[str, Any]] = []
    source = "code"
    parsed = R.parse_qr(body.qr) if body.qr else None
    if body.qr and not parsed:
        _fail(who.judge_id)
        raise HTTPException(400, "To nie jest kod wydarzenia BAZY")
    if parsed:
        source = "qr"
        candidates = [await _event(parsed[0])]
    else:
        code = R.normalize_code(body.code)
        if len(code) != R.CHECKIN_CODE_LEN:
            raise HTTPException(400, f"Kod ma {R.CHECKIN_CODE_LEN} znaki")
        rows = await database.fetch_all(
            select(province_events)
            .where(province_events.c.deleted_at.is_(None))
            .where(province_events.c.event_date >= now - timedelta(days=R.MAX_DURATION.days + 1))
            .where(province_events.c.event_date <= now + R.CHECKIN_OPEN_BEFORE + timedelta(minutes=5))
            .where(province_events.c.data_json["checkin"]["code"].astext == code)
        )
        candidates = [{**_row(r), "data_json": _data(r["data_json"])} for r in rows]
        if not candidates:
            _fail(who.judge_id)
            raise HTTPException(404, "Nie znam tego kodu - sprawdź znaki na ekranie komisji")

    last_refusal = "Ten kod nie pasuje do wydarzenia"
    for event in candidates:
        checkin_data = event["data_json"].get("checkin") if isinstance(event["data_json"].get("checkin"), Mapping) else {}
        matches = (
            bool(checkin_data.get("token")) and parsed is not None and parsed[1] == checkin_data.get("token")
        ) or (parsed is None and R.normalize_code(body.code) == _s(checkin_data.get("code")))
        invited = R.invited_ids(await _judges(_province(event["province"])), event["data_json"])
        refusal = R.checkin_refusal(
            now=now,
            start=event["event_date"],
            end=event.get("end_date"),
            cancelled=event.get("cancelled_at") is not None,
            invited=who.judge_id in invited,
            code_matches=matches,
        )
        if refusal:
            last_refusal = refusal
            continue
        rows = (await _attendance([int(event["id"])])).get(int(event["id"]), {})
        already = R.attendance_state(who.judge_id, rows, event["data_json"].get("present_ids") or []) == "present"
        if not already:
            await _set_attendance(int(event["id"]), [(who.judge_id, "present")], source=source, marked_by=who.judge_id)
        view = await item(int(event["id"]), actor)
        return {"already": already, "event": view}
    _fail(who.judge_id)
    raise HTTPException(409, last_refusal)


# ---------------------------------------------------------------------------
# PDF listy obecności
# ---------------------------------------------------------------------------

_STATUS_LABEL = {"present": "obecność", "excused": "usprawiedliwiona", "absent": "nieobecność"}
_RESPONSE_LABEL = {"yes": "Będę", "no": "Nie będę"}


def _attendance_html(event: Mapping[str, Any], people: List[Dict[str, Any]], counts: Mapping[str, int]) -> str:
    esc = html.escape
    data = _data(event.get("data_json"))
    local = event["event_date"].astimezone(R.WARSAW)
    end = event.get("end_date")
    when = f"{local:%d.%m.%Y}, {local:%H:%M}" + (f" - {end.astimezone(R.WARSAW):%H:%M}" if end else "")
    place = _place_label(data)
    rows = "".join(
        f"<tr class='{p['status']}'><td class='lp'>{i}</td><td><b>{esc(p['name'])}</b><span class='id'>{esc(p['judge_id'])}</span></td>"
        f"<td>{esc(_RESPONSE_LABEL.get(p['response'] or '', '-'))}</td><td class='st'>{esc(_STATUS_LABEL[p['status']])}</td><td class='sign'></td></tr>"
        for i, p in enumerate(people, start=1)
    )
    return f"""<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 16mm 13mm 16mm 13mm;
  @bottom-center {{ content: "Strona " counter(page) " z " counter(pages); font-size: 8pt; color: #888; font-family: "DejaVu Sans", "Noto Sans", sans-serif; }} }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: "DejaVu Sans", "Noto Sans", sans-serif; font-size: 9.5pt; color: #1d1d1f; }}
.head {{ border-bottom: 2pt solid #c38e70; padding-bottom: 10pt; margin-bottom: 12pt; }}
.kicker {{ color: #8a5a44; font-size: 8pt; letter-spacing: 1.2pt; text-transform: uppercase; font-weight: bold; }}
h1 {{ font-size: 17pt; margin: 4pt 0 3pt; }}
.meta {{ color: #555; font-size: 9pt; }}
.stats {{ display: flex; gap: 8pt; margin: 10pt 0 14pt; }}
.stat {{ border: 1pt solid #e6d5c6; border-radius: 6pt; padding: 6pt 10pt; }}
.stat b {{ font-size: 13pt; display: block; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ text-align: left; font-size: 8pt; color: #8a5a44; text-transform: uppercase; letter-spacing: .6pt; border-bottom: 1pt solid #c38e70; padding: 5pt 6pt; }}
td {{ padding: 6pt; border-bottom: .6pt solid #eee; vertical-align: middle; }}
td.lp {{ width: 22pt; color: #999; }}
.id {{ color: #999; font-size: 7.5pt; margin-left: 6pt; }}
td.sign {{ width: 120pt; border-bottom: .6pt solid #bbb; }}
tr.present .st {{ color: #2f855a; font-weight: bold; }}
tr.excused .st {{ color: #b7791f; font-weight: bold; }}
tr.absent .st {{ color: #c53030; }}
</style></head><body>
<div class="head"><div class="kicker">Lista obecności · {esc(R.EVENT_TYPES.get(event.get('event_type') or '', 'Wydarzenie'))} · {esc(_s(event['province']))}</div>
<h1>{esc(event['name'])}</h1><div class="meta">{esc(when)}{(' · ' + esc(place)) if place else ''}{' · odwołane' if event.get('cancelled_at') else ''}</div></div>
<div class="stats"><div class="stat"><b>{counts['invited']}</b>zaproszonych</div><div class="stat"><b>{counts['present']}</b>obecnych</div>
<div class="stat"><b>{counts['excused']}</b>usprawiedliwionych</div><div class="stat"><b>{counts['absent']}</b>nieobecnych</div></div>
<table><thead><tr><th>Lp.</th><th>Sędzia</th><th>Odpowiedź</th><th>Obecność</th><th>Podpis</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""


@router.post("/{event_id}/attendance/pdf", summary="Lista obecności do PDF")
async def attendance_pdf(event_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    judges = await _judges(prov)
    by_id = {_s(j["judge_id"]): j for j in judges}
    invited = R.invited_ids(judges, event["data_json"])
    responses = (await _responses([event_id])).get(event_id, {})
    rows = (await _attendance([event_id])).get(event_id, {})
    legacy = event["data_json"].get("present_ids") or []
    people = sorted(
        (
            {
                "judge_id": jid,
                "name": _s((by_id.get(jid) or {}).get("full_name")) or jid,
                "status": R.attendance_state(jid, rows, legacy),
                "response": _s((responses.get(jid) or {}).get("status")) or None,
            }
            for jid in invited
        ),
        key=lambda p: p["name"],
    )
    counts = {
        "invited": len(people),
        "present": sum(1 for p in people if p["status"] == "present"),
        "excused": sum(1 for p in people if p["status"] == "excused"),
        "absent": sum(1 for p in people if p["status"] == "absent"),
    }
    import weasyprint

    os.makedirs(PDF_DIR, exist_ok=True)
    token = uuid.uuid4().hex
    tmp = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp, "lista.html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(_attendance_html(event, people, counts))
        weasyprint.HTML(filename=html_path).write_pdf(os.path.join(PDF_DIR, f"{token}.pdf"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    local = event["event_date"].astimezone(R.WARSAW)
    filename = f"obecnosc_{local:%Y-%m-%d}_{event_id}.pdf"
    return {
        "download_url": f"/province-events/pdf/{token}?filename={urllib.parse.quote(filename)}",
        "filename": filename,
        "counts": counts,
    }


@router.get("/pdf/{token}", summary="Pobierz wygenerowaną listę obecności")
async def pdf_download(token: str, filename: str = Query("obecnosc.pdf")):
    safe = os.path.basename(token)
    path = os.path.join(PDF_DIR, f"{safe}.pdf")
    if not os.path.exists(path):
        raise HTTPException(404, "Plik wygasł albo nie istnieje")
    return FileResponse(path, media_type="application/pdf", filename=os.path.basename(filename))


# ---------------------------------------------------------------------------
# Grafika tytułowa
# ---------------------------------------------------------------------------


class TitleImageBody(BaseModel):
    province: str
    name: str
    event_type: Optional[str] = None
    place: Optional[str] = None
    event_date: Optional[str] = None
    regeneration_count: int = 0
    regenerate: bool = False
    extra_prompt: Optional[str] = None


@router.post("/title-image", summary="Wygeneruj grafikę tytułową (OpenAI)")
async def title_image(body: TitleImageBody, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    who = _require_judge(actor)
    prov = _resolve_province(who, body.province)
    _require_manager(who, prov)
    if not _s(body.name):
        raise HTTPException(400, "Najpierw wpisz nazwę wydarzenia")
    count = max(0, int(body.regeneration_count or 0))
    if body.regenerate and count >= R.TITLE_IMAGE_REGENERATIONS:
        raise HTTPException(400, "Grafikę można odświeżyć najwyżej 2 razy")
    date_label = ""
    if body.event_date:
        try:
            parsed = R.parse_iso(body.event_date)
            date_label = parsed.astimezone(R.WARSAW).strftime("%d.%m.%Y") if parsed else ""
        except R.Invalid:
            date_label = ""
    prompt = R.title_image_prompt(
        name=_s(body.name),
        event_type=_s(body.event_type) or R.DEFAULT_TYPE,
        place=_s(body.place),
        date_label=date_label,
        extra=_s(body.extra_prompt)[:300],
    )
    from app.beach.tournaments import _generate_openai_title_image, _public_static_url, _static_root_dir

    image = await _generate_openai_title_image(prompt)
    out_dir = _static_root_dir() / "province-events" / "title-images"
    out_dir.mkdir(parents=True, exist_ok=True)
    path: Path = out_dir / f"{uuid.uuid4().hex}.png"
    path.write_bytes(image)
    return {
        "url": _public_static_url(path),
        "generated_at": _now().isoformat(),
        "regeneration_count": count + 1 if body.regenerate else count,
    }


# ---------------------------------------------------------------------------
# Podgląd dla Tablicy Komisji (BAZA_web) - bez tokenu sędziego, woła `board.py`
# ---------------------------------------------------------------------------


async def board_preview(spellings: List[str]) -> List[Dict[str, Any]]:
    """Wydarzenia okręgu do kalendarza Tablicy: bez obecności i bez odpowiedzi imiennie.

    Tablica zna kilka zapisów nazwy województwa, wydarzenia trzymają WIELKIE
    LITERY z polskimi znakami - pytamy o każdy zapis.
    """
    names = sorted({alias for name in spellings if _s(name) for alias in _names(name)})
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province.in_(names))
        .where(province_events.c.deleted_at.is_(None))
        .order_by(province_events.c.event_date.asc())
    )
    events = [_row(r) for r in rows]
    if not events:
        return []
    judges: List[Dict[str, Any]] = []
    for name in {_province(e["province"]) for e in events}:
        judges += await _judges(name)
    responses = await _responses([int(e["id"]) for e in events])
    out = []
    for event in events:
        data = _data(event.get("data_json"))
        invited = R.invited_ids(judges, data)
        answers = responses.get(int(event["id"]), {})
        details = _details(data)
        out.append(
            {
                "id": int(event["id"]),
                "name": event["name"],
                "description": event.get("description"),
                "event_type": event.get("event_type") or R.DEFAULT_TYPE,
                "type_label": R.EVENT_TYPES.get(event.get("event_type") or R.DEFAULT_TYPE, "Inne"),
                "event_date": _iso(event["event_date"]),
                "end_date": _iso(event.get("end_date")),
                "cancelled_at": _iso(event.get("cancelled_at")),
                "cancel_reason": event.get("cancel_reason"),
                "place": details["place"],
                "online_url": details["online_url"],
                "obligatory": details["obligatory"],
                "program": details["program"],
                "title_image": details["title_image"],
                "invited": len(invited),
                "going": sum(1 for jid, row in answers.items() if row.get("status") == "yes" and jid in invited),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Stare trasy - wydana wersja aplikacji (kształt odpowiedzi bez zmian)
# ---------------------------------------------------------------------------


async def _legacy_item(row: Mapping[str, Any], judges: List[Dict[str, Any]], me: Optional[str]) -> ProvinceEventItem:
    data = _data(row.get("data_json"))
    invited = R.invited_ids(judges, data)
    rows = (await _attendance([int(row["id"])])).get(int(row["id"]), {})
    legacy = data.get("present_ids") or []
    present = [jid for jid in invited if R.attendance_state(jid, rows, legacy) == "present"]
    data = {**data, "invited_ids": invited, "present_ids": present}
    return ProvinceEventItem(
        id=int(row["id"]),
        province=row["province"],
        event_date=row["event_date"],
        name=row["name"],
        description=row.get("description"),
        data_json=data,
        updated_at=row["updated_at"],
        invited_total=len(invited),
        present_total=len(present),
        user_invited=bool(me and me in invited),
        user_present=bool(me and me in present),
    )


@router.post("/", response_model=dict, summary="Utwórz wydarzenie okręgowe (stara wersja aplikacji)")
async def create_province_event(req: CreateProvinceEventRequest, actor: Actor = Depends(market_actor)):
    who = _require_judge(actor)
    prov = _resolve_province(who, req.province)
    _require_manager(who, prov)
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Brak nazwy wydarzenia")
    raw = _data(req.data_json)
    data = {"target": R.clean_target(raw.get("target"))}
    now = _now()
    row = await database.fetch_one(
        insert(province_events)
        .values(
            province=prov,
            event_date=req.event_date,
            name=req.name.strip(),
            description=(req.description or "").strip() or None,
            event_type=R.DEFAULT_TYPE,
            data_json=data,
            created_by=who.judge_id,
            created_by_name=actor.full_name or None,
            created_at=now,
            updated_at=now,
        )
        .returning(province_events.c.id)
    )
    event = await _event(int(row["id"]))
    await _notify_new(event, R.invited_ids(await _judges(prov), data), 1, who.judge_id)
    return {"success": True, "id": int(row["id"])}


@router.get("/", response_model=ListProvinceEventsResponse, summary="Lista wydarzeń okręgowych (stara wersja, komisja)")
async def list_province_events(
    province: str = Query(...),
    judge_id: Optional[str] = Query(None),
    actor: Actor = Depends(market_actor),
):
    who = _require_judge(actor)
    prov = _resolve_province(who, province)
    _require_manager(who, prov)
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province.in_(_names(prov)))
        .where(province_events.c.deleted_at.is_(None))
        .order_by(province_events.c.event_date.asc(), province_events.c.id.asc())
    )
    judges = await _judges(prov)
    return ListProvinceEventsResponse(events=[await _legacy_item(_row(r), judges, who.judge_id) for r in rows])


@router.get("/visible", response_model=ListProvinceEventsResponse, summary="Wydarzenia widoczne dla sędziego (stara wersja)")
async def list_visible_events_for_judge(
    judge_id: str = Query(""),
    province: str = Query(""),
    actor: Actor = Depends(market_actor),
):
    # Numer z adresu NIE decyduje - liczy się podpisany token.
    who = _require_judge(actor)
    prov = _resolve_province(who, province)
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province.in_(_names(prov)))
        .where(province_events.c.deleted_at.is_(None))
        .order_by(province_events.c.event_date.asc(), province_events.c.id.asc())
    )
    judges = await _judges(prov)
    out = []
    for raw in rows:
        row = _row(raw)
        if who.judge_id in R.invited_ids(judges, _data(row.get("data_json"))):
            out.append(await _legacy_item(row, judges, who.judge_id))
    return ListProvinceEventsResponse(events=out)


@router.get("/{event_id}", response_model=ProvinceEventItem, summary="Wydarzenie po ID (stara wersja)")
async def get_province_event(event_id: int, judge_id: Optional[str] = Query(None), actor: Actor = Depends(market_actor)):
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    judges = await _judges(prov)
    if not R.can_manage(who, prov) and who.judge_id not in R.invited_ids(judges, event["data_json"]):
        raise HTTPException(403, "To wydarzenie nie jest skierowane do Ciebie")
    return await _legacy_item(event, judges, who.judge_id)


@router.patch("/{event_id}", response_model=ProvinceEventItem, summary="Edycja wydarzenia (stara wersja)")
async def patch_province_event(event_id: int, body: UpdateProvinceEventRequest, actor: Actor = Depends(market_actor)):
    who = _require_judge(actor)
    existing = await _event(event_id)
    prov = _resolve_province(who, existing["province"])
    _require_manager(who, prov)
    values: Dict[str, Any] = {}
    if body.event_date is not None:
        values["event_date"] = body.event_date
    if body.name is not None:
        values["name"] = body.name.strip()
    if body.description is not None:
        values["description"] = (body.description or "").strip() or None
    if body.data_json is not None:
        # Stara wersja zna tylko adresatów - pozostałe pola nowego formularza zostają.
        data = dict(existing["data_json"])
        data["target"] = R.clean_target(_data(body.data_json).get("target"))
        values["data_json"] = data
    if values:
        values["updated_at"] = _now()
        await database.execute(update(province_events).where(province_events.c.id == event_id).values(**values))
        if "event_date" in values and values["event_date"] != existing["event_date"]:
            await database.execute(
                delete(province_event_notifications).where(province_event_notifications.c.event_id == event_id)
            )
    event = await _event(event_id)
    return await _legacy_item(event, await _judges(prov), who.judge_id)


@router.delete("/{event_id}", response_model=dict, summary="Usuń wydarzenie (do kosza)")
async def delete_province_event(event_id: int, actor: Actor = Depends(market_actor)):
    who = _require_judge(actor)
    event = await _event(event_id)
    _require_manager(who, _resolve_province(who, event["province"]))
    await database.execute(update(province_events).where(province_events.c.id == event_id).values(deleted_at=_now()))
    return {"success": True}


@router.patch("/{event_id}/attendance", response_model=ProvinceEventItem, summary="Obecność pełną listą (stara wersja)")
async def update_event_attendance(
    event_id: int,
    body: UpdateProvinceEventAttendanceRequest,
    actor: Actor = Depends(market_actor),
):
    who = _require_judge(actor)
    event = await _event(event_id)
    prov = _resolve_province(who, event["province"])
    _require_manager(who, prov)
    await _migrate_legacy_present(event)
    wanted = {_s(x) for x in body.present_ids or [] if _s(x)}
    rows = (await _attendance([event_id])).get(event_id, {})
    entries: List[Tuple[str, str]] = [(jid, "present") for jid in wanted if _s((rows.get(jid) or {}).get("status")) != "present"]
    # Stara lista nie zna usprawiedliwień - usuwa tylko obecnych, których odznaczono.
    entries += [(jid, "absent") for jid, row in rows.items() if row.get("status") == "present" and jid not in wanted]
    await _set_attendance(event_id, entries, source="manual", marked_by=who.judge_id)
    event = await _event(event_id)
    return await _legacy_item(event, await _judges(prov), who.judge_id)
