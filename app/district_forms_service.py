"""
Formularze okręgowe - dostęp do bazy wspólny dla aplikacji, webu, wydarzeń i przejścia w tle.

Trasy: `app/district_forms.py` (aplikacja i web po QR), `app/district_forms_public.py`
(anonimowy web). Reguły bez bazy: `app/district_forms_rules.py`. Kontrakt:
`docs/formularze-okregowe.md`.

Zasady, których pilnuje ten moduł:
  - jeden zapis komórek = jedna transakcja z blokadą wiersza; najpierw wszystkie
    sprawdzenia, potem zapis, potem log każdej zmiany (z IP i urządzeniem dla webu),
  - powiadomienie: najpierw wiersz w dzienniku (`district_form_notifications`,
    unikalny klucz), potem push - powtórzone przejście nie wyśle drugi raz,
  - lista spięta z wydarzeniem: status w formularzu jest JEDYNĄ prawdą o RSVP;
    tabela odpowiedzi wydarzenia dostaje kopię (dla czytników spoza tego modułu).
"""
from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from sqlalchemy import and_, delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import district_form_info as INFO
from app import district_form_schema as SC
from app import district_forms_rules as R
from app.db import (
    database,
    district_form_entries,
    district_form_log,
    district_form_notifications,
    district_form_pairs,
    district_form_uploads,
    district_forms,
    province_event_responses,
    province_events,
)
from app.push.push import send_push_to_judges_report
from app.settlement_province import canonical, display

logger = logging.getLogger(__name__)

FORMS, ENTRIES, LOG, NOTES, PAIRS, UPLOADS = (
    district_forms,
    district_form_entries,
    district_form_log,
    district_form_notifications,
    district_form_pairs,
    district_form_uploads,
)

PUSH_PREFERENCE = "province_events"
PUSH_VARIANT = "baza"
UPLOAD_MAX_BYTES = 10 * 1024 * 1024


def now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _row(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row)


# ---------------------------------------------------------------------------
# Formularz i ludzie
# ---------------------------------------------------------------------------


def parse_form(raw: Any) -> Dict[str, Any]:
    form = _row(raw)
    form["schema_json"] = R.loads(form.get("schema_json"), {})
    form["settings_json"] = R.loads(form.get("settings_json"), {})
    form["audience_json"] = R.loads(form.get("audience_json"), {})
    form["cover_json"] = R.loads(form.get("cover_json"), {}) or None
    form["info_json"] = INFO.stored_info(R.loads(form.get("info_json"), {}))
    return form


def parse_entry(raw: Any) -> Dict[str, Any]:
    entry = _row(raw)
    entry["cells_json"] = R.loads(entry.get("cells_json"), {})
    entry["answers_json"] = R.loads(entry.get("answers_json"), {})
    return entry


async def load_form(form_id: str) -> Dict[str, Any]:
    if not R.FORM_ID_RE.match(_s(form_id)):
        raise R.not_found()
    row = await database.fetch_one(select(FORMS).where(FORMS.c.id == _s(form_id)))
    if not row:
        raise R.not_found()
    return parse_form(row)


async def judges(province: str) -> List[Dict[str, Any]]:
    """Sędziowie okręgu z odznakami i znacznikiem nieaktywnego - ta sama lista co w wydarzeniach."""
    from app.province_events import _judges

    return await _judges(display(province) or _s(province))


def inactive_of(people: Iterable[Mapping[str, Any]]) -> Set[str]:
    return {_s(j.get("judge_id")) for j in people if j.get("inactive")}


def circles_of(form: Mapping[str, Any], people: Sequence[Mapping[str, Any]]) -> R.Circles:
    return R.resolve_audience(
        people,
        form.get("audience_json") or {},
        author=_s(form.get("created_by")),
        inactive=inactive_of(people),
    )


@dataclass
class Ctx:
    form: Dict[str, Any]
    judges: List[Dict[str, Any]]
    by_id: Dict[str, Dict[str, Any]]
    circles: R.Circles
    roles: List[str]
    status: str
    who: Optional[R.Viewer] = None
    entries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    #: Odpowiedzi gości formularza otwartego (bez judge_id).
    guests: int = 0

    @property
    def manager(self) -> bool:
        return "manager" in self.roles

    @property
    def kind(self) -> str:
        return self.form.get("kind") or "list"

    @property
    def columns(self) -> List[Dict[str, Any]]:
        return R.columns_of(self.form.get("schema_json"))


async def context(form_id: str, who: R.Viewer, *, with_entries: bool = True, moment: Optional[datetime] = None) -> Ctx:
    """Formularz z rolami pytającego. Obcy (bez roli) dostaje 404 - nie widzi nawet tytułu."""
    form = await load_form(form_id)
    people = await judges(form["province"])
    circles = circles_of(form, people)
    roles = R.roles_for(who, province=form["province"], author=_s(form.get("created_by")), circles=circles)
    status = R.form_status(form, moment or now())
    R.check_access(roles, status)
    if status == "trash" and not R.restorable(form.get("deleted_at"), moment or now()):
        raise R.not_found()
    ctx = Ctx(form=form, judges=people, by_id={_s(j["judge_id"]): j for j in people}, circles=circles,
              roles=roles, status=status, who=who)
    if with_entries:
        await load_entries(ctx)
    return ctx


async def load_entries(ctx: Ctx) -> None:
    rows = await all_entries([ctx.form["id"]])
    ctx.entries = {_s(e["judge_id"]): e for e in rows if _s(e.get("judge_id"))}
    ctx.guests = sum(1 for e in rows if not _s(e.get("judge_id")) and e.get("submitted_at"))


async def public_context(form: Dict[str, Any], *, moment: Optional[datetime] = None) -> Ctx:
    people = await judges(form["province"])
    circles = circles_of(form, people)
    ctx = Ctx(form=form, judges=people, by_id={_s(j["judge_id"]): j for j in people}, circles=circles,
              roles=[], status=R.form_status(form, moment or now()))
    await load_entries(ctx)
    return ctx


async def all_entries(form_ids: Sequence[str]) -> List[Dict[str, Any]]:
    if not form_ids:
        return []
    rows = await database.fetch_all(select(ENTRIES).where(ENTRIES.c.form_id.in_(list(form_ids))).order_by(ENTRIES.c.id.asc()))
    return [parse_entry(r) for r in rows]


async def entries_by_judge(form_ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    """judge_id -> wiersz (dla JEDNEGO formularza); goście bez judge_id nie wchodzą."""
    return {_s(e["judge_id"]): e for e in await all_entries(form_ids) if _s(e.get("judge_id"))}


def judge_name(ctx_by_id: Mapping[str, Mapping[str, Any]], judge_id: Optional[str]) -> str:
    judge = ctx_by_id.get(_s(judge_id)) or {}
    return _s(judge.get("full_name")) or _s(judge_id)


# ---------------------------------------------------------------------------
# Widoki (FormSummary, FormDetail, Entry)
# ---------------------------------------------------------------------------


def entry_view(
    ctx: Ctx,
    entry: Optional[Mapping[str, Any]],
    *,
    judge_id: Optional[str],
    mode: str,
    include_answers: bool = False,
) -> Dict[str, Any]:
    judge = ctx.by_id.get(_s(judge_id)) or {}
    columns = ctx.columns
    cells = (entry or {}).get("cells_json") or {}
    from app.match_market_access import badge_names

    view: Dict[str, Any] = {
        "judge_id": _s(judge_id) or None,
        "name": _s(judge.get("full_name")) or _s((entry or {}).get("guest_name")) or _s(judge_id),
        "guest_name": (entry or {}).get("guest_name"),
        "photo_url": _s(judge.get("photo_url")) or None,
        "badges": badge_names(judge.get("badges")),
        "cells": R.filter_cells(columns, cells, mode) if ctx.kind == "list" else {},
        "verified": bool((entry or {}).get("verified")),
        "self_source": (entry or {}).get("self_source"),
        "web_review": bool((entry or {}).get("web_review")),
        "web_at": R.iso((entry or {}).get("web_at")),
        "filled": R.entry_filled(ctx.kind, ctx.form.get("schema_json"), entry),
        "updated_at": R.iso((entry or {}).get("updated_at")),
        "submitted_at": R.iso((entry or {}).get("submitted_at")),
    }
    if ctx.kind == "form" and include_answers:
        view["answers"] = dict((entry or {}).get("answers_json") or {})
    return view


def _counts(ctx: Ctx) -> Dict[str, Any]:
    participants = ctx.circles.participants
    filled = sum(
        1 for jid in participants if R.entry_filled(ctx.kind, ctx.form.get("schema_json"), ctx.entries.get(jid))
    )
    out: Dict[str, Any] = {"participants": len(participants), "filled": filled}
    if ctx.kind == "form" and ctx.circles.open:
        out["guests"] = ctx.guests
    column = R.status_column(ctx.columns) if ctx.kind == "list" else None
    if column:
        out["status"] = R.status_counts(
            column, participants, {jid: e.get("cells_json") or {} for jid, e in ctx.entries.items()}
        )
    return out


def summary(ctx: Ctx, *, event: Optional[Mapping[str, Any]] = None, moment: Optional[datetime] = None) -> Dict[str, Any]:
    form = ctx.form
    me = ctx.who.judge_id if ctx.who else ""
    mine = ctx.entries.get(me)
    column = R.status_column(ctx.columns) if ctx.kind == "list" else None
    my_status = ((mine or {}).get("cells_json") or {}).get(column["id"], {}).get("v") if column and mine else None
    return {
        "id": form["id"],
        "kind": ctx.kind,
        "title": form["title"],
        "description": form.get("description"),
        "cover": form.get("cover_json") or None,
        "status": ctx.status,
        "closes_at": R.iso(form.get("closes_at")),
        "published_at": R.iso(form.get("published_at")),
        "created_at": R.iso(form.get("created_at")),
        "created_by": {
            "judge_id": _s(form.get("created_by")),
            "name": _s(form.get("created_by_name")) or judge_name(ctx.by_id, form.get("created_by")),
        },
        "event": (
            {"id": int(event["id"]), "name": event.get("name"), "event_date": R.iso(event.get("event_date")),
             "image_url": R.event_image_url(event.get("data_json"))}
            if event
            else None
        ),
        "web_enabled": bool(form.get("web_enabled")),
        "web_url": R.web_url(form.get("web_code")) if form.get("web_enabled") else None,
        "silent": bool(form.get("silent")),
        "roles": list(ctx.roles),
        "me": {
            "participant": me in ctx.circles.participants,
            "filled": R.entry_filled(ctx.kind, form.get("schema_json"), mine),
            "status": my_status,
            "web_review": bool((mine or {}).get("web_review")),
        },
        "counts": _counts(ctx),
        "rev": int(form.get("rev") or 1),
    }


def can_flags(ctx: Ctx) -> Dict[str, bool]:
    settings = ctx.form.get("settings_json") or {}
    manage = ctx.manager
    observer = "observer" in ctx.roles
    participant = "participant" in ctx.roles
    if ctx.kind == "list":
        view_rows, view_results = R.list_visibility(manage=manage, observer=observer, participant=participant,
                                                    summary=bool(settings.get("roster_visible", True)))
        late = manage or (participant and any(R.self_editable(c) and not c.get("lock_after_deadline", True) for c in ctx.columns))
        respond = participant and ctx.status == "open"
    else:
        level = settings.get("results_visibility") or "managers"
        view_rows = manage or (observer and level in ("observers", "participants"))
        view_results = manage or observer or (participant and level == "participants")
        late = manage
        mine = ctx.entries.get(ctx.who.judge_id if ctx.who else "")
        answered = R.entry_filled("form", ctx.form.get("schema_json"), mine)
        respond = participant and ctx.status == "open" and (not answered or bool(settings.get("allow_edit", True)))
    return {"manage": manage, "respond": respond, "view_rows": view_rows, "view_results": view_results, "edit_after_deadline": late}


def resolved_info(form: Mapping[str, Any], event: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    return INFO.resolve_info(
        form.get("info_json"),
        closes_at=form.get("closes_at"),
        event_start=(event or {}).get("event_date"),
        schema=form.get("schema_json"),
    )


def detail(ctx: Ctx, *, event: Optional[Mapping[str, Any]] = None, viewer_name: Optional[str] = None) -> Dict[str, Any]:
    out = summary(ctx, event=event)
    me = ctx.who.judge_id if ctx.who else ""
    full_name = viewer_name or _s((ctx.by_id.get(me) or {}).get("full_name"))
    participant = me in ctx.circles.participants
    out.update(
        {
            "schema": SC.with_image_urls(ctx.form.get("schema_json") or {}, ctx.form["id"]),
            "settings": ctx.form.get("settings_json") or {},
            "audience": ctx.form.get("audience_json") if ctx.manager else None,
            "my_entry": entry_view(ctx, ctx.entries.get(me), judge_id=me, mode="own", include_answers=True) if participant else None,
            "can": can_flags(ctx),
            "info": resolved_info(ctx.form, event),
            "viewer": INFO.viewer_info(me, full_name),
        }
    )
    if ctx.manager:
        out["web_code"] = ctx.form.get("web_code")
    return out


async def events_by_id(event_ids: Iterable[Any]) -> Dict[int, Dict[str, Any]]:
    ids = sorted({int(x) for x in event_ids if x is not None})
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(province_events.c.id, province_events.c.name, province_events.c.event_date, province_events.c.province,
               province_events.c.deleted_at, province_events.c.data_json)
        .where(province_events.c.id.in_(ids))
    )
    return {int(r["id"]): _row(r) for r in rows if r["deleted_at"] is None}


# ---------------------------------------------------------------------------
# Zapis komórek listy
# ---------------------------------------------------------------------------


@dataclass
class Meta:
    """Ślad zapisu: IP (pierwszy hop X-Forwarded-For), przeglądarka, urządzenie, położenie."""

    ip: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None
    geo: Optional[Dict[str, Any]] = None


def _writable_status(form: Mapping[str, Any], source: str, moment: datetime) -> None:
    status = R.form_status(form, moment)
    if status == "trash":
        raise R.not_found()
    if status == "draft" and R.draft_writable(source):
        return
    if source == "manager":
        return
    if status == "draft":
        raise R.FormError("draft", "Formularz nie jest jeszcze opublikowany.", 409)
    if status == "archived":
        raise R.FormError("closed", "Formularz jest w archiwum - odpowiedzi są zamknięte.", 409)


async def _ensure_entry(form_id: str, judge_id: str, moment: datetime) -> None:
    await database.execute(
        pg_insert(ENTRIES)
        .values(form_id=form_id, judge_id=judge_id, cells_json={}, answers_json={}, verified=False, web_review=False,
                updated_at=moment)
        .on_conflict_do_nothing(constraint="uq_district_form_entries_judge")
    )


async def _locked_entry(form_id: str, judge_id: str) -> Dict[str, Any]:
    row = await database.fetch_one(
        select(ENTRIES).where(and_(ENTRIES.c.form_id == form_id, ENTRIES.c.judge_id == judge_id)).with_for_update()
    )
    return parse_entry(row) if row else {}


def _blank(value: Any) -> bool:
    # Bez `value in (None, False, ...)`: 0 == False w Pythonie, a zero osób towarzyszących to odpowiedź.
    return value is None or value is False or (isinstance(value, (str, list)) and not value)


def _same(a: Any, b: Any) -> bool:
    if _blank(a) or _blank(b):
        return _blank(a) and _blank(b)
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    return a == b


async def _log(form_id: str, entry_id: Optional[int], owner: Optional[str], column_id: Optional[str], old: Any, new: Any,
               *, actor: Optional[str], source: str, meta: Meta, moment: datetime) -> None:
    await database.execute(
        insert(LOG).values(
            form_id=form_id, entry_id=entry_id, owner_judge_id=owner, column_id=column_id, old_json=old, new_json=new,
            actor_judge_id=actor, source=source, ip=(meta.ip or None), user_agent=(meta.user_agent or "")[:300] or None,
            device_id=meta.device_id or None, geo_json=meta.geo, created_at=moment,
        )
    )


async def write_cells(
    form: Dict[str, Any],
    *,
    judge_id: str,
    changes: Mapping[str, Any],
    source: str,
    actor_id: Optional[str],
    meta: Optional[Meta] = None,
    force: bool = False,
    moment: Optional[datetime] = None,
) -> Tuple[Dict[str, Any], Dict[str, Tuple[Any, Any]]]:
    """Zapis komórek jednego wiersza listy. Zwraca (wiersz po zapisie, zmiany kolumna -> (stara, nowa)).

    `source`: app | web_qr | web | manager. Wywołujący sprawdził już, że wiersz należy do
    uczestnika i że pytający ma prawo pisać tym źródłem.
    """
    meta = meta or Meta()
    stamp = moment or now()
    if form.get("kind") != "list":
        raise R.FormError("wrong_kind", "To jest formularz, nie lista - wyślij odpowiedzi.", 400)
    _writable_status(form, source, stamp)
    if not isinstance(changes, Mapping):
        raise R.FormError("bad_value", "Brak komórek do zapisu.", 400)
    columns = R.columns_of(form.get("schema_json"))
    by_id = {c["id"]: c for c in columns}
    cleaned: Dict[str, Any] = {}
    for cid, raw in changes.items():
        column = by_id.get(_s(cid))
        if column is None:
            raise R.FormError("unknown_column", "Takiej kolumny nie ma - odśwież listę.", 400, column_id=_s(cid))
        cleaned[column["id"]] = R.clean_value(column, raw)
    closed = R.is_closed(form, stamp)
    changed: Dict[str, Tuple[Any, Any]] = {}
    async with database.transaction():
        await _ensure_entry(form["id"], judge_id, stamp)
        entry = await _locked_entry(form["id"], judge_id)
        if source == "web":
            refusal = R.web_row_refusal(entry, device_id=meta.device_id or "", force=force)
            if refusal:
                raise refusal
        cells = dict(entry.get("cells_json") or {})
        for cid, value in cleaned.items():
            current = (cells.get(cid) or {}).get("v") if isinstance(cells.get(cid), Mapping) else None
            if _same(current, value):
                continue
            refusal = R.cell_refusal(by_id[cid], source=source, current=current, new=value, closed=closed)
            if refusal:
                raise refusal
            changed[cid] = (current, value)
        for cid, (_old, value) in changed.items():
            cells[cid] = R.make_cell(value, source=source, by=actor_id, now=stamp)
        values: Dict[str, Any] = {"cells_json": cells, "updated_at": stamp}
        if changed and entry.get("submitted_at") is None:
            values["submitted_at"] = stamp
        if source in ("app", "web_qr"):
            values.update(verified=True, web_review=False, self_source=source)
        elif source == "web" and changed:
            values.update(web_device=meta.device_id, web_at=stamp, web_review=True, self_source="web")
        await database.execute(update(ENTRIES).where(ENTRIES.c.id == entry["id"]).values(**values))
        for cid, (old, value) in changed.items():
            await _log(form["id"], entry["id"], judge_id, cid, {"v": old}, {"v": value}, actor=actor_id, source=source,
                       meta=meta, moment=stamp)
    fresh = parse_entry(await database.fetch_one(select(ENTRIES).where(ENTRIES.c.id == entry["id"])))
    status = R.status_column(columns)
    if status and status["id"] in changed and form.get("event_id"):
        await mirror_rsvp(int(form["event_id"]), judge_id, changed[status["id"]][1], stamp)
    if source == "web" and changed:
        await notify_web_review(form, judge_id, R.describe_change(columns, {c: v for c, (_o, v) in changed.items()}), stamp)
    return fresh, changed


async def clear_entry(
    form: Dict[str, Any],
    *,
    judge_id: str,
    column_id: Optional[str],
    actor_id: str,
    meta: Optional[Meta] = None,
) -> Optional[Dict[str, Any]]:
    """Komisja usuwa odpowiedź sędziego: jedną komórkę listy albo całą odpowiedź.

    Komórka idzie zwykłym zapisem komisji (historia, odbicie RSVP). Cała odpowiedź:
    wiersz wraca do stanu sprzed pierwszego zapisu, jeden wpis w historii, pliki odpowiedzi
    znikają, spięte wydarzenie traci RSVP tej osoby. Bez powiadomienia sędziego.
    """
    meta = meta or Meta()
    stamp = now()
    if R.form_status(form, stamp) == "trash":
        raise R.not_found()
    if column_id:
        entry, _changed = await write_cells(form, judge_id=judge_id, changes={column_id: None}, source="manager",
                                            actor_id=actor_id, meta=meta, moment=stamp)
        return entry
    row = await database.fetch_one(select(ENTRIES).where(and_(ENTRIES.c.form_id == form["id"], ENTRIES.c.judge_id == judge_id)))
    if not row:
        return None
    async with database.transaction():
        entry = await _locked_entry(form["id"], judge_id)
        old, new = R.clear_log_payload(entry.get("cells_json"), entry.get("answers_json"))
        await database.execute(update(ENTRIES).where(ENTRIES.c.id == entry["id"]).values(**R.cleared_entry_values(stamp)))
        if old is not None:
            await _log(form["id"], entry["id"], judge_id, None, old, new, actor=actor_id, source="manager", meta=meta,
                       moment=stamp)
        files = await database.fetch_all(select(UPLOADS.c.token).where(and_(
            UPLOADS.c.form_id == form["id"], UPLOADS.c.judge_id == judge_id, UPLOADS.c.purpose == "answer")))
        await database.execute(delete(UPLOADS).where(and_(
            UPLOADS.c.form_id == form["id"], UPLOADS.c.judge_id == judge_id, UPLOADS.c.purpose == "answer")))
    for item in files:
        try:
            upload_path(form["id"], item["token"]).unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            logger.warning("formularze: nie usunięto pliku odpowiedzi form=%s", form["id"], exc_info=True)
    if form.get("event_id") and form.get("kind") == "list" and R.status_column(R.columns_of(form.get("schema_json"))):
        await mirror_rsvp(int(form["event_id"]), judge_id, None, stamp)
    return parse_entry(await database.fetch_one(select(ENTRIES).where(ENTRIES.c.id == entry["id"])))


async def confirm_me(form: Dict[str, Any], judge_id: str, *, source: str, meta: Optional[Meta] = None) -> Dict[str, Any]:
    """„To ja": weryfikacja wiersza bez zmiany wartości."""
    stamp = now()
    async with database.transaction():
        await _ensure_entry(form["id"], judge_id, stamp)
        entry = await _locked_entry(form["id"], judge_id)
        await database.execute(
            update(ENTRIES).where(ENTRIES.c.id == entry["id"]).values(
                verified=True, web_review=False, self_source=source, updated_at=stamp)
        )
        if entry.get("web_review"):
            await _log(form["id"], entry["id"], judge_id, None, {"web_review": True}, {"verified": True},
                       actor=judge_id, source=source, meta=meta or Meta(), moment=stamp)
    return parse_entry(await database.fetch_one(select(ENTRIES).where(ENTRIES.c.id == entry["id"])))


# ---------------------------------------------------------------------------
# Odpowiedź formularza
# ---------------------------------------------------------------------------


async def my_files(form_id: str, judge_id: Optional[str]) -> SC.Files:
    if not judge_id:
        return SC.Files()
    rows = await database.fetch_all(
        select(UPLOADS.c.token, UPLOADS.c.mime).where(
            and_(UPLOADS.c.form_id == form_id, UPLOADS.c.judge_id == judge_id, UPLOADS.c.purpose == "answer")
        )
    )
    return SC.Files(mine={r["token"]: _s(r["mime"]).startswith("image/") for r in rows})


async def write_answers(
    form: Dict[str, Any],
    *,
    judge_id: Optional[str],
    guest_name: Optional[str],
    answers: Mapping[str, Any],
    client_id: Optional[str],
    fill: Any,
    source: str,
    actor_id: Optional[str],
    meta: Optional[Meta] = None,
    force: bool = False,
    moment: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Wysłanie albo poprawka odpowiedzi (`kind = form`). Idempotentne po `client_id`."""
    meta = meta or Meta()
    stamp = moment or now()
    if form.get("kind") != "form":
        raise R.FormError("wrong_kind", "To jest lista - zapisz komórki wiersza.", 400)
    _writable_status(form, source, stamp)
    if R.is_closed(form, stamp):
        raise R.FormError("closed", "Termin minął - formularz nie przyjmuje już odpowiedzi.", 409)
    settings = form.get("settings_json") or {}
    sections = SC.sections_of(form.get("schema_json"))
    files = await my_files(form["id"], judge_id) if source != "web" else SC.Files()
    clean, errors = SC.check_answers(sections, answers if isinstance(answers, Mapping) else {}, files=files)
    if errors:
        first = next(iter(errors.values()))
        raise R.FormError("invalid_answers", f"Popraw odpowiedzi zaznaczone w formularzu. {first}", 400, errors=errors)
    client = _s(client_id)[:64] or None
    anonymous = bool(settings.get("anonymous"))
    async with database.transaction():
        target: Dict[str, Any] = {}
        if client:
            row = await database.fetch_one(
                select(ENTRIES).where(and_(ENTRIES.c.form_id == form["id"], ENTRIES.c.client_id == client)).with_for_update()
            )
            if row:
                target = parse_entry(row)
                if _s(target.get("judge_id")) != _s(judge_id):
                    raise R.FormError("client_conflict", "Ta odpowiedź jest już zapisana - wyślij ją jeszcze raz.", 409)
        if not target and judge_id:
            await _ensure_entry(form["id"], judge_id, stamp)
            target = await _locked_entry(form["id"], judge_id)
        if judge_id and source == "web":
            refusal = R.web_row_refusal(target, device_id=meta.device_id or "", force=force)
            if refusal:
                raise refusal
        answered = bool(target.get("submitted_at")) and bool(target.get("answers_json"))
        same_retry = bool(client) and _s(target.get("client_id")) == client
        if answered and not same_retry and not settings.get("allow_edit", True):
            raise R.FormError("already_answered", "Twoja odpowiedź jest już zapisana - ten formularz nie pozwala jej poprawiać.", 409)
        values: Dict[str, Any] = {"answers_json": clean, "updated_at": stamp}
        if not answered:
            values["submitted_at"] = stamp
            values["fill_seconds"] = R.fill_seconds(fill)
        if client and not target.get("client_id"):
            values["client_id"] = client
        if source in ("app", "web_qr"):
            values.update(verified=True, web_review=False, self_source=source)
        elif source == "web" and judge_id:
            values.update(web_device=meta.device_id, web_at=stamp, web_review=True, self_source="web")
        elif source == "web":
            values.update(web_device=meta.device_id, web_at=stamp, self_source="web")
        if target:
            entry_id = target["id"]
            await database.execute(update(ENTRIES).where(ENTRIES.c.id == entry_id).values(**values))
        else:
            row = await database.fetch_one(
                insert(ENTRIES)
                .values(form_id=form["id"], judge_id=None, guest_name=guest_name, cells_json={}, verified=False,
                        web_review=False, **values)
                .returning(ENTRIES.c.id)
            )
            entry_id = int(row["id"])
        old = None if anonymous else (target.get("answers_json") or None)
        new = None if anonymous else clean
        await _log(form["id"], entry_id, judge_id, None, old, new, actor=actor_id, source=source, meta=meta, moment=stamp)
    fresh = parse_entry(await database.fetch_one(select(ENTRIES).where(ENTRIES.c.id == entry_id)))
    if source == "web" and judge_id:
        await notify_web_review(form, judge_id, "wysłano odpowiedź", stamp)
    return fresh


# ---------------------------------------------------------------------------
# Powiadomienia
# ---------------------------------------------------------------------------


def push_data(form: Mapping[str, Any], kind: str) -> Dict[str, Any]:
    return {
        "type": "district_form",
        "kind": "district_form",
        "formId": _s(form.get("id")),
        "action": R.notification_action(kind),
        "notice": kind,
        "province": _s(form.get("province")),
    }


async def notify(
    form: Mapping[str, Any],
    judge_ids: Iterable[str],
    *,
    kind: str,
    slot: str,
    title: str,
    body: str,
    moment: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Najpierw wpis w dzienniku (unikalny klucz), potem push do tych, których wpis jest nowy.

    Szkic i tryb cichy (`R.pushes_muted`) nie wysyłają NIC i nie piszą do dziennika.
    """
    stamp = moment or now()
    if R.pushes_muted(form):
        return {"sent_to": 0, "devices": 0, "judge_ids": [], "muted": True}
    fresh: List[str] = []
    for jid in sorted({_s(j) for j in judge_ids if _s(j)}):
        row = await database.fetch_one(
            pg_insert(NOTES)
            .values(form_id=form["id"], judge_id=jid, kind=kind, slot=slot, sent_at=stamp, title=title, body=body)
            .on_conflict_do_nothing(constraint="uq_district_form_notifications")
            .returning(NOTES.c.id)
        )
        if row:
            fresh.append(jid)
    report: Dict[str, Any] = {"acceptedDevices": 0}
    if fresh:
        try:
            report = await send_push_to_judges_report(
                fresh, title, body, push_data(form, kind), app_variant=PUSH_VARIANT, preference_key=PUSH_PREFERENCE
            )
        except Exception:  # noqa: BLE001 - push nie może wywrócić zapisu
            logger.warning("formularze: push nieudany form=%s kind=%s", form.get("id"), kind, exc_info=True)
    return {"sent_to": len(fresh), "devices": int(report.get("acceptedDevices") or 0), "judge_ids": fresh}


async def notify_web_review(form: Mapping[str, Any], judge_id: str, change: str, moment: datetime) -> None:
    """„To Ty?" do właściciela wiersza - najwyżej raz na 30 minut na wiersz."""
    try:
        recent = await database.fetch_one(
            select(NOTES.c.id)
            .where(and_(NOTES.c.form_id == form["id"], NOTES.c.judge_id == judge_id, NOTES.c.kind == "web_review"))
            .where(NOTES.c.sent_at > moment - R.WEB_REVIEW_DEDUP)
        )
        if recent:
            return
        await notify(
            form,
            [judge_id],
            kind="web_review",
            slot=moment.strftime("%Y%m%dT%H%M%S"),
            title="Zaznaczono Cię przez stronę",
            body=f"{form['title']}: {change}. To Ty? Potwierdź albo popraw w aplikacji.",
            moment=moment,
        )
    except Exception:  # noqa: BLE001
        logger.warning("formularze: „To Ty?” nieudane form=%s", form.get("id"), exc_info=True)


async def notify_published(form: Mapping[str, Any], participants: Sequence[str], actor_id: str, *, slot: str = "1") -> None:
    deadline = R.deadline_label(form.get("closes_at"))
    columns = R.columns_of(form.get("schema_json"))
    if form.get("kind") == "list" and R.status_column(columns):
        body = f"Będziesz? Odpowiedz w BAZIE{f' do {deadline}' if deadline else ''}."
    else:
        body = f"Odpowiedz w BAZIE{f' do {deadline}' if deadline else ''} - zajmie chwilę."
    await notify(
        form,
        [j for j in participants if j != actor_id],
        kind="published",
        slot=slot,
        title=f"📋 {form['title']}",
        body=body,
    )


async def clear_test_answers(form: Mapping[str, Any]) -> int:
    """Tryb cichy -> „cofnij do szkicu”: znikają wiersze, historia, dziennik powiadomień
    i pliki odpowiedzi. Spięte wydarzenie traci tylko odbicie RSVP z listy (kliknięcia sprzed publikacji zostają)."""
    form_id = form["id"]
    async with database.transaction():
        gone = await database.fetch_all(select(ENTRIES.c.id).where(ENTRIES.c.form_id == form_id))
        files = await database.fetch_all(
            select(UPLOADS.c.token).where(and_(UPLOADS.c.form_id == form_id, UPLOADS.c.purpose == "answer")))
        await database.execute(delete(ENTRIES).where(ENTRIES.c.form_id == form_id))
        await database.execute(delete(LOG).where(LOG.c.form_id == form_id))
        await database.execute(delete(NOTES).where(NOTES.c.form_id == form_id))
        await database.execute(delete(UPLOADS).where(and_(UPLOADS.c.form_id == form_id, UPLOADS.c.purpose == "answer")))
        if form.get("event_id") and form.get("published_at") is not None:
            # Kasujemy tylko kopie z listy (mirror_rsvp powstaje po publikacji). RSVP kliknięte
            # na wydarzeniu przed publikacją mają updated_at starszy - zostają.
            await database.execute(
                delete(province_event_responses).where(and_(
                    province_event_responses.c.event_id == int(form["event_id"]),
                    province_event_responses.c.updated_at >= form["published_at"])))
    for row in files:
        try:
            upload_path(form_id, row["token"]).unlink(missing_ok=True)
        except Exception:  # noqa: BLE001 - plik bez wpisu nikomu nie szkodzi
            logger.warning("formularze: nie usunięto pliku testowego form=%s", form_id, exc_info=True)
    return len(gone)


def reminder_text(form: Mapping[str, Any]) -> Tuple[str, str]:
    deadline = R.deadline_label(form.get("closes_at"))
    columns = R.columns_of(form.get("schema_json"))
    if form.get("kind") == "list" and R.status_column(columns):
        return f"⏳ {form['title']}", f"Będziesz? Daj znać do {deadline} - jednym dotknięciem w BAZIE."
    return f"⏳ {form['title']}", f"Czekamy na Twoją odpowiedź do {deadline}."


# ---------------------------------------------------------------------------
# Spięcie z wydarzeniem (§8)
# ---------------------------------------------------------------------------


async def mirror_rsvp(event_id: int, judge_id: str, status_value: Any, moment: datetime) -> None:
    """Kopia statusu do tabeli odpowiedzi wydarzenia - czytniki spoza modułu widzą to samo."""
    rsvp = R.rsvp_from_status(status_value)
    try:
        if rsvp is None:
            await database.execute(
                delete(province_event_responses).where(
                    and_(province_event_responses.c.event_id == event_id, province_event_responses.c.judge_id == judge_id)
                )
            )
            return
        await database.execute(
            pg_insert(province_event_responses)
            .values(event_id=event_id, judge_id=judge_id, status=rsvp, reason=None, updated_at=moment)
            .on_conflict_do_update(index_elements=["event_id", "judge_id"], set_={"status": rsvp, "updated_at": moment})
        )
    except Exception:  # noqa: BLE001
        logger.warning("formularze: kopia RSVP nieudana event=%s", event_id, exc_info=True)


async def event_rsvp_info(ctx: Ctx) -> Optional[Dict[str, int]]:
    """Dla zarządzających: ile RSVP leży na spiętym wydarzeniu i ile już przeszło do listy."""
    form = ctx.form
    column = R.status_column(R.columns_of(form.get("schema_json"))) if form.get("kind") == "list" else None
    if not form.get("event_id") or not column:
        return None
    rows = await database.fetch_all(
        select(province_event_responses.c.judge_id, province_event_responses.c.status)
        .where(province_event_responses.c.event_id == int(form["event_id"]))
    )
    return R.event_rsvp_summary({r["judge_id"]: r["status"] for r in rows}, ctx.circles.participants, ctx.entries, column["id"])


async def seed_from_event_rsvps(form: Mapping[str, Any], *, before: Optional[datetime] = None) -> int:
    """Przenosi RSVP oddane na wydarzeniu (yes/no) do kolumny statusu spiętej listy.

    Migracja danych, nie zapis uczestnika: źródło `event`, bez powiadomień, bez blokady terminu,
    bez kopii zwrotnej (RSVP już leży w tabeli wydarzenia). Tylko uczestnicy listy i tylko komórki
    bez wartości - odpowiedzi z formularza nigdy nie są nadpisywane. Idempotentne.
    `before`: bierzemy tylko RSVP z `updated_at` sprzed tej chwili (publikacja listy). Kopie
    z `mirror_rsvp` powstają dopiero po publikacji, więc nie wrócą po „cofnij do szkicu" ani na starcie.
    Zwraca liczbę przeniesionych odpowiedzi.
    """
    event_id = form.get("event_id")
    if not event_id or form.get("kind") != "list" or form.get("published_at") is None or form.get("deleted_at") is not None:
        return 0
    column = R.status_column(R.columns_of(form.get("schema_json")))
    if not column:
        return 0
    query = select(province_event_responses).where(
        and_(province_event_responses.c.event_id == int(event_id), province_event_responses.c.status.in_(("yes", "no")))
    )
    if before is not None:
        query = query.where(province_event_responses.c.updated_at < before)
    rsvps = {r["judge_id"]: r["status"] for r in await database.fetch_all(query)}
    if not rsvps:
        return 0
    people = await judges(form["province"])
    participants = circles_of(form, people).participants
    stamp = now()
    moved = 0
    for judge_id, rsvp in rsvps.items():
        if judge_id not in participants:
            continue
        try:
            value = R.status_from_rsvp(column, rsvp)
        except R.FormError:
            continue
        async with database.transaction():
            await _ensure_entry(form["id"], judge_id, stamp)
            entry = await _locked_entry(form["id"], judge_id)
            cells = dict(entry.get("cells_json") or {})
            current = cells.get(column["id"])
            if isinstance(current, Mapping) and not _blank(current.get("v")):
                continue
            cells[column["id"]] = R.make_cell(value, source="event", by=None, now=stamp)
            values: Dict[str, Any] = {"cells_json": cells, "updated_at": stamp}
            if entry.get("submitted_at") is None:
                values["submitted_at"] = stamp
            await database.execute(update(ENTRIES).where(ENTRIES.c.id == entry["id"]).values(**values))
            await _log(form["id"], entry["id"], judge_id, column["id"], {"v": None}, {"v": value}, actor=None,
                       source="event", meta=Meta(), moment=stamp)
            moved += 1
    return moved


async def seed_all_linked_forms() -> int:
    """Jednorazowa naprawa przy starcie: opublikowane spięte listy dostają RSVP sprzed publikacji."""
    rows = await database.fetch_all(
        select(FORMS).where(and_(FORMS.c.event_id.is_not(None), FORMS.c.kind == "list", FORMS.c.deleted_at.is_(None),
                                 FORMS.c.published_at.is_not(None)))
    )
    total = 0
    for raw in rows:
        form = parse_form(raw)
        try:
            total += await seed_from_event_rsvps(form, before=R.aware(form.get("published_at")))
        except Exception:  # noqa: BLE001
            logger.warning("formularze: seed RSVP nieudany form=%s", form.get("id"), exc_info=True)
    return total


async def mirror_participants(form: Mapping[str, Any]) -> None:
    """Zaproszeni na wydarzenie = uczestnicy listy ze statusem (kopiujemy do `data_json`)."""
    event_id = form.get("event_id")
    if not event_id or form.get("kind") != "list" or not R.status_column(R.columns_of(form.get("schema_json"))):
        return
    row = await database.fetch_one(select(province_events).where(province_events.c.id == int(event_id)))
    if not row:
        return
    data = R.loads(row["data_json"], {})
    data.update(R.event_target((form.get("audience_json") or {}).get("participants") or {}))
    await database.execute(
        update(province_events).where(province_events.c.id == int(event_id)).values(data_json=data, updated_at=now())
    )


async def check_event_link(event_id: Optional[int], *, province: str, form_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if event_id is None:
        return None
    row = await database.fetch_one(select(province_events).where(province_events.c.id == int(event_id)))
    if not row or row["deleted_at"] is not None:
        raise R.FormError("event_not_found", "Nie ma takiego wydarzenia.", 404)
    if canonical(row["province"]) != canonical(province):
        raise R.FormError("event_not_found", "To wydarzenie jest w innym okręgu.", 404)
    query = select(FORMS.c.id).where(and_(FORMS.c.event_id == int(event_id), FORMS.c.deleted_at.is_(None)))
    if form_id:
        query = query.where(FORMS.c.id != form_id)
    if await database.fetch_one(query):
        raise R.FormError("event_linked", "To wydarzenie ma już swój formularz.", 409)
    return _row(row)


async def event_overlay(event_ids: Sequence[int]) -> Dict[int, Dict[str, Any]]:
    """Formularze spięte z wydarzeniami: event_id -> {form, column, entries}."""
    ids = sorted({int(x) for x in event_ids})
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(FORMS).where(and_(FORMS.c.event_id.in_(ids), FORMS.c.deleted_at.is_(None), FORMS.c.published_at.is_not(None)))
    )
    forms = [parse_form(r) for r in rows]
    if not forms:
        return {}
    by_form: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for entry in await all_entries([f["id"] for f in forms]):
        if _s(entry.get("judge_id")):
            by_form.setdefault(entry["form_id"], {})[_s(entry["judge_id"])] = entry
    out: Dict[int, Dict[str, Any]] = {}
    for form in forms:
        column = R.status_column(R.columns_of(form.get("schema_json"))) if form.get("kind") == "list" else None
        out[int(form["event_id"])] = {"form": form, "column": column, "entries": by_form.get(form["id"], {})}
    return out


def overlay_responses(item: Mapping[str, Any], original: Mapping[str, Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """RSVP wydarzenia: kolumna statusu formularza wygrywa tylko tam, gdzie ma wartość.

    Uczestnik bez wartości w komórce statusu zachowuje RSVP z tabeli wydarzenia - spięcie nigdy
    nie chowa odpowiedzi oddanych na wydarzeniu (np. przed publikacją listy albo w starej aplikacji).
    Wartość spoza yes/no (np. „może”) to odpowiedź formularza: brak RSVP, bez cofania do tabeli.
    """
    column = item.get("column")
    if not column:
        return dict(original)
    out: Dict[str, Dict[str, Any]] = {}
    claimed: Set[str] = set()
    for jid, entry in (item.get("entries") or {}).items():
        cell = (entry.get("cells_json") or {}).get(column["id"])
        value = cell.get("v") if isinstance(cell, Mapping) else None
        if _blank(value):
            continue
        claimed.add(jid)
        rsvp = R.rsvp_from_status(value)
        if rsvp is None:
            continue
        previous = original.get(jid) or {}
        out[jid] = {
            "judge_id": jid,
            "status": rsvp,
            "reason": previous.get("reason") if previous.get("status") == rsvp else None,
            "updated_at": R.parse_iso(cell.get("at")) if isinstance(cell, Mapping) and cell.get("at") else entry.get("updated_at"),
        }
    for jid, row in original.items():
        if jid not in claimed and jid not in out:
            out[jid] = dict(row)
    return out


def event_form_summary(item: Mapping[str, Any], *, invited: Sequence[str], me: str, moment: Optional[datetime] = None) -> Dict[str, Any]:
    form = item["form"]
    column = item.get("column")
    entries = item.get("entries") or {}
    kind = form.get("kind") or "list"
    mine = entries.get(me)
    my_status = None
    if column and mine:
        cell = (mine.get("cells_json") or {}).get(column["id"])
        my_status = cell.get("v") if isinstance(cell, Mapping) else None
    counts = R.status_counts(column, invited, {jid: e.get("cells_json") or {} for jid, e in entries.items()}) if column else {}
    return {
        "id": form["id"],
        "kind": kind,
        "title": form["title"],
        "closes_at": R.iso(form.get("closes_at")),
        "web_enabled": bool(form.get("web_enabled")),
        "status": R.form_status(form, moment or now()),
        "my_status": my_status,
        "filled": R.entry_filled(kind, form.get("schema_json"), mine),
        "counts": counts,
        "status_column": column,
    }


async def rsvp_through_form(event_id: int, judge_id: str, rsvp: str) -> bool:
    """POST /province-events/:id/rsvp przy spiętej liście ze statusem - zapis do formularza.

    Zwraca False, gdy wydarzenie nie ma takiej listy (zwykła ścieżka RSVP).
    """
    rows = await database.fetch_all(
        select(FORMS).where(and_(FORMS.c.event_id == int(event_id), FORMS.c.deleted_at.is_(None), FORMS.c.published_at.is_not(None)))
    )
    for raw in rows:
        form = parse_form(raw)
        column = R.status_column(R.columns_of(form.get("schema_json"))) if form.get("kind") == "list" else None
        if not column:
            continue
        people = await judges(form["province"])
        if judge_id not in circles_of(form, people).participants:
            raise R.FormError("not_participant", "To wydarzenie nie jest skierowane do Ciebie.", 403)
        value = R.status_from_rsvp(column, rsvp)
        await write_cells(form, judge_id=judge_id, changes={column["id"]: value}, source="app", actor_id=judge_id)
        return True
    return False


async def linked_event_ids(event_ids: Sequence[int]) -> Set[int]:
    ids = sorted({int(x) for x in event_ids})
    if not ids:
        return set()
    rows = await database.fetch_all(
        select(FORMS.c.event_id, FORMS.c.kind, FORMS.c.schema_json).where(
            and_(FORMS.c.event_id.in_(ids), FORMS.c.deleted_at.is_(None), FORMS.c.published_at.is_not(None))
        )
    )
    return {
        int(r["event_id"])
        for r in rows
        if r["kind"] == "list" and R.status_column(R.columns_of(R.loads(r["schema_json"], {})))
    }


# ---------------------------------------------------------------------------
# Pliki odpowiedzi i pytań
# ---------------------------------------------------------------------------


def uploads_root() -> Path:
    """Poza katalogiem `static` (ten jest publiczny), na wolumenie Railway, jeśli jest."""
    volume = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
    base = Path(volume) / "private" if volume else Path(__file__).resolve().parents[1] / "private_uploads"
    return base / "district-forms"


def upload_path(form_id: str, token: str) -> Path:
    return uploads_root() / form_id / token


# ---------------------------------------------------------------------------
# Przejście w tle
# ---------------------------------------------------------------------------


async def purge_trash(moment: datetime) -> int:
    rows = await database.fetch_all(
        select(FORMS.c.id).where(and_(FORMS.c.deleted_at.is_not(None), FORMS.c.deleted_at < moment - timedelta(days=R.TRASH_DAYS)))
    )
    ids = [r["id"] for r in rows]
    for form_id in ids:
        for table in (ENTRIES, LOG, NOTES, PAIRS, UPLOADS):
            await database.execute(delete(table).where(table.c.form_id == form_id))
        await database.execute(delete(FORMS).where(FORMS.c.id == form_id))
        shutil.rmtree(uploads_root() / form_id, ignore_errors=True)
    return len(ids)


async def sweep_district_forms(moment: Optional[datetime] = None) -> int:
    """Przypomnienia wg presetów (cisza nocna w regułach), kosz po 30 dniach, stare kody QR."""
    stamp = moment or now()
    rows = await database.fetch_all(
        select(FORMS)
        .where(FORMS.c.published_at.is_not(None))
        .where(FORMS.c.closed_at.is_(None))
        .where(FORMS.c.archived_at.is_(None))
        .where(FORMS.c.deleted_at.is_(None))
        .where(FORMS.c.silent.is_not(True))
        .where(FORMS.c.closes_at > stamp)
        .where(FORMS.c.closes_at <= stamp + timedelta(days=8))
        .limit(500)
    )
    people_cache: Dict[str, List[Dict[str, Any]]] = {}
    total = 0
    for raw in rows:
        form = parse_form(raw)
        preset = (form.get("settings_json") or {}).get("reminders") or R.DEFAULT_REMINDERS
        slot = R.due_slot(preset, closes_at=form.get("closes_at"), published_at=form.get("published_at"), now=stamp)
        if not slot:
            continue
        if form["province"] not in people_cache:
            people_cache[form["province"]] = await judges(form["province"])
        circles = circles_of(form, people_cache[form["province"]])
        entries = await entries_by_judge([form["id"]])
        silent = [jid for jid in circles.participants if not R.entry_filled(form["kind"], form.get("schema_json"), entries.get(jid))]
        if not silent:
            continue
        title, body = reminder_text(form)
        result = await notify(form, silent, kind="reminder", slot=slot[0], title=title, body=body, moment=stamp)
        total += result["sent_to"]
    try:
        await purge_trash(stamp)
        await database.execute(delete(PAIRS).where(PAIRS.c.expires_at < stamp - timedelta(days=1)))
    except Exception:  # noqa: BLE001
        logger.warning("formularze: sprzątanie nieudane", exc_info=True)
    try:
        from app.district_form_export import sweep_files

        sweep_files()
    except Exception:  # noqa: BLE001
        logger.warning("formularze: sprzątanie eksportów nieudane", exc_info=True)
    return total
