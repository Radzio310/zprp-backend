"""
Formularze okręgowe - trasy aplikacji i webu po logowaniu QR (prefiks `/district-forms`).

Kontrakt: `docs/formularze-okregowe.md` §10. Reguły: `app/district_forms_rules.py`,
schemat: `app/district_form_schema.py`, baza: `app/district_forms_service.py`,
anonimowy web: `app/district_forms_public.py`.

Tożsamość i okręg pytającego biorą się z tokenu i z `province_judges` (`market_actor`).
Token `scope:"form-web"` (logowanie QR na stronie) przechodzi tylko pod `/district-forms`
(`deps._SCOPE_PREFIXES`) i tylko dla formularza, dla którego go wydano. Błędy w kopercie
`{"error": kod, "message": "po polsku"}`.
"""
from __future__ import annotations

import asyncio
import mimetypes
import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, File, Header, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.routing import APIRoute
from sqlalchemy import and_, insert, select, update

from app import district_form_export as X
from app import district_form_info as INFO
from app import district_form_schema as SC
from app import district_form_templates as T
from app import district_forms_rules as R
from app import district_forms_service as S
from app import province_event_rules as PR
from app.db import database, province_events, push_tokens
from app.deps import FORM_WEB_SCOPE, get_jwt_payload
from app.match_market import Actor, market_actor
from app.settlement_province import canonical, display, spellings


class FormRoute(APIRoute):
    """`FormError` z trasy albo zależności -> koperta `{"error": kod, "message": ...}`."""

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except R.FormError as error:
                headers = {}
                if error.status == 429 and error.extra.get("retry_after"):
                    headers["Retry-After"] = str(error.extra["retry_after"])
                return JSONResponse(error.body(), status_code=error.status, headers=headers or None)

        return handler


router = APIRouter(prefix="/district-forms", tags=["District forms"], route_class=FormRoute)

#: Telefon zatwierdził logowanie przeglądarki - budzi długie odpytywanie w tym samym procesie.
pair_events: Dict[str, asyncio.Event] = {}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


# ---------------------------------------------------------------------------
# Kto pyta
# ---------------------------------------------------------------------------


@dataclass
class Who:
    actor: Actor
    viewer: PR.Viewer
    scope: Optional[str]
    token_form: Optional[str]

    @property
    def judge_id(self) -> str:
        return self.viewer.judge_id

    @property
    def source(self) -> str:
        return "web_qr" if self.scope == FORM_WEB_SCOPE else "app"


async def who_dep(request: Request, payload: Dict[str, Any] = Depends(get_jwt_payload)) -> Who:
    actor = await market_actor(payload)
    viewer = PR.viewer(judge_id=actor.judge_id, province=actor.province, is_admin=actor.is_admin, badges=actor.badges)
    scope = payload.get("scope")
    token_form = None
    if scope == FORM_WEB_SCOPE:
        token_form = _s(payload.get("form_id"))
        if not token_form or _s(request.path_params.get("form_id")) != token_form:
            raise R.FormError("form_web_scope", "To logowanie na stronie dotyczy jednego formularza.", 403)
    return Who(actor=actor, viewer=viewer, scope=scope, token_form=token_form)


def _app_only(who: Who) -> None:
    if who.scope is not None:
        raise R.FormError("app_only", "To robi aplikacja BAZA na telefonie, nie strona.", 403)


def _province_for(who: Who, requested: Any) -> str:
    own = canonical(who.actor.province)
    wanted = canonical(requested) if _s(requested) else own
    if not wanted:
        raise R.FormError("no_province", "Nie ma Cię na liście sędziów okręgu - zgłoś to administratorowi okręgu.", 403)
    if wanted != own and not who.viewer.is_admin:
        raise R.FormError("forbidden", "Formularze innego okręgu widzi tylko administrator.", 403)
    return wanted


def _manager(ctx: S.Ctx) -> None:
    if not ctx.manager:
        raise R.FormError("forbidden", "Tym formularzem zarządza komisja i osoby wskazane przez twórcę.", 403)


def _participant(ctx: S.Ctx, judge_id: str) -> None:
    if judge_id not in ctx.circles.participants:
        raise R.FormError("not_participant", "Nie ma Cię na liście tego formularza.", 403)


def _meta(request: Request, device_id: Any = None, geo: Any = None) -> S.Meta:
    return S.Meta(
        ip=R.ip_from(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else ""),
        user_agent=(request.headers.get("user-agent") or "")[:300] or None,
        device_id=_s(device_id)[:200] or None,
        geo=R.clean_geo(geo),
    )


def _future(value: Any, moment: datetime) -> Optional[datetime]:
    when = R.parse_iso(value)
    if when is not None and when <= moment:
        raise R.FormError("bad_deadline", "Termin musi być w przyszłości.", 400)
    return when


async def _detail(form_id: str, who: Who) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer)
    events = await S.events_by_id([ctx.form.get("event_id")])
    out = S.detail(ctx, event=events.get(int(ctx.form["event_id"])) if ctx.form.get("event_id") else None,
                   viewer_name=who.actor.full_name or None)
    if ctx.manager:
        out["event_rsvp"] = await S.event_rsvp_info(ctx)
    return out


def _sorted_people(ctx: S.Ctx, ids: List[str]) -> List[str]:
    return sorted(ids, key=lambda j: (S.judge_name(ctx.by_id, j).casefold(), j))


# ---------------------------------------------------------------------------
# Listy
# ---------------------------------------------------------------------------


async def _contexts(who: Who, province: str, *, include_trash: bool) -> List[S.Ctx]:
    query = select(S.FORMS).where(S.FORMS.c.province == province)
    if not include_trash:
        query = query.where(S.FORMS.c.deleted_at.is_(None))
    rows = await database.fetch_all(query.order_by(S.FORMS.c.created_at.desc()).limit(500))
    forms = [S.parse_form(r) for r in rows]
    if not forms:
        return []
    people = await S.judges(province)
    by_id = {_s(j["judge_id"]): j for j in people}
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for entry in await S.all_entries([f["id"] for f in forms]):
        grouped.setdefault(entry["form_id"], []).append(entry)
    moment = S.now()
    out: List[S.Ctx] = []
    for form in forms:
        circles = S.circles_of(form, people)
        roles = R.roles_for(who.viewer, province=form["province"], author=_s(form.get("created_by")), circles=circles)
        status = R.form_status(form, moment)
        try:
            R.check_access(roles, status)
        except R.FormError:
            continue
        if status == "trash" and not R.restorable(form.get("deleted_at"), moment):
            continue
        rows_for = grouped.get(form["id"], [])
        ctx = S.Ctx(form=form, judges=people, by_id=by_id, circles=circles, roles=roles, status=status, who=who.viewer,
                    entries={_s(e["judge_id"]): e for e in rows_for if _s(e.get("judge_id"))},
                    guests=sum(1 for e in rows_for if not _s(e.get("judge_id")) and e.get("submitted_at")))
        out.append(ctx)
    return out


def _deadline_key(item: Mapping[str, Any]) -> Any:
    return (item.get("closes_at") is None, item.get("closes_at") or "", item.get("created_at") or "")


@router.get("", summary="Formularze okręgu dla mnie (zakładki: todo, active, manage, drafts, closed, archived, trash)")
async def list_forms(scope: str = Query("active"), province: str = Query(""), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    if scope not in R.SCOPES:
        raise R.FormError("bad_scope", "Nieznana zakładka formularzy.", 400)
    prov = _province_for(who, province)
    # Kosz liczymy zawsze - zakładki dostają liczniki (`scope_counts`), a `in_scope`
    # i tak nie wpuszcza formularza z kosza do innej zakładki.
    contexts = await _contexts(who, prov, include_trash=True)
    events = await S.events_by_id(c.form.get("event_id") for c in contexts)
    out = []
    every = []
    for ctx in contexts:
        item = S.summary(ctx, event=events.get(int(ctx.form["event_id"])) if ctx.form.get("event_id") else None)
        me = item["me"]
        every.append({"roles": ctx.roles, "status": ctx.status, "me": me})
        if R.in_scope(scope, roles=ctx.roles, status=ctx.status, participant=me["participant"], filled=me["filled"],
                      web_review=me["web_review"]):
            out.append(item)
    if scope in ("todo", "active"):
        out.sort(key=_deadline_key)
    return {"forms": out, "can_create": R.can_create(who.viewer, prov), "scope_counts": R.scope_counts(every)}


@router.get("/pending", summary="Na kartę panelu: czeka na Ciebie (posortowane wg terminu)")
async def pending(who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    prov = _province_for(who, "")
    contexts = await _contexts(who, prov, include_trash=False)
    events = await S.events_by_id(c.form.get("event_id") for c in contexts)
    out = []
    for ctx in contexts:
        if (ctx.form.get("settings_json") or {}).get("home_prompt") is False:
            continue
        item = S.summary(ctx, event=events.get(int(ctx.form["event_id"])) if ctx.form.get("event_id") else None)
        me = item["me"]
        if R.in_scope("todo", roles=ctx.roles, status=ctx.status, participant=me["participant"], filled=me["filled"],
                      web_review=me["web_review"]):
            item["status_column"] = R.status_column(ctx.columns) if ctx.kind == "list" else None
            item["fields"] = R.my_fields(ctx.kind, ctx.form.get("schema_json"), ctx.columns)
            event = events.get(int(ctx.form["event_id"])) if ctx.form.get("event_id") else None
            item["info_countdown"] = INFO.first_countdown(S.resolved_info(ctx.form, event))
            out.append(item)
    out.sort(key=_deadline_key)
    return {"forms": out}


@router.get("/templates", summary="Gotowe szablony (§13)")
async def templates(who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    if not R.can_create(who.viewer, _province_for(who, "")) and not who.viewer.is_admin:
        raise R.FormError("forbidden", "Formularze tworzy komisja sędziowska okręgu i administrator.", 403)
    return {"templates": T.all_templates()}


async def _require_audience_editor(who: Who, province: str, form_id: Optional[str]) -> None:
    if R.can_create(who.viewer, province):
        return
    if form_id:
        ctx = await S.context(form_id, who.viewer, with_entries=False)
        if ctx.manager and canonical(ctx.form["province"]) == province:
            return
    raise R.FormError("forbidden", "Listę sędziów do odbiorców widzi twórca i zarządzający.", 403)


@router.get("/people", summary="Sędziowie i odznaki okręgu do edytora odbiorców")
async def people(province: str = Query(""), form_id: str = Query(""), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    prov = _province_for(who, province)
    await _require_audience_editor(who, prov, form_id or None)
    from app.match_market_access import badge_names

    judges = await S.judges(prov)
    return {
        "judges": [
            {
                "judge_id": _s(j["judge_id"]),
                "name": _s(j.get("full_name")) or _s(j["judge_id"]),
                "photo_url": _s(j.get("photo_url")) or None,
                "badges": badge_names(j.get("badges")),
                "inactive": bool(j.get("inactive")),
            }
            for j in sorted(judges, key=lambda x: _s(x.get("full_name")).casefold())
        ],
        "badges": R.badge_catalog(judges),
    }


@router.get("/info/recall", summary="Kreator: przelewy, miejsca i kontakty z poprzednich list okręgu (podpowiedzi)")
async def info_recall(province: str = Query(""), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    prov = _province_for(who, province)
    if not R.can_create(who.viewer, prov) and not who.viewer.is_admin:
        raise R.FormError("forbidden", "Podpowiedzi widzi komisja sędziowska okręgu i administrator.", 403)
    rows = await database.fetch_all(
        select(S.FORMS.c.id, S.FORMS.c.title, S.FORMS.c.event_id, S.FORMS.c.info_json, S.FORMS.c.updated_at, S.FORMS.c.created_at)
        .where(S.FORMS.c.province == prov, S.FORMS.c.deleted_at.is_(None))
        .order_by(S.FORMS.c.updated_at.desc())
        .limit(200)
    )
    forms = [S.parse_form(r) for r in rows]
    events = await S.events_by_id(f.get("event_id") for f in forms)
    return {"items": INFO.recall_sightings(forms, events)}


@router.post("/audience/preview", summary="Ilu ludzi obejmą kręgi odbiorców")
async def audience_preview(body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    prov = _province_for(who, body.get("province"))
    await _require_audience_editor(who, prov, _s(body.get("form_id")) or None)
    audience = body.get("audience") if isinstance(body.get("audience"), Mapping) else {}
    judges = await S.judges(prov)
    cleaned = {
        "participants": R.clean_target(audience.get("participants"), allow_open=True),
        "observers": R.clean_target(audience.get("observers")),
        "managers": R.clean_target(audience.get("managers")),
    }
    circles = R.resolve_audience(judges, cleaned, author=who.judge_id, inactive=S.inactive_of(judges))
    by_id = {_s(j["judge_id"]): j for j in judges}
    names = sorted((_s((by_id.get(j) or {}).get("full_name")) or j for j in circles.participants), key=str.casefold)
    return {
        "participants": len(circles.participants),
        "observers": len(circles.observers),
        "managers": len(circles.managers),
        "open": circles.open,
        "sample": names[:8],
    }


@router.get("/inbox", summary="Skrzynka powiadomień formularzy dla instalacji (jak /push/match-events)")
async def inbox(installation_id: str = Query(...), limit: int = Query(100, ge=1, le=200)) -> Dict[str, Any]:
    """Trwała skrzynka: aplikacja scala ją z panelem powiadomień, nawet gdy system nie pokazał pusha.

    Tożsamość z rekordu urządzenia (jak `/push/match-events`), nie z adresu.
    """
    device = await database.fetch_one(
        select(push_tokens.c.judge_id, push_tokens.c.app_id).where(push_tokens.c.installation_id == installation_id)
    )
    if not device or not _s(device["judge_id"]):
        return {"items": []}
    from app.push.device_policy import dev_pushes_enabled, device_allowed

    if not device_allowed(device, await dev_pushes_enabled()):
        return {"items": []}
    rows = await database.fetch_all(
        select(S.NOTES, S.FORMS.c.title.label("form_title"))
        .select_from(S.NOTES.join(S.FORMS, S.NOTES.c.form_id == S.FORMS.c.id))
        .where(S.NOTES.c.judge_id == _s(device["judge_id"]))
        .where(S.FORMS.c.deleted_at.is_(None))
        .order_by(S.NOTES.c.sent_at.desc())
        .limit(limit)
    )
    items = []
    for raw in rows:
        row = S._row(raw)
        data = {"type": "district_form", "kind": "district_form", "formId": row["form_id"],
                "action": R.notification_action(row["kind"]), "notice": row["kind"]}
        items.append(
            {
                "id": f"district-form:{row['id']}",
                "event_id": 0,
                "title": row.get("title") or row.get("form_title") or "Formularz",
                "body": row.get("body") or "",
                "data_json": data,
                "status": "sent",
                "created_at": R.iso(row.get("sent_at")),
                "sent_at": R.iso(row.get("sent_at")),
                "match_code": None,
                "event_type": "district_form",
            }
        )
    return {"items": items}


@router.get("/by-code/{code}", summary="Link /f/<kod> otwarty w aplikacji -> id formularza")
async def by_code(code: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    clean = R.normalize_code(code)
    if not clean:
        raise R.not_found()
    row = await database.fetch_one(select(S.FORMS.c.id).where(S.FORMS.c.web_code == clean))
    if not row:
        raise R.link_retired() if await S.retired_code(clean) else R.not_found()
    await S.context(row["id"], who.viewer, with_entries=False)
    return {"id": row["id"]}


@router.get("/file/{token}", summary="Pobierz eksport (otwarta ścieżka, 15 minut)")
async def export_file(token: str, filename: str = Query("")):
    found = X.find(token)
    if not found:
        raise R.FormError("file_expired", "Plik wygasł - wygeneruj eksport jeszcze raz.", 404)
    path, ext = found
    name = X.safe_filename(filename.rsplit(".", 1)[0] if filename else "formularz", ext)
    return FileResponse(path, media_type=X.MEDIA[ext], filename=name, headers={"Cache-Control": "no-store"})


@router.post("/pair/{code}/approve", summary="Telefon zatwierdza logowanie przeglądarki (QR z /f/p/<kod>)")
async def pair_approve(code: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    clean = R.normalize_code(code)
    row = await database.fetch_one(select(S.PAIRS).where(S.PAIRS.c.code == clean)) if clean else None
    if not row:
        raise R.FormError("pair_not_found", "Ten kod nie istnieje albo wygasł - odśwież stronę.", 404)
    pair = S._row(row)
    if pair["status"] != "pending":
        raise R.FormError("pair_used", "Ten kod został już użyty - odśwież stronę na komputerze.", 409)
    if R.aware(pair["expires_at"]) <= S.now():
        raise R.FormError("pair_expired", "Kod wygasł - odśwież stronę na komputerze i zeskanuj nowy.", 404)
    ctx = await S.context(pair["form_id"], who.viewer, with_entries=False)
    await database.execute(
        update(S.PAIRS).where(and_(S.PAIRS.c.code == clean, S.PAIRS.c.status == "pending")).values(
            status="approved", judge_id=who.judge_id, judge_name=who.actor.full_name or None)
    )
    event = pair_events.get(clean)
    if event:
        event.set()
    return {"ok": True, "form": {"id": ctx.form["id"], "title": ctx.form["title"]}}


# ---------------------------------------------------------------------------
# Tworzenie i edycja
# ---------------------------------------------------------------------------


def _clean_definition(kind: str, body: Mapping[str, Any], base: Mapping[str, Any]) -> Dict[str, Any]:
    """Pola definicji obecne w `body` (PATCH) albo wszystkie (POST z `base` z szablonu)."""
    out: Dict[str, Any] = {}
    merged = {**base, **body}
    if "title" in merged:
        out["title"] = R.clean_title(merged.get("title"))
    if "description" in merged:
        out["description"] = R.clean_description(merged.get("description"))
    if "cover" in merged:
        out["cover_json"] = R.clean_cover(merged.get("cover"))
    if "schema" in merged:
        out["schema_json"] = SC.clean_schema(kind, merged.get("schema"))
    if "settings" in merged:
        out["settings_json"] = R.clean_settings(merged.get("settings"), kind=kind)
    if "audience" in merged:
        out["audience_json"] = R.clean_audience(merged.get("audience"), kind=kind)
    return out


@router.post("", summary="Utwórz formularz albo listę deklaracji")
async def create(background: BackgroundTasks, body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    prov = _province_for(who, body.get("province"))
    if not R.can_create(who.viewer, prov):
        raise R.FormError("forbidden", "Formularze tworzy komisja sędziowska okręgu i administrator.", 403)
    base: Dict[str, Any] = {}
    if _s(body.get("template_id")):
        template = T.template(body.get("template_id"))
        if not template:
            raise R.FormError("bad_template", "Nie ma takiego szablonu.", 400)
        base = {k: template[k] for k in ("kind", "title", "description", "schema", "settings", "info") if k in template}
    kind = _s(body.get("kind")) or _s(base.get("kind"))
    if kind not in R.KINDS:
        raise R.FormError("bad_kind", "Rodzaj: lista deklaracji albo formularz.", 400)
    if base.get("kind") and base["kind"] != kind:
        base = {}
    for required in ("title", "schema", "audience"):
        if required not in body and required not in base:
            raise R.FormError("missing_field", f"Brakuje pola „{required}”.", 400)
    values = _clean_definition(kind, body, {**base, "settings": base.get("settings", {}), "cover": None})
    moment = S.now()
    closes_at = _future(body.get("closes_at"), moment)
    event_id = body.get("event_id")
    event = await S.check_event_link(int(event_id) if event_id not in (None, "") else None, province=prov, form_id=None)
    if "info" in body:
        values["info_json"] = INFO.clean_info(body.get("info"), values["schema_json"], has_event=event is not None)
    elif base.get("info"):
        adapted = INFO.adapt_template_info(base["info"], has_event=event is not None,
                                           template_title=_s(base.get("title")), form_title=values["title"])
        values["info_json"] = INFO.clean_info(adapted, values["schema_json"], has_event=event is not None)
    else:
        values["info_json"] = INFO.clean_info(None)
    refusal = R.anonymous_web_refusal(kind=kind, settings=values["settings_json"], audience=values["audience_json"], web_enabled=False)
    if refusal:
        raise refusal
    publish = bool(body.get("publish"))
    form_id = R.new_form_id()
    await database.execute(
        insert(S.FORMS).values(
            id=form_id,
            province=prov,
            kind=kind,
            event_id=int(event["id"]) if event else None,
            web_enabled=False,
            created_by=who.judge_id,
            created_by_name=who.actor.full_name or None,
            created_at=moment,
            updated_at=moment,
            published_at=moment if publish else None,
            closes_at=closes_at,
            rev=1,
            **values,
        )
    )
    form = await S.load_form(form_id)
    await S.mirror_participants(form)
    detail = await _detail(form_id, who)
    if publish:
        participants = (await S.context(form_id, who.viewer, with_entries=False)).circles.participants
        background.add_task(S.notify_published, form, participants, who.judge_id)
    return detail


@router.get("/{form_id}", summary="Formularz (FormDetail)")
async def get_form(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    return await _detail(form_id, who)


def _check_rev(form: Mapping[str, Any], if_match: Optional[str]) -> None:
    wanted = _s(if_match).strip('"').replace("W/", "")
    if wanted and wanted != str(int(form.get("rev") or 1)):
        raise R.FormError("stale", "Ktoś zmienił ten formularz w międzyczasie - odśwież i spróbuj ponownie.", 409,
                          rev=int(form.get("rev") or 1))


async def _drop_columns(form: Mapping[str, Any], old_schema: Mapping[str, Any], new_schema: Mapping[str, Any], actor: str) -> None:
    """Usunięta kolumna znika z wierszy, a jej wartości zostają w logu. Zmiana rodzaju kolumny z danymi = 409."""
    old_columns = {c["id"]: c for c in R.columns_of(old_schema)}
    new_columns = {c["id"]: c for c in R.columns_of(new_schema)}
    entries = await S.all_entries([form["id"]])
    for cid, column in old_columns.items():
        fresh = new_columns.get(cid)
        if fresh is not None and fresh.get("type") != column.get("type"):
            if any(R.has_value(column, ((e.get("cells_json") or {}).get(cid) or {}).get("v")) for e in entries):
                raise R.FormError("column_type_locked", f"Kolumna „{column['title']}” ma już odpowiedzi - nie można zmienić jej rodzaju.", 409)
    removed = [cid for cid in old_columns if cid not in new_columns]
    if not removed:
        return
    moment = S.now()
    for entry in entries:
        cells = dict(entry.get("cells_json") or {})
        gone = {cid: cells.pop(cid) for cid in removed if cid in cells}
        if not gone:
            continue
        await database.execute(update(S.ENTRIES).where(S.ENTRIES.c.id == entry["id"]).values(cells_json=cells))
        for cid, cell in gone.items():
            await S._log(form["id"], entry["id"], entry.get("judge_id"), cid, cell, None, actor=actor, source="manager",
                         meta=S.Meta(), moment=moment)


@router.patch("/{form_id}", summary="Zmień formularz (If-Match: rev)")
async def patch_form(
    form_id: str,
    body: Dict[str, Any] = Body(...),
    if_match: Optional[str] = Header(None),
    who: Who = Depends(who_dep),
) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer)
    _manager(ctx)
    form = ctx.form
    _check_rev(form, if_match)
    if "kind" in body and _s(body.get("kind")) != form["kind"]:
        raise R.FormError("kind_locked", "Rodzaju formularza nie można zmienić - utwórz nowy.", 400)
    values = _clean_definition(form["kind"], body, {})
    moment = S.now()
    if "closes_at" in body:
        values["closes_at"] = _future(body.get("closes_at"), moment) if body.get("closes_at") else None
    if "event_id" in body:
        if not R.can_create(who.viewer, form["province"]):
            raise R.FormError("forbidden", "Spięcie z wydarzeniem zmienia komisja okręgu.", 403)
        raw = body.get("event_id")
        event = await S.check_event_link(int(raw) if raw not in (None, "") else None, province=form["province"], form_id=form_id)
        values["event_id"] = int(event["id"]) if event else None
    if "info" in body or {"schema_json", "event_id"} & set(values):
        # Bloki sprawdzamy też przy zmianie listy albo wydarzenia: licznik do wydarzenia
        # i odwołania do kolumny wpłaty muszą dalej mieć cel.
        has_event = (values["event_id"] if "event_id" in values else form.get("event_id")) is not None
        cleaned = INFO.clean_info(body.get("info") if "info" in body else form.get("info_json"),
                                  values.get("schema_json", form.get("schema_json")), has_event=has_event)
        if "info" in body or INFO.info_changed(form.get("info_json"), cleaned):
            values["info_json"] = cleaned
    settings = values.get("settings_json", form.get("settings_json") or {})
    audience = values.get("audience_json", form.get("audience_json") or {})
    if form["kind"] == "form" and "settings_json" in values:
        before = bool((form.get("settings_json") or {}).get("anonymous"))
        if bool(settings.get("anonymous")) != before and any(e.get("submitted_at") for e in ctx.entries.values()):
            raise R.FormError("anonymous_frozen", "Anonimowość ustala się przed pierwszą odpowiedzią.", 409)
    refusal = R.anonymous_web_refusal(kind=form["kind"], settings=settings, audience=audience, web_enabled=bool(form.get("web_enabled")))
    if refusal:
        raise refusal
    if "schema_json" in values and form["kind"] == "list":
        await _drop_columns(form, form.get("schema_json") or {}, values["schema_json"], who.judge_id)
    async with database.transaction():
        row = await database.fetch_one(select(S.FORMS.c.rev).where(S.FORMS.c.id == form_id).with_for_update())
        _check_rev({"rev": row["rev"]}, if_match)
        if values:
            values.update(rev=int(row["rev"] or 1) + 1, updated_at=moment)
            await database.execute(update(S.FORMS).where(S.FORMS.c.id == form_id).values(**values))
    if {"audience_json", "event_id", "schema_json"} & set(values):
        fresh = await S.load_form(form_id)
        await S.mirror_participants(fresh)
        if values.get("event_id") is not None:
            # Opublikowana lista spięta z (nowym) wydarzeniem: RSVP z wydarzenia nie mogą zniknąć.
            await S.seed_from_event_rsvps(fresh)
    return await _detail(form_id, who)


async def _lifecycle(form_id: str, who: Who, change: Callable[[S.Ctx, datetime], Dict[str, Any]]) -> S.Ctx:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    moment = S.now()
    values = change(ctx, moment)
    values.update(rev=int(ctx.form.get("rev") or 1) + 1, updated_at=moment)
    await database.execute(update(S.FORMS).where(S.FORMS.c.id == form_id).values(**values))
    return ctx


@router.post("/{form_id}/publish", summary="Opublikuj szkic (push do uczestników)")
async def publish(form_id: str, background: BackgroundTasks, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status != "draft":
            raise R.FormError("not_draft", "Ten formularz jest już opublikowany.", 409)
        closes = R.aware(ctx.form.get("closes_at"))
        if closes is not None and closes <= moment:
            raise R.FormError("bad_deadline", "Termin minął - ustaw nowy przed publikacją.", 400)
        return {"published_at": moment}

    ctx = await _lifecycle(form_id, who, change)
    published = await S.load_form(form_id)
    # RSVP oddane na wydarzeniu przed publikacją (updated_at < published_at) trafiają do listy.
    await S.seed_from_event_rsvps(published, before=R.aware(published.get("published_at")))
    background.add_task(S.notify_published, await S.load_form(form_id), ctx.circles.participants, who.judge_id)
    return await _detail(form_id, who)


@router.post("/{form_id}/close", summary="Zamknij teraz")
async def close(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status != "open":
            raise R.FormError("not_open", "Zamknąć można tylko otwarty formularz.", 409)
        return {"closed_at": moment}

    await _lifecycle(form_id, who, change)
    return await _detail(form_id, who)


@router.post("/{form_id}/reopen", summary="Otwórz ponownie (opcjonalnie z nowym terminem)")
async def reopen(form_id: str, body: Optional[Dict[str, Any]] = Body(None), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    payload = body or {}

    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status != "closed":
            raise R.FormError("not_closed", "Otworzyć ponownie można tylko zamknięty formularz.", 409)
        values: Dict[str, Any] = {"closed_at": None}
        if payload.get("closes_at"):
            values["closes_at"] = _future(payload.get("closes_at"), moment)
        elif R.aware(ctx.form.get("closes_at")) is not None and R.aware(ctx.form.get("closes_at")) <= moment:
            values["closes_at"] = None
        return values

    await _lifecycle(form_id, who, change)
    return await _detail(form_id, who)


@router.post("/{form_id}/archive", summary="Do archiwum")
async def archive(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status in ("archived", "trash"):
            raise R.FormError("not_allowed", "Ten formularz jest już w archiwum albo w koszu.", 409)
        return {"archived_at": moment}

    await _lifecycle(form_id, who, change)
    return await _detail(form_id, who)


@router.post("/{form_id}/unarchive", summary="Z archiwum")
async def unarchive(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status != "archived":
            raise R.FormError("not_archived", "Ten formularz nie jest w archiwum.", 409)
        return {"archived_at": None}

    await _lifecycle(form_id, who, change)
    return await _detail(form_id, who)


@router.delete("/{form_id}", summary="Do kosza (30 dni na przywrócenie)")
async def trash(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status == "trash":
            raise R.FormError("in_trash", "Ten formularz jest już w koszu.", 409)
        return {"deleted_at": moment}

    await _lifecycle(form_id, who, change)
    return await _detail(form_id, who)


@router.post("/{form_id}/restore", summary="Przywróć z kosza")
async def restore(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    def change(ctx: S.Ctx, moment: datetime) -> Dict[str, Any]:
        if ctx.status != "trash":
            raise R.FormError("not_in_trash", "Ten formularz nie leży w koszu.", 409)
        if not R.restorable(ctx.form.get("deleted_at"), moment):
            raise R.FormError("trash_expired", "Minęło 30 dni - tego formularza nie da się już przywrócić.", 410)
        return {"deleted_at": None}

    ctx = await _lifecycle(form_id, who, change)
    if ctx.form.get("event_id"):
        clash = await database.fetch_one(
            select(S.FORMS.c.id).where(and_(S.FORMS.c.event_id == ctx.form["event_id"], S.FORMS.c.deleted_at.is_(None),
                                            S.FORMS.c.id != form_id))
        )
        if clash:
            await database.execute(update(S.FORMS).where(S.FORMS.c.id == form_id).values(event_id=None))
    return await _detail(form_id, who)


@router.post("/{form_id}/duplicate", summary="Kopia jako nowy szkic (bez odpowiedzi)")
async def duplicate(form_id: str, body: Optional[Dict[str, Any]] = Body(None), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    _app_only(who)
    payload = body or {}
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    moment = S.now()
    form = ctx.form
    title = R.clean_title(payload.get("title") or f"{form['title']} (kopia)"[: R.TITLE_MAX])
    closes_at = _future(payload.get("closes_at"), moment) if payload.get("closes_at") else None
    new_id = R.new_form_id()
    await database.execute(
        insert(S.FORMS).values(
            id=new_id, province=form["province"], kind=form["kind"], title=title, description=form.get("description"),
            cover_json=form.get("cover_json"), schema_json=form.get("schema_json") or {},
            settings_json=form.get("settings_json") or {}, audience_json=form.get("audience_json") or {},
            # Kopia nie ma wydarzenia: licznik do wydarzenia odlicza do terminu.
            info_json=INFO.adapt_template_info(form.get("info_json"), has_event=False, template_title="", form_title=title),
            event_id=None, web_enabled=False, created_by=who.judge_id, created_by_name=who.actor.full_name or None,
            created_at=moment, updated_at=moment, closes_at=closes_at, rev=1,
        )
    )
    return await _detail(new_id, who)


# ---------------------------------------------------------------------------
# Moja odpowiedź
# ---------------------------------------------------------------------------


@router.put("/{form_id}/me", summary="Mój wiersz listy albo moja odpowiedź formularza")
async def put_me(form_id: str, request: Request, body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _participant(ctx, who.judge_id)
    meta = _meta(request, body.get("device_id"))
    if ctx.kind == "list":
        cells = body.get("cells") if isinstance(body.get("cells"), Mapping) else {}
        entry, _changed = await S.write_cells(ctx.form, judge_id=who.judge_id, changes=cells, source=who.source,
                                              actor_id=who.judge_id, meta=meta)
    else:
        entry = await S.write_answers(
            ctx.form, judge_id=who.judge_id, guest_name=None,
            answers=body.get("answers") if isinstance(body.get("answers"), Mapping) else {},
            client_id=body.get("client_id"), fill=body.get("fill_seconds"), source=who.source,
            actor_id=who.judge_id, meta=meta,
        )
    return {"entry": S.entry_view(ctx, entry, judge_id=who.judge_id, mode="own", include_answers=True)}


@router.post("/{form_id}/me/confirm", summary="„To ja” po zapisie z weba")
async def confirm_me(form_id: str, request: Request, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _participant(ctx, who.judge_id)
    entry = await S.confirm_me(ctx.form, who.judge_id, source=who.source, meta=_meta(request))
    return {"entry": S.entry_view(ctx, entry, judge_id=who.judge_id, mode="own", include_answers=True)}


# ---------------------------------------------------------------------------
# Wiersze (zarządzający, obserwator, uczestnik przy roster_visible)
# ---------------------------------------------------------------------------


def _row_mode(ctx: S.Ctx, judge_id: str) -> str:
    if ctx.manager:
        return "manager"
    if "observer" in ctx.roles:
        return "observer"
    return "own" if judge_id == ctx.who.judge_id else "roster"


def _filtered_participants(ctx: S.Ctx, flt: Mapping[str, Any], *, q: str = "") -> List[str]:
    out = []
    for jid in _sorted_people(ctx, ctx.circles.participants):
        if q and not R.name_matches(S.judge_name(ctx.by_id, jid), q):
            continue
        entry = ctx.entries.get(jid) or {}
        mode = _row_mode(ctx, jid)
        visible = R.filter_cells(ctx.columns, entry.get("cells_json") or {}, mode) if ctx.kind == "list" else {}
        if flt and not R.matches_filter(
            ctx.columns, cells=visible, filled=R.entry_filled(ctx.kind, ctx.form.get("schema_json"), entry),
            web_review=bool(entry.get("web_review")), verified=bool(entry.get("verified")), flt=flt,
        ):
            continue
        out.append(jid)
    return out


@router.get("/{form_id}/rows", summary="Wszyscy uczestnicy (także z pustym wierszem)")
async def rows(form_id: str, q: str = Query(""), filter: str = Query(""), who: Who = Depends(who_dep)) -> Dict[str, Any]:  # noqa: A002
    ctx = await S.context(form_id, who.viewer)
    if not S.can_flags(ctx)["view_rows"]:
        raise R.FormError("forbidden", "Listę widzą zarządzający i obserwatorzy.", 403)
    flt = R.clean_filter(filter)
    out = [
        S.entry_view(ctx, ctx.entries.get(jid), judge_id=jid, mode=_row_mode(ctx, jid))
        for jid in _filtered_participants(ctx, flt, q=q)
    ]
    if ctx.manager and ctx.kind == "form" and ctx.circles.open:
        for entry in await S.all_entries([form_id]):
            if not _s(entry.get("judge_id")) and (not q or R.name_matches(_s(entry.get("guest_name")), q)):
                out.append(S.entry_view(ctx, entry, judge_id=None, mode="manager"))
    mode = "manager" if ctx.manager else ("observer" if "observer" in ctx.roles else "own")
    return {"rows": out, "columns": R.visible_columns(ctx.columns, mode) if ctx.kind == "list" else []}


@router.patch("/{form_id}/rows/{judge_id}", summary="Zarządzający zmienia wiersz sędziego")
async def patch_row(form_id: str, judge_id: str, request: Request, body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    if judge_id not in ctx.circles.participants:
        raise R.FormError("not_participant", "Tego sędziego nie ma na liście.", 404)
    cells = body.get("cells") if isinstance(body.get("cells"), Mapping) else {}
    entry, _changed = await S.write_cells(ctx.form, judge_id=judge_id, changes=cells, source="manager",
                                          actor_id=who.judge_id, meta=_meta(request))
    return {"entry": S.entry_view(ctx, entry, judge_id=judge_id, mode="manager")}


@router.post("/{form_id}/rows/{judge_id}/clear", summary="Komisja usuwa odpowiedź sędziego (cały wiersz albo komórkę)")
async def clear_row(form_id: str, judge_id: str, request: Request, body: Optional[Dict[str, Any]] = Body(None),
                    who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    column_id = _s((body or {}).get("column_id")) or None
    if column_id:
        if ctx.kind != "list":
            raise R.FormError("wrong_kind", "Komórki ma tylko lista deklaracji.", 400)
        if column_id not in {c["id"] for c in ctx.columns}:
            raise R.FormError("unknown_column", "Takiej kolumny nie ma - odśwież listę.", 400)
        if judge_id not in ctx.circles.participants:
            raise R.FormError("not_participant", "Tego sędziego nie ma na liście.", 404)
    entry = await S.clear_entry(ctx.form, judge_id=judge_id, column_id=column_id, actor_id=who.judge_id, meta=_meta(request))
    if entry is None:
        return {"entry": None}
    await S.load_entries(ctx)
    return {"entry": S.entry_view(ctx, ctx.entries.get(judge_id), judge_id=judge_id, mode="manager")}


@router.post("/{form_id}/rows/bulk", summary="Jedna wartość w jednej kolumnie dla wielu sędziów")
async def bulk(form_id: str, request: Request, body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    column_id = _s(body.get("column_id"))
    if column_id not in {c["id"] for c in ctx.columns}:
        raise R.FormError("unknown_column", "Takiej kolumny nie ma - odśwież listę.", 400)
    wanted = [_s(j) for j in (body.get("judge_ids") or [])[:2000] if _s(j)]
    allowed = set(ctx.circles.participants)
    meta = _meta(request)
    updated = 0
    for jid in dict.fromkeys(wanted):
        if jid not in allowed:
            continue
        _entry, changed = await S.write_cells(ctx.form, judge_id=jid, changes={column_id: body.get("value")},
                                              source="manager", actor_id=who.judge_id, meta=meta)
        updated += 1 if changed else 0
    return {"updated": updated}


@router.get("/{form_id}/log", summary="Historia zmian (z IP i urządzeniem dla webu)")
async def log(form_id: str, judge_id: str = Query(""), limit: int = Query(200, ge=1, le=1000), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    query = select(S.LOG).where(S.LOG.c.form_id == form_id)
    if _s(judge_id):
        query = query.where(S.LOG.c.owner_judge_id == _s(judge_id))
    rows_ = await database.fetch_all(query.order_by(S.LOG.c.created_at.desc(), S.LOG.c.id.desc()).limit(limit))
    titles = {c["id"]: c["title"] for c in ctx.columns}
    items = []
    for raw in rows_:
        row = S._row(raw)
        owner = _s(row.get("owner_judge_id"))
        actor = _s(row.get("actor_judge_id"))
        column_id = row.get("column_id")
        items.append(
            {
                "id": int(row["id"]),
                "owner": {"judge_id": owner or None, "name": S.judge_name(ctx.by_id, owner) if owner else None},
                "column_id": column_id,
                "column_title": titles.get(column_id, "Usunięta kolumna") if column_id else None,
                "old": R.loads(row.get("old_json"), None),
                "new": R.loads(row.get("new_json"), None),
                "source": row.get("source"),
                "actor": {"judge_id": actor, "name": S.judge_name(ctx.by_id, actor)} if actor else None,
                "ip": row.get("ip"),
                "user_agent": row.get("user_agent"),
                "device_id": row.get("device_id"),
                "geo": R.loads(row.get("geo_json"), None),
                "created_at": R.iso(row.get("created_at")),
            }
        )
    return {"items": items}


# ---------------------------------------------------------------------------
# Wyniki i eksport
# ---------------------------------------------------------------------------


async def _form_responses(ctx: S.Ctx) -> List[Dict[str, Any]]:
    out = []
    for entry in await S.all_entries([ctx.form["id"]]):
        if not entry.get("submitted_at") or not entry.get("answers_json"):
            continue
        jid = _s(entry.get("judge_id"))
        if jid and jid not in ctx.circles.participants:
            continue
        out.append(entry)
    return out


def form_stats(ctx: S.Ctx, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    sections = SC.sections_of(ctx.form.get("schema_json"))
    results, hidden = SC.aggregate(sections, [e.get("answers_json") or {} for e in responses])
    participants = ctx.circles.participants
    filled_ids = [jid for jid in participants if R.entry_filled("form", ctx.form.get("schema_json"), ctx.entries.get(jid))]
    seconds = [e["fill_seconds"] for e in responses if e.get("fill_seconds")]
    return {
        "kind": "form",
        "participants": len(participants),
        "filled": len(filled_ids),
        "guests": sum(1 for e in responses if not _s(e.get("judge_id"))),
        "total": len(responses),
        "last_at": max((R.iso(e.get("submitted_at")) for e in responses), default=None),
        "timeline": R.timeline(R._day(e.get("submitted_at")) for e in responses),
        "questions": results,
        "hidden_question_ids": hidden,
        "median_fill_seconds": SC.median(seconds) if len(seconds) >= 2 else None,
    }


@router.get("/{form_id}/stats", summary="Statystyki (§11)")
async def stats(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer)
    if not S.can_flags(ctx)["view_results"]:
        raise R.FormError("forbidden", "Wyniki tego formularza widzi komisja.", 403)
    if ctx.kind == "list":
        # Uczestnik widzi same liczby jawnych kolumn statusu i wyboru (bez wpłat), obserwator - bez kolumn komisji.
        if ctx.manager or "observer" in ctx.roles:
            columns = R.visible_columns(ctx.columns, "manager" if ctx.manager else "observer")
        else:
            columns = R.summary_columns(R.visible_columns(ctx.columns, "roster"))
        return R.list_stats(columns, ctx.circles.participants, ctx.entries)
    return form_stats(ctx, await _form_responses(ctx))


@router.get("/{form_id}/responses", summary="Pojedyncze odpowiedzi formularza")
async def responses(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer)
    if ctx.kind != "form":
        raise R.FormError("wrong_kind", "Lista nie ma odpowiedzi - użyj wierszy.", 400)
    if not S.can_flags(ctx)["view_rows"]:
        raise R.FormError("forbidden", "Odpowiedzi widzi komisja.", 403)
    anonymous = bool((ctx.form.get("settings_json") or {}).get("anonymous"))
    out = []
    for entry in await _form_responses(ctx):
        view = S.entry_view(ctx, entry, judge_id=entry.get("judge_id"), mode="manager", include_answers=True)
        if anonymous:
            for key in ("judge_id", "name", "guest_name", "photo_url", "badges"):
                view.pop(key, None)
        out.append(view)
    return {"responses": out}


@router.get("/{form_id}/export", summary="Eksport xlsx / csv / pdf -> adres do pobrania (15 minut)")
async def export(form_id: str, format: str = Query("xlsx"), who: Who = Depends(who_dep)) -> Dict[str, Any]:  # noqa: A002
    if format not in X.FORMATS:
        raise R.FormError("bad_format", "Format: xlsx, csv albo pdf.", 400)
    ctx = await S.context(form_id, who.viewer)
    _manager(ctx)
    generated = S.now().astimezone(R.WARSAW).strftime("%d.%m.%Y %H:%M")
    if ctx.kind == "list":
        people = [(jid, S.judge_name(ctx.by_id, jid)) for jid in _sorted_people(ctx, ctx.circles.participants)]
        header, table, tones = X.list_table(ctx.columns, people, ctx.entries)
        totals = X.summary_rows("list", R.list_stats(ctx.columns, ctx.circles.participants, ctx.entries), ctx.columns)
    else:
        anonymous = bool((ctx.form.get("settings_json") or {}).get("anonymous"))
        answers = [
            {
                "answers": e.get("answers_json") or {},
                "submitted_at": e.get("submitted_at"),
                "self_source": e.get("self_source"),
                "name": S.judge_name(ctx.by_id, e.get("judge_id")) if e.get("judge_id") else e.get("guest_name"),
            }
            for e in await _form_responses(ctx)
        ]
        header, table = X.form_table(ctx.form.get("schema_json") or {}, answers, with_person=not anonymous)
        tones = None
        totals = X.summary_rows("form", form_stats(ctx, await _form_responses(ctx)), [])
    data = await asyncio.to_thread(
        X.build, format, form=ctx.form, province=R.province_label(display(ctx.form["province"])), header=header,
        rows=table, tones=tones, summary=totals, generated=generated,
        payment=INFO.first_payment(S.resolved_info(ctx.form, (await S.events_by_id([ctx.form.get("event_id")])).get(
            int(ctx.form["event_id"])) if ctx.form.get("event_id") else None)),
    )
    token = X.store(data, format)
    filename = X.safe_filename(ctx.form["title"], format)
    return {"url": f"/district-forms/file/{token}?filename={urllib.parse.quote(filename)}", "filename": filename}


# ---------------------------------------------------------------------------
# Push, web, wydarzenie
# ---------------------------------------------------------------------------


@router.post("/{form_id}/remind", summary="Ręczny push do uczestników (segment, limit 1 na 10 minut)")
async def remind(form_id: str, body: Optional[Dict[str, Any]] = Body(None), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    payload = body or {}
    ctx = await S.context(form_id, who.viewer)
    _manager(ctx)
    if ctx.status != "open":
        raise R.FormError("not_open", "Przypominać można tylko o otwartym formularzu.", 409)
    if ctx.form.get("silent"):
        raise R.FormError("silent", "Lista jest w trybie cichym - włącz powiadomienia, żeby przypomnieć.", 409)
    moment = S.now()
    last = await database.fetch_one(
        select(S.NOTES.c.sent_at)
        .where(and_(S.NOTES.c.form_id == form_id, S.NOTES.c.kind == "manual"))
        .order_by(S.NOTES.c.sent_at.desc())
        .limit(1)
    )
    if last and R.aware(last["sent_at"]) > moment - R.MANUAL_REMIND_EVERY:
        retry = R.aware(last["sent_at"]) + R.MANUAL_REMIND_EVERY
        raise R.FormError("rate_limited", f"Kolejne przypomnienie wyślesz o {retry.astimezone(R.WARSAW):%H:%M}.", 429,
                          retry_at=retry.isoformat(), retry_after=max(1, int((retry - moment).total_seconds())))
    picked = {_s(j) for j in payload.get("judge_ids") or [] if _s(j)}
    only_unfilled = payload.get("only_unfilled")
    if only_unfilled is None:
        only_unfilled = not picked
    flt = R.clean_filter(payload.get("filter"))
    people = _filtered_participants(ctx, flt)
    if picked:
        people = [j for j in people if j in picked]
    if only_unfilled:
        people = [j for j in people if not R.entry_filled(ctx.kind, ctx.form.get("schema_json"), ctx.entries.get(j))]
    if not people:
        return {"sent_to": 0, "devices": 0}
    default_title, default_body = S.reminder_text(ctx.form) if ctx.form.get("closes_at") else (f"📋 {ctx.form['title']}", "Komisja czeka na Twoją odpowiedź w BAZIE.")
    title = _s(payload.get("title"))[:80] or default_title
    text = _s(payload.get("body"))[:300] or default_body
    result = await S.notify(ctx.form, people, kind="manual", slot=moment.strftime("%Y%m%dT%H%M%S"), title=title, body=text, moment=moment)
    return {"sent_to": result["sent_to"], "devices": result["devices"]}


@router.post("/{form_id}/silent", summary="Tryb cichy: lista widoczna, bez pushy i przypomnień (testy)")
async def silent_toggle(form_id: str, background: BackgroundTasks, body: Dict[str, Any] = Body(...),
                        who: Who = Depends(who_dep)) -> Dict[str, Any]:
    """`{"silent": true}` wycisza. `{"silent": false, "mode": ...}` włącza powiadomienia z powrotem:
    `reset` cofa do szkicu i czyści testowe odpowiedzi (potem zwykła publikacja z pushem),
    `send` zostawia odpowiedzi i wysyła powiadomienie o publikacji teraz, `later` tylko odcisza.
    Szkic odcisza się bez trybu - nikt go jeszcze nie widział."""
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    moment = S.now()
    rev = int(ctx.form.get("rev") or 1) + 1
    if bool(body.get("silent")):
        if ctx.status == "trash":
            raise R.FormError("trash", "Formularz jest w koszu.", 409)
        await database.execute(update(S.FORMS).where(S.FORMS.c.id == form_id).values(silent=True, rev=rev, updated_at=moment))
        return await _detail(form_id, who)
    mode = _s(body.get("mode")) or ("later" if ctx.status == "draft" else "")
    refusal = R.silent_off_refusal(ctx.status, mode)
    if refusal:
        raise refusal
    values: Dict[str, Any] = {"silent": False, "rev": rev, "updated_at": moment}
    if mode == "reset":
        await S.clear_test_answers(ctx.form)
        values.update(published_at=None, closed_at=None)
    await database.execute(update(S.FORMS).where(S.FORMS.c.id == form_id).values(**values))
    if mode == "send":
        background.add_task(S.notify_published, await S.load_form(form_id), ctx.circles.participants, who.judge_id,
                            slot=R.silent_publish_slot(moment))
    return await _detail(form_id, who)


@router.post("/{form_id}/web", summary="Włącz albo wyłącz stronę www (kod zostaje na stałe)")
async def web_toggle(form_id: str, body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    enabled = bool(body.get("enabled"))
    form = ctx.form
    if enabled:
        refusal = R.anonymous_web_refusal(kind=form["kind"], settings=form.get("settings_json") or {},
                                          audience=form.get("audience_json") or {}, web_enabled=True)
        if refusal:
            raise refusal
    code = form.get("web_code")
    if enabled and not code:
        code = await S.free_code()
    await database.execute(
        update(S.FORMS).where(S.FORMS.c.id == form_id).values(
            web_enabled=enabled, web_code=code, rev=int(form.get("rev") or 1) + 1, updated_at=S.now())
    )
    return {"web_enabled": enabled, "web_code": code, "web_url": R.web_url(code) if code else None}


@router.post("/{form_id}/web/rotate", summary="Wygeneruj nowy link strony (stary przestaje działać)")
async def web_rotate(form_id: str, who: Who = Depends(who_dep)) -> Dict[str, Any]:
    """Nowy kod `/f/<kod>` na życzenie komisji. Stary trafia do `district_form_retired_codes`:
    strona, aplikacja i karta komunikatora mówią „link nieaktualny” (410), nie „nie ma takiego”.
    Stan strony (włączona albo wyłączona) zostaje bez zmian."""
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    _manager(ctx)
    form = ctx.form
    old = form.get("web_code")
    code = await S.free_code()
    async with database.transaction():
        if old:
            await database.execute(insert(S.RETIRED).values(code=old, form_id=form_id, retired_by=who.judge_id, retired_at=S.now()))
        await database.execute(
            update(S.FORMS).where(S.FORMS.c.id == form_id).values(
                web_code=code, rev=int(form.get("rev") or 1) + 1, updated_at=S.now())
        )
    enabled = bool(form.get("web_enabled"))
    return {"web_enabled": enabled, "web_code": code, "web_url": R.web_url(code), "retired_code": old}


@router.post("/{form_id}/invite-to-event", summary="Zaproś na wydarzenie sędziów z wyników (filtr)")
async def invite_to_event(form_id: str, body: Dict[str, Any] = Body(...), who: Who = Depends(who_dep)) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer)
    _manager(ctx)
    if not PR.can_manage(who.viewer, ctx.form["province"]):
        raise R.FormError("forbidden", "Zaproszenia na wydarzenia zmienia komisja okręgu.", 403)
    try:
        event_id = int(body.get("event_id"))
    except (TypeError, ValueError) as error:
        raise R.FormError("event_not_found", "Wybierz wydarzenie.", 400) from error
    row = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    if not row or row["deleted_at"] is not None or canonical(row["province"]) != canonical(ctx.form["province"]):
        raise R.FormError("event_not_found", "Nie ma takiego wydarzenia w tym okręgu.", 404)
    people = _filtered_participants(ctx, R.clean_filter(body.get("filter")))
    data = R.loads(row["data_json"], {})
    include = [_s(x) for x in data.get("include_ids") or [] if _s(x)]
    exclude = [_s(x) for x in data.get("exclude_ids") or [] if _s(x)]
    added = [jid for jid in people if jid not in include]
    data["include_ids"] = include + added
    data["exclude_ids"] = [x for x in exclude if x not in set(people)]
    await database.execute(update(province_events).where(province_events.c.id == event_id).values(data_json=data, updated_at=S.now()))
    return {"added": len(added)}


# ---------------------------------------------------------------------------
# Pliki (form)
# ---------------------------------------------------------------------------


@router.post("/{form_id}/uploads", summary="Obraz przy pytaniu (question) albo plik odpowiedzi (answer)")
async def upload(
    form_id: str,
    request: Request,
    purpose: str = Query("answer", pattern="^(question|answer)$"),
    file: UploadFile = File(...),
    who: Who = Depends(who_dep),
) -> Dict[str, Any]:
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    if ctx.kind != "form":
        raise R.FormError("wrong_kind", "Pliki są tylko w formularzu.", 400)
    if purpose == "question":
        _manager(ctx)
    else:
        _participant(ctx, who.judge_id)
        if ctx.status != "open":
            raise R.FormError("closed", "Formularz nie przyjmuje już odpowiedzi.", 409)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > S.UPLOAD_MAX_BYTES + 64 * 1024:
        raise R.FormError("too_large", "Ten plik jest za duży (najwyżej 10 MB).", 413)
    data = await file.read(S.UPLOAD_MAX_BYTES + 1)
    if len(data) > S.UPLOAD_MAX_BYTES:
        raise R.FormError("too_large", "Ten plik jest za duży (najwyżej 10 MB).", 413)
    if not data:
        raise R.FormError("empty_file", "Plik jest pusty.", 400)
    mime = (file.content_type or "").split(";")[0].strip().lower() or (mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream")
    if purpose == "question" and not mime.startswith("image/"):
        raise R.FormError("bad_file", "Przy pytaniu można dodać tylko obraz.", 415)
    token = secrets.token_hex(8)
    path = S.upload_path(form_id, token)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    name = _s(file.filename).replace("/", "_").replace("\\", "_")[:120] or None
    await database.execute(
        insert(S.UPLOADS).values(token=token, form_id=form_id, judge_id=who.judge_id, purpose=purpose, name=name,
                                 mime=mime, size_bytes=len(data), created_at=S.now())
    )
    return {"token": token, "purpose": purpose, "name": name, "mime": mime, "size_bytes": len(data)}


@router.get("/{form_id}/files/{token}", summary="Plik pytania albo odpowiedzi")
async def form_file(form_id: str, token: str, who: Who = Depends(who_dep)):
    ctx = await S.context(form_id, who.viewer, with_entries=False)
    row = await database.fetch_one(select(S.UPLOADS).where(and_(S.UPLOADS.c.form_id == form_id, S.UPLOADS.c.token == _s(token))))
    if not row:
        raise R.FormError("file_not_found", "Nie ma takiego pliku.", 404)
    item = S._row(row)
    if item["purpose"] == "answer" and _s(item.get("judge_id")) != who.judge_id and not S.can_flags(ctx)["view_rows"]:
        raise R.FormError("file_not_found", "Nie ma takiego pliku.", 404)
    path = S.upload_path(form_id, item["token"])
    if not path.exists():
        raise R.FormError("file_not_found", "Nie ma takiego pliku.", 404)
    mime = _s(item.get("mime")) or "application/octet-stream"
    image = mime.startswith("image/")
    return FileResponse(
        str(path),
        media_type=mime if image or mime == "application/pdf" else "application/octet-stream",
        filename=None if image else (item.get("name") or f"plik-{token}"),
        headers={"Cache-Control": "private, max-age=86400"},
    )

