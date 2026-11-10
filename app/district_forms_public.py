"""
Formularze okręgowe - publiczny web bez logowania (prefiks `/public/forms`).

Kontrakt: `docs/formularze-okregowe.md` §9 i §12. Strona `https://www.bazapodreka.app/f/<kod>`.

Zapis anonimowy (źródło `web`) przechodzi tylko przez wiersz NIEZWERYFIKOWANY i tylko
w kolumnach sędziego. Każdy zostawia ślad (IP z X-Forwarded-For, przeglądarka,
urządzenie, położenie za zgodą), ustawia „czeka na potwierdzenie" i wysyła właścicielowi
push „To Ty?". Logowanie QR daje token `scope:"form-web"` na 12 h dla jednego formularza.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Optional

from fastapi import APIRouter, Body, Query, Request
from sqlalchemy import and_, insert, select, update

from app import district_form_info as INFO
from app import district_form_schema as SC
from app import district_forms_rules as R
from app import district_forms_service as S
from app.db import database, province_events
from app.deps import FORM_WEB_SCOPE
from app.district_forms import FormRoute, pair_events
from app.pod_reka_login_rules import AttemptLimiter
from app.settlement_province import display

router = APIRouter(prefix="/public/forms", tags=["District forms (web)"], route_class=FormRoute)

#: 30 zapisów na minutę z jednego adresu; 20 kodów QR na 10 minut.
WRITE_LIMITER = AttemptLimiter(limit=30, window=timedelta(minutes=1), max_keys=20_000)
QR_LIMITER = AttemptLimiter(limit=20, window=timedelta(minutes=10), max_keys=20_000)
QR_POLL_MAX_S = 25

PRIVACY_NOTE = (
    "Zapisując odpowiedź na tej stronie, przekazujesz ją komisji sędziowskiej okręgu. "
    "Do ochrony przed podszywaniem się zapisujemy adres IP, przeglądarkę, identyfikator urządzenia "
    "i - jeśli się zgodzisz - przybliżone położenie. Sędzia, w którego imieniu zaznaczono odpowiedź, "
    "dostanie powiadomienie i może ją poprawić w aplikacji BAZA. Administratorem danych jest komisja "
    "sędziowska okręgu; dane służą wyłącznie do obsługi tego formularza."
)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _address(request: Request) -> str:
    return R.ip_from(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")


def _limit(limiter: AttemptLimiter, key: str) -> None:
    if limiter.blocked(key):
        raise R.FormError("rate_limited", "Za dużo prób naraz. Spróbuj za chwilę.", 429,
                          retry_after=limiter.retry_after(key))
    limiter.fail(key)


async def _form_by_code(code: str) -> Dict[str, Any]:
    clean = R.normalize_code(code)
    if not clean:
        raise R.not_found()
    row = await database.fetch_one(select(S.FORMS).where(S.FORMS.c.web_code == clean))
    if not row:
        raise R.not_found()
    form = S.parse_form(row)
    # Szkic też: strona działa w pełni przed publikacją (decyzja 10.11.2026), komisja
    # testuje link i QR, zanim lista pójdzie do sędziów. Kosz zostaje 404.
    if form.get("deleted_at") is not None:
        raise R.not_found()
    return form


def _web_on(form: Mapping[str, Any]) -> None:
    if not form.get("web_enabled"):
        raise R.FormError("web_disabled", "Ten formularz nie jest dostępny na stronie - odpowiedz w aplikacji BAZA.", 403)


def _closed(ctx: S.Ctx, moment: datetime) -> bool:
    return ctx.status in ("closed", "archived") or R.is_closed(ctx.form, moment)


def public_row(ctx: S.Ctx, judge_id: str, *, with_cells: bool) -> Dict[str, Any]:
    entry = ctx.entries.get(judge_id) or {}
    judge = ctx.by_id.get(judge_id) or {}
    return {
        "judge_id": judge_id,
        "name": _s(judge.get("full_name")) or judge_id,
        "photo_url": _s(judge.get("photo_url")) or None,
        "cells": R.filter_cells(ctx.columns, entry.get("cells_json") or {}, "web") if with_cells else {},
        "verified": bool(entry.get("verified")),
        "web_claimed": {"at": R.iso(entry.get("web_at"))} if entry.get("web_device") and entry.get("web_at") else None,
        "filled": R.entry_filled(ctx.kind, ctx.form.get("schema_json"), entry),
    }


def _counts(ctx: S.Ctx) -> Dict[str, Any]:
    participants = ctx.circles.participants
    out: Dict[str, Any] = {
        "participants": len(participants),
        "filled": sum(1 for j in participants if R.entry_filled(ctx.kind, ctx.form.get("schema_json"), ctx.entries.get(j))),
    }
    column = R.status_column(ctx.columns) if ctx.kind == "list" else None
    if column:
        out["status"] = R.status_counts(column, participants, {j: e.get("cells_json") or {} for j, e in ctx.entries.items()})
    return out


def _people(ctx: S.Ctx):
    return sorted(ctx.circles.participants, key=lambda j: (S.judge_name(ctx.by_id, j).casefold(), j))


async def _info(form: Mapping[str, Any], *, web_enabled: bool) -> Dict[str, Any]:
    """Bloki informacyjne strony; przy wyłączonym webie tylko licznik i tekst."""
    event = (await S.events_by_id([form.get("event_id")])).get(int(form["event_id"])) if form.get("event_id") else None
    return INFO.public_info(S.resolved_info(form, event), web_enabled=web_enabled)


async def _event(form: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Wydarzenie okręgowe spięte z listą: nazwa, daty i grafika tytułowa (tło strony WWW)."""
    if not form.get("event_id"):
        return None
    row = await database.fetch_one(
        select(province_events.c.id, province_events.c.name, province_events.c.event_date, province_events.c.end_date,
               province_events.c.data_json, province_events.c.deleted_at)
        .where(province_events.c.id == int(form["event_id"]))
    )
    if row is None or row["deleted_at"] is not None:
        return None
    data = row["data_json"] if isinstance(row["data_json"], Mapping) else {}
    image = data.get("title_image") if isinstance(data.get("title_image"), Mapping) else {}
    url = str(image.get("url") or "").strip()
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "event_date": R.iso(row["event_date"]),
        "end_date": R.iso(row["end_date"]),
        "title_image": url if url.startswith("/static/") or url.startswith("https://") else None,
    }


@router.get("/{code}", summary="Formularz na stronie (bez logowania)")
async def public_form(code: str) -> Dict[str, Any]:
    form = await _form_by_code(code)
    if not form.get("web_enabled"):
        return {"web_enabled": False, "title": form["title"], "info": await _info(form, web_enabled=False)}
    moment = S.now()
    ctx = await S.public_context(form, moment=moment)
    if ctx.status == "trash":
        raise R.not_found()
    out: Dict[str, Any] = {
        "web_enabled": True,
        "id": form["id"],
        "kind": ctx.kind,
        "title": form["title"],
        "description": form.get("description"),
        "cover": form.get("cover_json") or None,
        "closes_at": R.iso(form.get("closes_at")),
        "closed": _closed(ctx, moment),
        "draft": ctx.status == "draft",
        "province_label": R.province_label(display(form["province"])),
        "counts": _counts(ctx),
        "privacy_note": PRIVACY_NOTE,
        "info": await _info(form, web_enabled=True),
        "event": await _event(form),
    }
    if ctx.kind == "list":
        out["columns"] = R.visible_columns(ctx.columns, "web")
        out["rows"] = [public_row(ctx, jid, with_cells=True) for jid in _people(ctx)]
    else:
        out["schema"] = SC.with_image_urls(form.get("schema_json") or {}, form["id"], public_code=form.get("web_code"))
        out["open"] = ctx.circles.open
        settings = form.get("settings_json") or {}
        out["fill_mode"] = settings.get("fill_mode") or "steps"
        out["confirmation"] = settings.get("confirmation")
        out["rows"] = [] if ctx.circles.open and not ctx.circles.participants else [
            public_row(ctx, jid, with_cells=False) for jid in _people(ctx)
        ]
    return out


@router.put("/{code}/rows/{judge_id}", summary="Zaznacz w wierszu sędziego (bez logowania)")
async def public_row_write(code: str, judge_id: str, request: Request, body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    _limit(WRITE_LIMITER, f"w:{_address(request)}")
    form = await _form_by_code(code)
    _web_on(form)
    if form["kind"] != "list":
        raise R.FormError("wrong_kind", "To jest formularz - wyślij odpowiedzi.", 400)
    device = R.clean_device_id(body.get("device_id"))
    ctx = await S.public_context(form)
    if judge_id not in ctx.circles.participants:
        raise R.FormError("not_participant", "Tego sędziego nie ma na liście.", 404)
    cells = body.get("cells") if isinstance(body.get("cells"), Mapping) else {}
    meta = S.Meta(ip=_address(request), user_agent=(request.headers.get("user-agent") or "")[:300] or None,
                  device_id=device, geo=R.clean_geo(body.get("geo")))
    await S.write_cells(form, judge_id=judge_id, changes=cells, source="web", actor_id=None, meta=meta,
                        force=bool(body.get("force")))
    await S.load_entries(ctx)
    return {"row": public_row(ctx, judge_id, with_cells=True)}


@router.put("/{code}/responses", summary="Odpowiedź formularza ze strony (sędzia z listy albo gość)")
async def public_response(code: str, request: Request, body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    _limit(WRITE_LIMITER, f"w:{_address(request)}")
    form = await _form_by_code(code)
    _web_on(form)
    if form["kind"] != "form":
        raise R.FormError("wrong_kind", "To jest lista - zaznacz w wierszu.", 400)
    device = R.clean_device_id(body.get("device_id"))
    ctx = await S.public_context(form)
    judge_id = _s(body.get("judge_id")) or None
    guest_name: Optional[str] = None
    if judge_id:
        if judge_id not in ctx.circles.participants:
            raise R.FormError("not_participant", "Tego sędziego nie ma na liście.", 404)
    else:
        if not ctx.circles.open:
            raise R.FormError("not_open", "Wybierz siebie z listy - ten formularz nie jest otwarty dla gości.", 403)
        guest_name = R.clean_guest_name(body.get("guest_name"))
    meta = S.Meta(ip=_address(request), user_agent=(request.headers.get("user-agent") or "")[:300] or None,
                  device_id=device, geo=R.clean_geo(body.get("geo")))
    entry = await S.write_answers(
        form, judge_id=judge_id, guest_name=guest_name,
        answers=body.get("answers") if isinstance(body.get("answers"), Mapping) else {},
        client_id=body.get("client_id"), fill=body.get("fill_seconds"), source="web", actor_id=None, meta=meta,
        force=bool(body.get("force")),
    )
    await S.load_entries(ctx)
    return {
        "ok": True,
        "submitted_at": R.iso(entry.get("submitted_at")),
        "confirmation": (form.get("settings_json") or {}).get("confirmation"),
        "row": public_row(ctx, judge_id, with_cells=False) if judge_id else None,
    }


@router.get("/{code}/files/{token}", summary="Obraz przy pytaniu formularza (tylko pliki pytań, nie odpowiedzi)")
async def public_question_image(code: str, token: str):
    from fastapi.responses import FileResponse

    form = await _form_by_code(code)
    _web_on(form)
    row = await database.fetch_one(
        select(S.UPLOADS).where(and_(S.UPLOADS.c.form_id == form["id"], S.UPLOADS.c.token == _s(token),
                                     S.UPLOADS.c.purpose == "question"))
    )
    path = S.upload_path(form["id"], row["token"]) if row else None
    if not row or not path.exists() or not _s(row["mime"]).startswith("image/"):
        raise R.FormError("file_not_found", "Nie ma takiego pliku.", 404)
    return FileResponse(str(path), media_type=_s(row["mime"]), headers={"Cache-Control": "public, max-age=86400"})


# ---------------------------------------------------------------------------
# Logowanie QR
# ---------------------------------------------------------------------------


@router.post("/{code}/qr", summary="Kod QR do zatwierdzenia w aplikacji (logowanie strony)")
async def qr_start(code: str, request: Request) -> Dict[str, Any]:
    _limit(QR_LIMITER, f"q:{_address(request)}")
    form = await _form_by_code(code)
    _web_on(form)
    poll_token = secrets.token_urlsafe(24)
    moment = S.now()
    for _ in range(6):
        pair = R.new_code()
        if await database.fetch_one(select(S.PAIRS.c.code).where(S.PAIRS.c.code == pair)):
            continue
        await database.execute(
            insert(S.PAIRS).values(
                code=pair, poll_token_hash=_hash(poll_token), form_id=form["id"], status="pending",
                created_at=moment, expires_at=moment + R.PAIR_TTL, ip=_address(request),
                user_agent=(request.headers.get("user-agent") or "")[:300] or None,
            )
        )
        break
    else:
        raise R.FormError("qr_unavailable", "Nie udało się utworzyć kodu. Spróbuj ponownie.", 503)
    return {"pair_code": pair, "poll_token": poll_token, "qr_url": R.pair_url(pair),
            "expires_at": (moment + R.PAIR_TTL).isoformat()}


def _pair_status(row: Optional[Mapping[str, Any]], moment: datetime) -> str:
    if not row or row.get("status") in ("used", "expired"):
        return "expired"
    if row.get("status") == "approved":
        return "approved"
    expires = R.aware(row.get("expires_at"))
    return "expired" if not expires or expires <= moment else "pending"


def issue_token(judge_id: str, name: str, form_id: str) -> str:
    import jwt as pyjwt

    from app.deps import get_settings

    settings = get_settings()
    moment = S.now()
    payload = {
        "sub": f"form-web:{judge_id}",
        "judge_id": judge_id,
        "account_type": "judge",
        "display_name": name,
        "scope": FORM_WEB_SCOPE,
        "form_id": form_id,
        "iat": int(moment.timestamp()),
        "exp": int((moment + timedelta(hours=R.WEB_TOKEN_HOURS)).timestamp()),
    }
    return pyjwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


@router.get("/qr/{pair_code}", summary="Długie odpytywanie: czy telefon zatwierdził logowanie")
async def qr_poll(pair_code: str, poll_token: str = Query("", max_length=200), wait: int = Query(20, ge=0, le=QR_POLL_MAX_S)) -> Dict[str, Any]:
    clean = R.normalize_code(pair_code)
    row = await database.fetch_one(select(S.PAIRS).where(S.PAIRS.c.code == clean)) if clean else None
    pair = S._row(row) if row else None
    if not pair or not poll_token or not hmac.compare_digest(_hash(poll_token), _s(pair.get("poll_token_hash"))):
        raise R.FormError("pair_not_found", "Ten kod nie istnieje albo wygasł.", 404)
    deadline = time.monotonic() + wait
    status = _pair_status(pair, S.now())
    while status == "pending" and time.monotonic() < deadline:
        event = pair_events.setdefault(clean, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), timeout=min(2.0, max(0.05, deadline - time.monotonic())))
        except asyncio.TimeoutError:
            pass
        pair = S._row(await database.fetch_one(select(S.PAIRS).where(S.PAIRS.c.code == clean)))
        status = _pair_status(pair, S.now())
    if status != "approved":
        if status == "expired":
            pair_events.pop(clean, None)
        return {"status": status}
    await database.execute(
        update(S.PAIRS).where(and_(S.PAIRS.c.code == clean, S.PAIRS.c.status == "approved")).values(status="used")
    )
    pair_events.pop(clean, None)
    judge_id = _s(pair.get("judge_id"))
    name = _s(pair.get("judge_name"))
    return {
        "status": "approved",
        "token": issue_token(judge_id, name, pair["form_id"]),
        "judge": {"judge_id": judge_id, "name": name},
        "form_id": pair["form_id"],
    }

