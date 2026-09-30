"""Kolizja niedyspozycyjności z meczem centralnym ZPRP.

Moduł ma dwa zadania:

* przechowuje globalną konfigurację kategorii i skrzynki obsadowego;
* trzyma trwałą kolejkę wiadomości Brevo. Zapis w ZPRP i zapis koperty w bazie
  kończą żądanie telefonu, a dostarczenie może być ponawiane po restarcie.

Nie przechowujemy haseł ani tokenów. W kolejce zostają wyłącznie dane, które
użytkownik zobaczył na ekranie potwierdzenia.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.admin_guard import admin_write_guard, bearer_token, decode_token
from app.beach.email_config import get_email_config
from app.mail_brand import NIEDYSPO_SENDER_EMAIL, brand_cell
from app.zprp_unavailability_rules import conflict_when, is_tentative, subject_prefix
from app.db import (
    database,
    province_judges,
    zprp_unavailability_mail_outbox as OUTBOX,
    zprp_unavailability_settings as SETTINGS,
)
from app.extra_report_discord import normalize_webhook_url
from app.zprp_accounts import normalize_province

log = logging.getLogger(__name__)

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
SUCCESS = {200, 201, 202}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")

# II liga i wszystkie szczeble ponad nią, rozgrywki mistrzowskie i pucharowe.
# Kolejność jest taka sama jak w panelu - od imprez do lig.
DEFAULT_CATEGORIES = [
    "MP",
    "PP",
    "SPM",
    "SPK",
    "OSM",
    "OSK",
    "SM",
    "SK",
    "LCM",
    "LCK",
    "IM",
    "IK",
    "IIM",
    "IIK",
]

# Najdłuższe / bardziej szczegółowe kody muszą wygrać przed krótszymi.
ALL_CATEGORY_PRIORITY = [
    "MłM1213",
    "MłK1213",
    "IIIM",
    "IIIK",
    "IIM",
    "IIK",
    "LCM",
    "LCK",
    "OSM",
    "OSK",
    "SPM",
    "SPK",
    "JmM",
    "JmK",
    "MłM",
    "MłK",
    "MP",
    "PP",
    "JM",
    "JK",
    "IM",
    "IK",
    "SM",
    "SK",
]

admin_router = APIRouter(
    prefix="/admin/zprp-unavailability",
    tags=["Niedyspozycje ZPRP: admin"],
    dependencies=[Depends(admin_write_guard)],
)
public_router = APIRouter(
    prefix="/zprp-unavailability", tags=["Niedyspozycje ZPRP"]
)


class SettingsBody(BaseModel):
    recipientEmails: list[str] = Field(default_factory=list)
    # Zgodność z pierwszą wersją klienta.
    recipientEmail: str = ""
    senderEmail: str = NIEDYSPO_SENDER_EMAIL
    senderName: str = "Niedyspo BAZA"
    discordWebhookUrl: str = ""
    provinceCc: dict[str, list[str]] = Field(default_factory=dict)
    categories: list[str] = Field(default_factory=lambda: list(DEFAULT_CATEGORIES))


class ConflictMatch(BaseModel):
    id: str = ""
    code: str
    category: str = ""
    startAt: str = ""
    home: str = ""
    away: str = ""
    role: str = ""
    # Mecz bez daty: możliwa kolizja z terminu kolejki (okno dni ISO).
    tentative: bool = False
    windowStart: str = ""
    windowEnd: str = ""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _email(value: Any, *, required: bool) -> str:
    email = _clean(value).lower()
    if not email and not required:
        return ""
    if not EMAIL_RE.match(email):
        raise HTTPException(422, detail="Podaj poprawny adres e-mail.")
    return email


def normalize_categories(raw: Iterable[Any]) -> list[str]:
    known = set(ALL_CATEGORY_PRIORITY)
    out: list[str] = []
    for value in raw or []:
        category = _clean(value)
        if category in known and category not in out:
            out.append(category)
    return out


def detect_category(code: Any) -> str:
    text = _clean(code).upper()
    # Zachowujemy wielkość liter kodu wyjściowego, lecz porównujemy bez niej.
    for category in ALL_CATEGORY_PRIORITY:
        if category.upper() in text:
            return category
    # Stare aliasy dzieci, potrzebne tylko po to, by nie uznać ich za centralne.
    if "DZM" in text:
        return "MłM1213"
    if "DZK" in text:
        return "MłK1213"
    return "Pozostałe"


async def _settings_row() -> dict[str, Any]:
    row = await database.fetch_one(select(SETTINGS).where(SETTINGS.c.id == 1))
    if row:
        result = dict(row)
        if not result.get("categories"):
            result["categories"] = list(DEFAULT_CATEGORIES)
        return result

    values = {
        "id": 1,
        "recipient_email": "",
        "recipient_emails": [],
        "sender_email": NIEDYSPO_SENDER_EMAIL,
        "sender_name": "Niedyspo BAZA",
        "categories": list(DEFAULT_CATEGORIES),
        "discord_webhook_url": "",
        "province_cc": {},
    }
    try:
        await database.execute(
            pg_insert(SETTINGS)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SETTINGS.c.id])
        )
    except Exception:
        # Testy czystych reguł mogą korzystać z SQLite.
        try:
            await database.execute(SETTINGS.insert().values(**values))
        except Exception:
            pass
    row = await database.fetch_one(select(SETTINGS).where(SETTINGS.c.id == 1))
    return dict(row) if row else values


def _settings_payload(row: dict[str, Any]) -> dict[str, Any]:
    recipients: list[str] = []
    for raw in list(row.get("recipient_emails") or []) + [row.get("recipient_email")]:
        email = _clean(raw).lower()
        if EMAIL_RE.match(email) and email not in recipients:
            recipients.append(email)
    return {
        "recipientEmail": recipients[0] if recipients else "",
        "recipientEmails": recipients,
        "senderEmail": _clean(row.get("sender_email")) or NIEDYSPO_SENDER_EMAIL,
        "senderName": _clean(row.get("sender_name")) or "Niedyspo BAZA",
        "categories": normalize_categories(row.get("categories") or DEFAULT_CATEGORIES),
        # URL wraca do panelu administratora, bo musi dać się edytować. Nigdy
        # nie trafia do logów ani publicznych komunikatów błędu.
        "discordWebhookUrl": _clean(row.get("discord_webhook_url")),
        "discordConfigured": bool(_clean(row.get("discord_webhook_url"))),
        "provinceCc": {
            _clean(province): [
                _clean(email)
                for email in emails or []
                if EMAIL_RE.match(_clean(email))
            ]
            for province, emails in dict(row.get("province_cc") or {}).items()
            if _clean(province)
        },
        "configured": bool(
            recipients
            or _clean(row.get("discord_webhook_url"))
        ),
        "updatedAt": (
            row.get("updated_at").isoformat()
            if hasattr(row.get("updated_at"), "isoformat")
            else row.get("updated_at")
        ),
    }


@public_router.get("/config", summary="Publiczna reguła kolizji z obsadą centralną")
async def get_public_settings() -> dict[str, Any]:
    payload = _settings_payload(await _settings_row())
    # Webhook jest sekretem wykonawczym Discorda. Telefon potrzebuje tylko
    # informacji, czy kanał jest aktywny; pełny URL wraca wyłącznie z endpointu
    # administratora.
    payload["discordWebhookUrl"] = ""
    return payload


@admin_router.get("/config", summary="Konfiguracja alertów niedyspozycji")
async def get_admin_settings() -> dict[str, Any]:
    return _settings_payload(await _settings_row())


@admin_router.put("/config", summary="Zapis konfiguracji alertów niedyspozycji")
async def save_admin_settings(
    body: SettingsBody,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    recipients: list[str] = []
    for raw in list(body.recipientEmails or []) + [body.recipientEmail]:
        email = _email(raw, required=False)
        if email and email not in recipients:
            recipients.append(email)
    sender = _email(body.senderEmail, required=True)
    sender_name = _clean(body.senderName)
    if len(sender_name) < 2:
        raise HTTPException(422, detail="Nazwa nadawcy jest zbyt krótka.")
    categories = normalize_categories(body.categories)
    if not categories:
        raise HTTPException(422, detail="Włącz co najmniej jedną kategorię rozgrywek.")

    try:
        webhook = normalize_webhook_url(body.discordWebhookUrl)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from None

    province_cc: dict[str, list[str]] = {}
    for raw_province, raw_emails in body.provinceCc.items():
        province = normalize_province(raw_province)
        emails: list[str] = []
        for raw_email in raw_emails or []:
            email = _email(raw_email, required=True)
            if email not in emails:
                emails.append(email)
        if province and emails:
            province_cc[province] = emails

    payload, _ = decode_token(bearer_token(authorization))
    actor = _clean((payload or {}).get("judge_id")) or None
    values = {
        "recipient_email": recipients[0] if recipients else "",
        "recipient_emails": recipients,
        "sender_email": sender,
        "sender_name": sender_name,
        "categories": categories,
        "discord_webhook_url": webhook,
        "province_cc": province_cc,
        "updated_by": actor,
        "updated_at": datetime.now(timezone.utc),
    }
    try:
        await database.execute(
            pg_insert(SETTINGS)
            .values(id=1, **values)
            .on_conflict_do_update(index_elements=[SETTINGS.c.id], set_=values)
        )
    except Exception:
        existing = await database.fetch_one(select(SETTINGS).where(SETTINGS.c.id == 1))
        if existing:
            await database.execute(update(SETTINGS).where(SETTINGS.c.id == 1).values(**values))
        else:
            await database.execute(SETTINGS.insert().values(id=1, **values))

    # Koperty zatrzymane z powodu braku odbiorcy ruszą natychmiast po zapisie.
    await database.execute(
        update(OUTBOX)
        .where(OUTBOX.c.status == "waiting_config")
        .values(status="pending", due_at=datetime.now(timezone.utc), last_error=None)
    )
    wake_mail_scheduler()
    return _settings_payload(await _settings_row())


def central_conflicts(
    matches: Iterable[ConflictMatch | dict[str, Any]], categories: Iterable[str]
) -> list[dict[str, Any]]:
    enabled = set(normalize_categories(categories))
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in matches or []:
        item = raw.model_dump() if isinstance(raw, BaseModel) else dict(raw or {})
        code = _clean(item.get("code"))
        category = detect_category(code)
        if category not in enabled:
            continue
        key = _clean(item.get("id")) or f"{code}|{_clean(item.get('startAt'))}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "id": _clean(item.get("id")),
                "code": code,
                "category": category,
                "startAt": _clean(item.get("startAt")),
                "home": _clean(item.get("home")),
                "away": _clean(item.get("away")),
                "role": _clean(item.get("role")),
                **(
                    {
                        "tentative": True,
                        "windowStart": _clean(item.get("windowStart")),
                        "windowEnd": _clean(item.get("windowEnd")),
                    }
                    if is_tentative(item)
                    else {}
                ),
            }
        )
    return out


async def enqueue_overlap_mail(
    *,
    request_id: str,
    judge_id: str,
    judge_name: str,
    province: str,
    date_from: date,
    date_to: date,
    reason: str,
    matches: Iterable[ConflictMatch | dict[str, Any]],
) -> dict[str, Any]:
    """Zapisz kopertę idempotentnie. Wywoływane dopiero po sukcesie w ZPRP."""
    cfg = await _settings_row()
    filtered = central_conflicts(matches, cfg.get("categories") or DEFAULT_CATEGORIES)
    if not filtered:
        return {"queued": False, "matches": 0, "status": "not_required"}

    rid = _clean(request_id)
    if not rid:
        # Stare aplikacje nie wysyłają request_id. Deduplikacja nadal obejmuje
        # treść jednego zapisu, lecz nowa aplikacja zawsze używa UUID.
        rid = f"legacy:{judge_id}:{date_from.isoformat()}:{date_to.isoformat()}:{'|'.join(m['id'] or m['code'] for m in filtered)}"
    # Okręg rozstrzyga rejestr sędziów na serwerze. Wartość z telefonu jest
    # tylko awaryjnym fallbackiem dla osoby, której nie ma jeszcze w rejestrze.
    # Dzięki temu DW nie zależy od okręgu meczu ani od hali.
    registered = await database.fetch_one(
        select(province_judges.c.province).where(
            province_judges.c.judge_id == _clean(judge_id)
        )
    )
    registered_province = (
        normalize_province(dict(registered).get("province")) if registered else ""
    )
    reporter_province = registered_province or normalize_province(province)
    values = {
        "request_id": rid[:180],
        "judge_id": _clean(judge_id),
        "judge_name": _clean(judge_name) or f"Sędzia {judge_id}",
        "province": reporter_province or None,
        "date_from": date_from,
        "date_to": date_to,
        "reason": _clean(reason),
        "matches_json": filtered,
        "status": "pending",
        "due_at": datetime.now(timezone.utc),
    }
    try:
        await database.execute(
            pg_insert(OUTBOX)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[OUTBOX.c.request_id])
        )
    except Exception:
        existing = await database.fetch_one(select(OUTBOX.c.id).where(OUTBOX.c.request_id == values["request_id"]))
        if not existing:
            await database.execute(OUTBOX.insert().values(**values))

    row = await database.fetch_one(select(OUTBOX).where(OUTBOX.c.request_id == values["request_id"]))
    wake_mail_scheduler()
    return {
        "queued": True,
        "matches": len(filtered),
        "status": _clean(dict(row).get("status")) if row else "pending",
        "recipientEmail": _clean(cfg.get("recipient_email")),
    }


def _day(value: Any) -> str:
    if isinstance(value, date):
        return value.strftime("%d.%m.%Y")
    return _clean(value)


def _match_time(value: str) -> str:
    if not value:
        return "Termin bez godziny"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d.%m.%Y · %H:%M")
    except ValueError:
        return value


def render_overlap_email(row: dict[str, Any]) -> tuple[str, str, str]:
    matches = list(row.get("matches_json") or [])
    judge = _clean(row.get("judge_name"))
    judge_id = _clean(row.get("judge_id"))
    subject = f"{subject_prefix(matches)} · {judge}"
    cards = "".join(
        f"""
        <tr><td style="padding:0 26px 12px 26px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #DDE5F0;border-left:4px {'dashed' if is_tentative(m) else 'solid'} #F0A500;border-radius:12px;background:{'#FFFBF2' if is_tentative(m) else '#FFFFFF'};">
            <tr><td style="padding:14px 16px;font-family:Arial,Helvetica,sans-serif;">
              <div style="font-size:11px;font-weight:bold;letter-spacing:1.2px;color:#A36A00;">{html.escape(_clean(m.get('code')))} · {html.escape(_clean(m.get('category')))}{' &nbsp;<span style="display:inline-block;padding:2px 7px;border:1px dashed #F0A500;border-radius:999px;font-size:10px;letter-spacing:0.8px;">MOŻLIWY MECZ</span>' if is_tentative(m) else ''}</div>
              <div style="margin-top:6px;font-size:16px;font-weight:bold;color:#172033;">{html.escape(_clean(m.get('home')))} – {html.escape(_clean(m.get('away')))}</div>
              <div style="margin-top:6px;font-size:13px;color:#5E6B7E;">{html.escape(conflict_when(m, _match_time))}{(' · ' + html.escape(_clean(m.get('role')))) if _clean(m.get('role')) else ''}</div>
            </td></tr>
          </table>
        </td></tr>"""
        for m in matches
    )
    html_body = f"""<!doctype html><html lang="pl"><body style="margin:0;background:#EEF2F8;font-family:Arial,Helvetica,sans-serif;color:#172033;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:30px 14px;background:#EEF2F8;"><tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;background:#F8FAFD;border-radius:18px;overflow:hidden;border:1px solid #DDE5F0;">
        <tr><td style="padding:22px 26px;background:#0D1B2A;color:#FFFFFF;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            {brand_cell("obsi.png", 60, "Niedyspo BAZA")}
            <td valign="middle" style="font-family:Arial,Helvetica,sans-serif;color:#FFFFFF;">
              <div style="font-size:11px;font-weight:bold;letter-spacing:2px;color:#F0A500;">NIEDYSPO BAZA · OBSADA CENTRALNA</div>
              <div style="margin-top:7px;font-size:22px;line-height:28px;font-weight:bold;">Nowa niedyspozycyjność nachodzi na mecz</div>
            </td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:20px 26px 14px 26px;font-size:14px;line-height:22px;">
          <strong>{html.escape(judge)}</strong> (nr {html.escape(judge_id)}) zapisał niedyspozycyjność <strong>{_day(row.get('date_from'))} – {_day(row.get('date_to'))}</strong>.
          <div style="margin-top:10px;padding:11px 13px;border-radius:10px;background:#FFF4DE;color:#704900;"><strong>Powód:</strong> {html.escape(_clean(row.get('reason')))}</div>
        </td></tr>
        {cards}
        <tr><td style="padding:8px 26px 24px 26px;font-size:12px;line-height:18px;color:#6D788A;border-top:1px solid #DDE5F0;">Wiadomość wygenerowana automatycznie po świadomym potwierdzeniu kolizji w aplikacji BAZA.</td></tr>
      </table>
    </td></tr></table></body></html>"""
    text_matches = "\n".join(
        f"- {_clean(m.get('code'))}: {_clean(m.get('home'))} - {_clean(m.get('away'))}, {conflict_when(m, _match_time)}"
        for m in matches
    )
    text_body = (
        f"{judge} (nr {judge_id}) zapisał niedyspozycyjność "
        f"{_day(row.get('date_from'))} - {_day(row.get('date_to'))}.\n"
        f"Powód: {_clean(row.get('reason'))}\n\nMecze w kolizji:\n{text_matches}"
    )
    return subject, html_body, text_body


async def _send_row(row: dict[str, Any], cfg: dict[str, Any]) -> str:
    email_cfg = get_email_config()
    api_key = _clean(email_cfg.brevo_api_key)
    if not api_key:
        raise RuntimeError("Brak klucza Brevo")
    recipients = list(_settings_payload(cfg).get("recipientEmails") or [])
    if not recipients:
        raise LookupError("Brak adresu odbiorcy w konfiguracji Niedyspo ZPRP")
    subject, html_body, text_body = render_overlap_email(row)
    payload = {
        "sender": {
            "email": _clean(cfg.get("sender_email")) or NIEDYSPO_SENDER_EMAIL,
            "name": _clean(cfg.get("sender_name")) or "Niedyspo BAZA",
        },
        "to": [{"email": email} for email in recipients],
        "subject": subject,
        "htmlContent": html_body,
        "textContent": text_body,
        "tags": ["zprp-unavailability-overlap"],
    }
    province = normalize_province(row.get("province"))
    cc = list(dict(cfg.get("province_cc") or {}).get(province) or [])
    cc = [
        email
        for email in cc
        if EMAIL_RE.match(_clean(email)) and _clean(email) not in recipients
    ]
    if cc:
        payload["cc"] = [{"email": email} for email in cc]
    headers = {"api-key": api_key, "accept": "application/json", "content-type": "application/json"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(BREVO_URL, headers=headers, json=payload)
    if response.status_code not in SUCCESS:
        raise RuntimeError(f"Brevo HTTP {response.status_code}")
    try:
        return _clean(response.json().get("messageId"))
    except Exception:
        return ""


async def _send_discord(row: dict[str, Any], cfg: dict[str, Any]) -> str:
    webhook = _clean(cfg.get("discord_webhook_url"))
    if not webhook:
        raise LookupError("Brak webhooka Discord")
    matches = list(row.get("matches_json") or [])
    judge = _clean(row.get("judge_name"))
    lines = []
    for match in matches[:10]:
        code = _clean(match.get("code"))
        teams = " – ".join(filter(None, [_clean(match.get("home")), _clean(match.get("away"))]))
        when = conflict_when(match, _match_time)
        lines.append(f"**{code}** · {when}\n{teams}")
    if len(matches) > 10:
        lines.append(f"…i jeszcze {len(matches) - 10}")
    payload = {
        "username": _clean(cfg.get("sender_name")) or "Niedyspo BAZA",
        "embeds": [
            {
                "title": "Niedyspozycyjność nachodzi na obsadę ZPRP",
                "description": "\n\n".join(lines),
                "color": 15770880,
                "fields": [
                    {"name": "Sędzia", "value": f"{judge} · nr {_clean(row.get('judge_id'))}", "inline": False},
                    {"name": "Zakres", "value": f"{_day(row.get('date_from'))} – {_day(row.get('date_to'))}", "inline": True},
                    {"name": "Powód", "value": _clean(row.get("reason"))[:1024] or "—", "inline": False},
                ],
                "footer": {"text": "BAZA · świadomie potwierdzona kolizja"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
        "allowed_mentions": {"parse": []},
    }
    separator = "&" if "?" in webhook else "?"
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(f"{webhook}{separator}wait=true", json=payload)
    if response.status_code not in SUCCESS:
        raise RuntimeError(f"Discord HTTP {response.status_code}")
    try:
        return _clean(response.json().get("id"))
    except Exception:
        return ""


async def flush_overlap_mail_outbox(limit: int = 10) -> int:
    now = datetime.now(timezone.utc)
    rows = await database.fetch_all(
        select(OUTBOX)
        .where(
            OUTBOX.c.status.in_(["pending", "retry", "waiting_config"]),
            OUTBOX.c.due_at <= now,
        )
        .order_by(OUTBOX.c.id.asc())
        .limit(limit)
    )
    sent = 0
    cfg = await _settings_row()
    for raw in rows:
        row = dict(raw)
        wants_email = bool(_settings_payload(cfg).get("recipientEmails"))
        wants_discord = bool(_clean(cfg.get("discord_webhook_url")))
        if not wants_email and not wants_discord:
            await database.execute(
                update(OUTBOX)
                .where(OUTBOX.c.id == row["id"])
                .values(
                    status="waiting_config",
                    last_error="Brak adresu e-mail i webhooka Discord",
                    due_at=now + timedelta(hours=12),
                    updated_at=now,
                )
            )
            continue
        errors: list[str] = []
        email_sent_at = row.get("email_sent_at")
        discord_sent_at = row.get("discord_sent_at")
        email_message_id = _clean(row.get("brevo_message_id")) or None
        discord_message_id = _clean(row.get("discord_message_id")) or None
        jobs: list[tuple[str, Any]] = []
        if wants_email and not email_sent_at:
            jobs.append(("email", _send_row(row, cfg)))
        if wants_discord and not discord_sent_at:
            jobs.append(("discord", _send_discord(row, cfg)))
        if jobs:
            results = await asyncio.gather(
                *(job for _, job in jobs), return_exceptions=True
            )
            delivered_at = datetime.now(timezone.utc)
            for (channel, _), result in zip(jobs, results):
                if isinstance(result, Exception):
                    errors.append(f"{channel}:{type(result).__name__}")
                elif channel == "email":
                    email_message_id = _clean(result) or None
                    email_sent_at = delivered_at
                else:
                    discord_message_id = _clean(result) or None
                    discord_sent_at = delivered_at

        email_done = (not wants_email) or bool(email_sent_at)
        discord_done = (not wants_discord) or bool(discord_sent_at)
        if email_done and discord_done:
            await database.execute(
                update(OUTBOX)
                .where(OUTBOX.c.id == row["id"])
                .values(
                    status="sent",
                    brevo_message_id=email_message_id,
                    email_sent_at=email_sent_at,
                    discord_message_id=discord_message_id,
                    discord_sent_at=discord_sent_at,
                    sent_at=now,
                    last_error=None,
                    updated_at=now,
                )
            )
            sent += 1
        else:
            attempts = int(row.get("attempts") or 0) + 1
            delay = min(6 * 60 * 60, 30 * (2 ** min(attempts, 9)))
            await database.execute(
                update(OUTBOX)
                .where(OUTBOX.c.id == row["id"])
                .values(
                    status="retry",
                    attempts=attempts,
                    brevo_message_id=email_message_id,
                    email_sent_at=email_sent_at,
                    discord_message_id=discord_message_id,
                    discord_sent_at=discord_sent_at,
                    due_at=now + timedelta(seconds=delay),
                    last_error=", ".join(errors)[:240] or "Kanał niedostarczony",
                    updated_at=now,
                )
            )
            log.warning("Niedyspo ZPRP delivery retry id=%s attempt=%s channels=%s", row["id"], attempts, ",".join(errors))
    return sent


_WAKE = asyncio.Event()


def wake_mail_scheduler() -> None:
    try:
        _WAKE.set()
    except RuntimeError:
        pass


async def run_overlap_mail_scheduler() -> None:
    while True:
        try:
            await flush_overlap_mail_outbox()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Niedyspo ZPRP mail scheduler failed")
        try:
            await asyncio.wait_for(_WAKE.wait(), timeout=30.0)
            _WAKE.clear()
        except asyncio.TimeoutError:
            pass
