from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from app.db import database, beach_users

logger = logging.getLogger(__name__)


def _parse_jsonish(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return fallback
    return fallback


def _display_roles(roles: Any) -> List[Dict[str, Any]]:
    parsed = _parse_jsonish(roles, [])
    if not isinstance(parsed, list):
        return []

    status_rank = {"approved": 3, "pending": 2, "rejected": 1}
    by_type: Dict[str, Dict[str, Any]] = {}

    for raw in parsed:
        role: Optional[Dict[str, Any]]
        if isinstance(raw, str):
            if raw not in {"judge", "coach", "player"}:
                continue
            role = {"type": raw, "verified": "approved"}
        elif isinstance(raw, dict):
            role = raw
        else:
            continue

        role_type = role.get("type")
        if role_type not in {"judge", "coach", "player"}:
            continue

        current = by_type.get(role_type)
        if not current:
            by_type[role_type] = role
            continue

        role_status = str(role.get("verified") or "")
        current_status = str(current.get("verified") or "")
        role_rank = status_rank.get(role_status, 0)
        current_rank = status_rank.get(current_status, 0)
        role_linked = bool(role.get("judge_id") or role.get("person_id") or role.get("player_id"))
        current_linked = bool(
            current.get("judge_id") or current.get("person_id") or current.get("player_id")
        )
        if role_rank > current_rank or (role_rank == current_rank and role_linked and not current_linked):
            by_type[role_type] = role

    return list(by_type.values())


def _has_approved_role(roles: Any) -> bool:
    return any(role.get("verified") == "approved" for role in _display_roles(roles))


def _pct(value: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(value / total) * 100:.1f}%"


def _discord_bar(value: int, total: int, width: int = 12) -> str:
    if total <= 0:
        return "░" * width
    filled = round((value / total) * width)
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


async def build_beach_account_report_payload(now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    user_rows = await database.fetch_all(
        select(
            beach_users.c.id,
            beach_users.c.roles,
            beach_users.c.email_verified,
            beach_users.c.email_verified_at,
        ).where(beach_users.c.is_active == True)  # noqa: E712
    )

    verified_with_role = 0
    role_unverified = 0
    verified_no_role = 0
    rest = 0
    # Udane, samodzielne weryfikacje e-mail z ostatniej doby.
    email_verified_24h = 0

    for row in user_rows:
        has_role = _has_approved_role(row["roles"])
        email_verified = bool(row["email_verified"])
        if has_role and email_verified:
            verified_with_role += 1
        elif has_role:
            role_unverified += 1
        elif email_verified:
            verified_no_role += 1
        else:
            rest += 1

        if email_verified:
            ev_at = row["email_verified_at"]
            if ev_at is not None:
                if ev_at.tzinfo is None:
                    ev_at = ev_at.replace(tzinfo=timezone.utc)
                if ev_at >= since:
                    email_verified_24h += 1

    total = len(user_rows)
    email_verified_total = verified_with_role + verified_no_role
    fields = [
        {
            "name": "✅ Zweryfikowane z rolą",
            "value": f"**{verified_with_role}** ({_pct(verified_with_role, total)})\n`{_discord_bar(verified_with_role, total)}`",
            "inline": False,
        },
        {
            "name": "🟠 Z rolą, bez weryfikacji e-mail",
            "value": f"**{role_unverified}** ({_pct(role_unverified, total)})\n`{_discord_bar(role_unverified, total)}`",
            "inline": False,
        },
        {
            "name": "🟦 Zweryfikowane bez roli",
            "value": f"**{verified_no_role}** ({_pct(verified_no_role, total)})\n`{_discord_bar(verified_no_role, total)}`",
            "inline": False,
        },
        {
            "name": "⚪ Bez roli i weryfikacji",
            "value": f"**{rest}** ({_pct(rest, total)})\n`{_discord_bar(rest, total)}`",
            "inline": False,
        },
        {
            "name": "📧 Potwierdzone e-maile w 24h",
            "value": (
                f"**{email_verified_24h}** w ostatniej dobie\n"
                f"Łącznie zweryfikowanych: **{email_verified_total}**"
            ),
            "inline": False,
        },
    ]

    return {
        "embeds": [
            {
                "title": "📊 BAZA Beach — dzienny stan kont",
                "description": f"Aktywne konta: **{total}**",
                "color": 3447999,
                "fields": fields,
                "timestamp": now.isoformat(),
                "footer": {"text": "Raport automatyczny • BAZA Beach"},
            }
        ]
    }


def _send_webhook_sync(url: str, payload: Dict[str, Any]) -> None:
    if "hooks.slack.com" in url:
        embed = (payload.get("embeds") or [{}])[0]
        lines = [embed.get("title") or "BAZA Beach report", embed.get("description") or ""]
        for field in embed.get("fields") or []:
            lines.append(f"{field.get('name')}: {field.get('value')}")
        payload = {"text": "\n".join(lines)}

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "BAZA-Beach-DailyReport/1.0 (zprp-backend)",
        },
    )
    urllib.request.urlopen(req, timeout=10)


async def send_daily_beach_account_report(webhook_url: Optional[str] = None) -> bool:
    url = (
        webhook_url
        or os.getenv("BEACH_DAILY_ACCOUNT_REPORT_WEBHOOK_URL")
        or os.getenv("BACKUP_NOTIFY_WEBHOOK_URL")
    )
    if not url:
        return False

    payload = await build_beach_account_report_payload()
    try:
        await asyncio.to_thread(_send_webhook_sync, url, payload)
        logger.info("Beach daily account report sent")
        return True
    except Exception as exc:
        logger.warning("Beach daily account report webhook failed: %s", exc)
        return False
