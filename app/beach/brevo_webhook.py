"""
Brevo transactional webhook (BEACH).

POST /beach/webhooks/brevo/transactional — records delivery events and flags
addresses on hard bounces / invalid recipients. Protected by a shared secret
(``BREVO_WEBHOOK_SECRET``) passed either as ``?secret=`` or the
``X-Webhook-Secret`` header. The payload is never fully trusted nor logged.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import and_, select, update

from app.db import database, beach_users, beach_email_delivery_events
from app.beach.email_config import get_email_config
from app.beach.email_masking import mask_email
from app.beach.email_normalization import normalize_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/webhooks/brevo", tags=["Beach: Brevo Webhook"])

_HANDLED_EVENTS = {"delivered", "hard_bounce", "soft_bounce", "blocked", "spam", "invalid"}
_BLOCKING_EVENTS = {"hard_bounce", "invalid"}


def _secret_ok(qs_secret: Optional[str], header_secret: Optional[str]) -> bool:
    configured = get_email_config().webhook_secret
    if not configured:
        # No secret configured → reject (fail closed).
        return False
    provided = (qs_secret or header_secret or "").strip()
    return bool(provided) and provided == configured


@router.post("/transactional", summary="Webhook zdarzeń transakcyjnych Brevo")
async def brevo_transactional(
    request: Request,
    secret: Optional[str] = Query(default=None),
    x_webhook_secret: Optional[str] = Header(default=None),
):
    if not _secret_ok(secret, x_webhook_secret):
        return JSONResponse(status_code=401, content={"success": False})

    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"success": False})

    event = str(payload.get("event") or "").strip().lower()
    email = (payload.get("email") or "").strip()
    message_id = str(payload.get("message-id") or payload.get("messageId") or "") or None

    # Persist every event we understand (ignore unknown noise).
    if event in _HANDLED_EVENTS:
        try:
            await database.execute(
                beach_email_delivery_events.insert().values(
                    id=uuid.uuid4(),
                    provider="brevo",
                    event=event,
                    email=email or None,
                    message_id=message_id,
                    payload_json=payload,
                    created_at=datetime.now(timezone.utc),
                )
            )
        except Exception:
            logger.exception("brevo webhook: failed to persist event")

    # Flag delivery-blocked addresses, but never un-verify an already-verified user.
    if event in _BLOCKING_EVENTS and email:
        try:
            await database.execute(
                update(beach_users)
                .where(
                    and_(
                        beach_users.c.email_normalized == normalize_email(email),
                        beach_users.c.email_verified.is_(False),
                    )
                )
                .values(email_delivery_blocked=True, updated_at=datetime.now(timezone.utc))
            )
        except Exception:
            logger.exception("brevo webhook: failed to flag delivery-blocked")

    logger.info("brevo_webhook event=%s email=%s", event or "unknown", mask_email(email))
    return {"success": True}
