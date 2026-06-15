"""
Brevo transactional-email client (REST API, no SMTP).

Sends the verification code via ``POST https://api.brevo.com/v3/smtp/email``.
The API key is read from configuration and is NEVER logged. Raw Brevo error
bodies are never surfaced to the end user.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.beach.email_config import get_email_config

logger = logging.getLogger(__name__)

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
_TIMEOUT_SECONDS = 15.0
_SUCCESS_STATUSES = {200, 201, 202}


class EmailDeliveryError(Exception):
    """Raised when Brevo delivery fails. ``kind`` drives HTTP mapping upstream.

    kind ∈ {"timeout", "network", "config", "rate_limited", "server", "integration"}
    """

    def __init__(self, message: str, *, kind: str = "unknown", status_code: Optional[int] = None):
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code


def email_delivery_to_http(exc: "EmailDeliveryError") -> tuple[int, str]:
    """Map a Brevo ``EmailDeliveryError`` to (http_status, user-facing message)."""
    if exc.kind == "rate_limited":
        return 503, "Zbyt wiele prób wysyłki. Spróbuj ponownie za chwilę."
    return 503, "Nie udało się wysłać kodu weryfikacyjnego. Spróbuj ponownie później."


def _classify_status(status_code: int) -> str:
    if status_code in (401, 403):
        return "config"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 500:
        return "server"
    return "integration"


def _build_html(code: str, expires_minutes: int, app_name: str) -> str:
    spaced = " ".join(list(code))
    return f"""<!DOCTYPE html>
<html lang="pl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#0B0E14;color:#E6EAF2;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0B0E14;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:440px;background-color:#141A24;border:1px solid #232C3A;border-radius:18px;overflow:hidden;">
        <tr><td style="padding:28px 28px 8px 28px;" align="center">
          <div style="font-size:18px;font-weight:800;color:#FFFFFF;letter-spacing:0.3px;">{app_name}</div>
          <div style="margin-top:6px;font-size:13px;color:#8A95A8;">Potwierdzenie adresu e-mail</div>
        </td></tr>
        <tr><td style="padding:8px 28px 0 28px;" align="center">
          <div style="font-size:14px;line-height:21px;color:#C2CAD8;">
            Użyj poniższego kodu, aby potwierdzić swój adres e-mail.
          </div>
        </td></tr>
        <tr><td style="padding:22px 28px;" align="center">
          <div style="display:inline-block;background-color:#0B0E14;border:1px solid #2A3445;border-radius:14px;padding:18px 26px;">
            <span style="font-size:34px;font-weight:900;letter-spacing:12px;color:#4FD1C5;font-family:'Courier New',monospace;">{spaced}</span>
          </div>
        </td></tr>
        <tr><td style="padding:0 28px 8px 28px;" align="center">
          <div style="font-size:13px;color:#8A95A8;">Kod jest ważny przez {expires_minutes} minut.</div>
        </td></tr>
        <tr><td style="padding:18px 28px 26px 28px;" align="center">
          <div style="font-size:12px;line-height:18px;color:#6B7587;">
            Jeśli to nie Ty zakładałeś konto, zignoruj tę wiadomość — nic się nie stanie.
          </div>
        </td></tr>
      </table>
      <div style="margin-top:16px;font-size:11px;color:#4A5365;">Wiadomość wygenerowana automatycznie — nie odpowiadaj na nią.</div>
    </td></tr>
  </table>
</body>
</html>"""


def _build_text(code: str, expires_minutes: int, app_name: str) -> str:
    return (
        f"{app_name} — potwierdzenie adresu e-mail\n\n"
        f"Twój kod weryfikacyjny: {code}\n"
        f"Kod jest ważny przez {expires_minutes} minut.\n\n"
        "Jeśli to nie Ty zakładałeś konto, zignoruj tę wiadomość."
    )


async def send_verification_code(
    recipient_email: str,
    recipient_name: Optional[str],
    code: str,
    expires_minutes: int,
) -> str:
    """Send the verification email through Brevo. Returns Brevo ``messageId``.

    Raises ``EmailDeliveryError`` on any failure. Never logs the API key nor the
    full code, and never returns Brevo's raw error body to the caller.
    """
    cfg = get_email_config()
    if not cfg.brevo_api_key or not cfg.from_email:
        raise EmailDeliveryError("Brak konfiguracji nadawcy Brevo", kind="config")

    to_entry: dict = {"email": recipient_email}
    name = (recipient_name or "").strip()
    if name:
        to_entry["name"] = name

    app_name = cfg.from_name or "BAZA Beach"
    payload = {
        "sender": {"name": app_name, "email": cfg.from_email},
        "to": [to_entry],
        "subject": "Kod weryfikacyjny",
        "htmlContent": _build_html(code, expires_minutes, app_name),
        "textContent": _build_text(code, expires_minutes, app_name),
        "tags": ["email-verification"],
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": cfg.brevo_api_key,  # never logged
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.post(BREVO_URL, headers=headers, json=payload)
    except httpx.TimeoutException as exc:
        logger.error("Brevo send timeout")
        raise EmailDeliveryError("Brevo timeout", kind="timeout") from exc
    except httpx.HTTPError as exc:
        logger.error("Brevo network error: %s", type(exc).__name__)
        raise EmailDeliveryError("Brevo network error", kind="network") from exc

    if resp.status_code in _SUCCESS_STATUSES:
        message_id: Optional[str] = None
        try:
            message_id = resp.json().get("messageId")
        except Exception:
            message_id = None
        logger.info("Brevo send ok status=%s messageId=%s", resp.status_code, message_id)
        return str(message_id or "")

    kind = _classify_status(resp.status_code)
    # Log status only — never the body (may echo payload) nor the key.
    logger.error("Brevo send failed status=%s kind=%s", resp.status_code, kind)
    raise EmailDeliveryError(
        "Brevo delivery failed", kind=kind, status_code=resp.status_code
    )
