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


def _logo_url() -> str:
    base = (get_email_config().app_public_url or "").rstrip("/")
    return f"{base}/beach/auth/assets/logo.png" if base else ""


def _build_html(
    code: str,
    expires_minutes: int,
    app_name: str,
    *,
    heading: str = "Weryfikacja konta",
    intro: str = "Cześć! Użyj poniższego kodu, aby potwierdzić swój adres e-mail i dokończyć zakładanie konta.",
) -> str:
    spaced = " ".join(list(code))
    logo_url = _logo_url()
    logo_block = (
        f'<img src="{logo_url}" width="84" height="84" alt="{app_name}" '
        'style="width:84px;height:84px;display:block;margin:0 auto 10px auto;border:0;outline:none;">'
        if logo_url
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="pl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#F4F6FA;color:#1A2233;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#F4F6FA;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:460px;background-color:#FFFFFF;border:1px solid #E6EAF0;border-radius:20px;overflow:hidden;box-shadow:0 6px 24px rgba(20,30,50,0.06);">
        <!-- Header band -->
        <tr><td style="background:linear-gradient(135deg,#FF8A3D 0%,#FF6A4A 100%);padding:26px 28px 22px 28px;" align="center">
          {logo_block}
          <div style="font-size:19px;font-weight:800;color:#FFFFFF;letter-spacing:0.3px;">{app_name}</div>
          <div style="margin-top:4px;font-size:13px;color:rgba(255,255,255,0.92);">{heading}</div>
        </td></tr>
        <!-- Intro -->
        <tr><td style="padding:26px 30px 6px 30px;" align="center">
          <div style="font-size:15px;line-height:22px;color:#41506A;">
            {intro}
          </div>
        </td></tr>
        <!-- Code -->
        <tr><td style="padding:20px 30px 6px 30px;" align="center">
          <div style="display:inline-block;background-color:#FFF4EC;border:1px solid #FFD3B8;border-radius:14px;padding:16px 24px;">
            <span style="font-size:34px;font-weight:900;letter-spacing:12px;color:#E0531F;font-family:'Courier New',Courier,monospace;">{spaced}</span>
          </div>
          <div style="margin-top:12px;font-size:13px;color:#6B7587;">Kod jest ważny przez <strong style="color:#41506A;">{expires_minutes} minut</strong>.</div>
        </td></tr>
        <!-- Spam note -->
        <tr><td style="padding:18px 30px 4px 30px;">
          <div style="background-color:#F4F6FA;border-radius:12px;padding:12px 14px;font-size:12.5px;line-height:18px;color:#55617A;">
            📁 Nie widzisz wiadomości? Sprawdź folder <strong>SPAM / Oferty</strong> i oznacz ją jako „nie spam”, aby kolejne kody trafiały do skrzynki odbiorczej.
          </div>
        </td></tr>
        <!-- Ignore note -->
        <tr><td style="padding:14px 30px 28px 30px;" align="center">
          <div style="font-size:12px;line-height:18px;color:#8A93A6;">
            Jeśli to nie Ty zakładałeś konto, po prostu zignoruj tę wiadomość — nic się nie stanie.
          </div>
        </td></tr>
      </table>
      <div style="margin-top:16px;font-size:11px;color:#A2AAB8;">Wiadomość wygenerowana automatycznie — nie odpowiadaj na nią.</div>
    </td></tr>
  </table>
</body>
</html>"""


def _build_text(
    code: str,
    expires_minutes: int,
    app_name: str,
    *,
    heading: str = "weryfikacja konta",
    closing: str = "Jeśli to nie Ty zakładałeś konto, zignoruj tę wiadomość.",
) -> str:
    return (
        f"{app_name} — {heading}\n\n"
        f"Twój kod: {code}\n"
        f"Kod jest ważny przez {expires_minutes} minut.\n\n"
        "Nie widzisz wiadomości? Sprawdź folder SPAM/Oferty.\n"
        f"{closing}"
    )


async def send_verification_code(
    recipient_email: str,
    recipient_name: Optional[str],
    code: str,
    expires_minutes: int,
) -> str:
    """Wyślij kod weryfikacji adresu e-mail. Returns Brevo ``messageId``."""
    return await _send_code_email(
        recipient_email,
        recipient_name,
        code,
        expires_minutes,
        subject="BAZA Beach - weryfikacja konta",
        heading="Weryfikacja konta",
        intro="Cześć! Użyj poniższego kodu, aby potwierdzić swój adres e-mail i dokończyć zakładanie konta.",
        text_heading="weryfikacja konta",
        text_closing="Jeśli to nie Ty zakładałeś konto, zignoruj tę wiadomość.",
        tag="email-verification",
    )


async def send_password_reset_code(
    recipient_email: str,
    recipient_name: Optional[str],
    code: str,
    expires_minutes: int,
) -> str:
    """Wyślij kod resetu hasła. Returns Brevo ``messageId``."""
    return await _send_code_email(
        recipient_email,
        recipient_name,
        code,
        expires_minutes,
        subject="BAZA Beach - reset hasła",
        heading="Reset hasła",
        intro="Otrzymaliśmy prośbę o reset hasła do Twojego konta. Użyj poniższego kodu, aby ustawić nowe hasło.",
        text_heading="reset hasła",
        text_closing="Jeśli to nie Ty prosiłeś o reset hasła, zignoruj tę wiadomość — hasło pozostanie bez zmian.",
        tag="password-reset",
    )


async def _send_code_email(
    recipient_email: str,
    recipient_name: Optional[str],
    code: str,
    expires_minutes: int,
    *,
    subject: str,
    heading: str,
    intro: str,
    text_heading: str,
    text_closing: str,
    tag: str,
) -> str:
    """Send a code e-mail through Brevo. Returns Brevo ``messageId``.

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
        "subject": subject,
        "htmlContent": _build_html(code, expires_minutes, app_name, heading=heading, intro=intro),
        "textContent": _build_text(code, expires_minutes, app_name, heading=text_heading, closing=text_closing),
        "tags": [tag],
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
