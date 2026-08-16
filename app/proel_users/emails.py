# app/proel_users/emails.py
#
# Wysyłka e-maili kont ProEl przez Brevo — to samo konto nadawcy co Beach
# (env BREVO_API_KEY / BREVO_FROM_EMAIL), ale WŁASNE szablony i tagi:
# w skrzynce użytkownika nadawcą sensu jest „ProEl — BAZA", a tagi
# `proel-*` rozdzielają statystyki dostarczeń od beachowych.
#
# Transport jest kopią wzorca z app/beach/brevo_email.py (klucz nigdy nie jest
# logowany, klasyfikacja błędów po statusie); klasę wyjątku i mapowanie na HTTP
# WSPÓŁDZIELIMY importem — to publiczne nazwy modułu wolnego od bazy.

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

from app.beach.brevo_email import (  # moduł bez importu app.db — bezpieczny
    EmailDeliveryError,
    email_delivery_to_http,  # re-eksport dla warstwy routerów
)
from app.beach.email_config import get_email_config

logger = logging.getLogger(__name__)

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
_TIMEOUT_SECONDS = 15.0
_SUCCESS_STATUSES = (200, 201, 202)

__all__ = [
    "EmailDeliveryError",
    "email_delivery_to_http",
    "send_verification_code",
    "send_password_reset_code",
    "send_new_password_email",
]


def _app_name() -> str:
    return (os.getenv("PROEL_EMAIL_FROM_NAME") or "ProEl — BAZA").strip()


def _classify_status(status_code: int) -> str:
    if status_code in (401, 403):
        return "config"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 500:
        return "provider"
    return "request"


async def _send(payload: dict, *, what: str) -> str:
    cfg = get_email_config()
    if not cfg.brevo_api_key or not cfg.from_email:
        raise EmailDeliveryError("Brak konfiguracji nadawcy Brevo", kind="config")

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": cfg.brevo_api_key,  # never logged
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.post(BREVO_URL, headers=headers, json=payload)
    except httpx.TimeoutException as exc:
        logger.error("Brevo proel %s timeout", what)
        raise EmailDeliveryError("Brevo timeout", kind="timeout") from exc
    except httpx.HTTPError as exc:
        logger.error("Brevo proel %s network error: %s", what, type(exc).__name__)
        raise EmailDeliveryError("Brevo network error", kind="network") from exc

    if resp.status_code in _SUCCESS_STATUSES:
        try:
            message_id = resp.json().get("messageId")
        except Exception:
            message_id = None
        logger.info("Brevo proel %s ok status=%s messageId=%s", what, resp.status_code, message_id)
        return str(message_id or "")

    kind = _classify_status(resp.status_code)
    logger.error("Brevo proel %s failed status=%s kind=%s", what, resp.status_code, kind)
    raise EmailDeliveryError("Brevo delivery failed", kind=kind, status_code=resp.status_code)


# ─────────────────────────── szablony ───────────────────────────
#
# Prosty, jednokolumnowy HTML — czytelny wszędzie, bursztynowy akcent ProEla.

_ACCENT = "#E8970A"


def _code_html(heading: str, intro: str, code: str, expires_minutes: int) -> str:
    return f"""<!doctype html>
<html lang="pl"><body style="margin:0;padding:0;background:#f4f1ec;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:28px 12px;">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:14px;border:1px solid #e5ddd1;">
        <tr><td style="padding:22px 28px 6px 28px;">
          <div style="font-size:13px;font-weight:bold;letter-spacing:1px;color:{_ACCENT};">PROEL &middot; BAZA</div>
          <h1 style="margin:10px 0 0 0;font-size:20px;color:#1a1210;">{heading}</h1>
        </td></tr>
        <tr><td style="padding:10px 28px 0 28px;font-size:14px;line-height:21px;color:#4c4238;">{intro}</td></tr>
        <tr><td align="center" style="padding:22px 28px;">
          <div style="display:inline-block;padding:14px 30px;border-radius:12px;background:#faf6ef;
                      border:1px dashed {_ACCENT};font-size:30px;font-weight:bold;letter-spacing:9px;color:#1a1210;">{code}</div>
        </td></tr>
        <tr><td style="padding:0 28px 22px 28px;font-size:12px;line-height:18px;color:#8a7f72;">
          Kod jest ważny przez {expires_minutes} minut. Jeśli to nie Ty prosiłeś o ten kod, zignoruj tę wiadomość.
        </td></tr>
      </table>
      <div style="padding-top:14px;font-size:11px;color:#a49a8d;">Protokół elektroniczny ProEl &middot; aplikacja BAZA</div>
    </td></tr>
  </table>
</body></html>"""


def _code_text(heading: str, intro: str, code: str, expires_minutes: int) -> str:
    return (
        f"{_app_name()} — {heading}\n\n"
        f"{intro}\n\n"
        f"Kod: {code}\n"
        f"Kod jest ważny przez {expires_minutes} minut.\n\n"
        "Jeśli to nie Ty prosiłeś o ten kod, zignoruj tę wiadomość."
    )


async def send_verification_code(
    recipient_email: str,
    recipient_name: Optional[str],
    code: str,
    expires_minutes: int,
) -> str:
    to_entry: dict = {"email": recipient_email}
    if (recipient_name or "").strip():
        to_entry["name"] = recipient_name.strip()
    cfg = get_email_config()
    heading = "Potwierdź adres e-mail"
    intro = "Ten adres został podany przy koncie ProEl w aplikacji BAZA. Wpisz poniższy kod, aby go potwierdzić."
    payload = {
        "sender": {"name": _app_name(), "email": cfg.from_email},
        "to": [to_entry],
        "subject": "ProEl — kod weryfikacyjny",
        "htmlContent": _code_html(heading, intro, code, expires_minutes),
        "textContent": _code_text(heading, intro, code, expires_minutes),
        "tags": ["proel-verify"],
    }
    return await _send(payload, what="verify-code")


async def send_password_reset_code(
    recipient_email: str,
    recipient_name: Optional[str],
    code: str,
    expires_minutes: int,
) -> str:
    to_entry: dict = {"email": recipient_email}
    if (recipient_name or "").strip():
        to_entry["name"] = recipient_name.strip()
    cfg = get_email_config()
    heading = "Reset hasła konta ProEl"
    intro = "Ktoś (mamy nadzieję, że Ty) poprosił o reset hasła. Wpisz poniższy kod w aplikacji, aby ustawić nowe hasło."
    payload = {
        "sender": {"name": _app_name(), "email": cfg.from_email},
        "to": [to_entry],
        "subject": "ProEl — kod resetu hasła",
        "htmlContent": _code_html(heading, intro, code, expires_minutes),
        "textContent": _code_text(heading, intro, code, expires_minutes),
        "tags": ["proel-reset"],
    }
    return await _send(payload, what="reset-code")


async def send_new_password_email(
    recipient_email: str,
    recipient_name: Optional[str],
    new_password: str,
    login: Optional[str],
) -> str:
    """Hasło tymczasowe ustawione przez administratora (panel BAZA)."""
    to_entry: dict = {"email": recipient_email}
    if (recipient_name or "").strip():
        to_entry["name"] = recipient_name.strip()
    cfg = get_email_config()
    login_html = f"<p style='margin:6px 0 0 0;'>Login: <b>{login}</b></p>" if login else ""
    login_text = f"Login: {login}\n" if login else ""
    html = f"""<!doctype html>
<html lang="pl"><body style="margin:0;padding:0;background:#f4f1ec;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:28px 12px;">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:14px;border:1px solid #e5ddd1;">
        <tr><td style="padding:22px 28px;">
          <div style="font-size:13px;font-weight:bold;letter-spacing:1px;color:{_ACCENT};">PROEL &middot; BAZA</div>
          <h1 style="margin:10px 0 8px 0;font-size:20px;color:#1a1210;">Hasło zostało zresetowane</h1>
          <p style="margin:0;font-size:14px;line-height:21px;color:#4c4238;">
            Administrator zresetował hasło do Twojego konta ProEl.</p>
          <p style="margin:14px 0 0 0;font-size:16px;color:#1a1210;">Nowe hasło: <b>{new_password}</b></p>
          {login_html}
          <p style="margin:16px 0 0 0;font-size:12px;line-height:18px;color:#8a7f72;">
            Ze względów bezpieczeństwa zmień to hasło po pierwszym zalogowaniu.
            Jeśli to nie Ty prosiłeś o reset, skontaktuj się z administratorem BAZY.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""
    text = (
        f"{_app_name()} — hasło zostało zresetowane\n\n"
        "Administrator zresetował hasło do Twojego konta ProEl.\n"
        f"Nowe hasło: {new_password}\n{login_text}\n"
        "Ze względów bezpieczeństwa zmień to hasło po pierwszym zalogowaniu."
    )
    payload = {
        "sender": {"name": _app_name(), "email": cfg.from_email},
        "to": [to_entry],
        "subject": "ProEl — Twoje hasło zostało zresetowane",
        "htmlContent": html,
        "textContent": text,
        "tags": ["proel-admin-reset"],
    }
    return await _send(payload, what="new-password")
