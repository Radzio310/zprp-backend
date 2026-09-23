"""
Mail z alertem o saldzie klubów - szablon i wysyłka przez Brevo.

Transport jak w `app/proel_users/emails.py` (to samo konto nadawcy Brevo,
BREVO_API_KEY / BREVO_FROM_EMAIL), ale WŁASNA nazwa nadawcy: Brevo przyjmuje
dowolną nazwę przy zweryfikowanym adresie, więc w skrzynce widać
„BAZA - Rozliczenia okręgu" (env `SETTLEMENT_ALERT_FROM_NAME`), a tag
`settlement-alert` oddziela statystyki dostarczeń.

Szablon: tabelki z CSS w atrybutach `style` - Gmail wycina <style>, a Outlook
nie zna flexboksa. Barwy jak w PDF-ach okręgu: granat #0B4F9E i złoto #F0A500.
Logo okręgu idzie adresem publicznej trasy backendu (Gmail nie pokazuje
obrazków w data: URI), a gdy adresu nie znamy - nagłówek obywa się bez niego.

Budowanie treści jest czyste (bez bazy i sieci) - testy renderują je wprost.
"""

from __future__ import annotations

import html
import logging
import os
from dataclasses import dataclass
from datetime import date
from typing import Iterable, Optional

import httpx

from app.beach.brevo_email import EmailDeliveryError  # moduł bez importu app.db
from app.beach.email_config import get_email_config
from app.province_alert_rules import Pace, format_pln, pace_sentence, plural, province_title, subject_line

logger = logging.getLogger(__name__)

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
_TIMEOUT_SECONDS = 15.0
_SUCCESS_STATUSES = (200, 201, 202)

NAVY = "#0B4F9E"
NAVY_DARK = "#083B77"
GOLD = "#F0A500"
RED = "#C62828"
AMBER = "#B86E00"
INK = "#1B2433"
MUTED = "#5E6B7E"
LINE = "#E3E8F0"
PAGE = "#EEF2F8"

#: Adres BAZA_web - przycisk w mailu prowadzi do Rozliczeń.
DEFAULT_BAZA_WEB_URL = "https://baza-web-two.vercel.app"


def sender_name() -> str:
    return (os.getenv("SETTLEMENT_ALERT_FROM_NAME") or "BAZA - Rozliczenia okręgu").strip()


def baza_web_url() -> str:
    return (os.getenv("BAZA_WEB_URL") or DEFAULT_BAZA_WEB_URL).strip().rstrip("/")


def panel_url() -> str:
    """Rozliczenia w BAZA_web (`app/(tabs)/explore.tsx`). Panel nie ma parametru
    otwierającego konkretny klub, więc prowadzimy do samego panelu."""
    return f"{baza_web_url()}/explore"


def logo_url(province_key: str) -> str:
    base = (os.getenv("BACKEND_URL") or "").strip().rstrip("/")
    if not base or not province_key:
        return ""
    return f"{base}/province/alerts/logo/{province_key}.png"


@dataclass(frozen=True)
class BudgetCard:
    budget_id: str
    name: str
    balance: float
    charged: float
    matches: int
    last_payment: Optional[tuple[Optional[date], float]]
    pace: Pace
    teams_label: str = ""


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _day(value: Optional[date]) -> str:
    return value.strftime("%d.%m.%Y") if value else "data nieznana"


def _payment_text(card: BudgetCard) -> str:
    if not card.last_payment:
        return "brak wpłat"
    day, amount = card.last_payment
    return f"{format_pln(amount)} · {_day(day)}"


def _charged_text(card: BudgetCard) -> str:
    return f"{format_pln(card.charged)} · {card.matches} {plural(card.matches, 'mecz', 'mecze', 'meczów')}"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _detail_row(label: str, value: str, *, last: bool = False) -> str:
    border = "" if last else f"border-bottom:1px solid {LINE};"
    return (
        f'<tr><td style="padding:8px 0;{border}font-size:13px;color:{MUTED};">{_e(label)}</td>'
        f'<td align="right" style="padding:8px 0;{border}font-size:13px;font-weight:bold;color:{INK};">{_e(value)}</td></tr>'
    )


def _card_html(card: BudgetCard, threshold: float) -> str:
    negative = card.balance < 0
    tone = RED if negative else AMBER
    tint = "#FDECEC" if negative else "#FFF4E0"
    badge = "NA MINUSIE" if negative else "PONIŻEJ PROGU"
    teams = (
        f'<div style="margin-top:3px;font-size:12px;color:{MUTED};">{_e(card.teams_label)}</div>'
        if card.teams_label
        else ""
    )
    return f"""
<tr><td style="padding:0 28px 16px 28px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {LINE};border-left:5px solid {tone};border-radius:12px;background:#FFFFFF;">
    <tr><td style="padding:16px 18px 6px 18px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
        <td valign="top" style="font-family:Arial,Helvetica,sans-serif;">
          <div style="display:inline-block;padding:3px 8px;border-radius:999px;background:{tint};
                      font-size:10px;font-weight:bold;letter-spacing:1px;color:{tone};">{badge}</div>
          <div style="margin-top:8px;font-size:17px;font-weight:bold;color:{INK};">{_e(card.name)}</div>
          {teams}
        </td>
        <td valign="top" align="right" style="font-family:Arial,Helvetica,sans-serif;white-space:nowrap;">
          <div style="font-size:11px;letter-spacing:1px;color:{MUTED};">SALDO</div>
          <div style="font-size:28px;line-height:34px;font-weight:bold;color:{tone};">{_e(format_pln(card.balance))}</div>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:4px 18px 4px 18px;font-family:Arial,Helvetica,sans-serif;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        {_detail_row("Próg alertu", format_pln(threshold))}
        {_detail_row("Ostatnia wpłata", _payment_text(card))}
        {_detail_row("Obciążenia w sezonie", _charged_text(card), last=True)}
      </table>
    </td></tr>
    <tr><td style="padding:6px 18px 16px 18px;font-family:Arial,Helvetica,sans-serif;">
      <div style="padding:10px 12px;border-radius:10px;background:#F4F7FC;font-size:13px;line-height:19px;color:{NAVY_DARK};">
        &#9201;&nbsp; {_e(pace_sentence(card.pace))}
      </div>
    </td></tr>
  </table>
</td></tr>"""


def _stat(label: str, value: str, color: str) -> str:
    return (
        f'<td align="center" width="33%" style="padding:12px 6px;font-family:Arial,Helvetica,sans-serif;">'
        f'<div style="font-size:20px;font-weight:bold;color:{color};">{_e(value)}</div>'
        f'<div style="margin-top:2px;font-size:11px;letter-spacing:0.5px;color:{MUTED};">{_e(label)}</div></td>'
    )


def render_html(
    *,
    province_display: str,
    threshold: float,
    cards: list[BudgetCard],
    link: str,
    logo: str = "",
    account_label: str = "",
    test: bool = False,
    preview_note: str = "",
) -> str:
    name = province_title(province_display)
    count = len(cards)
    heading = (
        f"{count} {plural(count, 'klub', 'kluby', 'klubów')} poniżej {format_pln(threshold)}"
        if count
        else "Wszystkie kluby powyżej progu"
    )
    negatives = sum(1 for card in cards if card.balance < 0)
    total = sum(card.balance for card in cards)
    logo_html = (
        f'<td width="64" valign="middle" style="padding-right:14px;">'
        f'<img src="{_e(logo)}" width="56" height="56" alt="{_e(name)}" '
        f'style="display:block;width:56px;height:56px;border-radius:28px;background:#FFFFFF;border:2px solid {GOLD};"></td>'
        if logo
        else ""
    )
    test_html = (
        f'<tr><td style="padding:14px 28px 0 28px;"><div style="padding:10px 12px;border-radius:10px;'
        f'border:1px dashed {GOLD};background:#FFF8E6;font-family:Arial,Helvetica,sans-serif;font-size:12px;'
        f'line-height:18px;color:{INK};"><b>Wiadomość próbna.</b> Tak będzie wyglądał alert. '
        f'{_e(preview_note)}</div></td></tr>'
        if test
        else ""
    )
    stats = (
        f'<tr><td style="padding:18px 28px 16px 28px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border:1px solid {LINE};border-radius:12px;background:#FAFBFD;"><tr>'
        + _stat(plural(count, "klub", "kluby", "klubów"), str(count), NAVY)
        + _stat("na minusie", str(negatives), RED if negatives else MUTED)
        + _stat("łączne saldo", format_pln(total), RED if total < 0 else INK)
        + "</tr></table></td></tr>"
        if count
        else ""
    )
    cards_html = "".join(_card_html(card, threshold) for card in cards)
    if not cards:
        cards_html = (
            f'<tr><td style="padding:18px 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;'
            f'line-height:21px;color:{INK};">Żaden obserwowany klub nie ma teraz salda poniżej '
            f'{_e(format_pln(threshold))}.</td></tr>'
        )
    who = f" Alert ustawiło konto <b>{_e(account_label)}</b>." if account_label else ""
    intro = (
        "Te kluby rozliczają się przez okręg, wpłaciły w tym sezonie zaliczkę i ich saldo spadło poniżej progu. "
        "O każdym piszemy raz - kolejny mail przyjdzie dopiero, gdy saldo wróci powyżej progu i znów spadnie."
    )
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(name)} - saldo klubów</title></head>
<body style="margin:0;padding:0;background:{PAGE};">
<div style="display:none;max-height:0;overflow:hidden;color:{PAGE};">{_e(name)}: {_e(heading)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{PAGE};">
<tr><td align="center" style="padding:26px 10px;">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0"
         style="width:100%;max-width:600px;background:#FFFFFF;border-radius:16px;overflow:hidden;border:1px solid {LINE};">
    <tr><td style="background:{NAVY};padding:22px 28px;">
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        {logo_html}
        <td valign="middle" style="font-family:Arial,Helvetica,sans-serif;">
          <div style="font-size:11px;font-weight:bold;letter-spacing:2px;color:{GOLD};">ROZLICZENIA OKRĘGU &middot; {_e(name.upper())}</div>
          <div style="margin-top:6px;font-size:22px;line-height:28px;font-weight:bold;color:#FFFFFF;">{_e(heading)}</div>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="height:4px;line-height:4px;font-size:0;background:{GOLD};">&nbsp;</td></tr>
    {test_html}
    <tr><td style="padding:18px 28px 0 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:{INK};">
      {_e(intro)}
    </td></tr>
    {stats}
    {cards_html}
    <tr><td align="center" style="padding:6px 28px 26px 28px;">
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        <td align="center" bgcolor="{GOLD}" style="border-radius:10px;background:{GOLD};">
          <a href="{_e(link)}" target="_blank"
             style="display:inline-block;padding:13px 26px;font-family:Arial,Helvetica,sans-serif;font-size:14px;
                    font-weight:bold;color:{NAVY_DARK};text-decoration:none;border-radius:10px;">Otwórz panel klubów &rarr;</a>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:16px 28px 22px 28px;border-top:1px solid {LINE};font-family:Arial,Helvetica,sans-serif;
                   font-size:11px;line-height:17px;color:{MUTED};">
      Dostajesz tę wiadomość, bo Twój adres jest na liście alertów o saldzie klubów w BAZA_web.{who}
      Próg, częstotliwość i adresy zmienisz w Rozliczeniach, pod ikoną koła zębatego.
    </td></tr>
  </table>
  <div style="padding-top:12px;font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#8A96A8;">BAZA &middot; Rozliczenia okręgu</div>
</td></tr>
</table>
</body></html>"""


def render_text(
    *,
    province_display: str,
    threshold: float,
    cards: list[BudgetCard],
    link: str,
    test: bool = False,
    preview_note: str = "",
) -> str:
    name = province_title(province_display)
    lines: list[str] = []
    if test:
        lines += ["WIADOMOŚĆ PRÓBNA - tak będzie wyglądał alert. " + preview_note, ""]
    if cards:
        lines.append(f"{name}: {len(cards)} {plural(len(cards), 'klub', 'kluby', 'klubów')} poniżej {format_pln(threshold)}")
    else:
        lines.append(f"{name}: żaden obserwowany klub nie ma salda poniżej {format_pln(threshold)}")
    lines.append("")
    for card in cards:
        lines += [
            f"* {card.name}",
            f"  Saldo: {format_pln(card.balance)} (próg {format_pln(threshold)})",
            f"  Ostatnia wpłata: {_payment_text(card)}",
            f"  Obciążenia w sezonie: {_charged_text(card)}",
            f"  {pace_sentence(card.pace)}",
            "",
        ]
    lines += [
        f"Panel klubów: {link}",
        "",
        "O każdym klubie piszemy raz - kolejny mail dopiero, gdy saldo wróci powyżej progu i znów spadnie.",
        "Ustawienia alertów: Rozliczenia w BAZA_web, ikona koła zębatego.",
    ]
    return "\n".join(lines).replace(" ", " ")


def build_message(
    *,
    province_key: str,
    province_display: str,
    threshold: float,
    cards: list[BudgetCard],
    account_label: str = "",
    test: bool = False,
    preview_note: str = "",
) -> tuple[str, str, str]:
    """(temat, HTML, tekst)."""
    link = panel_url()
    subject = subject_line(province_display, len(cards), threshold) if cards else (
        f"{province_title(province_display)}: saldo klubów w normie"
    )
    if test:
        subject = "[TEST] " + subject
    html_body = render_html(
        province_display=province_display,
        threshold=threshold,
        cards=cards,
        link=link,
        logo=logo_url(province_key),
        account_label=account_label,
        test=test,
        preview_note=preview_note,
    )
    text_body = render_text(
        province_display=province_display,
        threshold=threshold,
        cards=cards,
        link=link,
        test=test,
        preview_note=preview_note,
    )
    return subject, html_body, text_body


# ---------------------------------------------------------------------------
# Wysyłka
# ---------------------------------------------------------------------------

def _classify_status(status_code: int) -> str:
    if status_code in (401, 403):
        return "config"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 500:
        return "provider"
    return "request"


async def send_alert_email(
    recipients: Iterable[str],
    subject: str,
    html_body: str,
    text_body: str,
    *,
    test: bool = False,
) -> str:
    """Jeden mail do wszystkich adresów (każdy widzi pozostałych - to lista komisji)."""
    cfg = get_email_config()
    if not cfg.brevo_api_key or not cfg.from_email:
        raise EmailDeliveryError("Brak konfiguracji nadawcy Brevo", kind="config")
    to = [{"email": item} for item in recipients]
    if not to:
        raise EmailDeliveryError("Brak adresatów", kind="request")
    payload = {
        "sender": {"name": sender_name(), "email": cfg.from_email},
        "to": to,
        "subject": subject,
        "htmlContent": html_body,
        "textContent": text_body,
        "tags": ["settlement-alert-test" if test else "settlement-alert"],
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": cfg.brevo_api_key,  # nigdy nie trafia do logu
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.post(BREVO_URL, headers=headers, json=payload)
    except httpx.TimeoutException as exc:
        logger.error("Brevo settlement-alert timeout")
        raise EmailDeliveryError("Brevo timeout", kind="timeout") from exc
    except httpx.HTTPError as exc:
        logger.error("Brevo settlement-alert network error: %s", type(exc).__name__)
        raise EmailDeliveryError("Brevo network error", kind="network") from exc

    if resp.status_code in _SUCCESS_STATUSES:
        try:
            message_id = resp.json().get("messageId")
        except Exception:  # noqa: BLE001
            message_id = None
        logger.info("Brevo settlement-alert ok status=%s messageId=%s", resp.status_code, message_id)
        return str(message_id or "")

    kind = _classify_status(resp.status_code)
    logger.error("Brevo settlement-alert failed status=%s kind=%s", resp.status_code, kind)
    raise EmailDeliveryError("Brevo delivery failed", kind=kind, status_code=resp.status_code)


def delivery_message(exc: EmailDeliveryError) -> str:
    """Powód nieudanej wysyłki po ludzku - na ekran i do `last_error`."""
    kind = getattr(exc, "kind", "")
    return {
        "config": "Serwer nie ma skonfigurowanej wysyłki maili (Brevo). Zgłoś to administratorowi aplikacji.",
        "rate_limited": "Dostawca maili chwilowo ogranicza wysyłkę. Spróbuj za kilka minut.",
        "provider": "Dostawca maili (Brevo) ma awarię. Spróbuj później.",
        "timeout": "Dostawca maili nie odpowiedział na czas. Spróbuj jeszcze raz.",
        "network": "Serwer nie połączył się z dostawcą maili. Spróbuj jeszcze raz.",
    }.get(kind, "Dostawca maili odrzucił wiadomość. Sprawdź adresy i spróbuj ponownie.")
