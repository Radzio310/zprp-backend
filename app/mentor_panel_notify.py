"""
Panel „Mentor" - powiadomienia: push (BAZA) od razu i zbiorczy e-mail (Brevo)
najwyżej co 30 minut na osobę (`docs/mentor-panel.md`, 4.3 i 4.8).

Push: `kind=mentor_panel` + `pairId`, `matchId`, `clipId`, `threadId`, `messageId`, `clipS`/`videoS`,
`sheetId`, `target` (sheet|thread|message), `tag` (napisy - FCM przyjmuje tylko
napisy), przełącznik w telefonie `mentorPanel`. `tag` skleja powiadomienia w jeden kafelek.
E-mail: zdarzenia czekają w pamięci procesu i wychodzą jednym listem, gdy od
poprzedniego listu do tej osoby minęło 30 minut. Restart serwera gubi
oczekujące (push już dotarł), więc e-mail jest tylko przypomnieniem.
Wysyłka nigdy nie cofa zapisu - błędy kończą się wpisem w logu.
"""

from __future__ import annotations

import asyncio
import html
import logging
import time
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("app.mentor_panel")

EMAIL_EVERY_S = 30 * 60
FLUSH_EVERY_S = 60
PREFERENCE_KEY = "mentorPanel"

_pending: Dict[str, List[Dict[str, Any]]] = {}
_last_email: Dict[str, float] = {}
_province_of: Dict[str, str] = {}


def recipients_for(ctx: Dict[str, Any], actor_id: str, only: Optional[Iterable[str]] = None) -> List[str]:
    """Pozostałe osoby pary i aktywni mentorzy (bez autora zdarzenia)."""
    everyone = [*ctx["judge_ids"], *ctx["mentor_ids"]]
    if only is not None:
        wanted = {str(x) for x in only}
        everyone = [x for x in everyone if x in wanted]
    return sorted({str(x) for x in everyone if str(x) and str(x) != str(actor_id)})


ACCENT = "#FF7A59"  # koral Mentora (kolor ikony powiadomienia Androida)


async def match_image(match_id: Optional[str]) -> Optional[str]:
    """Herb gospodarza meczu (https, nie SVG) jako obraz powiadomienia; brak = bez obrazu."""
    if not match_id:
        return None
    try:
        from sqlalchemy import select

        from app.db import database, zprp_public_clubs, zprp_public_matches

        match = await database.fetch_one(select(zprp_public_matches.c.home_club_id)
                                         .where(zprp_public_matches.c.match_id == str(match_id)))
        club_id = match["home_club_id"] if match else None
        if not club_id:
            return None
        club = await database.fetch_one(select(zprp_public_clubs.c.logo_url).where(zprp_public_clubs.c.club_id == club_id))
        url = str(club["logo_url"] or "") if club else ""
        return url if url.startswith("https://") and not url.lower().split("?")[0].endswith(".svg") else None
    except Exception:  # noqa: BLE001
        return None


def push_data(pair_id: Any, *, target: Optional[str] = None, match_id: Optional[str] = None, clip_id: Optional[str] = None,
              thread_id: Optional[str] = None, message_id: Optional[str] = None, sheet_id: Optional[str] = None,
              tag: Optional[str] = None, quiet: bool = False, image: Optional[str] = None,
              extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Ładunek push panelu (FCM: same napisy). `tag` = tag Androida + collapse key + apns-collapse-id."""
    data = {"type": "mentor_panel", "kind": "mentor_panel", "pairId": str(pair_id)}
    for key, value in (("matchId", match_id), ("clipId", clip_id), ("threadId", thread_id), ("messageId", message_id),
                       ("sheetId", sheet_id), ("target", target), ("tag", tag)):
        if value:
            data[key] = str(value)
    if tag:
        data["notificationTag"] = str(tag)
    data["notificationColor"] = ACCENT
    # Dodatki celu (np. `clipS`/`videoS` - sekunda kotwicy wątku klipu); same napisy.
    for key, value in (extra or {}).items():
        if value not in (None, "") and key not in data:
            data[str(key)] = str(value)
    if image:
        data["notificationImage"] = image
    if quiet:
        data["notificationSilent"] = "1"
        data["notificationPriority"] = "normal"
    return data


async def notify(ctx: Dict[str, Any], actor_id: str, title: str, body: str, *, recipients: Optional[List[str]] = None,
                 match_id: Optional[str] = None, clip_id: Optional[str] = None, thread_id: Optional[str] = None,
                 link: str = "", message_id: Optional[str] = None, sheet_id: Optional[str] = None,
                 target: Optional[str] = None, tag: Optional[str] = None, quiet: bool = False,
                 extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    ids = recipients if recipients is not None else recipients_for(ctx, actor_id)
    if not ids:
        return {"push": None, "queued": 0}
    target = target or ("thread" if thread_id else None)
    data = push_data(ctx["pair_id"], target=target, match_id=match_id, clip_id=clip_id, thread_id=thread_id,
                     message_id=message_id, sheet_id=sheet_id, tag=tag, quiet=quiet, image=await match_image(match_id),
                     extra=extra)
    report = None
    try:
        from app.push.push import send_push_to_judges_report

        report = await send_push_to_judges_report(ids, title, body, data, app_variant="baza", preference_key=PREFERENCE_KEY)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: push nieudany", exc_info=True)
    web = link or f"https://www.bazapodreka.app/mentor/{ctx['pair_id']}"
    for judge_id in ids:
        _pending.setdefault(judge_id, []).append({"title": title, "body": body, "link": web})
        _province_of[judge_id] = str(ctx["pair"].get("province") or "")
    return {"push": report, "queued": len(ids)}


def _digest(items: List[Dict[str, Any]]) -> tuple[str, str, str]:
    subject = items[0]["title"] if len(items) == 1 else f"Mentor: {len(items)} nowe sprawy w panelu pary"
    lines = [f"- {i['title']}: {i['body']}" for i in items[:20]]
    link = items[-1]["link"]
    text = "\n".join(lines) + f"\n\nOtwórz panel: {link}"
    rows = "".join(f"<li><b>{html.escape(i['title'])}</b> - {html.escape(i['body'])}</li>" for i in items[:20])
    body = (
        '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:24px;color:#1f2937">'
        '<h2 style="color:#6d4ccf">Mentor - co nowego</h2>'
        f"<ul>{rows}</ul>"
        f'<p><a href="{html.escape(link, quote=True)}" style="display:inline-block;padding:12px 18px;background:#a78bfa;'
        'color:#1b1230;text-decoration:none;border-radius:10px;font-weight:bold">Otwórz panel Mentor</a></p></div>'
    )
    return subject, body, text


async def flush_emails(now: Optional[float] = None) -> int:
    """Wyślij zaległe listy osobom, którym minęło 30 minut od poprzedniego."""
    moment = now if now is not None else time.monotonic()
    due = [j for j, items in _pending.items() if items and moment - _last_email.get(j, -1e12) >= EMAIL_EVERY_S]
    sent = 0
    for judge_id in due:
        items = _pending.pop(judge_id, [])
        if not items:
            continue
        _last_email[judge_id] = moment
        try:
            from app.district_alerts import _judge_email_detail
            from app.province_alert_emails import send_alert_email

            emails = await _judge_email_detail(_province_of.get(judge_id, ""), [judge_id])
            address = (emails.get(judge_id) or ("", ""))[0]
            if not address:
                continue
            subject, body, text = _digest(items)
            await send_alert_email([address], subject, body, text, sender="BAZA · Mentor", tag="mentor-panel")
            sent += 1
        except Exception:  # noqa: BLE001
            logger.warning("mentor: e-mail zbiorczy nieudany", exc_info=True)
    return sent


async def run_email_digest() -> None:
    """Pętla w tle - ta sama forma, co pozostałe zadania cykliczne w `main.py`."""
    while True:
        try:
            await flush_emails()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: przebieg e-maili nieudany")
        await asyncio.sleep(FLUSH_EVERY_S)
