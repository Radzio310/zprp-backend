"""Push do partnera, gdy sędzia zgłosi albo odwoła niedyspozycję.

Reguły (co jest „nowe”, treść) leżą w ``partner_offtime_notify_rules``.
Tu tylko decyzja, KOMU wolno wysłać, i sama wysyłka.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select

from app.db import database, partner_offtimes
from app.partner_offtime_notify_rules import (
    WARSAW,
    diff_future_offtimes,
    event_key,
    notification_text,
)

logger = logging.getLogger(__name__)

#: Klucz przełącznika w ``notificationTypes`` ustawień aplikacji.
PREFERENCE_KEY = "partnerOfftimes"


async def notify_partner_about_new_offtimes(
    *,
    judge_id: str,
    full_name: str,
    old_partner_id: Optional[str],
    new_partner_id: Optional[str],
    old_data: Any,
    new_data: Any,
) -> int:
    """Wysyła push i zwraca liczbę urządzeń, które go przyjęły. Nigdy nie rzuca.

    Milczy, gdy:
    - w tym samym zapisie zmienia się partner (parowanie i rozparowanie
      wysyłają całą listę - to nie są nowe zgłoszenia),
    - parowanie nie jest obustronne (sam wpis ``partner_id`` u mnie to
      dopiero zaproszenie; ktoś niesparowany nie może dostawać moich pushy).
    """
    try:
        partner_id = str(new_partner_id or "").strip()
        if not partner_id or partner_id != str(old_partner_id or "").strip():
            return 0
        change = diff_future_offtimes(old_data, new_data, datetime.now(WARSAW).date())
        if not change:
            return 0
        partner_row = await database.fetch_one(
            select(partner_offtimes.c.partner_id).where(
                partner_offtimes.c.judge_id == partner_id
            )
        )
        if not partner_row or str(partner_row["partner_id"] or "").strip() != str(judge_id):
            return 0

        title, body = notification_text(full_name, change)
        from app.push.push import send_push_to_judges

        return await send_push_to_judges(
            [partner_id],
            title,
            body,
            data={
                # `type` + `screen` otwierają ekran niedyspozycji także
                # w wersjach aplikacji, które nie znają `kind`.
                "type": "more_screen",
                "screen": "niedyspozycznosc",
                "kind": "partner_offtime",
                "partnerId": str(judge_id),
                "judgeId": partner_id,
                "event_key": event_key(judge_id, change),
            },
            app_variant="baza",
            preference_key=PREFERENCE_KEY,
        )
    except Exception:  # noqa: BLE001
        # Zapis niedyspozycji już się udał; push jest dodatkiem.
        logger.warning("partner_offtime: powiadomienie partnera nieudane", exc_info=True)
        return 0
