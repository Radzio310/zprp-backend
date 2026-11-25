"""Cichy push „wynik skrócony zapisany" do urządzeń obsady meczu.

Po udanym `POST /proel/zprp/summary` pozostałe telefony obsady (i inne
urządzenia wpisującego) trzymałyby stary wynik aż do własnego odświeżenia.
Wysyłamy więc push DANYCH (bez bloku `notification`, patrz
`push.fcm.fcm_message_payload`): telefon łata lokalne pliki i odświeża widoki,
a sędzia nie widzi niczego na ekranie.

Obsadę bierzemy z `province_match_judges` (zasila ją monitor okręgowy), więc
mecze z okręgów poza `configured_provinces()` nie mają tam wpisów. Wtedy
zostają urządzenia wpisującego (numer z nagłówka `X-Judge-Id`).

Nigdy nie rzuca: to dodatek do zapisu, który już się udał.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select

logger = logging.getLogger(__name__)

KIND = "match_result_sync"

#: Pola, które telefon umie nałożyć na wpis meczu (kształt formularza ZPRP).
_PREFIXES = ("wynik_", "dogrywka_", "karne_", "timeout")
_EXACT = {"widzowie"}


def pushable_fields(fields: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Tylko pola wyniku; reszta (np. `data_fakt`) nie opuszcza serwera."""
    out: Dict[str, str] = {}
    for key, value in (fields or {}).items():
        k = str(key)
        if k in _EXACT or k.startswith(_PREFIXES):
            out[k] = "" if value is None else str(value)
    return out


async def recipients(id_zawody: Any, actor_judge_id: Optional[str]) -> List[str]:
    from app.db import database, province_match_judges

    ids = set()
    actor = str(actor_judge_id or "").strip()
    if actor:
        ids.add(actor)
    try:
        rows = await database.fetch_all(
            select(province_match_judges.c.judge_id)
            .where(province_match_judges.c.match_id == str(id_zawody))
            .where(province_match_judges.c.active.is_(True))
        )
        ids.update(str(r["judge_id"]).strip() for r in rows if str(r["judge_id"] or "").strip())
    except Exception:
        logger.warning("short_result_sync: odczyt obsady nieudany", exc_info=True)
    return sorted(ids)


async def notify_short_result_saved(
    id_zawody: Any,
    fields: Optional[Dict[str, Any]],
    actor_judge_id: Optional[str],
) -> None:
    try:
        if not id_zawody:
            return
        payload_fields = pushable_fields(fields)
        if not payload_fields:
            return
        judges = await recipients(id_zawody, actor_judge_id)
        if not judges:
            return
        from app.push.push import send_push_to_judges_report

        await send_push_to_judges_report(
            judges,
            "",
            "",
            data={
                "kind": KIND,
                "dataOnly": "1",
                "matchId": str(id_zawody),
                "fields": json.dumps(payload_fields, ensure_ascii=False),
            },
            app_variant="baza",
        )
    except Exception:
        logger.warning("short_result_sync: push nieudany", exc_info=True)
