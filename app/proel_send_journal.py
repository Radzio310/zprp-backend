"""Ślad wysyłki do ZPRP w dzienniku meczu - zapisywany przez SERWER.

DLACZEGO NIE TELEFON
Do tej pory wpis „wynik skrócony trafił do bazy ZPRP" powstawał z markera
(`post.shortResultSent`), który aplikacja zapisywała PO udanej wysyłce, osobnym
zapisem best-effort bez ponowień. Wystarczyło, że tamten zapis nie doszedł
(brak zasięgu w hali, wygaszona sesja, starsza wersja aplikacji), a mecz
wyglądał w dzienniku tak, jakby nikt niczego nie wysłał - dokładnie to widać
przy LCM/5 z 11.09.2026: komplet ręcznych poprawek pól i ani jednej wysyłki.

Wysyłki i tak idą przez nasz serwer (`app/proel_zprp.py` jest pośrednikiem do
formularzy ZPRP), więc to on wie najlepiej, co naprawdę poszło i z jakim
skutkiem. Dziennik przestaje zależeć od dobrej woli i wersji telefonu.

Wpis NIGDY nie może wywrócić wysyłki, którą opisuje - stąd `try` wokół
wszystkiego i cichy powrót, gdy meczu nie da się wskazać.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy import select

from app.proel_auth import Actor
from app.proel_journal import log_match_event

logger = logging.getLogger(__name__)


async def match_number_for_zprp_id(zprp_match_id: Any) -> str:
    """Numer meczu spod identyfikatora ZPRP, albo pusty napis.

    Zapis szkoleniowy (`T-XXXXXXXX/NUMER`) nosi ten sam identyfikator co mecz
    oficjalny, a dziennik wysyłki należy do OFICJALNEGO - ćwiczenie do ZPRP
    nic nie wysyła. Stąd jawne odsianie kluczy szkoleniowych zamiast „pierwszy
    z brzegu".
    """
    raw = str(zprp_match_id or "").strip()
    if not raw.isdigit():
        return ""
    try:
        from app.db import database, saved_matches

        row = await database.fetch_one(
            select(saved_matches.c.match_number)
            .where(
                saved_matches.c.zprp_match_id == raw,
                ~saved_matches.c.match_number.like("T-%"),
            )
            .order_by(saved_matches.c.updated_at.desc())
            .limit(1)
        )
        return str(row["match_number"]) if row is not None else ""
    except Exception:
        logger.debug("dziennik wysyłki: nie udało się wskazać meczu", exc_info=True)
        return ""


async def log_by_zprp_id(
    event: str,
    *,
    zprp_match_id: Any = None,
    match_number: Optional[str] = None,
    actor: Optional[Actor] = None,
    details: Optional[Dict[str, Any]] = None,
    event_key: Optional[str] = None,
) -> None:
    """Wpis do dziennika meczu wskazanego identyfikatorem ZPRP.

    Używają tego miejsca, które znają mecz TYLKO po stronie związku: pośrednik
    wysyłek i raport dodatkowy (jego klucz to także IdZawody). Cichy, gdy meczu
    nie da się wskazać - wpis bez meczu nie ma gdzie stanąć.
    """
    try:
        number = str(match_number or "").strip() or await match_number_for_zprp_id(
            zprp_match_id
        )
        if not number:
            # Mecz spoza ProEla (wysyłka z ekranu szczegółów przy meczu, który
            # nigdy nie miał protokołu) - nie ma dziennika, do którego pisać.
            return
        await log_match_event(
            match_number=number,
            event=event,
            actor=actor,
            zprp_match_id=str(zprp_match_id or "").strip() or None,
            details=details,
            event_key=event_key,
        )
    except Exception:
        logger.debug("dziennik wysyłki: wpis nieudany", exc_info=True)
