"""Znacznik „to już poszło do ZPRP" stawiany przez SERWER, nie przez telefon.

DLACZEGO
Znaczniki `post.shortResultSent` / `post.fullDataSent` / `post.protocolSent`
zapisywała dotąd wyłącznie aplikacja, osobnym `/proel/patch` PO udanej wysyłce,
best-effort i bez ponowień. Skutki widać było przy LCM/5 (11.09.2026): wysyłki
poszły, a mecz wyglądał na nietknięty. Trzy drogi, którymi tamten zapis ginął:

  • brak zasięgu zaraz po wysyłce (sędzia chowa telefon i wychodzi z hali),
  • odmowa roli - `patch` sprawdza obsadę, a wysyłał ktoś spoza niej,
  • starsza wersja aplikacji, która tej ścieżki jeszcze nie zna.

Każda wysyłka i tak przechodzi przez nasz serwer (`app/proel_zprp.py`), więc to
on wie najlepiej, co naprawdę poszło - i to on stawia znacznik. Efekt jest
widoczny wszędzie tam, gdzie dotąd świeciła pustka: kafle zadań pomeczowych
zapalają się na KAŻDYM telefonie (wpis niesie `by` i `at`), a zatwierdzenie
meczu przestaje się blokować u kogoś, kto sam niczego nie wysyłał.

CZEGO TO NIE ROBI
Nie nadpisuje znacznika, który już stoi. Pierwszy wpis mówi prawdę o TYM, kto
wysłał jako pierwszy; ponowna wysyłka (bezpieczna i częsta) nie ma powodu
przesuwać nazwiska ani godziny.

Nie wywraca wysyłki, którą opisuje - stąd `try` wokół wszystkiego i ciche
`False`, gdy meczu nie da się wskazać. Wysyłka już się udała.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy import func, update

from app.proel_auth import Actor

logger = logging.getLogger(__name__)

#: Zadania pomeczowe, które serwer umie odhaczyć sam. SMS-a tu NIE MA i mieć
#: nie może: wiadomość wychodzi z telefonu, nasz serwer jej nie widzi, więc
#: jedynym świadkiem zostaje aplikacja.
SERVER_MARKED_TASKS = frozenset({"shortResultSent", "fullDataSent", "protocolSent"})


async def mark_post_task(
    task: str,
    *,
    match_number: str = "",
    zprp_match_id: Any = None,
    actor: Optional[Actor] = None,
    note: Optional[Dict[str, Any]] = None,
) -> bool:
    """Stawia `post.<task>` w overlayu meczu. Zwraca True, gdy coś dopisano.

    Mecz wskazuje numer albo identyfikator ZPRP - ten drugi tą samą drogą co
    dziennik wysyłki (`match_number_for_zprp_id` odsiewa zapisy szkoleniowe).
    """
    if task not in SERVER_MARKED_TASKS:
        return False
    try:
        from app.db import database, proel_match_state
        from app.proel import (
            _apply_reprojection_to_doc,
            _fetch_state,
            _overlay_of,
        )
        from app.proel_lease import now_utc
        from app.proel_send_journal import match_number_for_zprp_id

        number = str(match_number or "").strip() or await match_number_for_zprp_id(
            zprp_match_id
        )
        if not number:
            return False

        path = f"post.{task}"
        async with database.transaction():
            state = await _fetch_state(number, for_update=True)
            if state is None:
                # Mecz bez wiersza stanu - nie ma gdzie postawić znacznika.
                # Zakładanie go tutaj byłoby zakładaniem meczu przy okazji
                # wysyłki, a to należy do `/proel/ensure`.
                return False

            overlay: Dict[str, Any] = dict(_overlay_of(state))
            current = overlay.get(path)
            if isinstance(current, dict) and current.get("v") is True:
                return False

            next_rev = int(state.get("rev") or 0) + 1
            entry: Dict[str, Any] = {
                "v": True,
                "rev": next_rev,
                "at": now_utc().isoformat(),
                # Bez nagłówków tożsamości (starsza aplikacja) zostaje sam fakt
                # wysyłki. Pusty podpis jest uczciwszy niż zgadywanie - ekran
                # napisze wtedy „Zapisano 14:51" zamiast cudzego nazwiska.
                "by": actor.as_by() if actor is not None else {},
                # Odróżnia znacznik postawiony przez serwer od tego z telefonu.
                # Dziennik i ekran czytają tak samo, ale przy diagnozie („czemu
                # kafel się zapalił, skoro nic nie klikałem") to jedyna
                # odpowiedź.
                "src": "zprp",
                "superseded_at": None,
            }
            if note:
                entry["note"] = note
            overlay[path] = entry

            # ZATWIERDZONEGO MECZU TU NIE OMIJAMY. `/proel/patch` odmawia przy
            # statusie „approved" i słusznie - to edycja protokołu. Tutaj jest
            # odwrotnie: protokół PDF bardzo często idzie do ZPRP już PO
            # zatwierdzeniu, a znacznik jest zapisem faktu, nie zmianą treści.
            # Widok pochodny w `proel_matches` i tak zostaje nietknięty, bo
            # `_apply_reprojection_to_doc` zatwierdzonego bloba nie rusza.
            await database.execute(
                update(proel_match_state)
                .where(proel_match_state.c.match_number == number)
                .values(fields_json=overlay, rev=next_rev, updated_at=func.now())
            )
            refreshed = dict(state)
            refreshed["fields_json"] = overlay
            await _apply_reprojection_to_doc(number, refreshed)
        return True
    except Exception:
        logger.debug("znacznik wysyłki: nie udało się postawić", exc_info=True)
        return False
