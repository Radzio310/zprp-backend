# app/admin_alerts.py
#
# Jedna droga powiadomień dla administratora.
#
# Do tej pory każdy moduł wysyłał je po swojemu: `reports.py` miał własną
# funkcję, giełda własną, a nowy użytkownik nie zawiadamiał nikogo. Trzy kopie
# tego samego rozjeżdżają się przy pierwszej poprawce - i tak właśnie powstaje
# rodzaj zdarzenia, o którym administrator się nie dowiaduje, bo dołożono go
# tylko w jednym z trzech miejsc.
#
# Ten moduł robi trzy rzeczy i nic ponad to:
#
#   1. ustala, kto jest administratorem (ta sama lista, co w panelu),
#   2. odsiewa urządzenia, które ten rodzaj powiadomień wyciszyły,
#   3. wysyła - i NIGDY nie wywraca operacji, przy której powstało.
#
# Punkt trzeci jest tu najważniejszy. Powiadomienie o nowym zgłoszeniu nie ma
# prawa sprawić, że zgłoszenie się nie zapisze.

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from app.admin_alert_rules import (
    admin_pushes_allowed,
    alert_payload,
    alert_title,
    dedup_key,
)

logger = logging.getLogger("app.admin_alerts")

#: Pamięć ostatnio wysłanych kluczy - odsiew powtórzeń w obrębie procesu.
#:
#: Świadomie BEZ tabeli w bazie. To jest zabezpieczenie przed podwójnym
#: kliknięciem i przed dwoma zapisami w tej samej sekundzie, a nie kronika.
#: Restart procesu czyści pamięć i to jest w porządku: gorzej wysłać jedno
#: powiadomienie dwa razy po wdrożeniu niż trzymać kolejną tabelę do sprzątania.
_RECENT: Dict[str, float] = {}
_RECENT_LIMIT = 500


def _remember(key: str, stamp: float) -> bool:
    """Czy ten klucz jest nowy. Pusty klucz zawsze przechodzi."""
    if not key:
        return True
    if key in _RECENT:
        return False
    if len(_RECENT) >= _RECENT_LIMIT:
        # Najstarsza połowa wylatuje. Kolejność wstawiania w dict jest gwarantowana.
        for old in list(_RECENT)[: _RECENT_LIMIT // 2]:
            _RECENT.pop(old, None)
    _RECENT[key] = stamp
    return True


async def admin_judge_ids() -> List[str]:
    """Numery sędziów z uprawnieniem administratora.

    Ta sama lista, którą pokazuje panel (`admin_settings.allowed_admins`), więc
    uprawnienie widoczne w aplikacji i adresat powiadomienia to jedno i to samo.
    """
    from app.db import admin_settings, database

    try:
        row = await database.fetch_one(
            select(admin_settings.c.allowed_admins).where(admin_settings.c.id == 1)
        )
    except Exception:  # noqa: BLE001
        logger.warning("admin_alerts: odczyt listy adminów nieudany", exc_info=True)
        return []
    raw = (row["allowed_admins"] if row else None) or []
    return sorted({str(a).strip() for a in raw if str(a).strip()})


async def _willing_admins(kind: str, exclude: str = "") -> List[str]:
    """Administratorzy, którzy CHCĄ dostać ten rodzaj powiadomienia.

    Preferencje siedzą per instalacja, bo ten sam człowiek miewa dwa telefony.
    Wystarczy, że jedno urządzenie chce - powiadomienie i tak rozejdzie się na
    wszystkie jego urządzenia, a wyciszenie wszędzie jest tym, o co prosi ten,
    kto przestawił wyłącznik na każdym telefonie.
    """
    from app.db import database, push_tokens

    admins = [a for a in await admin_judge_ids() if a != str(exclude or "").strip()]
    if not admins:
        return []
    try:
        rows = await database.fetch_all(
            select(push_tokens.c.judge_id, push_tokens.c.notification_prefs)
            .where(push_tokens.c.judge_id.in_(admins))
            .where(push_tokens.c.app_variant == "baza")
        )
    except Exception:  # noqa: BLE001
        logger.warning("admin_alerts: odczyt preferencji nieudany", exc_info=True)
        # Wolimy wysłać niż zamilczeć - cisza wygląda jak „nic się nie stało".
        return admins

    wanted: Dict[str, bool] = {}
    for row in rows:
        judge_id = str(row["judge_id"] or "").strip()
        if not judge_id:
            continue
        wanted[judge_id] = wanted.get(judge_id, False) or admin_pushes_allowed(
            row["notification_prefs"], kind
        )
    # Administrator bez ani jednego urządzenia w tabeli nie ma jak niczego
    # wyciszyć - zostaje na liście, choćby po to, żeby dostał push po
    # zarejestrowaniu telefonu.
    for admin in admins:
        wanted.setdefault(admin, True)
    return sorted(j for j, ok in wanted.items() if ok)


async def notify_admins(
    kind: str,
    subject: str,
    body: str,
    *,
    reference: object = "",
    extra: Optional[Dict[str, Any]] = None,
    exclude_judge_id: str = "",
) -> int:
    """Zawiadamia administratorów. Zwraca liczbę urządzeń, do których poszło.

    NIGDY nie rzuca. Powiadomienie o zdarzeniu nie ma prawa przerwać zdarzenia -
    nowe zgłoszenie ma się zapisać także wtedy, gdy push nie wyjdzie.
    """
    try:
        import time

        key = dedup_key(kind, reference)
        if not _remember(key, time.time()):
            return 0

        targets = await _willing_admins(kind, exclude_judge_id)
        if not targets:
            return 0

        from app.push.push import send_push_to_judges

        return await send_push_to_judges(
            targets,
            alert_title(kind, subject),
            body,
            alert_payload(kind, reference, extra),
        )
    except Exception:  # noqa: BLE001
        logger.warning("admin_alerts: wysyłka %s nieudana", kind, exc_info=True)
        return 0
