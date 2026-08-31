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

from sqlalchemy import or_, select

from app.admin_alert_rules import (
    ADMIN_NO_DEVICE,
    DEVICE_OK,
    admin_pushes_allowed,
    alert_payload,
    alert_title,
    dedup_key,
    summarize_admin_reach,
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
            .where(
                or_(
                    push_tokens.c.app_variant == "baza",
                    # Wiersz bez wariantu to instalacja sprzed tego pola.
                    # Nieznany wariant nie może znaczyć „to nie nasz telefon" -
                    # to jest dokładnie ta cisza, której szukamy.
                    push_tokens.c.app_variant.is_(None),
                )
            )
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
            logger.warning(
                "admin_alerts: %s bez adresatów (ref=%s)", kind, reference
            )
            return 0

        from app.push.push import send_push_to_judges

        sent = await send_push_to_judges(
            targets,
            alert_title(kind, subject),
            body,
            alert_payload(kind, reference, extra),
        )
        # Log JEST tu potrzebny. Bez niego pytanie „dlaczego jeden admin dostał,
        # a drugi nie" nie ma odpowiedzi: po fakcie nie da się odtworzyć, kto
        # był adresatem i ile urządzeń odpowiedziało.
        logger.info(
            "admin_alerts: %s -> %d adm., %d urz. (ref=%s)",
            kind,
            len(targets),
            sent,
            reference,
        )
        if not sent:
            logger.warning(
                "admin_alerts: %s nie doszło do nikogo z %s",
                kind,
                ",".join(targets),
            )
        return sent
    except Exception:  # noqa: BLE001
        logger.warning("admin_alerts: wysyłka %s nieudana", kind, exc_info=True)
        return 0


async def admin_alert_reach(kind: str = "new_report") -> List[Dict[str, Any]]:
    """Kto z administratorów DOSTANIE powiadomienie tego rodzaju - i dlaczego nie.

    Odpowiedź na jedyne pytanie, którego nie dało się zadać: po cichej wysyłce
    administrator widzi to samo co przy braku zdarzenia. Tu lejek jest
    rozpisany na stany z `admin_alert_rules`, więc widać różnicę między
    „wyciszył", „nie ma go w tabeli urządzeń" i „Firebase odrzucił token".

    Nigdy nie rzuca - podgląd diagnostyczny nie ma prawa wywrócić panelu.
    """
    from app.db import database, push_tokens

    try:
        admins = await admin_judge_ids()
        if not admins:
            return []
        rows = await database.fetch_all(
            select(
                push_tokens.c.judge_id,
                push_tokens.c.token,
                push_tokens.c.token_type,
                push_tokens.c.platform,
                push_tokens.c.app_variant,
                push_tokens.c.notification_prefs,
                push_tokens.c.updated_at,
            ).where(push_tokens.c.judge_id.in_(admins))
        )
    except Exception:  # noqa: BLE001
        logger.warning("admin_alerts: podgląd zasięgu nieudany", exc_info=True)
        return []

    by_judge: Dict[str, List[Dict[str, Any]]] = {a: [] for a in admins}
    for row in rows:
        judge_id = str(row["judge_id"] or "").strip()
        if judge_id in by_judge:
            by_judge[judge_id].append(dict(row))

    out: List[Dict[str, Any]] = []
    for judge_id in admins:
        devices = by_judge.get(judge_id) or []
        summary = summarize_admin_reach(judge_id, devices, kind)
        newest = max(
            (d.get("updated_at") for d in devices if d.get("updated_at")),
            default=None,
        )
        summary["last_seen"] = newest.isoformat() if newest else None
        summary["platforms"] = sorted(
            {str(d.get("platform") or "?") for d in devices}
        )
        out.append(summary)
    # Niedostępni na górze - po to się ten podgląd otwiera.
    out.sort(key=lambda item: (item["state"] == DEVICE_OK, item["judge_id"]))
    return out


#: Stan, który znaczy „serwer nie wie, gdzie szukać tego administratora".
#: Reeksport dla wołających, żeby nie sięgali po moduł reguł tylko po nazwę.
NO_DEVICE = ADMIN_NO_DEVICE
