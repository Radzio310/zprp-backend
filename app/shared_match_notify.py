"""Powiadomienia o meczach wspólnych (31.10.2026): dodanie do meczu, usunięcie z obsady, usunięcie meczu przez twórcę.

Treści to liście (bez bazy) - zdanie zawsze ma podmiot-człowieka i składa się też wtedy, gdy czegoś brakuje.
Przełącznik w telefonie: `sharedMatch` (`app/push/preferences.py`). Autor zmiany nie dostaje własnego pusha.
Wysyłka nigdy nie cofa zapisu - błąd kończy się wpisem w logu.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional

from app.shared_match_rules import role_label, s

logger = logging.getLogger("app.shared_match")

PREFERENCE_KEY = "sharedMatch"
ACCENT = "#2E7DD7"


def match_label(match: Mapping[str, Any]) -> str:
    """„SPR Gliwice - KS Opole (12.10)" albo kod, albo samo „mecz"."""
    home, away = s(match.get("home_name")), s(match.get("away_name"))
    teams = f"{home} - {away}" if home and away else (home or away)
    code = s(match.get("code"))
    day = s(match.get("date_key"))
    when = ""
    if len(day) == 10 and day[4] == "-":
        when = f"{day[8:10]}.{day[5:7]}"
    label = teams or code or "mecz"
    if teams and code:
        label = f"{teams}, {code}"
    return f"{label} ({when})" if when else label


def added(match: Mapping[str, Any], actor_name: Any, role: Any) -> tuple[str, str]:
    who = s(actor_name) or "Ktoś"
    as_role = role_label(role)
    return "Dodano Cię do meczu", f"{who} dodał(a) Cię do meczu {match_label(match)} jako {as_role}."


def joined(match: Mapping[str, Any], actor_name: Any, role: Any) -> tuple[str, str]:
    who = s(actor_name) or "Ktoś"
    return "Ktoś dołączył do Twojego meczu", f"{who} dołączył(a) do meczu {match_label(match)} jako {role_label(role)}. Możesz usunąć tę osobę z obsady."


def removed(match: Mapping[str, Any], actor_name: Any) -> tuple[str, str]:
    who = s(actor_name) or "Twórca meczu"
    return "Usunięto Cię z obsady meczu", f"{who} usunął(ęła) Cię z obsady meczu {match_label(match)}."


def deleted(match: Mapping[str, Any], actor_name: Any) -> tuple[str, str]:
    who = s(actor_name) or "Twórca meczu"
    return "Mecz został usunięty", f"{who} usunął(ęła) mecz {match_label(match)} u wszystkich."


def push_data(match_id: str, event: str) -> Dict[str, str]:
    return {
        "type": "shared_match", "kind": "shared_match", "event": event, "matchId": s(match_id),
        "tag": f"shared-match-{match_id}", "notificationTag": f"shared-match-{match_id}", "notificationColor": ACCENT,
    }


async def send(recipients: Iterable[str], actor_id: str, title: str, body: str, match_id: str, event: str) -> Optional[Dict[str, Any]]:
    """Push do wskazanych sędziów, bez autora zmiany. Zwraca raport wysyłki albo None."""
    ids: List[str] = sorted({s(r) for r in recipients if s(r) and s(r) != s(actor_id)})
    if not ids:
        return None
    try:
        from app.push.push import send_push_to_judges_report

        return await send_push_to_judges_report(ids, title, body, push_data(match_id, event), app_variant="baza",
                                                preference_key=PREFERENCE_KEY)
    except Exception:  # noqa: BLE001 - push nie cofa zapisu
        logger.warning("mecz wspólny: push nieudany", exc_info=True)
        return None
