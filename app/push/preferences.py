"""Jedna interpretacja preferencji zewnętrznych powiadomień BAZY.

Pole ``notifications.enabled`` w aplikacji steruje przypomnieniami przed
meczem. Nie jest przełącznikiem skrzynki serwerowej ani zmian wykrytych przez
monitor. Zewnętrzne wiadomości mają własne przełączniki w
``notificationTypes``. Wcześniejsze mieszanie tych dwóch znaczeń powodowało,
że wyłączenie przypomnień blokowało dodanie/usunięcie meczu, podczas gdy
powiadomienia dotyczące własnej czynności na Giełdzie nadal przychodziły.
"""
from __future__ import annotations

import json
from typing import Any, Mapping


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, Mapping) else {}
    return {}


def _type_enabled(preferences: Any, key: str) -> bool:
    prefs = _mapping(preferences)
    types = _mapping(prefs.get("notificationTypes"))
    # Brak pola oznacza zgodę: starsze wersje aplikacji nie znały wszystkich
    # przełączników i po aktualizacji nie mogą nagle zamilknąć.
    return types.get(key, True) is not False


def province_event_preference_key(event_type: str) -> str:
    if event_type in ("match_added", "match_removed", "assignment_removed"):
        return "newMatchAdded"
    if event_type == "lineup_changed":
        return "changeLineup"
    return "changeMatchData"


def province_event_allowed(preferences: Any, event_type: str) -> bool:
    """Czy urządzenie chce dany typ zmiany meczu z serwera."""
    return _type_enabled(preferences, province_event_preference_key(event_type))


def market_broadcast_allowed(preferences: Any) -> bool:
    """Czy urządzenie chce rozsyłkę o nowej ofercie na Giełdzie."""
    return _type_enabled(preferences, "matchMarket")
