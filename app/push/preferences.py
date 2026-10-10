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


def _type_enabled_compat(preferences: Any, key: str, legacy_key: str) -> bool:
    """Czyta nowy przełącznik, a w starym pliku zachowuje dawną decyzję."""
    prefs = _mapping(preferences)
    types = _mapping(prefs.get("notificationTypes"))
    if key in types:
        return types.get(key) is not False
    return types.get(legacy_key, True) is not False


def province_event_preference_key(event_type: str) -> str:
    if event_type in ("match_added", "match_removed", "assignment_removed"):
        return "matchAssignment"
    if event_type == "lineup_changed":
        return "lineup"
    if event_type in ("protocol_approved", "protocol_reopened"):
        return "protocolStatus"
    if event_type == "delegate_evaluation_available":
        return "delegateEvaluation"
    if event_type in ("match_date_changed", "match_updated"):
        return "scheduleVenue"
    return "changeMatchData"


def province_event_allowed(
    preferences: Any,
    event_type: str,
    *,
    preference_keys: Any = None,
) -> bool:
    """Czy urządzenie chce dany typ zmiany meczu z serwera."""
    keys = [str(key) for key in (preference_keys or []) if str(key)]
    if not keys:
        keys = [province_event_preference_key(event_type)]
    legacy = {
        "matchAssignment": "newMatchAdded",
        "scheduleVenue": "changeMatchData",
        "lineup": "changeLineup",
        "protocolStatus": "changeMatchData",
        "delegateEvaluation": "changeMatchData",
        "changeMatchData": "changeMatchData",
    }
    # Scalona rewizja może należeć do kilku kategorii. Wysyłamy ją, jeżeli
    # użytkownik pozostawił włączoną przynajmniej jedną z nich.
    return any(
        _type_enabled_compat(preferences, key, legacy.get(key, key))
        for key in keys
    )


def notification_type_allowed(preferences: Any, key: str) -> bool:
    """Czy urządzenie chce powiadomienia z przełącznikiem ``key``."""
    return _type_enabled(preferences, key)


def market_broadcast_allowed(preferences: Any) -> bool:
    """Czy urządzenie chce rozsyłkę o nowej ofercie na Giełdzie."""
    return _type_enabled(preferences, "matchMarket")
