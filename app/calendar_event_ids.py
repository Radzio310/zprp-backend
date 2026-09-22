"""Stable Google event IDs used by the idempotent calendar write path."""

import hashlib


def google_event_id(user_login: str, match_id: str) -> str:
    # Google accepts base32hex characters 0-9 and a-v; hexadecimal is a subset.
    return "baba" + hashlib.sha256(
        f"{user_login}:{match_id}".encode("utf-8")
    ).hexdigest()
