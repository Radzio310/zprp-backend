"""Szkice ocen młodych sędziów - reguły bez bazy (testowane osobno).

Szkic = niedokończony formularz oceny. Autor to numer sędziego z tokenu;
klucz szkicu wybiera aplikacja (`<id oceny>` albo `new:<mecz>:<sędzia>`).
JSON z bazy bywa surowym napisem (zob. gielda-meczow-reguly), więc każdy
odczyt payloadu idzie przez `payload_dict`.
"""

from __future__ import annotations

import json
from typing import Any, Optional

MAX_KEY_LEN = 200
MAX_PAYLOAD_BYTES = 400_000


def clean_key(raw: Any) -> str:
    key = str(raw or "").strip()
    if not key or len(key) > MAX_KEY_LEN:
        return ""
    return key


def payload_dict(raw: Any) -> dict:
    """Payload jako słownik - z napisu JSON albo gotowego dict; inaczej pusty."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (str, bytes)):
        try:
            val = json.loads(raw)
        except (ValueError, TypeError):
            return {}
        return val if isinstance(val, dict) else {}
    return {}


def encode_payload(payload: Any) -> Optional[str]:
    """Napis JSON do zapisu albo None, gdy payload nie jest słownikiem lub jest za duży."""
    if not isinstance(payload, dict) or not payload:
        return None
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return None
    return text
