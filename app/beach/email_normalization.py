"""Email normalization + validation helpers."""
from __future__ import annotations

import re

# Pragmatic, deliberately permissive RFC-ish validation. Full RFC 5322 is not
# worth the complexity here — Brevo will reject anything truly invalid.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(raw: str | None) -> str:
    """Trim + lowercase. Returns "" for None/blank."""
    return (raw or "").strip().lower()


def is_valid_email(raw: str | None) -> bool:
    candidate = (raw or "").strip()
    if not candidate or len(candidate) > 254:
        return False
    return bool(_EMAIL_RE.match(candidate))
