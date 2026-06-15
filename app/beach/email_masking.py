"""Email masking for safe logging / responses (never expose the full address)."""
from __future__ import annotations


def mask_email(email: str | None) -> str:
    """``radoslaw@domena.pl`` -> ``ra***@domena.pl``.

    Keeps at most the first two characters of the local part, masks the rest.
    Returns "" for blank input.
    """
    value = (email or "").strip()
    if not value or "@" not in value:
        return ""
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        masked_local = (local[:1] or "*") + "***"
    else:
        masked_local = local[:2] + "***"
    return f"{masked_local}@{domain}"
