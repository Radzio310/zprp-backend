"""
Verification-code generation and hashing.

- 6-digit codes from a cryptographically secure source (``secrets``).
- Codes are NEVER stored in plaintext. We store an HMAC-SHA256 digest keyed by
  an application secret (``EMAIL_CODE_SECRET``), bound to the user id so the same
  code for two users yields different hashes.
- Constant-time comparison via ``hmac.compare_digest``.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from app.beach.email_config import get_email_config

CODE_REGEX = r"^[0-9]{6}$"


def generate_code() -> str:
    """Return a uniformly-random 6-digit code, e.g. ``"007421"``."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_code_for_key(key: str, code: str) -> str:
    """HMAC-SHA256 of ``"{key}:{code}"`` keyed by EMAIL_CODE_SECRET.

    ``key`` binds the code to a context (a user id, or ``"signup:<email>"`` for
    pre-account verification) so the same code yields different hashes.
    """
    secret = get_email_config().code_secret
    return hmac.new(
        secret.encode("utf-8"),
        f"{key}:{code}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_code_for_key(key: str, code: str, expected_hash: str) -> bool:
    candidate = hash_code_for_key(key, code)
    return hmac.compare_digest(candidate, expected_hash or "")


def hash_code(user_id: int, code: str) -> str:
    """HMAC-SHA256 bound to a user id (post-account verification)."""
    return hash_code_for_key(str(int(user_id)), code)


def verify_code(user_id: int, code: str, expected_hash: str) -> bool:
    """Constant-time check of ``code`` against a stored hash."""
    return hmac.compare_digest(hash_code(user_id, code), expected_hash or "")


def signup_key(email_normalized: str) -> str:
    return f"signup:{email_normalized}"
