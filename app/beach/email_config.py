"""
Email-verification configuration (Brevo).

Reads configuration from environment variables only. The Brevo API key lives
exclusively on the host (Railway) — it must never be logged nor exposed to the
mobile client (no EXPO_PUBLIC_* mirror).

Provides ``validate_email_config()`` for fail-fast startup validation in
production.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)


class EmailConfigError(RuntimeError):
    """Raised when required email configuration is missing/invalid."""


def _get(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _get_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid int for %s=%r — using default %s", name, raw, default)
        return default


@dataclass(frozen=True)
class EmailConfig:
    brevo_api_key: str
    from_email: str
    from_name: str
    code_secret: str
    ttl_minutes: int
    resend_seconds: int
    app_public_url: str
    environment: str
    webhook_secret: str
    grace_days: int
    grace_delete_enabled: bool

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def ttl_seconds(self) -> int:
        return self.ttl_minutes * 60


@lru_cache(maxsize=1)
def get_email_config() -> EmailConfig:
    return EmailConfig(
        brevo_api_key=_get("BREVO_API_KEY"),
        from_email=_get("BREVO_FROM_EMAIL"),
        from_name=_get("BREVO_FROM_NAME", "BAZA Beach"),
        code_secret=_get("EMAIL_CODE_SECRET"),
        ttl_minutes=_get_int("EMAIL_VERIFICATION_TTL_MINUTES", 15),
        resend_seconds=_get_int("EMAIL_VERIFICATION_RESEND_SECONDS", 60),
        app_public_url=_get("APP_PUBLIC_URL"),
        environment=_get("ENVIRONMENT", "development"),
        webhook_secret=_get("BREVO_WEBHOOK_SECRET"),
        grace_days=_get_int("EMAIL_VERIFICATION_GRACE_DAYS", 90),
        grace_delete_enabled=_get("EMAIL_GRACE_DELETE_ENABLED", "true").lower()
        not in ("0", "false", "no"),
    )


def validate_email_config() -> None:
    """Fail-fast in production when critical secrets are missing.

    In non-production environments missing values only emit a warning so local
    development without Brevo still boots.
    """
    cfg = get_email_config()
    missing = [
        name
        for name, value in (
            ("BREVO_API_KEY", cfg.brevo_api_key),
            ("BREVO_FROM_EMAIL", cfg.from_email),
            ("EMAIL_CODE_SECRET", cfg.code_secret),
        )
        if not value
    ]
    if missing:
        msg = "Brakuje wymaganych zmiennych konfiguracji e-mail: " + ", ".join(missing)
        if cfg.is_production:
            # Never log the values themselves — only the names.
            raise EmailConfigError(msg)
        logger.warning("%s (ostrzeżenie poza produkcją)", msg)
    else:
        logger.info(
            "✅ Email verification config OK (env=%s, ttl=%dmin, resend=%ds)",
            cfg.environment,
            cfg.ttl_minutes,
            cfg.resend_seconds,
        )
