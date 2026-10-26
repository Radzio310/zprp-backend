"""Konfiguracja connectora ze zmiennych srodowiskowych (bez wartosci domyslnych dla sekretow)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


def _csv(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


@dataclass
class Settings:
    portal_base_url: str = "https://portal.handball-bastion.pl"
    secrets_key: str = ""
    secrets_key_previous: list[str] = field(default_factory=list)
    connector_token: str = ""
    ticket_secret: str = ""
    allowed_origins: list[str] = field(default_factory=list)
    attempt_ttl_s: int = 600
    ticket_ttl_s: int = 60
    max_active_logins: int = 2
    embed_host_suffixes: list[str] = field(default_factory=lambda: ["mediadelivery.net"])
    probe_bunny_item_id: int | None = None
    data_dir: str = "./.data"
    test_page: bool = False
    headful: bool = False
    chromium_path: str = ""

    @property
    def portal_host(self) -> str:
        return urlsplit(self.portal_base_url).hostname or ""

    @classmethod
    def from_env(cls) -> "Settings":
        probe = os.environ.get("BASTION_PROBE_BUNNY_ITEM_ID", "").strip()
        flag = lambda n: os.environ.get(n, "").lower() in ("1", "true", "yes")  # noqa: E731
        return cls(
            portal_base_url=os.environ.get("BASTION_PORTAL_BASE_URL", cls.portal_base_url).rstrip("/"),
            secrets_key=os.environ.get("BASTION_SECRETS_KEY", ""),
            secrets_key_previous=_csv("BASTION_SECRETS_KEY_PREVIOUS"),
            connector_token=os.environ.get("BASTION_CONNECTOR_TOKEN", ""),
            ticket_secret=os.environ.get("BASTION_TICKET_SECRET", ""),
            allowed_origins=_csv("BASTION_ALLOWED_ORIGINS"),
            attempt_ttl_s=int(os.environ.get("BASTION_LOGIN_ATTEMPT_TTL_SECONDS", "600")),
            ticket_ttl_s=int(os.environ.get("BASTION_TICKET_TTL_SECONDS", "60")),
            max_active_logins=int(os.environ.get("BASTION_MAX_ACTIVE_LOGINS", "2")),
            embed_host_suffixes=_csv("BASTION_EMBED_HOST_SUFFIXES") or ["mediadelivery.net"],
            probe_bunny_item_id=int(probe) if probe.isdigit() else None,
            data_dir=os.environ.get("BASTION_DATA_DIR", "./.data"),
            test_page=flag("BASTION_TEST_PAGE"),
            headful=flag("BASTION_HEADFUL"),
            chromium_path=os.environ.get("BASTION_CHROMIUM_PATH", ""),
        )
