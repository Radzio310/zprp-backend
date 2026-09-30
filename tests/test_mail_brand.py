"""Grafiki w nagłówkach maili BAZY i nadawcy (`app/mail_brand.py`)."""

import asyncio

import pytest
from fastapi import HTTPException

from app import mail_brand as B


def test_asset_urls_only_for_allowed_files(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "https://api.test/")
    assert B.mail_asset_url("obsi.png") == "https://api.test/mail-assets/obsi.png"
    with pytest.raises(ValueError):
        B.mail_asset_url("../db.py")


def test_assets_exist_and_are_small():
    for name in B.ALLOWED_ASSETS:
        path = B.ASSETS_DIR / name
        assert path.is_file(), name
        assert path.stat().st_size < 200_000, name


def test_route_serves_allowlist_only():
    response = asyncio.run(B.mail_asset("bazus.png"))
    assert response.media_type == "image/png"
    with pytest.raises(HTTPException):
        asyncio.run(B.mail_asset("main.py"))


def test_brand_image_has_fixed_size_for_outlook():
    img = B.brand_image("bazus.png", 52)
    assert 'width="52"' in img and 'height="52"' in img


def test_baza_sender_falls_back_until_env_is_set(monkeypatch):
    monkeypatch.delenv(B.BAZA_SENDER_ENV, raising=False)
    assert B.baza_sender_email("obsady@catchapp.com.pl") == "obsady@catchapp.com.pl"
    monkeypatch.setenv(B.BAZA_SENDER_ENV, "baza@catchapp.com.pl")
    assert B.baza_sender_email("obsady@catchapp.com.pl") == "baza@catchapp.com.pl"


def test_templates_use_brand_images():
    root = B.ASSETS_DIR.parent
    unavailability = (root / "zprp_unavailability.py").read_text(encoding="utf-8")
    assert 'brand_cell("obsi.png"' in unavailability
    for name in ("province_alert_emails.py", "district_alert_emails.py"):
        assert "baza_signature(" in (root / name).read_text(encoding="utf-8"), name
    assert 'brand_cell("bazus.png"' in (root / "proel_users" / "emails.py").read_text(encoding="utf-8")
