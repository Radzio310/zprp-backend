"""Cicha odnowa sesji (05.11.2026): osobny zaszyfrowany stan Discorda i bezpieczniki odnowy."""
import asyncio
import base64
import os
import time

import pytest

from connector import crypto
from connector.config import Settings
from connector.service import Service
from connector.store import StateStore, filter_state_to_host


def key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


DISCORD = {"cookies": [{"name": "__dcfduid", "value": "x", "domain": ".discord.com", "path": "/"}],
           "origins": [{"origin": "https://discord.com", "localStorage": [{"name": "token", "value": "SECRET"}]}]}


def test_discord_state_roundtrip_separate_aad_and_delete(tmp_path):
    st = StateStore(str(tmp_path), key())
    st.save("default", {"cookies": [], "origins": []}, {"generation": 1})
    assert not st.has_discord("default")
    st.save_discord("default", DISCORD)
    assert st.has_discord("default")
    raw = (tmp_path / "states" / "default.discord.enc").read_bytes()
    assert b"SECRET" not in raw  # zaszyfrowane
    assert st.load_discord("default") == DISCORD
    # plik Discorda nie odszyfruje sie jako stan innego polaczenia
    other = tmp_path / "states" / "personal-7.discord.enc"
    other.write_bytes(raw)
    with pytest.raises(crypto.CryptoError):
        st.load_discord("personal-7")
    # rozlaczenie kasuje oba pliki
    assert st.delete("default")
    assert not st.has_discord("default")


def test_filter_discord_host_keeps_only_discord():
    full = {"cookies": DISCORD["cookies"] + [{"name": "s", "value": "p", "domain": "portal.handball-bastion.pl"}],
            "origins": DISCORD["origins"] + [{"origin": "https://portal.handball-bastion.pl", "localStorage": []}]}
    out = filter_state_to_host(full, "discord.com")
    assert [c["name"] for c in out["cookies"]] == ["__dcfduid"]
    assert [o["origin"] for o in out["origins"]] == ["https://discord.com"]


def _svc(tmp_path, **kw) -> Service:
    return Service(Settings(secrets_key=key(), data_dir=str(tmp_path), **kw))


def test_renew_needs_discord_and_flag(tmp_path):
    svc = _svc(tmp_path)
    svc.store.save("default", {"cookies": [], "origins": []}, {"generation": 1})
    assert asyncio.run(svc.renew("default")) is False  # brak stanu Discorda
    off = _svc(tmp_path, auto_renew=False)
    off.store.save_discord("default", DISCORD)
    assert asyncio.run(off.renew("default")) is False  # wylaczona flaga


def test_renew_respects_cooldown_without_browser(tmp_path):
    svc = _svc(tmp_path, renew_cooldown_s=1800)
    svc.store.save("default", {"cookies": [], "origins": []}, {"generation": 1, "renew_failed_ts": time.time() - 60})
    svc.store.save_discord("default", DISCORD)

    async def boom(*a, **k):  # przegladarka nie moze ruszyc w trakcie przerwy po porazce
        raise AssertionError("odnowa w trakcie przerwy")

    svc._renew_run = boom
    assert asyncio.run(svc.renew("default")) is False


def test_renew_failure_is_recorded(tmp_path):
    svc = _svc(tmp_path)
    svc.store.save("default", {"cookies": [], "origins": []}, {"generation": 3})
    svc.store.save_discord("default", DISCORD)

    async def fail(key, discord, meta):
        assert discord == DISCORD and meta["generation"] == 3
        return False, "discord wymaga logowania"

    svc._renew_run = fail
    assert asyncio.run(svc.renew("default")) is False
    meta = svc.store.load("default")[1]
    assert meta["renew_failed_reason"] == "discord wymaga logowania" and meta["renew_failed_ts"] > 0
    assert meta["generation"] == 3  # stan sesji nietkniety
