"""Reguly miniatur Trybuny: blad nie zakrywa przyczyny, wybor ponowien (bez bazy)."""
import importlib
from datetime import datetime, timedelta, timezone

import pytest

from tests.mentor_panel_support import Env

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def TH(monkeypatch, tmp_path):
    Env(monkeypatch, tmp_path)  # baza testowa musi stac przed importem app.db
    return importlib.import_module("app.mentor_trybuna_thumbs")


def test_not_connected_does_not_overwrite_real_error(TH):
    first = TH.merge_error(None, "BASTION_FRAME_FAILED", "ffprobe:timeout 30s")
    assert first == "BASTION_FRAME_FAILED: ffprobe:timeout 30s"
    assert TH.merge_error(first, "BASTION_NOT_CONNECTED") == first


def test_real_error_replaces_soft_one_and_detail_is_cut(TH):
    assert TH.merge_error("BASTION_NOT_CONNECTED", "BASTION_FRAME_FAILED", "x") == "BASTION_FRAME_FAILED: x"
    assert TH.merge_error(None, "BASTION_NOT_CONNECTED") == "BASTION_NOT_CONNECTED"
    assert len(TH.merge_error(None, "E", "y" * 500)) == 200


def test_reply_error_reads_error_and_detail(TH):
    class R:
        status, body = 502, {"error": "BASTION_FRAME_FAILED", "detail": "goto:TimeoutError"}
    assert TH.reply_error(R) == ("BASTION_FRAME_FAILED", "goto:TimeoutError")
    class R2:
        status, body = 500, {}
    assert TH.reply_error(R2) == ("HTTP 500", None)


def row(error, attempts=5, hours=7, status="failed"):
    return {"status": status, "error": error, "attempts": attempts, "updated_at": NOW - timedelta(hours=hours)}


def test_should_retry_transient_after_six_hours(TH):
    assert TH.should_retry(row("BASTION_NOT_CONNECTED"), NOW)
    assert TH.should_retry(row("BASTION_FRAME_FAILED: ffmpeg:rc=1"), NOW)
    assert TH.should_retry(row("HTTP 502"), NOW)
    assert not TH.should_retry(row("BASTION_NOT_CONNECTED", hours=5), NOW)


def test_should_not_retry_permanent_limit_or_other_status(TH):
    assert not TH.should_retry(row("BASTION_NO_EMBED"), NOW)
    assert not TH.should_retry(row("BASTION_NOT_CONNECTED", attempts=TH.LIFETIME_MAX_ATTEMPTS), NOW)
    assert not TH.should_retry(row("BASTION_NOT_CONNECTED", status="ready"), NOW)
    assert not TH.should_retry({"status": "failed", "error": "BASTION_NOT_CONNECTED", "attempts": 5, "updated_at": None}, NOW)
