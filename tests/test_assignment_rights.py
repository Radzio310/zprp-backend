"""Pamięć praw do formularza obsady i rozgrywanie w tle - na atrapach, bez ZPRP."""
import asyncio
import time

import pytest

from app import assignment_rights as R
from test_assignment_access import state, table_official_form_html
from app.zprp import assignments as Z


@pytest.fixture(autouse=True)
def clean():
    R._memory.clear()
    R._warming.clear()
    yield
    R._memory.clear()
    R._warming.clear()


def parsed(mid="208136"):
    return Z._parse_referee_form(table_official_form_html())


def test_compact_keeps_roles_and_names_only_for_editable_slots():
    rights = R.compact(parsed())
    assert rights["slots"]["sekretarz"]["editable"] and rights["slots"]["czas"]["editable"]
    assert not rights["slots"]["sedzia1"]["editable"]
    assert rights["slots"]["sedzia1"]["names"] == []
    assert rights["slots"]["sekretarz"]["names"]


def test_public_view_never_exposes_names():
    view = R.public_view(R.compact(parsed()))
    assert all(set(slot) == {"editable", "field_kind"} for slot in view["slots"].values())


def test_info_for_candidates_matches_live_read_shape():
    info = R.info_from_rights(R.compact(parsed()))
    assert info["verified"] and info["auto_slots"] == ["sekretarz", "czas"]
    assert set(info["allowed_names"]) == {"sekretarz", "czas"}


def test_account_key_needs_the_password_too():
    assert R.account_key("jan", "a") != R.account_key("jan", "b")
    assert R.account_key("Jan ", "a") == R.account_key("jan", "a")


async def test_remember_and_recall_by_age():
    rights = R.compact(parsed())
    await R.remember("acc", "1", rights)
    assert "1" in await R.recall_many("acc", ["1"])
    assert "1" in await R.recall_many("acc", ["1"], R.FRESH_SECONDS)
    assert await R.recall_many("other", ["1"]) == {}
    _memory_old = {**rights, "at": time.time() - R.FRESH_SECONDS - 5}
    await R.remember("acc", "2", _memory_old)
    assert "2" in await R.recall_many("acc", ["2"])          # panel pokazuje też nieświeże
    assert await R.recall_many("acc", ["2"], R.FRESH_SECONDS) == {}


async def test_warm_reads_in_order_two_at_a_time_and_skips_fresh():
    await R.remember("acc", "1", R.compact(parsed()))
    seen, running, peak = [], 0, 0

    async def read(mid):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        seen.append(mid)
        await asyncio.sleep(0.01)
        running -= 1
        return {**parsed(), "IdZawody": mid}

    out = await R.warm("acc", ["1", "2", "3", "4", "5"], read)
    assert "1" not in seen and sorted(seen) == ["2", "3", "4", "5"]
    assert seen[:2] == ["2", "3"]
    assert peak <= 2
    assert set(out["rights"]) == {"1", "2", "3", "4", "5"} and not out["failed"]
    # Drugie wołanie nie dotyka ZPRP.
    seen.clear()
    await R.warm("acc", ["1", "2", "3"], read)
    assert seen == []


async def test_warm_failures_and_foreign_form_are_not_remembered():
    async def read(mid):
        if mid == "bad":
            raise RuntimeError("ZPRP padło")
        return {**parsed(), "IdZawody": "inny" if mid == "wrong" else mid}

    out = await R.warm("acc", ["ok", "bad", "wrong"], read)
    assert set(out["rights"]) == {"ok"}
    assert sorted(out["failed"]) == ["bad", "wrong"]
    assert await R.recall_many("acc", ["bad", "wrong"]) == {}


async def test_warm_is_limited_and_one_per_account():
    async def read(mid):
        await asyncio.sleep(0.05)
        return {**parsed(), "IdZawody": mid}

    ids = [str(i) for i in range(20)]
    first = asyncio.create_task(R.warm("acc", ids, read))
    await asyncio.sleep(0.01)
    second = await R.warm("acc", ids, read)
    assert second["busy"] and second["rights"] == {}
    done = await first
    assert len(done["rights"]) == R.WARM_MAX_IDS


async def test_candidates_use_stored_monitor_rights_without_zprp(monkeypatch):
    from types import SimpleNamespace
    from app import assignment_live_access as live
    from app import zprp_accounts, deps
    live._cache.clear()
    monkeypatch.setattr(zprp_accounts, "credentials_for", lambda *args: ("monitor", "pw"))
    monkeypatch.setattr(deps, "get_settings", lambda: SimpleNamespace(ZPRP_BASE_URL="https://example.invalid"))
    await R.remember(R.account_key("monitor", "pw"), "208136", R.compact(parsed()))
    result = await live.verify_matches("SLASKIE", {"208136": state()})
    access = result["208136"]["assignment_access"]
    assert access["verified"] and access["auto_slots"] == ["sekretarz", "czas"]
    # Zapamiętane prawa nie poszerzają zawężonej maski z terminarza.
    narrow = state()
    narrow["assignment_access"]["auto_slots"] = ["czas"]
    result = await live.verify_matches("SLASKIE", {"208136": narrow})
    assert result["208136"]["assignment_access"]["auto_slots"] == ["czas"]


async def test_stale_stored_rights_are_not_used_for_candidates(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from app import assignment_live_access as live
    from app import zprp_accounts, deps, utils
    from app.zprp import schedule
    live._cache.clear()
    monkeypatch.setattr(zprp_accounts, "credentials_for", lambda *args: ("monitor", "pw"))
    monkeypatch.setattr(deps, "get_settings", lambda: SimpleNamespace(ZPRP_BASE_URL="https://example.invalid"))
    old = {**R.compact(parsed()), "at": time.time() - R.FRESH_SECONDS - 10}
    await R.remember(R.account_key("monitor", "pw"), "208136", old)
    calls = []

    async def login(*args):
        return {}

    async def fetch(client, path, **kwargs):
        calls.append(kwargs["data"])
        return None, table_official_form_html()
    monkeypatch.setattr(schedule, "_login_zprp_and_get_cookies", login)
    monkeypatch.setattr(utils, "fetch_with_correct_encoding", fetch)
    await live.verify_matches("SLASKIE", {"208136": state()})
    assert len(calls) == 1
    live._cache.clear()
