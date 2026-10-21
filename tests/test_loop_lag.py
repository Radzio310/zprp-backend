import asyncio
import time

import pytest

from app import loop_lag


@pytest.mark.asyncio
async def test_monitor_catches_blocking_task_with_stack():
    loop_lag._spikes.clear()
    loop_lag.start()
    await asyncio.sleep(0.3)

    async def blocker():
        time.sleep(0.6)  # celowa blokada pętli

    await asyncio.create_task(blocker(), name="test-blocker")
    await asyncio.sleep(0.3)
    rep = loop_lag.report()
    loop_lag.stop()
    assert rep["spikes"], rep
    spike = rep["spikes"][0]
    assert spike["lag_ms"] >= 400
    assert "blocker" in spike["task"]
    assert any("blocker" in f for f in spike["stack"])


def test_busy_after_request():
    loop_lag._state["recent_lag_ms"] = 0.0
    loop_lag._state["last_request"] = time.monotonic()
    assert loop_lag.busy()
    loop_lag._state["last_request"] = 0.0
    assert not loop_lag.busy()
