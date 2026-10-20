from datetime import datetime, timedelta, timezone

from app.zprp_public.ondemand import NegativeCache, backfill_sort_key, is_finished, needs_details

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def test_is_finished():
    assert is_finished(21, None, None, NOW)
    assert is_finished(None, NOW - timedelta(hours=1), None, NOW)
    assert not is_finished(None, None, NOW - timedelta(days=1), NOW)


def test_needs_details_staleness():
    recent = NOW - timedelta(days=1)
    old = NOW - timedelta(days=30)
    assert needs_details(None, True, old, NOW)
    assert not needs_details(None, False, recent, NOW)
    assert needs_details(NOW - timedelta(hours=7), True, recent, NOW)
    assert not needs_details(NOW - timedelta(hours=1), True, recent, NOW)
    assert not needs_details(NOW - timedelta(days=20), True, old, NOW)


def test_backfill_order():
    rows = {
        "old": (NOW - timedelta(days=60), None, 20),
        "new": (NOW - timedelta(days=2), None, 20),
        "newer": (NOW - timedelta(days=1), None, 20),
        "future": (None, NOW + timedelta(days=3), None),
        "nodate_sched": (None, NOW - timedelta(days=5), 18),
    }
    order = sorted(rows, key=lambda k: backfill_sort_key(*rows[k], NOW))
    assert order == ["newer", "new", "nodate_sched", "old", "future"]


def test_negative_cache_ttl():
    t = [0.0]
    cache = NegativeCache(ttl=10, clock=lambda: t[0])
    assert not cache.blocked("a")
    cache.block("a")
    assert cache.blocked("a")
    t[0] = 11
    assert not cache.blocked("a")


def test_invalidate_caches_clears_referee_index_and_extras():
    from app.zprp_public import extras, portal

    portal._REF_INDEX.update(at=1e12, rows=[{"referee_id": "1"}])
    portal._map_cache["x"] = (0.0, {})
    extras._cache["venue-index"] = (0.0, [])
    portal.invalidate_caches()
    assert portal._REF_INDEX["rows"] == [] and not portal._map_cache and not extras._cache
