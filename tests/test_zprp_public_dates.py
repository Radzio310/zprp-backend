def test_naive_local_converts_aware_datetimes():
    from datetime import datetime, timezone
    from app.zprp_public.match_rules import naive_local as _naive_local

    assert _naive_local(None) is None
    assert _naive_local(datetime(2026, 10, 16, 10, 0)) == datetime(2026, 10, 16, 10, 0)
    aware = _naive_local(datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc))
    assert aware == datetime(2026, 10, 16, 12, 0) and aware.tzinfo is None
