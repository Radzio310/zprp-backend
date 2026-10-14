from app.zprp_public.discord import alert_payload


def test_sync_alert_is_minimal_and_disables_mentions():
    payload = alert_payload(kind="clubs", run_id=42, error_count=3)

    assert payload["allowed_mentions"] == {"parse": []}
    assert payload["embeds"][0]["color"] == 0xD94B55
    encoded = str(payload)
    assert "clubs" in encoded
    assert "3" in encoded
    assert "error" not in encoded.casefold()


def test_recovery_alert_has_distinct_success_state():
    payload = alert_payload(kind="live", run_id="77", error_count=0, recovered=True)

    assert payload["embeds"][0]["color"] == 0x2EAF72
    assert "wróciła" in payload["embeds"][0]["title"]
