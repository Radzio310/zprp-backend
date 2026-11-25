"""Rejestr prób ProEla: reguły bez bazy (`app/proel_attempt_rules.py`)."""
from datetime import datetime, timedelta, timezone

from app.proel_attempt_rules import (
    REASON_LABELS,
    bump_episode,
    clean_event,
    dispute_push,
    dispute_push_due,
    is_hard_start_block,
    lease_episode_key,
    login_cutoff,
    login_failure_reason,
    merge_update,
    reason_label,
    start_block_push,
    summarize,
)

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


def test_clean_event_rejects_without_key_kind_or_outcome():
    assert clean_event({"kind": "start", "outcome": "ok"}) is None
    assert clean_event({"event_key": "a", "kind": "zly", "outcome": "ok"}) is None
    assert clean_event({"event_key": "a", "kind": "start", "outcome": "zly"}) is None
    assert clean_event("x") is None


def test_clean_event_drops_password_and_unknown_fields_and_ok_reason():
    ev = clean_event({
        "event_key": "k1", "kind": "login", "outcome": "ok", "reason": "BAD_CREDENTIALS",
        "password": "tajne", "path": "proel_account", "actor_login": "jan", "count": 3,
        "steps": [{"step": "a", "result": "ok", "ms": 12}, {"step": "b", "result": "??"}],
        "device": {"platform": "ios", "form": "tablet", "junk": 1},
    })
    assert ev is not None
    assert "password" not in ev
    assert ev["reason"] is None
    assert ev["path"] == "proel_account"
    assert ev["count"] == 3
    assert ev["steps"] == [{"step": "a", "result": "ok", "ms": 12}]
    assert ev["device"] == {"platform": "ios", "form": "tablet"}


def test_clean_event_path_must_match_kind():
    ev = clean_event({"event_key": "k", "kind": "start", "outcome": "blocked", "path": "identity_gate"})
    assert ev["path"] is None


def test_merge_update_keeps_identity_and_takes_latest_result():
    existing = {"count": 2, "reason_text": "stary", "steps": [{"step": "a", "result": "ok"}], "blocker": "app"}
    incoming = clean_event({"event_key": "k", "kind": "start", "outcome": "ok", "count": 1})
    out = merge_update(existing, incoming, NOW)
    assert out["outcome"] == "ok" and out["reason"] is None
    assert out["count"] == 2 and out["last_at"] == NOW
    assert out["reason_text"] == "stary" and out["blocker"] == "app"
    assert "kind" not in out and "actor_judge_id" not in out


def test_bump_episode_increments():
    assert bump_episode({"count": 4}, NOW) == {"count": 5, "last_at": NOW}


def test_lease_episode_key_stable_and_short():
    k = lease_episode_key("LEASE_HELD", "JmK 12/34", "inst", 7)
    assert k == lease_episode_key("LEASE_HELD", "JmK 12/34", "inst", 7)
    assert k != lease_episode_key("LEASE_HELD", "JmK 12/34", "inst", 8)
    assert len(lease_episode_key("LEASE_HELD", "x" * 200, "i" * 200, 1)) <= 80


def test_dispute_push_throttled_once_per_match_per_window():
    last = {}
    assert dispute_push_due(last, "M1", 1000.0) is True
    assert dispute_push_due(last, "M1", 1300.0) is False
    assert dispute_push_due(last, "M2", 1300.0) is True
    assert dispute_push_due(last, "M1", 1601.0) is True


def test_hard_start_block_only_official_blocked_not_yet_escalated():
    base = {"kind": "start", "outcome": "blocked", "official": True}
    assert is_hard_start_block(base)
    assert not is_hard_start_block({**base, "official": False})
    assert not is_hard_start_block({**base, "official": None})
    assert not is_hard_start_block({**base, "outcome": "bypassed"})
    assert not is_hard_start_block({**base, "kind": "lead"})
    assert not is_hard_start_block({**base, "escalated_at": NOW})


def test_push_texts_polish_and_no_long_dashes():
    row = {"actor_name": "Jan Kowalski", "match_number": "12/34", "reason": "RATE_LIMIT",
           "holder_name": "Ewa", "kind": "lead"}
    for t in (start_block_push(row), dispute_push({**row, "reason": "TAKEN_OVER"}),
              dispute_push({**row, "reason": "LEASE_LOST"}), dispute_push({**row, "reason": "LEASE_HELD"})):
        assert "12/34" in t["body"]
        assert "—" not in t["body"] + t["title"] and "–" not in t["body"] + t["title"]
    assert "Jan Kowalski" in start_block_push(row)["body"]


def test_labels_have_no_long_dashes_and_cover_contract_codes():
    for code, text in REASON_LABELS.items():
        assert text and "—" not in text and "–" not in text, code
    for code in ("LEASE_HELD", "LEASE_LOST", "TAKEN_OVER", "RECLAIMED", "BAD_CREDENTIALS", "ACCOUNT_DISABLED", "OFFLINE"):
        assert code in REASON_LABELS
    assert reason_label("NIEZNANY") == "NIEZNANY"


def test_login_failure_reason():
    assert login_failure_reason(403, "Konto zostało dezaktywowane") == "ACCOUNT_DISABLED"
    assert login_failure_reason(401, "Nie ma takiego użytkownika") == "UNKNOWN_USER"
    assert login_failure_reason(401, "Nieprawidłowe hasło") == "BAD_CREDENTIALS"


def test_login_cutoff_is_12_months():
    assert NOW - login_cutoff(NOW) == timedelta(days=365)


def test_summarize_counts_attempts_by_count_and_ranks():
    rows = [
        {"kind": "start", "outcome": "ok", "count": 1, "actor_judge_id": "1", "actor_name": "A", "match_number": "M1", "duration_ms": 4000},
        {"kind": "start", "outcome": "ok", "count": 1, "actor_judge_id": "1", "actor_name": "A", "match_number": "M1", "duration_ms": 6000},
        {"kind": "start", "outcome": "blocked", "reason": "RATE_LIMIT", "count": 3, "actor_judge_id": "2", "actor_name": "B", "match_number": "M1"},
        {"kind": "login", "outcome": "blocked", "reason": "BAD_CREDENTIALS", "count": 2},
        {"kind": "lead", "outcome": "blocked", "reason": "LEASE_HELD", "count": 2, "actor_judge_id": "2", "actor_name": "B", "match_number": "M2"},
        {"kind": "zly", "outcome": "ok", "count": 9},
    ]
    s = summarize(rows)
    assert s["totals"]["start"] == {"ok": 2, "blocked": 3, "bypassed": 0, "abandoned": 0}
    assert s["totals"]["login"]["blocked"] == 2
    assert s["totals"]["lead"]["blocked"] == 2
    assert s["median_start_ms"] == 5000
    assert s["top_reasons"][0] == {"reason": "RATE_LIMIT", "label": reason_label("RATE_LIMIT"), "kind": "start", "count": 3}
    assert s["top_people"][0]["judge_id"] == "2" and s["top_people"][0]["blocked"] == 5
    assert s["matches"][0] == {"match_number": "M1", "blocked": 3, "lead_conflicts": 0}
    assert {"match_number": "M2", "blocked": 0, "lead_conflicts": 2} in s["matches"]


def test_summarize_empty():
    s = summarize([])
    assert s["median_start_ms"] is None and s["top_reasons"] == [] and s["matches"] == []


# ── dopasowania pod zakładkę admina ──
from sqlalchemy.dialects import postgresql

from app.proel_attempt_stmt import build_list_stmt


def _sql(**kw):
    c = build_list_stmt(**kw).compile(dialect=postgresql.dialect())
    return str(c), c.params


def test_before_id_is_exclusive_and_works_alone():
    sql, params = _sql(before_id=43)
    where = sql.split("WHERE")[1].split("ORDER BY")[0]
    assert "proel_attempt_log.id <" in where and "<=" not in where
    assert " AND " not in where and "kind" not in where
    assert 43 in params.values()


def test_actor_matches_judge_id_or_login_case_insensitive():
    sql, params = _sql(actor="  Jan.K ")
    where = sql.split("WHERE")[1]
    assert "lower(proel_attempt_log.actor_judge_id)" in where
    assert "lower(proel_attempt_log.actor_login)" in where and " OR " in where
    assert "LIKE" not in where.upper()
    assert list(params.values()).count("jan.k") == 2


def test_summary_by_blocker_counts_only_blocked_with_blocker():
    rows = [
        {"kind": "start", "outcome": "blocked", "blocker": "zprp", "count": 3},
        {"kind": "lead", "outcome": "blocked", "blocker": "other_device", "count": 1},
        {"kind": "start", "outcome": "blocked", "blocker": "zprp", "count": 1},
        {"kind": "start", "outcome": "blocked", "blocker": None, "count": 5},
        {"kind": "start", "outcome": "ok", "blocker": "app", "count": 7},
    ]
    assert summarize(rows)["by_blocker"] == [
        {"blocker": "zprp", "count": 4}, {"blocker": "other_device", "count": 1}]
    assert summarize([])["by_blocker"] == []


def test_push_data_matches_admin_alert_shape():
    from app.proel_attempt_rules import attempt_push_data

    d = attempt_push_data({"id": 17, "kind": "lead", "match_number": "12/34"})
    assert d == {"kind": "admin_alert", "alertKind": "proel_attempt", "type": "proel_attempt",
                 "ref": "17", "id": "17", "attemptKind": "lead", "match_number": "12/34"}
    assert all(isinstance(v, str) for v in d.values())


# ── scalanie odmowy klienta z epizodem serwera ──
from app.proel_attempt_rules import fill_server_row, should_merge_into_server

_SRV = {"source": "server", "kind": "lead", "reason": "LEASE_LOST", "match_number": "M1",
        "actor_install": "i1", "last_at": NOW, "count": 3, "holder_name": "Ewa"}


def _cli(**kw):
    base = {"kind": "lead", "reason": "LEASE_LOST", "match_number": "M1", "actor_install": "i1",
            "client_at": NOW + timedelta(minutes=2)}
    base.update(kw)
    return base


def test_merge_same_match_install_reason_in_window():
    assert should_merge_into_server(_cli(), _SRV, NOW)
    assert should_merge_into_server(_cli(client_at=None), _SRV, NOW + timedelta(minutes=9))
    assert should_merge_into_server(_cli(reason="LEASE_HELD"), {**_SRV, "reason": "LEASE_HELD"}, NOW)


def test_no_merge_outside_window():
    assert not should_merge_into_server(_cli(client_at=NOW + timedelta(minutes=11)), _SRV, NOW)
    assert not should_merge_into_server(_cli(client_at=None), _SRV, NOW + timedelta(minutes=11))


def test_no_merge_other_reason_or_kind_or_source():
    assert not should_merge_into_server(_cli(reason="LEASE_SHARED"), {**_SRV, "reason": "LEASE_SHARED"}, NOW)
    assert not should_merge_into_server(_cli(reason="LEASE_HELD"), _SRV, NOW)
    assert not should_merge_into_server(_cli(kind="start"), _SRV, NOW)
    assert not should_merge_into_server(_cli(), {**_SRV, "source": "client"}, NOW)
    assert not should_merge_into_server(_cli(match_number="M2"), _SRV, NOW)


def test_no_merge_without_install():
    assert not should_merge_into_server(_cli(actor_install=None), _SRV, NOW)
    assert not should_merge_into_server(_cli(actor_install=""), {**_SRV, "actor_install": ""}, NOW)


def test_fill_server_row_never_touches_count_or_holder():
    out = fill_server_row({**_SRV, "reason_text": "ogólny", "actor_name": ""},
                          {"reason_text": "Mecz prowadzi Ewa", "net": "online", "queued": True,
                           "actor_name": "Jan", "steps": [{"step": "a", "result": "fail"}]})
    assert out["reason_text"] == "Mecz prowadzi Ewa" and out["actor_name"] == "Jan"
    assert out["net"] == "online" and out["queued"] is True
    assert "count" not in out and not any(k.startswith("holder_") for k in out)
    assert fill_server_row({"actor_name": "Stary"}, {"actor_name": "Nowy"})["actor_name"] == "Stary"


def test_clean_event_rejects_server_keys_and_future_times():
    from app.proel_attempt_rules import clean_event
    base = {"kind": "lead", "outcome": "blocked", "reason": "LEASE_HELD"}
    assert clean_event({**base, "event_key": "srv:LEASE_HELD:1:x:1"}) is None
    assert clean_event({**base, "event_key": "SRV:x"}) is None
    ok = clean_event({**base, "event_key": "u-1", "last_at": "2999-01-01T00:00:00Z"})
    assert ok is not None and ok["last_at"] is None
