from datetime import datetime, timedelta, timezone

import pytest

from app import exam_rules as X
from app import exam_web_rules as R

NOW = datetime(2026, 10, 24, 20, 0, tzinfo=timezone.utc)


def test_domyslna_reakcja_ostrzezenie_i_oddanie_po_trzech():
    assert X.DEFAULT_ANTI["web"] == {"reaction": "submit", "submit_after": 3}
    assert R.web_policy({"anti": {}}) == {"reaction": "submit", "submit_after": 3}
    assert R.web_policy({"anti": {"web": {"reaction": "zle"}}}) == {"reaction": "submit", "submit_after": 3}


def test_clean_web_odrzuca_zle_wartosci_zdaniem():
    with pytest.raises(X.ExamError):
        X.clean_web({"reaction": "kara"})
    with pytest.raises(X.ExamError):
        X.clean_web({"reaction": "submit", "submit_after": 0})
    assert X.clean_web({"reaction": "log"}) == {"reaction": "log", "submit_after": 3}


def test_stary_egzamin_bez_web_nie_blokuje_patcha():
    old = {"anti": {"leave_app": "log", "screenshots": False}}
    new = {"anti": {"leave_app": "log", "screenshots": False, "web": dict(X.DEFAULT_WEB)}}
    assert "anti" not in X.locked_changes(old, new)


def test_zapis_naruszen_i_sygnalow_cichych():
    leave = R.record_shape("tab_hidden", {"seconds": 4})
    assert leave["kind"] == "app_background" and leave["detail"]["source"] == "web" and leave["counted"]
    assert R.record_shape("printscreen", {})["kind"] == "screenshot"
    assert R.record_shape("devtools", {})["kind"] == "web_signal"
    quiet = R.record_shape("copy", {})
    assert quiet["kind"] is None and not quiet["counted"]
    assert R.record_shape("cokolwiek", {}) is None


def test_reakcja_ostrzega_a_potem_oddaje():
    policy = {"reaction": "submit", "submit_after": 3}
    assert R.decide(policy, 1, 1)["action"] == "warned"
    assert R.decide(policy, 2, 1)["left"] == 1
    assert R.decide(policy, 3, 1)["action"] == "submitted"
    assert R.decide({"reaction": "log", "submit_after": 3}, 9, 1)["action"] == "logged"
    assert R.decide({"reaction": "warn", "submit_after": 3}, 9, 1)["action"] == "warned"
    assert R.decide(policy, 3, 0)["action"] == "none"


def test_rytm_rowny_szybki_i_zawieszenia():
    assert "rhythm_uniform" in R.rhythm_flags([10000, 10100, 9900, 10050, 9950, 10000])
    assert "rhythm_rapid" in R.rhythm_flags([1500, 2000, 1800, 9000, 12000, 2500])
    assert "rhythm_spike" in R.rhythm_flags([8000, 9000, 7000, 90000, 8500, 95000, 9000])
    assert R.rhythm_flags([1000, 2000]) == []
    assert R.rhythm_flags([5000, 14000, 8000, 22000, 11000, 6500]) == []


def test_flagi_podejscia():
    events = [{"kind": "web_signal", "detail": {"source": "web", "signal": "devtools", "counted": True}},
              {"kind": "app_background", "detail": {"source": "web", "signal": "tab_hidden", "seconds": 40}},
              {"kind": "app_background", "detail": {}}, {"kind": "app_background", "detail": {}}]
    quiet = {"clicks": 30, "counts": {"copy": 3, "context_menu": 2}}
    flags = R.attempt_flags(events, [], quiet, "web_violations")
    assert flags[0] == "auto_submitted"
    assert {"devtools", "left_often", "long_absence", "clicks_outside", "blocked_attempts"} <= set(flags)
    assert R.violation_count(events) == 4


def test_merge_quiet_sumuje_klikniecia_i_strefy():
    q = R.merge_quiet({}, "click_outside", {"count": 3, "zones": {"top": 2, "left": 1}})
    q = R.merge_quiet(q, "click_outside", {"count": 2, "zones": {"top": 1}})
    q = R.merge_quiet(q, "copy", {})
    assert q["clicks"] == 5 and q["zones"] == {"top": 3, "left": 1} and q["counts"] == {"copy": 1}


def test_os_zdarzen_t_ms_i_etykiety():
    start = NOW
    events = [{"id": 1, "kind": "web_signal", "detail": {"source": "web", "signal": "guard_left", "counted": True},
               "at": (start + timedelta(seconds=12)).isoformat()}]
    axis = R.timeline_events(events, start)
    assert axis[0]["t_ms"] == 12000 and axis[0]["label"].startswith("Telefon-strażnik") and axis[0]["counted"]


def test_stan_straznika():
    assert R.guard_state(None, NOW)["state"] == "none"
    link = {"guard_device_id": "d1", "guard_seen_at": NOW - timedelta(seconds=3), "guard_state": "ok", "guard_label": "iPhone"}
    assert R.guard_state(link, NOW)["state"] == "ok"
    assert R.guard_state({**link, "guard_state": "away"}, NOW)["state"] == "away"
    assert R.guard_state({**link, "guard_seen_at": NOW - timedelta(seconds=60)}, NOW)["state"] == "silent"
