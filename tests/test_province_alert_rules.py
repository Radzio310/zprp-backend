"""Alerty mailowe o saldzie klubów - reguły, szablon i schemat (bez bazy)."""

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import MetaData

from app import province_alert_rules as A
from app.province_alert_emails import BudgetCard, build_message, render_text
from app.province_alert_tables import define_tables


# ---------------------------------------------------------------- konto i walidacja

def test_account_key_judge_vs_vip():
    assert A.account_key({"sub": "slaskie_vip", "account_type": "org"}) == "slaskie_vip"
    assert A.account_key({"sub": "Jan Kowalski", "judge_id": "1234"}) == "judge:1234"


@pytest.mark.parametrize("hours", [4, 8, 12, 24, "12"])
def test_intervals_allowed(hours):
    assert A.normalize_interval(hours) == int(hours)


@pytest.mark.parametrize("hours", [0, 1, 6, 48, "abc", None])
def test_intervals_rejected(hours):
    with pytest.raises(A.AlertRuleError):
        A.normalize_interval(hours)


def test_threshold():
    assert A.normalize_threshold("500,5") == 500.5
    for bad in (0, -10, "x", 2_000_000, float("nan")):
        with pytest.raises(A.AlertRuleError):
            A.normalize_threshold(bad)


def test_emails_dedupe_and_validation():
    assert A.normalize_emails([" a@b.pl ", "A@B.pl", "", "komisja@slzpr.pl"]) == ["a@b.pl", "komisja@slzpr.pl"]
    for bad in ("bez-malpy.pl", "a@b", "a b@c.pl", "a@.pl", "a@b..pl"):
        with pytest.raises(A.AlertRuleError) as err:
            A.normalize_emails([bad])
        assert bad in str(err.value)
    with pytest.raises(A.AlertRuleError):
        A.normalize_emails([f"x{i}@b.pl" for i in range(A.MAX_EMAILS + 1)])


def test_enabled_needs_address_but_disabled_does_not():
    with pytest.raises(A.AlertRuleError):
        A.validate_settings(enabled=True, threshold=500, interval_hours=24, emails=[])
    ok = A.validate_settings(enabled=False, threshold=500, interval_hours=24, emails=[])
    assert ok.enabled is False and ok.emails == []


# ---------------------------------------------------------------- harmonogram

def test_is_due_with_slack():
    now = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
    assert A.is_due(None, 4, now)
    assert A.is_due(now - timedelta(hours=3, minutes=56), 4, now)  # luz 5 minut
    assert not A.is_due(now - timedelta(hours=3, minutes=50), 4, now)
    assert A.next_check_at(now - timedelta(hours=1), 8, now) == now + timedelta(hours=7)
    assert A.next_check_at(None, 8, now) == now


# ---------------------------------------------------------------- wybór i „raz przy przekroczeniu"

BUDGETS = {
    "1": {"name": "MKS", "settles_via_district": True, "paid_in": 1000, "balance": 200},
    "2": {"name": "KS", "settles_via_district": True, "paid_in": 1000, "balance": 900},
    "3": {"name": "Poza okręgiem", "settles_via_district": False, "paid_in": 1000, "balance": -50},
    "4": {"name": "Bez wpłat", "settles_via_district": True, "paid_in": 0, "balance": -300},
    "5": {"name": "Na minusie", "settles_via_district": True, "paid_in": 300, "balance": -20},
}


def test_watched_budgets_only_district_with_payment():
    assert set(A.watched_budgets(BUDGETS)) == {"1", "2", "5"}


def test_decide_alerts_once_and_rearms():
    first = A.decide(BUDGETS, [], 500)
    assert first.alert == ["1", "5"] and first.rearm == [] and first.still_below == []

    # Mail poszedł - kolejne sprawdzenie milczy.
    second = A.decide(BUDGETS, ["1", "5"], 500)
    assert second.alert == [] and second.still_below == ["1", "5"]

    # Klub 1 dostał wpłatę - znacznik gaśnie, a po ponownym spadku mail wraca.
    topped = {**BUDGETS, "1": {**BUDGETS["1"], "balance": 500}}
    third = A.decide(topped, ["1", "5"], 500)
    assert third.rearm == ["1"] and third.alert == []
    fourth = A.decide(BUDGETS, ["5"], 500)
    assert fourth.alert == ["1"]


def test_decide_rearms_budget_that_left_watch():
    decision = A.decide(BUDGETS, ["3", "99"], 500)
    assert "3" in decision.rearm and "99" in decision.rearm


# ---------------------------------------------------------------- treść

def test_last_payment_skips_out_and_season_close():
    entries = [
        {"id": 1, "kind": "in", "amount": 300, "day": date(2026, 9, 1)},
        {"id": 2, "kind": "out", "amount": 999, "day": date(2026, 9, 20)},
        {"id": 3, "kind": "in", "amount": 150, "day": "2026-09-10"},
        {"id": 4, "kind": "in", "amount": 5000, "day": date(2026, 9, 21), "source": "season-close"},
    ]
    assert A.last_payment(entries) == (date(2026, 9, 10), 150.0)
    assert A.last_payment([]) is None


def test_spending_pace_formula():
    today = date(2026, 9, 23)
    charges = [
        (today - timedelta(days=1), 200),
        (today - timedelta(days=8), 200),
        (today - timedelta(days=20), 400),
        (today - timedelta(days=28), 999),  # poza oknem (granica wyłączna)
        (today + timedelta(days=2), 999),  # przyszłość
    ]
    pace = A.spending_pace(1000, charges, today)
    assert pace.window_matches == 3 and pace.window_total == 800
    assert pace.per_match == pytest.approx(266.67, abs=0.01)
    assert pace.per_week == 200
    assert pace.matches_left == 3 and pace.weeks_left == 5
    assert "ok. 3 mecze" in A.pace_sentence(pace) and "ok. 5 tygodni" in A.pace_sentence(pace)


def test_spending_pace_negative_and_empty():
    today = date(2026, 9, 23)
    assert A.spending_pace(-10, [(today, 100)], today).negative
    assert "na minusie" in A.pace_sentence(A.spending_pace(-10, [(today, 100)], today))
    empty = A.spending_pace(300, [], today)
    assert empty.matches_left is None and "nie było obciążeń" in A.pace_sentence(empty)


def test_plural_and_money_and_subject():
    assert [A.plural(n, "klub", "kluby", "klubów") for n in (1, 2, 5, 12, 22, 25)] == [
        "klub", "kluby", "klubów", "klubów", "kluby", "klubów",
    ]
    assert A.format_pln(1234.5) == "1 234,50 zł"
    assert A.format_pln(-20) == "-20 zł"
    assert A.subject_line("ŚLĄSKIE", 3, 500) == "Śląskie: 3 kluby poniżej 500 zł"
    assert A.province_title("KUJAWSKO-POMORSKIE") == "Kujawsko-Pomorskie"


def _card(balance: float) -> BudgetCard:
    today = date(2026, 9, 23)
    return BudgetCard(
        budget_id="1",
        name="MKS <Zabrze>",
        balance=balance,
        charged=1200,
        matches=6,
        last_payment=(date(2026, 9, 1), 1000.0),
        pace=A.spending_pace(balance, [(today, 200)], today),
        teams_label="3 drużyny",
    )


def test_message_renders_escaped_html_and_text(monkeypatch):
    monkeypatch.setenv("BAZA_WEB_URL", "https://baza.example/")
    monkeypatch.setenv("BACKEND_URL", "https://api.example")
    subject, html_body, text_body = build_message(
        province_key="SLASKIE",
        province_display="ŚLĄSKIE",
        threshold=500,
        cards=[_card(-40), _card(120)],
        account_label="slaskie_vip",
    )
    assert subject == "Śląskie: 2 kluby poniżej 500 zł"
    assert "MKS &lt;Zabrze&gt;" in html_body and "<Zabrze>" not in html_body
    assert "https://baza.example/explore" in html_body
    assert "https://api.example/province/alerts/logo/SLASKIE.png" in html_body
    assert "NA MINUSIE" in html_body and "PONIŻEJ PROGU" in html_body
    long_dash = chr(0x2014)  # zero długich myślników w treści maila
    assert long_dash not in html_body and long_dash not in text_body
    assert "Ostatnia wpłata: 1 000 zł · 01.09.2026" in text_body


def test_test_message_without_cards():
    text = render_text(province_display="ŚLĄSKIE", threshold=500, cards=[], link="x", test=True, preview_note="n")
    assert text.startswith("WIADOMOŚĆ PRÓBNA") and "żaden obserwowany klub" in text


# ---------------------------------------------------------------- schemat

def test_tables_schema():
    settings, state = define_tables(MetaData())
    assert [c.name for c in settings.primary_key.columns] == ["account_key", "province"]
    assert [c.name for c in state.primary_key.columns] == ["account_key", "province", "budget_id"]
    assert settings.c.enabled.default.arg is False
    assert str(settings.c.emails.type) == "TEXT"


# ---------------------------------------------------------------- trasy (bez bazy)

def test_alert_routes_require_token():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.province_alerts import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    assert client.get("/province/alerts/settings", params={"province": "SLASKIE"}).status_code == 401
    assert client.put("/province/alerts/settings", json={"province": "SLASKIE"}).status_code == 401
    assert client.post("/province/alerts/test", json={"province": "SLASKIE"}).status_code == 401


def test_refusal_reuses_settlements_permission(monkeypatch):
    import asyncio

    from app import province_alerts, province_panel_guard
    from app.province_panel_access import VipRecord

    async def lookup(payload):
        return False, VipRecord(username="vip", province="ŚLĄSKIE", permissions={"assignments": True})

    monkeypatch.setattr(province_panel_guard, "_lookup", lookup)
    reason = asyncio.run(
        province_alerts._refusal({"sub": "vip", "account_type": "org"}, "SLASKIE")
    )
    assert "Rozliczenia" in reason

    async def lookup_ok(payload):
        return False, VipRecord(username="vip", province="ŚLĄSKIE", permissions={"settlements": True})

    monkeypatch.setattr(province_panel_guard, "_lookup", lookup_ok)
    assert asyncio.run(province_alerts._refusal({"sub": "vip", "account_type": "org"}, "SLASKIE")) == ""


def test_test_preview_picks_below_or_lowest():
    from app.province_alerts import Snapshot, _preview

    snap = Snapshot(budgets=BUDGETS, charges={}, entries={}, source="clubs")
    ids, note = _preview(snap, 500)
    assert ids == ["5", "1"] and "Poniżej progu" in note
    ids, note = _preview(snap, 10)
    assert ids == ["5"]
    ids, note = _preview(snap, -100)
    assert ids == ["5", "1", "2"] and "dla przykładu" in note
