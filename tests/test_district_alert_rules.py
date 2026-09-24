"""Powiadomienia okręgu z Obsady - reguły, teksty, szablony i schemat (bez bazy)."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import MetaData

from app import assignment_rules as AR
from app import district_alert_rules as R
from app import offtime_rules as O
from app.district_alert_emails import (
    CollisionCard,
    CollisionRow,
    SlotLine,
    Suggestion,
    UnassignedCard,
    build_collision_message,
    build_unassigned_message,
    obsada_url,
)
from app.district_alert_tables import define_tables
from app.province_alert_rules import AlertRuleError

UTC = timezone.utc


def utc(*args):
    return datetime(*args, tzinfo=UTC)


# ---------------------------------------------------------------- konfiguracja


def test_defaults_are_off_and_threshold_72():
    cfg = R.default_config()
    assert not cfg[R.UNASSIGNED]["enabled"] and not cfg[R.COLLISION]["enabled"]
    assert cfg[R.UNASSIGNED]["threshold_hours"] == 72
    assert cfg["quiet"] == {"enabled": True, "start": 22, "end": 7}
    assert cfg[R.COLLISION]["kinds"] == list(R.KINDS)
    assert not R.any_enabled(cfg)


def test_normalize_is_lenient():
    cfg = R.normalize_config({"unassigned": {"threshold_hours": 13, "enabled": "true"}, "quiet": {"start": 99}, "junk": 1})
    assert cfg[R.UNASSIGNED]["threshold_hours"] == 72
    assert cfg[R.UNASSIGNED]["enabled"] is True
    assert cfg["quiet"]["start"] == 22
    assert "junk" not in cfg
    assert R.normalize_config(None) == R.default_config()


def test_validate_rejects_bad_threshold_and_nowhere_to_go():
    with pytest.raises(AlertRuleError):
        R.validate_config({"unassigned": {"threshold_hours": 50}})
    with pytest.raises(AlertRuleError):
        R.validate_config({"unassigned": {"enabled": True, "email": False, "push": False}})
    with pytest.raises(AlertRuleError):
        R.validate_config(
            {"unassigned": {"enabled": True, "email": True, "emails": [], "email_managers": False, "push": True}}
        )
    with pytest.raises(AlertRuleError):
        R.validate_config({"collision": {"enabled": True, "kinds": []}})
    with pytest.raises(AlertRuleError):
        R.validate_config({"unassigned": {"emails": ["zly-adres"]}})


def test_validate_accepts_and_dedupes_emails():
    cfg = R.validate_config(
        {"unassigned": {"enabled": True, "threshold_hours": 48, "emails": ["a@b.pl", "A@B.pl"]}, "collision": {"kinds": ["offtime", "x"]}}
    )
    assert cfg[R.UNASSIGNED]["emails"] == ["a@b.pl"]
    assert cfg[R.UNASSIGNED]["threshold_hours"] == 48
    assert cfg[R.COLLISION]["kinds"] == ["offtime"]
    assert R.any_enabled(cfg)


def test_scope_filter():
    section = {"competitions": ["S/JmM"], "categories": []}
    assert R.scope_allows(section, "s/jmm", "Junior ml.")
    assert not R.scope_allows(section, "S/MłM", "Młodzik")
    assert R.scope_allows({}, "x", "y")


# ---------------------------------------------------------------- cisza nocna


def test_quiet_window_wraps_midnight():
    assert R.in_quiet(datetime(2026, 9, 26, 23, 0), 22, 7)
    assert R.in_quiet(datetime(2026, 9, 27, 6, 59), 22, 7)
    assert not R.in_quiet(datetime(2026, 9, 27, 7, 0), 22, 7)
    assert not R.in_quiet(datetime(2026, 9, 27, 12, 0), 22, 7)
    assert R.in_quiet(datetime(2026, 9, 27, 13, 0), 12, 14)
    assert not R.in_quiet(datetime(2026, 9, 27, 13, 0), 5, 5)


def test_push_waits_until_morning_in_polish_time():
    # 23:00 w Polsce (CEST, UTC+2) = 21:00 UTC. Mecz za dwa dni.
    now = utc(2026, 9, 26, 21, 0)
    due = R.push_due_at(now, now + timedelta(days=2), {"enabled": True, "start": 22, "end": 7})
    assert due == utc(2026, 9, 27, 5, 0)  # 7:00 w Polsce
    # Po północy - ten sam poranek.
    now = utc(2026, 9, 27, 1, 30)
    assert R.push_due_at(now, now + timedelta(days=2), {"enabled": True, "start": 22, "end": 7}) == utc(2026, 9, 27, 5, 0)


def test_push_urgent_or_daytime_goes_now():
    now = utc(2026, 9, 26, 21, 0)
    assert R.push_due_at(now, now + timedelta(hours=11), {"enabled": True, "start": 22, "end": 7}) == now
    day = utc(2026, 9, 26, 10, 0)
    assert R.push_due_at(day, day + timedelta(days=3), {"enabled": True, "start": 22, "end": 7}) == day
    assert R.push_due_at(now, now + timedelta(days=3), {"enabled": False}) == now


# ---------------------------------------------------------------- mecz bez obsady


def person(name, number="1"):
    return {"number": number, "name": name}


def test_missing_slots_uses_needs_model():
    # Senior/junior: 2 boiskowych, 2 stolikowych od okręgu.
    needs = AR.club_crew_needs("S/JmM/12")
    crew = {"pierwszy": person("NOWAK Jan"), "sekretarz": person("KOWAL Ewa")}
    assert R.missing_slots(crew, needs) == {"field": 1, "table": 1}
    assert R.missing_slots(crew, needs, count_soft_table=False) == {"field": 1, "table": 0}
    # Klub stawia drugiego stolikowego - jeden od okręgu to komplet.
    club = AR.club_crew_needs("S/JmM/12", 1)
    assert R.missing_slots({**crew, "drugi": person("A B")}, club) == {"field": 0, "table": 0}
    # Dzieci: jeden boiskowy, stolika od okręgu nie ma.
    kids = AR.club_crew_needs("S/DZM/3")
    assert R.missing_slots({"pierwszy": person("X Y")}, kids) == {"field": 0, "table": 0}
    # Delegat nie liczy się nigdy.
    assert R.missing_slots({"delegat": person("D E")}, kids) == {"field": 1, "table": 0}


def test_due_stages():
    assert R.due_stages(80, 72) == []
    assert R.due_stages(70, 72) == [R.STAGE_THRESHOLD]
    assert R.due_stages(20, 72) == [R.STAGE_THRESHOLD, R.STAGE_FINAL]
    assert R.due_stages(20, 72, remind_24h=False) == [R.STAGE_THRESHOLD]
    assert R.due_stages(20, 24) == [R.STAGE_THRESHOLD]
    assert R.due_stages(-1, 72) == []


def item(match_id, hours, now, **extra):
    base = {
        "match_id": match_id,
        "code": f"S/JmM/{match_id}",
        "competition": "S/JmM",
        "category": "Junior ml.",
        "host": "KS Zgoda",
        "guest": "Grunwald",
        "hall": "Hala MOSiR",
        "city": "Zabrze",
        "crew": {},
        "needs": AR.club_crew_needs("S/JmM/1"),
        "league": False,
        "season_unknown": False,
        "approved": False,
        "score": None,
        "match_at_dt": now + timedelta(hours=hours),
    }
    base.update(extra)
    return base


def test_plan_unassigned_once_per_stage_and_rearm():
    now = utc(2026, 9, 24, 10, 0)
    section = R.default_config()[R.UNASSIGNED]
    items = [
        item("1", 60, now),
        item("2", 20, now),
        item("3", 100, now),
        item("4", 30, now, crew={s: person(s) for s in ("pierwszy", "drugi", "sekretarz", "czas")}),
        item("5", 30, now, league=True),
        item("6", 30, now, host="SPR Sośnica pauzuje"),
    ]
    plan = R.plan_unassigned(items, set(), section, now)
    ids = [hit.match_id for hit in plan.hits]
    assert ids == ["2", "1"]  # najbliższy pierwszy; 3 poza oknem, 4 komplet, 5 liga, 6 pauza
    first = plan.hits[0]
    assert first.stages == [R.STAGE_THRESHOLD, R.STAGE_FINAL] and first.email and first.push_stage == R.STAGE_FINAL
    assert first.missing == {"field": 2, "table": 2}

    done = {R.unassigned_key("1", R.STAGE_THRESHOLD), R.unassigned_key("2", R.STAGE_THRESHOLD), R.unassigned_key("4", R.STAGE_THRESHOLD)}
    plan = R.plan_unassigned(items, done, section, now)
    # Mecz 2 dostaje tylko przypomnienie 24 h (bez maila), mecz 1 nic, mecz 4 gasi znacznik.
    assert [(hit.match_id, hit.stages, hit.email) for hit in plan.hits] == [("2", [R.STAGE_FINAL], False)]
    assert plan.rearm == ["4"]
    assert plan.open_in_window == 2


def test_plan_unassigned_filters():
    now = utc(2026, 9, 24, 10, 0)
    section = {**R.default_config()[R.UNASSIGNED], "categories": ["Senior"]}
    assert R.plan_unassigned([item("1", 10, now)], set(), section, now).hits == []


# ---------------------------------------------------------------- kolizje


def info(match_id, local_dt, city, host="KS Zgoda", guest="Grunwald"):
    return R.MatchInfo(match_id=match_id, code=f"S/JmM/{match_id}", moment=local_dt, city=city, hall="Hala", host=host, guest=guest)


def km_table(a, b):
    return {frozenset({"Zabrze", "Gliwice"}): 38.0}.get(frozenset({a, b}), 0.0 if a == b else None)


def test_overlap_and_city_and_offtime():
    moved = info("10", datetime(2026, 9, 26, 14, 0), "Zabrze")
    near = info("11", datetime(2026, 9, 26, 15, 0), "Gliwice", host="Sośnica", guest="Piast")
    evening = info("12", datetime(2026, 9, 26, 20, 0), "Gliwice")
    other_day = info("13", datetime(2026, 9, 27, 14, 0), "Gliwice")
    offs, _ = O.parse_entries(
        [
            {"from": "2026-09-26T12:00:00", "to": "2026-09-26T18:00:00", "category_name": "Praca"},
            {"from": "2026-09-26T13:30:00", "isMatch": True},
        ]
    )
    found = R.find_collisions("7", "Jan Nowak", moved, [moved, near, evening, other_day], offs, km_table)
    kinds = sorted(item.kind for item in found)
    assert kinds == [R.KIND_CITY, R.KIND_OFFTIME, R.KIND_OVERLAP]
    overlap = next(item for item in found if item.kind == R.KIND_OVERLAP)
    assert overlap.other.match_id == "11" and overlap.km == 38.0 and overlap.gap_minutes == 60
    # Junior młodszy (S/JmM) trwa 1:30, do tego dojazd 38 km przy 60 km/h i 30 min zapasu.
    assert overlap.short_minutes == 90 + 38 + 30 - 60
    only = R.find_collisions("7", "Jan Nowak", moved, [near], [], km_table, kinds=[R.KIND_CITY])
    assert only == []


def test_collision_key_is_symmetric_and_includes_time():
    a = info("10", datetime(2026, 9, 26, 14, 0), "Zabrze")
    b = info("11", datetime(2026, 9, 26, 15, 0), "Zabrze")
    one = R.Collision(kind=R.KIND_OVERLAP, judge_id="7", judge_name="x", moved=a, other=b)
    two = R.Collision(kind=R.KIND_OVERLAP, judge_id="7", judge_name="x", moved=b, other=a)
    assert one.key == two.key
    moved_again = info("10", datetime(2026, 9, 26, 16, 0), "Zabrze")
    assert R.Collision(kind=R.KIND_OVERLAP, judge_id="7", judge_name="x", moved=moved_again, other=b).key != one.key
    assert len(R.short_key("x" * 400)) < 200


def test_undated_never_collides():
    moved = info("10", None, "Zabrze")
    assert R.find_collisions("7", "x", moved, [info("11", datetime(2026, 9, 26, 15, 0), "Zabrze")], [], km_table) == []


# ---------------------------------------------------------------- teksty


def test_judge_push_is_concrete():
    moved = info("10", datetime(2026, 9, 26, 14, 0), "Zabrze")
    near = info("11", datetime(2026, 9, 26, 15, 0), "Gliwice")
    item_ = R.find_collisions("7", "Nowak Jan", moved, [near], [], km_table, kinds=[R.KIND_OVERLAP])[0]
    title, body = R.judge_push(item_)
    assert title == "Kolizja w Twoim terminarzu"
    assert body == "Kolizja: KS Zgoda - Grunwald przeniesiony na sob. 26.09, 14:00, a o 15:00 masz mecz (Gliwice, 38 km)."
    m_title, m_body = R.manager_push([item_])
    assert m_title == "Kolizja po zmianie terminu · S/JmM/10"
    assert "NOWAK Jan: o 15:00 ma mecz (Gliwice, 38 km)" in m_body
    assert "—" not in body + m_body and "–" not in body + m_body


def test_offtime_push_mentions_entry():
    moved = info("10", datetime(2026, 9, 26, 14, 0), "Zabrze")
    offs, _ = O.parse_entries([{"from": "2026-09-26T12:00:00", "to": "2026-09-26T18:00:00", "category_name": "Praca"}])
    item_ = R.find_collisions("7", "Jan Nowak", moved, [], offs, km_table)[0]
    assert R.judge_push(item_)[1].endswith("w tym czasie masz niedyspozycję (Praca, 12:00-18:00).")


def test_times_are_polish():
    # 12:00 UTC w lecie to 14:00 w Polsce, a w zimie 13:00.
    assert R.when_text(utc(2026, 9, 26, 12, 0)) == "sob. 26.09, 14:00"
    assert R.when_text(utc(2026, 12, 5, 12, 0)) == "sob. 05.12, 13:00"
    assert R.when_long(utc(2026, 9, 26, 12, 0)) == "sobota 26.09.2026, 14:00"


def test_unassigned_push_and_summary():
    now = utc(2026, 9, 24, 10, 0)
    plan = R.plan_unassigned([item("1", 50, now), item("2", 60, now)], set(), R.default_config()[R.UNASSIGNED], now)
    title, body = R.unassigned_push(plan.hits[0])
    assert title == "Brak obsady · S/JmM/1 · za 2 dni 2 h"
    assert body == "KS Zgoda - Grunwald, sob. 26.09, 14:00, Zabrze. Brakuje: 2 sędziów boiskowych i 2 stolikowych."
    s_title, s_body = R.unassigned_summary_push(plan.hits, 72)
    assert s_title == "2 mecze bez obsady w ciągu 72 h"


def test_missing_text_and_hours():
    assert R.missing_text({"field": 1, "table": 0}) == "1 sędziego boiskowego"
    assert R.missing_text({"field": 2, "table": 1}) == "2 sędziów boiskowych i 1 stolikowego"
    assert R.hours_left_text(0.5) == "za 30 min"
    assert R.hours_left_text(9) == "za 9 h"
    assert R.hours_left_text(48) == "za 2 dni"


def test_push_data_is_strings_and_opens_match():
    data = R.push_data(
        alert=R.COLLISION, audience="judge", province="SLASKIE", match_id="123", code="S/JmM/1",
        title="t", body="b", extra={"count": 3, "empty": ""},
    )
    assert all(isinstance(value, str) for value in data.values())
    assert data["kind"] == "district_alert" and data["matchId"] == "123" and data["matchNumber"] == "S/JmM/1"
    assert data["count"] == "3" and "empty" not in data


# ---------------------------------------------------------------- maile


def test_unassigned_email_renders_concrete_card():
    card = UnassignedCard(
        match_id="123", code="S/JmM/1", teams="KS Zgoda - <Grunwald>", when="sobota 26.09.2026, 14:00",
        hours_left=50, left_text="za 2 dni 2 h", competition="Junior młodszy", hall="Hala MOSiR", city="Zabrze",
        missing={"field": 1, "table": 0},
        slots=[SlotLine("Sędzia 1", "NOWAK Jan"), SlotLine("Sędzia 2", None), SlotLine("Mierzący czas", None, required=False, from_club=True)],
        suggestions=[Suggestion("KOWALSKI Adam", 12.4, "para z NOWAK Jan")],
        suggest_kind="field",
    )
    subject, html_body, text_body = build_unassigned_message(
        province_key="SLASKIE", province_display="ŚLĄSKIE", threshold=72, cards=[card]
    )
    assert subject == "Śląskie: brak obsady - S/JmM/1, sobota 26.09.2026, 14:00"
    assert "&lt;Grunwald&gt;" in html_body and "<Grunwald>" not in html_body
    assert "BRAK" in html_body and "od klubu gospodarza" in html_body and "KOWALSKI Adam" in html_body
    assert obsada_url("123") in html_body and "12 km" in html_body
    assert "Automat proponuje: KOWALSKI Adam (12 km)" in text_body


def test_collision_email_renders():
    card = CollisionCard(
        match_id="10", code="S/JmM/10", teams="KS Zgoda - Grunwald", when="sobota 26.09.2026, 14:00",
        previous="piątek 25.09.2026, 18:00", hall="Hala", city="Zabrze",
        rows=[CollisionRow("NOWAK Jan", R.KIND_OVERLAP, "O 15:00 ma mecz (Gliwice, 38 km).", "")],
    )
    subject, html_body, text_body = build_collision_message(
        province_key="SLASKIE", province_display="ŚLĄSKIE", cards=[card], test=True, preview_note="Próbka."
    )
    assert subject.startswith("[TEST] Śląskie: kolizja - S/JmM/10 przeniesiony na sobota")
    assert "DWA MECZE NARAZ" in html_body and "<s>piątek 25.09.2026, 18:00</s>" in html_body
    assert "Wiadomość próbna" in html_body and "Było: piątek" in text_body


# ---------------------------------------------------------------- schemat


def test_tables_schema():
    settings, marks, outbox, times = define_tables(MetaData())
    assert [c.name for c in settings.primary_key.columns] == ["province"]
    assert [c.name for c in marks.primary_key.columns] == ["province", "dedupe_key"]
    assert [c.name for c in times.primary_key.columns] == ["province", "match_id"]
    assert str(settings.c.config.type) == "TEXT" and str(outbox.c.data.type) == "TEXT"
