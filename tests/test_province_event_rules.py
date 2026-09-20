from datetime import datetime, timedelta, timezone

import pytest

from app import province_event_rules as R

UTC = timezone.utc


def judges():
    return [
        {"judge_id": "1", "badges": {"Delegaci": True}},
        {"judge_id": "2", "badges": {"Komisja sędziowska": True}},
        {"judge_id": "3", "badges": ["Młodzi"]},
        {"judge_id": "4", "badges": '{"Delegaci": true, "Młodzi": true}'},
        {"judge_id": "5", "badges": {}},
    ]


def test_zaproszeni_licza_sie_z_aktualnych_odznak_i_osob():
    assert R.invited_ids(judges(), {"target": {"include_badges": ["Delegaci"]}}) == ["1", "4"]
    everyone_but = {"target": {"include_all": True, "exclude_badges": ["Młodzi"]}}
    assert R.invited_ids(judges(), everyone_but) == ["1", "2", "5"]
    people = {"target": {"include_badges": ["Delegaci"]}, "include_ids": ["5"], "exclude_ids": ["4"]}
    assert R.invited_ids(judges(), people) == ["1", "5"]
    # Ręczne dopisanie wygrywa z wykluczoną odznaką, wyłączenie osoby - ze wszystkim.
    assert R.invited_ids(judges(), {"target": {"include_all": True, "exclude_badges": ["Młodzi"]}, "include_ids": ["3"]}) == ["1", "2", "3", "5"]
    # Stare wydarzenie bez kryteriów idzie do wszystkich, jak liczył dawny serwer.
    assert R.invited_ids(judges(), {"target": {}}) == ["1", "2", "3", "4", "5"]
    # Same osoby bez odznak = tylko te osoby.
    assert R.invited_ids(judges(), {"target": {}, "include_ids": ["2"]}) == ["2"]
    young = judges() + [{"judge_id": "6", "badges": [R.YOUNG_DISTRICT_BADGE]}]
    assert R.invited_ids(young, {"target": {"include_badges": [R.YOUNG_DISTRICT_BADGE]}}) == ["6"]


def test_komisja_zarzadza_tylko_swoim_okregiem():
    commission = R.viewer(judge_id="2", province="śląskie", is_admin=False, badges={"Komisja Sędziowska": True})
    assert R.can_manage(commission, "ŚLĄSKIE")
    assert not R.can_manage(commission, "OPOLSKIE")
    plain = R.viewer(judge_id="1", province="ŚLĄSKIE", is_admin=False, badges={"Delegaci": True})
    assert not R.can_manage(plain, "ŚLĄSKIE")
    assert R.can_view_province(plain, "ŚLĄSKIE") and not R.can_view_province(plain, "OPOLSKIE")
    admin = R.viewer(judge_id="9", province="", is_admin=True, badges={})
    assert R.can_manage(admin, "OPOLSKIE") and R.can_view_province(admin, "LUBUSKIE")


def test_walidacja_terminow_i_pol():
    start, end = R.clean_period("2026-10-01T16:00:00Z", "2026-10-01T18:00:00Z")
    assert end - start == timedelta(hours=2)
    with pytest.raises(R.Invalid, match="później"):
        R.clean_period("2026-10-01T16:00:00Z", "2026-10-01T15:00:00Z")
    with pytest.raises(R.Invalid, match="14 dni"):
        R.clean_period("2026-10-01T16:00:00Z", "2026-10-20T15:00:00Z")
    with pytest.raises(R.Invalid, match="przed rozpoczęciem"):
        R.clean_deadline("2026-10-02T00:00:00Z", start)
    assert R.clean_capacity("0") is None and R.clean_capacity(25) == 25
    with pytest.raises(R.Invalid):
        R.clean_capacity(-3)
    assert R.clean_type("") == "other"
    with pytest.raises(R.Invalid):
        R.clean_type("mecz")
    program = R.clean_program([{"time": "10:00", "title": " Powitanie "}, {"title": ""}, "x", {"time": "11:30", "title": "Testy"}])
    assert [p["title"] for p in program] == ["Powitanie", "Testy"]
    with pytest.raises(R.Invalid, match="GG:MM"):
        R.clean_program([{"time": "25:00", "title": "Źle"}])
    details = R.clean_details({"online_url": "meet.google.com/abc", "place": {"name": " Hala "}}, start)
    assert details["online_url"] == "https://meet.google.com/abc"
    assert details["place"] == {"name": "Hala", "address": None}


def test_odpowiedz_bede_nie_bede():
    now = datetime(2026, 9, 20, 12, tzinfo=UTC)
    start = datetime(2026, 9, 25, 16, tzinfo=UTC)
    base = dict(now=now, start=start, deadline=None, cancelled=False, invited=True, current=None, yes_count=0, capacity=None)
    assert R.rsvp_refusal(**base, status="yes") is None
    assert "Będę" in R.rsvp_refusal(**base, status="maybe")
    assert "skierowane" in R.rsvp_refusal(**{**base, "invited": False}, status="yes")
    assert "odwołane" in R.rsvp_refusal(**{**base, "cancelled": True}, status="no")
    assert "zaczęło" in R.rsvp_refusal(**{**base, "now": start}, status="yes")
    assert "minął" in R.rsvp_refusal(**{**base, "deadline": now - timedelta(minutes=1)}, status="yes")
    full = {**base, "capacity": 10, "yes_count": 10}
    assert "limit" in R.rsvp_refusal(**full, status="yes")
    # Kto już ma miejsce, może potwierdzić ponownie; odmowa przy pełnej sali przechodzi.
    assert R.rsvp_refusal(**{**full, "current": "yes"}, status="yes") is None
    assert R.rsvp_refusal(**full, status="no") is None


def test_kod_obecnosci_okno_i_format():
    code = R.new_checkin_code()
    assert len(code) == 4 and all(ch in R.CHECKIN_ALPHABET for ch in code)
    assert R.normalize_code(" ab-2c ") == "AB2C"
    payload = R.qr_payload(17, "tok")
    assert R.parse_qr(payload) == (17, "tok")
    assert R.parse_qr("https://example.com") is None
    start = datetime(2026, 10, 1, 16, tzinfo=UTC)
    common = dict(start=start, end=None, cancelled=False, invited=True, code_matches=True)
    assert "od" in R.checkin_refusal(now=start - timedelta(hours=3), **common)
    assert R.checkin_refusal(now=start - timedelta(hours=1), **common) is None
    assert R.checkin_refusal(now=start + timedelta(hours=4, minutes=59), **common) is None
    assert "minął" in R.checkin_refusal(now=start + timedelta(hours=5, minutes=1), **common)
    assert "nie pasuje" in R.checkin_refusal(now=start, **{**common, "code_matches": False})


def test_stan_obecnosci_z_tabeli_i_starej_listy():
    rows = {"1": {"status": "excused"}, "2": {"status": "present"}}
    assert R.attendance_state("1", rows, ["1"]) == "excused"
    assert R.attendance_state("3", rows, ["3"]) == "present"
    assert R.attendance_state("4", rows, []) == "absent"


def test_seria_trzyma_godzine_polska_przez_zmiane_czasu():
    # 18:00 w Polsce: w październiku UTC+2, po 25.10 UTC+1.
    start = datetime(2026, 10, 14, 16, tzinfo=UTC)
    dates = R.expand_recurrence(start, start + timedelta(hours=2), "weekly", "2026-11-04T00:00:00Z")
    local = [d.astimezone(R.WARSAW).strftime("%d.%m %H:%M") for d, _ in dates]
    assert local == ["14.10 18:00", "21.10 18:00", "28.10 18:00", "04.11 18:00"]
    assert all(e - d == timedelta(hours=2) for d, e in dates)
    monthly = R.expand_recurrence(datetime(2027, 1, 31, 17, tzinfo=UTC), None, "monthly", "2027-04-30T00:00:00Z")
    assert [d.astimezone(R.WARSAW).day for d, _ in monthly] == [31, 28, 31, 30]
    assert R.expand_recurrence(start, None, "", None) == [(start, None)]
    with pytest.raises(R.Invalid, match="najwyżej"):
        R.expand_recurrence(start, None, "weekly", "2028-01-01T00:00:00Z")


def test_przypomnienia_doba_godzina_i_ponaglenie():
    start = datetime(2026, 10, 1, 16, tzinfo=UTC)
    created = start - timedelta(days=7)
    invited = ["1", "2", "3"]
    responses = {"1": "yes", "2": "no"}
    day = R.due_reminders(now=start - timedelta(hours=20), start=start, created_at=created, deadline=None, invited=invited, responses=responses, sent=set())
    assert day == [("day", ["1", "3"])]
    # Świeże wydarzenie (utworzone w ostatniej dobie) nie dostaje „day".
    fresh = R.due_reminders(now=start - timedelta(hours=20), start=start, created_at=start - timedelta(hours=22), deadline=None, invited=invited, responses=responses, sent=set())
    assert fresh == []
    hour = R.due_reminders(now=start - timedelta(minutes=40), start=start, created_at=created, deadline=None, invited=invited, responses=responses, sent={("1", "hour")})
    assert hour == [("hour", ["3"])]
    nudge = R.due_reminders(now=start - timedelta(days=3), start=start, created_at=created, deadline=start - timedelta(days=2, hours=12), invited=invited, responses=responses, sent=set())
    assert nudge == [("rsvp", ["3"])]
    assert R.due_reminders(now=start, start=start, created_at=created, deadline=None, invited=invited, responses={}, sent=set()) == []


def test_kosz_i_zmiana_warta_powiadomienia():
    now = datetime(2026, 9, 20, tzinfo=UTC)
    assert R.restorable(now - timedelta(days=29), now) and not R.restorable(now - timedelta(days=31), now)
    assert R.days_left(now - timedelta(days=1), now) == 29
    before = {"event_date": "a", "place": {"name": "Hala"}, "online_url": None, "end_date": None}
    assert not R.meaningful_change(before, dict(before))
    assert R.meaningful_change(before, {**before, "place": {"name": "Sala"}})

    # Pinezka dopięta do starego wydarzenia pod tym samym adresem - bez pusha.
    pinned = {**before, "place": {"name": "Hala", "address": None, "lat": 50.2641, "lng": 19.0238}}
    assert not R.meaningful_change(before, pinned)
    # Poprawka o kilkadziesiąt metrów to nie zmiana, inna hala w mieście - tak.
    nudged = {**pinned, "place": {**pinned["place"], "lat": 50.2645, "lng": 19.0242}}
    assert not R.meaningful_change(pinned, nudged)
    moved = {**pinned, "place": {**pinned["place"], "lat": 50.2841, "lng": 19.0238}}
    assert R.meaningful_change(pinned, moved)


def test_miejsce_z_pinezka():
    place = R.clean_place({"name": " Hala MOSiR ", "address": "Sportowa 1, Katowice", "lat": "50.2641234567", "lng": 19.02381, "place_id": "ChIJx9Lr6d3OFkcRabc123"})
    assert place == {"name": "Hala MOSiR", "address": "Sportowa 1, Katowice", "lat": 50.264123, "lng": 19.02381, "place_id": "ChIJx9Lr6d3OFkcRabc123"}
    # Bez współrzędnych kształt jak dawniej; śmieciowy identyfikator Google przepada.
    assert R.clean_place({"name": "Hala", "lat": None, "lng": ""}) == {"name": "Hala", "address": None}
    assert "place_id" not in R.clean_place({"lat": 50, "lng": 19, "place_id": "<script>"})
    for bad in ({"lat": 50}, {"lat": 95, "lng": 19}, {"lat": "x", "lng": 19}, {"lat": True, "lng": 19}):
        with pytest.raises(R.Invalid, match="współrzędne"):
            R.clean_place(bad)


def test_prompt_grafiki_bez_tekstu():
    prompt = R.title_image_prompt(name="Szkolenie przed rundą", event_type="training", place="Katowice", date_label="01.10")
    assert "No text" in prompt and "Katowice" in prompt and "Szkolenie" in prompt
