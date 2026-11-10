"""Formularze okręgowe - czyste reguły (docs/formularze-okregowe.md).

Scena: okręg śląski. Komisja (2), delegaci (1, 4), młodzi (3, 4), sędzia bez odznak (5),
nieaktywny (6). Lista „Wigilia sędziowska": Będę/Nie będę, wpłata 80 zł (sędzia zgłasza,
komisja potwierdza), menu, osoby towarzyszące, notatka komisji.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app import district_form_schema as SC
from app import district_form_templates as T
from app import district_forms_rules as R
from app import province_event_rules as PR

UTC = timezone.utc


def judges():
    return [
        {"judge_id": "1", "full_name": "Adam Nowak", "badges": {"Delegaci": True}},
        {"judge_id": "2", "full_name": "Beata Kowalska", "badges": {"Komisja sędziowska": True}},
        {"judge_id": "3", "full_name": "Cezary Lis", "badges": ["Młodzi"]},
        {"judge_id": "4", "full_name": "Dorota Wrona", "badges": '{"Delegaci": true, "Młodzi": true}'},
        {"judge_id": "5", "full_name": "Edward Sowa", "badges": {}},
        {"judge_id": "6", "full_name": "Filip Kruk", "badges": {"Delegaci": True}, "inactive": True},
    ]


def wigilia_columns():
    return SC.clean_list_schema(
        {
            "columns": [
                {"id": "status", "type": "status", "title": "Obecność"},
                {"id": "pay", "type": "confirm", "title": "Wpłata", "amount": 80, "visibility": "self"},
                {
                    "id": "menu",
                    "type": "choice",
                    "title": "Menu",
                    "options": [{"id": "meat", "label": "Mięsne"}, {"id": "vege", "label": "Wegetariańskie"}],
                },
                {"id": "guests", "type": "number", "title": "Osoby towarzyszące", "min": 0, "max": 3, "integer": True},
                {"id": "note", "type": "text", "title": "Notatka komisji", "editor": "managers", "visibility": "managers"},
            ]
        }
    )["columns"]


def cell(v, src="app", at="2026-11-10T10:00:00+00:00"):
    return {"v": v, "src": src, "by": None, "at": at}


# ---------------------------------------------------------------------------
# Odbiorcy
# ---------------------------------------------------------------------------


def test_pusty_krag_to_nikt_a_nie_wszyscy():
    assert R.target_ids(judges(), {}) == []
    assert R.target_ids(judges(), {"include_all": True}, inactive={"6"}) == ["1", "2", "3", "4", "5"]
    assert R.target_ids(judges(), {"include_badges": ["Delegaci"]}, inactive={"6"}) == ["1", "4"]
    # Ręczne dopisanie wygrywa z nieaktywnością i wykluczoną odznaką, wyłączenie - ze wszystkim.
    assert R.target_ids(judges(), {"include_all": True, "exclude_badges": ["Młodzi"], "include_ids": ["3", "6"]}, inactive={"6"}) == [
        "1", "2", "3", "5", "6"
    ]
    assert R.target_ids(judges(), {"include_all": True, "exclude_ids": ["1"]}) == ["2", "3", "4", "5", "6"]


def test_audience_wymaga_wyboru_uczestnikow_a_open_tylko_w_formularzu():
    with pytest.raises(R.FormError) as err:
        R.clean_audience({"participants": {}}, kind="list")
    assert err.value.code == "bad_audience"
    with pytest.raises(R.FormError):
        R.clean_audience({"participants": {"open": True}}, kind="list")
    ok = R.clean_audience({"participants": {"open": True}}, kind="form")
    assert ok["participants"]["open"] is True
    assert ok["observers"]["include_all"] is False


def test_zarzadzajacy_to_autor_komisja_i_wskazani_a_admin_wszedzie():
    audience = R.clean_audience(
        {"participants": {"include_badges": ["Delegaci"]}, "observers": {"include_ids": ["5"]}, "managers": {"include_ids": ["3"]}},
        kind="list",
    )
    circles = R.resolve_audience(judges(), audience, author="1", inactive={"6"})
    assert circles.participants == ["1", "4"]
    assert circles.observers == ["5"]
    assert circles.managers == ["1", "2", "3"]

    def who(jid, admin=False, province="ŚLĄSKIE", badges=None):
        return PR.viewer(judge_id=jid, province=province, is_admin=admin, badges=badges or {})

    assert R.roles_for(who("1"), province="SLASKIE", author="1", circles=circles) == ["manager", "participant"]
    assert R.roles_for(who("4"), province="SLASKIE", author="1", circles=circles) == ["participant"]
    assert R.roles_for(who("5"), province="SLASKIE", author="1", circles=circles) == ["observer"]
    assert R.roles_for(who("99"), province="SLASKIE", author="1", circles=circles) == []
    assert R.roles_for(who("99", admin=True, province="OPOLSKIE"), province="SLASKIE", author="1", circles=circles) == ["manager"]
    # Komisja innego okręgu nie zarządza.
    foreign = who("77", province="OPOLSKIE", badges={"Komisja sędziowska": True})
    assert R.roles_for(foreign, province="SLASKIE", author="1", circles=circles) == []
    assert R.can_create(who("2", badges={"Komisja sędziowska": True}), "SLASKIE")
    assert not R.can_create(who("1"), "SLASKIE")


def test_obcy_dostaje_404_a_szkic_widzi_tylko_zarzadzajacy():
    with pytest.raises(R.FormError) as err:
        R.check_access([], "open")
    assert err.value.status == 404
    with pytest.raises(R.FormError):
        R.check_access(["participant"], "draft")
    with pytest.raises(R.FormError):
        R.check_access(["observer"], "trash")
    R.check_access(["manager"], "draft")
    R.check_access(["participant"], "archived")


def test_stan_formularza_i_zakladki():
    now = datetime(2026, 11, 10, 12, tzinfo=UTC)
    base = {"published_at": now - timedelta(days=1), "closes_at": now + timedelta(days=1)}
    assert R.form_status({}, now) == "draft"
    assert R.form_status(base, now) == "open"
    assert R.form_status({**base, "closes_at": now}, now) == "closed"
    assert R.form_status({**base, "closed_at": now}, now) == "closed"
    assert R.form_status({**base, "archived_at": now}, now) == "archived"
    assert R.form_status({**base, "deleted_at": now}, now) == "trash"
    assert R.in_scope("todo", roles=["participant"], status="open", participant=True, filled=False, web_review=False)
    assert R.in_scope("todo", roles=["participant"], status="open", participant=True, filled=True, web_review=True)
    assert not R.in_scope("todo", roles=["participant"], status="open", participant=True, filled=True, web_review=False)
    assert R.in_scope("drafts", roles=["manager"], status="draft", participant=False, filled=False, web_review=False)
    assert not R.in_scope("trash", roles=["participant"], status="trash", participant=True, filled=False, web_review=False)


# ---------------------------------------------------------------------------
# Widoczność
# ---------------------------------------------------------------------------


def test_widocznosc_kolumn_wg_roli_i_webu():
    columns = wigilia_columns()
    ids = lambda mode: [c["id"] for c in R.visible_columns(columns, mode)]  # noqa: E731
    assert ids("manager") == ["status", "pay", "menu", "guests", "note"]
    assert ids("observer") == ["status", "pay", "menu", "guests"]
    assert ids("own") == ["status", "pay", "menu", "guests"]
    assert ids("roster") == ["status", "menu", "guests"]
    # Web: jawne + edytowalne przez sędziego (wpłata jest „self", ale sędzia ją zgłasza).
    assert ids("web") == ["status", "pay", "menu", "guests"]

    cells = {"status": cell("yes"), "pay": cell("declared"), "note": cell("spóźni się", src="manager")}
    web = R.filter_cells(columns, cells, "web")
    assert web["status"]["v"] == "yes"
    assert web["pay"] == {"set": True}
    assert "note" not in web
    assert "by" not in web["status"]
    assert "note" in R.filter_cells(columns, cells, "manager")
    assert "pay" not in R.filter_cells(columns, cells, "roster")


def test_status_zawsze_jawny_na_webie_nawet_przy_self():
    columns = SC.clean_list_schema({"columns": [{"id": "s", "type": "status", "title": "Będę?", "visibility": "self"}]})["columns"]
    assert R.filter_cells(columns, {"s": cell("no")}, "web")["s"]["v"] == "no"


# ---------------------------------------------------------------------------
# Wartości i blokady
# ---------------------------------------------------------------------------


def test_wartosci_komorek_sa_sprawdzane_i_normalizowane():
    by_id = {c["id"]: c for c in wigilia_columns()}
    assert R.clean_value(by_id["status"], "yes") == "yes"
    assert R.clean_value(by_id["guests"], "2") == 2
    assert R.clean_value(by_id["menu"], None) is None
    assert R.clean_value(by_id["note"], "  ok  ") == "ok"
    for column, bad in (("status", "maybe"), ("guests", 4), ("guests", 1.5), ("pay", "paid"), ("menu", "fish")):
        with pytest.raises(R.FormError) as err:
            R.clean_value(by_id[column], bad)
        assert err.value.code == "bad_value"
    check = {"id": "c", "type": "check", "title": "Obecny"}
    assert R.clean_value(check, True) is True and R.clean_value(check, False) is None
    multi = {"id": "m", "type": "choice", "multi": True, "title": "M", "options": [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}]}
    assert R.clean_value(multi, ["b", "a"]) == ["a", "b"]
    assert R.clean_value(multi, []) is None


def test_maszyna_stanow_wplaty():
    pay = {c["id"]: c for c in wigilia_columns()}["pay"]
    assert pay["editor"] == "self_confirm" and pay["lock_after_deadline"] is False
    ok = lambda **kw: R.cell_refusal(pay, closed=False, **kw)  # noqa: E731
    assert ok(source="app", current=None, new="declared") is None
    assert ok(source="web", current="declared", new=None) is None
    assert ok(source="app", current=None, new="confirmed").code == "column_forbidden"
    locked = ok(source="app", current="confirmed", new=None)
    assert locked.code == "confirmed_locked" and locked.status == 403
    assert ok(source="manager", current="confirmed", new=None) is None
    assert ok(source="manager", current=None, new="confirmed") is None
    # editor=self: sędzia sam dochodzi do „confirmed".
    own = {**pay, "editor": "self"}
    assert R.cell_refusal(own, source="app", current=None, new="confirmed", closed=False) is None
    managers = {**pay, "editor": "managers"}
    assert R.cell_refusal(managers, source="app", current=None, new="declared", closed=False).code == "column_forbidden"


def test_termin_blokuje_deklaracje_ale_nie_wplate_ani_komisji():
    by_id = {c["id"]: c for c in wigilia_columns()}
    late = R.cell_refusal(by_id["status"], source="app", current=None, new="yes", closed=True)
    assert late.code == "closed" and late.status == 409
    assert R.cell_refusal(by_id["pay"], source="web", current=None, new="declared", closed=True) is None
    assert R.cell_refusal(by_id["status"], source="manager", current=None, new="yes", closed=True) is None
    assert R.cell_refusal(by_id["note"], source="web", current=None, new="x", closed=False).code == "column_forbidden"


def test_blokady_wiersza_dla_webu():
    at = datetime(2026, 11, 10, 9, tzinfo=UTC)
    assert R.web_row_refusal(None, device_id="d1", force=False) is None
    hard = R.web_row_refusal({"verified": True, "web_device": "d1"}, device_id="d1", force=True)
    assert hard.code == "verified_lock" and hard.status == 423
    assert hard.message == "Ten sędzia potwierdził wybór w aplikacji."
    soft = R.web_row_refusal({"verified": False, "web_device": "d1", "web_at": at}, device_id="d2", force=False)
    assert soft.code == "soft_claimed" and soft.status == 409 and soft.extra["at"] == at.isoformat()
    assert soft.body()["error"] == "soft_claimed"
    assert R.web_row_refusal({"verified": False, "web_device": "d1", "web_at": at}, device_id="d2", force=True) is None
    assert R.web_row_refusal({"verified": False, "web_device": "d1"}, device_id="d1", force=False) is None


# ---------------------------------------------------------------------------
# Wypełnienie
# ---------------------------------------------------------------------------


def test_wypelnione_to_status_a_bez_niego_wymagane_kolumny_sedziego():
    columns = wigilia_columns()
    assert not R.list_filled(columns, {})
    assert not R.list_filled(columns, {"menu": cell("meat")})
    assert R.list_filled(columns, {"status": cell("no")})
    no_status = SC.clean_list_schema(
        {
            "columns": [
                {"id": "fee", "type": "confirm", "title": "Składka", "required": True},
                {"id": "shirt", "type": "text", "title": "Rozmiar", "required": True},
                {"id": "ok", "type": "check", "title": "Odebrał", "editor": "managers", "required": True},
            ]
        }
    )["columns"]
    assert not R.list_filled(no_status, {"fee": cell("declared")})
    assert R.list_filled(no_status, {"fee": cell("declared"), "shirt": cell("L")})
    optional = SC.clean_list_schema({"columns": [{"id": "t", "type": "text", "title": "Uwagi"}]})["columns"]
    assert not R.list_filled(optional, {}) and R.list_filled(optional, {"t": cell("x")})
    assert R.entry_filled("form", {}, {"submitted_at": datetime.now(UTC), "answers_json": {"q": 1}})
    assert not R.entry_filled("form", {}, {"submitted_at": None, "answers_json": {}})


# ---------------------------------------------------------------------------
# Przypomnienia i cisza nocna
# ---------------------------------------------------------------------------


def warsaw(y, m, d, hh, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=PR.WARSAW).astimezone(UTC)


def test_presety_przypomnien():
    deadline = warsaw(2026, 12, 18, 18)
    names = lambda preset: [k.split("@")[0] for k, _ in R.reminder_slots(preset, deadline)]  # noqa: E731
    assert names("off") == []
    assert names("gentle") == ["1d"]
    assert names("standard") == ["3d", "1d", "3h"]
    assert names("intense") == ["7d", "3d", "1d", "6h", "2h"]
    assert R.reminder_slots("standard", None) == []
    slots = dict(R.reminder_slots("standard", deadline))
    assert slots[R.slot_key("3h", deadline)] == warsaw(2026, 12, 18, 15)


def test_cisza_nocna_przesuwa_na_8_a_gdy_termin_wczesniej_na_20_30():
    deadline = warsaw(2026, 12, 18, 23, 30)
    # 3 h przed = 20:30 - poza ciszą. 1 dzień przed = 23:30 poprzedniego dnia -> 8:00.
    slots = dict(R.reminder_slots("standard", deadline))
    assert slots[R.slot_key("3h", deadline)] == warsaw(2026, 12, 18, 20, 30)
    assert slots[R.slot_key("1d", deadline)] == warsaw(2026, 12, 18, 8)
    # Termin o 7:00: slot 2 h przed (5:00) nie może iść na 8:00 - idzie 20:30 poprzedniego wieczoru.
    early = warsaw(2026, 12, 18, 7)
    assert R.quiet_shift(early - timedelta(hours=2), early) == warsaw(2026, 12, 17, 20, 30)
    # Slot o 21:30, termin rano o 9:00 następnego dnia -> 8:00.
    assert R.quiet_shift(warsaw(2026, 12, 17, 21, 30), warsaw(2026, 12, 18, 9)) == warsaw(2026, 12, 18, 8)
    # Slot o 21:30, termin o 7:00 następnego dnia -> 20:30 tego samego wieczoru.
    assert R.quiet_shift(warsaw(2026, 12, 17, 21, 30), warsaw(2026, 12, 18, 7)) == warsaw(2026, 12, 17, 20, 30)
    assert not R.in_quiet_hours(warsaw(2026, 12, 17, 8)) and R.in_quiet_hours(warsaw(2026, 12, 17, 21))


def test_due_slot_wybiera_ostatni_i_pomija_sprzed_publikacji():
    deadline = warsaw(2026, 12, 18, 18)
    published = warsaw(2026, 12, 10, 12)
    assert R.due_slot("standard", closes_at=deadline, published_at=published, now=warsaw(2026, 12, 14, 12)) is None
    key, at = R.due_slot("standard", closes_at=deadline, published_at=published, now=warsaw(2026, 12, 17, 19))
    assert key.startswith("1d@") and at == warsaw(2026, 12, 17, 18)
    # Przejście spóźnione o kilka slotów wysyła tylko ostatni.
    key, _ = R.due_slot("standard", closes_at=deadline, published_at=published, now=warsaw(2026, 12, 18, 16))
    assert key.startswith("3h@")
    # Opublikowany dzień przed terminem: sloty 3 dni i 1 dzień przepadają.
    late_pub = warsaw(2026, 12, 17, 20)
    assert R.due_slot("standard", closes_at=deadline, published_at=late_pub, now=warsaw(2026, 12, 18, 9)) is None
    assert R.due_slot("standard", closes_at=deadline, published_at=published, now=deadline) is None
    assert R.due_slot("off", closes_at=deadline, published_at=published, now=warsaw(2026, 12, 18, 16)) is None
    # Nowy termin = nowe klucze slotów (przypomnienia od nowa).
    assert R.slot_key("1d", deadline) != R.slot_key("1d", deadline + timedelta(days=1))


# ---------------------------------------------------------------------------
# Statystyki i kwoty
# ---------------------------------------------------------------------------


def test_statystyki_listy_z_kwotami():
    columns = wigilia_columns()
    entries = {
        "1": {"cells_json": {"status": cell("yes"), "pay": cell("confirmed", "manager", "2026-11-11T10:00:00+00:00"), "menu": cell("meat"), "guests": cell(2)},
              "submitted_at": datetime(2026, 11, 10, 10, tzinfo=UTC), "verified": True},
        "2": {"cells_json": {"status": cell("yes", "web"), "pay": cell("declared", "web"), "menu": cell("vege", "web"), "guests": cell(0, "web")},
              "submitted_at": datetime(2026, 11, 11, 10, tzinfo=UTC), "web_review": True},
        "3": {"cells_json": {"status": cell("no", "web_qr")}, "submitted_at": datetime(2026, 11, 11, 12, tzinfo=UTC)},
        "9": {"cells_json": {"status": cell("yes")}},  # spoza listy - nie liczy się
    }
    stats = R.list_stats(columns, ["1", "2", "3", "4"], entries)
    assert stats["participants"] == 4 and stats["filled"] == 3
    assert stats["sources"] == {"app": 0, "web_qr": 1, "web": 1, "manager": 1}
    assert stats["web_review"] == 1
    assert stats["timeline"] == [{"date": "2026-11-10", "filled": 1}, {"date": "2026-11-11", "filled": 3}]
    by_id = {c["id"]: c for c in stats["columns"]}
    assert by_id["status"] == {"id": "status", "type": "status", "counts": {"yes": 2, "no": 1}, "none": 1}
    assert by_id["pay"]["declared"] == 1 and by_id["pay"]["confirmed"] == 1 and by_id["pay"]["none"] == 2
    assert by_id["pay"]["expected_total"] == 160  # 80 zł x 2 „Będę"
    assert by_id["pay"]["declared_total"] == 160
    assert by_id["pay"]["confirmed_total"] == 80
    assert by_id["menu"]["counts"] == {"meat": 1, "vege": 1}
    assert by_id["guests"] == {"id": "guests", "type": "number", "count": 2, "sum": 2, "avg": 1.0, "min": 0.0, "max": 2.0}
    assert by_id["note"] == {"id": "note", "type": "text", "count": 0}


def test_kwota_oczekiwana_bez_statusu_to_wszyscy_uczestnicy():
    columns = SC.clean_list_schema({"columns": [{"id": "fee", "type": "confirm", "title": "Składka", "amount": 50.5}]})["columns"]
    stats = R.list_stats(columns, ["1", "2"], {"1": {"cells_json": {"fee": cell("declared")}}})
    col = stats["columns"][0]
    assert col["expected_total"] == 101 and col["declared_total"] == 50.5 and col["confirmed_total"] == 0
    no_amount = SC.clean_list_schema({"columns": [{"id": "fee", "type": "confirm", "title": "Składka"}]})["columns"]
    assert R.list_stats(no_amount, ["1"], {})["columns"][0]["expected_total"] is None


def test_status_counts_i_rsvp():
    column = wigilia_columns()[0]
    counts = R.status_counts(column, ["1", "2", "3"], {"1": {"status": cell("yes")}, "2": {"status": cell(None)}})
    assert counts == {"yes": 1, "no": 0, "none": 2}
    assert R.rsvp_from_status("yes") == "yes" and R.rsvp_from_status("maybe") is None and R.rsvp_from_status(None) is None
    assert R.status_from_rsvp(column, "no") == "no"
    custom = {**column, "options": [{"id": "tak", "label": "Tak"}, {"id": "nie", "label": "Nie"}]}
    with pytest.raises(R.FormError):
        R.status_from_rsvp(custom, "yes")
    target = R.event_target({"include_badges": ["Delegaci"], "include_ids": ["5"], "exclude_ids": ["4"], "open": True})
    assert target == {
        "target": {"include_all": False, "include_badges": ["Delegaci"], "exclude_badges": []},
        "include_ids": ["5"],
        "exclude_ids": ["4"],
    }
    # Zaproszeni wydarzenia liczeni z kopii = uczestnicy formularza.
    assert PR.invited_ids(judges(), target, inactive={"6"}) == R.target_ids(judges(), {"include_badges": ["Delegaci"], "include_ids": ["5"], "exclude_ids": ["4"]}, inactive={"6"})


# ---------------------------------------------------------------------------
# Filtry, opisy, drobne
# ---------------------------------------------------------------------------


def test_filtry_wierszy():
    columns = wigilia_columns()
    cells = {"status": cell("yes"), "menu": cell("vege"), "pay": cell("declared")}
    match = lambda flt, **kw: R.matches_filter(columns, cells=cells, filled=kw.get("filled", True), web_review=kw.get("web_review", False), verified=False, flt=flt)  # noqa: E731
    assert match({"status": "yes"})
    assert not match({"status": "no"})
    assert match({"guests": "none"})
    assert not match({"menu": "none"})
    assert match({"status": ["yes", "maybe"], "pay": "declared"})
    assert not match({"_filled": False})
    assert match({"_web_review": True}, web_review=True)
    assert R.clean_filter('{"status":"yes"}') == {"status": "yes"}
    assert R.clean_filter("") == {}
    with pytest.raises(R.FormError):
        R.clean_filter("{zly")


def test_opis_zmiany_do_pusha_i_etykiety():
    columns = wigilia_columns()
    assert R.describe_change(columns, {"status": "yes"}) == "Będę"
    assert R.describe_change(columns, {"pay": "declared", "menu": "vege"}) == "Wpłata: Zgłoszone, Menu: Wegetariańskie"
    assert R.describe_change(columns, {}) == "zmiana odpowiedzi"
    assert R.notification_action("web_review") == "review_web"
    assert R.notification_action("reminder") == "fill"


def test_kody_linki_i_drobne():
    code = R.new_code()
    assert R.normalize_code(code.upper()) == code and len(code) == 8
    assert R.normalize_code("abc") is None and R.normalize_code("0000oooo") is None
    assert R.web_url(code) == f"https://www.bazapodreka.app/f/{code}"
    assert R.pair_url(code) == f"https://www.bazapodreka.app/f/p/{code}"
    assert R.FORM_ID_RE.match(R.new_form_id())
    assert R.province_label("ŚLĄSKIE") == "Śląskie"
    assert R.province_label("KUJAWSKO-POMORSKIE") == "Kujawsko-pomorskie"
    assert R.ip_from("1.2.3.4, 10.0.0.1", "9.9.9.9") == "1.2.3.4" and R.ip_from("", "9.9.9.9") == "9.9.9.9"
    assert R.clean_geo({"lat": "50.1", "lon": 19, "acc": 12.34}) == {"lat": 50.1, "lon": 19.0, "acc": 12.3}
    assert R.clean_geo({"denied": True}) == {"denied": True}
    assert R.clean_geo({"lat": 500, "lon": 1}) is None
    assert R.clean_guest_name("  Jan   Kowalski ") == "Jan Kowalski"
    with pytest.raises(R.FormError):
        R.clean_guest_name("Jan")
    assert R.fill_seconds(12.4) == 12 and R.fill_seconds("x") is None and R.fill_seconds(0) is None
    assert R.name_matches("Łukasz Żółć", "zolc") and not R.name_matches("Adam", "ewa")
    assert R.loads('{"a": 1}', {}) == {"a": 1} and R.loads(None, []) == [] and R.loads("zly", {}) == {}


def test_ustawienia_i_anonimowosc_na_webie():
    settings = R.clean_settings({}, kind="list")
    assert settings == {"roster_visible": False, "reminders": "standard", "home_prompt": True, "confirmation": None}
    form = R.clean_settings({"anonymous": True}, kind="form")
    assert form["allow_edit"] is True and form["results_visibility"] == "managers" and form["fill_mode"] == "steps"
    with pytest.raises(R.FormError):
        R.clean_settings({"reminders": "loud"}, kind="list")
    closed = {"participants": {"include_all": True}}
    assert R.anonymous_web_refusal(kind="form", settings=form, audience=closed, web_enabled=True).code == "anonymous_web"
    assert R.anonymous_web_refusal(kind="form", settings=form, audience={"participants": {"open": True}}, web_enabled=True) is None
    assert R.anonymous_web_refusal(kind="form", settings=form, audience=closed, web_enabled=False) is None
    assert R.clean_cover({"tone": "red", "emoji": "🎄"}) == {"tone": "red", "emoji": "🎄"}
    assert R.clean_cover(None) is None
    with pytest.raises(R.FormError):
        R.clean_cover({"tone": "pink"})


def test_szablony_przechodza_walidacje():
    templates = T.all_templates()
    assert [t["id"] for t in templates] == ["party_payment", "fee", "meeting", "attendance", "training_survey", "application"]
    for template in templates:
        SC.clean_schema(template["kind"], template["schema"])
        R.clean_settings(template["settings"], kind=template["kind"])
    assert T.template("nope") is None
    party = T.template("party_payment")
    party["schema"]["columns"].clear()
    assert T.template("party_payment")["schema"]["columns"]  # kopia, nie oryginał


# ---------------------------------------------------------------- tryb cichy i szkic (10.11.2026)


def test_szkic_i_tryb_cichy_wyciszaja_pushe():
    published = {"published_at": datetime(2026, 11, 10, tzinfo=UTC)}
    assert R.pushes_muted({"published_at": None}) is True
    assert R.pushes_muted({**published, "silent": True}) is True
    assert R.pushes_muted({**published, "silent": False}) is False
    assert R.pushes_muted(published) is False


def test_szkic_przyjmuje_zapis_ze_strony_i_od_komisji_ale_nie_z_aplikacji():
    assert R.draft_writable("web") and R.draft_writable("web_qr") and R.draft_writable("manager")
    assert not R.draft_writable("app")


def test_wylaczenie_trybu_cichego_tryby():
    assert R.silent_off_refusal("open", "reset") is None
    assert R.silent_off_refusal("closed", "reset") is None
    assert R.silent_off_refusal("open", "send") is None
    assert R.silent_off_refusal("draft", "later") is None
    assert R.silent_off_refusal("draft", "reset").code == "not_published"
    assert R.silent_off_refusal("closed", "send").code == "not_open"
    assert R.silent_off_refusal("open", "").code == "bad_mode"
    assert R.silent_off_refusal("trash", "later").code == "trash"


def test_slot_publikacji_po_trybie_cichym_nie_dubluje_pierwszego():
    slot = R.silent_publish_slot(datetime(2026, 11, 10, 12, 30, tzinfo=UTC))
    assert slot != "1" and slot.startswith("loud-")
