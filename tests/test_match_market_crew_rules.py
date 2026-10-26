"""Oferty obsadowego na giełdzie - reguły (liść, bez bazy)."""

import json
from datetime import datetime, timedelta, timezone

from app import match_market_crew_rules as R
from app.assignment_rules import club_crew_needs, crew as crew_of

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
MATCH = NOW + timedelta(days=5)


def test_slots_normalizacja_i_role():
    assert R.normalize_slots(["sedzia2", "czas", "czas", "delegat", "x"]) == ["drugi", "czas"]
    assert R.roles_of(["czas", "sekretarz"]) == ["table"]
    assert R.roles_of(["pierwszy", "czas"]) == ["table", "field"]


def test_podpowiedz_drk_tylko_stolik():
    crew = crew_of({"RozgrywkiCode": "LCM1/1"})
    out = R.suggest_slots(crew, ["pierwszy", "drugi", "sekretarz", "czas"], {"field": 0, "table": 2})
    assert out["slots"] == ["sekretarz", "czas"]
    assert {s["slot"] for s in out["skipped"]} == {"pierwszy", "drugi"}


def test_podpowiedz_pomija_obsadzone_i_cudze():
    state = {"NrSedzia_pierwszy": "12", "NrSedzia_pierwszy_nazwisko": "Kowalski Jan"}
    out = R.suggest_slots(crew_of(state), ["pierwszy", "drugi", "sekretarz"], club_crew_needs("S/JmM/1"))
    assert out["slots"] == ["drugi", "sekretarz"]
    reasons = {s["slot"]: s["reason"] for s in out["skipped"]}
    assert "obsadzone" in reasons["pierwszy"] and "prawa" in reasons["czas"]


def test_odmowa_slotow_mowi_dlaczego():
    assert "co najmniej jedno" in R.slots_refusal([], {}, [])
    assert "nie obsadza" in R.slots_refusal(["czas"], {}, ["sekretarz"])
    assert "już obsadzone" in R.slots_refusal(["czas"], {"czas": {"name": "X"}}, ["czas"])
    assert R.slots_refusal(["czas"], {}, ["czas"]) is None


def test_filtr_odznak_include_exclude_i_napisowy_json():
    flt = R.parse_filter({"mode": "include", "badges": ["Stolikowi"]})
    assert R.passes_filter(json.dumps({"Stolikowi": True}), flt)
    assert not R.passes_filter(json.dumps(["Ligowcy"]), flt)
    ex = R.parse_filter({"mode": "exclude", "badges": ["Młodzi"]})
    assert not R.passes_filter(json.dumps({"Młodzi": True}), ex)
    assert R.passes_filter("{}", ex)
    assert R.passes_filter(None, R.parse_filter(None))


def test_filtr_zle_ksztalty_to_wyjasnienie():
    for bad in ({"mode": "x"}, {"mode": "include", "badges": []}, "tekst"):
        try:
            R.parse_filter(bad)
        except ValueError as exc:
            assert str(exc)
        else:
            raise AssertionError(bad)


def test_termin_domyslny_i_walidacja():
    assert R.default_deadline(MATCH) == MATCH - timedelta(hours=24)
    assert R.deadline_refusal(None, MATCH, NOW) is None
    assert "przeszłości" in R.deadline_refusal(NOW - timedelta(hours=1), MATCH, NOW)
    assert "po rozpoczęciu" in R.deadline_refusal(MATCH + timedelta(hours=1), MATCH, NOW)
    assert "rozpoczął" in R.deadline_refusal(None, NOW - timedelta(hours=1), NOW)


def test_wygasanie_leniwe():
    dl = NOW + timedelta(hours=1)
    later = NOW + timedelta(hours=2)
    assert R.effective_status("open", dl, MATCH, 0, NOW) == "open"
    assert R.effective_status("open", dl, MATCH, 0, later) == "expired"
    assert R.effective_status("open", dl, MATCH, 2, later) == "open"
    assert R.effective_status("open", dl, MATCH, 2, MATCH) == "expired"
    assert R.effective_status("filled", dl, MATCH, 0, later) == "filled"
    assert not R.accepting_claims("open", dl, later)


def test_rola_wymagana_tylko_przy_obu_rodzajach():
    assert R.resolve_role(["table"], "") == ("table", None)
    assert R.resolve_role(["table"], "table") == ("table", None)
    assert R.resolve_role(["table"], "field")[1]
    assert R.resolve_role(["table", "field"], "")[1]
    assert R.resolve_role(["table", "field"], "field") == ("field", None)
    assert R.resolve_role(["field"], "xyz")[1]


def test_odmowa_zgloszenia():
    base = dict(status="open", deadline=MATCH - timedelta(hours=24), match_at=MATCH, now=NOW,
                flt={"mode": "none", "badges": []}, badges_raw="{}", holds_slot_in_match=False)
    assert R.claim_refusal(**base) is None
    assert "zamknięta" in R.claim_refusal(**{**base, "status": "filled"})
    assert "termin" in R.claim_refusal(**{**base, "now": MATCH - timedelta(hours=2)}).lower()
    assert "odznak" in R.claim_refusal(**{**base, "flt": {"mode": "include", "badges": ["A"]}})
    assert "obsadzie" in R.claim_refusal(**{**base, "holds_slot_in_match": True})
    assert R.claim_refusal(**{**base, "role_blocked": "delegat - nie na boisko"}) == "delegat - nie na boisko"


def test_obsadowy_i_admin_moga_sie_zglosic():
    base = dict(status="open", deadline=MATCH - timedelta(hours=24), match_at=MATCH, now=NOW,
                flt={"mode": "include", "badges": ["Liga"]}, badges_raw="{}", holds_slot_in_match=False)
    # Zwykły sędzia bez odznaki - odmowa z wyjaśnieniem; obsadowy przechodzi.
    assert "odznak" in R.claim_refusal(**base)
    assert R.claim_refusal(**base, manager=True) is None
    # Reszta reguł obowiązuje obsadowego tak samo.
    assert "obsadzie" in R.claim_refusal(**{**base, "holds_slot_in_match": True}, manager=True)
    assert "zamknięta" in R.claim_refusal(**{**base, "status": "filled"}, manager=True)
    assert R.claim_refusal(**base, manager=True, role_blocked="delegat") == "delegat"
    # Okręg: zwykły tylko swój, obsadowy/admin zawsze swoim numerem.
    gate = dict(known=True, judge_province="śląskie", offer_province="śląskie", manager=False)
    assert R.claim_province_refusal(**gate) is None
    assert "innego okręgu" in R.claim_province_refusal(**{**gate, "judge_province": "opolskie"})
    assert "liście" in R.claim_province_refusal(**{**gate, "known": False})
    assert R.claim_province_refusal(**{**gate, "known": False, "judge_province": "", "manager": True}) is None


def test_partner():
    kw = dict(role="field", partner_id="2", self_id="1", offer_field_slots=2, partner_known=True, partner_passes=True)
    assert R.partner_refusal(**kw) is None
    assert R.partner_refusal(**{**kw, "partner_id": ""}) is None
    assert R.partner_refusal(**{**kw, "role": "table"})
    assert R.partner_refusal(**{**kw, "partner_id": "1"})
    assert "jedno miejsce" in R.partner_refusal(**{**kw, "offer_field_slots": 1})
    assert R.partner_refusal(**{**kw, "partner_known": False})
    assert R.partner_refusal(**{**kw, "partner_passes": False})
    assert R.partner_refusal(**{**kw, "partner_role_blocked": "tylko stolik"})


def test_pakiet_gdy_oboje_wskazali_siebie():
    claims = [
        {"id": 1, "judge_id": "1", "role": "field", "partner_id": "2", "status": "pending"},
        {"id": 2, "judge_id": "2", "role": "field", "partner_id": "1", "status": "pending"},
        {"id": 3, "judge_id": "3", "role": "field", "partner_id": "4", "status": "pending"},
        {"id": 4, "judge_id": "4", "role": "field", "partner_id": "", "status": "pending"},
        {"id": 5, "judge_id": "5", "role": "field", "partner_id": "6", "status": "pending"},
        {"id": 6, "judge_id": "6", "role": "field", "partner_id": "5", "status": "withdrawn"},
    ]
    assert R.packages(claims) == [{"judge_ids": ["1", "2"], "claim_ids": [1, 2]}]


def test_wybor_gniazda():
    slots = ["pierwszy", "drugi", "czas"]
    assert R.pick_slot(slots, {}, "field") == ("pierwszy", None)
    assert R.pick_slot(slots, {"pierwszy": 1}, "field") == ("drugi", None)
    assert R.pick_slot(slots, {"czas": 1}, "table")[1]
    assert R.pick_slot(slots, {}, "table", "pierwszy")[1]
    assert R.pick_slot(slots, {}, "field", "sekretarz")[1]
    assert R.pick_slot(slots, {}, "field", "drugi") == ("drugi", None)
    assert R.pick_slot(slots, {"drugi": 1}, "field", "drugi")[1]
    assert R.pick_slot(slots, {}, "field", "zzz")[1]
    assert R.offer_filled(slots, {"pierwszy": 1, "drugi": 2}) is False
    assert R.offer_filled(slots, {"pierwszy": 1, "drugi": 2, "czas": 3}) is True


def test_km_lancuch_zrodel():
    none = lambda a, b: None
    same = lambda a, b: a == b

    def f(**k):
        args = {"district": none, "national": none, "remembered": none, "same_city": same, **k}
        return R.km_chain("A", "B", **args)

    assert f() == {"km": None, "source": "unknown"}
    assert f(district=lambda a, b: 12.34)["source"] == "district_table"
    assert f(national=lambda a, b: 80)["source"] == "national_table"
    assert f(remembered=lambda a, b: 5)["source"] == "google"
    assert f(district=lambda a, b: 1, national=lambda a, b: 2)["km"] == 1.0
    assert R.km_chain("A", "A", district=none, national=none, remembered=none, same_city=same) == {"km": 0.0, "source": "same_city"}
    assert R.km_chain("", "A", district=none, national=none, remembered=none, same_city=same)["source"] == "unknown"


def _e(mid, dt, city="Katowice", hall="H1"):
    return {"match_id": mid, "moment": dt, "code": "S/JmM/1", "hall": hall, "venue": "", "city": city}


def test_obciazenie_tydzien_odstep_kolizja():
    day = datetime(2026, 11, 7, 12, 0)  # sobota
    match = _e("m", day, "Gliwice", "G")
    entries = [
        _e("a", day - timedelta(days=3)),
        _e("b", day + timedelta(minutes=30), "Kraków", "K"),
        _e("c", day + timedelta(days=9)),
        _e("m", day),
    ]
    view = R.judge_load_view(entries, match, lambda a, b: 80.0)
    assert view["week_matches"] == 2
    assert view["nearest"]["match_id"] == "b"
    assert view["gap"]["level"] == "red" and view["gap"]["overlap"] is True
    assert [c["match_id"] for c in view["collisions"]] == ["b"]


def test_obciazenie_bez_kolizji():
    day = datetime(2026, 11, 7, 12, 0)
    view = R.judge_load_view([_e("a", day - timedelta(days=2))], _e("m", day, "Gliwice", "G"), lambda a, b: 20.0)
    assert view["gap"] is None and view["collisions"] == []
    assert R.judge_load_view([], _e("m", day), lambda a, b: None)["nearest"] is None


def test_teksty_push_sa_pelne():
    offer = {
        "match_code": "S/JmM/1",
        "match_at": MATCH,
        "match_snapshot": json.dumps({"ID_zespoly_gosp_ZespolNazwa": "A", "ID_zespoly_gosc_ZespolNazwa": "B"}),
    }
    title, body = R.text_new_offer(offer, ["sekretarz", "czas"])
    assert title == "Nowy mecz do wzięcia" and "S/JmM/1 A - B" in body and "sekretarza" in body
    assert "sędzia 1" in R.text_assigned(offer, "pierwszy")[1]
    assert R.text_filled(offer)[0] == "Mecz obsadzony"
    assert ".." not in R.text_withdrawn({})[1]


def test_szybki_odczyt_obsadowego_mowi_czy_dociagac_km():
    unknown = {"km": {"km": None, "source": "unknown", "from": "Gliwice", "to": "Zabrze"}}
    known = {"km": {"km": 20, "source": "district_table", "from": "Gliwice", "to": "Zabrze"}}
    no_city = {"km": {"km": None, "source": "unknown", "from": "", "to": "Zabrze"}}
    assert R.crew_metrics_pending(True, {"1": unknown, "2": known}) is True
    assert R.crew_metrics_pending(False, {"1": unknown}) is False
    # Bez miasta Google i tak nic nie da - nie każemy pobierać drugi raz.
    assert R.crew_metrics_pending(True, {"1": no_city, "2": known}) is False
