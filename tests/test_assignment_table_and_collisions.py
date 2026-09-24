"""
Stolik i kolizje w Automacie i w alertach okręgu (decyzje z 24.09.2026).

  - stolik OKRĘGOWY: najpierw „Stolikowi" (także „Stolikowy"), reszta po nich;
    II liga, I liga, Liga Centralna, Superliga - wszyscy na równi,
  - ta sama hala: bez dojazdu i zapasu, czas meczu z kategorii,
  - inna hala: czas meczu + dojazd 60 km/h + 30 min zapasu,
  - turniej młodzików w jednej hali (10:00, 11:50, 13:40) to NIE kolizja.
"""

from datetime import datetime

import pytest

from app import collision_rules as CR
from app import district_alert_rules as R
from app import offtime_rules as O
from app.assignment_auto import (
    OFF,
    TIGHT,
    BusyMatch,
    Context,
    MatchNeed,
    build_plan,
    describe_candidates,
    table_badge_first,
)
from app.assignment_people import fold, make_judge
from app.province_alert_rules import AlertRuleError

HALL = "Hala Sportowa MOSiR"


def world(judges, km_of=lambda a, b: 20.0, **rest):
    people = {judge.judge_id: judge for judge in judges}
    options = {
        "judges": people,
        "available": lambda judge_id, moment: True,
        "paused": lambda judge_id, day: False,
        "city_of": lambda judge_id, day: people[judge_id].city,
        "km": km_of,
    }
    options.update(rest)
    return Context(**options)


def need(code="S/JmM/1", *, field=0, table=1, when=datetime(2026, 10, 3, 13, 40), city="Gliwice", hall=HALL):
    return MatchNeed(
        match_id="500",
        code=code,
        moment=when,
        day=when.date(),
        host_city=city,
        hall=hall,
        field_needed=["pierwszy", "drugi"][:field],
        table_needed=["sekretarz", "czas"][:table],
    )


# ───────────────────────────────── stolik ─────────────────────────────────


class TestStolik:
    def test_okregowy_stolik_najpierw_stolikowi(self):
        # Stolikowy daleko i z trzema stolikami więcej - i tak idzie pierwszy.
        badge = make_judge("1", "STOLIKOWY Marek", city="Rybnik", badges=["Stolikowi"])
        other = make_judge("2", "BLISKI Adam", city="Zabrze")
        km = lambda a, b: {"rybnik": 70.0, "zabrze": 5.0}.get(fold(a))
        ctx = world([badge, other], km, season_counts={"1": {"table": 3}})
        plan = build_plan([need()], ctx)
        assert [p.judge_id for p in plan.proposals] == ["1"]

    def test_odznaka_w_liczbie_pojedynczej(self):
        badge = make_judge("1", "STOLIKOWY Marek", city="Rybnik", badges=["Stolikowy"])
        assert badge.table_specialist

    def test_reszta_dopiero_po_stolikowych(self):
        badge = make_judge("1", "STOLIKOWY Marek", city="Rybnik", badges=["Stolikowi"])
        other = make_judge("2", "BLISKI Adam", city="Zabrze")
        km = lambda a, b: {"rybnik": 70.0, "zabrze": 5.0}.get(fold(a))
        plan = build_plan([need(table=2)], world([badge, other], km))
        assert [p.judge_id for p in sorted(plan.proposals, key=lambda p: p.slot)] == ["2", "1"]  # czas, sekretarz
        # Stolikowy wziął pierwsze gniazdo (sekretarz), Adam dopiero drugie.
        first = next(p for p in plan.proposals if p.slot == "sekretarz")
        assert first.judge_id == "1"

    @pytest.mark.parametrize("code", ["IIK4/3", "IM/2", "LCM/1", "SM/5", "SK/2"])
    def test_ligi_bez_preferencji_stolikowych(self, code):
        assert not table_badge_first(code)
        badge = make_judge("1", "STOLIKOWY Marek", city="Rybnik", badges=["Stolikowi", "Ligowcy"], letters=["SL", "LC", "I"])
        other = make_judge("2", "BLISKI Adam", city="Zabrze", badges=["Ligowcy"], letters=["SL", "LC", "I"])
        km = lambda a, b: {"rybnik": 70.0, "zabrze": 5.0}.get(fold(a))
        plan = build_plan([need(code)], world([badge, other], km))
        assert [p.judge_id for p in plan.proposals] == ["2"]

    @pytest.mark.parametrize("code", ["S/JmM/4", "S/MłKR/16", "S/IIIM/2", "DZM/1"])
    def test_rozgrywki_okregowe_z_preferencja(self, code):
        assert table_badge_first(code)


# ───────────────────────────────── kolizje ─────────────────────────────────


def info(match_id, when, code, *, hall=HALL, city="Gliwice"):
    return R.MatchInfo(match_id=match_id, code=code, moment=when, city=city, hall=hall, host="A", guest="B")


def km_table(a, b):
    return 0.0 if fold(a) == fold(b) else 20.0


class TestKolizje:
    def test_czas_meczu_z_kategorii(self):
        assert CR.match_minutes("S/JM/1") == 105
        assert CR.match_minutes("IIK4/1") == 105
        assert CR.match_minutes("S/JmM/1") == 90
        assert CR.match_minutes("S/MłKR/16") == 75
        assert CR.match_minutes("S/MLM1213/3") == 60
        assert CR.match_minutes("DZK/2") == 60

    def test_turniej_mlodzikow_w_jednej_hali_to_nie_kolizja(self):
        """Mail testowy: 23 fałszywe kolizje z tego jednego turnieju."""
        a = info("16", datetime(2026, 10, 3, 10, 0), "S/MłKR/16")
        b = info("17", datetime(2026, 10, 3, 11, 50), "S/MłKR/17")
        c = info("18", datetime(2026, 10, 3, 13, 40), "S/MłKR/18")
        for moved in (a, b, c):
            others = [item for item in (a, b, c) if item is not moved]
            assert R.find_collisions("7", "Jan Nowak", moved, others, [], km_table) == []

    def test_ta_sama_hala_po_innym_zapisie_nazwy(self):
        assert CR.same_hall("Hala Sportowa MOSiR", "Gliwice", "hala sportowa - mosir", "GLIWICE")
        assert not CR.same_hall("Hala Sportowa MOSiR", "Gliwice", "Hala Sportowa MOSiR", "Zabrze")
        assert not CR.same_hall("", "Gliwice", "", "Gliwice")
        assert CR.same_hall("Hala A", "Gliwice", "Hala B", "Gliwice", a_venue="12", b_venue="12")

    def test_prawdziwe_nakladanie_w_tej_samej_hali(self):
        a = info("16", datetime(2026, 10, 3, 10, 0), "S/MłKR/16")
        b = info("17", datetime(2026, 10, 3, 11, 0), "S/MłKR/17")
        found = R.find_collisions("7", "Jan Nowak", b, [a], [], km_table)
        assert [item.kind for item in found] == [R.KIND_OVERLAP]
        assert found[0].same_hall and found[0].short_minutes == 15

    def test_inna_hala_czas_meczu_dojazd_i_zapas(self):
        a = info("16", datetime(2026, 10, 3, 10, 0), "S/MłKR/16", hall="Hala A")
        b = info("17", datetime(2026, 10, 3, 11, 50), "S/MłKR/17", hall="Hala B", city="Zabrze")
        # 75 min meczu + 20 km (20 min) + 30 min zapasu = 125 > 110.
        found = R.find_collisions("7", "Jan Nowak", b, [a], [], km_table, kinds=[R.KIND_OVERLAP])
        assert found and found[0].short_minutes == 15
        # Inna hala w tym samym mieście: 75 + 0 + 30 = 105 <= 110 - zdąży.
        c = info("18", datetime(2026, 10, 3, 11, 50), "S/MłKR/18", hall="Hala C")
        assert R.find_collisions("7", "Jan Nowak", c, [a], [], km_table, kinds=[R.KIND_OVERLAP]) == []

    def test_ustawienia_okregu_zmieniaja_regule(self):
        rules = CR.rules_from_config({"durations": {"mlodzik": 120}})
        a = info("16", datetime(2026, 10, 3, 10, 0), "S/MłKR/16")
        b = info("17", datetime(2026, 10, 3, 11, 50), "S/MłKR/17")
        assert R.find_collisions("7", "x", b, [a], [], km_table, kinds=[R.KIND_OVERLAP], rules=rules)

    def test_automat_bierze_sedziego_z_turnieju_w_tej_samej_hali(self):
        judge = make_judge("1", "KOWALSKI Jan", city="Zabrze")
        busy = {
            "1": [
                BusyMatch(moment=datetime(2026, 10, 3, 10, 0), city="Gliwice", match_id="16", code="S/MłKR/16", hall=HALL),
                BusyMatch(moment=datetime(2026, 10, 3, 11, 50), city="Gliwice", match_id="17", code="S/MłKR/17", hall=HALL),
            ]
        }
        plan = build_plan([need("S/MłKR/18", field=1, table=0)], world([judge], busy=busy))
        assert [p.judge_id for p in plan.proposals] == ["1"]
        # Ta sama godzina w innej hali 20 km dalej - już nie.
        other = need("S/MłKR/18", field=1, table=0, city="Zabrze", hall="Hala Zabrze")
        plan = build_plan([other], world([judge], busy=busy))
        assert not plan.proposals and "nie zdąży" in plan.gaps[0].reason

    def test_ustawienia_w_konfiguracji_alertow(self):
        base = R.default_config()
        assert base["timing"] == {
            "travel_kmh": 60,
            "margin_minutes": 30,
            "durations": {
                "senior": 105,
                "junior": 105,
                "junior_mlodszy": 90,
                "mlodzik": 75,
                "mlodzik_mlodszy": 60,
                "dzieci": 60,
            },
        }
        # Łagodnie: śmieci wracają do wartości domyślnych.
        assert R.normalize_config({"timing": {"travel_kmh": "abc", "durations": {"dzieci": 5}}})["timing"] == base["timing"]
        clean = R.validate_config({"timing": {"margin_minutes": 45, "durations": {"dzieci": 50}}})
        assert clean["timing"]["margin_minutes"] == 45 and clean["timing"]["durations"]["dzieci"] == 50
        with pytest.raises(AlertRuleError):
            R.validate_config({"timing": {"travel_kmh": 500}})
        with pytest.raises(AlertRuleError):
            R.validate_config({"timing": {"durations": {"senior": 10}}})


# ─────────────────────────────── kandydaci ───────────────────────────────


class TestKandydaci:
    def test_stany_i_kolejnosc(self):
        free = make_judge("1", "WOLNY Adam", city="Zabrze")
        tight = make_judge("2", "NAPIĘTY Jan", city="Zabrze")
        off = make_judge("3", "ZAJĘTY Piotr", city="Zabrze")
        clash = make_judge("4", "KOLIZJA Ewa", city="Zabrze")
        badge = make_judge("5", "STOLIKOWY Marek", city="Rybnik", badges=["Stolikowi"])
        offs, _ = O.parse_entries([{"from": "2026-10-03T12:00:00", "to": "2026-10-03T18:00:00", "category_name": "Praca"}])
        busy = {
            "2": [BusyMatch(moment=datetime(2026, 10, 3, 9, 0), city="Gliwice", match_id="9", code="S/JmM/9", hall=HALL)],
            "4": [BusyMatch(moment=datetime(2026, 10, 3, 13, 0), city="Katowice", match_id="8", code="S/JmM/8", hall="Hala K")],
        }
        ctx = world(
            [free, tight, off, clash, badge],
            available=lambda judge_id, moment: judge_id != "3",
            busy=busy,
        )
        views = describe_candidates(
            ctx,
            need(),
            off_reason=lambda judge_id, moment: R.offtime_text(offs[0]) if judge_id == "3" else "",
        )
        by_id = {view.judge_id: view for view in views}
        assert by_id["1"].status == "free" and by_id["1"].fits == ["field", "table"]
        assert by_id["2"].status == TIGHT and "09:00" in by_id["2"].reason
        assert by_id["3"].status == OFF and by_id["3"].reason == "niedyspozycja: Praca, 12:00-18:00"
        assert by_id["4"].status == OFF and "kolizja" in by_id["4"].reason and "13:00" in by_id["4"].reason
        # Stolik okręgowy: stolikowy pierwszy, zajęci na końcu.
        assert views[0].judge_id == "5" and views[0].rank == 1
        assert [view.status for view in views[-2:]] == [OFF, OFF]
        assert any("km" in item for item in by_id["1"].why)
