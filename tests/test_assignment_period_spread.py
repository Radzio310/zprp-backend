"""
Rozkład meczów OKRESU w Automacie (zgłoszenie użytkownika z 25.09.2026:
„powiela ciągle tych samych sędziów" i „nie optymalizuje liczby sędziów na
zadany okres").

Scenariusz jak z prawdziwego przebiegu: 20 meczów w dwa tygodnie, 30 aktywnych
sędziów z różnym obciążeniem w sezonie i różną odległością od hal, pary
sędziowskie, czterech „Stolikowych", 2 boiskowych i 2 stolikowych na mecz.

Oczekiwania:
  - nikt nie dostaje więcej meczów okresu niż sufit(gniazda / sędziowie)
    plus jeden, dopóki ktoś wolny i uprawniony nie ma żadnego,
  - przydziały z TEGO przebiegu liczą się od razu (w punktach i w opisie),
  - uzasadnienie pokazuje stan w chwili wyboru, razem z wcześniejszymi
    wyborami przebiegu („(+1 w tym przebiegu)").
"""

import math
from datetime import datetime, timedelta

from app.assignment_auto import Context, MatchNeed, build_plan
from app.assignment_people import fold, make_judge

HALLS = ("Gliwice", "Zabrze", "Rybnik")


def period_world(*, seed_loads=True):
    judges = []
    cities = {}
    for index in range(30):
        city = f"Miasto{index}"
        badges = ["Stolikowi"] if index in (26, 27, 28, 29) else []
        judges.append(make_judge(str(index), f"SĘDZIA {index:02d}", city=city, badges=badges))
        # 4 .. 90 km - bliscy dostawali wszystko.
        cities[fold(city)] = 4.0 + (index * 37) % 87

    def km(a, b):
        base = cities.get(fold(a))
        if base is None:
            return None
        # Każda hala trochę inaczej, żeby kilometry nie były jednym szeregiem.
        shift = {fold(h): i * 7.0 for i, h in enumerate(HALLS)}.get(fold(b), 0.0)
        return abs(base - shift) + 3.0

    season = {}
    if seed_loads:
        for index in range(30):
            season[str(index)] = {"field": index % 5, "table": (index * 3) % 4}
    pairs = {}
    for left, right in ((0, 1), (2, 3), (4, 5), (6, 7), (8, 9)):
        pairs[str(left)] = str(right)
        pairs[str(right)] = str(left)
    people = {judge.judge_id: judge for judge in judges}
    ctx = Context(
        judges=people,
        available=lambda judge_id, moment: True,
        paused=lambda judge_id, day: False,
        city_of=lambda judge_id, day: people[judge_id].city,
        km=km,
        partner_of=pairs,
        season_counts=season,
    )
    return judges, ctx


def period_needs(count=20):
    """20 meczów w dwa tygodnie: po dwa w dniu, w dwóch różnych halach."""
    start = datetime(2026, 10, 3, 12, 0)
    out = []
    for index in range(count):
        day = start + timedelta(days=(index // 2) * 14 // (count // 2))
        moment = day + timedelta(hours=5 * (index % 2))
        out.append(
            MatchNeed(
                match_id=str(5000 + index),
                code=f"S/JmM/{index}",
                moment=moment,
                day=moment.date(),
                host_city=HALLS[index % len(HALLS)],
                field_needed=["pierwszy", "drugi"],
                table_needed=["sekretarz", "czas"],
            )
        )
    return out


def per_judge(plan, judges):
    counts = {judge.judge_id: 0 for judge in judges}
    for item in plan.proposals:
        counts[item.judge_id] += 1
    return counts


class TestRozkladOkresu:
    def test_nikt_nie_dostaje_drugiego_zanim_inni_pierwszy(self):
        judges, ctx = period_world()
        needs = period_needs()
        plan = build_plan(needs, ctx)
        counts = per_judge(plan, judges)
        slots = sum(len(n.field_needed) + len(n.table_needed) for n in needs)
        assert len(plan.proposals) == slots, plan.gaps
        cap = math.ceil(slots / len(judges))
        # Tolerancja jednego meczu: twarde reguły (kolizje dnia, pary) czasem
        # nie pozwalają na idealny podział.
        assert max(counts.values()) <= cap + 1, counts
        assert max(counts.values()) - min(counts.values()) <= 2, counts
        assert min(counts.values()) >= 1, counts

    def test_bez_licznikow_sezonu_tak_samo_rowno(self):
        judges, ctx = period_world(seed_loads=False)
        needs = period_needs()
        plan = build_plan(needs, ctx)
        counts = per_judge(plan, judges)
        assert max(counts.values()) - min(counts.values()) <= 1, counts

    def test_krotki_okres_kazdy_najwyzej_jeden(self):
        # 6 meczów = 24 gniazda, 30 sędziów: nikt nie powinien mieć dwóch.
        judges, ctx = period_world()
        plan = build_plan(period_needs(6), ctx)
        counts = per_judge(plan, judges)
        assert max(counts.values()) <= 1, counts

    def test_opis_pokazuje_wybory_z_przebiegu(self):
        judges, ctx = period_world(seed_loads=False)
        plan = build_plan(period_needs(), ctx)
        texts = [" ".join(item.reasons) for item in plan.proposals]
        # Druga propozycja dla tego samego sędziego mówi, ile już ma z przebiegu.
        assert any("w tym przebiegu" in text for text in texts), texts[:5]
        assert any("w okresie" in text for text in texts), texts[:5]

    def test_wybory_przebiegu_licza_sie_od_razu(self):
        # Dwóch sędziów, dwa mecze po jednym boiskowym w różne dni: bliższy
        # bierze pierwszy, drugi mecz idzie do dalszego, bo bliższy ma już
        # mecz w okresie - choć różnica w sezonie to tylko jeden.
        near = make_judge("1", "BLISKI Adam", city="Zabrze")
        far = make_judge("2", "DALEKI Jan", city="Rybnik")
        people = {"1": near, "2": far}
        ctx = Context(
            judges=people,
            available=lambda judge_id, moment: True,
            paused=lambda judge_id, day: False,
            city_of=lambda judge_id, day: people[judge_id].city,
            km=lambda a, b: {"zabrze": 5.0, "rybnik": 80.0}.get(fold(a)),
        )
        needs = [
            MatchNeed(
                match_id=str(i),
                code=f"S/JmM/{i}",
                moment=datetime(2026, 10, 3 + i, 12, 0),
                day=datetime(2026, 10, 3 + i, 12, 0).date(),
                host_city="Gliwice",
                field_needed=["pierwszy"],
            )
            for i in range(2)
        ]
        plan = build_plan(needs, ctx)
        assert sorted(p.judge_id for p in plan.proposals) == ["1", "2"]


def two_judges(**rest):
    near = make_judge("1", "BLISKI Adam", city="Zabrze")
    far = make_judge("2", "DALEKI Jan", city="Rybnik")
    people = {"1": near, "2": far}
    options = {
        "judges": people,
        "available": lambda judge_id, moment: True,
        "paused": lambda judge_id, day: False,
        "city_of": lambda judge_id, day: people[judge_id].city,
        "km": lambda a, b: {"zabrze": 5.0, "rybnik": 80.0}.get(fold(a)),
    }
    options.update(rest)
    return Context(**options)


def one_slot_need(index):
    moment = datetime(2026, 10, 3 + index, 12, 0)
    return MatchNeed(
        match_id=str(index),
        code=f"S/JmM/{index}",
        moment=moment,
        day=moment.date(),
        host_city="Gliwice",
        field_needed=["pierwszy"],
    )


class TestWyrownanie:
    def test_wyrownanie_przenosi_mecz_na_wolnego(self):
        # Jan nie może 4.10, więc drugi mecz musi wziąć Adam. Zachłannie Adam
        # wziąłby też pierwszy (bliżej) i miałby dwa, a Jan zero - wyrównanie
        # przenosi pierwszy mecz na Jana.
        ctx = two_judges(
            available=lambda judge_id, moment: not (judge_id == "2" and moment.day == 4),
        )
        plan = build_plan([one_slot_need(0), one_slot_need(1)], ctx)
        by_match = {p.match_id: p.judge_id for p in plan.proposals}
        assert by_match == {"0": "2", "1": "1"}, by_match
        assert any("wyrównanie okresu" in " ".join(p.reasons) for p in plan.proposals)

    def test_mecze_juz_obsadzone_w_okresie_licza_sie(self):
        # Adam ma już mecz w tym zakresie (Context.load) - nowy idzie do Jana,
        # choć ten jest dalej.
        plan = build_plan([one_slot_need(0)], two_judges(load={"1": 1}))
        assert [p.judge_id for p in plan.proposals] == ["2"]


class TestRolaWObsadzie:
    def test_tylko_stolik_z_zprp_nie_idzie_na_boisko(self):
        table_only = make_judge("1", "WOJTYCZKA Grzegorz", city="Zabrze", roles=["stolikowy"])
        other = make_judge("2", "DALEKI Jan", city="Rybnik", roles=["sedzia", "stolikowy"])
        people = {"1": table_only, "2": other}
        ctx = two_judges(judges=people, city_of=lambda judge_id, day: people[judge_id].city)
        plan = build_plan([one_slot_need(0)], ctx)
        assert [p.judge_id for p in plan.proposals] == ["2"]

    def test_tylko_stolik_bez_innych_zostawia_puste_z_powodem(self):
        table_only = make_judge("1", "MAJKA Marek", city="Zabrze", roles=["Stolikowy"])
        people = {"1": table_only}
        ctx = two_judges(judges=people, city_of=lambda judge_id, day: people[judge_id].city)
        plan = build_plan([one_slot_need(0)], ctx)
        assert not plan.proposals
        assert "tylko stolik (ZPRP)" in plan.gaps[0].reason

    def test_reczne_ustawienie_wygrywa_z_zprp(self):
        # ZPRP dalej pisze „Sędzia", ale okręg wie, że to już tylko stolik.
        manual = make_judge("1", "MAJKA Marek", city="Zabrze", roles=["sedzia"], assign_role="table")
        people = {"1": manual}
        ctx = two_judges(judges=people, city_of=lambda judge_id, day: people[judge_id].city)
        plan = build_plan([one_slot_need(0)], ctx)
        assert not plan.proposals
        assert "tylko stolik (ustawienie okręgu)" in plan.gaps[0].reason
        # I odwrotnie: ręczne „boisko i stolik" zdejmuje ograniczenie z ZPRP.
        both = make_judge("1", "MAJKA Marek", city="Zabrze", roles=["stolikowy"], assign_role="both")
        people = {"1": both}
        ctx = two_judges(judges=people, city_of=lambda judge_id, day: people[judge_id].city)
        assert [p.judge_id for p in build_plan([one_slot_need(0)], ctx).proposals] == ["1"]

    def test_tylko_boisko_nie_idzie_do_stolika(self):
        field_only = make_judge("1", "BLISKI Adam", city="Zabrze", assign_role="field")
        people = {"1": field_only}
        ctx = two_judges(judges=people, city_of=lambda judge_id, day: people[judge_id].city)
        need = one_slot_need(0)
        need.field_needed = []
        need.table_needed = ["sekretarz"]
        plan = build_plan([need], ctx)
        assert not plan.proposals and "tylko boisko" in plan.gaps[0].reason

    def test_role_nieznane_bez_ograniczen(self):
        from app.assignment_people import effective_assign_role, role_refusal, zprp_role_label

        unknown = make_judge("1", "NOWY Jan")
        assert role_refusal(unknown, "field") is None
        assert effective_assign_role(unknown) == "both"
        assert effective_assign_role(make_judge("2", "X Y", roles=["Stolikowy"])) == "table"
        assert zprp_role_label(["Sędzia", "Stolikowy"]) == "boisko i stolik"
        assert zprp_role_label(["delegat"]) == "tylko delegat"
        assert role_refusal(make_judge("3", "D E", roles=["delegat"]), "field") == "bez roli sędziego w ZPRP"
