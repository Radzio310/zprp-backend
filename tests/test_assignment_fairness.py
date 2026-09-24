"""
Równy podział w Automacie (decyzja użytkownika z 24.09.2026: „proponuje
w kółko tych samych").

  - sezon i miesiąc, boisko i stolik osobno, razem z przydziałami z TEGO
    przebiegu i z kolejki (`pending`),
  - kilometry decydują tylko między podobnie obciążonymi (różnica 1 meczu),
  - para nie przebije różnicy 2 meczów,
  - stara reguła (`legacy_load`) skupiała mecze na najbliższych.
"""

from datetime import datetime, timedelta, timezone

from app import judge_season_load as L
from app import settlement_rates as R
from app.assignment_auto import Context, Loads, MatchNeed, build_plan, fair_points
from app.assignment_people import fold, make_judge

HOST = "Gliwice"


def world(judges, km_of, **rest):
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


def need(index, *, field=2, table=0, code=None, day=None):
    moment = day or datetime(2026, 10, 1, 18, 0) + timedelta(days=index)
    return MatchNeed(
        match_id=str(1000 + index),
        code=code or f"S/JmM/{index}",
        moment=moment,
        day=moment.date(),
        host_city=HOST,
        field_needed=["pierwszy", "drugi"][:field],
        table_needed=["sekretarz", "czas"][:table],
    )


def spread(plan, judges):
    counts = {judge.judge_id: 0 for judge in judges}
    for item in plan.proposals:
        counts[item.judge_id] += 1
    return max(counts.values()) - min(counts.values()), counts


def staircase():
    """Ośmiu sędziów: 5, 15, 25 ... 75 km od hali."""
    judges = [make_judge(str(i), f"SĘDZIA {i}", city=f"Miasto{i}") for i in range(8)]
    table = {fold(f"Miasto{i}"): 5.0 + 10.0 * i for i in range(8)}

    def km(a, b):
        return table.get(fold(a)) if fold(b) == fold(HOST) else None

    return judges, km


class TestStaraRegulaSkupiala:
    def test_stara_regula_bierze_w_kolko_najblizszych(self):
        judges, km = staircase()
        needs = [need(i) for i in range(10)]
        plan = build_plan(needs, world(judges, km, legacy_load=True))
        gap, counts = spread(plan, judges)
        # Najbliżsi po 4 mecze, najdalszy żadnego.
        assert gap >= 4 and counts["7"] == 0, counts

    def test_nowa_regula_dzieli_rowno_mimo_roznych_odleglosci(self):
        judges, km = staircase()
        needs = [need(i) for i in range(10)]
        plan = build_plan(needs, world(judges, km))
        gap, counts = spread(plan, judges)
        assert len(plan.proposals) == 20
        # Kilometry rozstrzygają tylko przy różnicy 1 meczu, więc bliższy może
        # mieć o jeden więcej niż ktoś, a ten o jeden więcej niż najdalszy -
        # ale nigdy więcej, i nikt nie zostaje bez meczu.
        assert gap <= 2 and min(counts.values()) >= 1, counts

    def test_rowne_odleglosci_dziesiec_meczow_osmiu_sedziow(self):
        judges = [make_judge(str(i), f"SĘDZIA {i}", city="Zabrze") for i in range(8)]
        plan = build_plan([need(i) for i in range(10)], world(judges, lambda a, b: 20.0))
        gap, counts = spread(plan, judges)
        assert gap <= 1, counts


class TestKilometryMiedzyPodobnymi:
    def test_roznica_jednego_meczu_rozstrzyga_dojazd(self):
        near = make_judge("1", "BLISKI Adam", city="Zabrze")
        far = make_judge("2", "DALEKI Jan", city="Rybnik")
        km = lambda a, b: {"zabrze": 5.0, "rybnik": 60.0}.get(fold(a))
        ctx = world([near, far], km, season_counts={"1": {"field": 1}})
        plan = build_plan([need(0, field=1)], ctx)
        assert [p.judge_id for p in plan.proposals] == ["1"]

    def test_roznica_dwoch_meczow_przewaza_nad_dojazdem(self):
        near = make_judge("1", "BLISKI Adam", city="Zabrze")
        far = make_judge("2", "DALEKI Jan", city="Rybnik")
        km = lambda a, b: {"zabrze": 5.0, "rybnik": 140.0}.get(fold(a))
        ctx = world([near, far], km, season_counts={"1": {"field": 2}})
        plan = build_plan([need(0, field=1)], ctx)
        assert [p.judge_id for p in plan.proposals] == ["2"]
        assert any("najmniej meczów" in " ".join(p.reasons) for p in plan.proposals)

    def test_miesiac_liczy_sie_osobno_od_sezonu(self):
        # Sezon po równo (3), ale Adam ma już 2 mecze w październiku.
        near = make_judge("1", "BLISKI Adam", city="Zabrze")
        far = make_judge("2", "DALEKI Jan", city="Rybnik")
        km = lambda a, b: {"zabrze": 5.0, "rybnik": 70.0}.get(fold(a))
        ctx = world(
            [near, far],
            km,
            season_counts={"1": {"field": 3}, "2": {"field": 3}},
            month_counts={"1": {"2026-10": {"field": 2}}},
        )
        plan = build_plan([need(0, field=1)], ctx)
        assert [p.judge_id for p in plan.proposals] == ["2"]

    def test_boisko_i_stolik_licza_sie_osobno(self):
        # Adam ma dużo stolików, ale na boisku tyle samo co Jan - boisko po km.
        near = make_judge("1", "BLISKI Adam", city="Zabrze")
        far = make_judge("2", "DALEKI Jan", city="Rybnik")
        km = lambda a, b: {"zabrze": 5.0, "rybnik": 70.0}.get(fold(a))
        ctx = world([near, far], km, season_counts={"1": {"field": 0, "table": 9}})
        plan = build_plan([need(0, field=1)], ctx)
        assert [p.judge_id for p in plan.proposals] == ["1"]


class TestParaNiePrzebijeRoznicyDwoch:
    def test_para_przegrywa_z_roznica_dwoch_meczow(self):
        x = make_judge("10", "IKSIŃSKI Xawery", city="Zabrze")
        y = make_judge("11", "IGREKOWA Ula", city="Zabrze")
        a = make_judge("12", "ALFA Adam", city="Rybnik")
        b = make_judge("13", "BETA Beata", city="Rybnik")
        km = lambda one, two: {"zabrze": 10.0, "rybnik": 50.0}.get(fold(one))
        ctx = world(
            [x, y, a, b],
            km,
            partner_of={"10": "11", "11": "10"},
            season_counts={"10": {"field": 4}, "11": {"field": 4}, "12": {"field": 2}, "13": {"field": 2}},
        )
        plan = build_plan([need(0)], ctx)
        assert {p.judge_id for p in plan.proposals} == {"12", "13"}

    def test_para_wygrywa_przy_roznicy_jednego_meczu(self):
        x = make_judge("10", "IKSIŃSKI Xawery", city="Zabrze")
        y = make_judge("11", "IGREKOWA Ula", city="Zabrze")
        a = make_judge("12", "ALFA Adam", city="Rybnik")
        b = make_judge("13", "BETA Beata", city="Rybnik")
        km = lambda one, two: {"zabrze": 10.0, "rybnik": 50.0}.get(fold(one))
        ctx = world(
            [x, y, a, b],
            km,
            partner_of={"10": "11", "11": "10"},
            season_counts={"10": {"field": 3}, "11": {"field": 3}, "12": {"field": 2}, "13": {"field": 2}},
        )
        plan = build_plan([need(0)], ctx)
        assert {p.judge_id for p in plan.proposals} == {"10", "11"}


class TestLicznikiIKolejka:
    def test_kara_rosnie_szybko(self):
        assert fair_points(0, 0, 0.0) == 0
        assert fair_points(1, 0, 1.0) < fair_points(2, 0, 1.0) / 10
        assert fair_points(5, 0, 1.0) > fair_points(3, 0, 1.0) * 2

    def test_przebieg_nie_rusza_licznikow_z_zewnatrz(self):
        judges = [make_judge(str(i), f"SĘDZIA {i}", city="Zabrze") for i in range(2)]
        season = {"0": {"field": 1}}
        build_plan([need(0, field=2)], world(judges, lambda a, b: 5.0, season_counts=season))
        assert season == {"0": {"field": 1}}

    def test_loads_dodaje_sezon_i_miesiac(self):
        loads = Loads({"1": {"field": 2}}, {})
        loads.add("1", "field", "2026-10")
        assert loads.count("1", "field") == 3
        assert loads.month_count("1", "2026-10", "field") == 1
        assert loads.count("1", "table") == 0

    def test_kolejka_i_terminarz_przykrywaja_rejestr(self):
        now = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
        at = datetime(2026, 10, 4, 14, 0, tzinfo=timezone.utc)
        register = [
            # Stary wiersz meczu 77: w rejestrze stał jeszcze sędzia 5.
            {"judge_id": "5", "match_key": "d:77", "match_at": at, "match_code": "S/JmM/1", "role": R.ROLE_FIELD},
            # Stolik ligowy spoza terminarza okręgu zostaje z rejestru.
            {"judge_id": "5", "match_key": "o:88", "match_at": at, "match_code": "IIK4/1", "role": R.ROLE_TABLE},
        ]
        matches = {
            "77": {"match_at": at, "match_code": "S/JmM/1", "crew": {"pierwszy": "6", "drugi": "", "sekretarz": "", "czas": ""}},
            "78": {"match_at": at, "match_code": "S/JmM/2", "crew": {"pierwszy": "", "drugi": "", "sekretarz": "", "czas": ""}},
        }
        season, months = L.counts_for_auto(
            register, matches, now=now, pending=[{"match_id": "78", "slot": "sekretarz", "judge_id": "6"}]
        )
        assert season["5"]["field"] == 0 and season["5"]["table"] == 1
        assert season["6"]["field"] == 1 and season["6"]["table"] == 1
        assert months["6"]["2026-10"]["table"] == 1

    def test_miesiac_w_czasie_polskim(self):
        # 30.09 22:30 UTC to już 1 października w Polsce.
        assert L.month_of(datetime(2026, 9, 30, 22, 30, tzinfo=timezone.utc)) == "2026-10"
        rows = [
            {
                "judge_id": "1",
                "match_at": datetime(2026, 9, 30, 22, 30, tzinfo=timezone.utc),
                "match_code": "S/JmM/1",
                "role": R.ROLE_FIELD,
            }
        ]
        out = L.tally_by_month(rows, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
        assert out == {"1": {"2026-10": {"field": 1, "table": 0, "future_field": 1, "future_table": 0}}}
