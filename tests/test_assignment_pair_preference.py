"""
Pary w Automacie (decyzja użytkownika z 24.09.2026: „mocno, równość jako druga").

  - na boisku ustalona para razem, nawet gdy ktoś obcy siedzi bliżej,
  - gdy połówka pary nie może - druga połówka z kimś z JEJ pary mentorskiej,
  - para traci pierwszeństwo przy wyraźnie większej liczbie meczów w sezonie
    (powyżej mediany aktywnych + 2),
  - przy stoliku ustalona para też razem, ale bez mentorów.
"""

from datetime import datetime

from app.assignment_auto import Context, MatchNeed, build_plan
from app.assignment_context import Roster, build_context, merge_pairs
from app.assignment_distances import DistanceBook
from app.assignment_people import (
    MENTOR,
    PAIR,
    fold,
    heavy_judges,
    make_judge,
    median,
    pair_key,
    pair_relation,
)

KM = {
    ("gliwice", "zabrze"): 12,
    ("gliwice", "katowice"): 28,
    ("gliwice", "bielsko-biala"): 78,
    ("zabrze", "katowice"): 20,
    ("zabrze", "bielsko-biala"): 85,
    ("katowice", "bielsko-biala"): 60,
}


def km(a, b):
    left, right = fold(a), fold(b)
    if not left or not right:
        return None
    if left == right:
        return 0.0
    return KM.get((left, right)) or KM.get((right, left))


X = make_judge("10", "IKSIŃSKI Xawery", city="Zabrze")
Y = make_judge("11", "IGREKOWA Ula", city="Bielsko-Biała")
Z = make_judge("12", "ZETOWSKI Zenon", city="Katowice")
M1 = make_judge("20", "MENTOR Marek", city="Bielsko-Biała")
M2 = make_judge("21", "MENTORKA Maria", city="Bielsko-Biała")

PAIRS = {"10": "11", "11": "10"}
MENTORS = {"10": ("20", "21"), "11": ("20", "21")}


def world(judges, **rest):
    people = {judge.judge_id: judge for judge in judges}
    options = {
        "judges": people,
        "available": lambda judge_id, moment: True,
        "paused": lambda judge_id, day: False,
        "city_of": lambda judge_id, day: people[judge_id].city,
        "km": km,
        "partner_of": PAIRS,
        "mentors_of": MENTORS,
    }
    options.update(rest)
    return Context(**options)


def match(code="S/JmM/1", city="Gliwice", field=2, table=0):
    moment = datetime(2026, 10, 5, 18, 0)
    return MatchNeed(
        match_id="1",
        code=code,
        moment=moment,
        day=moment.date(),
        host_city=city,
        field_needed=["pierwszy", "drugi"][:field],
        table_needed=["sekretarz", "czas"][:table],
    )


def names(plan):
    return {item.judge_name for item in plan.proposals}


def reasons(plan):
    return " | ".join(" ".join(item.reasons) for item in plan.proposals)


class TestParyNaBoisku:
    def test_para_razem_mimo_blizszego_obcego(self):
        # Zenon (28 km) jest bliżej niż Ula (78 km), ale Xawery i Ula to para.
        plan = build_plan([match()], world([X, Y, Z, M1]))
        assert names(plan) == {X.name, Y.name}
        assert "para z" in reasons(plan)

    def test_bez_pary_wygrywa_odleglosc(self):
        plan = build_plan([match()], world([X, Y, Z], partner_of={}, mentors_of={}))
        assert names(plan) == {X.name, Z.name}

    def test_polowka_pary_z_mentorem_gdy_partner_nie_moze(self):
        ctx = world(
            [X, Y, Z, M1],
            available=lambda judge_id, moment: judge_id != "11",
        )
        plan = build_plan([match()], ctx)
        assert names(plan) == {X.name, M1.name}
        assert "para mentorska" in reasons(plan)

    def test_para_traci_pierwszenstwo_przy_duzej_liczbie_meczow(self):
        ctx = world([X, Y, Z, M1], heavy={"10"})
        plan = build_plan([match()], ctx)
        assert names(plan) == {X.name, Z.name}
        # Zero cichych decyzji: w uzasadnieniu widać, czemu para ustąpiła.
        plan_y = build_plan([match()], world([X, Y], heavy={"10"}))
        assert "bez pierwszeństwa" in reasons(plan_y)

    def test_pierwszy_boiskowy_z_para_ktora_moze_przyjechac(self):
        # Xawery (12 km) nie ma tu pary, Zenon (28 km) ma parę z Markiem (78 km).
        # Bez premii za gotową parę pierwszy wszedłby Xawery, a Zenon do niego -
        # para Zenon-Marek by się rozjechała.
        ctx = world([X, Z, M1], partner_of={"12": "20", "20": "12"}, mentors_of={})
        plan = build_plan([match()], ctx)
        assert names(plan) == {Z.name, M1.name}
        assert "może stanąć ze swoją parą" in reasons(plan)


class TestParyPrzyStoliku:
    def test_para_razem_przy_stoliku(self):
        plan = build_plan([match(field=0, table=2)], world([X, Y, Z]))
        assert names(plan) == {X.name, Y.name}

    def test_przy_stoliku_bez_mentorow(self):
        ctx = world(
            [X, Y, Z, M1],
            available=lambda judge_id, moment: judge_id != "11",
        )
        plan = build_plan([match(field=0, table=2)], ctx)
        assert names(plan) == {X.name, Z.name}


class TestRegulParyWLisciu:
    def test_relacja_pary_i_mentora_w_obie_strony(self):
        assert pair_relation("10", "11", partner_of=PAIRS, mentors_of=MENTORS) == PAIR
        assert pair_relation("10", "20", partner_of=PAIRS, mentors_of=MENTORS) == MENTOR
        assert pair_relation("20", "10", partner_of=PAIRS, mentors_of=MENTORS) == MENTOR
        assert pair_relation("10", "12", partner_of=PAIRS, mentors_of=MENTORS) is None
        assert (
            pair_relation("10", "20", partner_of=PAIRS, mentors_of=MENTORS, allow_mentor=False)
            is None
        )

    def test_mediana(self):
        assert median([]) == 0.0
        assert median([1, 5, 3]) == 3.0
        assert median([1, 2, 3, 10]) == 2.5

    def test_ciezcy_ponad_mediane_plus_dwa(self):
        counts = {"a": 3, "b": 4, "c": 5, "d": 6, "e": 9}
        # Mediana 5, próg 7 - tylko „e".
        assert heavy_judges(counts, counts.keys()) == {"e"}
        # Zero w liczniku to też informacja: nieaktywni bez meczów obniżają medianę.
        assert heavy_judges({"a": 3}, ["a", "b", "c"]) == {"a"}
        assert heavy_judges({}, ["a"]) == set()

    def test_klucz_pary_niezalezny_od_kolejnosci(self):
        assert pair_key("11", "10") == pair_key("10", "11") == "10|11"


class TestKontekstu:
    def test_wlasna_para_wygrywa_cala(self):
        pairs, source = merge_pairs(
            [("1", "2", "zprp"), ("2", "1", "zprp"), ("1", "3", "own"), ("3", "1", "own")]
        )
        assert pairs == {"1": "3", "3": "1"}
        assert source == {"1": "own", "3": "own"}

    def test_para_zprp_uzupelnia_braki(self):
        pairs, source = merge_pairs([("4", "5", "zprp"), ("5", "4", "zprp")])
        assert pairs == {"4": "5", "5": "4"}
        assert source["4"] == "zprp"

    def test_mentorzy_pary_i_ciezcy_w_kontekscie(self):
        roster = Roster()
        for judge in (X, Y, Z, M1):
            roster.judges[judge.judge_id] = judge
        roster.pairs = dict(PAIRS)
        roster.mentor_pairs = {pair_key("10", "11"): ["20", "21"]}
        assert roster.mentors_of("11") == ["20", "21"]
        assert roster.mentors_of("12") == []
        ctx = build_context(
            roster,
            DistanceBook.__new__(DistanceBook),
            season_field={"10": 9, "11": 1, "12": 0, "20": 1},
        )
        assert ctx.mentors_of["10"] == ("20", "21")
        assert ctx.heavy == {"10"}

    def test_bez_licznikow_nikt_nie_traci_pierwszenstwa(self):
        roster = Roster()
        roster.judges["10"] = X
        ctx = build_context(roster, DistanceBook.__new__(DistanceBook))
        assert ctx.heavy == set()

