"""
Automat obsady na danych w skali ŚLĄSKIEGO - czy śmiga i czy układ ma sens.

Nie mam dostępu do produkcji, więc buduję świat tej samej WIELKOŚCI i o tym
samym kształcie: ~200 sędziów rozsianych po miastach Śląska, ~200 meczów w dwa
tygodnie, prawdziwe odległości między miastami, realny rozkład kategorii
(dużo dzieci i młodzików, mniej juniorów, kilka meczów II ligi).

Sprawdzam sześć rzeczy, które decydują o tym, czy to się nadaje do użytku:
  1. ILE gniazd zostaje pustych i dlaczego,
  2. czy zdarza się MECZ Z SAMYM STOLIKIEM, bez sędziego na boisku,
  3. jak wygląda PODZIAŁ pracy między sędziów,
  4. ile wychodzi KILOMETRÓW i czy nikt nie jeździ absurdalnie daleko,
  5. czy twarde zasady są dotrzymane (dwoje młodych, para wykluczona, licencja A),
  6. ile to TRWA.
"""
import random
import pathlib
import sys
import time
from datetime import date, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.assignment_auto import BusyMatch, Context, MatchNeed, build_plan
from app.assignment_people import fold, make_judge
from app.assignment_report import build_report

# Miasta Śląska z odległościami - szkielet tabeli okręgowej.
CITIES = {
    "Katowice": (0, 0), "Gliwice": (-25, 5), "Zabrze": (-18, 4), "Bytom": (-12, 10),
    "Sosnowiec": (10, 2), "Chorzów": (-8, 6), "Ruda Śląska": (-15, 6),
    "Tychy": (2, -18), "Rybnik": (-35, -25), "Częstochowa": (20, 65),
    "Bielsko-Biała": (18, -50), "Jastrzębie-Zdrój": (-40, -35),
    "Zawiercie": (28, 30), "Piekary Śląskie": (-6, 14), "Siemianowice Śląskie": (-2, 9),
    "Żory": (-30, -28), "Mysłowice": (8, -3), "Dąbrowa Górnicza": (16, 12),
    "Tarnowskie Góry": (-10, 22), "Wodzisław Śląski": (-42, -30),
    "Racibórz": (-55, -18), "Cieszyn": (-8, -60), "Lubliniec": (-5, 40),
    "Pszczyna": (-5, -30), "Knurów": (-30, 0), "Łaziska Górne": (-12, -22),
}


def km(a, b):
    """Odległość drogowa - prosta razy 1,25, bo drogi nie są liniami."""
    pa = CITIES.get(_city(a))
    pb = CITIES.get(_city(b))
    if pa is None or pb is None:
        return None
    if pa == pb:
        return 0.0
    dx, dy = pa[0] - pb[0], pa[1] - pb[1]
    return round(((dx * dx + dy * dy) ** 0.5) * 1.25, 1)


def _city(value):
    wanted = fold(value)
    for name in CITIES:
        if fold(name) == wanted:
            return name
    return None


# Rozkład kategorii zbliżony do okręgowego terminarza.
CATEGORIES = (
    ["S/DzM"] * 30 + ["S/DzK"] * 25 + ["S/MłM"] * 25 + ["S/MłK"] * 20
    + ["S/JmM"] * 20 + ["S/JmK"] * 15 + ["S/JM"] * 12 + ["S/JK"] * 10
    + ["IIK4"] * 6 + ["IIM4"] * 6 + ["S/PPK"] * 2
)

FIRST = ["Jan", "Anna", "Paweł", "Ewa", "Marek", "Tomasz", "Zofia", "Piotr", "Julia",
         "Adam", "Katarzyna", "Michał", "Agnieszka", "Rafał", "Marta", "Łukasz"]
LAST = ["KOWALSKI", "NOWAK", "WÓJCIK", "KOWALCZYK", "KAMIŃSKI", "LEWANDOWSKI",
        "ZIELIŃSKI", "SZYMAŃSKI", "WOŹNIAK", "DĄBROWSKI", "KOZŁOWSKI", "JANKOWSKI",
        "MAZUR", "KWIATKOWSKI", "KRAWCZYK", "PIOTROWSKI", "GRABOWSKI", "NOWICKI",
        "PAWŁOWSKI", "MICHALSKI", "ADAMCZYK", "DUDEK", "ZAJĄC", "WIECZOREK"]


def build_world(seed=7, judges_count=190, matches_count=200, days=14):
    rng = random.Random(seed)
    cities = list(CITIES)

    judges = {}
    for index in range(judges_count):
        city = rng.choices(cities, weights=[6 if c in ("Katowice", "Gliwice", "Sosnowiec",
                                                       "Bytom", "Zabrze") else 2
                                            for c in cities])[0]
        # Piramida uprawnień: mało centralnych, sporo okręgowych, dużo młodych.
        roll = rng.random()
        if roll < 0.06:
            letters, badges = ["SL", "LC", "I", "II", "MP"], ["Ligowcy"]
        elif roll < 0.18:
            letters, badges = ["I", "II", "III", "MP"], ["Ligowcy"]
        elif roll < 0.36:
            letters, badges = ["II", "III"], ["Ligowcy"] if rng.random() < 0.5 else []
        elif roll < 0.70:
            letters, badges = ["III"], ["Stolikowi"] if rng.random() < 0.35 else []
        else:
            letters, badges = ["Mł"], ["Młodzi"]
        judge = make_judge(
            str(1000 + index),
            f"{rng.choice(LAST)} {rng.choice(FIRST)}",
            city=city,
            letters=letters,
            badges=badges,
            preferred_days=(
                rng.sample([0, 1, 2, 3, 4, 5, 6], rng.choice([2, 3]))
                if rng.random() < 0.25 else []
            ),
            needs_experienced=rng.random() < 0.05,
        )
        judges[judge.judge_id] = judge

    # Pary: co czwarty sędzia ma stałego partnera.
    ids = list(judges)
    rng.shuffle(ids)
    partner_of = {}
    for left, right in zip(ids[::2], ids[1::2]):
        if rng.random() < 0.25:
            partner_of[left] = right
            partner_of[right] = left

    # Pary wykluczone - kilkanaście w okręgu.
    blocked = set()
    for _ in range(15):
        a, b = rng.sample(ids, 2)
        blocked.add((a, b))
        blocked.add((b, a))

    # Niedyspozycje: każdy sędzia ma średnio kilka zajętych dni.
    today = date.today()
    busy_days = {}
    for judge_id in judges:
        taken = set()
        for _ in range(rng.randint(0, 5)):
            taken.add(today + timedelta(days=rng.randint(0, days)))
        busy_days[judge_id] = taken

    needs = []
    for index in range(matches_count):
        code = f"{rng.choice(CATEGORIES)}/{index + 1}"
        day = today + timedelta(days=rng.randint(0, days - 1))
        hour = rng.choice([9, 10, 11, 12, 14, 16, 18, 20])
        moment = datetime.combine(day, datetime.min.time()) + timedelta(hours=hour)
        city = rng.choice(cities)
        from app import assignment_rules as A

        crew = A.crew_needs(code)
        needs.append(
            MatchNeed(
                match_id=str(index + 1),
                code=code,
                moment=moment,
                day=day,
                host_city=city,
                host=f"Klub {index % 40}",
                guest=f"Klub {(index + 7) % 40}",
                field_needed=list(A.FIELD_SLOTS[: crew["field"]]),
                table_needed=list(A.TABLE_SLOTS[: crew["table"]]),
            )
        )

    ctx = Context(
        judges=judges,
        available=lambda judge_id, moment: (
            moment is None or moment.date() not in busy_days.get(judge_id, ())
        ),
        paused=lambda judge_id, day: False,
        city_of=lambda judge_id, day: judges[judge_id].city,
        km=km,
        busy={},
        partner_of=partner_of,
        blocked=blocked,
        load={},
    )
    return needs, ctx, judges


def check(needs, ctx, judges, label):
    started = time.monotonic()
    plan = build_plan(needs, ctx)
    took = time.monotonic() - started
    report = build_report(plan, needs, judges=judges)

    slots = report["slots"]
    filled = report["filled"]
    print(f"\n=== {label} ===")
    print(f"  mecze:              {report['matches']}")
    print(f"  gniazda:            {filled} z {slots}  ({filled * 100 // max(1, slots)}%)")
    print(f"  bez obsady:         {report['gaps']}")
    print(f"  sędziowie użyci:    {report['judges_used']} z {len(judges)}")
    print(f"  km: średnio {report['travel']['avg']}, max {report['travel']['max']}, "
          f"razem {report['travel']['total']}")
    print(f"  podział: {report['balance']['min']}-{report['balance']['max']} "
          f"meczów na sędziego (rozrzut {report['balance']['spread']})")
    print(f"  drugi obieg:        {report['rounds']['later']}")
    print(f"  czas liczenia:      {took:.2f} s")

    problems = []

    # 1. Mecz z samym stolikiem, bez boiskowego.
    by_match = {}
    for item in plan.proposals:
        by_match.setdefault(item.match_id, set()).add(item.slot)
    need_by_id = {need.match_id: need for need in needs}
    table_only = [
        match_id
        for match_id, got in by_match.items()
        if "pierwszy" in (need_by_id[match_id].field_needed or [])
        and "pierwszy" not in got
        and got & {"sekretarz", "czas"}
    ]
    if table_only:
        problems.append(f"mecze z samym stolikiem: {len(table_only)} (np. {table_only[:3]})")

    # 2. Ten sam sędzia dwa razy w jednym meczu.
    for match_id, got in by_match.items():
        people = [p.judge_id for p in plan.proposals if p.match_id == match_id]
        if len(people) != len(set(people)):
            problems.append(f"mecz {match_id}: ten sam sędzia w dwóch gniazdach")

    # 3. Dwoje młodych w jednej parze / para wykluczona.
    for match_id in by_match:
        field = [p for p in plan.proposals if p.match_id == match_id and p.slot in ("pierwszy", "drugi")]
        if len(field) == 2:
            a, b = judges[field[0].judge_id], judges[field[1].judge_id]
            if a.young and b.young:
                problems.append(f"mecz {match_id}: dwoje młodych na boisku")
            if (a.judge_id, b.judge_id) in ctx.blocked:
                problems.append(f"mecz {match_id}: para wykluczona przez okręg")
            if a.needs_experienced and not b.central:
                problems.append(f"mecz {match_id}: {a.name} bez partnera z licencją A")
            if b.needs_experienced and not a.central:
                problems.append(f"mecz {match_id}: {b.name} bez partnera z licencją A")

    # 4. Kolizja: dwa mecze tego samego sędziego tego samego dnia bez szansy dojazdu.
    from app.assignment_auto import can_make_both

    per_judge_day = {}
    for item in plan.proposals:
        need = need_by_id[item.match_id]
        per_judge_day.setdefault((item.judge_id, need.day), []).append(need)
    for (judge_id, day), matches in per_judge_day.items():
        for i in range(len(matches)):
            for j in range(i + 1, len(matches)):
                first, second = matches[i], matches[j]
                if not can_make_both(first.moment, second.moment, km(first.host_city, second.host_city)):
                    problems.append(
                        f"{judges[judge_id].name}: {first.code} i {second.code} tego samego dnia bez szansy dojazdu"
                    )

    # 5. Niedyspozycja zlamana.
    for item in plan.proposals:
        need = need_by_id[item.match_id]
        if not ctx.available(item.judge_id, need.moment):
            problems.append(f"{judges[item.judge_id].name}: obsadzony mimo niedyspozycji")

    # 6. Zbyt daleko.
    far = [p for p in plan.proposals if p.km is not None and p.km > 120]
    if far:
        problems.append(f"przejazdy ponad 120 km: {len(far)} (max {max(p.km for p in far)})")

    if problems:
        print("  PROBLEMY:")
        for line in sorted(set(problems))[:12]:
            print(f"    - {line}")
    else:
        print("  twarde zasady: wszystkie dotrzymane")

    # Najczęstsze powody pustych gniazd.
    from collections import Counter

    reasons = Counter()
    for gap in plan.gaps:
        for part in gap.reason.split(","):
            reasons[part.strip().split(" (")[0]] += 1
    if reasons:
        print("  najczęstsze powody pustych gniazd:")
        for reason, count in reasons.most_common(5):
            print(f"    {count:4}  {reason}")

    return plan, report, problems


if __name__ == "__main__":
    total_problems = []
    for seed in (7, 13, 42):
        needs, ctx, judges = build_world(seed=seed)
        _, _, problems = check(needs, ctx, judges, f"ŚLĄSKIE, ziarno {seed}")
        total_problems += problems

    # Skrajność: mało sędziów, dużo meczów - tu widać, czy podział jest uczciwy.
    needs, ctx, judges = build_world(seed=7, judges_count=60, matches_count=200)
    check(needs, ctx, judges, "MAŁO SĘDZIÓW (60 na 200 meczów)")

    print("\n" + ("ZNALEZIONE PROBLEMY: " + str(len(set(total_problems))) if total_problems
                  else "Bez naruszeń twardych zasad."))
