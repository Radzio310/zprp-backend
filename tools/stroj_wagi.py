"""
Dobór wag automatu - który zestaw daje najsensowniejszy układ.

Podejrzenie: `W_LOAD = 35` znaczy, że jeden mecz różnicy w obciążeniu jest wart
35 km drogi. Przy sędzim, który ma już dwa mecze, automat woli kogoś o 70 km
dalej - a kilometry miały być GŁÓWNYM kryterium, zaś równy podział korektą
(„dziel równo, ale nie za wszelką cenę").

Sprawdzamy kilka zestawów na tych samych trzech światach i patrzymy na trzy
liczby naraz: wypełnienie, kilometry i rozrzut obciążenia. Zestaw, który skraca
drogę kosztem pustych gniazd, jest gorszy - dlatego wypełnienie idzie pierwsze.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app import assignment_auto as AA
from app.assignment_report import build_report
from symulacja_slaskie import build_world

VARIANTS = [
    {"name": "obecny", "W_LOAD": 35.0, "FAR_KM": None, "FAR_FACTOR": 1.0},
    {"name": "load 35 + daleko x3 od 50", "W_LOAD": 35.0, "FAR_KM": 50.0, "FAR_FACTOR": 3.0},
    {"name": "load 30 + daleko x3 od 50", "W_LOAD": 30.0, "FAR_KM": 50.0, "FAR_FACTOR": 3.0},
    {"name": "load 25 + daleko x3 od 50", "W_LOAD": 25.0, "FAR_KM": 50.0, "FAR_FACTOR": 3.0},
    {"name": "load 25 + daleko x4 od 45", "W_LOAD": 25.0, "FAR_KM": 45.0, "FAR_FACTOR": 4.0},
    {"name": "load 35 + daleko x4 od 45", "W_LOAD": 35.0, "FAR_KM": 45.0, "FAR_FACTOR": 4.0},
]


def patched_score(original, far_km, far_factor):
    """Dokłada progresywną karę za bardzo daleko, nie ruszając reszty punktów."""
    def score(ctx, judge, need, *, kind, partner, round_no, load):
        points, reasons, km = original(
            ctx, judge, need, kind=kind, partner=partner, round_no=round_no, load=load
        )
        if far_km and km is not None and km > far_km:
            extra = (km - far_km) * (far_factor - 1.0) * AA.W_KM
            points += extra
            reasons.append("bardzo daleko")
        return points, reasons, km

    return score


def run(variant, worlds):
    original_load = AA.W_LOAD
    original_score = AA._score
    AA.W_LOAD = variant["W_LOAD"]
    if variant["FAR_KM"]:
        AA._score = patched_score(original_score, variant["FAR_KM"], variant["FAR_FACTOR"])
    try:
        rows = []
        for needs, ctx, judges in worlds:
            plan = AA.build_plan(needs, ctx)
            report = build_report(plan, needs, judges=judges)
            far = [p for p in plan.proposals if p.km is not None and p.km > 120]
            rows.append(
                {
                    "fill": report["filled"] / max(1, report["slots"]),
                    "avg": report["travel"]["avg"] or 0,
                    "max": report["travel"]["max"] or 0,
                    "total": report["travel"]["total"] or 0,
                    "spread": report["balance"]["spread"],
                    "far": len(far),
                }
            )
        n = len(rows)
        return {
            "name": variant["name"],
            "fill": sum(r["fill"] for r in rows) / n,
            "avg": sum(r["avg"] for r in rows) / n,
            "max": max(r["max"] for r in rows),
            "total": sum(r["total"] for r in rows) / n,
            "spread": sum(r["spread"] for r in rows) / n,
            "far": sum(r["far"] for r in rows),
        }
    finally:
        AA.W_LOAD = original_load
        AA._score = original_score


if __name__ == "__main__":
    worlds = [build_world(seed=seed) for seed in (7, 13, 42)]
    print(f"{'zestaw':30} {'wypeln.':>8} {'śr.km':>7} {'max':>7} {'razem':>9} {'rozrzut':>8} {'>120km':>7}")
    for variant in VARIANTS:
        r = run(variant, worlds)
        print(
            f"{r['name']:30} {r['fill']*100:7.1f}% {r['avg']:7.1f} {r['max']:7.1f} "
            f"{r['total']:9.0f} {r['spread']:8.1f} {r['far']:7}"
        )
