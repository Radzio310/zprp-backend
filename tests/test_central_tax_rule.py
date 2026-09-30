"""
Reguła zaokrągleń rachunku ZPRP dla meczów centralnych (`central_tax_parts`).

Wzór z prawdziwego rachunku ZPRP: brutto 389 zł, przejazd 2 x 122 km po 0,80.
Koszty 20% do grosza, dochód do grosza, podatek 12% do pełnych złotych
(połówka w górę), netto = brutto - podatek. Mecze okręgowe bez zmian.
"""

from app import settlement_engine as E
from app import settlement_rates as R
from tests.test_settlement_zprp import at, make, settle


def test_wzor_z_rachunku_zprp_389():
    parts = R.central_tax_parts(389)
    assert parts == {"gross": 389, "costs": 77.80, "taxable": 311.20, "tax": 37, "net": 352}
    travel = R.travel_pln(122, 0.80)
    assert travel == 195.20
    assert round(parts["net"] + travel, 2) == 547.20


def test_297_zl():
    assert R.central_tax_parts(297) == {
        "gross": 297, "costs": 59.40, "taxable": 237.60, "tax": 29, "net": 268,
    }


def test_prog_200_zl_zostaje():
    # Równe 200 zł: kosztów nie ma, podatek 12% od całości.
    assert R.central_tax_parts(200) == {"gross": 200, "costs": 0, "taxable": 200, "tax": 24, "net": 176}
    assert R.central_tax_parts(200.01)["costs"] == 40.00


def test_polowka_podatku_w_gore_nie_bankierska():
    # 296,88 zł: koszty 59,376 -> 59,38, dochód 237,50, 12% = 28,50 -> 29.
    # `round(28.5)` w Pythonie dałby 28 - tu ma wyjść 29 (Math.round/Excel).
    parts = R.central_tax_parts(296.88)
    assert parts["costs"] == 59.38
    assert parts["taxable"] == 237.50
    assert parts["tax"] == 29
    assert parts["net"] == 267.88
    # Poniżej progu: 37,50 zł -> 4,50 -> 5 (bankierskie: 4).
    assert R.central_tax_parts(37.50)["tax"] == 5


def test_polowka_grosza_kosztow_w_gore():
    # 0,2 x 250,03 = 50,006 -> 50,01; 0,2 x 250,025 nie wystąpi (brutto do grosza).
    assert R.central_tax_parts(250.03)["costs"] == 50.01


def test_zero():
    assert R.central_tax_parts(0) == {"gross": 0, "costs": 0, "taxable": 0, "tax": 0, "net": 0}


def test_okreg_bez_zmian():
    # Okręg: koszty i dochód do pełnych złotych - dokładnie jak dotąd.
    assert R.net_parts(389) == {"gross": 389, "costs": 78, "taxable": 311, "tax": 37, "net": 352}
    assert R.settle_period(297)["costs"] == 59


def test_platnicy_osobno_bez_obsad_zprp_to_settle_period():
    assert R.settle_by_payer(450, []) == R.settle_period(450)
    assert R.settle_by_payer(450, [0]) == R.settle_period(450)
    assert R.settle_by_payer(0, [389]) == R.central_tax_parts(389)
    assert R.settle_by_payer(0, []) == R.settle_period(0)


def test_platnicy_osobno_suma_dwoch_rachunkow():
    parts = R.settle_by_payer(117, [389])
    district = R.settle_period(117)
    assert parts["gross"] == 506
    assert parts["costs"] == 77.80
    assert parts["taxable"] == round(district["taxable"] + 311.20, 2)
    assert parts["tax"] == district["tax"] + 37
    assert parts["net"] == round(district["net"] + 352, 2)


def test_zprp_rachunek_po_rachunku_nie_od_sumy():
    # Dwa mecze po 297 zł: każdy rachunek ma podatek 29 zł (237,60 x 12% = 28,51),
    # razem 58 zł. Od sumy 594 zł wyszłoby 57 zł (475,20 x 12% = 57,02).
    assert R.central_tax_parts(594)["tax"] == 57
    parts = R.settle_by_payer(0, [297, 297])
    assert parts["tax"] == 58
    assert parts["costs"] == 118.80
    assert parts["net"] == 536
    # Koszty też jako suma zaokrąglonych: 2 x 59,38 = 118,76, od sumy 118,75.
    assert R.central_tax_parts(593.76)["costs"] == 118.75
    assert R.settle_by_payer(0, [296.88, 296.88])["costs"] == 118.76


def test_silnik_dwa_mecze_zprp_w_miesiacu_osobne_rachunki():
    items = [
        make("a", "SM/8", R.ROLE_FIELD, at("2026-10-04T18:00"), km=486, city="Kwidzyn"),
        make("b", "SM/9", R.ROLE_FIELD, at("2026-10-11T18:00"), km=486, city="Kwidzyn"),
    ]
    [entry] = settle(items, include_zprp=True)
    assert entry.tax == sum(R.central_tax_parts(m.gross)["tax"] for m in entry.matches)
    assert entry.costs == round(sum(R.central_tax_parts(m.gross)["costs"] for m in entry.matches), 2)


def test_silnik_z_przelacznikiem_zprp_liczy_superlige_regula_zprp():
    items = [
        make("d", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00")),
        make("l", "SM/8", R.ROLE_FIELD, at("2026-10-09T18:00"), km=486, city="Kwidzyn"),
    ]
    [entry] = settle(items, include_zprp=True)
    district = [m for m in entry.matches if not m.zprp_reason]
    central = [m for m in entry.matches if m.zprp_reason]
    expected = R.settle_by_payer(
        sum(m.gross for m in district), [m.gross for m in central]
    )
    assert entry.costs == expected["costs"]
    assert entry.tax == expected["tax"]
    assert entry.net == expected["net"]
    # Część okręgowa nie przekracza progu - superliga jej nie podbija.
    d = R.settle_period(sum(m.gross for m in district))
    assert entry.tax == d["tax"] + sum(R.central_tax_parts(m.gross)["tax"] for m in central)


def test_silnik_bez_przelacznika_bez_zmian():
    items = [make("d", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00"))]
    [entry] = settle(items)
    parts = R.settle_period(entry.gross)
    assert (entry.costs, entry.taxable, entry.tax, entry.net) == (
        parts["costs"], parts["taxable"], parts["tax"], parts["net"],
    )
    totals = E.totals_of([entry])
    assert totals["costs"] == parts["costs"]


def test_oom_rozlicza_zprp_w_kazdej_roli():
    assert R.zprp_settlement_reason("OOM/3", R.ROLE_FIELD) == R.ZPRP_OOM
    assert R.zprp_settlement_reason("OOMK/1", R.ROLE_TABLE) == R.ZPRP_OOM
    assert R.zprp_settlement_reason("OOM", R.ROLE_DELEGATE) == R.ZPRP_OOM
    assert R.zprp_settlement_reason("ZOOM/1", R.ROLE_FIELD) is None
