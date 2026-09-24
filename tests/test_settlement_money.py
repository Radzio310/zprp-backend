"""
Kwoty w rozliczeniach zawsze z groszami (zgłoszenie z 24.09.2026).

Karta klubu pokazywała „Obciążenia 704,60 zł" i „SALDO -705,00 zł". Saldo,
brutto meczu i ręczne ryczałty nie mogą tracić groszy. Wyjątek zamierzony:
koszty uzyskania, podstawa i zaliczka na podatek - pełne złote (ordynacja).
"""

from app import manual_charge_rules as M
from app import settlement_rates as R
from app.club_charges import CHARGED, balance, club_totals
from app.settlement_money import balance as money_balance, money, money_sum
from tests.test_club_charges import SOSNICA, charges, crew


def test_saldo_z_groszami_jak_obciazenia():
    assert balance(paid_in=0, paid_out=0, charged=704.6) == -704.6
    assert money_balance(paid_in=100.4, paid_out=0.2, charged=300.6) == -200.4
    assert balance(paid_in=0.1, paid_out=0, charged=0.1) == 0.0


def test_suma_bez_dryfu_float():
    assert money_sum([0.1, 0.2]) == 0.3
    assert money_sum([704.6, -704.6]) == 0.0
    assert money("abc") == 0.0
    assert money(None) == 0.0
    assert str(money(-0.001)) == "0.0"


def test_brutto_meczu_nie_gubi_groszy():
    rows = charges(
        [
            crew("d:1", "5124", "Sędzia 1", 150.3, 20.0),
            crew("d:1", "7788", "Sędzia 2", 150.3, 0.0),
        ],
        hosts={"d:1": SOSNICA.name},
    )
    assert rows[0].status == CHARGED
    assert rows[0].gross == 300.6
    assert rows[0].amount == 320.6
    assert [share.gross for share in rows[0].referees] == [150.3, 150.3]
    totals = club_totals(rows)[SOSNICA.club_id]
    assert totals["charged"] == 320.6
    assert totals["gross"] == 300.6


def test_podatek_w_pelnych_zlotych_brutto_i_netto_z_groszami():
    parts = R.settle_period(350.5)
    assert parts["gross"] == 350.5
    # KUP 70,10 -> 70 zł; podstawa 280,50 -> 281 zł; zaliczka 33,72 -> 34 zł.
    assert parts["costs"] == 70
    assert parts["taxable"] == 281
    assert parts["tax"] == 34
    assert parts["net"] == 316.5
    # Całe brutto: dokładnie to samo co przed zmianą.
    assert R.settle_period(450) == {"gross": 450, "costs": 90, "taxable": 360, "tax": 43, "net": 407}


def test_reczny_ryczalt_zostaje_z_groszami():
    assert M.fee_gross(150.5, M.MODE_GROSS) == 150.5
    gross = M.fee_gross(103.4, M.MODE_NET)
    assert M.net_of(gross) >= 103.4
    assert round(gross % 1, 2) == 0.4
    # Całe kwoty bez zmian.
    assert M.gross_from_net(103) == 117
    assert M.gross_from_net(226) == 250

