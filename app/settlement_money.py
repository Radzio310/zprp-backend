"""
Kwoty pieniężne w rozliczeniach - zawsze z groszami.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

SKĄD TO SIĘ WZIĘŁO. Karta klubu pokazywała „Obciążenia 704,60 zł" i obok
„SALDO -705,00 zł" (zgłoszenie użytkownika 24.09.2026). Saldo liczyło się
przez `round(...)` do pełnych złotych, a brutto meczu przez `int(...)` ucinało
grosze z ręcznie wpisanych kwot. Pieniądze w rozliczeniach NIGDZIE nie mogą
być zaokrąglane do złotówki - każda suma, saldo i kwota idzie przez `money()`,
czyli do dwóch miejsc po przecinku.

Wyjątek, którego to NIE dotyczy: koszty uzyskania przychodu i zaliczka na
podatek w `settlement_rates` - te zaokrągla się do pełnych złotych z mocy
przepisów (ordynacja podatkowa, art. 63), tak samo jak robi to kalkulator
urzędowy. Brutto i netto zostają z groszami.
"""
from __future__ import annotations

from typing import Any


def money(value: Any) -> float:
    """Kwota do dwóch miejsc po przecinku; pustka i śmieci to 0."""
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    if amount != amount or amount in (float("inf"), float("-inf")):
        return 0.0
    # `+ 0.0` zamienia „-0.0" na „0.0" - inaczej ekran pokazałby „-0,00 zł".
    return round(amount, 2) + 0.0


def money_sum(values: Any) -> float:
    """Suma kwot bez dryfu float (0.1 + 0.2) - liczona w groszach."""
    total = 0
    for value in values or ():
        total += int(round(money(value) * 100))
    return money(total / 100)


def balance(*, paid_in: Any, paid_out: Any, charged: Any) -> float:
    """
    Saldo klubu: wpłaty minus wypłaty minus obciążenia, z groszami.

    Dodatnie = klub ma u okręgu nadwyżkę, ujemne = zalega.
    """
    cents = (
        int(round(money(paid_in) * 100))
        - int(round(money(paid_out) * 100))
        - int(round(money(charged) * 100))
    )
    return money(cents / 100)
