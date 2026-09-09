"""
Kwota slownie po polsku - „dziewiecset piecdziesiat piec 20/100".

Postac wzieta wprost z dotychczasowej Listy kosztow przejazdow okregu: slownie
sama zlotowka, a grosze jako ulamek. Ksiegowosc czyta ten dokument od lat w tej
formie i nie ma powodu jej zmieniac.

MODUL-LISC, zeby odmiana liczebnikow miala test - bo „dwiescie" i „dwadziescia"
brzmia podobnie tylko do momentu, w ktorym trafia na przelew.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

_ONES = (
    "", "jeden", "dwa", "trzy", "cztery", "pięć", "sześć", "siedem", "osiem", "dziewięć",
)
_TEENS = (
    "dziesięć", "jedenaście", "dwanaście", "trzynaście", "czternaście",
    "piętnaście", "szesnaście", "siedemnaście", "osiemnaście", "dziewiętnaście",
)
_TENS = (
    "", "", "dwadzieścia", "trzydzieści", "czterdzieści", "pięćdziesiąt",
    "sześćdziesiąt", "siedemdziesiąt", "osiemdziesiąt", "dziewięćdziesiąt",
)
_HUNDREDS = (
    "", "sto", "dwieście", "trzysta", "czterysta", "pięćset",
    "sześćset", "siedemset", "osiemset", "dziewięćset",
)

#: (pojedyncza, mnoga „2-4", mnoga „5+") dla kolejnych grup trzycyfrowych.
_GROUPS = (
    ("", "", ""),
    ("tysiąc", "tysiące", "tysięcy"),
    ("milion", "miliony", "milionów"),
    ("miliard", "miliardy", "miliardów"),
)


def _plural(value: int, forms: tuple[str, str, str]) -> str:
    """Polska odmiana: 1 / 2-4 / reszta, z wyjatkiem nastek (12-14)."""
    if value == 1:
        return forms[0]
    last_two = value % 100
    last = value % 10
    if 2 <= last <= 4 and not 12 <= last_two <= 14:
        return forms[1]
    return forms[2]


def _under_thousand(value: int) -> list[str]:
    out: list[str] = []
    hundreds, rest = divmod(value, 100)
    if hundreds:
        out.append(_HUNDREDS[hundreds])
    if 10 <= rest <= 19:
        out.append(_TEENS[rest - 10])
        return out
    tens, ones = divmod(rest, 10)
    if tens:
        out.append(_TENS[tens])
    if ones:
        out.append(_ONES[ones])
    return out


def integer_in_words(value: int) -> str:
    """Liczba calkowita slownie. Zero ma wlasna nazwe, bo pusty napis to blad."""
    value = int(value)
    if value == 0:
        return "zero"
    if value < 0:
        return "minus " + integer_in_words(-value)

    groups: list[int] = []
    while value:
        value, remainder = divmod(value, 1000)
        groups.append(remainder)

    parts: list[str] = []
    for index in range(len(groups) - 1, -1, -1):
        group = groups[index]
        if not group:
            continue
        # „tysiac" nie potrzebuje swojego „jeden".
        if not (index and group == 1):
            parts.extend(_under_thousand(group))
        if index:
            parts.append(_plural(group, _GROUPS[index]))
    return " ".join(p for p in parts if p)


def amount_in_words(amount: Any) -> str:
    """
    Kwota w postaci z dokumentu: `955.20` -> „dziewięćset pięćdziesiąt pięć 20/100".

    Grosze zaokraglamy tak, jak robi to ksiegowosc (polowka w gore), a nie tak,
    jak robi to zmiennoprzecinkowy typ Pythona.
    """
    try:
        value = Decimal(str(amount or 0))
    except Exception:
        value = Decimal(0)
    value = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    zlotys = int(value)
    grosze = int((abs(value) - abs(zlotys)) * 100)
    return f"{integer_in_words(zlotys)} {grosze:02d}/100"


def money(amount: Any) -> str:
    """`1896` -> „1 896,00 zł". Spacja nierozdzielajaca, zeby nie lamalo wiersza."""
    try:
        value = Decimal(str(amount or 0))
    except Exception:
        value = Decimal(0)
    value = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    whole, _, fraction = f"{value:.2f}".partition(".")
    sign = ""
    if whole.startswith("-"):
        sign, whole = "-", whole[1:]
    grouped = ""
    while len(whole) > 3:
        grouped = " " + whole[-3:] + grouped
        whole = whole[:-3]
    return f"{sign}{whole}{grouped},{fraction} zł"


def number(amount: Any, decimals: int = 0) -> str:
    """Liczba z separatorem tysiecy, bez waluty."""
    try:
        value = Decimal(str(amount or 0))
    except Exception:
        value = Decimal(0)
    quant = Decimal(1).scaleb(-decimals) if decimals else Decimal(1)
    value = value.quantize(quant, rounding=ROUND_HALF_UP)
    text = f"{value:.{decimals}f}"
    whole, _, fraction = text.partition(".")
    sign = ""
    if whole.startswith("-"):
        sign, whole = "-", whole[1:]
    grouped = ""
    while len(whole) > 3:
        grouped = " " + whole[-3:] + grouped
        whole = whole[:-3]
    return f"{sign}{whole}{grouped}" + (f",{fraction}" if fraction else "")
