"""
Płatność zatwierdzonej faktury - czyste reguły (bez bazy).

"paid"    - wpłata istnieje w saldzie klubu (wpis kind "in", source "invoice").
"pending" - faktura zatwierdzona, ale NIEopłacona: brak wpisu w saldzie do czasu
            potwierdzenia płatności. NULL w bazie = "paid" (dane sprzed funkcji).
"""

from __future__ import annotations

from typing import Any, Iterable

PAY_PAID = "paid"
PAY_PENDING = "pending"


def is_pending(value: Any) -> bool:
    return str(value if value is not None else "").strip() == PAY_PENDING


def pay_mode(value: Any, default: str = PAY_PAID) -> str:
    """Tryb płatności z żądania: tylko "paid" albo "pending", reszta = domyślny."""
    text = str(value if value is not None else "").strip().lower()
    return text if text in (PAY_PAID, PAY_PENDING) else default


def _cents(value: Any) -> int:
    return int(round(float(value or 0) * 100))


def register_totals(items: Iterable[dict]) -> dict:
    """Sumy rejestru liczone w groszach na intach (bez dryfu float)."""
    items = list(items)
    pending = [i for i in items if i["payment_status"] == PAY_PENDING]
    pending_c = sum(_cents(i["amount"]) for i in pending)
    paid_c = sum(_cents(i["amount"]) for i in items if i["payment_status"] != PAY_PENDING)
    return {
        "pending": round(pending_c / 100, 2),
        "paid": round(paid_c / 100, 2),
        "total": round((pending_c + paid_c) / 100, 2),
        "pending_count": len(pending),
        "paid_count": len(items) - len(pending),
    }


def pending_sum(pending: dict[str, list[dict]], club_ids: list[str]) -> float:
    """Suma oczekujących faktur wskazanych klubów (zł, z groszami)."""
    return round(sum(_cents(item["amount"]) for cid in club_ids for item in pending.get(cid, [])) / 100, 2)
