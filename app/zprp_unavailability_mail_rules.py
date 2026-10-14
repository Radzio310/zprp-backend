"""Czyste reguły adresowania maili o kolizji niedyspozycyjności."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


DEFAULT_DELEGATE_RECIPIENT = "mystkowski@zprp.org.pl"


def _clean(value: Any) -> str:
    return str(value or "").strip()


def is_delegate_overlap(matches: Iterable[Mapping[str, Any]]) -> bool:
    """Delegata rozpoznajemy po jego roli w meczu, nie po danych z telefonu."""
    return any(_clean(match.get("role")).casefold().startswith("delegat") for match in matches or ())


def mutual_partner_id(
    judge_id: Any,
    proposed_partner_id: Any,
    reverse_partner_id: Any,
) -> str:
    """Zwraca partnera tylko wtedy, gdy obie strony wskazują siebie nawzajem."""
    judge = _clean(judge_id)
    partner = _clean(proposed_partner_id)
    reverse = _clean(reverse_partner_id)
    return partner if partner and partner != judge and reverse == judge else ""


def primary_recipients(row: Mapping[str, Any], settings: Mapping[str, Any]) -> list[str]:
    """Delegat ma osobną skrzynkę; pozostali używają listy obsady centralnej."""
    if is_delegate_overlap(row.get("matches_json") or []):
        email = _clean(settings.get("delegate_recipient_email")) or DEFAULT_DELEGATE_RECIPIENT
        return [email.lower()]

    out: list[str] = []
    for raw in list(settings.get("recipient_emails") or []) + [settings.get("recipient_email")]:
        email = _clean(raw).lower()
        if email and email not in out:
            out.append(email)
    return out


def cc_recipients(
    configured: Iterable[Any],
    *,
    partner_email: Any = "",
    primary: Iterable[Any] = (),
) -> list[str]:
    """Scala administracyjne DW z partnerem, bez duplikatów adresatów Do."""
    blocked = {_clean(value).lower() for value in primary if _clean(value)}
    out: list[str] = []
    for raw in [*(configured or ()), partner_email]:
        email = _clean(raw).lower()
        if email and email not in blocked and email not in out:
            out.append(email)
    return out
