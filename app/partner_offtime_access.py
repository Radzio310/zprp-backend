"""Kto może zapisać który wpis w ``partner_offtimes``.

Bez bazy i bez sieci. Dotąd zapis przyjmował każdy, kto znał adres - a od
kiedy zapis wysyła partnerowi push, obcy mógłby wysyłać powiadomienia
w cudzym imieniu. Numer sędziego bierzemy z tokenu, nie z adresu.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional


def caller_judge_id(jwt_payload: Mapping[str, Any]) -> str:
    return str(jwt_payload.get("judge_id") or "").strip()


def write_allowed(
    caller_id: str,
    target_id: str,
    update_data: Optional[Mapping[str, Any]] = None,
    row_partner_id: Optional[str] = None,
) -> bool:
    """Własny wpis - zawsze. Cudzy - tylko rozparowanie ze mną.

    Rozparowanie czyści ``partner_id`` po OBU stronach
    (``unlinkPartnerCompletely`` w ustawieniach aplikacji), więc sędzia musi
    móc wyzerować pole u partnera - ale tylko wtedy, gdy to pole wskazuje na
    niego i tylko to jedno pole.
    """
    caller = str(caller_id or "").strip()
    if not caller:
        return False
    if caller == str(target_id or "").strip():
        return True
    return (
        update_data is not None
        and dict(update_data) == {"partner_id": None}
        and str(row_partner_id or "").strip() == caller
    )
