"""Udostępnianie arkuszy delegatów (Ustawienia -> Udostępniane dane).

Mały moduł bez zależności od tras, żeby panel Mentora i analizy obsad mogły
odfiltrować zablokowane pary bez importu całego `delegate_evaluations`.
Reguła w `delegate_evaluation_utils.pair_sharing_blocked`.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from sqlalchemy import select

from app.db import database, delegate_evaluation_sharing
from app.delegate_evaluation_utils import split_shared


async def opted_out_judges() -> set:
    """Numery sędziów, którzy wyłączyli udostępnianie (tabela jest mała)."""
    rows = await database.fetch_all(
        select(delegate_evaluation_sharing.c.judge_id).where(
            delegate_evaluation_sharing.c.sharing_enabled.is_(False)
        )
    )
    return {str(row["judge_id"]).strip() for row in rows}


async def drop_blocked_pairs(rows: Iterable[Any], viewer: str = "") -> List[Dict[str, Any]]:
    """Wycina arkusze, których treści serwer nie wydaje (obaj z pary wyłączyli
    albo `viewer` sam wyłączył)."""
    items = [dict(row) for row in rows]
    opted_out = await opted_out_judges()
    if not opted_out:
        return items
    return split_shared(items, opted_out, str(viewer or "").strip())[0]
