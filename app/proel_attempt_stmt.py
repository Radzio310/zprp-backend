"""Zapytanie listy Rejestru prób bez `app.db` (testowalne bez bazy)."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import func, or_, select

from app.proel_attempt_tables import attempt_log


def _like(v: str) -> str:
    return "%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def build_list_stmt(
    *, kind: Optional[str] = None, outcome: Optional[str] = None, reason: Optional[str] = None,
    match: Optional[str] = None, actor: Optional[str] = None, q: Optional[str] = None,
    lo: Optional[datetime] = None, hi: Optional[datetime] = None, before_id: Optional[int] = None,
):
    T = attempt_log
    stmt = select(T).order_by(T.c.id.desc())
    if kind:
        stmt = stmt.where(T.c.kind == kind)
    if outcome:
        stmt = stmt.where(T.c.outcome == outcome)
    if reason:
        stmt = stmt.where(T.c.reason == reason)
    if match:
        stmt = stmt.where(T.c.match_number == match.strip())
    if actor and actor.strip():
        a = actor.strip().lower()
        # Numer sędziego ALBO wpisany login: dokładnie, bez rozróżniania wielkości liter.
        stmt = stmt.where(or_(func.lower(T.c.actor_judge_id) == a, func.lower(T.c.actor_login) == a))
    if q and q.strip():
        pat = _like(q.strip())
        stmt = stmt.where(or_(
            T.c.actor_name.ilike(pat, escape="\\"), T.c.actor_login.ilike(pat, escape="\\"),
            T.c.match_number.ilike(pat, escape="\\"), T.c.reason_text.ilike(pat, escape="\\"),
            T.c.holder_name.ilike(pat, escape="\\"),
        ))
    if lo:
        stmt = stmt.where(T.c.last_at >= lo)
    if hi:
        stmt = stmt.where(T.c.last_at <= hi)
    if before_id is not None:
        stmt = stmt.where(T.c.id < int(before_id))
    return stmt
