"""Kto widzi mecze ręczne (`M-<tuleja>/<numer>`) na liście `GET /proel` (02.11.2026).

Mecz ręczny bez numerycznego IdZawody nie jest publiczny (zob. `proel_match_key.public_rows_clause`), więc lista nie może go
oddawać każdemu. Widzi go: piszący protokół oraz członek meczu wspólnego, do którego należy ta tuleja. Mecz ręczny połączony
z prawdziwym IdZawody jest zwykłym meczem. `GET /proel/{pełny klucz}` jest poza tym filtrem (reguła czytania wspólnego).
"""

from __future__ import annotations

from typing import Any, Iterable, List

from sqlalchemy import and_, or_, select

from app.db import database, saved_matches, shared_match_members, shared_matches
from app.proel_match_key import SHARED_KEY_LIKE, stem_of_row

S = saved_matches
MAX_MEMBER_MATCHES = 500


def _variants(judge_id: Any) -> List[str]:
    text = str(judge_id or "").strip()
    return [v for v in dict.fromkeys((text, text.lstrip("0"))) if v]


async def member_stems(judge_id: Any) -> List[str]:
    """Tuleje meczów wspólnych, do których należy sędzia (bez usuniętych meczów)."""
    if not str(judge_id or "").strip():
        return []
    rows = await database.fetch_all(
        select(shared_matches.c.id, shared_matches.c.proel_stem)
        .join(shared_match_members, shared_match_members.c.match_id == shared_matches.c.id)
        .where(shared_match_members.c.judge_id.in_(_variants(judge_id)))
        .where(shared_matches.c.deleted_at.is_(None)).limit(MAX_MEMBER_MATCHES))
    return sorted({stem_of_row(dict(r)) for r in rows if stem_of_row(dict(r))})


async def manual_rows_clause(judge_id: Any):
    """Warunek SQL dla wierszy `M-...`: widoczne tylko z IdZawody, dla piszącego albo członka meczu wspólnego."""
    manual = S.c.match_number.ilike(SHARED_KEY_LIKE)
    linked = and_(S.c.zprp_match_id.isnot(None), S.c.zprp_match_id != "")
    visible: List[Any] = [~manual, linked]
    variants = _variants(judge_id)
    if variants:
        visible.append(S.c.doc_writer_judge.in_(variants))
    stems: Iterable[str] = await member_stems(judge_id)
    visible.extend(S.c.match_number.ilike(f"M-{stem}/%") for stem in stems)
    return or_(*visible)
