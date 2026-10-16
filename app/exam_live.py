# app/exam_live.py
"""
Egzamin na żywo - wiązanie produkcyjne (etap 5, 16.10.2026).

Cała logika jest w `exam_live_rules.py` (reguły), `exam_live_service.py` (baza),
`exam_live_hub.py` (gniazda w pamięci jednego procesu) i `exam_live_routes.py` (trasy, WebSocket,
strony rzutnika i gościa). Tu tylko doklejamy żywą bazę, uprawnienia z etapu 1 i JWT aplikacji.
Kontrakt: BAZA/docs/egzamin-api.md, sekcja „Na żywo”.
"""
from __future__ import annotations

from typing import Optional

from app import exam_live_service as V
from app.exam_live_routes import LiveDeps, build_router
from app.exams import _store, _who


def _live_store() -> V.LiveStore:
    from app import db as D

    return V.LiveStore(
        exam=_store(),
        t=V.LiveTables(sessions=D.exam_live_sessions, participants=D.exam_live_participants, answers=D.exam_live_answers),
    )


async def _identify(token: str) -> Optional[str]:
    """Numer sędziego z JWT aplikacji (gniazdo nie ma nagłówka Authorization, token idzie w zapytaniu)."""
    from jose import JWTError, jwt

    from app.deps import get_settings

    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None
    judge = str(payload.get("judge_id") or "").strip()
    return judge or None


router = build_router(LiveDeps(store=_live_store, who=_who, identify=_identify))
