# app/exam_live.py
"""
Egzamin na żywo - wiązanie produkcyjne (etap 5, 16.10.2026).

Cała logika jest w `exam_live_rules.py` (reguły), `exam_live_service.py` (baza),
`exam_live_hub.py` (gniazda w pamięci jednego procesu) i `exam_live_routes.py` (trasy, WebSocket,
strony rzutnika i gościa). Tu tylko doklejamy żywą bazę, uprawnienia z etapu 1 i JWT aplikacji.
Kontrakt: BAZA/docs/egzamin-api.md, sekcja „Na żywo”.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from app import exam_live_service as V
from app.exam_live_routes import LiveDeps, build_router
from app.exam_rules import ExamError
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


WEB_TOKEN_HOURS = 12


async def _web_login(username: str, password: str) -> Dict[str, Any]:
    """Logowanie kontem BAZY ze strony uczestnika: ten sam login ZPRP co w aplikacji (`app.auth.login`).

    Strona dostaje WŁASNY, okrojony token (12 h): numer sędziego i nazwa, bez ciasteczek sesji ZPRP,
    które niesie token aplikacji - przeglądarka trzyma go w localStorage, więc nie może otwierać panelu ZPRP.
    Dołączenie tym tokenem to zwykłe `POST /exam-live/join`, więc wynik trafia do historii jak z aplikacji."""
    import datetime as dt

    import jwt as pyjwt
    from fastapi import HTTPException

    from app.auth import LoginRequest, login
    from app.deps import WEB_SCOPE, get_settings

    settings = get_settings()
    try:
        res = await login(LoginRequest(username=username, password=password), settings)
    except HTTPException as error:
        if error.status_code == 401:
            raise ExamError("LIVE_LOGIN_FAILED", "Login albo hasło się nie zgadza. To te same dane, co w aplikacji BAZA.", 401)
        raise ExamError("LIVE_LOGIN_DOWN", "Logowanie chwilowo nie działa. Spróbuj za moment.", 502)
    except Exception:  # noqa: BLE001 - serwer ZPRP nie odpowiada, zerwane połączenie
        raise ExamError("LIVE_LOGIN_DOWN", "Serwer ZPRP nie odpowiada. Spróbuj za moment.", 502)
    data = res if isinstance(res, dict) else res.model_dump()
    judge = str(data.get("judge_id") or "").strip()
    if not judge:
        raise ExamError("LIVE_LOGIN_NOT_JUDGE", "To konto nie ma numeru sędziego. Zaloguj się kontem sędziowskim "
                        "albo dołącz jako gość, jeśli prowadzący na to pozwala.", 403)
    name = str(data.get("display_name") or "").split("|")[0].strip()
    now = dt.datetime.now(dt.timezone.utc)
    payload = {"sub": username, "judge_id": judge, "account_type": "judge", "display_name": name, "scope": WEB_SCOPE,
               "iat": int(now.timestamp()), "exp": int((now + dt.timedelta(hours=WEB_TOKEN_HOURS)).timestamp())}
    token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": WEB_TOKEN_HOURS * 3600, "judge_id": judge, "name": name}


router = build_router(LiveDeps(store=_live_store, who=_who, identify=_identify, login=_web_login))
