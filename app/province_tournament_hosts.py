"""
Gospodarz TURNIEJU wskazany w panelu klubów - baza i trasa.

Decyzja użytkownika z 06.10.2026: turniej dzieci i młodzików regionalnych
(dzień w jednej hali) ma JEDNEGO płatnika - gospodarza turnieju. Reguła
w liściu `club_charges` rozpoznaje go sama (drużyna z miasta hali albo jeden
klub we wszystkich meczach); tutaj zapisujemy wskazanie człowieka, które
z automatem wygrywa. Puste wskazanie = powrót do automatu.

Klucz turnieju liczy `club_charges.tournament_key` i przychodzi z panelu
dokładnie taki, jaki panel dostał w wierszu obciążenia.

⚠ Router dołączamy PRZED routerem `/province/clubs` (tak jak budżety) - tam
trasy z `{club_id}` połknęłyby `/tournaments`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import club_charges as C
from app.district_payer import DISTRICT_PAYER_ID
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate
from app.settlement_province import canonical

router = APIRouter(
    prefix="/province/clubs/tournaments",
    tags=["province_clubs"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Zapis w panelu klubów"))],
)


def _s(value: Any) -> str:
    return str(value or "").strip()


async def tournament_host_overrides(province: str) -> dict[str, C.MatchOverride]:
    """Wskazani gospodarze turniejów okręgu: klucz turnieju -> drużyna."""
    from app.db import database, province_tournament_hosts

    key = canonical(province) or _s(province)
    rows = await database.fetch_all(
        select(province_tournament_hosts).where(province_tournament_hosts.c.province == key)
    )
    return {
        _s(row["tournament_key"]): C.MatchOverride(
            team_id=_s(row["team_id"]), team_name=_s(row["team_name"])
        )
        for row in rows
    }


class TournamentHostRequest(BaseModel):
    province: str
    tournament_key: str
    #: Drużyna gospodarza (numer ze słownika sezonu) albo `OKREG`. Pusto =
    #: wróć do rozpoznania automatycznego.
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    updated_by: Optional[str] = None


@router.put("/host", summary="Wskaż gospodarza turnieju (cały dzień w hali)")
async def set_tournament_host(payload: TournamentHostRequest):
    from app.db import database, province_tournament_hosts

    key = canonical(payload.province)
    if not key:
        raise HTTPException(400, f"Nieznane województwo: {payload.province}")
    tournament = _s(payload.tournament_key)
    if not tournament.startswith("t:"):
        raise HTTPException(
            400,
            "To nie jest klucz turnieju - odśwież panel klubów i wskaż gospodarza jeszcze raz.",
        )
    team_id = _s(payload.team_id)
    team_name = _s(payload.team_name)
    where = and_(
        province_tournament_hosts.c.province == key,
        province_tournament_hosts.c.tournament_key == tournament,
    )
    if not team_id and not team_name:
        await database.execute(delete(province_tournament_hosts).where(where))
        return {"ok": True, "tournament_key": tournament, "team_id": None, "automatic": True}

    values = {
        "province": key,
        "tournament_key": tournament,
        "team_id": team_id or None,
        "team_name": team_name or (DISTRICT_PAYER_ID if team_id == DISTRICT_PAYER_ID else None),
        "updated_by": _s(payload.updated_by) or None,
        "updated_at": datetime.now(timezone.utc),
    }
    statement = pg_insert(province_tournament_hosts).values(**values)
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[
                province_tournament_hosts.c.province,
                province_tournament_hosts.c.tournament_key,
            ],
            set_={k: v for k, v in values.items() if k not in ("province", "tournament_key")},
        )
    )
    return {"ok": True, "tournament_key": tournament, "team_id": team_id or None, "automatic": False}
