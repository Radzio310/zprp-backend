from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import beach_admins, beach_app_settings, beach_users, database
from app.deps import beach_get_current_user_id, beach_get_optional_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/score", tags=["Beach: BeachScore"])

# Klucz w beach_app_settings: per-użytkownik obserwowane drużyny/zawodnicy.
FOLLOWS_PREFIX = "beach_follows:"


def _follows_key(user_id: int) -> str:
    return f"{FOLLOWS_PREFIX}{int(user_id)}"


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _empty() -> dict[str, Any]:
    return {"teams": [], "players": [], "v": 1}


def _parse_follows(raw: Any) -> dict[str, Any]:
    if not raw:
        return _empty()
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return _empty()
    if not isinstance(parsed, dict):
        return _empty()
    teams = parsed.get("teams") if isinstance(parsed.get("teams"), list) else []
    players = parsed.get("players") if isinstance(parsed.get("players"), list) else []
    return {"teams": teams, "players": players, "v": 1}


async def _get_follows(user_id: int) -> dict[str, Any]:
    row = await database.fetch_one(
        select(beach_app_settings.c.value).where(
            beach_app_settings.c.key == _follows_key(user_id)
        )
    )
    return _parse_follows(row["value"] if row else None)


# ─────────────────── modele ───────────────────


class FollowedTeam(BaseModel):
    id: int
    team_name: str = ""
    gender: str = ""
    category: str | None = None
    club: str | None = None


class FollowedPlayer(BaseModel):
    player_id: int
    full_name: str = ""
    photo_url: str | None = None
    team_id: int = 0
    team_name: str = ""
    jersey: str | None = None
    position: str | None = None


class FollowsPayload(BaseModel):
    teams: list[FollowedTeam] = Field(default_factory=list)
    players: list[FollowedPlayer] = Field(default_factory=list)


# ─────────────────── endpoints użytkownika ───────────────────


@router.get("/follows", summary="Obserwowane drużyny/zawodnicy bieżącego użytkownika")
async def get_follows(
    current_user_id: int | None = Depends(beach_get_optional_user_id),
):
    # Tolerujemy brak/wygasły token (zwracamy pusto) — bez 401 w logach.
    if current_user_id is None:
        return _empty()
    return await _get_follows(current_user_id)


@router.put("/follows", summary="Zapisz obserwowane (zastępuje całość)")
async def save_follows(
    payload: FollowsPayload,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    data = {
        "teams": [t.model_dump() for t in payload.teams],
        "players": [p.model_dump() for p in payload.players],
        "v": 1,
    }
    value = json.dumps(data, ensure_ascii=False)
    stmt = (
        pg_insert(beach_app_settings)
        .values(key=_follows_key(current_user_id), value=value)
        .on_conflict_do_update(
            index_elements=[beach_app_settings.c.key],
            set_={"value": value},
        )
    )
    await database.execute(stmt)
    return {"saved": True, "teams": len(data["teams"]), "players": len(data["players"])}


# ─────────────────── statystyki admina ───────────────────


@router.get("/stats", summary="Statystyki obserwowanych (admin)")
async def get_stats(current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    rows = await database.fetch_all(
        select(beach_app_settings.c.key, beach_app_settings.c.value).where(
            beach_app_settings.c.key.like(f"{FOLLOWS_PREFIX}%")
        )
    )

    # user_id -> {teams, players}
    per_user: dict[int, dict[str, Any]] = {}
    team_counts: dict[int, dict[str, Any]] = {}
    player_counts: dict[int, dict[str, Any]] = {}

    for r in rows:
        key = r["key"]
        try:
            uid = int(str(key)[len(FOLLOWS_PREFIX):])
        except Exception:
            continue
        data = _parse_follows(r["value"])
        teams = data["teams"]
        players = data["players"]
        if not teams and not players:
            continue
        per_user[uid] = {"teams": len(teams), "players": len(players)}

        for t in teams:
            if not isinstance(t, dict):
                continue
            tid = t.get("id")
            if tid is None:
                continue
            entry = team_counts.setdefault(
                int(tid),
                {"id": int(tid), "name": t.get("team_name") or "", "gender": t.get("gender") or "", "count": 0},
            )
            entry["count"] += 1
            if not entry["name"] and t.get("team_name"):
                entry["name"] = t.get("team_name")

        for p in players:
            if not isinstance(p, dict):
                continue
            pid = p.get("player_id")
            if pid is None:
                continue
            entry = player_counts.setdefault(
                int(pid),
                {
                    "player_id": int(pid),
                    "name": p.get("full_name") or "",
                    "team_name": p.get("team_name") or "",
                    "photo_url": p.get("photo_url"),
                    "count": 0,
                },
            )
            entry["count"] += 1
            if not entry["name"] and p.get("full_name"):
                entry["name"] = p.get("full_name")

    # Dołącz dane użytkowników (full_name, login)
    users: list[dict[str, Any]] = []
    if per_user:
        urows = await database.fetch_all(
            select(
                beach_users.c.id, beach_users.c.full_name, beach_users.c.login
            ).where(beach_users.c.id.in_(list(per_user.keys())))
        )
        umap = {int(u["id"]): u for u in urows}
        for uid, counts in per_user.items():
            u = umap.get(uid)
            users.append(
                {
                    "user_id": uid,
                    "full_name": (u["full_name"] if u else None) or f"#{uid}",
                    "login": (u["login"] if u else None) or "",
                    "teams": counts["teams"],
                    "players": counts["players"],
                    "total": counts["teams"] + counts["players"],
                }
            )

    users.sort(key=lambda x: (-x["total"], x["full_name"]))
    top_teams = sorted(team_counts.values(), key=lambda x: -x["count"])[:20]
    top_players = sorted(player_counts.values(), key=lambda x: -x["count"])[:20]

    return {
        "followers_count": len(users),
        "top_teams": top_teams,
        "top_players": top_players,
        "users": users,
    }
