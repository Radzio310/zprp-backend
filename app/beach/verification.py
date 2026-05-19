from __future__ import annotations

from datetime import datetime, timezone
import traceback
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, update

import asyncio
from app.db import database, beach_users, beach_verification_requests, beach_teams
from app.beach.notifications import notify_admins, create_notification
from app.schemas import (
    BeachVerificationCreateRequest,
    BeachVerificationItem,
    BeachVerificationPatchRequest,
    BeachVerificationsListResponse,
)
from app.deps import beach_get_current_user_id
from app.beach.activity_log import log_activity, get_actor_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/verifications", tags=["Beach: Verifications"])

ALLOWED_ROLES = {"judge", "coach", "player"}
ALLOWED_STATUSES = {"pending", "approved", "rejected"}

# Aktualny sezon (synchronizowany z CURRENT_SEASON_ID w aplikacji mobilnej)
_CURRENT_SEASON_ID = "8"


async def _expand_roles_to_all_teams(
    role_type: str,
    person_id: Optional[int],
    player_id: Optional[int],
    already_approved_team_id: Optional[int],
    new_roles: list,
) -> list:
    """Po zatwierdzeniu roli dla jednej drużyny szuka tej osoby we wszystkich drużynach
    aktualnego sezonu i automatycznie przyznaje dostęp do każdej z nich."""
    try:
        if role_type == "coach" and person_id:
            all_teams = await database.fetch_all(
                select(beach_teams.c.id, beach_teams.c.companions_json)
                .where(beach_teams.c.season_id == _CURRENT_SEASON_ID)
            )
            for team_row in all_teams:
                tid = int(team_row["id"])
                if tid == already_approved_team_id:
                    continue
                companions = team_row["companions_json"]
                if not isinstance(companions, list):
                    continue
                if not any(
                    isinstance(c, dict) and c.get("person_id") == person_id
                    for c in companions
                ):
                    continue
                # Nie dodawaj jeśli już ma tę rolę dla tej drużyny
                if any(
                    isinstance(r, dict)
                    and r.get("type") == "coach"
                    and r.get("team_id") == tid
                    for r in new_roles
                ):
                    continue
                new_roles.append({"type": "coach", "verified": "approved", "person_id": person_id, "team_id": tid})

        elif role_type == "player" and player_id:
            all_teams = await database.fetch_all(
                select(beach_teams.c.id, beach_teams.c.roster_json)
                .where(beach_teams.c.season_id == _CURRENT_SEASON_ID)
            )
            for team_row in all_teams:
                tid = int(team_row["id"])
                if tid == already_approved_team_id:
                    continue
                roster = team_row["roster_json"]
                if not isinstance(roster, list):
                    continue
                if not any(
                    isinstance(p, dict) and p.get("player_id") == player_id
                    for p in roster
                ):
                    continue
                if any(
                    isinstance(r, dict)
                    and r.get("type") == "player"
                    and r.get("team_id") == tid
                    for r in new_roles
                ):
                    continue
                new_roles.append({"type": "player", "verified": "approved", "player_id": player_id, "team_id": tid})

    except Exception:
        logger.exception("_expand_roles_to_all_teams failed — kontynuuję bez auto-expand")

    return new_roles


# ──────────────────────────────────────────────────
# Shared utilities (called from teams.py and main.py)
# ──────────────────────────────────────────────────

async def expand_roles_for_squad_sync(
    team_id: int,
    roster: list,
    companions: list,
) -> int:
    """Po zsynchronizowaniu składu drużyny team_id sprawdza, czy któryś
    z zarejestrowanych użytkowników (z zatwierdzoną rolą) figuruje w tym
    składzie i jeśli tak — dodaje mu brakującą rolę dla tej drużyny.
    Zwraca liczbę zaktualizowanych użytkowników."""
    updated = 0
    try:
        player_ids = [
            int(p["player_id"]) for p in roster
            if isinstance(p, dict) and p.get("player_id")
        ]
        person_ids = [
            int(c["person_id"]) for c in companions
            if isinstance(c, dict) and c.get("person_id")
        ]
        if not player_ids and not person_ids:
            return 0

        entries: list = []
        if player_ids:
            rows = await database.fetch_all(
                select(beach_users).where(beach_users.c.player_id.in_(player_ids))
            )
            entries.extend({"row": dict(r), "role": "player"} for r in rows)
        if person_ids:
            rows = await database.fetch_all(
                select(beach_users).where(beach_users.c.person_id.in_(person_ids))
            )
            entries.extend({"row": dict(r), "role": "coach"} for r in rows)

        for entry in entries:
            user_dict = entry["row"]
            role_type = entry["role"]
            current_roles: list = _parse_jsonish(user_dict.get("roles"), [])

            # Tylko zweryfikowani (mają już zatwierdzoną rolę danego typu)
            if not any(
                isinstance(r, dict) and r.get("type") == role_type and r.get("verified") == "approved"
                for r in current_roles
            ):
                continue

            # Pomiń jeśli już ma tę drużynę
            if any(
                isinstance(r, dict) and r.get("type") == role_type and r.get("team_id") == team_id
                for r in current_roles
            ):
                continue

            new_role: Dict[str, Any] = {
                "type": role_type, "verified": "approved", "team_id": team_id,
            }
            if role_type == "player":
                new_role["player_id"] = user_dict.get("player_id")
            elif role_type == "coach":
                new_role["person_id"] = user_dict.get("person_id")

            current_roles.append(new_role)
            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == user_dict["id"])
                .values(roles=current_roles)
            )
            updated += 1

    except Exception:
        logger.exception("expand_roles_for_squad_sync(team_id=%s) failed", team_id)

    return updated


async def run_roles_multiTeam_migration() -> int:
    """Jednorazowa migracja: dla każdego zatwierdzonego wniosku coach/player
    rozszerza role użytkownika na wszystkie drużyny bieżącego sezonu,
    w których ta osoba figuruje w składzie.
    Zwraca liczbę zaktualizowanych użytkowników."""
    approved_rows = await database.fetch_all(
        select(beach_verification_requests).where(
            beach_verification_requests.c.status == "approved",
        )
    )
    approved_rows = [
        dict(r) for r in approved_rows
        if dict(r).get("role") in ("coach", "player")
    ]
    if not approved_rows:
        return 0

    all_teams = await database.fetch_all(
        select(
            beach_teams.c.id,
            beach_teams.c.roster_json,
            beach_teams.c.companions_json,
        ).where(beach_teams.c.season_id == _CURRENT_SEASON_ID)
    )
    all_teams = [dict(t) for t in all_teams]

    # Indeksy: person_id → [team_id], player_id → [team_id]
    person_to_teams: Dict[int, List[int]] = {}
    player_to_teams: Dict[int, List[int]] = {}
    for team in all_teams:
        tid = int(team["id"])
        for c in (_parse_jsonish(team.get("companions_json"), []) or []):
            if isinstance(c, dict) and c.get("person_id"):
                pid = int(c["person_id"])
                person_to_teams.setdefault(pid, [])
                if tid not in person_to_teams[pid]:
                    person_to_teams[pid].append(tid)
        for p in (_parse_jsonish(team.get("roster_json"), []) or []):
            if isinstance(p, dict) and p.get("player_id"):
                plid = int(p["player_id"])
                player_to_teams.setdefault(plid, [])
                if tid not in player_to_teams[plid]:
                    player_to_teams[plid].append(tid)

    # Grupuj wnioski per user_id
    user_to_vers: Dict[int, List[dict]] = {}
    for row in approved_rows:
        uid = int(row["user_id"])
        user_to_vers.setdefault(uid, [])
        user_to_vers[uid].append(row)

    total_updated = 0
    for user_id, verifications in user_to_vers.items():
        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == user_id)
        )
        if not user_row:
            continue
        user_dict = dict(user_row)
        new_roles: list = _parse_jsonish(user_dict.get("roles"), [])
        added_any = False

        for ver in verifications:
            role_type: str = ver["role"]
            meta: dict = _parse_jsonish(ver.get("meta"), {})

            if role_type == "coach":
                pid = meta.get("person_id")
                if not pid:
                    continue
                for tid in person_to_teams.get(int(pid), []):
                    if any(isinstance(r, dict) and r.get("type") == "coach" and r.get("team_id") == tid for r in new_roles):
                        continue
                    new_roles.append({"type": "coach", "verified": "approved", "person_id": int(pid), "team_id": tid})
                    added_any = True

            elif role_type == "player":
                plid = meta.get("player_id")
                if not plid:
                    continue
                for tid in player_to_teams.get(int(plid), []):
                    if any(isinstance(r, dict) and r.get("type") == "player" and r.get("team_id") == tid for r in new_roles):
                        continue
                    new_roles.append({"type": "player", "verified": "approved", "player_id": int(plid), "team_id": tid})
                    added_any = True

        if added_any:
            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == user_id)
                .values(roles=new_roles)
            )
            total_updated += 1

    return total_updated


# Role type → badge name mapping
ROLE_BADGE_MAP = {
    "judge": "Sędzia",
    "coach": "Trener",
    "player": "Zawodnik",
}


def _to_item(row: dict) -> BeachVerificationItem:
    return BeachVerificationItem(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        role=row["role"],
        status=row["status"],
        meta=row.get("meta") or {},
        admin_note=row.get("admin_note"),
        reviewed_by_user_id=row.get("reviewed_by_user_id"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _parse_jsonish(raw: Any, fallback: Any):
    if raw is None:
        return fallback
    if isinstance(raw, (dict, list)):
        return raw
    try:
        import json
        return json.loads(raw)
    except Exception:
        return fallback


# ──────────────────────────────────────────────────
# GET /beach/verifications/pending_count  (admin)
# ──────────────────────────────────────────────────

@router.get(
    "/pending_count",
    response_model=dict,
    summary="Liczba oczekujących wniosków weryfikacyjnych (BEACH)",
)
async def get_pending_count():
    rows = await database.fetch_all(
        select(beach_verification_requests).where(
            beach_verification_requests.c.status == "pending"
        )
    )
    return {"pending_count": len(rows)}


# ──────────────────────────────────────────────────
# GET /beach/verifications/  (admin)
# ──────────────────────────────────────────────────

@router.get(
    "/",
    response_model=BeachVerificationsListResponse,
    summary="Lista wniosków weryfikacyjnych (BEACH) — wymaga admina",
)
async def list_verifications(status: Optional[str] = None):
    q = select(beach_verification_requests).order_by(
        beach_verification_requests.c.created_at.desc()
    )
    rows = await database.fetch_all(q)
    items = [_to_item(dict(r)) for r in rows]

    if status:
        items = [i for i in items if i.status == status]

    pending_count = sum(1 for i in items if i.status == "pending")

    return BeachVerificationsListResponse(
        requests=items,
        total=len(items),
        pending_count=pending_count,
    )


# ──────────────────────────────────────────────────
# POST /beach/verifications/  (auth user)
# ──────────────────────────────────────────────────

@router.post(
    "/",
    response_model=BeachVerificationItem,
    summary="Złóż wniosek o weryfikację roli (BEACH)",
)
async def create_verification(
    req: BeachVerificationCreateRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    if req.role not in ALLOWED_ROLES:
        raise HTTPException(400, f"Nieznana rola: {req.role}. Dozwolone: {ALLOWED_ROLES}")

    # Sprawdź czy nie ma już pending wniosku dla tej roli
    existing = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.user_id == user_id,
            beach_verification_requests.c.role == req.role,
            beach_verification_requests.c.status == "pending",
        )
    )
    if existing:
        raise HTTPException(
            409,
            {
                "code": "VERIFICATION_PENDING",
                "message": f"Masz już złożony wniosek o rolę '{req.role}' oczekujący na rozpatrzenie.",
            },
        )

    now = datetime.now(timezone.utc)
    stmt = beach_verification_requests.insert().values(
        user_id=user_id,
        role=req.role,
        status="pending",
        meta=req.meta or {},
        admin_note=None,
        reviewed_by_user_id=None,
        created_at=now,
        updated_at=now,
    )

    try:
        new_id = await database.execute(stmt)
    except Exception as e:
        logger.error("create_verification failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"Błąd tworzenia wniosku: {e}")

    row = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id == int(new_id)
        )
    )
    item = _to_item(dict(row))

    # Fetch submitter name for notification
    user_row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == user_id)
    )
    user_name = user_row["full_name"] if user_row else f"Użytkownik #{user_id}"
    role_label = {"judge": "sędzia", "coach": "trener", "player": "zawodnik"}.get(req.role, req.role)

    asyncio.ensure_future(notify_admins(
        notif_type="admin_new_verification",
        title="🔍 Nowy wniosek weryfikacyjny",
        body=f"👤 {user_name}\nRola: {role_label} — oczekuje na zatwierdzenie.",
        data={"verification_id": int(new_id), "user_id": user_id, "role": req.role},
    ))

    # ── Activity log ──
    await log_activity(
        area="verification",
        action="verification.requested",
        actor_user_id=user_id,
        actor_name=user_name,
        target_id=str(new_id),
        details={"role": req.role},
    )

    return item


# ──────────────────────────────────────────────────
# PATCH /beach/verifications/{request_id}  (admin)
# ──────────────────────────────────────────────────

@router.patch(
    "/{request_id}",
    response_model=BeachVerificationItem,
    summary="Rozpatrz wniosek weryfikacyjny (BEACH) — wymaga admina",
)
async def patch_verification(
    request_id: int,
    req: BeachVerificationPatchRequest,
    admin_user_id: int = Depends(beach_get_current_user_id),
):
    if req.status not in ("approved", "rejected"):
        raise HTTPException(400, "status musi być 'approved' lub 'rejected'")

    ver_row = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id == request_id
        )
    )
    if not ver_row:
        raise HTTPException(404, "Wniosek nie znaleziony")

    ver = dict(ver_row)
    now = datetime.now(timezone.utc)

    # Aktualizuj wniosek
    await database.execute(
        update(beach_verification_requests)
        .where(beach_verification_requests.c.id == request_id)
        .values(
            status=req.status,
            admin_note=req.admin_note,
            reviewed_by_user_id=admin_user_id,
            updated_at=now,
        )
    )

    # Jeśli APPROVED → aktualizuj beach_users
    if req.status == "approved":
        user_id = int(ver["user_id"])
        role_type = ver["role"]
        meta = _parse_jsonish(ver.get("meta"), {})

        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")

        user_dict = dict(user_row)
        current_roles: list = _parse_jsonish(user_dict.get("roles"), [])

        # Wyciągnij team_id z meta PRZED filtrowaniem (trener/zawodnik mogą mieć wiele drużyn)
        _approval_team_id = meta.get("team_id") if isinstance(meta, dict) else None

        # Usuń stary wpis TYLKO dla tej samej roli i tej samej drużyny (lub wszystkich jeśli brak team_id, np. sędzia)
        if _approval_team_id is not None:
            new_roles = [r for r in current_roles if not (
                isinstance(r, dict) and
                r.get("type") == role_type and
                r.get("team_id") == _approval_team_id
            )]
        else:
            new_roles = [r for r in current_roles if not (isinstance(r, dict) and r.get("type") == role_type)]

        # Buduj nowy wpis roli
        new_role_entry: Dict[str, Any] = {"type": role_type, "verified": "approved"}

        if role_type == "judge":
            judge_id = req.judge_id or (meta.get("judge_id") if isinstance(meta, dict) else None)
            new_role_entry["judge_id"] = judge_id
        elif role_type == "coach":
            person_id = req.person_id or (meta.get("person_id") if isinstance(meta, dict) else None)
            team_id = meta.get("team_id") if isinstance(meta, dict) else None
            new_role_entry["person_id"] = person_id
            new_role_entry["team_id"] = team_id
        elif role_type == "player":
            player_id = req.player_id or (meta.get("player_id") if isinstance(meta, dict) else None)
            team_id = meta.get("team_id") if isinstance(meta, dict) else None
            new_role_entry["player_id"] = player_id
            new_role_entry["team_id"] = team_id

        new_roles.append(new_role_entry)

        # Auto-rozszerz dostęp do wszystkich drużyn aktualnego sezonu gdzie ta osoba figuruje
        if role_type in ("coach", "player") and _approval_team_id is not None:
            new_roles = await _expand_roles_to_all_teams(
                role_type=role_type,
                person_id=new_role_entry.get("person_id"),
                player_id=new_role_entry.get("player_id"),
                already_approved_team_id=_approval_team_id,
                new_roles=new_roles,
            )

        # Buduj patch dla beach_users
        user_update: Dict[str, Any] = {
            "roles": new_roles,
            "updated_at": now,
        }

        if role_type == "judge" and new_role_entry.get("judge_id"):
            user_update["judge_id"] = str(new_role_entry["judge_id"])
        elif role_type == "coach" and new_role_entry.get("person_id"):
            user_update["person_id"] = int(new_role_entry["person_id"])
        elif role_type == "player" and new_role_entry.get("player_id"):
            user_update["player_id"] = int(new_role_entry["player_id"])

        # Przyznaj badge jeśli istnieje
        badge_name = ROLE_BADGE_MAP.get(role_type)
        if badge_name:
            from app.db import beach_badges
            badge_row = await database.fetch_one(
                select(beach_badges).where(beach_badges.c.name == badge_name)
            )
            if badge_row:
                current_badges = _parse_jsonish(user_dict.get("badges"), {})
                if isinstance(current_badges, dict):
                    current_badges[badge_name] = True
                elif isinstance(current_badges, list):
                    if badge_name not in current_badges:
                        current_badges.append(badge_name)
                user_update["badges"] = current_badges

        await database.execute(
            update(beach_users)
            .where(beach_users.c.id == user_id)
            .values(**user_update)
        )

    elif req.status == "rejected":
        # Ustaw status roli na "rejected" w beach_users.roles
        user_id = int(ver["user_id"])
        role_type = ver["role"]

        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == user_id)
        )
        if user_row:
            user_dict = dict(user_row)
            current_roles: list = _parse_jsonish(user_dict.get("roles"), [])

            # Wyciągnij team_id z odrzucanego wniosku (żeby nie dotknąć innych drużyn tego samego trenera/zawodnika)
            _reject_meta = _parse_jsonish(ver.get("meta"), {})
            _reject_team_id = _reject_meta.get("team_id") if isinstance(_reject_meta, dict) else None

            # Aktualizuj lub dodaj wpis z verified=rejected (dopasuj team_id jeśli dostępny)
            updated = False
            for r in current_roles:
                if isinstance(r, dict) and r.get("type") == role_type:
                    if _reject_team_id is None or r.get("team_id") == _reject_team_id:
                        r["verified"] = "rejected"
                        updated = True
                        break
            if not updated:
                current_roles.append({"type": role_type, "verified": "rejected"})

            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == user_id)
                .values(roles=current_roles, updated_at=now)
            )

    updated_row = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id == request_id
        )
    )

    # Notify the applicant about the decision
    applicant_id = int(ver["user_id"])
    role_label = {"judge": "sędzia", "coach": "trener", "player": "zawodnik"}.get(ver["role"], ver["role"])

    # Fetch user name for admin notification
    name_row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == applicant_id)
    )
    user_name = name_row["full_name"] if name_row else f"Użytkownik #{applicant_id}"

    if req.status == "approved":
        asyncio.ensure_future(create_notification(
            notif_type="verification_approved",
            title="✅ Weryfikacja zatwierdzona",
            body=f"Twój wniosek o rolę {role_label} został zatwierdzony. Witaj w drużynie!",
            data={"role": ver["role"], "verification_id": request_id},
            target_user_ids=[applicant_id],
        ))
        # Notify all admins about successful verification
        asyncio.ensure_future(notify_admins(
            notif_type="admin_verification_approved",
            title="✅ Weryfikacja zakończona",
            body=f"👤 {user_name}\nRola: {role_label} — zweryfikowano pomyślnie.",
            data={"verification_id": request_id, "user_id": applicant_id, "role": ver["role"]},
            exclude_user_id=admin_user_id,
        ))
    else:
        note_part = f"\nUwaga admina: {req.admin_note}" if req.admin_note else ""
        asyncio.ensure_future(create_notification(
            notif_type="verification_rejected",
            title="❌ Weryfikacja odrzucona",
            body=f"Twój wniosek o rolę {role_label} nie został zatwierdzony.{note_part}",
            data={"role": ver["role"], "verification_id": request_id, "admin_note": req.admin_note or ""},
            target_user_ids=[applicant_id],
        ))

    # ── Activity log ──
    await log_activity(
        area="verification",
        action=f"verification.{req.status}",
        actor_user_id=admin_user_id,
        actor_name=await get_actor_name(admin_user_id),
        target_id=str(request_id),
        target_label=user_name,
        details={"role": ver["role"], "admin_note": req.admin_note},
    )

    return _to_item(dict(updated_row))


# ──────────────────────────────────────────────────
# DELETE /beach/verifications/{request_id}  (admin)
# ──────────────────────────────────────────────────

@router.delete(
    "/{request_id}",
    response_model=dict,
    summary="Usuń wniosek weryfikacyjny (BEACH) — wymaga admina",
)
async def delete_verification(request_id: int):
    from sqlalchemy import delete
    await database.execute(
        delete(beach_verification_requests).where(
            beach_verification_requests.c.id == request_id
        )
    )

    # ── Activity log ──
    await log_activity(
        area="verification",
        action="verification.deleted",
        target_id=str(request_id),
    )

    return {"success": True}
