"""
migrate_roles_multiTeam.py
==========================
Jednorazowy skrypt migracyjny naprawiający role użytkowników, którym
poprzednia logika zatwierdzania usunęła wcześniejsze wpisy (bug: przy
zatwierdzeniu drugiej weryfikacji coach/player usuwano pierwszą rolę).

Co robi:
  1. Wczytuje wszystkie ZATWIERDZONE wnioski weryfikacyjne (coach / player).
  2. Dla każdego wnioskodawcy sprawdza, które drużyny bieżącego sezonu
     zawierają tę osobę (wg person_id w companions_json lub player_id w
     roster_json).
  3. Porównuje z aktualnymi rolami użytkownika i DOKŁADA brakujące wpisy
     (nie dotyka istniejących).
  4. Wypisuje co dodano / co pominięto.

Uruchomienie:
  cd zprp-backend
  python migrate_roles_multiTeam.py [--dry-run]

Opcja --dry-run: wyświetla planowane zmiany bez zapisu do bazy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Optional

from sqlalchemy import select, update

# ── importy z aplikacji ─────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from app.db import database, beach_users, beach_verification_requests, beach_teams

CURRENT_SEASON_ID = "8"  # 2025/2026 – zsynchronizowany z aplikacją mobilną


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse(raw: Any, default: Any) -> Any:
    if raw is None:
        return default
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            pass
    return default


def _roles_list(raw: Any) -> list:
    return _parse(raw, [])


def _has_role(roles: list, role_type: str, team_id: int) -> bool:
    return any(
        isinstance(r, dict)
        and r.get("type") == role_type
        and r.get("team_id") == team_id
        for r in roles
    )


# ── core migration ────────────────────────────────────────────────────────────

async def run(dry_run: bool) -> None:
    await database.connect()
    print(f"\n{'[DRY RUN] ' if dry_run else ''}Migracja ról multi-team – sezon {CURRENT_SEASON_ID}\n")

    # 1. Pobierz wszystkie zatwierdzone wnioski coach/player
    approved_rows = await database.fetch_all(
        select(beach_verification_requests).where(
            beach_verification_requests.c.status == "approved",
        )
    )
    approved_rows = [
        dict(r) for r in approved_rows
        if dict(r).get("role") in ("coach", "player")
    ]
    print(f"Zatwierdzone wnioski coach/player: {len(approved_rows)}")

    # 2. Pobierz składy wszystkich drużyn bieżącego sezonu (jednorazowo)
    all_teams = await database.fetch_all(
        select(
            beach_teams.c.id,
            beach_teams.c.team_name,
            beach_teams.c.roster_json,
            beach_teams.c.companions_json,
        ).where(beach_teams.c.season_id == CURRENT_SEASON_ID)
    )
    all_teams = [dict(t) for t in all_teams]
    print(f"Drużyny w sezonie {CURRENT_SEASON_ID}: {len(all_teams)}\n")

    # Zbuduj indeksy person_id→[team_id] i player_id→[team_id]
    person_to_teams: dict[int, list[int]] = {}
    player_to_teams: dict[int, list[int]] = {}

    for team in all_teams:
        tid = int(team["id"])

        companions = _parse(team["companions_json"], [])
        for c in companions:
            if isinstance(c, dict) and c.get("person_id"):
                pid = int(c["person_id"])
                person_to_teams.setdefault(pid, [])
                if tid not in person_to_teams[pid]:
                    person_to_teams[pid].append(tid)

        roster = _parse(team["roster_json"], [])
        for p in roster:
            if isinstance(p, dict) and p.get("player_id"):
                plid = int(p["player_id"])
                player_to_teams.setdefault(plid, [])
                if tid not in player_to_teams[plid]:
                    player_to_teams[plid].append(tid)

    # 3. Grupuj wnioski per user_id
    user_to_verifications: dict[int, list[dict]] = {}
    for row in approved_rows:
        uid = int(row["user_id"])
        user_to_verifications.setdefault(uid, [])
        user_to_verifications[uid].append(row)

    total_users_changed = 0
    total_roles_added = 0

    for user_id, verifications in user_to_verifications.items():
        # Pobierz aktualne role użytkownika
        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == user_id)
        )
        if not user_row:
            print(f"  ⚠  user_id={user_id} nie istnieje – pomijam")
            continue

        user_dict = dict(user_row)
        current_roles: list = _roles_list(user_dict.get("roles"))
        new_roles = list(current_roles)  # kopia do modyfikacji
        additions: list[str] = []

        team_name_map = {t["id"]: t["team_name"] for t in all_teams}

        for ver in verifications:
            role_type: str = ver["role"]
            meta: dict = _parse(ver.get("meta"), {})

            if role_type == "coach":
                person_id: Optional[int] = meta.get("person_id")
                if not person_id:
                    continue
                teams_for_person = person_to_teams.get(int(person_id), [])
                for tid in teams_for_person:
                    if _has_role(new_roles, "coach", tid):
                        continue
                    new_roles.append({
                        "type": "coach",
                        "verified": "approved",
                        "person_id": int(person_id),
                        "team_id": tid,
                    })
                    additions.append(f"coach @ {tid} ({team_name_map.get(tid, '?')})")

            elif role_type == "player":
                player_id: Optional[int] = meta.get("player_id")
                if not player_id:
                    continue
                teams_for_player = player_to_teams.get(int(player_id), [])
                for tid in teams_for_player:
                    if _has_role(new_roles, "player", tid):
                        continue
                    new_roles.append({
                        "type": "player",
                        "verified": "approved",
                        "player_id": int(player_id),
                        "team_id": tid,
                    })
                    additions.append(f"player @ {tid} ({team_name_map.get(tid, '?')})")

        if not additions:
            continue

        total_users_changed += 1
        total_roles_added += len(additions)

        print(f"  user_id={user_id} ({user_dict.get('full_name', '?')})")
        for a in additions:
            print(f"    + {a}")

        if not dry_run:
            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == user_id)
                .values(roles=new_roles)
            )

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Gotowe.")
    print(f"  Użytkownicy do zaktualizowania : {total_users_changed}")
    print(f"  Ról do dodania                 : {total_roles_added}")
    if dry_run:
        print("\n  Uruchom bez --dry-run aby zapisać zmiany.")

    await database.disconnect()


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migracja ról multi-team")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Tylko pokaż planowane zmiany, nie zapisuj do bazy",
    )
    args = parser.parse_args()
    asyncio.run(run(dry_run=args.dry_run))
