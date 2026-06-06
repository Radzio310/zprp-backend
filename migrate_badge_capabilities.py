"""
migrate_badge_capabilities.py
=============================
Jednorazowy skrypt migracyjny, który ustawia pole ``capabilities`` w
``config_json`` istniejących badge'y na podstawie mapy ``LEGACY_BADGE_CAPS``
z modułu ``app.beach.capabilities``.

Co robi:
  1. Wczytuje wszystkie badge'y z tabeli ``beach_badges``.
  2. Dla każdego badge'a, którego ``config_json`` NIE ma jeszcze klucza
     ``capabilities``, ustawia go na podstawie ``LEGACY_BADGE_CAPS``
     (badge nieznany w mapie dostaje pustą listę).
  3. Nie nadpisuje badge'y, które już mają ustawione ``capabilities``
     (chyba że podano ``--force``).

Uruchomienie:
  cd zprp-backend
  python migrate_badge_capabilities.py [--dry-run] [--force]

Opcje:
  --dry-run  Pokaż planowane zmiany bez zapisu do bazy.
  --force    Nadpisz capabilities także dla badge'y, które już je mają,
             wartościami z LEGACY_BADGE_CAPS.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update

# ── importy z aplikacji ─────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from app.db import database, beach_badges
from app.beach.capabilities import LEGACY_BADGE_CAPS


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


async def run(dry_run: bool, force: bool) -> None:
    await database.connect()

    rows = await database.fetch_all(
        select(beach_badges.c.id, beach_badges.c.name, beach_badges.c.config_json)
    )

    total_changed = 0

    print(f"Znaleziono {len(rows)} badge'y.\n")

    for r in rows:
        rd = dict(r)
        badge_id = int(rd["id"])
        name = str(rd["name"])
        config = _parse(rd.get("config_json"), {})
        if not isinstance(config, dict):
            config = {}

        has_caps = "capabilities" in config and isinstance(config.get("capabilities"), list)
        if has_caps and not force:
            print(f"  = {name}: capabilities już ustawione ({config['capabilities']}), pomijam")
            continue

        new_caps = list(LEGACY_BADGE_CAPS.get(name, []))
        new_config = dict(config)
        new_config["capabilities"] = new_caps

        total_changed += 1
        print(f"  + {name}: capabilities -> {new_caps}")

        if not dry_run:
            await database.execute(
                update(beach_badges)
                .where(beach_badges.c.id == badge_id)
                .values(config_json=new_config, updated_at=datetime.now(timezone.utc))
            )

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Gotowe.")
    print(f"  Badge'y zaktualizowanych: {total_changed}")
    if dry_run:
        print("\n  Uruchom bez --dry-run aby zapisać zmiany.")

    await database.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migracja capabilities badge'y")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Tylko pokaż planowane zmiany, nie zapisuj do bazy",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Nadpisz capabilities także dla badge'y, które już je mają",
    )
    args = parser.parse_args()
    asyncio.run(run(dry_run=args.dry_run, force=args.force))
