"""
migrate_email_verification.py
=============================
Migracja schematu dla weryfikacji adresów e-mail (Brevo).

Co robi (idempotentnie):
  1. Dodaje kolumny do beach_users:
       email_normalized, email_verified, email_verified_at,
       email_delivery_blocked, email_verification_deadline
     (ALTER TABLE ... ADD COLUMN IF NOT EXISTS).
  2. Tworzy tabele email_verification_codes, email_delivery_events,
     email_rate_events (przez metadata.create_all — patrz app/db.py).
  3. Backfilluje email_normalized = lower(trim(email)).
  4. Ustawia 90-dniowy termin weryfikacji dla niezweryfikowanych kont.
  5. Wykrywa konflikty (duplikaty po lower/trim) i:
       - jeśli BRAK konfliktów → tworzy partial unique index,
       - jeśli SĄ konflikty → wypisuje RAPORT (zamaskowane adresy) i NIE tworzy
         unikalnego indeksu (operator musi rozwiązać duplikaty ręcznie).

Bezpieczna dla istniejących rekordów. Nowe tabele tworzy metadata.create_all
przy imporcie app.db, więc wystarczy uruchomić ten skrypt:

  cd zprp-backend
  python migrate_email_verification.py [--dry-run]

--dry-run: pokazuje raport konfliktów i planowane akcje, bez tworzenia indeksu.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))

from app.db import database  # noqa: E402  (import po sys.path)
from app.beach.email_config import get_email_config  # noqa: E402
from app.beach.email_masking import mask_email  # noqa: E402

_ALTERS = [
    "ALTER TABLE beach_users ADD COLUMN IF NOT EXISTS email_normalized VARCHAR",
    "ALTER TABLE beach_users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE beach_users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ",
    "ALTER TABLE beach_users ADD COLUMN IF NOT EXISTS email_delivery_blocked BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE beach_users ADD COLUMN IF NOT EXISTS email_verification_deadline TIMESTAMPTZ",
    "CREATE INDEX IF NOT EXISTS ix_beach_users_email_normalized ON beach_users (email_normalized)",
]


async def run(dry_run: bool) -> None:
    await database.connect()
    print(f"\n{'[DRY RUN] ' if dry_run else ''}Migracja weryfikacji e-mail\n")

    # 1. Kolumny
    for stmt in _ALTERS:
        if dry_run:
            print(f"  (plan) {stmt}")
            continue
        try:
            await database.execute(stmt)
            print(f"  ✓ {stmt.split('IF NOT EXISTS')[0].strip()} …")
        except Exception as exc:  # noqa: BLE001
            print(f"  ⚠ ALTER pominięty: {type(exc).__name__}")

    # 2. Backfill email_normalized
    if not dry_run:
        await database.execute(
            "UPDATE beach_users SET email_normalized = lower(btrim(email)) "
            "WHERE email IS NOT NULL AND btrim(email) <> '' AND email_normalized IS NULL"
        )
        cfg = get_email_config()
        deadline = datetime.now(timezone.utc) + timedelta(days=cfg.grace_days)
        await database.execute(
            "UPDATE beach_users SET email_verification_deadline = :d "
            "WHERE email_verified = false AND email_verification_deadline IS NULL",
            {"d": deadline},
        )
        print("  ✓ backfill email_normalized + terminy weryfikacji")

    # 3. Raport konfliktów
    dupes = await database.fetch_all(
        "SELECT email_normalized, count(*) AS c FROM beach_users "
        "WHERE email_normalized IS NOT NULL GROUP BY email_normalized HAVING count(*) > 1 "
        "ORDER BY c DESC"
    )
    if dupes:
        print(f"\n  ⚠ KONFLIKTY: {len(dupes)} adresów występuje wielokrotnie (po lower/trim):")
        for d in dupes:
            print(f"      {mask_email(d['email_normalized'])}  ×{d['c']}")
        print("\n  → NIE tworzę unikalnego indeksu. Rozwiąż duplikaty i uruchom ponownie.")
    else:
        if dry_run:
            print("\n  Brak konfliktów — unikalny indeks zostałby utworzony.")
        else:
            await database.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_beach_users_email_normalized "
                "ON beach_users (email_normalized) WHERE email_normalized IS NOT NULL"
            )
            print("\n  ✓ utworzono partial unique index na email_normalized")

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Gotowe.")
    await database.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migracja weryfikacji e-mail (Brevo)")
    parser.add_argument("--dry-run", action="store_true", help="Pokaż plan/raport bez zapisu indeksu")
    args = parser.parse_args()
    asyncio.run(run(dry_run=args.dry_run))
