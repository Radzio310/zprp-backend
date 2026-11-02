"""Jednorazowy backfill ogłoszeń okręgowych. DOMYŚLNIE tylko podgląd.

    python scripts/announcements_backfill.py                 # podgląd, bez zapisu
    python scripts/announcements_backfill.py --apply         # zapis

Baza z `DATABASE_URL`. Skrypt NIE importuje `app.db` (ten łączy się przy
imporcie). Zapis dat ustawia `updated_at` JAWNIE, a zapis miniatur trzyma
`updated_at = updated_at`, więc `onupdate=now()` niczego nie podbija.

a) miniatury dla ogłoszeń z grafiką i bez `thumb_url` (pliki z `--static-dir`,
   domyślnie `$RAILWAY_VOLUME_MOUNT_PATH/static` albo `./static`);
b) daty zniekształcone reakcją/komentarzem -> najwcześniejszy `created_at`
   z `likes` i `comments`. Konflikty kolejności z `id` są tylko wypisane.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.announcement_rules import (  # noqa: E402
    backfilled_updated_at,
    make_thumbnail,
    order_conflicts,
)


def _static_dir() -> str:
    vol = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
    return os.path.join(vol, "static") if vol else "static"


def _json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return []
    return value or []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="zapisz (domyślnie podgląd)")
    ap.add_argument("--static-dir", default=_static_dir())
    args = ap.parse_args()

    url = os.getenv("DATABASE_URL")
    if not url:
        sys.exit("Brak DATABASE_URL.")
    from sqlalchemy import create_engine, text

    engine = create_engine(url)
    mode = "ZAPIS" if args.apply else "PODGLĄD (bez zapisu)"
    print(f"Tryb: {mode}; static: {args.static_dir}")

    with engine.begin() as conn:
        rows = [
            dict(r._mapping)
            for r in conn.execute(
                text(
                    "SELECT id, title, province, image_url, thumb_url, updated_at, "
                    "likes, comments FROM announcements ORDER BY id"
                )
            )
        ]

        # a) miniatury
        thumbs = []
        for r in rows:
            if not r["image_url"] or r["thumb_url"]:
                continue
            src = os.path.join(args.static_dir, r["image_url"].split("/")[-1])
            if not os.path.isfile(src):
                print(f"  brak pliku dla #{r['id']}: {src}")
                continue
            if args.apply:
                name = make_thumbnail(src, args.static_dir)
                if name:
                    conn.execute(
                        text(
                            "UPDATE announcements SET thumb_url = :t, "
                            "updated_at = updated_at WHERE id = :i"
                        ),
                        {"t": f"/static/{name}", "i": r["id"]},
                    )
                    thumbs.append(r["id"])
                else:
                    print(f"  miniatura nie powstała dla #{r['id']}")
            else:
                thumbs.append(r["id"])
        print(f"Miniatury: {len(thumbs)} ogłoszeń {'zapisano' if args.apply else 'do dorobienia'}.")

        # b) daty
        changes = []
        for r in rows:
            new = backfilled_updated_at(r["updated_at"], _json(r["likes"]), _json(r["comments"]))
            if new:
                changes.append((r, new))
        print(f"\nDaty do poprawy: {len(changes)}")
        print(f"{'id':>5}  {'tytuł':<40}  {'stara data':<26}  nowa data")
        for r, new in changes:
            print(
                f"{r['id']:>5}  {str(r['title'])[:40]:<40}  "
                f"{str(r['updated_at'])[:26]:<26}  {new.isoformat()[:26]}"
            )
            if args.apply:
                conn.execute(
                    text("UPDATE announcements SET updated_at = :d WHERE id = :i"),
                    {"d": new, "i": r["id"]},
                )

        after = {r["id"]: dict(r) for r in rows}
        for r, new in changes:
            after[r["id"]]["updated_at"] = new
        conflicts = order_conflicts(after.values())
        print(f"\nKonflikty z id (nowsze id, wcześniejsza data): {len(conflicts)}")
        for newer, older in conflicts:
            print(
                f"  #{newer} ({after[newer]['updated_at']}) < "
                f"#{older} ({after[older]['updated_at']}) [{after[newer]['province']}]"
            )
        if not args.apply:
            print("\nPodgląd: nic nie zapisano. Użyj --apply, żeby zapisać.")


if __name__ == "__main__":
    main()
