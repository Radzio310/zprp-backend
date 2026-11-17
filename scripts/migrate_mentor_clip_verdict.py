"""Migracja Mentora 17.11.2026: „Dobra decyzja", „Zła decyzja", „Do dyskusji" z kategorii klipu na pole `verdict`.

Domyślnie SUCHY PRZEBIEG (tylko liczy, nic nie zapisuje). Zapis dopiero z `--apply`, w jednej transakcji.
Bezpieczna przy ponownym uruchomieniu: klip bez dawnych kategorii nie jest ruszany, drugi przebieg daje zera.

Reguła: klip z dawną kategorią dostaje ocenę z PIERWSZEJ dawnej kategorii w swoim `category_ids`
(good = dobra, bad = zla, discuss = dyskusja); dawne id znikają z `category_ids`, pozostałe kategorie zostają.
Klip, który już ma `verdict`, go zachowuje. Wiersze kategorii o kluczach dobra/zla/dyskusja dostają
`archived = true` (nie są kasowane: zrzuty klatek i stare odwołania dalej je nazywają).

Od 17.11.2026 ten sam skrypt przepisuje też ZNACZNIKI nagrań (`mentor_match_videos.markers_json`): dawny rodzaj
dobra/zla/dyskusja (i stare kategorie trafna, bledna, ustawienie...) staje się oceną `verdict`, a rodzaj pustym
(zostają pytanie i kluczowa). Nagrobki i pozostałe pola znaczników bez zmian; idempotentne.

Użycie (w kontenerze zprp-backend, z DATABASE_URL w środowisku):
    python -m scripts.migrate_mentor_clip_verdict            # suchy przebieg
    python -m scripts.migrate_mentor_clip_verdict --apply    # zapis
"""

import os
import sys

from sqlalchemy import create_engine, text

from app import mentor_panel_rules as R


def run(conn, apply: bool) -> dict:
    if apply and conn.dialect.name == "postgresql":
        conn.execute(text("ALTER TABLE mentor_clips ADD COLUMN IF NOT EXISTS verdict VARCHAR"))
    cats = [dict(r._mapping) for r in conn.execute(text("SELECT id, key, archived FROM mentor_categories WHERE key IN ('dobra','zla','dyskusja')"))]
    legacy = R.legacy_category_map(cats)
    has_col = bool(conn.execute(text("SELECT 1 FROM information_schema.columns WHERE table_name='mentor_clips' AND column_name='verdict'")).first()) \
        if conn.dialect.name == "postgresql" else True
    select_verdict = ", verdict" if has_col else ", NULL AS verdict"
    clips = [dict(r._mapping) for r in conn.execute(text(f"SELECT id, category_ids{select_verdict} FROM mentor_clips"))]
    plan = R.plan_verdict_migration(clips, legacy)
    stats = {**plan["stats"], "legacy_categories": len(cats), "categories_to_archive": sum(1 for c in cats if not c["archived"])}
    if apply:
        import json

        for clip_id, values in plan["updates"]:
            conn.execute(text("UPDATE mentor_clips SET category_ids = :c, verdict = :v, updated_at = CURRENT_TIMESTAMP WHERE id = :id"),
                         {"c": json.dumps(values["category_ids"], ensure_ascii=False), "v": values["verdict"], "id": clip_id})
        if cats:
            conn.execute(text("UPDATE mentor_categories SET archived = true WHERE key IN ('dobra','zla','dyskusja') AND archived IS NOT TRUE"))
    stats.update(run_markers(conn, apply))
    return stats


def run_markers(conn, apply: bool) -> dict:
    import json

    from app.mentor_video_rules import migrate_marker_item

    stats = {"videos_scanned": 0, "videos_changed": 0, "markers_changed": 0, "markers_good": 0, "markers_bad": 0, "markers_discuss": 0}
    rows = [dict(r._mapping) for r in conn.execute(text("SELECT id, markers_json FROM mentor_match_videos WHERE markers_json IS NOT NULL"))]
    for row in rows:
        stats["videos_scanned"] += 1
        try:
            items = json.loads(row["markers_json"])
        except (TypeError, ValueError):
            continue
        if not isinstance(items, list):
            continue
        changed = 0
        out = []
        for item in items:
            new, did = migrate_marker_item(item)
            out.append(new)
            if did:
                changed += 1
                stats["markers_" + str(new.get("verdict"))] = stats.get("markers_" + str(new.get("verdict")), 0) + 1
        if changed:
            stats["videos_changed"] += 1
            stats["markers_changed"] += changed
            if apply:
                conn.execute(text("UPDATE mentor_match_videos SET markers_json = :m WHERE id = :id"),
                             {"m": json.dumps(out, ensure_ascii=False), "id": row["id"]})
    return stats


def main() -> None:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("Brak DATABASE_URL w środowisku.")
        sys.exit(1)
    apply = "--apply" in sys.argv
    engine = create_engine(url)
    with engine.begin() as conn:
        stats = run(conn, apply)
    print(("ZAPISANO" if apply else "SUCHY PRZEBIEG (nic nie zapisano; dodaj --apply)"))
    for key, value in stats.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
