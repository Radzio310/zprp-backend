"""Kto włączył panel Mentor parom - TYLKO DO ODCZYTU (same SELECT, transakcja READ ONLY na PostgreSQL).

Drukuje pary z włączonym panelem: okręg, program, kto i kiedy założył parę, kto i kiedy włączył panel.
Niczego nie zapisuje; nie importuje `app.db`. Wymaga DATABASE_URL w środowisku (kontener zprp-backend).

Użycie:  python scripts/check_mentor_panels_enabled.py
"""

import os
from datetime import datetime

from sqlalchemy import create_engine, text


def main() -> None:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("Brak DATABASE_URL w środowisku.")
        return
    engine = create_engine(url)
    with engine.connect() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SET TRANSACTION READ ONLY"))
        rows = [dict(r._mapping) for r in conn.execute(text(
            "SELECT p.id, p.province, p.program, p.judge_ids, p.created_by, p.created_at, p.ended_at, "
            "m.enabled_by, m.enabled_at, m.updated_at "
            "FROM mentor_panels m JOIN mentoring_pairs p ON p.id = m.pair_id "
            "WHERE m.enabled IS TRUE ORDER BY m.enabled_at NULLS FIRST"))]
        print(f"--- pary z włączonym panelem: {len(rows)}")
        for r in rows:
            print("   ", {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()})
        off = conn.execute(text("SELECT COUNT(*) FROM mentor_panels WHERE enabled IS NOT TRUE")).scalar()
        print(f"--- wyłączone (z wierszem panelu): {off}")


if __name__ == "__main__":
    main()
