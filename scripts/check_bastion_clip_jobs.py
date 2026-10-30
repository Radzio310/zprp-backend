"""Stan zadań wycinania klipów z Bastionu - TYLKO DO ODCZYTU (same SELECT, transakcja READ ONLY na PostgreSQL).

Drukuje: zadania wg stanu oraz ostatnie zadania z etapem, liczbą pytań o gotowość, kodem błędu i stanem klipu (mp4_status, plik).
Niczego nie zapisuje; nie importuje `app.db`. Wymaga DATABASE_URL w środowisku (kontener zprp-backend).

Użycie:  python scripts/check_bastion_clip_jobs.py [ile_wierszy=10]
"""

import os
import sys
from datetime import datetime, timezone

from sqlalchemy import create_engine, text


def show(conn, title: str, sql: str, **params) -> None:
    rows = [dict(r._mapping) for r in conn.execute(text(sql), params)]
    print(f"--- {title}: {len(rows)}")
    for r in rows:
        print("   ", {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()})


def main() -> None:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("Brak DATABASE_URL w środowisku.")
        return
    limit = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 10
    engine = create_engine(url)
    with engine.connect() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SET TRANSACTION READ ONLY"))
        print(f"Teraz (UTC): {datetime.now(timezone.utc).isoformat()}")
        show(conn, "zadania wg stanu", "SELECT state, COUNT(*) AS n FROM mentor_bastion_clip_jobs GROUP BY state ORDER BY state")
        show(conn, "ostatnie zadania", """
            SELECT j.state, j.remote_clip_code, j.poll_count, j.attempts, j.last_error_code, j.last_error_message,
                   j.start_s, j.end_s, j.clip_revision, c.media_rev,
                   c.mp4_status, (c.mp4_key IS NOT NULL) AS has_file, c.card_status,
                   j.created_at, j.submitted_at, j.updated_at, j.next_attempt_at, j.lease_until, j.finished_at
            FROM mentor_bastion_clip_jobs j LEFT JOIN mentor_clips c ON c.id = j.clip_id
            ORDER BY j.created_at DESC LIMIT :limit""", limit=limit)
        show(conn, "retryable_failed (ostatni szczegół przyczyny)", """
            SELECT id, state, attempts, poll_count, last_error_code, last_error_message, next_attempt_at, updated_at
            FROM mentor_bastion_clip_jobs WHERE state = 'retryable_failed' ORDER BY updated_at DESC LIMIT :limit""", limit=limit)


if __name__ == "__main__":
    main()
