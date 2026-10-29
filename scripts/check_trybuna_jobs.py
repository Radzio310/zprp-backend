"""Stan zadań w tle Trybuny Mentora - TYLKO DO ODCZYTU (same SELECT, transakcja READ ONLY na PostgreSQL).

Drukuje: miniatury kaset (ile oczekuje `pending`/`working`, ile gotowych `ready`, ile trwale nieudanych `failed`) i ostatnie błędy `/frame`,
czas liczenia kanału obserwowanych (`computed_at`) oraz ostatnie wysyłki "Dziś sędziuje" i paczki nowych nagrań (`digest:`).
Niczego nie zapisuje; nie importuje `app.db`. Wymaga DATABASE_URL w środowisku (kontener zprp-backend).

Użycie:  python scripts/check_trybuna_jobs.py [ile_wierszy=10]
"""

import os
import sys
from datetime import datetime, timezone

from sqlalchemy import create_engine, text


def show(conn, title: str, sql: str, **params) -> list:
    rows = [dict(r._mapping) for r in conn.execute(text(sql), params)]
    print(f"--- {title}: {len(rows)}")
    for r in rows:
        print("   ", {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()})
    return rows


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
        by_status = show(conn, "miniatury wg statusu", "SELECT status, COUNT(*) AS n FROM mentor_trybuna_thumbs GROUP BY status ORDER BY status")
        total = sum(int(r["n"]) for r in by_status)
        counts = {r["status"]: int(r["n"]) for r in by_status}
        pending = counts.get("pending", 0) + counts.get("working", 0)
        print(f"=== thumb_pending (pending+working): {pending} | gotowe (ready): {counts.get('ready', 0)} | nieudane (failed): {counts.get('failed', 0)} | razem: {total}")
        show(conn, "najstarsze oczekujące", "SELECT bunny_item_id, status, attempts, error, next_attempt_at, updated_at FROM mentor_trybuna_thumbs "
             "WHERE status IN ('pending','working') ORDER BY updated_at ASC LIMIT :n", n=limit)
        show(conn, "ostatnie błędy /frame", "SELECT bunny_item_id, status, attempts, error, updated_at FROM mentor_trybuna_thumbs "
             "WHERE error IS NOT NULL AND error <> '' ORDER BY updated_at DESC LIMIT :n", n=limit)
        show(conn, "błędy /frame wg kodu", "SELECT error, COUNT(*) AS n FROM mentor_trybuna_thumbs WHERE error IS NOT NULL AND error <> '' "
             "GROUP BY error ORDER BY n DESC LIMIT :n", n=limit)
        show(conn, "kanał obserwowanych (computed_at, najstarsze i najnowsze)", "SELECT judge_id, computed_at FROM mentor_trybuna_feed_cache "
             "ORDER BY computed_at DESC LIMIT :n", n=limit)
        show(conn, "kanał: zakres", "SELECT COUNT(*) AS wpisow, MIN(computed_at) AS najstarszy, MAX(computed_at) AS najnowszy FROM mentor_trybuna_feed_cache")
        show(conn, "ostatnie wysyłki Dziś sędziuje", "SELECT day, COUNT(*) AS osob, MAX(sent_at) AS ostatnia FROM mentor_trybuna_today "
             "WHERE day NOT LIKE 'digest:%' GROUP BY day ORDER BY day DESC LIMIT :n", n=limit)
        show(conn, "ostatnie paczki nowych nagrań (digest)", "SELECT day, COUNT(*) AS osob, MAX(sent_at) AS ostatnia FROM mentor_trybuna_today "
             "WHERE day LIKE 'digest:%' GROUP BY day ORDER BY day DESC LIMIT :n", n=limit)
        show(conn, "oznaczone nagrania wg dnia wysyłki", "SELECT CAST(notified_at AS DATE) AS dzien, COUNT(*) AS nagran, COUNT(DISTINCT judge_id) AS osob "
             "FROM mentor_trybuna_notified GROUP BY CAST(notified_at AS DATE) ORDER BY dzien DESC LIMIT :n", n=limit)


if __name__ == "__main__":
    main()
