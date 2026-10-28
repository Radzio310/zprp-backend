"""READ ONLY: hala jednego meczu, wiersze rozliczen i pamiec pomiarow Google.

Uzycie na Railway:
  railway ssh -s zprp-backend "python scripts/match_venue_check.py 210953"

Wypisuje: zprp_match_venues, wiersze province_settlement_matches (km, zrodlo, dom)
i wpisy city_distances z kluczem hali zawierajacym podany tekst (domyslnie
"dabrowa"). Nic nie zapisuje (sesja readonly).
"""
from __future__ import annotations

import os
import sys


def main() -> None:
    match_id = sys.argv[1] if len(sys.argv) > 1 else "210953"
    needle = (sys.argv[2] if len(sys.argv) > 2 else "dabrowa").lower()
    import psycopg2
    import psycopg2.extras

    dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    conn = psycopg2.connect(dsn)
    conn.set_session(readonly=True)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM zprp_match_venues WHERE match_id = %s", (match_id,))
    print("VENUE:", cur.fetchall())
    cur.execute(
        "SELECT m.province, m.judge_id, m.match_key, m.match_at, m.match_code, m.home_city, m.city,"
        " m.teams, m.distance_km, m.distance_source FROM province_settlement_matches m"
        " WHERE m.match_key LIKE %s",
        ("%:" + match_id,),
    )
    for row in cur.fetchall():
        print("ROW:", dict(row))
    cur.execute(
        "SELECT from_key, to_key, km, source, updated_at FROM city_distances WHERE to_key ILIKE %s ORDER BY to_key, from_key",
        (f"%{needle}%",),
    )
    for row in cur.fetchall():
        print("MEM:", dict(row))
    conn.close()


if __name__ == "__main__":
    main()
