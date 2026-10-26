"""Audyt kilometrów rozliczeń okręgu - TYLKO ODCZYT.

    python scripts/settlement_km_audit.py --db --province slaskie [--since 2026-09-01] [--csv wynik.csv]

`DATABASE_URL` z otoczenia (sesja bazy tylko do odczytu). Wypisuje: sędzia,
mecz, para miejscowości, km obecne, km oczekiwane, źródło, powód. Reguły:
`app/settlement_km_audit_rules.py`. Nic nie zapisuje.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import national_lookup_rules as NL  # noqa: E402
from app import national_place_rules as P  # noqa: E402
from app import settlement_km_audit_rules as A  # noqa: E402
from app.settlement_distances import VersionedDistanceIndex  # noqa: E402
from app.settlement_province import spellings  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", action="store_true", required=True)
    parser.add_argument("--province", required=True)
    parser.add_argument("--since", default="2000-01-01")
    parser.add_argument("--csv")
    args = parser.parse_args()

    import psycopg2
    import psycopg2.extras

    dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    conn = psycopg2.connect(dsn)
    conn.set_session(readonly=True)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    names = list(spellings(args.province))
    cur.execute(
        "SELECT m.judge_id, j.full_name, m.match_key, m.match_at, m.match_code, m.home_city, m.city,"
        " m.distance_km, m.distance_source FROM province_settlement_matches m"
        " LEFT JOIN province_settlement_judges j ON j.province = m.province AND j.judge_id = m.judge_id"
        " WHERE m.province = ANY(%s) AND m.active AND m.match_at >= %s AND m.distance_km IS NOT NULL",
        (names, args.since),
    )
    rows = cur.fetchall()
    cur.execute("SELECT content FROM okreg_distances WHERE province = ANY(%s)", (names,))
    got = cur.fetchone()
    content = got["content"] if got else None
    if isinstance(content, str):
        content = json.loads(content)
    book = VersionedDistanceIndex(content)
    cur.execute("SELECT city_a_key, city_b_key, distance_km FROM national_distance_connections")
    pairs = NL.expand_pairs({(r["city_a_key"], r["city_b_key"]): r["distance_km"] for r in cur.fetchall()})
    conn.close()

    found = A.audit(
        rows,
        P.default_gazetteer(),
        province=args.province,
        table_lookup=lambda a, b, day: book.lookup(a, b, day),
        national_lookup=lambda a, b: NL.national_km(pairs, a, b, args.province),
    )
    cols = ["name", "judge_id", "match_at", "match_code", "home_city", "city", "km", "expected", "source", "reason"]
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore", delimiter=";")
            writer.writeheader()
            writer.writerows(found)
    print(f"Wiersze: {len(rows)}, podejrzane: {len(found)}, sędziowie: {len({f['judge_id'] for f in found})}")
    for f in found:
        print(f"{f['name'] or f['judge_id']} | {f['match_at']} {f['match_code']} | {f['home_city']} -> {f['city']} | "
              f"km {f['km']} (oczek. {f['expected']}) | {f['source']} | {f['reason']}")


if __name__ == "__main__":
    main()
