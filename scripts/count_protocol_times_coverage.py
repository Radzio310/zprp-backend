#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""READ ONLY: ile meczów ma zatwierdzony/zakończony protokół BAZA (źródło czasów kar w API publicznym).

Użycie (z DATABASE_URL produkcji):  python scripts/count_protocol_times_coverage.py
Tylko SELECT, nic nie zapisuje.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def main() -> None:
    from sqlalchemy import select
    from app.db import database, saved_matches as T
    from app.zprp_public.protocol_times import extract_times

    await database.connect()
    try:
        rows = await database.fetch_all(select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.data_json))
        stats = {"wszystkie": 0, "approved": 0, "finished": 0, "szkoleniowe": 0, "bez_zprp_id": 0, "z_czasami_kar": 0}
        ids = set()
        for r in rows:
            stats["wszystkie"] += 1
            if r["status"] not in ("approved", "finished"):
                continue
            blob = r["data_json"]
            if isinstance(blob, str):
                blob = json.loads(blob)
            cfg = (blob or {}).get("matchConfig") or {}
            if cfg.get("training") is not None:
                stats["szkoleniowe"] += 1
                continue
            stats[r["status"]] += 1
            if not r["zprp_match_id"]:
                stats["bez_zprp_id"] += 1
            else:
                ids.add(str(r["zprp_match_id"]))
            ex = extract_times(blob)
            if any(ex[s][b] for s in ex for b in ("players", "staff")):
                stats["z_czasami_kar"] += 1
        stats["unikalne_zprp_match_id"] = len(ids)
        for k, v in stats.items():
            print(f"{k}: {v}")
    finally:
        await database.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
