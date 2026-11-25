"""Audyt wspolnych dojazdow - TYLKO ODCZYT. Dziala tez ze stdin (`python -`).

  python scripts/settlement_trip_audit.py [--province SLASKIE] [--from 01.09.2026] [--to 31.10.2026] [--csv plik|-]

Liczy STARA regula (dojazd przy kazdym meczu) silnikiem panelu - bez meczow
przyszlych i bez obsad ZPRP - i wypisuje sytuacje: ten sam sedzia + dzien (PL) +
miejscowosc + 2 lub wiecej meczow z dojazdem > 0. Turnieje dzieci/MlMR i reczne
mecze z gotowa kwota sa pominiete. Platnika wyprowadza sam (z obciazen klubow),
wiec dziala na kodzie sprzed i po nowej regule. `--csv -` = CSV na stdout.
Diagnostyka na stderr. Baza: DATABASE_URL (jak w aplikacji).

Nic nie zapisuje: na czas importu `app.db` kazde polecenie inne niz SELECT jest
wycinane (migracje startowe), a `create_all` wylaczone.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import inspect
import logging
import os
import sys
from collections import defaultdict
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.getcwd())
if "__file__" in globals():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_PL = ZoneInfo("Europe/Warsaw")
KINDS = ("ten sam płatnik", "różni płatnicy")
COLS = ["day", "judge_name", "judge_id", "city", "matches", "payers", "kind", "trips",
        "travel_total", "excess", "saving_new_rule", "month"]


def _err(*a):
    print(*a, file=sys.stderr)


def _guard_import_ddl() -> None:
    import sqlalchemy
    from sqlalchemy.engine import Connection

    class _Nothing:
        rowcount = 0
        first = fetchone = scalar = lambda self: None
        fetchall = lambda self: []
        __iter__ = lambda self: iter(())

    original = Connection.execute

    def execute(self, statement, *args, **kwargs):
        if hasattr(statement, "text") and not str(statement.text).lstrip().upper().startswith(("SELECT", "SHOW")):
            return _Nothing()
        return original(self, statement, *args, **kwargs)

    Connection.execute = execute
    sqlalchemy.MetaData.create_all = lambda *a, **k: None


def _day(text: str) -> date:
    for fmt in ("%d.%m.%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text.strip(), fmt).date()
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"Zła data: {text}")


def _hour(value) -> str:
    if value is None:
        return "?"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_PL).strftime("%H:%M")


def build_situations(matches, payer_of, owner, payer_name, judge_name) -> list[dict]:
    """Rozliczone mecze (stara regula) -> sytuacje. Lisc: bez bazy."""
    from app import settlement_engine as E

    groups = defaultdict(list)
    for m in matches:
        if not getattr(m, "trip_eligible", True) or m.origin == "manual" or m.zprp_reason:
            continue
        if E._trip_kind(m.match_code) is not None:
            continue
        day, city = E._local_day(m), E._city_key(m.city)
        if day is None or not city or not m.travel or m.travel <= 0:
            continue
        groups[(m.judge_id, day, city)].append(m)
    out = []
    for (judge, day, _c), ms in groups.items():
        if len(ms) < 2:
            continue
        ms.sort(key=lambda m: (m.match_at or datetime.min.replace(tzinfo=timezone.utc), m.match_key))
        payers = [(owner.get(payer_of.get(m.match_key)) or payer_of.get(m.match_key)) for m in ms]
        total = round(sum(m.travel for m in ms), 2)
        by = defaultdict(list)
        for m, p in zip(ms, payers):
            if p:
                by[p].append(m)
        saving = sum(sum(m.travel for m in g) - g[0].travel for g in by.values() if len(g) > 1)
        out.append({
            "judge_name": judge_name(judge), "judge_id": judge, "day": day.isoformat(),
            "month": day.strftime("%Y-%m"), "city": ms[0].city,
            "matches": "; ".join(f"{m.match_code} {_hour(m.match_at)}" for m in ms),
            "payers": "; ".join(payer_name(p) for p in payers),
            "kind": KINDS[0] if len({*payers}) == 1 and all(payers) else KINDS[1],
            "trips": len(ms), "travel_total": total,
            "excess": round(total - ms[0].travel, 2), "saving_new_rule": round(saving, 2),
        })
    out.sort(key=lambda r: (r["day"], r["judge_name"], r["city"]))
    return out


async def collect(province: str, d_from: date, d_to: date) -> list[dict]:
    from sqlalchemy import select

    from app import club_charges as C
    from app import province_settlements as PS
    from app import settlement_engine as E
    from app.db import database, province_club_teams, province_clubs
    from app.district_payer import DISTRICT_PAYER_ID, default_label
    from app.settlement_club_scope import club_scope_many
    from app.settlement_seasons import season_of

    key = PS.require_province(province)
    await database.connect()
    try:
        base = await PS._base(key)
        kw = {}
        if "share_trips" in inspect.signature(E.settle_judges).parameters:
            kw["share_trips"] = False  # po wdrozeniu nowej reguly: licz po staremu
        settled = E.settle_judges(
            base["assignments"], province=key, central_versions=base["central_versions"],
            province_versions=base["province_versions"], now=datetime.now(timezone.utc),
            date_from=d_from, date_to=d_to, include_future=False, include_zprp=False,
            names=base["names"], **kw)
        matches = [m for e in settled for m in e.matches]
        by_season = defaultdict(list)
        for m in matches:
            if m.day is not None:
                by_season[season_of(m.day)].append(m)
        # Platnik kazdego meczu = klub z wiersza obciazen; podgladamy wiersze,
        # ktore `club_scope_many` i tak buduje (starszy kod nie zwraca `payer_of`).
        payer_of: dict[str, str] = {}
        original = C.build_charges

        def spy(*a, **k):
            rows = original(*a, **k)
            for r in rows:
                if r.status in (C.CHARGED, C.CLUB_OFF) and r.club_id:
                    payer_of[r.match_key] = r.club_id
            return rows

        C.build_charges = spy
        try:
            scope = await club_scope_many(key, dict(by_season))
        finally:
            C.build_charges = original
        excluded = scope.get("excluded_keys") or set()
        matches = [m for m in matches if m.match_key not in excluded]
        for k, v in (scope.get("club_of") or {}).items():
            payer_of.setdefault(k, v)

        owner: dict[str, str] = {}
        try:
            from app import province_club_budgets as CB
            from app import province_club_budgets_rules as BR

            for g in await CB.budget_groups(key):
                for member in g.get("member_ids") or []:
                    owner.setdefault(member, str(g.get("primary_club_id") or "").strip())
        except Exception as exc:
            _err("Budżety klubów pominięte:", exc)

        names: dict[str, str] = {}
        for r in await database.fetch_all(select(province_club_teams.c.club_id, province_club_teams.c.team_name).where(province_club_teams.c.province == key)):
            names.setdefault(str(r["club_id"]), str(r["team_name"] or ""))
        for r in await database.fetch_all(select(province_clubs.c.club_id, province_clubs.c.display_name).where(province_clubs.c.province == key)):
            if r["display_name"]:
                names[str(r["club_id"])] = str(r["display_name"])
        for c in scope.get("clubs") or []:
            names.setdefault(c["club_id"], c["club_name"])
        names[DISTRICT_PAYER_ID] = default_label(key)

        def judge_name(j):
            raw = base["names"].get(j, "")
            return f"{E.display_judge_name(raw)} ({j})" if raw else str(j)

        return build_situations(matches, payer_of, owner, lambda p: (names.get(p) or p) if p else "nieznany", judge_name)
    finally:
        await database.disconnect()


def report(rows, out=sys.stdout) -> None:
    for r in rows:
        print(f"{r['day']} | {r['judge_name']} | {r['city']} | mecze: {r['matches']} | płatnicy: {r['payers']} | "
              f"{r['kind']} | dojazdy: {r['trips']} = {r['travel_total']:.2f} zł | nadwyżka {r['excess']:.2f} zł", file=out)
    s = lambda part: sum(r["excess"] for r in part)
    print("-" * 60, file=out)
    print(f"Sytuacje: {len(rows)}, sędziowie: {len({r['judge_id'] for r in rows})}, łączna nadwyżka: {s(rows):.2f} zł", file=out)
    for kind in KINDS:
        part = [r for r in rows if r["kind"] == kind]
        note = " (jeden dojazd wg nowej reguły)" if kind == KINDS[0] else ""
        print(f"  {kind}{note}: {len(part)} sytuacji, sędziów {len({r['judge_id'] for r in part})}, nadwyżka {s(part):.2f} zł", file=out)
    print("Wg miesięcy:", file=out)
    for month in sorted({r["month"] for r in rows}):
        part = [r for r in rows if r["month"] == month]
        same = s([r for r in part if r["kind"] == KINDS[0]])
        print(f"  {month}: {len(part)} sytuacji, nadwyżka {s(part):.2f} zł (ten sam płatnik {same:.2f}, różni {s(part) - same:.2f})", file=out)
    print(f"Oszczędność wg nowej reguły (suma po płatnikach): {sum(r['saving_new_rule'] for r in rows):.2f} zł", file=out)


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    logging.getLogger().setLevel(logging.WARNING)
    p = argparse.ArgumentParser(description="Sędziowie z kilkoma dojazdami tego samego dnia w tej samej miejscowości (odczyt).")
    p.add_argument("--province", default="SLASKIE")
    p.add_argument("--from", dest="date_from", type=_day, default=date(2026, 9, 1))
    p.add_argument("--to", dest="date_to", type=_day, default=date(2026, 10, 31))
    p.add_argument("--csv", help="CSV (średniki) do pliku albo '-' na stdout zamiast tabeli")
    args = p.parse_args()
    _guard_import_ddl()
    rows = asyncio.run(collect(args.province, args.date_from, args.date_to))
    if args.csv == "-":
        w = csv.DictWriter(sys.stdout, fieldnames=COLS, delimiter=";", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        report(rows, out=sys.stderr)
        return
    report(rows)
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS, delimiter=";")
            w.writeheader()
            w.writerows(rows)
        _err("Zapisano:", args.csv)


if __name__ == "__main__":
    main()
