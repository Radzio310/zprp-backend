#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/apply_club_declarations.py
Nanosi pismo okręgu o klubach na panel: płatność przez okręg i „4. sędzia".

Pismo odpowiada klubowi na dwa pytania, a każde trafia gdzie indziej:

  - PŁATNOŚĆ PRZEZ OKRĘG -> Rozliczenia, kafel „Rozlicza się przez okręg"
    (`province_clubs.settles_via_district` + `settles_since`),
  - 4. SĘDZIA PRZEZ OKRĘG -> Obsada, zakładka Kluby: czy drugiego stolikowego
    klub stawia sam (`province_club_assignment.table_by_club` + data). Tej samej
    deklaracji słucha Automat (kogo wysłać) i rachunek klubu (za kogo płaci).

Nazwy klubów w panelu są zgadywane z najkrótszej nazwy drużyny, więc plik może
też poprawić nazwę wyświetlaną (`rename`) - żeby panel czytał się jak pismo.

ZASADY:
  - najpierw ODCZYT i PLAN; bez `--apply` nic nie jest zapisywane,
  - zmieniamy tylko to, co się różni od stanu na serwerze,
  - zmiana nazwy przenosi dotychczasowe rozliczanie i notatkę klubu - trasa
    ustawień nadpisuje wszystkie pola naraz, więc bez tego skasowałaby notatkę,
  - na starym backendzie (bez daty deklaracji stolikowego) pokazuje plan, ale
    odmawia ZAPISU: tam deklaracja zapisałaby się „od zawsze" i przeliczyła minione sezony,
  - po zapisie czyta wszystko jeszcze raz i porównuje z pismem.

Użycie:
  python scripts/apply_club_declarations.py --file scripts/data/slaskie_deklaracje_2026_2027.json
  python scripts/apply_club_declarations.py --file ... --apply --login <numer sędziego>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BACKEND = os.environ.get(
    "ZPRP_BACKEND_URL", "https://zprp-backend-production.up.railway.app"
)
PAYMENT = {"TAK": True, "NIE": False}
#: NIE w piśmie = klub stawia drugiego stolikowego sam = `table_by_club` 1.
FOURTH = {"TAK": 0, "NIE": 1, "NA": 0}


def call(method: str, path: str, body=None, token: str = ""):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(BACKEND + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        text = error.read().decode("utf-8", "replace")[:400]
        raise SystemExit(f"BŁĄD {error.code} przy {method} {path}: {text}")


def login(username: str) -> str:
    """Token tą samą drogą co aplikacja. Hasło z terminala, nigdzie nie zapisywane."""
    import getpass

    password = os.environ.get("ZPRP_PASSWORD") or getpass.getpass(f"Hasło do konta {username}: ")
    token = call("POST", "/auth/login", {"username": username, "password": password}).get(
        "access_token"
    )
    if not token:
        raise SystemExit("Logowanie nie zwróciło tokenu.")
    return token


def q(**params) -> str:
    return urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})


def read_state(province: str, season: str):
    """Rozliczanie i nazwy z panelu klubów, deklaracje stolika z Obsady."""
    settles: dict[str, dict] = {}
    # Poprzedni sezon też, bo klub z pisma może jeszcze nie mieć drużyn w tym.
    start = int(season[:4])
    for label in (f"{start - 1}/{start}", season):
        for club in call("GET", f"/province/clubs?{q(province=province, season=label)}")["clubs"]:
            settles[club["club_id"]] = club
    obsada = call("GET", f"/province/assignment/clubs?{q(province=province)}")
    return settles, obsada


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True)
    parser.add_argument("--apply", action="store_true", help="bez tego tylko plan")
    parser.add_argument("--login", help="numer sędziego - skrypt zaloguje się sam")
    parser.add_argument("--token", default=os.environ.get("ZPRP_ADMIN_JWT", ""))
    args = parser.parse_args()

    with open(args.file, encoding="utf-8") as handle:
        spec = json.load(handle)
    province, season, since = spec["province"], spec["season"], spec["since"]
    clubs = spec["clubs"]

    bad = [c for c in clubs if c["payment"] not in PAYMENT or c["fourth"] not in FOURTH]
    if bad:
        print("BŁĄD w pliku - nieznane odpowiedzi:", [c["club_id"] for c in bad])
        return 1
    ids = [c["club_id"] for c in clubs]
    if len(ids) != len(set(ids)):
        print("BŁĄD w pliku - ten sam klub dwa razy.")
        return 1

    print(f"Pismo: {spec.get('source', '')}")
    print(f"Okręg {province}, sezon {season}, obowiązuje od {since}. Klubów: {len(clubs)}\n")

    settles, obsada = read_state(province, season)
    rows = {row["club_id"]: row for row in obsada["clubs"]}
    old_backend = bool(obsada["clubs"]) and "table_by_club_since" not in obsada["clubs"][0]
    if old_backend:
        print(
            "UWAGA: backend nie zna jeszcze daty deklaracji stolikowego - plan pokażę,\n"
            "ale zapisu nie zrobię. Najpierw wdróż Railway: na starym backendzie\n"
            "deklaracja zapisałaby się „od zawsze” i przeliczyła minione sezony.\n"
        )

    pay_off, pay_on, own_table, full_table, renames = [], [], [], [], []
    for club in clubs:
        cid = club["club_id"]
        now = settles.get(cid)
        label = club["mail"] or (now or {}).get("name") or cid

        want_pay = PAYMENT[club["payment"]]
        have_pay = bool((now or {}).get("settles_via_district", True))
        have_since = (now or {}).get("settles_since")
        if not want_pay and (have_pay or have_since != since):
            pay_off.append((cid, label))
        if want_pay and not have_pay:
            pay_on.append((cid, label))

        want_table = FOURTH[club["fourth"]]
        rule = rows.get(cid) or {}
        have_table = int(rule.get("table_by_club", 0) or 0)
        if want_table and (have_table != 1 or rule.get("table_by_club_since") != since):
            own_table.append((cid, label))
        if not want_table and have_table:
            full_table.append((cid, label))

        new_name = (club.get("rename") or "").strip()
        if new_name and now and new_name != now.get("name"):
            renames.append((cid, now.get("name"), new_name, now))
        if new_name and not now:
            print(f"UWAGA: {cid} ({label}) - brak klubu w panelu, nazwy nie zmienię.")

    def show(title, items):
        print(f"{title}: {len(items)}")
        for item in items:
            print(f"   {item[0]:>6}  {item[1]}")

    show(f"Rozliczanie przez okręg WYŁĄCZ (od {since})", pay_off)
    show("Rozliczanie przez okręg WŁĄCZ", pay_on)
    show(f"Drugiego stolikowego stawia KLUB (od {since})", own_table)
    show("Obu stolikowych wysyła OKRĘG", full_table)
    print(f"Nazwa w panelu: {len(renames)}")
    for cid, old, new, _ in renames:
        print(f"   {cid:>6}  {old}  ->  {new}")

    if not (pay_off or pay_on or own_table or full_table or renames):
        print("\nPanel już zgadza się z pismem - nie ma czego zmieniać.")
        return 0
    if not args.apply:
        print("\nTo był plan. Zapis: dodaj --apply --login <numer sędziego>.")
        return 0
    if old_backend:
        print("\nSTOP: najpierw wdróż Railway, potem uruchom z --apply.")
        return 1

    token = args.token or (login(args.login) if args.login else "")
    if not token:
        print("\nBŁĄD: zapis wymaga --login <numer sędziego> albo --token.")
        return 1

    who = args.login or "skrypt"
    if pay_off:
        call("PUT", "/province/clubs/settings/bulk", {
            "province": province, "club_ids": [c for c, _ in pay_off],
            "settles_via_district": False, "settles_since": since, "updated_by": who,
        }, token)
    if pay_on:
        call("PUT", "/province/clubs/settings/bulk", {
            "province": province, "club_ids": [c for c, _ in pay_on],
            "settles_via_district": True, "updated_by": who,
        }, token)
    if own_table:
        call("PUT", "/province/assignment/clubs/bulk", {
            "province": province, "club_ids": [c for c, _ in own_table],
            "table_by_club": 1, "table_by_club_since": since, "updated_by": who,
        }, token)
    if full_table:
        call("PUT", "/province/assignment/clubs/bulk", {
            "province": province, "club_ids": [c for c, _ in full_table],
            "table_by_club": 0, "updated_by": who,
        }, token)
    for cid, _, new_name, now in renames:
        # Trasa ustawień zapisuje WSZYSTKIE pola naraz - przenosimy rozliczanie
        # i notatkę, inaczej zmiana nazwy skasowałaby notatkę klubu.
        call("PUT", f"/province/clubs/{urllib.parse.quote(cid)}/settings", {
            "province": province,
            "settles_via_district": bool(now.get("settles_via_district", True)),
            "settles_since": now.get("settles_since"),
            "display_name": new_name,
            "note": now.get("note") or None,
            "updated_by": who,
        }, token)
    print("\nZapisano. Sprawdzam, co naprawdę leży na serwerze...")

    settles, obsada = read_state(province, season)
    rows = {row["club_id"]: row for row in obsada["clubs"]}
    problems = []
    for club in clubs:
        cid = club["club_id"]
        now = settles.get(cid) or {}
        rule = rows.get(cid) or {}
        if now and bool(now.get("settles_via_district", True)) != PAYMENT[club["payment"]]:
            problems.append(f"{cid}: rozliczanie nie zgadza się z pismem")
        want_table = FOURTH[club["fourth"]]
        if rule and int(rule.get("table_by_club", 0) or 0) != want_table:
            problems.append(f"{cid}: stolik nie zgadza się z pismem")
        if rule and want_table and rule.get("table_by_club_since") != since:
            problems.append(f"{cid}: data deklaracji stolika to {rule.get('table_by_club_since')}")
        if club.get("rename") and now and now.get("name") != club["rename"]:
            problems.append(f"{cid}: nazwa to {now.get('name')!r}")
    if problems:
        print("ROZBIEŻNOŚCI:")
        for problem in problems:
            print("   -", problem)
        return 1
    print("Odczyt kontrolny: panel zgadza się z pismem co do klubu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
