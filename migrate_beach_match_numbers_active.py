"""
migrate_beach_match_numbers_active.py
=====================================
Jednorazowa migracja numerów meczów (Beach) do STABILNEGO, globalnie
unikalnego schematu — TYLKO dla turniejów TRWAJĄCYCH i NADCHODZĄCYCH.

Tło problemu:
  Numer meczu miał postać  PREFIX/CATGENDER/<ordinal>/<seq>, gdzie <ordinal>
  to pozycja turnieju wśród "rodzeństwa" liczona dynamicznie po dacie. Ordinal
  PRZESUWAŁ się przy dodaniu wcześniejszego turnieju, więc ten sam numer trafiał
  do dwóch turniejów i mecze ProEl (kluczowane po numerze) się nakładały.

Co robi migracja:
  Dla każdego TRWAJĄCEGO/NADCHODZĄCEGO turnieju zamienia <ordinal> w numerze na
  tournament_id (stały i unikalny), ZACHOWUJĄC prefix, catGender i seq:
      PREFIX/CATGENDER/<ordinal>/<seq>  ->  PREFIX/CATGENDER/<tournament_id>/<seq>
      PREFIX/CATGENDER/<seq>            ->  PREFIX/CATGENDER/<tournament_id>/<seq>
  i w lockstep aktualizuje WSZYSTKO, co jest jednoznacznie przypisane do turnieju:
    1. matchNumber w data_json.schedule.matches[]            (dane własne turnieju)
    2. match_id w data_json.disqualifications[]              (dane własne turnieju)
    3. wiersz beach_proel_matches — dopasowany po schedule_match_id (NIE po numerze!),
       zmiana match_number (PK) + wewnętrznego data_json.matchConfig.matchNumber

CELOWO NIE rusza (żeby nie uszkodzić niczego wstecz):
  • turniejów ZAKOŃCZONYCH (COALESCE(end_date, event_date) < dziś − grace),
  • short_result_records — brak kolumny wiążącej z turniejem; numer bywa
    współdzielony, więc rename mógłby ruszyć rekord MINIONEGO turnieju.
    Koszt pominięcia: po przenumerowaniu apka może uznać, że "wynik skrócony"
    dla danego meczu nie był wysłany (ewent. duplikat powiadomienia). Bez korupcji.
  • wygenerowanych protokołów (statyczne pliki PDF/xlsx z wdrukowanym numerem).
  • lokalnych wersji roboczych ProEl na telefonach (AsyncStorage, po numerze).

Bezpieczeństwo:
  • DRY-RUN jest DOMYŚLNY. Zapis tylko z jawnym  --apply.
  • Idempotentny: numery już w docelowym schemacie są pomijane.
  • Jeśli przeliczenie dałoby duplikat numeru w obrębie turnieju → turniej jest
    POMIJANY w całości (z ostrzeżeniem do ręcznego przeglądu).
  • Rename wiersza ProEl tylko gdy nowy PK nie jest zajęty przez INNY mecz.

Uruchomienie:
  cd zprp-backend
  python migrate_beach_match_numbers_active.py            # dry-run (nic nie zapisuje)
  python migrate_beach_match_numbers_active.py --apply     # właściwy zapis

ZALECENIE: przed --apply zrób backup bazy (np. pg_dump).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, update

sys.path.insert(0, os.path.dirname(__file__))
from app.db import database, beach_tournaments, beach_proel_matches  # noqa: E402

# Turnieje kończące się wcześniej niż (dziś − GRACE_DAYS) traktujemy jako minione.
# Grace chroni wielodniowe turnieje trwające oraz różnice stref czasowych.
GRACE_DAYS = 1


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse(raw: Any, default: Any) -> Any:
    if raw is None:
        return default
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            pass
    return default


def _parse_match_number(mn: Optional[str]):
    """Zwraca (prefix, cat_gender, seq) albo None gdy format nieobsługiwany."""
    if not mn or not isinstance(mn, str):
        return None
    parts = mn.split("/")
    if len(parts) == 3:
        prefix, cat_gender, seq_s = parts
    elif len(parts) == 4:
        prefix, cat_gender, _disc, seq_s = parts
    else:
        return None
    try:
        seq = int(seq_s)
    except ValueError:
        return None
    if not prefix or not cat_gender:
        return None
    return prefix, cat_gender, seq


def _new_number(mn: str, tournament_id: int) -> Optional[str]:
    """Docelowy numer dla danego matchNumber; None gdy już docelowy / nie do ruszenia."""
    parsed = _parse_match_number(mn)
    if not parsed:
        return None
    prefix, cat_gender, seq = parsed
    target = f"{prefix}/{cat_gender}/{tournament_id}/{seq}"
    return None if target == mn else target


# ── core ─────────────────────────────────────────────────────────────────────

async def run(apply: bool) -> None:
    await database.connect()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=GRACE_DAYS)

        # Trwające/nadchodzące: koniec (end_date, a gdy brak — event_date) >= cutoff.
        rows = await database.fetch_all(
            select(
                beach_tournaments.c.id,
                beach_tournaments.c.name,
                beach_tournaments.c.event_date,
                beach_tournaments.c.end_date,
                beach_tournaments.c.data_json,
            )
        )

        scope = []
        for r in rows:
            d = dict(r)
            end = d.get("end_date") or d.get("event_date")
            if end is None:
                continue
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            if end >= cutoff:
                scope.append(d)

        print(f"== Tryb: {'APPLY (zapis)' if apply else 'DRY-RUN (bez zapisu)'} ==")
        print(f"Turniejów trwających/nadchodzących w zakresie: {len(scope)}")

        stats = {
            "tournaments_changed": 0,
            "tournaments_skipped_conflict": 0,
            "matches_renumbered": 0,
            "disq_updated": 0,
            "proel_renamed": 0,
            "proel_pk_conflicts": 0,
            "proel_missing_link": 0,
        }

        for t in scope:
            tid = t["id"]
            data = _parse(t["data_json"], {})
            if not isinstance(data, dict):
                continue
            schedule = data.get("schedule") or {}
            matches = schedule.get("matches") or []
            if not isinstance(matches, list):
                continue

            # 1) mapping old->new oraz schedule_match_id -> new
            mapping: dict[str, str] = {}
            sid_to_new: dict[str, str] = {}
            for m in matches:
                if not isinstance(m, dict):
                    continue
                mn = m.get("matchNumber")
                new = _new_number(mn, tid) if mn else None
                if not new:
                    continue
                mapping[mn] = new
                sid = m.get("id")
                if sid:
                    sid_to_new[str(sid)] = new

            if not mapping:
                continue  # nic do zmiany (już docelowe / brak numerów)

            # 1a) Guard: czy po przeliczeniu numery są unikalne w obrębie turnieju?
            final_numbers = []
            for m in matches:
                if not isinstance(m, dict):
                    continue
                mn = m.get("matchNumber")
                if not mn:
                    continue
                final_numbers.append(mapping.get(mn, mn))
            dupes = {n for n in final_numbers if final_numbers.count(n) > 1}
            if dupes:
                stats["tournaments_skipped_conflict"] += 1
                print(f"  ⚠ Turniej {tid} ({t['name']}): POMINIĘTY — kolizja numerów po "
                      f"przeliczeniu: {sorted(dupes)}. Wymaga ręcznego przeglądu.")
                continue

            print(f"  • Turniej {tid} ({t['name']}): {len(mapping)} numerów do zmiany")
            for old, new in sorted(mapping.items()):
                print(f"      {old}  ->  {new}")

            # 2) Zmień matchNumber w terminarzu (in place)
            for m in matches:
                if isinstance(m, dict) and m.get("matchNumber") in mapping:
                    m["matchNumber"] = mapping[m["matchNumber"]]
                    stats["matches_renumbered"] += 1

            # 3) Zmień match_id w dyskwalifikacjach (dane własne turnieju)
            disqs = data.get("disqualifications") or []
            if isinstance(disqs, list):
                for dq in disqs:
                    if isinstance(dq, dict) and dq.get("match_id") in mapping:
                        dq["match_id"] = mapping[dq["match_id"]]
                        stats["disq_updated"] += 1

            # zapis data_json turnieju
            if apply:
                await database.execute(
                    update(beach_tournaments)
                    .where(beach_tournaments.c.id == tid)
                    .values(data_json=data, updated_at=datetime.now(timezone.utc))
                )

            # 4) Rename wierszy ProEl — dopasowanie po schedule_match_id (jednoznaczne)
            for sid, new in sid_to_new.items():
                pr = await database.fetch_one(
                    select(beach_proel_matches).where(
                        beach_proel_matches.c.schedule_match_id == sid
                    )
                )
                if not pr:
                    stats["proel_missing_link"] += 1
                    continue
                pr_d = dict(pr)
                cur = pr_d["match_number"]
                if cur == new:
                    continue  # już docelowy

                # nowy PK nie może być zajęty przez INNY mecz
                clash = await database.fetch_one(
                    select(beach_proel_matches.c.match_number, beach_proel_matches.c.schedule_match_id)
                    .where(beach_proel_matches.c.match_number == new)
                )
                if clash and dict(clash).get("schedule_match_id") != sid:
                    stats["proel_pk_conflicts"] += 1
                    print(f"      ⚠ ProEl: numer {new} już zajęty przez inny mecz "
                          f"(sid={dict(clash).get('schedule_match_id')}) — pomijam rename {cur}.")
                    continue

                # zaktualizuj wewnętrzny matchConfig.matchNumber dla spójności stanu
                pj = _parse(pr_d.get("data_json"), {})
                if isinstance(pj, dict) and isinstance(pj.get("matchConfig"), dict):
                    pj["matchConfig"]["matchNumber"] = new

                print(f"      ProEl: {cur} -> {new} (sid={sid})")
                stats["proel_renamed"] += 1
                if apply:
                    await database.execute(
                        update(beach_proel_matches)
                        .where(beach_proel_matches.c.schedule_match_id == sid)
                        .values(match_number=new, data_json=pj)
                    )

            stats["tournaments_changed"] += 1

        print("\n== Podsumowanie ==")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        if not apply:
            print("\nDRY-RUN — nic nie zapisano. Uruchom z --apply (po backupie), aby wykonać.")
    finally:
        await database.disconnect()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="Wykonaj zapis (domyślnie dry-run)")
    args = ap.parse_args()
    asyncio.run(run(apply=args.apply))


if __name__ == "__main__":
    main()
