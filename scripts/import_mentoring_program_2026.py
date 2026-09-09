"""Import the complete pairs from the 2026 Program Mentor presentation.

Dry-run is the default. Use ``--apply`` only after the mentoring migration is
deployed. The import is idempotent: an existing exact pair is reused and the
listed mentor is only added/reactivated; unrelated existing pair membership is
never overwritten.
"""
import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select, text, update

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.mentoring_rules import CROSS_PROVINCE, json_value


IMPORT_ACTOR = "program-mentor-presentation-2026"


@dataclass(frozen=True)
class PairSeed:
    judges: tuple[str, str]
    judge_names: tuple[str, str]
    mentor: str
    mentor_name: str


SEEDS = (
    PairSeed(("3614", "3613"), ("Dawid Celoch", "Mikołaj Sulisz"), "76", "Bogdan Lemanowicz"),
    PairSeed(("4694", "2767"), ("Eryk Jaśkowiak", "Patryk Żurawski"), "87", "Włodzimierz Chmielecki"),
    PairSeed(("2833", "2832"), ("Maciej Mleczko", "Krzysztof Paczyński"), "110", "Grzegorz Wojtyczka"),
    PairSeed(("3842", "3859"), ("Michał Jakubek", "Mikołaj Marcinkowski"), "186", "Mariusz Wołowicz"),
    PairSeed(("4291", "5124"), ("Krzysztof Witkowicz", "Radosław Witkowicz"), "425", "Artur Jędrycha"),
    PairSeed(("2847", "1447"), ("Bartosz Sandurski", "Michał Zalewski"), "666", "Marek Góralczyk"),
    PairSeed(("4856", "5491"), ("Kamil Marszałek", "Jakub Węgrzyn"), "200", "Cezary Kulesza"),
    PairSeed(("5540", "5539"), ("Piotr Kulesza", "Wiktor Paradowski"), "585", "Mirosław Majchrowski"),
    PairSeed(("3769", "3773"), ("Bartosz Osobiński", "Filip Rutecki"), "96", "Andrzej Kierczak"),
    PairSeed(("5159", "3646"), ("Filip Kalinowski", "Stanisław Kluczkowski"), "146", "Łukasz Kamrowski"),
    PairSeed(("3610", "2449"), ("Paweł Domański", "Marcin Mikołajów"), "155", "Andrzej Jaworski"),
    PairSeed(("3832", "4539"), ("Dawid Borucki", "Jakub Wasiak"), "120", "Jakub Tarczykowski"),
    PairSeed(("5512", "5127"), ("Kacper Bendych", "Wiktor Hordyński"), "104", "Marcin Zubek"),
    PairSeed(("987", "4654"), ("Kacper Pisarek", "Franciszek Rożek"), "90", "Tomasz Christ"),
    PairSeed(("5075", "5704"), ("Marta Berus", "Wiktoria Zielińska"), "208", "Andrzej Gratunik"),
)


SKIPPED_INCOMPLETE = (
    "Przemysław Chojnacki / Jakub Saluk — brak Leszka Sołodko",
    "Marcin Kret / Szymon Świętek — brak Marcina Kreta i Tomasza Olesińskiego",
    "Jakub Karaś / Szymon Leszczyński — brak Mirosława Bauma",
    "Jakub Firlej / Patryk Łabuz — brak Patryka Łabuza",
    "Marek Pietrus / Daniel Sętowski — mentor Cezary Figarski nie ma przypisanego okręgu",
)


def pair_province(seed: PairSeed, people: dict[str, dict]) -> str:
    provinces = {
        str(people[judge_id].get("province") or "").strip().upper()
        for judge_id in seed.judges
    }
    if "" in provinces:
        raise ValueError("sędzia bez przypisanego okręgu")
    return next(iter(provinces)) if len(provinces) == 1 else CROSS_PROVINCE


async def run(apply: bool) -> None:
    # Import dopiero po obsłużeniu argparse. Dzięki temu ``--help`` działa także
    # lokalnie bez produkcyjnego DATABASE_URL (app.db inicjalizuje cały schemat).
    from app.db import (
        database,
        province_judges,
        mentoring_pairs as pairs,
        mentoring_members as members,
        mentoring_assignments as assignments,
        mentoring_audit as audit,
    )

    await database.connect()
    try:
        wanted_ids = {value for seed in SEEDS for value in (*seed.judges, seed.mentor)}
        person_rows = await database.fetch_all(
            select(province_judges).where(province_judges.c.judge_id.in_(wanted_ids))
        )
        people = {str(row["judge_id"]): dict(row) for row in person_rows}
        active_pair_rows = await database.fetch_all(
            select(pairs).where(pairs.c.ended_at.is_(None))
        )
        active_pairs = {
            frozenset(str(value) for value in json_value(row["judge_ids"], [])): dict(row)
            for row in active_pair_rows
        }
        member_rows = await database.fetch_all(select(members))
        occupied = {str(row["judge_id"]): str(row["pair_id"]) for row in member_rows}

        planned = []
        skipped = []
        reused = []
        for seed in SEEDS:
            missing = [value for value in (*seed.judges, seed.mentor) if value not in people]
            if missing:
                skipped.append((seed, f"brak ID: {', '.join(missing)}"))
                continue
            without_province = [
                value
                for value in (*seed.judges, seed.mentor)
                if not str(people[value].get("province") or "").strip()
            ]
            if without_province:
                skipped.append(
                    (seed, f"brak przypisanego okręgu dla ID: {', '.join(without_province)}")
                )
                continue
            try:
                province = pair_province(seed, people)
            except ValueError as error:
                skipped.append((seed, str(error)))
                continue
            exact = active_pairs.get(frozenset(seed.judges))
            if exact:
                reused.append((seed, exact, province))
                continue
            conflicts = [judge for judge in seed.judges if judge in occupied]
            if conflicts:
                skipped.append((seed, f"aktywna inna para dla ID: {', '.join(conflicts)}"))
                continue
            planned.append((seed, province))

        mode = "ZAPIS" if apply else "DRY-RUN"
        print(f"[{mode}] nowe pary: {len(planned)}, istniejące: {len(reused)}, pominięte: {len(skipped)}")
        for seed, province in planned:
            print(f"  + {' / '.join(seed.judge_names)} → {seed.mentor_name} [{province}]")
        for seed, _, province in reused:
            print(f"  = {' / '.join(seed.judge_names)} → {seed.mentor_name} [{province}]")
        for seed, reason in skipped:
            print(f"  ! {' / '.join(seed.judge_names)}: {reason}")
        print("Pozycje świadomie pominięte z prezentacji:")
        for line in SKIPPED_INCOMPLETE:
            print(f"  - {line}")

        if not apply:
            print("Brak zmian w bazie. Uruchom ponownie z --apply, aby zatwierdzić import.")
            return

        async with database.transaction():
            await database.execute(text("SELECT pg_advisory_xact_lock(7419021)"))
            imported_at = datetime.now(timezone.utc)
            for seed, province in planned:
                pair_id = str(uuid4())
                await database.execute(
                    pairs.insert().values(
                        id=pair_id,
                        province=province,
                        judge_ids=sorted(seed.judges),
                        created_by=IMPORT_ACTOR,
                        baseline_at=imported_at,
                    )
                )
                for judge_id in seed.judges:
                    await database.execute(
                        members.insert().values(judge_id=judge_id, pair_id=pair_id)
                    )
                await database.execute(
                    assignments.insert().values(
                        pair_id=pair_id,
                        mentor_id=seed.mentor,
                        started_at=imported_at,
                        show_home=True,
                        notify=True,
                    )
                )
                await database.execute(
                    audit.insert().values(
                        actor_id=IMPORT_ACTOR,
                        pair_id=pair_id,
                        action="presentation_import",
                        data={
                            "judge_ids": list(seed.judges),
                            "mentor_ids": [seed.mentor],
                            "province": province,
                        },
                    )
                )

            for seed, exact, _ in reused:
                link = await database.fetch_one(
                    select(assignments)
                    .where(assignments.c.pair_id == exact["id"])
                    .where(assignments.c.mentor_id == seed.mentor)
                )
                if link and link["ended_at"] is None:
                    continue
                if link:
                    await database.execute(
                        update(assignments)
                        .where(assignments.c.pair_id == exact["id"])
                        .where(assignments.c.mentor_id == seed.mentor)
                        .values(
                            started_at=imported_at,
                            ended_at=None,
                            show_home=True,
                            notify=True,
                        )
                    )
                else:
                    await database.execute(
                        assignments.insert().values(
                            pair_id=exact["id"],
                            mentor_id=seed.mentor,
                            started_at=imported_at,
                            show_home=True,
                            notify=True,
                        )
                    )
                await database.execute(
                    audit.insert().values(
                        actor_id=IMPORT_ACTOR,
                        pair_id=exact["id"],
                        action="presentation_mentor_attached",
                        data={"mentor_ids": [seed.mentor]},
                    )
                )
        print("Import zakończony. Istniejące, niezwiązane pary nie zostały zmienione.")
    finally:
        await database.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="zapisz zweryfikowane pozycje")
    args = parser.parse_args()
    asyncio.run(run(args.apply))
