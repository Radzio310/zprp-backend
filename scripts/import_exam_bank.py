"""Import banku pytań do egzaminów (wersjonowany, idempotentny).

Użycie (z katalogu zprp-backend, z ustawionym DATABASE_URL):
    python -m scripts.import_exam_bank [ścieżka/do/questionsDefault.json]

Bez argumentu bierze kopię z app/data/exam_questions_default.json. Ten sam katalog
drugi raz nic nie dubluje; zmieniony dostaje nową wersję i staje się bieżący.
Egzaminy już utworzone zostają przy wersji, z którą powstały.
"""
import asyncio
import json
import sys
from pathlib import Path


async def main(path: Path) -> None:
    from app import db as D
    from app import exam_service as S

    data = json.loads(path.read_text(encoding="utf-8"))
    await D.database.connect()
    try:
        async def no_judges(_province):
            return []

        async def no_push(*_args):
            return None

        st = S.Store(database=D.database, t=S.Tables(
            banks=D.exam_banks, bank_questions=D.exam_bank_questions, definitions=D.exam_definitions,
            attempts=D.exam_attempts, answers=D.exam_answers, events=D.exam_events,
            reminders=D.exam_reminders_sent, province_events=D.province_events), judges=no_judges, push=no_push)
        print(await S.import_bank(st, data))
    finally:
        await D.database.disconnect()


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "app" / "data" / "exam_questions_default.json"
    asyncio.run(main(target))
