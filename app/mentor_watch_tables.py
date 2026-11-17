"""Miejsce oglądania nagrania (17.11.2026) - schemat. Reguły: `app/mentor_watch_rules.py`, trasy: `app/mentor_watch.py`.

Jedna tabela `mentor_watch_progress`: MOJE miejsce (per sędzia) osobno dla każdego nagrania meczu, wspólne dla urządzeń.
Nikt poza właścicielem wiersza go nie czyta (ani partner z pary, ani mentor). Tabela powstaje z `metadata.create_all`;
`MIGRATIONS` tylko domykają ją idempotentnie (indeksy).
"""

from sqlalchemy import Column, DateTime, Float, Index, String, Table, func


def define_tables(metadata):
    watch = Table(
        "mentor_watch_progress",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("video_id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("match_id", String, nullable=False),
        #: Ostatnio zapisane miejsce (sekunda nagrania) - „ostatni wygrywa" po `saved_at`.
        Column("position_s", Float, nullable=False),
        #: Najdalsze miejsce, do którego doszedłem (scalane przez max, niezależnie od kolejności zapisów).
        Column("furthest_s", Float, nullable=False),
        Column("duration_s", Float, nullable=True),
        #: `phone` | `tablet` | `desktop`.
        Column("device", String, nullable=True),
        #: Czas zapisu z urządzenia (obcięty do „teraz"); to on rozstrzyga, który zapis jest nowszy.
        Column("saved_at", DateTime(timezone=True), nullable=False),
        #: Kiedy klient stwierdził, że obejrzałem do okolic końca meczu (jego zegar gry >= 2 x połowa - 150 s). Lepki.
        Column("finished_at", DateTime(timezone=True), nullable=True),
        #: `saved_at` miejsca, które świadomie odrzuciłem; inny (nowszy) zapis znów może być proponowany.
        Column("dismissed_saved_at", DateTime(timezone=True), nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_mentor_watch_judge_match", watch.c.judge_id, watch.c.match_id)
    Index("ix_mentor_watch_judge_saved", watch.c.judge_id, watch.c.saved_at)
    return (watch,)


MIGRATIONS = (
    "ALTER TABLE mentor_watch_progress ADD COLUMN IF NOT EXISTS finished_at timestamptz",
    "CREATE INDEX IF NOT EXISTS ix_mentor_watch_judge_match ON mentor_watch_progress (judge_id, match_id)",
    "CREATE INDEX IF NOT EXISTS ix_mentor_watch_judge_saved ON mentor_watch_progress (judge_id, saved_at)",
)
