"""Sytuacje z arkuszy - poprawiony czas w nagraniu (23.11.2026). Kontrakt: `docs/mentor-panel.md`, sekcja 17.

Sytuacja z arkusza delegata/mentora zna tylko minutę meczu; sekundę nagrania panel wylicza z osi ProEla.
Para i mentorzy mogą ją poprawić RAZ dla wszystkich: początek i koniec w danym nagraniu (jak klip).
Klucz sytuacji (`situation_key`) jest stabilny - skrót treści sytuacji (`R.situation_key`).
"""

from sqlalchemy import Column, DateTime, Float, Index, String, Table, func


def define_tables(metadata):
    times = Table(
        "mentor_situation_times",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("match_id", String, nullable=False),
        Column("video_id", String, nullable=False),
        Column("situation_key", String, nullable=False),
        Column("start_s", Float, nullable=False),
        Column("end_s", Float, nullable=False),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Index("ux_mentor_situation_times", "pair_id", "match_id", "video_id", "situation_key", unique=True),
    )
    return (times,)
