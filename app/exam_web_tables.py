"""
Tabele egzaminu na komputerze (24.10.2026) - same schematy, bez połączenia z bazą.

  - `exam_web_codes`     kody QR: logowanie komputera (`login`) i parowanie strażnika (`guard`),
  - `exam_web_links`     zalogowany komputer + sparowany telefon-strażnik,
  - `exam_web_sessions`  sesja egzaminu w przeglądarce (jedna aktywna na konto).
Nowe tabele powstają przez `create_all` - bez migracji kolumn.
"""
from sqlalchemy import Column, DateTime, Index, Integer, String, Table, Text, func


def define_tables(metadata):
    codes = Table(
        "exam_web_codes",
        metadata,
        Column("code", String, primary_key=True),
        #: login | guard
        Column("purpose", String, nullable=False, default="login"),
        Column("poll_hash", String, nullable=False),
        #: Dla `guard`: komputer, do którego dołącza telefon, i wymagany sędzia.
        Column("link_id", String, nullable=True),
        Column("judge_id", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("approved_by", String, nullable=True),
        Column("approved_name", String, nullable=True),
        Column("approved_at", DateTime(timezone=True), nullable=True),
        Column("device_id", String, nullable=True),
        Column("device_label", String, nullable=True),
        Column("consumed_at", DateTime(timezone=True), nullable=True),
        Column("user_agent", String, nullable=True),
    )
    links = Table(
        "exam_web_links",
        metadata,
        Column("id", String, primary_key=True),
        Column("judge_id", String, nullable=False, index=True),
        Column("judge_name", String, nullable=True),
        Column("guard_device_id", String, nullable=True, index=True),
        Column("guard_label", String, nullable=True),
        Column("guard_seen_at", DateTime(timezone=True), nullable=True),
        #: ok | away (aplikacja w tle)
        Column("guard_state", String, nullable=True),
        Column("user_agent", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
    )
    sessions = Table(
        "exam_web_sessions",
        metadata,
        Column("id", String, primary_key=True),
        Column("link_id", String, nullable=False, index=True),
        Column("judge_id", String, nullable=False, index=True),
        Column("exam_id", String, nullable=False),
        Column("attempt_id", String, nullable=True, index=True),
        Column("browser_id", String, nullable=True),
        #: active | ended | replaced
        Column("status", String, nullable=False, default="active"),
        Column("started_at", DateTime(timezone=True), nullable=False),
        Column("beat_at", DateTime(timezone=True), nullable=True),
        Column("ended_at", DateTime(timezone=True), nullable=True),
        Column("end_reason", String, nullable=True),
        Column("violations", Integer, nullable=False, default=0),
        #: Ostatni stan z przeglądarki dla strażnika: {index,total,answered,deadline_at,fullscreen,visible}.
        Column("state_json", Text, nullable=False, default="{}"),
        #: Strażnik zamilkł - zapisane raz na przerwę (nie co uderzenie serca).
        Column("guard_alarm", String, nullable=True),
        #: Sygnały ciche (zablokowane kopiowanie, prawy klik, kliknięcia poza pytaniem) - do flag komisji.
        Column("quiet_json", Text, nullable=False, default="{}"),
        Column("user_agent", String, nullable=True),
    )
    Index("ix_exam_web_sessions_judge_status", sessions.c.judge_id, sessions.c.status)
    return codes, links, sessions
