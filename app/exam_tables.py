"""
Tabele modułu „Egzamin z przepisów" (16.10.2026) - same schematy, bez połączenia z bazą.

  - `exam_banks`            wersje banku pytań (hash zawartości = tożsamość wersji),
  - `exam_bank_questions`   pytania danej wersji (klucze odpowiedzi TYLKO tu i w ocenie),
  - `exam_definitions`      egzaminy (konfiguracja, okno, wydarzenia, unieważnione pytania),
  - `exam_attempts`         podejścia (arkusz, stan, wynik, urządzenie),
  - `exam_answers`          odpowiedzi z czasami liczonymi przez serwer,
  - `exam_events`           zdarzenia antyoszustwa (wyjścia, zrzuty, flagi czasu),
  - `exam_reminders_sent`   dziennik przypomnień push (dedup).

Tabele `exam_live_*` (egzamin na żywo, etap 5) są w `app/exam_live_tables.py`.
JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem.
"""

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Index, Integer, String, Table, Text, UniqueConstraint, func,
)

MIGRATIONS: list = []


def define_tables(metadata):
    banks = Table(
        "exam_banks",
        metadata,
        Column("version", String, primary_key=True),
        Column("content_hash", String, nullable=False, unique=True),
        Column("meta_json", Text, nullable=False, default="{}"),
        Column("question_count", Integer, nullable=False, default=0),
        Column("is_current", Boolean, nullable=False, default=False, index=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    bank_questions = Table(
        "exam_bank_questions",
        metadata,
        Column("bank_version", String, primary_key=True),
        Column("qid", String, primary_key=True),
        Column("number", String, nullable=False),
        Column("rule", Integer, nullable=True, index=True),
        Column("kind", String, nullable=True),
        Column("multi", Boolean, nullable=False, default=False),
        Column("topics_json", Text, nullable=False, default="[]"),
        Column("text", Text, nullable=False),
        Column("answers_json", Text, nullable=False),
        Column("refs_json", Text, nullable=False, default="[]"),
        Column("curiosity", Text, nullable=True),
    )
    definitions = Table(
        "exam_definitions",
        metadata,
        Column("id", String, primary_key=True),
        #: national | province
        Column("scope", String, nullable=False, index=True),
        #: Zapis wydarzeń okręgowych, np. „ŚLĄSKIE"; NULL dla krajowego.
        Column("province", String, nullable=True, index=True),
        Column("name", String, nullable=False),
        Column("description", Text, nullable=True),
        Column("template", String, nullable=True),
        Column("config_json", Text, nullable=False),
        Column("bank_version", String, nullable=False),
        #: Wspólny zestaw albo pula do losowania per osoba (lista qid).
        Column("question_ids_json", Text, nullable=False, default="[]"),
        #: {qid: "drop" | "credit"} - unieważnione pytania.
        Column("voided_json", Text, nullable=False, default="{}"),
        #: {"ŚLĄSKIE": 123, ...} - wydarzenia okręgowe tego egzaminu.
        Column("event_ids_json", Text, nullable=False, default="{}"),
        Column("opens_at", DateTime(timezone=True), nullable=False, index=True),
        Column("closes_at", DateTime(timezone=True), nullable=False, index=True),
        Column("created_by", String, nullable=True),
        Column("created_by_name", String, nullable=True),
        #: Idempotencja POST /exams: localId szkicu z telefonu (ten sam autor + klucz = ten sam egzamin).
        Column("client_key", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
    )
    attempts = Table(
        "exam_attempts",
        metadata,
        Column("id", String, primary_key=True),
        Column("exam_id", String, nullable=False, index=True),
        Column("judge_id", String, nullable=False, index=True),
        Column("judge_name", String, nullable=True),
        Column("province", String, nullable=True),
        Column("attempt_no", Integer, nullable=False),
        #: in_progress | submitted | expired
        Column("status", String, nullable=False, default="in_progress"),
        Column("finish_reason", String, nullable=True),
        Column("started_at", DateTime(timezone=True), nullable=False),
        Column("deadline_at", DateTime(timezone=True), nullable=False),
        Column("finished_at", DateTime(timezone=True), nullable=True),
        Column("current_index", Integer, nullable=False, default=0),
        Column("paper_json", Text, nullable=False),
        Column("score_json", Text, nullable=True),
        Column("percent", Float, nullable=True),
        Column("passed", Boolean, nullable=True),
        Column("device_id", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        UniqueConstraint("exam_id", "judge_id", "attempt_no", name="ux_exam_attempt_no"),
    )
    answers = Table(
        "exam_answers",
        metadata,
        Column("attempt_id", String, primary_key=True),
        Column("qid", String, primary_key=True),
        Column("position", Integer, nullable=False),
        Column("shown_at", DateTime(timezone=True), nullable=True),
        Column("answered_at", DateTime(timezone=True), nullable=True),
        Column("selected_json", Text, nullable=True),
        Column("timed_out", Boolean, nullable=False, default=False),
        Column("elapsed_ms", Integer, nullable=True),
        Column("changes", Integer, nullable=False, default=0),
        Column("flags_json", Text, nullable=False, default="[]"),
    )
    events = Table(
        "exam_events",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("exam_id", String, nullable=False, index=True),
        Column("attempt_id", String, nullable=False, index=True),
        Column("judge_id", String, nullable=False),
        Column("kind", String, nullable=False),
        Column("detail_json", Text, nullable=False, default="{}"),
        Column("client_ts_ms", Float, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    reminders = Table(
        "exam_reminders_sent",
        metadata,
        Column("exam_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("kind", String, primary_key=True),
        Column("sent_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_exam_answers_attempt", answers.c.attempt_id)
    return banks, bank_questions, definitions, attempts, answers, events, reminders
