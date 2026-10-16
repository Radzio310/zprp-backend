"""
Tabele egzaminu NA ŻYWO (etap 5, 16.10.2026) - same schematy, bez połączenia z bazą.

  - `exam_live_sessions`      sesja prowadzona przez jedną osobę (PIN, token QR, faza, konfiguracja,
                              po zakończeniu trwały wynik w `result_json`),
  - `exam_live_participants`  uczestnicy: użytkownik BAZY (judge_id) albo gość z przeglądarki (nick),
  - `exam_live_answers`       odpowiedzi z czasem i punktami liczonymi przez serwer (trwałe wyniki).

Stan gniazd WebSocket NIE leży w bazie (patrz `exam_live_hub.py`), ale faza, termin pytania i wyniki
tak - dzięki temu restart procesu niczego nie gubi, a klienci po ponownym połączeniu robią GET.
JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem.
"""

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Index, Integer, String, Table, Text, UniqueConstraint, func,
)

MIGRATIONS: list = []


def define_tables(metadata):
    sessions = Table(
        "exam_live_sessions",
        metadata,
        Column("id", String, primary_key=True),
        #: 6 cyfr; unikalny wśród AKTYWNYCH sesji (pilnuje kod, po zakończeniu PIN wraca do puli).
        Column("pin", String, nullable=False, index=True),
        #: Nie do zgadnięcia token z adresu rzutnika i z kodu QR.
        Column("token", String, nullable=False, unique=True),
        Column("host_id", String, nullable=False, index=True),
        Column("host_name", String, nullable=True),
        #: national | province
        Column("scope", String, nullable=False),
        Column("province", String, nullable=True),
        Column("exam_id", String, nullable=True, index=True),
        Column("title", String, nullable=False),
        #: quiz | exam
        Column("character", String, nullable=False, default="quiz"),
        #: full | tiles - co widzi telefon w fazie pytania.
        Column("phone_view", String, nullable=False, default="full"),
        Column("guests_allowed", Boolean, nullable=False, default=False),
        Column("config_json", Text, nullable=False, default="{}"),
        Column("bank_version", String, nullable=False),
        Column("question_ids_json", Text, nullable=False, default="[]"),
        #: lobby | question | reveal | leaderboard | end
        Column("phase", String, nullable=False, default="lobby"),
        Column("q_index", Integer, nullable=False, default=-1),
        Column("phase_started_at", DateTime(timezone=True), nullable=True),
        Column("deadline_at", DateTime(timezone=True), nullable=True),
        #: Rośnie przy każdej zmianie widocznej dla klientów (polling pyta „od rev").
        Column("rev", Integer, nullable=False, default=0),
        Column("result_json", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("ended_at", DateTime(timezone=True), nullable=True),
    )
    participants = Table(
        "exam_live_participants",
        metadata,
        Column("id", String, primary_key=True),
        Column("session_id", String, nullable=False, index=True),
        #: user | guest
        Column("kind", String, nullable=False, default="user"),
        Column("judge_id", String, nullable=True),
        Column("name", String, nullable=False),
        #: Sekret gościa (jedyne, co go identyfikuje po odświeżeniu strony).
        Column("guest_token", String, nullable=True, unique=True),
        Column("score", Integer, nullable=False, default=0),
        Column("correct_count", Integer, nullable=False, default=0),
        Column("answered_count", Integer, nullable=False, default=0),
        Column("joined_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        UniqueConstraint("session_id", "judge_id", name="ux_exam_live_participant_judge"),
    )
    answers = Table(
        "exam_live_answers",
        metadata,
        Column("session_id", String, primary_key=True),
        Column("participant_id", String, primary_key=True),
        Column("qid", String, primary_key=True),
        Column("q_index", Integer, nullable=False),
        Column("selected_json", Text, nullable=False, default="[]"),
        #: Ułamek poprawności 0-1 (przy wielokrotnym wyborze może być częściowy).
        Column("fraction", Float, nullable=False, default=0.0),
        Column("points", Integer, nullable=False, default=0),
        Column("elapsed_ms", Integer, nullable=True),
        Column("answered_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_exam_live_answers_session", answers.c.session_id, answers.c.q_index)
    return sessions, participants, answers
