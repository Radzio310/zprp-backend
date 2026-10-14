"""Tabele aplikacyjne portalu BAZA pod RĘKĄ.

Publiczna hurtownia pozostaje źródłem prawdy. Te tabele przechowują wyłącznie
funkcje produktu: udostępnione raporty, bezpieczne sesje klubowe i zgłoszenia
talentów wraz z audytem.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, MetaData, String, Table, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB


def define_tables(metadata: MetaData) -> tuple[Table, ...]:
    json_type = JSON().with_variant(JSONB, "postgresql")

    reports = Table(
        "pod_reka_reports",
        metadata,
        Column("report_id", String, primary_key=True),
        Column("mode", String, nullable=False, server_default=text("'snapshot'")),
        Column("title", String, nullable=False),
        Column("config_json", json_type, nullable=False, server_default=text("'{}'")),
        Column("snapshot_json", json_type, nullable=True),
        Column("manage_token_hash", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
    )
    Index("ix_pod_reka_reports_active", reports.c.created_at, reports.c.deleted_at)

    club_sessions = Table(
        "pod_reka_club_sessions",
        metadata,
        Column("session_hash", String, primary_key=True),
        Column("username", String, nullable=False),
        Column("display_name", String, nullable=False, server_default=text("''")),
        Column("account_type", String, nullable=False),
        Column("club_id", String, nullable=False, index=True),
        Column("team_ids_json", json_type, nullable=False, server_default=text("'[]'")),
        Column("upstream_cookies_encrypted", Text, nullable=False),
        Column("csrf_hash", String, nullable=False),
        Column("scope_refreshed_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False, index=True),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
    )

    talent_templates = Table(
        "pod_reka_talent_templates",
        metadata,
        Column("template_id", Integer, primary_key=True, autoincrement=True),
        Column("name", String, nullable=False),
        Column("version", Integer, nullable=False, server_default=text("1")),
        Column("gender", String, nullable=True),
        Column("category", String, nullable=True),
        Column("position", String, nullable=True),
        Column("schema_json", json_type, nullable=False, server_default=text("'{}'")),
        Column("active", Boolean, nullable=False, server_default=text("true")),
        Column("created_by", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_pod_reka_talent_template_scope", talent_templates.c.gender, talent_templates.c.category, talent_templates.c.position, talent_templates.c.active)

    talent_submissions = Table(
        "pod_reka_talent_submissions",
        metadata,
        Column("submission_id", String, primary_key=True),
        Column("player_id", String, nullable=False, index=True),
        Column("club_id", String, nullable=False, index=True),
        Column("team_id", String, nullable=False, index=True),
        Column("season_id", String, nullable=False, index=True),
        Column("coach_subject", String, nullable=False, index=True),
        Column("template_id", Integer, ForeignKey("pod_reka_talent_templates.template_id"), nullable=False),
        Column("template_version", Integer, nullable=False),
        Column("status", String, nullable=False, server_default=text("'draft'"), index=True),
        Column("data_json", json_type, nullable=False, server_default=text("'{}'")),
        Column("public_fields_json", json_type, nullable=False, server_default=text("'[]'")),
        Column("photo_url", Text, nullable=True),
        Column("video_url", Text, nullable=True),
        Column("private_score", Float, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("published_at", DateTime(timezone=True), nullable=True),
        Column("archived_at", DateTime(timezone=True), nullable=True),
    )
    Index("ix_pod_reka_talents_public", talent_submissions.c.status, talent_submissions.c.published_at)

    talent_audit = Table(
        "pod_reka_talent_audit",
        metadata,
        Column("audit_id", Integer, primary_key=True, autoincrement=True),
        Column("submission_id", String, ForeignKey("pod_reka_talent_submissions.submission_id", ondelete="CASCADE"), nullable=False, index=True),
        Column("actor", String, nullable=False),
        Column("action", String, nullable=False),
        Column("changes_json", json_type, nullable=False, server_default=text("'{}'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    push_subscriptions = Table(
        "pod_reka_push_subscriptions",
        metadata,
        Column("subscription_id", String, primary_key=True),
        Column("endpoint", Text, nullable=False, unique=True),
        Column("p256dh", Text, nullable=False),
        Column("auth", Text, nullable=False),
        Column("topics_json", json_type, nullable=False, server_default=text("'[]'")),
        Column("delete_token_hash", String, nullable=False),
        Column("user_agent_hash", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_sent_at", DateTime(timezone=True), nullable=True),
        Column("revoked_at", DateTime(timezone=True), nullable=True, index=True),
    )

    return reports, club_sessions, talent_templates, talent_submissions, talent_audit, push_subscriptions
