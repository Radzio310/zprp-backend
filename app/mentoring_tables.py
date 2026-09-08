"""Schema only: safe to inspect without connecting to production."""
from sqlalchemy import Table, Column, String, Boolean, DateTime, JSON, Integer, ForeignKey, func


def define_tables(metadata):
    config = Table("mentoring_config", metadata,
        Column("province", String, primary_key=True),
        Column("enabled", Boolean, nullable=False, default=False),
        Column("manager_ids", JSON, nullable=False, default=list))
    pairs = Table("mentoring_pairs", metadata,
        Column("id", String, primary_key=True),
        Column("province", String, nullable=False),
        Column("judge_ids", JSON, nullable=False),
        Column("created_by", String, nullable=False),
        Column("baseline_at", DateTime(timezone=True)),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("ended_at", DateTime(timezone=True)))
    members = Table("mentoring_active_members", metadata,
        Column("judge_id", String, primary_key=True),
        Column("pair_id", String, ForeignKey("mentoring_pairs.id"), nullable=False),
        Column("seen_at", DateTime(timezone=True)))
    mentors = Table("mentoring_assignments", metadata,
        Column("pair_id", String, ForeignKey("mentoring_pairs.id"), primary_key=True),
        Column("mentor_id", String, primary_key=True),
        Column("started_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("ended_at", DateTime(timezone=True)),
        Column("show_home", Boolean, nullable=False, default=True),
        Column("notify", Boolean, nullable=False, default=True))
    audit = Table("mentoring_audit", metadata,
        Column("id", Integer, primary_key=True),
        Column("actor_id", String, nullable=False),
        Column("pair_id", String),
        Column("action", String, nullable=False),
        Column("data", JSON, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()))
    return config, pairs, members, mentors, audit
