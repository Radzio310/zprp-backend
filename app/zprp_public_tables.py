"""Tabele lokalnej, publicznej hurtowni danych ``rozgrywki.zprp.pl``.

Nazwy mają wspólny prefiks, żeby warstwa nie mieszała się z istniejącymi
snapshotami okręgowymi i scraperami wymagającymi logowania do ``baza.zprp.pl``.
W JSON-ach tej warstwy nie wolno przechowywać pełnych dat urodzenia ani danych
o badaniach zawodników (pilnuje tego ``app.zprp_public.client``).
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB


def define_tables(metadata: MetaData) -> tuple[Table, ...]:
    json_type = JSON().with_variant(JSONB, "postgresql")

    seasons = Table(
        "zprp_public_seasons",
        metadata,
        Column("season_id", String, primary_key=True),
        Column("start_year", Integer, nullable=True, index=True),
        Column("name", String, nullable=False),
        Column("active", Boolean, nullable=False, server_default=text("false")),
        Column("competition_count", Integer, nullable=False, server_default=text("0")),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    associations = Table(
        "zprp_public_associations",
        metadata,
        Column("association_id", String, primary_key=True),
        Column("name", String, nullable=False),
        Column("code", String, nullable=True, index=True),
        Column("full_name", String, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    clubs = Table(
        "zprp_public_clubs",
        metadata,
        Column("club_id", String, primary_key=True),
        Column("association_id", String, nullable=True, index=True),
        Column("name", String, nullable=False, index=True),
        Column("member", Boolean, nullable=True),
        Column("city", String, nullable=True, index=True),
        Column("postal_code", String, nullable=True),
        Column("street", String, nullable=True),
        Column("email", String, nullable=True),
        Column("website", String, nullable=True),
        Column("phone_1", String, nullable=True),
        Column("phone_2", String, nullable=True),
        Column("archived", Boolean, nullable=False, server_default=text("false")),
        Column("logo_url", Text, nullable=True),
        Column("source_updated_at", String, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("details_fetched_at", DateTime(timezone=True), nullable=True),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    club_licenses = Table(
        "zprp_public_club_licenses",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("club_id", String, ForeignKey("zprp_public_clubs.club_id", ondelete="CASCADE"), nullable=False),
        Column("season_name", String, nullable=False),
        Column("name", String, nullable=False),
        Column("status", String, nullable=True),
        Column("gender", String, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        UniqueConstraint("club_id", "season_name", "name", "gender", name="uq_zprp_public_club_license"),
    )
    Index("ix_zprp_public_club_licenses_club_season", club_licenses.c.club_id, club_licenses.c.season_name)

    teams = Table(
        "zprp_public_teams",
        metadata,
        Column("team_id", String, primary_key=True),
        Column("season_id", String, primary_key=True),
        Column("club_id", String, nullable=True, index=True),
        Column("source_row_id", String, nullable=True),
        Column("season_name", String, nullable=True, index=True),
        Column("name", String, nullable=False, index=True),
        Column("gender", String, nullable=True, index=True),
        Column("category", String, nullable=True, index=True),
        Column("city", String, nullable=True),
        Column("postal_code", String, nullable=True),
        Column("street", String, nullable=True),
        Column("email", String, nullable=True),
        Column("website", String, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("roster_fetched_at", DateTime(timezone=True), nullable=True),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_zprp_public_teams_season_category", teams.c.season_id, teams.c.category, teams.c.gender)

    players = Table(
        "zprp_public_players",
        metadata,
        Column("player_id", String, primary_key=True),
        Column("first_name", String, nullable=False, index=True),
        Column("last_name", String, nullable=False, index=True),
        Column("gender", String, nullable=True),
        Column("birth_year", Integer, nullable=True, index=True),
        Column("photo_url", Text, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    rosters = Table(
        "zprp_public_team_rosters",
        metadata,
        Column("team_id", String, primary_key=True),
        Column("season_id", String, primary_key=True),
        Column("player_id", String, ForeignKey("zprp_public_players.player_id", ondelete="CASCADE"), primary_key=True),
        Column("shirt_number", String, nullable=True),
        Column("position_id", String, nullable=True),
        Column("position", String, nullable=True),
        Column("active", Boolean, nullable=False, server_default=text("true")),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    competitions = Table(
        "zprp_public_competitions",
        metadata,
        Column("competition_id", String, primary_key=True),
        Column("season_id", String, nullable=False, index=True),
        Column("association_id", String, nullable=True, index=True),
        Column("association_name", String, nullable=True),
        Column("name", String, nullable=False, index=True),
        Column("gender", String, nullable=True, index=True),
        Column("category", String, nullable=True, index=True),
        Column("code", String, nullable=True, index=True),
        Column("export_code", String, nullable=True),
        Column("team_count", Integer, nullable=False, server_default=text("0")),
        Column("started", Boolean, nullable=False, server_default=text("false")),
        Column("protocol_type", String, nullable=True),
        Column("regulations_url", Text, nullable=True),
        Column("has_groups", Boolean, nullable=False, server_default=text("false")),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_zprp_public_competitions_filters", competitions.c.season_id, competitions.c.association_id, competitions.c.category, competitions.c.gender)

    rounds = Table(
        "zprp_public_rounds",
        metadata,
        Column("round_id", String, primary_key=True),
        Column("competition_id", String, ForeignKey("zprp_public_competitions.competition_id", ondelete="CASCADE"), nullable=False, index=True),
        Column("name", String, nullable=False),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    matchdays = Table(
        "zprp_public_matchdays",
        metadata,
        Column("matchday_id", String, primary_key=True),
        Column("round_id", String, ForeignKey("zprp_public_rounds.round_id", ondelete="CASCADE"), nullable=False, index=True),
        Column("number", Integer, nullable=True),
        Column("sequence", Integer, nullable=True),
        Column("name", String, nullable=False),
        Column("starts_on", String, nullable=True),
        Column("ends_on", String, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    matches = Table(
        "zprp_public_matches",
        metadata,
        Column("match_id", String, primary_key=True),
        Column("season_id", String, nullable=True, index=True),
        Column("competition_id", String, nullable=True, index=True),
        Column("round_id", String, nullable=True),
        Column("matchday_id", String, nullable=True, index=True),
        Column("match_code", String, nullable=True, index=True),
        Column("competition_name", String, nullable=True),
        Column("round_name", String, nullable=True),
        Column("matchday_name", String, nullable=True),
        Column("home_team_id", String, nullable=True, index=True),
        Column("away_team_id", String, nullable=True, index=True),
        Column("home_club_id", String, nullable=True),
        Column("away_club_id", String, nullable=True),
        Column("home_team_name", String, nullable=True),
        Column("away_team_name", String, nullable=True),
        Column("scheduled_at", DateTime(timezone=False), nullable=True, index=True),
        Column("played_at", DateTime(timezone=False), nullable=True),
        Column("halftime_home", Integer, nullable=True),
        Column("halftime_away", Integer, nullable=True),
        Column("score_home", Integer, nullable=True),
        Column("score_away", Integer, nullable=True),
        Column("winner", String, nullable=True),
        Column("withdrawn", Boolean, nullable=False, server_default=text("false")),
        Column("walkover_team_id", String, nullable=True),
        Column("protocol_approved", Boolean, nullable=False, server_default=text("false")),
        Column("spectators", Integer, nullable=True),
        Column("stream_url", Text, nullable=True),
        Column("tickets_url", Text, nullable=True),
        Column("comment", Text, nullable=True),
        Column("referee_1_id", String, nullable=True),
        Column("referee_1_name", String, nullable=True),
        Column("referee_2_id", String, nullable=True),
        Column("referee_2_name", String, nullable=True),
        Column("delegate_1_id", String, nullable=True),
        Column("delegate_1_name", String, nullable=True),
        Column("delegate_2_id", String, nullable=True),
        Column("delegate_2_name", String, nullable=True),
        Column("secretary_id", String, nullable=True),
        Column("secretary_name", String, nullable=True),
        Column("timekeeper_id", String, nullable=True),
        Column("timekeeper_name", String, nullable=True),
        Column("venue_name", String, nullable=True),
        Column("venue_city", String, nullable=True),
        Column("venue_street", String, nullable=True),
        Column("venue_number", String, nullable=True),
        Column("venue_capacity", Integer, nullable=True),
        Column("upstream_changed_at", String, nullable=True),
        Column("details_fetched_at", DateTime(timezone=True), nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_zprp_public_matches_schedule_comp", matches.c.scheduled_at, matches.c.competition_id)

    match_players = Table(
        "zprp_public_match_players",
        metadata,
        Column("match_id", String, ForeignKey("zprp_public_matches.match_id", ondelete="CASCADE"), primary_key=True),
        Column("team_id", String, primary_key=True),
        Column("player_id", String, ForeignKey("zprp_public_players.player_id", ondelete="CASCADE"), primary_key=True),
        Column("side", String, nullable=False),
        Column("shirt_number", String, nullable=True),
        Column("position", String, nullable=True),
        Column("goals", Integer, nullable=False, server_default=text("0")),
        Column("warnings", Integer, nullable=False, server_default=text("0")),
        Column("two_minutes", Integer, nullable=False, server_default=text("0")),
        Column("disqualifications", Integer, nullable=False, server_default=text("0")),
        Column("direct_red_cards", Integer, nullable=False, server_default=text("0")),
        Column("penalty_attempts", Integer, nullable=False, server_default=text("0")),
        Column("penalty_goals", Integer, nullable=False, server_default=text("0")),
        Column("shootout_attempts", Integer, nullable=False, server_default=text("0")),
        Column("shootout_goals", Integer, nullable=False, server_default=text("0")),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    match_staff = Table(
        "zprp_public_match_staff",
        metadata,
        Column("match_id", String, ForeignKey("zprp_public_matches.match_id", ondelete="CASCADE"), primary_key=True),
        Column("team_id", String, primary_key=True),
        Column("person_id", String, primary_key=True),
        Column("side", String, nullable=False),
        Column("first_name", String, nullable=True),
        Column("last_name", String, nullable=True),
        Column("role", String, nullable=True),
        Column("function", String, nullable=True),
        Column("license", String, nullable=True),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    standings = Table(
        "zprp_public_standings",
        metadata,
        Column("competition_id", String, primary_key=True),
        Column("table_id", String, primary_key=True),
        Column("group_id", String, primary_key=True, server_default=text("''")),
        Column("team_id", String, primary_key=True),
        Column("club_id", String, nullable=True),
        Column("position", Integer, nullable=True),
        Column("team_name", String, nullable=False),
        Column("matches", Integer, nullable=False, server_default=text("0")),
        Column("wins", Integer, nullable=False, server_default=text("0")),
        Column("draws", Integer, nullable=False, server_default=text("0")),
        Column("losses", Integer, nullable=False, server_default=text("0")),
        Column("goals_for", Integer, nullable=False, server_default=text("0")),
        Column("goals_against", Integer, nullable=False, server_default=text("0")),
        Column("goal_difference", Integer, nullable=False, server_default=text("0")),
        Column("points", Integer, nullable=False, server_default=text("0")),
        Column("extra_json", json_type, nullable=False, server_default=text("'{}'")),
        Column("source_hash", String, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    scorers = Table(
        "zprp_public_scorers",
        metadata,
        Column("competition_id", String, primary_key=True),
        Column("player_id", String, ForeignKey("zprp_public_players.player_id", ondelete="CASCADE"), primary_key=True),
        Column("team_id", String, primary_key=True),
        Column("team_name", String, nullable=True),
        Column("goals", Integer, nullable=False, server_default=text("0")),
        Column("matches", Integer, nullable=False, server_default=text("0")),
        Column("average", String, nullable=True),
        Column("warnings", Integer, nullable=False, server_default=text("0")),
        Column("two_minutes", Integer, nullable=False, server_default=text("0")),
        Column("disqualifications", Integer, nullable=False, server_default=text("0")),
        Column("direct_red_cards", Integer, nullable=False, server_default=text("0")),
        Column("penalty_attempts", Integer, nullable=False, server_default=text("0")),
        Column("penalty_goals", Integer, nullable=False, server_default=text("0")),
        Column("shootout_attempts", Integer, nullable=False, server_default=text("0")),
        Column("shootout_goals", Integer, nullable=False, server_default=text("0")),
        Column("source_hash", String, nullable=False),
        Column("source_json", json_type, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    raw_snapshots = Table(
        "zprp_public_raw_snapshots",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("resource_type", String, nullable=False, index=True),
        Column("resource_key", String, nullable=False, index=True),
        Column("checksum", String, nullable=False),
        Column("payload_gzip", LargeBinary, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False, server_default=func.now(), index=True),
        UniqueConstraint("resource_type", "resource_key", "checksum", name="uq_zprp_public_raw_snapshot"),
    )

    changes = Table(
        "zprp_public_changes",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("resource_type", String, nullable=False, index=True),
        Column("resource_key", String, nullable=False, index=True),
        Column("old_hash", String, nullable=True),
        Column("new_hash", String, nullable=False),
        Column("changed_fields", json_type, nullable=False, server_default=text("'[]'")),
        Column("changed_at", DateTime(timezone=True), nullable=False, server_default=func.now(), index=True),
    )

    sync_runs = Table(
        "zprp_public_sync_runs",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("kind", String, nullable=False, index=True),
        Column("cycle_key", String, nullable=False, unique=True),
        Column("status", String, nullable=False, server_default=text("'running'"), index=True),
        Column("season_ids", json_type, nullable=False, server_default=text("'[]'")),
        Column("counters", json_type, nullable=False, server_default=text("'{}'")),
        Column("errors", json_type, nullable=False, server_default=text("'[]'")),
        Column("started_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("heartbeat_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("finished_at", DateTime(timezone=True), nullable=True),
    )

    sync_state = Table(
        "zprp_public_sync_state",
        metadata,
        Column("key", String, primary_key=True),
        Column("value_json", json_type, nullable=False, server_default=text("'{}'")),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    corrections = Table(
        "zprp_public_corrections",
        metadata,
        Column("correction_id", Integer, primary_key=True, autoincrement=True),
        Column("entity_type", String, nullable=False),
        Column("entity_id", String, nullable=False),
        Column("field", String, nullable=False),
        Column("value", Text, nullable=True),
        Column("note", Text, nullable=True),
        Column("actor", String, nullable=False, server_default=text("'admin'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
        Column("revoked_by", String, nullable=True),
    )
    Index("ix_zprp_public_corrections_active", corrections.c.entity_type, corrections.c.entity_id, corrections.c.revoked_at)

    return (
        seasons,
        associations,
        clubs,
        club_licenses,
        teams,
        players,
        rosters,
        competitions,
        rounds,
        matchdays,
        matches,
        match_players,
        match_staff,
        standings,
        scorers,
        raw_snapshots,
        changes,
        sync_runs,
        sync_state,
        corrections,
    )

