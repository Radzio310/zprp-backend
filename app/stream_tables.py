"""Tabele transmisji meczów (portal BAZA pod Ręką) - same schematy, bez bazy.

Kontrakt: `docs/streams.md`. Logika: `app/streams/`.

* `stream_channels` - znane kanały (YouTube, Facebook, playlisty producentów):
  zasiane (Handball Polska, Czarny Piotruś MEDIA), wykryte ze stron klubów
  albo dodane w panelu admina. `key` to tożsamość kanału
  (`youtube:UC...`, `youtube:@handle`, `youtube-playlist:PL...`, `facebook:<adres>`).
* `match_streams` - konkretna transmisja/nagranie meczu (jeden adres = jeden
  wiersz na mecz). `hidden` ukrywa wpis na zawsze (admin), `verified_by`
  mówi, kto potwierdził stan (`zprp`, `api`, `rss`, `page`, `admin`).
* `stream_quota` - zużycie limitu YouTube Data API na dobę (doba Pacyfiku,
  jak liczy Google) + licznik wyszukiwań per mecz.

JSON jako Text (jak `mentor_panel_tables`): czytamy go `json.loads`.
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)


def define_tables(metadata):
    channels = Table(
        "stream_channels",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("key", String, nullable=False, unique=True),
        Column("platform", String, nullable=False),
        Column("channel_id", String, nullable=True, index=True),
        Column("playlist_id", String, nullable=True),
        Column("handle", String, nullable=True),
        Column("title", String, nullable=True),
        Column("url", Text, nullable=True),
        Column("club_id", String, nullable=True, index=True),
        Column("association_id", String, nullable=True),
        Column("scope_json", Text, nullable=False, server_default=text("'[]'")),
        Column("kind", String, nullable=False, server_default=text("'club'")),
        Column("verified", Boolean, nullable=False, server_default=text("false")),
        Column("active", Boolean, nullable=False, server_default=text("true")),
        Column("discovered_from", String, nullable=True),
        Column("last_checked_at", DateTime(timezone=True), nullable=True),
        Column("next_check_at", DateTime(timezone=True), nullable=True),
        Column("etag", String, nullable=True),
        Column("error", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    streams = Table(
        "match_streams",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("match_id", String, nullable=False, index=True),
        Column("url", Text, nullable=False),
        Column("platform", String, nullable=False),
        Column("video_id", String, nullable=True, index=True),
        Column("channel_ref", Integer, nullable=True),
        Column("channel_title", String, nullable=True),
        Column("channel_url", Text, nullable=True),
        Column("title", Text, nullable=True),
        Column("thumbnail_url", Text, nullable=True),
        Column("state", String, nullable=False, server_default=text("'link'")),
        Column("starts_at", DateTime(timezone=True), nullable=True),
        Column("ended_at", DateTime(timezone=True), nullable=True),
        Column("duration_s", Integer, nullable=True),
        Column("confidence", String, nullable=False, server_default=text("'possible'")),
        Column("source", String, nullable=False),
        Column("first_seen_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_seen_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("hidden", Boolean, nullable=False, server_default=text("false")),
        Column("verified_by", String, nullable=True),
        UniqueConstraint("match_id", "url", name="uq_match_streams_match_url"),
    )
    quota = Table(
        "stream_quota",
        metadata,
        Column("day", String, primary_key=True),
        Column("units_used", Integer, nullable=False, server_default=text("0")),
        Column("search_calls", Integer, nullable=False, server_default=text("0")),
        Column("searches_json", Text, nullable=False, server_default=text("'{}'")),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return channels, streams, quota


#: Indeksy dokładane po `create_all` (działają w Postgresie i SQLite).
MIGRATIONS = (
    "CREATE INDEX IF NOT EXISTS ix_match_streams_state ON match_streams (state, hidden)",
    "CREATE INDEX IF NOT EXISTS ix_stream_channels_next_check ON stream_channels (active, next_check_at)",
)
