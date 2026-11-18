"""Kanały YouTube pary (18.11.2026) - schemat. Kontrakt: `docs/mentor-panel.md`, sekcja 16.

  - `mentor_channels`: kanał dodany przez parę w Ustawieniach (link / @uchwyt), wynik ostatniego przeglądu,
  - `mentor_channel_videos`: filmy kanału z propozycją meczu pary (pewność, powody, alternatywy) i decyzją
    (`new` | `added` | `dismissed`); połówki jednego meczu dzielą `group_id` grupy wgrań sklejanej na serwerze.
Przegląd tylko na żądanie („Przejrzyj kanał”). Tabele powstają z `metadata.create_all`.
"""

from sqlalchemy import Column, DateTime, Index, Integer, String, Table, Text, func, text


def define_tables(metadata):
    channels = Table(
        "mentor_channels",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("url", Text, nullable=False),
        #: Kanał YouTube (UC...) i uchwyt (@...) po rozpoznaniu; tytuł i miniatura do karty w Ustawieniach.
        Column("channel_id", String, nullable=True),
        Column("handle", String, nullable=True),
        Column("title", String, nullable=True),
        Column("thumbnail_url", Text, nullable=True),
        Column("added_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("scanned_at", DateTime(timezone=True), nullable=True),
        #: api (pełna lista z YouTube Data API) | page (strona kanału, ostatnie ~30 filmów) | None.
        Column("scan_source", String, nullable=True),
        Column("scan_complete", String, nullable=True),
        Column("scan_error", Text, nullable=True),
        Column("video_count", Integer, nullable=False, server_default=text("0")),
        Index("ix_mentor_channels_pair", "pair_id"),
    )
    videos = Table(
        "mentor_channel_videos",
        metadata,
        Column("id", String, primary_key=True),
        Column("channel_row_id", String, nullable=False),
        Column("pair_id", String, nullable=False),
        Column("video_id", String, nullable=False),
        Column("title", Text, nullable=False),
        Column("thumbnail_url", Text, nullable=True),
        Column("duration_s", Integer, nullable=True),
        Column("published_at", DateTime(timezone=True), nullable=True),
        Column("position", Integer, nullable=False, server_default=text("0")),
        #: Rozbiór tytułu: {date, home, away, half, code}.
        Column("parsed_json", Text, nullable=False, server_default=text("'{}'")),
        Column("match_id", String, nullable=True),
        #: sure | likely | possible | NULL (bez pary).
        Column("confidence", String, nullable=True),
        Column("reasons_json", Text, nullable=False, server_default=text("'[]'")),
        Column("alternatives_json", Text, nullable=False, server_default=text("'[]'")),
        #: new | added | dismissed.
        Column("state", String, nullable=False, server_default=text("'new'")),
        #: Mecz wybrany ręcznie zamiast propozycji (zostaje po ponownym przeglądzie).
        Column("chosen_match_id", String, nullable=True),
        Column("added_video_id", String, nullable=True),
        Column("group_id", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Index("ux_mentor_channel_videos", "channel_row_id", "video_id", unique=True),
        Index("ix_mentor_channel_videos_pair", "pair_id"),
    )
    return channels, videos


MIGRATIONS: tuple = ()
