"""Tabele „Trybuny" w panelu Mentor (28.10.2026) - same schematy, kontrakt: `docs/mentor-panel.md` 8.11.

Mecz z Trybuny (cudzy mecz oglądany przez parę) to wiersz `mentor_watched_matches`, a jego `match_id` ma przedrostek `tr_`.
Cała reszta (nagrania, klipy, wątki, znaczniki, zdarzenia ProEla) używa tego `match_id` w zwykłych tabelach pokoju
meczu - bez drugiego systemu. Tu są tylko rzeczy, których pokój nie ma: sam mecz, obserwowani, kolejka, półki,
oznaczenia sędziów na klipach, „Twoje zdanie" i ślad wysłanych powiadomień.
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)

#: Przedrostek identyfikatora meczu z Trybuny: odróżnia go od numerów ZPRP i od meczów pary.
WATCHED_PREFIX = "tr_"


def define_tables(metadata):
    watched = Table(
        "mentor_watched_matches",
        metadata,
        Column("match_id", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        Column("created_by", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
        Column("deleted_by", String, nullable=True),
        #: `bastion` | `youtube` | `link` - skąd mecz dodano.
        Column("origin", String, nullable=False, server_default=text("'link'")),
        Column("bunny_item_id", Integer, nullable=True, index=True),
        Column("title", Text, nullable=True),
        #: Migawka karty meczu (drużyny, rozgrywki, data, kod, wynik) - JSON jako tekst.
        Column("card_json", Text, nullable=False, server_default=text("'{}'")),
        Column("zprp_match_id", String, nullable=True, index=True),
        Column("proel_key", String, nullable=True),
        #: Bilet spinający: pewność i kandydaci per źródło (zprp / proel / video) + kto i kiedy poprawił ręcznie.
        Column("links_json", Text, nullable=False, server_default=text("'{}'")),
        #: Sędziowie meczu: [{name, judge_id|null, position|null}].
        Column("referees_json", Text, nullable=False, server_default=text("'[]'")),
        Column("note", Text, nullable=True),
    )
    Index("ix_mentor_watched_pair_created", watched.c.pair_id, watched.c.created_at)

    follows = Table(
        "mentor_trybuna_follows",
        metadata,
        Column("id", String, primary_key=True),
        Column("judge_id", String, nullable=False, index=True),
        #: `referee` (jeden sędzia) | `pair` (dwóch sędziów jako para).
        Column("kind", String, nullable=False),
        #: Klucz obserwowanego: numer sędziego ZPRP albo nazwa po normalizacji ("name:jan kowalski"); para = klucze po `|`.
        Column("ref_key", String, nullable=False),
        Column("name", String, nullable=False),
        Column("judge_ids", Text, nullable=False, server_default=text("'[]'")),
        Column("names", Text, nullable=False, server_default=text("'[]'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        UniqueConstraint("judge_id", "kind", "ref_key", name="uq_mentor_trybuna_follow"),
    )

    queue = Table(
        "mentor_trybuna_queue",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("pair_id", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        Column("position", Integer, nullable=False, server_default=text("0")),
        Column("progress_s", Integer, nullable=False, server_default=text("0")),
        Column("video_id", String, nullable=True),
        Column("added_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("done_at", DateTime(timezone=True), nullable=True),
        #: "Mentor poleca" (runda 2): kto, z jaką notką, kiedy i (opcjonalnie) który klip.
        Column("recommended_by", String, nullable=True),
        Column("note", String, nullable=True),
        Column("recommended_at", DateTime(timezone=True), nullable=True),
        Column("clip_id", String, nullable=True),
    )

    shelves = Table(
        "mentor_trybuna_shelves",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        Column("name", String, nullable=False),
        Column("color", String, nullable=True),
        Column("sort", Integer, nullable=False, server_default=text("0")),
        Column("created_by", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("archived", Boolean, nullable=False, server_default=text("false")),
    )
    shelf_clips = Table(
        "mentor_trybuna_shelf_clips",
        metadata,
        Column("shelf_id", String, primary_key=True),
        Column("clip_id", String, primary_key=True),
        Column("position", Integer, nullable=False, server_default=text("0")),
        Column("added_by", String, nullable=True),
        Column("added_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    clip_tags = Table(
        "mentor_trybuna_clip_tags",
        metadata,
        Column("clip_id", String, primary_key=True),
        Column("ref_key", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        Column("name", String, nullable=False),
        Column("judge_id", String, nullable=True),
        #: `A` | `B` | `?` (rola w parze sędziowskiej) oraz wolny opis pozycji ("bramkowy", "linia", ...).
        Column("role", String, nullable=False, server_default=text("'?'")),
        Column("position", String, nullable=True),
        Column("created_by", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    opinions = Table(
        "mentor_trybuna_opinions",
        metadata,
        Column("thread_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        #: `agree` | `differ` | `unsure` - to NIE ocena, tylko zdanie w rozmowie o klipie.
        Column("vote", String, nullable=False),
        #: Przy "Inaczej" (runda 2): powód (do 200 znaków) i odsyłacz do przepisu ("8:5b").
        Column("reason", String, nullable=True),
        Column("rule_ref", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    notified = Table(
        "mentor_trybuna_notified",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("bunny_item_id", Integer, primary_key=True),
        Column("notified_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    #: Miniatury kaset Bastionu trzymane u nas (jedna klatka na `bunny_item_id`, zadanie w tle).
    thumbs = Table(
        "mentor_trybuna_thumbs",
        metadata,
        Column("bunny_item_id", Integer, primary_key=True),
        Column("status", String, nullable=False, server_default=text("'pending'")),
        Column("storage_key", String, nullable=True),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
        Column("next_attempt_at", DateTime(timezone=True), nullable=True),
        Column("error", String, nullable=True),
        Column("duration_s", Integer, nullable=True),
        Column("requested_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    #: Kanał obserwowanych liczony w tle (co 30 min) i trzymany w bazie.
    feed_cache = Table(
        "mentor_trybuna_feed_cache",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("payload_json", Text, nullable=False, server_default=text("'{}'")),
        Column("computed_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    #: "Dziś sędziuje": jedna wiadomość na osobę na dzień.
    today = Table(
        "mentor_trybuna_today",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("day", String, primary_key=True),
        Column("sent_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return watched, follows, queue, shelves, shelf_clips, clip_tags, opinions, notified, thumbs, feed_cache, today


#: Kolumny i indeksy dokładane po wdrożeniu (PostgreSQL), każdy osobno.
MIGRATIONS = (
    "ALTER TABLE mentor_trybuna_opinions ADD COLUMN IF NOT EXISTS reason VARCHAR",
    "ALTER TABLE mentor_trybuna_opinions ADD COLUMN IF NOT EXISTS rule_ref VARCHAR",
    "ALTER TABLE mentor_trybuna_queue ADD COLUMN IF NOT EXISTS recommended_by VARCHAR",
    "ALTER TABLE mentor_trybuna_queue ADD COLUMN IF NOT EXISTS note VARCHAR",
    "ALTER TABLE mentor_trybuna_queue ADD COLUMN IF NOT EXISTS recommended_at TIMESTAMPTZ",
    "ALTER TABLE mentor_trybuna_queue ADD COLUMN IF NOT EXISTS clip_id VARCHAR",
    # Klucz idempotencji dodania nagrania (nagłówek `Idempotency-Key`): powtórka tego samego żądania = ten sam wiersz.
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_mentor_match_video_idem ON mentor_match_videos (pair_key, match_id, idempotency_key) "
    "WHERE idempotency_key IS NOT NULL",
)
