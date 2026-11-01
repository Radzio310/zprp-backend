"""Tabele meczów wspólnych (31.10.2026) i ręcznego podpięcia ProEla w panelu Mentor - same schematy, bez bazy.

Kontrakt: `docs/mecze-wspolne-api.md`. Decyzje: pamięć `mecze-reczne-wspolne-decyzje`.

  - `shared_matches`          mecz ręczny na serwerze (jeden wiersz = jeden mecz dla wszystkich członków),
  - `shared_match_members`    obsada: sędziowie z aplikacji (judge_id) albo wpis ręczny (sam podpis, bez dostępu),
  - `shared_match_blocks`     „nie dodawaj mnie więcej przez tę osobę",
  - `shared_match_log`        dziennik zmian (kto, kiedy, co),
  - `mentor_proel_links`      ręczne podpięcie protokołu ProEla do karty meczu pary (tylko odczyt).

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, a testy chodzą na SQLite.
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

#: Przedrostek identyfikatora karty meczu wspólnego w panelu pary (obok `tr_` Trybuny i numerów ZPRP).
SHARED_CARD_PREFIX = "my:"


def define_tables(metadata):
    matches = Table(
        "shared_matches",
        metadata,
        Column("id", String, primary_key=True),
        Column("creator_id", String, nullable=False, index=True),
        #: Identyfikator meczu w lokalnym pliku twórcy - ten sam twórca + ten sam local_id = ten sam mecz (migracja idempotentna).
        Column("local_id", String, nullable=True),
        #: Rośnie o 1 przy każdym zapisie treści (dane, wynik, obsada, powiązania). Podstawa wykrywania konfliktów.
        Column("rev", Integer, nullable=False, server_default=text("1")),
        #: Numer/kod meczu - opcjonalny i NIEUNIKALNY (numer nie jest kluczem).
        Column("code", String, nullable=True),
        Column("competition", String, nullable=True),
        Column("home_name", String, nullable=True),
        Column("away_name", String, nullable=True),
        Column("match_at", DateTime(timezone=True), nullable=True),
        #: Dzień meczu po polsku (YYYY-MM-DD) - klucz wykrywania duplikatu.
        Column("date_key", String, nullable=True, index=True),
        #: Drużyny po normalizacji, posortowane i złączone `|` - drugi człon klucza duplikatu.
        Column("teams_key", String, nullable=True, index=True),
        Column("hall", String, nullable=True),
        Column("city", String, nullable=True),
        Column("zprp_match_id", String, nullable=True, index=True),
        Column("proel_key", String, nullable=True),
        #: Wynik skrócony wpisany ręcznie. NIGDY nie idzie do ZPRP.
        Column("score_home", Integer, nullable=True),
        Column("score_away", Integer, nullable=True),
        Column("half_home", Integer, nullable=True),
        Column("half_away", Integer, nullable=True),
        Column("result_by", String, nullable=True),
        Column("result_at", DateTime(timezone=True), nullable=True),
        #: Dodatkowe pola aplikacji (JSON jako tekst, do 20 kB).
        Column("extra_json", Text, nullable=False, server_default=text("'{}'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_by", String, nullable=True),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
        Column("deleted_by", String, nullable=True),
        UniqueConstraint("creator_id", "local_id", name="uq_shared_match_creator_local"),
    )

    members = Table(
        "shared_match_members",
        metadata,
        Column("id", String, primary_key=True),
        Column("match_id", String, nullable=False, index=True),
        #: NULL = wpis ręczny osoby bez aplikacji (sam podpis, bez dostępu).
        Column("judge_id", String, nullable=True, index=True),
        Column("name", String, nullable=False, server_default=text("''")),
        #: sedzia1 | sedzia2 | czas | sekretarz | delegat
        Column("role", String, nullable=False),
        Column("added_by", String, nullable=True),
        Column("added_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        #: Ukrycie u siebie - nigdy nie kasuje niczego u innych.
        Column("hidden_at", DateTime(timezone=True), nullable=True),
        #: Czy mecz liczy się do statystyk TEJ osoby. Domyślnie nie.
        Column("counts_in_stats", Boolean, nullable=False, server_default=text("false")),
        UniqueConstraint("match_id", "judge_id", name="uq_shared_member_match_judge"),
    )

    blocks = Table(
        "shared_match_blocks",
        metadata,
        #: Osoba, która nie chce być dodawana.
        Column("judge_id", String, primary_key=True),
        #: Osoba, przez którą nie chce być dodawana.
        Column("via_judge_id", String, primary_key=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    log = Table(
        "shared_match_log",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("match_id", String, nullable=False, index=True),
        Column("rev", Integer, nullable=False, server_default=text("0")),
        Column("actor_id", String, nullable=True),
        Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("action", String, nullable=False),
        #: [{field, from, to}] jako tekst JSON.
        Column("changes_json", Text, nullable=False, server_default=text("'[]'")),
    )

    links = Table(
        "mentor_proel_links",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        Column("proel_key", String, nullable=False),
        Column("linked_by", String, nullable=False),
        Column("linked_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_mentor_proel_links_pair", links.c.pair_id)
    return matches, members, blocks, log, links
