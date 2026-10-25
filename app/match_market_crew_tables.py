"""
Tabele ofert obsadowego na giełdzie (25.10.2026) - same schematy, bez bazy.

  - `match_market_crew_offers`  oferta obsadowego: mecz + wybrane sloty,
  - `match_market_crew_claims`  zgłoszenia sędziów (rola, opcjonalny partner).

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, więc
każdy odczyt i tak go rozbiera (patrz pamięć gielda-meczow-reguly).
"""

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)


def define_tables(metadata):
    offers = Table(
        "match_market_crew_offers",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False, index=True),
        Column("match_id", String, nullable=False, index=True),
        Column("match_code", String, nullable=True),
        #: Lista gniazd modułu (pierwszy/drugi/sekretarz/czas) jako napis JSON.
        Column("slots", Text, nullable=False, server_default=text("'[]'")),
        Column("comment", Text, nullable=True),
        #: none | include | exclude
        Column("badge_mode", String, nullable=False, server_default=text("'none'")),
        Column("badges", Text, nullable=False, server_default=text("'[]'")),
        Column("deadline_at", DateTime(timezone=True), nullable=True),
        Column("match_at", DateTime(timezone=True), nullable=True),
        Column("match_snapshot", Text, nullable=False, server_default=text("'{}'")),
        #: open | filled | expired | withdrawn
        Column("status", String, nullable=False, server_default=text("'open'"), index=True),
        Column("closed_reason", String, nullable=True),
        Column("closed_at", DateTime(timezone=True), nullable=True),
        Column("created_by", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column(
            "updated_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
            onupdate=func.now(),
        ),
    )
    Index("ix_match_market_crew_offers_live", offers.c.province, offers.c.match_id, offers.c.status)
    claims = Table(
        "match_market_crew_claims",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column(
            "offer_id",
            Integer,
            ForeignKey("match_market_crew_offers.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        Column("judge_id", String, nullable=False, index=True),
        #: table | field
        Column("role", String, nullable=False),
        Column("partner_id", String, nullable=True),
        Column("note", Text, nullable=True),
        #: pending | assigned | declined | withdrawn
        Column("status", String, nullable=False, server_default=text("'pending'")),
        #: Gniazdo, na które przydzielono (gdy status = assigned).
        Column("slot", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column(
            "updated_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
            onupdate=func.now(),
        ),
        UniqueConstraint("offer_id", "judge_id", name="uq_match_market_crew_claim"),
    )
    return offers, claims
