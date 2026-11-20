"""Panel okręgowy (/panel) - kody QR logowania komputera (`app/panel_web_auth.py`)."""

from sqlalchemy import JSON, Column, DateTime, String, Table, func


def define_tables(metadata):
    qr_logins = Table(
        "panel_web_qr_logins",
        metadata,
        Column("code", String, primary_key=True),
        Column("poll_hash", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False, index=True),
        # Kto zatwierdził w aplikacji (numer sędziego) i kiedy.
        Column("approved_by", String, nullable=True),
        Column("approved_at", DateTime(timezone=True), nullable=True),
        Column("consumed_at", DateTime(timezone=True), nullable=True),
        Column("user_agent", String, nullable=True),
        # Wynik zatwierdzenia - leży tylko do odebrania przez komputer (najwyżej
        # kilka minut) i znika przy odbiorze: login ZPRP, szyfrogram pieczęci
        # hasła (`app/panel_web_seal.py`) i odpowiedź jak z `/baza_web/login`.
        Column("username", String, nullable=True),
        Column("sealed", String, nullable=True),
        Column("sealed_expires_at", DateTime(timezone=True), nullable=True),
        Column("payload_json", JSON, nullable=True),
    )
    return (qr_logins,)
