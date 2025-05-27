from sqlalchemy import Table, Column, Integer, String, MetaData
from app.db import database, calendar_tokens, metadata, engine

# -------------------------
# Table for storing OAuth2 CSRF state
# -------------------------
oauth_states = Table(
    "oauth_states",
    metadata,
    Column("user_id", Integer, primary_key=True),
    Column("state", String, nullable=False),
)

# Ensure the new table is created in the database
metadata.create_all(engine)

# -------------------------
# Functions to manage CSRF state
# -------------------------
async def save_oauth_state(user_id: int, state: str) -> None:
    """
    Save or update the OAuth2 state string for the given user_id.
    """
    query = oauth_states.insert().values(
        user_id=user_id,
        state=state
    ).on_conflict_do_update(
        index_elements=[oauth_states.c.user_id],
        set_={"state": state}
    )
    await database.execute(query)

async def get_oauth_state(user_id: int) -> str | None:
    """
    Retrieve the OAuth2 state string for the given user_id, or None if not found.
    """
    query = oauth_states.select().where(oauth_states.c.user_id == user_id)
    row = await database.fetch_one(query)
    return row["state"] if row else None

# -------------------------
# Functions to manage Calendar tokens
# -------------------------
async def save_calendar_tokens(
    user_id: int,
    access_token: str,
    refresh_token: str,
    expires_at: str
) -> None:
    """
    Insert or update Google Calendar access and refresh tokens for a user.
    """
    query = calendar_tokens.insert().values(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
    ).on_conflict_do_update(
        index_elements=[calendar_tokens.c.user_id],
        set_={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
        }
    )
    await database.execute(query)

async def get_calendar_tokens(user_id: int):
    """
    Retrieve the stored Google Calendar tokens for a given user_id.
    Returns a record with keys: access_token, refresh_token, expires_at, or None.
    """
    query = calendar_tokens.select().where(calendar_tokens.c.user_id == user_id)
    return await database.fetch_one(query)
