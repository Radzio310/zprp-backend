import logging
from sqlalchemy import Table, Column, String
from app.db import database, metadata, engine, calendar_tokens

# Logger dla tego modułu
logger = logging.getLogger(__name__)

# -------------------------
# Table for storing OAuth2 CSRF state
# -------------------------
oauth_states = Table(
    "oauth_states",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("state", String, nullable=False),
)

# Ensure the new table is created in the database
metadata.create_all(engine)

# -------------------------
# Functions to manage CSRF state
# -------------------------
async def save_oauth_state(user_login: str, state: str) -> None:
    """
    Save or update the OAuth2 state string for the given user_login.
    """
    try:
        query = oauth_states.insert().values(
            user_login=user_login,
            state=state
        ).on_conflict_do_update(
            index_elements=[oauth_states.c.user_login],
            set_={"state": state}
        )
        await database.execute(query)
    except Exception:
        logger.exception(
            "Failed to save OAuth state for user_login=%s, state=%s",
            user_login,
            state
        )
        raise

async def get_oauth_state(user_login: str) -> str | None:
    """
    Retrieve the OAuth2 state string for the given user_login, or None if not found.
    """
    try:
        query = oauth_states.select().where(
            oauth_states.c.user_login == user_login
        )
        row = await database.fetch_one(query)
        return row["state"] if row else None
    except Exception:
        logger.exception(
            "Failed to fetch OAuth state for user_login=%s",
            user_login
        )
        raise

# -------------------------
# Functions to manage Calendar tokens
# -------------------------
async def save_calendar_tokens(
    user_login: str,
    access_token: str,
    refresh_token: str,
    expires_at: str
) -> None:
    """
    Insert or update Google Calendar access and refresh tokens for a user.
    """
    try:
        query = calendar_tokens.insert().values(
            user_login=user_login,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
        ).on_conflict_do_update(
            index_elements=[calendar_tokens.c.user_login],
            set_={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expires_at,
            }
        )
        await database.execute(query)
    except Exception:
        logger.exception(
            "Failed to save calendar tokens for user_login=%s",
            user_login
        )
        raise

async def get_calendar_tokens(user_login: str):
    """
    Retrieve the stored Google Calendar tokens for a given user_login.
    Returns a record with keys: access_token, refresh_token, expires_at, or None.
    """
    try:
        query = calendar_tokens.select().where(
            calendar_tokens.c.user_login == user_login
        )
        return await database.fetch_one(query)
    except Exception:
        logger.exception(
            "Failed to fetch calendar tokens for user_login=%s",
            user_login
        )
        raise
