import logging
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.db import database, calendar_tokens, oauth_states, event_mappings

logger = logging.getLogger(__name__)

# -------------------------
# CSRF / OAuth-state storage
# -------------------------

async def save_oauth_state(user_login: str, state: str) -> None:
    """
    Save or update the OAuth2 state string for the given user_login.
    """
    try:
        stmt = pg_insert(oauth_states).values(
            user_login=user_login,
            state=state
        ).on_conflict_do_update(
            index_elements=[oauth_states.c.user_login],
            set_={"state": pg_insert(oauth_states).excluded.state}
        )
        await database.execute(stmt)
    except Exception:
        logger.exception("Failed to save OAuth state for %s", user_login)
        raise

async def get_oauth_state(user_login: str) -> str | None:
    """
    Retrieve the OAuth2 state string for the given user_login, or None if not found.
    """
    try:
        query = oauth_states.select().where(oauth_states.c.user_login == user_login)
        row = await database.fetch_one(query)
        return row["state"] if row else None
    except Exception:
        logger.exception("Failed to fetch OAuth state for %s", user_login)
        raise

async def get_user_login_by_state(state: str) -> str | None:
    """
    Lookup the user_login that corresponds to the given OAuth state.
    """
    try:
        query = oauth_states.select().where(oauth_states.c.state == state)
        row = await database.fetch_one(query)
        return row["user_login"] if row else None
    except Exception:
        logger.exception("Failed to lookup user_login by state %s", state)
        raise

# -------------------------
# Google Calendar tokens storage
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
        stmt = pg_insert(calendar_tokens).values(
            user_login=user_login,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
        ).on_conflict_do_update(
            index_elements=[calendar_tokens.c.user_login],
            set_={
                "access_token": pg_insert(calendar_tokens).excluded.access_token,
                "refresh_token": pg_insert(calendar_tokens).excluded.refresh_token,
                "expires_at": pg_insert(calendar_tokens).excluded.expires_at,
            }
        )
        await database.execute(stmt)
    except Exception:
        logger.exception("Failed to save calendar tokens for %s", user_login)
        raise

async def get_calendar_tokens(user_login: str):
    """
    Retrieve the stored Google Calendar tokens for a given user_login.
    Returns a record with keys access_token, refresh_token, expires_at or None.
    """
    try:
        query = calendar_tokens.select().where(calendar_tokens.c.user_login == user_login)
        return await database.fetch_one(query)
    except Exception:
        logger.exception("Failed to fetch calendar tokens for %s", user_login)
        raise

async def delete_calendar_tokens(user_login: str) -> None:
    """
    Remove stored Calendar tokens for the given user_login.
    """
    try:
        stmt = delete(calendar_tokens).where(calendar_tokens.c.user_login == user_login)
        await database.execute(stmt)
    except Exception:
        logger.exception("Failed to delete calendar tokens for %s", user_login)
        raise

# -------------------------
# Calendar event mappings storage
# -------------------------

async def save_event_mapping(
    user_login: str,
    match_id: str,
    event_id: str
) -> None:
    """
    Save or update the mapping between a match identifier and a Google Calendar event ID for a user.
    """
    try:
        stmt = pg_insert(event_mappings).values(
            user_login=user_login,
            match_id=match_id,
            event_id=event_id
        ).on_conflict_do_update(
            index_elements=[event_mappings.c.user_login, event_mappings.c.match_id],
            set_={"event_id": pg_insert(event_mappings).excluded.event_id}
        )
        await database.execute(stmt)
    except Exception:
        logger.exception("Failed to save event mapping for %s match %s", user_login, match_id)
        raise

async def get_event_mapping(user_login: str, match_id: str) -> str | None:
    """
    Retrieve the Google Calendar event ID for a given user_login and match_id.
    """
    try:
        query = event_mappings.select().where(
            (event_mappings.c.user_login == user_login) &
            (event_mappings.c.match_id == match_id)
        )
        row = await database.fetch_one(query)
        return row["event_id"] if row else None
    except Exception:
        logger.exception("Failed to fetch event mapping for %s match %s", user_login, match_id)
        raise

async def delete_event_mapping(user_login: str, match_id: str) -> None:
    """
    Delete the event mapping for a given user_login and match_id.
    """
    try:
        stmt = delete(event_mappings).where(
            (event_mappings.c.user_login == user_login) &
            (event_mappings.c.match_id == match_id)
        )
        await database.execute(stmt)
    except Exception:
        logger.exception("Failed to delete event mapping for %s match %s", user_login, match_id)
        raise
