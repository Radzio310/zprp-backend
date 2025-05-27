import logging
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.db import database, calendar_tokens, oauth_states

logger = logging.getLogger(__name__)

# -------------------------
# CSRF/OAuth-state
# -------------------------

async def save_oauth_state(user_login: str, state: str) -> None:
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
    try:
        query = oauth_states.select().where(oauth_states.c.user_login == user_login)
        row = await database.fetch_one(query)
        return row["state"] if row else None
    except Exception:
        logger.exception("Failed to fetch OAuth state for %s", user_login)
        raise

async def get_user_login_by_state(state: str) -> str | None:
    try:
        query = oauth_states.select().where(oauth_states.c.state == state)
        row = await database.fetch_one(query)
        return row["user_login"] if row else None
    except Exception:
        logger.exception("Failed to lookup user_login by state %s", state)
        raise

# -------------------------
# Google Calendar tokens
# -------------------------

async def save_calendar_tokens(
    user_login: str,
    access_token: str,
    refresh_token: str,
    expires_at: str
) -> None:
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
    try:
        query = calendar_tokens.select().where(calendar_tokens.c.user_login == user_login)
        return await database.fetch_one(query)
    except Exception:
        logger.exception("Failed to fetch calendar tokens for %s", user_login)
        raise
