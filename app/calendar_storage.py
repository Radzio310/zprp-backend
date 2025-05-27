# app/calendar_storage.py
from app.db import database, calendar_tokens

async def save_calendar_tokens(user_id: int, access_token: str, refresh_token: str, expires_at: str):
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
    query = calendar_tokens.select().where(calendar_tokens.c.user_id == user_id)
    return await database.fetch_one(query)
