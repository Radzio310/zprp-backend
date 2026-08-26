import logging
from datetime import datetime, timezone

from sqlalchemy import and_, update

from app.db import database, push_tokens
from .fcm import is_permanently_invalid_fcm_token


logger = logging.getLogger("app.push.token_cleanup")


async def invalidate_rejected_fcm_token(
    installation_id: str,
    rejected_token: str,
    error: BaseException,
) -> bool:
    """Czyści token odrzucony przez FCM, zachowując instalację i jej skrzynkę.

    Warunek po starej wartości tokenu chroni przed wyścigiem: jeżeli aplikacja
    zdążyła już zarejestrować świeży token, spóźniona odpowiedź FCM nie może go
    unieważnić.
    """

    if not is_permanently_invalid_fcm_token(error):
        return False

    installation_id = str(installation_id or "").strip()
    rejected_token = str(rejected_token or "").strip()
    if not installation_id or not rejected_token:
        return False

    try:
        invalidated = await database.fetch_val(
            update(push_tokens)
            .where(
                and_(
                    push_tokens.c.installation_id == installation_id,
                    push_tokens.c.token == rejected_token,
                )
            )
            .values(
                token="",
                token_type="invalid_fcm",
                updated_at=datetime.now(timezone.utc),
            )
            .returning(push_tokens.c.installation_id)
        )
    except Exception:
        logger.exception(
            "Could not invalidate rejected FCM token for installation %s",
            installation_id,
        )
        return False

    if invalidated:
        logger.warning(
            "Invalidated permanently rejected FCM token for installation %s",
            installation_id,
        )
        return True
    return False
