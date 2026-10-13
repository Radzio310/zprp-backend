"""Pure authorization and cooldown rules for mentor evaluation requests."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable, Optional
from urllib.parse import urlparse


REQUEST_COOLDOWN = timedelta(hours=72)


def normalized_video_url(value: Optional[str]) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Link do nagrania musi zaczynać się od http:// lub https://.")
    return value


def request_target_error(
    *,
    actor_id: str,
    pair: Iterable[str],
    assigned_mentors: Iterable[str],
    requested_mentors: Iterable[str],
    completed_mentors: Iterable[str] = (),
) -> tuple[int, str] | None:
    """Return an HTTP-like status and safe Polish explanation, or ``None``."""
    pair_ids = {str(value).strip() for value in pair if str(value).strip()}
    assigned = {str(value).strip() for value in assigned_mentors if str(value).strip()}
    requested = {str(value).strip() for value in requested_mentors if str(value).strip()}
    completed = {str(value).strip() for value in completed_mentors if str(value).strip()}
    if str(actor_id).strip() not in pair_ids:
        return 403, "Tylko sędziowie tej pary mogą poprosić o ocenę meczu."
    if not requested or not requested.issubset(assigned):
        return 422, "Możesz poprosić wyłącznie aktywnych mentorów swojej pary."
    if requested & completed:
        return 409, "Wybrany mentor opublikował już ocenę tego meczu."
    return None


def cooldown_hours(
    *,
    last_sent_at: Optional[datetime],
    now: datetime,
    fulfilled_at: Optional[datetime] = None,
) -> int:
    """Hours until retry, rounded up; zero means the request may be sent."""
    if fulfilled_at is not None or last_sent_at is None:
        return 0
    remaining = last_sent_at + REQUEST_COOLDOWN - now
    if remaining.total_seconds() <= 0:
        return 0
    return max(1, int(remaining.total_seconds() / 3600 + 0.999))
