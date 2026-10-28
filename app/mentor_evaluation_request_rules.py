"""Pure authorization and cooldown rules for mentor evaluation requests."""

from __future__ import annotations

from datetime import datetime, timedelta
import re
from typing import Iterable, Optional
from urllib.parse import parse_qs, urlparse, urlunparse


REQUEST_COOLDOWN = timedelta(hours=72)


DISCORD_HOSTS = {"discord.com", "discordapp.com", "discord.gg", "discord.me"}
DISCORD_MESSAGE = ("To link do rozmowy na Discordzie, nie nagranie. "
                   "Wklej link z portalu Bastion (portal.handball-bastion.pl/game?bunny_item_id=...).")


def normalized_video_url(value: Optional[str]) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise ValueError("Niepoprawny link do nagrania - sprawdź, czy został wklejony w całości.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Link do nagrania musi zaczynać się od http:// lub https://.")
    host = (parsed.hostname or "").lower()
    if host in DISCORD_HOSTS or host.endswith(".discord.com") or host.endswith(".discordapp.com"):
        raise ValueError(DISCORD_MESSAGE)
    # Host i schemat nie są semantycznie czułe na wielkość liter. Usuwamy też
    # samotny końcowy slash, żeby ten sam film nie powstawał dwa razy.
    path = parsed.path.rstrip("/") or ""
    # Handball Bastion (za flagą BASTION_ENABLED): adres meczu sprowadzamy do postaci kanonicznej
    # (bez `at` i śmieci w zapytaniu), by ten sam film nie powstawał dwa razy.
    from app import mentor_bastion_rules as bastion

    if bastion.enabled():
        canonical = bastion.canonicalize(value)
        if canonical:
            return canonical
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.params, parsed.query, parsed.fragment))


def video_provider(value: str) -> str:
    from app import mentor_bastion_rules as bastion

    # Dokładny host portalu + /game + bunny_item_id; domeny podszywające się trafiają niżej jako zwykły link.
    if bastion.enabled() and bastion.is_bastion_url(value):
        return bastion.PROVIDER
    host = (urlparse(value).hostname or "").lower()
    if host in {"youtu.be", "youtube.com"} or host.endswith(".youtube.com"):
        return "youtube"
    if host == "vimeo.com" or host.endswith(".vimeo.com"):
        return "vimeo"
    if host.endswith("facebook.com") or host == "fb.watch":
        return "facebook"
    if host.endswith("streamable.com"):
        return "streamable"
    if host.endswith("drive.google.com"):
        return "google_drive"
    return "video"


def youtube_thumbnail(value: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    video_id = parsed.path.strip("/") if host == "youtu.be" else (parse_qs(parsed.query).get("v") or [""])[0]
    if not video_id:
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2 and parts[0].lower() in {"shorts", "live", "embed"}:
            video_id = parts[1]
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,20}", video_id or ""):
        return ""
    return f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"


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
