"""Walidacja adresow: mecz Bastionu, embed Bunny, Origin, cele nawigacji przegladarki serwerowej."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlsplit

BASTION_HOST = "portal.handball-bastion.pl"
JUDGE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def parse_game_url(url: str) -> int | None:
    """Dokladny host, https, sciezka /game, jedno dodatnie bunny_item_id; bez userinfo i portu. Inaczej None."""
    try:
        u = urlsplit(url.strip())
        if u.scheme != "https" or u.username or u.password or u.port is not None:
            return None
        if (u.hostname or "").lower() != BASTION_HOST or u.path.rstrip("/") != "/game":
            return None
        vals = parse_qs(u.query).get("bunny_item_id", [])
        if len(vals) != 1 or not re.fullmatch(r"[1-9][0-9]{0,11}", vals[0]):
            return None
        return int(vals[0])
    except ValueError:
        return None


def embed_url_ok(url: str, suffixes: list[str]) -> bool:
    """Embed Bunny: https, bez userinfo/portu, host rowny sufiksowi albo konczacy sie na '.sufiks'."""
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        if u.scheme != "https" or u.username or u.password or u.port is not None or not host:
            return False
        sfx = [s.lower().lstrip(".") for s in suffixes]
        return any(host == s or host.endswith("." + s) for s in sfx)
    except ValueError:
        return False


def origin_allowed(origin: str | None, allowed: list[str]) -> bool:
    return bool(origin) and origin.rstrip("/") in [a.rstrip("/") for a in allowed if a]


def is_blocked_navigation(url: str) -> bool:
    """True = przegladarka serwerowa nie moze tam isc: siec prywatna/lokalna albo schemat inny niz http(s).
    about:blank i blob: (wewnetrzne) przechodza. Nie chroni przed DNS rebinding - to warstwa dodatkowa."""
    try:
        u = urlsplit(url)
    except ValueError:
        return True
    if u.scheme in ("about", "blob"):
        return False
    if u.scheme not in ("http", "https"):
        return True
    host = (u.hostname or "").lower()
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
