"""Jednorazowe, krotkotrwale bilety wejscia do widoku logowania.

Bilet = b64url(json) . b64url(HMAC-SHA256). Przypiety do judge_id i konkretnej proby, wazny ttl sekund,
zuzywany przy pierwszym uzyciu (rejestr nonce w pamieci - connector dziala jako pojedyncza instancja).
Bilet jedzie w pierwszej wiadomosci WebSocketu, nie w adresie URL (zeby nie trafial do logow proxy).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time


class TicketError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sig(secret: str, payload: str) -> str:
    return _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())


def mint(secret: str, judge_id: str, attempt_id: str, ttl_s: int, now: float | None = None) -> str:
    if len(secret) < 16:
        raise TicketError("sekret biletow za krotki")
    now = time.time() if now is None else now
    body = {"j": judge_id, "a": attempt_id, "n": os.urandom(12).hex(), "e": int(now + ttl_s)}
    payload = _b64(json.dumps(body, separators=(",", ":")).encode())
    return f"{payload}.{_sig(secret, payload)}"


class TicketRegistry:
    def __init__(self) -> None:
        self._used: dict[str, int] = {}

    def consume(self, secret: str, token: str, attempt_id: str, judge_id: str, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        try:
            payload, sig = token.split(".", 1)
            if not hmac.compare_digest(sig, _sig(secret, payload)):
                raise TicketError("zly podpis biletu")
            data = json.loads(_unb64(payload))
        except TicketError:
            raise
        except Exception as e:  # noqa: BLE001
            raise TicketError("uszkodzony bilet") from e
        if data.get("e", 0) < now:
            raise TicketError("bilet wygasl")
        if data.get("a") != attempt_id or data.get("j") != judge_id:
            raise TicketError("bilet nie dotyczy tej proby")
        self._used = {n: e for n, e in self._used.items() if e >= now}
        if data["n"] in self._used:
            raise TicketError("bilet zostal juz uzyty")
        self._used[data["n"]] = data["e"]
        return data
