"""Zaszyfrowany magazyn stanu polaczen (storage_state Playwrighta okrojony do domeny portalu).

Jeden plik na polaczenie: <data_dir>/states/<conn_key>.enc. Zapis atomowy (tmp + os.replace). Blokada profilu:
jedna asyncio.Lock na klucz polaczenia (connector = jedna instancja; wolumen Railway i tak montuje sie w jednej).
Do pliku nie trafiaja jawne cookie ani tokeny; meta (liczby, daty, bez wartosci) jest w tym samym zaszyfrowanym bloku.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path

from . import crypto

CONN_KEY_RE = re.compile(r"^(default|personal-[A-Za-z0-9_-]{1,64})$")


def conn_key_for(scope: str, judge_id: str | None) -> str:
    if scope == "default":
        return "default"
    if scope == "personal" and judge_id and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", judge_id):
        return f"personal-{judge_id}"
    raise ValueError("niepoprawny zakres polaczenia")


def filter_state_to_host(state: dict, host: str) -> dict:
    """Zostawia tylko cookie stosujace sie do hosta portalu i localStorage jego originu (nie zapisujemy
    szerszej sesji Discorda ubocznie, handoff 4.3)."""
    host = host.lower()

    def applies(domain: str) -> bool:
        d = domain.lower().lstrip(".")
        return bool(d) and "." in d and (host == d or host.endswith("." + d))

    cookies = [c for c in state.get("cookies", []) if applies(c.get("domain", ""))]
    origins = []
    for o in state.get("origins", []):
        m = re.match(r"^https?://([^/:]+)", o.get("origin", ""))
        if m and m.group(1).lower() == host:
            origins.append(o)
    return {"cookies": cookies, "origins": origins}


def cookie_summary(state: dict) -> dict:
    """Metadane bez wartosci: ile cookie, ile sesyjnych, najwczesniejsze i najpozniejsze wygasniecie."""
    cookies = state.get("cookies", [])
    exp = [c["expires"] for c in cookies if c.get("expires", -1) and c["expires"] > 0]
    return {
        "count": len(cookies),
        "session_only": sum(1 for c in cookies if not c.get("expires") or c["expires"] <= 0),
        "earliest_expiry": int(min(exp)) if exp else None,
        "latest_expiry": int(max(exp)) if exp else None,
    }


class StateStore:
    def __init__(self, data_dir: str, key_b64: str, previous_b64: list[str] | None = None) -> None:
        self.dir = Path(data_dir) / "states"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.keys = [crypto.parse_key(key_b64)] + [crypto.parse_key(k) for k in (previous_b64 or [])]
        self._locks: dict[str, asyncio.Lock] = {}

    def lock(self, conn_key: str) -> asyncio.Lock:
        return self._locks.setdefault(conn_key, asyncio.Lock())

    def _path(self, conn_key: str) -> Path:
        if not CONN_KEY_RE.match(conn_key):
            raise ValueError("niepoprawny klucz polaczenia")
        return self.dir / f"{conn_key}.enc"

    def save(self, conn_key: str, state: dict, meta: dict) -> None:
        blob = json.dumps({"state": state, "meta": meta}, separators=(",", ":")).encode()
        enc = crypto.encrypt(self.keys[0], blob, conn_key.encode())
        p = self._path(conn_key)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(enc)
        os.replace(tmp, p)

    def load(self, conn_key: str) -> tuple[dict, dict] | None:
        p = self._path(conn_key)
        if not p.exists():
            return None
        plain, idx = crypto.decrypt(self.keys, p.read_bytes(), conn_key.encode())
        data = json.loads(plain)
        if idx > 0:  # rotacja klucza: przepisz nowym
            self.save(conn_key, data["state"], data["meta"])
        return data["state"], data["meta"]

    def delete(self, conn_key: str) -> bool:
        p = self._path(conn_key)
        if p.exists():
            p.unlink()
            return True
        return False

    def touch_meta(self, conn_key: str, **updates) -> None:
        cur = self.load(conn_key)
        if cur:
            state, meta = cur
            meta.update(updates)
            self.save(conn_key, state, meta)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
