"""Trwały stan prób logowania: <data_dir>/attempts/<id>.json. Tylko metadane (zero cookie, zero tożsamości konta;
tożsamość żyje w zaszyfrowanym stanie połączenia). Zapis atomowy. Po restarcie próba, której przeglądarka zginęła,
przechodzi w `interrupted` z polskim komunikatem."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ACTIVE = ("creating", "waiting_for_user", "verifying")
KEEP_S = 7 * 24 * 3600
INTERRUPTED_CODE = "CONNECTOR_RESTARTED"
INTERRUPTED_MSG = ("Logowanie zostało przerwane, bo usługa połączenia z Bastionem została zrestartowana. "
                   "Rozpocznij logowanie od nowa.")
MESSAGES = {
    "interrupted": INTERRUPTED_MSG,
    "expired": "Czas na zalogowanie minął. Rozpocznij logowanie od nowa.",
}
FIELDS = ("id", "conn_key", "scope", "judge_id", "probe_item_id", "created", "expires", "status", "error", "updated")


class AttemptStore:
    def __init__(self, data_dir: str) -> None:
        self.dir = Path(data_dir) / "attempts"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, attempt_id: str) -> Path:
        if not ID_RE.match(attempt_id):
            raise ValueError("niepoprawne id proby")
        return self.dir / f"{attempt_id}.json"

    def save(self, rec: dict) -> None:
        data = {k: rec.get(k) for k in FIELDS}
        data["updated"] = time.time()
        p = self._path(data["id"])
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, p)

    def delete(self, attempt_id: str) -> None:
        try:
            self._path(attempt_id).unlink()
        except (FileNotFoundError, ValueError):
            pass

    def load_all(self) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(d, dict) and ID_RE.match(str(d.get("id", ""))) and d.get("conn_key"):
                    out.append(d)
            except (OSError, ValueError):
                continue  # uszkodzony plik próby nie blokuje startu
        return out

    def recover(self, now: float | None = None) -> list[dict]:
        """Wczytuje próby po starcie. Aktywna próba nie ma już przeglądarki: `expired` (gdy termin minął) albo
        `interrupted`. Pliki starsze niż 7 dni są usuwane."""
        now = now or time.time()
        res = []
        for d in self.load_all():
            if now - float(d.get("updated") or 0) > KEEP_S:
                self.delete(d["id"])
                continue
            if d.get("status") in ACTIVE:
                d["status"] = "expired" if float(d.get("expires") or 0) < now else "interrupted"
                d["error"] = INTERRUPTED_CODE if d["status"] == "interrupted" else d.get("error")
                self.save(d)
            res.append(d)
        return res
