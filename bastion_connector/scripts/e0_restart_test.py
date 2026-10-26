"""Test E0: game-context dla bunny_item_id (domyslnie 5632), restart connectora, ponowne uzyskanie embed_url.

Wymaga uprzedniego zalogowania (strona /test connectora). Nie wypisuje pelnego adresu embed (jest czasowy i
wrazliwy) - tylko host, dlugosc, odcisk SHA-256 i termin z adresu, jezeli go ma.

Uzycie:
  export BASTION_CONNECTOR_TOKEN=...   # ten sam, co w connectorze
  python scripts/e0_restart_test.py --url http://127.0.0.1:8770 --scope default --judge tester1 \
      [--item 5632] [--restart-cmd "docker restart bastion-connector"]
Bez --restart-cmd skrypt zatrzymuje sie po fazie 1 i czeka, az zrestartujesz usluge recznie (Enter).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time
from urllib.parse import urlsplit

import httpx


def probe(c: httpx.Client, a: argparse.Namespace) -> dict:
    r = c.get("/playback", params={"scope": a.scope, "judge_id": a.judge, "bunny_item_id": a.item})
    body = r.json()
    emb = body.pop("embed_url", None)
    out = {"http": r.status_code, **{k: body.get(k) for k in ("code", "video_state", "expires_at", "generation", "last_validated_at")}}
    if emb:
        out["embed_host"] = urlsplit(emb).hostname
        out["embed_len"] = len(emb)
        out["embed_sha256_8"] = hashlib.sha256(emb.encode()).hexdigest()[:8]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8770")
    ap.add_argument("--scope", default="default")
    ap.add_argument("--judge", default="tester1")
    ap.add_argument("--item", type=int, default=5632)
    ap.add_argument("--restart-cmd")
    ap.add_argument("--wait", type=float, default=20.0, help="sekundy czekania na /health po restarcie")
    a = ap.parse_args()
    tok = os.environ.get("BASTION_CONNECTOR_TOKEN", "")
    if not tok:
        print("Ustaw BASTION_CONNECTOR_TOKEN w srodowisku.")
        return 2
    c = httpx.Client(base_url=a.url, headers={"Authorization": f"Bearer {tok}"}, timeout=30)
    before = probe(c, a)
    print("FAZA 1 (przed restartem):", before)
    if before.get("code") != "OK":
        print("WYNIK: brak dzialajacej sesji - zaloguj sie najpierw (/test).")
        return 1
    if a.restart_cmd:
        subprocess.run(a.restart_cmd, shell=True, check=True)
    else:
        input("Zrestartuj connector (Railway: Restart/Redeploy), potem Enter... ")
    deadline = time.time() + a.wait
    while time.time() < deadline:
        try:
            if c.get("/health").status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    after = probe(c, a)
    print("FAZA 2 (po restarcie):   ", after)
    ok = after.get("code") == "OK" and bool(after.get("embed_host"))
    print("WYNIK:", "stan odtworzony, embed_url uzyskany ponownie" if ok else
          f"sesja NIE przetrwala (code={after.get('code')}) - wymagane ponowne logowanie")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
