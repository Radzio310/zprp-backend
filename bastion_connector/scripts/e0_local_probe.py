"""Lokalna proba bez poswiadczen: start proby logowania, klatki CDP przez WSS, zapis zrzutu strony Bastionu,
opcjonalnie klikniecie przycisku Discord i zapis zrzutu tego, co sie otworzylo (bez wpisywania hasel).

Uzycie (connector musi dzialac z BASTION_TEST_PAGE nieistotne):
  python scripts/e0_local_probe.py --url http://127.0.0.1:8770 --out <katalog> [--click-discord]
Zmienne: BASTION_CONNECTOR_TOKEN. Origin WS = --origin (musi byc w BASTION_ALLOWED_ORIGINS).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import httpx
import websockets


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8770")
    ap.add_argument("--origin", default="http://127.0.0.1:8770")
    ap.add_argument("--out", required=True)
    ap.add_argument("--click-discord", action="store_true")
    ap.add_argument("--wait", type=float, default=8.0)
    ap.add_argument("--click", help="x,y dodatkowego klikniecia (piksele okna 1100x700)")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tok = os.environ["BASTION_CONNECTOR_TOKEN"]
    h = {"Authorization": f"Bearer {tok}"}
    async with httpx.AsyncClient(base_url=a.url, headers=h, timeout=60) as c:
        r = await c.post("/attempts", json={"scope": "personal", "judge_id": "probe1", "probe_bunny_item_id": 5632})
        print("create attempt:", r.status_code, {k: v for k, v in r.json().items() if k != "ticket"})
        j = r.json()
        ws_url = a.url.replace("http", "ws", 1) + j["ws_path"]
        async with websockets.connect(ws_url, origin=a.origin, max_size=8_000_000) as ws:
            await ws.send(json.dumps({"type": "auth", "ticket": j["ticket"]}))
            frames = 0
            last = None

            async def drain(sec: float):
                nonlocal frames, last
                end = asyncio.get_event_loop().time() + sec
                while (left := end - asyncio.get_event_loop().time()) > 0:
                    try:
                        m = await asyncio.wait_for(ws.recv(), timeout=left)
                    except asyncio.TimeoutError:
                        break
                    if isinstance(m, bytes):
                        frames += 1
                        last = m
                    else:
                        print("ws msg:", m)

            await drain(6)
            (out / "01_bastion_start.jpg").write_bytes(last or b"")
            print("klatki po 6 s:", frames, "bytes:", len(last or b""))
            if a.click_discord:
                # przycisk Discord: klikniecie wskazane przez --click (po obejrzeniu zrzutu 01)
                pass
            if a.click:
                x, y = (int(v) for v in a.click.split(","))
                for act in ("move", "down", "up"):
                    await ws.send(json.dumps({"t": "mouse", "a": act, "x": x, "y": y}))
                await drain(a.wait)
                (out / "02_po_kliknieciu.jpg").write_bytes(last or b"")
                print("klatki po kliknieciu:", frames, "bytes:", len(last or b""))
        s = await c.post(f"/attempts/{j['id']}/cancel")
        print("cancel:", s.json())
        # drugi bilet tego samego typu nie moze zadzialac po anulowaniu; zuzyty bilet tez nie
        try:
            async with websockets.connect(ws_url, origin=a.origin) as ws2:
                await ws2.send(json.dumps({"type": "auth", "ticket": j["ticket"]}))
                await ws2.recv()
        except Exception as e:  # noqa: BLE001
            print("ponowne uzycie biletu po anulowaniu odrzucone:", type(e).__name__)
        try:
            async with websockets.connect(ws_url, origin="https://evil.example") as ws3:
                await ws3.recv()
        except Exception as e:  # noqa: BLE001
            print("zly Origin odrzucony:", type(e).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
