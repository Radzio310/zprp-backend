"""Próba TYLKO DO ODCZYTU: czy Meczoteka szuka po sędzi i w jakim polu zwraca obsadę (Trybuna Mentora).

Uruchamiana w kontenerze zprp-backend (ma BASTION_CONNECTOR_URL i BASTION_CONNECTOR_TOKEN), bez importu `app.db`.
Woła connector `GET /games/search` (połączenie domyślne) dla nazwiska sędziego, kolejno z parametrami portalu
q / referee / referees / referee_name / judge / sedzia, i drukuje: liczbę wyników, nazwy pól wiersza (`row_keys`),
sędziów z pierwszej kasety i pierwsze 3 tytuły. Niczego nie zapisuje, nie loguje ciasteczek ani tokenów.

Użycie:  python probe_meczoteka_referee.py "Jan Kowalski" [scope=default]
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

PARAMS = ("q", "referee", "referees", "referee_name", "judge", "sedzia")


def call(base: str, token: str, scope: str, name: str, param: str) -> dict:
    query = urllib.parse.urlencode({"scope": scope, "referee": name, "referee_param": param, "video": "any", "limit": 10})
    req = urllib.request.Request(f"{base}/games/search?{query}", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=40) as res:
            return {"http": res.status, "body": json.loads(res.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:
        return {"http": exc.code, "body": {"error": exc.read().decode("utf-8", "replace")[:200]}}
    except Exception as exc:  # noqa: BLE001
        return {"http": None, "body": {"error": type(exc).__name__}}


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else ""
    scope = sys.argv[2] if len(sys.argv) > 2 else "default"
    base = os.environ.get("BASTION_CONNECTOR_URL", "").rstrip("/")
    token = os.environ.get("BASTION_CONNECTOR_TOKEN", "")
    if not name or not base or not token:
        print("Podaj nazwisko; wymagane BASTION_CONNECTOR_URL i BASTION_CONNECTOR_TOKEN w środowisku.")
        return
    for param in PARAMS:
        out = call(base, token, scope, name, param)
        body = out["body"] if isinstance(out["body"], dict) else {}
        games = body.get("games") or []
        print(f"--- {param}: http={out['http']} wyników={len(games)} total={body.get('total')} has_more={body.get('has_more')}")
        if body.get("error"):
            print("   błąd:", body["error"])
        if games:
            print("   row_keys:", body.get("row_keys"))
            print("   sędziowie 1. kasety:", games[0].get("referees"))
            for g in games[:3]:
                print("   ", g.get("bunny_item_id"), g.get("title"), g.get("date"), "|", [r.get("name") for r in g.get("referees") or []])


if __name__ == "__main__":
    main()
