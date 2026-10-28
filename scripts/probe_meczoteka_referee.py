"""Próba TYLKO DO ODCZYTU: czy Meczoteka szuka po sędzi i w jakim polu zwraca obsadę (Trybuna Mentora).

Uruchamiana w kontenerze zprp-backend (ma BASTION_CONNECTOR_URL i BASTION_CONNECTOR_TOKEN), bez importu `app.db`.
Woła connector `GET /games/search` (połączenie domyślne) dla nazwiska sędziego, kolejno z parametrami portalu
q / referee / referees / referee_name / judge / sedzia, i drukuje: liczbę wyników, nazwy pól wiersza (`row_keys`),
sędziów z pierwszej kasety i pierwsze 3 tytuły. Niczego nie zapisuje, nie loguje ciasteczek ani tokenów.

Użycie:  python probe_meczoteka_referee.py "Jan Kowalski" [scope=default [data_od data_do]]   (z datami dodatkowo próba parametrów dat portalu)
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

PARAMS = ("q", "referee", "referees", "referee_name", "judge", "sedzia")


def call(base: str, token: str, scope: str, name: str, param: str, portal: str = "", limit: int = 10, offset: int = 0, video: str = "any") -> dict:
    args = {"scope": scope, "video": video, "limit": limit, "offset": offset, "debug": "true"}
    if name:
        args.update(referee=name, referee_param=param)
    if portal:
        args["portal"] = portal
    query = urllib.parse.urlencode(args)
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
        print(f"   wiersze: surowe={body.get('rows_raw')} po normalizacji={body.get('rows_kept')}")
        for raw in (body.get("raw_sample") or [])[:3]:
            print("   SUROWY:", json.dumps({k: raw.get(k) for k in ("id", "bunny_item_id", "video_state", "video_coverage", "nominees")}, ensure_ascii=False))
        if games:
            print("   row_keys:", body.get("row_keys"))
            print("   sędziowie 1. kasety:", games[0].get("referees"))
            for g in games[:3]:
                print("   ", g.get("bunny_item_id"), g.get("title"), g.get("date"), "|", [r.get("name") for r in g.get("referees") or []])


def probe_dates(base: str, token: str, scope: str, d1: str, d2: str) -> None:
    """Czy portal filtruje daty? Dla kazdej pary parametrow: total i daty wierszy (limit 50) wobec odpowiedzi bez parametrow."""
    print(f"=== DATY {d1} .. {d2}: czy portal zna parametry dat (total maleje, wiersze w zakresie) ===")
    base_out = call(base, token, scope, "", "q", "", 50)
    bb = base_out["body"] if isinstance(base_out["body"], dict) else {}
    print(f"--- bez parametrow: http={base_out['http']} total={bb.get('total')} wierszy={len(bb.get('games') or [])}")
    for k1, k2 in (("date_from", "date_to"), ("from", "to"), ("date_start", "date_end"), ("since", "until"), ("date", None)):
        portal = f"{k1}={d1}" + (f"&{k2}={d2}" if k2 else "")
        out = call(base, token, scope, "", "q", portal, 50)
        body = out["body"] if isinstance(out["body"], dict) else {}
        games = body.get("games") or []
        days = [str(g.get("date"))[:10] for g in games]
        inside = sum(1 for d in days if d1 <= d <= d2)
        print(f"--- {portal}: http={out['http']} total={body.get('total')} wierszy={len(games)} w_zakresie={inside} "
              f"pierwsza={days[:1]} ostatnia={days[-1:]}")
    print("Wniosek: portal filtruje, gdy total jest wyraznie mniejszy niz bez parametrow i prawie wszystkie wiersze sa w zakresie.")


def probe_order(base: str, token: str, scope: str) -> None:
    """Czy lista jest monotonicznie malejaca po dacie (podstawa wyszukiwania binarnego) i czy video=with zmienia total?"""
    print("=== PORZADEK: daty wierszy z offsetow 0, total/2, total-50 (limit 50) ===")
    first = call(base, token, scope, "", "q", "", 50, 0)
    body = first["body"] if isinstance(first["body"], dict) else {}
    total = body.get("total") or 0
    print(f"--- total={total} (video=any)")
    seen = []
    for off in (0, max(total // 2 // 50 * 50, 0), max(total - 50, 0)):
        out = call(base, token, scope, "", "q", "", 50, off)
        games = (out["body"] if isinstance(out["body"], dict) else {}).get("games") or []
        days = [str(g.get("date"))[:10] for g in games]
        seen.append((off, days[:1], days[-1:]))
        print(f"   offset={off}: wierszy={len(games)} pierwsza={days[:1]} ostatnia={days[-1:]} malejaco_w_stronie={days == sorted(days, reverse=True)}")
    firsts_lasts = [d for _, f, l in seen for d in (f + l) if d]
    print("   MONOTONICZNIE MALEJACO miedzy offsetami:", firsts_lasts == sorted(firsts_lasts, reverse=True))
    withv = call(base, token, scope, "", "q", "", 50, 0, "with")
    wb = withv["body"] if isinstance(withv["body"], dict) else {}
    print(f"--- video=with: total={wb.get('total')} (any: {total}) -> {'ZMIENIA total' if wb.get('total') != total else 'bez zmiany'}")


if __name__ == "__main__":
    main()
    if len(sys.argv) > 4:
        probe_dates(os.environ.get("BASTION_CONNECTOR_URL", "").rstrip("/"), os.environ.get("BASTION_CONNECTOR_TOKEN", ""),
                    sys.argv[2], sys.argv[3], sys.argv[4])
        probe_order(os.environ.get("BASTION_CONNECTOR_URL", "").rstrip("/"), os.environ.get("BASTION_CONNECTOR_TOKEN", ""), sys.argv[2])
