"""Zrzut pełnego zapisu jednego meczu ProEl - uruchamiany W KONTENERZE backendu.

TYLKO ODCZYT: sesja bazy jest READ ONLY i kończy się wycofaniem transakcji.
Skrypt nie importuje `app.db` (ten przy imporcie robi create_all, patrz pamięć
projektu), łączy się sam przez `DATABASE_URL`.

Wołany przez `raport.py`, który przesyła go przez `railway ssh` jako base64:
    echo <base64> | base64 -d | python - "SK/24"

Wynik idzie na standardowe wyjście między znacznikami, jako base64 z gzip-a
JSON-a. Suma SHA-256 paczki leci osobną linijką - po drugiej stronie sprawdzamy,
że nic nie zgubiło się po drodze przez terminal.
"""
import base64
import datetime as dt
import decimal
import gzip
import hashlib
import json
import os
import sys
import zlib

import psycopg2
import psycopg2.extras

WERSJA = 1


def _jawne(v):
    """Wartość z bazy jako coś, co da się zapisać w JSON-ie."""
    if isinstance(v, (dt.datetime, dt.date)):
        if isinstance(v, dt.datetime) and v.tzinfo is None:
            v = v.replace(tzinfo=dt.timezone.utc)
        return v.isoformat()
    if isinstance(v, decimal.Decimal):
        return str(v)
    if isinstance(v, memoryview):
        v = bytes(v)
    if isinstance(v, bytes):
        for fn in (zlib.decompress, gzip.decompress):
            try:
                tekst = fn(v).decode("utf-8")
            except Exception:
                continue
            try:
                return json.loads(tekst)
            except ValueError:
                return tekst
        return {"_bajty_base64": base64.b64encode(v).decode("ascii")}
    if isinstance(v, str) and v[:1] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _wiersze(cur, sql, args):
    cur.execute(sql, args)
    return [{k: _jawne(v) for k, v in r.items()} for r in cur.fetchall()]


def main():
    klucz = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
    if not klucz:
        print("BŁĄD: podaj numer meczu, np. SK/24")
        sys.exit(2)

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.set_session(readonly=True, autocommit=False)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    mecz = _wiersze(cur, "SELECT * FROM proel_matches WHERE match_number = %s", (klucz,))
    if not mecz:
        podobne = _wiersze(
            cur,
            "SELECT match_number, status FROM proel_matches WHERE match_number ILIKE %s "
            "ORDER BY updated_at DESC NULLS LAST LIMIT 20",
            (f"%{klucz}%",),
        )
        print(f"BŁĄD: nie ma meczu o kluczu {klucz!r}.")
        for p in podobne:
            print(f"  podobny: {p['match_number']!r} ({p['status']})")
        conn.rollback()
        sys.exit(3)
    zprp_id = mecz[0].get("zprp_match_id")

    zrzut = {
        "narzedzie": {"nazwa": "raport_dowodowy/zrzut.py", "wersja": WERSJA},
        "wykonano": dt.datetime.now(dt.timezone.utc).isoformat(),
        "klucz": klucz,
        "mecz": mecz[0],
        "stan": (_wiersze(cur, "SELECT * FROM proel_match_state WHERE match_number = %s", (klucz,)) or [None])[0],
        "migawki": _wiersze(
            cur,
            "SELECT * FROM proel_match_snapshots WHERE match_number = %s ORDER BY created_at, id",
            (klucz,),
        ),
        "dziennik": _wiersze(
            cur,
            "SELECT * FROM proel_activity_log WHERE match_number = %s ORDER BY created_at, id",
            (klucz,),
        ),
        "historia_sporow": _wiersze(
            cur,
            "SELECT * FROM proel_doc_history WHERE match_number = %s ORDER BY archived_at, id",
            (klucz,),
        ),
        "usuniete": _wiersze(
            cur,
            "SELECT * FROM proel_deleted_matches WHERE match_number = %s ORDER BY deleted_at, id",
            (klucz,),
        ),
        "protokoly_pdf": _wiersze(
            cur,
            "SELECT * FROM protocol_audit WHERE match_number = %s "
            "OR (%s IS NOT NULL AND match_id = %s) ORDER BY created_at",
            (klucz, zprp_id, zprp_id),
        ),
    }
    conn.rollback()
    conn.close()

    paczka = gzip.compress(
        json.dumps(zrzut, ensure_ascii=False, default=str).encode("utf-8"), 9
    )
    tekst = base64.b64encode(paczka).decode("ascii")
    print("===ZRZUT-POCZATEK===")
    for i in range(0, len(tekst), 76):
        print(tekst[i:i + 76])
    print("===ZRZUT-KONIEC===")
    print(f"===SHA256 {hashlib.sha256(paczka).hexdigest()}===")
    print(
        f"===LICZNIKI migawki={len(zrzut['migawki'])} dziennik={len(zrzut['dziennik'])} "
        f"pdf={len(zrzut['protokoly_pdf'])} bajty={len(paczka)}==="
    )


if __name__ == "__main__":
    main()
