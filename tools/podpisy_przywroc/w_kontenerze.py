"""Diagnoza i przywrócenie podpisów protokołu ProEl - uruchamiane W KONTENERZE backendu.

Nie importuje `app.db` (ten przy imporcie robi create_all) - łączy się sam przez
`DATABASE_URL`, tak jak `tools/raport_dowodowy/zrzut.py`.

Wołany przez `przywroc.py` z komputera administratora:
    echo <base64 gzip> | base64 -d | gunzip | python - SM/61 [opcje]

DOMYŚLNIE TYLKO CZYTA (sesja READ ONLY, wycofanie transakcji). Zapis wymaga
`--zapisz` i odbywa się w jednej transakcji z blokadą wierszy meczu.

SKĄD WIEMY, KTÓRY PODPIS BYŁ W KTÓREJ RUBRYCE. Migawki wersji
(`proel_match_snapshots`) zdejmują z treści tylko DUŻE wartości. Podpis to dziś
krótki adres `/static/<uuid>.png`, więc zostaje w migawce dokładnie w swojej
rubryce. To samo dotyczy wersji odłożonych przy sporze (`proel_doc_history`).
Kandydat do przywrócenia to OSTATNI niepusty adres, jaki dana rubryka miała
w którejkolwiek zapisanej wersji - nie domysł z kolejności składania.

CO ROBI ZAPIS (dla każdej przywracanej rubryki):
  * wpis w overlayu pól (`proel_match_state.fields_json`) - od tej chwili
    reprojekcja nakłada podpis na KAŻDY kolejny pełny zapis z dowolnego
    telefonu, więc nie da się go już zgubić pełnym zapisem,
  * ten sam adres w bieżącej treści protokołu (`proel_matches.data_json`),
  * wpis „match.signed" w dzienniku meczu z adnotacją o przywróceniu.
Rubryki z podpisem NIE są ruszane (chyba że `--nadpisz`). Mecz zatwierdzony
wymaga `--mimo-zatwierdzenia`.
"""
import argparse
import datetime as dt
import gzip
import json
import os
import re
import sys
import zlib

import psycopg2
import psycopg2.extras

ROLE = ("referee1", "referee2", "secretary", "timekeeper", "delegate", "delegate2")
NAZWY_ROL = {
    "referee1": "sędzia 1",
    "referee2": "sędzia 2",
    "secretary": "sekretarz",
    "timekeeper": "mierzący czas",
    "delegate": "delegat",
    "delegate2": "delegat 2",
}
#: Ścieżka rejestru -> droga w treści protokołu (`project_*` w app/proel_fields.py).
SCIEZKI = {f"official.{r}.signature": ("matchConfig", "extras", "officials", r, "signature") for r in ROLE}
SCIEZKI.update(
    {
        "sig.team.host": ("matchConfig", "extras", "hostTeamSignature"),
        "sig.team.guest": ("matchConfig", "extras", "guestTeamSignature"),
        "medic.signature": ("matchConfig", "extras", "medic", "signature"),
    }
)
KTO = {f"official.{r}.signature": NAZWY_ROL[r] for r in ROLE}
KTO.update({"sig.team.host": "drużyna gospodarzy", "sig.team.guest": "drużyna gości", "medic.signature": "medyk"})

AKTOR = {
    "judge_id": "",
    "name": "Przywrócenie podpisów (administrator)",
    "install": "admin-restore",
    "verified": True,
}


def _czas(v):
    if v is None:
        return ""
    if isinstance(v, dt.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=dt.timezone.utc)
        # Czas polski (CET/CEST) - tak czyta to administrator.
        return v.astimezone(dt.timezone(dt.timedelta(hours=1))).strftime("%d.%m %H:%M:%S")
    return str(v)


def _json(v):
    if v is None:
        return None
    if isinstance(v, memoryview):
        v = bytes(v)
    if isinstance(v, bytes):
        for fn in (zlib.decompress, gzip.decompress):
            try:
                return json.loads(fn(v).decode("utf-8"))
            except Exception:
                continue
        return None
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


def _wez(blob, droga):
    cur = blob
    for k in droga:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _poloz(blob, droga, wartosc):
    cur = blob
    for k in droga[:-1]:
        nxt = cur.get(k)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[k] = nxt
        cur = nxt
    cur[droga[-1]] = wartosc


def _podpis(v):
    """Prawdziwy podpis (adres serwera albo obrazek), nie ślad po zdjęciu."""
    if not isinstance(v, str):
        return ""
    s = v.strip()
    if not s or s.startswith("[zdjęto:"):
        return ""
    if s.startswith(("file:", "content:", "ph:")):
        return ""  # ścieżka z telefonu - PDF jej nie otworzy
    return s


def _krotko(v):
    s = _podpis(v)
    if not s:
        return "-"
    if s.startswith("data:"):
        return f"obrazek w treści ({len(s) // 1024} KB)"
    return s.rsplit("/", 1)[-1]


def _wiersze(cur, sql, args):
    cur.execute(sql, args)
    return cur.fetchall()


def _tabela_istnieje(cur, nazwa):
    cur.execute("SELECT to_regclass(%s) IS NOT NULL AS jest", (nazwa,))
    return bool(cur.fetchone()["jest"])


def _plik_istnieje(url):
    if not url.startswith("/static/"):
        return None
    katalog = os.path.join(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") or "", "static")
    return os.path.isfile(os.path.join(katalog, url.rsplit("/", 1)[-1]))


def zbierz(cur, klucz):
    """Wszystko, co baza wie o podpisach tego meczu - sam odczyt."""
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
        sys.exit(3)
    stan = (_wiersze(cur, "SELECT * FROM proel_match_state WHERE match_number = %s", (klucz,)) or [None])[0]
    migawki = _wiersze(
        cur,
        "SELECT id, created_at, source, milestone, doc_rev, writer_name, writer_judge, writer_install, payload "
        "FROM proel_match_snapshots WHERE match_number = %s ORDER BY created_at, id",
        (klucz,),
    )
    historia = []
    if _tabela_istnieje(cur, "proel_doc_history"):
        historia = _wiersze(
            cur,
            "SELECT id, archived_at, written_at, reason, doc_rev, writer_name, writer_install, "
            "archived_by_name, data_json FROM proel_doc_history WHERE match_number = %s ORDER BY archived_at, id",
            (klucz,),
        )
    dziennik = _wiersze(
        cur,
        "SELECT id, created_at, event, actor_judge_id, actor_name, actor_install, actor_verified, "
        "details_json, app_version, client_ip FROM proel_activity_log WHERE match_number = %s "
        "ORDER BY created_at, id",
        (klucz,),
    )
    return mecz[0], stan, migawki, historia, dziennik


def przebieg_rubryk(mecz, stan, migawki, historia):
    """Dla każdej rubryki: kolejne wartości w czasie (tylko zmiany) + stan bieżący."""
    zrodla = []  # (czas, opis, blob)
    for m in migawki:
        blob = _json(m["payload"])
        if isinstance(blob, dict):
            kto = m["writer_name"] or m["writer_install"] or "?"
            zrodla.append((m["created_at"], f"migawka #{m['id']} ({m['source']}, rev {m['doc_rev']}, {kto})", blob))
    for h in historia:
        blob = _json(h["data_json"])
        if isinstance(blob, dict):
            kto = h["writer_name"] or h["writer_install"] or "?"
            zrodla.append(
                (h["written_at"] or h["archived_at"], f"wersja odłożona #{h['id']} ({h['reason']}, rev {h['doc_rev']}, {kto})", blob)
            )
    zrodla.sort(key=lambda z: z[0] or dt.datetime.min.replace(tzinfo=dt.timezone.utc))

    overlay = _json(stan["fields_json"]) if stan else {}
    overlay = overlay if isinstance(overlay, dict) else {}
    tresc = _json(mecz["data_json"]) or {}

    wynik = {}
    for sciezka, droga in SCIEZKI.items():
        zmiany = []
        poprzednia = None
        ostatni_niepusty = None
        for czas, opis, blob in zrodla:
            v = _podpis(_wez(blob, droga))
            if v != poprzednia:
                zmiany.append((czas, opis, v))
                poprzednia = v
            if v:
                ostatni_niepusty = (czas, opis, v)
        wpis = overlay.get(sciezka)
        wynik[sciezka] = {
            "zmiany": zmiany,
            "ostatni": ostatni_niepusty,
            "overlay": wpis if isinstance(wpis, dict) else None,
            "w_overlayu": _podpis((wpis or {}).get("v")) if isinstance(wpis, dict) else "",
            "w_tresci": _podpis(_wez(tresc, droga)),
        }
    return wynik, overlay, tresc


def drukuj_diagnoze(klucz, mecz, stan, migawki, historia, dziennik, rubryki, cur):
    print(f"=== PODPISY {klucz} - DIAGNOZA (czas polski) ===")
    print(
        f"status: {mecz['status']}  doc_rev: {mecz.get('doc_rev')}  ostatni zapis treści: "
        f"{mecz.get('doc_writer_name') or '?'} {_czas(mecz.get('doc_written_at'))}"
    )
    print(f"migawki: {len(migawki)}  wersje odłożone: {len(historia)}  wpisy dziennika: {len(dziennik)}")

    guard = _json(stan["guard_json"]) if stan else None
    obsada = (guard or {}).get("officials") if isinstance(guard, dict) else None
    print("\n--- obsada znana serwerowi (od niej zależy rola piszącego) ---")
    if isinstance(obsada, dict) and obsada:
        for r in ROLE:
            o = obsada.get(r)
            if o in (None, "", {}):
                continue
            if isinstance(o, dict):
                print(f"  {NAZWY_ROL[r]:14} {o.get('name') or '-':28} nr: {o.get('judgeId') or '-'}")
            else:
                print(f"  {NAZWY_ROL[r]:14} {o}")
    else:
        print("  brak (serwer przepuszcza wtedy każdego)")

    print("\n--- rubryki podpisów: teraz i w historii ---")
    for sciezka, r in rubryki.items():
        if not (any(v for _, _, v in r["zmiany"]) or r["overlay"] or r["w_tresci"]):
            continue
        ov = r["overlay"]
        ov_opis = "brak wpisu"
        if ov:
            by = ov.get("by") or {}
            ov_opis = (
                f"{_krotko(ov.get('v'))} (rev {ov.get('rev')}, {ov.get('src')}, "
                f"{by.get('name') or by.get('install') or '?'}, {ov.get('at', '')[:19]})"
            )
        print(f"\n  [{KTO[sciezka]}] {sciezka}")
        print(f"    overlay pól : {ov_opis}")
        print(f"    treść teraz : {_krotko(r['w_tresci'])}")
        for czas, opis, v in r["zmiany"]:
            print(f"    {_czas(czas)}  {_krotko(v):45} <- {opis}")

    print("\n--- dziennik: podpisy, spory wersji, wysyłki, zapisy pól ---")
    ciekawe = re.compile(r"sign|conflict|overwrite|restore|zprp\.|protocol|pdf|approved|status|field\.changed|lease|takeover", re.I)
    for d in dziennik:
        if not ciekawe.search(d["event"] or ""):
            continue
        det = _json(d["details_json"]) or {}
        skrot = ""
        if isinstance(det, dict):
            if det.get("signatures"):
                skrot = ", ".join(str(s.get("who") or s.get("path")) for s in det["signatures"] if isinstance(s, dict))
            elif det.get("paths"):
                skrot = ", ".join(str(p) for p in det["paths"])[:160]
            else:
                skrot = json.dumps(det, ensure_ascii=False)[:160]
        kto = f"{d['actor_name'] or '?'} [{d['actor_judge_id'] or '-'}{' ✓' if d['actor_verified'] else ''}]"
        print(f"  {_czas(d['created_at'])}  {d['event']:26} {kto:40} {skrot}")

    print("\n--- audyt overlaya: KTÓRE zapisy podpisów serwer PRZYJĄŁ ---")
    audyt = _json(stan["audit_json"]) if stan else None
    log = audyt.get("log") if isinstance(audyt, dict) else None
    przyjete = 0
    for n in log or []:
        sciezki = [p for p in (n.get("paths") or []) if p in SCIEZKI]
        if not sciezki:
            continue
        przyjete += 1
        by = n.get("by") or {}
        print(
            f"  {str(n.get('at', ''))[:19]}  {', '.join(KTO[p] for p in sciezki):40} "
            f"{by.get('name') or '?'} [{by.get('judge_id') or '-'}] urządzenie {str(by.get('install') or '?')[:12]}"
        )
    if not przyjete:
        print("  (w audycie nie ma żadnego przyjętego zapisu podpisu)")
    print(
        "  Podpis, który telefon wysłał (POST /proel/patch), a którego tu nie ma, serwer ODRZUCIŁ\n"
        "  w odpowiedzi 200 (pole `rejected`) - telefon trzymał go potem tylko w swojej treści."
    )

    adresy = sorted({r["ostatni"][2] for r in rubryki.values() if r["ostatni"] and r["ostatni"][2].startswith("/static/")})
    if adresy:
        print("\n--- pliki podpisów na serwerze ---")
        for a in adresy:
            wiersz = _wiersze(cur, "SELECT id, created_at, signed_at FROM signatures WHERE image_url = %s", (a,))
            w = wiersz[0] if wiersz else None
            plik = _plik_istnieje(a)
            print(
                f"  {a.rsplit('/', 1)[-1]}  nr {w['id'] if w else '?'}  wysłany {_czas(w['created_at']) if w else '?'}  "
                f"złożony {_czas(w['signed_at']) if w else '?'}  plik: {'jest' if plik else ('BRAK' if plik is False else '?')}"
            )


def plan_przywrocenia(rubryki, recznie, tylko, nadpisz):
    plan = []
    for sciezka, r in rubryki.items():
        if tylko and sciezka not in tylko:
            continue
        teraz = r["w_overlayu"] or r["w_tresci"]
        if sciezka in recznie:
            cel, skad = recznie[sciezka], "wskazany ręcznie (--podpis)"
        elif r["ostatni"]:
            cel, skad = r["ostatni"][2], f"{r['ostatni'][1]}, {_czas(r['ostatni'][0])}"
        else:
            continue
        if teraz == cel:
            continue
        if teraz and not nadpisz:
            continue
        # Pusty wpis w overlayu to świadome skasowanie - przywracamy tylko,
        # gdy administrator wskazał rubrykę wprost.
        ov = r["overlay"]
        if ov is not None and not r["w_overlayu"] and sciezka not in recznie and not (tylko and sciezka in tylko):
            plan.append({"sciezka": sciezka, "cel": cel, "skad": skad, "pominiete": "w overlayu stoi PUSTY wpis (ktoś skasował podpis) - wskaż rubrykę przez --tylko, jeśli to błąd"})
            continue
        plan.append({"sciezka": sciezka, "cel": cel, "skad": skad, "pominiete": None})
    return plan


def zapisz(conn, klucz, plan, mimo_zatwierdzenia, nadpisz):
    teraz = dt.datetime.now(dt.timezone.utc)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM proel_matches WHERE match_number = %s FOR UPDATE", (klucz,))
        mecz = cur.fetchone()
        cur.execute("SELECT * FROM proel_match_state WHERE match_number = %s FOR UPDATE", (klucz,))
        stan = cur.fetchone()
        if mecz is None or stan is None:
            raise SystemExit("BŁĄD: brak wiersza meczu albo stanu pól - nic nie zapisano.")
        if mecz["status"] == "approved" and not mimo_zatwierdzenia:
            raise SystemExit("BŁĄD: protokół jest zatwierdzony. Cofnij zatwierdzenie albo dodaj --mimo-zatwierdzenia.")

        overlay = _json(stan["fields_json"]) or {}
        tresc = _json(mecz["data_json"]) or {}
        rev = int(stan["rev"] or 0) + 1
        zrobione = []
        for p in plan:
            if p["pominiete"]:
                continue
            sciezka, cel = p["sciezka"], p["cel"]
            wpis = overlay.get(sciezka) if isinstance(overlay.get(sciezka), dict) else None
            teraz_v = _podpis((wpis or {}).get("v")) or _podpis(_wez(tresc, SCIEZKI[sciezka]))
            if teraz_v and teraz_v != cel and not nadpisz:
                print(f"  pomijam {sciezka}: w międzyczasie ktoś złożył podpis ({_krotko(teraz_v)})")
                continue
            overlay[sciezka] = {
                "v": cel,
                "rev": rev,
                "at": teraz.isoformat(),
                "by": dict(AKTOR),
                "src": "restore",
                "superseded_at": None,
            }
            _poloz(tresc, SCIEZKI[sciezka], cel)
            zrobione.append({"path": sciezka, "who": KTO[sciezka], "restored_from": p["skad"]})
        if not zrobione:
            print("Nic do zapisania.")
            conn.rollback()
            return

        audyt = _json(stan["audit_json"])
        audyt = audyt if isinstance(audyt, dict) else {"log": [], "ops": []}
        log = list(audyt.get("log") or [])
        log.append({"at": teraz.isoformat(), "by": dict(AKTOR), "paths": [z["path"] for z in zrobione], "note": "przywrócenie podpisów"})
        audyt["log"] = log[-200:]

        cur.execute(
            "UPDATE proel_match_state SET fields_json = %s, rev = %s, audit_json = %s, updated_at = now() "
            "WHERE match_number = %s",
            (psycopg2.extras.Json(overlay), rev, psycopg2.extras.Json(audyt), klucz),
        )
        # Bez podbicia doc_rev: telefony nie dostaną arkusza sporu wersji, a podpis
        # i tak wróci do nich przez overlay (long-poll `/proel/state`).
        cur.execute(
            "UPDATE proel_matches SET data_json = %s, updated_at = now() WHERE match_number = %s",
            (psycopg2.extras.Json(tresc), klucz),
        )
        cur.execute(
            "INSERT INTO proel_activity_log (match_number, zprp_match_id, event, actor_judge_id, actor_name, "
            "actor_install, actor_verified, details_json, event_key, created_at) "
            "VALUES (%s, %s, 'match.signed', %s, %s, %s, true, %s, %s, now())",
            (
                klucz,
                mecz.get("zprp_match_id"),
                "",
                AKTOR["name"],
                AKTOR["install"],
                psycopg2.extras.Json({"signatures": zrobione, "rev": rev, "restored": True}),
                f"restore-sig:{klucz}:{rev}",
            ),
        )
    conn.commit()
    print(f"ZAPISANO: {len(zrobione)} podpis(y), rev pól {rev}.")
    for z in zrobione:
        print(f"  {z['who']:20} <- {z['restored_from']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mecz")
    ap.add_argument("--zapisz", action="store_true")
    ap.add_argument("--podpis", action="append", default=[], help="sciezka=adres, np. official.secretary.signature=/static/x.png")
    ap.add_argument("--tylko", default="", help="lista ścieżek po przecinku")
    ap.add_argument("--nadpisz", action="store_true")
    ap.add_argument("--mimo-zatwierdzenia", action="store_true")
    a = ap.parse_args()

    klucz = a.mecz.strip()
    recznie = {}
    for p in a.podpis:
        s, _, v = p.partition("=")
        s, v = s.strip(), v.strip()
        if s not in SCIEZKI or not _podpis(v):
            raise SystemExit(f"BŁĄD: zła para --podpis {p!r} (znane ścieżki: {', '.join(SCIEZKI)})")
        recznie[s] = v
    tylko = {s.strip() for s in a.tylko.split(",") if s.strip()}
    nieznane = tylko - set(SCIEZKI)
    if nieznane:
        raise SystemExit(f"BŁĄD: nieznane ścieżki w --tylko: {', '.join(sorted(nieznane))}")

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.set_session(readonly=True, autocommit=False)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    mecz, stan, migawki, historia, dziennik = zbierz(cur, klucz)
    rubryki, _, _ = przebieg_rubryk(mecz, stan, migawki, historia)
    drukuj_diagnoze(klucz, mecz, stan, migawki, historia, dziennik, rubryki, cur)

    plan = plan_przywrocenia(rubryki, recznie, tylko, a.nadpisz)
    print("\n=== PLAN PRZYWRÓCENIA ===")
    if not plan:
        print("  Nie ma czego przywracać: każda rubryka z historią ma dziś swój podpis.")
    for p in plan:
        flaga = "POMIJAM" if p["pominiete"] else "PRZYWRÓCĘ"
        plik = _plik_istnieje(p["cel"])
        print(f"  {flaga:10} {KTO[p['sciezka']]:20} {_krotko(p['cel'])}  plik: {'jest' if plik else ('BRAK' if plik is False else '?')}")
        print(f"             źródło: {p['skad']}")
        if p["pominiete"]:
            print(f"             powód: {p['pominiete']}")
    conn.rollback()
    conn.close()

    if not a.zapisz:
        print("\n(tryb diagnozy - nic nie zapisano; zapis: --zapisz)")
        return
    if not [p for p in plan if not p["pominiete"]]:
        print("\nNic do zapisania.")
        return
    braki = [p for p in plan if not p["pominiete"] and _plik_istnieje(p["cel"]) is False]
    if braki:
        raise SystemExit("BŁĄD: brak pliku podpisu na dysku serwera - nic nie zapisano: " + ", ".join(KTO[p["sciezka"]] for p in braki))

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.set_session(autocommit=False)
    try:
        zapisz(conn, klucz, plan, a.mimo_zatwierdzenia, a.nadpisz)
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
