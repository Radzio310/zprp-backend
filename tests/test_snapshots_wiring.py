"""Wpiecie migawek meczu - sprawdzane ODCZYTEM ZRODLA.

`app/proel.py` importuje `app/db.py`, ktory przy imporcie zaklada schemat i
wymaga zywego Postgresa (ten sam powod co w `test_proel_approve_guard.py`).
Reguly maja wlasne testy bez bazy (`test_snapshot_rules.py`) - tutaj pilnujemy
tego, czego regula nie widzi: GDZIE i W JAKIEJ KOLEJNOSCI jest wolana.

Zasada nadrzedna calej funkcji: MIGAWKA NIE MA PRAWA ZEPSUC ZAPISU MECZU.
"""
from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def function_source(name: str, func: str) -> str:
    """Zrodlo funkcji ALBO klasy - modele zadan tez sa regula do pilnowania."""
    tree = ast.parse(source(name))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and node.name == func:
            return ast.unparse(node)
    raise AssertionError(f"{name}: brak {func}")


# ── migawka nie moze dotknac zapisu meczu ────────────────────────


def test_migawka_powstaje_PO_transakcji_a_nie_w_srodku():
    """Gdyby szla w tej samej transakcji, jej blad wycofalby zapis protokolu."""
    body = function_source("app/proel.py", "update_proel_match")
    tree = ast.parse(body)
    fn = tree.body[0]

    inside = False
    for node in ast.walk(fn):
        if isinstance(node, ast.AsyncWith) and "database.transaction" in ast.unparse(node.items[0]):
            if "record_snapshot" in ast.unparse(node):
                inside = True
    assert not inside, "record_snapshot siedzi w transakcji meczu"
    assert "record_snapshot" in body, "zapis w ogole nie wola migawki"


def test_zapis_migawki_nigdy_nie_rzuca():
    """Sedzia prowadzacy mecz nie ma prawa zobaczyc problemu z archiwum."""
    body = function_source("app/proel_snapshots.py", "record_snapshot")
    tree = ast.parse(body)
    fn = tree.body[0]
    # Cale cialo opakowane: pierwszy element funkcji to `try`.
    assert isinstance(fn.body[-1], ast.Try), "cialo nie jest opakowane w try"
    handlers = " ".join(ast.unparse(h) for h in fn.body[-1].handlers)
    assert "Exception" in handlers
    assert "raise" not in handlers


def test_migawka_niesie_tresc_PO_reprojekcji_overlaya():
    """Ma odlozyc dokladnie to, co poszlo do bazy - nie to, co przyslal telefon.

    Inaczej migawka roznilaby sie od zapisanej wersji o wszystkie pola
    scalane po stronie serwera (podpisy, obsada, badania).
    """
    body = function_source("app/proel.py", "update_proel_match")
    call = body[body.index("record_snapshot") :]
    assert "projected" in call[:600]
    assert "req.data_json" not in call[:600]


# ── mecz i jego historia trzymaja sie razem ──────────────────────


def test_usuniecie_meczu_kasuje_migawki():
    """Usuniety zapis nie ma prawa wracac w panelu historii.

    Kasowanie siedzi w `archive_and_delete_match` - trasa admina jest tylko
    jego opakowaniem, a ta funkcja robi cala robote (archiwum + wiersze).
    """
    body = function_source("app/proel.py", "archive_and_delete_match")
    assert "drop_snapshots" in body
    # Po skasowaniu wiersza meczu, nie przed - inaczej migawka mogla by
    # zniknac przy transakcji, ktora sie nie powiodla.
    assert body.index("delete(saved_matches)") < body.index("drop_snapshots")


def test_awans_szkoleniowego_zabiera_historie_ze_soba():
    """Bez tego os czasu zaczynalaby sie od chwili awansu."""
    body = function_source("app/proel.py", "promote_training_match")
    assert "carry_snapshots" in body


# ── sprzatanie ───────────────────────────────────────────────────


def test_sprzatanie_idzie_PARTIAMI():
    """Jeden DELETE na calej tabeli zablokowalby zapisy na minuty."""
    body = function_source("app/proel_snapshots.py", "cleanup_expired")
    assert "limit" in body
    assert "CLEANUP_BATCH" in source("app/proel_snapshots.py")


def test_petla_sprzatajaca_startuje_z_aplikacja():
    body = source("main.py")
    assert "run_snapshot_cleanup" in body
    assert "asyncio.create_task(run_snapshot_cleanup())" in body


def test_jedna_porazka_nie_konczy_petli():
    body = function_source("app/proel_snapshots.py", "run_snapshot_cleanup")
    assert "while True" in body
    tree = ast.parse(body)
    tries = [n for n in ast.walk(tree) if isinstance(n, ast.Try)]
    assert tries, "petla bez zabezpieczenia - pierwszy blad ja zamknie"


# ── zapory ───────────────────────────────────────────────────────


def test_zapory_sa_wpiete_a_nie_tylko_zadeklarowane():
    body = function_source("app/proel_snapshots.py", "record_snapshot")
    assert "may_store" in body, "limit i odstep nie sa sprawdzane"
    assert "strip_heavy" in body, "podpisy jechalyby do migawki"
    assert "snapshot_hash" in body, "brak odsiewu powtorek"
    assert "too_big" in body, "brak limitu rozmiaru"


def test_za_duza_tresc_zostawia_SAM_wiersz():
    """Wersja ma byc widoczna w osi czasu takze wtedy, gdy nie da sie jej
    przechowac - inaczej dziura w historii wygladalaby jak brak zapisu."""
    body = function_source("app/proel_snapshots.py", "record_snapshot")
    assert "'payload': None if oversized" in body or "None if oversized else pack" in body


# ── trasy: kolejnosc i bramki ────────────────────────────────────


def test_router_migawek_stoi_PRZED_proel_router():
    """`app/proel.py` ma catch-all `/proel/{match_number:path}` - bez tej
    kolejnosci `/proel/snapshots/...` wpadnie tam jako numer meczu."""
    body = source("main.py")
    assert body.index("app.include_router(proel_snapshots_router)") < body.index(
        "app.include_router(proel_router)"
    )


def test_sciezki_stale_stoja_przed_lapaczem():
    """Ta sama pulapka WEWNATRZ routera: `/{match_number:path}` polyka wszystko."""
    body = source("app/proel_snapshots.py")
    catch = body.index('@router.get("/{match_number:path}"')
    assert body.index('@router.get("/matches"') < catch
    assert body.index('@router.get("/one/{snapshot_id}"') < catch


def test_odczyt_i_przywracanie_TYLKO_dla_admina():
    for name in ("snapshot_matches", "snapshot_body", "snapshot_timeline", "restore_snapshot"):
        assert "_require_admin" in function_source("app/proel_snapshots.py", name), name


def test_dosylka_z_telefonu_nie_wymaga_admina_ale_wymaga_tozsamosci():
    """Historie dosyla sedzia prowadzacy, nie administrator."""
    body = function_source("app/proel_snapshots.py", "upload_device_snapshots")
    assert "_require_admin" not in body
    assert "proel_actor" in body
    assert "source='device'" in body or 'source="device"' in body


def test_paczka_z_telefonu_ma_limit():
    body = function_source("app/proel_snapshots.py", "upload_device_snapshots")
    assert "MAX_BATCH" in body


# ── przywracanie: czego nie wolno stracic ────────────────────────


def test_przywracanie_ZACHOWUJE_wersje_nadpisywana():
    """To jest cala roznica miedzy przywroceniem a skasowaniem."""
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "proel_doc_history" in body
    assert "restored_over" in body
    # Archiwum PRZED nadpisaniem - inaczej zapisalibysmy juz nowa tresc.
    assert body.index("proel_doc_history.insert") < body.index("saved_matches.update")


def test_przywracanie_NIE_USUWA_podpisow():
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "merge_signatures_forward" in body
    # I druga droga: overlay naklada sie z wierzchu, tak jak przy kazdym zapisie.
    assert "project(" in body


def test_przywracanie_odmawia_na_zatwierdzonym_protokole():
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "MATCH_APPROVED" in body


def test_przywracanie_odmawia_gdy_mecz_JEST_PROWADZONY():
    """Inaczej telefon nadpisalby przywrocona wersje przy najblizszym takcie."""
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "lease_active" in body
    assert "LEASE_ACTIVE" in body


def test_przywracanie_zostawia_slad_w_dzienniku():
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "match.restored" in body
    assert "log_match_event" in body


def test_przywracanie_jest_kamieniem_milowym_w_historii():
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "milestone='restore'" in body or 'milestone="restore"' in body


def test_powiadomienie_obsady_jest_DOMYSLNIE_WYLACZONE():
    """Decyzja uzytkownika 14.09.2026 - do wyboru admina, domyslnie nie."""
    body = function_source("app/proel_snapshots.py", "RestoreRequest")
    assert "notify_crew: bool = False" in body


def test_overlay_przywracamy_tylko_na_zyczenie():
    """Overlay nie jest wersjonowany nigdzie indziej, wiec jego cofniecie
    jest osobna, swiadoma decyzja - nie skutkiem ubocznym."""
    body = function_source("app/proel_snapshots.py", "RestoreRequest")
    assert "restore_overlay: bool = False" in body


def test_zalozenie_meczu_TEZ_zostawia_migawke():
    """Mecz powstaje POST-em, nie PUT-em.

    Bez tego historia zaczynalaby sie od pierwszego autozapisu, a wersja
    poczatkowa - sklad, obsada, kolory, zanim ktokolwiek cokolwiek zmienil -
    nie istnialaby wcale. To byl realny brak: panel pokazywal "0 wersji"
    dla meczu, ktory dopiero co zalozono.
    """
    body = function_source("app/proel.py", "create_proel_match")
    assert "record_snapshot" in body
    assert "milestone='start'" in body or 'milestone="start"' in body


def test_przywrocenie_nie_podpisuje_sie_urzadzeniem():
    """Inaczej autozapis tego samego telefonu cofnalby przywrocenie po cichu.

    Tozsamosc NIE ginie - kto przywrocil, niosa `doc_writer_judge` i
    `doc_writer_name`. Znika wylacznie prawo do uznania tego za swoj zapis.
    """
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "restore_install(actor.installation_id)" in body
    assert "doc_writer_install=actor.installation_id" not in body
    assert "doc_writer_judge=actor.judge_id" in body


# ── ostatnie zdarzenie wersji: kafel w panelu ────────────────────


def test_wiersz_migawki_niesie_OSTATNIE_ZDARZENIE_protokolu():
    """Panel rysuje wersje ikona tego, co ja odroznia od poprzedniej.

    Bez tych kolumn oś czasu byla szara kolumna taktow: zeby znalezc bramke,
    trzeba bylo wchodzic w kazda wersje po kolei. Liczymy to PRZY ZAPISIE
    migawki, a nie przy odczycie - lista nie ma prawa rozpakowywac tresci
    kilkuset wierszy, zeby pokazac obrazek.
    """
    head = function_source("app/proel_snapshots.py", "_head")
    assert "_last_event(protocol)" in head

    fields = (
        "last_event_type",
        "last_event_team",
        "last_event_player",
        "last_event_ms",
        "last_event_tag",
    )
    row = function_source("app/proel_snapshots.py", "_public_row")
    for field in fields:
        assert field in row, field

    schema = source("app/db.py")
    for column in fields:
        assert column in schema, column


def test_pusty_protokol_nie_udaje_zdarzenia():
    """Brak zdarzenia MUSI byc pusty, a nie zerowy.

    Kafel po stronie telefonu (`utils/matchVersionTile.ts`) rozpoznaje brak
    danych po pustce - zero czytalby jako prawdziwe zdarzenie o numerze 0.
    """
    from app.proel_snapshots import _last_event

    assert _last_event([]) == {}
    assert _last_event(None) == {}
    assert _last_event("nie lista") == {}
    got = _last_event([{"type": "warning", "team": "guest", "player": 7, "time": 812000}])
    assert got["last_event_type"] == "warning"
    assert got["last_event_player"] == 7
    assert got["last_event_ms"] == 812000


def test_czas_dla_druzyny_niesie_swoj_numer_a_nie_zawodnika():
    """Czas dla druzyny zawodnika NIE MA - w protokole ma numer „T2".

    Bez tego kafelek pokazywal przy nim zawodnika nr 0, czyli takiego, ktorego
    nie ma na zadnej liscie meczowej.
    """
    from app.proel_snapshots import _last_event

    got = _last_event(
        [{"type": "teamTime", "team": "guest", "extra": "T2", "time": 1320000}]
    )
    assert got["last_event_tag"] == "T2"


def test_do_plakietki_nie_wchodzi_caly_JSON_z_usunietej_bramki():
    """To samo pole `extra` niesie przy usunietej bramce caly obiekt JSON.

    Kafelek nie ma go gdzie pokazac, a proba zmiescilaby w plakietce polowe
    zapisu czasu pierwotnego.
    """
    from app.proel_snapshots import _last_event

    got = _last_event(
        [
            {
                "type": "goalRemoved",
                "team": "host",
                "player": 7,
                "extra": '{"origTime": 1200, "penalty": false}',
                "time": 1300,
            }
        ]
    )
    assert got["last_event_tag"] is None


# ── slady w dzienniku: kazda dziura ma sie wytlumaczyc ───────────


def test_limit_migawek_zostawia_wpis_w_dzienniku():
    """Dziura w historii wyglada tak samo, jak mecz, ktorego nikt nie prowadzil.

    Klucz zdarzenia gasi powtorzenia - jeden wpis na mecz na dobe, a nie setka.
    """
    body = function_source("app/proel_snapshots.py", "record_snapshot")
    assert "match.snapshot_limit" in body
    assert "event_key=f'snapshot_limit:" in body or 'event_key=f"snapshot_limit:' in body


def test_doslylka_z_telefonu_zostawia_wpis_tylko_gdy_cos_przyjeto():
    """Paczka samych powtorek nie jest zdarzeniem - nic sie nie stalo."""
    body = function_source("app/proel_snapshots.py", "upload_device_snapshots")
    assert "match.snapshots_backfilled" in body
    tree = ast.parse(body)
    guarded = False
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and "match.snapshots_backfilled" in ast.unparse(node):
            if ast.unparse(node.test).strip() == "accepted":
                guarded = True
    assert guarded, "wpis powstaje takze przy zerowej paczce"


def test_przyjecie_wersji_z_serwera_zostawia_wpis():
    """Inaczej zapisy z jednego telefonu urywaja sie w dzienniku bez powodu."""
    body = function_source("app/proel.py", "post_proel_history")
    assert "match.version_adopted" in body


def test_cwiczenie_melduje_sie_w_dzienniku_MECZU_OFICJALNEGO():
    """Wpis pod kluczem szkoleniowym nie mowilby nikomu niczego.

    Pytanie brzmi: „czemu ten mecz ma drugi zapis obok prawdziwego" - i zadaje
    sie je przy MECZU, a nie przy cwiczeniu.
    """
    body = function_source("app/proel.py", "create_proel_match")
    assert "match.training_run" in body
    assert "match_number_from_key(req.match_number)" in body
    assert "event_key=f'training_run:" in body or 'event_key=f"training_run:' in body


def test_odmowa_zatwierdzenia_zostawia_wpis_PRZED_bledem():
    """Po `raise` nic sie nie wykona - wpis musi stac wyzej."""
    body = function_source("app/proel.py", "_require_approver")
    assert "match.approve_refused" in body
    assert body.index("match.approve_refused") < body.index("NOT_AN_APPROVER")


def test_awaria_archiwum_NIE_kasuje_kolejki_telefonu():
    """Telefon kasuje u siebie cala wyslana paczke, wiec „przyjete" musi byc prawda.

    Gdy nie weszlo NIC, a powodem byla awaria (a nie powtorka czy limit),
    trasa odpowiada bledem - wtedy telefon zatrzymuje paczke i sprobuje
    ponownie. Bez tego historia meczu prowadzonego bez zasiegu przepadala przy
    kazdej awarii archiwum, i raz naprawde przepadla (15.09.2026, brakujaca
    kolumna w tabeli migawek).
    """
    body = function_source("app/proel_snapshots.py", "upload_device_snapshots")
    assert "SNAPSHOT_STORE_FAILED" in body
    assert "if accepted == 0 and failed" in body
    # Awaria liczy sie OSOBNO od pominiecia - inaczej nie da sie ich rozroznic.
    assert "elif why == 'blad'" in body or 'elif why == "blad"' in body


# ── kolejnosc tras: zachlanna ZAWSZE na koncu ────────────────────


def _routes(module: str):
    """(metoda, sciezka, numer linii) dla kazdej trasy w pliku."""
    tree = ast.parse(source(module))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            fn = dec.func
            if not isinstance(fn, ast.Attribute) or not dec.args:
                continue
            if fn.attr not in ("get", "post", "put", "delete", "patch"):
                continue
            path = dec.args[0]
            if isinstance(path, ast.Constant) and isinstance(path.value, str):
                out.append((fn.attr, path.value, dec.lineno))
    return sorted(out, key=lambda item: item[2])


def test_trasa_zachlanna_stoi_PO_wszystkich_stalych():
    """FastAPI dopasowuje trasy w KOLEJNOSCI REJESTRACJI.

    `POST /{match_number:path}` polyka kazda sciezke tego routera, lacznie
    z ukosnikami. Gdy stala wyzej niz `POST /restore/{id}`, przywracanie
    wersji trafialo do dosylki z telefonu jako "paczka dla meczu restore/123":
    pusta lista migawek, odpowiedz 200, toast "Przywrocono" - i ani jednej
    zmiany w bazie (zgloszenie 15.09.2026). Cicha porazka udajaca sukces.
    """
    for method in ("get", "post", "put", "delete", "patch"):
        routes = [r for r in _routes("app/proel_snapshots.py") if r[0] == method]
        greedy = [r for r in routes if ":path}" in r[1]]
        if not greedy:
            continue
        first_greedy = min(r[2] for r in greedy)
        later_fixed = [r for r in routes if ":path}" not in r[1] and r[2] > first_greedy]
        assert not later_fixed, (
            f"{method.upper()}: trasy {[r[1] for r in later_fixed]} stoja PO "
            f"zachlannej {[r[1] for r in greedy]} - nigdy nie dostana zadania"
        )


def test_dosylka_odmawia_sciezkom_panelu_GLOSNO():
    """Druga linia obrony: gdyby kolejnosc kiedys znow sie zepsula.

    Cicho przyjeta paczka dla "meczu" o nazwie restore/123 wyglada z telefonu
    dokladnie jak udane przywrocenie - i tak wlasnie wygladala.
    """
    from app.proel_snapshots import _RESERVED_PATHS

    assert {"restore", "matches", "one"} <= _RESERVED_PATHS
    body = function_source("app/proel_snapshots.py", "upload_device_snapshots")
    assert "_RESERVED_PATHS" in body
    assert "RESERVED_PATH" in body


def test_przywrocenie_budzi_pozostale_urzadzenia():
    """Long-poll stanu czeka na WYZSZA rewizje wiersza stanu.

    Przywrocenie pisze do `proel_matches`, a nie do `proel_match_state` - wiec
    bez tego podbicia drugi telefon dowiadywalby sie o cofnieciu meczu dopiero
    przy wygasnieciu dlugiego zapytania. Jedna liczba w gore i wie od razu.
    """
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "proel_match_state.c.rev + 1" in body


def test_historia_nalezy_do_meczu_ktory_ISTNIEJE():
    """Dowolny klucz zakladal w panelu mecz-widmo.

    Tak wygladal mecz "W/JmK/3" obok prowadzonego naprawde zapisu
    szkoleniowego "T-.../W/JmK/3" (zgloszenie 15.09.2026): telefon dosylal
    historie pod GOLYM numerem, a serwer przyjmowal ja bez pytania - razem
    z wpisami w dzienniku pod numerem, ktorego w ProElu nie ma.

    Odmowa, a nie ciche przyjecie: telefon ma zatrzymac paczke i sprobowac
    ponownie, gdy mecz juz bedzie.
    """
    body = function_source("app/proel_snapshots.py", "upload_device_snapshots")
    assert "MATCH_NOT_FOUND" in body
    assert "saved_matches.c.match_number == key" in body


def test_wlasne_prowadzenie_nie_blokuje_przywrocenia():
    """Odmowa dla SIEBIE samego znaczyla: poczekaj na koniec meczu, ktorego
    sam nie mozesz skonczyc, bo wlasnie go prowadzisz.

    Cudze prowadzenie blokuje dalej - tam przywrocona wersja naprawde
    zniknelaby pod najblizszym autozapisem obcego telefonu.
    """
    body = function_source("app/proel_snapshots.py", "restore_snapshot")
    assert "same_judge_number" in body
    assert "LEASE_ACTIVE" in body
