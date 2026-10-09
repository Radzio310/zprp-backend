"""Materiał dowodowy: reguły (`app/proel_evidence_rules.py`) i okablowanie.

Testy z Postgresem są w tym projekcie pomijane, więc okablowanie pilnujemy
czytając źródło (AST i napisy) - tak samo jak `test_snapshots_wiring.py`.
Najważniejsze tu jest to, czego NIE widać w działaniu przez tydzień: że
sprzątanie omija chroniony mecz, a usunięcie go odmawia.
"""
import ast
import datetime as dt
import gzip
import hashlib
import json
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "raport_dowodowy"))

from app.proel_evidence_rules import (  # noqa: E402
    REASON_MAX,
    build_package,
    has_any_trace,
    hold_view,
    jawne,
    normalize_reason,
    package_doc,
    package_filename,
)


def source(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _fn_body(rel: str, name: str) -> str:
    text = source(rel)
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(text, node) or ""
    raise AssertionError(f"brak funkcji {name} w {rel}")


# ─────────────────────────── reguły ───────────────────────────


def test_uzasadnienie_bez_spacji_i_przyciete():
    assert normalize_reason("  spór  o\n karę  ") == "spór o karę"
    assert len(normalize_reason("x" * 2000)) == REASON_MAX
    assert normalize_reason(None) == ""


def test_jawne_rozpakowuje_migawke_i_protokol():
    blob = {"protocol": [{"type": "penalty3", "player": 39}]}
    assert jawne(zlib.compress(json.dumps(blob).encode())) == blob
    assert jawne(gzip.compress(json.dumps(blob).encode())) == blob
    assert jawne(gzip.compress("tekst wydruku".encode())) == "tekst wydruku"
    assert jawne(memoryview(b"\x00\x01")) == {"_bajty_base64": "AAE="}
    assert jawne(dt.datetime(2026, 10, 7, 17, 23, 59)) == "2026-10-07T17:23:59+00:00"
    assert jawne('{"a": 1}') == {"a": 1}


def _paczka(**over):
    now = dt.datetime(2026, 10, 9, 12, 0, tzinfo=dt.timezone.utc)
    args = dict(
        match_number="SK/24",
        mecz={"match_number": "SK/24", "status": "approved", "data_json": {"protocol": []}},
        stan=None,
        migawki=[{"id": 1, "payload": zlib.compress(b'{"protocol": []}'), "created_at": now}],
        dziennik=[{"id": 5, "event": "match.created", "created_at": now}],
        historia_sporow=[],
        usuniete=[],
        protokoly_pdf=[],
        teczka={"powod": "spór o III karę", "utworzono": now},
        now=now,
    )
    args.update(over)
    return build_package(**args)


def test_teczka_ma_sume_z_wlasnych_bajtow_i_jest_powtarzalna():
    paczka, sha, counts = _paczka()
    assert hashlib.sha256(paczka).hexdigest() == sha
    # Ta sama treść = te same bajty (gzip bez znacznika czasu).
    assert _paczka()[1] == sha
    assert counts["migawki"] == 1 and counts["zapis"] == 1
    zrzut = json.loads(gzip.decompress(paczka))
    assert zrzut["klucz"] == "SK/24"
    assert zrzut["migawki"][0]["payload"] == {"protocol": []}
    assert zrzut["teczka"]["powod"] == "spór o III karę"


def test_teczka_czyta_sie_narzedziem_raportu():
    """Ten sam format co `zrzut.py` - pobrana teczka to gotowe wejście raportu."""
    import analiza

    paczka, _, _ = _paczka()
    wynik = analiza.analizuj(json.loads(gzip.decompress(paczka)))
    assert wynik["mecz"]["numer"] == "SK/24"
    assert wynik["zrodla"]["migawki"] == 1


def test_pusta_teczka_to_brak_meczu():
    _, _, counts = _paczka(mecz=None, migawki=[], dziennik=[])
    assert not has_any_trace(counts)
    _, _, tylko_kosz = _paczka(mecz=None, migawki=[], dziennik=[], usuniete=[{"id": 1}])
    assert has_any_trace(tylko_kosz)


def test_nazwa_pliku_i_znak_tokenu():
    assert package_filename("SK/24", 3) == "teczka_SK-24_nr3.json.gz"
    assert package_filename("T-1A2B/S/JmM/24", 1) == "teczka_T-1A2B-S-JmM-24_nr1.json.gz"
    assert package_doc(3) == "evidence:3"
    assert package_doc(3) != package_doc(4)


def test_widok_oznaczenia():
    now = dt.datetime(2026, 10, 9, 12, 0, tzinfo=dt.timezone.utc)
    v = hold_view({"match_number": "SK/24", "reason": "spór", "marked_at": now,
                   "marked_by_name": "ADMIN Jan", "released_at": None})
    assert v["active"] is True and v["marked_by"] == "ADMIN Jan"
    assert v["marked_at"] == "2026-10-09T12:00:00+00:00"
    assert hold_view(None) is None


# ─────────────────────────── okablowanie ───────────────────────────


def test_sprzatanie_migawek_omija_chronione_mecze():
    body = _fn_body("app/proel_snapshots.py", "cleanup_expired")
    assert "not_in(active_holds_select())" in body


def test_kosz_i_historia_sporow_nie_wygasaja_dla_chronionych():
    for fn in ("_purge_expired", "_purge_expired_history"):
        assert "not_in(active_holds_select())" in _fn_body("app/proel_archive.py", fn), fn


def test_migawka_chronionego_meczu_nie_ma_daty_waznosci_ani_limitu():
    body = _fn_body("app/proel_snapshots.py", "record_snapshot")
    assert "held = await is_held(key)" in body
    assert '"expires_at": None if held else expires_at(stamp, mark)' in body
    assert "today = 0" in body
    # Sprawdzenie stoi W try - `record_snapshot` nie ma prawa rzucić.
    tree = ast.parse(body)
    fn = tree.body[0]
    tries = [n for n in fn.body if isinstance(n, ast.Try)]
    assert tries and "is_held" in ast.unparse(tries[0].body)


def test_usuniecie_odmawia_chronionemu_meczowi():
    body = _fn_body("app/proel.py", "archive_and_delete_match")
    assert "proel_evidence_holds" in body and 'return "evidence"' in body
    # Odmowa PRZED przepisaniem do kosza i skasowaniem wiersza.
    assert body.index('return "evidence"') < body.index("proel_deleted_matches.insert()")
    route = _fn_body("app/proel.py", "delete_proel_match")
    assert 'outcome == "evidence"' in route and "HTTP_423_LOCKED" in route
    bulk = _fn_body("app/proel_archive.py", "bulk_delete")
    assert 'outcome == "evidence"' in bulk and '"reason": "evidence"' in bulk


def test_drop_snapshots_nie_rusza_chronionego():
    assert "is_held(key)" in _fn_body("app/proel_snapshots.py", "drop_snapshots")


def test_awans_szkoleniowego_przenosi_oznaczenie():
    assert "await carry_evidence(key, official)" in source("app/proel.py")


def test_router_przed_zachlanna_trasa_proela():
    main = source("main.py")
    assert main.index("app.include_router(proel_evidence_router)") < main.index(
        "app.include_router(proel_router)"
    )


def _routes(rel: str):
    tree = ast.parse(source(rel))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr in ("get", "post") and dec.args
                    and isinstance(dec.args[0], ast.Constant)):
                out.append((dec.func.attr, dec.args[0].value, dec.lineno, node.name))
    return sorted(out, key=lambda r: r[2])


def test_trasa_zachlanna_na_koncu_i_bramka_admina():
    routes = _routes("app/proel_evidence.py")
    for method in ("get", "post"):
        mine = [r for r in routes if r[0] == method]
        greedy = [r for r in mine if ":path}" in r[1]]
        if greedy:
            first = min(r[2] for r in greedy)
            assert not [r for r in mine if ":path}" not in r[1] and r[2] > first]
    text = source("app/proel_evidence.py")
    # Każda trasa poza podpisanym plikiem ma twardą bramkę admina.
    for _m, path, line, name in routes:
        dec_line = text.splitlines()[line - 1:line + 6]
        if path.endswith("/file"):
            assert "verify_pdf_token" in _fn_body("app/proel_evidence.py", name)
        else:
            assert any("_ADMIN_GUARD" in ln for ln in dec_line), path
            assert "await _require_admin(actor)" in _fn_body("app/proel_evidence.py", name), path


def test_zdjecie_oznaczenia_wymaga_pinu_i_zostawia_teczki():
    body = _fn_body("app/proel_evidence.py", "release")
    assert "pin_is_valid(who, req.pin)" in body
    assert "proel_evidence_packages" not in body  # teczek nie dotyka
    text = source("app/proel_evidence.py")
    assert "P.delete()" not in text and "delete(P)" not in text


def test_nazwy_zdarzen_w_dzienniku():
    from app.proel_journal import EVENT_LABELS, event_summary

    for ev in ("evidence.marked", "evidence.released", "evidence.package"):
        assert ev in EVENT_LABELS
    zdanie = event_summary("evidence.marked", {"reason": "spór", "package_id": 3, "sha256": "ab" * 32})
    assert "teczce nr 3" in zdanie and "Powód: spór" in zdanie
