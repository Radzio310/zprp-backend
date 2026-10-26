"""Oferty obsadowego - wiązania tras i tabel, bez importowania żywej bazy."""

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def routes(src):
    out = {}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in {"get", "post", "delete"}:
                    path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else ""
                    out[(dec.func.attr.upper(), path)] = node.name
    return out


def test_router_zarejestrowany_i_tabele_w_db():
    assert "app.include_router(match_market_crew_router)" in source("main.py")
    db = source("app", "db.py")
    assert "_define_crew_market_tables(metadata)" in db
    tables = source("app", "match_market_crew_tables.py")
    assert "match_market_crew_offers" in tables and "match_market_crew_claims" in tables


def test_kontrakt_tras():
    found = routes(source("app", "match_market_crew.py"))
    for key in [
        ("GET", "/suggest"),
        ("POST", ""),
        ("GET", ""),
        ("GET", "/{offer_id}"),
        ("DELETE", "/{offer_id}"),
        ("POST", "/{offer_id}/claims"),
        ("DELETE", "/{offer_id}/claims/me"),
        ("POST", "/{offer_id}/assign"),
        ("POST", "/{offer_id}/claims/{claim_id}/unassign"),
    ]:
        assert key in found, key


def test_suggest_przed_trasa_z_parametrem():
    src = source("app", "match_market_crew.py")
    assert src.index('"/suggest"') < src.index('"/{offer_id}"')


def test_baza_importowana_leniwie_w_regulach():
    src = source("app", "match_market_crew_rules.py")
    assert "app.db" not in src and "fastapi" not in src


def test_przydzial_idzie_do_wspolnego_szkicu_z_plakietka_market():
    src = source("app", "match_market_crew.py")
    assert '"source": "market"' in src and "put_draft" in src
    # Do ZPRP nie wysyłamy: żadnego zapisu obsady w tym module.
    assert "apply_referee_assignment" not in src and "obsada_save" not in src


def test_pole_json_jako_napis_idzie_przez_parsowanie():
    src = source("app", "match_market_crew.py")
    assert "state_dict(data.get(\"match_snapshot\"))" in src and "_jl(" in src


def test_trasy_sugestii_na_manager_actor_i_zarejestrowane():
    src = source("app", "match_market_crew_suggest.py")
    found = routes(src)
    assert ("GET", "/{offer_id}/suggestions") in found and ("POST", "/{offer_id}/invite") in found
    for name in ("suggestions", "invite"):
        head = src[src.index(f"async def {name}("):]
        assert "M.manager_actor" in head[: head.index(") ->")], name
    assert "app.include_router(match_market_crew_suggest_router)" in source("main.py")


def test_liscie_sugestii_bez_bazy_i_fastapi():
    src = source("app", "match_market_crew_suggest_rules.py")
    assert "app.db" not in src and "fastapi" not in src


def test_tabela_zaproszen_i_migracja_kolumny_source():
    tables = source("app", "match_market_crew_tables.py")
    assert "match_market_crew_invites" in tables and "uq_match_market_crew_invite" in tables
    assert "ADD COLUMN IF NOT EXISTS source" in tables
    db = source("app", "db.py")
    assert "_define_crew_invites(metadata)" in db and "_CREW_MARKET_MIGRATIONS" in db
