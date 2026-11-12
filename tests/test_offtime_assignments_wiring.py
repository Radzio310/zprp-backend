"""Wiązania niedyspozycji od obsadowego - z drzewa składni (app.db żąda Postgresa)."""
import ast
import pathlib

APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def _fns(name):
    tree = ast.parse((APP / name).read_text(encoding="utf-8"))
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _calls(fn):
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            out.add(f.id if isinstance(f, ast.Name) else getattr(f, "attr", ""))
    return out


def test_kazda_trasa_wymaga_tokenu_i_roli():
    fns = _fns("offtime_assignments.py")
    for name in ("list_assigned", "create_assigned", "update_assigned", "delete_assigned"):
        defaults = [ast.unparse(d) for d in fns[name].args.defaults]
        assert "Depends(get_jwt_payload)" in defaults, name
        assert "_actor" in _calls(fns[name]), name


def test_zmiana_i_usuniecie_biora_okreg_z_wiersza_nie_z_zadania():
    fns = _fns("offtime_assignments.py")
    for name in ("update_assigned", "delete_assigned"):
        src = ast.unparse(fns[name])
        assert "_actor(token_payload, row['province'])" in src, name


def test_zapis_dodania_zmiany_i_usuniecia_wysyla_push():
    fns = _fns("offtime_assignments.py")
    for name in ("create_assigned", "update_assigned", "delete_assigned"):
        assert "_notify" in _calls(fns[name]), name


def test_set_wycina_wpisy_obsadowego_a_odczyt_je_dokleja():
    fns = _fns("silesia.py")
    assert "strip_assigned" in _calls(fns["set_offtimes"])
    assert "assigned_ids" in _calls(fns["set_offtimes"])
    composed = _calls(fns["_composed_offtime_records"])
    assert "assigned_rows" in composed and "build_item" in composed


def test_router_podpiety_pod_silesie():
    src = (APP / "silesia.py").read_text(encoding="utf-8")
    assert "router.include_router(assigned_router)" in src


def test_tabela_ma_pola_kontraktu():
    src = (APP / "offtime_assignments_tables.py").read_text(encoding="utf-8")
    for col in ("judge_id", "created_by_role", "created_by_name", "deleted_at", "updated_by", "category_color"):
        assert f'"{col}"' in src
