"""Wiązania pośrednika ZPRP - czytane z drzewa składni.

Trzy rzeczy, które cofnięte jedną linijką wróciłyby po cichu i nikt by tego
nie zauważył aż do hali:
  • trasa zapisu znowu CZEKA na dziennik, zanim odpowie telefonowi,
  • żądanie do ZPRP znowu otwiera własnego klienta (nowy uścisk TLS na
    każdego zawodnika),
  • zapis do ZPRP idzie z pominięciem zamka meczu i zderza się z drugim
    zapisem tej samej sesji.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app" / "proel_zprp.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
BATCH_SOURCE = (ROOT / "app" / "proel_zprp_batch.py").read_text(encoding="utf-8")
BATCH_TREE = ast.parse(BATCH_SOURCE)
MAIN_SOURCE = (ROOT / "main.py").read_text(encoding="utf-8")

FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}
BATCH_FUNCTIONS = {
    node.name: node
    for node in ast.walk(BATCH_TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}

#: Trasy zapisu do ZPRP - każda zostawia ślad w dzienniku.
WRITE_ROUTES = (
    "zprp_summary",
    "zprp_player_stats",
    "zprp_officials_stats",
    "zprp_match_comment",
    "zprp_attachment",
)

#: Rdzenie zapisu - każdy rozmawia z ZPRP pod zamkiem meczu.
WRITE_CORES = (
    "submit_summary",
    "submit_player_stats",
    "submit_officials_stats",
    "submit_match_comment",
    "upload_attachment",
)


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def awaited_calls(node: ast.AST) -> set:
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Await) and isinstance(sub.value, ast.Call):
            out.add(_call_name(sub.value))
    return out


def all_calls(node: ast.AST) -> set:
    return {_call_name(sub) for sub in ast.walk(node) if isinstance(sub, ast.Call)}


def test_trasy_zapisu_nie_czekaja_na_dziennik():
    for name in WRITE_ROUTES:
        fn = FUNCTIONS[name]
        assert "_journal_send" not in awaited_calls(fn), name
        assert "_journal_send_later" in all_calls(fn), name


def test_dziennik_w_tle_ma_silna_referencje_i_log_bledu():
    fn = FUNCTIONS["_journal_send_later"]
    calls = all_calls(fn)
    assert "create_task" in calls
    assert "add_done_callback" in calls
    assert "add" in calls  # referencja w `_journal_tasks`


def test_zadanie_do_zprp_przez_wspolnego_klienta():
    for name in ("_post_upstream", "_post_upstream_file"):
        calls = all_calls(FUNCTIONS[name])
        assert "_upstream_client" in calls, name
        assert "AsyncClient" not in calls, name
    # Klienta tworzy wyłącznie fabryka wspólnego klienta.
    creators = {
        name
        for name, fn in FUNCTIONS.items()
        if "AsyncClient" in all_calls(fn)
    }
    assert creators == {"_upstream_client"}


def test_rdzenie_zapisu_pod_zamkiem_meczu():
    for name in WRITE_CORES:
        fn = FUNCTIONS[name]
        locked = False
        for sub in ast.walk(fn):
            if isinstance(sub, ast.AsyncWith):
                for item in sub.items:
                    expr = item.context_expr
                    if isinstance(expr, ast.Call) and _call_name(expr) == "match_write_lock":
                        locked = True
        assert locked, name


def test_pakiet_idzie_przez_rdzenie_pojedynczych_tras():
    calls = all_calls(BATCH_FUNCTIONS["_submit"])
    assert {"submit_player_stats", "submit_officials_stats"} <= calls
    # Żadnego własnego wywołania ZPRP w pakiecie.
    assert "_call_upstream" not in all_calls(BATCH_TREE)
    assert "_post_upstream" not in all_calls(BATCH_TREE)
    # Odnowienie sesji tą samą drogą co `POST /proel/zprp/auth`.
    assert "authorize" in all_calls(BATCH_FUNCTIONS["_renew"])


def test_pakiet_nie_czeka_na_dziennik():
    assert "_journal_send" not in awaited_calls(BATCH_TREE)
    assert "_journal_send_later" in all_calls(BATCH_FUNCTIONS["_journal_first_success"])


def test_main_rejestruje_pakiet_przed_catch_allem_i_zamyka_klienta():
    batch = MAIN_SOURCE.index("app.include_router(proel_zprp_batch_router)")
    catch_all = MAIN_SOURCE.index("app.include_router(proel_router)")
    assert batch < catch_all
    shutdown = MAIN_SOURCE.index("async def shutdown()")
    assert MAIN_SOURCE.index("await close_proel_zprp_client()") > shutdown
