"""Lista GET /proel: mecz ręczny (M-) bez IdZawody widzi tylko piszący i członek meczu wspólnego (02.11.2026)."""

import importlib
import sys

import pytest
from sqlalchemy import select

from tests.mentor_panel_support import JUDGES, Env

A, B = JUDGES
BLOB = {"matchConfig": {"hostTeamName": "SPR Gliwice", "guestTeamName": "KS Opole"}}


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    import app as app_package

    monkeypatch.delitem(sys.modules, "app.proel_list_scope", raising=False)
    monkeypatch.delattr(app_package, "proel_list_scope", raising=False)
    e.scope = importlib.import_module("app.proel_list_scope")
    return e


def test_lista_nie_oddaje_cudzych_meczow_recznych_a_oddaje_wlasne_i_wspolne(env):
    async def go():
        created = await env.shared.create_match(env.shared.CreateBody(
            home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", code="EHF/1", my_role="sedzia1",
            crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")]), await env.actor(A))
        stem = created["match"]["key_stem"]
        shared_key = f"M-{stem}/EHF/1"
        rows = [(shared_key, None, "666"),               # prowadził go ktoś trzeci, A i B są w obsadzie
                ("M-ZZZZZZZZ/EHF/1", None, "666"),        # cudzy mecz ręczny
                ("M-YYYYYYYY/EHF/9", None, A),            # własny mecz ręczny A (jeszcze bez meczu wspólnego)
                ("M-XXXXXXXX/EHF/5", "12345", "666"),     # połączony z IdZawody: zwykły mecz
                ("ISM/1", None, "666"), ("T-K3N8P2WQ/ISM/2", None, "666")]
        for key, zid, writer in rows:
            await env.ins("saved_matches", match_number=key, zprp_match_id=zid, data_json=BLOB, status="in_progress", doc_writer_judge=writer)
        table = env.T["saved_matches"]

        async def listed(judge):
            clause = await env.scope.manual_rows_clause(judge)
            found = await env.db.fetch_all(select(table.c.match_number).where(clause))
            return sorted(r["match_number"] for r in found)

        return shared_key, await listed(A), await listed(B), await listed("888"), await listed("")

    key, as_a, as_b, as_stranger, as_empty = env.run(go)
    assert as_a == sorted([key, "M-YYYYYYYY/EHF/9", "M-XXXXXXXX/EHF/5", "ISM/1", "T-K3N8P2WQ/ISM/2"])
    assert as_b == sorted([key, "M-XXXXXXXX/EHF/5", "ISM/1", "T-K3N8P2WQ/ISM/2"])  # członek meczu wspólnego, nie cudzy
    assert as_stranger == sorted(["M-XXXXXXXX/EHF/5", "ISM/1", "T-K3N8P2WQ/ISM/2"])  # reszta listy bez zmian
    assert as_empty == as_stranger


def test_trasa_listy_uzywa_filtra():
    import pathlib

    source = pathlib.Path("app/proel.py").read_text(encoding="utf-8")
    assert "manual_rows_clause(actor.judge_id)" in source


def _results_function(name):
    import ast
    import logging
    import pathlib

    source = pathlib.Path("app/results.py").read_text(encoding="utf-8")
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
    namespace = {"logger": logging.getLogger("test"), "Dict": dict, "Any": object}
    exec(compile(ast.Module([node], []), "results.py", "exec"), namespace)
    return namespace[name], source


def test_klucz_m_z_bloba_do_overlaya_tylko_dla_piszacego_i_czlonka_meczu(env):
    check, source = _results_function("_may_read_shared_key")
    assert "_may_read_shared_key(explicit_key, judge_id)" in source and "_with_exam_overlay(data_json, actor_judge_id)" in source

    async def go():
        created = await env.shared.create_match(env.shared.CreateBody(
            home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", code="EHF/1", my_role="sedzia1",
            crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")]), await env.actor(A))
        key = f"M-{created['match']['key_stem']}/EHF/1"
        await env.ins("saved_matches", match_number="M-ABCDEFGH/EHF/1", zprp_match_id=None, data_json=BLOB, status="in_progress", doc_writer_judge="666")
        return (await check(key, A), await check(key, B), await check(key, "888"), await check(key, ""),
                await check("M-ABCDEFGH/EHF/1", "666"), await check("M-ABCDEFGH/EHF/1", A))

    member_a, member_b, stranger, anonymous, writer, foreign = env.run(go)
    assert (member_a, member_b, writer) == (True, True, True)
    assert (stranger, anonymous, foreign) == (False, False, False)
