"""Szkice ocen młodych: reguły (bez bazy) i bramka tras (z drzewa składni)."""

from __future__ import annotations

import ast
import pathlib

from app.young_rating_drafts_rules import (
    MAX_PAYLOAD_BYTES,
    clean_key,
    encode_payload,
    payload_dict,
)

APP = pathlib.Path(__file__).resolve().parents[1] / "app"
TREE = ast.parse((APP / "young_rating_drafts.py").read_text(encoding="utf-8"))
FUNCS = {n.name: n for n in ast.walk(TREE) if isinstance(n, ast.AsyncFunctionDef)}


def _calls(name):
    return {
        (s.func.id if isinstance(s.func, ast.Name) else getattr(s.func, "attr", ""))
        for s in ast.walk(FUNCS[name])
        if isinstance(s, ast.Call)
    }


def test_clean_key():
    assert clean_key("  new:IIM4/1:12 ") == "new:IIM4/1:12"
    assert clean_key("") == "" and clean_key(None) == "" and clean_key("x" * 201) == ""


def test_payload_dict_accepts_string_from_db():
    assert payload_dict('{"a": 1}') == {"a": 1}
    assert payload_dict({"a": 1}) == {"a": 1}
    assert payload_dict("[1]") == {} and payload_dict("nie json") == {} and payload_dict(None) == {}


def test_encode_payload_limits():
    assert encode_payload({}) is None and encode_payload("x") is None
    assert encode_payload({"imię": "Łukasz"}) == '{"imię":"Łukasz"}'
    assert encode_payload({"x": "a" * (MAX_PAYLOAD_BYTES + 1)}) is None


def test_every_route_needs_token_and_author():
    for name in ("get_drafts", "put_draft", "delete_draft"):
        assert "_me" in _calls(name), name
        args = [a.arg for a in FUNCS[name].args.args]
        assert "token" in args, name


def test_author_comes_from_token_not_body():
    src = (APP / "young_rating_drafts.py").read_text(encoding="utf-8")
    assert "body.judge" not in src and "judge_id=body" not in src
    assert "actor_judge_id" in src
