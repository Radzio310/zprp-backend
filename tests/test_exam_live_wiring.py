"""Egzamin na żywo - wiązania (bez importu żywej bazy) i zegar terminu pytania."""

import ast
import asyncio
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def test_router_tabele_i_zaleznosc_websocketow():
    assert "app.include_router(exam_live_router)" in source("main.py")
    db = source("app", "db.py")
    for name in ("exam_live_sessions", "exam_live_participants", "exam_live_answers"):
        assert name in db
    assert "websockets" in source("requirements.txt")


def test_moduly_logiki_nie_importuja_bazy_na_gorze():
    for name in ("exam_live_rules.py", "exam_live_service.py", "exam_live_routes.py", "exam_live_hub.py", "exam_live_tables.py"):
        for node in ast.parse(source("app", name)).body:
            if isinstance(node, ast.ImportFrom):
                assert node.module not in ("app.db", "app.exams", "app.province_events"), f"{name}: import bazy na górze"


async def test_zegar_terminu_uruchamia_odslonicie_i_nowy_termin_zastepuje_stary():
    from app.exam_live_hub import Hub

    hub = Hub()
    fired = []

    async def fire(tag):
        fired.append(tag)

    hub.arm("s", ("q", 0), 0.05, lambda: fire("first"))
    hub.arm("s", ("q", 0), 0.05, lambda: fire("dup"))  # ten sam klucz: bez drugiego zegara
    await asyncio.sleep(0.2)
    assert fired == ["first"]
    hub.arm("s", ("q", 1), 5.0, lambda: fire("late"))
    hub.arm("s", ("q", 2), 0.05, lambda: fire("second"))  # nowe pytanie anuluje stary zegar
    await asyncio.sleep(0.2)
    assert fired == ["first", "second"]
    hub.forget("s")
