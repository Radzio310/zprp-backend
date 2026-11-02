"""Kolejność ogłoszeń = dodanie i edycja. Reakcje i komentarze nie ruszają `updated_at`."""
from __future__ import annotations

import ast
import pathlib
from datetime import datetime, timezone

from app.announcement_rules import (
    backfilled_updated_at,
    make_thumbnail,
    order_conflicts,
)

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "app" / "silesia.py").read_text(
    encoding="utf-8"
)


def _func_source(name: str) -> str:
    for node in ast.walk(ast.parse(SOURCE)):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name:
            return ast.get_source_segment(SOURCE, node)
    raise AssertionError(name)


def test_reactions_and_comments_keep_updated_at():
    for name in ("toggle_reaction", "add_comment", "pin_comment", "delete_comment"):
        src = _func_source(name)
        assert "updated_at=announcements.c.updated_at" in src, name
        assert "activity_at=func.now()" in src, name


def test_create_and_update_bump_updated_at():
    # edycja nie podaje updated_at, więc `onupdate=now()` je podbija
    assert "updated_at" not in _func_source("update_announcement").replace(
        "ann_id", ""
    ).replace("_announcement_row", "")


def test_last_update_signal_includes_activity():
    src = _func_source("get_last_update")
    assert "activity_at" in src and "updated_at" in src


def _d(h, m=0):
    return datetime(2026, 10, 1, h, m, tzinfo=timezone.utc)


def test_backfill_date_uses_earliest_activity():
    likes = [{"created_at": "2026-10-01T10:00:00"}, {"created_at": "2026-10-01T12:00:00"}]
    comments = [{"created_at": "2026-10-01T09:30:00"}]
    assert backfilled_updated_at(_d(15), likes, comments) == _d(9, 30)


def test_backfill_leaves_untouched_rows():
    likes = [{"created_at": "2026-10-01T10:00:00"}]
    assert backfilled_updated_at(_d(9), likes, []) is None  # edycja przed reakcją
    assert backfilled_updated_at(_d(10), likes, []) is None  # idempotentne
    assert backfilled_updated_at(_d(9), [], []) is None
    assert backfilled_updated_at(_d(9), None, "x") is None


def test_order_conflicts_listed_not_guessed():
    rows = [
        {"id": 1, "province": "a", "updated_at": _d(12)},
        {"id": 2, "province": "a", "updated_at": _d(10)},
        {"id": 3, "province": "b", "updated_at": _d(8)},
    ]
    assert order_conflicts(rows) == [(2, 1)]


def test_thumbnail_width_and_no_raise(tmp_path):
    from PIL import Image

    src = tmp_path / "abc.png"
    Image.new("RGB", (1200, 600), "red").save(src)
    name = make_thumbnail(str(src), str(tmp_path))
    assert name and name.startswith("abc_thumb.")
    with Image.open(tmp_path / name) as im:
        assert im.size == (480, 240)
    assert make_thumbnail(str(tmp_path / "nie-ma.png"), str(tmp_path)) is None
