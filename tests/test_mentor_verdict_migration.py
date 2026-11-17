"""Ocena klipu: czyste funkcje i skrypt migracji (`scripts/migrate_mentor_clip_verdict.py`) na SQLite."""

import json

import pytest
import sqlalchemy as sa

from app import mentor_panel_rules as R
from scripts import migrate_mentor_clip_verdict as M

LEGACY = {"c-dobra": "good", "c-zla": "bad", "c-dysk": "discuss"}


def test_clean_verdict():
    assert R.clean_verdict(None) is None and R.clean_verdict("  ") is None and R.clean_verdict("GOOD") == "good"
    with pytest.raises(R.RuleError):
        R.clean_verdict("ok")


def test_legacy_map_i_podzial():
    rows = [{"id": "a", "key": "dobra"}, {"id": "b", "key": "pytanie"}, {"id": "c", "key": "dyskusja"}, {"id": "d", "key": None}]
    assert R.legacy_category_map(rows) == {"a": "good", "c": "discuss"}
    assert R.split_legacy_categories(["x", "c", "a", "x", "y"], {"a": "good", "c": "discuss"}) == (["x", "y"], "discuss")
    assert R.split_legacy_categories(None, {}) == ([], None)
    assert R.verdict_of_key("zla") == "bad" and R.verdict_of_key("pytanie") is None


def test_plan_regula_pierwszej_i_idempotencja():
    clips = [
        {"id": "1", "category_ids": json.dumps(["c-dobra"]), "verdict": None},
        {"id": "2", "category_ids": json.dumps(["c-dysk", "custom", "c-dobra"]), "verdict": None},
        {"id": "3", "category_ids": json.dumps(["custom"]), "verdict": None},
        {"id": "4", "category_ids": json.dumps(["c-zla"]), "verdict": "good"},
        {"id": "5", "category_ids": "[]", "verdict": None},
    ]
    plan = R.plan_verdict_migration(clips, LEGACY)
    got = dict(plan["updates"])
    assert got["1"] == {"category_ids": [], "verdict": "good"}
    assert got["2"] == {"category_ids": ["custom"], "verdict": "discuss"}
    assert got["4"] == {"category_ids": [], "verdict": "good"} and "3" not in got and "5" not in got
    st = plan["stats"]
    assert (st["scanned"], st["migrated"], st["multi"], st["conflicts"], st["left_without_category"]) == (5, 3, 1, 1, 2)
    after = [{**c, **dict(plan["updates"]).get(c["id"], {}), "category_ids": json.dumps(dict(plan["updates"]).get(c["id"], {}).get("category_ids", json.loads(c["category_ids"])))} for c in clips]
    assert R.plan_verdict_migration(after, LEGACY)["updates"] == []


def test_skrypt_na_sqlite(tmp_path):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    with engine.begin() as c:
        c.execute(sa.text("CREATE TABLE mentor_categories (id TEXT PRIMARY KEY, key TEXT, archived BOOLEAN)"))
        c.execute(sa.text("CREATE TABLE mentor_clips (id TEXT PRIMARY KEY, category_ids TEXT, verdict TEXT, updated_at TIMESTAMP)"))
        for i, k in (("c-dobra", "dobra"), ("c-zla", "zla"), ("c-dysk", "dyskusja"), ("k", "pytanie")):
            c.execute(sa.text("INSERT INTO mentor_categories VALUES (:i, :k, 0)"), {"i": i, "k": k})
        for i, ids in (("1", ["c-dobra", "k"]), ("2", ["c-zla", "c-dysk"]), ("3", ["k"])):
            c.execute(sa.text("INSERT INTO mentor_clips (id, category_ids) VALUES (:i, :c)"), {"i": i, "c": json.dumps(ids)})
    with engine.begin() as c:
        dry = M.run(c, apply=False)
    with engine.begin() as c:
        assert c.execute(sa.text("SELECT COUNT(*) FROM mentor_clips WHERE verdict IS NOT NULL")).scalar() == 0
        first = M.run(c, apply=True)
    with engine.begin() as c:
        second = M.run(c, apply=True)
        rows = {r[0]: (json.loads(r[1]), r[2]) for r in c.execute(sa.text("SELECT id, category_ids, verdict FROM mentor_clips"))}
        archived = c.execute(sa.text("SELECT COUNT(*) FROM mentor_categories WHERE archived = 1 AND key IN ('dobra','zla','dyskusja')")).scalar()
    assert dry["migrated"] == 2 and dry["multi"] == 1 and dry["categories_to_archive"] == 3
    assert first["migrated"] == 2 and first["left_without_category"] == 1
    assert second["migrated"] == 0 and second["categories_to_archive"] == 0
    assert rows == {"1": (["k"], "good"), "2": ([], "bad"), "3": (["k"], None)} and archived == 3
