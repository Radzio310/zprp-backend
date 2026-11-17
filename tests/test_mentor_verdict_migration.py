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
        c.execute(sa.text("CREATE TABLE mentor_match_videos (id TEXT PRIMARY KEY, markers_json TEXT)"))
        marks = [{"id": "a", "video_s": 5, "important": True, "category": "dobra", "comment": "x"},
                 {"id": "b", "video_s": 9, "important": True, "category": "kluczowa", "verdict": "bad"},
                 {"id": "c", "video_s": 9, "important": True, "category": "gwizdek"},
                 {"id": "gone", "deleted_at": 1}]
        c.execute(sa.text("INSERT INTO mentor_match_videos VALUES ('v1', :m)"), {"m": json.dumps(marks)})
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
    with engine.begin() as c:
        stored = json.loads(c.execute(sa.text("SELECT markers_json FROM mentor_match_videos")).scalar())
    by = {m["id"]: m for m in stored}
    assert (by["a"]["category"], by["a"]["verdict"], by["a"]["comment"]) == (None, "good", "x")
    assert (by["b"]["category"], by["b"]["verdict"]) == ("kluczowa", "bad")
    assert (by["c"]["category"], by["c"]["verdict"], by["c"]["legacy_category"]) == (None, "discuss", "gwizdek")
    assert by["gone"] == {"id": "gone", "deleted_at": 1}
    assert first["markers_changed"] == 2 and second["markers_changed"] == 0 and dry["markers_changed"] == 2
    assert rows == {"1": (["k"], "good"), "2": ([], "bad"), "3": (["k"], None)} and archived == 3


def test_znacznik_rodzaj_i_ocena_niezalezne():
    from app import mentor_video_rules as V

    base = {"video_s": 10, "important": True}
    out = {m["id"]: m for m in V.clean_markers([
        {**base, "id": "a", "category": "dobra"},
        {**base, "id": "b", "category": "pytanie", "verdict": "bad"},
        {**base, "id": "c", "category": "gwizdek", "comment": "zostaje"},
        {**base, "id": "d"},
        {**base, "id": "e", "category": "trafna"},
    ])}
    assert (out["a"]["category"], out["a"]["verdict"]) == (None, "good")
    assert (out["b"]["category"], out["b"]["verdict"]) == ("pytanie", "bad")
    assert (out["c"]["verdict"], out["c"]["legacy_category"]) == ("discuss", "gwizdek")
    assert (out["d"]["category"], out["d"]["verdict"]) == (None, None)
    assert out["e"]["verdict"] == "good" and out["e"]["legacy_category"] is None
    again = V.clean_markers(list(out.values()))
    assert [(m["category"], m["verdict"], m["legacy_category"]) for m in again] == [(m["category"], m["verdict"], m["legacy_category"]) for m in out.values()]
    assert V.MARKER_CATEGORIES == ("pytanie", "kluczowa") and V.MARKER_VERDICTS == tuple(R.VERDICTS)


def test_klip_ze_znacznika_dziedziczy_ocene_i_rodzaj():
    from app import mentor_video_rules as V

    video = {"id": "v", "match_id": "m", "duration_s": 3600}
    marks = V.clean_markers([{"id": "a", "video_s": 100, "important": True, "category": "kluczowa", "verdict": "bad"}])
    clip = R.markers_as_clips(video, marks)[0]
    assert clip["verdict"] == "bad" and clip["category_key"] == "kluczowa"
    row = R.clip_row_from_marker(clip, {"kluczowa": "cat-k"})
    assert row["verdict"] == "bad" and row["category_ids"] == ["cat-k"]
    only = R.markers_as_clips(video, V.clean_markers([{"id": "b", "video_s": 100, "verdict": "good"}]))
    assert only and only[0]["verdict"] == "good"
