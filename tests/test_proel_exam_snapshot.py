from datetime import datetime, timezone
from pathlib import Path

from app.proel_exam_snapshot_rules import (
    clean_snapshot,
    snapshot_hash,
    snapshot_is_frozen,
)


ROOT = Path(__file__).resolve().parents[1]


def test_snapshot_freezes_exactly_after_polish_midnight():
    # 29.03.2026 Polska jest już w CEST (UTC+2).
    assert snapshot_is_frozen(
        "2026-03-29", datetime(2026, 3, 29, 21, 59, 59, tzinfo=timezone.utc)
    ) is False
    assert snapshot_is_frozen(
        "2026-03-29", datetime(2026, 3, 29, 22, 0, 0, tzinfo=timezone.utc)
    ) is True


def test_snapshot_keeps_manual_mark_and_strips_unneeded_player_data():
    snapshot = clean_snapshot(
        [
            {
                "number": "7",
                "fullName": "KOWALSKI Jan",
                "exam": "manual",
                "stats": {"goals": 12},
                "secret": "nie zapisuj",
            }
        ],
        [],
    )
    assert snapshot["hostPlayers"] == [
        {"number": 7, "fullName": "KOWALSKI Jan", "exam": "manual"}
    ]


def test_snapshot_hash_is_stable_and_changes_with_exam_status():
    first = clean_snapshot([{"number": 7, "fullName": "A", "exam": "none"}], [])
    same = clean_snapshot([{"exam": "none", "fullName": "A", "number": 7}], [])
    changed = clean_snapshot([{"number": 7, "fullName": "A", "exam": "zprp"}], [])
    assert snapshot_hash("2026-09-29", first) == snapshot_hash("2026-09-29", same)
    assert snapshot_hash("2026-09-29", first) != snapshot_hash("2026-09-29", changed)


def test_route_is_registered_before_proel_catch_all_and_columns_are_migrated():
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    assert main.index("app.include_router(proel_exam_snapshot_router)") < main.index(
        "app.include_router(proel_router)"
    )

    db = (ROOT / "app" / "db.py").read_text(encoding="utf-8")
    for column in (
        "exam_snapshot_json",
        "exam_snapshot_rev",
        "exam_snapshot_date",
        "exam_snapshot_hash",
        "exam_snapshot_at",
    ):
        assert f"ALTER TABLE proel_match_state ADD COLUMN IF NOT EXISTS {column}" in db


def test_archive_restore_keeps_shared_exam_snapshot():
    archive = (ROOT / "app" / "proel_archive.py").read_text(encoding="utf-8")
    for field in (
        "exam_snapshot_json=state.get(\"exam_snapshot_json\")",
        "exam_snapshot_rev=int(state.get(\"exam_snapshot_rev\") or 0)",
        "exam_snapshot_date=state.get(\"exam_snapshot_date\")",
        "exam_snapshot_hash=state.get(\"exam_snapshot_hash\")",
        "exam_snapshot_at=_datetime_value(state.get(\"exam_snapshot_at\"))",
    ):
        assert field in archive


def test_snapshot_route_does_not_load_heavy_match_overlay():
    route = (ROOT / "app" / "proel_exam_snapshot.py").read_text(encoding="utf-8")
    assert "select(*EXAM_STATE_COLUMNS)" in route
    columns = route.split("EXAM_STATE_COLUMNS = (", 1)[1].split(")", 1)[0]
    assert "fields_json" not in columns
    assert "audit_json" not in columns
