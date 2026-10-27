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
    # Overlay i karty bloba czyta osobne, wąskie zapytanie potwierdzeń.
    assert 'data_json["matchConfig"]' in route


# ─────────── potwierdzenia z zapisu ProEla (odsłona 2, 27.10) ───────────

from app.proel_exam_snapshot_rules import (  # noqa: E402
    exam_confirmations,
    merge_exam_confirmations,
)


def _entry(mark, name, at, src="patch", by="KOWALSKI Jan"):
    return {
        "v": {"mark": mark, "name": name},
        "rev": 3,
        "at": at,
        "by": {"name": by},
        "src": src,
        "superseded_at": None,
    }


def test_manual_confirmation_from_overlay_lands_in_frozen_snapshot():
    # IMD/45: nr 71 WZPR w rozgrywce centralnej, sędzia potwierdził ręcznie
    # w meczu ProEl; migawka ze szczegółów meczu tego nie widziała.
    overlay = {"exam.guest.#71": _entry("manual", "GODLEWSKI Dorian", "2026-10-25T15:10:00+00:00")}
    conf = exam_confirmations(overlay, None, "2026-10-25")
    players = [
        {"number": 71, "fullName": "GODLEWSKI Dorian", "exam": "wzpr"},
        {"number": 80, "fullName": "KOZAK Mikołaj", "exam": "zprp"},
    ]
    merged = merge_exam_confirmations(players, "guest", conf, "zprp")
    assert merged[0]["exam"] == "manual"
    assert merged[0]["examBy"] == "KOWALSKI Jan"
    assert merged[1]["exam"] == "zprp"
    # Strona się liczy: gospodarze z numerem 71 nie dostają cudzego ptaszka.
    assert merge_exam_confirmations(players, "host", conf, "zprp")[0]["exam"] == "wzpr"


def test_blob_only_manual_card_counts_and_overlay_withdrawal_wins():
    config = {
        "hostPlayerCards": [
            {"number": 5, "fullName": "NOWAK Anna", "exam": "manual"},
            {"number": 9, "fullName": "LIS Ewa", "exam": "manual"},
        ]
    }
    overlay = {"exam.host.#9": _entry("none", "LIS Ewa", "2026-10-25T10:00:00+00:00")}
    conf = exam_confirmations(overlay, config, "2026-10-25")
    assert [(c["number"], c["mark"], c["src"]) for c in conf] == [(5, "manual", "blob")]


def test_patch_after_match_day_is_ignored_blob_adoption_is_not():
    overlay = {
        "exam.host.#3": _entry("manual", "A B", "2026-10-26T08:00:00+00:00"),
        "exam.host.#4": _entry("manual", "C D", "2026-10-26T00:30:00+00:00", src="blob"),
    }
    conf = exam_confirmations(overlay, None, "2026-10-25")
    assert [c["number"] for c in conf] == [4]


def test_merge_never_lowers_and_respects_requirement():
    conf = [{"team": "host", "number": 7, "name": "X Y", "mark": "manual", "by": ""}]
    any_req = merge_exam_confirmations(
        [{"number": 7, "fullName": "X Y", "exam": "wzpr"}], "host", conf, "any"
    )
    assert any_req[0]["exam"] == "wzpr"  # WZPR wystarcza, ręczny go nie zastępuje
    # Inny człowiek pod tym numerem - bez awansu.
    other = merge_exam_confirmations(
        [{"number": 7, "fullName": "ZET Ola", "exam": "none"}], "host", conf, "any"
    )
    assert other[0]["exam"] == "none"
