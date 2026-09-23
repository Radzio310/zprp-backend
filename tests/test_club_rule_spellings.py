"""Jedna deklaracja na klub mimo dwóch pisowni okręgu - `newest_rule_per_club`."""
from __future__ import annotations

from datetime import datetime, timezone

from app.province_clubs_bulk import newest_rule_per_club


def rule(province, club, table, when):
    return {"province": province, "club_id": club, "table_by_club": table, "updated_at": when}


OLD = datetime(2026, 9, 10, tzinfo=timezone.utc)
NEW = datetime(2026, 9, 23, tzinfo=timezone.utc)


def test_newest_write_wins_over_old_row_under_other_spelling():
    rows = [rule("SLASKIE", "5001", 1, NEW), rule("ŚLĄSKIE", "5001", 0, OLD)]
    assert newest_rule_per_club(rows, "SLASKIE")["5001"]["table_by_club"] == 1
    # Kolejność z bazy nie ma znaczenia.
    assert newest_rule_per_club(list(reversed(rows)), "SLASKIE")["5001"]["table_by_club"] == 1


def test_tie_prefers_canonical_key():
    rows = [rule("ŚLĄSKIE", "27", 0, None), rule("SLASKIE", "27", 1, None)]
    assert newest_rule_per_club(rows, "SLASKIE")["27"]["province"] == "SLASKIE"


def test_naive_dates_do_not_crash():
    rows = [rule("ŚLĄSKIE", "41", 0, datetime(2026, 9, 1)), rule("SLASKIE", "41", 1, NEW)]
    assert newest_rule_per_club(rows, "SLASKIE")["41"]["table_by_club"] == 1
