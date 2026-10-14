"""Jawne, testowalne kształty publicznych rekordów hurtowni."""

from __future__ import annotations

from typing import Any, Mapping


def _mapping(row: Any) -> dict[str, Any]:
    if not row:
        return {}
    if isinstance(row, Mapping):
        return dict(row)
    return dict(row)


def public_club(row: Any) -> dict[str, Any]:
    data = _mapping(row)
    return {
        key: data.get(key)
        for key in (
            "club_id",
            "association_id",
            "name",
            "member",
            "city",
            "website",
            "archived",
            "logo_url",
            "source_updated_at",
            "updated_at",
        )
    }


def public_team(row: Any) -> dict[str, Any]:
    data = _mapping(row)
    return {
        key: data.get(key)
        for key in (
            "team_id",
            "season_id",
            "club_id",
            "season_name",
            "name",
            "gender",
            "category",
            "city",
            "roster_fetched_at",
            "updated_at",
        )
    }
