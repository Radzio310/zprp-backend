"""Uruchamia właściwy endpoint bez uruchamiania produkcyjnej bazy przy imporcie."""
import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, MetaData, String, Table, select
from sqlalchemy.dialects.postgresql import insert as pg_insert


NOW = datetime(2026, 10, 24, 10, tzinfo=timezone.utc)


@pytest.fixture
def endpoint():
    meta = MetaData()
    tokens = Table("tokens", meta, Column("installation_id", String), Column("judge_id", String))
    receipts = Table("receipts", meta, Column("installation_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True), Column("match_id", String, primary_key=True),
        Column("observed_at", DateTime(timezone=True)))
    db = MagicMock(fetch_one=AsyncMock(return_value={"judge_id": "865"}), execute=AsyncMock())
    namespace = dict(database=db, push_tokens=tokens, push_local_match_receipts=receipts,
        select=select, pg_insert=pg_insert, BaseModel=BaseModel, HTTPException=HTTPException,
        datetime=datetime, timezone=timezone, timedelta=timedelta, _utc_now=lambda: NOW,
        _clean_judge_id=lambda value: str(value or "").strip() or None)
    path = Path(__file__).resolve().parents[1] / "app/push/push.py"
    nodes = [node for node in ast.parse(path.read_text(encoding="utf-8")).body
             if isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef))
             and node.name in {"LocalMatchReceiptRequest", "acknowledge_local_match_added"}]
    for node in nodes:
        node.decorator_list = []
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace, db


@pytest.mark.asyncio
async def test_receipt_is_idempotent_and_future_timestamp_is_clamped(endpoint):
    ns, db = endpoint
    req = ns["LocalMatchReceiptRequest"](installation_id="iphone", judge_id="865", match_id="208136",
        observed_at=NOW + timedelta(hours=1))
    assert await ns["acknowledge_local_match_added"](req) == {"ok": True}
    query = db.execute.call_args.args[0]
    compiled = query.compile()
    assert compiled.params["observed_at"] == NOW
    assert "ON CONFLICT" in str(compiled)
    assert "receipts.observed_at <" in str(compiled)


@pytest.mark.asyncio
async def test_receipt_cannot_be_attached_to_the_previous_logged_in_judge(endpoint):
    ns, db = endpoint
    req = ns["LocalMatchReceiptRequest"](installation_id="iphone", judge_id="123", match_id="208136", observed_at=NOW)
    with pytest.raises(HTTPException) as error:
        await ns["acknowledge_local_match_added"](req)
    assert error.value.status_code == 409
    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_receipts_older_than_seven_days_are_not_revived(endpoint):
    ns, db = endpoint
    req = ns["LocalMatchReceiptRequest"](installation_id="iphone", judge_id="865", match_id="208136",
        observed_at=NOW - timedelta(days=8))
    assert (await ns["acknowledge_local_match_added"](req))["expired"] is True
    db.execute.assert_not_called()
