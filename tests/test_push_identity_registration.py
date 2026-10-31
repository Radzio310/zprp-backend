"""A restored iOS token has one installation owner, other phones keep working."""
import ast
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from fastapi import HTTPException
from sqlalchemy import Column, DateTime, JSON, MetaData, String, Table, create_engine, insert, select, text, update

from app.push.models import PushRegisterRequest
from test_settlement_live import LocalDB


@pytest.mark.asyncio
async def test_registering_restored_token_detaches_only_the_obsolete_installation():
    meta = MetaData()
    tokens = Table("push_tokens", meta, Column("installation_id", String, primary_key=True),
        *(Column(k, String) for k in ["token", "token_type", "platform", "app_variant", "app_id", "app_version", "judge_id", "province"]),
        Column("notification_prefs", JSON), Column("updated_at", DateTime))
    engine = create_engine("sqlite://")
    meta.create_all(engine)
    with engine.connect() as conn:
        conn.connection.create_function("pg_advisory_xact_lock", 1, lambda key: 0)
        db = LocalDB(conn)
        tree = ast.parse((Path(__file__).resolve().parents[1] / "app/push/push.py").read_text(encoding="utf-8"))
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name in {"register", "_register", "_clean_judge_id"}]
        for node in nodes:
            node.decorator_list = []
        scope = {"database": db, "push_tokens": tokens, "PushRegisterRequest": PushRegisterRequest,
            "HTTPException": HTTPException, "Optional": Optional, "Dict": Dict, "Any": Any,
            "hashlib": hashlib, "select": select, "insert": insert, "update": update, "text": text,
            "_utc_now": lambda: datetime.now(timezone.utc), "normalize_province": lambda s: s}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "push_registration", "exec"), scope)
        for ins, token in [("old-ios", "same-fcm"), ("other-phone", "different-fcm")]:
            await scope["register"](PushRegisterRequest(installation_id=ins, token=token, token_type="device_fcm",
                judge_id="865", identity_known=True))
        await scope["register"](PushRegisterRequest(installation_id="restored-ios", token="same-fcm", token_type="device_fcm",
            judge_id="999", identity_known=True))
        rows = {r["installation_id"]: r for r in await db.fetch_all(select(tokens))}
        assert rows["old-ios"]["token"] == ""
        assert rows["old-ios"]["judge_id"] is None
        assert rows["restored-ios"]["token"] == "same-fcm"
        assert rows["restored-ios"]["judge_id"] == "999"
        assert rows["other-phone"]["token"] == "different-fcm"
        assert rows["other-phone"]["judge_id"] == "865"
    engine.dispose()
