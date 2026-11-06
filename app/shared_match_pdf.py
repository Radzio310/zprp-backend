"""PDF protokołu meczu ręcznego zapisany na naszym serwerze (bez ZPRP).

Mecz z kluczem `M-<tuleja>/<numer>` jest oficjalny, ale nie ma IdZawody, więc
wygenerowany protokół nie ma dokąd pójść. Zostaje tutaj: generator woła
`store_pdf` zaraz po konwersji, a obsada meczu pobiera plik trasami niżej.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi.responses import Response
from sqlalchemy import delete, insert, select

from app import mentor_panel_core as C
from app.db import database, shared_match_pdfs
from app.proel_match_key import shared_key_of_blob  # noqa: F401  (re-eksport)

logger = logging.getLogger("app.shared_match_pdf")
T = shared_match_pdfs


async def store_pdf(key: str, pdf_bytes: bytes, *, filename: str, audit_code: str = "",
                    actor_name: str = "", actor_judge_id: str = "") -> bool:
    """Zapisz (zastąp) PDF meczu ręcznego. Błąd zapisu nie psuje generowania protokołu."""
    if not key or not pdf_bytes:
        return False
    try:
        async with database.transaction():
            await database.execute(delete(T).where(T.c.proel_key == key))
            await database.execute(insert(T).values(
                proel_key=key, pdf=pdf_bytes, filename=filename or "protokol.pdf",
                audit_code=audit_code or None, actor_name=actor_name or None,
                actor_judge_id=actor_judge_id or None, size=len(pdf_bytes),
            ))
        return True
    except Exception:  # noqa: BLE001
        logger.warning("nie zapisano PDF meczu ręcznego %s", key, exc_info=True)
        return False


async def pdf_meta(key: str) -> Optional[Dict[str, Any]]:
    """Metadane zapisanego PDF-a (bez bajtów) albo None."""
    if not key:
        return None
    row = await C.one(select(T.c.proel_key, T.c.filename, T.c.audit_code, T.c.actor_name, T.c.size, T.c.created_at)
                      .where(T.c.proel_key == key))
    if not row:
        return None
    created = row.get("created_at")
    return {
        "exists": True,
        "filename": row.get("filename"),
        "audit_code": row.get("audit_code"),
        "actor_name": row.get("actor_name"),
        "size": int(row.get("size") or 0),
        "created_at": created.isoformat() if hasattr(created, "isoformat") else created,
    }


async def pdf_bytes(key: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(T.c.pdf, T.c.filename).where(T.c.proel_key == key)) if key else None


def pdf_response(row: Dict[str, Any]) -> Response:
    name = str(row.get("filename") or "protokol.pdf").replace('"', "")
    return Response(
        content=bytes(row["pdf"]), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"},
    )
