"""Zadania klipów Bastionu - trwała kolejka (etap 1: zapis, idempotencja, przypięcie do konta; worker to etap 4).

Zasady (handoff 10.3): zadanie i jego odcisk zapisujemy PRZED jakimkolwiek zewnętrznym zapisem; jedna operacja
na rewizję klipu; zdalne id zapisujemy natychmiast; po utracie sesji zadanie czeka (`waiting_for_auth`) na to samo
konto; spóźniony wynik starej rewizji nie zastępuje nowej. Importy bazy w funkcjach (`app.db` łączy się przy imporcie).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from app import mentor_bastion_rules as BR


async def enqueue_clip_job(*, clip: Dict[str, Any], bunny_item_id: int, revision: int, requested_by: str,
                           acted_as: Optional[str] = None, connection: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Dodaje zadanie dla klipu (`mentor_clips`) i rewizji. Ten sam klip + rewizja = to samo zadanie (bez duplikatu).
    Rzuca `BR.ClipRangeError`, gdy zakres nie mieści się w limitach Bastionu."""
    from sqlalchemy import select

    from app import mentor_panel_core as C
    from app import mentor_panel_rules as R
    from app.db import database, mentor_bastion_clip_jobs as J

    rng = BR.bastion_clip_range(float(clip["start_s"]), float(clip["end_s"]))
    fingerprint = BR.clip_fingerprint(clip_id=clip["id"], revision=revision, bunny_item_id=bunny_item_id,
                                      start_s=rng["start_s"], end_s=rng["end_s"])
    existing = await C.one(select(J).where(J.c.clip_id == clip["id"]).where(J.c.clip_revision == int(revision)))
    if existing:
        return existing
    stamp = C.now()
    row = {
        "id": R.new_id(), "clip_id": clip["id"], "pair_id": clip["pair_id"], "match_id": clip["match_id"],
        "source_video_id": clip["video_id"], "source_bunny_item_id": int(bunny_item_id),
        "requested_by_real_judge_id": str(requested_by), "acted_as_judge_id": acted_as or None,
        "connection_id": (connection or {}).get("id"), "external_identity_id": (connection or {}).get("external_identity_id"),
        "clip_revision": int(revision), "start_s": rng["start_s"], "end_s": rng["end_s"],
        "idempotency_key": fingerprint, "request_fingerprint": fingerprint, "state": "queued", "attempts": 0,
        "created_at": stamp, "updated_at": stamp,
    }
    try:
        await database.execute(J.insert().values(**row))
    except Exception:  # noqa: BLE001 - wyścig dwóch zapisów tej samej rewizji kończy się jednym zadaniem
        again = await C.one(select(J).where(J.c.clip_id == clip["id"]).where(J.c.clip_revision == int(revision)))
        if not again:
            raise
        return again
    return row


async def hold_jobs_for_connection(connection_id: str, error_code: str = "BASTION_AUTH_REQUIRED") -> int:
    """Utrata/odłączenie sesji: aktywne zadania tego połączenia czekają na to samo konto (zdalne id zostaje)."""
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    waiting = [s for s in BR.JOB_ACTIVE if s not in ("waiting_for_auth", "needs_reconciliation", "uploading")]
    res = await database.execute(update(J).where(J.c.connection_id == connection_id).where(J.c.state.in_(waiting))
                                 .values(state="waiting_for_auth", last_error_code=error_code, updated_at=C.now(),
                                         lease_until=None, worker_id=None))
    return int(res or 0)
