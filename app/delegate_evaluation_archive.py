"""Oceny delegatów zbierane w tle przy pobieraniu meczów.

Przy każdym pobraniu meczów telefon i tak ma pod ręką linki z komórki
„Ocena" - wysyła je razem z ryczałtami i niczego więcej nie robi. Endpoint
rezerwuje nowe arkusze i od razu odpowiada 202; logowanie do ZPRP, pobranie
i przerobienie formularza dzieją się później, jedno konto naraz i ze
spokojnym tempem.

Tylko formularz `ocena2` z sezonów liczonych w statystyce (od 2025/2026);
stare PDF-y pomijamy. Przerobiona ocena trafia do `delegate_evaluations` -
tak samo, jak dotąd wysyłał ją telefon - a oryginał HTML zostaje w archiwum.
Poświadczenia żyją tylko w pamięci jednego zadania.
"""

from __future__ import annotations

import asyncio
import gzip
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import insert, select, update

from app import delegate_evaluation_archive_rules as R
from app.delegate_evaluation_parser import parse_delegate_evaluation_html
from app.db import database, delegate_evaluation_documents
from app.deps import Settings, get_rsa_keys, get_settings
from app.zprp_session import decrypt_field, login_and_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/delegate-evaluations", tags=["Delegate evaluations"])

_MAX_BATCH = 250
_STALE_AFTER = timedelta(minutes=30)
_RETRY_AFTER = timedelta(hours=6)
_MAX_ATTEMPTS = 3
#: Arkusz bieżącego sezonu delegat potrafi jeszcze poprawić albo dopiero
#: wypełnić - co trzy dni pobieramy go ponownie. Zakończone sezony są niezmienne.
_REFRESH_CURRENT_AFTER = timedelta(days=3)
_PAUSE_BETWEEN_DOCUMENTS = 0.35
_slots = asyncio.Semaphore(1)
_bg_tasks: set[asyncio.Task] = set()


class ArchiveCandidate(BaseModel):
    url: str = Field(min_length=8, max_length=600)
    match_id: str = Field(min_length=1, max_length=40)
    match_code: Optional[str] = Field(default=None, max_length=80)
    season: Optional[str] = Field(default=None, max_length=24)
    match_date: Optional[str] = Field(default=None, max_length=40)
    referee_ids: list[str] = Field(default_factory=list, max_length=4)
    referee_names: list[str] = Field(default_factory=list, max_length=4)
    delegate_name: Optional[str] = Field(default=None, max_length=160)


class ArchiveHarvestRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    province: Optional[str] = Field(default=None, max_length=80)
    links: list[ArchiveCandidate] = Field(default_factory=list, max_length=_MAX_BATCH)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _current_season_start(now: datetime) -> int:
    return now.year if now.month >= 7 else now.year - 1


def _is_current_season(season: str) -> bool:
    from app.delegate_evaluation_utils import season_start

    start = season_start(season)
    return start is not None and start >= _current_season_start(_now())


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


async def _reserve(candidate: dict[str, Any], province: str) -> bool:
    key = candidate["source_key"]
    row = await database.fetch_one(
        select(delegate_evaluation_documents).where(
            delegate_evaluation_documents.c.source_key == key
        )
    )
    now = _now()
    meta = {
        "match_code": candidate["match_code"] or None,
        "season": candidate["season"],
        "province": province or None,
        "match_date": candidate["match_date"] or None,
        "referee_ids": candidate["referee_ids"],
        "referee_names": candidate["referee_names"],
        "delegate_name": candidate["delegate_name"] or None,
    }
    if row:
        state = str(row["status"] or "")
        updated = _as_utc(row["updated_at"])
        age = now - updated if updated else _STALE_AFTER
        fetched = _as_utc(row["fetched_at"])
        if state == "done":
            stale = fetched is None or now - fetched >= _REFRESH_CURRENT_AFTER
            if not (_is_current_season(candidate["season"]) and stale):
                return False
        elif state in {"queued", "processing"} and age < _STALE_AFTER:
            return False
        elif state == "failed" and (
            int(row["attempts"] or 0) >= _MAX_ATTEMPTS or age < _RETRY_AFTER
        ):
            return False
        # Uzupełniamy opis tylko tym, co przyszło - pusty napis nie kasuje wiedzy.
        filled = {k: v for k, v in meta.items() if v not in (None, "", [])}
        await database.execute(
            update(delegate_evaluation_documents)
            .where(delegate_evaluation_documents.c.source_key == key)
            .values(status="queued", error=None, updated_at=now, **filled)
        )
        return True
    try:
        await database.execute(
            insert(delegate_evaluation_documents).values(
                source_key=key,
                path=candidate["path"],
                kind="html",
                match_id=candidate["match_id"],
                status="queued",
                attempts=0,
                created_at=now,
                updated_at=now,
                **meta,
            )
        )
        return True
    except Exception:  # wyścig dwóch telefonów z tym samym arkuszem
        return False


async def _mark(key: str, **values: Any) -> None:
    await database.execute(
        update(delegate_evaluation_documents)
        .where(delegate_evaluation_documents.c.source_key == key)
        .values(updated_at=_now(), **values)
    )


async def _store_evaluation(
    candidate: dict[str, Any], judge_id: str, province: str, evaluation: dict[str, Any]
) -> str:
    """Do statystyk tą samą drogą, co z telefonu - ten sam klucz i ta sama wersja."""
    if not R.judge_on_sheet(judge_id, candidate["referee_ids"]):
        return "skipped"
    from app.delegate_evaluations import EvaluationIn, upsert_evaluation

    return await upsert_evaluation(
        EvaluationIn(
            match_id=candidate["match_id"],
            season=candidate["season"],
            province=province or "brak",
            match_number=candidate["match_code"],
            match_date=candidate["match_date"],
            referee_ids=candidate["referee_ids"],
            referee_names=candidate["referee_names"],
            delegate_name=candidate["delegate_name"],
            source_kind="html",
            source_url=candidate["path"].lstrip("/"),
            evaluation=evaluation,
        ),
        judge_id,
    )


async def _fetch_one(client, candidate: dict[str, Any]) -> bytes:
    last: Exception | None = None
    for attempt in range(2):
        try:
            response = await client.get(candidate["path"], timeout=30.0)
            if response.status_code != 200:
                raise ValueError(f"ZPRP zwrócił HTTP {response.status_code}")
            return await response.aread()
        except Exception as exc:  # noqa: BLE001 - źródło zewnętrzne
            last = exc
            await asyncio.sleep(1.0 + attempt)
    raise last or ValueError("Brak odpowiedzi ZPRP")


async def _process_inner(
    username: str,
    password: str,
    judge_id: str,
    province: str,
    candidates: list[dict[str, Any]],
    settings: Settings,
) -> None:
    client = None
    try:
        client = await login_and_client(username, password, settings)
        for candidate in candidates:
            key = candidate["source_key"]
            try:
                row = await database.fetch_one(
                    select(delegate_evaluation_documents.c.attempts).where(
                        delegate_evaluation_documents.c.source_key == key
                    )
                )
                await _mark(
                    key,
                    status="processing",
                    attempts=int(row["attempts"] or 0) + 1 if row else 1,
                    error=None,
                )
                data = await _fetch_one(client, candidate)
                from app.delegate import _decode_html_bytes

                html = _decode_html_bytes(data, "")
                if R.looks_like_login_page(html) or len(html.strip()) < 40:
                    raise ValueError("ZPRP oddał stronę logowania zamiast arkusza")
                evaluation = parse_delegate_evaluation_html(html)
                stored = "empty"
                if R.has_grades(evaluation):
                    stored = await _store_evaluation(candidate, judge_id, province, evaluation)
                await _mark(
                    key,
                    status="done",
                    # Nie błąd - ślad, czemu arkusz nie trafił do statystyk.
                    error=None if stored != "empty" and stored != "skipped" else stored,
                    content_hash=R.content_hash(data),
                    fetched_at=_now(),
                    submitted_by=judge_id,
                    html_gz=gzip.compress(html.encode("utf-8")),
                )
            except Exception as exc:  # jeden wadliwy arkusz nie zatrzymuje paczki
                logger.warning("Arkusz oceny %s nie został pobrany: %s", key, exc)
                await _mark(key, status="failed", error=str(exc)[:700])
            await asyncio.sleep(_PAUSE_BETWEEN_DOCUMENTS)
    except Exception as exc:
        logger.warning("Nie udało się otworzyć sesji ZPRP dla ocen delegatów: %s", exc)
        for candidate in candidates:
            await _mark(candidate["source_key"], status="failed", error=str(exc)[:700])
    finally:
        if client is not None:
            await client.aclose()
        username = ""
        password = ""


async def _process(*args: Any) -> None:
    # Jedno konto naraz: archiwum to dodatek, nie może dławić ZPRP ani ryczałtów.
    async with _slots:
        await _process_inner(*args)


@router.post(
    "/harvest",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Kolejkuj oceny delegatów (formularz ocena2) bez blokowania pobierania meczów",
)
async def harvest_delegate_evaluations(
    body: ArchiveHarvestRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    unique: dict[str, dict[str, Any]] = {}
    rejected = 0
    for item in body.links[:_MAX_BATCH]:
        try:
            normalized = R.validated_candidate(item.model_dump())
            unique[normalized["source_key"]] = normalized
        except ValueError:
            rejected += 1

    province = str(body.province or "").strip()
    accepted = [item for item in unique.values() if await _reserve(item, province)]
    if accepted:
        private_key, _ = keys
        try:
            username = decrypt_field(body.username, private_key)
            password = decrypt_field(body.password, private_key)
            judge_id = decrypt_field(body.judge_id, private_key)
        except HTTPException:
            for item in accepted:
                await _mark(item["source_key"], status="failed", error="Błąd deszyfrowania")
            raise
        _spawn(_process(username, password, judge_id, province, accepted, settings))
        username = ""
        password = ""

    return {
        "accepted": len(accepted),
        "known": max(0, len(unique) - len(accepted)),
        "rejected": rejected,
        "processing": bool(accepted),
    }
