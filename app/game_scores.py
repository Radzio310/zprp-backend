"""
Wspólny ranking mini-gier BAZY.

Model jest celowo ubogi: klient wysyła wiersz TYLKO wtedy, gdy pobił własny
rekord lokalny, więc tabela rośnie wolno i nie trzeba nic czyścić ani
przeliczać w tle. Ranking to zwykłe `MAX(score) GROUP BY judge_id` z okna
czasowego — stąd jeden zapis obsługuje zarówno listę wieczną, jak i miesięczną.

Tożsamość: `judge_id` (tak jak w całej BAZIE — bez tokenów), a `display_name`
i `province` przychodzą z ustawień aplikacji i są nadpisywane przy każdym
kolejnym rekordzie, więc zmiana nazwiska w profilu naprawia się sama.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func as sa_func, insert, select

from app.db import database, game_scores

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/game-scores", tags=["Mini-gry — ranking"])

# Klucze gier akceptowane przez serwer. Nowa gra = jedna linijka tutaj,
# inaczej wyniki lecą do kosza (celowo — chroni ranking przed śmieciami).
ALLOWED_GAMES = {"arena", "keeper", "referee", "targets", "juggle"}
ALLOWED_DIFFICULTIES = {"", "easy", "medium", "hard", "legend"}

# Sufit wyniku per gra — grubo powyżej tego, co da się osiągnąć grając, ale
# poniżej tego, co wpisałby ktoś podrabiający żądanie. Ranking jest po to, żeby
# się ścigać, więc niech nie wystarczy jeden curl, aby go zaorać.
# (Refleks: runda trwa 60 s, więc 300 trafień to jedno co 200 ms — nierealne.)
SCORE_CAP = {
    "arena": 1000,
    "referee": 300,
    "keeper": 500,
    "targets": 200,
    "juggle": 5000,
}

MAX_SCORE = 1_000_000
MAX_PLAYERS_SCANNED = 5000  # sufit bezpieczeństwa przy liczeniu pozycji


class SubmitScoreRequest(BaseModel):
    judge_id: str = Field(..., min_length=1, max_length=64)
    game: str = Field(..., min_length=1, max_length=32)
    difficulty: str = Field("", max_length=16)
    score: int = Field(..., ge=0, le=MAX_SCORE)
    display_name: str = Field(..., min_length=1, max_length=80)
    province: Optional[str] = Field(None, max_length=64)
    # Metryki gry: {"avgMs": 412, "bestMs": 233, ...}
    extra: Optional[Dict[str, Any]] = None


class LeaderboardEntry(BaseModel):
    rank: int
    judge_id: str
    display_name: str
    province: Optional[str] = None
    score: int
    extra: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    is_me: bool = False


class LeaderboardResponse(BaseModel):
    game: str
    difficulty: str
    scope: str
    total: int
    items: List[LeaderboardEntry]
    me: Optional[LeaderboardEntry] = None


class SubmitScoreResponse(BaseModel):
    ok: bool
    rank: Optional[int] = None
    total: int = 0
    improved: bool = False


def _validate(game: str, difficulty: str) -> tuple[str, str]:
    g = (game or "").strip().lower()
    d = (difficulty or "").strip().lower()
    if g not in ALLOWED_GAMES:
        raise HTTPException(status_code=400, detail=f"Nieznana gra: {game}")
    if d not in ALLOWED_DIFFICULTIES:
        raise HTTPException(status_code=400, detail=f"Nieznany poziom: {difficulty}")
    return g, d


def _month_start() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, 1, tzinfo=timezone.utc)


async def _ranking(
    game: str, difficulty: str, scope: str
) -> List[Dict[str, Any]]:
    """Pełna lista graczy (najlepszy wynik każdego) w kolejności rankingowej.

    Remis rozstrzyga czas: kto pierwszy osiągnął ten wynik, stoi wyżej.
    """
    best_score = sa_func.max(game_scores.c.score).label("best")
    first_at = sa_func.min(game_scores.c.created_at).label("first_at")

    q = (
        select(game_scores.c.judge_id, best_score, first_at)
        .where(game_scores.c.game == game)
        .where(game_scores.c.difficulty == difficulty)
        .group_by(game_scores.c.judge_id)
        .order_by(best_score.desc(), first_at.asc())
        .limit(MAX_PLAYERS_SCANNED)
    )
    if scope == "month":
        q = q.where(game_scores.c.created_at >= _month_start())

    grouped = await database.fetch_all(q)
    if not grouped:
        return []

    ids = [r["judge_id"] for r in grouped]

    # Dane opisowe bierzemy z wiersza z NAJLEPSZYM wynikiem danego gracza
    # (a przy remisie — z najnowszego, bo tam nazwisko jest najświeższe).
    detail_q = (
        select(game_scores)
        .where(game_scores.c.game == game)
        .where(game_scores.c.difficulty == difficulty)
        .where(game_scores.c.judge_id.in_(ids))
        .order_by(game_scores.c.score.desc(), game_scores.c.created_at.desc())
    )
    if scope == "month":
        detail_q = detail_q.where(game_scores.c.created_at >= _month_start())

    details: Dict[str, Any] = {}
    for row in await database.fetch_all(detail_q):
        details.setdefault(row["judge_id"], row)

    out: List[Dict[str, Any]] = []
    for i, row in enumerate(grouped):
        jid = row["judge_id"]
        d = details.get(jid)
        created = d["created_at"] if d is not None else None
        out.append(
            {
                "rank": i + 1,
                "judge_id": jid,
                "display_name": (d["display_name"] if d is not None else jid),
                "province": (d["province"] if d is not None else None),
                "score": int(row["best"] or 0),
                "extra": (d["extra"] if d is not None else None),
                "created_at": created.isoformat() if created is not None else None,
            }
        )
    return out


@router.post("", response_model=SubmitScoreResponse)
@router.post("/", response_model=SubmitScoreResponse, include_in_schema=False)
async def submit_score(payload: SubmitScoreRequest) -> SubmitScoreResponse:
    game, difficulty = _validate(payload.game, payload.difficulty)
    judge_id = payload.judge_id.strip()
    name = payload.display_name.strip() or judge_id

    cap = SCORE_CAP.get(game, MAX_SCORE)
    if payload.score > cap:
        raise HTTPException(
            status_code=400,
            detail=f"Wynik {payload.score} przekracza limit gry ({cap})",
        )

    # Nie zapisujemy wyników gorszych od tego, co gracz już ma na koncie —
    # inaczej reinstalacja aplikacji (pusty AsyncStorage) zasypywałaby tabelę.
    prev = await database.fetch_val(
        select(sa_func.max(game_scores.c.score))
        .where(game_scores.c.judge_id == judge_id)
        .where(game_scores.c.game == game)
        .where(game_scores.c.difficulty == difficulty)
    )
    improved = prev is None or payload.score > int(prev)

    if improved:
        await database.execute(
            insert(game_scores).values(
                judge_id=judge_id,
                game=game,
                difficulty=difficulty,
                score=int(payload.score),
                display_name=name[:80],
                province=(payload.province or "").strip()[:64] or None,
                extra=payload.extra or None,
                created_at=datetime.now(timezone.utc),
            )
        )

    board = await _ranking(game, difficulty, "all")
    rank = next((e["rank"] for e in board if e["judge_id"] == judge_id), None)
    return SubmitScoreResponse(
        ok=True, rank=rank, total=len(board), improved=improved
    )


@router.get("/leaderboard", response_model=LeaderboardResponse)
async def leaderboard(
    game: str = Query(...),
    difficulty: str = Query(""),
    scope: str = Query("all", pattern="^(all|month)$"),
    limit: int = Query(50, ge=1, le=200),
    judge_id: Optional[str] = Query(None),
) -> LeaderboardResponse:
    g, d = _validate(game, difficulty)
    board = await _ranking(g, d, scope)

    me_row: Optional[LeaderboardEntry] = None
    items: List[LeaderboardEntry] = []
    for entry in board[:limit]:
        is_me = judge_id is not None and entry["judge_id"] == judge_id
        item = LeaderboardEntry(**entry, is_me=is_me)
        items.append(item)
        if is_me:
            me_row = item

    # Gracz spoza czołówki i tak dostaje swój wiersz — po to, żeby aplikacja
    # mogła go przykleić na dole listy.
    if me_row is None and judge_id:
        mine = next((e for e in board if e["judge_id"] == judge_id), None)
        if mine is not None:
            me_row = LeaderboardEntry(**mine, is_me=True)

    return LeaderboardResponse(
        game=g,
        difficulty=d,
        scope=scope,
        total=len(board),
        items=items,
        me=me_row,
    )
