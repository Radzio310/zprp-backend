"""
Kara za nieobecność naliczana w sezonie - rozmowa z bazą.

Reguły (kolejność, kwota, ręczne nadpisanie) mieszkają w liściu
`app/bomb_penalty_rules.py`. Tu tylko czytamy skale okręgów i czynne bomby
sezonu, żeby rejestr (`match_bombs`) i rozliczenie (`province_settlements`)
liczyły KARĘ TĄ SAMĄ DROGĄ - ta sama kwota stoi na kaflu w aplikacji, w panelu
Rozliczeń i na zestawieniu.

Osobny moduł, a nie część `match_bombs`, bo rozliczenia nie mogą importować
tras (koło importów), a obie strony potrzebują dokładnie tego samego.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.sql import func

from app import bomb_penalty_rules as BP
from app.db import database, match_bombs, province_bomb_penalty_scale

#: Kolumny potrzebne do numeracji - bez reszty wiersza.
_ORDER_COLUMNS = (
    match_bombs.c.id,
    match_bombs.c.season,
    match_bombs.c.status,
    match_bombs.c.subject_judge_id,
    match_bombs.c.subject_name,
    match_bombs.c.match_at,
    match_bombs.c.created_at,
)


def _row(row: Any) -> Dict[str, Any]:
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})


province_key = BP.province_key
effective_from_pool = BP.effective_from_pool


async def load_scales() -> Dict[str, BP.Scale]:
    """Skale wszystkich okręgów, które zapisały własną (tabela ma najwyżej 16 wierszy)."""
    rows = await database.fetch_all(select(province_bomb_penalty_scale))
    out: Dict[str, BP.Scale] = {}
    for raw in rows:
        row = _row(raw)
        out[province_key(row.get("province"))] = BP.scale_from_row(row)
    return out


async def scale_for(province: Any) -> BP.Scale:
    return (await load_scales()).get(province_key(province), BP.DEFAULT_SCALE)


async def save_scale(province: Any, start: Any, step: Any, by: str) -> BP.Scale:
    """Zapis skali okręgu. Rzuca `ValueError` ze zdaniem, co poprawić."""
    key = province_key(province)
    if not key:
        raise ValueError("Brak okręgu.")
    scale = BP.normalize_scale(start, step)
    stmt = pg_insert(province_bomb_penalty_scale).values(
        province=key, start=scale.start, step=scale.step, updated_by=by or None
    )
    await database.execute(
        stmt.on_conflict_do_update(
            index_elements=[province_bomb_penalty_scale.c.province],
            set_={
                "start": scale.start,
                "step": scale.step,
                "updated_by": by or None,
                "updated_at": func.now(),
            },
        )
    )
    return scale


async def reset_scale(province: Any) -> BP.Scale:
    """Powrót do skali domyślnej (60 zł, +30 zł) - wiersz okręgu znika."""
    key = province_key(province)
    await database.execute(
        delete(province_bomb_penalty_scale).where(province_bomb_penalty_scale.c.province == key)
    )
    return BP.DEFAULT_SCALE


async def counted_rows(seasons: Iterable[Optional[int]]) -> List[Dict[str, Any]]:
    """Czynne bomby wskazanych sezonów ze WSZYSTKICH okręgów - pula do numeracji."""
    wanted = {s for s in seasons if s is not None}
    query = select(*_ORDER_COLUMNS).where(match_bombs.c.status == "active")
    if wanted:
        query = query.where(match_bombs.c.season.in_(sorted(wanted)))
    else:
        query = query.where(match_bombs.c.season.is_(None))
    return [_row(r) for r in await database.fetch_all(query)]


async def effective_for(rows: Iterable[Mapping[str, Any]]) -> Dict[int, BP.Effective]:
    """Kara dla tych wierszy - dociąga pulę ich sezonów i skale okręgów."""
    items = list(rows)
    if not items:
        return {}
    pool = await counted_rows({r.get("season") for r in items})
    return effective_from_pool(items, pool, await load_scales())
